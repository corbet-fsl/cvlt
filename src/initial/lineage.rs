//! An explicit original-network consensus observation of the retained genesis.
use super::*;
use crate::{LineageEvidence, MAX_LINEAGE_EVIDENCE_BYTES, records::tor::Verifier};
use cdht::Backend as _;
use zeroize::Zeroizing;

/// A forced read observed the exact retained signed pair at the original read
/// agreement target. This owns the incomplete creation, never usable Keys.
/// Current Foyer membership and Charter must still be reborrowed after this
/// await before any later completion. No constructor, clone, serialization or
/// acknowledgment is exposed.
pub struct InitialLineageRead<B: Backend> {
    creation: InitialCreation<B>,
    evidence: LineageEvidence,
    checked_at: u64,
}
impl<B: Backend> InitialLineageRead<B> {
    /// Original public evidence, requiring fresh current-Charter verification.
    /// Neither this evidence nor its receipt grants completion authority.
    pub fn evidence(&self) -> &LineageEvidence {
        &self.evidence
    }

    /// Exact pending original receipt retained by this incomplete owner.
    pub fn receipt(&self) -> &ckmg::Receipt {
        self.creation.receipt()
    }

    /// Local observation floor, not an authenticated server timestamp or lease.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
}
impl<B: Backend> std::fmt::Debug for InitialLineageRead<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialLineageRead([redacted])")
    }
}

impl<B: Backend> InitialCreation<B> {
    /// Read through a fresh original NetworkBackend, retaining its explicit
    /// consensus report. The supplied Network is the original Mesh transport
    /// contract; production must supply its authenticated owner, not caller JSON.
    /// Partial/missing/unavailable replies never prove absence or permit Create.
    /// A different authenticated value selected by the original read report
    /// fences this operation durably, even below consensus. The report does not
    /// expose every equal-sequence disagreement. Cancellation consumes this
    /// in-memory attempt; reopening the exact durable phase remains allowed.
    pub async fn read_first_lineage<N: cdht::Network>(
        mut self,
        network: N,
        clock: &mut impl Clock,
    ) -> Result<InitialLineageRead<B>, InitialError> {
        if self.phase()? != InitialPhase::Staged {
            return Err(InitialError::Invalid);
        }
        let intent = decode_intent(required(&self.store, INTENT)?)?;
        let started = clock.now().map_err(InitialError::Keys)?;
        if started < self.pending.last_time().max(intent.prepared_at) {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        if started >= intent.expires {
            return Err(InitialError::Keys(ckmg::Error::Expired));
        }
        self.require_current_checkpoint().await?;
        let retained = self.retained()?;
        let descriptor = retained
            .descriptor
            .decode()
            .map_err(InitialError::Publication)?;
        let value = retained.value.decode().map_err(InitialError::Publication)?;
        let key = descriptor.key();
        let records = cdht::NetworkBackend::new(network, Verifier);
        if records
            .descriptor(&key)
            .await
            .map_err(InitialError::Publication)?
            != Some(descriptor)
        {
            return Err(InitialError::Records(crate::RecordError::Unavailable));
        }
        let report = records
            .read(&key, 0)
            .await
            .map_err(InitialError::Publication)?;
        if let Some(observed) = &report.value {
            if observed != &value {
                let state = self.staged_state()?;
                let mut client = cdht::Dht::with_state(records, Verifier, state.clone());
                if client.state() != &state {
                    return Err(InitialError::Invalid);
                }
                client
                    .observe_original(&key, 0, observed)
                    .map_err(InitialError::Publication)?;
                self.retain_conflict(client.state()).await?;
                return Err(InitialError::Publication(cdht::Error::Conflict));
            }
        }
        if !report.has_consensus() || report.value.as_ref() != Some(&value) {
            return Err(InitialError::Records(crate::RecordError::Unavailable));
        }
        // The original private CKMG construction encrypted this immutable
        // packed intent into the exact signed value. No new decryptor, root
        // reader or supplied plaintext is accepted at this boundary.
        let compressed = Zeroizing::new(
            cprz_pad::unpad(&intent.packed_evidence).map_err(|_| InitialError::Invalid)?,
        );
        let bytes = Zeroizing::new(
            cprz::portable::decompress(
                &compressed,
                cdht::MAX_SUBKEY_SIZE,
                MAX_LINEAGE_EVIDENCE_BYTES,
            )
            .map_err(|_| InitialError::Invalid)?,
        );
        let evidence = LineageEvidence::from_bytes(&bytes).map_err(|_| InitialError::Invalid)?;
        if !evidence.matches_receipt(self.receipt()) {
            return Err(InitialError::Invalid);
        }
        self.require_current_checkpoint().await?;
        let checked_at = clock.now().map_err(InitialError::Keys)?;
        if checked_at < started {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        if checked_at >= intent.expires {
            return Err(InitialError::Keys(ckmg::Error::Expired));
        }
        Ok(InitialLineageRead {
            creation: self,
            evidence,
            checked_at,
        })
    }

    async fn require_current_checkpoint(&self) -> Result<(), InitialError> {
        let committed = self
            .store
            .sealed_checkpoint()
            .map_err(InitialError::Storage)?;
        if self
            .backend
            .read()
            .await
            .map_err(InitialError::Storage)?
            .as_deref()
            != Some(committed)
        {
            return Err(InitialError::Storage(cwst::Error::Conflict));
        }
        Ok(())
    }
}
