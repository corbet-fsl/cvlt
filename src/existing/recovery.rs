//! Verified passkey recovery into the original compound Store.
use super::*;

/// Temporary opaque root bootstrap, retained only for this opening session.
/// Its descendants borrow it; it exposes no root/device/Wallet capability.
pub struct PreparedRecovery<'attempt> {
    opening: &'attempt PreparedOpen,
    custody: ckmg::CheckpointBootstrap,
    evidence: &'attempt [u8],
    checked_at: u64,
}

/// Verified public preparation, carrying only original sealed Keys bytes and
/// evidence across the next await. It grants no current authority or root custody.
pub struct RecoveryCandidate {
    opening: PreparedOpen,
    sealed: zeroize::Zeroizing<Vec<u8>>,
    evidence: Vec<u8>,
}

impl PreparedOpen {
    /// Verify the original receipt/assertion/certificate against the actual
    /// current Charter, then ask Authority to force the decided current lineage
    /// read and live HTTPS membership check for these exact checkpoint claims.
    /// The Authority rechecks current policy after its awaits; the borrowed
    /// Charter observation here is never an accepting cache or lease.
    pub fn prepare_recovery(
        self,
        checkpoint: &RecordCheckpoint,
        current: &cchr::VerifiedCharter,
        expected_member: &str,
        now: u64,
    ) -> Result<RecoveryCandidate, OpenError> {
        let evidence = checkpoint.evidence().ok_or(OpenError::RecoveryRequired)?;
        let observed = evidence
            .verify(current, expected_member, now)
            .map_err(OpenError::Evidence)?;
        let inspection = self.inspect_record(checkpoint)?;
        if inspection.lineage() != observed.lineage(now).map_err(OpenError::Evidence)? {
            return Err(OpenError::Keys(ckmg::Error::Unauthorized));
        }
        let wire = evidence
            .to_bytes()
            .map_err(|_| OpenError::Records(crate::RecordError::Invalid))?;
        Ok(RecoveryCandidate {
            opening: self,
            sealed: zeroize::Zeroizing::new(checkpoint.sealed().to_vec()),
            evidence: wire,
        })
    }
}

impl RecoveryCandidate {
    /// Borrow only the approved provisional lineage read key for this attempt.
    /// Current policy and fresh HTTPS are rechecked by the supplied original
    /// recovery authority. Drop the reader before consuming/dropping the attempt.
    pub async fn read_lineage(
        &self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<ckmg::ProvisionalLineage<'_>, OpenError> {
        self.opening
            .inspector()?
            .read_lineage(&self.sealed, &self.evidence, clock, authority)
            .await
            .map_err(OpenError::Keys)
    }

    /// Obtain current member authority using the exact prepared source claims.
    /// Authority must reborrow the live policy after its forced Records/HTTPS
    /// reads; the earlier synchronous preparation is not an accepting result.
    pub async fn authorize(
        &self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<PreparedRecovery<'_>, OpenError> {
        let custody = self
            .opening
            .inspector()?
            .bootstrap(&self.sealed, &self.evidence, clock, authority)
            .await
            .map_err(OpenError::Keys)?;
        let checked_at = custody.checked_at();
        Ok(PreparedRecovery {
            opening: &self.opening,
            custody,
            evidence: &self.evidence,
            checked_at,
        })
    }
}

impl std::fmt::Debug for RecoveryCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCandidate([redacted])")
    }
}

impl PreparedRecovery<'_> {
    /// Independent read custody for normal member checks, available only after
    /// the provisional forced read and full member authority have succeeded.
    pub fn lineage_reader(&self) -> Result<ckmg::LineageReadCustody, OpenError> {
        self.custody.lineage_reader().map_err(OpenError::Keys)
    }

    async fn check_current(
        &mut self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<(), OpenError> {
        let inspection = self.custody.inspection();
        let lineage = inspection.lineage();
        let now = clock.now().map_err(OpenError::Keys)?;
        if now < self.checked_at || now < inspection.last_time() {
            return Err(OpenError::Keys(ckmg::Error::Clock));
        }
        authority
            .check(ckmg::Authorization {
                binding: &lineage.binding,
                root: Some(lineage.root),
                device: inspection.device(),
                epoch: lineage.epoch,
                action: ckmg::Action::Use,
                target: None,
                statement: Some(lineage.digest().map_err(OpenError::Keys)?),
                signing: None,
                now,
                evidence: self.evidence,
            })
            .await
            .map_err(OpenError::Keys)?;
        let after = clock.now().map_err(OpenError::Keys)?;
        if after < now {
            return Err(OpenError::Keys(ckmg::Error::Clock));
        }
        self.checked_at = after;
        Ok(())
    }
    /// Fixed original compound manifest/chunk custody, without an arbitrary
    /// purpose selector. The trusted Records adapter uses DFLT(32) only.
    pub fn record(
        &self,
        child: Option<u8>,
    ) -> Result<ckmg::CheckpointRecordCustody<'_>, OpenError> {
        self.custody.record(child).map_err(OpenError::Keys)
    }

    /// Construct the recovered member owner's original passkey Records handle.
    /// It retains only read custody after a fresh member check. Neither this
    /// handle nor a lookup grants current membership or permits creation/writes.
    pub async fn tor_passkey_records<N: cdht::Network>(
        &mut self,
        network: N,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<crate::PasskeyRecords<crate::TorPasskeyRecord<'static, N>>, OpenError> {
        self.check_current(clock, authority).await?;
        let reader = self
            .custody
            .passkey_reader(&self.opening.prf)
            .map_err(OpenError::Keys)?;
        let backend = crate::TorPasskeyRecord::open(network, reader)
            .await
            .map_err(|_| OpenError::Records(crate::RecordError::Unavailable))?;
        let record = cdht::runtime::Record::new(backend)
            .map_err(|_| OpenError::Records(crate::RecordError::Invalid))?;
        self.check_current(clock, authority).await?;
        crate::PasskeyRecords::new(self.opening.locator, record).map_err(OpenError::Records)
    }

    /// Read the existing compound checkpoint through the original signed Tor
    /// Records backend. Every selected manifest and part requires independent
    /// three-holder agreement. Temporary root/child readers are dropped before
    /// returning sealed Store bytes; no writer or Store key escapes this attempt.
    pub async fn tor_checkpoint<N: cdht::Network + Clone>(
        &mut self,
        network: N,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<crate::RetainedCheckpoint, OpenError> {
        self.check_current(clock, authority).await?;
        let retained = {
            let root =
                crate::records::tor::TorReadRecord::checkpoint(network.clone(), self.record(None)?)
                    .and_then(cdht::runtime::Record::new)
                    .map_err(|_| OpenError::Checkpoint(crate::CheckpointError::Unavailable))?;
            let mut children = Vec::with_capacity(crate::MAX_CHECKPOINT_RECORDS);
            for index in 0..crate::MAX_CHECKPOINT_RECORDS {
                let child = crate::records::tor::TorReadRecord::checkpoint(
                    network.clone(),
                    self.record(Some(index as u8))?,
                )
                .and_then(cdht::runtime::Record::new)
                .map_err(|_| OpenError::Checkpoint(crate::CheckpointError::Unavailable))?;
                children.push(child);
            }
            let mut records = crate::CompoundRecords::new(&self.opening.scope, root, children)
                .map_err(OpenError::Checkpoint)?;
            records.checkpoint().await.map_err(OpenError::Checkpoint)?
        };
        // A long read cannot retain a successful member observation. Recheck
        // after dropping record custody, and Store opening will check once more.
        self.check_current(clock, authority).await?;
        Ok(retained)
    }

    /// Open the existing local common-root checkpoint and reconcile its exact
    /// selected passkey entry before constructing Keys. Missing data never creates.
    pub async fn open_existing<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        mut self,
        backend: B,
        mut owners: Owners<C, E, A, R, W>,
    ) -> Result<Vault<B, C, E, A, R, W>, OpenError> {
        self.check_current(&mut owners.clock, &mut owners.authority)
            .await?;
        let store = cwst::Store::open(
            backend,
            self.custody.store_cipher().map_err(OpenError::Keys)?,
            &self.opening.scope,
        )
        .await
        .map_err(OpenError::Storage)?;
        self.finish(store, owners).await
    }

    /// Restore the one retained compound checkpoint into an empty destination.
    /// Its exact selected passkey entry is checked before the persistence CAS.
    pub async fn restore<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        mut self,
        retained: crate::RetainedCheckpoint,
        backend: B,
        mut owners: Owners<C, E, A, R, W>,
    ) -> Result<Vault<B, C, E, A, R, W>, OpenError> {
        self.check_current(&mut owners.clock, &mut owners.authority)
            .await?;
        let store = retained
            .restore_keys(
                backend,
                self.custody.store_cipher().map_err(OpenError::Keys)?,
                &self.opening.scope,
                self.opening.locator,
                self.custody.inspection().sealed_digest(),
            )
            .await
            .map_err(OpenError::Checkpoint)?;
        self.finish(store, owners).await
    }

    async fn finish<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        self,
        store: cwst::Store<B>,
        mut owners: Owners<C, E, A, R, W>,
    ) -> Result<Vault<B, C, E, A, R, W>, OpenError> {
        if owners.clock.now().map_err(OpenError::Keys)? < self.checked_at {
            return Err(OpenError::Keys(ckmg::Error::Clock));
        }
        let sealed = store
            .read("keys", self.opening.locator.as_bytes())
            .map_err(OpenError::Storage)?
            .ok_or(OpenError::Keys(ckmg::Error::MissingCheckpoint))?;
        if blake3::hash(sealed).as_bytes() != self.custody.inspection().sealed_digest() {
            return Err(OpenError::Keys(ckmg::Error::Unauthorized));
        }
        let mut vault = Vault::new(
            store,
            &self.opening.scope,
            owners.clock,
            owners.entropy,
            owners.authority,
            owners.records,
            owners.wallet,
        )
        .map_err(OpenError::Composition)?;
        vault
            .keys()
            .unlock(&self.opening.prf, &self.opening.scope)
            .await
            .map_err(OpenError::Keys)?;
        let lineage = vault.keys().lineage().await.map_err(OpenError::Keys)?;
        if &lineage != self.custody.inspection().lineage() {
            return Err(OpenError::Keys(ckmg::Error::Unauthorized));
        }
        Ok(vault)
    }
}
impl std::fmt::Debug for PreparedRecovery<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRecovery([redacted])")
    }
}
