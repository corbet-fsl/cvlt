//! Completed original acknowledgment, distinct from an unfinished intent lease.
use super::*;
use zeroize::Zeroizing;

/// Private normal bootstrap plus the actual authenticated acknowledged Store.
/// No constructor or custody escapes before both original owners agree.
pub(super) struct AcknowledgedRecovery {
    pub(super) bootstrap: ckmg::CheckpointBootstrap,
    pub(super) inner: cwst::Store<cwst::backend::Memory>,
    pub(super) evidence: crate::LineageEvidence,
    pub(super) checked_at: Option<u64>,
}

impl<B: Backend> InitialCreation<B> {
    pub(super) async fn acknowledged_recovery(
        &self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<AcknowledgedRecovery, InitialError> {
        if !matches!(
            self.phase()?,
            InitialPhase::Acknowledged
                | InitialPhase::RecoveryStaged
                | InitialPhase::RecoveryProgress
                | InitialPhase::RecoveryDiverged
                | InitialPhase::RetirementSelected
        ) {
            return Err(InitialError::Invalid);
        }
        let intent = decode_intent(required(&self.store, INTENT)?)?;
        let started = clock.now().map_err(InitialError::Keys)?;
        if started < intent.prepared_at.max(self.pending.last_time()) {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        let compressed = Zeroizing::new(
            cprz_pad::unpad(&intent.packed_evidence).map_err(|_| InitialError::Invalid)?,
        );
        let bytes = Zeroizing::new(
            cprz::portable::decompress(
                &compressed,
                cdht::MAX_SUBKEY_SIZE,
                crate::MAX_LINEAGE_EVIDENCE_BYTES,
            )
            .map_err(|_| InitialError::Invalid)?,
        );
        let evidence =
            crate::LineageEvidence::from_bytes(&bytes).map_err(|_| InitialError::Invalid)?;
        if !evidence.matches_receipt(self.receipt()) {
            return Err(InitialError::Invalid);
        }
        let sealed = required(&self.store, ACKNOWLEDGED_KEYS)?;
        let inspector = self.opening.inspector().map_err(InitialError::Open)?;
        // The ordinary inspector refuses all pending Keys. This can acquire
        // only normal checkpoint custody from fresh original Use authority.
        // The custody remains private until the actual inner MAC/receipt agrees.
        let bootstrap = inspector
            .bootstrap(sealed, &bytes, clock, authority)
            .await
            .map_err(InitialError::Keys)?;
        if bootstrap.inspection().lineage()
            != self
                .receipt()
                .attested_lineage()
                .map_err(InitialError::Keys)?
                .0
            || bootstrap.inspection().revision() != 2
        {
            return Err(InitialError::Invalid);
        }
        let operation = *self.receipt().operation.as_bytes();
        let inner = cwst::Store::restore_checked(
            cwst::backend::Memory::new(),
            bootstrap.store_cipher().map_err(InitialError::Keys)?,
            &self.opening.scope,
            2,
            required(&self.store, ACKNOWLEDGED_INNER)?,
            |inner| {
                if inner.operation()? != operation
                    || inner.read("keys", self.opening.locator.as_bytes())? != Some(sealed)
                {
                    return Err(cwst::Error::Corrupt);
                }
                Ok(())
            },
        )
        .await
        .map_err(InitialError::Storage)?;
        if self
            .store
            .read(OWNER, ENROLLMENT)
            .map_err(InitialError::Storage)?
            .is_some()
        {
            let provenance = evidence
                .initial_acknowledgment(&inspector, sealed)
                .map_err(InitialError::Open)?;
            if provenance.seed() != self.enrollment_commitment()?
                || provenance.publication() != self.publication_commitment()?
            {
                return Err(InitialError::Invalid);
            }
            crate::retention::check_initial_ack(&inner, &provenance)
                .map_err(InitialError::Storage)?;
        }
        let retained = crate::LineageEvidence::load(&inner, &operation)
            .map_err(|_| InitialError::Invalid)?
            .ok_or(InitialError::Invalid)?;
        if !retained.matches_receipt(self.receipt())
            || retained
                .to_bytes()
                .map_err(|_| InitialError::Invalid)?
                .as_slice()
                != bytes.as_slice()
        {
            return Err(InitialError::Invalid);
        }
        let checked_at = bootstrap.checked_at().max(started);
        let mut result = AcknowledgedRecovery {
            bootstrap,
            inner,
            evidence: retained,
            checked_at: Some(checked_at),
        };
        result.check_current(clock, authority)?;
        Ok(result)
    }
}

impl AcknowledgedRecovery {
    /// Fresh original synchronous owner join after awaits. Failure consumes this
    /// attempt's check state; the old genesis attempt's expiry is never changed.
    pub(super) fn check_current(
        &mut self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<u64, InitialError> {
        let floor = self.checked_at.take().ok_or(InitialError::Invalid)?;
        let now = clock.now().map_err(InitialError::Keys)?;
        if now < floor {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        let inspection = self.bootstrap.inspection();
        let lineage = inspection.lineage();
        let evidence = self
            .evidence
            .to_bytes()
            .map_err(|_| InitialError::Invalid)?;
        let owner_floor = authority
            .check_checkpoint_current(ckmg::Authorization {
                binding: &lineage.binding,
                root: Some(lineage.root),
                device: inspection.device(),
                epoch: lineage.epoch,
                action: ckmg::Action::Use,
                target: None,
                statement: Some(lineage.digest().map_err(InitialError::Keys)?),
                signing: None,
                now,
                evidence: &evidence,
            })
            .map_err(InitialError::Keys)?;
        let completed = clock.now().map_err(InitialError::Keys)?;
        if completed < now.max(owner_floor) {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        self.checked_at = Some(completed);
        Ok(completed)
    }
}
