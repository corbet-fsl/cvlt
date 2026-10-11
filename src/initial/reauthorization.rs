//! Present-day verification of one durably acknowledged original creation.
use super::*;
use zeroize::Zeroizing;

/// Sealed original ACK preparation. It is neither membership nor ordinary Keys
/// authority. Only the original provisional read can be requested from it, and
/// that read still requires its own fresh Authority decision. The actual inner
/// Store MAC/receipt is checked separately before recovery output can escape.
pub struct AcknowledgedInitialCandidate {
    inspector: ckmg::CheckpointInspector,
    sealed: Zeroizing<Vec<u8>>,
    evidence: crate::LineageEvidence,
    seed: [u8; 32],
    publication: [u8; 32],
}

/// A current same-key verification of the immutable original receipt assertion.
/// This makes no claim about an old certificate's historical validity or time.
/// It is deliberately not a generic lineage observation or Keys capability.
pub struct CurrentInitialLineage<'a>(crate::VerifiedLineageObservation<'a>);
impl CurrentInitialLineage<'_> {
    /// Original exact lineage within this current verification lifetime.
    pub fn lineage(&self, now: u64) -> Result<&ckmg::Lineage, crate::LineageError> {
        self.0.lineage(now)
    }
    /// Original device author, verified by the unchanged receipt.
    pub fn author(&self, now: u64) -> Result<ckmg::PublicKey, crate::LineageError> {
        self.0.author(now)
    }
    /// Exact currently certified credential that verifies the old assertion.
    pub fn credential_id(&self, now: u64) -> Result<&[u8], crate::LineageError> {
        self.0.credential_id(now)
    }
}

impl<B: Backend> InitialCreation<B> {
    /// Retain only the original acknowledged checkpoint's provisional read
    /// preparation. Pending/Prepared/Staged states refuse, irrespective of a
    /// fresh certificate. No old completion deadline is renewed by this method.
    pub fn acknowledged_candidate(&self) -> Result<AcknowledgedInitialCandidate, InitialError> {
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
        let evidence = crate::LineageEvidence::from_packed(&intent.packed_evidence)
            .map_err(|_| InitialError::Invalid)?;
        if !evidence.matches_receipt(self.receipt()) {
            return Err(InitialError::Invalid);
        }
        let inspector = self.opening.inspector().map_err(InitialError::Open)?;
        let sealed = required(&self.store, ACKNOWLEDGED_KEYS)?;
        let inspection = inspector.inspect(sealed).map_err(InitialError::Keys)?;
        if inspection.revision() != 2
            || inspection.lineage()
                != self
                    .receipt()
                    .attested_lineage()
                    .map_err(InitialError::Keys)?
                    .0
        {
            return Err(InitialError::Invalid);
        }
        let provenance = evidence
            .initial_acknowledgment(&inspector, sealed)
            .map_err(InitialError::Open)?;
        if provenance.seed() != self.enrollment_commitment()?
            || provenance.publication() != self.publication_commitment()?
        {
            return Err(InitialError::Invalid);
        }
        Ok(AcknowledgedInitialCandidate {
            inspector,
            sealed: Zeroizing::new(sealed.to_vec()),
            evidence,
            seed: self.enrollment_commitment()?,
            publication: self.publication_commitment()?,
        })
    }
}

impl AcknowledgedInitialCandidate {
    pub(crate) fn from_checkpoint(
        inspector: ckmg::CheckpointInspector,
        sealed: &[u8],
        evidence: crate::LineageEvidence,
        initial: &ckmg::InitialCheckpointProvenance,
    ) -> Self {
        Self {
            inspector,
            sealed: Zeroizing::new(sealed.to_vec()),
            evidence,
            seed: initial.seed(),
            publication: initial.publication(),
        }
    }

    /// Immutable original encrypted enrollment commitment; not authority.
    pub fn enrollment_commitment(&self) -> [u8; 32] {
        self.seed
    }
    /// Immutable server-bound original output commitment; not authority.
    pub fn publication_commitment(&self) -> [u8; 32] {
        self.publication
    }
    /// Exact public original evidence, still requiring fresh owner verification.
    pub fn evidence(&self) -> &crate::LineageEvidence {
        &self.evidence
    }
    /// Verify the unchanged original assertion using the genuine current same
    /// key certificate at NOW. The original verifier checks credential ID, SPKI,
    /// RP, origin, UV, revocation and certificate/Charter lifetimes. This result
    /// cannot claim that the old certificate was valid at any historical time.
    pub fn reauthorize<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        current_certificate: &'a [u8],
        expected_member: &str,
        now: u64,
    ) -> Result<CurrentInitialLineage<'a>, crate::LineageError> {
        self.evidence
            .reauthorize_initial(current, current_certificate, expected_member, now)
            .map(CurrentInitialLineage)
    }
    /// Original provisional read admission; no root, signer or Store cipher is
    /// returned, and a caller-supplied timestamp cannot authorize the read.
    pub async fn read_lineage(
        &self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<ckmg::ProvisionalLineage<'_>, InitialError> {
        let evidence = self
            .evidence
            .to_bytes()
            .map_err(|_| InitialError::Invalid)?;
        self.inspector
            .read_lineage(&self.sealed, &evidence, clock, authority)
            .await
            .map_err(InitialError::Keys)
    }
}
impl std::fmt::Debug for AcknowledgedInitialCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AcknowledgedInitialCandidate([redacted])")
    }
}
impl std::fmt::Debug for CurrentInitialLineage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CurrentInitialLineage([redacted])")
    }
}
