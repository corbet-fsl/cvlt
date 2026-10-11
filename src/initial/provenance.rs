//! Immutable original enrollment identity from this authenticated outer Store.
use super::*;

impl<B: Backend> InitialCreation<B> {
    /// Recompute the accepted original seed from the actual retained encrypted
    /// candidate and require its exact original receipt/slot to match. Legacy
    /// creation without this provenance refuses; a certificate cannot supply it.
    pub fn enrollment_commitment(&self) -> Result<[u8; 32], InitialError> {
        self.phase()?;
        let candidate = ckmg::UnenrolledCreation::reopen(
            &self.opening.prf,
            &self.opening.scope,
            required(&self.store, ENROLLMENT)?,
        )
        .map_err(InitialError::Keys)?;
        if !candidate.matches_pending(&self.pending) {
            return Err(InitialError::Invalid);
        }
        candidate.commitment().map_err(InitialError::Keys)
    }

    /// Original authenticated Prepared checkpoint identity for the trusted
    /// composer to compare at each dedicated completion check. These public
    /// coordinates grant no authority and cannot refresh the immutable intent.
    pub fn completion_binding(
        &self,
    ) -> Result<(ckmg::CompletionIntent, ckmg::Locator, [u8; 32]), InitialError> {
        if self.phase()? != InitialPhase::Prepared {
            return Err(InitialError::Invalid);
        }
        let intent = decode_intent(required(&self.store, INTENT)?)?;
        Ok((
            ckmg::CompletionIntent {
                outer_generation: self.store.version().map_err(InitialError::Storage)?,
                outer_digest: *blake3::hash(
                    self.store
                        .sealed_checkpoint()
                        .map_err(InitialError::Storage)?,
                )
                .as_bytes(),
                inner_version: 1,
                inner_operation: initial_operation(&self.store)?,
                inner_digest: *blake3::hash(required(&self.store, INNER)?).as_bytes(),
                nonce: intent.nonce,
                packed_evidence: intent.packed_evidence,
                prepared_at: intent.prepared_at,
                expires: intent.expires,
            },
            *self.pending.location(),
            *self.pending.sealed_digest(),
        ))
    }

    /// Exact immutable output identity, recomputed by Keys from this original
    /// receipt and the actual durable Prepared intent. It grants no signing or
    /// recovery authority and cannot renew an unfinished expired intent.
    pub fn publication_commitment(&self) -> Result<[u8; 32], InitialError> {
        self.phase()?;
        let intent = decode_intent(required(&self.store, INTENT)?)?;
        self.receipt()
            .initial_publication_commitment(
                &intent.nonce,
                &intent.packed_evidence,
                intent.prepared_at,
                intent.expires,
            )
            .map_err(InitialError::Keys)
    }
}
