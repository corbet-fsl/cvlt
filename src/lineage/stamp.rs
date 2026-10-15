//! Genesis lineage evidence by confirmation stamp (one-confirmation model).
//!
//! The offline verifier lives in Charter (`cchr::genesis_stamp`), so that the server verifies the
//! same evidence without device crates; Vault re-exports it and maps its refusals to
//! [`LineageError`] with the same meaning.
use super::LineageError;
use cchr::{GenesisError, StampTrust, VerifiedCharter, VerifiedGenesis};
use ckmg::Receipt;
use cpsd::StampPresentation;

pub use cchr::genesis_stamp::{
    GenesisStampEvidence, LINEAGE_GENESIS_ACTION, StampKeyPeriod, genesis_stamp_scope,
    lineage_genesis_action, lineage_genesis_action_for, lineage_stamp_scope,
};

impl From<GenesisError> for LineageError {
    fn from(error: GenesisError) -> Self {
        match error {
            GenesisError::Receipt => Self::Receipt,
            GenesisError::Scope => Self::Scope,
            GenesisError::Clock => Self::Clock,
            GenesisError::Stamp | GenesisError::Invalid | GenesisError::Limit => Self::Stamp,
            GenesisError::Policy(policy) => Self::Policy(policy),
        }
    }
}

/// Verify `presentation` as the genesis evidence of `receipt` for `expected_member`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_genesis<'a>(
    current: &VerifiedCharter,
    trust: &StampTrust,
    receipt: &'a Receipt,
    presentation: &StampPresentation,
    salt: [u8; 32],
    at: u64,
    expected_member: &str,
    now: u64,
) -> Result<VerifiedGenesis<'a>, LineageError> {
    Ok(cchr::verify_genesis(
        current,
        trust,
        receipt,
        presentation,
        salt,
        at,
        expected_member,
        now,
    )?)
}
