//! Original passkey evidence joined to a borrowed current Charter, not G3 selection.
use cchr::{VerifiedCharter, VerifiedPasskeyBinding};
use ckmg::{Lineage, PublicKey, Receipt};
use ckyh::lineage::Assertion;

/// Fixed evidence refusal, with no supplied identities, ciphertext or assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineageError {
    /// Original receipt, device attestation or root lineage verification failed.
    Receipt,
    /// The requested member/community differs from the original signed lineage.
    Scope,
    /// Current Charter refused the signed descriptor or its revocation/freshness.
    Policy(cchr::Error),
    /// Original Keyhole verification refused the exact passkey assertion.
    Assertion,
    /// Time precedes the original verification observation.
    Clock,
}
impl std::fmt::Display for LineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lineage evidence: {self:?}")
    }
}
impl std::error::Error for LineageError {}

/// One original receipt whose exact change was signed by a passkey accepted by
/// this borrowed Charter's Policy binding and revocation publication. No caller
/// can construct, clone or deserialize this witness.
///
/// This is not globally current lineage, membership admission, Records freshness,
/// a signing intent or permission to adopt a checkpoint. The composer must obtain
/// current Charter again after any await and verify retained evidence against it.
/// It must separately apply the original lineage succession/conflict rules.
pub struct VerifiedLineageObservation<'a> {
    charter: &'a VerifiedCharter,
    binding: VerifiedPasskeyBinding<'a>,
    lineage: &'a Lineage,
    author: PublicKey,
    checked_at: u64,
}
impl VerifiedLineageObservation<'_> {
    fn live(&self, now: u64) -> Result<(), LineageError> {
        if now < self.checked_at {
            return Err(LineageError::Clock);
        }
        self.charter.settings(now).map_err(LineageError::Policy)?;
        self.binding.credential(now).map_err(LineageError::Policy)?;
        Ok(())
    }

    /// Exact original authenticated public lineage, within this witness's deadline.
    /// Its self-signature alone never grants globally current authority.
    pub fn lineage(&self, now: u64) -> Result<&Lineage, LineageError> {
        self.live(now)?;
        Ok(self.lineage)
    }
    /// Original device that attested the complete receipt, not a passkey ID.
    pub fn author(&self, now: u64) -> Result<PublicKey, LineageError> {
        self.live(now)?;
        Ok(self.author)
    }
    /// Exclusive bound from the original binding and complete Charter lifetimes.
    pub fn valid_until(&self) -> u64 {
        self.binding.valid_until()
    }
    /// Original Charter revision consulted by this observation, not a lineage epoch.
    pub fn charter_revision(&self) -> u64 {
        self.charter.revision()
    }
}
impl std::fmt::Debug for VerifiedLineageObservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedLineageObservation([redacted])")
    }
}

/// Verify existing owner evidence without adding a crypto transcript or wire format.
/// `current` must be borrowed from the actual current Charter/Envoy owner at this
/// point of use. A caller-supplied key ring, descriptor or currentness flag cannot
/// substitute for that private-field owner capability.
///
/// Neither a login assertion over another challenge nor a delegated device
/// signature alone satisfies the passkey proof. All original revocation, scope,
/// clock, UV, RP, origin and credential checks remain in their respective owners.
pub fn verify_lineage<'a>(
    current: &'a VerifiedCharter,
    receipt: &'a Receipt,
    assertion: &Assertion,
    signed_binding: &'a [u8],
    expected_member: &str,
    now: u64,
) -> Result<VerifiedLineageObservation<'a>, LineageError> {
    let (lineage, author) = receipt
        .attested_lineage()
        .map_err(|_| LineageError::Receipt)?;
    if lineage.binding.community() != current.community()
        || lineage.binding.member() != expected_member
    {
        return Err(LineageError::Scope);
    }
    let binding = current
        .passkey_binding(signed_binding, expected_member, now)
        .map_err(LineageError::Policy)?;
    let challenge = receipt
        .passkey_challenge()
        .map_err(|_| LineageError::Receipt)?;
    ckyh::lineage::verify(
        binding.credential(now).map_err(LineageError::Policy)?,
        assertion,
        challenge,
    )
    .map_err(|_| LineageError::Assertion)?;
    Ok(VerifiedLineageObservation {
        charter: current,
        binding,
        lineage,
        author,
        checked_at: now,
    })
}
