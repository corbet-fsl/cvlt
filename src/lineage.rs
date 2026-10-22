//! Original passkey evidence joined to a borrowed current Charter, not G3 selection.
use cchr::{VerifiedCharter, VerifiedPasskeyCertificate};
use ckmg::{Lineage, PublicKey, Receipt};
use ckyh::lineage::Assertion;

mod records;
mod revision;
mod stamp;
pub use cchr::{GenesisError, StampTrust};
pub use records::{LineageRead, LineageRecords};
pub use revision::publish_lineage_revision;
pub(crate) use stamp::verify_genesis;
pub use stamp::{
    GenesisStampEvidence, LINEAGE_GENESIS_ACTION, StampKeyPeriod, genesis_stamp_scope,
    lineage_genesis_action, lineage_genesis_action_for, lineage_stamp_scope,
};

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
    /// The genesis confirmation stamp, its key period or its expiry cohort refused the
    /// evidence at the receipt's signed time.
    Stamp,
}
impl std::fmt::Display for LineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lineage evidence: {self:?}")
    }
}
impl std::error::Error for LineageError {}

/// One original receipt whose exact change was signed by a passkey accepted by
/// this borrowed Charter's registration certificate and revocation publication. No caller
/// can construct, clone or deserialize this witness.
///
/// This is not globally current lineage, membership admission, Records freshness,
/// a signing intent or permission to adopt a checkpoint. The composer must obtain
/// current Charter again after any await and verify retained evidence against it.
/// It must separately apply the original lineage succession/conflict rules.
pub struct VerifiedLineageObservation<'a> {
    charter: &'a VerifiedCharter,
    authority: Authority<'a>,
    lineage: &'a Lineage,
    author: PublicKey,
    checked_at: u64,
}
/// What authorized the receipt: a passkey assertion under the Charter's certificate, or (for a
/// member's first lineage only) a wallet confirmation stamp under the member's pseudonym.
enum Authority<'a> {
    Passkey(VerifiedPasskeyCertificate<'a>),
    Stamp {
        digest: [u8; 32],
    },
    /// Wallet lineage only: the wallet-signed birth statement (one-ceremony registration),
    /// naming the passkey credential whose creation ceremony authorized the genesis.
    Birth {
        credential: Vec<u8>,
    },
}
impl<'a> VerifiedLineageObservation<'a> {
    pub(crate) fn stamped(
        charter: &'a VerifiedCharter,
        genesis: cchr::VerifiedGenesis<'a>,
        now: u64,
    ) -> Self {
        Self {
            charter,
            authority: Authority::Stamp {
                digest: genesis.stamp().digest().to_bytes(),
            },
            lineage: genesis.lineage(),
            author: *genesis.author(),
            checked_at: now,
        }
    }
}
impl<'a> VerifiedLineageObservation<'a> {
    // Birth genesis evidence (wallet scope only), verified offline by Charter under the
    // wallet key ring of `charter` at the statement time.
    pub(crate) fn born(
        charter: &'a VerifiedCharter,
        birth: &cchr::VerifiedBirth<'a>,
        now: u64,
    ) -> Self {
        Self {
            charter,
            authority: Authority::Birth {
                credential: birth.statement().credential().to_vec(),
            },
            lineage: birth.lineage(),
            author: *birth.device(),
            checked_at: now,
        }
    }
}
impl VerifiedLineageObservation<'_> {
    fn live(&self, now: u64) -> Result<(), LineageError> {
        if now < self.checked_at {
            return Err(LineageError::Clock);
        }
        self.charter.settings(now).map_err(LineageError::Policy)?;
        match &self.authority {
            Authority::Passkey(certificate) => {
                certificate.current(now).map_err(LineageError::Policy)?
            }
            Authority::Stamp { .. } => {
                if self
                    .charter
                    .revocations()
                    .member_revoked(self.lineage.binding.member())
                {
                    return Err(LineageError::Policy(cchr::Error::Unauthenticated));
                }
            }
            Authority::Birth { credential } => {
                let revocations = self.charter.revocations();
                if revocations.member_revoked(self.lineage.binding.member())
                    || revocations
                        .passkey_revoked(credential)
                        .map_err(LineageError::Policy)?
                {
                    return Err(LineageError::Policy(cchr::Error::Unauthenticated));
                }
            }
        }
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
    /// Exact original credential which verified this receipt assertion. This is
    /// public identity within the same current owner cut, never new authority.
    /// Genesis evidence by stamp has no passkey credential and refuses with `Scope`. Birth
    /// evidence returns the credential its wallet-signed statement names.
    pub fn credential_id(&self, now: u64) -> Result<&[u8], LineageError> {
        self.live(now)?;
        match &self.authority {
            Authority::Passkey(certificate) => {
                certificate.credential_id(now).map_err(LineageError::Policy)
            }
            Authority::Stamp { .. } => Err(LineageError::Scope),
            Authority::Birth { credential } => Ok(credential),
        }
    }
    /// The one-use digest of the genesis stamp (its action digest), the authority reference of
    /// stamp evidence. Passkey evidence refuses with `Scope`.
    pub fn stamp_digest(&self, now: u64) -> Result<[u8; 32], LineageError> {
        self.live(now)?;
        match &self.authority {
            Authority::Passkey(_) | Authority::Birth { .. } => Err(LineageError::Scope),
            Authority::Stamp { digest } => Ok(*digest),
        }
    }
    /// Exclusive bound from the original binding and complete Charter lifetimes. Stamp evidence
    /// and birth evidence are bounded by the Charter alone: their own validity was judged at the
    /// receipt (statement) time.
    pub fn valid_until(&self) -> u64 {
        match &self.authority {
            Authority::Passkey(certificate) => certificate.valid_until(),
            Authority::Stamp { .. } | Authority::Birth { .. } => self.charter.valid_until(),
        }
    }
    /// Original Charter revision consulted by this observation, not a lineage epoch.
    pub fn charter_revision(&self) -> u64 {
        self.charter.revision()
    }

    /// Deterministic ordering for concurrent valid lineage candidates: greater
    /// epoch wins, then smaller original Keys lineage digest. Greater means this
    /// candidate wins. Certificate renewal and transport formatting cannot affect
    /// that digest. The composer must first establish original succession; this
    /// comparison does not select a globally current lineage or authorize adoption.
    pub fn compare_conflict(
        &self,
        other: &Self,
        now: u64,
    ) -> Result<std::cmp::Ordering, LineageError> {
        self.live(now)?;
        other.live(now)?;
        if !std::ptr::eq(self.charter, other.charter)
            || self.lineage.binding != other.lineage.binding
        {
            return Err(LineageError::Scope);
        }
        let mine = self.lineage.digest().map_err(|_| LineageError::Receipt)?;
        let theirs = other.lineage.digest().map_err(|_| LineageError::Receipt)?;
        Ok(self
            .lineage
            .epoch
            .cmp(&other.lineage.epoch)
            .then_with(|| theirs.cmp(&mine)))
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
    signed_certificate: &'a [u8],
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
    let certificate = current
        .passkey_certificate(signed_certificate, expected_member, now)
        .map_err(LineageError::Policy)?;
    let challenge = receipt
        .passkey_challenge()
        .map_err(|_| LineageError::Receipt)?;
    certificate
        .assertion(assertion, challenge, now)
        .map_err(|_| LineageError::Assertion)?;
    Ok(VerifiedLineageObservation {
        charter: current,
        authority: Authority::Passkey(certificate),
        lineage,
        author,
        checked_at: now,
    })
}
