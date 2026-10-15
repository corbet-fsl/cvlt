//! Genesis lineage evidence by confirmation stamp (one-confirmation model).
//!
//! A member's FIRST community lineage (the Keys `Created` receipt, epoch 1, revision 1) counts
//! when one wallet confirmation stamp covers its exact digest under the member's pseudonym. Peers
//! verify offline: the stamp key comes from the wallet's signed key ring (retired keys stay with
//! their validity periods), the expiry cohort from the rulebook, the scope is the community
//! fingerprint, the action is `lineage_genesis` and its payload binds the receipt and the time
//! `at` at which the device made it. Validity is judged at `at`, never at the verifier's clock:
//! a stamp expires within two cohorts, the lineage it anchored does not.
//!
//! The stamp proves possession of the passport secret behind the member's pseudonym; it is not
//! globally current lineage. Later lineage changes are not accepted by this module.
use super::LineageError;
use cchr::VerifiedCharter;
use ckmg::{Change, Lineage, PublicKey, Receipt};
use cpsd::{
    ActionKind, CommunityFingerprint, CommunityId, PayloadDigest, StampAction, StampParams,
    StampPresentation, StampPublicKey, StampSalt, StampScope, verify_stamp,
};
use sha2::{Digest as _, Sha256};

/// Stamp action kind of a member's first community lineage.
pub const LINEAGE_GENESIS_ACTION: &str = "lineage_genesis";

/// Domain of the fingerprint of a community that has no founding document. It must equal the
/// community server's (`cvld::device_session::UNFOUNDED_FINGERPRINT_TAG`).
pub const UNFOUNDED_FINGERPRINT_TAG: &[u8] = b"cvld.stamp.unfounded-community.v1\0";

const PAYLOAD_CONTEXT: &str = "cvlt 2026-10-15 lineage genesis stamp v1";

/// One key of the wallet's signed stamp key ring with its validity period (`valid_from`
/// inclusive, `valid_until` exclusive; `None` while current). Retired keys stay in the ring so
/// that evidence made before a rotation still verifies.
#[derive(Clone)]
pub struct StampKeyPeriod {
    key: StampPublicKey,
    valid_from: u64,
    valid_until: Option<u64>,
}
impl StampKeyPeriod {
    /// A key period; an empty or inverted period is refused.
    pub fn new(
        key: StampPublicKey,
        valid_from: u64,
        valid_until: Option<u64>,
    ) -> Result<Self, LineageError> {
        if valid_until.is_some_and(|until| until <= valid_from) {
            return Err(LineageError::Stamp);
        }
        Ok(Self {
            key,
            valid_from,
            valid_until,
        })
    }
    fn covers(&self, at: u64) -> bool {
        self.valid_from <= at && self.valid_until.is_none_or(|until| at < until)
    }
}
impl std::fmt::Debug for StampKeyPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StampKeyPeriod")
            .field("key_id", self.key.key_id())
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// The stamp trust a peer verifies genesis evidence with: the wallet's stamp key ring from the
/// SIGNED global status (the caller authenticates it, as for cpsd's `verify_stamp`) and the
/// rulebook's stamp cohort. Key ids are unique.
#[derive(Clone, Debug)]
pub struct StampTrust {
    keys: Vec<StampKeyPeriod>,
    params: StampParams,
}
impl StampTrust {
    /// Refuses an empty ring and duplicate key ids.
    pub fn new(keys: Vec<StampKeyPeriod>, params: StampParams) -> Result<Self, LineageError> {
        if keys.is_empty() {
            return Err(LineageError::Stamp);
        }
        for (i, key) in keys.iter().enumerate() {
            if keys[..i]
                .iter()
                .any(|other| other.key.key_id() == key.key.key_id())
            {
                return Err(LineageError::Stamp);
            }
        }
        Ok(Self { keys, params })
    }
}

/// The stamp scope of the community `current` verifies: its id and its founding fingerprint
/// (csgn's genesis fingerprint, the identity the vault pins), or for a charter without one the
/// tagged id. The device building a stamp request and every verifier use this one derivation.
pub fn lineage_stamp_scope(current: &VerifiedCharter) -> Result<StampScope, LineageError> {
    let id = CommunityId::new(current.community()).map_err(|_| LineageError::Scope)?;
    let fingerprint = match current.fingerprint() {
        Some(fingerprint) => *fingerprint,
        None => {
            let mut hasher = Sha256::new();
            hasher.update(UNFOUNDED_FINGERPRINT_TAG);
            hasher.update(current.community().as_bytes());
            hasher.finalize().into()
        }
    };
    Ok(StampScope::new(
        id,
        CommunityFingerprint::from_bytes(fingerprint),
    ))
}

/// The `lineage_genesis` action for `receipt` made at `at` with the device's secret `salt`:
/// payload = BLAKE3 derive_key(context, receipt challenge || le64(at)). The receipt challenge
/// binds the receipt's operation and complete change (lineage, binding, root and device).
pub fn lineage_genesis_action(
    receipt: &Receipt,
    salt: [u8; 32],
    at: u64,
) -> Result<StampAction, LineageError> {
    let challenge = receipt
        .passkey_challenge()
        .map_err(|_| LineageError::Receipt)?;
    let mut hasher = blake3::Hasher::new_derive_key(PAYLOAD_CONTEXT);
    hasher.update(&challenge);
    hasher.update(&at.to_le_bytes());
    Ok(StampAction::new(
        ActionKind::new(LINEAGE_GENESIS_ACTION).map_err(|_| LineageError::Stamp)?,
        PayloadDigest::from_bytes(*hasher.finalize().as_bytes()),
        StampSalt::from_bytes(salt),
    ))
}

/// What a verified genesis stamp established, for the observation.
pub(crate) struct VerifiedGenesis<'a> {
    pub(crate) lineage: &'a Lineage,
    pub(crate) author: PublicKey,
    pub(crate) digest: [u8; 32],
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
    let (lineage, author) = receipt
        .attested_lineage()
        .map_err(|_| LineageError::Receipt)?;
    if !matches!(receipt.change, Change::Created(_)) || lineage.epoch != 1 || lineage.revision != 1
    {
        return Err(LineageError::Receipt);
    }
    if lineage.binding.community() != current.community()
        || lineage.binding.member() != expected_member
    {
        return Err(LineageError::Scope);
    }
    // The device made the receipt no later than the verifier observes it.
    if now < at {
        return Err(LineageError::Clock);
    }
    current.settings(now).map_err(LineageError::Policy)?;
    if current.revocations().member_revoked(expected_member) {
        return Err(LineageError::Policy(cchr::Error::Unauthenticated));
    }
    // The key that signed the stamp must have been valid when the receipt was made.
    let key = trust
        .keys
        .iter()
        .find(|period| period.key.key_id() == presentation.key_id())
        .filter(|period| period.covers(at))
        .ok_or(LineageError::Stamp)?;
    let scope = lineage_stamp_scope(current)?;
    let action = lineage_genesis_action(receipt, salt, at)?;
    // Judged at `at`: the cohort must cover the receipt time. The revealed epoch is the one the
    // key signed; the live epoch check belongs to the community at acceptance.
    let verified = verify_stamp(
        std::slice::from_ref(&key.key),
        &trust.params,
        &scope,
        presentation.epoch(),
        &action,
        presentation,
        at,
    )
    .map_err(|_| LineageError::Stamp)?;
    if verified.pseudonym().to_hex() != expected_member {
        return Err(LineageError::Scope);
    }
    Ok(VerifiedGenesis {
        lineage,
        author,
        digest: verified.digest().to_bytes(),
    })
}
