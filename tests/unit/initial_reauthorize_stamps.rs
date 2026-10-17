//! The device-key member's current verification of its acknowledged genesis evidence by
//! stamp (`reauthorize_with_stamps`): a real Keys `Created` receipt, a real blind stamp from
//! the opaque holder and a real wallet stamp key, against a signed Charter at NOW.
use super::*;
use ckmg::{Action, Authority, Authorization, Binding, DeviceInfo, Error, PublicKey};
use cpsd::{
    CommunityId, IssuanceChallenge, KeyId, OpaqueHolder, StampIssuerKey, StampParams,
    rand::rngs::OsRng,
};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{Value, json};
use std::{cell::Cell, rc::Rc};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const ORIGIN: &str = "https://members.example.com";
const SALT: [u8; 32] = [5; 32];

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(NOW)
    }
}

// Capture the derived device on a first refused attempt, then allow exactly that one Create.
struct FixtureCreate {
    binding: Binding,
    device: Option<PublicKey>,
    captured: Rc<Cell<Option<PublicKey>>>,
}
impl Authority for FixtureCreate {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.action != Action::Create || request.binding != &self.binding {
            return Err(Error::Unauthorized);
        }
        match self.device {
            None => {
                self.captured.set(Some(request.device));
                Err(Error::Unauthorized)
            }
            Some(expected) if expected == request.device => Ok(()),
            Some(_) => Err(Error::Unauthorized),
        }
    }
}

#[derive(Clone)]
struct FixtureStore<B: cwst::backend::Backend>(crate::KeyStore<B>);
impl<B: cwst::backend::Backend> ckmg::SecureStore for FixtureStore<B> {
    async fn load(&mut self, location: &ckmg::Locator) -> Result<Option<Vec<u8>>, Error> {
        ckmg::SecureStore::load(&mut self.0, location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<ckmg::Commit, Error> {
        ckmg::SecureStore::compare_exchange(&mut self.0, location, expected, replacement).await
    }
}

/// The member's first lineage in `scope`: a real Keys `Created` receipt for `member`.
fn first_lineage(prf: &ckmg::passkey::PrfOutput, scope: &str, member: &str) -> ckmg::Receipt {
    let binding = Binding::new(scope, member).unwrap();
    futures_executor::block_on(async {
        let cipher = ckmg::passkey::store_cipher(prf, scope).unwrap();
        let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, scope)
            .await
            .unwrap();
        let shared = crate::shared_store(store);
        let mut key_store = crate::KeyStore::new(shared, scope).unwrap();
        let captured = Rc::new(Cell::new(None));
        let device = DeviceInfo::new("fixture", &[9; 16]).unwrap();
        let mut probe = ckmg::Keys::new(
            FixtureStore(key_store.clone()),
            Clock,
            ckmg::SystemEntropy,
            FixtureCreate {
                binding: binding.clone(),
                device: None,
                captured: captured.clone(),
            },
        );
        assert!(
            probe
                .create_scope(prf, binding.clone(), device.clone(), b"fixture")
                .await
                .is_err()
        );
        drop(probe);
        let mut keys = ckmg::Keys::new(
            FixtureStore(key_store.clone()),
            Clock,
            ckmg::SystemEntropy,
            FixtureCreate {
                binding: binding.clone(),
                device: Some(captured.get().unwrap()),
                captured,
            },
        );
        let guard = key_store
            .stage(crate::Batch {
                expected: 0,
                operation: [61; 32],
                mutations: vec![],
                outputs: vec![],
            })
            .unwrap();
        let receipt = keys
            .create_scope(prf, binding, device, b"fixture")
            .await
            .unwrap();
        drop(guard);
        receipt
    })
}

fn sign(signer: &mut Signer, kind: Kind, payload: Value, at: u64) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(&payload).unwrap(), at, at + 500)
        .unwrap()
}

/// A complete signed Charter of `scope`, current at `at` (no founding document).
fn charter(scope: &str, at: u64, revoked_members: &[&str]) -> cchr::Charter {
    let mut signer =
        Signer::new(scope, SecretKey::from_seed(&mut [71; 32]), NOW - 1, 1000).unwrap();
    let schema = json!({"community":scope,"version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":scope,"revision":1,
        "policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),"schema_version":1});
    let mut feed = json!({"revision":1,"policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),
        "manifest":sign(&mut signer,Kind::SettingsSnapshot,manifest,at)});
    for (name, kind, content) in [
        ("settings", Kind::SettingsSnapshot, json!({})),
        ("schema", Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!([scope])),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            json!({"members":revoked_members,"devices":[],"passkeys":[]}),
        ),
    ] {
        feed[name] = json!(sign(
            &mut signer,
            kind,
            json!({"community":scope,"revision":1,"policy_epoch":1,"content":content}),
            at
        ));
    }
    let mut owner = cchr::Charter::new(cchr::Configuration {
        origin: ORIGIN.into(),
        community: scope.into(),
        key_ring: signer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    owner
        .install(&serde_json::to_vec(&feed).unwrap(), at)
        .unwrap();
    owner
}

fn params() -> StampParams {
    StampParams::new(DAY).unwrap()
}

fn trust(key: &StampIssuerKey) -> crate::StampTrust {
    crate::StampTrust::new(
        vec![crate::StampKeyPeriod::new(key.public_key().clone(), NOW - DAY, None).unwrap()],
        params(),
    )
    .unwrap()
}

/// Genesis evidence by one stamp over the receipt's `lineage_genesis` action at NOW, in the
/// published encoding (as a peer and the acknowledged checkpoint carry it).
fn stamped(
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    receipt: &ckmg::Receipt,
    current: &cchr::VerifiedCharter,
) -> crate::LineageEvidence {
    let scope = crate::lineage_stamp_scope(current).unwrap();
    let action = crate::lineage_genesis_action(receipt, SALT, NOW).unwrap();
    let nonce = IssuanceChallenge::generate(&mut OsRng);
    holder.cancel_stamp();
    let request = holder
        .begin_stamp(
            &mut OsRng,
            key.public_key(),
            &nonce,
            &[(scope.clone(), action.clone())],
            NOW,
        )
        .unwrap();
    let blind = key
        .issue_blind(&mut OsRng, &request, &nonce, 3, NOW)
        .unwrap();
    holder.finish_stamp(&blind, NOW).unwrap();
    let shown = holder
        .present_stamp(&mut OsRng, &scope, &action, NOW)
        .unwrap();
    crate::LineageEvidence::from_bytes(
        &serde_json::to_vec(&json!({
            "purpose": "cvlt.lineage-evidence.stamp.v1",
            "receipt": receipt,
            "presentation": shown.to_bytes(),
            "salt": SALT,
            "at": NOW,
        }))
        .unwrap(),
    )
    .unwrap()
}

fn candidate(
    prf: &ckmg::passkey::PrfOutput,
    evidence: crate::LineageEvidence,
) -> AcknowledgedInitialCandidate {
    AcknowledgedInitialCandidate {
        inspector: ckmg::CheckpointInspector::new(prf, "alpha").unwrap(),
        sealed: Zeroizing::new(Vec::new()),
        evidence,
        seed: [1; 32],
        publication: [2; 32],
    }
}

#[test]
fn stamp_genesis_reauthorizes_at_now_with_the_device_key_as_author_and_no_credential() {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
    let mut holder = OpaqueHolder::from_seed(&mut [40; 32]);
    let member = holder
        .pseudonym(&CommunityId::new("alpha").unwrap())
        .to_hex();
    let receipt = first_lineage(&prf, "alpha", &member);
    let (lineage, author) = receipt.attested_lineage().unwrap();
    let key =
        StampIssuerKey::generate(&mut OsRng, KeyId::new("stamp-1").unwrap(), &params()).unwrap();
    let stamps = trust(&key);
    let mut now_charter = charter("alpha", NOW, &[]);
    let current = now_charter.current(NOW).unwrap();
    let acknowledged = candidate(&prf, stamped(&mut holder, &key, &receipt, current));

    let fresh = acknowledged
        .reauthorize_with_stamps(current, &stamps, &member, NOW)
        .unwrap();
    assert_eq!(fresh.lineage(NOW).unwrap(), lineage);
    assert_eq!(fresh.author(NOW).unwrap(), author);
    // No passkey stands behind it: the caller compares the author with the device key.
    assert_eq!(
        fresh.credential_id(NOW).unwrap_err(),
        crate::LineageError::Scope
    );
    // A stamp observation lives as long as the current Charter.
    assert_eq!(fresh.valid_until(), NOW + 500);
    // The passkey twin never accepts stamp evidence, not even with an empty certificate.
    assert_eq!(
        acknowledged
            .reauthorize(current, &[], &member, NOW)
            .unwrap_err(),
        crate::LineageError::Scope
    );

    // Three days later the one-day stamp has long expired; the genesis still counts, at NOW.
    let later = NOW + 3 * DAY;
    let mut later_charter = charter("alpha", later, &[]);
    let later_current = later_charter.current(later).unwrap();
    assert_eq!(
        acknowledged
            .reauthorize_with_stamps(later_current, &stamps, &member, later)
            .unwrap()
            .lineage(later)
            .unwrap(),
        lineage
    );
    // A later member revocation is applied at every reauthorization.
    let mut revoked = charter("alpha", later, &[&member]);
    assert_eq!(
        acknowledged
            .reauthorize_with_stamps(revoked.current(later).unwrap(), &stamps, &member, later)
            .unwrap_err(),
        crate::LineageError::Policy(cchr::Error::Unauthenticated)
    );
    // Another member, or a stamp key the wallet does not trust, never verifies.
    assert!(
        acknowledged
            .reauthorize_with_stamps(current, &stamps, &"0".repeat(64), NOW)
            .is_err()
    );
    let other =
        StampIssuerKey::generate(&mut OsRng, KeyId::new("stamp-2").unwrap(), &params()).unwrap();
    assert_eq!(
        acknowledged
            .reauthorize_with_stamps(current, &trust(&other), &member, NOW)
            .unwrap_err(),
        crate::LineageError::Stamp
    );
}
