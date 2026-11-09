//! Genesis lineage evidence by confirmation stamp: a real Keys `Created` receipt, a real blind
//! stamp from the opaque holder and a real wallet stamp key, verified offline against a signed
//! Charter. Validity is judged at the receipt's signed time `at`, never at the verifier's clock.
#![cfg(not(target_arch = "wasm32"))]
use ckmg::{Action, Authority, Authorization, Binding, DeviceInfo, Error, PublicKey};
use cpsd::{
    ActionKind, CommunityId, IssuanceChallenge, KeyId, OpaqueHolder, StampAction, StampIssuerKey,
    StampParams, StampPresentation, StampScope,
};
use csgn::{Kind, SecretKey, Signer};
use cvlt::{
    EvidenceError, GenesisError, LineageError, LineageEvidence, StampKeyPeriod, StampTrust,
    lineage_genesis_action, lineage_stamp_scope,
};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use std::{cell::Cell, rc::Rc};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const EPOCH: u64 = 3;
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

// The ordinary-CAS (PRF-wrapped legacy) adapter, as in tests/lineage.rs, so that the store
// reopens under the same PRF cipher for the retention test.
#[derive(Clone)]
struct LegacyFixtureStore<B: cwst::backend::Backend>(cvlt::KeyStore<B>);
impl<B: cwst::backend::Backend> ckmg::SecureStore for LegacyFixtureStore<B> {
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

struct Receipt {
    receipt: ckmg::Receipt,
    prf: ckmg::passkey::PrfOutput,
    backend: cwst::native::FileBackend,
    _directory: tempfile::TempDir,
}

/// The member's first lineage in `scope`: a Keys `Created` receipt for `member`.
fn first_lineage(scope: &str, member: &str, seed: u8) -> Receipt {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[seed; 32]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let backend = cwst::native::FileBackend::new(directory.path());
    let binding = Binding::new(scope, member).unwrap();
    let receipt = futures_executor::block_on(async {
        let cipher = ckmg::passkey::store_cipher(&prf, scope).unwrap();
        let store = cwst::Store::create(backend.clone(), &cipher, scope)
            .await
            .unwrap();
        let shared = cvlt::shared_store(store);
        let mut key_store = cvlt::KeyStore::new(shared.clone(), scope).unwrap();
        let captured = Rc::new(Cell::new(None));
        let device = DeviceInfo::new("fixture", &[seed; 16]).unwrap();
        let mut probe = ckmg::Keys::new(
            LegacyFixtureStore(key_store.clone()),
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
                .create_scope(&prf, binding.clone(), device.clone(), b"fixture")
                .await
                .is_err()
        );
        drop(probe);
        let mut keys = ckmg::Keys::new(
            LegacyFixtureStore(key_store.clone()),
            Clock,
            ckmg::SystemEntropy,
            FixtureCreate {
                binding: binding.clone(),
                device: Some(captured.get().unwrap()),
                captured,
            },
        );
        let guard = key_store
            .stage(cvlt::Batch {
                expected: 0,
                operation: [61; 32],
                mutations: vec![],
                outputs: vec![],
            })
            .unwrap();
        let receipt = keys
            .create_scope(&prf, binding, device, b"fixture")
            .await
            .unwrap();
        drop(guard);
        receipt
    });
    Receipt {
        receipt,
        prf,
        backend,
        _directory: directory,
    }
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

fn key(name: &str) -> StampIssuerKey {
    StampIssuerKey::generate(&mut OsRng, KeyId::new(name).unwrap(), &params()).unwrap()
}

fn nym(holder: &OpaqueHolder, scope: &str) -> String {
    holder.pseudonym(&CommunityId::new(scope).unwrap()).to_hex()
}

/// One confirmation: the holder requests a stamp over `approvals` at `now` and presents the
/// first approval's slot.
fn stamp(
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    approvals: &[(StampScope, StampAction)],
    now: u64,
) -> StampPresentation {
    let nonce = IssuanceChallenge::generate(&mut OsRng);
    holder.cancel_stamp();
    let request = holder
        .begin_stamp(&mut OsRng, key.public_key(), &nonce, approvals, now)
        .unwrap();
    let blind = key
        .issue_blind(&mut OsRng, &request, &nonce, EPOCH, now)
        .unwrap();
    holder.finish_stamp(&blind, EPOCH, now).unwrap();
    let (scope, action) = &approvals[0];
    holder
        .present_stamp(&mut OsRng, scope, action, now)
        .unwrap()
}

fn trust(keys: &[(&StampIssuerKey, u64, Option<u64>)]) -> StampTrust {
    StampTrust::new(
        keys.iter()
            .map(|(key, from, until)| {
                StampKeyPeriod::new(key.public_key().clone(), *from, *until).unwrap()
            })
            .collect(),
        params(),
    )
    .unwrap()
}

struct Genesis {
    holder: OpaqueHolder,
    member: String,
    key: StampIssuerKey,
    first: Receipt,
}

fn genesis() -> Genesis {
    let holder = OpaqueHolder::from_seed(&mut [40; 32]);
    let member = nym(&holder, "alpha");
    Genesis {
        first: first_lineage("alpha", &member, 9),
        holder,
        member,
        key: key("stamp-1"),
    }
}

/// Genesis evidence for `receipt` from one stamp issued at `issued`, binding the time `at`.
fn evidence(
    g: &mut Genesis,
    receipt: &ckmg::Receipt,
    current: &cchr::VerifiedCharter,
    at: u64,
    issued: u64,
) -> LineageEvidence {
    let scope = lineage_stamp_scope(current).unwrap();
    let action = lineage_genesis_action(receipt, SALT, at).unwrap();
    let shown = stamp(&mut g.holder, &g.key, &[(scope, action)], issued);
    wire(receipt, &shown, SALT, at)
}

/// The published stamp evidence encoding, built without verification (as a peer receives it).
fn wire(
    receipt: &ckmg::Receipt,
    shown: &StampPresentation,
    salt: [u8; 32],
    at: u64,
) -> LineageEvidence {
    LineageEvidence::from_bytes(
        &serde_json::to_vec(&json!({
            "purpose": "cvlt.lineage-evidence.stamp.v1",
            "receipt": receipt,
            "presentation": shown.to_bytes(),
            "salt": salt,
            "at": at,
        }))
        .unwrap(),
    )
    .unwrap()
}

/// The presentation inside published stamp evidence.
fn presentation_of(evidence: &LineageEvidence) -> StampPresentation {
    let wire: Value = serde_json::from_slice(&evidence.to_bytes().unwrap()).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(wire["presentation"].clone()).unwrap();
    StampPresentation::from_bytes(&bytes).unwrap()
}

#[test]
fn genesis_stamp_verifies_at_the_receipt_time_also_after_the_stamp_expired() {
    let mut g = genesis();
    let mut now_charter = charter("alpha", NOW, &[]);
    let current = now_charter.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let evidence = evidence(&mut g, &receipt, current, NOW, NOW);
    let stamps = trust(&[(&g.key, NOW - DAY, None)]);
    let observed = evidence
        .verify_with_stamps(current, &stamps, &g.member, NOW)
        .unwrap();
    let (lineage, author) = receipt.attested_lineage().unwrap();
    assert_eq!(observed.lineage(NOW).unwrap(), lineage);
    assert_eq!(observed.author(NOW).unwrap(), author);
    assert_eq!(observed.valid_until(), NOW + 500);
    assert_eq!(
        observed.credential_id(NOW).unwrap_err(),
        LineageError::Scope
    );
    let digest = observed.stamp_digest(NOW).unwrap();
    assert_eq!(observed.lineage(NOW - 1).unwrap_err(), LineageError::Clock);
    // Without the stamp trust the evidence is unavailable, never accepted.
    assert_eq!(
        evidence.verify(current, &g.member, NOW).unwrap_err(),
        LineageError::Policy(cchr::Error::Unavailable)
    );
    assert!(evidence.is_stamp());

    // Three days later the stamp (one-day cohort) has long expired; the lineage still counts.
    let later = NOW + 3 * DAY;
    let mut later_charter = charter("alpha", later, &[]);
    let later_current = later_charter.current(later).unwrap();
    let observed = evidence
        .verify_with_stamps(later_current, &stamps, &g.member, later)
        .unwrap();
    assert_eq!(observed.lineage(later).unwrap(), lineage);
    assert_eq!(observed.stamp_digest(later).unwrap(), digest);

    // A later member revocation is applied live, at every use.
    let mut revoked = charter("alpha", later, &[&g.member]);
    assert_eq!(
        evidence
            .verify_with_stamps(revoked.current(later).unwrap(), &stamps, &g.member, later)
            .unwrap_err(),
        LineageError::Policy(cchr::Error::Unauthenticated)
    );

    // The published bytes and the packed record envelope round-trip exactly.
    let bytes = evidence.to_bytes().unwrap();
    assert_eq!(
        LineageEvidence::from_bytes(&bytes)
            .unwrap()
            .to_bytes()
            .unwrap(),
        bytes
    );
    let prepared = LineageEvidence::prepare_stamp(
        current,
        &stamps,
        &receipt,
        &presentation_of(&evidence),
        SALT,
        NOW,
        &g.member,
        NOW,
    )
    .unwrap();
    let packed = prepared.packed().unwrap();
    let unpacked = LineageEvidence::from_packed(&packed).unwrap();
    assert_eq!(unpacked.to_bytes().unwrap(), bytes);
    assert_eq!(unpacked.operation(), receipt.operation.as_bytes());
}

#[test]
fn verify_for_checks_stamp_evidence_only_with_the_stamp_trust() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let evidence = evidence(&mut g, &receipt, current, NOW, NOW);
    let stamps = trust(&[(&g.key, NOW - DAY, None)]);
    // With the trust: exactly the stamp verifier's observation, also after the stamp expired.
    let later = NOW + 3 * DAY;
    let mut later_owner = charter("alpha", later, &[]);
    let later_current = later_owner.current(later).unwrap();
    let observed = evidence
        .verify_for(later_current, Some(&stamps), &g.member, later)
        .unwrap();
    assert_eq!(
        observed.stamp_digest(later).unwrap(),
        evidence
            .verify_with_stamps(later_current, &stamps, &g.member, later)
            .unwrap()
            .stamp_digest(later)
            .unwrap()
    );
    // Without it the stamp evidence refuses, as `verify` does.
    assert_eq!(
        evidence
            .verify_for(current, None, &g.member, NOW)
            .unwrap_err(),
        LineageError::Policy(cchr::Error::Unavailable)
    );
    // Another member's trust never accepts it.
    assert!(
        evidence
            .verify_for(current, Some(&stamps), "another-member", NOW)
            .is_err()
    );
}

#[test]
fn a_receipt_time_outside_the_stamp_cohort_or_after_now_refuses() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let stamps = trust(&[(&g.key, 0, None)]);
    // The device claims a receipt time three days before the stamp's issuance: the stamp's
    // cohort does not cover it.
    let old = NOW - 3 * DAY;
    let evidence = evidence(&mut g, &receipt, current, old, NOW);
    assert_eq!(
        evidence
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );
    // A receipt time at or after the stamp's expiry is outside the cohort too.
    let expires = (NOW / DAY + 2) * DAY;
    let late = expires;
    let mut late_charter = charter("alpha", late, &[]);
    let late_current = late_charter.current(late).unwrap();
    let evidence = self::evidence(&mut g, &receipt, late_current, late, NOW);
    assert_eq!(
        evidence
            .verify_with_stamps(late_current, &stamps, &g.member, late)
            .unwrap_err(),
        LineageError::Stamp
    );
    // A receipt time in the verifier's future refuses as a clock error.
    let ahead = self::evidence(&mut g, &receipt, current, NOW + 60, NOW);
    assert_eq!(
        ahead
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Clock
    );
    // Preparation applies exactly the same rules.
    let shown = presentation_of(&ahead);
    assert!(matches!(
        LineageEvidence::prepare_stamp(
            current,
            &stamps,
            &receipt,
            &shown,
            SALT,
            NOW + 60,
            &g.member,
            NOW
        ),
        Err(EvidenceError::Evidence(LineageError::Clock))
    ));
}

#[test]
fn retired_stamp_keys_verify_only_inside_their_validity_period() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let evidence = evidence(&mut g, &receipt, current, NOW, NOW);
    let next = key("stamp-2");
    let later = NOW + 3 * DAY;
    let mut later_charter = charter("alpha", later, &[]);
    let later_current = later_charter.current(later).unwrap();
    // Rotated after the receipt: the retired key still verifies the old evidence.
    let rotated = trust(&[(&next, NOW + 10, None), (&g.key, NOW - DAY, Some(NOW + 10))]);
    assert!(
        evidence
            .verify_with_stamps(later_current, &rotated, &g.member, later)
            .is_ok()
    );
    // Retired before the receipt time, not yet valid, or absent from the ring: refused.
    for ring in [
        trust(&[(&next, NOW, None), (&g.key, NOW - DAY, Some(NOW))]),
        trust(&[(&g.key, NOW + 1, None)]),
        trust(&[(&next, 0, None)]),
    ] {
        assert_eq!(
            evidence
                .verify_with_stamps(later_current, &ring, &g.member, later)
                .unwrap_err(),
            LineageError::Stamp
        );
    }
    // Another rulebook cohort than the key's refuses.
    let hourly = StampTrust::new(
        vec![StampKeyPeriod::new(g.key.public_key().clone(), 0, None).unwrap()],
        StampParams::new(3_600).unwrap(),
    )
    .unwrap();
    assert_eq!(
        evidence
            .verify_with_stamps(current, &hourly, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );
    // The ring itself refuses empty, inverted and duplicate entries.
    assert_eq!(
        StampTrust::new(vec![], params()).unwrap_err(),
        GenesisError::Stamp
    );
    assert_eq!(
        StampKeyPeriod::new(g.key.public_key().clone(), NOW, Some(NOW)).unwrap_err(),
        GenesisError::Stamp
    );
    let twice = StampKeyPeriod::new(g.key.public_key().clone(), 0, None).unwrap();
    assert_eq!(
        StampTrust::new(vec![twice.clone(), twice], params()).unwrap_err(),
        GenesisError::Stamp
    );
}

#[test]
fn evidence_for_another_receipt_community_pseudonym_action_or_salt_never_verifies() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let stamps = trust(&[(&g.key, 0, None)]);
    let receipt = g.first.receipt.clone();
    let scope = lineage_stamp_scope(current).unwrap();
    let action = lineage_genesis_action(&receipt, SALT, NOW).unwrap();
    let shown = stamp(
        &mut g.holder,
        &g.key,
        &[(scope.clone(), action.clone())],
        NOW,
    );
    assert!(
        wire(&receipt, &shown, SALT, NOW)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .is_ok()
    );

    // Another receipt of the same member (another first lineage) under the same stamp.
    let other = first_lineage("alpha", &g.member, 11).receipt;
    assert_ne!(other.operation, receipt.operation);
    assert_eq!(
        wire(&other, &shown, SALT, NOW)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );
    // Another salt or another receipt time.
    assert_eq!(
        wire(&receipt, &shown, [6; 32], NOW)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );
    assert_eq!(
        wire(&receipt, &shown, SALT, NOW - 1)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );

    // Another action: the same payload and salt approved as a device join.
    let join = StampAction::new(
        ActionKind::new("device_join").unwrap(),
        *action.payload(),
        *action.salt(),
    );
    let joined = stamp(&mut g.holder, &g.key, &[(scope.clone(), join)], NOW);
    assert_eq!(
        wire(&receipt, &joined, SALT, NOW)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );

    // Another pseudonym: a second passport holder stamps the victim's receipt. The stamp is
    // genuine for the attacker's pseudonym and therefore not the member's.
    let mut attacker = OpaqueHolder::from_seed(&mut [41; 32]);
    let forged = stamp(
        &mut attacker,
        &g.key,
        &[(scope.clone(), action.clone())],
        NOW,
    );
    assert_eq!(
        wire(&receipt, &forged, SALT, NOW)
            .verify_with_stamps(current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Scope
    );
    // ... and a lineage claimed for another member than the expected one.
    assert_eq!(
        wire(&receipt, &shown, SALT, NOW)
            .verify_with_stamps(current, &stamps, &nym(&attacker, "alpha"), NOW)
            .unwrap_err(),
        LineageError::Scope
    );

    // Another community: the member's first lineage in "beta", stamped for "alpha".
    let beta_member = nym(&g.holder, "beta");
    let beta = first_lineage("beta", &beta_member, 12).receipt;
    let mut beta_owner = charter("beta", NOW, &[]);
    let beta_current = beta_owner.current(NOW).unwrap();
    let wrong_scope = stamp(
        &mut g.holder,
        &g.key,
        &[(scope, lineage_genesis_action(&beta, SALT, NOW).unwrap())],
        NOW,
    );
    assert_eq!(
        wire(&beta, &wrong_scope, SALT, NOW)
            .verify_with_stamps(beta_current, &stamps, &beta_member, NOW)
            .unwrap_err(),
        LineageError::Stamp
    );
    // The alpha evidence under the beta Charter is out of scope.
    assert_eq!(
        wire(&receipt, &shown, SALT, NOW)
            .verify_with_stamps(beta_current, &stamps, &g.member, NOW)
            .unwrap_err(),
        LineageError::Scope
    );
    // Correctly stamped for beta, it verifies there.
    let right = stamp(
        &mut g.holder,
        &g.key,
        &[(
            lineage_stamp_scope(beta_current).unwrap(),
            lineage_genesis_action(&beta, SALT, NOW).unwrap(),
        )],
        NOW,
    );
    assert!(
        wire(&beta, &right, SALT, NOW)
            .verify_with_stamps(beta_current, &stamps, &beta_member, NOW)
            .is_ok()
    );
}

#[test]
fn malformed_stamp_evidence_refuses_to_decode() {
    let g = genesis();
    let base = json!({
        "purpose": "cvlt.lineage-evidence.stamp.v1",
        "receipt": g.first.receipt,
        "presentation": [1, 2, 3],
        "salt": SALT,
        "at": NOW,
    });
    // Undecodable presentations are refused at use, never accepted.
    let decoded = LineageEvidence::from_bytes(&serde_json::to_vec(&base).unwrap()).unwrap();
    let mut owner = charter("alpha", NOW, &[]);
    assert_eq!(
        decoded
            .verify_with_stamps(
                owner.current(NOW).unwrap(),
                &trust(&[(&g.key, 0, None)]),
                &g.member,
                NOW
            )
            .unwrap_err(),
        LineageError::Stamp
    );
    for (field, value) in [
        ("purpose", json!("cvlt.lineage-evidence.v1")),
        ("purpose", json!("cvlt.lineage-evidence.stamp.v2")),
        ("extra", json!(1)),
        ("salt", json!([1, 2])),
    ] {
        let mut bad = base.clone();
        bad[field] = value;
        assert!(LineageEvidence::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}

struct Deny;
impl Authority for Deny {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}
struct NoRecords;
impl cvlt::Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
type TestVault =
    cvlt::Vault<cwst::native::FileBackend, Clock, ckmg::SystemEntropy, Deny, NoRecords, ()>;

async fn vault(first: &Receipt) -> TestVault {
    let scope = first
        .receipt
        .attested_lineage()
        .unwrap()
        .0
        .binding
        .community()
        .to_owned();
    let cipher = ckmg::passkey::store_cipher(&first.prf, &scope).unwrap();
    let store = cwst::Store::open(first.backend.clone(), &cipher, &scope)
        .await
        .unwrap();
    let mut vault = cvlt::Vault::new(
        store,
        &scope,
        Clock,
        ckmg::SystemEntropy,
        Deny,
        NoRecords,
        (),
    )
    .unwrap();
    vault.keys().unlock(&first.prf, &scope).await.unwrap();
    vault
}

#[test]
fn stamp_evidence_is_retained_locally_and_reverified_after_reopen() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let stamps = trust(&[(&g.key, 0, None)]);
    let shown = presentation_of(&evidence(&mut g, &receipt, current, NOW, NOW));
    let prepared = LineageEvidence::prepare_stamp(
        current, &stamps, &receipt, &shown, SALT, NOW, &g.member, NOW,
    )
    .unwrap();
    let published = prepared.evidence().to_bytes().unwrap();
    futures_executor::block_on(async {
        let mut vault = vault(&g.first).await;
        assert_eq!(
            vault.keys().pending_output().await.unwrap().unwrap(),
            receipt
        );
        let operation = *receipt.operation.as_bytes();
        assert!(
            LineageEvidence::load(&*vault.storage().lock().await, &operation)
                .unwrap()
                .is_none()
        );
        let committed = vault
            .retain_lineage_evidence(&prepared, [81; 32])
            .await
            .unwrap();
        {
            let store = vault.storage().lock().await;
            assert!(committed.is_commit(&store, &[81; 32]));
            // Only the receipt and the stamp proof are stored; no passkey owners.
            assert!(
                store
                    .read("lineage-assertion", &operation)
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .read("lineage-certificate", &operation)
                    .unwrap()
                    .is_none()
            );
            assert!(store.read("lineage-stamp", &operation).unwrap().is_some());
        }
        drop(committed);
        drop(vault);
        let reopened = self::vault(&g.first).await;
        let store = reopened.storage().lock().await;
        let retained = LineageEvidence::load(&store, &operation).unwrap().unwrap();
        assert_eq!(retained.to_bytes().unwrap(), published);
        assert!(
            retained
                .verify_with_stamps(current, &stamps, &g.member, NOW)
                .is_ok()
        );
        assert_eq!(
            retained.verify(current, &g.member, NOW).unwrap_err(),
            LineageError::Policy(cchr::Error::Unavailable)
        );
    });
}

#[test]
fn the_server_verifies_the_same_bytes_with_charter_alone_and_no_charter_document() {
    let mut g = genesis();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let receipt = g.first.receipt.clone();
    let evidence = evidence(&mut g, &receipt, current, NOW, NOW);
    let stamps = trust(&[(&g.key, NOW - DAY, None)]);
    let observed = evidence
        .verify_with_stamps(current, &stamps, &g.member, NOW)
        .unwrap();

    // The bind bytes are exactly the published evidence bytes; Charter decodes them.
    let bytes = evidence.genesis_stamp().unwrap().to_bytes().unwrap();
    assert_eq!(bytes, evidence.to_bytes().unwrap());
    let server = cchr::GenesisStampEvidence::from_bytes(&bytes).unwrap();
    assert_eq!(server.at(), NOW);
    assert_eq!(server.receipt(), &receipt);
    let verified = cchr::verify_genesis_parts(
        "alpha",
        current.fingerprint(),
        &stamps,
        &server,
        &g.member,
        NOW,
    )
    .unwrap();
    let (lineage, author) = receipt.attested_lineage().unwrap();
    assert_eq!(verified.lineage(), lineage);
    assert_eq!(verified.author(), &author);
    assert_eq!(
        verified.stamp().digest().to_bytes(),
        observed.stamp_digest(NOW).unwrap()
    );
    assert_eq!(
        verified.into_stamp().action_kind().as_str(),
        "lineage_genesis"
    );

    // Another member, community or fingerprint refuses; so does a time before the receipt.
    let refuse = |community: &str, fingerprint: Option<&[u8; 32]>, member: &str, now: u64| {
        cchr::verify_genesis_parts(community, fingerprint, &stamps, &server, member, now)
            .unwrap_err()
    };
    let other = nym(&OpaqueHolder::from_seed(&mut [41; 32]), "alpha");
    assert_eq!(
        refuse("alpha", current.fingerprint(), &other, NOW),
        GenesisError::Scope
    );
    assert_eq!(
        refuse("beta", current.fingerprint(), &g.member, NOW),
        GenesisError::Scope
    );
    assert_eq!(
        refuse("alpha", Some(&[7; 32]), &g.member, NOW),
        GenesisError::Stamp
    );
    assert_eq!(
        refuse("alpha", current.fingerprint(), &g.member, NOW - 1),
        GenesisError::Clock
    );

    // A pre-activation device derives the same action from the receipt's challenge digest.
    assert!(
        cvlt::lineage_genesis_action_for(receipt.passkey_challenge().unwrap(), SALT, NOW).unwrap()
            == lineage_genesis_action(&receipt, SALT, NOW).unwrap()
    );
    // Malformed and foreign-purpose bytes are refused before any verification.
    assert_eq!(
        cchr::GenesisStampEvidence::from_bytes(b"{}").unwrap_err(),
        GenesisError::Invalid
    );
    let mut foreign: Value = serde_json::from_slice(&bytes).unwrap();
    foreign["purpose"] = json!("cvlt.lineage-evidence.v1");
    assert_eq!(
        cchr::GenesisStampEvidence::from_bytes(&serde_json::to_vec(&foreign).unwrap()).unwrap_err(),
        GenesisError::Invalid
    );
}
