//! Birth genesis evidence of the wallet lineage (one-ceremony registration): accepted only for
//! the wallet scope, verified offline under the current wallet Charter's key ring, and a
//! restoring device additionally checks the credential and device key the statement names.
#![cfg(not(target_arch = "wasm32"))]
use cchr::{BirthGenesisEvidence, BirthStatement, wallet_fingerprint};
use ckmg::{Authority, Authorization, Binding, Commit, DeviceInfo, Error, Locator, Receipt};
use csgn::{Kind, SecretKey, Signer};
use cvlt::{EvidenceError, LineageError, LineageEvidence};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://wallet.example.com";
const ACCOUNT: &str = "5f0c9a52-6f43-4b8e-9d1a-2c7e1b3a4d60";
const CREDENTIAL: &[u8] = b"fixture wallet credential id";
const CREDENTIAL_KEY: [u8; 32] = [33; 32];
const COMMITMENT: [u8; 32] = [44; 32];
const PRF: [u8; 32] = [9; 32];

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<Locator, Vec<u8>>>>);
impl ckmg::SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let mut data = self.0.borrow_mut();
        if data
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
        Ok(Commit::Committed)
    }
}
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(NOW)
    }
}
struct Allow;
impl Authority for Allow {
    async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

/// The first lineage of `member` in `scope`, made with the PRF `prf`.
fn first_lineage(prf: [u8; 32], scope: &str, member: &str) -> Receipt {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&prf).unwrap();
    let mut keys = ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow);
    futures_executor::block_on(keys.create_scope(
        &prf,
        Binding::new(scope, member).unwrap(),
        DeviceInfo::new("fixture", CREDENTIAL).unwrap(),
        b"fixture",
    ))
    .unwrap()
}
fn signer(issuer: &str, seed: u8) -> Signer {
    Signer::new(issuer, SecretKey::from_seed(&mut [seed; 32]), NOW - 1, 1000).unwrap()
}
fn sign(signer: &mut Signer, kind: Kind, payload: Value) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(&payload).unwrap(), NOW, NOW + 500)
        .unwrap()
}
/// The signed five-document Charter publication of `scope` under `signer`'s ring (the same
/// shape as tests/lineage.rs), with `members` revoked.
fn charter(scope: &str, signer: &mut Signer, members: &[&str]) -> cchr::Charter {
    let schema = json!({"community":scope,"version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":scope,"revision":1,
        "policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),"schema_version":1});
    let mut feed = json!({"revision":1,"policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),
        "manifest":sign(signer,Kind::SettingsSnapshot,manifest)});
    let revocations = json!({"members":members,"devices":[],"passkeys":[]});
    for (name, kind, content) in [
        (
            "settings",
            Kind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
        ),
        ("schema", Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!([scope])),
        ("revocations", Kind::RevocationListSnapshot, revocations),
    ] {
        feed[name] = json!(sign(
            signer,
            kind,
            json!({"community":scope,"revision":1,"policy_epoch":1,"content":content})
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
        .install(&serde_json::to_vec(&feed).unwrap(), NOW)
        .unwrap();
    owner
}
fn device(receipt: &Receipt) -> ckmg::PublicKey {
    receipt.attested_lineage().unwrap().1
}
/// Birth evidence over `receipt`, its statement signed by `signer`.
fn evidence(receipt: &Receipt, signer: &mut Signer) -> BirthGenesisEvidence {
    let statement = BirthStatement::new(
        wallet_fingerprint(None),
        ACCOUNT,
        CREDENTIAL,
        CREDENTIAL_KEY,
        *device(receipt).value(),
        COMMITMENT,
        receipt.passkey_challenge().unwrap(),
        NOW,
    )
    .unwrap()
    .to_payload()
    .unwrap();
    let signed = signer
        .sign(Kind::Credential, &statement, NOW, NOW + 500)
        .unwrap();
    BirthGenesisEvidence::new(receipt.clone(), signed, NOW)
}

#[test]
fn birth_evidence_is_accepted_for_the_wallet_and_roundtrips() {
    let receipt = first_lineage(PRF, "wallet", ACCOUNT);
    let mut wallet = signer("wallet", 81);
    let mut charter = charter("wallet", &mut wallet, &[]);
    let current = charter.current(NOW).unwrap();
    let prepared =
        LineageEvidence::prepare_birth(current, evidence(&receipt, &mut wallet), ACCOUNT, NOW)
            .unwrap();
    assert!(prepared.evidence().is_birth());
    assert!(!prepared.evidence().is_stamp());
    assert!(prepared.evidence().genesis_stamp().is_none());
    let birth = prepared.evidence().birth_genesis().unwrap();
    assert_eq!(birth.receipt(), &receipt);
    // The wire is Charter's own birth evidence wire, and decodes back to birth evidence.
    let bytes = prepared.evidence().to_bytes().unwrap();
    assert_eq!(bytes, birth.to_bytes().unwrap());
    let decoded = LineageEvidence::from_bytes(&bytes).unwrap();
    assert!(decoded.is_birth());
    let packed = prepared.packed().unwrap();
    let unpacked = LineageEvidence::from_packed(&packed).unwrap();
    assert_eq!(unpacked.to_bytes().unwrap(), bytes);
    let observed = decoded.verify(current, ACCOUNT, NOW).unwrap();
    assert_eq!(observed.lineage(NOW).unwrap().binding.community(), "wallet");
    assert_eq!(observed.author(NOW).unwrap(), device(&receipt));
    assert_eq!(observed.credential_id(NOW).unwrap(), CREDENTIAL);
    assert_eq!(observed.stamp_digest(NOW), Err(LineageError::Scope));
    assert_eq!(observed.valid_until(), current.valid_until());
    // The verification is judged at the statement time; `now` may not precede it.
    assert_eq!(
        decoded.verify(current, ACCOUNT, NOW - 1).unwrap_err(),
        LineageError::Clock
    );
    // Another account's expectation refuses.
    assert_eq!(
        decoded.verify(current, "another-account", NOW).unwrap_err(),
        LineageError::Scope
    );
}

#[test]
fn birth_evidence_is_refused_for_every_community_scope() {
    // A community receipt under its own Charter, even with a statement signed by that ring.
    let receipt = first_lineage(PRF, "alpha", ACCOUNT);
    let mut community = signer("alpha", 71);
    let mut alpha = charter("alpha", &mut community, &[]);
    let current = alpha.current(NOW).unwrap();
    let foreign = evidence(&receipt, &mut community);
    assert!(matches!(
        LineageEvidence::prepare_birth(current, foreign.clone(), ACCOUNT, NOW),
        Err(EvidenceError::Evidence(LineageError::Scope))
    ));
    let decoded = LineageEvidence::from_bytes(&foreign.to_bytes().unwrap()).unwrap();
    assert!(decoded.is_birth());
    assert_eq!(
        decoded.verify(current, ACCOUNT, NOW).unwrap_err(),
        LineageError::Scope
    );
    // A genuine wallet birth presented under a community Charter refuses as well.
    let wallet_receipt = first_lineage(PRF, "wallet", ACCOUNT);
    let mut wallet = signer("wallet", 81);
    let genuine = evidence(&wallet_receipt, &mut wallet);
    assert!(matches!(
        LineageEvidence::prepare_birth(current, genuine.clone(), ACCOUNT, NOW),
        Err(EvidenceError::Evidence(LineageError::Scope))
    ));
    // A community receipt under the wallet Charter refuses at the binding.
    let mut wallet_charter = charter("wallet", &mut wallet, &[]);
    let wallet_current = wallet_charter.current(NOW).unwrap();
    assert!(matches!(
        LineageEvidence::prepare_birth(
            wallet_current,
            evidence(&receipt, &mut wallet),
            ACCOUNT,
            NOW
        ),
        Err(EvidenceError::Evidence(LineageError::Scope))
    ));
}

#[test]
fn foreign_signer_revoked_member_and_mismatched_restore_refuse() {
    let receipt = first_lineage(PRF, "wallet", ACCOUNT);
    let mut wallet = signer("wallet", 81);
    let mut charter_owner = charter("wallet", &mut wallet, &[]);
    let current = charter_owner.current(NOW).unwrap();
    // A statement signed by a key outside the wallet ring.
    let mut stranger = signer("wallet", 82);
    assert!(matches!(
        LineageEvidence::prepare_birth(current, evidence(&receipt, &mut stranger), ACCOUNT, NOW),
        Err(EvidenceError::Evidence(LineageError::Policy(
            cchr::Error::Signature
        )))
    ));
    let genuine =
        LineageEvidence::from_bytes(&evidence(&receipt, &mut wallet).to_bytes().unwrap()).unwrap();
    let k = device(&receipt);
    // The restoring device: exactly the named credential and its derived K.
    let observed = genuine
        .verify_restoring(current, ACCOUNT, CREDENTIAL, &k, NOW)
        .unwrap();
    assert_eq!(observed.author(NOW).unwrap(), k);
    assert_eq!(
        genuine
            .verify_restoring(current, ACCOUNT, b"another credential", &k, NOW)
            .unwrap_err(),
        LineageError::Scope
    );
    let other = device(&first_lineage([10; 32], "wallet", ACCOUNT));
    assert_ne!(other, k);
    assert_eq!(
        genuine
            .verify_restoring(current, ACCOUNT, CREDENTIAL, &other, NOW)
            .unwrap_err(),
        LineageError::Scope
    );
    // A revoked account refuses although the statement verifies.
    let mut revoked_owner = charter("wallet", &mut wallet, &[ACCOUNT]);
    let revoked = revoked_owner.current(NOW).unwrap();
    assert_eq!(
        genuine.verify(revoked, ACCOUNT, NOW).unwrap_err(),
        LineageError::Policy(cchr::Error::Unauthenticated)
    );
}
