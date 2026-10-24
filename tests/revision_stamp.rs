//! Pairing revision evidence: one wallet stamp over the per-community pairing digest AND the
//! host device key's signature over the same digest, for a real Keys `DeviceAuthorized`
//! receipt (revision 2), against a signed Charter and the verifier's CURRENT lineage.
#![cfg(not(target_arch = "wasm32"))]
#![allow(dead_code, unused_imports)]
use cchr::{Charter, Configuration, RevisionError, VerifiedCharter, pair_payload};
use cvlt::{EvidenceError, LineageError, LineageEvidence, StampKeyPeriod, StampTrust, lineage_stamp_scope};
use ckmg::{
    Authority, Authorization, Binding, Change, Commit, DeviceInfo, Error, Lineage, Locator,
    PairingApproval, Receipt,
};
use cpsd::{
    CommunityId, IssuanceChallenge, KeyId, OpaqueHolder, StampAction, StampIssuerKey, StampParams,
    StampPresentation, StampScope, rand::rngs::OsRng,
};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const EPOCH: u64 = 3;
const SALT: [u8; 32] = [5; 32];

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

/// The member's first lineage in `scope`: a Keys `Created` receipt.
fn first_lineage(scope: &str, member: &str) -> Receipt {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
    let mut keys = ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow);
    futures_executor::block_on(keys.create_scope(
        &prf,
        Binding::new(scope, member).unwrap(),
        DeviceInfo::new("fixture", &[9; 16]).unwrap(),
        b"fixture",
    ))
    .unwrap()
}

fn sign(signer: &mut Signer, kind: Kind, payload: Value, at: u64) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(&payload).unwrap(), at, at + 500)
        .unwrap()
}

/// A complete signed Charter of `scope`, current at `at` until `at + 500`.
fn charter(scope: &str, at: u64, revoked_members: &[&str]) -> Charter {
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
    let mut owner = Charter::new(Configuration {
        origin: "https://members.example.com".into(),
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

/// One confirmation over `approvals` at `now`, presenting the first approval's slot.
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
    holder.finish_stamp(&blind, now).unwrap();
    let (scope, action) = &approvals[0];
    holder
        .present_stamp(&mut OsRng, scope, action, now)
        .unwrap()
}

struct Fixture {
    holder: OpaqueHolder,
    member: String,
    key: StampIssuerKey,
    receipt: Receipt,
    owner: Charter,
}

fn fixture() -> Fixture {
    let holder = OpaqueHolder::from_seed(&mut [40; 32]);
    let member = nym(&holder, "alpha");
    Fixture {
        receipt: first_lineage("alpha", &member),
        holder,
        member,
        key: key("stamp-1"),
        owner: charter("alpha", NOW, &[]),
    }
}


type Machine = ckmg::Keys<Memory, Clock, ckmg::SystemEntropy, Allow>;
fn machine() -> Machine {
    ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow)
}

/// A host that created the member's lineage and approved a second device: the
/// `DeviceAuthorized` receipt (revision 2) with the host's machine kept to sign.
struct Pairing {
    host: Machine,
    host_key: ckmg::PublicKey,
    new_key: ckmg::PublicKey,
    anchor: Lineage,
    receipt: Receipt,
    requested: Receipt,
}

async fn pair(member: &str, host_seed: u8, guest_seed: u8) -> Pairing {
    let host_prf = ckmg::passkey::PrfOutput::from_bytes(&[host_seed; 32]).unwrap();
    let mut host = machine();
    let created = host
        .create_scope(
            &host_prf,
            Binding::new("alpha", member).unwrap(),
            DeviceInfo::new("host", &[host_seed; 16]).unwrap(),
            b"fixture",
        )
        .await
        .unwrap();
    host.acknowledge(created.operation).await.unwrap();
    let (anchor, host_key) = {
        let (lineage, author) = created.attested_lineage().unwrap();
        (lineage.clone(), author)
    };
    let guest_prf = ckmg::passkey::PrfOutput::from_bytes(&[guest_seed; 32]).unwrap();
    let mut guest = machine();
    let requested = guest
        .request_pairing(
            &guest_prf,
            &anchor,
            DeviceInfo::new("guest", &[guest_seed; 16]).unwrap(),
            &[],
        )
        .await
        .unwrap();
    guest.acknowledge(requested.operation).await.unwrap();
    let Change::PairingRequested(request) = &requested.change else {
        panic!("not a pairing request")
    };
    let new_key = request.device;
    let receipt = host.authorize_device(request, &[]).await.unwrap();
    host.acknowledge(receipt.operation).await.unwrap();
    Pairing {
        host,
        host_key,
        new_key,
        anchor,
        receipt,
        requested,
    }
}

const SESSION: [u8; 32] = [77; 32];

/// The pairing digest of `receipt` for `key`: the one the stamp and the host signature cover.
fn digest(receipt: &Receipt, member: &str, key: &[u8; 32], session: &[u8; 32]) -> [u8; 32] {
    pair_payload(
        "alpha",
        member,
        key,
        session,
        Some(&receipt.passkey_challenge().unwrap()),
    )
}

/// The host device key's signature over `digest`, through the typed pairing approval.
async fn host_signature(p: &mut Pairing, digest: &[u8; 32]) -> [u8; 64] {
    let approval = PairingApproval::new("alpha", digest).unwrap();
    p.host
        .sign_device_ed25519(&approval.message(), NOW + 60)
        .await
        .unwrap()
}

/// One wallet stamp over the pairing action whose payload is `digest`.
fn stamp_over(f: &mut Fixture, current: &VerifiedCharter, digest: [u8; 32]) -> StampPresentation {
    let scope = lineage_stamp_scope(current).unwrap();
    let action = StampAction::new(
        cpsd::ActionKind::new(cchr::PAIR_ACTION).unwrap(),
        cpsd::PayloadDigest::from_bytes(digest),
        cpsd::StampSalt::from_bytes(SALT),
    );
    stamp(&mut f.holder, &f.key, &[(scope, action)], NOW)
}

struct Ctx<'a> {
    current: &'a VerifiedCharter,
    stamps: &'a StampTrust,
    lineage: &'a Lineage,
}

/// Prepare the carrier, send it through its publication bytes and the packed record envelope,
/// then reverify it at a later use against the same (or a changed) current devices.
fn verify(
    c: &Ctx<'_>,
    receipt: &Receipt,
    presentation: &StampPresentation,
    signature: &[u8; 64],
    session: &[u8; 32],
    member: &str,
) -> Result<(ckmg::PublicKey, ckmg::PublicKey, u64), RevisionError> {
    let prepared = LineageEvidence::prepare_revision(
        c.current,
        c.stamps,
        c.lineage,
        receipt,
        presentation,
        SALT,
        *session,
        *signature,
        NOW,
        member,
        NOW,
    )
    .map_err(|error| match error {
        EvidenceError::Evidence(LineageError::Revision(error)) => error,
        other => panic!("unexpected {other:?}"),
    })?;
    let wire = prepared.evidence().to_bytes().unwrap();
    let decoded = LineageEvidence::from_bytes(&wire).unwrap();
    assert!(decoded.is_revision());
    assert_eq!(decoded.to_bytes().unwrap(), wire);
    let packed = prepared.packed().unwrap();
    let unpacked = LineageEvidence::from_packed(&packed).unwrap();
    assert_eq!(unpacked.to_bytes().unwrap(), wire);
    // Revision evidence never verifies as passkey or genesis evidence.
    assert!(decoded.verify(c.current, member, NOW).is_err());
    assert!(
        decoded
            .verify_with_stamps(c.current, c.stamps, member, NOW)
            .is_err()
    );
    let ok = unpacked
        .verify_revision(c.current, c.stamps, c.lineage, member, NOW)
        .map_err(|error| match error {
            LineageError::Revision(error) => error,
            other => panic!("unexpected {other:?}"),
        })?;
    Ok((*ok.host(), *ok.new_key(), ok.lineage().revision))
}

#[test]
fn revision_evidence_needs_the_stamp_and_the_hosts_signature_from_the_current_devices() {
    let mut f = fixture();
    let member = f.member.clone();
    let genesis = first_lineage("alpha", &member);
    futures_executor::block_on(async {
        let mut owner = charter("alpha", NOW, &[]);
        let current = owner.current(NOW).unwrap();
        let stamps = trust(&[(&f.key, NOW - DAY, None)]);
        let mut p = pair(&member, 9, 8).await;
        let key = *p.new_key.value();
        let good_digest = digest(&p.receipt, &member, &key, &SESSION);
        let presentation = stamp_over(&mut f, current, good_digest);
        let signature = host_signature(&mut p, &good_digest).await;
        let c = Ctx { current, stamps: &stamps, lineage: &p.anchor };

        // Valid: the host is in the CURRENT lineage's devices.
        let (host, new_key, revision) =
            verify(&c, &p.receipt, &presentation, &signature, &SESSION, &member).unwrap();
        assert_eq!(host, p.host_key);
        assert_eq!(new_key, p.new_key);
        assert!(revision >= 2);

        // A removed host (the current lineage no longer lists its key) is refused, valid stamp.
        let other = pair(&member, 3, 4).await;
        let removed = Ctx { lineage: &other.anchor, ..Ctx { current, stamps: &stamps, lineage: &p.anchor } };
        assert_eq!(
            verify(&removed, &p.receipt, &presentation, &signature, &SESSION, &member).unwrap_err(),
            RevisionError::Host
        );
        // A stamp without the host signature is refused ...
        assert_eq!(
            verify(&c, &p.receipt, &presentation, &[0; 64], &SESSION, &member).unwrap_err(),
            RevisionError::Host
        );
        // ... and so is the signature of a key that is no device of the member (a delegate or
        // any stranger) over the same digest.
        let mut stranger = pair(&member, 5, 6).await;
        let forged = host_signature(&mut stranger, &good_digest).await;
        assert_eq!(
            verify(&c, &p.receipt, &presentation, &forged, &SESSION, &member).unwrap_err(),
            RevisionError::Host
        );
        // The host signature alone is not enough: a stamp over another key, another session
        // or another receipt's digest is refused.
        for wrong in [
            digest(&p.receipt, &member, &[1; 32], &SESSION),
            digest(&p.receipt, &member, &key, &[78; 32]),
            digest(&other.receipt, &member, other.new_key.value(), &SESSION),
        ] {
            let stamped = stamp_over(&mut f, current, wrong);
            assert_eq!(
                verify(&c, &p.receipt, &stamped, &signature, &SESSION, &member).unwrap_err(),
                RevisionError::Stamp
            );
        }
        // A session the verifier does not know changes the digest it recomputes.
        assert_eq!(
            verify(&c, &p.receipt, &presentation, &signature, &[78; 32], &member).unwrap_err(),
            RevisionError::Host
        );
        // A receipt that is not a DeviceAuthorized revision above 1 is refused.
        for receipt in [&genesis, &p.requested] {
            assert_eq!(
                verify(&c, receipt, &presentation, &signature, &SESSION, &member).unwrap_err(),
                RevisionError::Receipt
            );
        }
        // Another member or another community's Charter is refused.
        assert_eq!(
            verify(&c, &p.receipt, &presentation, &signature, &SESSION, "ff").unwrap_err(),
            RevisionError::Scope
        );
        let mut beta_owner = charter("beta", NOW, &[]);
        let beta = Ctx { current: beta_owner.current(NOW).unwrap(), stamps: &stamps, lineage: &p.anchor };
        assert_eq!(
            verify(&beta, &p.receipt, &presentation, &signature, &SESSION, &member).unwrap_err(),
            RevisionError::Scope
        );
        // A revoked member is refused.
        let mut revoked_owner = charter("alpha", NOW, &[&member]);
        let revoked = Ctx { current: revoked_owner.current(NOW).unwrap(), stamps: &stamps, lineage: &p.anchor };
        assert!(matches!(
            verify(&revoked, &p.receipt, &presentation, &signature, &SESSION, &member).unwrap_err(),
            RevisionError::Policy(_)
        ));
    });
}
