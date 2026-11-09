//! Community-pin mutant kills (muse-mut124): every surviving mutation of
//! `src/community_pin.rs` is distinguished by a focused assertion through the
//! public Vault API plus raw planted records.
//!
//! These tests live in an integration target (not `tests/unit/credential.rs`)
//! because the pin unit tests only compile behind the `wallet` feature, while
//! `cargo test`, the land gates and `cargo mutants` run default features.

#![cfg(not(target_arch = "wasm32"))]

use ckmg::{
    Action, Authority, Authorization, Binding, DeviceInfo, Error,
    passkey::{PrfOutput, store_cipher},
};
use cvlt::{Batch, CommunityPin, CredentialError, PinnedHead, Records, RestoreLookup, Vault};
use cwst::backend::{Backend, Memory};
use std::{cell::Cell, rc::Rc};

const SCOPE: &str = "wallet-test";
const MEMBER: &str = "fixture-member";
const NOW: u64 = 1_800_000_000;

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(NOW)
    }
}

struct NoRecords;
impl Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> RestoreLookup {
        RestoreLookup::Unavailable
    }
}

// Test-only setup adapter: exactly this binding/device may Create once and Use.
struct TestOnlyAuthority {
    binding: Binding,
    device: Option<ckmg::PublicKey>,
    created: bool,
    deny_use: Rc<Cell<bool>>,
}

impl Authority for TestOnlyAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.binding != &self.binding
            || request.now != NOW
            || request.target.is_some()
            || request.signing.is_some()
        {
            return Err(Error::Unauthorized);
        }
        match request.action {
            Action::Create
                if !self.created
                    && request.root.is_none()
                    && request.epoch == 0
                    && request.statement.is_none()
                    && request.evidence == b"fixture-create"
                    && Some(request.device) == self.device =>
            {
                self.created = true;
                Ok(())
            }
            Action::Use if request.statement.is_none() && request.evidence.is_empty() => {
                if self.deny_use.get() {
                    return Err(Error::Unauthorized);
                }
                if Some(request.device) == self.device {
                    return Ok(());
                }
                Err(Error::Unauthorized)
            }
            _ => Err(Error::Unauthorized),
        }
    }
}

type TestVault = Vault<Memory, Clock, ckmg::SystemEntropy, TestOnlyAuthority, NoRecords, ()>;

// Real PRF/Keys/Memory store, mirroring the unit harness in
// `tests/unit/wallet_restore.rs` but without the `wallet` feature.
async fn base_on(backend: Memory) -> TestVault {
    let prf = PrfOutput::from_bytes(&[7; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, SCOPE).unwrap();
    let authority = TestOnlyAuthority {
        binding: Binding::new(SCOPE, MEMBER).unwrap(),
        device: Some(device),
        created: false,
        deny_use: Rc::new(Cell::new(false)),
    };
    let cipher = store_cipher(&prf, SCOPE).unwrap();
    let store = cwst::Store::create(backend, &cipher, SCOPE).await.unwrap();
    let mut vault = Vault::new(
        store,
        SCOPE,
        Clock,
        ckmg::SystemEntropy,
        authority,
        NoRecords,
        (),
    )
    .unwrap();
    let guard = vault
        .stage_keys(Batch {
            expected: 0,
            operation: [61; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    let receipt = vault
        .keys()
        .create_scope(
            &prf,
            Binding::new(SCOPE, MEMBER).unwrap(),
            DeviceInfo::new("fixture", b"fixture-credential").unwrap(),
            b"fixture-create",
        )
        .await
        .unwrap();
    drop(guard);
    let guard = vault
        .stage_keys(Batch {
            expected: 1,
            operation: [62; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    vault.keys().acknowledge(receipt.operation).await.unwrap();
    drop(guard);
    vault
}

async fn base() -> TestVault {
    base_on(Memory::new()).await
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

fn pin(fingerprint: u8, head: Option<(u64, u8)>) -> CommunityPin {
    CommunityPin {
        fingerprint: [fingerprint; 32],
        head: head.map(|(ring_revision, byte)| PinnedHead {
            ring_revision,
            digest: [byte; 32],
        }),
    }
}

// Byte offsets of a stored pin record, derived from the known binding rather
// than hardcoded so the layout assertion itself is the check.
struct PinLayout {
    device_at: usize,
    version_at: usize,
    fingerprint_at: usize,
    flag_at: usize,
    revision_at: usize,
    digest_at: usize,
    total: usize,
}

fn pin_layout(record: &[u8]) -> PinLayout {
    let community = b"wallet-test";
    let member = b"fixture-member";
    let community_at = record
        .windows(community.len())
        .position(|w| w == community)
        .expect("community binding in record");
    let header_len = community_at - 4;
    assert_eq!(&record[..header_len], b"cvlt.community-pin.v1\0");
    assert_eq!(
        u32::from_be_bytes(record[header_len..header_len + 4].try_into().unwrap()),
        community.len() as u32
    );
    let member_at = record
        .windows(member.len())
        .position(|w| w == member)
        .expect("member binding in record");
    let device_at = member_at + member.len();
    let version_at = device_at + 32;
    let fingerprint_at = version_at + 1;
    let flag_at = fingerprint_at + 32;
    let revision_at = flag_at + 1;
    let digest_at = revision_at + 8;
    PinLayout {
        device_at,
        version_at,
        fingerprint_at,
        flag_at,
        revision_at,
        digest_at,
        total: digest_at + 32,
    }
}

async fn stored_pin_record(vault: &TestVault) -> Vec<u8> {
    vault
        .storage()
        .lock()
        .await
        .read("cvlt.community-pin", b"current")
        .unwrap()
        .unwrap()
        .to_vec()
}

async fn plant_pin(vault: &TestVault, record: &[u8]) {
    let storage = vault.storage().clone();
    let mut store = storage.lock().await;
    let version = store.version().unwrap();
    store
        .commit(
            version,
            [77; 32],
            &[cwst::Change::Put {
                owner: "cvlt.community-pin",
                key: b"current",
                value: record,
            }],
            &[],
        )
        .await
        .unwrap();
}

fn assert_pin_foreign(result: Result<Option<CommunityPin>, CredentialError>) {
    assert_eq!(result, Err(CredentialError::Foreign));
}

// Kills 36:9 (frame replaced with vec![] / vec![0] / vec![1]): the stored
// bytes must be the exact 161-byte frame; and 89:18-false, 89:27, 89:47
// (headless guard arms): a headless pin reads back.
#[test]
fn pin_frame_bytes_are_exact_and_headless_reads_back() {
    run(async {
        let mut vault = base().await;
        let headless = pin(1, None);
        assert_eq!(
            vault.write_community_pin(None, &headless, None).await,
            Ok(true)
        );
        let record = stored_pin_record(&vault).await;
        let layout = pin_layout(&record);
        assert_eq!(record.len(), layout.total);
        assert_eq!(
            record.len(),
            22 + 4 + 11 + 4 + 14 + 32 + 1 + 32 + 1 + 8 + 32
        );
        assert_eq!(record[layout.version_at], 1);
        assert_eq!(
            &record[layout.fingerprint_at..layout.fingerprint_at + 32],
            &[1; 32]
        );
        assert_eq!(record[layout.flag_at], 0);
        assert_eq!(&record[layout.revision_at..layout.revision_at + 8], &[0; 8]);
        assert_eq!(&record[layout.digest_at..layout.digest_at + 32], &[0; 32]);
        assert_eq!(vault.community_pin().await, Ok(Some(headless)));
    });
}

// Kills 36:9 (frame replaced) and 90:13 (match arm 1 deleted): a headed pin
// stores flag 1 with the big-endian revision and digest, and reads back.
#[test]
fn pin_headed_frame_bytes_are_exact_and_read_back() {
    run(async {
        let mut vault = base().await;
        let headed = pin(1, Some((2, 5)));
        assert_eq!(
            vault.write_community_pin(None, &headed, None).await,
            Ok(true)
        );
        let record = stored_pin_record(&vault).await;
        let layout = pin_layout(&record);
        assert_eq!(record.len(), layout.total);
        assert_eq!(record[layout.flag_at], 1);
        assert_eq!(
            u64::from_be_bytes(
                record[layout.revision_at..layout.revision_at + 8]
                    .try_into()
                    .unwrap()
            ),
            2
        );
        assert_eq!(&record[layout.digest_at..layout.digest_at + 32], &[5; 32]);
        assert_eq!(vault.community_pin().await, Ok(Some(headed)));
    });
}

// Kills 68:27 (< replaced with ==, >, <=): every truncation of a valid headed
// record is Foreign. Under == or > the short reads skip the guard and panic
// in split_at, which also fails the test; under <= the exact-fit final takes
// break valid reads, covered by the round-trip tests above.
#[test]
fn pin_truncated_records_are_foreign() {
    run(async {
        let mut vault = base().await;
        vault
            .write_community_pin(None, &pin(1, Some((2, 5))), None)
            .await
            .unwrap();
        let record = stored_pin_record(&vault).await;
        assert!(record.len() > 22);
        for len in 22..record.len() {
            plant_pin(&vault, &record[..len]).await;
            assert_pin_foreign(vault.community_pin().await);
        }
        plant_pin(&vault, &record).await;
        assert_eq!(vault.community_pin().await, Ok(Some(pin(1, Some((2, 5))))));
    });
}

// Kills 77:59 (!= replaced with == on the community/member binding): a record
// bound to another community or member is Foreign, never accepted.
#[test]
fn pin_records_bound_to_another_community_or_member_are_foreign() {
    run(async {
        let mut vault = base().await;
        vault
            .write_community_pin(None, &pin(1, Some((2, 5))), None)
            .await
            .unwrap();
        let record = stored_pin_record(&vault).await;
        let community_at = record
            .windows(b"wallet-test".len())
            .position(|w| w == b"wallet-test")
            .unwrap();
        let member_at = record
            .windows(b"fixture-member".len())
            .position(|w| w == b"fixture-member")
            .unwrap();
        for at in [community_at, member_at] {
            let mut bad = record.clone();
            bad[at] ^= 1;
            plant_pin(&vault, &bad).await;
            assert_pin_foreign(vault.community_pin().await);
        }
        plant_pin(&vault, &record).await;
        assert_eq!(vault.community_pin().await, Ok(Some(pin(1, Some((2, 5))))));
    });
}

// Kills 81:32 (|| replaced with &&), 81:22 (device != replaced with ==) and
// 81:44 (version != replaced with ==): each single violation is Foreign. The
// && mutant accepts either single violation; the == mutants accept theirs.
#[test]
fn pin_device_or_version_mismatch_is_foreign() {
    run(async {
        let mut vault = base().await;
        vault
            .write_community_pin(None, &pin(1, Some((2, 5))), None)
            .await
            .unwrap();
        let record = stored_pin_record(&vault).await;
        let layout = pin_layout(&record);
        // Wrong version byte, device intact.
        let mut bad_version = record.clone();
        bad_version[layout.version_at] = 2;
        plant_pin(&vault, &bad_version).await;
        assert_pin_foreign(vault.community_pin().await);
        // Wrong device, version intact.
        let mut bad_device = record.clone();
        bad_device[layout.device_at] ^= 1;
        plant_pin(&vault, &bad_device).await;
        assert_pin_foreign(vault.community_pin().await);
        plant_pin(&vault, &record).await;
        assert_eq!(vault.community_pin().await, Ok(Some(pin(1, Some((2, 5))))));
    });
}

// Kills 89:18 (guard replaced with true) and 89:37 (guard && replaced with
// ||): flag 0 with a nonzero revision or digest is Foreign, never a headless
// pin. Each variant keeps the other half zero, so the || mutant accepts it.
#[test]
fn pin_flag_zero_with_nonzero_head_is_foreign() {
    run(async {
        let mut vault = base().await;
        vault
            .write_community_pin(None, &pin(1, None), None)
            .await
            .unwrap();
        let record = stored_pin_record(&vault).await;
        let layout = pin_layout(&record);
        assert_eq!(record[layout.flag_at], 0);
        let mut bad_revision = record.clone();
        bad_revision[layout.revision_at] = 1;
        plant_pin(&mut vault, &bad_revision).await;
        assert_pin_foreign(vault.community_pin().await);
        let mut bad_digest = record.clone();
        bad_digest[layout.digest_at] = 1;
        plant_pin(&mut vault, &bad_digest).await;
        assert_pin_foreign(vault.community_pin().await);
        plant_pin(&vault, &record).await;
        assert_eq!(vault.community_pin().await, Ok(Some(pin(1, None))));
    });
}

// Kills 96:12 (deleted ! on the trailing check): trailing bytes are Foreign.
#[test]
fn pin_trailing_bytes_are_foreign() {
    run(async {
        let mut vault = base().await;
        vault
            .write_community_pin(None, &pin(1, Some((2, 5))), None)
            .await
            .unwrap();
        let mut record = stored_pin_record(&vault).await;
        record.push(0);
        plant_pin(&vault, &record).await;
        assert_pin_foreign(vault.community_pin().await);
    });
}

// Kills 105:9 (succeeds replaced with true/false), 105:29 (!= replaced with
// ==), 112:35 (> replaced with ==, <, >=), 113:21 (|| replaced with &&),
// 113:64 (&& replaced with ||), 113:43 and 113:78 (== replaced with !=),
// 157:29 (!= replaced with ==), 162:36 (deleted !) and 147:9 (write replaced
// with Ok(true)/Ok(false)): advance accepted, retreat/sideways/replay gated.
#[test]
fn pin_successor_rules_accept_advance_and_refuse_retreat_sideways_replay() {
    run(async {
        let mut vault = base().await;
        let first = pin(1, None);
        assert_eq!(vault.community_pin().await, Ok(None));
        // A stale expectation never writes (kills 157:29 and 147:9-true).
        assert_eq!(
            vault
                .write_community_pin(Some(&pin(9, None)), &first, None)
                .await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(vault.community_pin().await, Ok(None));
        assert_eq!(
            vault.write_community_pin(None, &first, None).await,
            Ok(true)
        );
        // Advance to a higher revision with a new digest (kills 105:9-false,
        // 105:29, 112:35-==, 112:35-<, 113:21, 162:36).
        let at_two = pin(1, Some((2, 5)));
        assert_eq!(
            vault.write_community_pin(Some(&first), &at_two, None).await,
            Ok(true)
        );
        // Retreat (kills 105:9-true, 112:35-<) and losing the head are refused.
        for bad in [pin(1, Some((1, 5))), pin(1, Some((2, 6))), pin(1, None)] {
            assert_eq!(
                vault.write_community_pin(Some(&at_two), &bad, None).await,
                Err(CredentialError::Conflict)
            );
        }
        // Sideways with the same revision but another digest (kills 112:35->=
        // and 113:64) is refused; the identical replay writes nothing and
        // leaves the version alone (kills 113:43, 113:78, 147:9-true,
        // 177:29).
        assert_eq!(
            vault
                .write_community_pin(Some(&at_two), &pin(1, Some((2, 7))), None)
                .await,
            Err(CredentialError::Conflict)
        );
        let before = vault.storage().lock().await.version().unwrap();
        assert_eq!(
            vault
                .write_community_pin(Some(&at_two), &at_two, None)
                .await,
            Ok(false)
        );
        assert_eq!(vault.storage().lock().await.version().unwrap(), before);
        // Another founding key replaces the pin only headless (kills 105:29).
        assert_eq!(
            vault
                .write_community_pin(Some(&at_two), &pin(2, Some((1, 1))), None)
                .await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(
            vault
                .write_community_pin(Some(&at_two), &pin(2, None), None)
                .await,
            Ok(true)
        );
        assert_eq!(vault.community_pin().await, Ok(Some(pin(2, None))));
    });
}

// Kills 123:9 (community_pin replaced with Ok(None)) and 147:9 (write
// replaced with Ok(false)): reads observe writes.
#[test]
fn pin_reads_observe_writes() {
    run(async {
        let mut vault = base().await;
        assert_eq!(vault.community_pin().await, Ok(None));
        let first = pin(1, None);
        assert_eq!(
            vault.write_community_pin(None, &first, None).await,
            Ok(true)
        );
        assert_eq!(vault.community_pin().await, Ok(Some(first)));
    });
}

// Kills 177:42 (&& replaced with ||): replaying the identical pin together
// with a real credential change still commits the credential and reports a
// write. Under || the write is skipped and Ok(false) is returned.
#[test]
fn pin_replay_with_a_credential_change_still_commits() {
    run(async {
        let mut vault = base().await;
        let one = pin(1, None);
        assert_eq!(
            vault
                .write_community_pin(None, &one, Some((None, b"cred")))
                .await,
            Ok(true)
        );
        assert_eq!(
            vault
                .write_community_pin(Some(&one), &one, Some((Some(b"cred"), b"new")))
                .await,
            Ok(true)
        );
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"new"
        );
        assert_eq!(vault.community_pin().await, Ok(Some(one)));
        // The pure replay still writes nothing.
        let before = vault.storage().lock().await.version().unwrap();
        assert_eq!(
            vault
                .write_community_pin(Some(&one), &one, Some((Some(b"new"), b"new")))
                .await,
            Ok(false)
        );
        assert_eq!(vault.storage().lock().await.version().unwrap(), before);
    });
}

// Kills 202:17 (deleted `cwst::Error::Conflict` arm in write_community_pin):
// a commit that loses the backend compare-and-swap to a concurrent writer
// over the same backend must surface as Conflict (retryable), never Storage.
#[test]
fn pin_concurrent_backend_write_maps_to_conflict() {
    run(async {
        let backend = Memory::new();
        let mut vault = base_on(backend.clone()).await;
        let first = pin(1, None);
        assert_eq!(
            vault.write_community_pin(None, &first, None).await,
            Ok(true)
        );
        // A concurrent writer over the same backend advances the checkpoint
        // outside this vault's Store snapshot, so the fenced commit loses its
        // compare-and-swap.
        let wire = vault
            .storage()
            .lock()
            .await
            .sealed_checkpoint()
            .unwrap()
            .to_vec();
        let mut rival_wire = wire.clone();
        let last = rival_wire.len() - 1;
        rival_wire[last] ^= 1;
        backend
            .compare_exchange(Some(&wire), &rival_wire)
            .await
            .unwrap();
        // The pin itself is untouched and still the expected one, so only the
        // fenced commit can refuse, and only with Conflict.
        let next = pin(1, Some((2, 5)));
        assert_eq!(
            vault.write_community_pin(Some(&first), &next, None).await,
            Err(CredentialError::Conflict)
        );
    });
}
