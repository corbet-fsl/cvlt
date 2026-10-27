//! Resume bundle v2 at the byte level: it holds only sealed `ckmg::DeviceDelegation`s,
//! never `U_c` or the wallet PRF output, and refuses anything it did not seal itself.
//! The authority below is a permissive test adapter, not production membership.
use super::*;
use ckmg::{Authorization, Binding, Commit, DeviceInfo, Error, Keys, Locator, Purpose, Scope};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const W: [u8; 32] = [0x5a; 32];
const GARDEN: ([u8; 32], &str) = ([1; 32], "garden");
const ORCHARD: ([u8; 32], &str) = ([2; 32], "orchard");

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
        if data.get(location).map(|v| *blake3::hash(v).as_bytes()) != expected {
            return Ok(Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
        Ok(Commit::Committed)
    }
}

#[derive(Clone)]
struct Time;
impl ckmg::Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(1000)
    }
}

struct Live;
impl ckmg::Authority for Live {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

/// The community opening a ceremony yields (`W` -> `U_c` -> Keys), and the delegation
/// enrolled while it is open. Returns the opening's PRF-derived device key too.
async fn enrolled((fingerprint, scope): ([u8; 32], &str)) -> (DeviceDelegation, ckmg::PublicKey) {
    let unlock = crate::WalletUnlock::from_bytes_for_tests(W);
    let opening = if scope == crate::WALLET_SCOPE {
        unlock.wallet()
    } else {
        unlock.community(&fingerprint, scope)
    }
    .unwrap();
    let mut keys = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Live);
    let receipt = keys
        .create_scope(
            &opening.prf,
            Binding::new(scope, "member").unwrap(),
            DeviceInfo::new("device", b"credential").unwrap(),
            b"registration",
        )
        .await
        .unwrap();
    keys.acknowledge(receipt.operation).await.unwrap();
    let purposes = [Purpose::new(Scope::Member, "board", 1).unwrap()];
    let (receipt, delegation) = keys.delegate_device(&purposes, b"ceremony").await.unwrap();
    keys.acknowledge(receipt.operation).await.unwrap();
    (delegation, opening.device().unwrap())
}

async fn two_communities() -> ResumeBundle {
    let mut bundle = ResumeBundle::new();
    for community in [GARDEN, ORCHARD] {
        bundle
            .insert(community.0, community.1, enrolled(community).await.0)
            .unwrap();
    }
    bundle
}

/// Decision M6 as corrected by X1: after enrolment the persisted plaintext is exactly
/// the framed sealed delegations, and holds neither `W` nor any community's `U_c`.
#[test]
fn bundle_holds_only_sealed_delegations_never_u_c_or_the_prf_output() {
    futures_executor::block_on(async {
        let (delegation, opened_device) = enrolled(GARDEN).await;
        // The delegate key is fresh device entropy, not the PRF-derived device key.
        assert_ne!(delegation.device_public_key(), opened_device);
        let sealed = delegation.to_sealed_bytes().unwrap();
        let mut bundle = ResumeBundle::new();
        bundle.insert(GARDEN.0, GARDEN.1, delegation).unwrap();
        let plain = bundle.encode().unwrap();

        let mut expected = vec![VERSION];
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&GARDEN.0);
        expected.extend_from_slice(&(GARDEN.1.len() as u16).to_le_bytes());
        expected.extend_from_slice(GARDEN.1.as_bytes());
        expected.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        expected.extend_from_slice(&sealed);
        assert_eq!(plain.as_slice(), expected.as_slice());

        let full = two_communities().await.encode().unwrap();
        for secret in [
            W,
            *crate::unlock::community_secret(&W, &GARDEN.0),
            *crate::unlock::community_secret(&W, &ORCHARD.0),
        ] {
            assert!(!full.windows(32).any(|window| window == secret));
        }
    });
}

#[test]
fn encoding_round_trips_and_refuses_garbage_tampering_and_foreign_scopes() {
    futures_executor::block_on(async {
        let plain = two_communities().await.encode().unwrap();
        let back = ResumeBundle::decode(&plain).unwrap();
        assert_eq!(back.encode().unwrap().as_slice(), plain.as_slice());
        assert!(back.delegation(&GARDEN.0, GARDEN.1).is_some());
        assert!(back.delegation(&GARDEN.0, ORCHARD.1).is_none());
        assert!(back.delegation(&[3; 32], GARDEN.1).is_none());

        let mut long = plain.to_vec();
        long.push(0);
        assert_eq!(
            ResumeBundle::decode(&long).err(),
            Some(ResumeError::Invalid)
        );
        assert_eq!(
            ResumeBundle::decode(&plain[..plain.len() - 1]).err(),
            Some(ResumeError::Invalid)
        );
        assert_eq!(ResumeBundle::decode(&[1]).err(), Some(ResumeError::Invalid));
        // A flipped byte in a delegation's header, key or lineage refuses at decode. (Its
        // secrets carry no integrity of their own: the store's AEAD seal covers the whole
        // record, see the native and browser tamper tests.)
        let start = 1 + 4 + 32 + 2 + GARDEN.1.len() + 4;
        for offset in [start + 5, start + 20, start + 100, start + 130] {
            let mut tampered = plain.to_vec();
            tampered[offset] ^= 1;
            assert!(ResumeBundle::decode(&tampered).is_err(), "offset {offset}");
        }

        let mut one = ResumeBundle::new();
        let (garden, _) = enrolled(GARDEN).await;
        assert_eq!(
            one.insert(ORCHARD.0, ORCHARD.1, garden),
            Err(ResumeError::Invalid)
        );
        let (wallet, _) = enrolled(([4; 32], "wallet")).await;
        assert_eq!(
            one.insert([4; 32], "wallet", wallet),
            Err(ResumeError::Invalid)
        );
        assert!(one.is_empty());
        // Re-delegation replaces; removal forgets.
        one.insert(GARDEN.0, GARDEN.1, enrolled(GARDEN).await.0)
            .unwrap();
        one.insert(GARDEN.0, GARDEN.1, enrolled(GARDEN).await.0)
            .unwrap();
        assert_eq!(one.memberships().count(), 1);
        assert!(one.remove(&GARDEN.0, GARDEN.1));
        assert!(one.is_empty());
    });
}

/// Guard (X1): no code of the resume module may reach PRF material. If a future change
/// persists `U_c` or a PRF output again, it has to name one of these, and this fails.
#[test]
fn resume_code_names_no_prf_material() {
    let sources = [
        include_str!("../resume.rs"),
        include_str!("native.rs"),
        include_str!("browser.rs"),
    ];
    for source in sources {
        for line in source.lines().map(str::trim) {
            if line.starts_with("//") {
                continue;
            }
            for forbidden in [
                "PreparedOpen",
                "from_prf",
                "WalletUnlock",
                "community_secret",
                "PrfOutput",
                "UnlockSecret",
                "passkey::",
            ] {
                assert!(!line.contains(forbidden), "{forbidden} in: {line}");
            }
        }
    }
}

#[test]
fn aad_binds_length_and_binding() {
    assert_ne!(aad(b"ab"), aad(b"a"));
    assert!(aad(b"x").starts_with(AAD_PREFIX));
}
