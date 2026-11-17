//! Original-owner Wallet restore: both sealed owners reopen under one Keys identity.
//! Test-only cryptographic/setup adapter below admits exactly the fixture
//! binding/device Create and Use; it is not live G3 or runtime qualification.
use crate::{Batch, Records, RestoreLookup, Vault, WalletRestoreError};
use ckmg::{Action, Authority, Authorization, Binding, DeviceInfo, Error, passkey::store_cipher};
use cwlt::passport::{
    CommunityId, Pseudonym,
    rand::{SeedableRng as _, rngs::StdRng},
};
use cwst::backend::{Backend, Memory};
use std::{cell::Cell, rc::Rc};

const SCOPE: &str = "wallet-test";
const MEMBER: &str = "fixture-member";
const NOW: u64 = 1_800_000_000;
const ROTATION_EVIDENCE: &[u8] = b"fixture-rotate";

#[path = "account_genesis.rs"]
mod account_genesis_tests;
#[path = "account_restore.rs"]
mod account_restore_tests;
#[path = "credential.rs"]
mod credential_tests;
#[path = "delegation_outbox.rs"]
mod delegation_outbox_tests;
#[path = "update_outbox.rs"]
mod update_outbox_tests;
#[path = "voucher_custody.rs"]
mod voucher_custody_tests;
#[path = "witness_state.rs"]
mod witness_state_tests;

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
// Never live G3; a deny flag lets one test force Keys refusal without new keys.
struct TestOnlyAuthority {
    binding: Binding,
    device: Option<ckmg::PublicKey>,
    created: bool,
    deny_use: Rc<Cell<bool>>,
}
impl Authority for TestOnlyAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.binding != &self.binding || request.now != NOW || request.signing.is_some() {
            return Err(Error::Unauthorized);
        }
        // K1 S4 restore tests only: this device enrols one delegate and rotates it out,
        // which moves the scope to the next epoch root.
        if matches!(request.action, Action::DelegateDevice | Action::Rotate)
            && request.evidence == ROTATION_EVIDENCE
            && request.target.is_some()
            && Some(request.device) == self.device
        {
            return Ok(());
        }
        if request.target.is_some() {
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

// Real PRF/Keys/Memory store with actual KeyStore compare_exchange_wrapped.
// The create receipt is acknowledged here only as explicit local test setup.
async fn base() -> (TestVault, Rc<Cell<bool>>) {
    base_for(SCOPE, MEMBER, false).await
}
async fn base_for(scope: &str, member: &str, global: bool) -> (TestVault, Rc<Cell<bool>>) {
    base_with(scope, member, global, ckmg::SystemEntropy).await
}
async fn base_with<E: ckmg::Entropy>(
    scope: &str,
    member: &str,
    global: bool,
    entropy: E,
) -> (
    Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, ()>,
    Rc<Cell<bool>>,
) {
    use ckmg::passkey::PrfOutput;
    let prf = PrfOutput::from_bytes(&[7; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, scope).unwrap();
    let deny = Rc::new(Cell::new(false));
    let authority = TestOnlyAuthority {
        binding: Binding::new(scope, member).unwrap(),
        device: Some(device),
        created: false,
        deny_use: deny.clone(),
    };
    let cipher = store_cipher(&prf, scope).unwrap();
    let store = cwst::Store::create(Memory::new(), &cipher, scope)
        .await
        .unwrap();
    let mut vault = Vault::new(store, scope, Clock, entropy, authority, NoRecords, ()).unwrap();
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
            Binding::new(scope, member).unwrap(),
            DeviceInfo::new("fixture", b"fixture-credential").unwrap(),
            b"fixture-create",
        )
        .await
        .unwrap();
    drop(guard);
    let mutations = if global {
        let storage = vault.storage.clone();
        vec![
            crate::wallet::global::prepare_initial_passport(
                vault.keys(),
                &storage,
                &receipt,
                &mut StdRng::seed_from_u64(71),
            )
            .await
            .unwrap(),
        ]
    } else {
        vec![]
    };
    let guard = vault
        .stage_keys(Batch {
            expected: 1,
            operation: [62; 32],
            mutations,
            outputs: vec![],
        })
        .unwrap();
    vault.keys().acknowledge(receipt.operation).await.unwrap();
    drop(guard);
    (vault, deny)
}
// Both original sealed owners via original Durable constructors; pseudonym is the
// original CPSD value, never a hardcoded fabricated identity.
async fn seed_both<B: Backend, E: ckmg::Entropy>(
    vault: &mut Vault<B, Clock, E, TestOnlyAuthority, NoRecords, ()>,
) -> Pseudonym {
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let mut holder = vault
        .keys()
        .with_holder_seed(cwlt::PassportHolder::from_holder_seed)
        .await
        .unwrap()
        .unwrap();
    let engine = vault.keys().wallet_engine().await.unwrap();
    let before = holder.with_session(|s| s.pseudonym(&community));
    let mut rng = StdRng::seed_from_u64(7);
    let mut store = vault.storage().lock().await;
    cwlt::passport::DurableHolder::create(holder, &mut *store, SCOPE, [11; 32], &mut rng)
        .await
        .unwrap();
    cwlt::record::DurableRecord::create(engine, &mut *store, SCOPE, [12; 32])
        .await
        .unwrap();
    before
}
#[tokio::test]
async fn restore_opens_both_original_owners_with_stable_pseudonym() {
    let (mut vault, _) = base().await;
    let before = seed_both(&mut vault).await;
    let mut restored = vault.restore_wallet_custody().await.unwrap();
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let after = restored
        .with_wallet_custody(|passport, record, store| {
            let _ = std::mem::size_of_val(record);
            passport.session(store).unwrap().pseudonym(&community)
        })
        .await
        .unwrap();
    assert_eq!(before, after);
}
#[tokio::test]
async fn missing_owner_record_refuses() {
    let (vault, _) = base().await;
    assert!(matches!(
        vault.restore_wallet_custody().await,
        Err(WalletRestoreError::Passport(_))
    ));
}
#[tokio::test]
async fn wrong_owner_identity_refuses() {
    let (mut vault, _) = base().await;
    let engine = vault.keys().wallet_engine().await.unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let mut store = vault.storage().lock().await;
    cwlt::passport::DurableHolder::create(
        cwlt::PassportHolder::from_seed(&mut [99; 32]),
        &mut *store,
        SCOPE,
        [11; 32],
        &mut rng,
    )
    .await
    .unwrap();
    cwlt::record::DurableRecord::create(engine, &mut *store, SCOPE, [12; 32])
        .await
        .unwrap();
    drop(store);
    assert!(matches!(
        vault.restore_wallet_custody().await,
        Err(WalletRestoreError::Passport(_))
    ));
}
#[tokio::test]
async fn keys_authority_refusal_prevents_restore_and_callback() {
    let (mut vault, deny) = base().await;
    seed_both(&mut vault).await;
    deny.set(true);
    assert!(matches!(
        vault.restore_wallet_custody().await,
        Err(WalletRestoreError::Keys(_))
    ));
    let (mut vault, deny) = base().await;
    seed_both(&mut vault).await;
    let mut restored = vault.restore_wallet_custody().await.unwrap();
    deny.set(true);
    let called = Rc::new(Cell::new(false));
    let flag = called.clone();
    let refused = restored
        .with_wallet_custody(|_, _, _| {
            flag.set(true);
        })
        .await;
    assert_eq!(refused.unwrap_err(), Error::Unauthorized);
    assert!(!called.get());
}
// Original cancel path: pre-check Keys denial performs no Store mutation.
// Test-only authority stays setup-only/non-G3; it only admits the fixture binding.
#[tokio::test]
async fn cancel_precheck_denial_leaves_store_version_unchanged() {
    let (mut vault, deny) = base().await;
    seed_both(&mut vault).await;
    let mut vault = vault.restore_wallet_custody().await.unwrap();
    let before = vault.storage().lock().await.version().unwrap();
    deny.set(true);
    let mut rng = StdRng::seed_from_u64(21);
    assert!(matches!(
        vault.cancel_passport_issuance([21; 32], &mut rng).await,
        Err(WalletRestoreError::Keys(_))
    ));
    let after = vault.storage().lock().await.version().unwrap();
    assert_eq!(before, after);
}
// Successful cancellation commits the original sealed-holder state through the
// original Store CAS; the committed holder still opens with a stable pseudonym.
#[tokio::test]
async fn cancel_commits_original_sealed_holder_state() {
    let (mut vault, _) = base().await;
    let before_pseudonym = seed_both(&mut vault).await;
    let mut vault = vault.restore_wallet_custody().await.unwrap();
    let before = vault.storage().lock().await.version().unwrap();
    let mut rng = StdRng::seed_from_u64(22);
    vault
        .cancel_passport_issuance([22; 32], &mut rng)
        .await
        .unwrap();
    let after = vault.storage().lock().await.version().unwrap();
    assert_eq!(after, before + 1);
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let reopened = vault
        .with_wallet_custody(|passport, _, store| {
            passport.session(store).unwrap().pseudonym(&community)
        })
        .await
        .unwrap();
    assert_eq!(before_pseudonym, reopened);
}
// Test-only Backend that forwards the actual original Memory methods and flips
// the existing deny flag once after a successful CAS. No parallel Store.
#[derive(Clone)]
struct FlipDenyAfterCas {
    inner: Memory,
    deny: Rc<Cell<bool>>,
    armed: Rc<Cell<bool>>,
}
impl Backend for FlipDenyAfterCas {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.inner.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        let outcome = self.inner.compare_exchange(expected, next).await;
        if outcome.is_ok() && self.armed.get() {
            self.deny.set(true);
        }
        outcome
    }
}
type FlipVaultInit =
    Vault<FlipDenyAfterCas, Clock, ckmg::SystemEntropy, TestOnlyAuthority, NoRecords, ()>;
// Same fixture as base() but on the forwarding wrapper; armed only around cancel
// so setup CAS calls never flip the existing deny flag.
async fn flip_base() -> (FlipVaultInit, Rc<Cell<bool>>, Rc<Cell<bool>>) {
    use ckmg::passkey::PrfOutput;
    let prf = PrfOutput::from_bytes(&[7; 32]).unwrap();
    let device = ckmg::passkey::device_public_key(&prf, SCOPE).unwrap();
    let deny = Rc::new(Cell::new(false));
    let armed = Rc::new(Cell::new(false));
    let authority = TestOnlyAuthority {
        binding: Binding::new(SCOPE, MEMBER).unwrap(),
        device: Some(device),
        created: false,
        deny_use: deny.clone(),
    };
    let cipher = store_cipher(&prf, SCOPE).unwrap();
    let backend = FlipDenyAfterCas {
        inner: Memory::new(),
        deny: deny.clone(),
        armed: armed.clone(),
    };
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
    (vault, deny, armed)
}
// Post-commit Keys refusal suppresses the cancel output while the original
// commit stays durable: the wrapper flips deny after the CAS, so the second
// authority check fails but the Store version still advances.
#[tokio::test]
async fn cancel_post_commit_denial_suppresses_output_but_keeps_commit() {
    let (mut vault, deny, armed) = flip_base().await;
    seed_both(&mut vault).await;
    let mut vault = vault.restore_wallet_custody().await.unwrap();
    let before = vault.storage().lock().await.version().unwrap();
    armed.set(true);
    let mut rng = StdRng::seed_from_u64(23);
    assert!(matches!(
        vault.cancel_passport_issuance([23; 32], &mut rng).await,
        Err(WalletRestoreError::Keys(_))
    ));
    assert!(deny.get());
    let after = vault.storage().lock().await.version().unwrap();
    assert_eq!(after, before + 1);
}

// These exercise the production holder batch/restore composition against actual
// Keys/CWST/CPSD owners. The fixture authority above remains setup-only; global
// HTTPS/certificate/forced Tor qualification belongs to the integrated journey.
#[tokio::test]
async fn global_holder_initial_ack_and_restore_need_no_community_record() {
    let (vault, deny) = base_for("wallet", "fda91f17-ccbd-4f83-93f8-3beaf10dbd2b", true).await;
    assert_eq!(vault.storage().lock().await.version().unwrap(), 2);
    let mut vault = vault.restore_global_passport().await.unwrap();
    let community = CommunityId::new(b"alpha").unwrap();
    let original = vault
        .with_global_passport(|holder| {
            assert!(holder.attributes().is_none());
            holder.pseudonym(&community)
        })
        .await
        .unwrap();
    let mut rng = StdRng::seed_from_u64(73);
    vault
        .cancel_global_passport_issuance([73; 32], &mut rng)
        .await
        .unwrap();
    assert_eq!(
        vault
            .with_global_passport(|holder| holder.pseudonym(&community))
            .await
            .unwrap(),
        original
    );
    assert!(
        vault
            .with_global_passport(|_| {
                deny.set(true);
                "withheld presentation"
            })
            .await
            .is_err()
    );
    let called = Cell::new(false);
    assert!(
        vault
            .with_global_passport(|_| called.set(true))
            .await
            .is_err()
    );
    assert!(!called.get());
}

#[tokio::test]
async fn global_restore_refuses_absence_foreign_scope_and_wrong_holder() {
    let (vault, _) = base_for("wallet", "fda91f17-ccbd-4f83-93f8-3beaf10dbd2b", false).await;
    let storage = vault.storage.clone();
    let before = storage.lock().await.sealed_checkpoint().unwrap().to_vec();
    assert!(matches!(
        vault.restore_global_passport().await,
        Err(WalletRestoreError::Passport(_))
    ));
    assert_eq!(storage.lock().await.sealed_checkpoint().unwrap(), before);
    let (mut vault, _) = base().await;
    seed_both(&mut vault).await;
    assert!(matches!(
        vault.restore_global_passport().await,
        Err(WalletRestoreError::Scope)
    ));
    let (vault, _) = base_for("wallet", "fda91f17-ccbd-4f83-93f8-3beaf10dbd2b", false).await;
    cwlt::passport::DurableHolder::create(
        cwlt::PassportHolder::from_seed(&mut [99; 32]),
        &mut *vault.storage().lock().await,
        "wallet",
        [74; 32],
        &mut StdRng::seed_from_u64(74),
    )
    .await
    .unwrap();
    assert!(matches!(
        vault.restore_global_passport().await,
        Err(WalletRestoreError::Passport(_))
    ));
}

// K1 S4 (review B1): the PRODUCT restore path must reach the class R opening keys.
// A holder sealed under the pre-S4 identity key, or under an earlier epoch root,
// must restore with its pseudonym, and survive saves: each save reopens the stored
// ciphertext, and the first one reseals it under the current epoch's key.
const GLOBAL_MEMBER: &str = "fda91f17-ccbd-4f83-93f8-3beaf10dbd2b";
const HOLDER_OWNER: &str = "cwlt.passport";
const HOLDER_KEY: &[u8] = b"holder.v1";

/// Test-only deterministic Entropy: a byte counter. With it, `create_scope` draws the
/// same stable identity in a pre-S4 build (identity = epoch-1 root, one draw) and
/// in this build (identity first, then the independent epoch-1 root), so a holder
/// a pre-S4 build sealed for that identity belongs to this Vault's identity.
struct FixtureEntropy(u8);
impl ckmg::Entropy for FixtureEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// Put exact holder ciphertext as the committed passport owner record.
async fn put_holder<E: ckmg::Entropy>(
    vault: &Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, ()>,
    sealed: &[u8],
) {
    let mut store = vault.storage().lock().await;
    let base = store.version().unwrap();
    store
        .commit_with_receipt(
            base,
            [91; 32],
            &[cwst::Change::Put {
                owner: HOLDER_OWNER,
                key: HOLDER_KEY,
                value: sealed,
            }],
            &[],
        )
        .await
        .unwrap();
}

async fn staged<B: Backend, E: ckmg::Entropy, W, T>(
    vault: &mut Vault<B, Clock, E, TestOnlyAuthority, NoRecords, W>,
    operation: u8,
    change: impl AsyncFnOnce(&mut Vault<B, Clock, E, TestOnlyAuthority, NoRecords, W>) -> T,
) -> T {
    let expected = vault.storage().lock().await.version().unwrap();
    let guard = vault
        .stage_keys(Batch {
            expected,
            operation: [operation; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    let output = change(vault).await;
    drop(guard);
    output
}

/// The device enrols one delegate and rotates it out: the scope moves to epoch 2,
/// and this device is a survivor whose holder was sealed under the epoch-1 root.
async fn rotate_out_a_delegate<E: ckmg::Entropy, W>(
    vault: &mut Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, W>,
) {
    let (receipt, _) = staged(vault, 81, async |v| {
        v.keys()
            .delegate_device(&[], ROTATION_EVIDENCE)
            .await
            .unwrap()
    })
    .await;
    staged(vault, 82, async |v| {
        v.keys().acknowledge(receipt.operation).await.unwrap()
    })
    .await;
    let delegate = vault.keys().lineage().await.unwrap().delegates[0];
    vault
        .keys()
        .prepare_rotation(delegate, ROTATION_EVIDENCE)
        .await
        .unwrap();
    let receipt = staged(vault, 83, async |v| {
        v.keys().commit().await.unwrap().unwrap()
    })
    .await;
    staged(vault, 84, async |v| {
        v.keys().acknowledge(receipt.operation).await.unwrap()
    })
    .await;
    assert_eq!(vault.keys().lineage().await.unwrap().epoch, 2);
}

/// The pseudonym of the holder Keys initializes now (no stored state involved).
async fn fresh_pseudonym<E: ckmg::Entropy>(
    vault: &mut Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, ()>,
    community: &[u8],
) -> String {
    let community = CommunityId::new(community).unwrap();
    vault
        .keys()
        .with_holder_seed(cwlt::PassportHolder::from_holder_seed)
        .await
        .unwrap()
        .unwrap()
        .with_session(|s| s.pseudonym(&community))
        .to_hex()
}

/// Restore, read the pseudonym, save twice (cancel commits the holder), read again.
async fn restores_and_saves_community<E: ckmg::Entropy>(
    vault: Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, ()>,
    expected: &str,
) {
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let mut vault = vault.restore_wallet_custody().await.unwrap();
    for save in [25, 26] {
        let pseudonym = vault
            .with_wallet_custody(|passport, _, store| {
                passport.session(store).unwrap().pseudonym(&community)
            })
            .await
            .unwrap();
        assert_eq!(pseudonym.to_hex(), expected);
        vault
            .cancel_passport_issuance([save; 32], &mut StdRng::seed_from_u64(save.into()))
            .await
            .unwrap();
    }
}

async fn restores_and_saves_global<E: ckmg::Entropy>(
    vault: Vault<Memory, Clock, E, TestOnlyAuthority, NoRecords, ()>,
    expected: &str,
) {
    let community = CommunityId::new(b"alpha").unwrap();
    let mut vault = vault.restore_global_passport().await.unwrap();
    for save in [27, 28] {
        let pseudonym = vault
            .with_global_passport(|holder| holder.pseudonym(&community))
            .await
            .unwrap();
        assert_eq!(pseudonym.to_hex(), expected);
        vault
            .cancel_global_passport_issuance([save; 32], &mut StdRng::seed_from_u64(save.into()))
            .await
            .unwrap();
    }
}

// The fixtures are the exact holder owner records (`cwlt.passport`/`holder.v1`) a
// pre-S4 build wrote (cvlt 7b2cdb9 over ckmg cf4a1fb, generated in lane s4fixgen by
// `base_with(.., FixtureEntropy(1))` + `seed_both` for the community and
// `base_with("wallet", GLOBAL_MEMBER, true, FixtureEntropy(1))` for the global
// holder); the `.pseudonym` files hold the pseudonyms that build computed.
#[tokio::test]
async fn a_community_holder_a_pre_s4_build_sealed_under_the_identity_key_restores() {
    let (mut vault, _) = base_with(SCOPE, MEMBER, false, FixtureEntropy(1)).await;
    let expected = include_str!("fixtures/pre-s4-community.pseudonym");
    // Same identity as the pre-S4 build, so the fixture is this member's own holder.
    assert_eq!(
        fresh_pseudonym(&mut vault, SCOPE.as_bytes()).await,
        expected
    );
    seed_both(&mut vault).await;
    put_holder(&vault, include_bytes!("fixtures/pre-s4-community.holder")).await;
    restores_and_saves_community(vault, expected).await;
}

#[tokio::test]
async fn a_global_holder_a_pre_s4_build_sealed_under_the_identity_key_restores() {
    let (mut vault, _) = base_with("wallet", GLOBAL_MEMBER, true, FixtureEntropy(1)).await;
    let expected = include_str!("fixtures/pre-s4-global.pseudonym");
    assert_eq!(fresh_pseudonym(&mut vault, b"alpha").await, expected);
    put_holder(&vault, include_bytes!("fixtures/pre-s4-global.holder")).await;
    restores_and_saves_global(vault, expected).await;
}

#[tokio::test]
async fn a_community_holder_sealed_before_a_rotation_restores_on_the_surviving_device() {
    let (mut vault, _) = base().await;
    let before = seed_both(&mut vault).await.to_hex();
    rotate_out_a_delegate(&mut vault).await;
    restores_and_saves_community(vault, &before).await;
}

#[tokio::test]
async fn a_global_holder_sealed_before_a_rotation_restores_on_the_surviving_device() {
    let (mut vault, _) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let before = fresh_pseudonym(&mut vault, b"alpha").await;
    rotate_out_a_delegate(&mut vault).await;
    restores_and_saves_global(vault, &before).await;
}

// K1 S4 (review-s4b N1): a custody restored before a rotation holds the passport holder
// and the record engine bound to the pre-rotation epoch key, which the removed device
// still holds. Every save from it after the rotation is refused (`Rotated`), so the
// caller restores again and the next save seals under the current epoch's key.
fn record_epoch_descriptor() -> cwlt::record::Epoch {
    cwlt::record::Epoch {
        purpose: czkp::record::Purpose::RecordEpochV3,
        community: [1; 32],
        policy_epoch: 1,
        epoch: 18_000_000,
        starts_at: NOW - 10,
        expires_at: NOW + 90,
        root: [3; 32],
        issuer_key: [4; 32],
        proof_scope: czkp::ProofScope {
            circuit_digest: [5; 32],
            verifying_key_digest: [6; 32],
        },
        leaf_count: 2,
        download_digest: [7; 32],
        download_bytes: 64,
    }
}

#[tokio::test]
async fn a_community_custody_restored_before_a_rotation_refuses_every_save_after_it() {
    let (mut vault, _) = base().await;
    let before = seed_both(&mut vault).await.to_hex();
    let mut custody = vault.restore_wallet_custody().await.unwrap();
    // Saves before the rotation go through.
    custody
        .cancel_passport_issuance([31; 32], &mut StdRng::seed_from_u64(31))
        .await
        .unwrap();
    rotate_out_a_delegate(&mut custody).await;
    let version = custody.storage().lock().await.version().unwrap();
    assert!(matches!(
        custody
            .cancel_passport_issuance([32; 32], &mut StdRng::seed_from_u64(32))
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert!(matches!(
        custody
            .begin_record_epoch(&record_epoch_descriptor(), [8; 32], NOW, [33; 32])
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    // Nothing was written; reads still work.
    assert_eq!(custody.storage().lock().await.version().unwrap(), version);
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let pseudonym = custody
        .with_wallet_custody(|passport, _, store| {
            passport.session(store).unwrap().pseudonym(&community)
        })
        .await
        .unwrap();
    assert_eq!(pseudonym.to_hex(), before);
}

#[tokio::test]
async fn a_global_custody_restored_before_a_rotation_refuses_every_save_after_it() {
    let (vault, _) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let mut custody = vault.restore_global_passport().await.unwrap();
    custody
        .cancel_global_passport_issuance([34; 32], &mut StdRng::seed_from_u64(34))
        .await
        .unwrap();
    rotate_out_a_delegate(&mut custody).await;
    let version = custody.storage().lock().await.version().unwrap();
    assert!(matches!(
        custody
            .cancel_global_passport_issuance([35; 32], &mut StdRng::seed_from_u64(35))
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert_eq!(custody.storage().lock().await.version().unwrap(), version);
}

// L20261116a (owner, 2026-11-16): after a rotation the app reopens the custody itself.
// `reopen_after_rotation` re-opens the owners in place under the current epoch, so the
// next save seals under the new key; nothing the removed device holds can reopen.
#[tokio::test]
async fn a_community_custody_reopens_after_a_rotation_and_saves_under_the_new_epoch() {
    let (mut vault, _) = base().await;
    let before = seed_both(&mut vault).await.to_hex();
    let mut custody = vault.restore_wallet_custody().await.unwrap();
    rotate_out_a_delegate(&mut custody).await;
    assert!(matches!(
        custody
            .cancel_passport_issuance([36; 32], &mut StdRng::seed_from_u64(36))
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert!(custody.reopen_after_rotation().await.unwrap());
    custody
        .cancel_passport_issuance([37; 32], &mut StdRng::seed_from_u64(37))
        .await
        .unwrap();
    // The record save is past the epoch guard (the fixture record itself is not a valid one).
    assert!(!matches!(
        custody
            .begin_record_epoch(&record_epoch_descriptor(), [8; 32], NOW, [38; 32])
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    let community = CommunityId::new(SCOPE.as_bytes()).unwrap();
    let pseudonym = custody
        .with_wallet_custody(|passport, _, store| {
            passport.session(store).unwrap().pseudonym(&community)
        })
        .await
        .unwrap();
    assert_eq!(pseudonym.to_hex(), before);
}

#[tokio::test]
async fn a_global_custody_reopens_after_a_rotation_and_saves_under_the_new_epoch() {
    let (vault, _) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let mut custody = vault.restore_global_passport().await.unwrap();
    rotate_out_a_delegate(&mut custody).await;
    assert!(matches!(
        custody.with_global_passport(|_| ()).await,
        Err(WalletRestoreError::Rotated)
    ));
    assert!(custody.reopen_after_rotation().await.unwrap());
    custody.with_global_passport(|_| ()).await.unwrap();
    custody
        .cancel_global_passport_issuance([39; 32], &mut StdRng::seed_from_u64(39))
        .await
        .unwrap();
}

#[tokio::test]
async fn reopening_a_custody_that_did_not_rotate_changes_nothing() {
    let (mut vault, _) = base().await;
    seed_both(&mut vault).await;
    let mut custody = vault.restore_wallet_custody().await.unwrap();
    let version = custody.storage().lock().await.version().unwrap();
    assert!(!custody.reopen_after_rotation().await.unwrap());
    assert_eq!(custody.storage().lock().await.version().unwrap(), version);
    let (vault, _) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let mut global = vault.restore_global_passport().await.unwrap();
    let version = global.storage().lock().await.version().unwrap();
    assert!(!global.reopen_after_rotation().await.unwrap());
    assert_eq!(global.storage().lock().await.version().unwrap(), version);
}

#[tokio::test]
async fn a_device_without_current_authority_cannot_reopen_a_custody() {
    let (mut vault, deny) = base().await;
    seed_both(&mut vault).await;
    let mut custody = vault.restore_wallet_custody().await.unwrap();
    rotate_out_a_delegate(&mut custody).await;
    deny.set(true);
    assert!(matches!(
        custody.reopen_after_rotation().await,
        Err(WalletRestoreError::Keys(_))
    ));
    let (vault, deny) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let mut global = vault.restore_global_passport().await.unwrap();
    rotate_out_a_delegate(&mut global).await;
    deny.set(true);
    assert!(matches!(
        global.reopen_after_rotation().await,
        Err(WalletRestoreError::Keys(_))
    ));
}

// R1 (opus-review-custody): the member's community Vault is the ACCOUNT-ONLY custody (no
// passport; the record job fills the record slot at its first begin). Its reopen must
// open the account capsule and, once filled, the record owner, never a passport.
async fn account_only_custody()
-> Vault<Memory, Clock, ckmg::SystemEntropy, TestOnlyAuthority, NoRecords, super::WalletCustody> {
    let (mut vault, _) = base().await;
    let storage = vault.storage().clone();
    let engine = vault.keys().wallet_engine().await.unwrap();
    {
        let mut store = storage.lock().await;
        let mut pending =
            cwlt::account_owner::DurableAccountOwner::prepare(engine, &store, SCOPE, [85; 32])
                .unwrap();
        pending.commit(&mut store).await.unwrap();
    }
    vault.restore_account_only_custody().await.unwrap()
}

#[tokio::test]
async fn an_account_only_custody_reopens_after_a_rotation_keeping_its_record_owner() {
    let mut custody = account_only_custody().await;
    // The first begin fills the record slot (the fixture epoch itself is not provable).
    let _ = custody
        .begin_record_epoch(&record_epoch_descriptor(), [8; 32], NOW, [86; 32])
        .await;
    assert!(custody.wallet.record.is_some());
    rotate_out_a_delegate(&mut custody).await;
    assert!(matches!(
        custody
            .begin_record_epoch(&record_epoch_descriptor(), [8; 32], NOW, [87; 32])
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert!(custody.reopen_after_rotation().await.unwrap());
    assert!(custody.wallet.passport.is_none());
    assert!(custody.wallet.record.is_some());
    assert!(custody.wallet.account.is_some());
    // Past the epoch guard again: begin reaches the existing record owner (not `Scope`).
    assert!(!matches!(
        custody
            .begin_record_epoch(&record_epoch_descriptor(), [8; 32], NOW, [88; 32])
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert!(!matches!(custody.reopen_after_rotation().await, Ok(true)));
}

#[tokio::test]
async fn an_account_only_custody_without_a_record_owner_reopens_without_creating_one() {
    let mut custody = account_only_custody().await;
    rotate_out_a_delegate(&mut custody).await;
    assert!(custody.reopen_after_rotation().await.unwrap());
    assert!(custody.wallet.record.is_none());
    assert!(custody.wallet.account.is_some());
}

// Review D1: a rotation seen only AFTER a durable commit must not fail or repeat that write. The
// hook (wallet::ROTATE_AFTER_COMMIT) makes the custody's epoch stale between commit and check.
#[tokio::test]
async fn a_rotation_after_a_global_commit_returns_the_committed_result_and_reopens_next() {
    let (vault, _) = base_for("wallet", GLOBAL_MEMBER, true).await;
    let mut custody = vault.restore_global_passport().await.unwrap();
    let v0 = custody.storage().lock().await.version().unwrap();
    crate::wallet::ROTATE_AFTER_COMMIT.set(true);
    custody
        .cancel_global_passport_issuance([36; 32], &mut StdRng::seed_from_u64(36))
        .await
        .expect("the committed result is returned, not Rotated");
    assert!(
        !crate::wallet::ROTATE_AFTER_COMMIT.get(),
        "hook consumed once"
    );
    let v1 = custody.storage().lock().await.version().unwrap();
    assert_eq!(v1, v0 + 1, "exactly one write");
    // The next operation is refused BEFORE any write.
    assert!(matches!(
        custody
            .cancel_global_passport_issuance([37; 32], &mut StdRng::seed_from_u64(37))
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert_eq!(custody.storage().lock().await.version().unwrap(), v1);
    // It reopens, and then the same operation writes once under the current epoch.
    assert!(custody.reopen_after_rotation().await.unwrap());
    custody
        .cancel_global_passport_issuance([37; 32], &mut StdRng::seed_from_u64(37))
        .await
        .unwrap();
    assert_eq!(custody.storage().lock().await.version().unwrap(), v1 + 1);
}

#[tokio::test]
async fn a_rotation_after_a_community_commit_returns_the_committed_result_and_reopens_next() {
    let (mut vault, _) = base().await;
    seed_both(&mut vault).await;
    let mut custody = vault.restore_wallet_custody().await.unwrap();
    let v0 = custody.storage().lock().await.version().unwrap();
    crate::wallet::ROTATE_AFTER_COMMIT.set(true);
    custody
        .cancel_passport_issuance([38; 32], &mut StdRng::seed_from_u64(38))
        .await
        .expect("the committed result is returned, not Rotated");
    let v1 = custody.storage().lock().await.version().unwrap();
    assert_eq!(v1, v0 + 1, "exactly one write");
    assert!(matches!(
        custody
            .cancel_passport_issuance([39; 32], &mut StdRng::seed_from_u64(39))
            .await,
        Err(WalletRestoreError::Rotated)
    ));
    assert_eq!(custody.storage().lock().await.version().unwrap(), v1);
    assert!(custody.reopen_after_rotation().await.unwrap());
    custody
        .cancel_passport_issuance([39; 32], &mut StdRng::seed_from_u64(39))
        .await
        .unwrap();
    assert_eq!(custody.storage().lock().await.version().unwrap(), v1 + 1);
}
