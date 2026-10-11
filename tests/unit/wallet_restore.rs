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

// Real PRF/Keys/Memory store with actual KeyStore compare_exchange_wrapped.
// The create receipt is acknowledged here only as explicit local test setup.
async fn base() -> (TestVault, Rc<Cell<bool>>) {
    base_for(SCOPE, MEMBER, false).await
}
async fn base_for(scope: &str, member: &str, global: bool) -> (TestVault, Rc<Cell<bool>>) {
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
    let mut vault = Vault::new(
        store,
        scope,
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
async fn seed_both<B: Backend>(
    vault: &mut Vault<B, Clock, ckmg::SystemEntropy, TestOnlyAuthority, NoRecords, ()>,
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
