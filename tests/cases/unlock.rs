//! Unlock once (DESIGN-one-confirmation rule 5): ONE wallet passkey confirmation
//! opens the wallet vault and every community vault; a different passkey opens
//! nothing; a synced wallet passkey recovers every community root.
//! The ceremony count is structural: the passkey client is consumed after its one
//! sign-in, so no later step can ask for another confirmation.
use super::existing::{passkeys, unlock};
use cvlt::{Batch, Owners, PreparedOpen, WalletUnlock};
use cwst::backend::{Backend, Memory};

macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch = "wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}
/// (address, founding-key fingerprint): the fingerprint is the community's identity.
const COMMUNITIES: [(&str, [u8; 32]); 3] = [
    ("garden", [1; 32]),
    ("orchard", [2; 32]),
    ("meadow", [3; 32]),
];

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(10)
    }
}
struct NoRecords;
impl cvlt::Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
/// First creation only, for the exact device of the opening (test authority).
struct CreateOnly(ckmg::PublicKey);
impl ckmg::Authority for CreateOnly {
    async fn check(&mut self, r: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if r.action != ckmg::Action::Create || r.device != self.0 || r.root.is_some() {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}

/// Create one community vault from an opening; returns its attested lineage.
async fn create(opening: PreparedOpen, scope: &str, backend: Memory) -> ckmg::Lineage {
    let device = opening.device().unwrap();
    let created = opening
        .create_recoverable(
            backend,
            ckmg::Binding::new(scope, "member").unwrap(),
            ckmg::DeviceInfo::new("fixture", b"wallet passkey").unwrap(),
            b"unlock once fixture",
            Batch {
                expected: 0,
                operation: [8; 32],
                mutations: vec![],
                outputs: vec![],
            },
            Owners {
                clock: Clock,
                entropy: ckmg::SystemEntropy,
                authority: CreateOnly(device),
                records: NoRecords,
                wallet: (),
            },
        )
        .await
        .unwrap();
    created.receipt().attested_lineage().unwrap().0.clone()
}

/// The PRF-sealed checkpoint as the community's own records carry it to another device.
async fn copy(backend: &Memory) -> Memory {
    let bytes = backend.read().await.unwrap().expect("a created vault");
    let copy = Memory::new();
    copy.compare_exchange(None, &bytes).await.unwrap();
    copy
}

async fn reopen(opening: PreparedOpen, backend: Memory) -> Option<ckmg::Lineage> {
    let initial = opening.reopen_initial(backend).await.ok()?;
    Some(initial.receipt().attested_lineage().ok()?.0.clone())
}

shared!(one_confirmation_opens_the_wallet_and_every_community_vault, {
    let mut client = passkeys().await;
    let wallet = WalletUnlock::new(unlock(&mut client).await);
    drop(client); // the only confirmation of this app start
    let mut lineages = Vec::new();
    for (scope, id) in COMMUNITIES {
        let backend = Memory::new();
        let created = create(wallet.community(&id, scope).unwrap(), scope, backend.clone()).await;
        // The same unlock reopens it again, still without a ceremony.
        let again = reopen(wallet.community(&id, scope).unwrap(), backend).await;
        assert!(again == Some(created.clone()));
        lineages.push(created);
    }
    // Every community has its own device key and locator: nothing crosses scopes.
    let devices: std::collections::BTreeSet<_> = COMMUNITIES
        .iter()
        .map(|(scope, id)| *wallet.community(id, scope).unwrap().device().unwrap().value())
        .chain([*wallet.wallet().unwrap().device().unwrap().value()])
        .collect();
    assert_eq!(devices.len(), COMMUNITIES.len() + 1);
    let locators: std::collections::BTreeSet<_> = COMMUNITIES
        .iter()
        .map(|(scope, id)| *wallet.community(id, scope).unwrap().locator().as_bytes())
        .chain([*wallet.wallet().unwrap().locator().as_bytes()])
        .collect();
    assert_eq!(locators.len(), COMMUNITIES.len() + 1);
    assert!(lineages[0] != lineages[1]);
    // The wallet scope is not a community.
    assert!(wallet.community(&[9; 32], "wallet").is_err());
});

shared!(the_wallet_vault_keeps_the_direct_passkey_derivation, {
    let mut client = passkeys().await;
    let direct = PreparedOpen::new(unlock(&mut client).await, "wallet").unwrap();
    let once = WalletUnlock::new(unlock(&mut client).await).wallet().unwrap();
    assert_eq!(direct.locator().as_bytes(), once.locator().as_bytes());
    assert_eq!(direct.device().unwrap().value(), once.device().unwrap().value());
    // A community never opens with the raw wallet PRF derivation.
    let raw = PreparedOpen::new(unlock(&mut client).await, "garden").unwrap();
    let derived = WalletUnlock::new(unlock(&mut client).await)
        .community(&[1; 32], "garden")
        .unwrap();
    assert_ne!(raw.locator().as_bytes(), derived.locator().as_bytes());
    assert_ne!(raw.device().unwrap().value(), derived.device().unwrap().value());
});

shared!(a_different_wallet_passkey_opens_no_community_vault, {
    let mut owner = passkeys().await;
    let wallet = WalletUnlock::new(unlock(&mut owner).await);
    let mut stranger = passkeys().await;
    let wrong = WalletUnlock::new(unlock(&mut stranger).await);
    for (scope, id) in COMMUNITIES {
        let backend = Memory::new();
        create(wallet.community(&id, scope).unwrap(), scope, backend.clone()).await;
        let opening = wrong.community(&id, scope).unwrap();
        assert_ne!(
            opening.locator().as_bytes(),
            wallet.community(&id, scope).unwrap().locator().as_bytes()
        );
        assert!(reopen(opening, backend).await.is_none());
    }
});

shared!(a_synced_wallet_passkey_restores_every_community_root, {
    let platform = cpky::software::SoftwareAuthenticator::new(
        "https://members.example.com",
        cpky::software::TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap();
    let mut first = super::existing::registered(platform).await;
    let wallet = WalletUnlock::new(unlock(&mut first).await);
    let mut records = Vec::new();
    for (scope, id) in COMMUNITIES {
        let backend = Memory::new();
        let lineage = create(wallet.community(&id, scope).unwrap(), scope, backend.clone()).await;
        records.push((scope, id, copy(&backend).await, lineage));
    }
    // A new device: the provider syncs the same wallet passkey; ONE confirmation.
    let synced = first.into_authenticator().synced_test_device();
    let mut second = super::existing::client(synced);
    let restored = WalletUnlock::new(unlock(&mut second).await);
    drop(second);
    for (scope, id, record, lineage) in records {
        assert!(
            reopen(restored.community(&id, scope).unwrap(), record).await == Some(lineage),
            "{scope} restores its own roots"
        );
    }
});

shared!(a_new_community_at_a_reused_address_opens_nothing_of_the_old_one, {
    let mut client = passkeys().await;
    let wallet = WalletUnlock::new(unlock(&mut client).await);
    drop(client);
    // The old community at "garden" ended; a new one was founded at the same address.
    let (old, new) = ([1; 32], [4; 32]);
    let backend = Memory::new();
    let opening = wallet.community(&old, "garden").unwrap();
    let lineage = create(opening, "garden", backend.clone()).await;
    let reused = wallet.community(&new, "garden").unwrap();
    let previous = wallet.community(&old, "garden").unwrap();
    assert_ne!(reused.locator().as_bytes(), previous.locator().as_bytes());
    assert_ne!(reused.device().unwrap().value(), previous.device().unwrap().value());
    // The old community's vault does not open under the new identity ...
    assert!(reopen(reused, copy(&backend).await).await.is_none());
    // ... and still opens under its own.
    assert!(reopen(previous, backend).await == Some(lineage));
});
