//! Real encrypted storage composition. Unavailable G3/Records/Wallet stay unavailable.
use ckmg::{
    Commit, SecureStore,
    passkey::{PrfOutput, store_cipher, vault_location},
};
use cvlt::{Batch, Error, KeyStore, Mutation, shared_store};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
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
fn batch(version: u64, operation: u8) -> Batch {
    Batch {
        expected: version,
        operation: [operation; 32],
        mutations: vec![],
        outputs: vec![],
    }
}
shared!(keys_ciphertext_and_companions_commit_together, {
    let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
    let cipher = store_cipher(&prf, "garden").unwrap();
    let locator = vault_location(&prf, "garden").unwrap();
    let backend = cwst::backend::Memory::new();
    let storage = shared_store(
        cwst::Store::create(backend.clone(), &cipher, "garden")
            .await
            .unwrap(),
    );
    let mut keys = KeyStore::new(storage.clone(), "garden").unwrap();
    assert!(keys.load(&locator).await.unwrap().is_none());
    let replacement = cipher
        .seal(
            &mut ckmg::SystemEntropy,
            b"owner-payload",
            b"opaque sealed owner state",
        )
        .unwrap();
    assert_eq!(
        keys.compare_exchange(&locator, None, &replacement)
            .await
            .unwrap_err(),
        ckmg::Error::Unavailable
    );
    let mut combined = batch(0, 1);
    combined.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"accepted".to_vec(),
        value: Some(b"owner state".to_vec()),
    });
    combined.outputs.push(cwst::Output {
        id: [1; 32],
        bytes: replacement.clone(),
    });
    let armed = keys.stage(combined).unwrap();
    let mut other = keys.clone();
    assert!(matches!(other.stage(batch(0, 2)), Err(Error::Busy)));
    assert_eq!(
        keys.compare_exchange(&locator, None, &replacement)
            .await
            .unwrap(),
        Commit::Committed
    );
    assert!(matches!(other.stage(batch(1, 2)), Err(Error::Busy)));
    drop(armed);
    assert_eq!(keys.load(&locator).await.unwrap().unwrap(), replacement);
    {
        let store = storage.lock().await;
        assert_eq!(
            store.read("wallet", b"accepted").unwrap(),
            Some(b"owner state".as_slice())
        );
        assert_eq!(store.load_pending().unwrap()[0].bytes, replacement);
    }
    let mut deletion = batch(1, 2);
    deletion.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"accepted".to_vec(),
        value: None,
    });
    let armed = keys.stage(deletion).unwrap();
    assert_eq!(
        keys.compare_exchange(
            &locator,
            Some(*blake3::hash(&replacement).as_bytes()),
            &replacement
        )
        .await
        .unwrap(),
        Commit::Committed
    );
    drop(armed);
    let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
    assert!(reopened.read("wallet", b"accepted").unwrap().is_none());
    assert_eq!(
        reopened.read("keys", locator.as_bytes()).unwrap().unwrap(),
        replacement
    );
    assert_eq!(reopened.load_pending().unwrap()[0].bytes, replacement);
});
shared!(scope_versions_cancellation_and_reserved_owner_refuse, {
    use futures::FutureExt;
    let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
    let cipher = store_cipher(&prf, "garden").unwrap();
    let locator = vault_location(&prf, "garden").unwrap();
    let storage = shared_store(
        cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap(),
    );
    assert!(matches!(
        KeyStore::new(storage.clone(), ""),
        Err(Error::Scope)
    ));
    assert!(matches!(
        KeyStore::new(storage.clone(), &"s".repeat(257)),
        Err(Error::Scope)
    ));
    let mut wrong = KeyStore::new(storage.clone(), "other").unwrap();
    assert_eq!(
        wrong.load(&locator).await.unwrap_err(),
        ckmg::Error::Unauthorized
    );
    let _wrong = wrong.stage(batch(0, 1)).unwrap();
    assert_eq!(
        wrong
            .compare_exchange(&locator, None, b"ciphertext")
            .await
            .unwrap_err(),
        ckmg::Error::Unauthorized
    );
    let mut keys = KeyStore::new(storage.clone(), "garden").unwrap();
    assert!(matches!(keys.stage(batch(0, 0)), Err(Error::Invalid)));
    let mut reserved = batch(0, 1);
    reserved.mutations.push(Mutation {
        owner: "keys".into(),
        key: vec![1],
        value: None,
    });
    assert!(matches!(keys.stage(reserved), Err(Error::Invalid)));
    let armed = keys.stage(batch(0, 1)).unwrap();
    drop(armed);
    assert_eq!(
        keys.compare_exchange(&locator, None, b"ciphertext")
            .await
            .unwrap_err(),
        ckmg::Error::Unavailable
    );
    let armed = keys.stage(batch(0, 1)).unwrap();
    let held = storage.lock().await;
    assert!(
        keys.compare_exchange(&locator, None, b"ciphertext")
            .now_or_never()
            .is_none()
    );
    drop(held);
    drop(armed);
    assert!(keys.load(&locator).await.unwrap().is_none());
    let armed = keys.stage(batch(1, 1)).unwrap();
    assert_eq!(
        keys.compare_exchange(&locator, None, b"ciphertext")
            .await
            .unwrap(),
        Commit::Conflict
    );
    drop(armed);
    let armed = keys.stage(batch(0, 1)).unwrap();
    assert_eq!(
        keys.compare_exchange(&locator, Some([1; 32]), b"ciphertext")
            .await
            .unwrap(),
        Commit::Conflict
    );
    drop(armed);
    assert_eq!(
        keys.compare_exchange(&locator, None, &vec![0; ckmg::MAX_CHECKPOINT_BYTES + 1])
            .await
            .unwrap_err(),
        ckmg::Error::Limit
    );
    storage
        .lock()
        .await
        .commit(
            0,
            [9; 32],
            &[cwst::Change::Put {
                owner: "keys",
                key: locator.as_bytes(),
                value: &vec![0; ckmg::MAX_CHECKPOINT_BYTES + 1],
            }],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(keys.load(&locator).await.unwrap_err(), ckmg::Error::Limit);
});
struct UnavailableAuthority;
impl ckmg::Authority for UnavailableAuthority {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unavailable)
    }
}
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(1100)
    }
}
struct UnavailableRecords;
impl cvlt::Records for UnavailableRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
struct WalletNotIntegrated;
shared!(facade_lock_and_missing_records_never_mint_identity, {
    let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
    let cipher = store_cipher(&prf, "garden").unwrap();
    let locator = vault_location(&prf, "garden").unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    let mut vault = cvlt::Vault::new(
        store,
        "garden",
        Clock,
        ckmg::SystemEntropy,
        UnavailableAuthority,
        UnavailableRecords,
        WalletNotIntegrated,
    )
    .unwrap();
    assert_eq!(format!("{vault:?}"), "Vault([redacted])");
    assert_eq!(
        vault.keys().unlock(&prf, "garden").await.unwrap_err(),
        ckmg::Error::MissingCheckpoint
    );
    assert!(matches!(
        vault.restore_lookup(&locator).await,
        cvlt::RestoreLookup::Unavailable
    ));
    assert_eq!(vault.storage().lock().await.version().unwrap(), 0);
    let _wallet = vault.wallet();
    let armed = vault.stage_keys(batch(0, 1)).unwrap();
    drop(armed);
    let shared = vault.storage().clone();
    vault.lock().await;
    assert_eq!(
        shared.lock().await.version().unwrap_err(),
        cwst::Error::Locked
    );
    assert_eq!(
        format!("{:?}", cvlt::RestoreLookup::Present(vec![1])),
        "Present([redacted])"
    );
    assert_eq!(
        format!("{:?}", cvlt::RestoreLookup::KnownAbsent),
        "KnownAbsent"
    );
    assert_eq!(
        format!("{:?}", cvlt::RestoreLookup::Unavailable),
        "Unavailable"
    );
    assert_eq!(Error::Scope.to_string(), "vault: Scope");
});

#[derive(Clone)]
struct UncertainBackend {
    database: cwst::backend::Memory,
    fail: std::rc::Rc<std::cell::Cell<bool>>,
}
impl cwst::backend::Backend for UncertainBackend {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.database.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.database.compare_exchange(expected, next).await?;
        if self.fail.get() {
            Err(cwst::Error::Uncertain)
        } else {
            Ok(())
        }
    }
}
shared!(unknown_outcome_is_reconciled_and_locked_reads_refuse, {
    let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
    let cipher = store_cipher(&prf, "garden").unwrap();
    let locator = vault_location(&prf, "garden").unwrap();
    let fail = std::rc::Rc::new(std::cell::Cell::new(false));
    let backend = UncertainBackend {
        database: cwst::backend::Memory::new(),
        fail: fail.clone(),
    };
    let store = cwst::Store::create(backend.clone(), &cipher, "garden")
        .await
        .unwrap();
    assert!(matches!(
        cvlt::Vault::new(
            store,
            "wrong",
            Clock,
            ckmg::SystemEntropy,
            UnavailableAuthority,
            UnavailableRecords,
            WalletNotIntegrated
        ),
        Err(Error::Scope)
    ));
    let store = cwst::Store::open(backend.clone(), &cipher, "garden")
        .await
        .unwrap();
    let storage = shared_store(store);
    let mut keys = KeyStore::new(storage.clone(), "garden").unwrap();
    let replacement = cipher
        .seal(
            &mut ckmg::SystemEntropy,
            b"owner",
            b"opaque keys checkpoint",
        )
        .unwrap();
    let mut together = batch(0, 1);
    together.outputs.push(cwst::Output {
        id: [1; 32],
        bytes: replacement.clone(),
    });
    let armed = keys.stage(together).unwrap();
    fail.set(true);
    assert_eq!(
        keys.compare_exchange(&locator, None, &replacement)
            .await
            .unwrap(),
        Commit::Unknown
    );
    drop(armed);
    assert_eq!(
        keys.load(&locator).await.unwrap_err(),
        ckmg::Error::Unavailable
    );
    let armed = keys.stage(batch(0, 2)).unwrap();
    assert_eq!(
        keys.compare_exchange(&locator, None, &replacement)
            .await
            .unwrap_err(),
        ckmg::Error::Unavailable
    );
    drop(armed);
    fail.set(false);
    let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
    assert_eq!(reopened.operation().unwrap(), [1; 32]);
    assert_eq!(
        reopened.read("keys", locator.as_bytes()).unwrap().unwrap(),
        replacement
    );
    assert_eq!(reopened.load_pending().unwrap()[0].bytes, replacement);
});

// Link the maintained profiling runtime only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

#[cfg(feature = "passkeys")]
mod passkey_handover {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use cpky::{
        Client, Context, VaultOutcome,
        software::{SoftwareAuthenticator, TestConfiguration},
    };
    use cvlt::{PasskeyError, PasskeyUnlock};
    use serde_json::json;
    static_assertions::assert_not_impl_any!(PasskeyUnlock: std::fmt::Debug, Clone, serde::Serialize);
    const ORIGIN: &str = "https://vault.garden.example.com";
    const RP: &str = "garden.example.com";
    fn client() -> Client<SoftwareAuthenticator> {
        Client::new(
            Context::new(ORIGIN, RP).unwrap(),
            SoftwareAuthenticator::new(
                ORIGIN,
                TestConfiguration {
                    user_verified: true,
                    prf: true,
                    evaluate_at_create: false,
                },
            )
            .unwrap(),
        )
    }
    fn creation() -> serde_json::Value {
        json!({"publicKey":{
            "rp":{"id":RP,"name":"Synthetic community"},
            "user":{"id":URL_SAFE_NO_PAD.encode([17;16]),"name":"synthetic-member","displayName":"Test member"},
            "challenge":URL_SAFE_NO_PAD.encode([41;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required"},
            "timeout":42000,"excludeCredentials":[],"attestation":"none"
        }})
    }
    async fn sign_in(client: &mut Client<SoftwareAuthenticator>, scope: &str) -> PasskeyUnlock {
        let (_, outcome) = client.sign_in(json!({"publicKey":{"challenge":URL_SAFE_NO_PAD.encode([55;32]),"rpId":RP,"userVerification":"required","allowCredentials":[]}})).await.unwrap().into_parts();
        let VaultOutcome::Ready(secret) = outcome else {
            panic!("test authenticator PRF unavailable")
        };
        PasskeyUnlock::import(secret, scope).unwrap()
    }
    // Transport-layout qualification only: these opaque bytes do not claim a
    // verified common root or active-passkey G3. Production supplies the retained
    // Keys checkpoint from its actual committed outbox.
    #[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn native_root_staging_precedes_the_only_attach_attempt() {
        use std::{num::NonZeroUsize, time::Duration};
        let mut client = client();
        let (_, secret) = client
            .register_member(creation())
            .await
            .unwrap()
            .into_parts();
        let unlock = PasskeyUnlock::import(secret, "garden").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut config = cmsh::VeilidConfig::new(
            "vault_test",
            "staging",
            "org",
            Some(directory.path().to_str().unwrap()),
            None,
        );
        config.protected_store.always_use_insecure_storage = true;
        config.network.routing_table.bootstrap.clear();
        config.network.routing_table.bootstrap_keys.clear();
        let runtime = cmsh::VeilidRuntime::prepare(
            config,
            cmsh::VeilidLimits {
                queued_messages: NonZeroUsize::new(8).unwrap(),
                listeners: NonZeroUsize::new(2).unwrap(),
                deadline: Duration::from_secs(2),
            },
        )
        .await
        .unwrap();
        assert!(!runtime.ready().await.unwrap());
        let factory = runtime.records(NonZeroUsize::new(1).unwrap()).unwrap();
        let mut record = cvlt::PasskeyRecords::open(&unlock, &factory).await.unwrap();
        let wrapped = b"opaque retained checkpoint layout fixture";
        assert!(matches!(
            record.publish(7, wrapped).await.unwrap(),
            cdht::runtime::Publication::Queued
        ));
        assert!(matches!(
            record.publish(7, b"altered checkpoint").await.unwrap(),
            cdht::runtime::Publication::Conflict(_)
        ));
        assert!(matches!(
            record.publish(6, wrapped).await,
            Err(cvlt::RecordError::Invalid)
        ));
        record.close().await.unwrap();
        let unlock = sign_in(&mut client, "garden").await;
        let mut record = cvlt::PasskeyRecords::open(&unlock, &factory).await.unwrap();
        // Same passkey reopens the original full key/read custody and bytes.
        assert!(matches!(
            record.publish(7, wrapped).await.unwrap(),
            cdht::runtime::Publication::Queued
        ));
        // No bootstrap exists in this deliberately offline original-core fixture.
        // Once attach is attempted, the runtime must never reopen offline writes.
        assert!(runtime.attach().await.is_err());
        assert!(record.publish(8, wrapped).await.is_err());
        record.close().await.unwrap();
        runtime.shutdown().await;
    }

    shared!(
        maintained_passkey_opens_same_storage_after_device_restart,
        {
            let mut first = client();
            let (_, secret) = first
                .register_member(creation())
                .await
                .unwrap()
                .into_parts();
            let unlock = PasskeyUnlock::import(secret, "garden").unwrap();
            let backend = cwst::backend::Memory::new();
            assert!(matches!(
                unlock.open_storage(backend.clone()).await,
                Err(PasskeyError::Storage(cwst::Error::NotInitialized))
            ));
            let mut store = unlock.create_storage(backend.clone()).await.unwrap();
            assert!(matches!(
                unlock.create_storage(backend.clone()).await,
                Err(PasskeyError::Storage(cwst::Error::AlreadyInitialized))
            ));
            store
                .commit(
                    0,
                    [1; 32],
                    &[cwst::Change::Put {
                        owner: "history",
                        key: b"retained",
                        value: b"actual encrypted checkpoint",
                    }],
                    &[],
                )
                .await
                .unwrap();
            store.lock();
            drop(unlock);
            let authenticator = first.into_authenticator();
            let mut restarted = Client::new(
                Context::new(ORIGIN, RP).unwrap(),
                authenticator.synced_test_device(),
            );
            let unlock = sign_in(&mut restarted, "garden").await;
            let store = unlock.open_storage(backend.clone()).await.unwrap();
            assert_eq!(
                store.read("history", b"retained").unwrap(),
                Some(b"actual encrypted checkpoint".as_slice())
            );
            let mut vault = cvlt::Vault::new(
                store,
                "garden",
                Clock,
                ckmg::SystemEntropy,
                UnavailableAuthority,
                UnavailableRecords,
                WalletNotIntegrated,
            )
            .unwrap();
            // Storage continuity does not fabricate a Keys checkpoint or G3 authority.
            assert!(matches!(
                unlock.unlock(vault.keys()).await,
                Err(PasskeyError::Keys(ckmg::Error::MissingCheckpoint))
            ));
            let unlock = sign_in(&mut restarted, "garden").await;
            assert!(matches!(
                unlock
                    .create_scope(
                        vault.keys(),
                        ckmg::Binding::new("other", "member").unwrap(),
                        ckmg::DeviceInfo::new("test", b"credential").unwrap(),
                        b"unverified"
                    )
                    .await,
                Err(PasskeyError::Keys(ckmg::Error::Unauthorized))
            ));
            let unlock = sign_in(&mut restarted, "garden").await;
            assert!(matches!(
                unlock
                    .create_scope(
                        vault.keys(),
                        ckmg::Binding::new("garden", "member").unwrap(),
                        ckmg::DeviceInfo::new("test", b"credential").unwrap(),
                        b"unverified"
                    )
                    .await,
                Err(PasskeyError::Keys(ckmg::Error::Unavailable))
            ));
            let other_scope = sign_in(&mut restarted, "other").await;
            assert!(matches!(
                other_scope.open_storage(backend.clone()).await,
                Err(PasskeyError::Storage(cwst::Error::Unlock))
            ));
            let mut unrelated = client();
            let (_, secret) = unrelated
                .register_member(creation())
                .await
                .unwrap()
                .into_parts();
            let wrong_key = PasskeyUnlock::import(secret, "garden").unwrap();
            assert!(matches!(
                wrong_key.open_storage(backend).await,
                Err(PasskeyError::Storage(cwst::Error::Unlock))
            ));
            let (_, secret) = unrelated.sign_in(json!({"publicKey":{"challenge":URL_SAFE_NO_PAD.encode([56;32]),"rpId":RP,"userVerification":"required","allowCredentials":[]}})).await.unwrap().into_parts();
            let VaultOutcome::Ready(secret) = secret else {
                panic!("PRF unavailable")
            };
            assert!(matches!(
                PasskeyUnlock::import(secret, ""),
                Err(PasskeyError::Keys(_))
            ));
        }
    );
}

shared!(
    keys_reads_reenter_the_original_store_without_skipping_fences,
    {
        use futures::FutureExt;
        let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
        let cipher = store_cipher(&prf, "garden").unwrap();
        let locator = vault_location(&prf, "garden").unwrap();
        let backend = cwst::backend::Memory::new();
        let storage = shared_store(
            cwst::Store::create(backend, &cipher, "garden")
                .await
                .unwrap(),
        );
        let mut keys = KeyStore::new(storage.clone(), "garden").unwrap();
        let mut original = storage.lock().await;
        // Old KeyStore::load would remain Pending while this SAME guard is held.
        assert_eq!(keys.load(&locator).now_or_never(), Some(Ok(None)));
        original
            .commit(
                0,
                [1; 32],
                &[cwst::Change::Put {
                    owner: "keys",
                    key: locator.as_bytes(),
                    value: b"first committed ciphertext",
                }],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            keys.load(&locator).now_or_never(),
            Some(Ok(Some(b"first committed ciphertext".to_vec())))
        );
        original
            .commit(
                1,
                [2; 32],
                &[cwst::Change::Put {
                    owner: "keys",
                    key: locator.as_bytes(),
                    value: b"next committed ciphertext",
                }],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            keys.load(&locator).now_or_never(),
            Some(Ok(Some(b"next committed ciphertext".to_vec())))
        );
        original.lock_in_place();
        assert_eq!(
            keys.load(&locator).now_or_never(),
            Some(Err(ckmg::Error::Unavailable))
        );
    }
);
