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
