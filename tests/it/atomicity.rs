//! Atomicity of the vault composition: Keys ciphertext, companion owners,
//! and encrypted outbox commit or roll back together.
//!
//! These are opaque owner-composition fixtures only, using the real
//! `ckmg` StoreCipher and the real `cwst` encrypted checkpoint. They claim
//! no accepted MLS, wallet, or domain authority.

use ckmg::{
    Commit, SecureStore,
    passkey::{PrfOutput, store_cipher, vault_location},
};
use cvlt::{Batch, KeyStore, Mutation, shared_store};
use futures::FutureExt;
use std::{cell::Cell, rc::Rc};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn $name() {
            futures_executor::block_on(async $body);
        }
        #[cfg(target_arch = "wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}

const PASS: u8 = 0;
const BEFORE: u8 = 1;
const AFTER: u8 = 2;

#[derive(Clone)]
struct Gate {
    inner: cwst::backend::Memory,
    mode: Rc<Cell<u8>>,
    hits: Rc<Cell<u32>>,
}

impl cwst::backend::Backend for Gate {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.inner.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        if self.mode.get() == BEFORE {
            self.hits.set(self.hits.get() + 1);
            futures::future::pending::<()>().await;
        }
        self.inner.compare_exchange(expected, next).await?;
        if self.mode.get() == AFTER {
            self.hits.set(self.hits.get() + 1);
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
}

fn batch(version: u64, operation: u8) -> Batch {
    Batch {
        expected: version,
        operation: [operation; 32],
        mutations: vec![],
        outputs: vec![],
    }
}

shared!(
    cancellation_requires_reopen_to_determine_the_compound_outcome,
    {
        for phase in [BEFORE, AFTER] {
            let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
            let cipher = store_cipher(&prf, "garden").unwrap();
            let locator = vault_location(&prf, "garden").unwrap();
            let mode = Rc::new(Cell::new(PASS));
            let hits = Rc::new(Cell::new(0u32));
            let backend = Gate {
                inner: cwst::backend::Memory::new(),
                mode: mode.clone(),
                hits: hits.clone(),
            };
            let storage = shared_store(
                cwst::Store::create(backend.clone(), &cipher, "garden")
                    .await
                    .unwrap(),
            );
            let mut keys = KeyStore::new(storage.clone(), "garden").unwrap();

            let base_keys = cipher
                .seal(&mut ckmg::SystemEntropy, b"base-ad", b"base keys")
                .unwrap();
            let base_out = cipher
                .seal(&mut ckmg::SystemEntropy, b"base-out", b"base outbox")
                .unwrap();
            let mut base = batch(0, 1);
            base.mutations.push(Mutation {
                owner: "wallet".into(),
                key: b"base".to_vec(),
                value: Some(b"base owner".to_vec()),
            });
            base.outputs.push(cwst::Output {
                id: [1; 32],
                bytes: base_out.clone(),
            });
            let guard = keys.stage(base).unwrap();
            assert_eq!(
                keys.compare_exchange(&locator, None, &base_keys)
                    .await
                    .unwrap(),
                Commit::Committed
            );
            drop(guard);

            let next_keys = cipher
                .seal(&mut ckmg::SystemEntropy, b"next-ad", b"next keys")
                .unwrap();
            let next_out = cipher
                .seal(&mut ckmg::SystemEntropy, b"next-out", b"next outbox")
                .unwrap();
            let mut next = batch(1, 7);
            next.mutations.push(Mutation {
                owner: "wallet".into(),
                key: b"a".to_vec(),
                value: Some(b"a-next".to_vec()),
            });
            next.mutations.push(Mutation {
                owner: "notes".into(),
                key: b"k".to_vec(),
                value: Some(b"n-next".to_vec()),
            });
            next.outputs.push(cwst::Output {
                id: [7; 32],
                bytes: next_out.clone(),
            });
            let guard = keys.stage(next).unwrap();
            mode.set(phase);
            assert!(
                keys.compare_exchange(
                    &locator,
                    Some(*blake3::hash(&base_keys).as_bytes()),
                    &next_keys
                )
                .now_or_never()
                .is_none()
            );
            assert_eq!(hits.get(), 1);
            drop(guard);

            assert_eq!(
                storage.lock().await.version().unwrap_err(),
                cwst::Error::Locked
            );
            assert_eq!(
                keys.load(&locator).await.unwrap_err(),
                ckmg::Error::Unavailable
            );
            mode.set(PASS);
            let reopened = cwst::Store::open(backend.clone(), &cipher, "garden")
                .await
                .unwrap();
            let committed = phase == AFTER;
            assert_eq!(reopened.version().unwrap(), if committed { 2 } else { 1 });
            assert_eq!(
                reopened.operation().unwrap(),
                if committed { [7; 32] } else { [1; 32] }
            );
            assert_eq!(
                reopened.read("keys", locator.as_bytes()).unwrap().unwrap(),
                if committed { &next_keys } else { &base_keys }
            );
            assert_eq!(
                reopened.read("wallet", b"base").unwrap(),
                Some(b"base owner".as_slice())
            );
            assert_eq!(
                reopened.read("wallet", b"a").unwrap(),
                if committed {
                    Some(b"a-next".as_slice())
                } else {
                    None
                }
            );
            assert_eq!(
                reopened.read("notes", b"k").unwrap(),
                if committed {
                    Some(b"n-next".as_slice())
                } else {
                    None
                }
            );
            let pending = reopened.load_pending().unwrap();
            assert_eq!(pending.len(), if committed { 2 } else { 1 });
            assert_eq!(pending[0].id, [1; 32]);
            assert_eq!(pending[0].bytes, base_out);
            if committed {
                assert_eq!(pending[1].id, [7; 32]);
                assert_eq!(pending[1].bytes, next_out);
            }
        }
    }
);

shared!(stale_snapshot_conflict_keeps_winner_only, {
    let prf = PrfOutput::from_bytes(&[4; 32]).unwrap();
    let cipher = store_cipher(&prf, "garden").unwrap();
    let locator = vault_location(&prf, "garden").unwrap();
    let backend = cwst::backend::Memory::new();
    let storage_a = shared_store(
        cwst::Store::create(backend.clone(), &cipher, "garden")
            .await
            .unwrap(),
    );
    let storage_b = shared_store(
        cwst::Store::open(backend.clone(), &cipher, "garden")
            .await
            .unwrap(),
    );
    let mut a = KeyStore::new(storage_a.clone(), "garden").unwrap();
    let mut b = KeyStore::new(storage_b.clone(), "garden").unwrap();

    let keys_a = cipher
        .seal(&mut ckmg::SystemEntropy, b"a-ad", b"winner keys")
        .unwrap();
    let out_a = cipher
        .seal(&mut ckmg::SystemEntropy, b"a-out", b"winner outbox")
        .unwrap();
    let mut winner = batch(0, 11);
    winner.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"a".to_vec(),
        value: Some(b"a-winner".to_vec()),
    });
    winner.mutations.push(Mutation {
        owner: "notes".into(),
        key: b"k".to_vec(),
        value: Some(b"n-winner".to_vec()),
    });
    winner.outputs.push(cwst::Output {
        id: [11; 32],
        bytes: out_a.clone(),
    });
    let guard = a.stage(winner).unwrap();
    assert_eq!(
        a.compare_exchange(&locator, None, &keys_a).await.unwrap(),
        Commit::Committed
    );
    drop(guard);

    let keys_b = cipher
        .seal(&mut ckmg::SystemEntropy, b"b-ad", b"loser keys")
        .unwrap();
    let out_b = cipher
        .seal(&mut ckmg::SystemEntropy, b"b-out", b"loser outbox")
        .unwrap();
    let mut loser = batch(0, 22);
    loser.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"a".to_vec(),
        value: Some(b"a-loser".to_vec()),
    });
    loser.mutations.push(Mutation {
        owner: "notes".into(),
        key: b"k".to_vec(),
        value: Some(b"n-loser".to_vec()),
    });
    loser.outputs.push(cwst::Output {
        id: [22; 32],
        bytes: out_b.clone(),
    });
    let guard = b.stage(loser).unwrap();
    assert_eq!(
        b.compare_exchange(&locator, None, &keys_b).await.unwrap(),
        Commit::Conflict
    );
    drop(guard);
    assert_eq!(
        storage_b.lock().await.version().unwrap_err(),
        cwst::Error::Locked
    );
    assert_eq!(
        b.load(&locator).await.unwrap_err(),
        ckmg::Error::Unavailable
    );

    let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
    assert_eq!(reopened.version().unwrap(), 1);
    assert_eq!(reopened.operation().unwrap(), [11; 32]);
    assert_eq!(
        reopened.read("keys", locator.as_bytes()).unwrap().unwrap(),
        keys_a
    );
    assert_eq!(
        reopened.read("wallet", b"a").unwrap(),
        Some(b"a-winner".as_slice())
    );
    assert_eq!(
        reopened.read("notes", b"k").unwrap(),
        Some(b"n-winner".as_slice())
    );
    let pending = reopened.load_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, [11; 32]);
    assert_eq!(pending[0].bytes, out_a);
    assert_ne!(keys_a, keys_b);
    assert_ne!(out_a, out_b);
});

shared!(invalid_companion_refuses_entire_transaction, {
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

    let base_keys = cipher
        .seal(&mut ckmg::SystemEntropy, b"base-ad", b"base keys")
        .unwrap();
    let base_out = cipher
        .seal(&mut ckmg::SystemEntropy, b"base-out", b"base outbox")
        .unwrap();
    let mut base = batch(0, 3);
    base.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"keep".to_vec(),
        value: Some(b"keep-v".to_vec()),
    });
    base.outputs.push(cwst::Output {
        id: [3; 32],
        bytes: base_out.clone(),
    });
    let guard = keys.stage(base).unwrap();
    assert_eq!(
        keys.compare_exchange(&locator, None, &base_keys)
            .await
            .unwrap(),
        Commit::Committed
    );
    drop(guard);

    let next_keys = cipher
        .seal(&mut ckmg::SystemEntropy, b"next-ad", b"next keys")
        .unwrap();
    let next_out = cipher
        .seal(&mut ckmg::SystemEntropy, b"next-out", b"next outbox")
        .unwrap();
    let mut bad = batch(1, 5);
    bad.mutations.push(Mutation {
        owner: "wallet".into(),
        key: b"good".to_vec(),
        value: Some(b"good-v".to_vec()),
    });
    bad.mutations.push(Mutation {
        owner: "wallet".into(),
        key: vec![],
        value: Some(b"invalid never commits".to_vec()),
    });
    bad.outputs.push(cwst::Output {
        id: [5; 32],
        bytes: next_out.clone(),
    });
    let guard = keys.stage(bad).unwrap();
    assert_eq!(
        keys.compare_exchange(
            &locator,
            Some(*blake3::hash(&base_keys).as_bytes()),
            &next_keys
        )
        .await
        .unwrap(),
        Commit::Unknown
    );
    drop(guard);

    let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
    assert_eq!(reopened.version().unwrap(), 1);
    assert_eq!(reopened.operation().unwrap(), [3; 32]);
    assert_eq!(
        reopened.read("keys", locator.as_bytes()).unwrap().unwrap(),
        base_keys
    );
    assert_eq!(
        reopened.read("wallet", b"keep").unwrap(),
        Some(b"keep-v".as_slice())
    );
    assert!(reopened.read("wallet", b"good").unwrap().is_none());
    let pending = reopened.load_pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, [3; 32]);
    assert_eq!(pending[0].bytes, base_out);
    assert_ne!(pending[0].bytes, next_out);
});

// Link the maintained profiling runtime into this instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}
