//! Actual encrypted Store preparation and empty-destination CAS, with transport
//! faults around the original backend only. No authority success is synthesized.
use super::*;
use futures::FutureExt;
use std::cell::Cell;

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

const PASS: u8 = 0;
const BEFORE: u8 = 1;
const AFTER: u8 = 2;
const UNKNOWN: u8 = 3;
const READ_FAILURE: u8 = 4;
const HELD: u8 = 5;

#[derive(Clone)]
struct Gate {
    inner: cwst::backend::Memory,
    mode: Rc<Cell<u8>>,
    writes: Rc<Cell<u32>>,
    gate: Rc<futures::lock::Mutex<()>>,
}
impl Gate {
    fn new(mode: u8) -> Self {
        Self {
            inner: cwst::backend::Memory::new(),
            mode: Rc::new(Cell::new(mode)),
            writes: Rc::new(Cell::new(0)),
            gate: Rc::new(futures::lock::Mutex::new(())),
        }
    }
}
impl Backend for Gate {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        if self.mode.get() == READ_FAILURE {
            return Err(cwst::Error::Storage);
        }
        self.inner.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        if self.mode.get() == BEFORE {
            futures::future::pending::<()>().await;
        }
        if self.mode.get() == HELD {
            let _held = self.gate.lock().await;
        }
        self.inner.compare_exchange(expected, next).await?;
        if self.mode.get() == AFTER {
            futures::future::pending::<()>().await;
        }
        if self.mode.get() == UNKNOWN {
            return Err(cwst::Error::Uncertain);
        }
        Ok(())
    }
}
fn input() -> (
    ckmg::passkey::PrfOutput,
    ckmg::passkey::StoreCipher,
    Locator,
) {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[23; 32]).unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, "garden").unwrap();
    let locator = ckmg::passkey::vault_location(&prf, "garden").unwrap();
    (prf, cipher, locator)
}
fn batch() -> Batch {
    Batch {
        expected: 0,
        operation: [8; 32],
        mutations: vec![Mutation {
            owner: "companion".into(),
            key: b"one".to_vec(),
            value: Some(b"opaque owner".to_vec()),
        }],
        outputs: vec![cwst::Output {
            id: [9; 32],
            bytes: b"retained encrypted output".to_vec(),
        }],
    }
}

shared!(
    initial_store_publishes_keys_and_companions_in_one_actual_cas,
    {
        let (_, cipher, locator) = input();
        let backend = Gate::new(PASS);
        let mut adapter = KeyStore::initial(backend.clone(), "garden").unwrap();
        assert_eq!(adapter.load(&locator).await.unwrap(), None);
        assert_eq!(backend.writes.get(), 0);
        let _guard = adapter.stage(batch()).unwrap();
        assert_eq!(
            adapter
                .compare_exchange_wrapped(&locator, None, b"opaque Keys checkpoint", &cipher)
                .await
                .unwrap(),
            Commit::Committed
        );
        assert_eq!(backend.writes.get(), 1);
        let ready = adapter.ready().await.unwrap();
        let store = ready.lock().await;
        assert_eq!(store.version().unwrap(), 1);
        assert_eq!(store.operation().unwrap(), [8; 32]);
        assert_eq!(
            store.read("keys", locator.as_bytes()).unwrap(),
            Some(b"opaque Keys checkpoint".as_slice())
        );
        assert_eq!(
            store.read("companion", b"one").unwrap(),
            Some(b"opaque owner".as_slice())
        );
        assert_eq!(store.load_pending().unwrap().len(), 1);
        assert_eq!(
            backend.inner.read().await.unwrap().as_deref(),
            Some(store.sealed_checkpoint().unwrap())
        );
    }
);

shared!(
    initial_cancellation_and_uncertainty_never_report_or_retry_creation,
    {
        for phase in [BEFORE, AFTER, UNKNOWN] {
            let (_, cipher, locator) = input();
            let backend = Gate::new(phase);
            let mut adapter = KeyStore::initial(backend.clone(), "garden").unwrap();
            let guard = adapter.stage(batch()).unwrap();
            let mut commit =
                Box::pin(adapter.compare_exchange_wrapped(&locator, None, b"exact Keys", &cipher));
            if phase == UNKNOWN {
                assert_eq!(commit.await.unwrap(), Commit::Unknown);
            } else {
                assert!(commit.as_mut().now_or_never().is_none());
                drop(commit);
            }
            drop(guard);
            assert!(matches!(adapter.ready().await, Err(ckmg::Error::Reconcile)));
            assert_eq!(adapter.load(&locator).await, Err(ckmg::Error::Reconcile));
            let _retry = adapter.stage(batch()).unwrap();
            assert_eq!(
                adapter
                    .compare_exchange_wrapped(&locator, None, b"replacement root", &cipher)
                    .await,
                Err(ckmg::Error::Reconcile)
            );
            assert_eq!(backend.writes.get(), 1);
            backend.mode.set(PASS);
            if phase == BEFORE {
                assert!(backend.read().await.unwrap().is_none());
            } else {
                let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
                assert_eq!(
                    reopened.read("keys", locator.as_bytes()).unwrap(),
                    Some(b"exact Keys".as_slice())
                );
                assert_eq!(reopened.operation().unwrap(), [8; 32]);
            }
        }
    }
);

shared!(
    durable_before_ready_cancellation_preserves_exact_checkpoint_without_acceptance,
    {
        let (_, cipher, locator) = input();
        let backend = Gate::new(HELD);
        let mut adapter = KeyStore::initial(backend.clone(), "garden").unwrap();
        let _guard = adapter.stage(batch()).unwrap();
        let backing = adapter.backing.clone();
        let network_wait = backend.gate.lock().await;
        let mut commit =
            Box::pin(adapter.compare_exchange_wrapped(&locator, None, b"exact Keys", &cipher));
        assert!(commit.as_mut().now_or_never().is_none());
        let publish_wait = backing.lock().await;
        drop(network_wait);
        // The durable CAS has completed; only installing Ready remains pending.
        assert!(commit.as_mut().now_or_never().is_none());
        assert!(backend.read().await.unwrap().is_some());
        drop(commit);
        drop(publish_wait);
        assert!(matches!(adapter.ready().await, Err(ckmg::Error::Reconcile)));
        let reopened = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
        assert_eq!(
            reopened.read("keys", locator.as_bytes()).unwrap(),
            Some(b"exact Keys".as_slice())
        );
        assert_eq!(reopened.operation().unwrap(), [8; 32]);
    }
);

shared!(
    initial_reads_never_infer_absence_and_competing_destination_is_preserved,
    {
        let (_, cipher, locator) = input();
        let backend = Gate::new(READ_FAILURE);
        let mut adapter = KeyStore::initial(backend.clone(), "garden").unwrap();
        assert_eq!(adapter.load(&locator).await, Err(ckmg::Error::Unavailable));
        assert_eq!(backend.writes.get(), 0);
        backend.mode.set(PASS);
        let original = cwst::Store::create(backend.clone(), &cipher, "garden")
            .await
            .unwrap();
        let wire = original.sealed_checkpoint().unwrap().to_vec();
        assert_eq!(adapter.load(&locator).await, Err(ckmg::Error::RootExists));
        let _guard = adapter.stage(batch()).unwrap();
        assert_eq!(
            adapter
                .compare_exchange_wrapped(&locator, None, b"new root", &cipher)
                .await
                .unwrap(),
            Commit::Conflict
        );
        assert_eq!(backend.read().await.unwrap(), Some(wire));
        assert!(matches!(adapter.ready().await, Err(ckmg::Error::Reconcile)));
    }
);

shared!(
    initial_install_checks_original_scope_version_operation_and_exact_keys,
    {
        for wrong in 0..5 {
            let (_, cipher, locator) = input();
            let scope = if wrong == 0 { "other" } else { "garden" };
            let mut candidate = cwst::Store::create(cwst::backend::Memory::new(), &cipher, scope)
                .await
                .unwrap();
            let operation = if wrong == 2 { [6; 32] } else { [8; 32] };
            let value = if wrong == 3 {
                b"wrong Keys".as_slice()
            } else {
                b"exact Keys".as_slice()
            };
            candidate
                .commit(
                    0,
                    operation,
                    &[cwst::Change::Put {
                        owner: "keys",
                        key: locator.as_bytes(),
                        value,
                    }],
                    &[],
                )
                .await
                .unwrap();
            if wrong == 1 {
                candidate.commit(1, [8; 32], &[], &[]).await.unwrap();
            }
            let mut wire = candidate.sealed_checkpoint().unwrap().to_vec();
            if wrong == 4 {
                let last = wire.len() - 1;
                wire[last] ^= 1;
            }
            let backend = Gate::new(PASS);
            assert!(
                install_initial(
                    backend.clone(),
                    &cipher,
                    "garden",
                    &locator,
                    b"exact Keys",
                    [8; 32],
                    &wire
                )
                .await
                .is_err()
            );
            assert_eq!(backend.writes.get(), 0);
            assert!(backend.read().await.unwrap().is_none());
        }
    }
);

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(10)
    }
}
// Exact single original Create input only. No Use, restore, certificate,
// record currentness or publication authority is provided by this fixture.
struct CreateOnce {
    binding: ckmg::Binding,
    device: ckmg::PublicKey,
    spent: bool,
}
impl ckmg::Authority for CreateOnce {
    async fn check(&mut self, input: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if self.spent
            || input.action != ckmg::Action::Create
            || input.binding != &self.binding
            || input.device != self.device
            || input.root.is_some()
            || input.epoch != 0
            || input.target.is_some()
            || input.statement.is_some()
            || input.signing.is_some()
            || input.now != 10
            || input.evidence != b"exact original create fixture"
        {
            return Err(ckmg::Error::Unauthorized);
        }
        self.spent = true;
        Ok(())
    }
}
shared!(
    real_keys_create_uses_its_common_root_wrapper_and_keeps_receipt_pending,
    {
        let (prf, prf_cipher, locator) = input();
        let backend = Gate::new(PASS);
        let mut adapter = KeyStore::initial(backend.clone(), "garden").unwrap();
        let _guard = adapter.stage(batch()).unwrap();
        let binding = ckmg::Binding::new("garden", "fixture").unwrap();
        let authority = CreateOnce {
            binding: binding.clone(),
            device: ckmg::passkey::device_public_key(&prf, "garden").unwrap(),
            spent: false,
        };
        let mut keys = ckmg::Keys::new(adapter.clone(), Clock, ckmg::SystemEntropy, authority);
        let receipt = keys
            .create_scope(
                &prf,
                binding,
                ckmg::DeviceInfo::new("fixture", b"fixture credential").unwrap(),
                b"exact original create fixture",
            )
            .await
            .unwrap();
        let ckmg::Change::Created(lineage) = &receipt.change else {
            panic!("original creation receipt required")
        };
        assert_eq!(lineage.epoch, 1);
        assert_eq!(backend.writes.get(), 1);
        let ready = adapter.ready().await.unwrap();
        let store = ready.lock().await;
        let sealed = store.read("keys", locator.as_bytes()).unwrap().unwrap();
        assert!(matches!(
            ckmg::inspect_checkpoint(&prf, "garden", sealed),
            Err(ckmg::Error::Pending)
        ));
        assert_eq!(keys.pending_output().await.unwrap(), Some(receipt));
        assert_eq!(store.version().unwrap(), 1);
        // The initial compound Store is common-root wrapped: the old PRF-only
        // wrapper cannot open it. Keys' exact pending receipt has not been acked.
        assert!(matches!(
            cwst::Store::open(backend.clone(), &prf_cipher, "garden").await,
            Err(cwst::Error::Unlock)
        ));
        assert_eq!(keys.lineage().await, Err(ckmg::Error::Unauthorized));
        assert_eq!(backend.writes.get(), 1);
    }
);
