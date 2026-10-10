//! Original Keys/Storage/CDHT execution; faults replace only local persistence.
//! Scoped authorization fixtures do not model production passkey/policy admission.
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
#[derive(Clone)]
struct Destination {
    memory: cwst::backend::Memory,
    mode: Rc<Cell<u8>>,
    writes: Rc<Cell<u32>>,
    read_gate: Rc<futures::lock::Mutex<()>>,
}
impl Destination {
    fn new() -> Self {
        Self {
            memory: cwst::backend::Memory::new(),
            mode: Rc::new(Cell::new(0)),
            writes: Rc::new(Cell::new(0)),
            read_gate: Rc::new(futures::lock::Mutex::new(())),
        }
    }
}
impl Backend for Destination {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        if self.mode.get() == 5 {
            let _held = self.read_gate.lock().await;
        }
        if self.mode.get() == 4 {
            return Err(cwst::Error::Storage);
        }
        self.memory.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        if self.mode.get() == 1 {
            futures::future::pending::<()>().await;
        }
        self.memory.compare_exchange(expected, next).await?;
        if self.mode.get() == 2 {
            futures::future::pending::<()>().await;
        }
        if self.mode.get() == 3 {
            return Err(cwst::Error::Uncertain);
        }
        Ok(())
    }
}
struct TestClock(u64);
impl Clock for TestClock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(self.0)
    }
}
struct UnavailableRecords;
impl Records for UnavailableRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> crate::RestoreLookup {
        crate::RestoreLookup::Unavailable
    }
}
struct CreateOnce {
    device: ckmg::PublicKey,
    consumed: Rc<Cell<bool>>,
}
impl Authority for CreateOnce {
    async fn check(&mut self, r: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if self.consumed.get()
            || r.action != ckmg::Action::Create
            || r.binding != &ckmg::Binding::new("garden", "original").unwrap()
            || r.device != self.device
            || r.root.is_some()
            || r.epoch != 0
            || r.target.is_some()
            || r.statement.is_some()
            || r.signing.is_some()
            || r.now != 10
            || r.evidence != b"original creation fixture"
        {
            return Err(ckmg::Error::Unauthorized);
        }
        self.consumed.set(true);
        Ok(())
    }
}
fn opening(byte: u8, scope: &str) -> PreparedOpen {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[byte; 32]).unwrap();
    let locator = ckmg::passkey::vault_location(&prf, scope).unwrap();
    PreparedOpen {
        prf,
        scope: scope.into(),
        locator,
    }
}
async fn create(
    destination: Destination,
    consumed: Rc<Cell<bool>>,
) -> Result<InitialCreation<Destination>, InitialError> {
    let input = opening(23, "garden");
    let device = input.device().unwrap();
    input
        .create_recoverable(
            destination,
            ckmg::Binding::new("garden", "original").unwrap(),
            ckmg::DeviceInfo::new("fixture", b"original passkey").unwrap(),
            b"original creation fixture",
            Batch {
                expected: 0,
                operation: [8; 32],
                mutations: vec![],
                outputs: vec![],
            },
            Owners {
                clock: TestClock(10),
                entropy: ckmg::SystemEntropy,
                authority: CreateOnce { device, consumed },
                records: UnavailableRecords,
                wallet: (),
            },
        )
        .await
}

shared!(
    initial_cas_retains_original_pending_keys_and_common_root_together,
    {
        let destination = Destination::new();
        let created = create(destination.clone(), Rc::new(Cell::new(false)))
            .await
            .unwrap();
        assert_eq!(destination.writes.get(), 1);
        assert_eq!(created.phase().unwrap(), InitialPhase::Pending);
        assert_eq!(initial_operation(&created.store).unwrap(), [8; 32]);
        let expected = created.receipt().clone();
        let keys = required(&created.store, KEYS).unwrap().to_vec();
        assert!(matches!(
            created.opening.inspector().unwrap().inspect(&keys),
            Err(ckmg::Error::Pending)
        ));
        drop(created);
        let reopened = opening(23, "garden")
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.receipt(), &expected);
        assert_eq!(required(&reopened.store, KEYS).unwrap(), keys);
        assert_eq!(destination.writes.get(), 1);
        assert!(
            opening(24, "garden")
                .reopen_initial(destination.clone())
                .await
                .is_err()
        );
        assert!(
            opening(23, "other")
                .reopen_initial(destination.clone())
                .await
                .is_err()
        );
        assert_eq!(destination.writes.get(), 1);
    }
);

shared!(
    initial_cancellation_distinguishes_before_and_after_durable_cas,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            destination.mode.set(mode);
            let consumed = Rc::new(Cell::new(false));
            let future = create(destination.clone(), consumed.clone());
            if mode == 3 {
                assert!(matches!(
                    future.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(future.now_or_never().is_none());
            }
            assert!(consumed.get());
            destination.mode.set(0);
            let reopened = opening(23, "garden")
                .reopen_initial(destination.clone())
                .await;
            if mode == 1 {
                assert!(matches!(
                    reopened,
                    Err(InitialError::Storage(cwst::Error::NotInitialized))
                ));
                // Original provenance was consumed with no durable pending state.
                // No restart/Create fallback is manufactured by reopen.
                assert!(destination.read().await.unwrap().is_none());
            } else {
                assert_eq!(reopened.unwrap().phase().unwrap(), InitialPhase::Pending);
            }
            assert_eq!(destination.writes.get(), 1);
        }
    }
);

shared!(
    absent_unknown_nonempty_and_oversized_are_not_replace_authority,
    {
        let destination = Destination::new();
        let consumed = Rc::new(Cell::new(false));
        destination.mode.set(4);
        assert!(matches!(
            create(destination.clone(), consumed.clone()).await,
            Err(InitialError::Storage(cwst::Error::Storage))
        ));
        assert!(!consumed.get());
        destination.mode.set(0);
        destination
            .memory
            .compare_exchange(None, b"unrecognized existing ciphertext")
            .await
            .unwrap();
        assert!(matches!(
            create(destination.clone(), consumed.clone()).await,
            Err(InitialError::Storage(cwst::Error::AlreadyInitialized))
        ));
        assert!(!consumed.get());
        assert_eq!(destination.writes.get(), 0);
        let input = opening(23, "garden");
        let cipher = ckmg::passkey::store_cipher(&input.prf, "garden").unwrap();
        let empty = Destination::new();
        assert!(matches!(
            install(
                BackendRef(Rc::new(empty.clone())),
                &cipher,
                "garden",
                [8; 32],
                &vec![1; cwst::MAX_VALUE_BYTES + 1],
                b"opaque pending"
            )
            .await,
            Err(InitialError::Storage(cwst::Error::TooLarge))
        ));
        assert_eq!(empty.writes.get(), 0);
    }
);

// Directly freeze the exact lower-owner test transcript. Public prepare uses
// original verified certificate/assertion packing; these unit tests isolate the
// real durable state machine and deliberately claim no production admission.
async fn prepared(mut created: InitialCreation<Destination>) -> InitialCreation<Destination> {
    let intent = Intent {
        nonce: [7; 24],
        packed_evidence: b"exact owner completion fixture".to_vec(),
        prepared_at: 10,
        expires: 30,
    };
    let bytes = serde_json::to_vec(&intent).unwrap();
    created
        .store
        .commit(
            1,
            *created.receipt().operation.as_bytes(),
            &[cwst::Change::Put {
                owner: OWNER,
                key: INTENT,
                value: &bytes,
            }],
            &[],
        )
        .await
        .unwrap();
    created
}
struct ExactCompletion {
    receipt: ckmg::Receipt,
    location: ckmg::Locator,
    keys: [u8; 32],
    outer: [u8; 32],
    inner: [u8; 32],
    asynchronous: bool,
    refuse_final: Rc<Cell<bool>>,
}
impl ExactCompletion {
    fn new(created: &InitialCreation<Destination>) -> Self {
        Self {
            receipt: created.receipt().clone(),
            location: created.opening.locator,
            keys: *created.pending.sealed_digest(),
            outer: *blake3::hash(created.store.sealed_checkpoint().unwrap()).as_bytes(),
            inner: *blake3::hash(required(&created.store, INNER).unwrap()).as_bytes(),
            asynchronous: false,
            refuse_final: Rc::new(Cell::new(false)),
        }
    }
    fn check_exact(&self, r: &ckmg::CompletionAuthorization<'_>) -> Result<(), ckmg::Error> {
        if r.receipt != &self.receipt
            || r.authority_reference != b"original passkey"
            || r.location != &self.location
            || r.sealed_digest != &self.keys
            || r.intent.outer_generation != 2
            || r.intent.outer_digest != self.outer
            || r.intent.inner_version != 1
            || r.intent.inner_operation != [8; 32]
            || r.intent.inner_digest != self.inner
            || r.intent.nonce != [7; 24]
            || r.intent.packed_evidence != b"exact owner completion fixture"
            || r.intent.prepared_at != 10
            || r.intent.expires != 30
            || r.now != 10
        {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(())
    }
}
impl Authority for ExactCompletion {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn check_completion(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.check_exact(&r)?;
        self.asynchronous = true;
        TestClock(10).now()
    }
    fn check_completion_current(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        let asynchronous = std::mem::take(&mut self.asynchronous);
        if self.refuse_final.get() || !asynchronous {
            return Err(ckmg::Error::Unauthorized);
        }
        self.check_exact(&r)?;
        TestClock(10).now()
    }
}

shared!(
    retained_genesis_is_original_signed_output_reopened_without_resigning,
    {
        let destination = Destination::new();
        let initial = prepared(
            create(destination.clone(), Rc::new(Cell::new(false)))
                .await
                .unwrap(),
        )
        .await;
        let mut authority = ExactCompletion::new(&initial);
        let retained = initial
            .retain(&mut TestClock(10), &mut authority)
            .await
            .unwrap();
        assert_eq!(retained.phase().unwrap(), InitialPhase::Retained);
        let output = retained.retained().unwrap();
        let descriptor = output.descriptor().to_vec();
        let value = output.value().to_vec();
        drop(retained);
        let reopened = opening(23, "garden")
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.retained().unwrap().descriptor(), descriptor);
        assert_eq!(reopened.retained().unwrap().value(), value);
        assert!(matches!(
            reopened.retain(&mut TestClock(10), &mut authority).await,
            Err(InitialError::Invalid)
        ));
        assert_eq!(destination.writes.get(), 3);
    }
);

shared!(
    unknown_signed_output_commit_reopens_only_the_exact_outbox,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let initial = prepared(
                create(destination.clone(), Rc::new(Cell::new(false)))
                    .await
                    .unwrap(),
            )
            .await;
            let mut authority = ExactCompletion::new(&initial);
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let completion = initial.retain(&mut clock, &mut authority);
            if mode == 3 {
                assert!(matches!(
                    completion.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(completion.now_or_never().is_none());
            }
            destination.mode.set(0);
            let reopened = opening(23, "garden")
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            if mode == 1 {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Prepared);
                let mut exact = ExactCompletion::new(&reopened);
                assert_eq!(
                    reopened
                        .retain(&mut TestClock(10), &mut exact)
                        .await
                        .unwrap()
                        .phase()
                        .unwrap(),
                    InitialPhase::Retained
                );
            } else {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Retained);
            }
        }
    }
);

shared!(reopen_does_not_renew_expired_or_regressed_frozen_intent, {
    let destination = Destination::new();
    drop(
        prepared(
            create(destination.clone(), Rc::new(Cell::new(false)))
                .await
                .unwrap(),
        )
        .await,
    );
    for now in [30, 9] {
        let initial = opening(23, "garden")
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let mut authority = ExactCompletion::new(&initial);
        let expected = if now == 30 {
            ckmg::Error::Expired
        } else {
            ckmg::Error::Clock
        };
        assert!(
            matches!(initial.retain(&mut TestClock(now), &mut authority).await,
            Err(InitialError::Keys(e)) if e == expected)
        );
        assert_eq!(destination.writes.get(), 2);
    }
    let initial = opening(23, "garden")
        .reopen_initial(destination.clone())
        .await
        .unwrap();
    let mut deny = CreateOnce {
        device: initial.opening.device().unwrap(),
        consumed: Rc::new(Cell::new(true)),
    };
    assert!(matches!(
        initial.retain(&mut TestClock(10), &mut deny).await,
        Err(InitialError::Keys(ckmg::Error::Unauthorized))
    ));
    assert_eq!(destination.writes.get(), 2);
});

struct SharedClock(Rc<Cell<u64>>);
impl Clock for SharedClock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(self.0.get())
    }
}

shared!(
    final_actual_backend_wait_rechecks_expiry_owner_and_exact_snapshot,
    {
        for failure in 0..4 {
            let destination = Destination::new();
            let initial = prepared(
                create(destination.clone(), Rc::new(Cell::new(false)))
                    .await
                    .unwrap(),
            )
            .await;
            let mut authority = ExactCompletion::new(&initial);
            let final_refusal = authority.refuse_final.clone();
            let time = Rc::new(Cell::new(10));
            let mut clock = SharedClock(time.clone());
            let held = destination.read_gate.lock().await;
            destination.mode.set(5);
            let mut attempt = Box::pin(initial.retain(&mut clock, &mut authority));
            assert!(attempt.as_mut().now_or_never().is_none());
            match failure {
                0 => time.set(30),
                1 => final_refusal.set(true),
                2 => {
                    let old = destination.memory.read().await.unwrap().unwrap();
                    destination
                        .memory
                        .compare_exchange(Some(&old), b"competing backend replacement")
                        .await
                        .unwrap();
                }
                3 => {
                    drop(attempt);
                    drop(held);
                    destination.mode.set(0);
                    assert_eq!(
                        opening(23, "garden")
                            .reopen_initial(destination.clone())
                            .await
                            .unwrap()
                            .phase()
                            .unwrap(),
                        InitialPhase::Prepared
                    );
                    assert_eq!(destination.writes.get(), 2);
                    continue;
                }
                _ => unreachable!(),
            }
            drop(held);
            let expected = match failure {
                0 => InitialError::Keys(ckmg::Error::Expired),
                1 => InitialError::Keys(ckmg::Error::Unauthorized),
                2 => InitialError::Storage(cwst::Error::Conflict),
                _ => unreachable!(),
            };
            assert!(matches!(attempt.await, Err(error) if error == expected));
            assert_eq!(destination.writes.get(), 2);
        }
    }
);
