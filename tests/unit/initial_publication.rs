//! Actual Keys, encrypted Store, original queue and validating record backend.
//! Network faults are inert transport outcomes, not current-member authority.
use super::*;
use cdht::Backend as _;
use ed25519_dalek::{Digest, Sha512, SigningKey};

// Public fixture material only. Production still exposes no root signer.
struct FixtureEntropy;
impl Entropy for FixtureEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ckmg::Error> {
        bytes.fill(71);
        Ok(())
    }
}
struct FixtureSigner(SigningKey);
impl cdht::Signer for FixtureSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], cdht::Error> {
        self.0
            .sign_prehashed(Sha512::new().chain_update(bytes), Some(b"VLD0_SIGN"))
            .map(|signature| signature.to_bytes())
            .map_err(|_| cdht::Error::Signer)
    }
}

#[derive(Clone)]
struct PublicationBackend {
    records: cdht::LocalBackend<crate::records::tor::Verifier>,
    mode: Rc<Cell<u8>>,
    calls: Rc<Cell<u32>>,
}
impl PublicationBackend {
    fn new() -> Self {
        Self {
            records: cdht::LocalBackend::new(crate::records::tor::Verifier),
            mode: Rc::new(Cell::new(0)),
            calls: Rc::new(Cell::new(0)),
        }
    }
}
impl cdht::Backend for PublicationBackend {
    async fn create(&self, descriptor: &cdht::Descriptor) -> Result<(), cdht::Error> {
        self.calls.set(self.calls.get() + 1);
        self.records.create(descriptor).await
    }
    async fn descriptor(
        &self,
        key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        self.records.descriptor(key).await
    }
    async fn get(
        &self,
        key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        self.records.get(key, subkey).await
    }
    async fn set(
        &self,
        key: &cdht::RecordKey,
        subkey: u32,
        value: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        self.calls.set(self.calls.get() + 1);
        let outcome = self.records.set(key, subkey, value).await?;
        match self.mode.get() {
            1 => Err(cdht::Error::Unavailable),
            2 => futures::future::pending().await,
            _ => Ok(outcome),
        }
    }
    async fn watch(&self, key: &cdht::RecordKey) -> Result<cdht::WatchId, cdht::Error> {
        self.records.watch(key).await
    }
    async fn cancel_watch(&self, id: cdht::WatchId) -> Result<(), cdht::Error> {
        self.records.cancel_watch(id).await
    }
    async fn changes(&self, id: cdht::WatchId) -> Result<Vec<cdht::Change>, cdht::Error> {
        self.records.changes(id).await
    }
}

async fn retained(destination: Destination) -> InitialCreation<Destination> {
    let prepared = prepared(
        create(destination, Rc::new(Cell::new(false)))
            .await
            .unwrap(),
    )
    .await;
    let mut authority = ExactCompletion::new(&prepared);
    prepared
        .retain(&mut TestClock(10), &mut authority)
        .await
        .unwrap()
}

shared!(
    original_genesis_queue_commits_before_transport_and_reopens_exactly,
    {
        let destination = Destination::new();
        let records = PublicationBackend::new();
        let initial = retained(destination.clone()).await;
        let signed = initial.retained().unwrap();
        let descriptor = signed.descriptor.decode().unwrap();
        let value = signed.value.decode().unwrap();
        let staged = initial.stage(records.clone()).await.unwrap();
        assert_eq!(records.calls.get(), 0);
        assert_eq!(destination.writes.get(), 4);
        let committed = destination.memory.read().await.unwrap().unwrap();
        drop(staged);
        let reopened = opening(23, "garden")
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
        assert_eq!(reopened.store.load_pending().unwrap().len(), 2);
        let pending = reopened.staged_state().unwrap();
        assert_eq!(pending.queue().len(), 1);
        assert_eq!(pending.queue()[0].value, value);
        let (initial, report) = reopened
            .resume_publication(records.clone())
            .unwrap()
            .flush()
            .await
            .unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.remaining, 0);
        assert_eq!(initial.phase().unwrap(), InitialPhase::Staged);
        assert_eq!(initial.store.load_pending().unwrap().len(), 2);
        assert_eq!(initial.staged_state().unwrap(), pending);
        assert_eq!(destination.memory.read().await.unwrap(), Some(committed));
        assert_eq!(
            records.records.descriptor(&descriptor.key()).await.unwrap(),
            Some(descriptor.clone())
        );
        assert_eq!(
            records.records.get(&descriptor.key(), 0).await.unwrap(),
            Some(value)
        );
        // A successful transport reply is not an owner acknowledgment. Replay still
        // uses the same original durable queue, not a newly signed value.
        let (_, retried) = initial
            .resume_publication(records.clone())
            .unwrap()
            .flush()
            .await
            .unwrap();
        assert_eq!(retried.written, 1);
        assert_eq!(destination.writes.get(), 4);
    }
);

shared!(
    staging_cancellation_and_uncertain_cas_never_expose_transport,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let records = PublicationBackend::new();
            let initial = retained(destination.clone()).await;
            let original = initial.retained().unwrap();
            destination.mode.set(mode);
            let stage = initial.stage(records.clone());
            if mode == 3 {
                assert!(matches!(
                    stage.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(stage.now_or_never().is_none());
            }
            assert_eq!(records.calls.get(), 0);
            destination.mode.set(0);
            let reopened = opening(23, "garden")
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            assert_eq!(
                reopened.retained().unwrap().descriptor(),
                original.descriptor()
            );
            assert_eq!(reopened.retained().unwrap().value(), original.value());
            let staged = if mode == 1 {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Retained);
                reopened.stage(records.clone()).await.unwrap()
            } else {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
                reopened.resume_publication(records.clone()).unwrap()
            };
            assert_eq!(records.calls.get(), 0);
            assert_eq!(staged.flush().await.unwrap().1.written, 1);
        }
    }
);

shared!(
    lost_or_cancelled_transport_keeps_the_durable_original_queue,
    {
        for mode in [1, 2] {
            let destination = Destination::new();
            let records = PublicationBackend::new();
            let initial = retained(destination.clone()).await;
            let output = initial.retained().unwrap();
            let descriptor = output.descriptor.decode().unwrap();
            let value = output.value.decode().unwrap();
            let staged = initial.stage(records.clone()).await.unwrap();
            let committed = destination.memory.read().await.unwrap().unwrap();
            records.mode.set(mode);
            if mode == 1 {
                let (initial, report) = staged.flush().await.unwrap();
                assert_eq!(report.remaining, 1);
                assert_eq!(initial.phase().unwrap(), InitialPhase::Staged);
                drop(initial);
            } else {
                assert!(staged.flush().now_or_never().is_none());
            }
            assert_eq!(
                records.records.get(&descriptor.key(), 0).await.unwrap(),
                Some(value.clone())
            );
            assert_eq!(destination.memory.read().await.unwrap(), Some(committed));
            records.mode.set(0);
            let initial = opening(23, "garden")
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            assert_eq!(initial.staged_state().unwrap().queue()[0].value, value);
            let (_, report) = initial
                .resume_publication(records.clone())
                .unwrap()
                .flush()
                .await
                .unwrap();
            assert_eq!(report.written, 1);
            assert_eq!(destination.writes.get(), 4);
        }
    }
);

shared!(
    publication_refuses_changed_or_unknown_storage_before_any_transport,
    {
        for unknown in [false, true] {
            let destination = Destination::new();
            let records = PublicationBackend::new();
            let initial = retained(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let staged = initial.stage(records.clone()).await.unwrap();
            if unknown {
                destination.mode.set(4);
            } else {
                let current = destination.memory.read().await.unwrap().unwrap();
                destination
                    .memory
                    .compare_exchange(Some(&current), &old)
                    .await
                    .unwrap();
            }
            assert!(matches!(
                staged.flush().await,
                Err(InitialError::Storage(_))
            ));
            assert_eq!(records.calls.get(), 0);
        }
    }
);

shared!(
    authenticated_store_cannot_substitute_an_unrelated_publication_queue,
    {
        for case in 0..4 {
            let destination = Destination::new();
            let records = PublicationBackend::new();
            let mut initial = retained(destination.clone()).await;
            let output = initial.retained().unwrap();
            let descriptor = output.descriptor.decode().unwrap();
            let value = output.value.decode().unwrap();
            let mut client = cdht::Dht::new(records.clone(), crate::records::tor::Verifier);
            client.queue_original(&descriptor, 0, &value).unwrap();
            let mut state = serde_json::to_value(client.state()).unwrap();
            match case {
                0 => state["queue"] = serde_json::json!([]),
                1 => state["values"] = serde_json::json!({}),
                2 => state["queue"][0]["subkey"] = serde_json::json!(1),
                3 => state["descriptors"] = serde_json::json!({}),
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&state).unwrap();
            initial
                .store
                .commit(
                    3,
                    *initial.pending.receipt().operation.as_bytes(),
                    &[cwst::Change::Put {
                        owner: OWNER,
                        key: QUEUE,
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .unwrap();
            assert!(matches!(initial.phase(), Err(InitialError::Invalid)));
            drop(initial);
            assert!(matches!(
                opening(23, "garden").reopen_initial(destination).await,
                Err(InitialError::Invalid)
            ));
            assert_eq!(records.calls.get(), 0);
        }
    }
);

shared!(
    authenticated_conflicts_commit_terminal_original_state_and_never_revive,
    {
        for sequence in [0, 1] {
            for mode in [0, 1, 2, 3] {
                let destination = Destination::new();
                let records = PublicationBackend::new();
                let initial = prepared(
                    create_with_entropy(
                        destination.clone(),
                        Rc::new(Cell::new(false)),
                        FixtureEntropy,
                    )
                    .await
                    .unwrap(),
                )
                .await;
                let mut authority = ExactCompletion::new(&initial);
                let initial = initial
                    .retain(&mut TestClock(10), &mut authority)
                    .await
                    .unwrap();
                let original = initial.retained().unwrap();
                let descriptor = original.descriptor.decode().unwrap();
                let value = {
                    let signer = FixtureSigner(SigningKey::from_bytes(&[71; 32]));
                    assert_eq!(cdht::Signer::public_key(&signer), descriptor.owner);
                    cdht::SignedValue::sign_with_nonce(
                        &descriptor.owner,
                        0,
                        sequence,
                        b"another genuinely signed original owner value".to_vec(),
                        Some([99; 24]),
                        &signer,
                    )
                    .unwrap()
                };
                records.records.create(&descriptor).await.unwrap();
                records
                    .records
                    .set(&descriptor.key(), 0, &value)
                    .await
                    .unwrap();
                let staged = initial.stage(records.clone()).await.unwrap();
                destination.mode.set(mode);
                if mode == 0 {
                    let (conflicted, report) = staged.flush().await.unwrap();
                    assert_eq!(report.stale, vec![(descriptor.key(), 0)]);
                    assert_eq!(conflicted.phase().unwrap(), InitialPhase::Conflicted);
                    assert_eq!(conflicted.store.load_pending().unwrap().len(), 2);
                    assert!(matches!(
                        conflicted.resume_publication(records.clone()),
                        Err(InitialError::Invalid)
                    ));
                } else if mode == 3 {
                    assert!(matches!(
                        staged.flush().await,
                        Err(InitialError::Storage(cwst::Error::Uncertain))
                    ));
                } else {
                    assert!(staged.flush().now_or_never().is_none());
                }
                destination.mode.set(0);
                let mut reopened = opening(23, "garden")
                    .reopen_initial(destination.clone())
                    .await
                    .unwrap();
                if mode == 1 {
                    // The cancellation preceded durable conflict recording. It
                    // cannot claim memory of that lost observation. The next real
                    // backend outcome still fences the exact original obligation.
                    assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
                    reopened = reopened
                        .resume_publication(records.clone())
                        .unwrap()
                        .flush()
                        .await
                        .unwrap()
                        .0;
                }
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Conflicted);
                let state = reopened.conflicted_state().unwrap();
                let mut observed =
                    cdht::Dht::with_state(records.clone(), crate::records::tor::Verifier, state);
                assert_eq!(
                    observed
                        .get_signed_fresh(&descriptor.key(), 0)
                        .await
                        .unwrap(),
                    Some(value)
                );
                assert_eq!(
                    reopened.retained().unwrap().descriptor(),
                    original.descriptor()
                );
                assert_eq!(reopened.retained().unwrap().value(), original.value());
                let calls = records.calls.get();
                assert!(matches!(
                    reopened.resume_publication(records.clone()),
                    Err(InitialError::Invalid)
                ));
                assert_eq!(records.calls.get(), calls);
                // Even losing the network's newer holders cannot revive a locally
                // committed conflict into another publication attempt.
                let reopened = opening(23, "garden")
                    .reopen_initial(destination)
                    .await
                    .unwrap();
                assert!(matches!(
                    reopened.resume_publication(PublicationBackend::new()),
                    Err(InitialError::Invalid)
                ));
            }
        }
    }
);
