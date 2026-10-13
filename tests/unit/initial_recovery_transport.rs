//! Actual five independent validating nodes and original one-output stepping.
//! This exercises transport/persistence boundaries, never Vault readiness.
use super::*;

#[path = "initial_recovery_retirement.rs"]
mod retirement_tests;

#[derive(Clone)]
struct Transport {
    core: Network,
    calls: Rc<Cell<u32>>,
    mode: Rc<Cell<u8>>,
    gate: Rc<futures::lock::Mutex<()>>,
}
impl Transport {
    async fn new(network: &Network, initial: &InitialCreation<Destination>) -> Self {
        let retained = initial.retained().unwrap();
        let descriptor = retained.descriptor.decode().unwrap();
        let value = retained.value.decode().unwrap();
        let mut nodes = network.nodes.iter().cloned().collect::<Vec<_>>();
        for index in nodes.len()..cdht::SET_VALUE_COUNT {
            let node = cdht::LocalBackend::new(crate::records::tor::Verifier);
            node.create(&descriptor).await.unwrap();
            node.set(&descriptor.key(), 0, &value).await.unwrap();
            nodes.push(([(index + 1) as u8; 32], node));
        }
        Self {
            core: Network {
                candidates: Rc::new(nodes.iter().map(|(id, _)| *id).collect()),
                nodes: Rc::new(nodes),
                gets: network.gets.clone(),
                sets: Rc::new(Cell::new(0)),
                unavailable: network.unavailable.clone(),
                gate: network.gate.clone(),
            },
            calls: Rc::new(Cell::new(0)),
            mode: Rc::new(Cell::new(0)),
            gate: Rc::new(futures::lock::Mutex::new(())),
        }
    }
}
impl cdht::Network for Transport {
    fn now_ms(&self) -> u64 {
        cdht::Network::now_ms(&self.core)
    }
    async fn closest(&self, key: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        cdht::Network::closest(&self.core, key).await
    }
    async fn descriptor(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        cdht::Network::descriptor(&self.core, node, key).await
    }
    async fn get(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        cdht::Network::get(&self.core, node, key, subkey).await
    }
    async fn set(
        &self,
        node: &cdht::NodeId,
        descriptor: &cdht::Descriptor,
        subkey: u32,
        value: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        self.calls.set(self.calls.get() + 1);
        let local = self.core.node(node);
        if local.descriptor(&descriptor.key()).await?.is_none() {
            local.create(descriptor).await?;
        }
        let outcome = local.set(&descriptor.key(), subkey, value).await?;
        match self.mode.get() {
            1 => return Err(cdht::Error::Unavailable),
            2 => futures::future::pending::<()>().await,
            3 => {
                let _held = self.gate.lock().await;
            }
            _ => {}
        }
        Ok(outcome)
    }
    async fn watch(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        cdht::Network::watch(&self.core, node, key).await
    }
    async fn cancel_watch(
        &self,
        node: &cdht::NodeId,
        watch: cdht::WatchId,
    ) -> Result<(), cdht::Error> {
        cdht::Network::cancel_watch(&self.core, node, watch).await
    }
    async fn changes(
        &self,
        node: &cdht::NodeId,
        watch: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        cdht::Network::changes(&self.core, node, watch).await
    }
}

async fn queued(
    destination: Destination,
) -> (
    InitialCreation<Destination>,
    SameKey,
    Transport,
    RecoveryMember,
) {
    let (initial, key, network, mut member) = acknowledged(destination).await;
    let transport = Transport::new(&network, &initial).await;
    let initial = initial
        .stage_recovery(
            transport.clone(),
            &mut TestClock(10),
            &mut ckmg::SystemEntropy,
            &mut member,
        )
        .await
        .unwrap();
    (initial, key, transport, member)
}

fn first(initial: &InitialCreation<Destination>) -> (cdht::Descriptor, cdht::SignedValue, u32) {
    let retained: serde_json::Value =
        serde_json::from_slice(required(&initial.store, RECOVERY).unwrap()).unwrap();
    let pair = &retained["pairs"][0];
    (
        cdht::rpc::DescriptorBytes::from_bytes(
            serde_json::from_value(pair["descriptor"].clone()).unwrap(),
        )
        .unwrap()
        .decode()
        .unwrap(),
        cdht::rpc::ValueBytes::from_bytes(serde_json::from_value(pair["value"].clone()).unwrap())
            .unwrap()
            .decode()
            .unwrap(),
        pair["subkey"].as_u64().unwrap() as u32,
    )
}

shared!(
    one_recovery_output_commits_before_next_and_all_original_readers_roundtrip,
    {
        let destination = Destination::new();
        let (mut initial, mut key, transport, mut member) = queued(destination.clone()).await;
        let original = initial.recovery_state().unwrap();
        let retained = required(&initial.store, RECOVERY).unwrap().to_vec();
        let outbox: Vec<_> = initial
            .store
            .load_pending()
            .unwrap()
            .iter()
            .map(|output| (output.id, output.bytes.clone()))
            .collect();
        let inner_wire = required(&initial.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        for removed in 1..=original.queue().len() {
            let before = transport.calls.get();
            let (next, report) = initial
                .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await
                .unwrap();
            assert_eq!(report.written, 1);
            assert!(report.stale.is_empty());
            assert_eq!(report.remaining, original.queue().len() - removed);
            assert_eq!(transport.calls.get(), before + cdht::SET_VALUE_COUNT as u32);
            assert_eq!(destination.writes.get(), 6 + removed as u32);
            assert_eq!(next.store.version().unwrap(), 6 + removed as u64);
            assert_eq!(next.phase().unwrap(), InitialPhase::RecoveryProgress);
            assert_eq!(
                next.recovery_progress().unwrap().0.queue(),
                &original.queue()[removed..]
            );
            assert_eq!(required(&next.store, RECOVERY).unwrap(), retained);
            let retained_outbox: Vec<_> = next
                .store
                .load_pending()
                .unwrap()
                .iter()
                .map(|output| (output.id, output.bytes.clone()))
                .collect();
            assert_eq!(retained_outbox, outbox);
            drop(next);
            initial = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
        }
        let inspector = initial.opening.inspector().unwrap();
        let bootstrap = inspector
            .bootstrap(&keys, &key.evidence, &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let passkey = crate::TorPasskeyRecord::open(
            transport.clone(),
            bootstrap.passkey_reader(&initial.opening.prf).unwrap(),
        )
        .await
        .unwrap();
        let mut passkeys = crate::PasskeyRecords::new(
            initial.opening.locator,
            cdht::runtime::Record::new(passkey).unwrap(),
        )
        .unwrap();
        let checkpoint = passkeys.checkpoint(&initial.opening.locator).await.unwrap();
        assert_eq!(checkpoint.sealed(), keys);
        assert_eq!(
            checkpoint.evidence().unwrap().to_bytes().unwrap(),
            key.evidence
        );
        let root = cdht::runtime::Record::new(
            crate::TorReadRecord::checkpoint(transport.clone(), bootstrap.record(None).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut children = Vec::new();
        for index in 0..crate::MAX_CHECKPOINT_RECORDS {
            children.push(
                cdht::runtime::Record::new(
                    crate::TorReadRecord::checkpoint(
                        transport.clone(),
                        bootstrap.record(Some(index as u8)).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
        let mut compound = crate::CompoundRecords::new("garden", root, children).unwrap();
        let observed = compound.checkpoint().await.unwrap();
        let inner = observed
            .restore(
                cwst::backend::Memory::new(),
                bootstrap.store_cipher().unwrap(),
                "garden",
            )
            .await
            .unwrap();
        assert_eq!(inner.version().unwrap(), 2);
        assert_eq!(inner.sealed_checkpoint().unwrap(), inner_wire);
        drop(compound);
        drop(bootstrap);
        let calls = transport.calls.get();
        assert!(matches!(
            initial
                .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await,
            Err(InitialError::Invalid)
        ));
        assert_eq!(transport.calls.get(), calls);
    }
);

shared!(
    unknown_transport_and_actual_progress_cas_cuts_keep_exact_retry_obligations,
    {
        for mode in 1..=5 {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let original = initial.recovery_state().unwrap();
            let old = destination.memory.read().await.unwrap();
            if mode <= 2 {
                transport.mode.set(mode);
            } else {
                destination.mode.set(mode - 2);
            }
            let mut clock = TestClock(10);
            let mut pending =
                Box::pin(initial.publish_next_recovery(transport.clone(), &mut clock, &mut member));
            match mode {
                1 => {
                    let (same, report) = pending.await.unwrap();
                    assert_eq!(
                        (report.written, report.remaining),
                        (0, original.queue().len())
                    );
                    assert_eq!(same.phase().unwrap(), InitialPhase::RecoveryStaged);
                }
                5 => assert!(matches!(
                    pending.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                )),
                _ => {
                    assert!(pending.as_mut().now_or_never().is_none());
                    drop(pending);
                }
            }
            destination.mode.set(0);
            transport.mode.set(0);
            let initial = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            let (progress, conflict, _) = initial.recovery_progress().unwrap();
            assert!(!conflict);
            if mode <= 3 {
                assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryStaged);
                assert_eq!(progress, original);
                assert_eq!(destination.memory.read().await.unwrap(), old);
            } else {
                assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryProgress);
                assert_eq!(progress.queue(), &original.queue()[1..]);
            }
            let (next, report) = initial
                .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await
                .unwrap();
            assert_eq!(report.written, 1);
            let expected_removed = if mode <= 3 { 1 } else { 2 };
            assert_eq!(
                next.recovery_progress().unwrap().0.queue(),
                &original.queue()[expected_removed..]
            );
        }
    }
);

shared!(
    real_signed_newer_or_equal_conflict_is_durable_before_any_later_output,
    {
        for sequence in [2, 3] {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let original = initial.recovery_state().unwrap();
            let (descriptor, _, subkey) = first(&initial);
            let inspector = initial.opening.inspector().unwrap();
            let bootstrap = inspector
                .bootstrap(
                    required(&initial.store, ACKNOWLEDGED_KEYS).unwrap(),
                    &key.evidence,
                    &mut TestClock(10),
                    &mut member,
                )
                .await
                .unwrap();
            let custody = bootstrap.record(None).unwrap();
            let mut nonce = [0; 24];
            ckmg::Entropy::fill(&mut ckmg::SystemEntropy, &mut nonce).unwrap();
            let (actual, conflict) = custody
                .publication(
                    subkey,
                    sequence,
                    b"actual distinct signed owner content",
                    nonce,
                )
                .unwrap();
            assert_eq!(actual.key(), descriptor.key());
            for (_, node) in transport.core.nodes.iter() {
                node.create(&actual).await.unwrap();
                node.set(&actual.key(), subkey, &conflict).await.unwrap();
            }
            drop(custody);
            drop(bootstrap);
            let (initial, report) = initial
                .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await
                .unwrap();
            assert_eq!(
                (report.written, report.remaining),
                (0, original.queue().len() - 1)
            );
            assert_eq!(report.stale, vec![(descriptor.key(), subkey)]);
            assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryDiverged);
            assert_eq!(
                initial.recovery_progress().unwrap().0.queue(),
                &original.queue()[1..]
            );
            drop(initial);
            let reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            assert_eq!(reopened.phase().unwrap(), InitialPhase::RecoveryDiverged);
            let calls = transport.calls.get();
            assert!(matches!(
                reopened
                    .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
                    .await,
                Err(InitialError::Invalid)
            ));
            assert_eq!(transport.calls.get(), calls);
            assert_eq!(destination.writes.get(), 7);
        }
    }
);

struct FailingClock(Rc<Cell<bool>>, Rc<Cell<u64>>);
impl Clock for FailingClock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        if self.0.get() {
            Err(ckmg::Error::Clock)
        } else {
            Ok(self.1.get())
        }
    }
}
shared!(
    observed_transport_progress_retains_last_fresh_floor_even_when_output_is_refused,
    {
        for case in 0..3 {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            member.0.time.set(40);
            let time = member.0.time.clone();
            let failed = Rc::new(Cell::new(false));
            let held = transport.gate.lock().await;
            transport.mode.set(3);
            let mut clock = FailingClock(failed.clone(), time.clone());
            let mut pending =
                Box::pin(initial.publish_next_recovery(transport.clone(), &mut clock, &mut member));
            assert!(pending.as_mut().now_or_never().is_none());
            match case {
                0 => time.set(9),
                1 => time.set(70),
                2 => failed.set(true),
                _ => unreachable!(),
            }
            drop(held);
            assert!(pending.await.is_err());
            transport.mode.set(0);
            let reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            assert_eq!(reopened.phase().unwrap(), InitialPhase::RecoveryProgress);
            assert_eq!(
                reopened.recovery_progress().unwrap().2,
                if case == 1 { 70 } else { 40 }
            );
            let calls = transport.calls.get();
            time.set(39);
            failed.set(false);
            assert!(
                reopened
                    .publish_next_recovery(transport.clone(), &mut clock, &mut member)
                    .await
                    .is_err()
            );
            assert_eq!(transport.calls.get(), calls);
            assert_eq!(destination.writes.get(), 7);
        }
    }
);
