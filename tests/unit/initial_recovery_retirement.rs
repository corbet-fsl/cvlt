//! Genuine forced winner reads and two distinct original backend CAS boundaries.
//! Local strict member fixtures retain their explicit non-HTTPS qualification.
use super::*;

#[derive(Clone)]
struct RetirementBackend {
    inner: cwst::backend::Memory,
    writes: Rc<Cell<u32>>,
    target: Rc<Cell<u32>>,
    mode: Rc<Cell<u8>>,
    gate: Rc<futures::lock::Mutex<()>>,
    first: Rc<RefCell<Option<Vec<u8>>>>,
}
impl RetirementBackend {
    fn new(destination: &Destination) -> Self {
        Self {
            inner: destination.memory.clone(),
            writes: Rc::new(Cell::new(0)),
            target: Rc::new(Cell::new(0)),
            mode: Rc::new(Cell::new(0)),
            gate: Rc::new(futures::lock::Mutex::new(())),
            first: Rc::new(RefCell::new(None)),
        }
    }
    fn arm(&self, target: u32, mode: u8) {
        self.writes.set(0);
        self.target.set(target);
        self.mode.set(mode);
    }
}
impl Backend for RetirementBackend {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.inner.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        // Only persistence is faulted. The first CAS retains the selected actual
        // observations; the second CAS replaces that exact selected outer Store.
        let cut = self.writes.get() == self.target.get();
        if cut && self.mode.get() == 1 {
            futures::future::pending::<()>().await;
        }
        self.inner.compare_exchange(expected, next).await?;
        if self.writes.get() == 1 {
            *self.first.borrow_mut() = Some(next.to_vec());
        }
        if cut {
            match self.mode.get() {
                2 => futures::future::pending::<()>().await,
                3 => return Err(cwst::Error::Uncertain),
                4 => {
                    let _held = self.gate.lock().await;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

async fn publish_all(
    mut initial: InitialCreation<Destination>,
    transport: &Transport,
    member: &mut RecoveryMember,
) -> InitialCreation<Destination> {
    while !initial.recovery_progress().unwrap().0.queue().is_empty() {
        let (next, report) = initial
            .publish_next_recovery(transport.clone(), &mut TestClock(10), member)
            .await
            .unwrap();
        assert_eq!(report.written, 1);
        assert!(report.stale.is_empty());
        initial = next;
    }
    initial
}

shared!(
    original_progress_keeps_completed_and_distinct_cached_floors_but_not_planned_tail,
    {
        let (initial, key, transport, mut member) = queued(Destination::new()).await;
        let (initial, report) = initial
            .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        assert_eq!(report.written, 1);
        let progress = initial.recovery_progress().unwrap().0;
        assert!(!progress.queue().is_empty());
        let actual = cdht::Dht::with_state(
            cdht::LocalBackend::new(crate::records::tor::Verifier),
            crate::records::tor::Verifier,
            progress.clone(),
        );
        let observations = crate::records::tor::ReadObservations::default();
        observations.retain_completed(&progress).unwrap();
        let state = observations
            .state(&cdht::ClientState::default())
            .await
            .unwrap();
        let retained = cdht::Dht::with_state(
            cdht::LocalBackend::new(crate::records::tor::Verifier),
            crate::records::tor::Verifier,
            state,
        );
        assert!(retained.state().queue().is_empty());
        let mut completed = 0;
        for (descriptor, subkey, value) in actual.observations() {
            if progress
                .queue()
                .iter()
                .any(|queued| queued.key == descriptor.key() && queued.subkey == subkey)
            {
                if retained.schema(&descriptor.key()).is_ok() {
                    assert!(
                        retained
                            .observed_value(&descriptor.key(), subkey)
                            .unwrap()
                            .is_none()
                    );
                }
            } else {
                completed += 1;
                assert_eq!(
                    retained.observed_value(&descriptor.key(), subkey).unwrap(),
                    Some(value)
                );
            }
        }
        assert_eq!(completed, 1);

        // Original cache and queue are independent: an actual newer quorum can
        // coexist with this still-pending exact publication obligation.
        let queued = progress.queue()[0].clone();
        let keys = required(&initial.store, ACKNOWLEDGED_KEYS).unwrap();
        let bootstrap = initial
            .opening
            .inspector()
            .unwrap()
            .bootstrap(keys, &key.evidence, &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let (descriptor, higher) = bootstrap
            .record(None)
            .unwrap()
            .publication(
                queued.subkey,
                3,
                b"actual newer original queued-slot observation",
                [98; 24],
            )
            .unwrap();
        assert_eq!(descriptor.key(), queued.key);
        for (_, node) in transport.core.nodes.iter() {
            node.set(&descriptor.key(), queued.subkey, &higher)
                .await
                .unwrap();
        }
        let reader = cdht::NetworkBackend::new(transport.clone(), crate::records::tor::Verifier);
        cdht::Backend::create(&reader, &descriptor).await.unwrap();
        let quorum = reader.read(&descriptor.key(), queued.subkey).await.unwrap();
        assert!(quorum.has_consensus());
        assert_eq!(quorum.value.as_ref(), Some(&higher));
        let mut cached = cdht::Dht::with_state(
            cdht::LocalBackend::new(crate::records::tor::Verifier),
            crate::records::tor::Verifier,
            progress.clone(),
        );
        cached
            .observe_original(
                &descriptor.key(),
                queued.subkey,
                quorum.value.as_ref().unwrap(),
            )
            .unwrap();
        assert_eq!(cached.state().queue(), progress.queue());
        let observations = crate::records::tor::ReadObservations::default();
        observations.retain_completed(cached.state()).unwrap();
        let lower = cached.state().clone();
        let (same, newest) = bootstrap
            .record(None)
            .unwrap()
            .publication(
                queued.subkey,
                4,
                b"actual later unread durable floor",
                [99; 24],
            )
            .unwrap();
        assert_eq!(same.key(), descriptor.key());
        for (_, node) in transport.core.nodes.iter() {
            node.set(&descriptor.key(), queued.subkey, &newest)
                .await
                .unwrap();
        }
        let quorum = cdht::NetworkBackend::new(transport, crate::records::tor::Verifier)
            .read(&descriptor.key(), queued.subkey)
            .await
            .unwrap();
        assert!(quorum.has_consensus());
        assert_eq!(quorum.value.as_ref(), Some(&newest));
        cached
            .observe_original(
                &descriptor.key(),
                queued.subkey,
                quorum.value.as_ref().unwrap(),
            )
            .unwrap();
        // Neither imported state is a fresh selected read in this sink. Merge
        // their highest genuine floor in either order without false conflict.
        observations.retain_completed(cached.state()).unwrap();
        observations.retain_completed(&lower).unwrap();
        let state = observations
            .state(&cdht::ClientState::default())
            .await
            .unwrap();
        let retained = cdht::Dht::with_state(
            cdht::LocalBackend::new(crate::records::tor::Verifier),
            crate::records::tor::Verifier,
            state,
        );
        assert_eq!(
            retained
                .observed_value(&descriptor.key(), queued.subkey)
                .unwrap(),
            Some(&newest)
        );
        assert!(retained.state().queue().is_empty());
    }
);

async fn reopen(
    key: &mut SameKey,
    backend: &RetirementBackend,
    member: &mut RecoveryMember,
) -> InitialCreation<RetirementBackend> {
    // Fresh actual CPky sign-in; no carried synchronous currentness result.
    member.1 = false;
    key.opening()
        .await
        .reopen_initial(backend.clone())
        .await
        .unwrap()
}

async fn common_store(
    backend: &cwst::backend::Memory,
    key: &mut SameKey,
    keys: &[u8],
    member: &mut RecoveryMember,
) -> cwst::Store<cwst::backend::Memory> {
    let opening = key.opening().await;
    let inspector = opening.inspector().unwrap();
    let bootstrap = inspector
        .bootstrap(
            keys,
            &key.evidence,
            &mut TestClock(member.0.time.get()),
            member,
        )
        .await
        .unwrap();
    cwst::Store::open(backend.clone(), bootstrap.store_cipher().unwrap(), "garden")
        .await
        .unwrap()
}
async fn assert_common(
    backend: &cwst::backend::Memory,
    key: &mut SameKey,
    keys: &[u8],
    source: &[u8],
    member: &mut RecoveryMember,
) {
    let store = common_store(backend, key, keys, member).await;
    assert_eq!(store.version().unwrap(), 3);
    let carrier = crate::read_floors::load(&store).unwrap().unwrap();
    assert_eq!(carrier.source_digest, *blake3::hash(source).as_bytes());
    assert_eq!(carrier.source_version, 2);
    assert_eq!(carrier.checked_at, member.0.time.get());
    assert_eq!(
        store
            .read("keys", key.opening().await.locator.as_bytes())
            .unwrap(),
        Some(keys)
    );
    assert!(carrier.state.queue().is_empty());
}

fn selection<B: Backend>(initial: &InitialCreation<B>) -> serde_json::Value {
    serde_json::from_slice(required(&initial.store, RETIREMENT_SELECTION).unwrap()).unwrap()
}

shared!(
    retirement_selects_actual_consensus_then_common_root_without_vault,
    {
        let destination = Destination::new();
        let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
        let initial = publish_all(initial, &transport, &mut member).await;
        let expected = required(&initial.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        let before_reads = transport.core.gets.get();
        let backend = RetirementBackend::new(&destination);
        drop(initial);
        let initial = reopen(&mut key, &backend, &mut member).await;
        let retired = initial
            .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        assert_eq!(backend.writes.get(), 2);
        assert!(transport.core.gets.get() > before_reads);
        assert_common(&backend.inner, &mut key, &keys, &expected, &mut member).await;
        let candidate = {
            let mut current = member.0.current.borrow_mut();
            retired
                .prepare_recovery(current.current(10).unwrap(), "original", 10)
                .unwrap()
        };
        let prepared = candidate
            .authorize(&mut TestClock(10), &mut member)
            .await
            .unwrap();
        assert!(prepared.lineage_reader().is_ok());
        // Candidate/prepared bootstrap is not an ordinary Vault or a Create grant.
    }
);

shared!(
    each_selection_and_retirement_cas_cut_reopens_only_actual_durable_state,
    {
        for target in [1, 2] {
            for mode in [1, 2, 3] {
                let destination = Destination::new();
                let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
                let initial = publish_all(initial, &transport, &mut member).await;
                let old = destination.memory.read().await.unwrap().unwrap();
                let selected_inner = required(&initial.store, ACKNOWLEDGED_INNER)
                    .unwrap()
                    .to_vec();
                let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
                    .unwrap()
                    .to_vec();
                let backend = RetirementBackend::new(&destination);
                drop(initial);
                let initial = reopen(&mut key, &backend, &mut member).await;
                backend.arm(target, mode);
                let mut clock = TestClock(10);
                let mut future =
                    Box::pin(initial.retire_recovery(transport.clone(), &mut clock, &mut member));
                if mode == 3 {
                    assert!(matches!(
                        future.await,
                        Err(InitialError::Storage(cwst::Error::Uncertain))
                    ));
                } else {
                    assert!(future.as_mut().now_or_never().is_none());
                    drop(future);
                }
                assert_eq!(backend.writes.get(), target);
                backend.arm(0, 0);
                let actual = backend.inner.read().await.unwrap().unwrap();
                if target == 2 && mode != 1 {
                    assert_common(
                        &backend.inner,
                        &mut key,
                        &keys,
                        &selected_inner,
                        &mut member,
                    )
                    .await;
                    // Common-root bytes are no longer a PRF-wrapped initial Store.
                    assert!(
                        key.opening()
                            .await
                            .reopen_initial(backend.clone())
                            .await
                            .is_err()
                    );
                } else {
                    let initial = reopen(&mut key, &backend, &mut member).await;
                    if target == 1 && mode == 1 {
                        assert_eq!(actual, old);
                        assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryProgress);
                    } else {
                        assert_eq!(initial.phase().unwrap(), InitialPhase::RetirementSelected);
                        assert_eq!(selection(&initial)["revision"], 1);
                        assert_eq!(selection(&initial)["checked_at"], 10);
                        assert!(
                            !serde_json::from_value::<cdht::ClientState>(
                                selection(&initial)["state"].clone()
                            )
                            .unwrap()
                            .eq(&cdht::ClientState::default())
                        );
                        let calls = transport.calls.get();
                        assert!(matches!(
                            initial
                                .publish_next_recovery(
                                    transport.clone(),
                                    &mut TestClock(10),
                                    &mut member
                                )
                                .await,
                            Err(InitialError::Invalid)
                        ));
                        assert_eq!(transport.calls.get(), calls);
                    }
                    let initial = reopen(&mut key, &backend, &mut member).await;
                    initial
                        .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
                        .await
                        .unwrap();
                    assert_common(
                        &backend.inner,
                        &mut key,
                        &keys,
                        &selected_inner,
                        &mut member,
                    )
                    .await;
                }
            }
        }
    }
);

shared!(
    durable_selection_fences_equal_sequence_other_bytes_and_clock_reopen,
    {
        let destination = Destination::new();
        let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
        // Keep the planned publications queued: they cannot act as an exact byte
        // fence. The actual fresh read selection below establishes that fence.
        fixture_place_outputs(&initial, &transport.core).await;
        let base = initial.store.version().unwrap();
        let planned = required(&initial.store, RECOVERY).unwrap().to_vec();
        let (_, first_value, first_subkey) = first(&initial);
        let backend = RetirementBackend::new(&destination);
        drop(initial);
        let initial = reopen(&mut key, &backend, &mut member).await;
        backend.arm(1, 3);
        assert!(matches!(
            initial
                .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await,
            Err(InitialError::Storage(cwst::Error::Uncertain))
        ));
        backend.arm(0, 0);
        let initial = reopen(&mut key, &backend, &mut member).await;
        assert_eq!(initial.phase().unwrap(), InitialPhase::RetirementSelected);
        assert_eq!(initial.store.version().unwrap(), base + 1);
        assert_eq!(required(&initial.store, RECOVERY).unwrap(), planned);
        let selected_wire = backend.inner.read().await.unwrap().unwrap();
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
        let (descriptor, changed) = bootstrap
            .record(None)
            .unwrap()
            .publication(
                first_subkey,
                first_value.seq,
                b"genuine signed but different same-sequence owner bytes",
                [91; 24],
            )
            .unwrap();
        // Fresh independent validating nodes can hold a different actual signed
        // equal-sequence quorum. No mock observation or comparison result is used.
        let mut nodes = Vec::new();
        for (id, _) in transport.core.nodes.iter() {
            let node = cdht::LocalBackend::new(crate::records::tor::Verifier);
            node.create(&descriptor).await.unwrap();
            node.set(&descriptor.key(), first_subkey, &changed)
                .await
                .unwrap();
            nodes.push((*id, node));
        }
        drop(bootstrap);
        // Copy all original retained signed pairs except this conflicting slot.
        for output in initial
            .store
            .load_pending()
            .unwrap()
            .iter()
            .filter(|o| o.id[0] == 3)
        {
            let pair: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
            let d = cdht::rpc::DescriptorBytes::from_bytes(
                serde_json::from_value(pair["descriptor"].clone()).unwrap(),
            )
            .unwrap()
            .decode()
            .unwrap();
            let v = cdht::rpc::ValueBytes::from_bytes(
                serde_json::from_value(pair["value"].clone()).unwrap(),
            )
            .unwrap()
            .decode()
            .unwrap();
            let subkey = pair["subkey"].as_u64().unwrap() as u32;
            if d.key() == descriptor.key() && subkey == first_subkey {
                continue;
            }
            for (_, node) in &nodes {
                node.create(&d).await.unwrap();
                node.set(&d.key(), subkey, &v).await.unwrap();
            }
        }
        let mut replay = transport.clone();
        replay.core.nodes = Rc::new(nodes);
        let state: cdht::ClientState =
            serde_json::from_value(selection(&initial)["state"].clone()).unwrap();
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
        let record =
            crate::TorReadRecord::checkpoint(replay.clone(), bootstrap.record(None).unwrap())
                .unwrap()
                .with_state_floors(&state)
                .unwrap();
        assert!(matches!(
            cdht::runtime::Backend::get(&record, first_subkey, true).await,
            Err(cdht::Error::Conflict)
        ));
        drop(record);
        drop(bootstrap);
        drop(initial);
        let initial = reopen(&mut key, &backend, &mut member).await;
        assert!(
            initial
                .retire_recovery(replay, &mut TestClock(10), &mut member)
                .await
                .is_err()
        );
        assert_eq!(backend.writes.get(), 0);
        assert_eq!(backend.inner.read().await.unwrap().unwrap(), selected_wire);
        let initial = reopen(&mut key, &backend, &mut member).await;
        assert!(matches!(
            initial
                .retire_recovery(transport.clone(), &mut TestClock(9), &mut member)
                .await,
            Err(InitialError::Keys(ckmg::Error::Clock))
        ));
        assert_eq!(backend.writes.get(), 0);
        // Exact original selected quorum remains acceptable on a fresh normal owner.
        let initial = reopen(&mut key, &backend, &mut member).await;
        initial
            .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        assert_eq!(backend.writes.get(), 2);
    }
);

async fn clone_winners() -> (
    Destination,
    InitialCreation<Destination>,
    InitialCreation<Destination>,
    SameKey,
    Transport,
    RecoveryMember,
    RecoveryMember,
) {
    let destination = Destination::new();
    let (a, mut key, network) = staged(destination.clone()).await;
    let clone = Destination::new();
    clone
        .memory
        .compare_exchange(None, a.store.sealed_checkpoint().unwrap())
        .await
        .unwrap();
    let b = key.opening().await.reopen_initial(clone).await.unwrap();
    assert_eq!(a.receipt(), b.receipt());
    let mut ma = Member::new(&a, &key);
    let mut mb = Member::new(&b, &key);
    let a = attempt(a, network.clone(), &mut ma)
        .await
        .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut ma)
        .await
        .unwrap();
    let b = attempt(b, network.clone(), &mut mb)
        .await
        .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut mb)
        .await
        .unwrap();
    ma.original = ExactCompletion::new(&a);
    mb.original = ExactCompletion::new(&b);
    let mut ma = RecoveryMember(ma, false);
    let mut mb = RecoveryMember(mb, false);
    assert_ne!(
        required(&a.store, ACKNOWLEDGED_KEYS).unwrap(),
        required(&b.store, ACKNOWLEDGED_KEYS).unwrap()
    );
    let transport = Transport::new(&network, &a).await;
    let a = a
        .stage_recovery(
            transport.clone(),
            &mut TestClock(10),
            &mut ckmg::SystemEntropy,
            &mut ma,
        )
        .await
        .unwrap();
    let b = b
        .stage_recovery(
            transport.clone(),
            &mut TestClock(10),
            &mut ckmg::SystemEntropy,
            &mut mb,
        )
        .await
        .unwrap();
    assert_ne!(
        required(&a.store, RECOVERY).unwrap(),
        required(&b.store, RECOVERY).unwrap()
    );
    (destination, a, b, key, transport, ma, mb)
}

async fn replay_pairs(initial: &InitialCreation<Destination>, transport: &Transport) -> Transport {
    let mut nodes = Vec::new();
    // Keep the genuine fixed genesis lineage record, so fresh normal authority
    // still succeeds; replace only recovery nodes with actual original outputs.
    let genesis = initial.retained().unwrap();
    let gd = genesis.descriptor.decode().unwrap();
    let gv = genesis.value.decode().unwrap();
    for (id, _) in transport.core.nodes.iter() {
        let node = cdht::LocalBackend::new(crate::records::tor::Verifier);
        node.create(&gd).await.unwrap();
        node.set(&gd.key(), 0, &gv).await.unwrap();
        nodes.push((*id, node));
    }
    let mut replay = transport.clone();
    replay.core.nodes = Rc::new(nodes);
    fixture_place_outputs(initial, &replay.core).await;
    replay
}

shared!(
    planned_clone_bytes_allow_actual_same_root_winner_but_selection_fences_replay,
    {
        let (destination, a, b, mut key, transport, mut ma, mut mb) = clone_winners().await;
        let a_replay = replay_pairs(&a, &transport).await;
        let winner_inner = required(&b.store, ACKNOWLEDGED_INNER).unwrap().to_vec();
        let winner_keys = required(&b.store, ACKNOWLEDGED_KEYS).unwrap().to_vec();
        let loser_inner = required(&a.store, ACKNOWLEDGED_INNER).unwrap().to_vec();
        assert_ne!(winner_inner, loser_inner);
        let b = publish_all(b, &transport, &mut mb).await;
        drop(b);
        let planned = required(&a.store, RECOVERY).unwrap().to_vec();
        let outbox: Vec<_> = a
            .store
            .load_pending()
            .unwrap()
            .iter()
            .map(|o| (o.id, o.bytes.clone()))
            .collect();
        let backend = RetirementBackend::new(&destination);
        drop(a);
        let a = reopen(&mut key, &backend, &mut ma).await;
        // A's still-planned ciphertexts must not fence B's genuine same-root winner.
        backend.arm(1, 3);
        assert!(matches!(
            a.retire_recovery(transport.clone(), &mut TestClock(10), &mut ma)
                .await,
            Err(InitialError::Storage(cwst::Error::Uncertain))
        ));
        backend.arm(0, 0);
        let selected = reopen(&mut key, &backend, &mut ma).await;
        assert_eq!(selected.phase().unwrap(), InitialPhase::RetirementSelected);
        assert_eq!(required(&selected.store, RECOVERY).unwrap(), planned);
        let after: Vec<_> = selected
            .store
            .load_pending()
            .unwrap()
            .iter()
            .map(|o| (o.id, o.bytes.clone()))
            .collect();
        assert_eq!(after, outbox);
        assert_eq!(
            selection(&selected)["inner_digest"],
            serde_json::to_value(
                *blake3::hash(required(&selected.store, CARRIED_INNER).unwrap()).as_bytes()
            )
            .unwrap()
        );
        let wire = backend.inner.read().await.unwrap().unwrap();
        drop(selected);
        // A's replay is a complete valid MAC/keys/evidence winner for the SAME root,
        // not malformed ciphertext. Committed equal-sequence B bytes now fence it.
        let selected = reopen(&mut key, &backend, &mut ma).await;
        assert!(
            selected
                .retire_recovery(a_replay, &mut TestClock(10), &mut ma)
                .await
                .is_err()
        );
        assert_eq!(backend.writes.get(), 0);
        assert_eq!(backend.inner.read().await.unwrap().unwrap(), wire);
        let selected = reopen(&mut key, &backend, &mut ma).await;
        selected
            .retire_recovery(transport, &mut TestClock(10), &mut ma)
            .await
            .unwrap();
        assert_eq!(backend.writes.get(), 2);
        assert_common(
            &backend.inner,
            &mut key,
            &winner_keys,
            &winner_inner,
            &mut ma,
        )
        .await;
    }
);

shared!(
    durable_signed_publication_conflict_rejects_replayed_original_quorum,
    {
        let (destination, a, b, mut key, transport, mut ma, mut mb) = clone_winners().await;
        let replay = replay_pairs(&a, &transport).await;
        let winner = publish_all(b, &transport, &mut mb).await;
        let winner_inner = required(&winner.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        let winner_keys = required(&winner.store, ACKNOWLEDGED_KEYS).unwrap().to_vec();
        drop(winner);
        let (a, report) = a
            .publish_next_recovery(transport.clone(), &mut TestClock(10), &mut ma)
            .await
            .unwrap();
        assert_eq!(report.stale.len(), 1);
        assert_eq!(a.phase().unwrap(), InitialPhase::RecoveryDiverged);
        let before = destination.memory.read().await.unwrap().unwrap();
        drop(a);
        ma.1 = false;
        let a = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let writes = destination.writes.get();
        assert!(
            a.retire_recovery(replay, &mut TestClock(10), &mut ma)
                .await
                .is_err()
        );
        assert_eq!(destination.writes.get(), writes);
        assert_eq!(destination.memory.read().await.unwrap().unwrap(), before);
        ma.1 = false;
        let a = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        a.retire_recovery(transport, &mut TestClock(10), &mut ma)
            .await
            .unwrap();
        assert_common(
            &destination.memory,
            &mut key,
            &winner_keys,
            &winner_inner,
            &mut ma,
        )
        .await;
    }
);

shared!(
    post_selection_clock_or_current_owner_refusal_preserves_facts_and_no_retirement,
    {
        for failure in 0..4 {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let initial = publish_all(initial, &transport, &mut member).await;
            let backend = RetirementBackend::new(&destination);
            drop(initial);
            let initial = reopen(&mut key, &backend, &mut member).await;
            backend.arm(1, 4);
            let held = backend.gate.lock().await;
            let now = Rc::new(Cell::new(40));
            member.0.time.set(40);
            let owner_time = member.0.time.clone();
            let current = member.0.current.clone();
            let mut clock = ClockCell(now.clone());
            let mut future =
                Box::pin(initial.retire_recovery(transport.clone(), &mut clock, &mut member));
            assert!(future.as_mut().now_or_never().is_none());
            assert_eq!(backend.writes.get(), 1);
            match failure {
                0 => now.set(39),
                1 => {
                    now.set(70);
                    owner_time.set(70);
                }
                2 => {
                    let mut signer = csgn::Signer::new(
                        "garden",
                        csgn::SecretKey::from_seed(&mut [77; 32]),
                        9,
                        1000,
                    )
                    .unwrap();
                    *current.borrow_mut() = charter_members(&mut signer, &["original"]);
                }
                _ => {}
            }
            // Expiry and revocation are observed by the original checker after the
            // genuine selected-state CAS; no fallible result escapes as retirement.
            drop(held);
            if failure == 0 {
                assert!(matches!(
                    future.await,
                    Err(InitialError::Keys(ckmg::Error::Clock))
                ));
            } else if failure <= 2 {
                assert!(future.await.is_err());
            } else {
                // Cancellation after the real committed selection has no result.
                drop(future);
            }
            assert_eq!(backend.writes.get(), 1);
            backend.arm(0, 0);
            member.0.time.set(40);
            let mut signer =
                csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000)
                    .unwrap();
            *current.borrow_mut() = charter(&mut signer);
            let initial = reopen(&mut key, &backend, &mut member).await;
            assert_eq!(initial.phase().unwrap(), InitialPhase::RetirementSelected);
            assert_eq!(selection(&initial)["checked_at"], 40);
            assert!(matches!(
                initial
                    .retire_recovery(transport.clone(), &mut TestClock(39), &mut member)
                    .await,
                Err(InitialError::Keys(ckmg::Error::Clock))
            ));
            assert_eq!(backend.writes.get(), 0);
        }
    }
);

struct NormalAuthority(RecoveryMember);
impl Authority for NormalAuthority {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        if request.statement.is_some() {
            self.0.check(request).await
        } else {
            // Original Keys Use, with the original exact checks, real forced
            // Lineage Records and current Charter verification; no new grants.
            self.0.0.check(request).await
        }
    }
}

struct BorrowNormal<'a>(&'a mut NormalAuthority);
impl Authority for BorrowNormal<'_> {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        self.0.check(request).await
    }
}

struct AdvancingRead {
    inner: cwst::backend::Memory,
    time: Rc<Cell<u64>>,
}
impl Backend for AdvancingRead {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        let wire = self.inner.read().await?;
        self.time.set(20);
        Ok(wire)
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.inner.compare_exchange(expected, next).await
    }
}
struct RollbackLookup<R> {
    inner: R,
    time: Rc<Cell<u64>>,
}
impl<R: crate::Records> crate::Records for RollbackLookup<R> {
    async fn lookup(&mut self, locator: &ckmg::Locator) -> crate::RestoreLookup {
        let actual = self.inner.lookup(locator).await;
        self.time.set(15);
        actual
    }
    fn install_read_floors(&mut self, state: &cdht::ClientState) -> Result<(), crate::RecordError> {
        self.inner.install_read_floors(state)
    }
}

shared!(
    ordinary_open_retains_the_post_store_floor_across_actual_signed_lookup,
    {
        let destination = Destination::new();
        let (initial, _key, transport, mut member) = queued(destination.clone()).await;
        let initial = publish_all(initial, &transport, &mut member).await;
        let retired = initial
            .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let candidate = {
            let mut current = member.0.current.borrow_mut();
            retired
                .prepare_recovery(current.current(10).unwrap(), "original", 10)
                .unwrap()
        };
        let mut prepared = candidate
            .authorize(&mut TestClock(10), &mut member)
            .await
            .unwrap();
        let actual_records = prepared
            .tor_passkey_records(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let time = member.0.time.clone();
        let reads = transport.core.gets.get();
        let mut normal = NormalAuthority(member);
        assert!(matches!(
            prepared
                .open_existing(
                    AdvancingRead {
                        inner: destination.memory,
                        time: time.clone(),
                    },
                    Owners {
                        clock: FailingClock(Rc::new(Cell::new(false)), time.clone()),
                        entropy: ckmg::SystemEntropy,
                        authority: BorrowNormal(&mut normal),
                        records: RollbackLookup {
                            inner: actual_records,
                            time: time.clone(),
                        },
                        wallet: (),
                    },
                )
                .await,
            Err(OpenError::Keys(ckmg::Error::Clock))
        ));
        assert_eq!(time.get(), 15);
        assert!(transport.core.gets.get() > reads);
    }
);

shared!(
    ordinary_reopen_forces_same_key_signed_floors_before_unlock_and_keeps_local_carrier,
    {
        let destination = Destination::new();
        let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
        let initial = publish_all(initial, &transport, &mut member).await;
        let source_keys = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        let source = required(&initial.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        let packed = crate::records::pack_recovery(&source_keys, &member.0.evidence).unwrap();
        let inspector = initial.opening.inspector().unwrap();
        let bootstrap = inspector
            .bootstrap(&source_keys, &key.evidence, &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let (descriptor, alternate) = bootstrap
            .passkey_publication(&initial.opening.prf, 2, &packed, [93; 24])
            .unwrap();
        let original = transport.core.nodes[0]
            .1
            .get(&descriptor.key(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alternate.seq, original.seq);
        assert_ne!(alternate, original);
        let (same_descriptor, older) = bootstrap
            .passkey_publication(&initial.opening.prf, 1, &packed, [94; 24])
            .unwrap();
        assert_eq!(same_descriptor.key(), descriptor.key());
        drop(bootstrap);
        let exact = replay_pairs(&initial, &transport).await;
        let mut foreign = Vec::new();
        for value in [&alternate, &older] {
            let mut nodes = Vec::new();
            for (id, _) in exact.core.nodes.iter() {
                let node = cdht::LocalBackend::new(crate::records::tor::Verifier);
                node.create(&descriptor).await.unwrap();
                node.set(&descriptor.key(), 0, value).await.unwrap();
                nodes.push((*id, node));
            }
            let mut route = exact.clone();
            route.core.nodes = Rc::new(nodes);
            foreign.push(route);
        }
        let retired = initial
            .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let candidate = {
            let mut current = member.0.current.borrow_mut();
            retired
                .prepare_recovery(current.current(10).unwrap(), "original", 10)
                .unwrap()
        };
        let durable = destination.memory.read().await.unwrap().unwrap();
        assert_ne!(durable, source);
        assert_common(
            &destination.memory,
            &mut key,
            &source_keys,
            &source,
            &mut member,
        )
        .await;
        // Same plaintext Keys and genuine owner signatures at equal/lower sequence
        // are insufficient. This specifically exercises actual open_existing, not
        // a data-only floor setter or a fabricated lookup result.
        for route in foreign {
            member.1 = false;
            let mut prepared = candidate
                .authorize(&mut TestClock(10), &mut member)
                .await
                .unwrap();
            let records = prepared
                .tor_passkey_records(route, &mut TestClock(10), &mut member)
                .await
                .unwrap();
            let mut normal = NormalAuthority(member);
            assert!(matches!(
                prepared
                    .open_existing(
                        destination.memory.clone(),
                        Owners {
                            clock: TestClock(10),
                            entropy: ckmg::SystemEntropy,
                            authority: BorrowNormal(&mut normal),
                            records,
                            wallet: (),
                        }
                    )
                    .await,
                Err(OpenError::Records(crate::RecordError::Unavailable))
            ));
            member = normal.0;
            assert_eq!(destination.memory.read().await.unwrap().unwrap(), durable);
        }
        member.1 = false;
        let mut prepared = candidate
            .authorize(&mut TestClock(10), &mut member)
            .await
            .unwrap();
        prepared
            .load_existing_read_floors(&destination.memory, &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let retained = prepared
            .tor_checkpoint(exact.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let records = prepared
            .tor_passkey_records(exact.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let mut normal = NormalAuthority(member);
        assert!(matches!(
            prepared
                .restore(
                    retained,
                    destination.memory.clone(),
                    Owners {
                        clock: TestClock(10),
                        entropy: ckmg::SystemEntropy,
                        authority: BorrowNormal(&mut normal),
                        records,
                        wallet: (),
                    }
                )
                .await,
            Err(OpenError::Checkpoint(crate::CheckpointError::Storage(
                cwst::Error::AlreadyInitialized
            )))
        ));
        member = normal.0;
        assert_eq!(destination.memory.read().await.unwrap().unwrap(), durable);
        member.1 = false;
        let mut prepared = candidate
            .authorize(&mut TestClock(10), &mut member)
            .await
            .unwrap();
        let records = prepared
            .tor_passkey_records(exact, &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let mut normal = NormalAuthority(member);
        let expected_lineage = normal
            .0
            .0
            .original
            .receipt
            .attested_lineage()
            .unwrap()
            .0
            .clone();
        let mut vault = prepared
            .open_existing(
                destination.memory.clone(),
                Owners {
                    clock: TestClock(10),
                    entropy: ckmg::SystemEntropy,
                    authority: BorrowNormal(&mut normal),
                    records,
                    wallet: (),
                },
            )
            .await
            .unwrap();
        assert_eq!(vault.keys().lineage().await.unwrap(), expected_lineage);
        drop(vault);
        assert_eq!(destination.memory.read().await.unwrap().unwrap(), durable);
    }
);

shared!(
    noncapable_records_and_old_clock_cannot_open_persisted_common_root_floors,
    {
        let destination = Destination::new();
        let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
        let initial = publish_all(initial, &transport, &mut member).await;
        let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        initial
            .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
            .await
            .unwrap();
        let store = common_store(&destination.memory, &mut key, &keys, &mut member).await;
        let opening = key.opening().await;
        let records = opening.tor_records(transport.clone()).await.unwrap();
        let mut normal = NormalAuthority(member);
        assert!(
            crate::Vault::new(
                store,
                "garden",
                TestClock(9),
                ckmg::SystemEntropy,
                BorrowNormal(&mut normal),
                records,
                ()
            )
            .is_err()
        );
        member = normal.0;
        let store = common_store(&destination.memory, &mut key, &keys, &mut member).await;
        let normal = NormalAuthority(member);
        assert!(
            crate::Vault::new(
                store,
                "garden",
                TestClock(10),
                ckmg::SystemEntropy,
                normal,
                UnavailableRecords,
                ()
            )
            .is_err()
        );
        // No fallback silently strips the namespace or builds accepted Records.
        assert!(destination.memory.read().await.unwrap().is_some());
    }
);

shared!(
    failed_or_cancelled_local_floor_load_fences_every_later_recovery_port,
    {
        for cut in [0, 1] {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let initial = publish_all(initial, &transport, &mut member).await;
            let retired = initial
                .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await
                .unwrap();
            let candidate = {
                let mut current = member.0.current.borrow_mut();
                retired
                    .prepare_recovery(current.current(10).unwrap(), "original", 10)
                    .unwrap()
            };
            let mut prepared = candidate
                .authorize(&mut TestClock(10), &mut member)
                .await
                .unwrap();
            destination.mode.set(if cut == 0 { 4 } else { 5 });
            let held = destination.read_gate.lock().await;
            let mut clock = TestClock(20);
            member.0.time.set(20);
            let mut load =
                Box::pin(prepared.load_existing_read_floors(&destination, &mut clock, &mut member));
            if cut == 0 {
                assert!(matches!(
                    load.await,
                    Err(OpenError::Storage(cwst::Error::Storage))
                ));
            } else {
                assert!(load.as_mut().now_or_never().is_none());
                drop(load);
            }
            drop(held);
            destination.mode.set(0);
            member.0.time.set(15);
            let before = transport.core.gets.get();
            assert!(prepared.lineage_reader().is_err());
            assert!(prepared.record(None).is_err());
            assert!(matches!(
                prepared
                    .tor_checkpoint(transport.clone(), &mut TestClock(15), &mut member)
                    .await,
                Err(OpenError::Keys(ckmg::Error::Unauthorized))
            ));
            assert_eq!(transport.core.gets.get(), before);
            assert!(
                prepared
                    .load_existing_read_floors(&destination, &mut TestClock(20), &mut member)
                    .await
                    .is_err()
            );
            // Ignoring the returned error cannot turn this same borrowed attempt
            // into a fresh unfenced reader. A new actual owner is mandatory.
            assert_eq!(transport.core.gets.get(), before);
            let _ = key.opening().await;
        }
    }
);

shared!(
    selected_retry_reuses_exact_carrier_or_advances_its_actual_version,
    {
        for later in [10, 20] {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let initial = publish_all(initial, &transport, &mut member).await;
            let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
                .unwrap()
                .to_vec();
            let source = required(&initial.store, ACKNOWLEDGED_INNER)
                .unwrap()
                .to_vec();
            let backend = RetirementBackend::new(&destination);
            drop(initial);
            let initial = reopen(&mut key, &backend, &mut member).await;
            backend.arm(1, 3);
            assert!(matches!(
                initial
                    .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
                    .await,
                Err(InitialError::Storage(cwst::Error::Uncertain))
            ));
            backend.arm(0, 0);
            let initial = reopen(&mut key, &backend, &mut member).await;
            let carried = required(&initial.store, CARRIED_INNER).unwrap().to_vec();
            member.0.time.set(later);
            initial
                .retire_recovery(transport, &mut TestClock(later), &mut member)
                .await
                .unwrap();
            let store = common_store(&backend.inner, &mut key, &keys, &mut member).await;
            let carrier = crate::read_floors::load(&store).unwrap().unwrap();
            assert_eq!(carrier.source_digest, *blake3::hash(&source).as_bytes());
            assert_eq!(carrier.checked_at, later);
            assert_eq!(store.version().unwrap(), if later == 10 { 3 } else { 4 });
            if later == 10 {
                assert_eq!(backend.inner.read().await.unwrap().unwrap(), carried);
            } else {
                assert_ne!(backend.inner.read().await.unwrap().unwrap(), carried);
            }
        }
    }
);

shared!(
    actual_later_network_winner_preserves_carrier_and_refuses_reads_below_it,
    {
        for stale in [false, true] {
            let destination = Destination::new();
            let (initial, mut key, transport, mut member) = queued(destination.clone()).await;
            let initial = publish_all(initial, &transport, &mut member).await;
            let keys = required(&initial.store, ACKNOWLEDGED_KEYS)
                .unwrap()
                .to_vec();
            let inspector = initial.opening.inspector().unwrap();
            let bootstrap = inspector
                .bootstrap(&keys, &key.evidence, &mut TestClock(10), &mut member)
                .await
                .unwrap();
            let (descriptor, extra, subkey) = if stale {
                let packed = crate::records::pack_recovery(&keys, &member.0.evidence).unwrap();
                let (descriptor, value) = bootstrap
                    .passkey_publication(&initial.opening.prf, 3, &packed, [96; 24])
                    .unwrap();
                (descriptor, value, 0)
            } else {
                let (descriptor, value) = bootstrap
                    .record(None)
                    .unwrap()
                    .publication(31, 7, b"actual completed other root slot", [96; 24])
                    .unwrap();
                (descriptor, value, 31)
            };
            // An independent genuine quorum supplies the source's durable floor.
            // The selected route still holds passkey seq2 in the stale case.
            let extra_route = if stale {
                replay_pairs(&initial, &transport).await
            } else {
                transport.clone()
            };
            for (_, node) in extra_route.core.nodes.iter() {
                node.create(&descriptor).await.unwrap();
                node.set(&descriptor.key(), subkey, &extra).await.unwrap();
            }
            let reader = cdht::NetworkBackend::new(extra_route, crate::records::tor::Verifier);
            cdht::Backend::create(&reader, &descriptor).await.unwrap();
            let actual = reader.read(&descriptor.key(), subkey).await.unwrap();
            assert!(actual.has_consensus());
            assert_eq!(actual.value.as_ref(), Some(&extra));
            let local = cdht::LocalBackend::new(crate::records::tor::Verifier);
            local.create(&descriptor).await.unwrap();
            let mut observed = cdht::Dht::new(local, crate::records::tor::Verifier);
            observed.open(&descriptor.key()).await.unwrap();
            observed
                .observe_original(&descriptor.key(), subkey, actual.value.as_ref().unwrap())
                .unwrap();
            assert!(observed.state().queue().is_empty());
            let original_inner = required(&initial.store, ACKNOWLEDGED_INNER)
                .unwrap()
                .to_vec();
            let mut source = cwst::Store::restore_checked(
                cwst::backend::Memory::new(),
                bootstrap.store_cipher().unwrap(),
                "garden",
                2,
                &original_inner,
                |_| Ok(()),
            )
            .await
            .unwrap();
            let carrier = crate::read_floors::Carrier {
                state: observed.state().clone(),
                checked_at: 20,
                source_digest: *blake3::hash(&original_inner).as_bytes(),
                source_version: 2,
            };
            let bytes = carrier.bytes().unwrap();
            source
                .commit(
                    2,
                    *initial.receipt().operation.as_bytes(),
                    &[cwst::Change::Put {
                        owner: crate::read_floors::OWNER,
                        key: crate::read_floors::KEY,
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(source.version().unwrap(), 3);
            let source_wire = source.sealed_checkpoint().unwrap().to_vec();
            let root = crate::TorReadRecord::checkpoint(
                transport.clone(),
                bootstrap.record(None).unwrap(),
            )
            .and_then(cdht::runtime::Record::new)
            .unwrap();
            let mut children = Vec::new();
            for i in 0..crate::MAX_CHECKPOINT_RECORDS {
                children.push(
                    crate::TorReadRecord::checkpoint(
                        transport.clone(),
                        bootstrap.record(Some(i as u8)).unwrap(),
                    )
                    .and_then(cdht::runtime::Record::new)
                    .unwrap(),
                );
            }
            let records = crate::CompoundRecords::new("garden", root, children).unwrap();
            let prepared = records.prepare(&source, "garden").unwrap();
            drop(records);
            let mut outputs = Vec::new();
            prepared
                .for_each_part(|child, subkey, sequence, packed| {
                    let custody = bootstrap
                        .record(child.map(|i| i as u8))
                        .map_err(|_| crate::CheckpointError::Invalid)?;
                    let mut nonce = [0; 24];
                    ckmg::Entropy::fill(&mut ckmg::SystemEntropy, &mut nonce).unwrap();
                    let (d, v) = custody
                        .publication(subkey, sequence, packed, nonce)
                        .map_err(|_| crate::CheckpointError::Invalid)?;
                    outputs.push((d, subkey, v));
                    Ok(())
                })
                .unwrap();
            for (d, subkey, value) in outputs {
                for (_, node) in transport.core.nodes.iter() {
                    node.create(&d).await.unwrap();
                    assert_eq!(
                        node.set(&d.key(), subkey, &value).await.unwrap(),
                        cdht::SetOutcome::Accepted
                    );
                }
            }
            drop(bootstrap);
            let backend = RetirementBackend::new(&destination);
            drop(initial);
            let initial = reopen(&mut key, &backend, &mut member).await;
            let old = backend.inner.read().await.unwrap().unwrap();
            let result = initial
                .retire_recovery(transport.clone(), &mut TestClock(10), &mut member)
                .await;
            if stale {
                assert!(matches!(
                    result,
                    Err(InitialError::Publication(cdht::Error::Conflict))
                ));
                assert_eq!(backend.inner.read().await.unwrap().unwrap(), old);
                assert_eq!(backend.writes.get(), 0);
                continue;
            }
            assert!(matches!(
                result,
                Err(InitialError::Keys(ckmg::Error::Clock))
            ));
            assert_eq!(backend.inner.read().await.unwrap().unwrap(), old);
            assert_eq!(backend.writes.get(), 0);
            member.0.time.set(20);
            let initial = reopen(&mut key, &backend, &mut member).await;
            initial
                .retire_recovery(transport, &mut TestClock(20), &mut member)
                .await
                .unwrap();
            let store = common_store(&backend.inner, &mut key, &keys, &mut member).await;
            assert_eq!(store.version().unwrap(), 4);
            let retained = crate::read_floors::load(&store).unwrap().unwrap();
            assert_eq!(retained.checked_at, 20);
            assert_eq!(retained.source_version, 3);
            assert_eq!(
                retained.source_digest,
                *blake3::hash(&source_wire).as_bytes()
            );
            let actual = cdht::Dht::with_state(
                cdht::LocalBackend::new(crate::records::tor::Verifier),
                crate::records::tor::Verifier,
                retained.state.clone(),
            );
            assert_eq!(actual.state(), &retained.state);
            assert_eq!(
                actual.observed_value(&descriptor.key(), 31).unwrap(),
                Some(&extra)
            );
        }
    }
);
