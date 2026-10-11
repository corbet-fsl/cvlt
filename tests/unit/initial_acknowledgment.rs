//! Actual registration, certified evidence, forced Records and Keys acknowledgment.
//! The scoped checker below verifies original crypto and current Charter; it is
//! not an HTTPS membership lease or a production G3 adapter.
use super::*;
use cdht::Backend as _;
use std::cell::RefCell;

struct Member {
    original: ExactCompletion,
    credential: Vec<u8>,
    evidence: crate::LineageEvidence,
    current: Rc<RefCell<cchr::Charter>>,
    records: Option<crate::LineageRecords<crate::TorLineageRecord<'static, Network>>>,
    completion_started: bool,
    uses: Rc<Cell<u32>>,
    time: Rc<Cell<u64>>,
}
impl Member {
    fn new(initial: &InitialCreation<Destination>, key: &SameKey) -> Self {
        let mut signer =
            csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000)
                .unwrap();
        Self {
            original: ExactCompletion::new(initial),
            credential: key.descriptor.credential_id().to_vec(),
            evidence: crate::LineageEvidence::from_bytes(&key.evidence).unwrap(),
            current: Rc::new(RefCell::new(charter(&mut signer))),
            records: None,
            completion_started: false,
            uses: Rc::new(Cell::new(0)),
            time: Rc::new(Cell::new(10)),
        }
    }
    fn verify(&self, now: u64) -> Result<(), ckmg::Error> {
        let mut owner = self.current.borrow_mut();
        let current = owner.current(now).map_err(|_| ckmg::Error::Unauthorized)?;
        self.evidence
            .verify(current, "original", now)
            .map_err(|_| ckmg::Error::Unauthorized)?;
        Ok(())
    }
    fn exact(&self, r: &ckmg::CompletionAuthorization<'_>) -> Result<(), ckmg::Error> {
        if r.receipt != &self.original.receipt
            || r.authority_reference != self.credential.as_slice()
            || r.location != &self.original.location
            || r.sealed_digest != &self.original.keys
            || r.intent.outer_generation != 4
            || r.intent.outer_digest != self.original.outer
            || r.intent.inner_version != 1
            || r.intent.inner_operation != [8; 32]
            || r.intent.inner_digest != self.original.inner
            || r.intent.nonce != [71; 24]
            || r.intent.packed_evidence != self.evidence.packed().unwrap().as_slice()
            || r.intent.prepared_at != 10
            || r.intent.expires != 30
            || !(10..30).contains(&r.now)
        {
            return Err(ckmg::Error::Unauthorized);
        }
        self.verify(r.now)
    }
    async fn attach(
        &mut self,
        attempt: &crate::InitialAcknowledgment<Destination>,
        network: Network,
    ) {
        let backend =
            crate::TorLineageRecord::initial_lineage(network, attempt.lineage_reader().unwrap())
                .await
                .unwrap();
        self.records = Some(
            crate::LineageRecords::new(vec![cdht::runtime::Record::new(backend).unwrap()]).unwrap(),
        );
    }
}
impl Authority for Member {
    async fn check(&mut self, r: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        let (lineage, author) = self.original.receipt.attested_lineage()?;
        if r.action != ckmg::Action::Use
            || r.binding != &lineage.binding
            || r.root != Some(lineage.root)
            || r.device != author
            || r.epoch != lineage.epoch
            || r.target.is_some()
            || r.statement.is_some()
            || r.signing.is_some()
            || !r.evidence.is_empty()
            || !(10..30).contains(&r.now)
        {
            return Err(ckmg::Error::Unauthorized);
        }
        self.verify(r.now)?;
        // Force the original NetworkBackend again; the earlier witness cannot
        // substitute for normal Use. Reborrow actual Charter after the await.
        let read = self
            .records
            .as_mut()
            .ok_or(ckmg::Error::Unauthorized)?
            .read()
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        if read.evidence().len() != 1
            || read.evidence()[0].to_bytes().unwrap() != self.evidence.to_bytes().unwrap()
        {
            return Err(ckmg::Error::Unauthorized);
        }
        let now = ClockCell(self.time.clone()).now()?;
        if now < r.now || now >= 30 {
            return Err(ckmg::Error::Unauthorized);
        }
        self.verify(now)?;
        self.uses.set(self.uses.get() + 1);
        Ok(())
    }
    async fn check_completion(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        if self.completion_started {
            return Err(ckmg::Error::Unauthorized);
        }
        self.exact(&r)?;
        self.completion_started = true;
        ClockCell(self.time.clone()).now()
    }
    fn check_completion_current(
        &mut self,
        r: ckmg::CompletionAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        if !self.completion_started {
            return Err(ckmg::Error::Unauthorized);
        }
        self.exact(&r)?;
        ClockCell(self.time.clone()).now()
    }
}

async fn staged(destination: Destination) -> (InitialCreation<Destination>, SameKey, Network) {
    let (initial, mut key) = genuine(destination.clone()).await;
    let pair = initial.retained().unwrap();
    let descriptor = pair.descriptor.decode().unwrap();
    let value = pair.value.decode().unwrap();
    drop(initial.stage(PublicationBackend::new()).await.unwrap());
    let initial = key
        .opening()
        .await
        .reopen_initial(destination)
        .await
        .unwrap();
    let network = Network::new(
        &descriptor,
        &[Some(value.clone()), Some(value.clone()), Some(value)],
    )
    .await;
    (initial, key, network)
}
async fn attempt(
    initial: InitialCreation<Destination>,
    network: Network,
    member: &mut Member,
) -> crate::InitialAcknowledgment<Destination> {
    let witnessed = initial
        .read_first_lineage(network.clone(), &mut TestClock(10))
        .await
        .unwrap();
    let attempt = witnessed
        .prepare_acknowledgment(&mut TestClock(10), member)
        .await
        .unwrap();
    member.attach(&attempt, network).await;
    attempt
}
fn inspect_acknowledged(initial: &InitialCreation<Destination>) {
    assert_eq!(initial.phase().unwrap(), InitialPhase::Acknowledged);
    let inspector = initial.opening.inspector().unwrap();
    assert!(matches!(
        inspector.inspect(required(&initial.store, KEYS).unwrap()),
        Err(ckmg::Error::Pending)
    ));
    let inspected = inspector
        .inspect(required(&initial.store, ACKNOWLEDGED_KEYS).unwrap())
        .unwrap();
    assert_eq!(inspected.revision(), 2);
    assert_eq!(
        inspected.lineage(),
        initial.receipt().attested_lineage().unwrap().0
    );
    assert_eq!(initial.store.version().unwrap(), 5);
    // The original signed outbox/queue is retained; this phase does not publish
    // a per-passkey recovery checkpoint or return a usable Vault.
    assert_eq!(initial.store.load_pending().unwrap().len(), 2);
    assert_eq!(initial.staged_state().unwrap().queue().len(), 1);
    assert!(
        required(&initial.store, ACKNOWLEDGED_INNER).unwrap()
            != required(&initial.store, INNER).unwrap()
    );
}

shared!(
    actual_normal_use_and_acknowledgment_commit_once_then_reopen_same_key,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged(destination.clone()).await;
        let old = destination.memory.read().await.unwrap().unwrap();
        let mut member = Member::new(&initial, &key);
        let attempt = attempt(initial, network.clone(), &mut member).await;
        assert_eq!(network.gets.get(), 3);
        let acknowledged = attempt
            .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut member)
            .await
            .unwrap();
        assert_eq!(member.uses.get(), 1);
        assert_eq!(network.gets.get(), 6);
        assert_eq!(network.sets.get(), 0);
        assert_eq!(destination.writes.get(), 5);
        inspect_acknowledged(&acknowledged);
        assert_ne!(destination.memory.read().await.unwrap(), Some(old));
        drop(acknowledged);
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination)
            .await
            .unwrap();
        inspect_acknowledged(&reopened);
        assert!(matches!(
            reopened.resume_publication(PublicationBackend::new()),
            Err(InitialError::Invalid)
        ));
    }
);

shared!(
    acknowledgment_cancellation_and_unknown_cas_reopen_actual_phase,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let (initial, mut key, network) = staged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let mut member = Member::new(&initial, &key);
            let attempt = attempt(initial, network, &mut member).await;
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let mut entropy = FixtureEntropy;
            let mut pending = Box::pin(attempt.acknowledge(&mut clock, &mut entropy, &mut member));
            if mode == 3 {
                assert!(matches!(
                    pending.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(pending.as_mut().now_or_never().is_none());
                drop(pending);
            }
            destination.mode.set(0);
            let reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            if mode == 1 {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
                assert_eq!(destination.memory.read().await.unwrap(), Some(old));
            } else {
                inspect_acknowledged(&reopened);
            }
            assert_eq!(destination.writes.get(), 5);
        }
    }
);

shared!(
    two_same_key_attempts_cannot_overwrite_first_acknowledgment,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged(destination.clone()).await;
        let clone = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let mut a = Member::new(&initial, &key);
        let mut b = Member::new(&clone, &key);
        let first = attempt(initial, network.clone(), &mut a).await;
        let second = attempt(clone, network, &mut b).await;
        let done = first
            .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut a)
            .await
            .unwrap();
        inspect_acknowledged(&done);
        let committed = destination.memory.read().await.unwrap();
        assert!(matches!(
            second
                .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut b)
                .await,
            Err(InitialError::Storage(cwst::Error::Conflict))
        ));
        assert_eq!(destination.memory.read().await.unwrap(), committed);
        assert_eq!(destination.writes.get(), 5);
    }
);

shared!(normal_use_forces_fresh_quorum_and_exact_evidence, {
    for conflicting in [false, true] {
        let destination = Destination::new();
        let (initial, mut key, network) = staged(destination.clone()).await;
        let old = destination.memory.read().await.unwrap();
        let descriptor = initial.retained().unwrap().descriptor.decode().unwrap();
        let mut member = Member::new(&initial, &key);
        let attempt = attempt(initial, network.clone(), &mut member).await;
        if conflicting {
            let value = cdht::SignedValue::sign_with_nonce(
                &descriptor.owner,
                0,
                1,
                b"actual conflicting root signed data".to_vec(),
                Some([99; 24]),
                &FixtureSigner(SigningKey::from_bytes(&[71; 32])),
            )
            .unwrap();
            for (_, node) in network.nodes.iter() {
                node.set(&descriptor.key(), 0, &value).await.unwrap();
            }
        } else {
            network.unavailable.set(true);
        }
        assert!(matches!(
            attempt
                .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut member)
                .await,
            Err(InitialError::Keys(ckmg::Error::Unavailable))
        ));
        assert_eq!(member.uses.get(), 0);
        assert_eq!(destination.memory.read().await.unwrap(), old);
        assert_eq!(destination.writes.get(), 4);
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination)
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
    }
});

shared!(
    normal_use_wait_rechecks_clock_signed_policy_and_durable_checkpoint,
    {
        for case in 0..4 {
            let destination = Destination::new();
            let (initial, mut key, network) = staged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let mut member = Member::new(&initial, &key);
            let attempt = attempt(initial, network.clone(), &mut member).await;
            let current = member.current.clone();
            let held = network.gate.lock().await;
            let time = member.time.clone();
            let mut clock = ClockCell(time.clone());
            let mut entropy = FixtureEntropy;
            let mut pending = Box::pin(attempt.acknowledge(&mut clock, &mut entropy, &mut member));
            assert!(pending.as_mut().now_or_never().is_none());
            match case {
                0 => time.set(30),
                1 => time.set(9),
                2 => {
                    // Original signed revocation data, accepted by a real current
                    // Charter owner, changes while the actual normal Use read waits.
                    let mut signer = csgn::Signer::new(
                        "garden",
                        csgn::SecretKey::from_seed(&mut [77; 32]),
                        9,
                        1000,
                    )
                    .unwrap();
                    *current.borrow_mut() = charter_members(&mut signer, &["original"]);
                }
                3 => {
                    destination
                        .memory
                        .compare_exchange(Some(&old), &key.retained_checkpoint)
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(held);
            let result = pending.await;
            match case {
                0 | 1 => assert!(matches!(
                    result,
                    Err(InitialError::Keys(ckmg::Error::Unauthorized))
                )),
                2 => assert!(matches!(
                    result,
                    Err(InitialError::Keys(ckmg::Error::Unauthorized))
                )),
                3 => assert!(matches!(
                    result,
                    Err(InitialError::Storage(cwst::Error::Conflict))
                )),
                _ => unreachable!(),
            }
            assert_eq!(destination.writes.get(), 4);
            if case != 3 {
                assert_eq!(destination.memory.read().await.unwrap(), Some(old));
                let reopened = key
                    .opening()
                    .await
                    .reopen_initial(destination)
                    .await
                    .unwrap();
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
            }
        }
    }
);

shared!(
    wrong_genuine_key_scope_and_credential_cannot_complete_retained_operation,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged(destination.clone()).await;
        let old = destination.memory.read().await.unwrap();
        let (_, mut other_key, _) = staged(Destination::new()).await;
        assert!(
            other_key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .is_err()
        );
        let mut wrong_scope = key.opening().await;
        wrong_scope.scope = "another".into();
        wrong_scope.locator = ckmg::passkey::vault_location(&wrong_scope.prf, "another").unwrap();
        assert!(
            wrong_scope
                .reopen_initial(destination.clone())
                .await
                .is_err()
        );
        let mut member = Member::new(&initial, &other_key);
        let witness = initial
            .read_first_lineage(network, &mut TestClock(10))
            .await
            .unwrap();
        assert!(matches!(
            witness
                .prepare_acknowledgment(&mut TestClock(10), &mut member)
                .await,
            Err(InitialError::Keys(ckmg::Error::Unauthorized))
        ));
        assert_eq!(destination.memory.read().await.unwrap(), old);
        assert_eq!(destination.writes.get(), 4);
    }
);

shared!(
    final_backend_wait_rechecks_completion_deadline_policy_and_wire,
    {
        for case in 0..5 {
            let destination = Destination::new();
            let (initial, mut key, network) = staged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let mut member = Member::new(&initial, &key);
            let attempt = attempt(initial, network, &mut member).await;
            let current = member.current.clone();
            let uses = member.uses.clone();
            let time = member.time.clone();
            let held = destination.read_gate.lock().await;
            destination.mode.set(5);
            let mut clock = ClockCell(time.clone());
            let mut entropy = FixtureEntropy;
            let mut pending = Box::pin(attempt.acknowledge(&mut clock, &mut entropy, &mut member));
            assert!(pending.as_mut().now_or_never().is_none());
            // Actual normal Use and private Keys acknowledgment completed; the
            // genuine external read is the remaining await before durable CAS.
            assert_eq!(uses.get(), 1);
            match case {
                0 => time.set(30),
                1 => time.set(9),
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
                3 => destination
                    .memory
                    .compare_exchange(Some(&old), &key.retained_checkpoint)
                    .await
                    .unwrap(),
                4 => {}
                _ => unreachable!(),
            }
            destination.mode.set(0);
            if case == 4 {
                drop(pending);
                drop(held);
            } else {
                drop(held);
                let result = pending.await;
                match case {
                    0 => assert!(matches!(
                        result,
                        Err(InitialError::Keys(ckmg::Error::Expired))
                    )),
                    1 => assert!(matches!(
                        result,
                        Err(InitialError::Keys(ckmg::Error::Clock))
                    )),
                    2 => assert!(matches!(
                        result,
                        Err(InitialError::Keys(ckmg::Error::Unauthorized))
                    )),
                    3 => assert!(matches!(
                        result,
                        Err(InitialError::Storage(cwst::Error::Conflict))
                    )),
                    _ => unreachable!(),
                }
            }
            assert_eq!(destination.writes.get(), 4);
            if case != 3 {
                assert_eq!(destination.memory.read().await.unwrap(), Some(old));
                let reopened = key
                    .opening()
                    .await
                    .reopen_initial(destination)
                    .await
                    .unwrap();
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
            }
        }
    }
);

shared!(
    post_cas_expiry_or_signed_revocation_returns_no_handle_but_reopens_acknowledged,
    {
        for expired in [false, true] {
            let destination = Destination::new();
            let (initial, mut key, network) = staged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap();
            let mut member = Member::new(&initial, &key);
            let attempt = attempt(initial, network, &mut member).await;
            let current = member.current.clone();
            let time = member.time.clone();
            let held = destination.read_gate.lock().await;
            destination.mode.set(6);
            let mut clock = ClockCell(time.clone());
            let mut entropy = FixtureEntropy;
            let mut pending = Box::pin(attempt.acknowledge(&mut clock, &mut entropy, &mut member));
            assert!(pending.as_mut().now_or_never().is_none());
            assert_eq!(destination.writes.get(), 5);
            assert_ne!(destination.memory.read().await.unwrap(), old);
            if expired {
                time.set(30);
            } else {
                let mut signer =
                    csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000)
                        .unwrap();
                *current.borrow_mut() = charter_members(&mut signer, &["original"]);
            }
            drop(held);
            let result = pending.await;
            if expired {
                assert!(matches!(
                    result,
                    Err(InitialError::Keys(ckmg::Error::Expired))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(InitialError::Keys(ckmg::Error::Unauthorized))
                ));
            }
            destination.mode.set(0);
            let reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            inspect_acknowledged(&reopened);
            assert_eq!(destination.writes.get(), 5);
        }
    }
);
