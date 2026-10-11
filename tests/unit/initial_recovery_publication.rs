//! Real acknowledged Store, normal bootstrap and original recovery codecs.
//! Local node placement below checks interoperability, not production flush.
use super::*;

#[path = "initial_recovery_transport.rs"]
mod transport_tests;

struct RecoveryMember(Member, bool);
impl RecoveryMember {
    fn exact_use(&self, r: &ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        let (lineage, author) = self.0.original.receipt.attested_lineage()?;
        if r.action != ckmg::Action::Use
            || r.binding != &lineage.binding
            || r.root != Some(lineage.root)
            || r.device != author
            || r.epoch != lineage.epoch
            || r.target.is_some()
            || r.statement != Some(lineage.digest()?)
            || r.signing.is_some()
            || r.evidence != self.0.evidence.to_bytes().unwrap().as_slice()
            || !(10..70).contains(&r.now)
        {
            return Err(ckmg::Error::Unauthorized);
        }
        self.0.verify(r.now)
    }
}
impl Authority for RecoveryMember {
    async fn check(&mut self, r: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        self.1 = false;
        self.exact_use(&r)?;
        let read = self
            .0
            .records
            .as_mut()
            .ok_or(ckmg::Error::Unauthorized)?
            .read()
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        if read.evidence().len() != 1
            || read.evidence()[0].to_bytes().unwrap() != self.0.evidence.to_bytes().unwrap()
        {
            return Err(ckmg::Error::Unauthorized);
        }
        let completed = self.0.time.get();
        if completed < r.now || completed >= 70 {
            return Err(ckmg::Error::Unauthorized);
        }
        self.0.verify(completed)?;
        self.0.uses.set(self.0.uses.get() + 1);
        self.1 = true;
        Ok(())
    }
    // Dedicated pending creation ports deliberately keep their original default
    // denial. Completed recovery uses only the exact normal checkpoint request.
    fn check_checkpoint_current(&mut self, r: ckmg::Authorization<'_>) -> Result<u64, ckmg::Error> {
        if !self.1 {
            return Err(ckmg::Error::Unauthorized);
        }
        self.exact_use(&r)?;
        let completed = self.0.time.get();
        if completed < r.now || completed >= 70 {
            return Err(ckmg::Error::Unauthorized);
        }
        self.0.verify(completed)?;
        Ok(completed)
    }
}

async fn acknowledged(
    destination: Destination,
) -> (
    InitialCreation<Destination>,
    SameKey,
    Network,
    RecoveryMember,
) {
    let (initial, key, network) = staged(destination).await;
    let mut member = Member::new(&initial, &key);
    let attempt = attempt(initial, network.clone(), &mut member).await;
    let initial = attempt
        .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut member)
        .await
        .unwrap();
    member.original = ExactCompletion::new(&initial);
    member.completion_started = false;
    (initial, key, network, RecoveryMember(member, false))
}

async fn fixture_place_outputs(initial: &InitialCreation<Destination>, network: &Network) {
    // Each retained original descriptor/value is checked by every actual node.
    // This is test-owned node population; stage_recovery never calls Network.set.
    for output in initial
        .store
        .load_pending()
        .unwrap()
        .into_iter()
        .filter(|o| o.id[0] == 3)
    {
        let pair: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        let descriptor = cdht::rpc::DescriptorBytes::from_bytes(
            serde_json::from_value(pair["descriptor"].clone()).unwrap(),
        )
        .unwrap()
        .decode()
        .unwrap();
        let value = cdht::rpc::ValueBytes::from_bytes(
            serde_json::from_value(pair["value"].clone()).unwrap(),
        )
        .unwrap()
        .decode()
        .unwrap();
        let subkey = pair["subkey"].as_u64().unwrap() as u32;
        for (_, node) in network.nodes.iter() {
            if node.descriptor(&descriptor.key()).await.unwrap().is_none() {
                node.create(&descriptor).await.unwrap();
            }
            node.set(&descriptor.key(), subkey, &value).await.unwrap();
        }
    }
}

shared!(
    actual_recovery_queue_roundtrips_original_passkey_and_compound_readers,
    {
        let destination = Destination::new();
        let (initial, mut key, network, mut member) = acknowledged(destination.clone()).await;
        let acknowledged_wire = required(&initial.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        let acknowledged_keys = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        let uses = member.0.uses.get();
        let initial = initial
            .stage_recovery(
                network.clone(),
                &mut TestClock(10),
                &mut ckmg::SystemEntropy,
                &mut member,
            )
            .await
            .unwrap();
        assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryStaged);
        assert_eq!(initial.store.version().unwrap(), 6);
        assert_eq!(member.0.uses.get(), uses + 1);
        assert_eq!(network.sets.get(), 0);
        let state = initial.recovery_state().unwrap();
        assert!(state.queue().len() >= 3); // compound data + manifest + passkey
        assert_eq!(
            initial.store.load_pending().unwrap().len(),
            state.queue().len() + 2
        );
        assert!(
            state
                .queue()
                .iter()
                .all(|entry| entry.value.seq == 2 && entry.value.nonce.is_some())
        );
        let nonces: std::collections::BTreeSet<_> = state
            .queue()
            .iter()
            .map(|entry| entry.value.nonce.unwrap())
            .collect();
        assert_eq!(nonces.len(), state.queue().len());
        let retained = required(&initial.store, RECOVERY).unwrap().to_vec();
        fixture_place_outputs(&initial, &network).await;
        let inspector = initial.opening.inspector().unwrap();
        let bootstrap = inspector
            .bootstrap(
                &acknowledged_keys,
                &key.evidence,
                &mut TestClock(10),
                &mut member,
            )
            .await
            .unwrap();
        let passkey = crate::TorPasskeyRecord::open(
            network.clone(),
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
        assert_eq!(checkpoint.sequence(), 2);
        assert_eq!(checkpoint.sealed(), acknowledged_keys);
        assert_eq!(
            checkpoint.evidence().unwrap().to_bytes().unwrap(),
            key.evidence
        );
        let root = cdht::runtime::Record::new(
            crate::TorReadRecord::checkpoint(network.clone(), bootstrap.record(None).unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut children = Vec::new();
        for index in 0..crate::MAX_CHECKPOINT_RECORDS {
            children.push(
                cdht::runtime::Record::new(
                    crate::TorReadRecord::checkpoint(
                        network.clone(),
                        bootstrap.record(Some(index as u8)).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
        }
        let mut compound = crate::CompoundRecords::new("garden", root, children).unwrap();
        let observed = compound.checkpoint().await.unwrap();
        let restored = observed
            .restore(
                cwst::backend::Memory::new(),
                bootstrap.store_cipher().unwrap(),
                "garden",
            )
            .await
            .unwrap();
        assert_eq!(restored.version().unwrap(), 2);
        assert_eq!(restored.sealed_checkpoint().unwrap(), acknowledged_wire);
        assert_eq!(
            restored
                .read("keys", initial.opening.locator.as_bytes())
                .unwrap(),
            Some(acknowledged_keys.as_slice())
        );
        drop(compound);
        drop(bootstrap);
        drop(initial);
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(required(&reopened.store, RECOVERY).unwrap(), retained);
        assert_eq!(reopened.recovery_state().unwrap(), state);
        assert!(matches!(
            reopened
                .stage_recovery(
                    network.clone(),
                    &mut TestClock(10),
                    &mut ckmg::SystemEntropy,
                    &mut member
                )
                .await,
            Err(InitialError::Invalid)
        ));
        assert_eq!(destination.writes.get(), 6);
        assert_eq!(network.sets.get(), 0);
    }
);

shared!(
    recovery_cancellation_and_unknown_outer_cas_reopen_exact_durable_phase,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let (initial, mut key, network, mut member) = acknowledged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap();
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let mut entropy = ckmg::SystemEntropy;
            let mut pending = Box::pin(initial.stage_recovery(
                network.clone(),
                &mut clock,
                &mut entropy,
                &mut member,
            ));
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
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Acknowledged);
                assert_eq!(destination.memory.read().await.unwrap(), old);
            } else {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::RecoveryStaged);
                assert!(!reopened.recovery_state().unwrap().queue().is_empty());
            }
            assert_eq!(destination.writes.get(), 6);
            assert_eq!(network.sets.get(), 0);
        }
    }
);

shared!(
    recovery_normal_use_wait_and_final_outer_cas_recheck_actual_current_owner,
    {
        for case in 0..5 {
            let destination = Destination::new();
            let (initial, mut key, network, mut member) = acknowledged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap().unwrap();
            let time = member.0.time.clone();
            let current = member.0.current.clone();
            let held = if case == 4 {
                destination.mode.set(6);
                destination.read_gate.lock().await
            } else {
                network.gate.lock().await
            };
            let mut clock = ClockCell(time.clone());
            let mut entropy = ckmg::SystemEntropy;
            let mut pending = Box::pin(initial.stage_recovery(
                network.clone(),
                &mut clock,
                &mut entropy,
                &mut member,
            ));
            assert!(pending.as_mut().now_or_never().is_none());
            match case {
                0 | 4 => time.set(70),
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
            assert!(pending.await.is_err());
            destination.mode.set(0);
            assert_eq!(network.sets.get(), 0);
            if case == 4 {
                assert_eq!(destination.writes.get(), 6);
                let reopened = key
                    .opening()
                    .await
                    .reopen_initial(destination)
                    .await
                    .unwrap();
                assert_eq!(reopened.phase().unwrap(), InitialPhase::RecoveryStaged);
            } else {
                assert_eq!(destination.writes.get(), 5);
                if case != 3 {
                    assert_eq!(destination.memory.read().await.unwrap(), Some(old));
                }
            }
        }
    }
);

shared!(
    recovery_authenticates_acknowledged_inner_before_normal_bootstrap,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged(destination.clone()).await;
        let staged_wire = destination.memory.read().await.unwrap().unwrap();
        let mut original = Member::new(&initial, &key);
        let attempt = attempt(initial, network.clone(), &mut original).await;
        let acknowledged = attempt
            .acknowledge(&mut TestClock(10), &mut FixtureEntropy, &mut original)
            .await
            .unwrap();
        let mut inner = required(&acknowledged.store, ACKNOWLEDGED_INNER)
            .unwrap()
            .to_vec();
        inner[0] ^= 1;
        let keys = required(&acknowledged.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        drop(acknowledged);
        let counterfeit = Destination::new();
        counterfeit
            .memory
            .compare_exchange(None, &staged_wire)
            .await
            .unwrap();
        let mut initial = key
            .opening()
            .await
            .reopen_initial(counterfeit.clone())
            .await
            .unwrap();
        initial
            .store
            .commit(
                4,
                *initial.receipt().operation.as_bytes(),
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: ACKNOWLEDGED_INNER,
                        value: &inner,
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: ACKNOWLEDGED_KEYS,
                        value: &keys,
                    },
                ],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(initial.phase().unwrap(), InitialPhase::Acknowledged);
        original.original = ExactCompletion::new(&initial);
        original.completion_started = false;
        let mut member = RecoveryMember(original, false);
        let uses = member.0.uses.get();
        let old = counterfeit.memory.read().await.unwrap();
        assert!(matches!(
            initial
                .stage_recovery(
                    network.clone(),
                    &mut TestClock(10),
                    &mut ckmg::SystemEntropy,
                    &mut member
                )
                .await,
            Err(InitialError::Storage(_))
        ));
        assert_eq!(member.0.uses.get(), uses + 1);
        assert_eq!(counterfeit.memory.read().await.unwrap(), old);
        assert_eq!(network.sets.get(), 0);
    }
);

shared!(
    recovery_wrong_scope_or_real_other_passkey_cannot_open_acknowledged_state,
    {
        for wrong_prf in [false, true] {
            let destination = Destination::new();
            let (mut initial, _key, network, mut member) = acknowledged(destination.clone()).await;
            let old = destination.memory.read().await.unwrap();
            if wrong_prf {
                let (_other, mut key) = genuine(Destination::new()).await;
                // A distinct real resident passkey supplies this PRF via its own
                // original sign_in. No caller-crafted PRF/credential constructor.
                initial.opening.prf = key.opening().await.prf;
            } else {
                initial.opening.scope = "other-community".into();
            }
            let uses = member.0.uses.get();
            assert!(
                initial
                    .stage_recovery(
                        network.clone(),
                        &mut TestClock(10),
                        &mut ckmg::SystemEntropy,
                        &mut member
                    )
                    .await
                    .is_err()
            );
            assert_eq!(member.0.uses.get(), uses);
            assert_eq!(destination.memory.read().await.unwrap(), old);
            assert_eq!(destination.writes.get(), 5);
            assert_eq!(network.sets.get(), 0);
        }
    }
);

shared!(
    completed_acknowledgment_uses_fresh_normal_authority_before_and_after_old_intent_expiry,
    {
        for now in [20, 40] {
            let destination = Destination::new();
            let (initial, mut key, network, mut previous) = acknowledged(destination.clone()).await;
            drop(initial);
            let initial = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            // Rebuild the strict owner from the authenticated reopened state.
            // Transfer only fixed read custody; no earlier Use result survives.
            let mut fresh = Member::new(&initial, &key);
            fresh.records = previous.0.records.take();
            drop(previous);
            let mut member = RecoveryMember(fresh, false);
            member.0.time.set(now);
            let old = decode_intent(required(&initial.store, INTENT).unwrap()).unwrap();
            assert_eq!(old.expires, 30);
            let pending = initial
                .opening
                .inspector()
                .unwrap()
                .pending_creation(required(&initial.store, KEYS).unwrap())
                .unwrap();
            let pending_intent = ckmg::CompletionIntent {
                outer_generation: initial.store.version().unwrap(),
                outer_digest: *blake3::hash(initial.store.sealed_checkpoint().unwrap()).as_bytes(),
                inner_version: 1,
                inner_operation: initial_operation(&initial.store).unwrap(),
                inner_digest: *blake3::hash(required(&initial.store, INNER).unwrap()).as_bytes(),
                nonce: old.nonce,
                packed_evidence: old.packed_evidence.clone(),
                prepared_at: old.prepared_at,
                expires: old.expires,
            };
            // This real pending checkpoint remains a pending attempt: normal Use
            // cannot satisfy its dedicated completion port, or renew its expiry.
            let refused = pending
                .authorize_completion(pending_intent, &mut TestClock(now), &mut member)
                .await;
            assert!(matches!(
                (now, refused),
                (20, Err(ckmg::Error::Unauthorized)) | (40, Err(ckmg::Error::Expired))
            ));
            let gets_before = network.gets.get();
            let initial = initial
                .stage_recovery(
                    network.clone(),
                    &mut TestClock(now),
                    &mut ckmg::SystemEntropy,
                    &mut member,
                )
                .await
                .unwrap();
            assert_eq!(initial.phase().unwrap(), InitialPhase::RecoveryStaged);
            assert_eq!(
                decode_intent(required(&initial.store, INTENT).unwrap())
                    .unwrap()
                    .expires,
                30
            );
            assert_eq!(initial.store.version().unwrap(), 6);
            assert_eq!(destination.writes.get(), 6);
            assert_eq!(member.0.uses.get(), 1);
            assert_eq!(network.gets.get(), gets_before + 3);
            assert_eq!(network.sets.get(), 0);
        }
    }
);
