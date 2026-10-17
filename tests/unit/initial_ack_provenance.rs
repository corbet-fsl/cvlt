//! Original enrollment/Keyhole/Charter/Records/Store ACK roundtrip. The strict
//! local completion checker is not a production HTTPS membership lease.
use super::super::acknowledgment_tests::{Member, attempt, recovery_member};
use super::*;

shared!(
    authentic_inner_without_exact_initial_carrier_refuses_recovery_before_output,
    {
        let (mut initial, _, _, member) = enrolled_ack().await;
        let mut authority = recovery_member(member);
        let recovery = initial
            .acknowledged_recovery(&mut TestClock(10), &mut authority)
            .await
            .unwrap();
        let sealed = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        let provenance = recovery
            .evidence
            .initial_acknowledgment(&initial.opening.inspector().unwrap(), &sealed)
            .unwrap();
        crate::retention::check_initial_ack(&recovery.inner, &provenance).unwrap();
        // Authenticate a real original Store with the same cipher, Keys, evidence,
        // revision and operation, but deliberately omit just this owner carrier.
        let mut missing = cwst::Store::create(
            cwst::backend::Memory::new(),
            recovery.bootstrap.store_cipher().unwrap(),
            "garden",
        )
        .await
        .unwrap();
        missing.commit(0, [98; 32], &[], &[]).await.unwrap();
        let mutations = recovery.evidence.retained_mutations().unwrap();
        let mut changes = vec![cwst::Change::Put {
            owner: "keys",
            key: initial.opening.locator.as_bytes(),
            value: &sealed,
        }];
        for mutation in &mutations {
            changes.push(cwst::Change::Put {
                owner: &mutation.owner,
                key: &mutation.key,
                value: mutation.value.as_deref().unwrap(),
            });
        }
        let operation = *initial.receipt().operation.as_bytes();
        missing.commit(1, operation, &changes, &[]).await.unwrap();
        assert_eq!(missing.version().unwrap(), 2);
        let wire = missing.sealed_checkpoint().unwrap().to_vec();
        let generation = initial.store.version().unwrap();
        initial
            .store
            .commit(
                generation,
                operation,
                &[cwst::Change::Put {
                    owner: OWNER,
                    key: ACKNOWLEDGED_INNER,
                    value: &wire,
                }],
                &[],
            )
            .await
            .unwrap();
        let refused = initial
            .acknowledged_recovery(&mut TestClock(10), &mut authority)
            .await;
        // The extra durable commit raises the logical store version past the
        // staged phases, so the phase check now refuses with Invalid before the
        // restored inner Store can report Corrupt; either way no output exists.
        assert!(
            matches!(
                refused,
                Err(InitialError::Invalid | InitialError::Storage(cwst::Error::Corrupt))
            ),
            "{:?}",
            refused.map(|_| ())
        );
    }
);

async fn enrolled_ack() -> (InitialCreation<Destination>, SameKey, Network, Member) {
    let (initial, key, network) = enrolled_staged(Destination::new()).await;
    let mut member = Member::new(&initial, &key);
    let pending_ack = attempt(initial, network.clone(), &mut member).await;
    let acknowledged = pending_ack
        .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut member)
        .await
        .unwrap();
    (acknowledged, key, network, member)
}

pub(super) async fn enrolled_staged(
    destination: Destination,
) -> (InitialCreation<Destination>, SameKey, Network) {
    let mut enrolling = Enrolling::new(destination.clone()).await;
    let pending = enrolling.initial.take().unwrap();
    let auth = enrolling.accept().await;
    let mut owner = activation(&enrolling, auth, &pending);
    let created = pending
        .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
        .await
        .unwrap();
    drop(owner);
    let auth = enrolling.authenticate().await;
    let descriptor = enrolling
        .server
        .registered_public_credential(auth.member(), auth.credential_id())
        .unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "garden",
        csgn::SecretKey::from_seed(&mut [77; 32]),
        9,
        60,
    )
    .await
    .unwrap();
    let certificate = enrolling
        .server
        .registration_certificate(auth.member(), auth.credential_id(), "original")
        .unwrap()
        .sign(&mut signer, 10)
        .await
        .unwrap();
    let renewed = enrolling
        .server
        .registration_certificate(auth.member(), auth.credential_id(), "original")
        .unwrap()
        .sign(&mut signer, 70)
        .await
        .unwrap();
    let (prepared, key) =
        certify_creation(created, enrolling.client, descriptor, certificate, renewed).await;
    let publication = prepared.publication_commitment().unwrap();
    let bound = enrolling
        .server
        .bind_initial_publication(&auth, enrolling.seed, publication)
        .unwrap();
    assert_eq!(bound.publication(), Some(publication));
    let (retained, mut key) = retain_certified(prepared, key).await;
    let pair = retained.retained().unwrap();
    let descriptor = pair.descriptor.decode().unwrap();
    let value = pair.value.decode().unwrap();
    drop(retained.stage(PublicationBackend::new()).await.unwrap());
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

shared!(
    normal_ack_carries_original_seed_publication_and_current_same_key_reauthorizes_after_old_expiry,
    {
        let (initial, mut key, _, _) = enrolled_ack().await;
        let original_wire = required(&initial.store, ACKNOWLEDGED_KEYS)
            .unwrap()
            .to_vec();
        let seed = initial.enrollment_commitment().unwrap();
        let publication = initial.publication_commitment().unwrap();
        let acknowledged = initial.acknowledged_candidate().unwrap();
        assert_eq!(acknowledged.enrollment_commitment(), seed);
        assert_eq!(acknowledged.publication_commitment(), publication);
        let mut signer =
            csgn::Signer::new("garden", csgn::SecretKey::from_seed(&mut [77; 32]), 9, 1000)
                .unwrap();
        let mut policy = charter(&mut signer);
        let current = policy.current(70).unwrap();
        assert!(
            acknowledged
                .evidence()
                .verify(current, "original", 70)
                .is_err()
        );
        let fresh = acknowledged
            .reauthorize(current, &key.renewed_certificate, "original", 70)
            .unwrap();
        assert_eq!(
            fresh.credential_id(70).unwrap(),
            key.descriptor.credential_id()
        );
        assert_eq!(
            fresh.lineage(70).unwrap(),
            initial.receipt().attested_lineage().unwrap().0
        );
        // The stamp twin never accepts passkey evidence, whatever stamp trust it is given.
        let stamp_params = cpsd::StampParams::new(86_400).unwrap();
        let stamp_key = cpsd::StampIssuerKey::generate(
            &mut cpsd::rand::rngs::OsRng,
            cpsd::KeyId::new("stamp-1").unwrap(),
            &stamp_params,
        )
        .unwrap();
        let stamps = crate::StampTrust::new(
            vec![crate::StampKeyPeriod::new(stamp_key.public_key().clone(), 0, None).unwrap()],
            stamp_params,
        )
        .unwrap();
        assert_eq!(
            acknowledged
                .reauthorize_with_stamps(current, &stamps, "original", 70)
                .unwrap_err(),
            crate::LineageError::Scope
        );
        // A fresh original passkey opening, with no pending/completion owner, reads
        // only authenticated public facts from this normal encrypted checkpoint.
        let opening = key.opening().await;
        let inspector = opening.inspector().unwrap();
        let provenance = acknowledged
            .evidence()
            .initial_acknowledgment(&inspector, &original_wire)
            .unwrap();
        assert_eq!(provenance.seed(), seed);
        assert_eq!(provenance.publication(), publication);
        let wrong_evidence = genuine(Destination::new()).await.1.evidence;
        assert!(
            crate::LineageEvidence::from_bytes(&wrong_evidence)
                .unwrap()
                .initial_acknowledgment(&inspector, &original_wire)
                .is_err()
        );
        let mut revoked = charter_members(&mut signer, &["original"]);
        assert!(
            acknowledged
                .reauthorize(
                    revoked.current(70).unwrap(),
                    &key.renewed_certificate,
                    "original",
                    70
                )
                .is_err()
        );
        assert_eq!(
            required(&initial.store, ACKNOWLEDGED_KEYS).unwrap(),
            original_wire
        );
    }
);
