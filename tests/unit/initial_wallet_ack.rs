//! Real original wallet enrollment, certified lineage and production ACK batch.
//! The scoped crypto/currentness checker is not a live CGBl/HTTPS eligibility lease.
use super::super::acknowledgment_tests::{Member, attempt, recovered_wallet_holder};
use super::*;

const WALLET_ORIGIN: &str = "https://wallet.garden.example.test";
const WALLET_RP: &str = "wallet.garden.example.test";

async fn staged_wallet(
    destination: Destination,
) -> (InitialCreation<Destination>, SameKey, Network) {
    let member = ckyh::Uuid::from_u128(17).to_string();
    let mut enrolling = Enrolling::in_realm(
        destination.clone(),
        0,
        "wallet",
        WALLET_ORIGIN,
        WALLET_RP,
        member,
    )
    .await;
    let pending = enrolling.initial.take().unwrap();
    let auth = enrolling.accept().await;
    assert_eq!(auth.member().to_string(), enrolling.member);
    let mut owner = activation(&enrolling, auth, &pending);
    let created = pending
        .activate(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut owner)
        .await
        .unwrap();
    drop(owner);
    let auth = enrolling.authenticate().await;
    let descriptor = enrolling.server.public_credential(&auth).unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "wallet",
        csgn::SecretKey::from_seed(&mut [77; 32]),
        9,
        60,
    )
    .await
    .unwrap();
    // Actual registered wallet key projection chooses the authenticated UUID;
    // the fixture does not manufacture a community certificate or descriptor.
    let certificate = enrolling
        .server
        .wallet_registration_certificate(&auth)
        .unwrap()
        .sign(&mut signer, 10)
        .await
        .unwrap();
    let renewed = enrolling
        .server
        .wallet_registration_certificate(&auth)
        .unwrap()
        .sign(&mut signer, 70)
        .await
        .unwrap();
    let (prepared, key) = certify_creation_for(
        created,
        enrolling.client,
        descriptor,
        certificate,
        renewed,
        WALLET_ORIGIN,
    )
    .await;
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
    wallet_production_ack_commits_same_holder_with_original_keys_and_provenance,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged_wallet(destination.clone()).await;
        let duplicate = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let mut first = Member::new(&initial, &key);
        let mut second = Member::new(&duplicate, &key);
        let first_attempt = attempt(initial, network.clone(), &mut first).await;
        let duplicate_attempt = attempt(duplicate, network.clone(), &mut second).await;
        let mut acknowledged = first_attempt
            .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut first)
            .await
            .unwrap();
        let original_wire = destination.memory.read().await.unwrap().unwrap();
        let original_holder = recovered_wallet_holder(&mut acknowledged, first).await;
        assert!(!original_holder.0.is_empty());
        assert_eq!(original_holder.1.len(), 48);
        assert!(
            duplicate_attempt
                .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut second)
                .await
                .is_err()
        );
        assert_eq!(
            destination.memory.read().await.unwrap(),
            Some(original_wire.clone())
        );
        drop(acknowledged);
        let mut reopened = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Acknowledged);
        // Reuse the losing attempt's already-attached original forced record owner;
        // its immutable original lineage is exactly the winner's, not a new grant.
        assert_eq!(
            recovered_wallet_holder(&mut reopened, second).await,
            original_holder
        );
        assert!(
            reopened
                .read_first_lineage(network, &mut TestClock(10))
                .await
                .is_err()
        );
        assert_eq!(
            destination.memory.read().await.unwrap(),
            Some(original_wire)
        );
    }
);

shared!(
    wallet_ack_cancel_before_or_after_outer_cas_recovers_only_actual_phase,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let (initial, mut key, network) = staged_wallet(destination.clone()).await;
            let before = destination.memory.read().await.unwrap().unwrap();
            let mut member = Member::new(&initial, &key);
            let pending_ack = attempt(initial, network, &mut member).await;
            let before_writes = destination.writes.get();
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let mut entropy = ckmg::SystemEntropy;
            let mut future =
                Box::pin(pending_ack.acknowledge(&mut clock, &mut entropy, &mut member));
            if mode == 3 {
                assert!(matches!(
                    future.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(future.as_mut().now_or_never().is_none());
                drop(future);
            }
            // The only real backend write belongs to the final outer CAS. Reaching
            // this point means the original inner Keys/holder ACK batch has run.
            assert_eq!(destination.writes.get(), before_writes + 1);
            destination.mode.set(0);
            let mut reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            if mode == 1 {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
                assert!(reopened.acknowledged_candidate().is_err());
                assert_eq!(destination.memory.read().await.unwrap(), Some(before));
                assert!(
                    reopened
                        .store
                        .read(OWNER, ACKNOWLEDGED_INNER)
                        .unwrap()
                        .is_none()
                );
            } else {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Acknowledged);
                let record = recovered_wallet_holder(&mut reopened, member).await;
                assert!(!record.0.is_empty());
                assert_eq!(record.1.len(), 48);
                let exact = destination.memory.read().await.unwrap();
                drop(reopened);
                let again = key
                    .opening()
                    .await
                    .reopen_initial(destination.clone())
                    .await
                    .unwrap();
                assert_eq!(again.phase().unwrap(), InitialPhase::Acknowledged);
                assert_eq!(destination.memory.read().await.unwrap(), exact);
            }
        }
    }
);

shared!(
    wallet_ack_revoked_same_key_and_foreign_scope_never_install_or_regenerate_holder,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = staged_wallet(destination.clone()).await;
        let exact = destination.memory.read().await.unwrap();
        let writes = destination.writes.get();
        let mut member = Member::new(&initial, &key);
        let pending = attempt(initial, network, &mut member).await;
        member.revoke_original_member(WALLET_ORIGIN);
        assert!(
            pending
                .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut member)
                .await
                .is_err()
        );
        assert_eq!(destination.writes.get(), writes);
        assert_eq!(destination.memory.read().await.unwrap(), exact);
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
        assert!(reopened.acknowledged_candidate().is_err());
        assert!(
            reopened
                .store
                .read(OWNER, ACKNOWLEDGED_INNER)
                .unwrap()
                .is_none()
        );
        drop(reopened);
        // A real same-key PRF at a foreign scope cannot open the wallet ciphertext.
        let (_, custody) = key
            .client
            .sign_in(serde_json::to_value(key.descriptor.request([29; 32])).unwrap())
            .await
            .unwrap()
            .into_parts();
        let cpky::VaultOutcome::Ready(unlock) = custody else {
            panic!("original PRF missing")
        };
        let foreign = PreparedOpen::new(unlock, "garden").unwrap();
        assert!(foreign.reopen_initial(destination.clone()).await.is_err());
        assert_eq!(destination.writes.get(), writes);
        assert_eq!(destination.memory.read().await.unwrap(), exact);
    }
);
