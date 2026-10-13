//! Actual enrolled community ACK installs only the original durable account key.
//! The strict original fixture checks crypto/currentness, not live HTTPS G3.
use super::super::acknowledgment_tests::{Member, attempt, recovered_account_owner};
use super::acknowledged_provenance_tests::enrolled_staged;
use super::*;

shared!(
    community_ack_restores_one_original_account_owner_and_refuses_competing_clone,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = enrolled_staged(destination.clone()).await;
        let duplicate = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        let mut first = Member::new(&initial, &key);
        let mut second = Member::new(&duplicate, &key);
        let a = attempt(initial, network.clone(), &mut first).await;
        let b = attempt(duplicate, network, &mut second).await;
        let initial = a
            .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut first)
            .await
            .unwrap();
        let winner = recovered_account_owner(&initial, first).await;
        assert_ne!(winner.1.public_key, [0; 64]);
        assert_ne!(winner.1.registered_secret, [0; 32]);
        let exact = destination.memory.read().await.unwrap();
        assert!(
            b.acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut second)
                .await
                .is_err()
        );
        assert_eq!(destination.memory.read().await.unwrap(), exact);
        drop(initial);
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(recovered_account_owner(&reopened, second).await, winner);
        assert_eq!(destination.memory.read().await.unwrap(), exact);
    }
);

shared!(
    community_ack_cancel_and_unknown_never_expose_uncommitted_account_projection,
    {
        for mode in [1, 2, 3] {
            let destination = Destination::new();
            let (initial, mut key, network) = enrolled_staged(destination.clone()).await;
            let before = destination.memory.read().await.unwrap();
            let writes = destination.writes.get();
            let mut member = Member::new(&initial, &key);
            let pending = attempt(initial, network, &mut member).await;
            destination.mode.set(mode);
            let mut clock = TestClock(10);
            let mut entropy = ckmg::SystemEntropy;
            let mut future = Box::pin(pending.acknowledge(&mut clock, &mut entropy, &mut member));
            if mode == 3 {
                assert!(matches!(
                    future.await,
                    Err(InitialError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(future.as_mut().now_or_never().is_none());
                drop(future);
            }
            assert_eq!(destination.writes.get(), writes + 1);
            destination.mode.set(0);
            let reopened = key
                .opening()
                .await
                .reopen_initial(destination.clone())
                .await
                .unwrap();
            if mode == 1 {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
                assert!(reopened.acknowledged_candidate().is_err());
                assert!(
                    reopened
                        .store
                        .read(OWNER, ACKNOWLEDGED_INNER)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(destination.memory.read().await.unwrap(), before);
            } else {
                assert_eq!(reopened.phase().unwrap(), InitialPhase::Acknowledged);
                let owner = recovered_account_owner(&reopened, member).await;
                assert!(!owner.0.is_empty());
                assert_ne!(owner.1.public_key, [0; 64]);
            }
        }
    }
);

shared!(
    revoked_enrolled_community_cannot_install_account_or_create_global_passport,
    {
        let destination = Destination::new();
        let (initial, mut key, network) = enrolled_staged(destination.clone()).await;
        let before = destination.memory.read().await.unwrap();
        let writes = destination.writes.get();
        let mut member = Member::new(&initial, &key);
        let pending = attempt(initial, network, &mut member).await;
        member.revoke_original_member(ORIGIN);
        assert!(
            pending
                .acknowledge(&mut TestClock(10), &mut ckmg::SystemEntropy, &mut member)
                .await
                .is_err()
        );
        let reopened = key
            .opening()
            .await
            .reopen_initial(destination.clone())
            .await
            .unwrap();
        assert_eq!(reopened.phase().unwrap(), InitialPhase::Staged);
        assert!(reopened.acknowledged_candidate().is_err());
        assert_eq!(destination.writes.get(), writes);
        assert_eq!(destination.memory.read().await.unwrap(), before);
    }
);
