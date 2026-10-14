//! Actual Keys/Store refusal boundaries. The shared strict setup adapter is
//! explicitly not HTTPS membership, current enrollment, proof or G3 authority.
use super::*;
use ckmg::wallet_engine::account::{AccountPolicy, Enrollment, ExtensionPolicy, GenesisContext};
use czkp::poseidon::{hash, integer, limbs};

fn tagged(domain: &[u8], tag: u64, fields: &[[u8; 32]]) -> [u8; 32] {
    let mut prefix = [0; 32];
    prefix[32 - domain.len()..].copy_from_slice(domain);
    let mut input = vec![prefix, integer(tag)];
    input.extend_from_slice(fields);
    hash(&input).unwrap()
}

fn projected_context(public: ckmg::wallet_engine::account_key::Projection) -> GenesisContext {
    let mut context = public_context(SCOPE);
    let row = &mut context.enrollment;
    row.key = public.public_key;
    row.secret_hash = public.registered_secret;
    let community = czkp::decode(&czkp::digest(SCOPE.as_bytes())).unwrap();
    let x: [u8; 32] = row.key[..32].try_into().unwrap();
    let y: [u8; 32] = row.key[32..].try_into().unwrap();
    let mut fields = [limbs(&community), limbs(&row.member), limbs(&x), limbs(&y)].concat();
    fields.extend([
        row.secret_hash,
        integer(row.starts_at),
        integer(row.expires_at),
    ]);
    fields.extend(limbs(&row.delegation_digest));
    row.leaf = tagged(b"cfrm.account-state.v2", 1, &fields);
    let mut root = row.leaf;
    for sibling in row.path {
        root = tagged(b"cfrm.accounting.poseidon2.v1", 6, &[root, sibling]);
    }
    context.enrollment_root = root;
    context
}

#[test]
fn genuine_keys_prepare_and_current_check_then_refusal_and_cancellation_fence() {
    futures_executor::block_on(async {
        use futures::FutureExt;
        for cancel in [false, true] {
            let (mut vault, deny) = base().await;
            let storage = vault.storage.clone();
            let engine = vault.keys.wallet_engine().await.unwrap();
            {
                let mut store = storage.lock().await;
                let mut pending = cwlt::account_owner::DurableAccountOwner::prepare(
                    engine, &store, SCOPE, [83; 32],
                )
                .unwrap();
                pending.commit(&mut store).await.unwrap();
            }
            let mut vault = vault.restore_community_account().await.unwrap();
            let context = projected_context(vault.account_projection().await.unwrap());
            let before = storage.lock().await.sealed_checkpoint().unwrap().to_vec();
            let candidate = vault
                .prepare_community_genesis(context.clone(), NOW)
                .await
                .unwrap();
            vault
                .check_community_genesis(&candidate, &context, NOW)
                .await
                .unwrap();
            if cancel {
                let guard = storage.lock().await;
                let mut checking =
                    Box::pin(vault.check_community_genesis(&candidate, &context, NOW));
                assert!(checking.as_mut().now_or_never().is_none());
                drop(checking);
                drop(guard);
            } else {
                deny.set(true);
                assert!(matches!(
                    vault
                        .check_community_genesis(&candidate, &context, NOW)
                        .await,
                    Err(WalletRestoreError::Keys(Error::Unauthorized))
                ));
                deny.set(false);
                // The genuine Keys owner locked on authority refusal. Unlock
                // the same encrypted winner with its original PRF, no Create.
                let prf = ckmg::passkey::PrfOutput::from_bytes(&[7; 32]).unwrap();
                vault.keys.unlock(&prf, SCOPE).await.unwrap();
            }
            assert!(matches!(
                vault
                    .check_community_genesis(&candidate, &context, NOW)
                    .await,
                Err(WalletRestoreError::Account(_))
            ));
            assert_eq!(storage.lock().await.sealed_checkpoint().unwrap(), before);
        }
    });
}

#[test]
fn real_capsule_replacement_refuses_current_genesis_without_releasing_state() {
    futures_executor::block_on(async {
        let (mut vault, _) = base().await;
        let storage = vault.storage.clone();
        let engine = vault.keys.wallet_engine().await.unwrap();
        {
            let mut store = storage.lock().await;
            let mut pending =
                cwlt::account_owner::DurableAccountOwner::prepare(engine, &store, SCOPE, [84; 32])
                    .unwrap();
            pending.commit(&mut store).await.unwrap();
        }
        let mut vault = vault.restore_community_account().await.unwrap();
        let context = projected_context(vault.account_projection().await.unwrap());
        let candidate = vault
            .prepare_community_genesis(context.clone(), NOW)
            .await
            .unwrap();
        {
            let mut store = storage.lock().await;
            let version = store.version().unwrap();
            store
                .commit_with_receipt(
                    version,
                    [85; 32],
                    &[cwst::Change::Put {
                        owner: "cwlt.account",
                        key: b"owner.v1",
                        value: b"changed capsule",
                    }],
                    &[],
                )
                .await
                .unwrap();
        }
        assert!(
            vault
                .check_community_genesis(&candidate, &context, NOW)
                .await
                .is_err()
        );
        assert!(
            vault
                .check_community_genesis(&candidate, &context, NOW)
                .await
                .is_err()
        );
    });
}

fn public_context(scope: &str) -> GenesisContext {
    GenesisContext {
        community_id: scope.into(),
        owner: [3; 32],
        checked_at: NOW,
        policy: AccountPolicy {
            initial_credit: 20,
            maximum_available: 100,
            outgoing_reservation: 5,
            incoming_reservation: 5,
            policy_revision: 1,
            policy_valid_from: NOW - 1,
            policy_valid_until: NOW + 10000,
            newcomer_period: 100,
            rate_window: 100,
            newcomer_admissions: 2,
            maximum_admissions: 10,
            refill_period: 100,
            refill_units: 2,
            abandon_after: 200,
        },
        extension: ExtensionPolicy {
            revision: 1,
            quorum: 2,
            change_cost: 1,
            delay: 100,
            batch: 2,
            standing: ExtensionPolicy::standing_digest(czkp::reference::params()).unwrap(),
        },
        standing: czkp::reference::params(),
        bond: None,
        enrollment: Enrollment {
            member: [3; 32],
            key: [0; 64],
            secret_hash: [0; 32],
            starts_at: NOW - 1,
            expires_at: NOW + 10000,
            delegation_digest: [4; 32],
            leaf: [0; 32],
            index: 0,
            path: [[0; 32]; 32],
        },
        enrollment_root: [0; 32],
    }
}

#[test]
fn fresh_original_keys_refusal_and_wrong_community_do_not_prepare_or_write() {
    futures_executor::block_on(async {
        let (mut vault, deny) = base().await;
        let storage = vault.storage.clone();
        let engine = vault.keys.wallet_engine().await.unwrap();
        {
            let mut store = storage.lock().await;
            let mut candidate =
                cwlt::account_owner::DurableAccountOwner::prepare(engine, &store, SCOPE, [81; 32])
                    .unwrap();
            candidate.commit(&mut store).await.unwrap();
        }
        let mut vault = vault.restore_community_account().await.unwrap();
        let before = storage.lock().await.sealed_checkpoint().unwrap().to_vec();
        assert!(matches!(
            vault
                .prepare_community_genesis(public_context("foreign"), NOW)
                .await,
            Err(WalletRestoreError::Scope)
        ));
        deny.set(true);
        assert!(matches!(
            vault
                .prepare_community_genesis(public_context(SCOPE), NOW)
                .await,
            Err(WalletRestoreError::Keys(Error::Unauthorized))
        ));
        assert_eq!(storage.lock().await.sealed_checkpoint().unwrap(), before);
    });
}

#[test]
fn cancellation_while_waiting_for_actual_store_guard_releases_no_candidate() {
    futures_executor::block_on(async {
        use futures::FutureExt;
        let (mut vault, _) = base().await;
        let storage = vault.storage.clone();
        let engine = vault.keys.wallet_engine().await.unwrap();
        {
            let mut store = storage.lock().await;
            let mut candidate =
                cwlt::account_owner::DurableAccountOwner::prepare(engine, &store, SCOPE, [82; 32])
                    .unwrap();
            candidate.commit(&mut store).await.unwrap();
        }
        let mut vault = vault.restore_community_account().await.unwrap();
        let guard = storage.lock().await;
        let before = guard.sealed_checkpoint().unwrap().to_vec();
        let mut pending = Box::pin(vault.prepare_community_genesis(public_context(SCOPE), NOW));
        assert!(pending.as_mut().now_or_never().is_none());
        drop(pending);
        assert_eq!(guard.sealed_checkpoint().unwrap(), before);
    });
}
