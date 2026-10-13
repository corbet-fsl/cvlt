//! Community credential record: bound, replaced only by compare-and-swap.
use super::*;
use crate::{CredentialError, CredentialWrite, MAX_COMMUNITY_CREDENTIAL_BYTES};

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[test]
fn first_store_read_replay_and_compare_and_swap_replace() {
    run(async {
        let (mut vault, _) = base().await;
        assert!(vault.community_credential().await.unwrap().is_none());
        assert_eq!(
            vault.replace_community_credential(None, b"one").await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"one"
        );
        // Replaying the identical credential writes nothing, whatever `expected` says.
        let before = vault.storage().lock().await.version().unwrap();
        assert_eq!(
            vault.replace_community_credential(None, b"one").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(vault.storage().lock().await.version().unwrap(), before);
        // A stale or missing expectation never overwrites.
        for expected in [None, Some(&b"zero"[..])] {
            assert_eq!(
                vault.replace_community_credential(expected, b"two").await,
                Err(CredentialError::Conflict)
            );
        }
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"one"
        );
        assert_eq!(
            vault
                .replace_community_credential(Some(b"one"), b"two")
                .await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"two"
        );
    });
}

#[test]
fn refused_keys_authority_reads_and_writes_nothing() {
    run(async {
        let (mut vault, deny) = base().await;
        vault
            .replace_community_credential(None, b"one")
            .await
            .unwrap();
        let before = vault.storage().lock().await.version().unwrap();
        deny.set(true);
        assert!(matches!(
            vault.community_credential().await,
            Err(CredentialError::Keys(_))
        ));
        assert!(matches!(
            vault
                .replace_community_credential(Some(b"one"), b"two")
                .await,
            Err(CredentialError::Keys(_))
        ));
        deny.set(false);
        assert_eq!(vault.storage().lock().await.version().unwrap(), before);
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"one"
        );
    });
}

#[test]
fn empty_oversized_and_global_scope_are_refused() {
    run(async {
        let (mut vault, _) = base().await;
        for bad in [vec![], vec![1; MAX_COMMUNITY_CREDENTIAL_BYTES + 1]] {
            assert_eq!(
                vault.replace_community_credential(None, &bad).await,
                Err(CredentialError::Invalid)
            );
        }
        let (mut global, _) =
            base_for("wallet", "00000000-0000-0000-0000-000000000011", true).await;
        assert_eq!(
            global.replace_community_credential(None, b"one").await,
            Err(CredentialError::Scope)
        );
        assert!(matches!(
            global.community_credential().await,
            Err(CredentialError::Scope)
        ));
    });
}

// Plant raw bytes under the record key exactly as an attacker with a Store write
// path (or a bug) would; the reader must refuse every non-exact binding.
async fn plant(vault: &mut TestVault, record: &[u8]) {
    let storage = vault.storage().clone();
    let mut store = storage.lock().await;
    let version = store.version().unwrap();
    store
        .commit(
            version,
            [99; 32],
            &[cwst::Change::Put {
                owner: "cvlt.community-credential",
                key: b"current",
                value: record,
            }],
            &[],
        )
        .await
        .unwrap();
}

#[test]
fn records_bound_elsewhere_or_malformed_are_foreign_and_never_replaced() {
    run(async {
        let (mut vault, _) = base().await;
        vault
            .replace_community_credential(None, b"one")
            .await
            .unwrap();
        let good = vault
            .storage()
            .lock()
            .await
            .read("cvlt.community-credential", b"current")
            .unwrap()
            .unwrap()
            .to_vec();
        // Device bytes sit right before the 4-byte credential length and the credential.
        let device_at = good.len() - 3 - 4 - 32;
        let mut other_device = good.clone();
        other_device[device_at] ^= 1;
        let mut other_community = good.clone();
        other_community[good
            .windows(b"wallet-test".len())
            .position(|w| w == b"wallet-test")
            .unwrap()] ^= 1;
        let mut other_member = good.clone();
        other_member[good
            .windows(b"fixture-member".len())
            .position(|w| w == b"fixture-member")
            .unwrap()] ^= 1;
        let mut trailing = good.clone();
        trailing.push(0);
        let mut header = good.clone();
        header[0] ^= 1;
        let mut empty = good[..good.len() - 3].to_vec();
        let length_at = empty.len() - 4;
        empty[length_at..].copy_from_slice(&0u32.to_be_bytes());
        for bad in [
            other_device,
            other_community,
            other_member,
            trailing,
            header,
            empty,
            good[..good.len() - 1].to_vec(),
            good[..10].to_vec(),
            vec![],
        ] {
            plant(&mut vault, &bad).await;
            assert!(matches!(
                vault.community_credential().await,
                Err(CredentialError::Foreign)
            ));
            assert_eq!(
                vault
                    .replace_community_credential(Some(b"one"), b"two")
                    .await,
                Err(CredentialError::Foreign)
            );
        }
        plant(&mut vault, &good).await;
        assert_eq!(
            &**vault.community_credential().await.unwrap().unwrap(),
            b"one"
        );
    });
}

fn pin(fingerprint: u8, head: Option<(u64, u8)>) -> crate::CommunityPin {
    crate::CommunityPin {
        fingerprint: [fingerprint; 32],
        head: head.map(|(ring_revision, byte)| crate::PinnedHead {
            ring_revision,
            digest: [byte; 32],
        }),
    }
}

#[test]
fn the_pin_moves_forward_only_by_compare_and_swap() {
    run(async {
        let (mut vault, deny) = base().await;
        assert_eq!(vault.community_pin().await, Ok(None));
        let first = pin(1, None);
        assert_eq!(vault.write_community_pin(None, &first, None).await, Ok(true));
        assert_eq!(vault.community_pin().await, Ok(Some(first)));
        // Identical replay writes nothing.
        let before = vault.storage().lock().await.version().unwrap();
        assert_eq!(vault.write_community_pin(Some(&first), &first, None).await, Ok(false));
        assert_eq!(vault.storage().lock().await.version().unwrap(), before);
        // A stale expectation never overwrites.
        assert_eq!(
            vault.write_community_pin(None, &pin(1, Some((1, 5))), None).await,
            Err(CredentialError::Conflict)
        );
        let at_two = pin(1, Some((2, 5)));
        assert_eq!(vault.write_community_pin(Some(&first), &at_two, None).await, Ok(true));
        // Rollback, fork and losing the head are refused.
        for bad in [pin(1, Some((1, 5))), pin(1, Some((2, 6))), pin(1, None)] {
            assert_eq!(
                vault.write_community_pin(Some(&at_two), &bad, None).await,
                Err(CredentialError::Conflict)
            );
        }
        assert_eq!(vault.write_community_pin(Some(&at_two), &pin(1, Some((3, 7))), None).await, Ok(true));
        // Another founding key starts without a head, never with one.
        let current = pin(1, Some((3, 7)));
        assert_eq!(
            vault.write_community_pin(Some(&current), &pin(2, Some((1, 1))), None).await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(vault.write_community_pin(Some(&current), &pin(2, None), None).await, Ok(true));
        deny.set(true);
        assert!(matches!(vault.community_pin().await, Err(CredentialError::Keys(_))));
        assert!(matches!(
            vault.write_community_pin(Some(&pin(2, None)), &pin(2, Some((1, 1))), None).await,
            Err(CredentialError::Keys(_))
        ));
    });
}

#[test]
fn the_pin_and_the_credential_change_in_one_commit_or_not_at_all() {
    run(async {
        let (mut vault, _) = base().await;
        let one = pin(1, None);
        let v0 = vault.storage().lock().await.version().unwrap();
        assert_eq!(vault.write_community_pin(None, &one, Some((None, b"cred"))).await, Ok(true));
        assert_eq!(vault.storage().lock().await.version().unwrap(), v0 + 1);
        assert_eq!(&**vault.community_credential().await.unwrap().unwrap(), b"cred");
        // A wrong credential expectation leaves the pin untouched too.
        let next = pin(1, Some((1, 2)));
        assert_eq!(
            vault.write_community_pin(Some(&one), &next, Some((Some(b"other"), b"new"))).await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(vault.community_pin().await, Ok(Some(one)));
        assert_eq!(
            vault.write_community_pin(Some(&one), &next, Some((Some(b"cred"), b"new"))).await,
            Ok(true)
        );
        assert_eq!(vault.community_pin().await, Ok(Some(next)));
        assert_eq!(&**vault.community_credential().await.unwrap().unwrap(), b"new");
        // An empty credential is invalid and writes nothing.
        assert_eq!(
            vault.write_community_pin(Some(&next), &pin(1, Some((2, 2))), Some((Some(b"new"), b""))).await,
            Err(CredentialError::Invalid)
        );
        // An unchanged credential with an advanced pin still commits the pin.
        assert_eq!(
            vault.write_community_pin(Some(&next), &pin(1, Some((2, 2))), Some((Some(b"new"), b"new"))).await,
            Ok(true)
        );
    });
}

#[test]
fn a_pin_bound_elsewhere_or_malformed_is_never_returned() {
    run(async {
        let (mut vault, _) = base().await;
        vault.write_community_pin(None, &pin(1, None), None).await.unwrap();
        let mut store = vault.storage().lock().await;
        let version = store.version().unwrap();
        for (i, junk) in [&b"junk"[..], b"cvlt.community-pin.v1\0\0"].into_iter().enumerate() {
            store
                .commit(
                    version + i as u64,
                    [9 + i as u8; 32],
                    &[cwst::Change::Put { owner: "cvlt.community-pin", key: b"current", value: junk }],
                    &[],
                )
                .await
                .unwrap();
            drop(store);
            assert_eq!(vault.community_pin().await, Err(CredentialError::Foreign));
            store = vault.storage().lock().await;
        }
    });
}
