//! Delegation record: bound, replaced only by compare-and-swap, empty means none,
//! durable across a reopened vault, and independent of the owed update.
use super::*;
use crate::{CredentialError, CredentialWrite, MAX_DELEGATION_OUTBOX_BYTES};

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[test]
fn store_read_clear_and_compare_and_swap_replace() {
    run(async {
        let (mut vault, _) = base().await;
        assert!(vault.delegation_outbox().await.unwrap().is_none());
        assert_eq!(
            vault.replace_delegation_outbox(None, b"sent").await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(
            &**vault.delegation_outbox().await.unwrap().unwrap(),
            b"sent"
        );
        // A second writer that read nothing (or something else) loses and writes nothing.
        assert_eq!(
            vault.replace_delegation_outbox(None, b"other").await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(
            vault
                .replace_delegation_outbox(Some(b"stale"), b"other")
                .await,
            Err(CredentialError::Conflict)
        );
        assert_eq!(
            &**vault.delegation_outbox().await.unwrap().unwrap(),
            b"sent"
        );
        assert_eq!(
            vault
                .replace_delegation_outbox(Some(b"sent"), b"registered")
                .await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(
            vault.replace_delegation_outbox(None, b"registered").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(
            vault
                .replace_delegation_outbox(Some(b"registered"), b"")
                .await,
            Ok(CredentialWrite::Stored)
        );
        assert!(vault.delegation_outbox().await.unwrap().is_none());
    });
}

#[test]
fn it_is_independent_of_the_owed_update_and_bounded() {
    run(async {
        let (mut vault, _) = base().await;
        vault.replace_update_outbox(None, b"owed").await.unwrap();
        vault
            .replace_delegation_outbox(None, b"delegation")
            .await
            .unwrap();
        assert_eq!(&**vault.update_outbox().await.unwrap().unwrap(), b"owed");
        assert_eq!(
            &**vault.delegation_outbox().await.unwrap().unwrap(),
            b"delegation"
        );
        let big = vec![7u8; MAX_DELEGATION_OUTBOX_BYTES];
        assert_eq!(
            vault
                .replace_delegation_outbox(Some(b"delegation"), &big)
                .await,
            Ok(CredentialWrite::Stored)
        );
        let too_big = vec![7u8; MAX_DELEGATION_OUTBOX_BYTES + 1];
        assert_eq!(
            vault.replace_delegation_outbox(Some(&big), &too_big).await,
            Err(CredentialError::Invalid)
        );
    });
}
