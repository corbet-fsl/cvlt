//! Owed update outbox: bound, replaced only by compare-and-swap, empty means none,
//! and independent of the voucher custody.
use super::*;
use crate::{CredentialError, CredentialWrite, MAX_UPDATE_OUTBOX_BYTES};

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[test]
fn store_read_clear_and_compare_and_swap_replace() {
    run(async {
        let (mut vault, _) = base().await;
        assert!(vault.update_outbox().await.unwrap().is_none());
        assert_eq!(
            vault.replace_update_outbox(None, b"one").await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(&**vault.update_outbox().await.unwrap().unwrap(), b"one");
        assert_eq!(
            vault.replace_update_outbox(None, b"one").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(
            vault.replace_update_outbox(Some(b"zero"), b"two").await,
            Err(CredentialError::Conflict)
        );
        // Clearing is a compare-and-swap to the empty record; none is then expected.
        assert_eq!(
            vault.replace_update_outbox(Some(b"one"), b"").await,
            Ok(CredentialWrite::Stored)
        );
        assert!(vault.update_outbox().await.unwrap().is_none());
        assert_eq!(
            vault.replace_update_outbox(None, b"").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(
            vault.replace_update_outbox(None, b"three").await,
            Ok(CredentialWrite::Stored)
        );
    });
}

#[test]
fn it_is_independent_of_the_voucher_custody_and_bounded() {
    run(async {
        let (mut vault, _) = base().await;
        vault.replace_voucher_custody(None, b"book").await.unwrap();
        vault.replace_update_outbox(None, b"owed").await.unwrap();
        assert_eq!(&**vault.voucher_custody().await.unwrap().unwrap(), b"book");
        assert_eq!(&**vault.update_outbox().await.unwrap().unwrap(), b"owed");
        // A voucher custody at its cap leaves room for a full outbox.
        let big = vec![7u8; MAX_UPDATE_OUTBOX_BYTES];
        assert_eq!(
            vault.replace_update_outbox(Some(b"owed"), &big).await,
            Ok(CredentialWrite::Stored)
        );
        let too_big = vec![7u8; MAX_UPDATE_OUTBOX_BYTES + 1];
        assert_eq!(
            vault.replace_update_outbox(Some(&big), &too_big).await,
            Err(CredentialError::Invalid)
        );
    });
}
