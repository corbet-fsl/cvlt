//! Account witness state: bound, replaced only by compare-and-swap, empty means none,
//! and independent of the voucher custody.
use super::*;
use crate::{CredentialError, CredentialWrite, MAX_WITNESS_STATE_BYTES};

fn run<F: std::future::Future>(future: F) -> F::Output {
    futures_executor::block_on(future)
}

#[test]
fn store_read_clear_and_compare_and_swap_replace() {
    run(async {
        let (mut vault, _) = base().await;
        assert!(vault.witness_state().await.unwrap().is_none());
        assert_eq!(
            vault.replace_witness_state(None, b"one").await,
            Ok(CredentialWrite::Stored)
        );
        assert_eq!(&**vault.witness_state().await.unwrap().unwrap(), b"one");
        assert_eq!(
            vault.replace_witness_state(None, b"one").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(
            vault.replace_witness_state(Some(b"zero"), b"two").await,
            Err(CredentialError::Conflict)
        );
        // Clearing is a compare-and-swap to the empty record; none is then expected.
        assert_eq!(
            vault.replace_witness_state(Some(b"one"), b"").await,
            Ok(CredentialWrite::Stored)
        );
        assert!(vault.witness_state().await.unwrap().is_none());
        assert_eq!(
            vault.replace_witness_state(None, b"").await,
            Ok(CredentialWrite::Unchanged)
        );
        assert_eq!(
            vault.replace_witness_state(None, b"three").await,
            Ok(CredentialWrite::Stored)
        );
    });
}

#[test]
fn it_is_independent_of_the_voucher_custody_and_bounded() {
    run(async {
        let (mut vault, _) = base().await;
        vault.replace_voucher_custody(None, b"book").await.unwrap();
        vault.replace_witness_state(None, b"owed").await.unwrap();
        assert_eq!(&**vault.voucher_custody().await.unwrap().unwrap(), b"book");
        assert_eq!(&**vault.witness_state().await.unwrap().unwrap(), b"owed");
        // A voucher custody at its cap leaves room for a full outbox.
        let big = vec![7u8; MAX_WITNESS_STATE_BYTES];
        assert_eq!(
            vault.replace_witness_state(Some(b"owed"), &big).await,
            Ok(CredentialWrite::Stored)
        );
        let too_big = vec![7u8; MAX_WITNESS_STATE_BYTES + 1];
        assert_eq!(
            vault.replace_witness_state(Some(&big), &too_big).await,
            Err(CredentialError::Invalid)
        );
    });
}
