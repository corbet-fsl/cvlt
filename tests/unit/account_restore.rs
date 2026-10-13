//! Negative restoration boundaries; original setup grants no account creation.
use super::*;

#[test]
fn ordinary_absence_and_global_wallet_never_initialize_a_community_account() {
    futures_executor::block_on(async {
        for global in [false, true] {
            let (vault, _) = if global {
                base_for("wallet", "00000000-0000-0000-0000-000000000011", true).await
            } else {
                base().await
            };
            let storage = vault.storage().clone();
            let original = storage.lock().await.sealed_checkpoint().unwrap().to_vec();
            assert!(vault.restore_community_account().await.is_err());
            let store = storage.lock().await;
            assert_eq!(store.sealed_checkpoint().unwrap(), original);
            assert!(store.read("cwlt.account", b"owner.v1").unwrap().is_none());
        }
    });
}
