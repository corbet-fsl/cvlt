//! Original Passkeys/Store round trips with an explicitly unavailable G3/Wallet.
//! No accepting authority, fabricated key checkpoint or production-ready Vault.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ckmg::passkey::{PrfOutput, store_cipher};
use cpky::{
    Client, Context, UnlockSecret, VaultOutcome,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use cwst::backend::{Backend, Memory};
use serde_json::json;
use std::{cell::Cell, rc::Rc};

macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch = "wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}
const RP: &str = "members.example.com";
const ORIGIN: &str = "https://members.example.com";
const SCOPE: &str = "garden";
type Passkeys = Client<SoftwareAuthenticator>;

// The canonical Passkeys public fixture shape: actual maintained authenticator,
// resident credential, real PRF evaluation. Synthetic user gesture, never browser proof.
async fn passkeys() -> Passkeys {
    let platform = SoftwareAuthenticator::new(
        ORIGIN,
        TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap();
    let mut client = Client::new(Context::new(ORIGIN, RP).unwrap(), platform);
    client.register_member(json!({"publicKey": {
        "rp":{"id":RP,"name":"Synthetic community"},
        "user":{"id":URL_SAFE_NO_PAD.encode([17;16]),"name":"synthetic-member","displayName":"Test member"},
        "challenge":URL_SAFE_NO_PAD.encode([41;32]),
        "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
        "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required","authenticatorAttachment":"platform"},
        "timeout":42000,"excludeCredentials":[],"attestation":"none",
        "extensions":{"credProps":true},"hints":["client-device"]
    }})).await.unwrap();
    client
}
async fn unlock(client: &mut Passkeys) -> UnlockSecret {
    let authentication = client
        .sign_in(json!({"publicKey": {
            "challenge":URL_SAFE_NO_PAD.encode([55;32]),"rpId":RP,
            "userVerification":"required","allowCredentials":[],"timeout":21000,
        }}))
        .await
        .unwrap();
    match authentication.into_parts().1 {
        VaultOutcome::Ready(secret) => secret,
        VaultOutcome::Locked(_) => panic!("canonical PRF fixture is locked"),
    }
}
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(1100)
    }
}
struct UnavailableAuthority;
impl ckmg::Authority for UnavailableAuthority {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unavailable)
    }
}
struct UnavailableRecords;
impl cvlt::Records for UnavailableRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
struct WalletNotIntegrated;
fn owners() -> cvlt::Owners<
    Clock,
    ckmg::SystemEntropy,
    UnavailableAuthority,
    UnavailableRecords,
    WalletNotIntegrated,
> {
    cvlt::Owners {
        clock: Clock,
        entropy: ckmg::SystemEntropy,
        authority: UnavailableAuthority,
        records: UnavailableRecords,
        wallet: WalletNotIntegrated,
    }
}
async fn seed(backend: Memory, client: &mut Passkeys) {
    let prf = unlock(client)
        .await
        .import(|bytes| PrfOutput::from_bytes(bytes))
        .unwrap();
    let cipher = store_cipher(&prf, SCOPE).unwrap();
    let store = cwst::Store::create(backend, &cipher, SCOPE).await.unwrap();
    assert_eq!(store.version().unwrap(), 0);
    drop(store);
}

shared!(
    same_synced_passkey_opens_actual_store_but_missing_keys_never_become_custody,
    {
        let backend = Memory::new();
        let mut client = passkeys().await;
        seed(backend.clone(), &mut client).await;
        let before = backend.read().await.unwrap();
        let platform = client.into_authenticator();
        let mut fresh = Client::new(
            Context::new(ORIGIN, RP).unwrap(),
            platform.synced_test_device(),
        );
        let error =
            cvlt::Vault::open_existing(backend.clone(), unlock(&mut fresh).await, SCOPE, owners())
                .await
                .unwrap_err();
        // This can reach Keys only after the original Store authenticates its cipher.
        assert_eq!(error, cvlt::OpenError::Keys(ckmg::Error::MissingCheckpoint));
        assert_eq!(backend.read().await.unwrap(), before);
    }
);

shared!(
    absent_store_wrong_passkey_scope_and_corruption_never_write_or_create,
    {
        let backend = Memory::new();
        let mut client = passkeys().await;
        assert_eq!(
            cvlt::Vault::open_existing(backend.clone(), unlock(&mut client).await, SCOPE, owners())
                .await
                .unwrap_err(),
            cvlt::OpenError::Storage(cwst::Error::NotInitialized)
        );
        assert!(backend.read().await.unwrap().is_none());
        seed(backend.clone(), &mut client).await;
        let before = backend.read().await.unwrap();
        let mut other = passkeys().await;
        assert_eq!(
            cvlt::Vault::open_existing(backend.clone(), unlock(&mut other).await, SCOPE, owners())
                .await
                .unwrap_err(),
            cvlt::OpenError::Storage(cwst::Error::Unlock)
        );
        assert_eq!(
            cvlt::Vault::open_existing(
                backend.clone(),
                unlock(&mut client).await,
                "foreign",
                owners()
            )
            .await
            .unwrap_err(),
            cvlt::OpenError::Storage(cwst::Error::Unlock)
        );
        assert_eq!(
            cvlt::Vault::open_existing(backend.clone(), unlock(&mut client).await, "", owners())
                .await
                .unwrap_err(),
            cvlt::OpenError::Keys(ckmg::Error::Encoding)
        );
        assert_eq!(backend.read().await.unwrap(), before);
        let mut corrupt = before.clone().unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        backend
            .compare_exchange(before.as_deref(), &corrupt)
            .await
            .unwrap();
        assert!(matches!(
            cvlt::Vault::open_existing(backend.clone(), unlock(&mut client).await, SCOPE, owners())
                .await,
            Err(cvlt::OpenError::Storage(_))
        ));
        assert_eq!(backend.read().await.unwrap(), Some(corrupt));
    }
);

// Storage-only fault adapter. It cannot provide accepted custody or write success.
struct ReadFault {
    pending: bool,
    entered: Rc<Cell<bool>>,
    writes: Rc<Cell<usize>>,
}
impl Backend for ReadFault {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.entered.set(true);
        if self.pending {
            std::future::pending::<()>().await;
        }
        Err(cwst::Error::Storage)
    }
    async fn compare_exchange(&self, _: Option<&[u8]>, _: &[u8]) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        Err(cwst::Error::Storage)
    }
}
shared!(
    unavailable_or_cancelled_read_does_not_create_checkpoint_or_emit_vault,
    {
        use futures::FutureExt;
        let mut client = passkeys().await;
        for pending in [false, true] {
            let entered = Rc::new(Cell::new(false));
            let writes = Rc::new(Cell::new(0));
            let backend = ReadFault {
                pending,
                entered: entered.clone(),
                writes: writes.clone(),
            };
            let secret = unlock(&mut client).await;
            let opening = cvlt::Vault::open_existing(backend, secret, SCOPE, owners());
            if pending {
                let mut opening = Box::pin(opening);
                assert!(opening.as_mut().now_or_never().is_none());
                assert!(entered.get());
                drop(opening);
            } else {
                assert_eq!(
                    opening.await.unwrap_err(),
                    cvlt::OpenError::Storage(cwst::Error::Storage)
                );
            }
            assert!(entered.get());
            assert_eq!(writes.get(), 0);
        }
    }
);
