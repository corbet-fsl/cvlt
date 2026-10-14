//! The new device's pairing capability: request on an empty destination, reopen after a
//! restart, adopt exactly the grant that answers the pending request.
#![cfg(not(target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ckmg::{Authority, Authorization, Binding, Change, DeviceInfo, Error, Keys, Locator};
use cpky::{
    Client, Context, UnlockSecret, VaultOutcome,
    software::{SoftwareAuthenticator, TestConfiguration},
};
use cvlt::PairingGuest;
use serde_json::json;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const RP: &str = "members.example.com";
const ORIGIN: &str = "https://members.example.com";
const SCOPE: &str = "garden";

async fn passkeys() -> Client<SoftwareAuthenticator> {
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
    client
        .register_member(json!({"publicKey": {
            "rp":{"id":RP,"name":"Synthetic community"},
            "user":{"id":URL_SAFE_NO_PAD.encode([17;16]),"name":"synthetic-member","displayName":"Test member"},
            "challenge":URL_SAFE_NO_PAD.encode([41;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
            "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required","authenticatorAttachment":"platform"},
            "timeout":42000,"excludeCredentials":[],"attestation":"none",
            "extensions":{"credProps":true},"hints":["client-device"]
        }}))
        .await
        .unwrap();
    client
}

async fn unlock(client: &mut Client<SoftwareAuthenticator>) -> UnlockSecret {
    let authentication = client
        .sign_in(json!({"publicKey": {
            "challenge":URL_SAFE_NO_PAD.encode([55;32]),"rpId":RP,
            "userVerification":"required","allowCredentials":[],"timeout":21000,
        }}))
        .await
        .unwrap();
    match authentication.into_parts().1 {
        VaultOutcome::Ready(secret) => secret,
        VaultOutcome::Locked(_) => panic!("PRF fixture is locked"),
    }
}

#[derive(Clone)]
struct Time;
impl ckmg::Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(1100)
    }
}

/// Test-only store for the existing device.
#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<Locator, Vec<u8>>>>);
impl ckmg::SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<ckmg::Commit, Error> {
        let mut data = self.0.borrow_mut();
        let actual = data.get(location).map(|v| *blake3::hash(v).as_bytes());
        if actual != expected {
            return Ok(ckmg::Commit::Conflict);
        }
        data.insert(*location, replacement.into());
        Ok(ckmg::Commit::Committed)
    }
}

/// Test-only permissive authority of the existing device.
struct Live;
impl Authority for Live {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

fn info() -> DeviceInfo {
    DeviceInfo::new("device", b"reference").unwrap()
}

async fn live_anchor() -> (Keys<Memory, Time, ckmg::SystemEntropy, Live>, ckmg::Lineage) {
    let mut live = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Live);
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[7; 32]).unwrap();
    let receipt = live
        .create_scope(&prf, Binding::new(SCOPE, "pseudonym").unwrap(), info(), &[])
        .await
        .unwrap();
    live.acknowledge(receipt.operation).await.unwrap();
    let anchor = live.lineage().await.unwrap();
    (live, anchor)
}

#[test]
fn request_restart_and_adopt_exactly_the_answering_grant() {
    futures_executor::block_on(async {
        let (mut live, anchor) = live_anchor().await;
        let mut client = passkeys().await;
        let backend = cwst::backend::Memory::new();
        let (request, guest) = cvlt::PreparedOpen::new(unlock(&mut client).await, SCOPE)
            .unwrap()
            .request_pairing(backend.clone(), &anchor, info(), Time, ckmg::SystemEntropy)
            .await
            .unwrap();
        drop(guest);
        let receipt = live.authorize_device(&request, &[]).await.unwrap();
        live.acknowledge(receipt.operation).await.unwrap();
        let Change::DeviceAuthorized(grant) = receipt.change else {
            panic!("grant expected");
        };
        // A second request on the same destination is refused (no new identity).
        assert!(
            cvlt::PreparedOpen::new(unlock(&mut client).await, SCOPE)
                .unwrap()
                .request_pairing(backend.clone(), &anchor, info(), Time, ckmg::SystemEntropy)
                .await
                .is_err()
        );
        // Restart: the pending request is reopened with the same passkey.
        let guest = PairingGuest::reopen(
            unlock(&mut client).await,
            SCOPE,
            backend.clone(),
            Time,
            ckmg::SystemEntropy,
            &request,
        )
        .await
        .unwrap();
        // A grant for another request is refused before anything is touched.
        let mut other = (*grant).clone();
        other.request.nonce = [9; 32];
        assert!(guest.accept(&other).await.is_err());
        let guest = PairingGuest::reopen(
            unlock(&mut client).await,
            SCOPE,
            backend.clone(),
            Time,
            ckmg::SystemEntropy,
            &request,
        )
        .await
        .unwrap();
        let accepted = guest.accept(&grant).await.unwrap();
        let lineage = accepted.lineage().unwrap().clone();
        assert!(lineage.devices.contains(&request.device));
        assert_eq!(lineage.revision, grant.lineage.revision);
        accepted.acknowledge().await.unwrap();
    });
}

#[test]
fn consent_allows_the_request_only_for_the_shown_anchor() {
    futures_executor::block_on(async {
        let (_live, mut anchor) = live_anchor().await;
        let mut client = passkeys().await;
        anchor.epoch += 1; // no longer verifies: refused before any consent
        let result = cvlt::PreparedOpen::new(unlock(&mut client).await, SCOPE)
            .unwrap()
            .request_pairing(
                cwst::backend::Memory::new(),
                &anchor,
                info(),
                Time,
                ckmg::SystemEntropy,
            )
            .await;
        assert!(result.is_err());
        // A different scope than the opening's is refused.
        let (_live, anchor) = live_anchor().await;
        let result = cvlt::PreparedOpen::new(unlock(&mut client).await, "other")
            .unwrap()
            .request_pairing(
                cwst::backend::Memory::new(),
                &anchor,
                info(),
                Time,
                ckmg::SystemEntropy,
            )
            .await;
        assert!(result.is_err());
    });
}
