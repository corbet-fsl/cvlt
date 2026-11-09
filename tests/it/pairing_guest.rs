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

#[test]
fn the_guest_signs_only_pairing_possession_for_its_own_key() {
    futures_executor::block_on(async {
        let (mut live, anchor) = live_anchor().await;
        let mut client = passkeys().await;
        let backend = cwst::backend::Memory::new();
        let (request, guest) = cvlt::PreparedOpen::new(unlock(&mut client).await, SCOPE)
            .unwrap()
            .request_pairing(backend.clone(), &anchor, info(), Time, ckmg::SystemEntropy)
            .await
            .unwrap();
        let device = *request.device.value();
        let add =
            ckmg::PairingPossession::new(SCOPE, ckmg::PairingStep::Add, "challenge-add", &device)
                .unwrap();
        let signature = guest.sign_possession(&add).unwrap();
        ckmg::verify_ed25519(&device, &add.message(), &signature).unwrap();
        // Valid for the pairing purpose only: never as a join, session or salt message.
        for other in [
            ckmg::DeviceFormat::DeviceJoin,
            ckmg::DeviceFormat::DeviceSession,
            ckmg::DeviceFormat::PairingApproval,
        ] {
            let as_other = [other.tag(), &add.payload()[..]].concat();
            assert!(ckmg::verify_ed25519(&device, &as_other, &signature).is_err());
        }
        // Another key or another community is refused, nothing is signed for it.
        let foreign_key =
            ckmg::PairingPossession::new(SCOPE, ckmg::PairingStep::Add, "c", &[7; 32]).unwrap();
        assert!(guest.sign_possession(&foreign_key).is_err());
        let foreign_scope =
            ckmg::PairingPossession::new("other", ckmg::PairingStep::Add, "c", &device).unwrap();
        assert!(guest.sign_possession(&foreign_scope).is_err());
        // After the grant is adopted the same key signs the activation step, a different
        // message and signature.
        let receipt = live.authorize_device(&request, &[]).await.unwrap();
        live.acknowledge(receipt.operation).await.unwrap();
        let Change::DeviceAuthorized(grant) = receipt.change else {
            panic!("grant expected");
        };
        // The request's own consent is spent; adopting the grant reopens the durable request
        // (a restarted guest signs the very same possession bytes).
        drop(guest);
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
        assert_eq!(guest.sign_possession(&add).unwrap(), signature);
        let accepted = guest.accept(&grant).await.unwrap();
        let activate = ckmg::PairingPossession::new(
            SCOPE,
            ckmg::PairingStep::Activate,
            "challenge-activate",
            &device,
        )
        .unwrap();
        let activated = accepted.sign_possession(&activate).unwrap();
        ckmg::verify_ed25519(&device, &activate.message(), &activated).unwrap();
        assert_ne!(activated, signature);
        assert!(ckmg::verify_ed25519(&device, &add.message(), &activated).is_err());
        assert!(accepted.sign_possession(&foreign_key).is_err());
        accepted.acknowledge().await.unwrap();
    });
}

async fn live_anchor_in(
    scope: &str,
) -> (Keys<Memory, Time, ckmg::SystemEntropy, Live>, ckmg::Lineage) {
    let mut live = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Live);
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[7; 32]).unwrap();
    let receipt = live
        .create_scope(&prf, Binding::new(scope, "pseudonym").unwrap(), info(), &[])
        .await
        .unwrap();
    live.acknowledge(receipt.operation).await.unwrap();
    let anchor = live.lineage().await.unwrap();
    (live, anchor)
}

/// ONE passkey ceremony on the new device serves a pairing of several scopes: every opening
/// (request and adoption) derives from the one session unlock, and every possession
/// signature of every scope is made without another ceremony.
#[test]
fn one_session_unlock_pairs_several_scopes_with_one_ceremony() {
    futures_executor::block_on(async {
        let mut client = passkeys().await;
        // The only passkey ceremony of the whole pairing on this device.
        let session = cvlt::WalletUnlock::new(unlock(&mut client).await);
        let scopes = [("alpha", [1u8; 32]), ("beta", [2; 32]), ("gamma", [3; 32])];
        let mut devices = Vec::new();
        for (scope, fingerprint) in scopes {
            let (live, anchor) = live_anchor_in(scope).await;
            let backend = cwst::backend::Memory::new();
            let (request, guest) = session
                .community(&fingerprint, scope)
                .unwrap()
                .request_pairing(backend.clone(), &anchor, info(), Time, ckmg::SystemEntropy)
                .await
                .unwrap();
            let device = *request.device.value();
            let add = ckmg::PairingPossession::new(scope, ckmg::PairingStep::Add, "add", &device)
                .unwrap();
            let add_signature = guest.sign_possession(&add).unwrap();
            ckmg::verify_ed25519(&device, &add.message(), &add_signature).unwrap();
            devices.push((scope, fingerprint, backend, request, live, device));
            drop(guest);
        }
        // Every scope has its own device key: no value crosses scopes.
        assert_ne!(devices[0].5, devices[1].5);
        assert_ne!(devices[1].5, devices[2].5);
        for (scope, fingerprint, backend, request, mut live, device) in devices {
            let receipt = live.authorize_device(&request, &[]).await.unwrap();
            live.acknowledge(receipt.operation).await.unwrap();
            let Change::DeviceAuthorized(grant) = receipt.change else {
                panic!("grant expected");
            };
            // Adoption reopens from the same session unlock: no second ceremony.
            let guest = PairingGuest::reopen_with(
                session.community(&fingerprint, scope).unwrap(),
                backend.clone(),
                Time,
                ckmg::SystemEntropy,
                &request,
            )
            .await
            .unwrap();
            let accepted = guest.accept(&grant).await.unwrap();
            let activate =
                ckmg::PairingPossession::new(scope, ckmg::PairingStep::Activate, "act", &device)
                    .unwrap();
            let signature = accepted.sign_possession(&activate).unwrap();
            ckmg::verify_ed25519(&device, &activate.message(), &signature).unwrap();
            accepted.acknowledge().await.unwrap();
        }
        // An opening of another scope's secret cannot adopt this request.
        let (_live, anchor) = live_anchor_in("alpha").await;
        let backend = cwst::backend::Memory::new();
        let (request, guest) = session
            .community(&[9; 32], "alpha")
            .unwrap()
            .request_pairing(backend.clone(), &anchor, info(), Time, ckmg::SystemEntropy)
            .await
            .unwrap();
        drop(guest);
        assert!(
            PairingGuest::reopen_with(
                session.community(&[8; 32], "alpha").unwrap(),
                backend,
                Time,
                ckmg::SystemEntropy,
                &request,
            )
            .await
            .is_err()
        );
    });
}
