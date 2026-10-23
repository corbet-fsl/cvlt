//! The new device's side of a pairing, as the one narrow capability over Keys that it needs.
//!
//! The device asks to be paired over a lineage anchor it was shown, keeps the pending
//! request durable, and later adopts the exact grant that answers that request. Nothing
//! else of Keys is reachable: the private [`GuestConsent`] authority allows exactly one
//! `RequestPairing` check for the anchor digest, and (after a reopen) exactly one `Adopt`
//! check for the pending request digest. The PRF and the root never leave this crate, a
//! [`PairingGuest`] cannot be cloned or serialized, and `accept` consumes it.
use crate::{Batch, Error, KeyStore, OpenError, PreparedOpen, shared_store};
use ckmg::{
    Action, Authority, Authorization, Binding, Change, Clock, DeviceInfo, Entropy, Keys, Lineage,
    PairingGrant, PairingRequest, PublicKey, Receipt, passkey,
};
use cwst::backend::Backend;

/// What the single permitted check must look like.
struct Expected {
    action: Action,
    binding: Binding,
    root: PublicKey,
    epoch: u64,
    target: Option<PublicKey>,
    statement: [u8; 32],
}

/// Allows exactly one check and then nothing: a refused or used consent is spent.
struct GuestConsent {
    allowed: Option<Expected>,
}

impl Authority for GuestConsent {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), ckmg::Error> {
        let expected = self.allowed.take().ok_or(ckmg::Error::Unauthorized)?;
        let device_ok = match expected.action {
            Action::Adopt => Some(request.device) == expected.target,
            _ => true,
        };
        if request.action == expected.action
            && request.binding == &expected.binding
            && request.root == Some(expected.root)
            && request.epoch == expected.epoch
            && request.target == expected.target
            && request.statement == Some(expected.statement)
            && device_ok
        {
            Ok(())
        } else {
            Err(ckmg::Error::Unauthorized)
        }
    }
}

fn operation(request: &PairingRequest, phase: u8) -> Result<[u8; 32], OpenError> {
    let digest = request.digest().map_err(OpenError::Keys)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"cvlt.pairing_guest.operation.v1");
    hasher.update(&digest);
    hasher.update(&[phase]);
    Ok(*hasher.finalize().as_bytes())
}

/// One Keys write on the guest's store: the guard lives through the commit.
async fn write<B: Backend>(
    key_store: &KeyStore<B>,
    request: &PairingRequest,
    phase: u8,
) -> Result<crate::BatchGuard, OpenError> {
    let expected = match key_store.ready().await {
        Ok(shared) => shared.lock().await.version().map_err(OpenError::Storage)?,
        Err(_) => 0,
    };
    key_store
        .clone()
        .stage(Batch {
            expected,
            operation: operation(request, phase)?,
            mutations: vec![],
            outputs: vec![],
        })
        .map_err(OpenError::Composition)
}

/// The new device between its request and the grant.
pub struct PairingGuest<B: Backend, C: Clock, E: Entropy> {
    keys: Keys<KeyStore<B>, C, E, GuestConsent>,
    key_store: KeyStore<B>,
    request: PairingRequest,
    /// Kept only to sign the pairing possession messages; never exposed, zeroized on drop.
    prf: passkey::PrfOutput,
}

impl<B: Backend, C: Clock, E: Entropy> std::fmt::Debug for PairingGuest<B, C, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingGuest([redacted])")
    }
}

impl PreparedOpen {
    /// Ask to be paired over `anchor` on an EMPTY destination. Consumes the opening. The
    /// returned request is durable (acknowledged) before it is returned; the anchor must
    /// have been shown to the person by the trusted channel (its digest is the only
    /// statement the consent allows).
    pub async fn request_pairing<B: Backend, C: Clock, E: Entropy>(
        self,
        backend: B,
        anchor: &Lineage,
        info: DeviceInfo,
        clock: C,
        entropy: E,
    ) -> Result<(PairingRequest, PairingGuest<B, C, E>), OpenError> {
        if anchor.binding.community() != self.scope {
            return Err(OpenError::Composition(Error::Scope));
        }
        let consent = GuestConsent {
            allowed: Some(Expected {
                action: Action::RequestPairing,
                binding: anchor.binding.clone(),
                root: anchor.root,
                epoch: anchor.epoch,
                target: None,
                statement: anchor.digest().map_err(OpenError::Keys)?,
            }),
        };
        let cipher = passkey::store_cipher(&self.prf, &self.scope).map_err(OpenError::Keys)?;
        let mut key_store = KeyStore::initial_pairing(backend, &self.scope, cipher)
            .map_err(OpenError::Composition)?;
        let mut keys = Keys::new(key_store.clone(), clock, entropy, consent);
        // The request does not exist yet; its digest names the staged operation only for
        // later phases, so the first operation derives from the anchor.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"cvlt.pairing_guest.request.v1");
        hasher.update(&anchor.digest().map_err(OpenError::Keys)?);
        hasher.update(self.locator.as_bytes());
        let guard = key_store
            .stage(Batch {
                expected: 0,
                operation: *hasher.finalize().as_bytes(),
                mutations: vec![],
                outputs: vec![],
            })
            .map_err(OpenError::Composition)?;
        let receipt = keys
            .request_pairing(&self.prf, anchor, info, &[])
            .await
            .map_err(OpenError::Keys)?;
        drop(guard);
        let request = match &receipt.change {
            Change::PairingRequested(request) => (**request).clone(),
            _ => return Err(OpenError::Keys(ckmg::Error::Crypto)),
        };
        // The pending request is the durable fact; clearing the output makes it final.
        let guard = write(&key_store, &request, 1).await?;
        keys.acknowledge(receipt.operation)
            .await
            .map_err(OpenError::Keys)?;
        drop(guard);
        Ok((
            request.clone(),
            PairingGuest {
                keys,
                key_store,
                request,
                prf: self.prf,
            },
        ))
    }
}

impl<B: Backend, C: Clock, E: Entropy> PairingGuest<B, C, E> {
    /// Reopen the durable pending request after a restart with the same passkey. The
    /// consent allows only the adoption of exactly `request`.
    pub async fn reopen(
        unlock: cpky::UnlockSecret,
        scope: &str,
        backend: B,
        clock: C,
        entropy: E,
        request: &PairingRequest,
    ) -> Result<Self, OpenError> {
        let opening = PreparedOpen::new(unlock, scope)?;
        if request.binding.community() != scope {
            return Err(OpenError::Composition(Error::Scope));
        }
        let cipher = passkey::store_cipher(&opening.prf, scope).map_err(OpenError::Keys)?;
        let store = cwst::Store::open(backend, &cipher, scope)
            .await
            .map_err(OpenError::Storage)?;
        let key_store =
            KeyStore::new(shared_store(store), scope).map_err(OpenError::Composition)?;
        let consent = GuestConsent {
            allowed: Some(Expected {
                action: Action::Adopt,
                binding: request.binding.clone(),
                root: request.root,
                epoch: request.epoch,
                target: Some(request.device),
                statement: request.digest().map_err(OpenError::Keys)?,
            }),
        };
        let mut keys = Keys::new(key_store.clone(), clock, entropy, consent);
        keys.unlock(&opening.prf, scope)
            .await
            .map_err(OpenError::Keys)?;
        Ok(Self {
            keys,
            key_store,
            request: request.clone(),
            prf: opening.prf,
        })
    }

    /// The pending request (the digest the grant must answer).
    pub fn request(&self) -> &PairingRequest {
        &self.request
    }

    /// Sign possession of this request's device key for one stamped pairing step (the add
    /// step, before the grant). The only signature a pairing guest can make: typed input, its
    /// own key in its own community, under the dedicated pairing purpose.
    pub fn sign_possession(
        &self,
        possession: &ckmg::PairingPossession<'_>,
    ) -> Result<[u8; 64], OpenError> {
        sign_possession(&self.prf, &self.request, possession)
    }

    /// Adopt the grant that answers exactly this request: the root arrives sealed to the
    /// device key, the lineage must extend the pending one and carry the root's signature.
    pub async fn accept(
        mut self,
        grant: &PairingGrant,
    ) -> Result<AcceptedPairing<B, C, E>, OpenError> {
        if grant.request != self.request {
            return Err(OpenError::Keys(ckmg::Error::Unauthorized));
        }
        let guard = write(&self.key_store, &self.request, 2).await?;
        let receipt = self
            .keys
            .accept_pairing(grant, &[])
            .await
            .map_err(OpenError::Keys)?;
        drop(guard);
        Ok(AcceptedPairing {
            keys: self.keys,
            key_store: self.key_store,
            request: self.request,
            receipt,
            prf: self.prf,
        })
    }
}

/// The pairing possession signature of the request's own device key: the community is the
/// request's, so a possession for another community is refused.
fn sign_possession(
    prf: &passkey::PrfOutput,
    request: &PairingRequest,
    possession: &ckmg::PairingPossession<'_>,
) -> Result<[u8; 64], OpenError> {
    if possession.device() != request.device.value() {
        return Err(OpenError::Keys(ckmg::Error::Unauthorized));
    }
    passkey::sign_pairing_possession(prf, request.binding.community(), possession)
        .map_err(OpenError::Keys)
}

/// The adopted pairing, until its output is acknowledged.
pub struct AcceptedPairing<B: Backend, C: Clock, E: Entropy> {
    keys: Keys<KeyStore<B>, C, E, GuestConsent>,
    key_store: KeyStore<B>,
    request: PairingRequest,
    receipt: Receipt,
    prf: passkey::PrfOutput,
}

impl<B: Backend, C: Clock, E: Entropy> AcceptedPairing<B, C, E> {
    /// Sign possession of the device key for the activation step, after the grant was
    /// adopted: same key, same dedicated purpose and the same typed input as the add step.
    pub fn sign_possession(
        &self,
        possession: &ckmg::PairingPossession<'_>,
    ) -> Result<[u8; 64], OpenError> {
        sign_possession(&self.prf, &self.request, possession)
    }

    /// The paired lineage.
    pub fn lineage(&self) -> Option<&Lineage> {
        match &self.receipt.change {
            Change::Paired(lineage) => Some(lineage),
            _ => None,
        }
    }

    /// Clear the durable output and wipe the unlocked material.
    pub async fn acknowledge(mut self) -> Result<(), OpenError> {
        let guard = write(&self.key_store, &self.request, 3).await?;
        self.keys
            .acknowledge(self.receipt.operation)
            .await
            .map_err(OpenError::Keys)?;
        drop(guard);
        self.keys.lock();
        Ok(())
    }
}
