//! Vault composes Keys, encrypted Storage and injected Records/Wallet owners.
//! It never duplicates their lineage, record, proof or accepted-state logic.
#![forbid(unsafe_code)]
mod storage;
use ckmg::{Authority, Clock, Entropy, Locator};
use cwst::backend::Backend;
pub use storage::*;

/// A restore lookup distinguishes authenticated absence from unavailable data.
/// Neither outcome authorizes a replacement identity. Only the original root
/// passkey deterministically restores identity when all member records are lost.
pub enum RestoreLookup {
    /// Authenticated encrypted owner payload returned by the Records adapter.
    Present(Vec<u8>),
    /// Records established absence under its own protocol rules.
    KnownAbsent,
    /// Timeout, unavailable route, unverifiable response or incomplete knowledge.
    Unavailable,
}
impl std::fmt::Debug for RestoreLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Present(_) => "Present([redacted])",
            Self::KnownAbsent => "KnownAbsent",
            Self::Unavailable => "Unavailable",
        })
    }
}
/// Records owns authentication, Veilid format, retention and transport. This port
/// deliberately carries no raw identity/root key, URL, IP or operator backup path.
/// No permissive production implementation is supplied before cdht integration.
pub trait Records {
    /// Look up the passkey-derived opaque locator with explicit availability semantics.
    fn lookup(&mut self, locator: &Locator) -> impl std::future::Future<Output = RestoreLookup>;
}
/// Thin composition; private domain state remains exclusively in its owner.
/// The Wallet type is supplied by the accounting owner. There is no fake proof engine.
pub struct Vault<B: Backend, C, E, A, R, W> {
    keys: ckmg::Keys<KeyStore<B>, C, E, A>,
    storage: SharedStore<B>,
    key_store: KeyStore<B>,
    records: R,
    wallet: W,
}
impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Attach independently constructed owner capabilities to one authenticated
    /// community checkpoint. Construction grants no member or device authority.
    pub fn new(
        store: cwst::Store<B>,
        scope: &str,
        clock: C,
        entropy: E,
        authority: A,
        records: R,
        wallet: W,
    ) -> Result<Self, Error> {
        if !store.is_scope(scope) {
            return Err(Error::Scope);
        }
        let storage = shared_store(store);
        let key_store = KeyStore::new(storage.clone(), scope)?;
        let keys = ckmg::Keys::new(key_store.clone(), clock, entropy, authority);
        Ok(Self {
            keys,
            storage,
            key_store,
            records,
            wallet,
        })
    }
    /// Keys checks live authority for its own operations; roots remain opaque.
    pub fn keys(&mut self) -> &mut ckmg::Keys<KeyStore<B>, C, E, A> {
        &mut self.keys
    }
    /// Shared durable checkpoint used to compose owner candidates and outputs.
    pub fn storage(&self) -> &SharedStore<B> {
        &self.storage
    }
    /// Arm one Keys write with its companion owner changes. Keep the guard alive
    /// through Keys::commit/acknowledge; dropping it cancels unused companions.
    pub fn stage_keys(&mut self, batch: Batch) -> Result<BatchGuard, Error> {
        self.key_store.stage(batch)
    }
    /// Borrow the real accounting owner; Vault does not copy accepted openings.
    pub fn wallet(&mut self) -> &mut W {
        &mut self.wallet
    }
    /// Delegate lookup, preserving unavailable versus known-absent evidence. This
    /// never creates/replaces a local checkpoint or changes an identity/membership.
    pub async fn restore_lookup(&mut self, locator: &Locator) -> RestoreLookup {
        self.records.lookup(locator).await
    }
    /// Wipe unlocked keys and checkpoint material. Only encrypted backend data remains.
    pub async fn lock(mut self) {
        self.keys.lock();
        let mut store = self.storage.lock().await;
        store.lock_in_place();
    }
}
impl<B: Backend, C, E, A, R, W> std::fmt::Debug for Vault<B, C, E, A, R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault([redacted])")
    }
}
