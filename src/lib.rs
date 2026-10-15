//! Vault composes Keys, encrypted Storage and injected Records/Wallet owners.
//! It never duplicates their lineage, record, proof or accepted-state logic.
#![forbid(unsafe_code)]
mod community_pin;
mod compound;
mod credential;
mod existing;
mod initial;
mod lineage;
mod pairing_guest;
mod read_floors;
mod records;
mod retention;
mod storage;
mod unlock;
mod update_outbox;
mod witness_state;
mod voucher_custody;
use ckmg::{Authority, Clock, Entropy, Locator};
pub use community_pin::{CommunityPin, PinnedHead};
pub use compound::{
    CHECKPOINT_SUBKEYS, CheckpointError, CheckpointPublication, CompoundRecords,
    MAX_CHECKPOINT_RECORDS, MAX_PACKED_CHECKPOINT, PreparedCheckpoint, RetainedCheckpoint,
};
pub use credential::{CredentialError, CredentialWrite, MAX_COMMUNITY_CREDENTIAL_BYTES};
use cwst::backend::Backend;
pub use existing::{OpenError, Owners, PreparedOpen, PreparedRecovery, RecoveryCandidate};
pub use initial::{
    AcknowledgedInitialCandidate, CurrentInitialLineage, InitialAcknowledgment, InitialCreation,
    InitialError, InitialLineageRead, InitialPhase, InitialPublication, RetainedGenesis,
    RetiredInitial, UnenrolledInitial,
};
pub use lineage::{
    LineageError, LineageRead, LineageRecords, VerifiedLineageObservation,
    publish_lineage_revision, verify_lineage,
};
pub use pairing_guest::{AcceptedPairing, PairingGuest};
pub use records::{
    PasskeyRecords, RecordCheckpoint, RecordError, TorLineageRecord, TorPasskeyRecord,
    TorReadRecord,
};
pub use retention::{
    EvidenceError, LineageEvidence, MAX_LINEAGE_EVIDENCE_BYTES, PreparedLineageEvidence,
};
pub use storage::*;
pub use unlock::{WALLET_SCOPE, WalletUnlock};
pub use update_outbox::MAX_UPDATE_OUTBOX_BYTES;
pub use witness_state::MAX_WITNESS_STATE_BYTES;
pub use voucher_custody::MAX_VOUCHER_CUSTODY_BYTES;

/// A restore lookup distinguishes authenticated absence from unavailable data.
/// No lookup outcome authorizes a replacement identity. Equal enrolled passkeys
/// all require retained copies of their wrapped common identity root.
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
/// [`PasskeyRecords`] forwards original authenticated reads without an absence fallback.
pub trait Records {
    /// Look up the passkey-derived opaque locator with explicit availability semantics.
    fn lookup(&mut self, locator: &Locator) -> impl std::future::Future<Output = RestoreLookup>;
    /// Install original signed read floors from an authenticated Store before
    /// further lookups. Adapters without this actual owner capability refuse.
    /// This establishes only negative read boundaries, never current authority.
    fn install_read_floors(&mut self, _state: &cdht::ClientState) -> Result<(), RecordError> {
        Err(RecordError::Unavailable)
    }
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
        mut clock: C,
        entropy: E,
        authority: A,
        mut records: R,
        wallet: W,
    ) -> Result<Self, Error> {
        if !store.is_scope(scope) {
            return Err(Error::Scope);
        }
        if let Some(carrier) = read_floors::load(&store).map_err(|_| Error::Invalid)? {
            if clock.now().map_err(|_| Error::Invalid)? < carrier.checked_at {
                return Err(Error::Invalid);
            }
            records
                .install_read_floors(&carrier.state)
                .map_err(|_| Error::Invalid)?;
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

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

// Link the existing profiling runtime into this newly enabled unit test binary.
#[cfg(all(test, target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

#[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
pub use compound::native_checkpoint_record;

#[cfg(feature = "wallet")]
mod wallet;
#[cfg(feature = "wallet")]
pub use wallet::{
    AccountSlot, CommunityAccountCustody, GlobalPassportCustody, WalletCustody, WalletRestoreError,
};
