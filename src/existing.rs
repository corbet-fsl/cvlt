//! Consume-only reopening of an existing authenticated device checkpoint.
use crate::{Error, RecordCheckpoint, Records, Vault};
use ckmg::{Authority, Clock, Entropy, passkey};
use cwst::backend::Backend;

/// Independently constructed original owners. This carries no new authority,
/// session, lineage or accepted Wallet state and has no serializer or defaults.
pub struct Owners<C, E, A, R, W> {
    /// Current clock used by Keys after opening the checkpoint.
    pub clock: C,
    /// Original entropy capability used by Keys.
    pub entropy: E,
    /// Actual current device and local intent authority, checked before return.
    pub authority: A,
    /// Actual Records capability, retained without probing or inferring absence.
    pub records: R,
    /// Original accounting owner, retained without constructing accepted state.
    pub wallet: W,
}

/// Original value-free owner refusal. No path, identifier or dependency message
/// can be included in these variants; opening errors never trigger creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The encrypted Store refused its existing checkpoint.
    Storage(cwst::Error),
    /// Keys refused import, unlock or the original live authority check.
    Keys(ckmg::Error),
    /// The Vault rejected the owner composition.
    Composition(Error),
    /// The original authenticated Records owner refused this capability or read.
    Records(crate::RecordError),
}
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "existing vault: {self:?}")
    }
}
impl std::error::Error for OpenError {}

/// Consume-only opening state shared by Records and the existing local Store.
/// PRF custody stays inside Vault/Keys throughout asynchronous construction; no
/// root is created and no raw secret, serializer or clone is available.
pub struct PreparedOpen {
    prf: passkey::PrfOutput,
    scope: String,
    locator: ckmg::Locator,
}
impl PreparedOpen {
    /// Consume the original Passkeys result and validate the intended community.
    pub fn new(unlock: cpky::UnlockSecret, scope: &str) -> Result<Self, OpenError> {
        let prf = unlock
            .import(passkey::PrfOutput::from_bytes)
            .map_err(OpenError::Keys)?;
        let locator = passkey::vault_location(&prf, scope).map_err(OpenError::Keys)?;
        Ok(Self {
            prf,
            scope: scope.into(),
            locator,
        })
    }

    /// Original private local lookup key, not the canonical network record key.
    pub fn locator(&self) -> ckmg::Locator {
        self.locator
    }

    /// Lend the original narrow wrapping capability to the live Authority owner.
    /// It survives this preparation's consumption without cloning the PRF. The
    /// composer must retain it only inside custody and drop it on invalidation;
    /// consuming Vault::lock drops that Vault's Authority together with Keys.
    pub fn inspector(&self) -> Result<ckmg::CheckpointInspector, OpenError> {
        ckmg::CheckpointInspector::new(&self.prf, &self.scope).map_err(OpenError::Keys)
    }

    /// Inspect only the exact checkpoint returned for this opening's locator.
    /// The resulting public claims still require live Authority/intent checks;
    /// neither this method nor the record sequence grants current membership.
    pub fn inspect_record(
        &self,
        checkpoint: &RecordCheckpoint,
    ) -> Result<ckmg::CheckpointInspection, OpenError> {
        if checkpoint.locator != self.locator {
            return Err(OpenError::Composition(Error::Scope));
        }
        ckmg::inspect_checkpoint(&self.prf, &self.scope, checkpoint.sealed())
            .map_err(OpenError::Keys)
    }

    /// Bind both locators through the same consumed PRF/scope in the original
    /// native owner. The supplied Mesh factory retains the sole runtime instance.
    #[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
    pub async fn native_records(
        &self,
        records: &cmsh::VeilidRecords,
    ) -> Result<crate::PasskeyRecords<cmsh::VeilidRecord>, OpenError> {
        let initializer =
            passkey::native_passkey_record(&self.prf, &self.scope).map_err(OpenError::Keys)?;
        let record = records
            .initialize(initializer)
            .await
            .map_err(|_| OpenError::Records(crate::RecordError::Unavailable))?;
        crate::PasskeyRecords::new(self.locator, record).map_err(OpenError::Records)
    }

    /// Consume this opening into the existing Store and original Keys authority
    /// check. Absence/corruption/unavailability never selects a creation fallback.
    pub async fn open_existing<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        self,
        backend: B,
        owners: Owners<C, E, A, R, W>,
    ) -> Result<Vault<B, C, E, A, R, W>, OpenError> {
        let cipher = passkey::store_cipher(&self.prf, &self.scope).map_err(OpenError::Keys)?;
        let store = cwst::Store::open(backend, &cipher, &self.scope)
            .await
            .map_err(OpenError::Storage)?;
        let mut vault = Vault::new(
            store,
            &self.scope,
            owners.clock,
            owners.entropy,
            owners.authority,
            owners.records,
            owners.wallet,
        )
        .map_err(OpenError::Composition)?;
        vault
            .keys()
            .unlock(&self.prf, &self.scope)
            .await
            .map_err(OpenError::Keys)?;
        vault.keys().lineage().await.map_err(OpenError::Keys)?;
        Ok(vault)
    }
}
impl std::fmt::Debug for PreparedOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedOpen([redacted])")
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Consume an original Passkeys result into Keys and reopen an existing Store.
    /// Missing, unavailable, corrupt, revoked or stale state refuses. This never
    /// creates a Store/root, writes a checkpoint, restores network data or grants
    /// readiness. Keys rechecks original current authority before returning.
    /// Every later key operation still performs the owner's own authority check.
    pub async fn open_existing(
        backend: B,
        unlock: cpky::UnlockSecret,
        scope: &str,
        owners: Owners<C, E, A, R, W>,
    ) -> Result<Self, OpenError> {
        PreparedOpen::new(unlock, scope)?
            .open_existing(backend, owners)
            .await
    }
}
