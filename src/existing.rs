//! Consume-only reopening of an existing authenticated device checkpoint.
use crate::{Error, Records, Vault};
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
}
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "existing vault: {self:?}")
    }
}
impl std::error::Error for OpenError {}

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
        let prf = unlock
            .import(|bytes| passkey::PrfOutput::from_bytes(bytes))
            .map_err(OpenError::Keys)?;
        let cipher = passkey::store_cipher(&prf, scope).map_err(OpenError::Keys)?;
        let store = cwst::Store::open(backend, &cipher, scope)
            .await
            .map_err(OpenError::Storage)?;
        let mut vault = Self::new(
            store,
            scope,
            owners.clock,
            owners.entropy,
            owners.authority,
            owners.records,
            owners.wallet,
        )
        .map_err(OpenError::Composition)?;
        vault
            .keys()
            .unlock(&prf, scope)
            .await
            .map_err(OpenError::Keys)?;
        vault.keys().lineage().await.map_err(OpenError::Keys)?;
        Ok(vault)
    }
}
