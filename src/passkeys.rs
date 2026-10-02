//! Trusted Rust handover from Passkeys to Keys and encrypted Storage.
use ckmg::{Authority, Binding, Clock, DeviceInfo, Entropy, Keys, Receipt, SecureStore};
use cwst::{Store, backend::Backend};

/// Coarse owner errors, without PRF, credential, scope, or root material.
#[derive(Debug)]
pub enum PasskeyError {
    /// Keys refused the custody operation.
    Keys(ckmg::Error),
    /// Storage refused or cannot establish the checkpoint outcome.
    Storage(cwst::Error),
}
impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault passkey operation refused")
    }
}
impl std::error::Error for PasskeyError {}

/// Consume-only local custody material. It has no Debug, serde, raw PRF getter,
/// or product API representation. The caller supplies an authenticated scope.
pub struct PasskeyUnlock {
    prf: ckmg::passkey::PrfOutput,
    scope: String,
}
impl PasskeyUnlock {
    /// Initialize the exact passkey-owned DFLT(1) root record in Mesh's existing
    /// native engine. Neither local checkpoint locators nor raw keys cross this port.
    #[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
    pub fn record_initializer(&self) -> Result<ckmg::NativeRecordInitializer, PasskeyError> {
        ckmg::passkey::native_passkey_record(&self.prf, &self.scope).map_err(PasskeyError::Keys)
    }
    #[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
    pub(crate) fn local_locator(&self) -> Result<ckmg::Locator, PasskeyError> {
        ckmg::passkey::vault_location(&self.prf, &self.scope).map_err(PasskeyError::Keys)
    }
    /// Consume the browser/native secret entirely inside trusted Vault Rust.
    pub fn import(secret: cpky::UnlockSecret, scope: &str) -> Result<Self, PasskeyError> {
        let prf = secret
            .import(|bytes| ckmg::passkey::PrfOutput::from_bytes(bytes))
            .map_err(PasskeyError::Keys)?;
        // Validate the selected scope before retaining it.
        ckmg::passkey::vault_location(&prf, scope).map_err(PasskeyError::Keys)?;
        Ok(Self {
            prf,
            scope: scope.into(),
        })
    }
    /// Open the actual existing encrypted checkpoint. Absence stays an error;
    /// this never creates an identity or an empty replacement store.
    pub async fn open_storage<B: Backend>(&self, backend: B) -> Result<Store<B>, PasskeyError> {
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(PasskeyError::Keys)?;
        Store::open(backend, &cipher, &self.scope)
            .await
            .map_err(PasskeyError::Storage)
    }
    /// Explicit new-member storage initialization. It refuses existing storage;
    /// current create authority is still required by `create_scope` afterwards.
    pub async fn create_storage<B: Backend>(&self, backend: B) -> Result<Store<B>, PasskeyError> {
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(PasskeyError::Keys)?;
        Store::create(backend, &cipher, &self.scope)
            .await
            .map_err(PasskeyError::Storage)
    }
    /// Consume the handover to unlock retained Keys on the same scope. Each later
    /// operation still requires Keys' current live authority and generation checks.
    pub async fn unlock<S: SecureStore, C: Clock, E: Entropy, A: Authority>(
        self,
        keys: &mut Keys<S, C, E, A>,
    ) -> Result<(), PasskeyError> {
        keys.unlock(&self.prf, &self.scope)
            .await
            .map_err(PasskeyError::Keys)
    }
    /// Explicitly enroll new custody; never called as a fallback from failed restore.
    /// The actual Keys authority verifies the complete new-member binding.
    pub async fn create_scope<S: SecureStore, C: Clock, E: Entropy, A: Authority>(
        self,
        keys: &mut Keys<S, C, E, A>,
        binding: Binding,
        info: DeviceInfo,
        evidence: &[u8],
    ) -> Result<Receipt, PasskeyError> {
        if binding.community() != self.scope {
            return Err(PasskeyError::Keys(ckmg::Error::Unauthorized));
        }
        keys.create_scope(&self.prf, binding, info, evidence)
            .await
            .map_err(PasskeyError::Keys)
    }
}
