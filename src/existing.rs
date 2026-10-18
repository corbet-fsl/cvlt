//! Consume-only reopening of an existing authenticated device checkpoint.
use crate::{Error, RecordCheckpoint, Records, Vault};
use ckmg::{Authority, Clock, Entropy, passkey};
use cwst::backend::Backend;

mod recovery;
pub use recovery::{PreparedRecovery, RecoveryCandidate};

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
    /// The common-root path requires a verified per-passkey recovery record.
    RecoveryRequired,
    /// Original certificate/assertion/lineage verification refused recovery.
    Evidence(crate::LineageError),
    /// Compound checkpoint framing, agreement or original Store refused restore.
    Checkpoint(crate::CheckpointError),
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
    pub(crate) prf: passkey::PrfOutput,
    pub(crate) scope: String,
    pub(crate) locator: ckmg::Locator,
}
impl PreparedOpen {
    /// Consume the original Passkeys result and validate the intended community.
    pub fn new(unlock: cpky::UnlockSecret, scope: &str) -> Result<Self, OpenError> {
        let prf = unlock
            .import(|bytes| passkey::PrfOutput::from_bytes(bytes))
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

    /// Original device coordinate for the fresh HTTPS transport check.
    pub fn device(&self) -> Result<ckmg::PublicKey, OpenError> {
        passkey::device_public_key(&self.prf, &self.scope).map_err(OpenError::Keys)
    }

    /// The device key's session signature over `payload` (ckmg prepends the session tag), for
    /// a device-key member restarted after activation: its community sessions open before its
    /// Keys are live. Only the session purpose; before activation the enrollment signs.
    pub fn sign_device_session(&self, payload: &[u8]) -> Result<[u8; 64], OpenError> {
        passkey::sign_device_session(&self.prf, &self.scope, payload).map_err(OpenError::Keys)
    }

    /// The same opening signer for a device-key member restarted during its first
    /// publication: `DeviceSession` or `SaltDerivation` (its genesis stamp salt, rebuilt
    /// bit-exact); `DeviceJoin` is refused (the enrollment signs it before activation).
    pub fn sign_device(
        &self,
        purpose: ckmg::DevicePurpose,
        payload: &[u8],
    ) -> Result<[u8; 64], OpenError> {
        passkey::sign_device_opened(&self.prf, &self.scope, purpose, payload)
            .map_err(OpenError::Keys)
    }

    /// Create the independent node-only owner from this same consumed unlock.
    /// It must remain the runtime's sole transport custody owner throughout
    /// restore and member use, then be dropped/locked with this login session.
    pub fn transport<C: Clock, A: Authority>(
        &self,
        binding: ckmg::Binding,
        clock: C,
        authority: A,
    ) -> Result<ckmg::TransportSession<C, A>, OpenError> {
        if binding.community() != self.scope {
            return Err(OpenError::Composition(Error::Scope));
        }
        ckmg::TransportSession::new(&self.prf, binding, clock, authority).map_err(OpenError::Keys)
    }

    /// The storage cipher of this opening's scope; seals the wallet membership index.
    pub fn index_cipher(&self) -> Result<ckmg::passkey::StoreCipher, OpenError> {
        passkey::store_cipher(&self.prf, &self.scope).map_err(OpenError::Keys)
    }

    /// Lend the original narrow wrapping capability to the live Authority owner.
    /// It survives this preparation's consumption without cloning the PRF. The
    /// composer must retain it only inside custody and drop it on invalidation;
    /// consuming Vault::lock drops that Vault's Authority together with Keys.
    pub fn inspector(&self) -> Result<ckmg::CheckpointInspector, OpenError> {
        ckmg::CheckpointInspector::new(&self.prf, &self.scope).map_err(OpenError::Keys)
    }

    /// Read this exact passkey's original root record through a retained Mesh
    /// Tor Records network. No replica absence creates Keys. The read capability
    /// borrows this opening and must be dropped before consuming it for restore.
    pub async fn tor_records<N: cdht::Network>(
        &self,
        network: N,
    ) -> Result<crate::PasskeyRecords<crate::TorPasskeyRecord<'_, N>>, OpenError> {
        let reader =
            passkey::passkey_record_reader(&self.prf, &self.scope).map_err(OpenError::Keys)?;
        let backend = crate::TorPasskeyRecord::open(network, reader)
            .await
            .map_err(|_| OpenError::Records(crate::RecordError::Unavailable))?;
        crate::PasskeyRecords::tor(
            self.locator,
            backend,
            crate::records::tor::ReadFloors::default(),
        )
        .map_err(OpenError::Records)
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

    /// Explicit original first registration, never a fallback from failed restore.
    /// The injected Authority must consume original registration provenance for
    /// `Create`; this method establishes no membership or publication authority.
    /// Keys and companion values reach the empty destination in one actual CAS,
    /// already wrapped under the newly generated common root. No intermediate
    /// empty or PRF-wrapped durable checkpoint is installed.
    ///
    /// Uncertainty or cancellation requires reopening the exact destination;
    /// neither permits retrying Create with a replacement root. The returned
    /// Receipt remains pending until its original publication is acknowledged.
    pub async fn create_initial<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        self,
        backend: B,
        binding: ckmg::Binding,
        info: ckmg::DeviceInfo,
        evidence: &[u8],
        batch: crate::Batch,
        owners: Owners<C, E, A, R, W>,
    ) -> Result<(Vault<B, C, E, A, R, W>, ckmg::Receipt), OpenError> {
        self.create_initial_inner(backend, binding, info, evidence, batch, owners)
            .await
    }

    pub(crate) async fn create_initial_inner<
        B: Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        W,
    >(
        &self,
        backend: B,
        binding: ckmg::Binding,
        info: ckmg::DeviceInfo,
        evidence: &[u8],
        batch: crate::Batch,
        owners: Owners<C, E, A, R, W>,
    ) -> Result<(Vault<B, C, E, A, R, W>, ckmg::Receipt), OpenError> {
        if binding.community() != self.scope || batch.expected != 0 {
            return Err(OpenError::Composition(Error::Scope));
        }
        let mut key_store =
            crate::KeyStore::initial(backend, &self.scope).map_err(OpenError::Composition)?;
        let guard = key_store.stage(batch).map_err(OpenError::Composition)?;
        let mut keys = ckmg::Keys::new(
            key_store.clone(),
            owners.clock,
            owners.entropy,
            owners.authority,
        );
        let receipt = keys
            .create_scope(&self.prf, binding, info, evidence)
            .await
            .map_err(OpenError::Keys)?;
        let storage = key_store.ready().await.map_err(OpenError::Keys)?;
        drop(guard);
        Ok((
            Vault {
                keys,
                storage,
                key_store,
                records: owners.records,
                wallet: owners.wallet,
            },
            receipt,
        ))
    }

    /// A PRF-only open is no longer a restore path. Call `prepare_recovery` with the
    /// retained recovery record, or explicitly select `migrate_legacy` for the
    /// unpublished PRF-wrapped candidate. There is no silent cipher fallback.
    pub async fn open_existing<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        self,
        _backend: B,
        _owners: Owners<C, E, A, R, W>,
    ) -> Result<Vault<B, C, E, A, R, W>, OpenError> {
        Err(OpenError::RecoveryRequired)
    }

    /// Explicitly authenticate and migrate the unpublished PRF-wrapped Store.
    /// Current Keys authority is mandatory. The same random data key and all
    /// owner values/outbox entries move under the common root in one fenced CAS.
    pub async fn migrate_legacy<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W>(
        self,
        backend: B,
        owners: Owners<C, E, A, R, W>,
        expected_version: u64,
        operation: [u8; 32],
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
        let guard = vault
            .stage_keys(crate::Batch {
                expected: expected_version,
                operation,
                mutations: vec![],
                outputs: vec![],
            })
            .map_err(OpenError::Composition)?;
        vault
            .keys()
            .migrate_compound_wrapping()
            .await
            .map_err(OpenError::Keys)?;
        drop(guard);
        Ok(vault)
    }
}
impl std::fmt::Debug for PreparedOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedOpen([redacted])")
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Compatibility refusal for the unpublished PRF-only open API. Returns
    /// `RecoveryRequired` without accessing storage. Use `PreparedOpen` with a
    /// verified recovery record, or explicitly request `migrate_legacy`.
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
