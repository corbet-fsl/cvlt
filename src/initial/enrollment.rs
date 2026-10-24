//! Original encrypted candidate durably retained before registration acceptance.
use super::*;
use ckmg::SecureStore;

/// Only the original unaccepted candidate. No receipt, Keys, root or ordinary
/// Vault is available until the original enrollment owner and durable CAS agree.
pub struct UnenrolledInitial<B: Backend> {
    opening: PreparedOpen,
    backend: BackendRef<B>,
    store: cwst::Store<BackendRef<B>>,
    candidate: ckmg::UnenrolledCreation,
}
impl<B: Backend> std::fmt::Debug for UnenrolledInitial<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnenrolledInitial([redacted])")
    }
}

impl PreparedOpen {
    /// After original CPky creation, retain the exact original seed and passkey
    /// material and opaque original Foyer finish continuation in the existing
    /// encrypted Store format before register_finish. The continuation is data,
    /// never authority; its original owner validates any eventual replay.
    /// Unknown/cancelled writes require reopening; they never create a new seed.
    pub async fn retain_enrollment<B: Backend>(
        self,
        backend: B,
        seed: ckmg::EnrollmentSeed,
        info: ckmg::DeviceInfo,
        finish_continuation: &[u8],
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<UnenrolledInitial<B>, InitialError> {
        if finish_continuation.is_empty() || finish_continuation.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Invalid);
        }
        let candidate = seed
            .seal(&self.prf, info, clock, entropy)
            .map_err(InitialError::Keys)?;
        self.retain(backend, candidate, ENROLLMENT_FINISH, finish_continuation)
            .await
    }

    /// Retain a device-key member's creation: no passkey ceremony and no finish
    /// continuation. The candidate's authority reference is this scope's device key (the
    /// key `device_join` registers), and the creation time `genesis_at` that the genesis
    /// stamp binds is committed atomically with the candidate, so a restart rebuilds the
    /// same stamp action. Unknown/cancelled writes require reopening; never a new seed.
    pub async fn retain_device_enrollment<B: Backend>(
        self,
        backend: B,
        seed: ckmg::EnrollmentSeed,
        name: &str,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<UnenrolledInitial<B>, InitialError> {
        let device = self.device().map_err(InitialError::Open)?;
        let info = ckmg::DeviceInfo::new(name, device.value()).map_err(InitialError::Keys)?;
        let candidate = seed
            .seal(&self.prf, info, clock, entropy)
            .map_err(InitialError::Keys)?;
        let at = clock.now().map_err(InitialError::Keys)?;
        self.retain(backend, candidate, ENROLLMENT_GENESIS_AT, &at.to_le_bytes())
            .await
    }

    /// One version-1 commit of the sealed candidate and its continuation (`tail`).
    async fn retain<B: Backend>(
        self,
        backend: B,
        candidate: ckmg::UnenrolledCreation,
        tail: &[u8],
        continuation: &[u8],
    ) -> Result<UnenrolledInitial<B>, InitialError> {
        // Reopening under this actual scope rejects a caller's different Binding.
        let candidate =
            ckmg::UnenrolledCreation::reopen(&self.prf, &self.scope, candidate.as_bytes())
                .map_err(InitialError::Keys)?;
        let operation = candidate.commitment().map_err(InitialError::Keys)?;
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(InitialError::Keys)?;
        let backend = BackendRef(Rc::new(backend));
        let mut prepared = cwst::Store::create(cwst::backend::Memory::new(), &cipher, &self.scope)
            .await
            .map_err(InitialError::Storage)?;
        prepared
            .commit(
                0,
                operation,
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: ENROLLMENT,
                        value: candidate.as_bytes(),
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: tail,
                        value: continuation,
                    },
                ],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        let store = cwst::Store::restore_checked(
            backend.clone(),
            &cipher,
            &self.scope,
            1,
            prepared
                .sealed_checkpoint()
                .map_err(InitialError::Storage)?,
            |store| {
                if store.operation()? != operation
                    || store.read(OWNER, ENROLLMENT)? != Some(candidate.as_bytes())
                    || store.read(OWNER, tail)? != Some(continuation)
                    || !matches!(enrollment_kind(store), Ok(Some(_)))
                    || !store.load_pending()?.is_empty()
                {
                    return Err(cwst::Error::Corrupt);
                }
                Ok(())
            },
        )
        .await
        .map_err(InitialError::Storage)?;
        Ok(UnenrolledInitial {
            opening: self,
            backend,
            store,
            candidate,
        })
    }

    /// Reopen the actual encrypted, still-unaccepted candidate with the same
    /// original passkey. Missing storage or an accepted phase refuses unchanged.
    pub async fn reopen_enrollment<B: Backend>(
        self,
        backend: B,
    ) -> Result<UnenrolledInitial<B>, InitialError> {
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(InitialError::Keys)?;
        let backend = BackendRef(Rc::new(backend));
        let store = cwst::Store::open(backend.clone(), &cipher, &self.scope)
            .await
            .map_err(InitialError::Storage)?;
        let candidate =
            ckmg::UnenrolledCreation::reopen(&self.prf, &self.scope, required(&store, ENROLLMENT)?)
                .map_err(InitialError::Keys)?;
        let this = UnenrolledInitial {
            opening: self,
            backend,
            store,
            candidate,
        };
        this.validate()?;
        Ok(this)
    }
}

impl<B: Backend> UnenrolledInitial<B> {
    fn validate(&self) -> Result<(), InitialError> {
        if self.store.version().map_err(InitialError::Storage)? != 1
            || self.store.operation().map_err(InitialError::Storage)? != self.commitment()?
            || required(&self.store, ENROLLMENT)? != self.candidate.as_bytes()
            || enrollment_kind(&self.store)?.is_none()
            || !self
                .store
                .load_pending()
                .map_err(InitialError::Storage)?
                .is_empty()
        {
            return Err(InitialError::Invalid);
        }
        for key in [
            INNER,
            OPERATION,
            KEYS,
            INTENT,
            DESCRIPTOR,
            VALUE,
            QUEUE,
            ACKNOWLEDGED_INNER,
            ACKNOWLEDGED_KEYS,
            RECOVERY,
            RECOVERY_PROGRESS,
            RETIREMENT_SELECTION,
            CARRIED_INNER,
        ] {
            if self
                .store
                .read(OWNER, key)
                .map_err(InitialError::Storage)?
                .is_some()
            {
                return Err(InitialError::Invalid);
            }
        }
        Ok(())
    }

    /// Original opaque registration request retained in the same encrypted CAS.
    /// These bytes are data only: the Foyer owner must validate their original
    /// origin, credential, commitment and deadline before retrying the ceremony.
    /// Reading them grants no session, registration or creation authority.
    /// A device-key enrollment has none and refuses.
    pub fn finish_continuation(&self) -> Result<&[u8], InitialError> {
        self.validate()?;
        match enrollment_kind(&self.store)? {
            Some(Enrollment::Finish(finish)) => Ok(finish),
            _ => Err(InitialError::Invalid),
        }
    }

    /// The committed creation time of a device-key enrollment (the time its genesis
    /// stamp binds). A passkey enrollment has none and refuses.
    pub fn genesis_at(&self) -> Result<u64, InitialError> {
        self.validate()?;
        genesis_at(&self.store)
    }

    /// The creation receipt's lineage challenge digest, before activation. Public data.
    pub fn passkey_challenge(&self) -> Result<[u8; 32], InitialError> {
        self.validate()?;
        self.candidate
            .passkey_challenge()
            .map_err(InitialError::Keys)
    }

    /// The `lineage_genesis` stamp action of this device-key creation with the device's
    /// secret `salt`: the same action the published genesis evidence proves after activation.
    pub fn lineage_genesis_action(
        &self,
        salt: [u8; 32],
    ) -> Result<cpsd::StampAction, InitialError> {
        cchr::lineage_genesis_action_for(self.passkey_challenge()?, salt, self.genesis_at()?)
            .map_err(|_| InitialError::Invalid)
    }

    /// The device key's signature over `payload` in one typed `format` (ckmg prepends the
    /// format's tag and refuses formats the enrollment may not sign), the only device signer
    /// before activation. Only a validated device-key enrollment signs; after activation
    /// `Keys` signs.
    pub fn sign_device(
        &self,
        format: ckmg::DeviceFormat,
        payload: &[u8],
    ) -> Result<[u8; 64], InitialError> {
        self.validate()?;
        genesis_at(&self.store)?;
        self.candidate
            .sign_device(format, payload)
            .map_err(InitialError::Keys)
    }

    /// The device key's stamp salt over `payload` before activation (ckmg's device salt).
    pub fn device_salt(&self, payload: &[u8]) -> Result<[u8; 32], InitialError> {
        self.validate()?;
        genesis_at(&self.store)?;
        self.candidate
            .device_salt(payload)
            .map_err(InitialError::Keys)
    }

    /// Opaque original server commitment, recomputed by Keys from private state.
    pub fn commitment(&self) -> Result<[u8; 32], InitialError> {
        self.candidate.commitment().map_err(InitialError::Keys)
    }

    /// Actual authenticated local generation/digest for the dedicated original
    /// enrollment authority. These coordinates do not themselves grant authority.
    pub fn activation_intent(&self) -> Result<ckmg::InitialActivationIntent, InitialError> {
        self.validate()?;
        Ok(ckmg::InitialActivationIntent {
            generation: self.store.version().map_err(InitialError::Storage)?,
            digest: *blake3::hash(
                self.store
                    .sealed_checkpoint()
                    .map_err(InitialError::Storage)?,
            )
            .as_bytes(),
        })
    }

    /// Activate this same root and operation only through fresh genuine original
    /// enrollment authority. The private adapter commits accepted Keys and their
    /// common-root Store together in the already-existing outer generation.
    pub async fn activate(
        self,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        authority: &mut impl Authority,
    ) -> Result<InitialCreation<B>, InitialError> {
        let intent = self.activation_intent()?;
        let Self {
            opening,
            backend,
            store,
            candidate,
        } = self;
        let state = Rc::new(futures::lock::Mutex::new(Some(store)));
        let adapter = ActivationStore {
            state: state.clone(),
            backend: backend.clone(),
            scope: opening.scope.clone(),
            location: opening.locator,
            inspector: opening.inspector().map_err(InitialError::Open)?,
        };
        let mut keys = ckmg::Keys::new(
            adapter,
            BorrowClock(clock),
            BorrowEntropy(entropy),
            ActivationAuthority(authority),
        );
        let receipt = keys
            .activate_initial(candidate, intent)
            .await
            .map_err(InitialError::Keys)?;
        keys.lock();
        drop(keys);
        let store = state.lock().await.take().ok_or(InitialError::Invalid)?;
        let pending = opening
            .inspector()
            .map_err(InitialError::Open)?
            .pending_creation(required(&store, KEYS)?)
            .map_err(InitialError::Keys)?;
        if pending.receipt() != &receipt {
            return Err(InitialError::Invalid);
        }
        let initial = InitialCreation {
            opening,
            backend,
            store,
            pending,
        };
        if initial.phase()? != InitialPhase::Pending {
            return Err(InitialError::Invalid);
        }
        Ok(initial)
    }
}

struct ActivationStore<B: Backend> {
    state: Rc<futures::lock::Mutex<Option<cwst::Store<BackendRef<B>>>>>,
    backend: BackendRef<B>,
    scope: String,
    location: ckmg::Locator,
    inspector: ckmg::CheckpointInspector,
}
impl<B: Backend> SecureStore for ActivationStore<B> {
    async fn load(&mut self, location: &ckmg::Locator) -> Result<Option<Vec<u8>>, ckmg::Error> {
        if location != &self.location {
            return Err(ckmg::Error::Unauthorized);
        }
        let held = self.state.lock().await;
        let store = held.as_ref().ok_or(ckmg::Error::Reconcile)?;
        let actual = self
            .backend
            .read()
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        if actual.as_deref()
            != Some(
                store
                    .sealed_checkpoint()
                    .map_err(|_| ckmg::Error::Reconcile)?,
            )
        {
            return Err(ckmg::Error::Reconcile);
        }
        if store.version().map_err(|_| ckmg::Error::Reconcile)? != 1
            || store
                .read(OWNER, KEYS)
                .map_err(|_| ckmg::Error::Reconcile)?
                .is_some()
        {
            return Err(ckmg::Error::RootExists);
        }
        // Absence is only this reserved accepted-Keys slot in the exact actual
        // unaccepted outer checkpoint; this private adapter never escapes.
        Ok(None)
    }
    async fn compare_exchange(
        &mut self,
        _: &ckmg::Locator,
        _: Option<[u8; 32]>,
        _: &[u8],
    ) -> Result<ckmg::Commit, ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn compare_exchange_wrapped(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
        cipher: &ckmg::passkey::StoreCipher,
    ) -> Result<ckmg::Commit, ckmg::Error> {
        if location != &self.location || expected.is_some() {
            return Err(ckmg::Error::Unauthorized);
        }
        let mut store = self
            .state
            .lock()
            .await
            .take()
            .ok_or(ckmg::Error::Reconcile)?;
        if store.version().map_err(|_| ckmg::Error::Reconcile)? != 1 {
            return Err(ckmg::Error::Reconcile);
        }
        let pending = self.inspector.pending_creation(replacement)?;
        let operation = *pending.receipt().operation.as_bytes();
        let mut inner = cwst::Store::create(cwst::backend::Memory::new(), cipher, &self.scope)
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        inner
            .commit(
                0,
                operation,
                &[cwst::Change::Put {
                    owner: "keys",
                    key: location.as_bytes(),
                    value: replacement,
                }],
                &[],
            )
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        let wire = inner
            .sealed_checkpoint()
            .map_err(|_| ckmg::Error::Unavailable)?;
        if wire.len() > cwst::MAX_VALUE_BYTES || replacement.len() > cwst::MAX_VALUE_BYTES {
            return Err(ckmg::Error::Limit);
        }
        let result = store
            .commit_with_receipt(
                1,
                operation,
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: INNER,
                        value: wire,
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: KEYS,
                        value: replacement,
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: OPERATION,
                        value: &operation,
                    },
                ],
                &[],
            )
            .await;
        match result {
            Ok(receipt) => {
                if !receipt.is_commit(&store, &operation)
                    || !receipt.contains_record(OWNER, INNER, blake3::hash(wire).as_bytes())
                    || !receipt.contains_record(OWNER, KEYS, blake3::hash(replacement).as_bytes())
                {
                    return Ok(ckmg::Commit::Unknown);
                }
                *self.state.lock().await = Some(store);
                Ok(ckmg::Commit::Committed)
            }
            Err(cwst::Error::Conflict) => Ok(ckmg::Commit::Conflict),
            Err(_) => Ok(ckmg::Commit::Unknown),
        }
    }
}

struct BorrowClock<'a, C>(&'a mut C);
impl<C: Clock> Clock for BorrowClock<'_, C> {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        self.0.now()
    }
}
struct BorrowEntropy<'a, E>(&'a mut E);
impl<E: Entropy> Entropy for BorrowEntropy<'_, E> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ckmg::Error> {
        self.0.fill(bytes)
    }
}
struct ActivationAuthority<'a, A>(&'a mut A);
impl<A: Authority> Authority for ActivationAuthority<'_, A> {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
    async fn check_initial_activation(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.0.check_initial_activation(request).await
    }
    fn check_initial_activation_current(
        &mut self,
        request: ckmg::InitialActivationAuthorization<'_>,
    ) -> Result<u64, ckmg::Error> {
        self.0.check_initial_activation_current(request)
    }
}
