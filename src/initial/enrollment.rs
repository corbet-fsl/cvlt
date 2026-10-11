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
                        key: ENROLLMENT_FINISH,
                        value: finish_continuation,
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
                    || store.read(OWNER, ENROLLMENT_FINISH)? != Some(finish_continuation)
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
            || required(&self.store, ENROLLMENT_FINISH)?.is_empty()
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
    pub fn finish_continuation(&self) -> Result<&[u8], InitialError> {
        self.validate()?;
        required(&self.store, ENROLLMENT_FINISH)
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
