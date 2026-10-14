use ckmg::{Commit, Locator, SecureStore};
use cwst::backend::Backend;
use std::{cell::RefCell, rc::Rc};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Value-free composition refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Store scope does not match the intended community.
    Scope,
    /// Another batch remains active.
    Busy,
    /// Invalid operation or attempt to replace Keys-owned state.
    Invalid,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault: {self:?}")
    }
}
impl std::error::Error for Error {}
/// One authoritative checkpoint and its original Keys-only read capability.
/// Reads never re-lock the outer transaction mutex; Storage revokes them before
/// yielding a pending write and publishes only a completed authenticated CAS.
pub struct StoreCell<B: Backend> {
    store: futures::lock::Mutex<cwst::Store<B>>,
    keys: cwst::ReadHandle,
}
impl<B: Backend> StoreCell<B> {
    /// Borrow the original Store exclusively for an owner transaction.
    pub async fn lock(&self) -> futures::lock::MutexGuard<'_, cwst::Store<B>> {
        self.store.lock().await
    }
}
/// Shared ownership of one authoritative checkpoint, usable on native and browser.
pub type SharedStore<B> = Rc<StoreCell<B>>;
/// Wrap one already-authenticated checkpoint; no second domain snapshot is made.
/// Replacing this Store requires a new SharedStore and new Keys reconciliation.
pub fn shared_store<B: Backend>(store: cwst::Store<B>) -> SharedStore<B> {
    let keys = store
        .read_handle("keys")
        .expect("fixed Keys owner is valid");
    Rc::new(StoreCell {
        store: futures::lock::Mutex::new(store),
        keys,
    })
}

/// Opaque prepared owner mutation. None deletes; Some replaces. Secrets wipe on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mutation {
    /// Domain owner; the reserved `keys` namespace is rejected.
    pub owner: String,
    /// Owner-local record identifier.
    pub key: Vec<u8>,
    /// Opaque owner bytes, or explicit deletion.
    pub value: Option<Vec<u8>>,
}
/// A transient compound commit, never an accepted domain state.
pub struct Batch {
    /// Version observed before preparing every owner candidate.
    pub expected: u64,
    /// Nonzero exact operation identifier for reconciliation.
    pub operation: [u8; 32],
    /// Other owner candidates whose effects depend on this Keys transition.
    pub mutations: Vec<Mutation>,
    /// Exact already-encrypted/public output bytes; never plaintext roots or PRF.
    pub outputs: Vec<cwst::Output>,
}
#[derive(Default)]
struct Slot {
    active: bool,
    batch: Option<Batch>,
}
/// Cancellation guard for one staged batch. It carries no authority to emit outputs.
/// A consumed batch remains reserved until this guard drops, preventing guard ABA.
pub struct BatchGuard(Rc<RefCell<Slot>>);
impl Drop for BatchGuard {
    fn drop(&mut self) {
        let mut slot = self.0.borrow_mut();
        slot.batch = None;
        slot.active = false;
    }
}
/// ckmg's real durable adapter. Keys ciphertext and companion outputs share one
/// cwst transaction. It never reports a staged write as durably committed.
pub struct KeyStore<B: Backend> {
    backing: Rc<futures::lock::Mutex<Backing<B>>>,
    scope: String,
    slot: Rc<RefCell<Slot>>,
    /// Wrapping for the first write of a pending pairing (no common root exists yet).
    pending: Option<Rc<ckmg::passkey::StoreCipher>>,
}
enum Backing<B: Backend> {
    Initial(B),
    Ready(SharedStore<B>),
    Spent,
}
impl<B: Backend> Clone for KeyStore<B> {
    fn clone(&self) -> Self {
        Self {
            backing: self.backing.clone(),
            scope: self.scope.clone(),
            slot: self.slot.clone(),
            pending: self.pending.clone(),
        }
    }
}
impl<B: Backend> KeyStore<B> {
    /// Select the already-authenticated checkpoint's community. Rechecked on all I/O.
    pub fn new(storage: SharedStore<B>, scope: &str) -> Result<Self, Error> {
        if scope.is_empty() || scope.len() > cwst::MAX_KEY_BYTES {
            return Err(Error::Scope);
        }
        Ok(Self {
            backing: Rc::new(futures::lock::Mutex::new(Backing::Ready(storage))),
            scope: scope.into(),
            slot: Rc::new(RefCell::new(Slot::default())),
            pending: None,
        })
    }
    pub(crate) fn initial(backend: B, scope: &str) -> Result<Self, Error> {
        if scope.is_empty() || scope.len() > cwst::MAX_KEY_BYTES {
            return Err(Error::Scope);
        }
        Ok(Self {
            backing: Rc::new(futures::lock::Mutex::new(Backing::Initial(backend))),
            scope: scope.into(),
            slot: Rc::new(RefCell::new(Slot::default())),
            pending: None,
        })
    }

    /// An empty destination whose first write is a pending pairing request, wrapped
    /// under the passkey's own store cipher (the common root arrives only with the grant).
    pub(crate) fn initial_pairing(
        backend: B,
        scope: &str,
        cipher: ckmg::passkey::StoreCipher,
    ) -> Result<Self, Error> {
        let mut store = Self::initial(backend, scope)?;
        store.pending = Some(Rc::new(cipher));
        Ok(store)
    }

    pub(crate) async fn ready(&self) -> Result<SharedStore<B>, ckmg::Error> {
        match &*self.backing.lock().await {
            Backing::Ready(storage) => Ok(storage.clone()),
            _ => Err(ckmg::Error::Reconcile),
        }
    }

    /// Stage one compound write, refusing reserved owners and concurrent batches.
    pub fn stage(&mut self, batch: Batch) -> Result<BatchGuard, Error> {
        if batch.operation == [0; 32] || batch.mutations.iter().any(|m| m.owner == "keys") {
            return Err(Error::Invalid);
        }
        let mut slot = self.slot.borrow_mut();
        if slot.active {
            return Err(Error::Busy);
        }
        slot.active = true;
        slot.batch = Some(batch);
        Ok(BatchGuard(self.slot.clone()))
    }
}
impl<B: Backend> KeyStore<B> {
    async fn commit_checkpoint(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
        cipher: Option<&ckmg::passkey::StoreCipher>,
    ) -> Result<Commit, ckmg::Error> {
        if replacement.len() > ckmg::MAX_CHECKPOINT_BYTES {
            return Err(ckmg::Error::Limit);
        }
        let batch = self
            .slot
            .borrow_mut()
            .batch
            .take()
            .ok_or(ckmg::Error::Unavailable)?;
        let mut backing = self.backing.lock().await;
        let storage = match &*backing {
            Backing::Ready(storage) => storage.clone(),
            Backing::Spent => return Err(ckmg::Error::Reconcile),
            Backing::Initial(_) => {
                // Consume the destination before preparation or destination I/O. A dropped or
                // uncertain creation cannot retry with another random root.
                let Backing::Initial(backend) = std::mem::replace(&mut *backing, Backing::Spent)
                else {
                    unreachable!();
                };
                drop(backing);
                return self
                    .commit_initial(
                        backend,
                        location,
                        expected,
                        replacement,
                        cipher.or(self.pending.as_deref()),
                        batch,
                    )
                    .await;
            }
        };
        drop(backing);
        let mut store = storage.lock().await;
        if !store.is_scope(&self.scope) {
            return Err(ckmg::Error::Unauthorized);
        }
        let previous = store
            .read("keys", location.as_bytes())
            .map_err(|_| ckmg::Error::Unavailable)?;
        if previous.map(|bytes| *blake3::hash(bytes).as_bytes()) != expected {
            return Ok(Commit::Conflict);
        }
        let mut changes: Vec<_> = batch
            .mutations
            .iter()
            .map(|m| match &m.value {
                Some(value) => cwst::Change::Put {
                    owner: &m.owner,
                    key: &m.key,
                    value,
                },
                None => cwst::Change::Delete {
                    owner: &m.owner,
                    key: &m.key,
                },
            })
            .collect();
        changes.push(cwst::Change::Put {
            owner: "keys",
            key: location.as_bytes(),
            value: replacement,
        });
        let result = match cipher {
            Some(cipher) => {
                store
                    .commit_rewrapped(
                        batch.expected,
                        batch.operation,
                        &changes,
                        &batch.outputs,
                        cipher,
                    )
                    .await
            }
            None => {
                store
                    .commit(batch.expected, batch.operation, &changes, &batch.outputs)
                    .await
            }
        };
        match result {
            Ok(_) => Ok(Commit::Committed),
            Err(cwst::Error::Conflict) => Ok(Commit::Conflict),
            Err(_) => Ok(Commit::Unknown),
        }
    }
}

impl<B: Backend> SecureStore for KeyStore<B> {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, ckmg::Error> {
        let backing = self.backing.lock().await;
        let storage = match &*backing {
            Backing::Initial(backend) => {
                // This is actual destination absence, never a missing local
                // Keys entry, cache miss or a failed read interpreted as empty.
                return match backend.read().await {
                    Ok(None) => Ok(None),
                    Ok(Some(_)) => Err(ckmg::Error::RootExists),
                    Err(_) => Err(ckmg::Error::Unavailable),
                };
            }
            Backing::Ready(storage) => storage.clone(),
            Backing::Spent => return Err(ckmg::Error::Reconcile),
        };
        drop(backing);
        if !storage.keys.is_scope(&self.scope) {
            return Err(ckmg::Error::Unauthorized);
        }
        storage
            .keys
            .read(location.as_bytes(), ckmg::MAX_CHECKPOINT_BYTES)
            .map_err(|error| match error {
                cwst::Error::TooLarge => ckmg::Error::Limit,
                _ => ckmg::Error::Unavailable,
            })
    }

    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<Commit, ckmg::Error> {
        self.commit_checkpoint(location, expected, replacement, None)
            .await
    }

    async fn compare_exchange_wrapped(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
        cipher: &ckmg::passkey::StoreCipher,
    ) -> Result<Commit, ckmg::Error> {
        self.commit_checkpoint(location, expected, replacement, Some(cipher))
            .await
    }
}

impl<B: Backend> KeyStore<B> {
    async fn commit_initial(
        &self,
        backend: B,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
        cipher: Option<&ckmg::passkey::StoreCipher>,
        batch: Batch,
    ) -> Result<Commit, ckmg::Error> {
        let cipher = cipher.ok_or(ckmg::Error::Unauthorized)?;
        if expected.is_some() || batch.expected != 0 {
            return Ok(Commit::Conflict);
        }
        // Original ephemeral Storage is preparation only. No Memory receipt
        // escapes and no successful preparation is reported to Keys as durable.
        let mut prepared = cwst::Store::create(cwst::backend::Memory::new(), cipher, &self.scope)
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        let mut changes: Vec<_> = batch
            .mutations
            .iter()
            .map(|m| match &m.value {
                Some(value) => cwst::Change::Put {
                    owner: &m.owner,
                    key: &m.key,
                    value,
                },
                None => cwst::Change::Delete {
                    owner: &m.owner,
                    key: &m.key,
                },
            })
            .collect();
        changes.push(cwst::Change::Put {
            owner: "keys",
            key: location.as_bytes(),
            value: replacement,
        });
        prepared
            .commit(0, batch.operation, &changes, &batch.outputs)
            .await
            .map_err(|_| ckmg::Error::Unavailable)?;
        let wire = prepared
            .sealed_checkpoint()
            .map_err(|_| ckmg::Error::Unavailable)?;
        let result = install_initial(
            backend,
            cipher,
            &self.scope,
            location,
            replacement,
            batch.operation,
            wire,
        )
        .await;
        match result {
            Ok(store) => {
                // A cancellation waiting for this lock leaves Spent. The exact
                // durable bytes must then be reopened, never recreated.
                *self.backing.lock().await = Backing::Ready(shared_store(store));
                Ok(Commit::Committed)
            }
            Err(cwst::Error::AlreadyInitialized | cwst::Error::Conflict) => Ok(Commit::Conflict),
            Err(_) => Ok(Commit::Unknown),
        }
    }
}

async fn install_initial<B: Backend>(
    backend: B,
    cipher: &ckmg::passkey::StoreCipher,
    scope: &str,
    location: &Locator,
    replacement: &[u8],
    operation: [u8; 32],
    wire: &[u8],
) -> Result<cwst::Store<B>, cwst::Error> {
    cwst::Store::restore_checked(backend, cipher, scope, 1, wire, |store| {
        if !store.is_scope(scope)
            || store.operation()? != operation
            || store.read("keys", location.as_bytes())? != Some(replacement)
        {
            return Err(cwst::Error::Corrupt);
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
#[path = "../tests/unit/initial_store.rs"]
mod initial_tests;
