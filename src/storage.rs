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
/// One async mutex over the authoritative checkpoint, usable on native and browser.
pub type SharedStore<B> = Rc<futures::lock::Mutex<cwst::Store<B>>>;
/// Wrap one already-authenticated checkpoint; no second domain snapshot is made.
pub fn shared_store<B: Backend>(store: cwst::Store<B>) -> SharedStore<B> {
    Rc::new(futures::lock::Mutex::new(store))
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
    storage: SharedStore<B>,
    scope: String,
    slot: Rc<RefCell<Slot>>,
}
impl<B: Backend> Clone for KeyStore<B> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            scope: self.scope.clone(),
            slot: self.slot.clone(),
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
            storage,
            scope: scope.into(),
            slot: Rc::new(RefCell::new(Slot::default())),
        })
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
impl<B: Backend> SecureStore for KeyStore<B> {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, ckmg::Error> {
        let store = self.storage.lock().await;
        if !store.is_scope(&self.scope) {
            return Err(ckmg::Error::Unauthorized);
        }
        let bytes = store
            .read("keys", location.as_bytes())
            .map_err(|_| ckmg::Error::Unavailable)?;
        if bytes.is_some_and(|v| v.len() > ckmg::MAX_CHECKPOINT_BYTES) {
            return Err(ckmg::Error::Limit);
        }
        Ok(bytes.map(<[u8]>::to_vec))
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
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
        let mut store = self.storage.lock().await;
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
        match store
            .commit(batch.expected, batch.operation, &changes, &batch.outputs)
            .await
        {
            Ok(_) => Ok(Commit::Committed),
            Err(cwst::Error::Conflict) => Ok(Commit::Conflict),
            Err(_) => Ok(Commit::Unknown),
        }
    }
}
