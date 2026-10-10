//! Completion of an original creation from the original encrypted Store format.
use crate::{Batch, OpenError, Owners, PreparedLineageEvidence, PreparedOpen, Records};
use ckmg::{Authority, Clock, Entropy};
use cwst::backend::Backend;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

const OWNER: &str = "initial-creation";
const INNER: &[u8] = b"common-root-store";
const OPERATION: &[u8] = b"inner-operation";
const KEYS: &[u8] = b"pending-created-keys";
const INTENT: &[u8] = b"prepared-intent";
const DESCRIPTOR: &[u8] = b"genesis-descriptor";
const VALUE: &[u8] = b"genesis-value";

/// Coarse failure; absence never authorizes another Create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialError {
    /// Original owner preparation failed.
    Open(OpenError),
    /// Original encrypted Storage refused or has an uncertain outcome.
    Storage(cwst::Error),
    /// Original pending Keys custody or completion authority refused.
    Keys(ckmg::Error),
    /// Original evidence packing or record codec refused.
    Records(crate::RecordError),
    /// The authenticated owner state does not describe this exact operation.
    Invalid,
}
impl std::fmt::Display for InitialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "initial creation: {self:?}")
    }
}
impl std::error::Error for InitialError {}

/// Durable progress only; no phase represents normal member authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialPhase {
    /// Exact original pending Keys and common-root Store have committed together.
    Pending,
    /// The single nonce, evidence and deadline have committed before signing.
    Prepared,
    /// Exact original signed outputs have committed before any network output.
    Retained,
}

struct BackendRef<B>(Rc<B>);
impl<B> Clone for BackendRef<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<B: Backend> Backend for BackendRef<B> {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.0.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.0.compare_exchange(expected, next).await
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    nonce: [u8; 24],
    packed_evidence: Vec<u8>,
    prepared_at: u64,
    expires: u64,
}

/// Original passkey custody for this one incomplete creation. No ordinary Vault,
/// root signer, recovery capability or accepted member state is returned.
/// Every mutating method consumes the handle, including cancellation/refusal.
pub struct InitialCreation<B: Backend> {
    opening: PreparedOpen,
    backend: BackendRef<B>,
    store: cwst::Store<BackendRef<B>>,
    pending: ckmg::PendingCreation,
}
impl<B: Backend> std::fmt::Debug for InitialCreation<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialCreation([redacted])")
    }
}

/// Exact original upstream encodings read only from committed Storage. Publishing
/// them does not acknowledge Keys or establish current lineage/member authority.
pub struct RetainedGenesis {
    descriptor: cdht::rpc::DescriptorBytes,
    value: cdht::rpc::ValueBytes,
}
impl RetainedGenesis {
    /// Unchanged original signed descriptor bytes.
    pub fn descriptor(&self) -> &[u8] {
        self.descriptor.as_bytes()
    }
    /// Unchanged original signed value bytes, including its frozen nonce.
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}
impl std::fmt::Debug for RetainedGenesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedGenesis([redacted])")
    }
}

impl PreparedOpen {
    /// Consume original registration/Create authority and atomically install the
    /// exact pending Keys plus common-root Store in an original PRF-wrapped Store.
    /// Memory preparation never escapes as a durable receipt or usable Vault.
    ///
    /// If creation is consumed but the first durable CAS never happens, this path
    /// cannot recover it. Reopening absent storage refuses; it never retries Create.
    pub async fn create_recoverable<
        B: Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        W,
    >(
        self,
        backend: B,
        binding: ckmg::Binding,
        info: ckmg::DeviceInfo,
        evidence: &[u8],
        batch: Batch,
        owners: Owners<C, E, A, R, W>,
    ) -> Result<InitialCreation<B>, InitialError> {
        let backend = BackendRef(Rc::new(backend));
        match backend.read().await.map_err(InitialError::Storage)? {
            None => {}
            Some(_) => return Err(InitialError::Storage(cwst::Error::AlreadyInitialized)),
        }
        let operation = batch.operation;
        let (vault, receipt) = self
            .create_initial_inner(
                cwst::backend::Memory::new(),
                binding,
                info,
                evidence,
                batch,
                owners,
            )
            .await
            .map_err(InitialError::Open)?;
        let (wire, sealed) = {
            let store = vault.storage().lock().await;
            let wire = store
                .sealed_checkpoint()
                .map_err(InitialError::Storage)?
                .to_vec();
            let sealed = store
                .read("keys", self.locator.as_bytes())
                .map_err(InitialError::Storage)?
                .ok_or(InitialError::Invalid)?
                .to_vec();
            (wire, sealed)
        };
        drop(vault);
        let pending = self
            .inspector()
            .map_err(InitialError::Open)?
            .pending_creation(&sealed)
            .map_err(InitialError::Keys)?;
        if pending.receipt() != &receipt {
            return Err(InitialError::Invalid);
        }
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(InitialError::Keys)?;
        let store = install(
            backend.clone(),
            &cipher,
            &self.scope,
            operation,
            &wire,
            &sealed,
        )
        .await?;
        Ok(InitialCreation {
            opening: self,
            backend,
            store,
            pending,
        })
    }

    /// Reopen only this original passkey's durable incomplete operation. This is
    /// not ordinary restore; corrupt, missing, wrong-scope or other-passkey state
    /// refuses without any write or replacement root.
    pub async fn reopen_initial<B: Backend>(
        self,
        backend: B,
    ) -> Result<InitialCreation<B>, InitialError> {
        let cipher =
            ckmg::passkey::store_cipher(&self.prf, &self.scope).map_err(InitialError::Keys)?;
        let backend = BackendRef(Rc::new(backend));
        let store = cwst::Store::open(backend.clone(), &cipher, &self.scope)
            .await
            .map_err(InitialError::Storage)?;
        let sealed = required(&store, KEYS)?;
        let pending = self
            .inspector()
            .map_err(InitialError::Open)?
            .pending_creation(sealed)
            .map_err(InitialError::Keys)?;
        let this = InitialCreation {
            opening: self,
            backend,
            store,
            pending,
        };
        this.phase()?;
        Ok(this)
    }
}

async fn install<B: Backend>(
    backend: BackendRef<B>,
    cipher: &ckmg::passkey::StoreCipher,
    scope: &str,
    operation: [u8; 32],
    wire: &[u8],
    sealed: &[u8],
) -> Result<cwst::Store<BackendRef<B>>, InitialError> {
    // Opaque nested Store bytes count against the real per-value limit, and the
    // original encoder additionally bounds JSON expansion and the total frame.
    if wire.is_empty() || wire.len() > cwst::MAX_VALUE_BYTES || sealed.len() > cwst::MAX_VALUE_BYTES
    {
        return Err(InitialError::Storage(cwst::Error::TooLarge));
    }
    let mut prepared = cwst::Store::create(cwst::backend::Memory::new(), cipher, scope)
        .await
        .map_err(InitialError::Storage)?;
    prepared
        .commit(
            0,
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
                    value: sealed,
                },
                cwst::Change::Put {
                    owner: OWNER,
                    key: OPERATION,
                    value: &operation,
                },
            ],
            &[],
        )
        .await
        .map_err(InitialError::Storage)?;
    cwst::Store::restore_checked(
        backend,
        cipher,
        scope,
        1,
        prepared
            .sealed_checkpoint()
            .map_err(InitialError::Storage)?,
        |store| {
            if store.operation()? != operation
                || store.read(OWNER, INNER)? != Some(wire)
                || store.read(OWNER, KEYS)? != Some(sealed)
                || store.read(OWNER, OPERATION)? != Some(operation.as_slice())
            {
                return Err(cwst::Error::Corrupt);
            }
            Ok(())
        },
    )
    .await
    .map_err(InitialError::Storage)
}

fn required<'a, B: Backend>(
    store: &'a cwst::Store<B>,
    key: &[u8],
) -> Result<&'a [u8], InitialError> {
    store
        .read(OWNER, key)
        .map_err(InitialError::Storage)?
        .ok_or(InitialError::Invalid)
}

impl<B: Backend> InitialCreation<B> {
    /// The exact authenticated original Created receipt, solely for its dedicated
    /// original passkey challenge and public evidence; not a completion grant.
    pub fn receipt(&self) -> &ckmg::Receipt {
        self.pending.receipt()
    }

    /// Authenticate the local phase shape and immutable owner bindings.
    pub fn phase(&self) -> Result<InitialPhase, InitialError> {
        required(&self.store, INNER)?;
        if initial_operation(&self.store)? == [0; 32] {
            return Err(InitialError::Invalid);
        }
        if *blake3::hash(required(&self.store, KEYS)?).as_bytes() != *self.pending.sealed_digest()
            || self.pending.location() != &self.opening.locator
        {
            return Err(InitialError::Invalid);
        }
        let intent = self
            .store
            .read(OWNER, INTENT)
            .map_err(InitialError::Storage)?;
        let descriptor = self
            .store
            .read(OWNER, DESCRIPTOR)
            .map_err(InitialError::Storage)?;
        let value = self
            .store
            .read(OWNER, VALUE)
            .map_err(InitialError::Storage)?;
        let version = self.store.version().map_err(InitialError::Storage)?;
        let expected_operation = if version == 1 {
            initial_operation(&self.store)?
        } else {
            *self.pending.receipt().operation.as_bytes()
        };
        if self.store.operation().map_err(InitialError::Storage)? != expected_operation {
            return Err(InitialError::Invalid);
        }
        if version < 3
            && !self
                .store
                .load_pending()
                .map_err(InitialError::Storage)?
                .is_empty()
        {
            return Err(InitialError::Invalid);
        }
        match (version, intent, descriptor, value) {
            (1, None, None, None) => Ok(InitialPhase::Pending),
            (2, Some(bytes), None, None) => {
                decode_intent(bytes)?;
                Ok(InitialPhase::Prepared)
            }
            (3, Some(bytes), Some(_), Some(_)) => {
                decode_intent(bytes)?;
                self.retained()?;
                Ok(InitialPhase::Retained)
            }
            _ => Err(InitialError::Invalid),
        }
    }

    /// Freeze original packed evidence and one nonce before any signing. A failed
    /// or cancelled CAS consumes this handle; reopen its exact durable state.
    pub async fn prepare(
        mut self,
        evidence: &PreparedLineageEvidence,
        expires: u64,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Self, InitialError> {
        if self.phase()? != InitialPhase::Pending
            || !evidence.evidence().matches_receipt(self.pending.receipt())
        {
            return Err(InitialError::Invalid);
        }
        let prepared_at = clock.now().map_err(InitialError::Keys)?;
        if prepared_at < self.pending.last_time() {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        if prepared_at >= expires {
            return Err(InitialError::Keys(ckmg::Error::Expired));
        }
        let mut nonce = [0; 24];
        entropy.fill(&mut nonce).map_err(InitialError::Keys)?;
        let intent = Intent {
            nonce,
            packed_evidence: evidence
                .evidence()
                .packed()
                .map_err(InitialError::Records)?
                .to_vec(),
            prepared_at,
            expires,
        };
        let bytes = serde_json::to_vec(&intent).map_err(|_| InitialError::Invalid)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        self.store
            .commit(
                1,
                *self.pending.receipt().operation.as_bytes(),
                &[cwst::Change::Put {
                    owner: OWNER,
                    key: INTENT,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        let completed = clock.now().map_err(InitialError::Keys)?;
        if completed < prepared_at {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        if completed >= expires {
            return Err(InitialError::Keys(ckmg::Error::Expired));
        }
        Ok(self)
    }

    /// Read only the exact committed original outputs. Reopening never signs
    /// anew or manufactures another nonce, deadline, receipt or creation root.
    pub fn retained(&self) -> Result<RetainedGenesis, InitialError> {
        if self.store.version().map_err(InitialError::Storage)? != 3 {
            return Err(InitialError::Invalid);
        }
        let descriptor =
            cdht::rpc::DescriptorBytes::from_bytes(required(&self.store, DESCRIPTOR)?.to_vec())
                .map_err(|_| InitialError::Invalid)?;
        let value = cdht::rpc::ValueBytes::from_bytes(required(&self.store, VALUE)?.to_vec())
            .map_err(|_| InitialError::Invalid)?;
        let decoded = descriptor.decode().map_err(|_| InitialError::Invalid)?;
        let schema = decoded
            .validate(&crate::records::tor::Verifier)
            .map_err(|_| InitialError::Invalid)?;
        let (lineage, _) = self
            .pending
            .receipt()
            .attested_lineage()
            .map_err(InitialError::Keys)?;
        let signed = value.decode().map_err(|_| InitialError::Invalid)?;
        let intent = decode_intent(required(&self.store, INTENT)?)?;
        if decoded.owner != *lineage.root.value()
            || schema != cdht::Schema::dflt(1).map_err(|_| InitialError::Invalid)?
            || signed.seq != 0
            || signed.nonce != Some(intent.nonce)
            || signed.writer != decoded.owner
        {
            return Err(InitialError::Invalid);
        }
        signed
            .validate(
                &decoded.key(),
                &decoded.owner,
                &schema,
                0,
                &crate::records::tor::Verifier,
            )
            .map_err(|_| InitialError::Invalid)?;
        let outputs = self.store.load_pending().map_err(InitialError::Storage)?;
        if outputs.len() != 2
            || !outputs
                .iter()
                .any(|o| o.id == [1; 32] && o.bytes == descriptor.as_bytes())
            || !outputs
                .iter()
                .any(|o| o.id == [2; 32] && o.bytes == value.as_bytes())
        {
            return Err(InitialError::Invalid);
        }
        Ok(RetainedGenesis { descriptor, value })
    }

    /// Complete only the original immutable prepared intent. Dedicated original
    /// authority must admit this pending creation and recheck its retained live
    /// owners after the last backend wait. Exact signed outputs commit before
    /// this returns; conflict/cancellation/uncertainty returns no output.
    pub async fn retain(
        self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<Self, InitialError> {
        if self.phase()? != InitialPhase::Prepared {
            return Err(InitialError::Invalid);
        }
        let Self {
            opening,
            backend,
            mut store,
            pending,
        } = self;
        let intent = decode_intent(required(&store, INTENT)?)?;
        let mut clock = CompletionClock {
            clock,
            floor: intent.prepared_at,
        };
        let inner_wire = required(&store, INNER)?.to_vec();
        let sealed = required(&store, KEYS)?.to_vec();
        let outer_wire = store
            .sealed_checkpoint()
            .map_err(InitialError::Storage)?
            .to_vec();
        let completion = pending
            .authorize_completion(
                ckmg::CompletionIntent {
                    outer_generation: store.version().map_err(InitialError::Storage)?,
                    outer_digest: *blake3::hash(&outer_wire).as_bytes(),
                    inner_version: 1,
                    // The original initial inner commit may use a different ID from
                    // the Keys receipt. Read its authenticated operation below before
                    // accepting the completion. It was frozen with the initial wrapper.
                    inner_operation: initial_operation(&store)?,
                    inner_digest: *blake3::hash(&inner_wire).as_bytes(),
                    nonce: intent.nonce,
                    packed_evidence: intent.packed_evidence,
                    prepared_at: intent.prepared_at,
                    expires: intent.expires,
                },
                &mut clock,
                authority,
            )
            .await
            .map_err(InitialError::Keys)?;
        let operation = initial_operation(&store)?;
        // Original owner authentication, not a caller-supplied inner digest or
        // a successful decryption of only the outer wrapping checkpoint.
        let inner = cwst::Store::restore_checked(
            cwst::backend::Memory::new(),
            completion.store_cipher(),
            &opening.scope,
            1,
            &inner_wire,
            |inner| {
                if inner.operation()? != operation
                    || inner.read("keys", completion.location().as_bytes())?
                        != Some(sealed.as_slice())
                {
                    return Err(cwst::Error::Corrupt);
                }
                Ok(())
            },
        )
        .await
        .map_err(InitialError::Storage)?;
        drop(inner);
        // A real authoritative backend read is the final wait before the
        // synchronous owner check and fixed construction. The following CAS
        // additionally rejects a concurrent change before output can escape.
        if backend
            .read()
            .await
            .map_err(InitialError::Storage)?
            .as_deref()
            != Some(outer_wire.as_slice())
        {
            return Err(InitialError::Storage(cwst::Error::Conflict));
        }
        let (descriptor, value) = completion
            .complete_genesis(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        let descriptor =
            cdht::rpc::DescriptorBytes::encode(&descriptor).map_err(|_| InitialError::Invalid)?;
        let value = cdht::rpc::ValueBytes::encode(&value).map_err(|_| InitialError::Invalid)?;
        let receipt = opening
            .inspector()
            .map_err(InitialError::Open)?
            .pending_creation(&sealed)
            .map_err(InitialError::Keys)?;
        store
            .commit(
                2,
                *receipt.receipt().operation.as_bytes(),
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: DESCRIPTOR,
                        value: descriptor.as_bytes(),
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: VALUE,
                        value: value.as_bytes(),
                    },
                ],
                &[
                    cwst::Output {
                        id: [1; 32],
                        bytes: descriptor.as_bytes().to_vec(),
                    },
                    cwst::Output {
                        id: [2; 32],
                        bytes: value.as_bytes().to_vec(),
                    },
                ],
            )
            .await
            .map_err(InitialError::Storage)?;
        let now = clock.now().map_err(InitialError::Keys)?;
        if now < intent.prepared_at {
            return Err(InitialError::Keys(ckmg::Error::Clock));
        }
        if now >= intent.expires {
            return Err(InitialError::Keys(ckmg::Error::Expired));
        }
        Ok(Self {
            opening,
            backend,
            store,
            pending: receipt,
        })
    }
}

fn initial_operation<B: Backend>(store: &cwst::Store<B>) -> Result<[u8; 32], InitialError> {
    required(store, OPERATION)?
        .try_into()
        .map_err(|_| InitialError::Invalid)
}

struct CompletionClock<'a, C> {
    clock: &'a mut C,
    floor: u64,
}
impl<C: Clock> Clock for CompletionClock<'_, C> {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        let now = self.clock.now()?;
        if now < self.floor {
            return Err(ckmg::Error::Clock);
        }
        self.floor = now;
        Ok(now)
    }
}

fn decode_intent(bytes: &[u8]) -> Result<Intent, InitialError> {
    if bytes.len() > cwst::MAX_VALUE_BYTES {
        return Err(InitialError::Storage(cwst::Error::TooLarge));
    }
    let intent: Intent = serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
    if intent.packed_evidence.is_empty()
        || intent.packed_evidence.len() > cdht::MAX_SUBKEY_SIZE
        || intent.prepared_at >= intent.expires
    {
        return Err(InitialError::Invalid);
    }
    Ok(intent)
}

#[cfg(test)]
#[path = "../tests/unit/initial_completion.rs"]
mod tests;
