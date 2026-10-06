//! Compound Store retention through existing authenticated Veilid records.
//! Manifests are Vault-owned content, never a replacement DHT or authority proof.
use cdht::runtime::{Backend, Publication, Record, Value};
use zeroize::Zeroizing;

mod manifest;
use manifest::{Entry, Manifest, digest, scope_digest};

/// Owner-only record layout: subkey zero is a manifest; 31 subkeys carry data.
pub const CHECKPOINT_SUBKEYS: u16 = 32;
/// Bound includes compression framing and Padme overhead for an 8 MiB Store.
pub const MAX_PACKED_CHECKPOINT: usize = 9 * 1024 * 1024;
const PARTS: usize = CHECKPOINT_SUBKEYS as usize - 1;
const RECORD_BYTES: usize = PARTS * cdht::MAX_SUBKEY_SIZE;
/// Largest number of child records required by the bounded compound checkpoint.
pub const MAX_CHECKPOINT_RECORDS: usize = MAX_PACKED_CHECKPOINT.div_ceil(RECORD_BYTES);
const PAYLOAD_HEADER: &[u8] = b"cvlt.compound-store.v1\0";

/// Value-free checkpoint refusal. Missing content is always unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    /// Scope, manifest, hash, generation or authenticated owner is invalid.
    Invalid,
    /// Input, record layout or decompression exceeds the original owner limits.
    Limit,
    /// Records cannot establish a complete authenticated observation.
    Unavailable,
    /// The original Store refused its authenticated checkpoint.
    Storage(cwst::Error),
}
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("compound checkpoint refused")
    }
}
impl std::error::Error for CheckpointError {}

/// Publication progress, not application acknowledgement or a currentness grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointPublication {
    /// No publication has been attempted on this owner handle.
    Idle,
    /// The call is in progress, or was cancelled with an unknown partial outcome.
    InProgress,
    /// Writes may have completed before a transport refusal; reopen/read to reconcile.
    Partial,
    /// The original runtime returned an authenticated conflicting value.
    Conflict,
    /// All values, including the final manifest, entered the engine's durable queue.
    Queued,
    /// Every write completed the runtime's own network replication operation.
    Replicated,
}

/// Prepared only from the original authenticated Store. Holds sealed checkpoint
/// bytes, never a PRF, root or decrypted owner snapshot. Drop wipes packed bytes.
pub struct PreparedCheckpoint {
    scope: [u8; 32],
    root: cdht::RecordKey,
    sequence: u32,
    packed: Zeroizing<Vec<u8>>,
    // Root first, followed by child manifests in the configured record order.
    manifests: Vec<Zeroizing<Vec<u8>>>,
}
impl std::fmt::Debug for PreparedCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedCheckpoint([redacted])")
    }
}

/// A complete forced Records observation. Storage authentication is still required
/// before installation; neither this object nor its version authorizes G3.
pub struct RetainedCheckpoint {
    scope: [u8; 32],
    sequence: u32,
    wire: Zeroizing<Vec<u8>>,
}
impl RetainedCheckpoint {
    pub(crate) async fn restore_keys<B: cwst::backend::Backend>(
        self,
        backend: B,
        cipher: &ckmg::passkey::StoreCipher,
        scope: &str,
        locator: ckmg::Locator,
        expected_keys: &[u8; 32],
    ) -> Result<cwst::Store<B>, CheckpointError> {
        if scope_digest(scope)? != self.scope {
            return Err(CheckpointError::Invalid);
        }
        cwst::Store::restore_checked(
            backend,
            cipher,
            scope,
            u64::from(self.sequence),
            &self.wire,
            |store| match store.read("keys", locator.as_bytes())? {
                Some(sealed) if blake3::hash(sealed).as_bytes() == expected_keys => Ok(()),
                _ => Err(cwst::Error::Unlock),
            },
        )
        .await
        .map_err(CheckpointError::Storage)
    }
    /// Authenticate the original Store and install into an empty local destination.
    /// The exact manifest version must equal the authenticated Store version.
    /// This never overwrites existing state or creates Keys/root/Wallet state.
    pub async fn restore<B: cwst::backend::Backend>(
        self,
        backend: B,
        cipher: &ckmg::passkey::StoreCipher,
        scope: &str,
    ) -> Result<cwst::Store<B>, CheckpointError> {
        if scope_digest(scope)? != self.scope {
            return Err(CheckpointError::Invalid);
        }
        cwst::Store::restore(backend, cipher, scope, u64::from(self.sequence), &self.wire)
            .await
            .map_err(CheckpointError::Storage)
    }
}
impl std::fmt::Debug for RetainedCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedCheckpoint([redacted])")
    }
}

/// Thin owner of one root record and bounded purpose-separated child records.
/// All records use the original authenticated runtime and owner-only DFLT(32).
/// The trusted composer binds these capabilities to the same community/root;
/// request JSON cannot choose their association. Record observations never grant
/// membership or current lineage. Close the engines when custody is invalidated.
pub struct CompoundRecords<B: Backend> {
    scope: [u8; 32],
    root: Record<B>,
    children: Vec<Record<B>>,
    observed: Option<(u32, [u8; 32])>,
    publication: CheckpointPublication,
}
impl<B: Backend> CompoundRecords<B> {
    /// Attach original record capabilities; no record is created by this facade.
    pub fn new(
        scope: &str,
        root: Record<B>,
        children: Vec<Record<B>>,
    ) -> Result<Self, CheckpointError> {
        let scope = scope_digest(scope)?;
        if children.len() > MAX_CHECKPOINT_RECORDS {
            return Err(CheckpointError::Limit);
        }
        let schema =
            cdht::Schema::dflt(CHECKPOINT_SUBKEYS).map_err(|_| CheckpointError::Invalid)?;
        let mut keys = std::collections::BTreeSet::new();
        for record in std::iter::once(&root).chain(&children) {
            if record.identity().schema != schema || !keys.insert(record.identity().key) {
                return Err(CheckpointError::Invalid);
            }
        }
        Ok(Self {
            scope,
            root,
            children,
            observed: None,
            publication: CheckpointPublication::Idle,
        })
    }
    /// Return handles for explicit original-runtime shutdown or ownership transfer.
    pub fn into_records(self) -> (Record<B>, Vec<Record<B>>) {
        (self.root, self.children)
    }
    /// The last publication result; cancellation leaves InProgress, never success.
    pub fn publication(&self) -> CheckpointPublication {
        self.publication
    }

    /// Prepare an exact committed Store checkpoint, compress then Padme then split.
    /// The Store wire already provides its local at-rest encryption; Records adds
    /// the original VLD0 layer after packing. No domain state is reserialized here.
    pub fn prepare<S: cwst::backend::Backend>(
        &self,
        store: &cwst::Store<S>,
        scope: &str,
    ) -> Result<PreparedCheckpoint, CheckpointError> {
        if self.scope != scope_digest(scope)? || !store.is_scope(scope) {
            return Err(CheckpointError::Invalid);
        }
        let version = store.version().map_err(CheckpointError::Storage)?;
        let sequence = u32::try_from(version)
            .ok()
            .filter(|n| *n <= cdht::MAX_SEQ)
            .ok_or(CheckpointError::Limit)?;
        let packed = pack(
            store
                .sealed_checkpoint()
                .map_err(CheckpointError::Storage)?,
        )?;
        let root = self.root.identity().key;
        let header = Manifest::new(self.scope, root, version, &packed);
        let mut manifests = Vec::new();
        if packed.len() <= RECORD_BYTES {
            manifests.push(Zeroizing::new(header.direct(&packed).encode()?));
        } else {
            let needed = packed.len().div_ceil(RECORD_BYTES);
            if needed > self.children.len() {
                return Err(CheckpointError::Limit);
            }
            let mut index = header.clone();
            index.index = true;
            for (child, bytes) in self.children.iter().zip(packed.chunks(RECORD_BYTES)) {
                let manifest = Zeroizing::new(header.direct(bytes).encode()?);
                index.entries.push(Entry {
                    target: child.identity().key.0,
                    length: bytes.len() as u32,
                    hash: digest(&manifest),
                });
                manifests.push(manifest);
            }
            manifests.insert(0, Zeroizing::new(index.encode()?));
        }
        Ok(PreparedCheckpoint {
            scope: self.scope,
            root,
            sequence,
            packed,
            manifests,
        })
    }

    /// Write parts first, then their manifests, and root manifest last. Partial or
    /// cancelled writes may make the previous generation unavailable; they can
    /// never assemble a different generation or count as replicated/acknowledged.
    /// Retrying the same prepared bytes keeps the original sequence and hashes.
    pub async fn publish(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<CheckpointPublication, CheckpointError> {
        if prepared.scope != self.scope
            || prepared.root != self.root.identity().key
            || self.observed.is_some_and(|(floor, previous)| {
                prepared.sequence < floor
                    || (prepared.sequence == floor && digest(&prepared.manifests[0]) != previous)
            })
        {
            return Err(CheckpointError::Invalid);
        }
        let root_manifest = Manifest::decode(&prepared.manifests[0])?;
        if root_manifest.index
            && (prepared.manifests.len() - 1 > self.children.len()
                || root_manifest
                    .entries
                    .iter()
                    .zip(&self.children)
                    .any(|(entry, child)| entry.target != child.identity().key.0))
        {
            return Err(CheckpointError::Invalid);
        }
        self.publication = CheckpointPublication::InProgress;
        let result = self.publish_inner(prepared).await;
        match result {
            Ok(outcome) => {
                self.publication = outcome;
                Ok(outcome)
            }
            Err(error) => {
                self.publication = CheckpointPublication::Partial;
                Err(error)
            }
        }
    }
    async fn publish_inner(
        &mut self,
        prepared: &PreparedCheckpoint,
    ) -> Result<CheckpointPublication, CheckpointError> {
        let mut queued = false;
        let multi = prepared.manifests.len() > 1;
        for (index, chunk) in prepared.packed.chunks(RECORD_BYTES).enumerate() {
            let record = if multi {
                &self.children[index]
            } else {
                &self.root
            };
            for (part, bytes) in chunk.chunks(cdht::MAX_SUBKEY_SIZE).enumerate() {
                match put(record, (part + 1) as u32, prepared.sequence, bytes).await? {
                    Publication::Queued => queued = true,
                    Publication::Replicated => {}
                    Publication::Conflict(_) => return Ok(CheckpointPublication::Conflict),
                }
            }
            if multi {
                match put(record, 0, prepared.sequence, &prepared.manifests[index + 1]).await? {
                    Publication::Queued => queued = true,
                    Publication::Replicated => {}
                    Publication::Conflict(_) => return Ok(CheckpointPublication::Conflict),
                }
            }
        }
        match put(&self.root, 0, prepared.sequence, &prepared.manifests[0]).await? {
            Publication::Queued => queued = true,
            Publication::Replicated => {}
            Publication::Conflict(value) => {
                self.observe(value.seq, &value.data)?;
                return Ok(CheckpointPublication::Conflict);
            }
        }
        self.observe(prepared.sequence, &prepared.manifests[0])?;
        Ok(if queued {
            CheckpointPublication::Queued
        } else {
            CheckpointPublication::Replicated
        })
    }

    fn observe(&mut self, sequence: u32, bytes: &[u8]) -> Result<(), CheckpointError> {
        let hash = digest(bytes);
        if self.observed.is_some_and(|(floor, previous)| {
            sequence < floor || (sequence == floor && hash != previous)
        }) {
            return Err(CheckpointError::Invalid);
        }
        self.observed = Some((sequence, hash));
        Ok(())
    }
    /// Force every authenticated read, reject missing/mixed generations, then read
    /// the root manifest again. No backend cache or missing value proves absence.
    pub async fn checkpoint(&mut self) -> Result<RetainedCheckpoint, CheckpointError> {
        let root_value = get(&self.root, 0).await?;
        self.observe(root_value.seq, &root_value.data)?;
        let manifest = Manifest::decode(&root_value.data)?;
        manifest.bind(self.scope, self.root.identity().key, root_value.seq)?;
        let mut packed = Zeroizing::new(Vec::with_capacity(manifest.length as usize));
        if manifest.index {
            for entry in &manifest.entries {
                let child = self
                    .children
                    .iter()
                    .find(|child| child.identity().key.0 == entry.target)
                    .ok_or(CheckpointError::Unavailable)?;
                let child_value = get(child, 0).await?;
                if child_value.seq != root_value.seq || digest(&child_value.data) != entry.hash {
                    return Err(CheckpointError::Invalid);
                }
                let child_manifest = Manifest::decode(&child_value.data)?;
                child_manifest.bind(self.scope, self.root.identity().key, root_value.seq)?;
                if child_manifest.index
                    || child_manifest.length != manifest.length
                    || child_manifest.hash != manifest.hash
                    || child_manifest.data_length()? != entry.length as usize
                {
                    return Err(CheckpointError::Invalid);
                }
                append_parts(child, &child_manifest, root_value.seq, &mut packed).await?;
            }
        } else {
            if manifest.data_length()? != manifest.length as usize {
                return Err(CheckpointError::Invalid);
            }
            append_parts(&self.root, &manifest, root_value.seq, &mut packed).await?;
        }
        if packed.len() != manifest.length as usize || digest(&packed) != manifest.hash {
            return Err(CheckpointError::Invalid);
        }
        let latest = get(&self.root, 0).await?;
        self.observe(latest.seq, &latest.data)?;
        if latest.seq != root_value.seq || latest.data != root_value.data {
            return Err(CheckpointError::Unavailable);
        }
        Ok(RetainedCheckpoint {
            scope: self.scope,
            sequence: root_value.seq,
            wire: unpack(&packed)?,
        })
    }
}
impl<B: Backend> std::fmt::Debug for CompoundRecords<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompoundRecords([redacted])")
    }
}
async fn put<B: Backend>(
    record: &Record<B>,
    subkey: u32,
    seq: u32,
    bytes: &[u8],
) -> Result<Publication, CheckpointError> {
    record
        .republish(
            subkey,
            &Value {
                seq,
                writer: record.identity().owner,
                data: Zeroizing::new(bytes.to_vec()),
            },
        )
        .await
        .map_err(|_| CheckpointError::Unavailable)
}
async fn get<B: Backend>(record: &Record<B>, subkey: u32) -> Result<Value, CheckpointError> {
    record
        .get(subkey, true)
        .await
        .map_err(|_| CheckpointError::Unavailable)?
        .ok_or(CheckpointError::Unavailable)
}
async fn append_parts<B: Backend>(
    record: &Record<B>,
    manifest: &Manifest,
    sequence: u32,
    packed: &mut Vec<u8>,
) -> Result<(), CheckpointError> {
    for (index, entry) in manifest.entries.iter().enumerate() {
        let value = get(record, (index + 1) as u32).await?;
        if value.seq != sequence
            || value.data.len() != entry.length as usize
            || digest(&value.data) != entry.hash
        {
            return Err(CheckpointError::Invalid);
        }
        if packed
            .len()
            .checked_add(value.data.len())
            .is_none_or(|n| n > MAX_PACKED_CHECKPOINT)
        {
            return Err(CheckpointError::Limit);
        }
        packed.extend_from_slice(&value.data);
    }
    Ok(())
}
fn pack(wire: &[u8]) -> Result<Zeroizing<Vec<u8>>, CheckpointError> {
    if wire.is_empty() || wire.len() > cwst::MAX_CHECKPOINT_BYTES {
        return Err(CheckpointError::Limit);
    }
    let mut framed = Zeroizing::new(PAYLOAD_HEADER.to_vec());
    framed.extend_from_slice(wire);
    let compressed =
        Zeroizing::new(cprz::portable::compress(&framed).map_err(|_| CheckpointError::Invalid)?);
    let padded = Zeroizing::new(cprz_pad::pad(&compressed));
    if padded.len() > MAX_PACKED_CHECKPOINT {
        return Err(CheckpointError::Limit);
    }
    Ok(padded)
}
fn unpack(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CheckpointError> {
    if padded.is_empty() || padded.len() > MAX_PACKED_CHECKPOINT {
        return Err(CheckpointError::Limit);
    }
    let compressed = Zeroizing::new(cprz_pad::unpad(padded).map_err(|_| CheckpointError::Invalid)?);
    let framed = Zeroizing::new(
        cprz::portable::decompress(
            &compressed,
            MAX_PACKED_CHECKPOINT,
            cwst::MAX_CHECKPOINT_BYTES + PAYLOAD_HEADER.len(),
        )
        .map_err(|_| CheckpointError::Invalid)?,
    );
    let wire = framed
        .strip_prefix(PAYLOAD_HEADER)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(CheckpointError::Invalid)?;
    Ok(Zeroizing::new(wire.to_vec()))
}

/// Derive and open one compound record through the original live Keys and Mesh
/// owners. None selects the stable manifest record; Some selects a bounded child.
/// The purpose is member-scoped and root-derived, with no raw key export. This
/// requires already-authorized Keys; it does not solve passkey-root bootstrap.
#[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
pub async fn native_checkpoint_record<
    S: ckmg::SecureStore,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
>(
    keys: &mut ckmg::Keys<S, C, E, A>,
    records: &cmsh::VeilidRecords,
    scope: &str,
    child: Option<usize>,
) -> Result<Record<cmsh::VeilidRecord>, CheckpointError> {
    scope_digest(scope)?;
    let label = match child {
        None => "vault.checkpoint".to_owned(),
        Some(index) if index < MAX_CHECKPOINT_RECORDS => format!("vault.checkpoint.chunk.{index}"),
        Some(_) => return Err(CheckpointError::Limit),
    };
    let purpose =
        ckmg::Purpose::new(ckmg::Scope::Member, &label, 0).map_err(|_| CheckpointError::Invalid)?;
    let handle = keys
        .key(purpose)
        .await
        .map_err(|_| CheckpointError::Unavailable)?;
    if handle.certificate().binding.community() != scope {
        return Err(CheckpointError::Invalid);
    }
    let schema =
        ckmg::NativeRecordSchema::dflt(CHECKPOINT_SUBKEYS).map_err(|_| CheckpointError::Invalid)?;
    let initializer = keys
        .native_record_initializer(&handle, schema)
        .await
        .map_err(|_| CheckpointError::Unavailable)?;
    records
        .initialize(initializer)
        .await
        .map_err(|_| CheckpointError::Unavailable)
}

#[cfg(test)]
mod tests;
