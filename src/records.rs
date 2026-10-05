//! Original passkey-root retention format through Mesh and authenticated Records.
use crate::{Records, RestoreLookup};
use cdht::runtime::{Backend, Record};
use ckmg::Locator;
use zeroize::Zeroizing;

const HEADER: &[u8] = b"cvlt.passkey-root.v1\0";

/// Coarse record-layout/transport failure. No owner, locator, content or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Missing/invalid custody or framing.
    Invalid,
    /// Bounded root payload does not fit one native subkey.
    Limit,
    /// Actual record engine is unavailable or refused the operation.
    Unavailable,
}
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault root record refused")
    }
}
impl std::error::Error for RecordError {}

/// One original forced, authenticated record observation. Its sequence is the
/// Records sequence, not a Keys lineage revision or a membership policy epoch.
/// The payload remains encrypted by Keys; this grants no current device rights.
pub struct RecordCheckpoint {
    pub(crate) locator: Locator,
    key: cdht::RecordKey,
    sequence: u32,
    sealed: Zeroizing<Vec<u8>>,
}
impl RecordCheckpoint {
    /// Canonical record key from the actual authenticated record capability.
    pub fn record_key(&self) -> cdht::RecordKey {
        self.key
    }
    /// Authenticated original sequence selected by the record engine.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Exact opaque retained bytes for the original Keys decoder, never a new format.
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }
}
impl std::fmt::Debug for RecordCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordCheckpoint([redacted])")
    }
}

/// One PRF-owned DFLT(1) record in the original authenticated engine. Native
/// construction consumes original Keys custody through Mesh's existing factory.
/// It preserves a local observation floor, but DOES NOT attest globally current
/// lineage or grant G3. Empty/failed network reads are never authoritative absence.
pub struct PasskeyRecords<B: Backend> {
    local: ckmg::Locator,
    record: Record<B>,
    observed_sequence: Option<u32>,
}
impl<B: Backend> PasskeyRecords<B> {
    /// Bind original same-passkey/scope capabilities in the trusted composer.
    /// PreparedOpen::native_records performs this association inside Vault;
    /// request JSON must never select a locator/record pairing.
    pub fn new(local: Locator, record: Record<B>) -> Result<Self, RecordError> {
        if record.identity().schema != cdht::Schema::dflt(1).map_err(|_| RecordError::Invalid)? {
            return Err(RecordError::Invalid);
        }
        Ok(Self {
            local,
            record,
            observed_sequence: None,
        })
    }
    /// Release the original handle for explicit owner runtime shutdown.
    pub fn into_record(self) -> Record<B> {
        self.record
    }
    /// Force an original authenticated read, apply its observed sequence floor
    /// and decode the existing compressed/padded passkey-root format. Retain
    /// original provenance separately from the decrypted Keys checkpoint claims.
    pub async fn checkpoint(&mut self, locator: &Locator) -> Result<RecordCheckpoint, RecordError> {
        if locator != &self.local {
            return Err(RecordError::Invalid);
        }
        let value = self
            .record
            .get(0, true)
            .await
            .map_err(|_| RecordError::Unavailable)?
            .ok_or(RecordError::Unavailable)?;
        if self
            .observed_sequence
            .is_some_and(|floor| value.seq < floor)
        {
            return Err(RecordError::Invalid);
        }
        // Preserve the original observation floor even when application framing
        // refuses, so malformed current bytes cannot make older content current.
        self.observed_sequence = Some(value.seq);
        Ok(RecordCheckpoint {
            locator: self.local,
            key: self.record.identity().key,
            sequence: value.seq,
            sealed: Zeroizing::new(unpack(&value.data)?),
        })
    }
    /// Republish an exact owner-selected sequence and already PRF-wrapped root
    /// payload from its durable outbox. Compression, Padme, then actual-core VLD0.
    /// Queuing/replication is not application acknowledgement or lineage authority.
    pub async fn publish(
        &mut self,
        sequence: u32,
        wrapped_root: &[u8],
    ) -> Result<cdht::runtime::Publication, RecordError> {
        if self.observed_sequence.is_some_and(|floor| sequence < floor) {
            return Err(RecordError::Invalid);
        }
        let packed = pack(wrapped_root)?;
        let identity = self.record.identity();
        let value = cdht::runtime::Value {
            seq: sequence,
            writer: identity.owner,
            data: packed,
        };
        let outcome = self
            .record
            .republish(0, &value)
            .await
            .map_err(|_| RecordError::Unavailable)?;
        match &outcome {
            cdht::runtime::Publication::Queued | cdht::runtime::Publication::Replicated => {
                self.observed_sequence = Some(sequence)
            }
            cdht::runtime::Publication::Conflict(value) => {
                self.observed_sequence = Some(
                    self.observed_sequence
                        .map_or(value.seq, |floor| floor.max(value.seq)),
                )
            }
        }
        Ok(outcome)
    }
}
impl<B: Backend> Records for PasskeyRecords<B> {
    async fn lookup(&mut self, locator: &Locator) -> RestoreLookup {
        match self.checkpoint(locator).await {
            Ok(checkpoint) => RestoreLookup::Present(checkpoint.sealed.to_vec()),
            // No original protocol absence witness is provided by this port.
            Err(_) => RestoreLookup::Unavailable,
        }
    }
}
#[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
impl PasskeyRecords<cmsh::VeilidRecord> {
    /// Close this record in the existing core on lock/revocation/shutdown.
    pub async fn close(self) -> Result<(), RecordError> {
        self.record
            .into_backend()
            .close()
            .await
            .map_err(|_| RecordError::Unavailable)
    }
}
impl<B: Backend> std::fmt::Debug for PasskeyRecords<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasskeyRecords([redacted])")
    }
}

fn pack(wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    if wrapped.is_empty() || wrapped.len() > ckmg::MAX_CHECKPOINT_BYTES {
        return Err(RecordError::Limit);
    }
    let mut framed = Zeroizing::new(HEADER.to_vec());
    framed.extend_from_slice(wrapped);
    let compressed =
        Zeroizing::new(cprz::portable::compress(&framed).map_err(|_| RecordError::Invalid)?);
    let padded = Zeroizing::new(cprz_pad::pad(&compressed));
    if padded.len() > cdht::MAX_SUBKEY_SIZE {
        return Err(RecordError::Limit);
    }
    Ok(padded)
}
fn unpack(padded: &[u8]) -> Result<Vec<u8>, RecordError> {
    if padded.len() > cdht::MAX_SUBKEY_SIZE {
        return Err(RecordError::Limit);
    }
    let compressed = Zeroizing::new(cprz_pad::unpad(padded).map_err(|_| RecordError::Invalid)?);
    let framed = Zeroizing::new(
        cprz::portable::decompress(
            &compressed,
            cdht::MAX_SUBKEY_SIZE,
            ckmg::MAX_CHECKPOINT_BYTES + HEADER.len(),
        )
        .map_err(|_| RecordError::Invalid)?,
    );
    let wrapped = framed
        .strip_prefix(HEADER)
        .filter(|bytes| !bytes.is_empty())
        .ok_or(RecordError::Invalid)?;
    Ok(wrapped.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckmg::Entropy;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn real_compression_padding_roundtrip_and_decoder_bounds() {
        let wrapped = b"synthetic existing PRF-wrapped owner payload";
        let packed = pack(wrapped).unwrap();
        assert_eq!(unpack(&packed).unwrap(), wrapped);
        assert!(pack(&[]).is_err());
        assert!(pack(&vec![0; ckmg::MAX_CHECKPOINT_BYTES + 1]).is_err());
        let mut incompressible = vec![0; cdht::MAX_SUBKEY_SIZE];
        ckmg::SystemEntropy.fill(&mut incompressible).unwrap();
        assert_eq!(pack(&incompressible).unwrap_err(), RecordError::Limit);
        assert!(unpack(&vec![0; cdht::MAX_SUBKEY_SIZE + 1]).is_err());
        assert!(unpack(&[]).is_err());
        assert!(unpack(&cprz_pad::pad(&[0])).is_err());
        for malformed in [
            HEADER.to_vec(),
            b"foreign owner format".to_vec(),
            vec![0; ckmg::MAX_CHECKPOINT_BYTES + HEADER.len() + 1],
        ] {
            let packed = cprz_pad::pad(&cprz::portable::compress(&malformed).unwrap());
            assert!(unpack(&packed).is_err());
        }
        for error in [
            RecordError::Invalid,
            RecordError::Limit,
            RecordError::Unavailable,
        ] {
            assert_eq!(error.to_string(), "Vault root record refused");
        }
    }
}
