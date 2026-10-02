//! Passkey root retention through the existing Mesh and Records native engine.
use crate::{PasskeyUnlock, Records, RestoreLookup};
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

/// One PRF-owned DFLT(1) record, opened only through Mesh's actual native factory.
/// It preserves a local observation floor, but DOES NOT attest globally current
/// lineage or grant G3. Empty/failed network reads are never authoritative absence.
pub struct PasskeyRecords {
    local: ckmg::Locator,
    record: cdht::runtime::Record<cmsh::VeilidRecord>,
    observed_sequence: Option<u32>,
}
impl PasskeyRecords {
    /// Construct from the exact trusted passkey handover and existing shared core.
    /// The engine computes owner/schema/read custody from the opaque initializer.
    /// For retained startup values, obtain this factory from VeilidRuntime::prepare,
    /// publish the original committed values, then invoke that runtime's attach.
    /// Do not use start for staging: even failed/cancelled attach permanently ends
    /// the native engine's offline startup window. No second core is created here.
    pub async fn open(
        unlock: &PasskeyUnlock,
        factory: &cmsh::VeilidRecords,
    ) -> Result<Self, RecordError> {
        let local = unlock.local_locator().map_err(|_| RecordError::Invalid)?;
        let initializer = unlock
            .record_initializer()
            .map_err(|_| RecordError::Invalid)?;
        let record = factory
            .initialize(initializer)
            .await
            .map_err(|_| RecordError::Unavailable)?;
        Ok(Self {
            local,
            record,
            observed_sequence: None,
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
    /// Close this record in the existing core on lock/revocation/shutdown.
    pub async fn close(self) -> Result<(), RecordError> {
        self.record
            .into_backend()
            .close()
            .await
            .map_err(|_| RecordError::Unavailable)
    }
}
impl Records for PasskeyRecords {
    async fn lookup(&mut self, locator: &ckmg::Locator) -> RestoreLookup {
        if locator != &self.local {
            return RestoreLookup::Unavailable;
        }
        let Ok(Some(value)) = self.record.get(0, true).await else {
            return RestoreLookup::Unavailable;
        };
        if self
            .observed_sequence
            .is_some_and(|floor| value.seq < floor)
        {
            return RestoreLookup::Unavailable;
        }
        // Remember authenticated sequence even if the owner's application bytes
        // are malformed; a lower retained value must not silently replace it.
        self.observed_sequence = Some(value.seq);
        match unpack(&value.data) {
            Ok(bytes) => RestoreLookup::Present(bytes),
            Err(_) => RestoreLookup::Unavailable,
        }
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
    #[test]
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
