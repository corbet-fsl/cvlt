//! Bounded canonical owner content, carried inside original encrypted Records.
use super::{CheckpointError, MAX_CHECKPOINT_RECORDS, MAX_PACKED_CHECKPOINT, PARTS, RECORD_BYTES};
const HEADER: &[u8] = b"cvlt.compound.v1\0";
const FIXED: usize = HEADER.len() + 1 + 32 + 32 + 8 + 4 + 32 + 2;
const ENTRY: usize = 32 + 4 + 32;
#[derive(Clone)]
pub(super) struct Entry {
    pub target: [u8; 32],
    pub length: u32,
    pub hash: [u8; 32],
}
#[derive(Clone)]
pub(super) struct Manifest {
    pub index: bool,
    pub scope: [u8; 32],
    pub root: cdht::RecordKey,
    pub version: u64,
    pub length: u32,
    pub hash: [u8; 32],
    pub entries: Vec<Entry>,
}
pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
pub(super) fn scope_digest(scope: &str) -> Result<[u8; 32], CheckpointError> {
    if scope.is_empty() || scope.len() > cwst::MAX_KEY_BYTES || scope.chars().any(char::is_control)
    {
        return Err(CheckpointError::Invalid);
    }
    Ok(digest(scope.as_bytes()))
}
impl Manifest {
    pub fn new(scope: [u8; 32], root: cdht::RecordKey, version: u64, packed: &[u8]) -> Self {
        Self {
            index: false,
            scope,
            root,
            version,
            length: packed.len() as u32,
            hash: digest(packed),
            entries: vec![],
        }
    }
    pub fn direct(&self, bytes: &[u8]) -> Self {
        let mut result = self.clone();
        result.index = false;
        result.entries = bytes
            .chunks(cdht::MAX_SUBKEY_SIZE)
            .enumerate()
            .map(|(i, part)| {
                let mut target = [0; 32];
                target[..4].copy_from_slice(&((i + 1) as u32).to_le_bytes());
                Entry {
                    target,
                    length: part.len() as u32,
                    hash: digest(part),
                }
            })
            .collect();
        result
    }
    pub fn data_length(&self) -> Result<usize, CheckpointError> {
        self.entries.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.length as usize)
                .ok_or(CheckpointError::Limit)
        })
    }
    fn validate(&self) -> Result<(), CheckpointError> {
        if self.version > u64::from(cdht::MAX_SEQ)
            || self.length == 0
            || self.length as usize > MAX_PACKED_CHECKPOINT
            || self.entries.is_empty()
            || self.entries.len()
                > if self.index {
                    MAX_CHECKPOINT_RECORDS
                } else {
                    PARTS
                }
        {
            return Err(CheckpointError::Limit);
        }
        let mut targets = std::collections::BTreeSet::new();
        let maximum = if self.index {
            RECORD_BYTES
        } else {
            cdht::MAX_SUBKEY_SIZE
        };
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.length == 0
                || entry.length as usize > maximum
                || !targets.insert(entry.target)
                || (index + 1 != self.entries.len() && entry.length as usize != maximum)
            {
                return Err(CheckpointError::Invalid);
            }
            if !self.index {
                let mut expected = [0; 32];
                expected[..4].copy_from_slice(&((index + 1) as u32).to_le_bytes());
                if entry.target != expected {
                    return Err(CheckpointError::Invalid);
                }
            } else if entry.target == self.root.0 {
                return Err(CheckpointError::Invalid);
            }
        }
        let length = self.data_length()?;
        if length > self.length as usize
            || (self.index && (length != self.length as usize || length <= RECORD_BYTES))
        {
            return Err(CheckpointError::Invalid);
        }
        Ok(())
    }
    pub fn bind(
        &self,
        scope: [u8; 32],
        root: cdht::RecordKey,
        sequence: u32,
    ) -> Result<(), CheckpointError> {
        if self.scope != scope || self.root != root || self.version != u64::from(sequence) {
            return Err(CheckpointError::Invalid);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        let mut out = Vec::with_capacity(FIXED + ENTRY * self.entries.len());
        out.extend_from_slice(HEADER);
        out.push(u8::from(self.index));
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.root.0);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.target);
            out.extend_from_slice(&entry.length.to_le_bytes());
            out.extend_from_slice(&entry.hash);
        }
        if out.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(CheckpointError::Limit);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() < FIXED || bytes.len() > cdht::MAX_SUBKEY_SIZE || !bytes.starts_with(HEADER)
        {
            return Err(CheckpointError::Invalid);
        }
        let mut pos = HEADER.len();
        let index = match take::<1>(bytes, &mut pos)?[0] {
            0 => false,
            1 => true,
            _ => return Err(CheckpointError::Invalid),
        };
        let scope = take(bytes, &mut pos)?;
        let root = cdht::RecordKey(take(bytes, &mut pos)?);
        let version = u64::from_le_bytes(take(bytes, &mut pos)?);
        let length = u32::from_le_bytes(take(bytes, &mut pos)?);
        let hash = take(bytes, &mut pos)?;
        let count = u16::from_le_bytes(take(bytes, &mut pos)?) as usize;
        if count > if index { MAX_CHECKPOINT_RECORDS } else { PARTS }
            || bytes.len() != FIXED + count * ENTRY
        {
            return Err(CheckpointError::Invalid);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(Entry {
                target: take(bytes, &mut pos)?,
                length: u32::from_le_bytes(take(bytes, &mut pos)?),
                hash: take(bytes, &mut pos)?,
            });
        }
        let manifest = Self {
            index,
            scope,
            root,
            version,
            length,
            hash,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}
fn take<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], CheckpointError> {
    let end = pos.checked_add(N).ok_or(CheckpointError::Limit)?;
    let value = bytes
        .get(*pos..end)
        .ok_or(CheckpointError::Invalid)?
        .try_into()
        .map_err(|_| CheckpointError::Invalid)?;
    *pos = end;
    Ok(value)
}
