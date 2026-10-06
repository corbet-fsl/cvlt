//! Forced reads of certified lineage content in original authenticated Records.
use crate::{LineageEvidence, MAX_LINEAGE_EVIDENCE_BYTES, RecordError};
use cdht::runtime::{Backend, Record, Value};
use zeroize::Zeroizing;

/// The enclosing custody owner supplies its original root-owned lineage record
/// handles, including known rotation predecessors. No caller JSON selects these
/// handles. This facade never derives keys or changes the engine's read agreement.
pub struct LineageRecords<B: Backend> {
    records: Vec<Record<B>>,
    floors: Vec<Vec<Option<u32>>>,
}

/// One completed forced read of all configured lineage slots. Contains evidence
/// only, never an accepted head. Current Charter and HTTPS membership must be
/// rechecked after this await and before choosing a lineage.
pub struct LineageRead(Vec<LineageEvidence>);
impl LineageRead {
    /// Exact certified evidence bytes decoded from this completed forced read.
    pub fn evidence(&self) -> &[LineageEvidence] {
        &self.0
    }
}

impl<B: Backend> LineageRecords<B> {
    /// Retain actual authenticated handles, not public owner/record assertions.
    /// The total observation is bounded by the original Keys device limit.
    pub fn new(records: Vec<Record<B>>) -> Result<Self, RecordError> {
        let slots = records
            .iter()
            .try_fold(0usize, |total, record| {
                total.checked_add(record.identity().schema.subkey_count())
            })
            .ok_or(RecordError::Limit)?;
        if records.is_empty() || slots > ckmg::MAX_DEVICES {
            return Err(RecordError::Limit);
        }
        let mut unique = std::collections::HashSet::new();
        if records
            .iter()
            .any(|record| !unique.insert(record.identity().key))
        {
            return Err(RecordError::Invalid);
        }
        let floors = records
            .iter()
            .map(|r| vec![None; r.identity().schema.subkey_count()])
            .collect();
        Ok(Self { records, floors })
    }

    /// Every slot uses refresh=true. A replica/slot failure refuses the whole
    /// observation; a local or cached head is never a fallback. Original record
    /// signatures, writer sets and equal-sequence conflict rules remain in CDHT.
    pub async fn read(&mut self) -> Result<LineageRead, RecordError> {
        let mut evidence = Vec::new();
        let mut remaining = MAX_LINEAGE_EVIDENCE_BYTES;
        for (record, floors) in self.records.iter().zip(&mut self.floors) {
            for (subkey, floor) in floors.iter_mut().enumerate() {
                let value = record
                    .get(subkey as u32, true)
                    .await
                    .map_err(|_| RecordError::Unavailable)?;
                let Some(value) = value else {
                    // An earlier value disappearing is rollback/unavailability,
                    // never an empty current lineage or permission to create.
                    if floor.is_some() {
                        return Err(RecordError::Unavailable);
                    }
                    continue;
                };
                if floor.is_some_and(|previous| value.seq < previous) {
                    return Err(RecordError::Invalid);
                }
                *floor = Some(value.seq);
                let compressed =
                    Zeroizing::new(cprz_pad::unpad(&value.data).map_err(|_| RecordError::Invalid)?);
                let bytes = Zeroizing::new(
                    cprz::portable::decompress(&compressed, cdht::MAX_SUBKEY_SIZE, remaining)
                        .map_err(|_| RecordError::Invalid)?,
                );
                remaining = remaining
                    .checked_sub(bytes.len())
                    .ok_or(RecordError::Limit)?;
                evidence
                    .push(LineageEvidence::from_bytes(&bytes).map_err(|_| RecordError::Invalid)?);
            }
        }
        if evidence.is_empty() {
            return Err(RecordError::Unavailable);
        }
        Ok(LineageRead(evidence))
    }

    /// Publish original certified evidence using the already-authorized record
    /// writer. This does not acknowledge Keys, select a head or grant membership.
    pub async fn publish(
        &self,
        record: usize,
        subkey: u32,
        sequence: u32,
        evidence: &LineageEvidence,
    ) -> Result<cdht::runtime::Publication, RecordError> {
        let record = self.records.get(record).ok_or(RecordError::Invalid)?;
        let bytes = Zeroizing::new(evidence.to_bytes().map_err(|_| RecordError::Invalid)?);
        let compressed =
            Zeroizing::new(cprz::portable::compress(&bytes).map_err(|_| RecordError::Invalid)?);
        let data = Zeroizing::new(cprz_pad::pad(&compressed));
        if data.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(RecordError::Limit);
        }
        let writer = record.identity().writer.ok_or(RecordError::Invalid)?;
        record
            .republish(
                subkey,
                &Value {
                    seq: sequence,
                    writer,
                    data,
                },
            )
            .await
            .map_err(|_| RecordError::Unavailable)
    }
}
