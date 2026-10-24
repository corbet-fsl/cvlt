//! The wallet membership index (DESIGN-one-confirmation rule 5, STATUS 2026-10-15
//! "restore through a wallet membership index").
//!
//! With only the synced wallet passkey a new device derives the wallet secret `W` but
//! learns no community fingerprint, so it cannot derive any community unlock secret. The
//! index closes that gap: ONE wallet-scope record lists `(address, founding fingerprint)`
//! per membership.
//!
//! * Locator, record owner and read capability derive from `W` under the scope
//!   [`MEMBERSHIP_SCOPE`], never from a community: no community sees the record, and the
//!   record reveals no community to anyone without `W`.
//! * The payload is sealed under a storage cipher derived from `W` and the same scope (an
//!   independent HKDF label from custody encryption, see `ckmg::passkey::store_cipher`).
//! * The plaintext is zero-padded to a fixed size bucket, so the sealed size reveals only
//!   the bucket, never the number of memberships.
//! * Concurrent devices never overwrite one another: a publication is a compare-and-swap
//!   on the record sequence; a lost swap re-reads the winner, MERGES (set union) and swaps
//!   again. An entry is never removed here; an ended community answers its own refusal at
//!   restore and is shown as ended.
//! * The composer writes an entry and waits for [`Outcome::Confirmed`] BEFORE the
//!   community's first join or creation claim, so no membership exists that the index lacks.
//!
//! Like every record read, an unavailable record is not known absence: the loop treats a
//! failed read as "unknown", publishes sequence 1, and learns about an existing record from
//! the conflict it returns.
use crate::{PasskeyRecords, RecordError};
use cdht::runtime::{Backend, Publication};
use ckmg::{Entropy, Locator, passkey::StoreCipher};
use std::collections::BTreeSet;

/// The wallet-scope name that locates the index (`ckmg::passkey::vault_location(W, ..)`).
pub const MEMBERSHIP_SCOPE: &str = "wallet.memberships";
const CONTEXT: &[u8] = b"cvlt.membership-index.v1";
const VERSION: u8 = 1;
/// Plaintext bucket sizes; the smallest that fits is used. The largest sealed bucket plus
/// framing stays below one record subkey after padding.
const BUCKETS: [usize; 4] = [1024, 4096, 16384, 24576];
const MAX_ADDRESS_BYTES: usize = 256;
/// Bounded merge rounds against concurrent devices before the caller retries later.
const MAX_ROUNDS: usize = 8;

/// Coarse failure of the index. No address, fingerprint or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexError {
    /// Framing, padding or bound violation, or a payload that does not open.
    Invalid,
    /// More memberships than the largest bucket holds.
    Full,
    /// The record could not be read or published.
    Unavailable,
}
impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Membership index refused")
    }
}
impl std::error::Error for IndexError {}

/// One membership: where the community lives and WHICH community it is. The fingerprint is
/// the identity (an address can be taken again after a community ends).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MembershipEntry {
    address: String,
    fingerprint: [u8; 32],
}
impl MembershipEntry {
    /// An entry; the address is 1..=256 bytes without control characters.
    pub fn new(address: &str, fingerprint: [u8; 32]) -> Result<Self, IndexError> {
        if address.is_empty()
            || address.len() > MAX_ADDRESS_BYTES
            || address.chars().any(char::is_control)
        {
            return Err(IndexError::Invalid);
        }
        Ok(Self {
            address: address.to_owned(),
            fingerprint,
        })
    }
    /// The community address (the vault's Store scope).
    pub fn address(&self) -> &str {
        &self.address
    }
    /// The founding-key fingerprint (the input of the community unlock secret).
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// The set of memberships of one wallet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MembershipIndex(BTreeSet<MembershipEntry>);

impl MembershipIndex {
    /// The empty index.
    pub fn new() -> Self {
        Self::default()
    }
    /// Add an entry; true when it was new.
    pub fn insert(&mut self, entry: MembershipEntry) -> bool {
        self.0.insert(entry)
    }
    /// Set union (the merge of two devices' views).
    pub fn merge(&mut self, other: &Self) {
        self.0.extend(other.0.iter().cloned());
    }
    /// Whether `entry` is listed.
    pub fn contains(&self, entry: &MembershipEntry) -> bool {
        self.0.contains(entry)
    }
    /// The entries in canonical (sorted) order.
    pub fn entries(&self) -> impl Iterator<Item = &MembershipEntry> {
        self.0.iter()
    }
    /// Number of memberships.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// No membership listed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Canonical bytes: version, count, sorted entries, zero padding to a bucket.
    fn encode(&self) -> Result<Vec<u8>, IndexError> {
        let mut out = vec![VERSION];
        out.extend_from_slice(
            &u16::try_from(self.0.len())
                .map_err(|_| IndexError::Full)?
                .to_le_bytes(),
        );
        for entry in &self.0 {
            out.extend_from_slice(&(entry.address.len() as u16).to_le_bytes());
            out.extend_from_slice(entry.address.as_bytes());
            out.extend_from_slice(&entry.fingerprint);
        }
        let bucket = BUCKETS
            .iter()
            .copied()
            .find(|bucket| out.len() <= *bucket)
            .ok_or(IndexError::Full)?;
        out.resize(bucket, 0);
        Ok(out)
    }

    /// Strict decoding: exact bucket size, sorted unique entries, all padding zero.
    fn decode(bytes: &[u8]) -> Result<Self, IndexError> {
        if !BUCKETS.contains(&bytes.len()) || bytes[0] != VERSION {
            return Err(IndexError::Invalid);
        }
        let count = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
        let mut at = 3;
        let mut index = Self::new();
        let mut previous: Option<MembershipEntry> = None;
        for _ in 0..count {
            let length = usize::from(u16::from_le_bytes(
                bytes
                    .get(at..at + 2)
                    .ok_or(IndexError::Invalid)?
                    .try_into()
                    .map_err(|_| IndexError::Invalid)?,
            ));
            at += 2;
            let address =
                std::str::from_utf8(bytes.get(at..at + length).ok_or(IndexError::Invalid)?)
                    .map_err(|_| IndexError::Invalid)?;
            at += length;
            let fingerprint: [u8; 32] = bytes
                .get(at..at + 32)
                .ok_or(IndexError::Invalid)?
                .try_into()
                .map_err(|_| IndexError::Invalid)?;
            at += 32;
            let entry = MembershipEntry::new(address, fingerprint)?;
            if previous.as_ref().is_some_and(|before| *before >= entry) {
                return Err(IndexError::Invalid);
            }
            previous = Some(entry.clone());
            index.0.insert(entry);
        }
        if bytes[at..].iter().any(|byte| *byte != 0) {
            return Err(IndexError::Invalid);
        }
        Ok(index)
    }

    /// Seal under the wallet-derived cipher of [`MEMBERSHIP_SCOPE`].
    pub fn seal(
        &self,
        cipher: &StoreCipher,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<u8>, IndexError> {
        cipher
            .seal(entropy, CONTEXT, &self.encode()?)
            .map_err(|_| IndexError::Invalid)
    }

    /// Open a sealed payload; a payload under another wallet's cipher does not open.
    pub fn open(cipher: &StoreCipher, sealed: &[u8]) -> Result<Self, IndexError> {
        let plain = cipher
            .open(CONTEXT, sealed)
            .map_err(|_| IndexError::Invalid)?;
        Self::decode(&plain)
    }
}

/// How far a publication got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The record network replicated it: the composer may proceed to the join.
    Confirmed,
    /// Accepted into the durable outbox only; the composer must wait and ask again (an
    /// entry already in the record makes the next call a confirmed no-op).
    Queued,
}

/// A read of the winning/current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// Record sequence of the value.
    pub sequence: u32,
    /// The sealed payload.
    pub sealed: Vec<u8>,
}

/// What the loop needs from a record. [`PasskeyRecords`] is the product implementation.
pub trait IndexRecord {
    /// Forced read of a value the record's holders agree on; `None` when unavailable or
    /// without that agreement (never "absent").
    fn read(&mut self) -> impl std::future::Future<Output = Option<Observed>>;
    /// Publish `sealed` at `sequence`. `Err(winner)` is a lost swap with the winning value.
    fn publish(
        &mut self,
        sequence: u32,
        sealed: &[u8],
    ) -> impl std::future::Future<Output = Result<Outcome, Result<Observed, IndexError>>>;
}

/// The product record: the index record of one wallet at `locator`.
pub struct WalletIndexRecord<'a, B: Backend> {
    records: &'a mut PasskeyRecords<B>,
    locator: Locator,
}
impl<'a, B: Backend> WalletIndexRecord<'a, B> {
    /// Bind the records handle opened for [`MEMBERSHIP_SCOPE`] and its locator.
    pub fn new(records: &'a mut PasskeyRecords<B>, locator: Locator) -> Self {
        Self { records, locator }
    }
}
impl<B: Backend> IndexRecord for WalletIndexRecord<'_, B> {
    async fn read(&mut self) -> Option<Observed> {
        let checkpoint = self.records.checkpoint(&self.locator).await.ok()?;
        Some(Observed {
            sequence: checkpoint.sequence(),
            sealed: checkpoint.sealed().to_vec(),
        })
    }
    async fn publish(
        &mut self,
        sequence: u32,
        sealed: &[u8],
    ) -> Result<Outcome, Result<Observed, IndexError>> {
        match self.records.publish(sequence, sealed).await {
            Ok(Publication::Replicated) => Ok(Outcome::Confirmed),
            Ok(Publication::Queued) => Ok(Outcome::Queued),
            Ok(Publication::Conflict(value)) => Err(crate::records::unpack_sealed(&value.data)
                .map(|sealed| Observed {
                    sequence: value.seq,
                    sealed,
                })
                .map_err(|_: RecordError| IndexError::Invalid)),
            Err(_) => Err(Err(IndexError::Unavailable)),
        }
    }
}

/// Read the index. `Ok(None)`: the record is unavailable (NOT proof that none exists).
pub async fn read_index(
    record: &mut impl IndexRecord,
    cipher: &StoreCipher,
) -> Result<Option<(u32, MembershipIndex)>, IndexError> {
    match record.read().await {
        None => Ok(None),
        Some(seen) => Ok(Some((
            seen.sequence,
            MembershipIndex::open(cipher, &seen.sealed)?,
        ))),
    }
}

/// Add `entry` to the wallet's index by compare-and-swap with merging, never overwriting
/// another device's entries. Returns [`Outcome::Confirmed`] only when the final value is
/// replicated; a queued publication returns [`Outcome::Queued`] and the caller asks again.
pub async fn add_entry(
    record: &mut impl IndexRecord,
    cipher: &StoreCipher,
    entropy: &mut impl Entropy,
    entry: MembershipEntry,
) -> Result<Outcome, IndexError> {
    let mut known = read_index(record, cipher).await?;
    if known
        .as_ref()
        .is_some_and(|(_, index)| index.contains(&entry))
    {
        // A forced authenticated read already shows it: replicated state, nothing to add.
        return Ok(Outcome::Confirmed);
    }
    for _ in 0..MAX_ROUNDS {
        let (base, mut index) = match known.take() {
            Some((sequence, index)) => (sequence, index),
            None => (0, MembershipIndex::new()),
        };
        index.insert(entry.clone());
        let sealed = index.seal(cipher, entropy)?;
        match record
            .publish(base.checked_add(1).ok_or(IndexError::Full)?, &sealed)
            .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(Err(error)) => return Err(error),
            Err(Ok(winner)) => {
                // Lost the swap: merge the winner (it may hold other devices' entries).
                let theirs = MembershipIndex::open(cipher, &winner.sealed)?;
                // A lost swap's winner is one holder's answer, not replication: it confirms
                // only when an agreeing read lists the entry. Otherwise the loop republishes
                // the winner (with the entry) one sequence higher, so every holder gets it.
                if theirs.contains(&entry)
                    && read_index(record, cipher)
                        .await?
                        .is_some_and(|(_, index)| index.contains(&entry))
                {
                    return Ok(Outcome::Confirmed);
                }
                let mut merged = theirs;
                merged.insert(entry.clone());
                known = Some((winner.sequence, merged));
            }
        }
    }
    Err(IndexError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckmg::passkey::{PrfOutput, store_cipher};

    fn cipher(seed: u8) -> StoreCipher {
        store_cipher(
            &PrfOutput::from_bytes(&[seed; 32]).unwrap(),
            MEMBERSHIP_SCOPE,
        )
        .unwrap()
    }
    fn entry(name: &str, byte: u8) -> MembershipEntry {
        MembershipEntry::new(name, [byte; 32]).unwrap()
    }

    #[test]
    fn roundtrip_pads_to_a_bucket_and_hides_the_count() {
        let mut one = MembershipIndex::new();
        one.insert(entry("garden.example", 1));
        let mut ten = MembershipIndex::new();
        for byte in 0..10 {
            ten.insert(entry(&format!("c{byte}.example"), byte));
        }
        let (a, b) = (
            one.seal(&cipher(7), &mut ckmg::SystemEntropy).unwrap(),
            ten.seal(&cipher(7), &mut ckmg::SystemEntropy).unwrap(),
        );
        assert_eq!(a.len(), b.len(), "sealed size must not reveal the count");
        assert_eq!(MembershipIndex::open(&cipher(7), &a).unwrap(), one);
        assert_eq!(MembershipIndex::open(&cipher(7), &b).unwrap(), ten);
        // Another wallet opens nothing.
        assert!(MembershipIndex::open(&cipher(8), &a).is_err());
    }

    #[test]
    fn buckets_grow_and_the_largest_overflows() {
        let mut index = MembershipIndex::new();
        for n in 0..40u8 {
            index.insert(MembershipEntry::new(&format!("{n:0>200}"), [n; 32]).unwrap());
        }
        let sealed = index.seal(&cipher(1), &mut ckmg::SystemEntropy).unwrap();
        assert!(sealed.len() > 4096);
        assert_eq!(MembershipIndex::open(&cipher(1), &sealed).unwrap(), index);
        let mut huge = MembershipIndex::new();
        for n in 0..=255u8 {
            for m in 0..2u8 {
                huge.insert(MembershipEntry::new(&format!("{n:0>200}{m}"), [n; 32]).unwrap());
            }
        }
        assert_eq!(
            huge.seal(&cipher(1), &mut ckmg::SystemEntropy).unwrap_err(),
            IndexError::Full
        );
    }

    #[test]
    fn decoding_is_strict() {
        let mut index = MembershipIndex::new();
        index.insert(entry("a.example", 1));
        index.insert(entry("b.example", 2));
        let mut bytes = index.encode().unwrap();
        assert_eq!(MembershipIndex::decode(&bytes).unwrap(), index);
        let mut dirty = bytes.clone();
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(
            MembershipIndex::decode(&dirty).unwrap_err(),
            IndexError::Invalid
        );
        assert!(MembershipIndex::decode(&bytes[..100]).is_err());
        bytes[0] = 2;
        assert!(MembershipIndex::decode(&bytes).is_err());
        // Unsorted or duplicate entries are refused.
        let mut forged = vec![VERSION, 2, 0];
        for name in ["b", "a"] {
            forged.extend_from_slice(&1u16.to_le_bytes());
            forged.extend_from_slice(name.as_bytes());
            forged.extend_from_slice(&[0; 32]);
        }
        forged.resize(BUCKETS[0], 0);
        assert!(MembershipIndex::decode(&forged).is_err());
        assert!(MembershipEntry::new("", [0; 32]).is_err());
        assert!(MembershipEntry::new("bad\naddress", [0; 32]).is_err());
    }

    /// An in-memory record with real compare-and-swap semantics on the sequence.
    struct Memory {
        value: Option<(u32, Vec<u8>)>,
        readable: bool,
        replicate: bool,
        /// Another device's write that lands right after our read (before our publish).
        intruder: Option<Vec<u8>>,
    }
    impl IndexRecord for Memory {
        async fn read(&mut self) -> Option<Observed> {
            self.readable
                .then(|| self.value.clone())
                .flatten()
                .map(|(sequence, sealed)| Observed { sequence, sealed })
        }
        async fn publish(
            &mut self,
            sequence: u32,
            sealed: &[u8],
        ) -> Result<Outcome, Result<Observed, IndexError>> {
            if let Some(sealed) = self.intruder.take() {
                let next = self.value.as_ref().map_or(1, |(seq, _)| seq + 1);
                self.value = Some((next, sealed));
            }
            if let Some((current, winner)) = &self.value {
                if sequence <= *current {
                    return Err(Ok(Observed {
                        sequence: *current,
                        sealed: winner.clone(),
                    }));
                }
            }
            self.value = Some((sequence, sealed.to_vec()));
            Ok(if self.replicate {
                Outcome::Confirmed
            } else {
                Outcome::Queued
            })
        }
    }
    fn memory() -> Memory {
        Memory {
            value: None,
            readable: true,
            replicate: true,
            intruder: None,
        }
    }

    #[test]
    fn first_entry_confirms_and_a_second_device_merges() {
        let (c, mut rng) = (cipher(3), ckmg::SystemEntropy);
        let mut record = memory();
        let one =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(one, Ok(Outcome::Confirmed));
        let two =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("b.example", 2)));
        assert_eq!(two, Ok(Outcome::Confirmed));
        let (sequence, index) = futures_executor::block_on(read_index(&mut record, &c))
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(index.len(), 2);
        // Adding a known entry changes nothing the caller needs: still confirmed.
        let again =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(again, Ok(Outcome::Confirmed));
    }

    #[test]
    fn a_concurrent_device_is_merged_never_overwritten() {
        let (c, mut rng) = (cipher(4), ckmg::SystemEntropy);
        let mut record = memory();
        futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)))
            .unwrap();
        let mut theirs = MembershipIndex::new();
        theirs.insert(entry("a.example", 1));
        theirs.insert(entry("z.example", 9));
        record.intruder = Some(theirs.seal(&c, &mut rng).unwrap());
        let out =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("b.example", 2)));
        assert_eq!(out, Ok(Outcome::Confirmed));
        let (_, index) = futures_executor::block_on(read_index(&mut record, &c))
            .unwrap()
            .unwrap();
        assert!(index.contains(&entry("a.example", 1)));
        assert!(index.contains(&entry("b.example", 2)));
        assert!(index.contains(&entry("z.example", 9)));
    }

    #[test]
    fn an_unreadable_record_is_unknown_not_empty() {
        let (c, mut rng) = (cipher(5), ckmg::SystemEntropy);
        // The record exists (sequence 4) but the read fails: our sequence-1 publication loses,
        // the conflict returns the winner and the entry joins it.
        let mut existing = MembershipIndex::new();
        existing.insert(entry("old.example", 7));
        let mut record = Memory {
            value: Some((4, existing.seal(&c, &mut rng).unwrap())),
            readable: false,
            replicate: true,
            intruder: None,
        };
        let out = futures_executor::block_on(add_entry(
            &mut record,
            &c,
            &mut rng,
            entry("new.example", 8),
        ));
        assert_eq!(out, Ok(Outcome::Confirmed));
        record.readable = true;
        let (sequence, index) = futures_executor::block_on(read_index(&mut record, &c))
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 5);
        assert!(
            index.contains(&entry("old.example", 7)) && index.contains(&entry("new.example", 8))
        );
    }

    /// X1 M2: a lost swap's winner that already lists the entry is one holder's answer. It
    /// confirms only through an agreeing read; without one the winner is republished one
    /// sequence higher (entry included), so the confirmation rests on the new replication.
    #[test]
    fn a_winner_without_an_agreeing_read_is_republished_not_confirmed() {
        let (c, mut rng) = (cipher(7), ckmg::SystemEntropy);
        let mut existing = MembershipIndex::new();
        existing.insert(entry("a.example", 1));
        let mut record = Memory {
            value: Some((4, existing.seal(&c, &mut rng).unwrap())),
            readable: false,
            replicate: true,
            intruder: None,
        };
        let out =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(out, Ok(Outcome::Confirmed));
        assert_eq!(
            record.value.as_ref().map(|(sequence, _)| *sequence),
            Some(5)
        );
        // Without replication the republish is only queued: never Confirmed.
        record.readable = false;
        record.replicate = false;
        let out =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(out, Ok(Outcome::Queued));
        // An agreeing read that lists it confirms without any write.
        record.readable = true;
        let out =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(out, Ok(Outcome::Confirmed));
        assert_eq!(
            record.value.as_ref().map(|(sequence, _)| *sequence),
            Some(6)
        );
    }

    #[test]
    fn a_queued_publication_is_not_a_confirmation() {
        let (c, mut rng) = (cipher(6), ckmg::SystemEntropy);
        let mut record = memory();
        record.replicate = false;
        let out =
            futures_executor::block_on(add_entry(&mut record, &c, &mut rng, entry("a.example", 1)));
        assert_eq!(out, Ok(Outcome::Queued));
    }
}
