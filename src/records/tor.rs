//! Original passkey root records over the authenticated Tor network capability.
use cdht::{Backend as _, Network, NetworkBackend, RecordKey, Schema, runtime};
use std::{cell::RefCell, collections::BTreeMap};

pub(crate) struct Verifier;
impl cdht::Verifier for Verifier {
    fn verify(&self, public: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
        ckmg::verify(
            &ckmg::PublicKey::new(ckmg::VLD0, *public),
            data,
            &ckmg::Signature::new(ckmg::VLD0, *signature),
        )
        .is_ok()
    }
}

/// Read-only recovery handle over original signed Tor Records. Its Keys reader
/// borrows the same PreparedOpen, so it cannot survive that custody owner's drop.
/// Every read requires the original three-holder agreement, validates ciphertext
/// before decrypting, and rejects a sequence below this handle's observed floor.
/// This is not current member authority, a writer or a durable publication queue.
pub struct TorReadRecord<'unlock, N: Network> {
    network: NetworkBackend<N, Verifier>,
    reader: Reader<'unlock>,
    identity: runtime::Identity,
    sequences: RefCell<BTreeMap<u32, u32>>,
}
/// Original per-passkey recovery record, constrained to read-only custody.
pub type TorPasskeyRecord<'unlock, N> = TorReadRecord<'unlock, N>;
/// Original root-owned lineage record, constrained to read-only custody.
pub type TorLineageRecord<'attempt, N> = TorReadRecord<'attempt, N>;

enum Reader<'attempt> {
    Passkey(ckmg::passkey::PasskeyRecordReader<'attempt>),
    Provisional(ckmg::ProvisionalLineage<'attempt>),
    Member(ckmg::LineageReadCustody),
    Checkpoint(ckmg::CheckpointRecordCustody<'attempt>),
}
impl Reader<'_> {
    fn owner(&self) -> ckmg::PublicKey {
        match self {
            Self::Passkey(reader) => reader.owner(),
            Self::Provisional(reader) => reader.owner(),
            Self::Member(reader) => reader.owner(),
            Self::Checkpoint(reader) => reader.public_key(),
        }
    }
    fn open(
        &self,
        nonce: &[u8; 24],
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ckmg::Error> {
        match self {
            Self::Passkey(reader) => reader.with_cipher(|cipher| cipher.crypt(nonce, ciphertext)),
            Self::Provisional(reader) => reader.open(nonce, ciphertext),
            Self::Member(reader) => reader.open(nonce, ciphertext),
            Self::Checkpoint(reader) => {
                reader.with_record(|_, cipher| cipher.crypt(nonce, ciphertext))
            }
        }
    }
}
impl<'unlock, N: Network> TorReadRecord<'unlock, N> {
    pub(crate) async fn open(
        network: N,
        reader: ckmg::passkey::PasskeyRecordReader<'unlock>,
    ) -> Result<Self, cdht::Error> {
        Self::open_reader(network, Reader::Passkey(reader)).await
    }

    /// One restore attempt's original root-owned lineage record. Descriptor and
    /// each forced read use the same strict original verification/agreement as
    /// the passkey record. Absence never creates or authorizes anything.
    pub async fn provisional_lineage(
        network: N,
        reader: ckmg::ProvisionalLineage<'unlock>,
    ) -> Result<Self, cdht::Error> {
        Self::open_reader(network, Reader::Provisional(reader)).await
    }

    /// Fixed compound-record reader borrowed from this recovery attempt. Child
    /// descriptors are fetched only when the authenticated manifest selects them;
    /// unused child slots need not exist. This never creates a descriptor or value.
    pub fn checkpoint(
        network: N,
        reader: ckmg::CheckpointRecordCustody<'unlock>,
    ) -> Result<Self, cdht::Error> {
        let owner = *reader.public_key().value();
        let schema = Schema::dflt(crate::CHECKPOINT_SUBKEYS)?;
        let key = RecordKey::derive(&owner, &schema.compile());
        Ok(Self {
            network: NetworkBackend::new(network, Verifier),
            reader: Reader::Checkpoint(reader),
            identity: runtime::Identity {
                key,
                owner,
                schema,
                writer: None,
            },
            sequences: RefCell::new(BTreeMap::new()),
        })
    }

    async fn open_reader(network: N, reader: Reader<'unlock>) -> Result<Self, cdht::Error> {
        let owner = *reader.owner().value();
        let schema = Schema::dflt(1)?;
        let key = RecordKey::derive(&owner, &schema.compile());
        let network = NetworkBackend::new(network, Verifier);
        let descriptor = network
            .descriptor(&key)
            .await?
            .ok_or(cdht::Error::Unavailable)?;
        let observed = descriptor.validate_for(&key, &Verifier)?;
        if descriptor.owner != owner || observed != schema {
            return Err(cdht::Error::WrongRecord);
        }
        Ok(Self {
            network,
            reader,
            identity: runtime::Identity {
                key,
                owner,
                schema,
                writer: None,
            },
            sequences: RefCell::new(BTreeMap::new()),
        })
    }
}
impl<N: Network> TorReadRecord<'static, N> {
    /// Member-owned read custody after full recovery authorization. Retain this
    /// in the same member owner and drop it on lock; every Use still reads anew.
    pub async fn member_lineage(
        network: N,
        reader: ckmg::LineageReadCustody,
    ) -> Result<Self, cdht::Error> {
        Self::open_reader(network, Reader::Member(reader)).await
    }
}
impl<N: Network> runtime::Backend for TorReadRecord<'_, N> {
    fn identity(&self) -> runtime::Identity {
        self.identity.clone()
    }
    async fn get(
        &self,
        subkey: u32,
        _refresh: bool,
    ) -> Result<Option<runtime::Value>, cdht::Error> {
        if subkey as usize >= self.identity.schema.subkey_count() {
            return Err(cdht::Error::SubkeyOutOfRange);
        }
        let descriptor = self
            .network
            .descriptor(&self.identity.key)
            .await?
            .ok_or(cdht::Error::Unavailable)?;
        let schema = descriptor.validate_for(&self.identity.key, &Verifier)?;
        if descriptor.owner != self.identity.owner || schema != self.identity.schema {
            return Err(cdht::Error::WrongRecord);
        }
        // ReadReport retains the original replica agreement. The generic raw
        // Backend::get returns partial observations and cannot establish this.
        let report = self.network.read(&self.identity.key, subkey).await?;
        if !report.has_consensus() {
            return Err(cdht::Error::Unavailable);
        }
        let value = report.value.ok_or(cdht::Error::Unavailable)?;
        value.validate(
            &self.identity.key,
            &self.identity.owner,
            &self.identity.schema,
            subkey,
            &Verifier,
        )?;
        if self
            .sequences
            .borrow()
            .get(&subkey)
            .is_some_and(|floor| value.seq < *floor)
        {
            return Err(cdht::Error::Conflict);
        }
        self.sequences.borrow_mut().insert(subkey, value.seq);
        let nonce = value.nonce.ok_or(cdht::Error::Decrypt)?;
        let data = self
            .reader
            .open(&nonce, &value.data)
            .map_err(|_| cdht::Error::Decrypt)?;
        Ok(Some(runtime::Value {
            seq: value.seq,
            writer: value.writer,
            data,
        }))
    }
    async fn republish(
        &self,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> Result<runtime::Publication, cdht::Error> {
        Err(cdht::Error::WrongWriter)
    }
    async fn flush(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::WrongWriter)
    }
    async fn watch(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::WatchRefused)
    }
    async fn cancel_watch(&self) -> Result<bool, cdht::Error> {
        Ok(false)
    }
    fn changes(&self) -> Result<runtime::Changes, cdht::Error> {
        Ok(runtime::Changes {
            ranges: Vec::new(),
            lost: false,
        })
    }
}
