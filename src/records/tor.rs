//! Original passkey root records over the authenticated Tor network capability.
use cdht::{Backend as _, Network, NetworkBackend, RecordKey, Schema, runtime};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

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

// Shared only within one selection attempt. These are actual verified consensus
// observations, not authority and not durable until the enclosing Store CAS.
#[derive(Clone, Default)]
pub(crate) struct ReadObservations {
    values: Rc<RefCell<Vec<ReadObservation>>>,
    fresh: Rc<RefCell<BTreeSet<(RecordKey, u32)>>>,
}
type ReadObservation = (cdht::Descriptor, u32, cdht::SignedValue);
impl ReadObservations {
    fn observe(
        &self,
        descriptor: cdht::Descriptor,
        subkey: u32,
        value: cdht::SignedValue,
    ) -> Result<(), cdht::Error> {
        let mut observations = self.values.borrow_mut();
        let key = descriptor.key();
        if let Some((_, _, previous)) = observations
            .iter_mut()
            .find(|(d, s, _)| d.key() == descriptor.key() && *s == subkey)
        {
            if previous.seq > value.seq
                || (previous.seq == value.seq
                    && (!previous.same_value(&value) || previous.signature != value.signature))
            {
                return Err(cdht::Error::Conflict);
            }
            *previous = value;
        } else {
            observations.push((descriptor, subkey, value));
        }
        self.fresh.borrow_mut().insert((key, subkey));
        Ok(())
    }

    pub(crate) fn retain_state(&self, state: &cdht::ClientState) -> Result<(), cdht::Error> {
        crate::read_floors::validate_state(state).map_err(|_| cdht::Error::Encoding)?;
        self.retain_completed(state)
    }

    pub(crate) fn retain_completed(&self, state: &cdht::ClientState) -> Result<(), cdht::Error> {
        let client =
            cdht::Dht::with_state(cdht::LocalBackend::new(Verifier), Verifier, state.clone());
        if client.state() != state {
            return Err(cdht::Error::Encoding);
        }
        for (descriptor, subkey, value) in client.observations() {
            // The original queue stores a signed obligation separately from the
            // cache. Its exact still-queued bytes alone are planned publication.
            // A different cached higher/equal observation remains a read floor;
            // original remember never overwrites it with the queued obligation.
            if state.queue().iter().any(|queued| {
                queued.key == descriptor.key()
                    && queued.subkey == subkey
                    && queued.value.same_value(value)
                    && queued.value.signature == value.signature
            }) {
                continue;
            }
            let mut observations = self.values.borrow_mut();
            let previous = observations
                .iter_mut()
                .find(|(d, s, _)| d.key() == descriptor.key() && *s == subkey);
            // This state can be discovered inside the just-read remote Store.
            // Already-read overlapping slots must have met its durable floor;
            // importing a higher old value cannot repair a stale selected read.
            // Imported unread states instead merge their highest durable value;
            // import never claims that a network read met this floor.
            if let Some((_, _, previous)) = previous {
                if (previous.seq < value.seq
                    && self.fresh.borrow().contains(&(descriptor.key(), subkey)))
                    || (previous.seq == value.seq
                        && (!previous.same_value(value) || previous.signature != value.signature))
                {
                    return Err(cdht::Error::Conflict);
                }
                if previous.seq < value.seq {
                    *previous = value.clone();
                }
                continue;
            }
            observations.push((descriptor.clone(), subkey, value.clone()));
        }
        Ok(())
    }

    pub(crate) async fn state(
        &self,
        previous: &cdht::ClientState,
    ) -> Result<cdht::ClientState, cdht::Error> {
        let backend = cdht::LocalBackend::new(Verifier);
        let mut client = cdht::Dht::with_state(backend.clone(), Verifier, previous.clone());
        if client.state() != previous || !previous.queue().is_empty() {
            return Err(cdht::Error::Encoding);
        }
        // Clone before the await; no RefCell borrow is held across owner calls.
        let observations = self.values.borrow().clone();
        for (descriptor, subkey, value) in observations {
            backend.create(&descriptor).await?;
            client.open(&descriptor.key()).await?;
            if client
                .observed_value(&descriptor.key(), subkey)?
                .is_some_and(|prior| {
                    prior.seq == value.seq
                        && (!prior.same_value(&value) || prior.signature != value.signature)
                })
            {
                return Err(cdht::Error::Conflict);
            }
            client.observe_original(&descriptor.key(), subkey, &value)?;
        }
        Ok(client.state().clone())
    }
}

// A shared negative read boundary, never an accepting authority capability.
// Installation comes only from a successfully authenticated local Store. Within
// an attempt a different install refuses; restarting constructs a fresh port.
#[derive(Clone, Default)]
pub(crate) struct ReadFloors {
    state: Rc<RefCell<Option<cdht::ClientState>>>,
    observations: ReadObservations,
}
impl ReadFloors {
    pub(crate) fn install(&self, state: &cdht::ClientState) -> Result<(), cdht::Error> {
        crate::read_floors::validate_state(state).map_err(|_| cdht::Error::Encoding)?;
        let mut retained = self.state.borrow_mut();
        if retained.as_ref().is_some_and(|previous| previous != state) {
            return Err(cdht::Error::Conflict);
        }
        *retained = Some(state.clone());
        Ok(())
    }
    fn observe(
        &self,
        identity: &runtime::Identity,
        descriptor: cdht::Descriptor,
        subkey: u32,
        value: &cdht::SignedValue,
    ) -> Result<(), cdht::Error> {
        if let Some(state) = self.state.borrow().as_ref() {
            let client =
                cdht::Dht::with_state(cdht::LocalBackend::new(Verifier), Verifier, state.clone());
            match client.schema(&identity.key) {
                Ok((owner, schema)) => {
                    if owner != identity.owner || schema != identity.schema {
                        return Err(cdht::Error::WrongRecord);
                    }
                    if client
                        .observed_value(&identity.key, subkey)?
                        .is_some_and(|previous| {
                            previous.seq > value.seq
                                || (previous.seq == value.seq
                                    && (!previous.same_value(value)
                                        || previous.signature != value.signature))
                        })
                    {
                        return Err(cdht::Error::Conflict);
                    }
                }
                Err(cdht::Error::NotOpen) => {}
                Err(error) => return Err(error),
            }
        }
        self.observations.observe(descriptor, subkey, value.clone())
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
    observed: RefCell<BTreeMap<u32, cdht::SignedValue>>,
    observations: Option<ReadObservations>,
    floors: Option<ReadFloors>,
}
/// Original per-passkey recovery record, constrained to read-only custody.
pub type TorPasskeyRecord<'unlock, N> = TorReadRecord<'unlock, N>;
/// Original root-owned lineage record, constrained to read-only custody.
pub type TorLineageRecord<'attempt, N> = TorReadRecord<'attempt, N>;

enum Reader<'attempt> {
    Passkey(ckmg::passkey::PasskeyRecordReader<'attempt>),
    Provisional(ckmg::ProvisionalLineage<'attempt>),
    Member(ckmg::LineageReadCustody),
    Initial(ckmg::InitialLineageReader),
    Checkpoint(ckmg::CheckpointRecordCustody<'attempt>),
}
impl Reader<'_> {
    fn owner(&self) -> ckmg::PublicKey {
        match self {
            Self::Passkey(reader) => reader.owner(),
            Self::Provisional(reader) => reader.owner(),
            Self::Member(reader) => reader.owner(),
            Self::Initial(reader) => reader.owner(),
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
            Self::Initial(reader) => reader.open(nonce, ciphertext),
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
            observed: RefCell::new(BTreeMap::new()),
            observations: None,
            floors: None,
        })
    }

    /// Inherit original durable floors and completed signed observations. Queued
    /// values are planned publications, so their bytes cannot fence a different
    /// legitimate winner. No cached value substitutes for fresh consensus below.
    pub(crate) fn with_state_floors(self, state: &cdht::ClientState) -> Result<Self, cdht::Error> {
        let client =
            cdht::Dht::with_state(cdht::LocalBackend::new(Verifier), Verifier, state.clone());
        if client.state() != state {
            return Err(cdht::Error::Encoding);
        }
        match client.schema(&self.identity.key) {
            Ok((owner, schema)) => {
                if owner != self.identity.owner || schema != self.identity.schema {
                    return Err(cdht::Error::WrongRecord);
                }
                for subkey in 0..self.identity.schema.subkey_count() as u32 {
                    if let Some(value) = client.observed_value(&self.identity.key, subkey)? {
                        let mut sequences = self.sequences.borrow_mut();
                        let floor = sequences.entry(subkey).or_insert(value.seq);
                        *floor = (*floor).max(value.seq);
                        drop(sequences);
                        if !state.queue().iter().any(|queued| {
                            queued.key == self.identity.key && queued.subkey == subkey
                        }) {
                            let mut observed = self.observed.borrow_mut();
                            if observed.get(&subkey).is_some_and(|prior| {
                                prior.seq == value.seq
                                    && (!prior.same_value(value)
                                        || prior.signature != value.signature)
                            }) {
                                return Err(cdht::Error::Conflict);
                            }
                            if !observed
                                .get(&subkey)
                                .is_some_and(|prior| prior.seq > value.seq)
                            {
                                observed.insert(subkey, value.clone());
                            }
                        }
                    }
                }
            }
            Err(cdht::Error::NotOpen) => {}
            Err(error) => return Err(error),
        }
        Ok(self)
    }

    pub(crate) fn with_observations(mut self, observations: &ReadObservations) -> Self {
        self.observations = Some(observations.clone());
        self
    }

    pub(crate) fn with_read_floors(mut self, floors: &ReadFloors) -> Self {
        self.floors = Some(floors.clone());
        self
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
            observed: RefCell::new(BTreeMap::new()),
            observations: None,
            floors: None,
        })
    }
}
impl<N: Network> TorReadRecord<'static, N> {
    /// Fixed initial lineage read custody, retained only by the completion
    /// attempt's actual member checker. Reads grant no Keys or acknowledgment.
    pub async fn initial_lineage(
        network: N,
        reader: ckmg::InitialLineageReader,
    ) -> Result<Self, cdht::Error> {
        Self::open_reader(network, Reader::Initial(reader)).await
    }

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
        if self.observed.borrow().get(&subkey).is_some_and(|previous| {
            previous.seq == value.seq
                && (!previous.same_value(&value) || previous.signature != value.signature)
        }) {
            return Err(cdht::Error::Conflict);
        }
        self.sequences.borrow_mut().insert(subkey, value.seq);
        self.observed.borrow_mut().insert(subkey, value.clone());
        if let Some(floors) = &self.floors {
            floors.observe(&self.identity, descriptor.clone(), subkey, &value)?;
        }
        if let Some(observations) = &self.observations {
            observations.observe(descriptor, subkey, value.clone())?;
        }
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
