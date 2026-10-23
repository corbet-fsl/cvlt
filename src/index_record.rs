//! The product writer/reader of the wallet membership index over a Tor/loopback record
//! network (`cdht::Network`). The record is a passkey-scoped DFLT(1) record whose owner and
//! read cipher derive from the wallet secret under [`crate::MEMBERSHIP_SCOPE`]
//! (`ckmg::passkey::passkey_record_writer`). Values are the sealed index in the original
//! compressed and padded framing, signed and encrypted by `cdht::Dht`.
//!
//! A publication is a sequence-exact republish: a lost swap returns the authenticated winner
//! and the generic loop in [`crate::add_entry`] merges. The signed queue of this handle is
//! not persisted: the composer asks again after a restart, and an entry already in the record
//! makes that call a confirmed no-op.
use crate::membership_index::{IndexError, IndexRecord, Observed, Outcome};
use cdht::{Dht, NetworkBackend, RecordKey, Schema};

struct Signer<'a>(ckmg::Vld0Signer<'a>);
impl cdht::Signer for Signer<'_> {
    fn public_key(&self) -> cdht::NodeId {
        *self.0.public_key()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], cdht::Error> {
        self.0.sign(bytes).map_err(|_| cdht::Error::Signer)
    }
}

/// One wallet's index record on a record network.
pub struct TorIndexRecord<N: cdht::Network> {
    dht: Dht<NetworkBackend<N, crate::records::tor::Verifier>, crate::records::tor::Verifier>,
    writer: ckmg::passkey::PasskeyRecordWriter,
    schema: Schema,
    key: RecordKey,
}

impl<N: cdht::Network> TorIndexRecord<N> {
    /// Bind the wallet's index record. `writer` comes from
    /// `ckmg::passkey::passkey_record_writer(W, MEMBERSHIP_SCOPE)`.
    pub fn new(network: N, writer: ckmg::passkey::PasskeyRecordWriter) -> Result<Self, IndexError> {
        let schema = Schema::dflt(1).map_err(|_| IndexError::Invalid)?;
        let key = RecordKey::derive(writer.owner().value(), &schema.compile());
        Ok(Self {
            dht: Dht::new(
                NetworkBackend::new(network, crate::records::tor::Verifier),
                crate::records::tor::Verifier,
            ),
            writer,
            schema,
            key,
        })
    }

    /// Decrypt and unframe an authenticated signed value (the current one of the record).
    fn sealed_of(&self, value: &cdht::SignedValue) -> Result<Vec<u8>, IndexError> {
        let plain = self.writer.with_record(|_, cipher| {
            let open = |nonce: &[u8; 24], input: &[u8]| {
                cipher.crypt(nonce, input).map_err(|_| cdht::Error::Decrypt)
            };
            self.dht.open_value(&self.key, 0, value, Some(&open))
        });
        let plain = plain.map_err(|_| IndexError::Invalid)?;
        crate::records::unpack_sealed(&plain).map_err(|_| IndexError::Invalid)
    }
}

impl<N: cdht::Network> IndexRecord for TorIndexRecord<N> {
    /// Only a value that the read target's holders agree on counts (the agreement
    /// `cdht::ReadReport::has_consensus` demands, as the passkey records do): a value from a
    /// single, stale or eclipsing holder set reads as unavailable, never as the index.
    async fn read(&mut self) -> Option<Observed> {
        self.dht.open(&self.key).await.ok()?;
        let report = self.dht.backend().read(&self.key, 0).await.ok()?;
        if !report.has_consensus() {
            return None;
        }
        let value = report.value?;
        // Validates the value and keeps this handle's sequence floor (a lower value refuses).
        self.dht.observe_original(&self.key, 0, &value).ok()?;
        let sealed = self.sealed_of(&value).ok()?;
        Some(Observed {
            sequence: value.seq,
            sealed,
        })
    }

    async fn publish(
        &mut self,
        sequence: u32,
        sealed: &[u8],
    ) -> Result<Outcome, Result<Observed, IndexError>> {
        let packed = crate::records::pack(sealed).map_err(|_| Err(IndexError::Invalid))?;
        let queued = self.writer.with_record(|signer, cipher| {
            let signer = Signer(signer);
            let seal = |nonce: &[u8; 24], input: &[u8]| {
                cipher.crypt(nonce, input).map_err(|_| cdht::Error::Crypto)
            };
            if self.dht.schema(&self.key).is_err() {
                self.dht.queue_create(&self.schema, &signer)?;
            }
            self.dht
                .queue_republish(&self.key, 0, sequence, &packed, &signer, Some(&seal))
        });
        match queued.map_err(|_| Err(IndexError::Unavailable))? {
            cdht::QueuedPublication::Conflict(winner) => {
                return Err(self.sealed_of(&winner).map(|sealed| Observed {
                    sequence: winner.seq,
                    sealed,
                }));
            }
            cdht::QueuedPublication::Queued => {}
        }
        let report = self.dht.flush().await.map_err(|_| Err(IndexError::Unavailable))?;
        if let Some((_, _)) = report.stale.first() {
            // The network held a newer value; the flush cached it as the current one.
            let winner = self
                .dht
                .observed_value(&self.key, 0)
                .map_err(|_| Err(IndexError::Unavailable))?
                .cloned()
                .ok_or(Err(IndexError::Unavailable))?;
            return Err(self.sealed_of(&winner).map(|sealed| Observed {
                sequence: winner.seq,
                sealed,
            }));
        }
        Ok(if report.remaining == 0 {
            Outcome::Confirmed
        } else {
            Outcome::Queued
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership_index::{MembershipEntry, MEMBERSHIP_SCOPE, add_entry, read_index};
    use cdht::Backend;
    use ckmg::passkey::{PrfOutput, passkey_record_writer, store_cipher};
    use std::rc::Rc;

    /// Five validating nodes in process; only the transport is local. `reach` limits the
    /// holders this view of the network contacts (a lone or eclipsed holder set).
    #[derive(Clone)]
    struct Nodes(Rc<Vec<cdht::LocalBackend<crate::records::tor::Verifier>>>, u8);
    impl Nodes {
        fn new() -> Self {
            Self(
                Rc::new(
                    (0..5)
                        .map(|_| cdht::LocalBackend::new(crate::records::tor::Verifier))
                        .collect(),
                ),
                5,
            )
        }
        /// The same nodes, reaching only the first `reach` of them.
        fn reaching(&self, reach: u8) -> Self {
            Self(self.0.clone(), reach)
        }
        fn node(&self, node: &cdht::NodeId) -> Result<&cdht::LocalBackend<crate::records::tor::Verifier>, cdht::Error> {
            self.0.get(usize::from(node[0])).ok_or(cdht::Error::Unavailable)
        }
    }
    impl cdht::Network for Nodes {
        fn now_ms(&self) -> u64 {
            1
        }
        async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
            Ok((0..self.1).map(|index| [index; 32]).collect())
        }
        async fn descriptor(
            &self,
            node: &cdht::NodeId,
            key: &cdht::RecordKey,
        ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
            self.node(node)?.descriptor(key).await
        }
        async fn get(
            &self,
            node: &cdht::NodeId,
            key: &cdht::RecordKey,
            subkey: u32,
        ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
            self.node(node)?.get(key, subkey).await
        }
        async fn set(
            &self,
            node: &cdht::NodeId,
            descriptor: &cdht::Descriptor,
            subkey: u32,
            value: &cdht::SignedValue,
        ) -> Result<cdht::SetOutcome, cdht::Error> {
            let node = self.node(node)?;
            node.create(descriptor).await?;
            node.set(&descriptor.key(), subkey, value).await
        }
        async fn watch(&self, _: &cdht::NodeId, _: &cdht::RecordKey) -> Result<cdht::WatchId, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn changes(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<Vec<cdht::Change>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
    }

    fn handle(network: &Nodes, wallet: u8) -> TorIndexRecord<Nodes> {
        let prf = PrfOutput::from_bytes(&[wallet; 32]).unwrap();
        TorIndexRecord::new(network.clone(), passkey_record_writer(&prf, MEMBERSHIP_SCOPE).unwrap()).unwrap()
    }
    fn cipher(wallet: u8) -> ckmg::passkey::StoreCipher {
        store_cipher(&PrfOutput::from_bytes(&[wallet; 32]).unwrap(), MEMBERSHIP_SCOPE).unwrap()
    }

    #[test]
    fn two_devices_of_one_wallet_share_one_merged_index_on_a_real_record_network() {
        let network = Nodes::new();
        let (c, mut rng) = (cipher(9), ckmg::SystemEntropy);
        futures_executor::block_on(async {
            // Device one registers a community; device two (same wallet, own handle) another.
            let mut one = handle(&network, 9);
            let mut two = handle(&network, 9);
            let first = MembershipEntry::new("garden.example", [1; 32]).unwrap();
            let second = MembershipEntry::new("pond.example", [2; 32]).unwrap();
            assert_eq!(add_entry(&mut one, &c, &mut rng, first.clone()).await, Ok(Outcome::Confirmed));
            // Device two has not read yet: its first read happens inside add_entry.
            assert_eq!(add_entry(&mut two, &c, &mut rng, second.clone()).await, Ok(Outcome::Confirmed));
            // A brand-new device with only the wallet reads both.
            let mut fresh = handle(&network, 9);
            let (_, index) = read_index(&mut fresh, &c).await.unwrap().unwrap();
            assert!(index.contains(&first) && index.contains(&second) && index.len() == 2);
            // Another wallet finds nothing at its own locator.
            let mut other = handle(&network, 10);
            assert!(read_index(&mut other, &cipher(10)).await.unwrap().is_none());
            // A stale handle (never read) publishes blind and merges through the conflict.
            let mut blind = handle(&network, 9);
            let third = MembershipEntry::new("lake.example", [3; 32]).unwrap();
            assert_eq!(add_entry(&mut blind, &c, &mut rng, third.clone()).await, Ok(Outcome::Confirmed));
            let (_, index) = read_index(&mut fresh, &c).await.unwrap().unwrap();
            assert_eq!(index.len(), 3);
        });
    }

    /// X1 M2: a value held by a single node is not the index. Reading it is "unavailable"
    /// (never the index, never absence), and `add_entry` does not report `Confirmed` from it:
    /// it republishes until the agreeing holders list the entry.
    #[test]
    fn a_single_holder_value_neither_reads_nor_confirms() {
        let network = Nodes::new();
        let (c, mut rng) = (cipher(11), ckmg::SystemEntropy);
        futures_executor::block_on(async {
            let entry = MembershipEntry::new("garden.example", [1; 32]).unwrap();
            // A device that reaches only one holder writes the entry there alone.
            let mut lone = handle(&network.reaching(1), 11);
            let _ = add_entry(&mut lone, &c, &mut rng, entry.clone()).await;
            // A device reaching all holders sees no agreement: unavailable, not the index.
            let mut fresh = handle(&network, 11);
            assert!(matches!(read_index(&mut fresh, &c).await, Ok(None)));
            // Adding the same entry republishes it to every holder; the composer asks again
            // while it is only queued, and `Confirmed` comes only with agreeing holders.
            let mut full = handle(&network, 11);
            let mut confirmed = false;
            for _ in 0..3 {
                match add_entry(&mut full, &c, &mut rng, entry.clone()).await {
                    Ok(Outcome::Confirmed) => {
                        confirmed = true;
                        break;
                    }
                    Ok(Outcome::Queued) => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert!(confirmed);
            let report = full.dht.backend().read(&full.key, 0).await.unwrap();
            assert!(report.has_consensus());
            let mut after = handle(&network, 11);
            let (_, index) = read_index(&mut after, &c).await.unwrap().unwrap();
            assert!(index.contains(&entry));
        });
    }
}
