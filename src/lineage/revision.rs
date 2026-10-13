//! Publication of the next lineage revision of a member's own root-owned record.
//!
//! This is deliberately the whole capability: the caller (the existing device after a
//! pairing approval) holds a value that Keys already signed for the strictly next
//! sequence under a single-use admission. Nothing here signs, derives a key or reaches
//! Keys; the descriptor is fetched from the network and must be the root's own DFLT(1)
//! record. Success means a forced read at the original agreement target returned exactly
//! this signed value; only then may the caller acknowledge the receipt in Keys.
use crate::{RecordError, records::tor::Verifier};
use cdht::{Backend as _, Network, NetworkBackend, QueuedPublication, RecordKey, Schema};

/// Queue, flush and verify `value` on the root-owned lineage record of `root`.
///
/// Repeating the call with the same bytes is safe (exact idempotence in the queue and in
/// the network); a different value for the same sequence is refused as a conflict.
pub async fn publish_lineage_revision<N: Network + Clone>(
    network: N,
    root: &ckmg::PublicKey,
    value: &cdht::SignedValue,
) -> Result<(), RecordError> {
    if value.seq == 0 || value.nonce.is_none() || value.writer != *root.value() {
        return Err(RecordError::Invalid);
    }
    let schema = Schema::dflt(1).map_err(|_| RecordError::Invalid)?;
    let key = RecordKey::derive(root.value(), &schema.compile());
    let records = NetworkBackend::new(network.clone(), Verifier);
    let descriptor = records
        .descriptor(&key)
        .await
        .map_err(|_| RecordError::Unavailable)?
        .ok_or(RecordError::Unavailable)?;
    if descriptor.owner != *root.value()
        || descriptor
            .validate_for(&key, &Verifier)
            .map_err(|_| RecordError::Invalid)?
            != schema
    {
        return Err(RecordError::Invalid);
    }
    let mut client = cdht::Dht::new(records, Verifier);
    if !matches!(
        client
            .queue_original(&descriptor, 0, value)
            .map_err(|_| RecordError::Invalid)?,
        QueuedPublication::Queued
    ) {
        return Err(RecordError::Invalid);
    }
    let report = client.flush().await.map_err(|_| RecordError::Unavailable)?;
    if !report.stale.is_empty() {
        return Err(RecordError::Invalid);
    }
    if report.remaining != 0 {
        return Err(RecordError::Unavailable);
    }
    // A fresh backend: nothing the publication cached may stand in for this read.
    let fresh = NetworkBackend::new(network, Verifier);
    if fresh
        .descriptor(&key)
        .await
        .map_err(|_| RecordError::Unavailable)?
        .as_ref()
        != Some(&descriptor)
    {
        return Err(RecordError::Unavailable);
    }
    let read = fresh
        .read(&key, 0)
        .await
        .map_err(|_| RecordError::Unavailable)?;
    if !read.has_consensus() || read.value.as_ref() != Some(value) {
        return Err(RecordError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdht::{Backend as _, LocalBackend, Signer};
    use ed25519_dalek::{Digest, Sha512, SigningKey};
    use std::{cell::Cell, rc::Rc};

    struct Owner(SigningKey);
    impl Signer for Owner {
        fn public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn sign(&self, data: &[u8]) -> Result<[u8; 64], cdht::Error> {
            let mut digest = Sha512::new();
            digest.update(data);
            self.0
                .sign_prehashed(digest, Some(&b"VLD0_SIGN"[..]))
                .map(|s| s.to_bytes())
                .map_err(|_| cdht::Error::Signer)
        }
    }

    #[derive(Clone)]
    struct Nodes {
        nodes: Rc<Vec<(cdht::NodeId, LocalBackend<Verifier>)>>,
        sets_fail: Rc<Cell<bool>>,
    }
    impl Nodes {
        async fn new(descriptor: Option<&cdht::Descriptor>, first: &cdht::SignedValue) -> Self {
            let mut nodes = Vec::new();
            for index in 0..6u8 {
                let backend = LocalBackend::new(Verifier);
                if let Some(descriptor) = descriptor {
                    backend.create(descriptor).await.unwrap();
                    backend.set(&descriptor.key(), 0, first).await.unwrap();
                }
                nodes.push(([index + 1; 32], backend));
            }
            Self {
                nodes: Rc::new(nodes),
                sets_fail: Rc::new(Cell::new(false)),
            }
        }
        fn node(&self, id: &cdht::NodeId) -> &LocalBackend<Verifier> {
            &self.nodes.iter().find(|(n, _)| n == id).unwrap().1
        }
    }
    impl cdht::Network for Nodes {
        fn now_ms(&self) -> u64 {
            10_000
        }
        async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
            Ok(self.nodes.iter().map(|(id, _)| *id).collect())
        }
        async fn descriptor(
            &self,
            node: &cdht::NodeId,
            key: &cdht::RecordKey,
        ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
            self.node(node).descriptor(key).await
        }
        async fn get(
            &self,
            node: &cdht::NodeId,
            key: &cdht::RecordKey,
            subkey: u32,
        ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
            self.node(node).get(key, subkey).await
        }
        async fn set(
            &self,
            node: &cdht::NodeId,
            descriptor: &cdht::Descriptor,
            subkey: u32,
            value: &cdht::SignedValue,
        ) -> Result<cdht::SetOutcome, cdht::Error> {
            if self.sets_fail.get() {
                return Err(cdht::Error::Unavailable);
            }
            self.node(node).set(&descriptor.key(), subkey, value).await
        }
        async fn watch(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
        ) -> Result<cdht::WatchId, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn cancel_watch(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> Result<(), cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn changes(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> Result<Vec<cdht::Change>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
    }

    fn cipher() -> cdht::EncryptionKey {
        cdht::EncryptionKey::from_bytes([7; 32])
    }

    /// Descriptor, sequence 0 and sequence 1 values the owner signs.
    async fn fixture(next: &[u8]) -> (ckmg::PublicKey, cdht::Descriptor, [cdht::SignedValue; 2]) {
        let owner = Owner(SigningKey::from_bytes(&[5; 32]));
        let schema = cdht::Schema::dflt(1).unwrap();
        let descriptor = cdht::Descriptor::create(&schema, &owner).unwrap();
        let key = descriptor.key();
        let mut values = Vec::new();
        for (seq, data) in [(0, &b"genesis"[..]), (1, next)] {
            let mut signing = cdht::Dht::new(LocalBackend::new(Verifier), Verifier);
            signing.create(&schema, &owner).await.unwrap();
            signing
                .queue_republish(&key, 0, seq, data, &owner, Some(&cipher_ref()))
                .unwrap();
            values.push(signing.state().queue()[0].value.clone());
        }
        let second = values.pop().unwrap();
        let first = values.pop().unwrap();
        (
            ckmg::PublicKey::new(ckmg::VLD0, owner.public_key()),
            descriptor,
            [first, second],
        )
    }

    fn cipher_ref() -> impl cdht::RecordCipher {
        let key = cipher();
        move |nonce: &[u8; 24], input: &[u8]| key.crypt(nonce, input)
    }

    #[test]
    fn the_next_revision_reaches_all_holders_and_a_repeat_is_idempotent() {
        futures::executor::block_on(async {
            let (root, descriptor, [first, second]) = fixture(b"revision two").await;
            let network = Nodes::new(Some(&descriptor), &first).await;
            publish_lineage_revision(network.clone(), &root, &second)
                .await
                .unwrap();
            publish_lineage_revision(network.clone(), &root, &second)
                .await
                .unwrap();
        });
    }

    #[test]
    fn refusals_publish_nothing() {
        futures::executor::block_on(async {
            let (root, descriptor, [first, second]) = fixture(b"revision two").await;
            // Genesis is not a revision.
            let network = Nodes::new(Some(&descriptor), &first).await;
            assert_eq!(
                publish_lineage_revision(network.clone(), &root, &first).await,
                Err(RecordError::Invalid)
            );
            // Another owner's root.
            let other = ckmg::PublicKey::new(ckmg::VLD0, [9; 32]);
            assert_eq!(
                publish_lineage_revision(network.clone(), &other, &second).await,
                Err(RecordError::Invalid)
            );
            // Unreachable writers keep the obligation unfinished.
            network.sets_fail.set(true);
            assert_eq!(
                publish_lineage_revision(network.clone(), &root, &second).await,
                Err(RecordError::Unavailable)
            );
            // No record known to the network.
            let empty = Nodes::new(None, &first).await;
            assert_eq!(
                publish_lineage_revision(empty, &root, &second).await,
                Err(RecordError::Unavailable)
            );
        });
    }
}
