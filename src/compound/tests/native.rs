//! Real maintained Keys, Store and offline native Core. The fixture Authority
//! admits only explicit Create and current Use; it is not production G3 evidence.
use super::*;
use ckmg::{Action, Authority, Authorization, Binding, DeviceInfo, PublicKey};
use cwst::backend::{Backend as _, Memory};
use std::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
    rc::Rc,
    time::Duration,
};
const SCOPE: &str = "checkpoint-fixture";
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(1800000000)
    }
}
#[derive(Default)]
struct Permit {
    device: Option<PublicKey>,
    lineage: Option<ckmg::Lineage>,
    create: bool,
}
struct FixtureAuthority(Rc<RefCell<Permit>>);
impl Authority for FixtureAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), ckmg::Error> {
        let mut permit = self.0.borrow_mut();
        if request.binding != &Binding::new(SCOPE, "fixture-member").unwrap()
            || request.now != 1800000000
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
        {
            return Err(ckmg::Error::Unauthorized);
        }
        match request.action {
            Action::Create
                if request.root.is_none()
                    && request.epoch == 0
                    && request.evidence == b"fixture-create"
                    && permit.lineage.is_none() =>
            {
                if permit.device.is_none() {
                    permit.device = Some(request.device);
                    return Err(ckmg::Error::Unauthorized);
                }
                if permit.create && permit.device == Some(request.device) {
                    permit.create = false;
                    return Ok(());
                }
            }
            Action::Use if request.evidence.is_empty() => {
                if let Some(lineage) = &permit.lineage {
                    if request.root == Some(lineage.root)
                        && request.epoch == lineage.epoch
                        && lineage.devices.contains(&request.device)
                        && permit.device == Some(request.device)
                    {
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
        Err(ckmg::Error::Unauthorized)
    }
}
struct Fault<B> {
    inner: B,
    mode: Rc<Cell<u8>>,
    reached: Rc<tokio::sync::Notify>,
}
impl<B: cdht::runtime::Backend> cdht::runtime::Backend for Fault<B> {
    fn identity(&self) -> cdht::runtime::Identity {
        self.inner.identity()
    }
    async fn get(&self, subkey: u32, refresh: bool) -> Result<Option<Value>, cdht::Error> {
        self.inner.get(subkey, refresh).await
    }
    async fn republish(
        &self,
        subkey: u32,
        sequence: u32,
        data: &[u8],
    ) -> Result<Publication, cdht::Error> {
        if self.mode.get() == 1 {
            self.reached.notify_one();
            std::future::pending::<()>().await;
        }
        let result = self.inner.republish(subkey, sequence, data).await;
        if self.mode.get() == 2 {
            self.reached.notify_one();
            std::future::pending::<()>().await;
        }
        if self.mode.get() == 3 {
            return Err(cdht::Error::Unavailable);
        }
        result
    }
    async fn flush(&self) -> Result<bool, cdht::Error> {
        self.inner.flush().await
    }
    async fn watch(&self) -> Result<bool, cdht::Error> {
        self.inner.watch().await
    }
    async fn cancel_watch(&self) -> Result<bool, cdht::Error> {
        self.inner.cancel_watch().await
    }
    fn changes(&self) -> Result<cdht::runtime::Changes, cdht::Error> {
        self.inner.changes()
    }
}

#[tokio::test]
async fn original_core_chunk_publication_cancellation_conflict_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = cmsh::VeilidConfig::new(
        "checkpoint_test",
        "records",
        "org",
        Some(directory.path().to_str().unwrap()),
        None,
    );
    config.protected_store.always_use_insecure_storage = true;
    config.network.routing_table.bootstrap.clear();
    config.network.routing_table.bootstrap_keys.clear();
    let runtime = cmsh::VeilidRuntime::prepare(
        config,
        cmsh::VeilidLimits {
            queued_messages: NonZeroUsize::new(8).unwrap(),
            listeners: NonZeroUsize::new(2).unwrap(),
            deadline: Duration::from_millis(100),
        },
    )
    .await
    .unwrap();
    let factory = runtime.records(NonZeroUsize::new(12).unwrap()).unwrap();
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, SCOPE).unwrap();
    let backend = Memory::new();
    let store = cwst::Store::create(backend.clone(), &cipher, SCOPE)
        .await
        .unwrap();
    let shared = crate::shared_store(store);
    let mut key_store = crate::KeyStore::new(shared.clone(), SCOPE).unwrap();
    let permit = Rc::new(RefCell::new(Permit::default()));
    let mut keys = ckmg::Keys::new(
        key_store.clone(),
        Clock,
        ckmg::SystemEntropy,
        FixtureAuthority(permit.clone()),
    );
    assert!(
        keys.create_scope(
            &prf,
            Binding::new(SCOPE, "fixture-member").unwrap(),
            DeviceInfo::new("fixture", b"fixture-credential").unwrap(),
            b"fixture-create"
        )
        .await
        .is_err()
    );
    permit.borrow_mut().create = true;
    let armed = key_store
        .stage(crate::Batch {
            expected: 0,
            operation: [71; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    let receipt = keys
        .create_scope(
            &prf,
            Binding::new(SCOPE, "fixture-member").unwrap(),
            DeviceInfo::new("fixture", b"fixture-credential").unwrap(),
            b"fixture-create",
        )
        .await
        .unwrap();
    drop(armed);
    permit.borrow_mut().lineage = Some(receipt.attested_lineage().unwrap().0.clone());
    // This fixture publication is only the in-process Authority's explicit
    // observation of the original receipt, not live G3 or remote replication.
    // Acknowledge it using the original compound transaction before purpose use.
    let armed = key_store
        .stage(crate::Batch {
            expected: 1,
            operation: [74; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    keys.acknowledge(receipt.operation).await.unwrap();
    drop(armed);
    let root = native_checkpoint_record(&mut keys, &factory, SCOPE, None)
        .await
        .unwrap();
    let root_key = root.identity().key;
    let mut children = Vec::new();
    for index in 0..4 {
        children.push(
            native_checkpoint_record(&mut keys, &factory, SCOPE, Some(index))
                .await
                .unwrap(),
        );
    }
    assert!(
        native_checkpoint_record(&mut keys, &factory, SCOPE, Some(MAX_CHECKPOINT_RECORDS))
            .await
            .is_err()
    );
    assert!(
        native_checkpoint_record(&mut keys, &factory, "other", None)
            .await
            .is_err()
    );
    let mut records = CompoundRecords::new(SCOPE, root, children).unwrap();
    assert_eq!(records.publication(), CheckpointPublication::Idle);
    assert!(records.checkpoint().await.is_err()); // Offline never means absent.
    let small = {
        let store = shared.lock().await;
        records.prepare(&store, SCOPE).unwrap()
    };
    assert_eq!(small.manifests.len(), 1);
    assert_eq!(
        records.publish(&small).await.unwrap(),
        CheckpointPublication::Queued
    );
    // Different exact committed bytes at an already-observed sequence must be
    // refused before any part is written, preserving the original manifest.
    let mut competing = cwst::Store::create(Memory::new(), &cipher, SCOPE)
        .await
        .unwrap();
    competing.commit(0, [81; 32], &[], &[]).await.unwrap();
    competing.commit(1, [82; 32], &[], &[]).await.unwrap();
    let competing = records.prepare(&competing, SCOPE).unwrap();
    assert_eq!(competing.sequence, small.sequence);
    assert_eq!(
        records.publish(&competing).await.unwrap_err(),
        CheckpointError::Invalid
    );
    assert_eq!(
        records.root.get(0, false).await.unwrap().unwrap().data,
        small.manifests[0]
    );
    let first = random(400000);
    let second = random(400000);
    {
        let mut store = shared.lock().await;
        store
            .commit(
                2,
                [72; 32],
                &[
                    cwst::Change::Put {
                        owner: "fixture-first",
                        key: b"state",
                        value: &first,
                    },
                    cwst::Change::Put {
                        owner: "fixture-second",
                        key: b"state",
                        value: &second,
                    },
                ],
                &[cwst::Output {
                    id: [73; 32],
                    bytes: b"original-outbox".to_vec(),
                }],
            )
            .await
            .unwrap();
    }
    let prepared = {
        let store = shared.lock().await;
        assert!(records.prepare(&store, "other").is_err());
        records.prepare(&store, SCOPE).unwrap()
    };
    assert!(prepared.manifests.len() > 2);
    assert_eq!(format!("{prepared:?}"), "PreparedCheckpoint([redacted])");
    let (root, children) = records.into_records();
    let mode = Rc::new(Cell::new(1));
    let reached = Rc::new(tokio::sync::Notify::new());
    let wrap = |record: Record<cmsh::VeilidRecord>| {
        Record::new(Fault {
            inner: record.into_backend(),
            mode: mode.clone(),
            reached: reached.clone(),
        })
        .unwrap()
    };
    let mut records =
        CompoundRecords::new(SCOPE, wrap(root), children.into_iter().map(wrap).collect()).unwrap();
    for fault in [1, 2] {
        mode.set(fault);
        {
            let pending = records.publish(&prepared);
            tokio::pin!(pending);
            tokio::select! { _ = reached.notified() => {}, result = &mut pending => panic!("unexpected publication completion: {result:?}") }
        }
        assert_eq!(records.publication(), CheckpointPublication::InProgress);
    }
    mode.set(3);
    assert!(records.publish(&prepared).await.is_err());
    assert_eq!(records.publication(), CheckpointPublication::Partial);
    mode.set(0);
    assert_eq!(
        records.publish(&prepared).await.unwrap(),
        CheckpointPublication::Queued
    );
    assert_eq!(records.publication(), CheckpointPublication::Queued);
    assert!(records.checkpoint().await.is_err());
    let (root, children) = records.into_records();
    root.into_backend().inner.close().await.unwrap();
    for child in children {
        child.into_backend().inner.close().await.unwrap();
    }
    // Reopen exact original owner keys. Offline cached values are inspected only
    // as persistence/codec evidence, never passed off as fresh production lookup.
    let root = native_checkpoint_record(&mut keys, &factory, SCOPE, None)
        .await
        .unwrap();
    assert_eq!(root.identity().key, root_key);
    let root_value = root.get(0, false).await.unwrap().unwrap();
    assert_eq!(root_value.seq, 3);
    let manifest = Manifest::decode(&root_value.data).unwrap();
    assert!(manifest.index);
    let mut packed = Vec::new();
    let mut children = Vec::new();
    for (index, entry) in manifest.entries.iter().enumerate() {
        let child = native_checkpoint_record(&mut keys, &factory, SCOPE, Some(index))
            .await
            .unwrap();
        assert_eq!(child.identity().key.0, entry.target);
        let value = child.get(0, false).await.unwrap().unwrap();
        assert_eq!(digest(&value.data), entry.hash);
        let parts = Manifest::decode(&value.data).unwrap();
        for (part, expected) in parts.entries.iter().enumerate() {
            let value = child.get((part + 1) as u32, false).await.unwrap().unwrap();
            assert_eq!(value.seq, root_value.seq);
            assert_eq!(value.data.len(), expected.length as usize);
            assert_eq!(digest(&value.data), expected.hash);
            packed.extend_from_slice(&value.data);
        }
        children.push(child);
    }
    assert_eq!(digest(&packed), manifest.hash);
    let wire = unpack(&packed).unwrap();
    assert_eq!(wire.as_slice(), backend.read().await.unwrap().unwrap());
    let retained = RetainedCheckpoint {
        scope: scope_digest(SCOPE).unwrap(),
        sequence: root_value.seq,
        wire,
    };
    let restored = retained
        .restore(Memory::new(), &cipher, SCOPE)
        .await
        .unwrap();
    assert_eq!(
        restored.read("fixture-first", b"state").unwrap().unwrap(),
        first
    );
    assert_eq!(
        restored.read("fixture-second", b"state").unwrap().unwrap(),
        second
    );
    assert_eq!(
        restored.load_pending().unwrap()[0].bytes,
        b"original-outbox"
    );
    // A competing original same-owner write at the same sequence is refused.
    assert!(matches!(
        put(&children[0], 1, 3, b"conflicting generation bytes")
            .await
            .unwrap(),
        Publication::Conflict(_)
    ));
    let mut records = CompoundRecords::new(SCOPE, root, children).unwrap();
    assert_eq!(
        records.publish(&small).await.unwrap(),
        CheckpointPublication::Conflict
    );
    assert_eq!(records.publication(), CheckpointPublication::Conflict);
    let (root, children) = records.into_records();
    root.into_backend().close().await.unwrap();
    for child in children {
        child.into_backend().close().await.unwrap();
    }
    keys.lock();
    assert!(
        native_checkpoint_record(&mut keys, &factory, SCOPE, None)
            .await
            .is_err()
    );
    runtime.shutdown().await;
}
