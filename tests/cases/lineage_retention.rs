//! Original native FileBackend faults only; no simulated evidence or accepting Authority.
use super::*;
use cvlt::{EvidenceError, LineageEvidence, PreparedLineageEvidence};
use cwst::backend::Backend;
use futures::FutureExt;

struct Deny;
impl Authority for Deny {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}
struct NoRecords;
impl cvlt::Records for NoRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
type TestVault<B> = cvlt::Vault<B, Clock, ckmg::SystemEntropy, Deny, NoRecords, ()>;

async fn vault<B: Backend>(fixture: &Fixture, backend: B) -> TestVault<B> {
    let cipher = ckmg::passkey::store_cipher(&fixture.prf, SCOPE).unwrap();
    let store = cwst::Store::open(backend, &cipher, SCOPE).await.unwrap();
    let mut vault = cvlt::Vault::new(
        store,
        SCOPE,
        Clock,
        ckmg::SystemEntropy,
        Deny,
        NoRecords,
        (),
    )
    .unwrap();
    // Opening local bytes does not satisfy the original live lineage check.
    vault.keys().unlock(&fixture.prf, SCOPE).await.unwrap();
    assert_eq!(
        vault.keys().pending_output().await.unwrap().unwrap(),
        fixture.receipt
    );
    vault
}
fn prepared(
    fixture: &Fixture,
    charter: &mut cchr::Charter,
    signed: &[u8],
) -> PreparedLineageEvidence {
    LineageEvidence::prepare(
        charter.current(NOW).unwrap(),
        &fixture.receipt,
        &fixture.assertion,
        signed,
        MEMBER,
        NOW,
    )
    .unwrap()
}

#[derive(Clone)]
struct Faults {
    original: cwst::native::FileBackend,
    mode: Rc<Cell<u8>>,
    writes: Rc<Cell<u32>>,
}
impl Faults {
    fn new(fixture: &Fixture, mode: u8) -> Self {
        Self {
            original: fixture.backend.clone(),
            mode: Rc::new(Cell::new(mode)),
            writes: Rc::new(Cell::new(0)),
        }
    }
}
impl Backend for Faults {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.original.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.writes.set(self.writes.get() + 1);
        if self.mode.get() == 1 {
            futures::future::pending::<()>().await;
        }
        self.original.compare_exchange(expected, next).await?;
        if self.mode.get() == 2 {
            return Err(cwst::Error::Uncertain);
        }
        if self.mode.get() == 3 {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
}

#[test]
fn retention_is_local_atomic_and_reverified_after_reopen_without_keys_acknowledgement() {
    let fixture = fixture();
    let mut signer = signer();
    let mut policy = charter(SCOPE, &mut signer, &[], &[], true);
    let signed = binding(&mut signer, &fixture.descriptor, MEMBER, 1);
    let prepared = prepared(&fixture, &mut policy, &signed);
    futures_executor::block_on(async {
        let mut vault = vault(&fixture, fixture.backend.clone()).await;
        let locator = ckmg::passkey::vault_location(&fixture.prf, SCOPE).unwrap();
        let output = cwst::Output {
            id: [80; 32],
            bytes: serde_json::to_vec(&fixture.receipt).unwrap(),
        };
        vault
            .storage()
            .lock()
            .await
            .commit(1, [80; 32], &[], std::slice::from_ref(&output))
            .await
            .unwrap();
        let before = vault
            .storage()
            .lock()
            .await
            .read("keys", locator.as_bytes())
            .unwrap()
            .unwrap()
            .to_vec();
        assert!(
            LineageEvidence::load(
                &*vault.storage().lock().await,
                prepared.evidence().operation()
            )
            .unwrap()
            .is_none()
        );
        let committed = vault
            .retain_lineage_evidence(&prepared, [81; 32])
            .await
            .unwrap();
        let store = vault.storage().lock().await;
        assert!(committed.is_commit(&store, &[81; 32]));
        assert_eq!(committed.version(), 3);
        assert_eq!(store.load_pending().unwrap().len(), 1);
        assert_eq!(store.load_pending().unwrap()[0].id, output.id);
        assert_eq!(store.load_pending().unwrap()[0].bytes, output.bytes);
        assert!(committed.contains_output(&output.id, blake3::hash(&output.bytes).as_bytes()));
        assert_eq!(
            store.read("keys", locator.as_bytes()).unwrap().unwrap(),
            before
        );
        for (owner, bytes) in [
            (
                "lineage-receipt",
                serde_json::to_vec(&fixture.receipt).unwrap(),
            ),
            (
                "lineage-assertion",
                serde_json::to_vec(&fixture.assertion).unwrap(),
            ),
            ("lineage-binding", signed.clone()),
        ] {
            assert!(committed.contains_record(
                owner,
                fixture.receipt.operation.as_bytes(),
                blake3::hash(&bytes).as_bytes()
            ));
        }
        drop(store);
        assert_eq!(
            vault.keys().pending_output().await.unwrap().unwrap(),
            fixture.receipt
        );
        // Lose the reply and all open owners; the actual file retains all three
        // public values and the unchanged pending Keys receipt.
        drop(committed);
        drop(vault);
        let mut reopened = self::vault(&fixture, fixture.backend.clone()).await;
        let store = reopened.storage().lock().await;
        let retained = LineageEvidence::load(&store, fixture.receipt.operation.as_bytes())
            .unwrap()
            .unwrap();
        assert!(
            store
                .receipt(&[81; 32])
                .unwrap()
                .is_commit(&store, &[81; 32])
        );
        assert_eq!(
            retained
                .verify(policy.current(NOW).unwrap(), MEMBER, NOW)
                .unwrap()
                .lineage(NOW)
                .unwrap(),
            fixture.receipt.attested_lineage().unwrap().0
        );
        assert!(
            retained
                .verify(policy.current(NOW + 100).unwrap(), MEMBER, NOW + 100)
                .is_err()
        );
        let mut revoked = charter(SCOPE, &mut signer, &fixture.revoked, &[], true);
        assert!(
            retained
                .verify(revoked.current(NOW).unwrap(), MEMBER, NOW)
                .is_err()
        );
        drop(store);
        // Retention did not fabricate live custody permission.
        assert_eq!(
            reopened.keys().lineage().await.unwrap_err(),
            Error::Unauthorized
        );
    });
}

#[test]
fn cancellation_and_lost_write_reply_require_reopen_and_preserve_actual_outcome() {
    for mode in [1, 2, 3] {
        let fixture = fixture();
        let mut signer = signer();
        let mut policy = charter(SCOPE, &mut signer, &[], &[], true);
        let signed = binding(&mut signer, &fixture.descriptor, MEMBER, 1);
        let prepared = prepared(&fixture, &mut policy, &signed);
        futures_executor::block_on(async {
            let faults = Faults::new(&fixture, mode);
            let mut vault = vault(&fixture, faults.clone()).await;
            if mode == 2 {
                assert!(matches!(
                    vault.retain_lineage_evidence(&prepared, [82; 32]).await,
                    Err(EvidenceError::Storage(cwst::Error::Uncertain))
                ));
            } else {
                assert!(
                    vault
                        .retain_lineage_evidence(&prepared, [82; 32])
                        .now_or_never()
                        .is_none()
                );
            }
            assert_eq!(faults.writes.get(), 1);
            assert_eq!(
                vault.storage().lock().await.version().unwrap_err(),
                cwst::Error::Locked
            );
            assert_eq!(
                vault.keys().pending_output().await.unwrap_err(),
                Error::Locked
            );
            drop(vault);
            let mut reopened = self::vault(&fixture, fixture.backend.clone()).await;
            let store = reopened.storage().lock().await;
            let retained =
                LineageEvidence::load(&store, fixture.receipt.operation.as_bytes()).unwrap();
            assert_eq!(retained.is_some(), mode != 1);
            assert_eq!(store.version().unwrap(), if mode == 1 { 1 } else { 2 });
            if let Some(retained) = retained {
                assert!(
                    store
                        .receipt(&[82; 32])
                        .unwrap()
                        .is_commit(&store, &[82; 32])
                );
                retained
                    .verify(policy.current(NOW).unwrap(), MEMBER, NOW)
                    .unwrap();
            }
            drop(store);
            assert_eq!(
                reopened.keys().pending_output().await.unwrap().unwrap(),
                fixture.receipt
            );
        });
    }
}

#[test]
fn cancellation_before_storage_and_foreign_pending_receipt_make_no_write() {
    let fixture = fixture();
    let other = self::fixture();
    let mut signer = signer();
    let mut policy = charter(SCOPE, &mut signer, &[], &[], true);
    let signed = binding(&mut signer, &fixture.descriptor, MEMBER, 1);
    let prepared = prepared(&fixture, &mut policy, &signed);
    let other_signed = binding(&mut signer, &other.descriptor, MEMBER, 1);
    let other_prepared = self::prepared(&other, &mut policy, &other_signed);
    futures_executor::block_on(async {
        let faults = Faults::new(&fixture, 0);
        let mut vault = vault(&fixture, faults.clone()).await;
        let storage = vault.storage().clone();
        let held = storage.lock().await;
        assert!(
            vault
                .retain_lineage_evidence(&prepared, [83; 32])
                .now_or_never()
                .is_none()
        );
        drop(held);
        assert_eq!(faults.writes.get(), 0);
        assert_eq!(
            vault.keys().pending_output().await.unwrap().unwrap(),
            fixture.receipt
        );
        assert!(matches!(
            vault
                .retain_lineage_evidence(&other_prepared, [83; 32])
                .await,
            Err(EvidenceError::PendingMismatch)
        ));
        assert!(matches!(
            vault.retain_lineage_evidence(&prepared, [0; 32]).await,
            Err(EvidenceError::Invalid)
        ));
        assert_eq!(faults.writes.get(), 0);
        assert_eq!(vault.storage().lock().await.version().unwrap(), 1);
    });
}

#[test]
fn actual_competing_store_write_wins_without_partial_evidence() {
    let fixture = fixture();
    let mut signer = signer();
    let mut policy = charter(SCOPE, &mut signer, &[], &[], true);
    let signed = binding(&mut signer, &fixture.descriptor, MEMBER, 1);
    let prepared = prepared(&fixture, &mut policy, &signed);
    futures_executor::block_on(async {
        let mut vault = vault(&fixture, fixture.backend.clone()).await;
        let cipher = ckmg::passkey::store_cipher(&fixture.prf, SCOPE).unwrap();
        let mut other = cwst::Store::open(fixture.backend.clone(), &cipher, SCOPE)
            .await
            .unwrap();
        other
            .commit(
                1,
                [84; 32],
                &[cwst::Change::Put {
                    owner: "other",
                    key: b"value",
                    value: b"actual winner",
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            vault.retain_lineage_evidence(&prepared, [85; 32]).await,
            Err(EvidenceError::Storage(cwst::Error::Conflict))
        ));
        assert_eq!(
            vault.keys().pending_output().await.unwrap_err(),
            Error::Locked
        );
        assert_eq!(
            vault.storage().lock().await.version().unwrap_err(),
            cwst::Error::Locked
        );
        let reopened = self::vault(&fixture, fixture.backend.clone()).await;
        let store = reopened.storage().lock().await;
        assert_eq!(
            store.read("other", b"value").unwrap().unwrap(),
            b"actual winner"
        );
        assert!(
            LineageEvidence::load(&store, fixture.receipt.operation.as_bytes())
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn authenticated_storage_does_not_make_partial_corrupt_or_expired_evidence_authority() {
    let fixture = fixture();
    let mut signer = signer();
    let mut policy = charter(SCOPE, &mut signer, &[], &[], true);
    let signed = binding(&mut signer, &fixture.descriptor, MEMBER, 1);
    let prepared = prepared(&fixture, &mut policy, &signed);
    assert!(
        LineageEvidence::prepare(
            policy.current(NOW).unwrap(),
            &fixture.receipt,
            &fixture.other_assertion,
            &signed,
            MEMBER,
            NOW
        )
        .is_err()
    );
    futures_executor::block_on(async {
        let mut vault = vault(&fixture, fixture.backend.clone()).await;
        let key = fixture.receipt.operation.as_bytes();
        {
            let mut store = vault.storage().lock().await;
            store
                .commit(
                    1,
                    [86; 32],
                    &[cwst::Change::Put {
                        owner: "lineage-receipt",
                        key,
                        value: &serde_json::to_vec(&fixture.receipt).unwrap(),
                    }],
                    &[],
                )
                .await
                .unwrap();
            assert!(matches!(
                LineageEvidence::load(&store, key),
                Err(EvidenceError::Invalid)
            ));
        }
        vault
            .retain_lineage_evidence(&prepared, [87; 32])
            .await
            .unwrap();
        let mut store = vault.storage().lock().await;
        store
            .commit(
                3,
                [88; 32],
                &[cwst::Change::Put {
                    owner: "lineage-binding",
                    key,
                    value: b"invalid original COSE",
                }],
                &[],
            )
            .await
            .unwrap();
        let untrusted = LineageEvidence::load(&store, key).unwrap().unwrap();
        assert!(
            untrusted
                .verify(policy.current(NOW).unwrap(), MEMBER, NOW)
                .is_err()
        );
        store
            .commit(
                4,
                [89; 32],
                &[cwst::Change::Put {
                    owner: "lineage-binding",
                    key,
                    value: &vec![0; cvlt::MAX_LINEAGE_EVIDENCE_BYTES],
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            LineageEvidence::load(&store, key),
            Err(EvidenceError::Limit)
        ));
        store
            .commit(
                5,
                [90; 32],
                &[
                    cwst::Change::Put {
                        owner: "lineage-binding",
                        key,
                        value: &signed,
                    },
                    cwst::Change::Put {
                        owner: "lineage-receipt",
                        key,
                        value: b"invalid original receipt",
                    },
                ],
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            LineageEvidence::load(&store, key),
            Err(EvidenceError::Invalid)
        ));
    });
}
