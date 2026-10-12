//! Semantic facade tests only: this adapter does not qualify engine authentication.
use super::*;
use cdht::runtime::{Backend, Changes, Identity, Publication, Record, Value as RecordValue};
use cvlt::{LineageEvidence, LineageRecords, RecordError};
use std::cell::RefCell;
use zeroize::Zeroizing;

type Slots = Rc<RefCell<Vec<Option<(u32, Vec<u8>)>>>>;

#[derive(Clone)]
struct Runtime {
    identity: Identity,
    data: Slots,
    calls: Rc<RefCell<Vec<(u32, bool)>>>,
    failed: Rc<Cell<bool>>,
}
impl Runtime {
    fn new(slots: u16) -> Self {
        let schema = cdht::Schema::dflt(slots).unwrap();
        let owner = [7; 32];
        Self {
            identity: Identity {
                key: cdht::RecordKey::derive(&owner, &schema.compile()),
                owner,
                schema,
                writer: Some(owner),
            },
            data: Rc::new(RefCell::new(vec![None; usize::from(slots)])),
            calls: Rc::default(),
            failed: Rc::default(),
        }
    }
    fn handle(&self) -> Record<Self> {
        Record::new(self.clone()).unwrap()
    }
    fn put(&self, sequence: u32, bytes: &[u8]) {
        let packed = cprz_pad::pad(&cprz::portable::compress(bytes).unwrap());
        assert!(packed.len() <= cdht::MAX_SUBKEY_SIZE);
        self.data.borrow_mut()[0] = Some((sequence, packed));
    }
}
impl Backend for Runtime {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    async fn get(&self, subkey: u32, refresh: bool) -> Result<Option<RecordValue>, cdht::Error> {
        self.calls.borrow_mut().push((subkey, refresh));
        if self.failed.get() {
            return Err(cdht::Error::Unavailable);
        }
        Ok(self.data.borrow()[subkey as usize]
            .as_ref()
            .map(|(seq, bytes)| RecordValue {
                seq: *seq,
                writer: self.identity.owner,
                data: Zeroizing::new(bytes.clone()),
            }))
    }
    async fn republish(&self, _: u32, _: u32, _: &[u8]) -> Result<Publication, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn flush(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn watch(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    fn changes(&self) -> Result<Changes, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}
fn evidence() -> Vec<u8> {
    let fixture = fixture();
    let mut signer = signer();
    let mut owner = charter(SCOPE, &mut signer, &[], &[], true);
    LineageEvidence::prepare(
        owner.current(NOW).unwrap(),
        &fixture.receipt,
        &fixture.assertion,
        &fixture.certificate,
        MEMBER,
        NOW,
    )
    .unwrap()
    .evidence()
    .to_bytes()
    .unwrap()
}

#[test]
fn every_observation_forces_all_slots_and_preserves_original_evidence() {
    let bytes = evidence();
    let runtime = Runtime::new(2);
    runtime.put(4, &bytes);
    let mut records = LineageRecords::new(vec![runtime.handle()]).unwrap();
    for _ in 0..2 {
        let read = futures_executor::block_on(records.read()).unwrap();
        assert_eq!(read.evidence().len(), 1);
        assert_eq!(read.evidence()[0].to_bytes().unwrap(), bytes);
    }
    assert_eq!(
        *runtime.calls.borrow(),
        [(0, true), (1, true), (0, true), (1, true)]
    );
    runtime.failed.set(true);
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Unavailable)
    ));
}

#[test]
fn empty_failed_rollback_and_disappeared_records_never_fall_back_to_a_head() {
    let bytes = evidence();
    let runtime = Runtime::new(1);
    let mut records = LineageRecords::new(vec![runtime.handle()]).unwrap();
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Unavailable)
    ));
    runtime.put(4, &bytes);
    futures_executor::block_on(records.read()).unwrap();
    runtime.put(3, &bytes);
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Invalid)
    ));
    runtime.data.borrow_mut()[0] = None;
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Unavailable)
    ));
}

#[test]
fn malformed_and_over_budget_decompressed_content_refuse() {
    let runtime = Runtime::new(1);
    let mut records = LineageRecords::new(vec![runtime.handle()]).unwrap();
    runtime.put(1, b"{}");
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Invalid)
    ));
    runtime.put(2, &vec![0; cvlt::MAX_LINEAGE_EVIDENCE_BYTES + 1]);
    assert!(matches!(
        futures_executor::block_on(records.read()),
        Err(RecordError::Invalid)
    ));
    runtime.data.borrow_mut()[0] = Some((3, vec![0; cdht::MAX_SUBKEY_SIZE + 1]));
    assert!(futures_executor::block_on(records.read()).is_err());
}

#[test]
fn duplicate_record_identities_and_excess_slots_refuse() {
    let runtime = Runtime::new(1);
    assert!(matches!(
        LineageRecords::new(vec![] as Vec<Record<Runtime>>),
        Err(RecordError::Limit)
    ));
    assert!(matches!(
        LineageRecords::new(vec![runtime.handle(), runtime.handle()]),
        Err(RecordError::Invalid)
    ));
    let too_many = Runtime::new((ckmg::MAX_DEVICES + 1).try_into().unwrap());
    assert!(matches!(
        LineageRecords::new(vec![too_many.handle()]),
        Err(RecordError::Limit)
    ));
}
