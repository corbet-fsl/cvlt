//! Original public lineage evidence for local retention and Records publication.
use crate::{LineageError, Records, Vault, VerifiedLineageObservation, verify_lineage};
use ckmg::{Authority, Clock, Entropy, Receipt};
use cwst::{Store, backend::Backend};

const RECEIPT: &str = "lineage-receipt";
const ASSERTION: &str = "lineage-assertion";
const CERTIFICATE: &str = "lineage-certificate";

/// Aggregate bound for the three original public evidence values in local Storage.
pub const MAX_LINEAGE_EVIDENCE_BYTES: usize = cwst::MAX_VALUE_BYTES;

/// Value-free local retention refusal; uncertain Storage outcomes remain explicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// Original evidence verification refused preparation or later use.
    Evidence(LineageError),
    /// Original Storage error, including Conflict, Uncertain and Locked.
    Storage(cwst::Error),
    /// Original Keys could not read its exact committed pending receipt.
    Keys(ckmg::Error),
    /// Incomplete, malformed or differently bound retained public evidence.
    Invalid,
    /// Bounded local evidence exceeded the original Storage value limit.
    Limit,
    /// The exact receipt is no longer the current Keys pending output.
    PendingMismatch,
}
impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lineage retention: {self:?}")
    }
}
impl std::error::Error for EvidenceError {}

/// Retained public evidence, never a current-authority capability.
/// Every use must call `verify` inside the actual current Policy borrow.
/// This container has no network publication format or automatic acknowledgement.
pub struct LineageEvidence {
    receipt: Receipt,
    assertion: ckyh::lineage::Assertion,
    certificate: Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidence {
    purpose: String,
    receipt: Receipt,
    assertion: ckyh::lineage::Assertion,
    certificate: Vec<u8>,
}
impl std::fmt::Debug for LineageEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LineageEvidence([redacted])")
    }
}
/// Transient owner preparation verified synchronously by the original owners.
/// This is local storage input only, never current authority across an await.
/// Loading retained bytes cannot construct this type; they must be reverified.
pub struct PreparedLineageEvidence(LineageEvidence);
impl PreparedLineageEvidence {
    /// Borrow the public evidence container; this grants no current authority.
    pub fn evidence(&self) -> &LineageEvidence {
        &self.0
    }
}
impl std::fmt::Debug for PreparedLineageEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLineageEvidence([redacted])")
    }
}
impl LineageEvidence {
    pub(crate) fn matches_receipt(&self, receipt: &Receipt) -> bool {
        &self.receipt == receipt
    }

    pub(crate) fn packed(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::RecordError> {
        let bytes =
            zeroize::Zeroizing::new(self.to_bytes().map_err(|_| crate::RecordError::Invalid)?);
        let compressed = zeroize::Zeroizing::new(
            cprz::portable::compress(&bytes).map_err(|_| crate::RecordError::Invalid)?,
        );
        let data = zeroize::Zeroizing::new(cprz_pad::pad(&compressed));
        if data.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(crate::RecordError::Limit);
        }
        Ok(data)
    }

    /// Bounded publication envelope over original owner evidence. Unsigned
    /// WebAuthn userHandle routing data is omitted; all signed assertion bytes
    /// remain exact. Compression/padding/chunking belongs to original Records.
    /// Publishing these bytes never acknowledges the Keys output automatically.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EvidenceError> {
        self.encoded()?;
        let mut assertion = self.assertion.clone();
        assertion.user_handle = None;
        let bytes = serde_json::to_vec(&WireEvidence {
            purpose: "cvlt.lineage-evidence.v1".into(),
            receipt: self.receipt.clone(),
            assertion,
            certificate: self.certificate.clone(),
        })
        .map_err(|_| EvidenceError::Invalid)?;
        if bytes.len() > MAX_LINEAGE_EVIDENCE_BYTES {
            return Err(EvidenceError::Limit);
        }
        Ok(bytes)
    }

    /// Decode untrusted public bytes without granting authority. Every use must
    /// call `verify` with the actual current Charter, expected pseudonym and time.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > MAX_LINEAGE_EVIDENCE_BYTES {
            return Err(EvidenceError::Limit);
        }
        let wire: WireEvidence =
            serde_json::from_slice(bytes).map_err(|_| EvidenceError::Invalid)?;
        if wire.purpose != "cvlt.lineage-evidence.v1" || wire.assertion.user_handle.is_some() {
            return Err(EvidenceError::Invalid);
        }
        let evidence = Self {
            receipt: wire.receipt,
            assertion: wire.assertion,
            certificate: wire.certificate,
        };
        evidence.encoded()?;
        Ok(evidence)
    }

    /// Capture existing public owner values during a synchronous current-Policy
    /// callback. The returned container has no authority across subsequent awaits.
    pub fn prepare(
        current: &cchr::VerifiedCharter,
        receipt: &Receipt,
        assertion: &ckyh::lineage::Assertion,
        signed_certificate: &[u8],
        expected_member: &str,
        now: u64,
    ) -> Result<PreparedLineageEvidence, EvidenceError> {
        verify_lineage(
            current,
            receipt,
            assertion,
            signed_certificate,
            expected_member,
            now,
        )
        .map_err(EvidenceError::Evidence)?;
        let value = Self {
            receipt: receipt.clone(),
            assertion: assertion.clone(),
            certificate: signed_certificate.to_vec(),
        };
        value.encoded()?;
        Ok(PreparedLineageEvidence(value))
    }

    /// Original receipt operation; unrelated to a Store commit or network sequence.
    pub fn operation(&self) -> &[u8; 32] {
        self.receipt.operation.as_bytes()
    }

    /// Reverify all original evidence against the current Charter and clock.
    pub fn verify<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedLineageObservation<'a>, LineageError> {
        verify_lineage(
            current,
            &self.receipt,
            &self.assertion,
            &self.certificate,
            expected_member,
            now,
        )
    }

    /// Load three original public values from authenticated local Storage. This
    /// grants no currentness: `verify` remains mandatory at every point of use.
    /// An absent triple is None; partial/corrupt triples are refused.
    pub fn load<B: Backend>(
        store: &Store<B>,
        operation: &[u8; 32],
    ) -> Result<Option<Self>, EvidenceError> {
        let receipt = store
            .read(RECEIPT, operation)
            .map_err(EvidenceError::Storage)?;
        let assertion = store
            .read(ASSERTION, operation)
            .map_err(EvidenceError::Storage)?;
        let certificate = store
            .read(CERTIFICATE, operation)
            .map_err(EvidenceError::Storage)?;
        let (receipt, assertion, certificate) = match (receipt, assertion, certificate) {
            (None, None, None) => return Ok(None),
            (Some(r), Some(a), Some(b)) => (r, a, b),
            _ => return Err(EvidenceError::Invalid),
        };
        bound(receipt.len(), assertion.len(), certificate.len())?;
        let value = Self {
            receipt: serde_json::from_slice(receipt).map_err(|_| EvidenceError::Invalid)?,
            assertion: serde_json::from_slice(assertion).map_err(|_| EvidenceError::Invalid)?,
            certificate: certificate.to_vec(),
        };
        if value.operation() != operation
            || !store.is_scope(
                value
                    .receipt
                    .attested_lineage()
                    .map_err(|_| EvidenceError::Invalid)?
                    .0
                    .binding
                    .community(),
            )
        {
            return Err(EvidenceError::Invalid);
        }
        Ok(Some(value))
    }

    fn encoded(&self) -> Result<(Vec<u8>, Vec<u8>), EvidenceError> {
        let receipt = serde_json::to_vec(&self.receipt).map_err(|_| EvidenceError::Invalid)?;
        let assertion = serde_json::to_vec(&self.assertion).map_err(|_| EvidenceError::Invalid)?;
        bound(receipt.len(), assertion.len(), self.certificate.len())?;
        Ok((receipt, assertion))
    }

    pub(crate) fn retained_mutations(&self) -> Result<Vec<crate::Mutation>, EvidenceError> {
        let (receipt, assertion) = self.encoded()?;
        Ok([
            (RECEIPT, receipt),
            (ASSERTION, assertion),
            (CERTIFICATE, self.certificate.clone()),
        ]
        .into_iter()
        .map(|(owner, value)| crate::Mutation {
            owner: owner.into(),
            key: self.operation().to_vec(),
            value: Some(value),
        })
        .collect())
    }
}

fn bound(receipt: usize, assertion: usize, certificate: usize) -> Result<(), EvidenceError> {
    if receipt
        .checked_add(assertion)
        .and_then(|n| n.checked_add(certificate))
        .is_none_or(|n| n > MAX_LINEAGE_EVIDENCE_BYTES)
    {
        return Err(EvidenceError::Limit);
    }
    Ok(())
}

struct LockOnDrop<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for LockOnDrop<F> {
    fn drop(&mut self) {
        if let Some(lock) = self.0.take() {
            lock();
        }
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Atomically retain prepared public evidence without changing Keys bytes or
    /// clearing its pending receipt. No Keys transition is fabricated to consume
    /// a Batch. `operation` identifies this separate original Store transaction.
    ///
    /// A returned Store receipt proves local durability only; it never upgrades
    /// preparation verification into current authority after the await. Errors or
    /// cancellation during the write lock Keys; reopen the original checkpoint to
    /// reconcile its operation/values. No publication or output is acknowledged.
    pub async fn retain_lineage_evidence(
        &mut self,
        evidence: &PreparedLineageEvidence,
        operation: [u8; 32],
    ) -> Result<cwst::CommitReceipt, EvidenceError> {
        if operation == [0; 32] {
            return Err(EvidenceError::Invalid);
        }
        let evidence = &evidence.0;
        let (receipt, assertion) = evidence.encoded()?;
        let storage = self.storage.clone();
        let expected = storage
            .lock()
            .await
            .version()
            .map_err(EvidenceError::Storage)?;
        let pending = self
            .keys
            .pending_output()
            .await
            .map_err(EvidenceError::Keys)?;
        if pending.as_ref() != Some(&evidence.receipt) {
            return Err(EvidenceError::PendingMismatch);
        }
        let mut store = storage.lock().await;
        if store.version().map_err(EvidenceError::Storage)? != expected {
            self.keys.lock();
            return Err(EvidenceError::Storage(cwst::Error::Conflict));
        }
        let (lineage, _) = evidence
            .receipt
            .attested_lineage()
            .map_err(|_| EvidenceError::Invalid)?;
        if !store.is_scope(lineage.binding.community()) {
            return Err(EvidenceError::Invalid);
        }
        let changes = [
            cwst::Change::Put {
                owner: RECEIPT,
                key: evidence.operation(),
                value: &receipt,
            },
            cwst::Change::Put {
                owner: ASSERTION,
                key: evidence.operation(),
                value: &assertion,
            },
            cwst::Change::Put {
                owner: CERTIFICATE,
                key: evidence.operation(),
                value: &evidence.certificate,
            },
        ];
        let mut lock = LockOnDrop(Some(|| self.keys.lock()));
        let committed = store
            .commit_with_receipt(expected, operation, &changes, &[])
            .await
            .map_err(EvidenceError::Storage)?;
        lock.0 = None;
        Ok(committed)
    }
}
