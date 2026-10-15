//! Original public lineage evidence for local retention and Records publication.
use crate::{
    GenesisStampEvidence, LineageError, Records, StampTrust, Vault, VerifiedLineageObservation,
    verify_lineage,
};
use ckmg::{Authority, Clock, Entropy, Receipt};
use cpsd::StampPresentation;
use cwst::{Store, backend::Backend};

const RECEIPT: &str = "lineage-receipt";
const ASSERTION: &str = "lineage-assertion";
const CERTIFICATE: &str = "lineage-certificate";
const STAMP: &str = "lineage-stamp";
const PASSKEY_PURPOSE: &str = "cvlt.lineage-evidence.v1";

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
///
/// Two kinds exist: a passkey assertion under the Charter's registration certificate (every
/// lineage change of a passkey member), and a wallet confirmation stamp (a member's FIRST
/// community lineage only, verified offline with [`StampTrust`] at the receipt's signed time).
pub struct LineageEvidence {
    receipt: Receipt,
    proof: Proof,
}
enum Proof {
    Passkey {
        assertion: ckyh::lineage::Assertion,
        certificate: Vec<u8>,
    },
    /// Charter's public genesis stamp evidence (its wire bytes are this evidence's bytes).
    Stamp(Box<GenesisStampEvidence>),
}
/// Local Storage value of genesis stamp evidence beside the receipt: the presentation of the
/// `lineage_genesis` slot, the device's salt of that slot (public once presented) and the time
/// `at` the stamp payload binds.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StampProof {
    presentation: Vec<u8>,
    salt: [u8; 32],
    at: u64,
}
impl StampProof {
    fn evidence(self, receipt: &Receipt) -> Result<GenesisStampEvidence, EvidenceError> {
        let presentation =
            StampPresentation::from_bytes(&self.presentation).map_err(|_| EvidenceError::Invalid)?;
        Ok(GenesisStampEvidence::new(
            receipt.clone(),
            &presentation,
            self.salt,
            self.at,
        ))
    }
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

    /// The exact packed plaintext that a lineage record value carries (the
    /// `canonical_evidence` Keys signs a record revision over).
    pub fn packed(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::RecordError> {
        self.0.packed()
    }
}
impl std::fmt::Debug for PreparedLineageEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLineageEvidence([redacted])")
    }
}
impl LineageEvidence {
    pub(crate) fn initial_acknowledgment(
        &self,
        inspector: &ckmg::CheckpointInspector,
        sealed: &[u8],
    ) -> Result<ckmg::InitialCheckpointProvenance, crate::OpenError> {
        let packed = self.packed().map_err(crate::OpenError::Records)?;
        inspector
            .initial_acknowledgment(sealed, &self.receipt, &packed)
            .map_err(crate::OpenError::Keys)
    }

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
        let bytes = match &self.proof {
            Proof::Passkey {
                assertion,
                certificate,
            } => {
                let mut assertion = assertion.clone();
                assertion.user_handle = None;
                serde_json::to_vec(&WireEvidence {
                    purpose: PASSKEY_PURPOSE.into(),
                    receipt: self.receipt.clone(),
                    assertion,
                    certificate: certificate.clone(),
                })
                .map_err(|_| EvidenceError::Invalid)?
            }
            // Charter owns the stamp evidence wire, so the server decodes these exact bytes.
            Proof::Stamp(stamp) => stamp.to_bytes().map_err(|_| EvidenceError::Invalid)?,
        };
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
        let evidence = if let Ok(wire) = serde_json::from_slice::<WireEvidence>(bytes) {
            if wire.purpose != PASSKEY_PURPOSE || wire.assertion.user_handle.is_some() {
                return Err(EvidenceError::Invalid);
            }
            Self {
                receipt: wire.receipt,
                proof: Proof::Passkey {
                    assertion: wire.assertion,
                    certificate: wire.certificate,
                },
            }
        } else {
            let stamp =
                GenesisStampEvidence::from_bytes(bytes).map_err(|_| EvidenceError::Invalid)?;
            Self {
                receipt: stamp.receipt().clone(),
                proof: Proof::Stamp(Box::new(stamp)),
            }
        };
        evidence.encoded()?;
        Ok(evidence)
    }

    /// Decode the original Padme/compressed Records envelope without granting
    /// authority. Exact retained bytes remain the immutable publication input;
    /// callers must verify the decoded evidence under current original owners.
    pub fn from_packed(packed: &[u8]) -> Result<Self, EvidenceError> {
        if packed.is_empty() || packed.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(EvidenceError::Limit);
        }
        let compressed =
            zeroize::Zeroizing::new(cprz_pad::unpad(packed).map_err(|_| EvidenceError::Invalid)?);
        let bytes = zeroize::Zeroizing::new(
            cprz::portable::decompress(
                &compressed,
                cdht::MAX_SUBKEY_SIZE,
                MAX_LINEAGE_EVIDENCE_BYTES,
            )
            .map_err(|_| EvidenceError::Invalid)?,
        );
        Self::from_bytes(&bytes)
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
            proof: Proof::Passkey {
                assertion: assertion.clone(),
                certificate: signed_certificate.to_vec(),
            },
        };
        value.encoded()?;
        Ok(PreparedLineageEvidence(value))
    }

    /// Capture genesis evidence by stamp for a member's FIRST lineage: the presentation of
    /// the `lineage_genesis` slot (built over [`crate::lineage_genesis_action`] of this receipt
    /// with `salt` and `at`). Verified like every later use, within one synchronous current
    /// Policy borrow; the result has no authority across awaits.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_stamp(
        current: &cchr::VerifiedCharter,
        stamps: &StampTrust,
        receipt: &Receipt,
        presentation: &StampPresentation,
        salt: [u8; 32],
        at: u64,
        expected_member: &str,
        now: u64,
    ) -> Result<PreparedLineageEvidence, EvidenceError> {
        crate::lineage::verify_genesis(
            current,
            stamps,
            receipt,
            presentation,
            salt,
            at,
            expected_member,
            now,
        )
        .map_err(EvidenceError::Evidence)?;
        let value = Self {
            receipt: receipt.clone(),
            proof: Proof::Stamp(Box::new(GenesisStampEvidence::new(
                receipt.clone(),
                presentation,
                salt,
                at,
            ))),
        };
        value.encoded()?;
        Ok(PreparedLineageEvidence(value))
    }

    /// Whether this is genesis evidence by stamp (which needs [`StampTrust`] to verify).
    pub fn is_stamp(&self) -> bool {
        matches!(self.proof, Proof::Stamp(_))
    }

    /// The Charter genesis stamp evidence inside, if this is stamp evidence: what a device
    /// sends with its first publication bind (`GenesisStampEvidence::to_bytes`).
    pub fn genesis_stamp(&self) -> Option<&GenesisStampEvidence> {
        match &self.proof {
            Proof::Stamp(stamp) => Some(stamp),
            Proof::Passkey { .. } => None,
        }
    }

    /// Original receipt operation; unrelated to a Store commit or network sequence.
    pub fn operation(&self) -> &[u8; 32] {
        self.receipt.operation.as_bytes()
    }

    /// Reverify all original evidence against the current Charter and clock. Stamp evidence
    /// needs the stamp trust and refuses here as `Policy(Unavailable)`; use
    /// [`Self::verify_with_stamps`].
    pub fn verify<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedLineageObservation<'a>, LineageError> {
        match &self.proof {
            Proof::Passkey {
                assertion,
                certificate,
            } => verify_lineage(
                current,
                &self.receipt,
                assertion,
                certificate,
                expected_member,
                now,
            ),
            Proof::Stamp(_) => Err(LineageError::Policy(cchr::Error::Unavailable)),
        }
    }

    /// Reverify either kind against the current Charter and clock; stamp evidence also against
    /// the wallet's authenticated stamp key ring and the rulebook cohort in `stamps`, judged at
    /// the receipt's signed time (never at `now`).
    pub fn verify_with_stamps<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        stamps: &StampTrust,
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedLineageObservation<'a>, LineageError> {
        match &self.proof {
            Proof::Passkey { .. } => self.verify(current, expected_member, now),
            Proof::Stamp(stamp) => {
                let genesis = crate::lineage::verify_genesis(
                    current,
                    stamps,
                    &self.receipt,
                    &stamp.presentation()?,
                    stamp.salt(),
                    stamp.at(),
                    expected_member,
                    now,
                )?;
                Ok(VerifiedLineageObservation::stamped(current, genesis, now))
            }
        }
    }

    // Reachable publicly only through the sealed actual acknowledged-initial
    // candidate. Ordinary evidence verification retains its original semantics.
    pub(crate) fn reauthorize_initial<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        current_certificate: &'a [u8],
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedLineageObservation<'a>, LineageError> {
        let Proof::Passkey { assertion, .. } = &self.proof else {
            return Err(LineageError::Scope);
        };
        verify_lineage(
            current,
            &self.receipt,
            assertion,
            current_certificate,
            expected_member,
            now,
        )
    }

    // The stamp twin of `reauthorize_initial`: genesis evidence by stamp, verified at NOW
    // against the current Charter and the authenticated stamp trust (judged at the receipt
    // time). Passkey evidence refuses with `Scope`.
    pub(crate) fn reauthorize_initial_with_stamps<'a>(
        &'a self,
        current: &'a cchr::VerifiedCharter,
        stamps: &StampTrust,
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedLineageObservation<'a>, LineageError> {
        if !self.is_stamp() {
            return Err(LineageError::Scope);
        }
        self.verify_with_stamps(current, stamps, expected_member, now)
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
        let stamp = store
            .read(STAMP, operation)
            .map_err(EvidenceError::Storage)?;
        let value = match (receipt, assertion, certificate, stamp) {
            (None, None, None, None) => return Ok(None),
            (Some(receipt), Some(assertion), Some(certificate), None) => {
                bound(receipt.len(), assertion.len(), certificate.len())?;
                Self {
                    receipt: serde_json::from_slice(receipt).map_err(|_| EvidenceError::Invalid)?,
                    proof: Proof::Passkey {
                        assertion: serde_json::from_slice(assertion)
                            .map_err(|_| EvidenceError::Invalid)?,
                        certificate: certificate.to_vec(),
                    },
                }
            }
            (Some(receipt), None, None, Some(stamp)) => {
                bound(receipt.len(), stamp.len(), 0)?;
                let receipt: Receipt =
                    serde_json::from_slice(receipt).map_err(|_| EvidenceError::Invalid)?;
                let stamp: StampProof =
                    serde_json::from_slice(stamp).map_err(|_| EvidenceError::Invalid)?;
                Self {
                    proof: Proof::Stamp(Box::new(stamp.evidence(&receipt)?)),
                    receipt,
                }
            }
            _ => return Err(EvidenceError::Invalid),
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

    /// The retained Store values of this evidence, as (owner, value) pairs, within the bound.
    fn encoded(&self) -> Result<Vec<(&'static str, Vec<u8>)>, EvidenceError> {
        let receipt = serde_json::to_vec(&self.receipt).map_err(|_| EvidenceError::Invalid)?;
        match &self.proof {
            Proof::Passkey {
                assertion,
                certificate,
            } => {
                let assertion =
                    serde_json::to_vec(assertion).map_err(|_| EvidenceError::Invalid)?;
                bound(receipt.len(), assertion.len(), certificate.len())?;
                Ok(vec![
                    (RECEIPT, receipt),
                    (ASSERTION, assertion),
                    (CERTIFICATE, certificate.clone()),
                ])
            }
            Proof::Stamp(stamp) => {
                let stamp = serde_json::to_vec(&StampProof {
                    presentation: stamp.presentation_bytes().to_vec(),
                    salt: stamp.salt(),
                    at: stamp.at(),
                })
                .map_err(|_| EvidenceError::Invalid)?;
                bound(receipt.len(), stamp.len(), 0)?;
                Ok(vec![(RECEIPT, receipt), (STAMP, stamp)])
            }
        }
    }

    pub(crate) fn retained_mutations(&self) -> Result<Vec<crate::Mutation>, EvidenceError> {
        Ok(self
            .encoded()?
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
        let values = evidence.encoded()?;
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
        let changes: Vec<_> = values
            .iter()
            .map(|(owner, value)| cwst::Change::Put {
                owner,
                key: evidence.operation(),
                value,
            })
            .collect();
        let mut lock = LockOnDrop(Some(|| self.keys.lock()));
        let committed = store
            .commit_with_receipt(expected, operation, &changes, &[])
            .await
            .map_err(EvidenceError::Storage)?;
        lock.0 = None;
        Ok(committed)
    }
}

// This carrier is committed in the same original inner Store batch as the
// normal initial Keys ACK. Public matching bytes never replace its Store MAC.
pub(crate) fn check_initial_ack<B: Backend>(
    store: &Store<B>,
    initial: &ckmg::InitialCheckpointProvenance,
) -> Result<(), cwst::Error> {
    let expected = initial.to_bytes().map_err(|_| cwst::Error::Corrupt)?;
    if store.read("cvlt-initial-ack", initial.operation().as_bytes())? != Some(expected.as_slice())
    {
        return Err(cwst::Error::Corrupt);
    }
    Ok(())
}
