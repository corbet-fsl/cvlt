//! Original Keys acknowledgment retained in the actual durable outer Store.
use super::*;

/// One forced-read attempt's temporary completion custody. Its original
/// authority must remain alive through this operation. Only a fixed read key
/// can be lent to the member checker; no general Keys or Vault can escape.
pub struct InitialAcknowledgment<B: Backend> {
    opening: PreparedOpen,
    backend: BackendRef<B>,
    store: cwst::Store<BackendRef<B>>,
    completion: ckmg::PendingCompletion,
    evidence: crate::LineageEvidence,
    floor: u64,
}
impl<B: Backend> std::fmt::Debug for InitialAcknowledgment<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialAcknowledgment([redacted])")
    }
}

impl<B: Backend> InitialLineageRead<B> {
    /// Recheck dedicated original completion authority after the forced read.
    /// This does not replace normal member Use: acknowledgment below requires
    /// that check through the original Keys owner before preparing any change.
    pub async fn prepare_acknowledgment(
        self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<InitialAcknowledgment<B>, InitialError> {
        let Self {
            creation,
            evidence,
            checked_at,
        } = self;
        if creation.phase()? != InitialPhase::Staged
            || !evidence.matches_receipt(creation.receipt())
        {
            return Err(InitialError::Invalid);
        }
        let InitialCreation {
            opening,
            backend,
            store,
            pending,
        } = creation;
        let intent = decode_intent(required(&store, INTENT)?)?;
        let mut clock = CompletionClock {
            clock,
            floor: checked_at.max(intent.prepared_at),
        };
        let completion = pending
            .authorize_completion(
                ckmg::CompletionIntent {
                    outer_generation: store.version().map_err(InitialError::Storage)?,
                    outer_digest: *blake3::hash(
                        store.sealed_checkpoint().map_err(InitialError::Storage)?,
                    )
                    .as_bytes(),
                    inner_version: 1,
                    inner_operation: initial_operation(&store)?,
                    inner_digest: *blake3::hash(required(&store, INNER)?).as_bytes(),
                    nonce: intent.nonce,
                    packed_evidence: intent.packed_evidence,
                    prepared_at: intent.prepared_at,
                    expires: intent.expires,
                },
                &mut clock,
                authority,
            )
            .await
            .map_err(InitialError::Keys)?;
        Ok(InitialAcknowledgment {
            opening,
            backend,
            store,
            completion,
            evidence,
            floor: clock.floor,
        })
    }
}

impl<B: Backend> InitialAcknowledgment<B> {
    /// Original fixed lineage reader for the actual normal member checker.
    /// This grants no Use; the enclosing attempt must drop it with its authority.
    pub fn lineage_reader(&self) -> Result<ckmg::InitialLineageReader, InitialError> {
        self.completion.lineage_reader().map_err(InitialError::Keys)
    }

    /// Prepare privately with the original Keys/Store owners, then retain the
    /// complete acknowledged checkpoint and original public evidence in one
    /// actual backend CAS. Memory receipts never escape or prove durability.
    /// Cancellation or uncertainty requires reopening the actual outer phase.
    pub async fn acknowledge(
        mut self,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        authority: &mut impl Authority,
    ) -> Result<InitialCreation<B>, InitialError> {
        let mut clock = CompletionClock {
            clock,
            floor: self.floor,
        };
        self.completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        let original_keys = required(&self.store, KEYS)?.to_vec();
        let receipt = self.completion.receipt().clone();
        let original_operation = initial_operation(&self.store)?;
        let inner = cwst::Store::restore_checked(
            cwst::backend::Memory::new(),
            self.completion.store_cipher(),
            &self.opening.scope,
            1,
            required(&self.store, INNER)?,
            |inner| {
                if inner.operation()? != original_operation
                    || inner.read("keys", self.opening.locator.as_bytes())?
                        != Some(original_keys.as_slice())
                {
                    return Err(cwst::Error::Corrupt);
                }
                Ok(())
            },
        )
        .await
        .map_err(InitialError::Storage)?;
        let storage = crate::shared_store(inner);
        let mut key_store = crate::KeyStore::new(storage.clone(), &self.opening.scope)
            .map_err(|_| InitialError::Invalid)?;
        {
            let mut keys = ckmg::Keys::new(
                key_store.clone(),
                BorrowClock(&mut clock),
                BorrowEntropy(entropy),
                BorrowAuthority(authority),
            );
            keys.unlock(&self.opening.prf, &self.opening.scope)
                .await
                .map_err(InitialError::Keys)?;
            // Actual normal Use must force Records, current HTTPS membership and
            // Charter again. The earlier consensus report is not a cached grant.
            let lineage = keys.lineage().await.map_err(InitialError::Keys)?;
            if &lineage != receipt.attested_lineage().map_err(InitialError::Keys)?.0
                || keys
                    .pending_output()
                    .await
                    .map_err(InitialError::Keys)?
                    .as_ref()
                    != Some(&receipt)
            {
                return Err(InitialError::Invalid);
            }
            let _batch = key_store
                .stage(crate::Batch {
                    expected: 1,
                    operation: *receipt.operation.as_bytes(),
                    mutations: self
                        .evidence
                        .retained_mutations()
                        .map_err(|_| InitialError::Invalid)?,
                    outputs: vec![],
                })
                .map_err(|_| InitialError::Invalid)?;
            keys.acknowledge(receipt.operation)
                .await
                .map_err(InitialError::Keys)?;
            keys.lock();
        }
        let (inner, sealed) = {
            let store = storage.lock().await;
            if store.version().map_err(InitialError::Storage)? != 2
                || store.operation().map_err(InitialError::Storage)?
                    != *receipt.operation.as_bytes()
            {
                return Err(InitialError::Invalid);
            }
            let sealed = store
                .read("keys", self.opening.locator.as_bytes())
                .map_err(InitialError::Storage)?
                .ok_or(InitialError::Invalid)?
                .to_vec();
            let retained = crate::LineageEvidence::load(&store, receipt.operation.as_bytes())
                .map_err(|_| InitialError::Invalid)?
                .ok_or(InitialError::Invalid)?;
            if retained.to_bytes().map_err(|_| InitialError::Invalid)?
                != self
                    .evidence
                    .to_bytes()
                    .map_err(|_| InitialError::Invalid)?
            {
                return Err(InitialError::Invalid);
            }
            (
                store
                    .sealed_checkpoint()
                    .map_err(InitialError::Storage)?
                    .to_vec(),
                sealed,
            )
        };
        validate_acknowledged(&self.opening, &receipt, &sealed)?;
        // Fence the original generation after all preparatory owner awaits.
        if self
            .backend
            .read()
            .await
            .map_err(InitialError::Storage)?
            .as_deref()
            != Some(
                self.store
                    .sealed_checkpoint()
                    .map_err(InitialError::Storage)?,
            )
        {
            return Err(InitialError::Storage(cwst::Error::Conflict));
        }
        self.completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        let operation = *receipt.operation.as_bytes();
        let committed = self
            .store
            .commit_with_receipt(
                4,
                operation,
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: ACKNOWLEDGED_INNER,
                        value: &inner,
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: ACKNOWLEDGED_KEYS,
                        value: &sealed,
                    },
                ],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        if !committed.is_commit(&self.store, &operation)
            || !committed.contains_record(
                OWNER,
                ACKNOWLEDGED_INNER,
                blake3::hash(&inner).as_bytes(),
            )
            || !committed.contains_record(
                OWNER,
                ACKNOWLEDGED_KEYS,
                blake3::hash(&sealed).as_bytes(),
            )
        {
            return Err(InitialError::Invalid);
        }
        self.completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        drop(self.completion);
        let pending = self
            .opening
            .inspector()
            .map_err(InitialError::Open)?
            .pending_creation(&original_keys)
            .map_err(InitialError::Keys)?;
        let creation = InitialCreation {
            opening: self.opening,
            backend: self.backend,
            store: self.store,
            pending,
        };
        creation.acknowledged_state()?;
        Ok(creation)
    }
}

impl<B: Backend> InitialCreation<B> {
    pub(super) fn acknowledged_state(&self) -> Result<ckmg::CheckpointInspection, InitialError> {
        // Both outcomes consume generation four once. Their authenticated
        // record shapes distinguish acknowledgment from a terminal conflict.
        if self.store.version().map_err(InitialError::Storage)? != 5 {
            return Err(InitialError::Invalid);
        }
        self.staged_state()?;
        required(&self.store, ACKNOWLEDGED_INNER)?;
        validate_acknowledged(
            &self.opening,
            self.receipt(),
            required(&self.store, ACKNOWLEDGED_KEYS)?,
        )
    }
}

fn validate_acknowledged(
    opening: &PreparedOpen,
    receipt: &ckmg::Receipt,
    sealed: &[u8],
) -> Result<ckmg::CheckpointInspection, InitialError> {
    let inspected = opening
        .inspector()
        .map_err(InitialError::Open)?
        .inspect(sealed)
        .map_err(InitialError::Keys)?;
    let (lineage, author) = receipt.attested_lineage().map_err(InitialError::Keys)?;
    if inspected.lineage() != lineage || inspected.device() != author || inspected.revision() != 2 {
        return Err(InitialError::Invalid);
    }
    Ok(inspected)
}

struct BorrowClock<'a, C>(&'a mut C);
impl<C: Clock> Clock for BorrowClock<'_, C> {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        self.0.now()
    }
}
struct BorrowEntropy<'a, E>(&'a mut E);
impl<E: Entropy> Entropy for BorrowEntropy<'_, E> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ckmg::Error> {
        self.0.fill(bytes)
    }
}
struct BorrowAuthority<'a, A>(&'a mut A);
impl<A: Authority> Authority for BorrowAuthority<'_, A> {
    async fn check(&mut self, request: ckmg::Authorization<'_>) -> Result<(), ckmg::Error> {
        self.0.check(request).await
    }
}
