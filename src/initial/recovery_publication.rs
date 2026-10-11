//! Original recovery formats signed privately, then retained before transport.
use super::*;
use crate::records::tor::Verifier;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    subkey: u32,
    descriptor: Vec<u8>,
    value: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    pairs: Vec<Pair>,
    state: cdht::ClientState,
}

impl<B: Backend> InitialCreation<B> {
    /// Authenticate the actual acknowledged inner Store, obtain normal member
    /// bootstrap custody, and retain original compound/passkey recovery formats
    /// with their exact signed queue. This performs no network writes and never
    /// grants a usable Vault or claims a recoverable network checkpoint.
    pub async fn stage_recovery<N: cdht::Network + Clone>(
        self,
        network: N,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        authority: &mut impl Authority,
    ) -> Result<Self, InitialError> {
        if self.phase()? != InitialPhase::Acknowledged {
            return Err(InitialError::Invalid);
        }
        let Self {
            opening,
            backend,
            mut store,
            pending,
        } = self;
        let intent = decode_intent(required(&store, INTENT)?)?;
        let mut clock = CompletionClock {
            clock,
            floor: intent.prepared_at,
        };
        let original_keys = required(&store, KEYS)?.to_vec();
        let receipt = pending.receipt().clone();
        let operation = *receipt.operation.as_bytes();
        let mut completion = pending
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
                    packed_evidence: intent.packed_evidence.clone(),
                    prepared_at: intent.prepared_at,
                    expires: intent.expires,
                },
                &mut clock,
                authority,
            )
            .await
            .map_err(InitialError::Keys)?;
        let sealed = required(&store, ACKNOWLEDGED_KEYS)?.to_vec();
        let inner = cwst::Store::restore_checked(
            cwst::backend::Memory::new(),
            completion.store_cipher(),
            &opening.scope,
            2,
            required(&store, ACKNOWLEDGED_INNER)?,
            |inner| {
                if inner.operation()? != operation
                    || inner.read("keys", opening.locator.as_bytes())? != Some(sealed.as_slice())
                {
                    return Err(cwst::Error::Corrupt);
                }
                Ok(())
            },
        )
        .await
        .map_err(InitialError::Storage)?;
        let evidence = crate::LineageEvidence::load(&inner, &operation)
            .map_err(|_| InitialError::Invalid)?
            .ok_or(InitialError::Invalid)?;
        if !evidence.matches_receipt(&receipt)
            || evidence.packed().map_err(InitialError::Records)?.as_slice()
                != intent.packed_evidence.as_slice()
        {
            return Err(InitialError::Invalid);
        }
        let evidence_bytes = evidence.to_bytes().map_err(|_| InitialError::Invalid)?;
        let inspector = opening.inspector().map_err(InitialError::Open)?;
        let bootstrap = inspector
            .bootstrap(&sealed, &evidence_bytes, &mut clock, authority)
            .await
            .map_err(InitialError::Keys)?;
        if bootstrap.inspection().lineage()
            != receipt.attested_lineage().map_err(InitialError::Keys)?.0
            || bootstrap.inspection().revision() != 2
        {
            return Err(InitialError::Invalid);
        }
        // Build original identities only; these read-only constructors perform
        // no network I/O, descriptor creation or absence-based authority check.
        let root = crate::TorReadRecord::checkpoint(
            network.clone(),
            bootstrap.record(None).map_err(InitialError::Keys)?,
        )
        .and_then(cdht::runtime::Record::new)
        .map_err(InitialError::Publication)?;
        let mut children = Vec::new();
        for index in 0..crate::MAX_CHECKPOINT_RECORDS {
            children.push(
                crate::TorReadRecord::checkpoint(
                    network.clone(),
                    bootstrap
                        .record(Some(index as u8))
                        .map_err(InitialError::Keys)?,
                )
                .and_then(cdht::runtime::Record::new)
                .map_err(InitialError::Publication)?,
            );
        }
        let records = crate::CompoundRecords::new(&opening.scope, root, children)
            .map_err(|_| InitialError::Invalid)?;
        let prepared = records
            .prepare(&inner, &opening.scope)
            .map_err(|_| InitialError::Invalid)?;
        drop(records);
        let packed_recovery =
            crate::records::pack_recovery(&sealed, &evidence).map_err(InitialError::Records)?;
        // The final authoritative wait fences the actual local generation.
        if backend
            .read()
            .await
            .map_err(InitialError::Storage)?
            .as_deref()
            != Some(store.sealed_checkpoint().map_err(InitialError::Storage)?)
        {
            return Err(InitialError::Storage(cwst::Error::Conflict));
        }
        completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        let mut client = cdht::Dht::new(cdht::LocalBackend::new(Verifier), Verifier);
        let mut pairs = Vec::new();
        prepared
            .for_each_part(|child, subkey, sequence, bytes| {
                let custody = bootstrap
                    .record(child.map(|index| index as u8))
                    .map_err(|_| crate::CheckpointError::Invalid)?;
                let mut nonce = [0; 24];
                entropy
                    .fill(&mut nonce)
                    .map_err(|_| crate::CheckpointError::Unavailable)?;
                let (descriptor, value) = custody
                    .publication(subkey, sequence, bytes, nonce)
                    .map_err(|_| crate::CheckpointError::Invalid)?;
                retain_pair(&mut client, &mut pairs, subkey, descriptor, value)
                    .map_err(|_| crate::CheckpointError::Invalid)
            })
            .map_err(|_| InitialError::Invalid)?;
        let mut nonce = [0; 24];
        entropy.fill(&mut nonce).map_err(InitialError::Keys)?;
        let (descriptor, value) = bootstrap
            .passkey_publication(&opening.prf, 2, &packed_recovery, nonce)
            .map_err(InitialError::Keys)?;
        retain_pair(&mut client, &mut pairs, 0, descriptor, value)?;
        let recovery = Recovery {
            pairs,
            state: client.state().clone(),
        };
        let bytes = serde_json::to_vec(&recovery).map_err(|_| InitialError::Invalid)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        let outputs = recovery.outputs()?;
        completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        let committed = store
            .commit_with_receipt(
                store.version().map_err(InitialError::Storage)?,
                operation,
                &[cwst::Change::Put {
                    owner: OWNER,
                    key: RECOVERY,
                    value: &bytes,
                }],
                &outputs,
            )
            .await
            .map_err(InitialError::Storage)?;
        if !committed.is_commit(&store, &operation)
            || !committed.contains_record(OWNER, RECOVERY, blake3::hash(&bytes).as_bytes())
        {
            return Err(InitialError::Invalid);
        }
        completion
            .check_current(&mut clock, authority)
            .map_err(InitialError::Keys)?;
        drop(bootstrap);
        drop(completion);
        let pending = inspector
            .pending_creation(&original_keys)
            .map_err(InitialError::Keys)?;
        let result = Self {
            opening,
            backend,
            store,
            pending,
        };
        if result.phase()? != InitialPhase::RecoveryStaged {
            return Err(InitialError::Invalid);
        }
        Ok(result)
    }

    pub(super) fn recovery_state(&self) -> Result<cdht::ClientState, InitialError> {
        if logical_version(&self.store)? != 6 {
            return Err(InitialError::Invalid);
        }
        let bytes = required(&self.store, RECOVERY)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        let recovery: Recovery =
            serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
        let maximum =
            (crate::MAX_CHECKPOINT_RECORDS + 1) * usize::from(crate::CHECKPOINT_SUBKEYS) + 1;
        if recovery.pairs.is_empty() || recovery.pairs.len() > maximum {
            return Err(InitialError::Invalid);
        }
        let mut expected = cdht::Dht::new(cdht::LocalBackend::new(Verifier), Verifier);
        for pair in &recovery.pairs {
            let descriptor = cdht::rpc::DescriptorBytes::from_bytes(pair.descriptor.clone())
                .and_then(|bytes| bytes.decode())
                .map_err(InitialError::Publication)?;
            let value = cdht::rpc::ValueBytes::from_bytes(pair.value.clone())
                .and_then(|bytes| bytes.decode())
                .map_err(InitialError::Publication)?;
            if value.seq != 2
                || !matches!(
                    expected
                        .queue_original(&descriptor, pair.subkey, &value)
                        .map_err(InitialError::Publication)?,
                    cdht::QueuedPublication::Queued
                )
            {
                return Err(InitialError::Invalid);
            }
        }
        if expected.state() != &recovery.state {
            return Err(InitialError::Invalid);
        }
        let outputs = self.store.load_pending().map_err(InitialError::Storage)?;
        let expected_outputs = recovery.outputs()?;
        if outputs.len() != expected_outputs.len() + 2
            || expected_outputs.iter().any(|expected| {
                !outputs
                    .iter()
                    .any(|actual| actual.id == expected.id && actual.bytes == expected.bytes)
            })
        {
            return Err(InitialError::Invalid);
        }
        Ok(recovery.state)
    }
}

fn retain_pair<B: cdht::Backend>(
    client: &mut cdht::Dht<B, Verifier>,
    pairs: &mut Vec<Pair>,
    subkey: u32,
    descriptor: cdht::Descriptor,
    value: cdht::SignedValue,
) -> Result<(), InitialError> {
    if !matches!(
        client
            .queue_original(&descriptor, subkey, &value)
            .map_err(InitialError::Publication)?,
        cdht::QueuedPublication::Queued
    ) {
        return Err(InitialError::Invalid);
    }
    pairs.push(Pair {
        subkey,
        descriptor: cdht::rpc::DescriptorBytes::encode(&descriptor)
            .map_err(InitialError::Publication)?
            .as_bytes()
            .to_vec(),
        value: cdht::rpc::ValueBytes::encode(&value)
            .map_err(InitialError::Publication)?
            .as_bytes()
            .to_vec(),
    });
    Ok(())
}
impl Recovery {
    fn outputs(&self) -> Result<Vec<cwst::Output>, InitialError> {
        self.pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| {
                let mut id = [0; 32];
                id[0] = 3;
                id[24..].copy_from_slice(&(index as u64).to_be_bytes());
                Ok(cwst::Output {
                    id,
                    bytes: serde_json::to_vec(pair).map_err(|_| InitialError::Invalid)?,
                })
            })
            .collect()
    }
}
