//! One original transport output, then its actual durable owner transaction.
use super::recovery_publication::Pair;
use super::*;
use crate::records::tor::Verifier;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Progress {
    pub(super) state: cdht::ClientState,
    pub(super) checked_at: u64,
}

impl<B: Backend> InitialCreation<B> {
    /// Attempt only the oldest original recovery output. Actual authenticated
    /// outcomes/floors commit before another output can be attempted. No report
    /// implies quorum recovery, output acknowledgment or a usable Vault.
    pub async fn publish_next_recovery<N: cdht::Network + Clone>(
        mut self,
        network: N,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<(Self, cdht::FlushReport), InitialError> {
        if !matches!(
            self.phase()?,
            InitialPhase::RecoveryStaged | InitialPhase::RecoveryProgress
        ) {
            return Err(InitialError::Invalid);
        }
        let (state, conflict, floor) = self.recovery_progress()?;
        if conflict || state.queue().is_empty() {
            return Err(InitialError::Invalid);
        }
        let mut clock = CompletionClock { clock, floor };
        let mut checked = self.acknowledged_recovery(&mut clock, authority).await?;
        self.validate_recovery_outputs(&checked, network.clone())?;
        self.current_recovery_checkpoint().await?;
        let checked_floor = checked.check_current(&mut clock, authority)?;
        let mut client = cdht::Dht::with_state(
            cdht::NetworkBackend::new(network, Verifier),
            Verifier,
            state.clone(),
        );
        if client.state() != &state {
            return Err(InitialError::Invalid);
        }
        // Original one-output stepping prevents a later backend await from
        // hiding this write's authenticated newer/equal-sequence conflict.
        let report = client
            .flush_one()
            .await
            .map_err(InitialError::Publication)?;
        if report.written + report.stale.len() > 1 {
            return Err(InitialError::Invalid);
        }
        if report.written + report.stale.len() == 0 {
            if client.state() != &state || report.remaining != state.queue().len() {
                return Err(InitialError::Invalid);
            }
            checked.check_current(&mut clock, authority)?;
            return Ok((self, report));
        }
        // Persist authenticated transport facts even if the fresh authority has
        // expired during that await. This cannot sign or emit any further data;
        // withholding a result must not erase an already-observed sequence floor.
        let observed_at = clock.now().map_err(InitialError::Keys);
        let progress = Progress {
            state: client.state().clone(),
            checked_at: observed_at
                .as_ref()
                .copied()
                .unwrap_or(checked_floor)
                .max(checked_floor),
        };
        let bytes = serde_json::to_vec(&progress).map_err(|_| InitialError::Invalid)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        self.validate_progress(&progress, logical_version(&self.store)? + 1)?;
        let operation = *self.receipt().operation.as_bytes();
        let receipt = self
            .store
            .commit_with_receipt(
                self.store.version().map_err(InitialError::Storage)?,
                operation,
                &[cwst::Change::Put {
                    owner: OWNER,
                    key: RECOVERY_PROGRESS,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        if !receipt.is_commit(&self.store, &operation)
            || !receipt.contains_record(OWNER, RECOVERY_PROGRESS, blake3::hash(&bytes).as_bytes())
        {
            return Err(InitialError::Invalid);
        }
        observed_at?;
        checked.check_current(&mut clock, authority)?;
        self.recovery_progress()?;
        Ok((self, report))
    }

    /// Number of exact original outputs still present in the authenticated
    /// durable queue. This is progress only, never delivery or member authority.
    pub fn pending_recovery_outputs(&self) -> Result<usize, InitialError> {
        if !matches!(
            self.phase()?,
            InitialPhase::RecoveryStaged | InitialPhase::RecoveryProgress
        ) {
            return Err(InitialError::Invalid);
        }
        let (state, conflict, _) = self.recovery_progress()?;
        if conflict {
            return Err(InitialError::Invalid);
        }
        Ok(state.queue().len())
    }

    pub(super) fn recovery_progress(&self) -> Result<(cdht::ClientState, bool, u64), InitialError> {
        let version = logical_version(&self.store)?;
        if version == 6 {
            let intent = decode_intent(required(&self.store, INTENT)?)?;
            return Ok((self.recovery_state()?, false, intent.prepared_at));
        }
        let bytes = required(&self.store, RECOVERY_PROGRESS)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Invalid);
        }
        let progress: Progress =
            serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
        let conflict = self.validate_progress(&progress, version)?;
        Ok((progress.state, conflict, progress.checked_at))
    }

    fn validate_progress(&self, progress: &Progress, version: u64) -> Result<bool, InitialError> {
        let original = self.retained_recovery()?;
        let removed = original
            .state
            .queue()
            .len()
            .checked_sub(progress.state.queue().len())
            .ok_or(InitialError::Invalid)?;
        if removed == 0
            || version != 6 + removed as u64
            || progress.state.queue() != &original.state.queue()[removed..]
            || progress.checked_at < decode_intent(required(&self.store, INTENT)?)?.prepared_at
        {
            return Err(InitialError::Invalid);
        }
        let mut validated = cdht::Dht::with_state(
            cdht::LocalBackend::new(Verifier),
            Verifier,
            progress.state.clone(),
        );
        if validated.state() != &progress.state {
            return Err(InitialError::Invalid);
        }
        let mut conflict = false;
        for pair in &original.pairs {
            let (descriptor, value) = decode(pair)?;
            let (owner, schema) = validated
                .schema(&descriptor.key())
                .map_err(InitialError::Publication)?;
            if owner != descriptor.owner || schema.compile() != descriptor.schema {
                return Err(InitialError::Invalid);
            }
            if matches!(
                validated
                    .queue_original(&descriptor, pair.subkey, &value)
                    .map_err(InitialError::Publication)?,
                cdht::QueuedPublication::Conflict(_)
            ) {
                conflict = true;
            }
        }
        Ok(conflict)
    }

    fn validate_recovery_outputs<N: cdht::Network + Clone>(
        &self,
        checked: &super::acknowledged::AcknowledgedRecovery,
        network: N,
    ) -> Result<(), InitialError> {
        let original = self.retained_recovery()?;
        let root = crate::TorReadRecord::checkpoint(
            network.clone(),
            checked.bootstrap.record(None).map_err(InitialError::Keys)?,
        )
        .and_then(cdht::runtime::Record::new)
        .map_err(InitialError::Publication)?;
        let mut children = Vec::new();
        for index in 0..crate::MAX_CHECKPOINT_RECORDS {
            children.push(
                crate::TorReadRecord::checkpoint(
                    network.clone(),
                    checked
                        .bootstrap
                        .record(Some(index as u8))
                        .map_err(InitialError::Keys)?,
                )
                .and_then(cdht::runtime::Record::new)
                .map_err(InitialError::Publication)?,
            );
        }
        let records = crate::CompoundRecords::new(&self.opening.scope, root, children)
            .map_err(|_| InitialError::Invalid)?;
        let prepared = records
            .prepare(&checked.inner, &self.opening.scope)
            .map_err(|_| InitialError::Invalid)?;
        drop(records);
        let mut pairs = original.pairs.iter();
        prepared
            .for_each_part(|child, subkey, sequence, packed| {
                let pair = pairs.next().ok_or(crate::CheckpointError::Invalid)?;
                let (descriptor, value) =
                    decode(pair).map_err(|_| crate::CheckpointError::Invalid)?;
                let custody = checked
                    .bootstrap
                    .record(child.map(|index| index as u8))
                    .map_err(|_| crate::CheckpointError::Invalid)?;
                if pair.subkey != subkey
                    || value.seq != sequence
                    || descriptor.owner != *custody.public_key().value()
                    || descriptor.schema
                        != cdht::Schema::dflt(32)
                            .map_err(|_| crate::CheckpointError::Invalid)?
                            .compile()
                {
                    return Err(crate::CheckpointError::Invalid);
                }
                let nonce = value.nonce.ok_or(crate::CheckpointError::Invalid)?;
                let plaintext = custody
                    .with_record(|_, cipher| cipher.crypt(&nonce, &value.data))
                    .map_err(|_| crate::CheckpointError::Invalid)?;
                if plaintext.as_slice() != packed {
                    return Err(crate::CheckpointError::Invalid);
                }
                Ok(())
            })
            .map_err(|_| InitialError::Invalid)?;
        let pair = pairs.next().ok_or(InitialError::Invalid)?;
        let (descriptor, value) = decode(pair)?;
        let reader = checked
            .bootstrap
            .passkey_reader(&self.opening.prf)
            .map_err(InitialError::Keys)?;
        if pairs.next().is_some()
            || pair.subkey != 0
            || value.seq != 2
            || descriptor.owner != *reader.owner().value()
            || descriptor.schema
                != cdht::Schema::dflt(1)
                    .map_err(InitialError::Publication)?
                    .compile()
        {
            return Err(InitialError::Invalid);
        }
        let nonce = value.nonce.ok_or(InitialError::Invalid)?;
        let plaintext = reader
            .with_cipher(|cipher| cipher.crypt(&nonce, &value.data))
            .map_err(InitialError::Keys)?;
        let packed = crate::records::pack_recovery(
            required(&self.store, ACKNOWLEDGED_KEYS)?,
            &checked.evidence,
        )
        .map_err(InitialError::Records)?;
        if plaintext.as_slice() != packed.as_slice() {
            return Err(InitialError::Invalid);
        }
        Ok(())
    }

    pub(super) async fn current_recovery_checkpoint(&self) -> Result<(), InitialError> {
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
        Ok(())
    }
}

fn decode(pair: &Pair) -> Result<(cdht::Descriptor, cdht::SignedValue), InitialError> {
    let descriptor = cdht::rpc::DescriptorBytes::from_bytes(pair.descriptor.clone())
        .and_then(|bytes| bytes.decode())
        .map_err(InitialError::Publication)?;
    let value = cdht::rpc::ValueBytes::from_bytes(pair.value.clone())
        .and_then(|bytes| bytes.decode())
        .map_err(InitialError::Publication)?;
    let schema = descriptor
        .validate(&Verifier)
        .map_err(InitialError::Publication)?;
    value
        .validate(
            &descriptor.key(),
            &descriptor.owner,
            &schema,
            pair.subkey,
            &Verifier,
        )
        .map_err(InitialError::Publication)?;
    Ok((descriptor, value))
}
