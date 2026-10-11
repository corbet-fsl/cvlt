//! Retire the temporary outer Store only after genuine original recovery reads.
use super::acknowledged::AcknowledgedRecovery;
use super::*;

// One bounded authenticated selection slot. Publication progress and its outbox
// remain untouched; this is a read observation, never authority to publish.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    base_version: u64,
    revision: u64,
    state: cdht::ClientState,
    checked_at: u64,
    inner_digest: [u8; 32],
    inner_version: u64,
    keys_digest: [u8; 32],
    passkey_sequence: u32,
}

fn decode_selection(bytes: &[u8]) -> Result<Selection, InitialError> {
    if bytes.len() > cwst::MAX_VALUE_BYTES {
        return Err(InitialError::Invalid);
    }
    let selection: Selection = serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
    let client = cdht::Dht::with_state(
        cdht::LocalBackend::new(crate::records::tor::Verifier),
        crate::records::tor::Verifier,
        selection.state.clone(),
    );
    if selection.revision == 0
        || selection.inner_version < 2
        || selection.passkey_sequence < 2
        || selection.inner_digest == [0; 32]
        || selection.keys_digest == [0; 32]
        || !selection.state.queue().is_empty()
        || client.state() != &selection.state
        || selection.state == cdht::ClientState::default()
    {
        return Err(InitialError::Invalid);
    }
    Ok(selection)
}

// Derive the preselection generation from the actual retained record shapes.
// Serialized base_version alone cannot conceal missing/changed progress.
pub(super) fn selected_base<B: Backend>(
    store: &cwst::Store<B>,
    raw_version: u64,
) -> Result<u64, InitialError> {
    let Some(bytes) = store
        .read(OWNER, RETIREMENT_SELECTION)
        .map_err(InitialError::Storage)?
    else {
        return Ok(raw_version);
    };
    let selection = decode_selection(bytes)?;
    let carried = required(store, CARRIED_INNER)?;
    if carried.is_empty()
        || carried.len() > cwst::MAX_VALUE_BYTES
        || blake3::hash(carried).as_bytes() != &selection.inner_digest
    {
        return Err(InitialError::Invalid);
    }
    required(store, ACKNOWLEDGED_INNER)?;
    required(store, ACKNOWLEDGED_KEYS)?;
    let recovery = store.read(OWNER, RECOVERY).map_err(InitialError::Storage)?;
    let progress = store
        .read(OWNER, RECOVERY_PROGRESS)
        .map_err(InitialError::Storage)?;
    let base = match (recovery, progress) {
        (None, None) => 5,
        (Some(_), None) => 6,
        (Some(bytes), Some(progress)) => {
            if bytes.len() > cwst::MAX_VALUE_BYTES || progress.len() > cwst::MAX_VALUE_BYTES {
                return Err(InitialError::Invalid);
            }
            let original: super::recovery_publication::Recovery =
                serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
            let progress: super::recovery_transport::Progress =
                serde_json::from_slice(progress).map_err(|_| InitialError::Invalid)?;
            let removed = original
                .state
                .queue()
                .len()
                .checked_sub(progress.state.queue().len())
                .ok_or(InitialError::Invalid)?;
            if removed == 0
                || progress.state.queue() != &original.state.queue()[removed..]
                || selection.checked_at < progress.checked_at
            {
                return Err(InitialError::Invalid);
            }
            6u64.checked_add(u64::try_from(removed).map_err(|_| InitialError::Invalid)?)
                .ok_or(InitialError::Invalid)?
        }
        _ => return Err(InitialError::Invalid),
    };
    if selection.base_version != base
        || base.checked_add(selection.revision) != Some(raw_version)
        || selection.checked_at < decode_intent(required(store, INTENT)?)?.prepared_at
    {
        return Err(InitialError::Invalid);
    }
    Ok(base)
}

/// The actual backend accepted the authenticated common-root checkpoint.
/// This carries no usable Vault or current authority: ordinary recovery must
/// still obtain current Charter and normal owners before opening that backend.
pub struct RetiredInitial {
    opening: PreparedOpen,
    checkpoint: crate::RecordCheckpoint,
}
impl std::fmt::Debug for RetiredInitial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetiredInitial([redacted])")
    }
}
impl RetiredInitial {
    /// Join the exact observed recovery record to the existing ordinary recovery
    /// preparation. This does not reuse the earlier authority result or create.
    pub fn prepare_recovery(
        self,
        current: &cchr::VerifiedCharter,
        expected_member: &str,
        now: u64,
    ) -> Result<crate::RecoveryCandidate, OpenError> {
        self.opening
            .prepare_recovery(&self.checkpoint, current, expected_member, now)
    }
}

impl<B: Backend> InitialCreation<B> {
    /// Force original per-passkey and compound Records consensus, authenticate
    /// their actual Store and the retained creation receipt, then replace only
    /// this exact temporary outer checkpoint through the original backend CAS.
    ///
    /// A different valid same-root checkpoint may win a cloned-store race. Its
    /// actual signed recovery record and authenticated Store are decisive; local
    /// ciphertext equality is not authority. Missing/partial/stale reads refuse.
    /// Cancellation or unknown CAS returns no handle. After a committed CAS,
    /// reopening uses ordinary original recovery, never another Create. Actual
    /// winner observations first commit in a separate bounded selection slot;
    /// only those committed observations survive a restart.
    pub async fn retire_recovery<N: cdht::Network + Clone>(
        mut self,
        network: N,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<RetiredInitial, InitialError> {
        let phase = self.phase()?;
        if !matches!(
            phase,
            InitialPhase::Acknowledged
                | InitialPhase::RecoveryStaged
                | InitialPhase::RecoveryProgress
                | InitialPhase::RecoveryDiverged
                | InitialPhase::RetirementSelected
        ) {
            return Err(InitialError::Invalid);
        }
        let previous = self
            .store
            .read(OWNER, RETIREMENT_SELECTION)
            .map_err(InitialError::Storage)?
            .map(decode_selection)
            .transpose()?;
        let (floors, mut floor) = if logical_version(&self.store)? == 5 {
            (
                cdht::ClientState::default(),
                decode_intent(required(&self.store, INTENT)?)?.prepared_at,
            )
        } else {
            let (state, _, floor) = self.recovery_progress()?;
            (state, floor)
        };
        let selection_floors = previous
            .as_ref()
            .map(|selection| selection.state.clone())
            .unwrap_or_default();
        if let Some(selection) = &previous {
            floor = floor.max(selection.checked_at);
        }
        let observations = crate::records::tor::ReadObservations::default();
        let mut clock = CompletionClock { clock, floor };
        let mut historical = self.acknowledged_recovery(&mut clock, authority).await?;
        self.current_recovery_checkpoint().await?;
        historical.check_current(&mut clock, authority)?;
        let reader = historical
            .bootstrap
            .passkey_reader(&self.opening.prf)
            .map_err(InitialError::Keys)?;
        let passkey = crate::TorPasskeyRecord::open(network.clone(), reader)
            .await
            .map_err(InitialError::Publication)?
            .with_state_floors(&floors)
            .and_then(|record| record.with_state_floors(&selection_floors))
            .map(|record| record.with_observations(&observations))
            .map_err(InitialError::Publication)?;
        let mut records = crate::PasskeyRecords::new(
            self.opening.locator,
            cdht::runtime::Record::new(passkey).map_err(InitialError::Publication)?,
        )
        .map_err(InitialError::Records)?;
        let checkpoint = records
            .checkpoint(&self.opening.locator)
            .await
            .map_err(InitialError::Records)?;
        drop(records);
        historical.check_current(&mut clock, authority)?;
        let evidence = checkpoint.evidence().ok_or(InitialError::Invalid)?;
        if !evidence.matches_receipt(self.receipt()) || checkpoint.sequence() < 2 {
            return Err(InitialError::Invalid);
        }
        let evidence_bytes = evidence.to_bytes().map_err(|_| InitialError::Invalid)?;
        let evidence = crate::LineageEvidence::from_bytes(&evidence_bytes)
            .map_err(|_| InitialError::Invalid)?;
        // This checks the actual network winner through ordinary nonpending
        // checkpoint authority, rather than assigning authority from its bytes.
        let bootstrap = self
            .opening
            .inspector()
            .map_err(InitialError::Open)?
            .bootstrap(checkpoint.sealed(), &evidence_bytes, &mut clock, authority)
            .await
            .map_err(InitialError::Keys)?;
        if bootstrap.inspection().lineage()
            != self
                .receipt()
                .attested_lineage()
                .map_err(InitialError::Keys)?
                .0
            || bootstrap.inspection().revision() < 2
        {
            return Err(InitialError::Invalid);
        }
        drop(historical);
        let retained = {
            let root = crate::TorReadRecord::checkpoint(
                network.clone(),
                bootstrap.record(None).map_err(InitialError::Keys)?,
            )
            .and_then(|record| record.with_state_floors(&floors))
            .and_then(|record| record.with_state_floors(&selection_floors))
            .map(|record| record.with_observations(&observations))
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
                    .and_then(|record| record.with_state_floors(&floors))
                    .and_then(|record| record.with_state_floors(&selection_floors))
                    .map(|record| record.with_observations(&observations))
                    .and_then(cdht::runtime::Record::new)
                    .map_err(InitialError::Publication)?,
                );
            }
            let mut records = crate::CompoundRecords::new(&self.opening.scope, root, children)
                .map_err(|_| InitialError::Invalid)?;
            records
                .checkpoint()
                .await
                .map_err(|_| InitialError::Records(crate::RecordError::Unavailable))?
        };
        let inner = retained
            .restore(
                cwst::backend::Memory::new(),
                bootstrap.store_cipher().map_err(InitialError::Keys)?,
                &self.opening.scope,
            )
            .await
            .map_err(|_| InitialError::Invalid)?;
        if inner.version().map_err(InitialError::Storage)? < 2
            || inner
                .read("keys", self.opening.locator.as_bytes())
                .map_err(InitialError::Storage)?
                != Some(checkpoint.sealed())
        {
            return Err(InitialError::Invalid);
        }
        let operation = *self.receipt().operation.as_bytes();
        let retained_evidence = crate::LineageEvidence::load(&inner, &operation)
            .map_err(|_| InitialError::Invalid)?
            .ok_or(InitialError::Invalid)?;
        if !retained_evidence.matches_receipt(self.receipt())
            || retained_evidence
                .to_bytes()
                .map_err(|_| InitialError::Invalid)?
                != evidence_bytes
            || (inner.version().map_err(InitialError::Storage)? == 2
                && inner.operation().map_err(InitialError::Storage)? != operation)
        {
            return Err(InitialError::Invalid);
        }
        if self
            .store
            .read(OWNER, ENROLLMENT)
            .map_err(InitialError::Storage)?
            .is_some()
        {
            let provenance = evidence
                .initial_acknowledgment(
                    &self.opening.inspector().map_err(InitialError::Open)?,
                    checkpoint.sealed(),
                )
                .map_err(InitialError::Open)?;
            if provenance.seed() != self.enrollment_commitment()?
                || provenance.publication() != self.publication_commitment()?
            {
                return Err(InitialError::Invalid);
            }
            crate::retention::check_initial_ack(&inner, &provenance)
                .map_err(InitialError::Storage)?;
        }
        let checked_at = bootstrap.checked_at();
        let mut selected = AcknowledgedRecovery {
            bootstrap,
            inner,
            evidence,
            checked_at: Some(checked_at),
        };
        let source_digest = *blake3::hash(
            selected
                .inner
                .sealed_checkpoint()
                .map_err(InitialError::Storage)?,
        )
        .as_bytes();
        let source_version = selected.inner.version().map_err(InitialError::Storage)?;
        // Completed/stale publication outcomes are already durable in the outer
        // progress state, including slots a later smaller winner does not read.
        // Preserve them; still-queued exact intent bytes grant no read fact.
        observations
            .retain_completed(&floors)
            .map_err(InitialError::Publication)?;
        if let Some(source) =
            crate::read_floors::load(&selected.inner).map_err(InitialError::Storage)?
        {
            // A genuine later winner may already carry durable observations of
            // slots outside this read. Preserve every original signed floor.
            clock.floor = clock.floor.max(source.checked_at);
            observations
                .retain_state(&source.state)
                .map_err(InitialError::Publication)?;
        }
        if previous.is_some() {
            observations
                .retain_state(&selection_floors)
                .map_err(InitialError::Publication)?;
        }
        let state = observations
            .state(&cdht::ClientState::default())
            .await
            .map_err(InitialError::Publication)?;
        self.current_recovery_checkpoint().await?;
        let mut checked_at = selected.check_current(&mut clock, authority)?;
        let mut reuse = false;
        if let Some(previous) = &previous {
            let prior = cwst::Store::restore_checked(
                cwst::backend::Memory::new(),
                selected
                    .bootstrap
                    .store_cipher()
                    .map_err(InitialError::Keys)?,
                &self.opening.scope,
                previous.inner_version,
                required(&self.store, CARRIED_INNER)?,
                |inner| {
                    if inner
                        .read("keys", self.opening.locator.as_bytes())?
                        .is_none_or(|keys| blake3::hash(keys).as_bytes() != &previous.keys_digest)
                    {
                        return Err(cwst::Error::Corrupt);
                    }
                    Ok(())
                },
            )
            .await
            .map_err(InitialError::Storage)?;
            checked_at = selected.check_current(&mut clock, authority)?;
            let prior_evidence =
                crate::LineageEvidence::load(&prior, self.receipt().operation.as_bytes())
                    .map_err(|_| InitialError::Invalid)?
                    .ok_or(InitialError::Invalid)?;
            if !prior_evidence.matches_receipt(self.receipt())
                || prior_evidence
                    .to_bytes()
                    .map_err(|_| InitialError::Invalid)?
                    != evidence_bytes
            {
                return Err(InitialError::Invalid);
            }
            let carrier = crate::read_floors::load(&prior)
                .map_err(InitialError::Storage)?
                .ok_or(InitialError::Invalid)?;
            if carrier.state != previous.state || carrier.checked_at != previous.checked_at {
                return Err(InitialError::Invalid);
            }
            if carrier.source_digest == source_digest && carrier.source_version == source_version {
                reuse = state == carrier.state && checked_at == carrier.checked_at;
                // The exact already-durable carrier is the base of any renewal;
                // never recreate version three with different plaintext bytes.
                selected.inner = prior;
            } else if source_version < prior.version().map_err(InitialError::Storage)? {
                return Err(InitialError::Invalid);
            }
        }
        if !reuse {
            let carrier = crate::read_floors::Carrier {
                state: state.clone(),
                checked_at,
                source_digest,
                source_version,
            };
            let carrier_bytes = carrier.bytes().map_err(InitialError::Storage)?;
            let expected = selected.inner.version().map_err(InitialError::Storage)?;
            selected
                .inner
                .commit(
                    expected,
                    *self.receipt().operation.as_bytes(),
                    &[cwst::Change::Put {
                        owner: crate::read_floors::OWNER,
                        key: crate::read_floors::KEY,
                        value: &carrier_bytes,
                    }],
                    &[],
                )
                .await
                .map_err(InitialError::Storage)?;
            // This Memory commit is preparation, not durable acceptance. Exact
            // carrier ciphertext joins the following real outer Store CAS.
            selected.check_current(&mut clock, authority)?;
        }
        let carried_wire = selected
            .inner
            .sealed_checkpoint()
            .map_err(InitialError::Storage)?
            .to_vec();
        let selection = Selection {
            base_version: logical_version(&self.store)?,
            revision: previous.as_ref().map_or(Ok(1), |previous| {
                previous
                    .revision
                    .checked_add(1)
                    .ok_or(InitialError::Invalid)
            })?,
            state,
            checked_at,
            inner_digest: *blake3::hash(
                selected
                    .inner
                    .sealed_checkpoint()
                    .map_err(InitialError::Storage)?,
            )
            .as_bytes(),
            inner_version: selected.inner.version().map_err(InitialError::Storage)?,
            keys_digest: *blake3::hash(checkpoint.sealed()).as_bytes(),
            passkey_sequence: checkpoint.sequence(),
        };
        if previous.as_ref().is_some_and(|previous| {
            selection.passkey_sequence < previous.passkey_sequence
                || (selection.passkey_sequence == previous.passkey_sequence
                    && selection.keys_digest != previous.keys_digest)
                || selection.inner_version < previous.inner_version
        }) {
            return Err(InitialError::Invalid);
        }
        let bytes = serde_json::to_vec(&selection).map_err(|_| InitialError::Invalid)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        let operation = *self.receipt().operation.as_bytes();
        let receipt = self
            .store
            .commit_with_receipt(
                self.store.version().map_err(InitialError::Storage)?,
                operation,
                &[
                    cwst::Change::Put {
                        owner: OWNER,
                        key: RETIREMENT_SELECTION,
                        value: &bytes,
                    },
                    cwst::Change::Put {
                        owner: OWNER,
                        key: CARRIED_INNER,
                        value: &carried_wire,
                    },
                ],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        if !receipt.is_commit(&self.store, &operation)
            || !receipt.contains_record(
                OWNER,
                RETIREMENT_SELECTION,
                blake3::hash(&bytes).as_bytes(),
            )
            || !receipt.contains_record(
                OWNER,
                CARRIED_INNER,
                blake3::hash(&carried_wire).as_bytes(),
            )
            || self.phase()? != InitialPhase::RetirementSelected
        {
            return Err(InitialError::Invalid);
        }
        selected.check_current(&mut clock, authority)?;
        // Only committed selection facts survive a restart. A cancellation before
        // that CAS promises no durable selection; an unknown CAS consumes self.
        // Memory validation is not a durable receipt. Only this original opaque
        // backend CAS can replace the exact authenticated outer with the actual
        // independently authenticated common-root checkpoint selected above.
        self.backend
            .compare_exchange(
                Some(
                    self.store
                        .sealed_checkpoint()
                        .map_err(InitialError::Storage)?,
                ),
                selected
                    .inner
                    .sealed_checkpoint()
                    .map_err(InitialError::Storage)?,
            )
            .await
            .map_err(InitialError::Storage)?;
        selected.check_current(&mut clock, authority)?;
        drop(selected);
        Ok(RetiredInitial {
            opening: self.opening,
            checkpoint,
        })
    }
}
