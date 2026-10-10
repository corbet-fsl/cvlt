//! Durable staging of the one original signed genesis publication.
use super::*;
use crate::records::tor::Verifier;

/// A private original publication client, available only after its complete
/// ClientState has committed in the original encrypted Store. No signer, cipher,
/// arbitrary client mutation or Keys acknowledgment is exposed.
pub struct InitialPublication<B: Backend, R: cdht::Backend> {
    creation: InitialCreation<B>,
    client: cdht::Dht<R, Verifier>,
}
impl<B: Backend, R: cdht::Backend> std::fmt::Debug for InitialPublication<B, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InitialPublication([redacted])")
    }
}

impl<B: Backend> InitialCreation<B> {
    /// Commit the exact original signed pair through the original client's
    /// queue before returning any network-capable publication handle. Failure,
    /// cancellation and uncertain CAS consume this attempt; reopen the durable
    /// original phase instead of making another intent or signing again.
    pub async fn stage<R: cdht::Backend>(
        mut self,
        records: R,
    ) -> Result<InitialPublication<B, R>, InitialError> {
        if self.phase()? != InitialPhase::Retained {
            return Err(InitialError::Invalid);
        }
        let retained = self.retained()?;
        let descriptor = retained
            .descriptor
            .decode()
            .map_err(InitialError::Publication)?;
        let value = retained.value.decode().map_err(InitialError::Publication)?;
        let mut client = cdht::Dht::new(records, Verifier);
        if !matches!(
            client
                .queue_original(&descriptor, 0, &value)
                .map_err(InitialError::Publication)?,
            cdht::QueuedPublication::Queued
        ) {
            return Err(InitialError::Invalid);
        }
        let bytes = serde_json::to_vec(client.state()).map_err(|_| InitialError::Invalid)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        self.store
            .commit(
                3,
                *self.pending.receipt().operation.as_bytes(),
                &[cwst::Change::Put {
                    owner: OWNER,
                    key: QUEUE,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .map_err(InitialError::Storage)?;
        self.staged_state()?;
        Ok(InitialPublication {
            creation: self,
            client,
        })
    }

    /// Resume only the durably staged original publication. Original client
    /// revalidation may not discard or normalize any retained state. The exact
    /// queue, descriptor, cached value, nonce and signatures must still match.
    pub fn resume_publication<R: cdht::Backend>(
        self,
        records: R,
    ) -> Result<InitialPublication<B, R>, InitialError> {
        if self.phase()? != InitialPhase::Staged {
            return Err(InitialError::Invalid);
        }
        let state = self.staged_state()?;
        let client = cdht::Dht::with_state(records, Verifier, state.clone());
        if client.state() != &state {
            return Err(InitialError::Invalid);
        }
        Ok(InitialPublication {
            creation: self,
            client,
        })
    }

    pub(super) fn staged_state(&self) -> Result<cdht::ClientState, InitialError> {
        if self.store.version().map_err(InitialError::Storage)? != 4 {
            return Err(InitialError::Invalid);
        }
        let bytes = required(&self.store, QUEUE)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        let state: cdht::ClientState =
            serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
        let retained = self.retained()?;
        let descriptor = retained
            .descriptor
            .decode()
            .map_err(InitialError::Publication)?;
        let value = retained.value.decode().map_err(InitialError::Publication)?;
        // Use the original synchronous client validation, with no transport
        // method called. This expected state contains exactly one original pair.
        let mut expected = cdht::Dht::new(cdht::LocalBackend::new(Verifier), Verifier);
        if !matches!(
            expected
                .queue_original(&descriptor, 0, &value)
                .map_err(InitialError::Publication)?,
            cdht::QueuedPublication::Queued
        ) || expected.state() != &state
        {
            return Err(InitialError::Invalid);
        }
        Ok(state)
    }

    pub(super) fn conflicted_state(&self) -> Result<cdht::ClientState, InitialError> {
        if self.store.version().map_err(InitialError::Storage)? != 5 {
            return Err(InitialError::Invalid);
        }
        let bytes = required(&self.store, QUEUE)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(InitialError::Storage(cwst::Error::TooLarge));
        }
        let state: cdht::ClientState =
            serde_json::from_slice(bytes).map_err(|_| InitialError::Invalid)?;
        self.validate_conflict(&state)?;
        Ok(state)
    }

    fn validate_conflict(&self, state: &cdht::ClientState) -> Result<(), InitialError> {
        let mut validated =
            cdht::Dht::with_state(cdht::LocalBackend::new(Verifier), Verifier, state.clone());
        if validated.state() != state || !state.queue().is_empty() {
            return Err(InitialError::Invalid);
        }
        let retained = self.retained()?;
        let descriptor = retained
            .descriptor
            .decode()
            .map_err(InitialError::Publication)?;
        let value = retained.value.decode().map_err(InitialError::Publication)?;
        // An empty queue alone is not conflict evidence. The original client
        // must authenticate an actual cached value that fences the exact retained
        // pair. This is a disposable validation client and performs no I/O.
        if !matches!(
            validated
                .queue_original(&descriptor, 0, &value)
                .map_err(InitialError::Publication)?,
            cdht::QueuedPublication::Conflict(_)
        ) {
            return Err(InitialError::Invalid);
        }
        Ok(())
    }
}

impl<B: Backend, R: cdht::Backend> InitialPublication<B, R> {
    /// Attempt the exact durably retained publication through the original
    /// backend. A report describes only this transport attempt. It cannot select
    /// lineage, acknowledge Keys or outputs, unlock a Vault or establish readiness.
    ///
    /// The original durable queue remains intact even after an accepted reply.
    /// Only the later forced lineage read and normal owner acknowledgment may
    /// retire that intent. Cancellation or unknown completion can therefore
    /// reopen and retransmit exactly the same signed bytes. A genuine conflicting
    /// observation instead commits its original authenticated client state into
    /// a terminal refusal phase, retaining the original signed outbox unchanged.
    pub async fn flush(mut self) -> Result<(InitialCreation<B>, cdht::FlushReport), InitialError> {
        let committed = self
            .creation
            .store
            .sealed_checkpoint()
            .map_err(InitialError::Storage)?;
        if self
            .creation
            .backend
            .read()
            .await
            .map_err(InitialError::Storage)?
            .as_deref()
            != Some(committed)
        {
            return Err(InitialError::Storage(cwst::Error::Conflict));
        }
        let report = self
            .client
            .flush()
            .await
            .map_err(InitialError::Publication)?;
        if !report.stale.is_empty() {
            let retained = self.creation.retained()?;
            let descriptor = retained
                .descriptor
                .decode()
                .map_err(InitialError::Publication)?;
            if report.written != 0
                || report.remaining != 0
                || report.stale.as_slice() != [(descriptor.key(), 0)]
            {
                return Err(InitialError::Invalid);
            }
            self.creation.validate_conflict(self.client.state())?;
            let bytes =
                serde_json::to_vec(self.client.state()).map_err(|_| InitialError::Invalid)?;
            if bytes.len() > cwst::MAX_VALUE_BYTES {
                return Err(InitialError::Storage(cwst::Error::TooLarge));
            }
            self.creation
                .store
                .commit(
                    4,
                    *self.creation.pending.receipt().operation.as_bytes(),
                    &[cwst::Change::Put {
                        owner: OWNER,
                        key: QUEUE,
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .map_err(InitialError::Storage)?;
            self.creation.conflicted_state()?;
        }
        Ok((self.creation, report))
    }
}
