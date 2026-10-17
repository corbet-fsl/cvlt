//! The member's per-epoch record: Wallet keeps the epoch presentation key and the
//! cached proof (decided 2026-10-05: proven once per epoch in the background, cached
//! in the vault, bound to each relying party's challenge in milliseconds).
//!
//! Proving happens outside these calls: `begin_record_epoch` persists the epoch key
//! and returns its public half, the caller proves without holding the Store, and
//! `finish_record_epoch` commits the verified prover output.
use super::*;
use cwlt::record::{Context, DurableRecord, Epoch, Presentation, Record};

/// A wallet type that can hold the record owner. Wallets without record custody
/// (`()`) refuse every record operation.
pub trait RecordSlot {
    /// The record owner slot, or `None` when this wallet type keeps no records.
    fn record_slot(&mut self) -> Option<&mut Option<DurableRecord>>;
}
impl RecordSlot for () {
    fn record_slot(&mut self) -> Option<&mut Option<DurableRecord>> {
        None
    }
}
impl RecordSlot for WalletCustody {
    fn record_slot(&mut self) -> Option<&mut Option<DurableRecord>> {
        Some(&mut self.record)
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W: RecordSlot>
    Vault<B, C, E, A, R, W>
{
    /// Persist (or keep) this epoch's presentation key before background proving and
    /// return its public half. The first call in a community Store creates the record
    /// owner explicitly; later calls open the committed one.
    pub async fn begin_record_epoch(
        &mut self,
        epoch: &Epoch,
        owner: [u8; 32],
        now: u64,
        operation: [u8; 32],
    ) -> Result<[u8; 32], WalletRestoreError> {
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        let community = self.record_scope(&store).await?;
        if self
            .wallet
            .record_slot()
            .ok_or(WalletRestoreError::Scope)?
            .is_none()
        {
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            let record = match DurableRecord::open(engine, &store, &community) {
                Ok(record) => record,
                Err(_) => {
                    let engine = self
                        .keys
                        .wallet_engine()
                        .await
                        .map_err(WalletRestoreError::Keys)?;
                    DurableRecord::create(engine, &mut store, &community, operation)
                        .await
                        .map_err(WalletRestoreError::Record)?
                }
            };
            *self.wallet.record_slot().ok_or(WalletRestoreError::Scope)? = Some(record);
        }
        let record = self
            .wallet
            .record_slot()
            .and_then(Option::as_mut)
            .ok_or(WalletRestoreError::Scope)?;
        let public = record
            .begin_epoch(&mut store, epoch, owner, now, operation)
            .await
            .map_err(WalletRestoreError::Record)?;
        drop(store);
        self.same_record_scope(&community).await?;
        Ok(public)
    }

    /// Commit the prover's output for the begun epoch; presentations become available.
    pub async fn finish_record_epoch(
        &mut self,
        record: Record,
        proof: String,
        operation: [u8; 32],
    ) -> Result<(), WalletRestoreError> {
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        let community = self.record_scope(&store).await?;
        self.wallet
            .record_slot()
            .and_then(Option::as_mut)
            .ok_or(WalletRestoreError::Scope)?
            .finish_epoch(&mut store, record, proof, operation)
            .await
            .map_err(WalletRestoreError::Record)?;
        drop(store);
        self.same_record_scope(&community).await
    }

    /// Is a proof cached for exactly this epoch? Never proves or waits.
    pub async fn record_ready(
        &mut self,
        epoch: &Epoch,
        now: u64,
    ) -> Result<bool, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let community = self.record_scope(&store).await?;
        let ready = match self.wallet.record_slot().ok_or(WalletRestoreError::Scope)? {
            Some(record) => record
                .ready(&store, epoch, now)
                .map_err(WalletRestoreError::Record)?,
            None => false,
        };
        drop(store);
        self.same_record_scope(&community).await?;
        Ok(ready)
    }

    /// Bind the cached epoch record to a relying party's context (milliseconds).
    pub async fn present_record(
        &mut self,
        epoch: &Epoch,
        context: &Context,
        now: u64,
    ) -> Result<Presentation, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let community = self.record_scope(&store).await?;
        let presentation = self
            .wallet
            .record_slot()
            .and_then(|slot| slot.as_ref())
            .ok_or(WalletRestoreError::Scope)?
            .present(&store, epoch, context, now)
            .map_err(WalletRestoreError::Record)?;
        drop(store);
        self.same_record_scope(&community).await?;
        Ok(presentation)
    }

    /// The community of the current Keys lineage; the locked Store must be its scope.
    async fn record_scope(&mut self, store: &Store<B>) -> Result<String, WalletRestoreError> {
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() == "wallet" || !store.is_scope(binding.community()) {
            return Err(WalletRestoreError::Scope);
        }
        Ok(binding.community().to_owned())
    }

    async fn same_record_scope(&mut self, community: &str) -> Result<(), WalletRestoreError> {
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() != community {
            return Err(WalletRestoreError::Scope);
        }
        Ok(())
    }
}
