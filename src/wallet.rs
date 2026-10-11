//! Restore original Wallet custody from one authenticated compound checkpoint.
use crate::{Records, Vault};
use ckmg::{Authority, Clock, Entropy};
use cwst::{Store, backend::Backend};

pub(crate) mod global;
pub use global::GlobalPassportCustody;
pub(crate) mod account;
pub use account::CommunityAccountCustody;

/// Original durable passport and epoch-record owners. No accepted balance,
/// external proof runtime, Wave reservation or release is created by restoration.
/// Their private engines can only be borrowed through fresh Vault authority.
pub struct WalletCustody {
    passport: cwlt::passport::DurableHolder,
    record: cwlt::record::DurableRecord,
}

/// Wallet custody refuses missing owner records and failed authentication.
/// This error carries no passport, seed, record ciphertext or proof material.
#[derive(Debug)]
pub enum WalletRestoreError {
    /// Original Keys did not authorize current custody.
    Keys(ckmg::Error),
    /// Original passport ciphertext or checkpoint was refused.
    Passport(cwlt::passport::PersistenceError),
    /// Original epoch-record ciphertext or checkpoint was refused.
    Record(cwlt::record::Error),
    /// Original pending account capsule or checkpoint was refused.
    Account(cwlt::account_owner::Error),
    /// Vault scope or checkpoint changed during construction.
    Scope,
}
impl std::fmt::Display for WalletRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wallet custody operation refused")
    }
}
impl std::error::Error for WalletRestoreError {}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records> Vault<B, C, E, A, R, ()> {
    /// Consume a recovered original Vault, then open BOTH existing Wallet owner
    /// records. This never creates an owner, writes a checkpoint, or calls an
    /// external prover. The host binds this Vault only after complete success.
    pub async fn restore_wallet_custody(
        mut self,
    ) -> Result<Vault<B, C, E, A, R, WalletCustody>, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if !store.is_scope(binding.community()) {
            return Err(WalletRestoreError::Scope);
        }
        let passport = self
            .keys
            .with_holder_seed(cwlt::PassportHolder::from_holder_seed)
            .await
            .map_err(WalletRestoreError::Keys)?
            .map_err(WalletRestoreError::Keys)?;
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        let passport = cwlt::passport::DurableHolder::open(passport, &store, binding.community())
            .map_err(WalletRestoreError::Passport)?;
        let record = cwlt::record::DurableRecord::open(engine, &store, binding.community())
            .map_err(WalletRestoreError::Record)?;
        drop(store);
        Ok(Vault {
            keys: self.keys,
            storage: self.storage,
            key_store: self.key_store,
            records: self.records,
            wallet: WalletCustody { passport, record },
        })
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records>
    Vault<B, C, E, A, R, WalletCustody>
{
    async fn authorize_wallet_store(&mut self, store: &Store<B>) -> Result<(), WalletRestoreError> {
        let lineage = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?;
        if !store.is_scope(lineage.binding.community()) {
            return Err(WalletRestoreError::Scope);
        }
        Ok(())
    }

    async fn mutate_passport<
        T,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        rng: &mut G,
        prepare: impl FnOnce(
            &cwlt::passport::DurableHolder,
            &Store<B>,
            &mut G,
        )
            -> Result<cwlt::passport::Pending<T>, cwlt::passport::PersistenceError>,
    ) -> Result<T, WalletRestoreError> {
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        self.authorize_wallet_store(&store).await?;
        let pending =
            prepare(&self.wallet.passport, &store, rng).map_err(WalletRestoreError::Passport)?;
        // Original Pending checks its exact owner record and CAS receipt. No
        // request/finish result can escape before its private state is durable.
        let output = pending
            .commit(&mut self.wallet.passport, &mut store, &[], &[])
            .await
            .map_err(WalletRestoreError::Passport)?;
        // Revocation during persistence suppresses the output. The original
        // committed owner is retained for explicit reconciliation, never rolled
        // back to resurrect an already consumed issuance opening.
        self.authorize_wallet_store(&store).await?;
        Ok(output)
    }

    /// Begin original blind issuance and commit its private opening before
    /// returning the public request. The trusted Foyer composer must obtain the
    /// issuer/challenge from the actual authenticated issuer; JSON cannot install
    /// a holder or an accepted passport through this port.
    pub async fn begin_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
        issuer: &cwlt::passport::IssuerPublicKey,
        challenge: &cwlt::passport::IssuanceChallenge,
    ) -> Result<cwlt::passport::IssuanceRequest, WalletRestoreError> {
        self.mutate_passport(rng, |holder, store, rng| {
            holder.prepare_begin(store, operation, rng, issuer, challenge)
        })
        .await?
        .map_err(|error| WalletRestoreError::Passport(error.into()))
    }

    /// Complete original blind issuance. Even a rejected response consumes and
    /// durably commits the original attempt before its rejection is returned.
    pub async fn finish_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
        response: &cwlt::passport::BlindPassport,
    ) -> Result<(), WalletRestoreError> {
        self.mutate_passport(rng, |holder, store, rng| {
            holder.prepare_finish(store, operation, rng, response)
        })
        .await?
        .map_err(|error| WalletRestoreError::Passport(error.into()))
    }

    /// Cancel the pending issuance opening through its original Store CAS.
    pub async fn cancel_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
    ) -> Result<(), WalletRestoreError> {
        self.mutate_passport(rng, |holder, store, rng| {
            holder.prepare_cancel(store, operation, rng)
        })
        .await
    }

    /// Fresh member authority under the exact original Store guard, then one
    /// synchronous read-only callback. Opaque engines and Store borrows cannot
    /// escape. Original Wallet methods still check their exact committed records.
    pub async fn with_wallet_custody<T>(
        &mut self,
        read: impl for<'owner> FnOnce(
            &'owner cwlt::passport::DurableHolder,
            &'owner cwlt::record::DurableRecord,
            &'owner Store<B>,
        ) -> T,
    ) -> Result<T, ckmg::Error> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self.keys.lineage().await?.binding;
        if !store.is_scope(binding.community()) {
            return Err(ckmg::Error::Unauthorized);
        }
        Ok(read(&self.wallet.passport, &self.wallet.record, &store))
    }
}

#[cfg(test)]
#[path = "../tests/unit/wallet_restore.rs"]
mod wallet_restore_tests;
