//! Global passport custody, isolated from community accounting record owners.
use super::*;

/// Original global passport holder under certified literal-wallet Keys.
/// There is no constructor from a caller passport, community Vault, or missing
/// checkpoint. Initialization belongs to the genuine initial acknowledgment.
pub struct GlobalPassportCustody {
    passport: cwlt::passport::DurableHolder,
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records> Vault<B, C, E, A, R, ()> {
    /// Open the original durable global holder after normal Vault recovery.
    /// Fresh Keys authority must enforce the global certificate, current wallet
    /// eligibility and forced lineage. Missing state refuses instead of creating.
    pub async fn restore_global_passport(
        mut self,
    ) -> Result<Vault<B, C, E, A, R, GlobalPassportCustody>, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let lineage = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?;
        if lineage.binding.community() != "wallet" || !store.is_scope("wallet") {
            return Err(WalletRestoreError::Scope);
        }
        let holder = self
            .keys
            .with_holder_seed(cwlt::PassportHolder::from_holder_seed)
            .await
            .map_err(WalletRestoreError::Keys)?
            .map_err(WalletRestoreError::Keys)?;
        let passport = cwlt::passport::DurableHolder::open(holder, &store, "wallet")
            .map_err(WalletRestoreError::Passport)?;
        drop(store);
        Ok(Vault {
            keys: self.keys,
            storage: self.storage,
            key_store: self.key_store,
            records: self.records,
            wallet: GlobalPassportCustody { passport },
        })
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records>
    Vault<B, C, E, A, R, GlobalPassportCustody>
{
    async fn authorize_global_store(&mut self, store: &Store<B>) -> Result<(), WalletRestoreError> {
        let lineage = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?;
        if lineage.binding.community() != "wallet" || !store.is_scope("wallet") {
            return Err(WalletRestoreError::Scope);
        }
        Ok(())
    }

    async fn mutate_global_passport<T>(
        &mut self,
        prepare: impl FnOnce(
            &cwlt::passport::DurableHolder,
            &Store<B>,
        )
            -> Result<cwlt::passport::Pending<T>, cwlt::passport::PersistenceError>,
    ) -> Result<T, WalletRestoreError> {
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        self.authorize_global_store(&store).await?;
        let pending =
            prepare(&self.wallet.passport, &store).map_err(WalletRestoreError::Passport)?;
        let output = pending
            .commit(&mut self.wallet.passport, &mut store, &[], &[])
            .await
            .map_err(WalletRestoreError::Passport)?;
        // An uncertain CAS leaves the original owner invalid until reopen. A
        // successful CAS followed by revocation stays durable but releases no
        // request or issuer response to the caller.
        self.authorize_global_store(&store).await?;
        Ok(output)
    }

    /// Begin original blind issuance only after its private opening is durable.
    /// The upper composer obtains issuer and challenge from the genuine wallet
    /// HTTPS owner; this method cannot install a caller-provided passport.
    pub async fn begin_global_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
        issuer: &cwlt::passport::IssuerPublicKey,
        challenge: &cwlt::passport::IssuanceChallenge,
    ) -> Result<cwlt::passport::IssuanceRequest, WalletRestoreError> {
        self.mutate_global_passport(|holder, store| {
            holder.prepare_begin(store, operation, rng, issuer, challenge)
        })
        .await?
        .map_err(|error| WalletRestoreError::Passport(error.into()))
    }

    /// Complete signature-verified original blind issuance and atomically retain
    /// its consumed opening, including when the issuer response is refused.
    pub async fn finish_global_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
        response: &cwlt::passport::BlindPassport,
    ) -> Result<(), WalletRestoreError> {
        self.mutate_global_passport(|holder, store| {
            holder.prepare_finish(store, operation, rng, response)
        })
        .await?
        .map_err(|error| WalletRestoreError::Passport(error.into()))
    }

    /// Cancel the original pending issuance through its actual Store receipt.
    pub async fn cancel_global_passport_issuance<
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    >(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
    ) -> Result<(), WalletRestoreError> {
        self.mutate_global_passport(|holder, store| holder.prepare_cancel(store, operation, rng))
            .await
    }

    /// Borrow only the original read/proof session after fresh global Use and
    /// exact sealed-record checks. No holder, seed or mutable engine can escape.
    pub async fn with_global_passport<T>(
        &mut self,
        read: impl for<'owner> FnOnce(cwlt::passport::DurableSession<'owner>) -> T,
    ) -> Result<T, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        self.authorize_global_store(&store).await?;
        let session = self
            .wallet
            .passport
            .session(&store)
            .map_err(WalletRestoreError::Passport)?;
        let output = read(session);
        // Proof generation can be substantial synchronous work. Re-observe the
        // genuine global owner before returning even a public presentation.
        self.authorize_global_store(&store).await?;
        Ok(output)
    }
}

/// Private creation-only batch composition. The caller retains the genuine
/// enrollment completion capability; this rechecks exact pending Keys state.
pub(crate) async fn prepare_initial_passport<
    B: Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
>(
    keys: &mut ckmg::Keys<crate::KeyStore<B>, C, E, A>,
    storage: &crate::SharedStore<B>,
    receipt: &ckmg::Receipt,
    rng: &mut G,
) -> Result<crate::Mutation, crate::InitialError> {
    use crate::InitialError;
    let ckmg::Change::Created(expected) = &receipt.change else {
        return Err(InitialError::Invalid);
    };
    let lineage = keys.lineage().await.map_err(InitialError::Keys)?;
    if lineage != *expected
        || lineage.binding.community() != "wallet"
        || keys
            .pending_output()
            .await
            .map_err(InitialError::Keys)?
            .as_ref()
            != Some(receipt)
    {
        return Err(InitialError::Invalid);
    }
    let holder = keys
        .with_holder_seed(cwlt::PassportHolder::from_holder_seed)
        .await
        .map_err(InitialError::Keys)?
        .map_err(InitialError::Keys)?;
    let store = storage.lock().await;
    if store.version().map_err(InitialError::Storage)? != 1 {
        return Err(InitialError::Invalid);
    }
    let operation = *receipt.operation.as_bytes();
    let candidate =
        cwlt::passport::DurableHolder::prepare_initial(holder, &*store, "wallet", operation, rng)
            .map_err(|_| InitialError::Invalid)?;
    let cwst::Change::Put { owner, key, value } = candidate
        .change_for(&*store, &operation)
        .map_err(|_| InitialError::Invalid)?
    else {
        return Err(InitialError::Invalid);
    };
    Ok(crate::Mutation {
        owner: owner.into(),
        key: key.to_vec(),
        value: Some(value.to_vec()),
    })
}
