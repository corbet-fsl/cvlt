//! Community account owner, distinct from global passport and accepted records.
use super::*;

/// Original durable pending account-key owner. Initialization belongs to the
/// genuine initial acknowledgment; this is not an accepted account or proof.
pub struct CommunityAccountCustody {
    account: cwlt::account_owner::DurableAccountOwner,
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records> Vault<B, C, E, A, R, ()> {
    /// Restore only the existing original community account capsule after normal
    /// Vault recovery. Missing state, foreign binding and global wallet refuse;
    /// ordinary Use never grants replacement-key creation.
    pub async fn restore_community_account(
        mut self,
    ) -> Result<Vault<B, C, E, A, R, CommunityAccountCustody>, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() == "wallet" || !store.is_scope(binding.community()) {
            return Err(WalletRestoreError::Scope);
        }
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        let account =
            cwlt::account_owner::DurableAccountOwner::open(engine, &store, binding.community())
                .map_err(WalletRestoreError::Account)?;
        // The decrypt/open work grants no authority of its own. Recheck the
        // original owner before exposing even opaque movable account custody.
        if self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding
            != binding
        {
            return Err(WalletRestoreError::Scope);
        }
        drop(store);
        Ok(Vault {
            keys: self.keys,
            storage: self.storage,
            key_store: self.key_store,
            records: self.records,
            wallet: CommunityAccountCustody { account },
        })
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records>
    Vault<B, C, E, A, R, CommunityAccountCustody>
{
    /// Prepare opaque private genesis for the receipt-installed account capsule.
    /// Context and observation are data supplied by the independently current
    /// admission owner. This grants no proof, account acceptance or installation.
    pub async fn prepare_community_genesis(
        &mut self,
        context: ckmg::wallet_engine::account::GenesisContext,
        now: u64,
    ) -> Result<cwlt::account_owner::AccountGenesis, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() == "wallet"
            || context.community_id != binding.community()
            || !store.is_scope(binding.community())
        {
            return Err(WalletRestoreError::Scope);
        }
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        let candidate = self
            .wallet
            .account
            .prepare_genesis(engine, &store, context.clone(), now)
            .map_err(WalletRestoreError::Account)?;
        // The final original Keys await must precede any candidate return.
        if self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding
            != binding
        {
            return Err(WalletRestoreError::Scope);
        }
        let fresh = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        candidate
            .check_current(&self.wallet.account, &fresh, &store, &context, now)
            .map_err(WalletRestoreError::Account)?;
        Ok(candidate)
    }

    /// Reauthorize original Keys and recheck the frozen candidate's durable
    /// capsule. The caller separately refreshes genuine remote admission and
    /// supplies its exact unchanged public context; this does not fetch it.
    pub async fn check_community_genesis(
        &mut self,
        candidate: &cwlt::account_owner::AccountGenesis,
        context: &ckmg::wallet_engine::account::GenesisContext,
        now: u64,
    ) -> Result<(), WalletRestoreError> {
        let mut attempt = GenesisCheck {
            candidate,
            completed: false,
        };
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() == "wallet"
            || context.community_id != binding.community()
            || !store.is_scope(binding.community())
        {
            return Err(WalletRestoreError::Scope);
        }
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        candidate
            .check_current(&self.wallet.account, &engine, &store, context, now)
            .map_err(WalletRestoreError::Account)?;
        if self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding
            != binding
        {
            return Err(WalletRestoreError::Scope);
        }
        let fresh = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        candidate
            .check_current(&self.wallet.account, &fresh, &store, context, now)
            .map_err(WalletRestoreError::Account)?;
        attempt.completed = true;
        Ok(())
    }

    /// Public enrollment coordinate and original secret commitment after fresh
    /// Keys authority and exact sealed-record/Store receipt checks. Neither this
    /// data nor successful restoration is account admission or a delegation.
    pub async fn account_projection(
        &mut self,
    ) -> Result<ckmg::wallet_engine::account_key::Projection, WalletRestoreError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let binding = self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding;
        if binding.community() == "wallet" || !store.is_scope(binding.community()) {
            return Err(WalletRestoreError::Scope);
        }
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        let public = self
            .wallet
            .account
            .projection(&engine, &store)
            .map_err(WalletRestoreError::Account)?;
        if self
            .keys
            .lineage()
            .await
            .map_err(WalletRestoreError::Keys)?
            .binding
            != binding
        {
            return Err(WalletRestoreError::Scope);
        }
        Ok(public)
    }
}

struct GenesisCheck<'owner> {
    candidate: &'owner cwlt::account_owner::AccountGenesis,
    completed: bool,
}
impl Drop for GenesisCheck<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.candidate.invalidate();
        }
    }
}

/// Creation-only companion; absence in normal restoration never calls here.
pub(crate) async fn prepare_initial_account<B: Backend, C: Clock, E: Entropy, A: Authority>(
    keys: &mut ckmg::Keys<crate::KeyStore<B>, C, E, A>,
    storage: &crate::SharedStore<B>,
    receipt: &ckmg::Receipt,
) -> Result<crate::Mutation, crate::InitialError> {
    use crate::InitialError;
    let ckmg::Change::Created(expected) = &receipt.change else {
        return Err(InitialError::Invalid);
    };
    let lineage = keys.lineage().await.map_err(InitialError::Keys)?;
    if &lineage != expected
        || lineage.binding.community() == "wallet"
        || keys
            .pending_output()
            .await
            .map_err(InitialError::Keys)?
            .as_ref()
            != Some(receipt)
    {
        return Err(InitialError::Invalid);
    }
    let engine = keys.wallet_engine().await.map_err(InitialError::Keys)?;
    let store = storage.lock().await;
    if store.version().map_err(InitialError::Storage)? != 1 {
        return Err(InitialError::Invalid);
    }
    let operation = *receipt.operation.as_bytes();
    let candidate = cwlt::account_owner::DurableAccountOwner::prepare_initial(
        engine,
        &*store,
        lineage.binding.community(),
        operation,
    )
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
