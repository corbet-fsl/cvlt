//! Community account owner, distinct from global passport and accepted records.
use super::*;

/// Original durable pending account-key owner. Initialization belongs to the
/// genuine initial acknowledgment; this is not an accepted account or proof.
pub struct CommunityAccountCustody {
    account: cwlt::account_owner::DurableAccountOwner,
}

/// A wallet type that carries the community account owner: the dedicated
/// account custody, or the member Vault's wallet custody when it was restored
/// with the account capsule. The Vault's single Store stays the only owner.
pub trait AccountSlot {
    /// The community account owner, or a scope refusal when none was restored.
    fn account(&self) -> Result<&cwlt::account_owner::DurableAccountOwner, WalletRestoreError>;
}

impl AccountSlot for CommunityAccountCustody {
    fn account(&self) -> Result<&cwlt::account_owner::DurableAccountOwner, WalletRestoreError> {
        Ok(&self.account)
    }
}

impl AccountSlot for WalletCustody {
    fn account(&self) -> Result<&cwlt::account_owner::DurableAccountOwner, WalletRestoreError> {
        self.account.as_ref().ok_or(WalletRestoreError::Scope)
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records> Vault<B, C, E, A, R, ()> {
    /// Like `restore_community_account`, but the Vault keeps the member's wallet
    /// custody type, holding only the account capsule (no passport or record owner,
    /// which a community Store enrolled through the account path does not have).
    pub async fn restore_account_only_custody(
        self,
    ) -> Result<Vault<B, C, E, A, R, WalletCustody>, WalletRestoreError> {
        let Vault {
            keys,
            storage,
            key_store,
            records,
            wallet,
        } = self.restore_community_account().await?;
        Ok(Vault {
            keys,
            storage,
            key_store,
            records,
            wallet: WalletCustody {
                passport: None,
                record: None,
                account: Some(wallet.account),
            },
        })
    }

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

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W: AccountSlot>
    Vault<B, C, E, A, R, W>
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
        let candidate = self.wallet.account()?
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
            .check_current(self.wallet.account()?, &fresh, &store, &context, now)
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
            .check_current(self.wallet.account()?, &engine, &store, context, now)
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
            .check_current(self.wallet.account()?, &fresh, &store, context, now)
            .map_err(WalletRestoreError::Account)?;
        attempt.completed = true;
        Ok(())
    }

    /// Prove the frozen candidate with the bounded original native prover, only
    /// for this exact receipt-installed account capsule. The candidate is consumed
    /// (refusal or cancellation invalidates it); original Keys authority is checked
    /// before and after the computation. The proof grants no enrollment, issuer
    /// acceptance or custody release; the caller separately refreshes remote
    /// admission and supplies the unchanged public context.
    #[cfg(all(feature = "wallet-native-prover", not(target_arch = "wasm32")))]
    pub async fn prove_community_genesis(
        &mut self,
        candidate: cwlt::account_owner::AccountGenesis,
        context: &ckmg::wallet_engine::account::GenesisContext,
        prover: &ckmg::wallet_engine::native_prover::NativeProver,
        mut clock: impl FnMut() -> std::result::Result<u64, ckmg::wallet_engine::Error>,
    ) -> Result<cwlt::account_owner::AccountGenesisProof, WalletRestoreError> {
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
            candidate.invalidate();
            return Err(WalletRestoreError::Scope);
        }
        let engine = self
            .keys
            .wallet_engine()
            .await
            .map_err(WalletRestoreError::Keys)?;
        let proof = candidate
            .prove(self.wallet.account()?, &engine, &store, prover, &mut clock)
            .map_err(WalletRestoreError::Account)?;
        // The final original Keys await follows all computation.
        let after = self.keys.lineage().await;
        let fresh = self.keys.wallet_engine().await;
        let (Ok(after), Ok(fresh)) = (after, fresh) else {
            proof.invalidate();
            return Err(WalletRestoreError::Scope);
        };
        if after.binding != binding {
            proof.invalidate();
            return Err(WalletRestoreError::Scope);
        }
        let now = clock().map_err(|e| WalletRestoreError::Account(e.into()))?;
        proof
            .check_current(self.wallet.account()?, &fresh, &store, context, now)
            .map_err(WalletRestoreError::Account)?;
        Ok(proof)
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
        let public = self.wallet.account()?
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

#[cfg(all(feature = "wallet-native-prover", not(target_arch = "wasm32")))]
mod pending {
    //! Durable pending companion and accepted account under original Keys
    //! authority. The same discipline as genesis preparation: Keys before and
    //! after every Store operation, the Store lock held across it.
    use super::*;
    use ckmg::wallet_engine::account::{
        AcceptedAccount, AcceptedResponse, PendingGenesisBinding, ResponseTrust,
    };
    use cwlt::account_owner::{
        AccountGenesisProof, ActivatedAccount, GenesisRequestMaterial, PendingActivation,
        ReopenedPending,
    };

    impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W: AccountSlot>
        Vault<B, C, E, A, R, W>
    {
        /// Borrow the verified public request data of a proven candidate after
        /// the same Keys and Store checks. It borrows only the proof.
        pub async fn community_genesis_material<'proof>(
            &mut self,
            proof: &'proof AccountGenesisProof,
            context: &ckmg::wallet_engine::account::GenesisContext,
            now: u64,
        ) -> Result<GenesisRequestMaterial<'proof>, WalletRestoreError> {
            let storage = self.storage.clone();
            let store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            let material = proof
                .request_material(self.wallet.account()?, &engine, &store, context, now)
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(material)
        }

        /// Commit state A and the exact signed outbox in ONE Store commit. A
        /// pending row is never replaced; every later step reopens from it.
        pub async fn stage_pending_genesis(
            &mut self,
            proof: &AccountGenesisProof,
            binding: &PendingGenesisBinding,
            outbox: Vec<u8>,
            operation: [u8; 32],
            now: u64,
        ) -> Result<(), WalletRestoreError> {
            let storage = self.storage.clone();
            let mut store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            proof
                .stage_pending(
                    self.wallet.account()?,
                    &engine,
                    &mut store,
                    binding,
                    outbox,
                    operation,
                    now,
                )
                .await
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await
        }

        /// Reopen the durable pending companion (state A or B) with its exact outbox.
        pub async fn reopen_pending_genesis(
            &mut self,
            now: u64,
        ) -> Result<ReopenedPending, WalletRestoreError> {
            let storage = self.storage.clone();
            let store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            let reopened = self.wallet.account()?
                .reopen_pending(&engine, &store, now)
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(reopened)
        }

        /// Move state A to state B after the actual response arrived.
        pub async fn advance_pending_genesis(
            &mut self,
            response: &AcceptedResponse,
            trust: &ResponseTrust,
            operation: [u8; 32],
            now: u64,
        ) -> Result<(), WalletRestoreError> {
            let storage = self.storage.clone();
            let mut store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            self.wallet.account()?
                .advance_pending(&engine, &mut store, response, trust, operation, now)
                .await
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await
        }

        /// Reopen state B and re-verify the stored response under the CURRENT trust.
        pub async fn begin_account_activation(
            &mut self,
            trust: &ResponseTrust,
            now: u64,
        ) -> Result<PendingActivation, WalletRestoreError> {
            let storage = self.storage.clone();
            let store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            let activation = self.wallet.account()?
                .begin_activation(&engine, &store, trust, now)
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(activation)
        }

        /// Replace the unchanged pending row with the accepted account record.
        pub async fn commit_account_activation(
            &mut self,
            activation: PendingActivation,
            operation: [u8; 32],
            acknowledgement: [u8; 32],
        ) -> Result<ActivatedAccount, WalletRestoreError> {
            let storage = self.storage.clone();
            let mut store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let activated = activation
                .commit(self.wallet.account()?, &mut store, operation, acknowledgement)
                .await
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(activated)
        }

        /// Acknowledge the outbox of an already accepted account (repeatable).
        pub async fn settle_account_outbox(
            &mut self,
            operation: [u8; 32],
        ) -> Result<bool, WalletRestoreError> {
            let storage = self.storage.clone();
            let mut store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let settled = self.wallet.account()?
                .settle_outbox(&mut store, operation)
                .await
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(settled)
        }

        /// Reopen the accepted account record under a fresh engine.
        pub async fn restore_accepted_account(
            &mut self,
        ) -> Result<AcceptedAccount, WalletRestoreError> {
            let storage = self.storage.clone();
            let store = storage.lock().await;
            let scope = self.account_scope(&store).await?;
            let engine = self
                .keys
                .wallet_engine()
                .await
                .map_err(WalletRestoreError::Keys)?;
            let accepted = self.wallet.account()?
                .restore_accepted(&engine, &store)
                .map_err(WalletRestoreError::Account)?;
            self.same_scope(&scope).await?;
            Ok(accepted)
        }

        /// The community binding of the original Keys lineage, which must be a
        /// community scope of the locked Store (never the global wallet).
        async fn account_scope(
            &mut self,
            store: &cwst::Store<B>,
        ) -> Result<ckmg::Binding, WalletRestoreError> {
            let binding = self
                .keys
                .lineage()
                .await
                .map_err(WalletRestoreError::Keys)?
                .binding;
            if binding.community() == "wallet" || !store.is_scope(binding.community()) {
                return Err(WalletRestoreError::Scope);
            }
            Ok(binding)
        }

        /// Original Keys still authorize the same lineage after the Store work.
        async fn same_scope(&mut self, binding: &ckmg::Binding) -> Result<(), WalletRestoreError> {
            let after = self
                .keys
                .lineage()
                .await
                .map_err(WalletRestoreError::Keys)?
                .binding;
            if &after != binding {
                return Err(WalletRestoreError::Scope);
            }
            Ok(())
        }
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
    let engine = keys
        .wallet_engine_for_pending_creation(receipt)
        .await
        .map_err(InitialError::Keys)?;
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
