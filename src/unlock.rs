//! Unlock once: ONE wallet passkey confirmation opens every vault of the device
//! (DESIGN-one-confirmation-2026-10-14, rule 5).
//!
//! The wallet passkey's PRF output `W` is imported once into a [`WalletUnlock`].
//! The wallet vault opens with `W` itself (unchanged derivation). Each community
//! vault opens with its own community unlock secret
//!
//! ```text
//! U_c = BLAKE3-derive_key("cvlt 2026-10-15 community unlock v1",
//!                          W || le64(len(c)) || c)
//! ```
//!
//! where `c` is the community's IDENTITY: the founding-key fingerprint (SHA-256 of
//! its genesis document) that the vault pins in [`crate::CommunityPin`], never its
//! address. An address can be taken again after a community ends; a new community
//! at the same address has another fingerprint, so it derives another `U_c` and
//! opens nothing of the old one. This is the per-community salt of the design:
//! bound into the derivation, so no value crosses communities. The vault's Store
//! scope (the address the Door is configured with) still names the vault and is
//! bound into its locator by ckmg. `U_c` then plays
//! the role of a passkey PRF for that community's vault: ckmg derives the
//! private locator, the Store wrapping key and the device key from it, and the
//! community's random roots stay wrapped in its own PRF-sealed checkpoint inside
//! that community's own records. There is no shared locator: every community's
//! record location is derived from its own `U_c`. One-way: `U_c` reveals neither
//! `W` nor another community's `U_c'`.
//!
//! Restore: a synced wallet passkey yields the same `W`, so one confirmation
//! re-derives every `U_c` and each community restores through the existing
//! records path. A different passkey yields different `U_c` and opens nothing.
use crate::{OpenError, PreparedOpen};
use ckmg::passkey;
use zeroize::Zeroizing;

const COMMUNITY_UNLOCK_CONTEXT: &str = "cvlt 2026-10-15 community unlock v1";
/// The wallet vault scope; it opens with the wallet PRF itself.
pub const WALLET_SCOPE: &str = "wallet";

/// The wallet passkey's PRF output, held for one app session. No Debug, Clone,
/// serializer or byte getter; wiped on drop. Holding it is not authentication.
///
/// ```compile_fail
/// fn copy(value: cvlt::WalletUnlock) { let _ = value.clone(); }
/// ```
pub struct WalletUnlock(Zeroizing<[u8; 32]>);

impl WalletUnlock {
    /// Consume the one wallet passkey PRF result of this app start.
    pub fn new(unlock: cpky::UnlockSecret) -> Self {
        Self(unlock.import(|bytes| Zeroizing::new(*bytes)))
    }

    #[cfg(test)]
    pub(crate) fn from_bytes_for_tests(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The wallet vault: exactly the same derivation as a direct wallet unlock
    /// (`PreparedOpen::new(unlock, "wallet")`), so existing wallet vaults open.
    pub fn wallet(&self) -> Result<PreparedOpen, OpenError> {
        PreparedOpen::from_prf(self.0.as_slice(), WALLET_SCOPE)
    }

    /// The wallet membership index record (see [`crate::membership_index`]): its locator and
    /// record material derive from `W` under [`crate::MEMBERSHIP_SCOPE`], no community.
    pub fn membership_index(&self) -> Result<PreparedOpen, OpenError> {
        PreparedOpen::from_prf(self.0.as_slice(), crate::MEMBERSHIP_SCOPE)
    }

    /// The wallet's membership index on a record network, with the cipher that seals it.
    /// Both derive from `W` under [`crate::MEMBERSHIP_SCOPE`] only.
    pub fn index_record<N: cdht::Network>(
        &self,
        network: N,
    ) -> Result<(crate::TorIndexRecord<N>, ckmg::passkey::StoreCipher), crate::IndexError> {
        let prf = passkey::PrfOutput::from_bytes(self.0.as_slice())
            .map_err(|_| crate::IndexError::Invalid)?;
        let writer = passkey::passkey_record_writer(&prf, crate::MEMBERSHIP_SCOPE)
            .map_err(|_| crate::IndexError::Invalid)?;
        let cipher = passkey::store_cipher(&prf, crate::MEMBERSHIP_SCOPE)
            .map_err(|_| crate::IndexError::Invalid)?;
        Ok((crate::TorIndexRecord::new(network, writer)?, cipher))
    }

    /// One community's vault, without any further passkey ceremony.
    /// `fingerprint` is the community's founding-key fingerprint (its identity,
    /// as pinned in [`crate::CommunityPin::fingerprint`]); `scope` is the vault's
    /// Store scope (the community address of this membership).
    pub fn community(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> Result<PreparedOpen, OpenError> {
        if scope == WALLET_SCOPE {
            return Err(OpenError::Composition(crate::Error::Scope));
        }
        let secret = community_secret(&self.0, fingerprint);
        PreparedOpen::from_prf(secret.as_slice(), scope)
    }
}

pub(crate) fn community_secret(wallet: &[u8; 32], fingerprint: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(COMMUNITY_UNLOCK_CONTEXT);
    hasher.update(wallet);
    hasher.update(&(fingerprint.len() as u64).to_le_bytes());
    hasher.update(fingerprint);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

impl PreparedOpen {
    pub(crate) fn from_prf(bytes: &[u8], scope: &str) -> Result<Self, OpenError> {
        let prf = passkey::PrfOutput::from_bytes(bytes).map_err(OpenError::Keys)?;
        let locator = passkey::vault_location(&prf, scope).map_err(OpenError::Keys)?;
        Ok(Self {
            prf,
            scope: scope.into(),
            locator,
        })
    }
}
