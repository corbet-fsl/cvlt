//! Persistent unlock v2 (U2b; DESIGN-secure-convenience-2026-10-23 part 4, M5/M6, as
//! corrected by the X1 HIGH finding): a device stays unlocked across restarts for the
//! communities it has already joined, without a passkey ceremony.
//!
//! What is persisted is, per joined community, ONE [`ckmg::DeviceDelegation`]: a fresh
//! device key from this device's own entropy (never derived from a PRF), enrolled in that
//! community's lineage as a delegate, plus only the granted epoch's member-purpose
//! secrets on ckmg's closed allowlist. The bundle never holds the wallet PRF output `W`,
//! a community unlock secret `U_c`, a root, the identity, history, the ring key, the
//! device seed or a passkey record reader or writer. A resumed start therefore opens
//! community sessions (as the delegate) and nothing else: the wallet, new communities,
//! pairing, rotation, lineage changes, restore and every per-passkey record still need
//! the passkey. A revoked delegate is rotated out of the lineage, and the server checks
//! the current lineage per request.
//!
//! Enrolment rides on a ceremony that happens anyway: the caller mints each delegation
//! with `ckmg::Keys::delegate_device` while that ceremony's custody is open and adds it
//! with [`ResumeBundle::insert`]. There is no path from a bundle to a wallet opening, a
//! community opening or a PRF:
//!
//! ```compile_fail
//! fn wallet(bundle: &cvlt::ResumeBundle) { let _ = bundle.wallet(); }
//! ```
//! ```compile_fail
//! fn opening(bundle: &cvlt::ResumeBundle) { let _ = bundle.community(&[0; 32], "garden"); }
//! ```
//! ```compile_fail
//! fn back(bundle: cvlt::ResumeBundle) -> cvlt::WalletUnlock { bundle.into() }
//! ```
//! ```compile_fail
//! fn copy(bundle: &cvlt::ResumeBundle) { let _: cvlt::ResumeBundle = bundle.clone(); }
//! ```
//!
//! Stores (adopted building blocks, no own cryptography):
//! - native ([`NativeResume`]): AES-256-GCM (RustCrypto `aes-gcm`) record file, its wrapping
//!   key in the OS key store through the `keyring` crate (feature `os-keyring`: Keychain,
//!   Credential Manager, Secret Service); where no key store is usable (headless Linux),
//!   a user-only key file (mode 0600) beside the record, so a reboot needs no confirmation.
//! - browser ([`BrowserResume`]): a WebCrypto AES-GCM key generated with
//!   `extractable: false`, kept as a `CryptoKey` in IndexedDB on the wallet origin.
//!
//! Every failure to open (missing, evicted, tampered, other binding, a delegation whose
//! lineage does not verify or does not list its key) reads as "no unlock": one passkey
//! confirmation, never fail-open.
use ckmg::DeviceDelegation;
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
pub use browser::{BrowserResume, erase_local_databases};
#[cfg(not(target_arch = "wasm32"))]
pub use native::NativeResume;

/// Additional authenticated data prefix of every sealed bundle.
const AAD_PREFIX: &[u8] = b"cvlt.resume.v2\0";
const VERSION: u8 = 2;
/// Upper bound on memberships in one bundle (decode refuses more).
pub const MAX_RESUME_MEMBERSHIPS: usize = 4096;
const MAX_SCOPE: usize = 1024;

/// One joined community's resume custody: its founding-key fingerprint, its Store scope
/// and this device's delegation in it. Never `U_c`, never the wallet PRF output.
struct Membership {
    fingerprint: [u8; 32],
    scope: String,
    delegation: DeviceDelegation,
}

/// The persisted unlock of this device: one delegation per joined community. No Debug,
/// Clone or serializer; the delegations wipe their secrets on drop. Holding it opens
/// community sessions as the delegate only.
#[derive(Default)]
pub struct ResumeBundle {
    memberships: Vec<Membership>,
}

/// Error of a resume bundle or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    /// The platform store could not be read or written.
    Storage,
    /// The bundle is too large or malformed, or a delegation does not belong to its scope.
    Invalid,
}

impl ResumeBundle {
    /// An empty bundle (nothing enrolled yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol one joined community: `delegation` is what `ckmg::Keys::delegate_device`
    /// returned during a ceremony that happened anyway. It must be granted in the
    /// community named `scope`; the wallet scope is refused. A later delegation for the
    /// same community replaces the earlier one (re-delegation).
    pub fn insert(
        &mut self,
        fingerprint: [u8; 32],
        scope: &str,
        delegation: DeviceDelegation,
    ) -> Result<(), ResumeError> {
        checked_scope(scope, &delegation)?;
        self.remove(&fingerprint, scope);
        if self.memberships.len() >= MAX_RESUME_MEMBERSHIPS {
            return Err(ResumeError::Invalid);
        }
        self.memberships.push(Membership {
            fingerprint,
            scope: scope.to_owned(),
            delegation,
        });
        Ok(())
    }

    /// Drop one community's delegation (revoked, left, or stale); whether one was held.
    pub fn remove(&mut self, fingerprint: &[u8; 32], scope: &str) -> bool {
        let before = self.memberships.len();
        self.memberships
            .retain(|entry| !(&entry.fingerprint == fingerprint && entry.scope == scope));
        self.memberships.len() != before
    }

    /// Whether nothing is enrolled.
    pub fn is_empty(&self) -> bool {
        self.memberships.is_empty()
    }

    /// The joined communities this bundle resumes, as (fingerprint, scope).
    pub fn memberships(&self) -> impl Iterator<Item = (&[u8; 32], &str)> {
        self.memberships
            .iter()
            .map(|entry| (&entry.fingerprint, entry.scope.as_str()))
    }

    /// This device's delegation in one joined community, without any ceremony. A
    /// community not in the bundle has none: joining it needs the passkey.
    pub fn delegation(&self, fingerprint: &[u8; 32], scope: &str) -> Option<&DeviceDelegation> {
        self.memberships
            .iter()
            .find(|entry| &entry.fingerprint == fingerprint && entry.scope == scope)
            .map(|entry| &entry.delegation)
    }

    /// Plain encoding, only ever handed to a sealing store of this module.
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ResumeError> {
        let mut out = Zeroizing::new(Vec::with_capacity(5 + self.memberships.len() * 512));
        out.push(VERSION);
        out.extend_from_slice(&(self.memberships.len() as u32).to_le_bytes());
        for entry in &self.memberships {
            let sealed = entry
                .delegation
                .to_sealed_bytes()
                .map_err(|_| ResumeError::Invalid)?;
            out.extend_from_slice(&entry.fingerprint);
            out.extend_from_slice(&(entry.scope.len() as u16).to_le_bytes());
            out.extend_from_slice(entry.scope.as_bytes());
            let length = u32::try_from(sealed.len()).map_err(|_| ResumeError::Invalid)?;
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(&sealed);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ResumeError> {
        let mut cursor = Cursor(bytes);
        if cursor.take(1)? != [VERSION] {
            return Err(ResumeError::Invalid);
        }
        let count = u32::from_le_bytes(cursor.array()?) as usize;
        if count > MAX_RESUME_MEMBERSHIPS {
            return Err(ResumeError::Invalid);
        }
        let mut bundle = Self::new();
        for _ in 0..count {
            let fingerprint: [u8; 32] = cursor.array()?;
            let len = u16::from_le_bytes(cursor.array()?) as usize;
            let scope = std::str::from_utf8(cursor.take(len)?)
                .map_err(|_| ResumeError::Invalid)?
                .to_owned();
            let length = u32::from_le_bytes(cursor.array()?) as usize;
            let delegation = DeviceDelegation::from_sealed_bytes(cursor.take(length)?)
                .map_err(|_| ResumeError::Invalid)?;
            if bundle.delegation(&fingerprint, &scope).is_some() {
                return Err(ResumeError::Invalid);
            }
            bundle.insert(fingerprint, &scope, delegation)?;
        }
        if !cursor.0.is_empty() {
            return Err(ResumeError::Invalid);
        }
        Ok(bundle)
    }
}

/// A resumable community scope: not empty, bounded, never the wallet, and the scope the
/// delegation was granted in.
fn checked_scope(scope: &str, delegation: &DeviceDelegation) -> Result<(), ResumeError> {
    if scope.is_empty()
        || scope.len() > MAX_SCOPE
        || scope == crate::WALLET_SCOPE
        || delegation.community() != scope
    {
        return Err(ResumeError::Invalid);
    }
    Ok(())
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ResumeError> {
        if self.0.len() < n {
            return Err(ResumeError::Invalid);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ResumeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// The AAD binding a sealed bundle to its store `binding` (wallet host and account,
/// chosen by the caller), so a record moved to another binding does not open.
fn aad(binding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + 8 + binding.len());
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(&(binding.len() as u64).to_le_bytes());
    out.extend_from_slice(binding);
    out
}

#[cfg(test)]
#[path = "resume/tests.rs"]
mod tests;
