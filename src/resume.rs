//! Persistent unlock (DESIGN-secure-convenience-2026-10-23 part 4, decisions M5/M6):
//! a device stays unlocked across restarts without a passkey ceremony.
//!
//! What is persisted is the NARROWER [`ResumeBundle`]: this device's opened material for
//! the communities it has ALREADY joined, i.e. each community's unlock secret
//! `U_c` (see [`crate::unlock`]). `U_c` opens that community's vault and yields its device
//! key, and nothing else: it is a one-way derivation of the wallet passkey's PRF output
//! `W`, which is NEVER part of the bundle. A copied profile therefore yields at most this
//! device's role in its existing memberships until the member revokes the device. A new
//! community still needs a stamp, so `W` comes from the passkey then, as before.
//!
//! The bundle is minted where the openings are minted (M5): only
//! [`crate::WalletUnlock::resume_bundle`] creates one. It has no constructor from bytes
//! outside the sealed stores of this module, no path back to a [`crate::WalletUnlock`], and
//! no wallet opening:
//!
//! ```compile_fail
//! fn wallet(bundle: &cvlt::ResumeBundle) { let _ = bundle.wallet(); }
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
//! Every failure to open (missing, evicted, tampered, other binding) reads as "no unlock":
//! one passkey confirmation, never fail-open.
use crate::{OpenError, PreparedOpen};
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
const AAD_PREFIX: &[u8] = b"cvlt.resume.v1\0";
const VERSION: u8 = 1;
/// Upper bound on memberships in one bundle (decode refuses more).
pub const MAX_RESUME_MEMBERSHIPS: usize = 4096;
const MAX_SCOPE: usize = 1024;

/// One joined community's opened material: its identity, its Store scope and its
/// community unlock secret `U_c`. Never the wallet PRF output.
struct Membership {
    fingerprint: [u8; 32],
    scope: String,
    secret: Zeroizing<[u8; 32]>,
}

/// The persisted unlock of this device: the openings of the communities it has
/// already joined. No Debug, Clone or serializer; wiped on drop. Holding it is not
/// authentication anywhere.
pub struct ResumeBundle {
    memberships: Vec<Membership>,
}

/// Error of a resume store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    /// The platform store could not be read or written.
    Storage,
    /// The bundle is too large or malformed.
    Invalid,
}

impl ResumeBundle {
    pub(crate) fn mint(memberships: Vec<(([u8; 32], String), Zeroizing<[u8; 32]>)>) -> Self {
        Self {
            memberships: memberships
                .into_iter()
                .map(|((fingerprint, scope), secret)| Membership {
                    fingerprint,
                    scope,
                    secret,
                })
                .collect(),
        }
    }

    /// The joined communities this bundle opens, as (fingerprint, scope).
    pub fn memberships(&self) -> impl Iterator<Item = (&[u8; 32], &str)> {
        self.memberships
            .iter()
            .map(|entry| (&entry.fingerprint, entry.scope.as_str()))
    }

    /// One joined community's vault opening, exactly as
    /// [`crate::WalletUnlock::community`] derives it, without any ceremony. A community
    /// not in the bundle is refused: joining it needs the passkey.
    pub fn community(
        &self,
        fingerprint: &[u8; 32],
        scope: &str,
    ) -> Result<PreparedOpen, OpenError> {
        let entry = self
            .memberships
            .iter()
            .find(|entry| &entry.fingerprint == fingerprint && entry.scope == scope)
            .ok_or(OpenError::Composition(crate::Error::Scope))?;
        PreparedOpen::from_prf(entry.secret.as_slice(), scope)
    }

    /// Plain encoding, only ever handed to a sealing store of this module.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(3 + self.memberships.len() * 100));
        out.push(VERSION);
        out.extend_from_slice(&(self.memberships.len() as u32).to_le_bytes());
        for entry in &self.memberships {
            out.extend_from_slice(&entry.fingerprint);
            out.extend_from_slice(&(entry.scope.len() as u16).to_le_bytes());
            out.extend_from_slice(entry.scope.as_bytes());
            out.extend_from_slice(entry.secret.as_slice());
        }
        out
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
        let mut memberships = Vec::with_capacity(count);
        for _ in 0..count {
            let fingerprint: [u8; 32] = cursor.array()?;
            let len = u16::from_le_bytes(cursor.array()?) as usize;
            if len == 0 || len > MAX_SCOPE {
                return Err(ResumeError::Invalid);
            }
            let scope = std::str::from_utf8(cursor.take(len)?)
                .map_err(|_| ResumeError::Invalid)?
                .to_owned();
            if scope == crate::WALLET_SCOPE {
                return Err(ResumeError::Invalid);
            }
            let secret = Zeroizing::new(cursor.array::<32>()?);
            memberships.push(Membership {
                fingerprint,
                scope,
                secret,
            });
        }
        if !cursor.0.is_empty() {
            return Err(ResumeError::Invalid);
        }
        Ok(Self { memberships })
    }
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
mod tests {
    use super::*;

    fn bundle() -> ResumeBundle {
        ResumeBundle::mint(vec![
            (([1; 32], "garden".into()), Zeroizing::new([7; 32])),
            (([2; 32], "orchard".into()), Zeroizing::new([8; 32])),
        ])
    }

    #[test]
    fn encoding_round_trips_and_refuses_garbage() {
        let plain = bundle().encode();
        let back = ResumeBundle::decode(&plain).unwrap();
        assert_eq!(back.encode().as_slice(), plain.as_slice());
        assert!(back.community(&[1; 32], "garden").is_ok());
        assert!(back.community(&[1; 32], "orchard").is_err());
        assert!(back.community(&[3; 32], "garden").is_err());
        let mut long = plain.to_vec();
        long.push(0);
        assert_eq!(
            ResumeBundle::decode(&long).err(),
            Some(ResumeError::Invalid)
        );
        assert_eq!(
            ResumeBundle::decode(&plain[..plain.len() - 1]).err(),
            Some(ResumeError::Invalid)
        );
        assert_eq!(ResumeBundle::decode(&[2]).err(), Some(ResumeError::Invalid));
        let wallet =
            ResumeBundle::mint(vec![(([1; 32], "wallet".into()), Zeroizing::new([7; 32]))]);
        assert_eq!(
            ResumeBundle::decode(&wallet.encode()).err(),
            Some(ResumeError::Invalid)
        );
    }

    /// Decision M6 at the byte level: the persisted plaintext of a real bundle holds
    /// every `U_c` and not `W`, and `U_c` differs from `W`.
    #[test]
    fn bundle_never_contains_the_wallet_prf_output() {
        let w = [0x5a; 32];
        let wallet = crate::WalletUnlock::from_bytes_for_tests(w);
        let bundle = wallet
            .resume_bundle(&[([1; 32], "garden"), ([2; 32], "orchard")])
            .unwrap();
        let plain = bundle.encode();
        assert!(!plain.windows(32).any(|window| window == w));
        for entry in &bundle.memberships {
            assert_ne!(entry.secret.as_slice(), &w);
        }
        let direct = wallet
            .community(&[1; 32], "garden")
            .unwrap()
            .device()
            .unwrap();
        let resumed = ResumeBundle::decode(&plain)
            .unwrap()
            .community(&[1; 32], "garden")
            .unwrap()
            .device()
            .unwrap();
        assert_eq!(direct, resumed);
        assert!(wallet.resume_bundle(&[([1; 32], "wallet")]).is_err());
        assert!(wallet.resume_bundle(&[([1; 32], "")]).is_err());
    }

    #[test]
    fn aad_binds_length_and_binding() {
        assert_ne!(aad(b"ab"), aad(b"a"));
        assert!(aad(b"x").starts_with(AAD_PREFIX));
    }
}
