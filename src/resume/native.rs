//! Native resume store: the sealed bundle is a file in the device's private vault
//! directory; its AES-256-GCM wrapping key lives in the OS key store through the
//! `keyring` crate (feature `os-keyring`), else in a user-only key file (0600) beside it.
//!
//! Own glue only: file layout, fallback order and AAD. Sealing is RustCrypto `aes-gcm`,
//! randomness is `getrandom`, key custody is the platform store.
use super::{ResumeBundle, ResumeError, aad};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::Digest;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const RECORD_FILE: &str = "resume.v1";
const KEY_FILE: &str = "resume.v1.key";
const NONCE: usize = 12;

/// The native persistent unlock of one wallet binding.
pub struct NativeResume {
    dir: PathBuf,
    binding: Vec<u8>,
    #[cfg_attr(not(feature = "os-keyring"), allow(dead_code))]
    keyring: Option<(String, String)>,
}

impl NativeResume {
    /// A store in `dir` (the device's private vault directory) for `binding` (wallet host
    /// and account, as the caller names the wallet). `keyring_service` names the OS key
    /// store entry; `None`, or a build without `os-keyring`, keeps the wrapping key in a
    /// user-only file instead.
    pub fn new(dir: &Path, binding: &[u8], keyring_service: Option<&str>) -> Self {
        let user = hex(sha2::Sha256::digest(binding).as_slice());
        Self {
            dir: dir.to_owned(),
            binding: binding.to_owned(),
            keyring: keyring_service.map(|service| (service.to_owned(), user)),
        }
    }

    /// Seal `bundle` as this device's persistent unlock, replacing any earlier one.
    pub fn save(&self, bundle: &ResumeBundle) -> Result<(), ResumeError> {
        std::fs::create_dir_all(&self.dir).map_err(|_| ResumeError::Storage)?;
        let key = self.key_or_create()?;
        let mut nonce = [0; NONCE];
        getrandom::fill(&mut nonce).map_err(|_| ResumeError::Storage)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        let plain = bundle.encode();
        let aad = aad(&self.binding);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| ResumeError::Storage)?;
        let mut record = Vec::with_capacity(NONCE + sealed.len());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&sealed);
        write_private(&self.dir.join(RECORD_FILE), &record)
    }

    /// The persisted unlock, if one opens. Missing, tampered or foreign records read as
    /// `None` (one passkey confirmation follows); a record that fails to open is forgotten.
    pub fn load(&self) -> Option<ResumeBundle> {
        let record = std::fs::read(self.dir.join(RECORD_FILE)).ok()?;
        let opened = self.key().and_then(|key| {
            let (nonce, sealed) = record.split_at_checked(NONCE)?;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
            let aad = aad(&self.binding);
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: sealed,
                            aad: &aad,
                        },
                    )
                    .ok()?,
            );
            ResumeBundle::decode(&plain).ok()
        });
        if opened.is_none() {
            let _ = self.forget();
        }
        opened
    }

    /// Delete the persisted unlock: the record, the key file and the OS key store entry.
    /// Explicit lock, the "passkey at every start" opt-out and revocation call this.
    pub fn forget(&self) -> Result<(), ResumeError> {
        let mut result = Ok(());
        #[cfg(feature = "os-keyring")]
        if let Some(entry) = self.entry() {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(_) => result = Err(ResumeError::Storage),
            }
        }
        for name in [RECORD_FILE, KEY_FILE] {
            match std::fs::remove_file(self.dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => result = Err(ResumeError::Storage),
            }
        }
        result
    }

    /// Whether the wrapping key is held by the OS key store (not the fallback file).
    pub fn in_os_keyring(&self) -> bool {
        #[cfg(feature = "os-keyring")]
        if let Some(entry) = self.entry() {
            return entry.get_secret().is_ok();
        }
        false
    }

    #[cfg(feature = "os-keyring")]
    fn entry(&self) -> Option<keyring::Entry> {
        let (service, user) = self.keyring.as_ref()?;
        keyring::Entry::new(service, user).ok()
    }

    fn key(&self) -> Option<Zeroizing<Vec<u8>>> {
        #[cfg(feature = "os-keyring")]
        if let Some(entry) = self.entry()
            && let Ok(key) = entry.get_secret()
        {
            let key = Zeroizing::new(key);
            return (key.len() == 32).then_some(key);
        }
        let key = Zeroizing::new(std::fs::read(self.dir.join(KEY_FILE)).ok()?);
        (key.len() == 32).then_some(key)
    }

    fn key_or_create(&self) -> Result<Zeroizing<Vec<u8>>, ResumeError> {
        if let Some(key) = self.key() {
            return Ok(key);
        }
        let mut key = Zeroizing::new(vec![0; 32]);
        getrandom::fill(key.as_mut_slice()).map_err(|_| ResumeError::Storage)?;
        #[cfg(feature = "os-keyring")]
        if let Some(entry) = self.entry()
            && entry.set_secret(key.as_slice()).is_ok()
        {
            return Ok(key);
        }
        // No usable OS key store (headless Linux, no Secret Service): user-only file.
        write_private(&self.dir.join(KEY_FILE), key.as_slice())?;
        Ok(key)
    }
}

/// Write `bytes` to `path` atomically, readable by the user only (0600 on Unix).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ResumeError> {
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).map_err(|_| ResumeError::Storage)?;
    let temporary = path.with_extension(format!("tmp-{}", hex(&suffix)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(ResumeError::Storage);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
