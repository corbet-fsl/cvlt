//! The member's community credential: one record family inside the Vault Store.
//!
//! The credential is the signed admission output the community issued to this
//! member's device when joining. It is stored here, under the same Keys-held
//! wrapping as every other Vault owner, bound to community + member + device,
//! and replaced only by version-fenced compare-and-swap. It is never part of a
//! command or reply; the Board's Profile owner reads it through the Vault.
use crate::{Records, Vault};
use ckmg::{Authority, Clock, Entropy};
use cwst::{Change, backend::Backend};
use zeroize::Zeroizing;

const OWNER: &str = "cvlt.community-credential";
const KEY: &[u8] = b"current";
const HEADER: &[u8] = b"cvlt.community-credential.v1\0";

/// Largest credential accepted. A signed credential is a few hundred bytes.
pub const MAX_COMMUNITY_CREDENTIAL_BYTES: usize = 16 * 1024;

/// Coarse credential-record failure. It carries no credential bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// Keys refused fresh current authority.
    Keys(ckmg::Error),
    /// The Vault Store is not this community's scope.
    Scope,
    /// The credential is empty or too large.
    Invalid,
    /// The stored record is malformed or bound to another community, member or
    /// device. It is never returned.
    Foreign,
    /// The stored credential is not the expected one, or the Store version moved.
    /// Nothing was written.
    Conflict,
    /// The Store refused or could not complete the write.
    Storage,
}
impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Community credential operation refused")
    }
}
impl std::error::Error for CredentialError {}

/// What a replacement did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialWrite {
    /// The record changed.
    Stored,
    /// The identical credential was already current; nothing was written.
    Unchanged,
}

fn frame(
    community: &str,
    member: &str,
    device: &[u8; 32],
    credential: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        HEADER.len() + community.len() + member.len() + 32 + credential.len() + 12,
    ));
    out.extend_from_slice(HEADER);
    for text in [community.as_bytes(), member.as_bytes()] {
        out.extend_from_slice(&(text.len() as u32).to_be_bytes());
        out.extend_from_slice(text);
    }
    out.extend_from_slice(device);
    out.extend_from_slice(&(credential.len() as u32).to_be_bytes());
    out.extend_from_slice(credential);
    out
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CredentialError> {
        if self.0.len() < length {
            return Err(CredentialError::Foreign);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn counted(&mut self) -> Result<&'a [u8], CredentialError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CredentialError::Foreign)?;
        self.take(u32::from_be_bytes(bytes) as usize)
    }
}

/// Split a record that must be bound to exactly this community, member and device.
fn unframe<'a>(
    record: &'a [u8],
    community: &str,
    member: &str,
    device: &[u8; 32],
) -> Result<&'a [u8], CredentialError> {
    let mut cursor = Cursor(
        record
            .strip_prefix(HEADER)
            .ok_or(CredentialError::Foreign)?,
    );
    let found_community = cursor.counted()?;
    let found_member = cursor.counted()?;
    let found_device = cursor.take(32)?;
    let credential = cursor.counted()?;
    if !cursor.0.is_empty()
        || found_community != community.as_bytes()
        || found_member != member.as_bytes()
        || found_device != device
        || credential.is_empty()
        || credential.len() > MAX_COMMUNITY_CREDENTIAL_BYTES
    {
        return Err(CredentialError::Foreign);
    }
    Ok(credential)
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Read the stored community credential for this exact community, member and
    /// current device after fresh Keys Use authority. `None` means no credential
    /// was ever stored. A record bound to another device or member is `Foreign`.
    pub async fn community_credential(
        &mut self,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let (community, member, device) = self.credential_binding(&store).await?;
        match store
            .read(OWNER, KEY)
            .map_err(|_| CredentialError::Storage)?
        {
            None => Ok(None),
            Some(record) => unframe(record, &community, &member, &device)
                .map(|credential| Some(Zeroizing::new(credential.to_vec()))),
        }
    }

    /// Store or replace the community credential by compare-and-swap. `expected`
    /// is the credential the caller believes is current (`None` for the first);
    /// anything else is `Conflict` and nothing is written. Replaying the
    /// identical credential is `Unchanged`. The credential is bound to the
    /// current community, member and device and committed under the Store's
    /// version fence in one operation.
    pub async fn replace_community_credential(
        &mut self,
        expected: Option<&[u8]>,
        credential: &[u8],
    ) -> Result<CredentialWrite, CredentialError> {
        if credential.is_empty() || credential.len() > MAX_COMMUNITY_CREDENTIAL_BYTES {
            return Err(CredentialError::Invalid);
        }
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        let (community, member, device) = self.credential_binding(&store).await?;
        let current = match store
            .read(OWNER, KEY)
            .map_err(|_| CredentialError::Storage)?
        {
            None => None,
            Some(record) => Some(unframe(record, &community, &member, &device)?.to_vec()),
        };
        if current.as_deref() == Some(credential) {
            return Ok(CredentialWrite::Unchanged);
        }
        if current.as_deref() != expected {
            return Err(CredentialError::Conflict);
        }
        let record = frame(&community, &member, &device, credential);
        let version = store.version().map_err(|_| CredentialError::Storage)?;
        let mut operation =
            blake3::Hasher::new_derive_key("cvlt.community-credential.operation.v1");
        operation.update(&version.to_be_bytes());
        operation.update(blake3::hash(&record).as_bytes());
        store
            .commit(
                version,
                *operation.finalize().as_bytes(),
                &[Change::Put {
                    owner: OWNER,
                    key: KEY,
                    value: &record,
                }],
                &[],
            )
            .await
            .map_err(|error| match error {
                cwst::Error::Conflict => CredentialError::Conflict,
                _ => CredentialError::Storage,
            })?;
        Ok(CredentialWrite::Stored)
    }

    pub(crate) async fn credential_binding(
        &mut self,
        store: &cwst::Store<B>,
    ) -> Result<(String, String, [u8; 32]), CredentialError> {
        let lineage = self.keys.lineage().await.map_err(CredentialError::Keys)?;
        let device = self
            .keys
            .device_public_key()
            .await
            .map_err(CredentialError::Keys)?;
        let binding = lineage.binding;
        if binding.community() == "wallet" || !store.is_scope(binding.community()) {
            return Err(CredentialError::Scope);
        }
        Ok((
            binding.community().to_owned(),
            binding.member().to_owned(),
            *device.value(),
        ))
    }
}
