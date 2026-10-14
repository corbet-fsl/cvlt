//! The owed account update: one record in the Vault Store, separate from the
//! voucher custody so that neither can fill the other's size cap.
//!
//! It holds the exact signed bytes of the account update that was sent or is
//! about to be sent (public data, opaque here). It is bound to community +
//! member + device, replaced only by version-fenced compare-and-swap, and an
//! EMPTY record means "nothing owed" (the reader returns `None`).
use crate::{CredentialError, CredentialWrite};
use crate::{Records, Vault};
use ckmg::{Authority, Clock, Entropy};
use cwst::{Change, backend::Backend};
use zeroize::Zeroizing;

const OWNER: &str = "cvlt.update-outbox";
const KEY: &[u8] = b"current";
const HEADER: &[u8] = b"cvlt.update-outbox.v1\0";

/// Largest custody blob accepted.
pub const MAX_UPDATE_OUTBOX_BYTES: usize = 768 * 1024;

fn frame(community: &str, member: &str, device: &[u8; 32], custody: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(
        HEADER.len() + community.len() + member.len() + 32 + custody.len() + 12,
    ));
    out.extend_from_slice(HEADER);
    for text in [community.as_bytes(), member.as_bytes()] {
        out.extend_from_slice(&(text.len() as u32).to_be_bytes());
        out.extend_from_slice(text);
    }
    out.extend_from_slice(device);
    out.extend_from_slice(&(custody.len() as u32).to_be_bytes());
    out.extend_from_slice(custody);
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
    let custody = cursor.counted()?;
    if !cursor.0.is_empty()
        || found_community != community.as_bytes()
        || found_member != member.as_bytes()
        || found_device != device
        || custody.len() > MAX_UPDATE_OUTBOX_BYTES
    {
        return Err(CredentialError::Foreign);
    }
    Ok(custody)
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Read the stored voucher custody for this exact community, member and
    /// current device after fresh Keys Use authority. `None` means no custody
    /// was ever stored. A record bound to another device or member is `Foreign`.
    pub async fn update_outbox(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, CredentialError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let (community, member, device) = self.credential_binding(&store).await?;
        match store
            .read(OWNER, KEY)
            .map_err(|_| CredentialError::Storage)?
        {
            None => Ok(None),
            Some(record) => unframe(record, &community, &member, &device).map(|custody| {
                (!custody.is_empty()).then(|| Zeroizing::new(custody.to_vec()))
            }),
        }
    }

    /// Store or replace the voucher custody by compare-and-swap. `expected`
    /// is the custody blob the caller believes is current (`None` for the first);
    /// anything else is `Conflict` and nothing is written. Replaying the
    /// identical custody is `Unchanged`. The custody is bound to the
    /// current community, member and device and committed under the Store's
    /// version fence in one operation.
    pub async fn replace_update_outbox(
        &mut self,
        expected: Option<&[u8]>,
        custody: &[u8],
    ) -> Result<CredentialWrite, CredentialError> {
        if custody.len() > MAX_UPDATE_OUTBOX_BYTES {
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
        let current = current.filter(|bytes| !bytes.is_empty());
        if current.as_deref().unwrap_or(&[]) == custody {
            return Ok(CredentialWrite::Unchanged);
        }
        if current.as_deref() != expected {
            return Err(CredentialError::Conflict);
        }
        let record = frame(&community, &member, &device, custody);
        let version = store.version().map_err(|_| CredentialError::Storage)?;
        let mut operation = blake3::Hasher::new_derive_key("cvlt.update-outbox.operation.v1");
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
}
