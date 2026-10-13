//! The member's pin of the community's founding key: a record beside the
//! community credential, under the same Keys-held wrapping and bound to the same
//! community + member + device. It remembers which founding key this membership
//! belongs to and the newest verified key-chain head, so a feed that rolls back,
//! forks or belongs to another founding key can be recognised on the device.
//! The pin is written in the same Store commit as any credential change.
use crate::{CredentialError, Records, Vault};
use ckmg::{Authority, Clock, Entropy};
use cwst::{Change, backend::Backend};

const OWNER: &str = "cvlt.community-pin";
const KEY: &[u8] = b"current";
const HEADER: &[u8] = b"cvlt.community-pin.v1\0";
const RECORD_LEN: usize = 1 + 32 + 1 + 8 + 32;

/// Newest verified key-chain head: ring revision and ring digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedHead {
    /// Sequence number of the public key ring.
    pub ring_revision: u64,
    /// Digest of that exact ring.
    pub digest: [u8; 32],
}

/// The pinned founding key of one membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityPin {
    /// SHA-256 of the community's genesis document.
    pub fingerprint: [u8; 32],
    /// Newest verified chain head; `None` until a feed has verified.
    pub head: Option<PinnedHead>,
}

impl CommunityPin {
    fn frame(&self, community: &str, member: &str, device: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER.len() + RECORD_LEN + 80);
        out.extend_from_slice(HEADER);
        for text in [community.as_bytes(), member.as_bytes()] {
            out.extend_from_slice(&(text.len() as u32).to_be_bytes());
            out.extend_from_slice(text);
        }
        out.extend_from_slice(device);
        out.push(1);
        out.extend_from_slice(&self.fingerprint);
        match self.head {
            Some(head) => {
                out.push(1);
                out.extend_from_slice(&head.ring_revision.to_be_bytes());
                out.extend_from_slice(&head.digest);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 40]);
            }
        }
        out
    }

    fn unframe(
        record: &[u8],
        community: &str,
        member: &str,
        device: &[u8; 32],
    ) -> Result<Self, CredentialError> {
        let foreign = CredentialError::Foreign;
        let mut rest = record.strip_prefix(HEADER).ok_or(foreign)?;
        let mut take = |length: usize| -> Result<&[u8], CredentialError> {
            if rest.len() < length {
                return Err(foreign);
            }
            let (head, tail) = rest.split_at(length);
            rest = tail;
            Ok(head)
        };
        for expected in [community.as_bytes(), member.as_bytes()] {
            let length: [u8; 4] = take(4)?.try_into().map_err(|_| foreign)?;
            if take(u32::from_be_bytes(length) as usize)? != expected {
                return Err(foreign);
            }
        }
        if take(32)? != device || take(1)? != [1] {
            return Err(foreign);
        }
        let fingerprint: [u8; 32] = take(32)?.try_into().map_err(|_| foreign)?;
        let flag = take(1)?[0];
        let revision: [u8; 8] = take(8)?.try_into().map_err(|_| foreign)?;
        let digest: [u8; 32] = take(32)?.try_into().map_err(|_| foreign)?;
        let head = match flag {
            0 if revision == [0; 8] && digest == [0; 32] => None,
            1 => Some(PinnedHead {
                ring_revision: u64::from_be_bytes(revision),
                digest,
            }),
            _ => return Err(foreign),
        };
        if !rest.is_empty() {
            return Err(foreign);
        }
        Ok(Self { fingerprint, head })
    }

    /// Whether `self` may replace `current`: the same founding key never moves
    /// its head backwards or sideways; another founding key starts without a head.
    fn succeeds(&self, current: &Self) -> bool {
        if self.fingerprint != current.fingerprint {
            return self.head.is_none();
        }
        match (current.head, self.head) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(old), Some(new)) => {
                new.ring_revision > old.ring_revision
                    || (new.ring_revision == old.ring_revision && new.digest == old.digest)
            }
        }
    }
}

impl<B: Backend, C: Clock, E: Entropy, A: Authority, R: Records, W> Vault<B, C, E, A, R, W> {
    /// Read the pin for this exact community, member and current device after
    /// fresh Keys Use authority. `None` means nothing was ever pinned.
    pub async fn community_pin(&mut self) -> Result<Option<CommunityPin>, CredentialError> {
        let storage = self.storage.clone();
        let store = storage.lock().await;
        let (community, member, device) = self.credential_binding(&store).await?;
        match store
            .read(OWNER, KEY)
            .map_err(|_| CredentialError::Storage)?
        {
            None => Ok(None),
            Some(record) => CommunityPin::unframe(record, &community, &member, &device).map(Some),
        }
    }

    /// Store `pin` by compare-and-swap: `expected` must be the current pin
    /// (`None` for the first). The head only moves forward (see
    /// [`CommunityPin`]); a different founding key replaces the pin only with a
    /// headless one. Replaying the identical pin writes nothing. When
    /// `credential` is given, the credential record is replaced in the same
    /// Store commit: both change or neither does.
    pub async fn write_community_pin(
        &mut self,
        expected: Option<&CommunityPin>,
        pin: &CommunityPin,
        credential: Option<(Option<&[u8]>, &[u8])>,
    ) -> Result<bool, CredentialError> {
        let storage = self.storage.clone();
        let mut store = storage.lock().await;
        let (community, member, device) = self.credential_binding(&store).await?;
        let current = match store
            .read(OWNER, KEY)
            .map_err(|_| CredentialError::Storage)?
        {
            None => None,
            Some(record) => Some(CommunityPin::unframe(record, &community, &member, &device)?),
        };
        if current.as_ref() != expected {
            return Err(CredentialError::Conflict);
        }
        if current
            .as_ref()
            .is_some_and(|current| !pin.succeeds(current))
        {
            return Err(CredentialError::Conflict);
        }
        let credential_record = match credential {
            None => None,
            Some((expected_credential, new)) => crate::credential::credential_record(
                &store,
                &community,
                &member,
                &device,
                expected_credential,
                new,
            )?,
        };
        if current.as_ref() == Some(pin) && credential_record.is_none() {
            return Ok(false);
        }
        let record = pin.frame(&community, &member, &device);
        let version = store.version().map_err(|_| CredentialError::Storage)?;
        let mut operation = blake3::Hasher::new_derive_key("cvlt.community-pin.operation.v1");
        operation.update(&version.to_be_bytes());
        operation.update(blake3::hash(&record).as_bytes());
        let mut changes = vec![Change::Put {
            owner: OWNER,
            key: KEY,
            value: &record,
        }];
        if let Some(credential_record) = &credential_record {
            operation.update(blake3::hash(credential_record).as_bytes());
            changes.push(Change::Put {
                owner: crate::credential::CREDENTIAL_OWNER,
                key: crate::credential::CREDENTIAL_KEY,
                value: credential_record,
            });
        }
        store
            .commit(version, *operation.finalize().as_bytes(), &changes, &[])
            .await
            .map_err(|error| match error {
                cwst::Error::Conflict => CredentialError::Conflict,
                _ => CredentialError::Storage,
            })?;
        Ok(true)
    }
}
