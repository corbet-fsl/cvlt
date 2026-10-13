//! Bounded original read observations retained in the authenticated common Store.
use crate::records::tor::Verifier;
use cwst::{Store, backend::Backend};
use serde::{Deserialize, Serialize};

pub(crate) const OWNER: &str = "cvlt-read-observations";
pub(crate) const KEY: &[u8] = b"recovery-selection";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Carrier {
    pub(crate) state: cdht::ClientState,
    pub(crate) checked_at: u64,
    pub(crate) source_digest: [u8; 32],
    pub(crate) source_version: u64,
}
impl Carrier {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, cwst::Error> {
        validate_state(&self.state)?;
        if self.source_digest == [0; 32] || self.source_version < 2 {
            return Err(cwst::Error::Corrupt);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| cwst::Error::Corrupt)?;
        if bytes.len() > cwst::MAX_VALUE_BYTES {
            return Err(cwst::Error::TooLarge);
        }
        Ok(bytes)
    }
}
pub(crate) fn validate_state(state: &cdht::ClientState) -> Result<(), cwst::Error> {
    let client = cdht::Dht::with_state(cdht::LocalBackend::new(Verifier), Verifier, state.clone());
    if client.state() != state
        || !state.queue().is_empty()
        || state == &cdht::ClientState::default()
    {
        return Err(cwst::Error::Corrupt);
    }
    Ok(())
}
pub(crate) fn load<B: Backend>(store: &Store<B>) -> Result<Option<Carrier>, cwst::Error> {
    let Some(bytes) = store.read(OWNER, KEY)? else {
        return Ok(None);
    };
    if bytes.len() > cwst::MAX_VALUE_BYTES {
        return Err(cwst::Error::TooLarge);
    }
    let carrier: Carrier = serde_json::from_slice(bytes).map_err(|_| cwst::Error::Corrupt)?;
    carrier.bytes()?;
    if carrier.source_version >= store.version()? {
        return Err(cwst::Error::Corrupt);
    }
    Ok(Some(carrier))
}

// Borrowing is confined to authentication of this actual backend; no clone or
// caller-supplied decrypted checkpoint replaces its source.
pub(crate) struct BorrowBackend<'a, B>(pub(crate) &'a B);
impl<B: Backend> Backend for BorrowBackend<'_, B> {
    async fn read(&self) -> Result<Option<Vec<u8>>, cwst::Error> {
        self.0.read().await
    }
    async fn compare_exchange(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<(), cwst::Error> {
        self.0.compare_exchange(expected, next).await
    }
}
