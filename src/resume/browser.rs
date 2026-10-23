//! Browser resume store: WebCrypto AES-GCM with a non-extractable key in IndexedDB on
//! the wallet origin (`browser/resume.js`, a sibling of cwst's `checkpoint.js`).
//! The member origin never sees the key; the vault frame is the only caller.
use super::{ResumeBundle, ResumeError, aad};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[wasm_bindgen(module = "/browser/resume.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = resumeSave)]
    async fn resume_save(name: &str, aad: &[u8], plain: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = resumeLoad)]
    async fn resume_load(name: &str, aad: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = resumeForget)]
    async fn resume_forget(name: &str) -> Result<JsValue, JsValue>;
}

/// The browser persistent unlock of one wallet binding, in IndexedDB database `name`.
pub struct BrowserResume {
    name: String,
    binding: Vec<u8>,
}

impl BrowserResume {
    /// A store in IndexedDB database `name` (local, opaque) for `binding` (wallet host
    /// and account).
    pub fn new(name: &str, binding: &[u8]) -> Result<Self, ResumeError> {
        if name.is_empty() || name.len() > 256 {
            return Err(ResumeError::Invalid);
        }
        Ok(Self {
            name: name.to_owned(),
            binding: binding.to_owned(),
        })
    }

    /// Seal `bundle` as this device's persistent unlock, replacing any earlier one.
    pub async fn save(&self, bundle: &ResumeBundle) -> Result<(), ResumeError> {
        let plain = bundle.encode();
        resume_save(&self.name, &aad(&self.binding), &plain)
            .await
            .map(|_| ())
            .map_err(|_| ResumeError::Storage)
    }

    /// The persisted unlock, if one opens; anything else reads as `None` and is forgotten.
    pub async fn load(&self) -> Option<ResumeBundle> {
        let opened = match resume_load(&self.name, &aad(&self.binding)).await {
            Ok(value) if value.is_instance_of::<js_sys::Uint8Array>() => {
                let plain = Zeroizing::new(js_sys::Uint8Array::from(value).to_vec());
                ResumeBundle::decode(&plain).ok()
            }
            _ => None,
        };
        if opened.is_none() {
            let _ = self.forget().await;
        }
        opened
    }

    /// Delete the persisted unlock (key and record).
    pub async fn forget(&self) -> Result<(), ResumeError> {
        resume_forget(&self.name)
            .await
            .map(|_| ())
            .map_err(|_| ResumeError::Storage)
    }
}
