//! Persistent unlock (DESIGN-secure-convenience part 4, M6): the device reopens its joined
//! communities after a restart from the sealed bundle, with NO passkey ceremony; forgetting
//! the bundle (explicit lock, opt-out, revocation) forces one again. The bundle never holds W.
use super::existing::{passkeys, unlock};
use cvlt::{ResumeBundle, WalletUnlock};

const JOINED: [([u8; 32], &str); 2] = [([1; 32], "garden"), ([2; 32], "orchard")];

fn device(bundle: &ResumeBundle, (fingerprint, scope): ([u8; 32], &str)) -> ckmg::PublicKey {
    bundle.community(&fingerprint, scope).unwrap().device().unwrap()
}

async fn minted() -> (WalletUnlock, ResumeBundle) {
    let wallet = WalletUnlock::new(unlock(&mut passkeys().await).await);
    let bundle = wallet.resume_bundle(&JOINED).unwrap();
    (wallet, bundle)
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use cvlt::NativeResume;

    fn store(dir: &std::path::Path) -> NativeResume {
        NativeResume::new(dir, b"wallet.example.test\0account-1", None)
    }

    #[test]
    fn restart_reopens_joined_communities_without_a_ceremony() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (wallet, bundle) = minted().await;
            store(dir.path()).save(&bundle).unwrap();
            drop(bundle);
            // Restart: a fresh store object, no passkey client exists at all.
            let resumed = store(dir.path()).load().expect("resumed without a ceremony");
            for joined in JOINED {
                let direct = wallet.community(&joined.0, joined.1).unwrap().device().unwrap();
                assert_eq!(device(&resumed, joined), direct);
            }
            // A community not yet joined is not in the bundle: it needs the passkey (a stamp).
            assert!(resumed.community(&[3; 32], "meadow").is_err());
            assert_eq!(resumed.memberships().count(), 2);
        });
    }

    #[test]
    fn forget_forces_a_ceremony_and_files_are_user_only() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (_, bundle) = minted().await;
            let store = store(dir.path());
            store.save(&bundle).unwrap();
            #[cfg(unix)]
            for name in ["resume.v1", "resume.v1.key"] {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.path().join(name)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            assert!(!store.in_os_keyring());
            store.forget().unwrap();
            assert!(store.load().is_none());
            assert!(!dir.path().join("resume.v1").exists());
            assert!(!dir.path().join("resume.v1.key").exists());
            store.forget().unwrap();
        });
    }

    #[test]
    fn tampered_or_foreign_records_fail_safe_and_are_forgotten() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (_, bundle) = minted().await;
            store(dir.path()).save(&bundle).unwrap();
            let other = NativeResume::new(dir.path(), b"wallet.example.test\0account-2", None);
            assert!(other.load().is_none());
            assert!(!dir.path().join("resume.v1").exists());

            store(dir.path()).save(&bundle).unwrap();
            let path = dir.path().join("resume.v1");
            let mut record = std::fs::read(&path).unwrap();
            let last = record.len() - 1;
            record[last] ^= 1;
            std::fs::write(&path, record).unwrap();
            assert!(store(dir.path()).load().is_none());

            store(dir.path()).save(&bundle).unwrap();
            std::fs::write(dir.path().join("resume.v1.key"), [0; 31]).unwrap();
            assert!(store(dir.path()).load().is_none());
            assert!(store(dir.path()).load().is_none());
        });
    }

    #[test]
    fn save_over_an_earlier_unlock_replaces_it() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (wallet, bundle) = minted().await;
            store(dir.path()).save(&bundle).unwrap();
            let one = wallet.resume_bundle(&JOINED[..1]).unwrap();
            store(dir.path()).save(&one).unwrap();
            assert_eq!(store(dir.path()).load().unwrap().memberships().count(), 1);
        });
    }

    #[test]
    fn unwritable_directory_is_a_storage_error() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("file");
            std::fs::write(&file, b"x").unwrap();
            let (_, bundle) = minted().await;
            let store = NativeResume::new(&file.join("sub"), b"b", None);
            assert_eq!(store.save(&bundle), Err(cvlt::ResumeError::Storage));
        });
    }

    /// With the OS key store enabled the round trip works wherever it lands: in the key
    /// store when one is usable, else in the user-only file (headless Linux CI).
    #[cfg(feature = "os-keyring")]
    #[test]
    fn os_keyring_or_file_fallback_round_trips() {
        futures_executor::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (_, bundle) = minted().await;
            let service = format!("cvlt-resume-test-{}", std::process::id());
            let store = NativeResume::new(dir.path(), b"wallet.example.test\0kr", Some(&service));
            store.save(&bundle).unwrap();
            assert_eq!(
                store.in_os_keyring(),
                !dir.path().join("resume.v1.key").exists()
            );
            assert!(store.load().is_some());
            store.forget().unwrap();
            assert!(store.load().is_none());
            assert!(!store.in_os_keyring());
        });
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::*;
    use cvlt::BrowserResume;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(inline_js = "
export async function probeResumeKey(name) {
  const db = await new Promise((resolve, reject) => {
    const r = indexedDB.open(name, 1);
    r.onerror = () => reject(new Error('storage'));
    r.onsuccess = () => resolve(r.result);
  });
  const key = await new Promise((resolve, reject) => {
    const tx = db.transaction('resume', 'readonly');
    const g = tx.objectStore('resume').get('key');
    tx.oncomplete = () => resolve(g.result);
    tx.onabort = () => reject(new Error('storage'));
  });
  db.close();
  let exported = true;
  try { await crypto.subtle.exportKey('raw', key); } catch (_) { exported = false; }
  return [key instanceof CryptoKey, key.extractable, exported];
}")]
    extern "C" {
        #[wasm_bindgen(catch, js_name = probeResumeKey)]
        async fn probe_resume_key(name: &str) -> Result<JsValue, JsValue>;
    }

    #[wasm_bindgen_test]
    async fn browser_restart_reopens_and_key_is_not_extractable() {
        let name = "cvlt-resume-test-1";
        let (wallet, bundle) = minted().await;
        let store = BrowserResume::new(name, b"wallet.example.test\0account-1").unwrap();
        store.save(&bundle).await.unwrap();
        let resumed = BrowserResume::new(name, b"wallet.example.test\0account-1")
            .unwrap()
            .load()
            .await
            .expect("resumed without a ceremony");
        let direct = wallet.community(&JOINED[0].0, JOINED[0].1).unwrap().device().unwrap();
        assert_eq!(device(&resumed, JOINED[0]), direct);
        let probe = js_sys::Array::from(&probe_resume_key(name).await.unwrap());
        assert_eq!(probe.get(0).as_bool(), Some(true), "a CryptoKey object");
        assert_eq!(probe.get(1).as_bool(), Some(false), "extractable: false");
        assert_eq!(probe.get(2).as_bool(), Some(false), "exportKey is refused");
        let foreign = BrowserResume::new(name, b"wallet.example.test\0account-2").unwrap();
        assert!(foreign.load().await.is_none());
        assert!(store.load().await.is_none());
        store.save(&bundle).await.unwrap();
        store.forget().await.unwrap();
        assert!(store.load().await.is_none());
        assert!(BrowserResume::new("", b"x").is_err());
    }
}
