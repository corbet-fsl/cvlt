//! Persistent unlock v2 (U2b): the device reopens its joined communities after a restart
//! from the sealed bundle of per-community `ckmg::DeviceDelegation`s, with NO passkey
//! ceremony; forgetting the bundle (explicit lock, opt-out, revocation) forces one again.
//! The bundle never holds W or U_c (byte tests in `src/resume/tests.rs`).
use ckmg::{Authorization, Binding, DeviceInfo, Error, Keys, Purpose, Scope};
use cvlt::ResumeBundle;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const JOINED: [([u8; 32], &str); 2] = [([1; 32], "garden"), ([2; 32], "orchard")];

fn device(bundle: &ResumeBundle, (fingerprint, scope): ([u8; 32], &str)) -> ckmg::PublicKey {
    bundle
        .delegation(&fingerprint, scope)
        .unwrap()
        .device_public_key()
}

#[derive(Clone)]
struct Time;
impl ckmg::Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(1000)
    }
}

/// Permissive test authority; not production membership.
struct Live;
impl ckmg::Authority for Live {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

/// The delegate keys enrolled per joined community, in `JOINED` order.
struct Enrolled(Vec<ckmg::PublicKey>);
impl Enrolled {
    fn community(&self, fingerprint: &[u8; 32], _: &str) -> Result<&ckmg::PublicKey, ()> {
        let index = JOINED.iter().position(|joined| &joined.0 == fingerprint);
        index.map(|index| &self.0[index]).ok_or(())
    }
}

/// Test-only in-memory key store.
#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<ckmg::Locator, Vec<u8>>>>);
impl ckmg::SecureStore for Memory {
    async fn load(&mut self, location: &ckmg::Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<ckmg::Commit, Error> {
        let mut data = self.0.borrow_mut();
        if data.get(location).map(|v| *blake3::hash(v).as_bytes()) != expected {
            return Ok(ckmg::Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
        Ok(ckmg::Commit::Committed)
    }
}

/// A ceremony's community custody per joined community, and the delegation enrolled under
/// each while it is open (the PRF's origin is irrelevant here; `src/resume/tests.rs`
/// derives it from `W` and checks the bytes).
async fn mint(joined: &[([u8; 32], &str)]) -> (Enrolled, ResumeBundle) {
    let mut bundle = ResumeBundle::new();
    let mut enrolled = Vec::new();
    for (fingerprint, scope) in joined {
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[fingerprint[0] ^ 0x40; 32]).unwrap();
        let mut keys = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Live);
        let receipt = keys
            .create_scope(
                &prf,
                Binding::new(scope, "member").unwrap(),
                DeviceInfo::new("device", b"credential").unwrap(),
                b"registration",
            )
            .await
            .unwrap();
        keys.acknowledge(receipt.operation).await.unwrap();
        let purposes = [Purpose::new(Scope::Member, "board", 1).unwrap()];
        let (receipt, delegation) = keys.delegate_device(&purposes, b"ceremony").await.unwrap();
        keys.acknowledge(receipt.operation).await.unwrap();
        enrolled.push(delegation.device_public_key());
        bundle.insert(*fingerprint, scope, delegation).unwrap();
    }
    (Enrolled(enrolled), bundle)
}

async fn minted() -> (Enrolled, ResumeBundle) {
    mint(&JOINED).await
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
            let resumed = store(dir.path())
                .load()
                .expect("resumed without a ceremony");
            for joined in JOINED {
                let direct = *wallet.community(&joined.0, joined.1).unwrap();
                assert_eq!(device(&resumed, joined), direct);
            }
            // A community not yet joined is not in the bundle: it needs the passkey (a stamp).
            assert!(resumed.delegation(&[3; 32], "meadow").is_none());
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
            for name in ["resume.v2", "resume.v2.key"] {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            assert!(!store.in_os_keyring());
            store.forget().unwrap();
            assert!(store.load().is_none());
            assert!(!dir.path().join("resume.v2").exists());
            assert!(!dir.path().join("resume.v2.key").exists());
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
            assert!(!dir.path().join("resume.v2").exists());

            store(dir.path()).save(&bundle).unwrap();
            let path = dir.path().join("resume.v2");
            let mut record = std::fs::read(&path).unwrap();
            let last = record.len() - 1;
            record[last] ^= 1;
            std::fs::write(&path, record).unwrap();
            assert!(store(dir.path()).load().is_none());

            store(dir.path()).save(&bundle).unwrap();
            std::fs::write(dir.path().join("resume.v2.key"), [0; 31]).unwrap();
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
            let (_, one) = mint(&JOINED[..1]).await;
            let _ = wallet;
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
                !dir.path().join("resume.v2.key").exists()
            );
            assert!(store.load().is_some());
            store.forget().unwrap();
            assert!(store.load().is_none());
            assert!(!store.in_os_keyring());
        });
    }

    /// Headless Linux (no D-Bus session bus, so no Secret Service): the wrapping key lands in the
    /// user-only file, the unlock round-trips and its files are forgotten, nothing panics and nothing hangs.
    /// A child process runs the round trip with the bus variables pointed at nothing, so the result
    /// does not depend on the session of the machine running the suite; the parent bounds it.
    #[cfg(all(feature = "os-keyring", target_os = "linux"))]
    #[test]
    fn headless_without_a_session_bus_falls_back_to_the_key_file() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
        let work = tempfile::tempdir().unwrap();
        let vault = work.path().join("vault");
        let empty_runtime_dir = work.path().join("runtime");
        std::fs::create_dir(&empty_runtime_dir).unwrap();
        let log = |name| std::fs::File::create(work.path().join(name)).unwrap();
        let test = format!(
            "{}::headless_child",
            module_path!().split_once("::").unwrap().1
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture", "--test-threads=1"])
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
            .env("XDG_RUNTIME_DIR", &empty_runtime_dir)
            .env("CVLT_TEST_HEADLESS_VAULT", &vault)
            .stdout(log("stdout"))
            .stderr(log("stderr"))
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if started.elapsed() > DEADLINE {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let text = |name| std::fs::read_to_string(work.path().join(name)).unwrap_or_default();
        let (out, err) = (text("stdout"), text("stderr"));
        assert!(status.is_some(), "hung past {DEADLINE:?}\n{out}\n{err}");
        assert!(status.unwrap().success(), "child failed\n{out}\n{err}");
        assert!(
            out.contains("1 passed"),
            "child test did not run\n{out}\n{err}"
        );
    }

    /// The child of the headless test: a no-op unless the parent set `CVLT_TEST_HEADLESS_VAULT`.
    /// The calls run on a tokio worker thread, as cmsg makes them, so a key store backend that
    /// cannot be called from inside a runtime would panic here.
    #[cfg(all(feature = "os-keyring", target_os = "linux"))]
    #[test]
    fn headless_child() {
        let Some(vault) = std::env::var_os("CVLT_TEST_HEADLESS_VAULT") else {
            return;
        };
        let vault = std::path::PathBuf::from(vault);
        let (_, bundle) = futures_executor::block_on(minted());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let store = NativeResume::new(
                    &vault,
                    b"wallet.example.test\0headless",
                    Some("cvlt-resume-test-headless"),
                );
                store.save(&bundle).unwrap();
                assert!(!store.in_os_keyring());
                let key = vault.join("resume.v2.key");
                let mode = std::os::unix::fs::PermissionsExt::mode(
                    &std::fs::metadata(&key).unwrap().permissions(),
                );
                assert_eq!(mode & 0o777, 0o600);
                assert!(store.load().is_some());
                // `forget` reports the unreachable key store as a storage error; the record and
                // the key file are gone either way, which is what this checks.
                let _ = store.forget();
                assert!(store.load().is_none());
                assert!(!key.exists());
            })
            .await
            .unwrap();
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
        let direct = *wallet.community(&JOINED[0].0, JOINED[0].1).unwrap();
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
        // Revocation wipe: the vault's databases are deleted (also the resume store's).
        store.save(&bundle).await.unwrap();
        cvlt::erase_local_databases(&[name]).await.unwrap();
        assert!(store.load().await.is_none());
    }
}
