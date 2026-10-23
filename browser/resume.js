// cvlt persistent unlock (browser): a WebCrypto AES-GCM key generated with
// extractable: false, kept as a CryptoKey (structured clone) in IndexedDB on the
// wallet origin, seals the resume bundle. The key is never exported or wrapped.
// Layout: database <name>, store "resume", keys "key" (CryptoKey) and "record"
// ({iv, sealed}). Any failure to open reads as null (one passkey confirmation).
const STORE = 'resume';

function open(name) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onerror = () => reject(new Error('storage'));
    request.onsuccess = () => resolve(request.result);
  });
}

function run(db, mode, act) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const out = act(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(out.result);
    tx.onabort = tx.onerror = () => reject(new Error('storage'));
  });
}

async function key(db, create) {
  const held = await run(db, 'readonly', (s) => s.get('key'));
  if (held instanceof CryptoKey || !create) return held || null;
  const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false,
    ['encrypt', 'decrypt']);
  await run(db, 'readwrite', (s) => s.put(fresh, 'key'));
  return fresh;
}

export async function resumeSave(name, aad, plain) {
  const db = await open(name);
  try {
    const k = await key(db, true);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, k, plain));
    await run(db, 'readwrite', (s) => s.put({ iv, sealed }, 'record'));
  } finally {
    db.close();
  }
  if (navigator.storage && navigator.storage.persist) {
    try { await navigator.storage.persist(); } catch (_) { /* best effort */ }
  }
}

export async function resumeLoad(name, aad) {
  const db = await open(name);
  try {
    const k = await key(db, false);
    const record = await run(db, 'readonly', (s) => s.get('record'));
    if (!k || !record) return null;
    try {
      return new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: record.iv, additionalData: aad }, k, record.sealed));
    } catch (_) {
      return null;
    }
  } finally {
    db.close();
  }
}

export async function resumeForget(name) {
  const db = await open(name);
  try {
    await run(db, 'readwrite', (s) => s.clear());
  } finally {
    db.close();
  }
}
