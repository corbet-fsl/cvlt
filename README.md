# cvlt — Vault

## Scope

### Purpose

The member's safe on the device: it wires Keys (`ckmg`), Storage (`cwst`), Records (`cdht`) and Wallet (`cwlt`), opens when the passkey PRF secret arrives, and hands out operations, never secret roots.

### Owns

Capability wiring of `ckmg`, `cwst`, `cdht` and `cwlt` with one shared transaction boundary for cross-owner checkpoints. Sole holder of the client storage connection, so all other member-side state goes through the vault. The one handover of the PRF secret from Passkeys into Keys, consume-only and zeroizing. Restore orchestration with three outcomes: Present, KnownAbsent, Unavailable. On the web, runs isolated with heavy proof work in a worker inside that isolation.

### Never

Exposes raw secrets, root secrets, or wrapping secrets to callers. Recovers through operator identity or any path beyond the passkey. Contains network code. Joins stores from different communities. Resolves domain conflicts or keeps a second wallet or device roster. Infers absence from unavailable data or creates a new identity during restore.

### States

Derived Locked, Ready, Restoring, Unavailable, or Unrecoverable. Locked with PRF unavailable when a sign-in yields no PRF secret.

### Test obligations

Same facade contract against native and browser stores, with locked access refused. Restore verifies records before use; missing replicas report Unavailable, never a new account. A combined checkpoint across owners survives injected failures at every point. Lock wipes Keys and decrypted storage together. End-to-end restore with Records and Wallet. Identical test vectors on native and browser builds, explicit states with injected clock, randomness, storage and network, full line and branch coverage with real round trips and injected delay, loss, duplication, cancellation, clock regression, corruption and storage conflicts, atomic publication where unknown outcomes reconcile without regenerating keys, proofs or effects, strict per-community isolation, and bounded work with identifiers, plaintext and secrets omitted from errors.

## Implementation boundaries

The KeyStore adapter commits actual encrypted Keys checkpoints with opaque
companion changes and outputs under one storage fence. Staging never reports
durable success. Cancellation, conflicts and unknown outcomes reconcile through
the owner. Keys' pending receipt remains inside its sealed checkpoint.

Records, Wallet, live G3 authority, equal-passkey root custody and the browser
iframe ceremony are pending owner integrations. Current Keys dependency behavior
that derives a privileged identity from PRF does not satisfy this restore contract. No permissive authority or proof engine
is supplied. The decided custody and restore rules above are requirements, not
claims that these missing integrations already pass.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

## License

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
