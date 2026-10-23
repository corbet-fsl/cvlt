# cvlt — Vault

## Scope

**Purpose and home.** The member's safe on the device, under `cmsg → cvlt`: wire
Keys, Storage, Records and Wallet, open through the passkey PRF handover, and lend
operations rather than roots.

**Owns.** Capability wiring of `ckmg`, `cwst`, `cdht` and `cwlt`, the sole client
storage connection, and their shared `cwst` transaction boundary. Vault performs
the consume-only, non-serializable, zeroizing Passkeys-to-Keys handover and restore
orchestration. Web isolation uses `vault.<baseDomain>` with proof work in a worker
inside that iframe; the door includes that origin and pins its RP ID.

**Never.** Exposes root, holder or wrapping secrets; implements operator recovery,
network code, domain conflict rules, a second wallet or device roster; joins
community stores; infers absence or creates an identity during restore. Keys owns
lineage and derives the passport holder seed. Wallet holds the passport and makes
presentations with Pseudonyms' holder engine.

**States and ports.** Intended derived states: Locked, Ready, Restoring, Unavailable
or Unrecoverable. Not yet implemented: this crate defines no type or variant of those
names. Today the Vault carries no state of its own: no Vault exists before an opening
succeeds, `lock` consumes it, and Keys reports its own `ckmg::State`. Missing PRF
leaves the vault Locked independently of server sign-in. The implemented
ports lend Keys, shared Storage, staged compound batches, Records lookup and Wallet,
and provide `lock`. Restore distinguishes Present, KnownAbsent and Unavailable.
Full unlock/restore wiring depends on the corresponding owner capabilities.

**Restore invariant.** Every enrolled passkey has equal capabilities. A random
common identity root is retained in member DHT records as a separate authenticated
wrapped copy under each passkey. Active devices refresh their records. There is
no privileged first passkey or operator-held copy. If long absence and loss of all
local copies also leave no DHT records, identity and data can both be lost, with
the same implications for every passkey. Unavailable data never authorizes a
replacement identity. Keys and Records own the wrapping and discovery formats;
Vault wires their capabilities without inventing a recovery mechanism.

**Test obligations.** Native and browser storage contracts, locked refusal,
authenticated restore records, and failures at every combined owner checkpoint
boundary. `lock` wipes Keys and shared decrypted Storage. Full active-member
restore requires real Records and Wallet, with unavailable replicas kept distinct
from authenticated absence; adapter coverage is not that end-to-end evidence.

## Implementation boundaries

The KeyStore adapter commits actual encrypted Keys checkpoints with opaque
companion changes and outputs under one storage fence. Staging never reports
durable success. Cancellation, conflicts and unknown outcomes reconcile through
the owner. Keys' pending receipt remains inside its sealed checkpoint.

Records adapters (`PasskeyRecords`, `TorPasskeyRecord`, `CompoundRecords`) and,
behind the non-default `wallet` feature, Wallet custody (`WalletCustody` over the
`cwlt` passport, record and account owners) exist in this crate; their end-to-end use
with the real owners is not accepted. Live G3 authority, equal-passkey root custody
and the browser iframe ceremony are pending owner integrations. Opening a local Keys checkpoint
does not demonstrate equal-passkey custody or restore. No permissive authority or
proof engine is supplied. The decided custody and restore rules above are requirements, not
claims that these missing integrations already pass.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

## License

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).

## Existing checkpoint handover

`PreparedOpen::new` consumes the original Passkeys `UnlockSecret` through Keys'
opaque PRF importer. `Vault::open_existing` with a bare unlock secret is only a
compatibility refusal for the unpublished PRF-only open: it returns
`OpenError::RecoveryRequired` without accessing storage. The restore path is
`PreparedOpen::prepare_recovery` with the retained recovery record, then
`RecoveryCandidate::authorize` (current member authority from the supplied
Authority), then `PreparedRecovery::open_existing`: it opens the existing local
Store under the common-root cipher, requires its Keys checkpoint to be the
verified record's, unlocks Keys and validates that the current lineage equals
the authorized one. `PreparedOpen::migrate_legacy` is the separate, explicit path
for the unpublished PRF-wrapped Store. `Owners` groups the original Clock,
Entropy, Authority, Records and Wallet capabilities; it creates none of them. No
secret or plaintext key is returned. Missing/corrupt/unavailable state refuses
without creating a Store, root or replacement identity.
Later Keys operations still check their own current authority.

This is a local prerequisite, not production login or restored custody. The real
live Authority/Records/Wallet composer, DHT restore and successful current-custody
fixture remain outstanding. Actual Passkeys software-authenticator/Store tests
exercise refusal after the Store opens correctly, wrong passkeys/scopes,
corruption, unavailable storage and cancellation. They do not simulate accepted
G3 authority or a working Wallet. Native/browser execution and full coverage
remain required.
