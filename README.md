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

**States and ports.** Derived Locked, Ready, Restoring, Unavailable or Unrecoverable.
Missing PRF leaves the vault Locked independently of server sign-in. The implemented
ports lend Keys, shared Storage, staged compound batches, Records lookup and Wallet,
and provide `lock`. Restore distinguishes Present, KnownAbsent and Unavailable.
Full unlock/restore wiring depends on the corresponding owner capabilities.

**Restore invariant.** The first root passkey deterministically derives the root.
Pairing transfers it to a new device, which retains an authenticated copy wrapped
under its own passkey PRF in member records. Any registered passkey restores while
those records exist; only the root passkey restores identity after record loss.
Contacts and history need retained records. Vault never invents a replacement
identity, operator backup or weaker retention guarantee.

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

Records, Wallet, live G3 authority, paired-root retention and the browser iframe
ceremony are pending owner integrations. No permissive authority or proof engine
is supplied. The decided custody and restore rules above are requirements, not
claims that these missing integrations already pass.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.

## License

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
