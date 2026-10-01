# cvlt

## Scope

Vault is the device trust facade over Keys (`ckmg`), Storage (`cwst`), Records
(`cdht`) and Wallet (`cwlt`). It owns capability wiring and the shared transaction
boundary. Each drawer keeps its own lineage, record, proof and accepted state.

The implemented KeyStore adapter commits actual encrypted Keys checkpoints with
opaque companion owner changes and output bytes under one cwst fence. A staged
batch never reports durable success. Cancellation, conflicts and unknown outcomes
require reopening/reconciliation through the owner. Keys' own pending receipt
remains inside its sealed checkpoint. No PRF or root enters this storage adapter.

Records and Wallet adapters remain external owner integration seams. There is no
fake proof engine, implicit enrollment or permissive authority implementation.
The real ckmg machine is constructed with the caller's current G3 Authority port.

Restore distinguishes unavailable records from authenticated known absence.
Neither erases deterministic same-passkey identity or membership. Actual active
member restoration of contacts/history still requires retained device records.
A distinct paired PRF also requires the original root's authenticated encrypted
transfer; its product retention/reenrollment decision remains open. Vault invents
no operator backup or replacement identity to fill that gap.

Native and actual browser tests, coverage and independent review are required;
CI status is evidence only for the exercised adapters, not end-to-end restore.

## License

[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
