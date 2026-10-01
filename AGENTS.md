# Agent instructions

Comments and documentation are English. Vault is a thin device facade over
Keys/Storage/Records/Wallet, with no copied domain truth or cryptographic primitive.
No raw roots, PRF, signing seeds or holder scalars enter storage/logs/public APIs.
Follow docs/CONTRACT.md. Restore promises and gaps must remain explicit; unavailable
records are not known absence. Do not invent operator backups or live authority.
This facade is FSL-1.1-ALv2; executing leaves remain LGPL.

No workstation Cargo, even fmt/metadata. Run stable native checks, actual Wasm
vectors and strict reachable line/branch coverage on public CI. First-party git
dependencies follow branch main with one revision per crate. Dependabot changes
need every protected exact-head substantive check before auto-merge. No registry
publication, secrets, personal identifiers in outbound requests or AI attribution.
