# Browser hosting contract — integration checklist

Placement contract for the real browser runtime. Items marked MISSING are
not implemented in `cvlt` main, and this document implements none of them.

Scope: top-level community UI origin, one `cmsg` Wasm instance in the
hosting cross-origin vault frame, exact-origin-bounded `MessageChannel`
API, top-level vault pop-up with no opener, ciphertext-only same-origin
handover. No plaintext PRF or key material through JavaScript. Compound
custody and restore semantics stay owner capabilities composed through
the vault.

Vault source truth: [CONTRACT], [README], [lib], [storage]. Coverage
rules: [COVERAGE].

## 1. Hosting topology

- [ ] H1 — The UI runs at the community origin; vault logic runs in the
  cross-origin frame `vault.<community>.<base>`, which hosts one `cmsg`
  Wasm instance. The frame serves one community scope; joining stores of
  different communities is out of scope.
  Status: MISSING in `cvlt` main — no frame, no `cmsg` door, no
  `createClient()` in [lib] / [storage]. In-crate scope refusal only:
  `Vault::new` returns `Err(Error::Scope)` on mismatch, `KeyStore::new`
  refuses empty or oversize scope, and `load` / `compare_exchange`
  recheck scope on every call.
- [ ] H2 — The frame API is a `MessageChannel` port. Establishment
  validates the exact expected top-level origin and the source window
  before accepting the transferred port/session; the bound port/session
  then carries only messages bounded to the vault API. `MessagePort`
  messages carry no independently authenticated origin, so origin trust
  is established at handover, not per port message. No wildcard origins.
  Status: MISSING in `cvlt` main — no channel, origin/window check, or
  JS binding exists.
- [ ] H3 — Heavy proof work runs in a worker inside the vault frame, never
  in the top-level page.
  Status: MISSING in `cvlt` main — no worker and no proof engine
  ([CONTRACT]: no substitute proof path).
- [ ] H4 — Exactly one client storage connection, held by the vault:
  `Vault::new` takes the single `cwst::Store`, shared as
  `shared_store` / `SharedStore<B>`; capability lenders are `keys()`,
  `storage()`, `wallet()` ([lib]).

## 2. Pop-up and sealed handover

- [ ] P1 — The vault pop-up is a top-level page under the vault origin in
  all browsers, opened with no opener.
  Status: MISSING in `cvlt` main. No pop-up code in this crate.
- [ ] P2 — The passkey ceremony runs in the pop-up; the result is sealed
  inside pop-up Wasm to a one-time vault-frame Wasm key, bound to the
  handover nonce and both origins. Only ciphertext crosses the
  same-origin channel (e.g. `BroadcastChannel`). Binding seal: the
  existing maintained HPKE (RFC 9180); no new crypto in this crate. The
  frame opens it inside Wasm into the opaque unlock secret and discards
  the one-time key pair.
  Status: MISSING in `cvlt` main — no ceremony, no key pair, no channel,
  and no JS-visible secret path.
- [ ] P3 — The frame refuses replays, wrong nonce, wrong origin, and
  timeouts.
  Status: MISSING in `cvlt` main.
- [ ] P4 — No plaintext PRF output or key/root material passes through
  JavaScript at any point (frame, channel, or pop-up glue).
  Status: MISSING end to end. Distinct in-crate facts, not JS-custody
  proof: public types expose no raw-secret getters; `Debug` redacts
  `Vault` and the `RestoreLookup::Present` payload ([lib]); `Mutation`
  zeroizes on drop ([storage]). `Batch.outputs` is `Vec<cwst::Output>`
  of opaque bytes that callers construct directly (see
  `Output { id, bytes }` in [vault-tests]); the "already-encrypted
  bytes" rule is the documented caller contract on the `Batch` field
  ([storage]), not a type-level guarantee.

## 3. Current `cvlt` implementation

Public surface (all in [lib] unless noted):

- Construction and scope: `Vault::new`, `Error::Scope`,
  `KeyStore::new` ([storage]), `shared_store`, `SharedStore<B>`
  ([storage]).
- Capability lenders: `keys()`, `storage()`, `wallet()`.
- Compound custody staging: `stage_keys(Batch)`, `Batch`, `BatchGuard`,
  `Mutation`, `Error::Busy`, `Error::Invalid` ([storage]). One staged
  batch at a time; `keys`-owned writes refused without an armed batch;
  a consumed batch stays reserved until the guard drops; cancellation,
  conflict, and unknown outcomes reconcile through reopen, never as
  reported commits ([CONTRACT], [storage]).
- Lifecycle: `lock()` wipes Keys and decrypted shared storage; further
  shared reads then report locked ([lib]).
- Restore lookup port only: `Records::lookup`, `restore_lookup`,
  `RestoreLookup::Present / KnownAbsent / Unavailable` ([lib]).
  Installing record data needs the owner's authenticated merge/lineage
  evidence and the shared checkpoint transaction ([CONTRACT]).

Behaviour vectors, configured for native and browser execution via the
`shared!` cfg branches in [vault-tests] and [atomicity-tests]:

- `keys_ciphertext_and_companions_commit_together` — staged Keys
  ciphertext plus companion owner state and outbox commit in one `cwst`
  transaction; deletion path round-trips through reopen.
- `scope_versions_cancellation_and_reserved_owner_refuse` — scope
  refusal, reserved `keys` owner refusal, cancellation, conflict vs
  unknown handling, size limits.
- `facade_lock_and_missing_records_never_mint_identity` — unavailable
  authority/records stay unavailable, `lock` seals the shared store,
  lookup never mints an identity.
- `unknown_outcome_is_reconciled_and_locked_reads_refuse` — uncertain
  backend reports `Commit::Unknown`; reopen determines the outcome;
  wrong-scope construction refused.
- `cancellation_requires_reopen_to_determine_the_compound_outcome` —
  injected failure before/after the durable write; reopen reconciles.
- `stale_snapshot_conflict_keeps_winner_only` — competing writers; loser
  gets `Commit::Conflict`; winner only survives.
- `invalid_companion_refuses_entire_transaction` — one invalid companion
  refuses the whole transaction (`Commit::Unknown`, nothing committed).

Evidence selectors ([ci]; this document claims no execution result):

- `cargo fmt --all -- --check`; `cargo clippy --locked --all-targets --
  -D warnings`; `cargo test --locked`.
- `cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D
  warnings`; `wasm-pack test --headless --chrome -- --locked`.
- Native and browser coverage gates require full measured lines and
  branches over the same execution ([COVERAGE]). A compile check is not
  execution evidence.

## 4. Acceptance prerequisites (not in `cvlt` main)

- [ ] M1 — Real Keys authority and passkey/PRF handover into Keys.
  Production G3 authority is blocked on the live adapter; current
  fixture-driven Keys behaviour demonstrates composition mechanics
  only, never live authority ([CONTRACT], [README]).
- [ ] M2 — Real Records adapter: authenticated encrypted records,
  protocol-owned `KnownAbsent` evidence, install path through the
  owner's merge/lineage evidence and the shared checkpoint transaction.
  `cvlt::Records` is lookup-only by design ([lib], [CONTRACT]).
- [ ] M3 — Real Wallet adapter: borrowed capability only
  (`Vault::wallet`); no substitute proof path exists ([CONTRACT]).
- [ ] M4 — Equal-passkey retained root copies and refresh/discovery in
  member records. The rule is a requirement, not an implemented
  guarantee ([CONTRACT], [README]).
- [ ] M5 — Real `cmsg` Wasm runtime in the vault frame, generated API /
  `createClient()`, real browser network path with Tor as the required
  path, and the native CLI end-to-end bed.
- [ ] M6 — Per-browser proof of the top-level pop-up passkey ceremony
  plus sealed transfer to the cross-origin vault frame.

## 5. Startup / lock / restore distinctions for the showcase

- Startup (to implement, not current behaviour): scope-checked open
  grants no member or device authority ([lib]). Locked is the default
  until the sealed handover delivers the unlock secret; a sign-in
  yielding no PRF stays Locked with reason PrfUnavailable. `cvlt` main
  exports no unlock port or state enum — these are scope-required
  states (see P1–P4).
- Lock: `Vault::lock` wipes Keys and decrypted shared storage at once;
  existing shared references then observe locked ([lib],
  `facade_lock_and_missing_records_never_mint_identity` in
  [vault-tests]).
- Restore outcomes (`RestoreLookup`, [lib]; semantics [CONTRACT]):
  `Present` means an authenticated encrypted record and still requires
  owner merge evidence before use; `KnownAbsent` requires the Records
  owner's protocol evidence; `Unavailable` covers timeouts and
  unverifiable or incomplete knowledge. Unavailable is never known
  absence; no outcome creates or replaces an identity.
- Showcase (real runtime only): community page drives the vault frame
  over the exact-origin channel; no-opener pop-up ceremony with
  ciphertext-only handover; unlock → staged compound checkpoint (Keys
  plus owner companions and outputs in one `cwst` transaction) → `lock`
  wipes; restore shows each of Present / KnownAbsent / Unavailable
  distinctly with no invented identity. Proof work runs in the in-frame
  worker.

## 6. Non-goals

No network code in `cvlt`; no joining of community stores; no domain
conflict resolution, second wallet, or device roster; no operator
recovery path; no raw-secret getters; no new wrapping, discovery, or
retention format in this crate. Compound custody stays owner work
composed through `stage_keys` / `KeyStore::compare_exchange`.

[CONTRACT]: CONTRACT.md
[COVERAGE]: COVERAGE.md
[README]: ../README.md
[lib]: ../src/lib.rs
[storage]: ../src/storage.rs
[vault-tests]: ../tests/vault.rs
[atomicity-tests]: ../tests/atomicity.rs
[ci]: ../.github/workflows/ci.yml
