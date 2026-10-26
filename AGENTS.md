# cvlt — agent notes

Commands (repo root; work in a lane, never edit `~/agents/scratch/ws`; lane-wide checks run via `cargo xtask check/test`):
- `bash .ci/update-our-crates.sh` first: advances internal crates to newest main; the `--locked` gates below assume it
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked`
- `cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings`

Hard invariants (enforcing check after each):
- No raw roots, PRF material, signing seeds or holder scalars in storage, logs or public APIs (`Vault([redacted])`, zeroizing handover). Enforced by `tests/vault.rs` (`facade_lock_and_missing_records_never_mint_identity`), `tests/cases/records.rs`, `tests/cases/existing.rs`, `tests/lineage.rs`.
- Thin facade: no copied domain truth, no cryptographic primitive, `unsafe_code = "forbid"`. Enforced by `tests/vault.rs` (composition-only construction) + the crate-level forbid lint in `Cargo.toml`.
- Restore is explicit: `Unavailable` is never known absence; missing state never mints an identity or an operator backup. Enforced by `tests/cases/records.rs` (`retained_encrypted_bytes_reopen_but_offline_cache_is_not_fresh_authority`) and `tests/cases/existing.rs` (`same_synced_passkey_opens_actual_store_but_missing_keys_never_become_custody`).
- `lock` wipes keys and shared decrypted storage; locked reads refuse. Enforced by `tests/vault.rs` (post-`lock` version check) and `tests/cases/lineage_retention.rs`.

Pointers: `docs/CONTRACT.md`, `docs/COVERAGE.md`; facade in `src/lib.rs`; restore in `src/existing/`; records in `src/records.rs`; lineage in `src/lineage.rs`.
FSL-1.1-ALv2 facade; executing leaves stay LGPL; no registry publication, secrets, or personal identifiers in outbound requests.
