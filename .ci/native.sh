#!/usr/bin/env bash
# Original native owner gates; Wasm/browser/coverage remain in full verify.
set -euo pipefail
exec 2>&1
# The wallet facade's native prover feature is compiled and linted in the original
# verifier owner's authenticated native SDK shell (as cmsg's native-prover check).
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
python3 -B .ci/import-native-prover-sdk.py
env NIX_BUILD_SHELL=bash nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo clippy --locked --lib --features wallet-native-prover -- -D warnings'
python3 .github/scripts/check-lock.py
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
rustc --version --verbose
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
