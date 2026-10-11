#!/usr/bin/env bash
# Original native owner gates; Wasm/browser/coverage remain in full verify.
set -euo pipefail
exec 2>&1
python3 .github/scripts/check-lock.py
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
rustc --version --verbose
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
