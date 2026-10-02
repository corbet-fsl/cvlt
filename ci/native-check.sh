#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_HTTP_USER_AGENT=custody-ci
export CARGO_NET_GIT_FETCH_WITH_CLI=true
rustc --version --verbose
cargo --version
sha256sum Cargo.lock
# Exact retained lock only. Fresh resolution is a separately receipted Crow step.
cargo fmt --all --check
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
sha256sum Cargo.lock
