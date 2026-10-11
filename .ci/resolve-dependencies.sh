#!/usr/bin/env bash
# Resolve the changed integration graph; this is not a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
sha256sum Cargo.lock
echo 'Resolved dependency locks only; retain them in a commit and run verify.'
