#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
: "${CARGO_INSTALL_ROOT:?run-cached.sh must export per-repo CARGO_INSTALL_ROOT}"
export GITHUB_OUTPUT="${GITHUB_OUTPUT:-$RUNNER_TEMP/github_output.txt}"
touch "$GITHUB_OUTPUT"

python3 .github/scripts/check-lock.py
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
rustc --version --verbose
bash .ci/update-our-crates.sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

printf '%s\n' 'cvlt ci: stage=wasm-clippy'
command -v cargo || true
cargo --version || true
cargo clippy --version || true
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings
printf '%s\n' 'cvlt ci: stage=wasm-pack'
command -v wasm-pack || true
wasm-pack --version || true
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
# The nix wrapper `clang` on PATH breaks the wasm32 C build (host glibc
# headers); resolve `clang` to the pinned unwrapped compiler for this leg
# only: the subshell keeps native builds and nightly coverage on the wrapper.
: "${CVLT_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CVLT_WASM_CLANG_BIN:$PATH"
wasm-pack test --headless --chrome -- --locked
)

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --text --output-path coverage.txt --ignore-filename-regex '/tests/'
python3 .github/scripts/check-coverage.py coverage.lcov coverage.json coverage.txt

# The wasm-coverage CI job runs entirely on the nightly toolchain; select it
# here with the same RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN pattern so every
# bare `cargo`/`rustc` below resolves nightly exactly as in CI.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB="1"
export WASM_BINDGEN_SPLIT_LINKED_MODULES="1"
# CI hardcodes /usr/bin/chromedriver from the runner image (also inside
# browser-coverage-runner.py); the job runtime supplies paired nix
# chromium+chromedriver via CHROMEDRIVER/CHROME_BIN.
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver || echo /usr/bin/chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || echo chromium)}"
export CC_wasm32_unknown_unknown="$CVLT_WASM_CLANG"
rustc --version --verbose
"$NIGHTLY_CARGO" llvm-cov --version
clang --version
command -v clang >/dev/null || { echo 'missing clang' >&2; exit 2; }
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
python3 - <<'PYCODE'
import os, tomllib
packages = tomllib.load(open('Cargo.lock', 'rb'))['package']
version = next(p['version'] for p in packages if p['name'] == 'wasm-bindgen')
with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
    f.write('version=' + version + '\n')
PYCODE
binding_version=$(sed -n 's/^version=//p' "$GITHUB_OUTPUT" | tail -n 1)
test -n "$binding_version" || { echo 'could not resolve wasm-bindgen version from Cargo.lock' >&2; exit 2; }
# Per-repo install under the repo lock: package wasm-bindgen-cli provides the
# binary wasm-bindgen. Guard probes the exact per-repo binary with exact
# `<binary> <version>` equality, never global. Output captured, never piped.
binding_have=$("$CARGO_INSTALL_ROOT/bin/wasm-bindgen" --version 2>/dev/null || true)
if [[ $binding_have != "wasm-bindgen $binding_version" ]]; then
  cargo install wasm-bindgen-cli --locked --version "$binding_version" --root "$CARGO_INSTALL_ROOT" || exit 2
  binding_have=$("$CARGO_INSTALL_ROOT/bin/wasm-bindgen" --version 2>/dev/null || true)
  [[ $binding_have == "wasm-bindgen $binding_version" ]] || exit 2
fi
# Python environment: requirements.txt pins exactly `selenium>=4`; the runner
# supplies a pinned python3.withPackages env (selenium 4.40.0 plus transitive
# deps and pip), so the import below succeeds without network. The pip install
# stays as the CI fallback.
python3 -c 'import selenium; print(selenium.__version__)' || python3 -m pip install -r .github/requirements.txt
# browser-coverage-runner.py hardcodes Service("/usr/bin/chromedriver") and
# sets no binary_location. Adapt exactly those two narrowly-checked facts in
# a job-temp copy: driver service path -> $CHROMEDRIVER, and binary_location
# -> $CHROME_BIN (resolved pinned chromium executable). Any other source
# drift fails the gate; Chrome options and all tests are preserved byte for
# byte (diff audit: exactly one removed line, two added lines).
: "${CHROME_BIN:?Missing resolved chromium executable from run-cached.sh}"
test -x "$CHROME_BIN" || { echo "chromium not executable at $CHROME_BIN" >&2; exit 2; }
runner_src=.github/scripts/browser-coverage-runner.py
runner_copy="$RUNNER_TEMP/browser-coverage-runner.py"
anchor_hits=$(grep -cF 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)' "$runner_src" || true)
test "$anchor_hits" -eq 1
existing_binary_location=$(grep -cF 'binary_location' "$runner_src" || true)
test "$existing_binary_location" -eq 0
python3 - "$runner_src" "$runner_copy" "$CHROMEDRIVER" "$CHROME_BIN" <<'PYEOF'
import sys
src, dst, driver, chrome = sys.argv[1:5]
text = open(src).read()
anchor = 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)'
assert text.count(anchor) == 1, 'runner driver-construction text drifted'
replacement = 'options.binary_location = "' + chrome + '"\n        driver = webdriver.Chrome(service=Service("' + driver + '"), options=options)'
open(dst, 'w').write(text.replace(anchor, replacement))
PYEOF
drift_removed=$(diff "$runner_src" "$runner_copy" | grep -c '^<' || true)
drift_added=$(diff "$runner_src" "$runner_copy" | grep -c '^>' || true)
test "$drift_removed" -eq 1
test "$drift_added" -eq 2
grep -F "$CHROMEDRIVER" "$runner_copy"
grep -F "$CHROME_BIN" "$runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 $runner_copy"
: "${CVLT_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CVLT_WASM_CLANG_BIN:$PATH"
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --coverage-target-only --target wasm32-unknown-unknown --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
)
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --text --output-path wasm-coverage.txt --ignore-filename-regex '/tests/'
)
python3 .github/scripts/check-coverage.py wasm-coverage.lcov wasm-coverage.json wasm-coverage.txt wasm
