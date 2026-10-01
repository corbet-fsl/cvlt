# Coverage contract

CI measures production Rust lines and branches with cargo-llvm-cov and requires
100% of both. A zero-count report fails. Test harness files are excluded from the
production denominator. Browser
vectors execute in headless Chrome; a compile check is not execution evidence.
Native coverage does not establish coverage of wasm-only adapters.

Stable Rust runs product validation. Nightly is used only for upstream Rust's
experimental branch instrumentation. CI resolves dependencies once and uploads
Cargo.lock; all jobs consume that exact snapshot with --locked. Weekly CI refreshes
the snapshot and Dependabot proposes manifest/lock updates. A failed coverage gate
is an open requirement, never evidence of complete coverage.

Actual browser Rust coverage runs the same owner vectors through wasm-bindgen
minicov on current nightly. Upstream instrumentation failures remain red and
are reported separately from stable browser execution.
Stable Rust separately builds and executes the product vectors. Native and wasm
line/branch gates are independent; neither substitutes for the other. LCOV
merges generic instantiations at the source-line boundary and preserves every
measured branch. The JSON report remains available as diagnostic evidence.

## Current browser profiling runtime

The test-only `.github/coverage-runtime` adapter calls maintained minicov directly
from its maintained upstream master branch. wasm-bindgen-test currently fixes its optional
profiling dependency to minicov 0.3.8 for LLVM 22; current minicov implements the
LLVM 23 profile format. The CI job reports compiler/runtime versions, disables
only wasm-bindgen-test's obsolete optional profiler, and instruments the same
real browser tests. Selenium drives the original upstream test server, waits for
all tests, invokes the tiny test-only capture binding, and waits for the original
server's successful nonempty profile upload before closing Chrome. LLVM still
parses and checks the actual raw profile and enforces every measured line/branch.
No production API, counter implementation, profile format, synthetic report or
version impersonation is introduced. A version mismatch or missing capture fails.

Current cargo-llvm-cov supplies instrumentation through its workspace wrapper.
The target flags deliberately omit a duplicate global `-Cinstrument-coverage`,
which would also instrument foreign standalone cdylibs without a test runtime.
Every owned source file and test target remains instrumented by the maintained
wrapper; third-party source is outside this library's coverage denominator.

The published minicov 0.3.9 semver range was tested with wasm-bindgen-test 0.3.79.
Cargo refuses its overlap with the runner's optional exact minicov 0.3.8. With an
older unrestricted test range it instead downgraded wasm-bindgen-test to 0.3.45;
that is explicitly rejected. The test harness requires the current 0.3.79-or-newer
protocol. A separate upstream git source is used solely to separate these Cargo
package identities. The obsolete runner profiler is disabled; only the maintained
current runtime is linked into the instrumented test. There is no patched version
number, compiler pin or product dependency on this helper.

## Report integrity

The gate reuses the shared source-counter checker and requires companion LLVM
JSON from the same native or browser execution. It checks the complete production
file inventory, summaries, unique branch locations, record termination and
nonnegative unique counters before requiring every reachable source line and
emitted branch. Raw generic-instantiation diagnostics are retained; merged source
coverage does not claim that every generic instantiation executes. Regression
cases reject incomplete, duplicated, inconsistent and uncovered reports. Any
documented line exclusion must still match its exact source, occur in the report
with zero hits, and contain no branch; stale or exercised exclusions fail.
