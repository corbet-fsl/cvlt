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
minicov, using the upstream nightly-2026-02-18 coverage-runtime workaround.
Stable Rust separately builds and executes the product vectors. Native and wasm
line/branch gates are independent; neither substitutes for the other. LCOV
merges generic instantiations at the source-line boundary and preserves every
measured branch. The JSON report remains available as diagnostic evidence.
