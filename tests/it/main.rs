//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/unit` stays put (the library compiles it via `#[path]`).
mod atomicity;
mod birth;
mod community_pin;
mod genesis_stamp;
mod lineage;
mod pairing_guest;
mod revision_stamp;
mod vault;
