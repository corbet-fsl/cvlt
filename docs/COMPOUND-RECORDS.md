# Compound checkpoint retention

`CompoundRecords` connects the original authenticated Store ciphertext to the
original Records runtime. It does not replace the existing DFLT(1) passkey-root
record or its codec. The generic owner is available natively and in Wasm; the
native constructor uses live Keys purpose handles and the existing Mesh factory.

One owner-only DFLT(32) record uses subkey zero for its manifest and subkeys 1–31
for data. The original Store wire is framed with `cvlt.compound-store.v1\0`,
compressed by cprz, padded by Padme, then split. Records applies its original VLD0
encryption afterwards. The Store wire already has its original at-rest encryption;
packing does not decrypt or reserialize domain owners. Consequently compression
cannot remove most of that ciphertext's entropy. The original Store limit is 8 MiB;
a 9 MiB packed limit bounds padding/compression overhead and parser allocations.

Up to 1,015,808 packed bytes fit in one record. Larger checkpoints use a stable
manifest record whose subkey zero points to up to ten purpose-separated child
DFLT(32) records. Each child has the same manifest-plus-parts layout. Every record
stays below Veilid's original 1 MiB data limit and every value below 32 KiB.
`vault.checkpoint` and `vault.checkpoint.chunk.<index>` are member-scoped Keys
purposes at version zero. The original Keys root epoch still governs derivation.
Their keys are never exported; the original native initializer goes straight to
Mesh's existing engine. Dropping/closing the underlying engine releases custody.

## Owner content

The proposed v1 application manifest is `cvlt.compound.v1\0`, kind byte (0 direct,
1 child index), scope BLAKE3 digest, original root RecordKey, Store version u64 LE,
complete packed length u32 LE, complete packed BLAKE3 digest, entry count u16 LE,
then entries. Each entry is target[32], length u32 LE and BLAKE3 hash[32]. A direct
target is subkey u32 LE followed by 28 zero bytes. Direct entries appear in
subkey order, with full 32 KiB parts except the last. A child index target is the
original child RecordKey; its length is the child's aggregate data length and its
hash covers that child's manifest bytes. Index children are full except the last.
Child manifests retain the complete checkpoint length/digest, not a local substitute.

This is content inside maintained Records, not a new Veilid schema or Tor format.
Manifest version must fit the original Veilid usable sequence range and equal
every part's authenticated sequence and the decrypted Store version. Reads check
scope/root, limits, canonical targets/order, each part/manifest hash and length,
complete digest, bounded decompression, and a second forced root-manifest read.
Malformed, missing, stale, mixed-generation or changed observations refuse.
Unavailable replicas never imply KnownAbsent or create a replacement identity.

## Persistence and cancellation

Preparation accepts only an original authenticated Store and copies its exact
committed wire. Publication writes data parts first, child manifests next, and
the root manifest last, using original exact-sequence republish operations. It
never acknowledges an application output. Queued is distinct from Replicated;
only all original runtime flush successes produce Replicated. Equal-sequence or
newer original conflicts stop publication without inventing a winner. Cancellation
leaves InProgress, meaning unknown partial outcome; a transport refusal marks
Partial. There is no rollback claim. In-place subkey updates may make the old
manifest temporarily unreadable if interrupted. Retry the same prepared bytes or
reopen and reconcile actual original records; do not infer success from elapsed time.

After a complete forced Records observation, `RetainedCheckpoint::restore` asks
original Storage to authenticate and CAS the exact ciphertext into an empty local
destination. It verifies the expected Store version before any write. Existing
local state is never overwritten. Store authentication still grants no Keys,
Wallet, membership or G3 authority. A publication object's scoped preparation is
not a lasting authorization lease: the trusted runtime must check live custody
and close all record engines on lock or revocation.

## Remaining runtime boundary

The native record constructor requires already-authorized Keys. The full restore
bootstrap still needs passkey root record → authenticated current root → compound
record discovery without circularly requiring an opened compound Store. Original
Store wrapping currently uses the passkey-derived capability; this slice preserves
it and does not establish that a different enrolled passkey can open the same
compound Store. Production equal-passkey wrapping/rewrapping and Authority/Wallet
composition remain unfinished. Browser hosting is independent and undecided.

Source fixtures exercise real compression/Padme, malformed/bounded manifests,
original Store authentication/CAS/reopen and actual native offline Core publication,
interrupted real writes and conflicts. Offline cache inspection is expressly
persistence/codec evidence; forced offline reads refuse. Fresh network read/restore,
browser runtime, cancellation at every network boundary and full coverage must
still run in available CI. No local build/test execution or network milestone is
claimed by this implementation.
