use super::*;
use ckmg::Entropy;
macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        fn $name() $body
    };
}
fn random(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    ckmg::SystemEntropy.fill(&mut bytes).unwrap();
    bytes
}
shared!(
    original_compression_padding_roundtrips_all_layout_boundaries,
    {
        for length in [
            1,
            cdht::MAX_SUBKEY_SIZE - 1,
            cdht::MAX_SUBKEY_SIZE,
            cdht::MAX_SUBKEY_SIZE + 1,
            RECORD_BYTES - 1,
            RECORD_BYTES,
            RECORD_BYTES + 1,
            cwst::MAX_CHECKPOINT_BYTES,
        ] {
            let bytes = random(length);
            let packed = pack(&bytes).unwrap();
            assert_eq!(unpack(&packed).unwrap().as_slice(), bytes);
            assert!(packed.len() <= MAX_PACKED_CHECKPOINT);
        }
        assert!(pack(&[]).is_err());
        assert!(pack(&vec![0; cwst::MAX_CHECKPOINT_BYTES + 1]).is_err());
        for bad in [
            vec![],
            vec![0],
            vec![0; MAX_PACKED_CHECKPOINT + 1],
            cprz_pad::pad(&[1]),
            cprz_pad::pad(&cprz::portable::compress(b"wrong owner").unwrap()),
            cprz_pad::pad(&cprz::portable::compress(PAYLOAD_HEADER).unwrap()),
            cprz_pad::pad(
                &cprz::portable::compress(&vec![
                    0;
                    cwst::MAX_CHECKPOINT_BYTES
                        + PAYLOAD_HEADER.len()
                        + 1
                ])
                .unwrap(),
            ),
        ] {
            assert!(unpack(&bad).is_err());
        }
        assert!(scope_digest("").is_err());
        assert!(scope_digest("bad\nscope").is_err());
        assert!(scope_digest(&"x".repeat(cwst::MAX_KEY_BYTES + 1)).is_err());
    }
);
shared!(
    canonical_manifest_bounds_and_bindings_reject_ambiguous_content,
    {
        let bytes = random(cdht::MAX_SUBKEY_SIZE + 1);
        let header = Manifest::new(
            scope_digest("scope").unwrap(),
            cdht::RecordKey([7; 32]),
            4,
            &bytes,
        );
        let direct = header.direct(&bytes);
        let encoded = direct.encode().unwrap();
        let decoded = Manifest::decode(&encoded).unwrap();
        decoded.bind(header.scope, header.root, 4).unwrap();
        assert!(decoded.bind([0; 32], header.root, 4).is_err());
        assert!(
            decoded
                .bind(header.scope, cdht::RecordKey([8; 32]), 4)
                .is_err()
        );
        assert!(decoded.bind(header.scope, header.root, 5).is_err());
        assert_eq!(decoded.data_length().unwrap(), bytes.len());
        assert_eq!(decoded.encode().unwrap(), encoded);
        for index in [0, 16, 17, 126, 127] {
            let mut bad = encoded.clone();
            bad[index] = 255;
            assert!(Manifest::decode(&bad).is_err());
        }
        for length in 0..encoded.len() {
            assert!(Manifest::decode(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
        for number in 0..12 {
            let mut bad = direct.clone();
            match number {
                0 => bad.entries.clear(),
                1 => bad.entries[0].length = 0,
                2 => bad.entries[0].length += 1,
                3 => bad.entries[0].length -= 1,
                4 => bad.entries[1].target = bad.entries[0].target,
                5 => bad.entries[0].target[4] = 1,
                6 => bad.entries[0].target = [0; 32],
                7 => bad.length = 0,
                8 => bad.length = MAX_PACKED_CHECKPOINT as u32 + 1,
                9 => bad.version = u64::MAX,
                10 => bad.entries = vec![bad.entries[0].clone(); PARTS + 1],
                _ => bad.length = 1,
            }
            assert!(bad.encode().is_err());
        }
    }
);
shared!(
    child_manifests_bind_complete_generation_and_root_index_hashes,
    {
        let bytes = random(RECORD_BYTES + 1);
        let header = Manifest::new(
            scope_digest("scope").unwrap(),
            cdht::RecordKey([7; 32]),
            8,
            &bytes,
        );
        let mut index = header.clone();
        index.index = true;
        for (i, part) in bytes.chunks(RECORD_BYTES).enumerate() {
            let child = header.direct(part).encode().unwrap();
            let decoded = Manifest::decode(&child).unwrap();
            assert_eq!(decoded.length as usize, bytes.len());
            assert_eq!(decoded.hash, digest(&bytes));
            assert_eq!(decoded.data_length().unwrap(), part.len());
            index.entries.push(Entry {
                target: [i as u8 + 20; 32],
                length: part.len() as u32,
                hash: digest(&child),
            });
        }
        let encoded = index.encode().unwrap();
        assert_eq!(
            Manifest::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        for number in 0..6 {
            let mut bad = index.clone();
            match number {
                0 => bad.entries[0].target = header.root.0,
                1 => bad.entries[1].target = bad.entries[0].target,
                2 => bad.entries[0].length -= 1,
                3 => bad.entries[1].length += 1,
                4 => {
                    bad.entries.truncate(1);
                    bad.length = RECORD_BYTES as u32;
                }
                _ => bad.entries = vec![bad.entries[0].clone(); MAX_CHECKPOINT_RECORDS + 1],
            }
            assert!(bad.encode().is_err());
        }
        let full = Manifest::new(
            header.scope,
            header.root,
            cdht::MAX_SEQ.into(),
            &vec![1; MAX_PACKED_CHECKPOINT],
        );
        let mut largest = full.clone();
        largest.index = true;
        for (i, part) in vec![1; MAX_PACKED_CHECKPOINT]
            .chunks(RECORD_BYTES)
            .enumerate()
        {
            largest.entries.push(Entry {
                target: [i as u8 + 30; 32],
                length: part.len() as u32,
                hash: digest(part),
            });
        }
        assert!(largest.encode().is_ok());
        for error in [
            CheckpointError::Invalid,
            CheckpointError::Limit,
            CheckpointError::Unavailable,
            CheckpointError::Storage(cwst::Error::Locked),
        ] {
            assert_eq!(error.to_string(), "compound checkpoint refused");
        }
    }
);

#[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
mod native;

// Mutant-killing boundary pins for compound retention (muse-mut126). Each test
// below fails on at least one listed cargo-mutants survivor while passing on
// the real code. Tests only; no product change.

/// Offline stub engine: only its authenticated identity is ever consulted by
/// `CompoundRecords::new`; reads and writes refuse as unavailable.
#[derive(Clone)]
struct StubEngine {
    identity: cdht::runtime::Identity,
}

impl cdht::runtime::Backend for StubEngine {
    fn identity(&self) -> cdht::runtime::Identity {
        self.identity.clone()
    }
    async fn get(
        &self,
        _subkey: u32,
        _refresh: bool,
    ) -> Result<Option<cdht::runtime::Value>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn republish(
        &self,
        _subkey: u32,
        _seq: u32,
        _data: &[u8],
    ) -> Result<cdht::runtime::Publication, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn flush(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn watch(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self) -> Result<bool, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    fn changes(&self) -> Result<cdht::runtime::Changes, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}

fn stub_record(owner_byte: u8) -> cdht::runtime::Record<StubEngine> {
    let schema = cdht::Schema::dflt(CHECKPOINT_SUBKEYS).unwrap();
    let owner = [owner_byte; 32];
    let key = cdht::RecordKey::derive(&owner, &schema.compile());
    cdht::runtime::Record::new(StubEngine {
        identity: cdht::runtime::Identity {
            key,
            owner,
            schema,
            writer: None,
        },
    })
    .unwrap()
}

#[test]
fn owner_record_layout_pins_subkey_arithmetic() {
    // PARTS is exactly one manifest subkey less than the owner layout: a `+`
    // or `/` mutant changes how many bytes one record carries and how many
    // child records the bound allows.
    assert_eq!(super::PARTS, CHECKPOINT_SUBKEYS as usize - 1);
    assert_eq!(super::PARTS, 31);
    assert_eq!(super::RECORD_BYTES, super::PARTS * cdht::MAX_SUBKEY_SIZE);
    assert_eq!(super::RECORD_BYTES, 31 * 32_768);
    assert_eq!(MAX_PACKED_CHECKPOINT, 9 * 1024 * 1024);
    assert_eq!(
        MAX_CHECKPOINT_RECORDS,
        MAX_PACKED_CHECKPOINT.div_ceil(super::RECORD_BYTES)
    );
    assert_eq!(MAX_CHECKPOINT_RECORDS, 10);
}

#[test]
fn debug_impls_redact_instead_of_printing_bytes() {
    // An `Ok(Default::default())` mutant prints nothing; the redaction must
    // stay exact so sealed bytes never reach logs.
    let prepared = PreparedCheckpoint {
        scope: [3; 32],
        root: cdht::RecordKey([7; 32]),
        sequence: 9,
        packed: Zeroizing::new(vec![0xAA; 64]),
        manifests: vec![Zeroizing::new(b"manifest-bytes".to_vec())],
    };
    assert_eq!(format!("{prepared:?}"), "PreparedCheckpoint([redacted])");
    let retained = RetainedCheckpoint {
        scope: [5; 32],
        sequence: 11,
        wire: Zeroizing::new(b"sealed-wire-bytes".to_vec()),
    };
    assert_eq!(format!("{retained:?}"), "RetainedCheckpoint([redacted])");
}

#[test]
fn for_each_part_visits_child_parts_and_manifests_in_order() {
    // A `>`-to-`<` mutant on the multi flag drops every child address; a
    // `+`-to-`-` mutant underflows the child manifest index; a `+`-to-`*`
    // mutant replays the root manifest where a child manifest belongs.
    let sequence = 7;
    let root_manifest = b"mut126-root-manifest".to_vec();
    let child_zero = b"mut126-child-zero".to_vec();
    let child_one = b"mut126-child-one".to_vec();
    let mut packed = Vec::with_capacity(super::RECORD_BYTES + 5);
    for i in 0..super::RECORD_BYTES + 5 {
        packed.push((i % 251) as u8);
    }
    let prepared = PreparedCheckpoint {
        scope: [1; 32],
        root: cdht::RecordKey([7; 32]),
        sequence,
        packed: Zeroizing::new(packed.clone()),
        manifests: vec![
            Zeroizing::new(root_manifest.clone()),
            Zeroizing::new(child_zero.clone()),
            Zeroizing::new(child_one.clone()),
        ],
    };
    let mut seen: Vec<(Option<usize>, u32, u32, Vec<u8>)> = Vec::new();
    prepared
        .for_each_part(|child, subkey, seq, bytes| {
            seen.push((child, subkey, seq, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
    let mut expected = Vec::new();
    for (part, bytes) in packed[..super::RECORD_BYTES]
        .chunks(cdht::MAX_SUBKEY_SIZE)
        .enumerate()
    {
        expected.push((Some(0), (part + 1) as u32, sequence, bytes.to_vec()));
    }
    expected.push((Some(0), 0, sequence, child_zero.clone()));
    expected.push((Some(1), 1, sequence, packed[super::RECORD_BYTES..].to_vec()));
    expected.push((Some(1), 0, sequence, child_one.clone()));
    expected.push((None, 0, sequence, root_manifest.clone()));
    assert_eq!(expected.len(), 31 + 4);
    assert_eq!(seen, expected);
    // A single-chunk checkpoint addresses the root record only.
    let small_bytes = vec![0x11; 100];
    let small = PreparedCheckpoint {
        scope: [1; 32],
        root: cdht::RecordKey([7; 32]),
        sequence,
        packed: Zeroizing::new(small_bytes.clone()),
        manifests: vec![Zeroizing::new(root_manifest.clone())],
    };
    let mut small_seen: Vec<(Option<usize>, u32, u32, Vec<u8>)> = Vec::new();
    small
        .for_each_part(|child, subkey, seq, bytes| {
            small_seen.push((child, subkey, seq, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        small_seen,
        vec![
            (None, 1, sequence, small_bytes),
            (None, 0, sequence, root_manifest),
        ]
    );
}

#[test]
fn restore_keys_rejects_wrong_expected_digest() {
    // A `true` match guard would restore into any digest: the wrong digest
    // must refuse while the exact retained digest restores.
    futures_executor::block_on(async {
        let scope = "mut126-keys-guard";
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf, scope).unwrap();
        let locator = ckmg::passkey::vault_location(&prf, scope).unwrap();
        let sealed = b"mut126 sealed owner bytes";
        let mut source = cwst::Store::create(cwst::backend::Memory::new(), &cipher, scope)
            .await
            .unwrap();
        source
            .commit(
                0,
                [7; 32],
                &[cwst::Change::Put {
                    owner: "keys",
                    key: locator.as_bytes(),
                    value: sealed,
                }],
                &[],
            )
            .await
            .unwrap();
        let wire = source.sealed_checkpoint().unwrap().to_vec();
        let version = source.version().unwrap();
        let scope_hash = scope_digest(scope).unwrap();
        let expected = digest(sealed);
        let retained = RetainedCheckpoint {
            scope: scope_hash,
            sequence: version as u32,
            wire: Zeroizing::new(wire.clone()),
        };
        assert!(
            retained
                .restore_keys(
                    cwst::backend::Memory::new(),
                    &cipher,
                    scope,
                    locator,
                    &expected
                )
                .await
                .is_ok()
        );
        let wrong = [0x5A; 32];
        assert_ne!(wrong, expected);
        let retained = RetainedCheckpoint {
            scope: scope_hash,
            sequence: version as u32,
            wire: Zeroizing::new(wire),
        };
        assert!(
            retained
                .restore_keys(
                    cwst::backend::Memory::new(),
                    &cipher,
                    scope,
                    locator,
                    &wrong
                )
                .await
                .is_err()
        );
    });
}

#[test]
fn prepare_rejects_either_scope_mismatch() {
    // An `||`-to-`&&` mutant prepares when only one side matches: each single
    // mismatch must refuse while the full match succeeds.
    futures_executor::block_on(async {
        let scope_a = "mut126-scope-a";
        let scope_b = "mut126-scope-b";
        let cipher_a = ckmg::passkey::store_cipher(
            &ckmg::passkey::PrfOutput::from_bytes(&[11; 32]).unwrap(),
            scope_a,
        )
        .unwrap();
        let cipher_b = ckmg::passkey::store_cipher(
            &ckmg::passkey::PrfOutput::from_bytes(&[12; 32]).unwrap(),
            scope_b,
        )
        .unwrap();
        let store_a = cwst::Store::create(cwst::backend::Memory::new(), &cipher_a, scope_a)
            .await
            .unwrap();
        let store_b = cwst::Store::create(cwst::backend::Memory::new(), &cipher_b, scope_b)
            .await
            .unwrap();
        let records_a = CompoundRecords::new(scope_a, stub_record(21), vec![]).unwrap();
        assert!(records_a.prepare(&store_a, scope_a).is_ok());
        assert!(records_a.prepare(&store_b, scope_a).is_err());
        assert!(records_a.prepare(&store_b, scope_b).is_err());
    });
}

#[test]
fn prepare_bounds_child_records_by_needed_chunks() {
    // A `>`-to-`==` mutant refuses the exact fit; a `>`-to-`<` mutant refuses
    // every surplus. Too few children must refuse while the exact fit and a
    // surplus prepare fine.
    futures_executor::block_on(async {
        let scope = "mut126-multi-chunk";
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[13; 32]).unwrap();
        let cipher = ckmg::passkey::store_cipher(&prf, scope).unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, scope)
            .await
            .unwrap();
        let first = random(400_000);
        let second = random(400_000);
        let third = random(400_000);
        store
            .commit(
                0,
                [7; 32],
                &[
                    cwst::Change::Put {
                        owner: "fixture-first",
                        key: b"state",
                        value: &first,
                    },
                    cwst::Change::Put {
                        owner: "fixture-second",
                        key: b"state",
                        value: &second,
                    },
                    cwst::Change::Put {
                        owner: "fixture-third",
                        key: b"state",
                        value: &third,
                    },
                ],
                &[],
            )
            .await
            .unwrap();
        let abundant = CompoundRecords::new(
            scope,
            stub_record(31),
            (0u8..MAX_CHECKPOINT_RECORDS as u8)
                .map(|i| stub_record(40 + i))
                .collect(),
        )
        .unwrap();
        let prepared = abundant.prepare(&store, scope).unwrap();
        let needed = prepared.manifests.len() - 1;
        assert!(needed >= 2, "fixture must span records, got {needed}");
        assert!(needed + 1 <= MAX_CHECKPOINT_RECORDS);
        let short = CompoundRecords::new(
            scope,
            stub_record(32),
            (0..needed as u8 - 1).map(|i| stub_record(50 + i)).collect(),
        )
        .unwrap();
        assert!(matches!(
            short.prepare(&store, scope),
            Err(CheckpointError::Limit)
        ));
        let exact = CompoundRecords::new(
            scope,
            stub_record(33),
            (0..needed as u8).map(|i| stub_record(60 + i)).collect(),
        )
        .unwrap();
        assert!(exact.prepare(&store, scope).is_ok());
        let extra = CompoundRecords::new(
            scope,
            stub_record(34),
            (0..needed as u8 + 1).map(|i| stub_record(70 + i)).collect(),
        )
        .unwrap();
        assert!(extra.prepare(&store, scope).is_ok());
    });
}
