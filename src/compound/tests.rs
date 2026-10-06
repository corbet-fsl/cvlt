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
