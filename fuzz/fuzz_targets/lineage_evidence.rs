#![no_main]
//! Lineage evidence arrives as public bytes from the network: the plain wire form and the Padme-padded,
//! compressed Records envelope. Neither decoder may panic or run out of memory (decompression bounds), and evidence
//! a decoder accepts must encode and decode again.
use cvlt::LineageEvidence;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(evidence) = LineageEvidence::from_bytes(data) {
        let encoded = evidence.to_bytes().expect("accepted evidence encodes");
        LineageEvidence::from_bytes(&encoded)
            .expect("accepted evidence decodes from its own encoding");
    }
    let _ = LineageEvidence::from_packed(data);
});
