use super::*;

/// Poorly compressible bytes, so the zlib stream spans several RSA blocks.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn stream_round_trip(stream: &[u8]) -> Option<Vec<u8>> {
    let keys = &*KEYS;
    decrypt_stream(&encrypt_stream(stream), &keys.modified_n, &keys.modified_e)
}

#[test]
fn decrypt_restores_encrypted_payload() {
    let raw = noise(1000);
    assert_eq!(decrypt(&encrypt(&raw)), Ok(raw));
}

#[test]
fn stream_of_exact_block_multiple_keeps_its_last_block() {
    let stream = noise(2 * CHUNK_LEN);
    assert_eq!(encrypt_stream(&stream).len(), 2 * BLOCK_LEN);
    assert_eq!(stream_round_trip(&stream), Some(stream));
}

#[test]
fn stream_with_partial_last_block_round_trips() {
    let stream = noise(CHUNK_LEN + 1);
    assert_eq!(stream_round_trip(&stream), Some(stream));
}

#[test]
fn trailer_stores_crc_of_header_and_blocks() {
    let out = encrypt(&noise(500));
    let body_end = out.len() - TRAILER_LEN;
    let mut crc = Crc::new();
    crc.update(&out[..body_end]);
    let stored = u32::from_le_bytes(out[out.len() - 8..out.len() - 4].try_into().unwrap());
    assert_eq!(stored, crc.sum());
}

#[test]
fn decrypt_accepts_missing_trailer() {
    let raw = noise(700);
    let out = encrypt(&raw);
    assert_eq!(decrypt(&out[..out.len() - TRAILER_LEN]), Ok(raw));
}
