use super::*;

/// Container encrypted by mxencdec v2.1 from [`MXENCDEC_PLAIN`] (named `user.ini`).
const MXENCDEC_SEALED: &[u8] = include_bytes!("fixtures/user.ini");
const MXENCDEC_PLAIN: &[u8] = b"[L2Enc]\r\nFixture=RSA 413 sealed by mxencdec v2.1\r\n";

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

fn encrypt_ok(raw: &[u8]) -> Vec<u8> {
    encrypt(raw, &Progress::new()).expect("payload fits in 413")
}

fn stream_round_trip(stream: &[u8]) -> Option<Vec<u8>> {
    let keys = &*KEYS;
    let progress = Progress::new();
    let mut sealed = vec![0u8; stream.len().div_ceil(CHUNK_LEN) * BLOCK_LEN];
    encrypt_stream(stream, &mut sealed, &progress);
    decrypt_stream(&sealed, &keys.modified_n, &keys.modified_e, &progress)
}

#[test]
fn decrypts_container_sealed_by_mxencdec() {
    assert_eq!(
        decrypt(MXENCDEC_SEALED, &Progress::new()),
        Ok(MXENCDEC_PLAIN.to_vec())
    );
}

#[test]
fn decrypt_restores_encrypted_payload_and_both_complete_progress() {
    let raw = noise(1000);
    let encrypt_progress = Progress::new();
    let encrypted = encrypt(&raw, &encrypt_progress).expect("payload fits in 413");
    assert_eq!(encrypt_progress.fraction(), 1.0);
    let decrypt_progress = Progress::new();
    assert_eq!(decrypt(&encrypted, &decrypt_progress), Ok(raw));
    assert_eq!(decrypt_progress.fraction(), 1.0);
}

#[test]
fn stream_of_exact_block_multiple_round_trips() {
    let stream = noise(2 * CHUNK_LEN);
    assert_eq!(stream_round_trip(&stream), Some(stream));
}

#[test]
fn stream_with_partial_last_block_round_trips() {
    let stream = noise(CHUNK_LEN + 1);
    assert_eq!(stream_round_trip(&stream), Some(stream));
}

#[test]
fn trailer_stores_crc_of_header_and_blocks() {
    let out = encrypt_ok(&noise(500));
    let body_end = out.len() - TRAILER_LEN;
    let mut crc = Crc::new();
    crc.update(&out[..body_end]);
    let stored = u32::from_le_bytes(out[out.len() - 8..out.len() - 4].try_into().unwrap());
    assert_eq!(stored, crc.sum());
}

#[test]
fn decrypt_accepts_missing_trailer() {
    let raw = noise(700);
    let out = encrypt_ok(&raw);
    assert_eq!(
        decrypt(&out[..out.len() - TRAILER_LEN], &Progress::new()),
        Ok(raw)
    );
}
