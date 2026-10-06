//! Version 413: zlib stream split into 124-byte chunks, each sealed in a
//! 128-byte big-endian RSA block, followed by a 20-byte trailer holding a CRC32.

use std::io::{Read, Write};
use std::num::NonZero;
use std::sync::LazyLock;
use std::thread;

use flate2::Compression;
use flate2::Crc;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use num_bigint::BigUint;

use crate::codec::{CodecError, HEADER_LEN, container_header};
use crate::progress::Progress;

const BLOCK_LEN: usize = 128;
/// Largest chunk a block carries: the block minus its 4-byte size prefix.
const CHUNK_LEN: usize = 124;
const TRAILER_LEN: usize = 20;
/// Offset of the little-endian CRC32 inside the trailer.
const TRAILER_CRC_OFFSET: usize = 12;
/// Raw bytes fed to zlib between progress updates.
const COMPRESS_PIECE_LEN: usize = 256 * 1024;

/// Community ("modified") key pair: the private exponent is known, so files
/// can be both decrypted and encrypted.
const N_MODIFIED: &[u8] = b"75b4d6de5c016544068a1acf125869f43d2e09fc55b8b1e289556daf9b8757635593446288b3653da1ce91c87bb1a5c18f16323495c55d7d72c0890a83f69bfd1fd9434eb1c02f3e4679edfa43309319070129c267c85604d87bb65bae205de3707af1d2108881abb567c3b3d069ae67c3a4c6a3aa93d26413d4c66094ae2039";
const E_MODIFIED: u32 = 0x1D;
const D_MODIFIED: &[u8] = b"30b4c2d798d47086145c75063c8e841e719776e400291d7838d3e6c4405b504c6a07f8fca27f32b86643d2649d1d5f124cdd0bf272f0909dd7352fe10a77b34d831043d9ae541f8263c6fe3d1c14c2f04e43a7253a6dda9a8c1562cbd493c1b631a1957618ad5dfe5ca28553f746e2fc6f2db816c7db223ec91e955081c1de65";
/// NCSoft's original public key: decrypt only.
const N_ORIGINAL: &[u8] = b"97df398472ddf737ef0a0cd17e8d172f0fef1661a38a8ae1d6e829bc1c6e4c3cfc19292dda9ef90175e46e7394a18850b6417d03be6eea274d3ed1dde5b5d7bde72cc0a0b71d03608655633881793a02c9a67d9ef2b45eb7c08d4be329083ce450e68f7867b6749314d40511d09bc5744551baa86a89dc38123dc1668fd72d83";
const E_ORIGINAL: u32 = 0x35;

struct Keys {
    modified_n: BigUint,
    modified_e: BigUint,
    modified_d: BigUint,
    original_n: BigUint,
    original_e: BigUint,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let hex = |digits: &[u8]| BigUint::parse_bytes(digits, 16).expect("valid RSA hex constant");
    Keys {
        modified_n: hex(N_MODIFIED),
        modified_e: BigUint::from(E_MODIFIED),
        modified_d: hex(D_MODIFIED),
        original_n: hex(N_ORIGINAL),
        original_e: BigUint::from(E_ORIGINAL),
    }
});

/// Decrypts a whole 413 container (at least [`HEADER_LEN`] bytes). The trailer
/// is optional: only complete blocks are read.
pub fn decrypt(data: &[u8], progress: &Progress) -> Result<Vec<u8>, CodecError> {
    let body = &data[HEADER_LEN..];
    let block_count = body.len() / BLOCK_LEN;
    if block_count == 0 {
        return Err(CodecError::Truncated);
    }
    let blocks = &body[..block_count * BLOCK_LEN];
    let keys = &*KEYS;
    [
        (&keys.modified_n, &keys.modified_e),
        (&keys.original_n, &keys.original_e),
    ]
    .into_iter()
    .find_map(|(modulus, exponent)| {
        progress.start_phase(0, 1, block_count);
        decrypt_stream(blocks, modulus, exponent, progress).and_then(|stream| inflate(&stream))
    })
    .ok_or(CodecError::Rsa413Invalid)
}

/// Encrypts `raw` into a 413 container with the modified key. Progress has two
/// phases: compression, then sealing the RSA blocks.
pub fn encrypt(raw: &[u8], progress: &Progress) -> Result<Vec<u8>, CodecError> {
    let raw_len = u32::try_from(raw.len()).map_err(|_| CodecError::TooLargeFor413)?;
    progress.start_phase(0, 2, raw.len());
    // The stream is the plain size (u32 LE) followed by the zlib data.
    let mut encoder = ZlibEncoder::new(raw_len.to_le_bytes().to_vec(), Compression::default());
    for piece in raw.chunks(COMPRESS_PIECE_LEN) {
        encoder
            .write_all(piece)
            .expect("writing to a Vec cannot fail");
        progress.advance(piece.len());
    }
    let stream = encoder.finish().expect("writing to a Vec cannot fail");

    let block_count = stream.len().div_ceil(CHUNK_LEN);
    let blocks_end = HEADER_LEN + block_count * BLOCK_LEN;
    let mut out = vec![0u8; blocks_end + TRAILER_LEN];
    out[..HEADER_LEN].copy_from_slice(&container_header(413));
    progress.start_phase(1, 2, block_count);
    encrypt_stream(&stream, &mut out[HEADER_LEN..blocks_end], progress);

    let mut crc = Crc::new();
    crc.update(&out[..blocks_end]);
    let crc_at = blocks_end + TRAILER_CRC_OFFSET;
    out[crc_at..crc_at + 4].copy_from_slice(&crc.sum().to_le_bytes());
    Ok(out)
}

fn align4(size: usize) -> usize {
    (size + 3) & !3
}

/// Big-endian bytes of `n`, left-padded with zeros to a full block.
fn to_block(n: &BigUint) -> [u8; BLOCK_LEN] {
    let bytes = n.to_bytes_be();
    let mut block = [0u8; BLOCK_LEN];
    block[BLOCK_LEN - bytes.len()..].copy_from_slice(&bytes);
    block
}

/// Opens every block of `body` (a whole number of blocks) and concatenates the
/// chunks. `None` when a block size is impossible, meaning the key is wrong.
fn decrypt_stream(
    body: &[u8],
    modulus: &BigUint,
    exponent: &BigUint,
    progress: &Progress,
) -> Option<Vec<u8>> {
    let block_count = body.len() / BLOCK_LEN;
    let mut stream = Vec::with_capacity(block_count * CHUNK_LEN);
    for (index, block) in body.as_chunks::<BLOCK_LEN>().0.iter().enumerate() {
        let plain = to_block(&BigUint::from_bytes_be(block).modpow(exponent, modulus));
        let size = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
        let is_last = index + 1 == block_count;
        if size > CHUNK_LEN || (size < CHUNK_LEN && !is_last) {
            return None;
        }
        let start = BLOCK_LEN - align4(size);
        stream.extend_from_slice(&plain[start..start + size]);
        progress.advance(1);
    }
    Some(stream)
}

/// Inflates `stream` (u32 LE plain size + zlib data), checking the size.
fn inflate(stream: &[u8]) -> Option<Vec<u8>> {
    let (size, compressed) = stream.split_first_chunk::<4>()?;
    let mut out = Vec::new();
    ZlibDecoder::new(compressed).read_to_end(&mut out).ok()?;
    (out.len() == u32::from_le_bytes(*size) as usize).then_some(out)
}

/// Seals `stream` into the RSA blocks of `out` (exactly one 128-byte block per
/// started 124-byte chunk), advancing `progress` by one unit per block. The
/// private-key exponentiation dominates, so blocks are spread across all cores.
fn encrypt_stream(stream: &[u8], out: &mut [u8], progress: &Progress) {
    let block_count = stream.len().div_ceil(CHUNK_LEN);
    debug_assert_eq!(out.len(), block_count * BLOCK_LEN);
    if block_count == 0 {
        return;
    }
    let workers = thread::available_parallelism().map_or(1, NonZero::get);
    let per_worker = block_count.div_ceil(workers);
    let keys = &*KEYS;
    thread::scope(|scope| {
        for (chunks, blocks) in stream
            .chunks(CHUNK_LEN * per_worker)
            .zip(out.chunks_mut(BLOCK_LEN * per_worker))
        {
            scope.spawn(move || {
                for (chunk, block) in chunks.chunks(CHUNK_LEN).zip(blocks.chunks_mut(BLOCK_LEN)) {
                    block.copy_from_slice(&encrypt_block(chunk, keys));
                    progress.advance(1);
                }
            });
        }
    });
}

fn encrypt_block(chunk: &[u8], keys: &Keys) -> [u8; BLOCK_LEN] {
    let mut plain = [0u8; BLOCK_LEN];
    plain[..4].copy_from_slice(&(chunk.len() as u32).to_be_bytes());
    let start = BLOCK_LEN - align4(chunk.len());
    plain[start..start + chunk.len()].copy_from_slice(chunk);
    to_block(&BigUint::from_bytes_be(&plain).modpow(&keys.modified_d, &keys.modified_n))
}

#[cfg(test)]
#[path = "tests/rsa413.rs"]
mod tests;
