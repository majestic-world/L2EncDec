//! XOR-based containers: 111 and 121 (single-byte key), 120 (positional
//! keystream), 211 and 212 (repeating 8-byte key).
//!
//! Every `decrypt_*` takes the whole container (at least [`HEADER_LEN`] bytes)
//! and returns the payload without the header.

use crate::codec::{
    BITMAP_MAGIC, FileClass, HEADER_LEN, UNREAL_MAGIC, container_header, filename_key,
};

const KEY_111: u8 = 0xAC;
const KEY_211: [u8; 8] = [0x1E, 0x52, 0x46, 0xF9, 0x96, 0x10, 0xCD, 0x33];
const KEY_212: [u8; 8] = [0x42, 0xC1, 0x36, 0xE6, 0x6C, 0x1F, 0x68, 0xE6];
/// Offset added to the payload index before deriving the 120 keystream byte.
const KEYSTREAM_120_OFFSET: usize = 0xE6;

pub fn decrypt_111(data: &[u8]) -> Vec<u8> {
    xor_payload(data, |_| KEY_111)
}

pub fn decrypt_120(data: &[u8]) -> Vec<u8> {
    xor_payload(data, |i| keystream_120(i + KEYSTREAM_120_OFFSET))
}

/// Decrypts a 121 container. Textures and packages recover their key from the
/// known plain magic, so renamed files still decrypt; everything else (and a
/// payload whose magic matches no key) uses the file-name key.
pub fn decrypt_121(data: &[u8], file_name: &str, class: FileClass) -> Vec<u8> {
    let inferred = match class {
        FileClass::Texture | FileClass::Package => infer_key_121(&data[HEADER_LEN..]),
        FileClass::Rsa | FileClass::Text | FileClass::Other => None,
    };
    let key = inferred.unwrap_or_else(|| filename_key(file_name));
    xor_payload(data, |_| key)
}

pub fn decrypt_211(data: &[u8]) -> Vec<u8> {
    xor_payload(data, |i| KEY_211[i % KEY_211.len()])
}

pub fn decrypt_212(data: &[u8]) -> Vec<u8> {
    xor_payload(data, |i| KEY_212[i % KEY_212.len()])
}

pub fn encrypt_111(raw: &[u8]) -> Vec<u8> {
    wrap(111, raw, KEY_111)
}

pub fn encrypt_121(raw: &[u8], file_name: &str) -> Vec<u8> {
    wrap(121, raw, filename_key(file_name))
}

fn xor_payload(data: &[u8], key: impl Fn(usize) -> u8) -> Vec<u8> {
    data[HEADER_LEN..]
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key(i))
        .collect()
}

fn wrap(version: u16, raw: &[u8], key: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + raw.len());
    out.extend_from_slice(&container_header(version));
    out.extend(raw.iter().map(|byte| byte ^ key));
    out
}

fn keystream_120(x: usize) -> u8 {
    let high = ((x >> 12) ^ (x >> 4)) & 0xF;
    let low = ((x >> 8) ^ x) & 0xF;
    ((high << 4) | low) as u8
}

/// First key that turns the payload start into an Unreal package or bitmap magic.
fn infer_key_121(payload: &[u8]) -> Option<u8> {
    let decodes_to = |magic: &[u8], key: u8| {
        payload.len() >= magic.len()
            && payload
                .iter()
                .zip(magic)
                .all(|(byte, expected)| byte ^ key == *expected)
    };
    (0..=u8::MAX).find(|&key| decodes_to(UNREAL_MAGIC, key) || decodes_to(BITMAP_MAGIC, key))
}

#[cfg(test)]
#[path = "tests/xor.rs"]
mod tests;
