//! File-format detection and dispatch: decides whether a file is encrypted or
//! plain, which cipher applies, and toggles it.

use std::fmt;

use crate::progress::Progress;
use crate::{rsa413, xor};

/// Length of the `Lineage2VerNNN` container header (14 UTF-16LE code units).
pub(crate) const HEADER_LEN: usize = 28;

/// `Lineage2Ver` in UTF-16LE: the version-independent part of the header.
const CONTAINER_PREFIX: &[u8; 22] = b"L\0i\0n\0e\0a\0g\0e\x002\0V\0e\0r\0";
pub(crate) const UNREAL_MAGIC: &[u8; 4] = &[0xC1, 0x83, 0x2A, 0x9E];
const OGG_MAGIC: &[u8; 4] = b"OggS";
const L2SD_MAGIC: &[u8; 4] = b"L2SD";
pub(crate) const BITMAP_MAGIC: &[u8; 2] = b"BM";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Decrypt111,
    Decrypt120,
    Decrypt121,
    Decrypt211,
    Decrypt212,
    Decrypt413,
    DecryptOgg,
    Encrypt111,
    Encrypt121,
    Encrypt413,
    EncryptOgg,
}

impl Operation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Decrypt111 => "decrypt 111",
            Self::Decrypt120 => "decrypt 120",
            Self::Decrypt121 => "decrypt 121",
            Self::Decrypt211 => "decrypt 211",
            Self::Decrypt212 => "decrypt 212",
            Self::Decrypt413 => "decrypt 413",
            Self::DecryptOgg => "decrypt OGG",
            Self::Encrypt111 => "encrypt 111",
            Self::Encrypt121 => "encrypt 121",
            Self::Encrypt413 => "encrypt 413",
            Self::EncryptOgg => "encrypt OGG",
        }
    }

    pub fn is_encrypt(self) -> bool {
        match self {
            Self::Encrypt111 | Self::Encrypt121 | Self::Encrypt413 | Self::EncryptOgg => true,
            Self::Decrypt111
            | Self::Decrypt120
            | Self::Decrypt121
            | Self::Decrypt211
            | Self::Decrypt212
            | Self::Decrypt413
            | Self::DecryptOgg => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    Empty,
    Truncated,
    UnknownFormat,
    /// Container whose version is not handled; holds the 3 decoded characters.
    UnsupportedVersion(String),
    Rsa413Invalid,
    /// Plain file too large for the 32-bit size field of a 413 stream.
    TooLargeFor413,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("input file is empty"),
            Self::Truncated => f.write_str("file is truncated"),
            Self::UnknownFormat => f.write_str("unknown file format"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported Lineage2Ver{version}"),
            Self::Rsa413Invalid => {
                f.write_str("Lineage2Ver413 payload does not decrypt under either RSA key")
            }
            Self::TooLargeFor413 => f.write_str("file is too large for Lineage2Ver413 (4 GiB max)"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Category of a file, derived from its name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileClass {
    Texture,
    Package,
    Rsa,
    Text,
    Other,
}

pub(crate) fn classify(file_name: &str) -> FileClass {
    let (stem, ext) = file_name.rsplit_once('.').unwrap_or((file_name, ""));
    let ext_is = |names: &[&str]| names.iter().any(|name| ext.eq_ignore_ascii_case(name));
    let stem_is = |names: &[&str]| names.iter().any(|name| stem.eq_ignore_ascii_case(name));
    if ext_is(&["utx", "ugx", "bmp"]) {
        FileClass::Texture
    } else if ext_is(&["uax", "unr", "uix", "ukx", "usx", "usk", "u"]) {
        FileClass::Package
    } else if ext_is(&["dat"]) || (ext_is(&["ini"]) && stem_is(&["l2", "user"])) {
        FileClass::Rsa
    } else if ext_is(&["htm", "int"])
        || (ext_is(&["xdat"]) && stem_is(&["interface"]))
        || (ext_is(&["ini"]) && stem_is(&["ttfontinfo", "localization"]))
    {
        FileClass::Text
    } else {
        FileClass::Other
    }
}

/// Picks the operation that toggles `data` between its plain and encrypted form.
pub fn select(file_name: &str, data: &[u8]) -> Result<Operation, CodecError> {
    if data.is_empty() {
        return Err(CodecError::Empty);
    }
    if data.starts_with(CONTAINER_PREFIX) {
        return container_operation(data);
    }
    let operation = if data.starts_with(UNREAL_MAGIC) {
        match classify(file_name) {
            FileClass::Texture => Operation::Encrypt121,
            FileClass::Package | FileClass::Rsa | FileClass::Text | FileClass::Other => {
                Operation::Encrypt111
            }
        }
    } else if data.starts_with(OGG_MAGIC) {
        Operation::EncryptOgg
    } else if data.starts_with(L2SD_MAGIC) {
        Operation::DecryptOgg
    } else if data.starts_with(BITMAP_MAGIC) {
        Operation::Encrypt121
    } else {
        match classify(file_name) {
            FileClass::Rsa => Operation::Encrypt413,
            FileClass::Text => Operation::Encrypt111,
            FileClass::Package | FileClass::Texture | FileClass::Other => {
                return Err(CodecError::UnknownFormat);
            }
        }
    };
    Ok(operation)
}

fn container_operation(data: &[u8]) -> Result<Operation, CodecError> {
    let Some(version) = data.get(CONTAINER_PREFIX.len()..HEADER_LEN) else {
        return Err(CodecError::Truncated);
    };
    let (pairs, _) = version.as_chunks::<2>();
    let units: [u16; 3] = std::array::from_fn(|i| u16::from_le_bytes(pairs[i]));
    let unsupported = || CodecError::UnsupportedVersion(String::from_utf16_lossy(&units));
    if !units
        .iter()
        .all(|unit| (u16::from(b'0')..=u16::from(b'9')).contains(unit))
    {
        return Err(unsupported());
    }
    let number = units
        .iter()
        .fold(0, |acc, unit| acc * 10 + (unit - u16::from(b'0')));
    match number {
        111 => Ok(Operation::Decrypt111),
        120 => Ok(Operation::Decrypt120),
        121 => Ok(Operation::Decrypt121),
        211 => Ok(Operation::Decrypt211),
        212 => Ok(Operation::Decrypt212),
        413 => Ok(Operation::Decrypt413),
        _ => Err(unsupported()),
    }
}

/// Runs `operation` (as chosen by [`select`]) on `data`, reporting progress for
/// the slow RSA path; the XOR and OGG paths finish instantly.
pub fn apply(
    operation: Operation,
    file_name: &str,
    data: &[u8],
    progress: &Progress,
) -> Result<Vec<u8>, CodecError> {
    let out = match operation {
        Operation::Decrypt111 => xor::decrypt_111(data),
        Operation::Decrypt120 => xor::decrypt_120(data),
        Operation::Decrypt121 => xor::decrypt_121(data, file_name, classify(file_name)),
        Operation::Decrypt211 => xor::decrypt_211(data),
        Operation::Decrypt212 => xor::decrypt_212(data),
        Operation::Decrypt413 => rsa413::decrypt(data, progress)?,
        Operation::DecryptOgg => with_magic(data, OGG_MAGIC),
        Operation::Encrypt111 => xor::encrypt_111(data),
        Operation::Encrypt121 => xor::encrypt_121(data, file_name),
        Operation::Encrypt413 => rsa413::encrypt(data, progress)?,
        Operation::EncryptOgg => with_magic(data, L2SD_MAGIC),
    };
    Ok(out)
}

/// Copies `data` (at least 4 bytes) with its first 4 bytes replaced by `magic`.
fn with_magic(data: &[u8], magic: &[u8; 4]) -> Vec<u8> {
    let mut out = data.to_vec();
    out[..4].copy_from_slice(magic);
    out
}

/// `Lineage2Ver<NNN>` in UTF-16LE; `version` has at most 3 digits.
pub(crate) fn container_header(version: u16) -> [u8; HEADER_LEN] {
    debug_assert!(version < 1000, "container versions have 3 digits");
    let mut header = [0; HEADER_LEN];
    let (prefix, digits) = header.split_at_mut(CONTAINER_PREFIX.len());
    prefix.copy_from_slice(CONTAINER_PREFIX);
    let values = [version / 100, version / 10 % 10, version % 10];
    for (slot, value) in digits.as_chunks_mut::<2>().0.iter_mut().zip(values) {
        *slot = (u16::from(b'0') + value).to_le_bytes();
    }
    header
}

/// Version 121 key: sum of the ASCII-lowercased file name bytes, truncated to `u8`.
pub(crate) fn filename_key(file_name: &str) -> u8 {
    file_name
        .bytes()
        .map(|byte| u32::from(byte.to_ascii_lowercase()))
        .sum::<u32>() as u8
}

#[cfg(test)]
#[path = "tests/codec.rs"]
mod tests;
