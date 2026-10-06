use super::*;

fn container(version: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = container_header(version).to_vec();
    data.extend_from_slice(payload);
    data
}

#[test]
fn keystream_120_matches_reference_vectors() {
    assert_eq!(keystream_120(0xE6), 0xE6);
    assert_eq!(keystream_120(1 + 0xE6), 0xE7);
    assert_eq!(keystream_120(0x1F1A + 0xE6), 0x20);
    assert_eq!(keystream_120(0x2000 + 0xE6), 0xC6);
    assert_eq!(keystream_120(0xFFFF + 0xE6), 0xE5);
}

#[test]
fn eight_byte_keys_repeat_over_the_payload() {
    let zeros = [0u8; 16];
    assert_eq!(decrypt_211(&container(211, &zeros)), KEY_211.repeat(2));
    assert_eq!(decrypt_212(&container(212, &zeros)), KEY_212.repeat(2));
}

#[test]
fn renamed_121_texture_recovers_its_key() {
    let mut raw = UNREAL_MAGIC.to_vec();
    raw.extend_from_slice(b"texture package body");
    assert_ne!(filename_key("a.utx"), filename_key("b.utx"));
    let encrypted = encrypt_121(&raw, "a.utx");
    assert_eq!(decrypt_121(&encrypted, "b.utx", FileClass::Texture), raw);
}

#[test]
fn text_121_uses_the_file_name_key() {
    // 'a' ^ 'n' == 'B' ^ 'M', so magic inference would find a wrong key here.
    let raw = b"another text file".to_vec();
    let encrypted = encrypt_121(&raw, "a.htm");
    assert_ne!(decrypt_121(&encrypted, "a.htm", FileClass::Texture), raw);
    assert_eq!(decrypt_121(&encrypted, "a.htm", FileClass::Text), raw);
}
