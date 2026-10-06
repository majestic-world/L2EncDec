use super::*;

fn unreal_package() -> Vec<u8> {
    let mut data = UNREAL_MAGIC.to_vec();
    data.extend((0..300u32).map(|i| (i * 7) as u8));
    data
}

fn assert_toggles_back(file_name: &str, data: &[u8]) {
    let (_, encrypted) = transform(file_name, data).expect("first toggle");
    assert_ne!(encrypted, data);
    let (_, restored) = transform(file_name, &encrypted).expect("second toggle");
    assert_eq!(restored, data);
}

#[test]
fn raw_unreal_selects_121_for_textures_and_111_otherwise() {
    let data = unreal_package();
    assert_eq!(select("pledge.utx", &data), Ok(Operation::Encrypt121));
    assert_eq!(select("entry.unr", &data), Ok(Operation::Encrypt111));
    assert_eq!(select("x.bak", &data), Ok(Operation::Encrypt111));
}

#[test]
fn unknown_magic_selects_by_file_name() {
    let data = b"[Engine]\r\nkey=value\r\n";
    assert_eq!(select("L2.ini", data), Ok(Operation::Encrypt413));
    assert_eq!(select("user.ini", data), Ok(Operation::Encrypt413));
    assert_eq!(select("foo.ini", data), Err(CodecError::UnknownFormat));
    assert_eq!(select("Interface.xdat", data), Ok(Operation::Encrypt111));
    assert_eq!(select("other.xdat", data), Err(CodecError::UnknownFormat));
    assert_eq!(select("a.htm", data), Ok(Operation::Encrypt111));
    assert_eq!(select("a.txt", data), Err(CodecError::UnknownFormat));
}

#[test]
fn magic_signatures_select_their_operation() {
    assert_eq!(select("a.ogg", b"OggS\0\0"), Ok(Operation::EncryptOgg));
    assert_eq!(select("a.ogg", b"L2SD\0\0"), Ok(Operation::DecryptOgg));
    assert_eq!(select("a.bmp", b"BM\0\0"), Ok(Operation::Encrypt121));
}

#[test]
fn container_with_unknown_version_is_rejected() {
    let data = container_header(811);
    assert_eq!(
        select("a.utx", &data),
        Err(CodecError::UnsupportedVersion("811".to_owned()))
    );
}

#[test]
fn empty_and_truncated_inputs_are_rejected() {
    assert_eq!(select("a.utx", &[]), Err(CodecError::Empty));
    assert_eq!(
        select("a.utx", &container_header(111)[..24]),
        Err(CodecError::Truncated)
    );
}

#[test]
fn transform_twice_restores_the_original() {
    assert_toggles_back("pledge.utx", &unreal_package());
    assert_toggles_back("entry.unr", &unreal_package());
    assert_toggles_back(
        "hairgrp.dat",
        b"plain 413 table contents, not a known magic",
    );
    assert_toggles_back("a.ogg", b"OggS\x00\x02rest of the stream");
    assert_toggles_back("sp.bmp", b"BM\x36\x00\x0c\x00pixels");
}
