use minimint_ng::codec::text::{
    TextError, base32_decode, base32_encode, base64url_decode, base64url_encode, hex_decode,
    hex_encode,
};

#[test]
fn hex_vectors_and_rejections() {
    assert_eq!(hex_encode(&[]), "");
    assert_eq!(hex_decode(""), Ok(vec![]));
    assert_eq!(hex_encode(&[0, 1, 15, 16, 127, 128, 255]), "00010f107f80ff");
    assert_eq!(
        hex_decode("00aAbBcCdDeEfF"),
        Ok(vec![0, 170, 187, 204, 221, 238, 255])
    );
    for invalid in ["0", "000", "gg", "0x00", " 00", "00\n", "é", "💰"] {
        assert!(hex_decode(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn base32_uses_low_bits_first() {
    let vectors: &[(&[u8], &str)] = &[
        (&[], ""),
        (&[0], "00"),
        (&[1], "10"),
        (&[102], "63"),
        (&[255], "v7"),
        (&[255, 0], "v700"),
        (&[0, 255], "0ov1"),
        (&[255, 255, 255, 255, 255], "vvvvvvvv"),
    ];
    for &(bytes, encoded) in vectors {
        assert_eq!(base32_encode(bytes), encoded);
        assert_eq!(base32_decode(encoded).unwrap(), bytes);
    }
}

#[test]
fn base32_discards_even_nonzero_trailing_bits() {
    assert_eq!(base32_decode("v"), Ok(vec![]));
    assert_eq!(base32_decode("vv"), Ok(vec![255]));
    assert_eq!(base32_decode("vvv"), Ok(vec![255]));
    assert_eq!(base32_decode("vvvv"), Ok(vec![255, 255]));
    assert_eq!(base32_decode("1v"), Ok(vec![225]));
    for invalid in ["V7", "ABC", "w", "=", "v7=", " v7", "é", "💰"] {
        assert!(base32_decode(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn base64url_vectors_and_canonical_rejections() {
    let vectors: &[(&[u8], &str)] = &[
        (&[], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
        (&[251, 255, 255], "-___"),
        (&[255], "_w"),
        (&[255, 255], "__8"),
    ];
    for &(bytes, encoded) in vectors {
        assert_eq!(base64url_encode(bytes), encoded);
        assert_eq!(base64url_decode(encoded).unwrap(), bytes);
    }
    for invalid in [
        "A", "AAAAA", "Zg=", "Zg==", "+///", "Zg\n", "Zg ", "é", "💰", "Zh", "Zm9", "_x", "__9",
    ] {
        assert!(base64url_decode(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn roundtrips_cover_all_bytes_and_group_boundaries() {
    let bytes: Vec<u8> = (0..=255).collect();
    for len in 0..=bytes.len() {
        let input = &bytes[..len];
        assert_eq!(hex_decode(&hex_encode(input)).unwrap(), input);
        assert_eq!(base32_decode(&base32_encode(input)).unwrap(), input);
        assert_eq!(base64url_decode(&base64url_encode(input)).unwrap(), input);
    }
}

#[test]
fn text_errors_implement_standard_traits() {
    fn assert_traits<T: std::fmt::Debug + Eq + std::error::Error>() {}
    assert_traits::<TextError>();
    let error = hex_decode("!").unwrap_err();
    assert!(!error.to_string().is_empty());
}
