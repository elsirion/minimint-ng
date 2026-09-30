use minimint_ng::json::{JsonError, encode, parse, unsigned};
use sonic_rs::JsonValueTrait;

#[test]
fn exact_unsigned_values_never_pass_through_float() {
    let v = parse(
        br#"{"n":18446744073709551615,"precise":9007199254740993}"#,
        1024,
        8,
    )
    .unwrap();
    assert_eq!(unsigned(v.get("n").unwrap()), Ok(u64::MAX));
    assert_eq!(unsigned(v.get("precise").unwrap()), Ok(9007199254740993));
    assert_eq!(
        encode(&v).unwrap(),
        br#"{"n":18446744073709551615,"precise":9007199254740993}"#
    );
    for text in [
        "-1",
        "1.5",
        "1e3",
        "18446744073709551616",
        "true",
        "null",
        "\"1\"",
    ] {
        if let Ok(v) = parse(text.as_bytes(), 1024, 8) {
            assert!(unsigned(&v).is_err(), "{text}");
        }
    }
}

#[test]
fn invalid_documents_and_duplicate_escaped_fields_fail() {
    for bytes in [
        b"{} {}".as_slice(),
        b"[1,]",
        b"{",
        b"\"\xff\"",
        br#""\uD800""#,
        b"NaN",
    ] {
        assert_eq!(
            parse(bytes, 1024, 8).map(|_| ()).unwrap_err(),
            JsonError::Syntax
        );
    }
    for bytes in [
        br#"{"auth":1,"auth":2}"#.as_slice(),
        br#"{"x":{"a":1,"\u0061":2}}"#,
    ] {
        assert_eq!(
            parse(bytes, 1024, 8).map(|_| ()).unwrap_err(),
            JsonError::DuplicateField
        );
    }
}

#[test]
fn resource_limits_and_strings_containing_container_characters() {
    assert_eq!(parse(b"null", 3, 8).unwrap_err(), JsonError::Size);
    assert_eq!(parse(b"[[[0]]]", 1024, 2).unwrap_err(), JsonError::Depth);
    assert!(parse(b"[[0]]", 1024, 2).is_ok());
    assert!(parse(br#"{"text":"[[[\"{\\"}"#, 1024, 1).is_ok());
    let nested = format!("{}0{}", "[".repeat(10000), "]".repeat(10000));
    assert_eq!(
        parse(nested.as_bytes(), 30000, 64).unwrap_err(),
        JsonError::Depth
    );
}

#[test]
fn raw_number_lexemes_roundtrip_exactly_and_scaling_is_checked() {
    use minimint_ng::json::scaled_unsigned;
    for (text, scale, expected) in [
        ("0.00001000", 8, 1000),
        ("1e-8", 8, 1),
        ("1E+3", 0, 1000),
        ("1.2300e+2", 0, 123),
        ("123000e-3", 0, 123),
        ("0.0000000100000000000000000000000", 8, 1),
        ("184467440737.09551615", 8, u64::MAX),
        ("184467440737095516150000000000000000000e-19", 0, u64::MAX),
        ("0e999999999999999999999999999999999999999999", 8, 0),
        ("0.0000e-999999999999999999999999999999999999999", 8, 0),
    ] {
        let value = parse(text.as_bytes(), 1024, 8).unwrap();
        assert_eq!(encode(&value).unwrap(), text.as_bytes());
        assert_eq!(scaled_unsigned(&value, scale), Ok(expected), "{text}");
    }
    for text in [
        "-1",
        "-0",
        "-0.0e-8",
        "0.000000001",
        "184467440737.09551616",
        "1e10000000000000000000000000000000000000000000",
        "1e-1000000000000000000000000000000000000000000000",
        "1.000000000000000000000000000000000000001",
        "true",
        "\"1\"",
        "null",
    ] {
        let value = parse(text.as_bytes(), 1024, 8).unwrap();
        assert_eq!(scaled_unsigned(&value, 8), Err(JsonError::Type), "{text}");
    }
    for text in ["1e3", "1.0", "-0", "0e0"] {
        assert_eq!(
            unsigned(&parse(text.as_bytes(), 1024, 8).unwrap()),
            Err(JsonError::Type)
        );
    }
    assert_eq!(
        scaled_unsigned(&parse(b"1", 10, 8).unwrap(), u32::MAX),
        Err(JsonError::Type)
    );
    assert_eq!(
        scaled_unsigned(&parse(b"0", 10, 8).unwrap(), u32::MAX),
        Ok(0)
    );
}

#[test]
fn rounded_scaling_rounds_exact_lexeme_half_up() {
    use minimint_ng::json::rounded_scaled_unsigned;
    for (text, scale, expected) in [
        // Esplora renders Core's 1070 sat/kvB as this sat/vB float.
        ("1.0699999999999998", 3, 1070),
        ("1.014", 3, 1014),
        ("1.0005", 3, 1001),
        ("1.00049999", 3, 1000),
        ("1", 3, 1000),
        ("0.0004", 3, 0),
        ("0.0005", 3, 1),
        ("4e-4", 3, 0),
        ("5e-4", 3, 1),
        ("1e-999999999999999999999999999999", 3, 0),
        ("2.5E+1", 0, 25),
        ("0.00001000", 8, 1000),
        ("18446744073709551.615", 3, u64::MAX),
        ("18446744073709551614.5", 0, u64::MAX),
        ("0e999999999999999999999999999999", 3, 0),
    ] {
        let value = parse(text.as_bytes(), 1024, 8).unwrap();
        assert_eq!(
            rounded_scaled_unsigned(&value, scale),
            Ok(expected),
            "{text}"
        );
    }
    for text in [
        "-1",
        "-0",
        "18446744073709551615.5",
        "18446744073709551.616",
        "1e17",
        "1e999999999999999999999999999999",
        "true",
        "\"1\"",
        "null",
    ] {
        let value = parse(text.as_bytes(), 1024, 8).unwrap();
        assert_eq!(
            rounded_scaled_unsigned(&value, 3),
            Err(JsonError::Type),
            "{text}"
        );
    }
}

#[test]
fn decimal_scaling_matches_integer_arithmetic_for_small_exact_values() {
    use minimint_ng::json::scaled_unsigned;
    for numerator in [0u64, 1, 2, 9, 10, 11, 12345, 99999999] {
        for places in 0..=8 {
            let text = format!("{numerator}e-{places}");
            let value = parse(text.as_bytes(), 128, 4).unwrap();
            for scale in 0..=8 {
                let expected = if scale >= places {
                    Ok(numerator * 10u64.pow(scale - places))
                } else {
                    let divisor = 10u64.pow(places - scale);
                    if numerator % divisor == 0 {
                        Ok(numerator / divisor)
                    } else {
                        Err(JsonError::Type)
                    }
                };
                assert_eq!(
                    scaled_unsigned(&value, scale),
                    expected,
                    "{text}, scale {scale}"
                );
            }
        }
    }
}
#[test]
fn output_limit_counts_json_escaping_before_allocation_growth() {
    let value = sonic_rs::json!({"text":"\n\n\n","n":u64::MAX});
    let expected = encode(&value).unwrap();
    assert_eq!(
        minimint_ng::json::encode_bounded(&value, expected.len()).unwrap(),
        expected
    );
    assert_eq!(
        minimint_ng::json::encode_bounded(&value, expected.len() - 1).unwrap_err(),
        JsonError::Size
    );
}
#[test]
fn bounded_output_handles_container_minima_raw_numbers_and_all_string_escapes() {
    use minimint_ng::json::encode_bounded;
    for text in [
        "[]",
        "{}",
        "[0]",
        "{\"\":0}",
        "[false,null,{},[]]",
        "18446744073709551615",
        "-0",
        "1.2300e+200",
        "1e999999999999999999999999999999",
    ] {
        let value = parse(text.as_bytes(), 1024, 8).unwrap();
        let expected = encode(&value).unwrap();
        assert_eq!(encode_bounded(&value, expected.len()).unwrap(), expected);
        for maximum in 0..expected.len() {
            assert_eq!(encode_bounded(&value, maximum), Err(JsonError::Size));
        }
    }
    let controls: String = (0u8..32).map(char::from).collect();
    let value = sonic_rs::json!({"\n\"\\":format!("{controls}\"\\é😀")});
    let expected = encode(&value).unwrap();
    assert_eq!(encode_bounded(&value, expected.len()).unwrap(), expected);
    assert_eq!(
        encode_bounded(&value, expected.len() - 1),
        Err(JsonError::Size)
    );
    let large = sonic_rs::json!(vec![0u8; 65536]);
    assert_eq!(encode_bounded(&large, 3), Err(JsonError::Size));
    let raw = format!("1{}", "0".repeat(65536));
    let value = parse(raw.as_bytes(), raw.len(), 8).unwrap();
    assert_eq!(encode_bounded(&value, 32), Err(JsonError::Size));
    assert_eq!(encode_bounded(&value, raw.len()).unwrap(), raw.as_bytes());
}
