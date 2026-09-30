use minimint_ng::codec::{DecodeError, Reader, bigsize, encode_bytes, encode_enum};

#[test]
fn canonical_integer_boundaries() {
    for (value, expected) in [
        (0, vec![0]),
        (252, vec![252]),
        (253, vec![253, 0, 253]),
        (65535, vec![253, 255, 255]),
        (65536, vec![254, 0, 1, 0, 0]),
        (u32::MAX as u64, vec![254, 255, 255, 255, 255]),
        (u32::MAX as u64 + 1, vec![255, 0, 0, 0, 1, 0, 0, 0, 0]),
        (u64::MAX, vec![255; 9]),
    ] {
        assert_eq!(bigsize(value), expected);
        let mut r = Reader::new(&expected);
        assert_eq!(r.u64(), Ok(value));
        assert_eq!(r.finish(), Ok(()));
    }
}
#[test]
fn reject_nonminimal_truncated_and_narrow_overflow() {
    for input in [
        &[253, 0, 252][..],
        &[254, 0, 0, 255, 255],
        &[255, 0, 0, 0, 0, 255, 255, 255, 255],
    ] {
        assert_eq!(Reader::new(input).u64(), Err(DecodeError::NonCanonical));
    }
    for input in [
        &[][..],
        &[253],
        &[253, 1],
        &[254, 1, 2, 3],
        &[255, 1, 2, 3, 4, 5, 6, 7],
    ] {
        assert_eq!(Reader::new(input).u64(), Err(DecodeError::Truncated));
    }
    assert_eq!(
        Reader::new(&bigsize(65536)).u16(),
        Err(DecodeError::Overflow)
    );
    assert_eq!(
        Reader::new(&bigsize(1u64 << 32)).u32(),
        Err(DecodeError::Overflow)
    );
    assert_eq!(Reader::new(&[255]).byte(), Ok(255));
}
#[test]
fn strict_flags_utf8_and_consumption() {
    assert_eq!(Reader::new(&[2]).boolean(), Err(DecodeError::InvalidFlag));
    assert_eq!(
        Reader::new(&[2]).optional(|r| r.u64()),
        Err(DecodeError::InvalidFlag)
    );
    assert_eq!(Reader::new(&[0]).optional(|r| r.u64()), Ok(None));
    assert_eq!(Reader::new(&[1, 42]).optional(|r| r.u64()), Ok(Some(42)));
    assert_eq!(
        Reader::new(&[1, 255]).string(),
        Err(DecodeError::InvalidUtf8)
    );
    assert_eq!(Reader::new(&[0]).finish(), Err(DecodeError::TrailingBytes));
}
#[test]
fn framed_values_and_lengths_are_bounded_by_input() {
    let bytes = encode_enum(7, &[10, 11]);
    assert_eq!(bytes, vec![7, 2, 10, 11]);
    let mut r = Reader::new(&bytes);
    let (tag, mut body) = r.variant().unwrap();
    assert_eq!(tag, 7);
    assert_eq!(body.byte(), Ok(10));
    assert_eq!(body.finish(), Err(DecodeError::TrailingBytes));
    assert_eq!(r.finish(), Ok(()));
    assert_eq!(
        Reader::new(&bigsize(u64::MAX)).bytes(),
        Err(DecodeError::Truncated)
    );
    assert_eq!(encode_bytes(&[3, 4]), vec![2, 3, 4]);
}
#[test]
fn dynamic_module_frame_has_u16_id_and_bounded_body() {
    let mut r = Reader::new(&[42, 2, 0, 0]);
    let (id, body) = r.module().unwrap();
    assert_eq!(id, 42);
    assert_eq!(body.remaining(), 2);
    assert_eq!(r.finish(), Ok(()));
    let bytes = [254, 0, 1, 0, 0, 0];
    assert_eq!(
        Reader::new(&bytes).module().unwrap_err(),
        DecodeError::Overflow
    );
}
#[test]
fn map_order_is_numeric_and_rejects_duplicates() {
    let mut r = Reader::new(&[2, 252, 1, 253, 0, 253, 2]);
    assert_eq!(
        r.ordered_map(|r| r.u16(), |r| r.byte()).unwrap(),
        vec![(252, 1), (253, 2)]
    );
    for bytes in [&[2, 1, 7, 1, 8][..], &[2, 2, 7, 1, 8]] {
        assert_eq!(
            Reader::new(bytes).ordered_map(|r| r.u16(), |r| r.byte()),
            Err(DecodeError::Unordered)
        );
    }
}

#[test]
fn frames_cannot_borrow_bytes_from_the_next_value() {
    assert_eq!(
        Reader::new(&[0, 2, 1]).variant().unwrap_err(),
        DecodeError::Truncated
    );
    assert_eq!(
        Reader::new(&[0, 2, 1]).module().unwrap_err(),
        DecodeError::Truncated
    );
    let mut outer = Reader::new(&[0, 1, 253, 0, 253]);
    let (_, mut inner) = outer.variant().unwrap();
    assert_eq!(inner.u64(), Err(DecodeError::Truncated));
    assert_eq!(outer.u16(), Ok(0));
    assert_eq!(outer.byte(), Ok(253));
}

#[test]
fn finite_buffer_has_no_universal_sixteen_million_byte_cap() {
    let payload = vec![0; 16_000_001];
    let encoded = encode_bytes(&payload);
    let mut r = Reader::new(&encoded);
    assert_eq!(r.bytes().unwrap().len(), payload.len());
    assert_eq!(r.finish(), Ok(()));
}

#[test]
fn buggy_zero_consumption_schema_cannot_loop_on_declared_count() {
    let count = bigsize(u64::MAX);
    let mut key = 0u64;
    assert_eq!(
        Reader::new(&count).ordered_map(
            |_| {
                key += 1;
                Ok(key)
            },
            |_| Ok(())
        ),
        Err(DecodeError::NoProgress)
    );
    assert_eq!(
        Reader::new(&[1]).ordered_map(|_| Ok(()), |_| Ok(())),
        Ok(vec![((), ())])
    );
}

#[test]
fn collections_and_result_flags() {
    use minimint_ng::codec::{ConsensusEncode, decode_whole};
    use std::collections::{BTreeMap, BTreeSet};
    assert_eq!(
        decode_whole::<Vec<u16>>(&[2, 252, 253, 0, 253]),
        Ok(vec![252, 253])
    );
    assert_eq!(
        decode_whole::<BTreeSet<u16>>(&[2, 1, 1]),
        Err(DecodeError::Unordered)
    );
    assert_eq!(
        decode_whole::<BTreeSet<u16>>(&[2, 2, 1]),
        Err(DecodeError::Unordered)
    );
    let map = BTreeMap::from([(252u16, 1u8), (253, 2)]);
    assert_eq!(map.consensus_encode(), vec![2, 252, 1, 253, 0, 253, 2]);
    assert_eq!(decode_whole::<Result<u16, u16>>(&[1, 42]), Ok(Ok(42)));
    assert_eq!(decode_whole::<Result<u16, u16>>(&[0, 42]), Ok(Err(42)));
    assert_eq!(
        decode_whole::<Result<u16, u16>>(&[2]),
        Err(DecodeError::InvalidFlag)
    );
    assert_eq!(
        Reader::new(&[255, 255, 255, 255, 255, 255, 255, 255, 255]).sequence(|_| Ok(())),
        Err(DecodeError::NoProgress)
    );
}
#[test]
fn foreign_integer_boundaries() {
    use minimint_ng::codec::boundary::*;
    for (n, b) in [
        (252, vec![252]),
        (253, vec![253, 253, 0]),
        (65536, vec![254, 0, 0, 1, 0]),
        (1u64 << 32, vec![255, 0, 0, 0, 0, 1, 0, 0, 0]),
    ] {
        assert_eq!(compact_size(n), b);
        assert_eq!(read_compact_size(&mut Reader::new(&b)), Ok(n));
    }
    assert_eq!(
        read_compact_size(&mut Reader::new(&[253, 252, 0])),
        Err(DecodeError::NonCanonical)
    );
    assert_eq!(
        read_compact_size(&mut Reader::new(&[254, 0])),
        Err(DecodeError::Truncated)
    );
    for (n, b) in [
        (63, vec![252]),
        (64, vec![1, 1]),
        (16383, vec![253, 255]),
        (16384, vec![2, 0, 1, 0]),
        (1 << 30, vec![3, 0, 0, 0, 64]),
        (u32::MAX, vec![3, 255, 255, 255, 255]),
    ] {
        assert_eq!(scale_length(n), b);
        assert_eq!(read_scale_length(&mut Reader::new(&b)), Ok(n));
    }
    assert_eq!(
        read_scale_length(&mut Reader::new(&[1, 0])),
        Err(DecodeError::NonCanonical)
    );
    assert_eq!(
        read_scale_length(&mut Reader::new(&[7, 0, 0, 0, 0, 1])),
        Err(DecodeError::Overflow)
    );
}
#[test]
fn legacy_priority_and_lengths() {
    use minimint_ng::codec::boundary::*;
    assert_eq!(
        common_first(&[1], |r| r.byte(), |_| panic!("legacy must not run")),
        Ok(1)
    );
    assert_eq!(
        common_first(&[1, 2], |r| r.byte(), |r| r.byte().map(|x| x + 10)),
        Ok(11)
    );
    assert_eq!(
        read_legacy_bytes(&mut Reader::new(&[255; 8])),
        Err(DecodeError::Truncated)
    );
    assert_eq!(legacy_bytes(&[42]), vec![1, 0, 0, 0, 0, 0, 0, 0, 42]);
}
