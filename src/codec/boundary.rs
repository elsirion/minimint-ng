//! Small primitives for foreign formats. These are not consensus BigSize.
use super::{DecodeError, Reader};

pub fn compact_size(value: u64) -> Vec<u8> {
    match value {
        0..=252 => vec![value as u8],
        253..=65535 => [vec![253], (value as u16).to_le_bytes().to_vec()].concat(),
        65536..=4294967295 => [vec![254], (value as u32).to_le_bytes().to_vec()].concat(),
        _ => [vec![255], value.to_le_bytes().to_vec()].concat(),
    }
}
pub fn read_compact_size(r: &mut Reader<'_>) -> Result<u64, DecodeError> {
    let (value, min) = match r.byte()? {
        253 => (u16::from_le_bytes(r.array()?) as u64, 253),
        254 => (u32::from_le_bytes(r.array()?) as u64, 65536),
        255 => (u64::from_le_bytes(r.array()?), 1u64 << 32),
        n => return Ok(n as u64),
    };
    if value < min {
        Err(DecodeError::NonCanonical)
    } else {
        Ok(value)
    }
}
/// SCALE list lengths are bounded to u32 in the guardian protocol.
pub fn scale_length(value: u32) -> Vec<u8> {
    match value {
        0..=63 => vec![(value as u8) << 2],
        64..=16383 => (((value as u16) << 2) | 1).to_le_bytes().to_vec(),
        16384..=1073741823 => ((value << 2) | 2).to_le_bytes().to_vec(),
        _ => [vec![3], value.to_le_bytes().to_vec()].concat(),
    }
}
pub fn read_scale_length(r: &mut Reader<'_>) -> Result<u32, DecodeError> {
    let first = r.byte()?;
    let (value, min) = match first & 3 {
        0 => return Ok(u32::from(first >> 2)),
        1 => (u32::from(u16::from_le_bytes([first, r.byte()?]) >> 2), 64),
        2 => {
            let rest = r.array::<3>()?;
            (
                u32::from_le_bytes([first, rest[0], rest[1], rest[2]]) >> 2,
                16384,
            )
        }
        _ => {
            if first != 3 {
                return Err(DecodeError::Overflow);
            }
            (u32::from_le_bytes(r.array()?), 1 << 30)
        }
    };
    if value < min {
        Err(DecodeError::NonCanonical)
    } else {
        Ok(value)
    }
}
pub fn legacy_bytes(bytes: &[u8]) -> Vec<u8> {
    [(bytes.len() as u64).to_le_bytes().to_vec(), bytes.to_vec()].concat()
}
pub fn read_legacy_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    let count = u64::from_le_bytes(r.array()?);
    if count > r.remaining() as u64 {
        return Err(DecodeError::Truncated);
    }
    r.take(count as usize)
}
/// NET-003 common decoding gets whole-frame priority. Legacy may leave a suffix.
pub fn common_first<T>(
    bytes: &[u8],
    common: impl FnOnce(&mut Reader<'_>) -> Result<T, DecodeError>,
    legacy: impl FnOnce(&mut Reader<'_>) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(bytes);
    if let Ok(value) = common(&mut r)
        && r.finish().is_ok()
    {
        return Ok(value);
    }
    legacy(&mut Reader::new(bytes))
}
