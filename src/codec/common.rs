use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    NonCanonical,
    Overflow,
    InvalidFlag,
    InvalidUtf8,
    TrailingBytes,
    Unordered,
    NoProgress,
    UnknownVariant,
    UnknownModule,
    InvalidValue,
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated value",
            Self::NonCanonical => "noncanonical integer",
            Self::Overflow => "integer exceeds field width",
            Self::InvalidFlag => "invalid boolean/option flag",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::TrailingBytes => "unconsumed bytes",
            Self::Unordered => "duplicate or descending key",
            Self::NoProgress => "map schema made no decoding progress",
            Self::UnknownVariant => "unknown variant",
            Self::UnknownModule => "unconfigured module instance",
            Self::InvalidValue => "invalid schema value",
        })
    }
}
impl Error for DecodeError {}

/// A finite-buffer decoder. Borrowed frames cannot read past their declared body.
/// Failed reads need not preserve the cursor: discard the containing value.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    input: &'a [u8],
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }
    pub fn remaining(&self) -> usize {
        self.input.len()
    }
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        if count > self.input.len() {
            return Err(DecodeError::Truncated);
        }
        let (value, rest) = self.input.split_at(count);
        self.input = rest;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    pub fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let tag = self.byte()?;
        let (value, minimum) = match tag {
            253 => (u16::from_be_bytes(self.array()?) as u64, 253),
            254 => (u32::from_be_bytes(self.array()?) as u64, 65536),
            255 => (u64::from_be_bytes(self.array()?), 1u64 << 32),
            n => return Ok(n as u64),
        };
        if value < minimum {
            Err(DecodeError::NonCanonical)
        } else {
            Ok(value)
        }
    }
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        self.u64()?.try_into().map_err(|_| DecodeError::Overflow)
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        self.u64()?.try_into().map_err(|_| DecodeError::Overflow)
    }
    pub fn boolean(&mut self) -> Result<bool, DecodeError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidFlag),
        }
    }
    pub fn optional<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        if self.boolean()? {
            decode(self).map(Some)
        } else {
            Ok(None)
        }
    }
    /// Incremental lists; zero-byte element schemas need an explicitly bounded caller.
    pub fn sequence<T>(
        &mut self,
        mut decode: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let count = self.u64()?;
        let mut out = Vec::new();
        for _ in 0..count {
            let before = self.remaining();
            let value = decode(self)?;
            if self.remaining() == before {
                return Err(DecodeError::NoProgress);
            }
            out.push(value);
        }
        Ok(out)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let count = self.u64()?;
        // Check before allocation/conversion. This is a finite-buffer bound,
        // not the spec's separate partial-reader consumption limit.
        if count > self.input.len() as u64 {
            return Err(DecodeError::Truncated);
        }
        self.take(count as usize)
    }
    pub fn string(&mut self) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| DecodeError::InvalidUtf8)
    }
    pub fn variant(&mut self) -> Result<(u64, Self), DecodeError> {
        let tag = self.u64()?;
        Ok((tag, Self::new(self.bytes()?)))
    }
    pub fn module(&mut self) -> Result<(u16, Self), DecodeError> {
        let id = self.u16()?;
        Ok((id, Self::new(self.bytes()?)))
    }
    /// Callbacks select the schema; the key's Ord must be its protocol order.
    /// Do not reserve capacity from an untrusted declared count. For more than
    /// one entry, callbacks must consume bytes: a zero-sized key cannot encode
    /// multiple distinct values. Callers enforce any endpoint work limits.
    pub fn ordered_map<K: Ord, V>(
        &mut self,
        mut key: impl FnMut(&mut Self) -> Result<K, DecodeError>,
        mut value: impl FnMut(&mut Self) -> Result<V, DecodeError>,
    ) -> Result<Vec<(K, V)>, DecodeError> {
        let count = self.u64()?;
        let mut entries: Vec<(K, V)> = Vec::new();
        for _ in 0..count {
            let before = self.remaining();
            let k = key(self)?;
            if entries.last().is_some_and(|(last, _)| last >= &k) {
                return Err(DecodeError::Unordered);
            }
            entries.push((k, value(self)?));
            if count > 1 && self.remaining() == before {
                return Err(DecodeError::NoProgress);
            }
        }
        Ok(entries)
    }
}

pub fn bigsize(value: u64) -> Vec<u8> {
    match value {
        0..=252 => vec![value as u8],
        253..=65535 => [vec![253], (value as u16).to_be_bytes().to_vec()].concat(),
        65536..=4294967295 => [vec![254], (value as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![255], value.to_be_bytes().to_vec()].concat(),
    }
}
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = bigsize(bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}
pub fn encode_string(value: &str) -> Vec<u8> {
    encode_bytes(value.as_bytes())
}
pub fn encode_enum(tag: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = bigsize(tag);
    out.extend(encode_bytes(payload));
    out
}
