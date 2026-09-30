//! Dependency-free text representations over finite input buffers.
//!
//! Custom base32 follows ENC-011 / MINT-009, including discarded trailing
//! bits. Prefix-aware callers must lowercase the entire text before removing
//! their prefix; the unprefixed decoder here accepts only the lowercase alphabet.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextError {
    InvalidLength,
    InvalidCharacter { byte_index: usize },
    NonzeroPaddingBits,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid encoded text length"),
            Self::InvalidCharacter { byte_index } => {
                write!(f, "invalid encoded character at byte {byte_index}")
            }
            Self::NonzeroPaddingBits => f.write_str("nonzero base64url padding bits"),
        }
    }
}

impl std::error::Error for TextError {}

const HEX: &[u8; 16] = b"0123456789abcdef";
const BASE32: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn hex_encode(input: &[u8]) -> String {
    let mut output = String::new();
    for &byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

pub fn hex_decode(input: &str) -> Result<Vec<u8>, TextError> {
    if !input.len().is_multiple_of(2) {
        return Err(TextError::InvalidLength);
    }
    let mut output = Vec::new();
    let mut high = 0;
    for (byte_index, byte) in input.bytes().enumerate() {
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(TextError::InvalidCharacter { byte_index }),
        };
        if byte_index % 2 == 0 {
            high = value << 4;
        } else {
            output.push(high | value);
        }
    }
    Ok(output)
}

/// Encodes custom base32hex with the least-significant bits first.
pub fn base32_encode(input: &[u8]) -> String {
    let mut output = String::new();
    let mut accumulator = 0u16;
    let mut bits = 0;
    for &byte in input {
        accumulator |= u16::from(byte) << bits;
        bits += 8;
        while bits >= 5 {
            output.push(char::from(BASE32[usize::from(accumulator & 31)]));
            accumulator >>= 5;
            bits -= 5;
        }
    }
    if bits != 0 {
        output.push(char::from(BASE32[usize::from(accumulator)]));
    }
    output
}

/// Decodes lowercase custom base32 and discards leftover sub-byte bits,
/// including nonzero bits. Prefix normalization belongs to the caller.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, TextError> {
    let mut output = Vec::new();
    let mut accumulator = 0u16;
    let mut bits = 0;
    for (byte_index, byte) in input.bytes().enumerate() {
        let value = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'v' => byte - b'a' + 10,
            _ => return Err(TextError::InvalidCharacter { byte_index }),
        };
        accumulator |= u16::from(value) << bits;
        bits += 5;
        if bits >= 8 {
            output.push(accumulator as u8);
            accumulator >>= 8;
            bits -= 8;
        }
    }
    Ok(output)
}

/// Encodes conventional URL-safe base64 without `=` padding.
pub fn base64url_encode(input: &[u8]) -> String {
    let mut output = String::new();
    let mut accumulator = 0u16;
    let mut bits = 0;
    for &byte in input {
        accumulator = (accumulator << 8) | u16::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            output.push(char::from(
                BASE64URL[usize::from((accumulator >> bits) & 63)],
            ));
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits != 0 {
        output.push(char::from(
            BASE64URL[usize::from(accumulator << (6 - bits))],
        ));
    }
    output
}

/// Decodes canonical URL-safe base64 without padding. Rejects impossible
/// lengths and nonzero trailing padding bits, unlike custom base32.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, TextError> {
    if input.len() % 4 == 1 {
        return Err(TextError::InvalidLength);
    }
    let mut output = Vec::new();
    let mut accumulator = 0u16;
    let mut bits = 0;
    for (byte_index, byte) in input.bytes().enumerate() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(TextError::InvalidCharacter { byte_index }),
        };
        accumulator = (accumulator << 6) | u16::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
        accumulator &= (1 << bits) - 1;
    }
    if accumulator != 0 {
        return Err(TextError::NonzeroPaddingBits);
    }
    Ok(output)
}
