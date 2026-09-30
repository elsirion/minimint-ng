//! Checked JSON boundary shared by server requests and Bitcoin RPC replies.
//! Limits are local transport policy, not consensus encoding rules.
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    Size,
    Depth,
    Syntax,
    DuplicateField,
    Type,
}
impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include untrusted request bodies, which may contain credentials.
        write!(f, "invalid JSON: {self:?}")
    }
}
impl std::error::Error for JsonError {}

/// Bound parser recursion before allocating a DOM. This counts containers only;
/// all grammar, string escape and UTF-8 validation belongs to the checked parser.
fn depth_limit(bytes: &[u8], maximum: usize) -> Result<(), JsonError> {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth = depth.checked_add(1).ok_or(JsonError::Depth)?;
                    if depth > maximum {
                        return Err(JsonError::Depth);
                    }
                }
                b']' | b'}' => depth = depth.checked_sub(1).ok_or(JsonError::Syntax)?,
                _ => {}
            }
        }
    }
    Ok(())
}

/// Reject ambiguous duplicate names, including names equal after JSON unescaping.
/// Callers still validate their schema before any state transition.
pub fn parse(bytes: &[u8], maximum_bytes: usize, maximum_depth: usize) -> Result<Value, JsonError> {
    if bytes.len() > maximum_bytes {
        return Err(JsonError::Size);
    }
    depth_limit(bytes, maximum_depth)?;
    // The low-level Deserializer does not provide from_slice's outer UTF-8
    // validation. Validate before constructing any DOM strings.
    let text = std::str::from_utf8(bytes).map_err(|_| JsonError::Syntax)?;
    let mut parser = sonic_rs::Deserializer::from_str(text).use_rawnumber();
    let value: Value = parser.deserialize().map_err(|_| JsonError::Syntax)?;
    parser.end().map_err(|_| JsonError::Syntax)?;
    let mut pending = vec![&value];
    while let Some(node) = pending.pop() {
        if let Some(object) = node.as_object() {
            let mut names = BTreeSet::new();
            for (name, child) in object.iter() {
                if !names.insert(name) {
                    return Err(JsonError::DuplicateField);
                }
                pending.push(child);
            }
        } else if let Some(array) = node.as_array() {
            pending.extend(array.iter());
        }
    }
    Ok(value)
}

/// Requires an unsigned integer lexeme: decimal points, signs and exponents are
/// rejected even when the mathematical value would be an integer.
pub fn unsigned(value: &Value) -> Result<u64, JsonError> {
    let text = number_text(value)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(JsonError::Type);
    }
    text.parse().map_err(|_| JsonError::Type)
}

// Serialization of raw-number Values preserves their exact original lexeme.
// Do not access ValueRef::Number or any float accessor along this conversion.
fn number_text(value: &Value) -> Result<String, JsonError> {
    if !value.is_number() {
        return Err(JsonError::Type);
    }
    sonic_rs::to_string(value).map_err(|_| JsonError::Type)
}

/// Multiplies an exact nonnegative JSON number by 10^decimal_places. The result
/// must be an integral u64; no truncation or rounding is allowed. Use 8 for
/// BTC/kvB to sat/kvB. Numeric values from `parse` retain their original lexeme;
/// callers must not construct the value through a floating-point conversion.
/// A leading minus (including negative zero) is rejected.
pub fn scaled_unsigned(value: &Value, decimal_places: u32) -> Result<u64, JsonError> {
    let text = number_text(value)?;
    if text.starts_with('-') {
        return Err(JsonError::Type);
    }
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((&text, "0"));
    let fractional = mantissa.split_once('.').map_or(0, |(_, tail)| tail.len());
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(JsonError::Type);
    }
    let significant = digits.trim_start_matches('0');
    // Zero stays exact even for an exponent larger than any machine integer.
    if significant.is_empty() {
        return Ok(0);
    }
    let trimmed = significant.trim_end_matches('0');
    let trailing = significant.len() - trimmed.len();
    let exponent: i128 = exponent.parse().map_err(|_| JsonError::Type)?;
    let power = exponent
        .checked_add(i128::from(decimal_places))
        .and_then(|p| p.checked_sub(fractional as i128))
        .and_then(|p| p.checked_add(trailing as i128))
        .ok_or(JsonError::Type)?;
    // Removing all trailing zeroes makes a negative power necessarily fractional.
    // Positive powers >=20 overflow any nonzero u64, so no huge exponent loop.
    if !(0..=19).contains(&power) || trimmed.len() > 20 {
        return Err(JsonError::Type);
    }
    let coefficient: u64 = trimmed.parse().map_err(|_| JsonError::Type)?;
    coefficient
        .checked_mul(10u64.pow(power as u32))
        .ok_or(JsonError::Type)
}

pub fn encode(value: &Value) -> Result<Vec<u8>, JsonError> {
    sonic_rs::to_vec(value).map_err(|_| JsonError::Type)
}

/// Stop serialization before growing an output buffer beyond its transport cap.
pub fn encode_bounded(value: &Value, maximum_bytes: usize) -> Result<Vec<u8>, JsonError> {
    // Preflight the compact JSON length before entering a writer adapter that
    // may reserve scratch space for an entire string. The final sink checks the
    // actual encoded length too, so a serializer change cannot bypass the cap.
    fn string_length(text: &str) -> Option<usize> {
        text.bytes().try_fold(2usize, |n, b| {
            n.checked_add(match b {
                b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
                0..=31 => 6,
                _ => 1,
            })
        })
    }
    let mut total = 0usize;
    let mut pending = vec![value];
    while let Some(node) = pending.pop() {
        let remaining = maximum_bytes.saturating_sub(total);
        let count = if let Some(object) = node.as_object() {
            let mut n = 2usize
                .checked_add(object.len().saturating_sub(1))
                .ok_or(JsonError::Size)?;
            // Each member needs at least an empty quoted key, colon, and a
            // one-byte value. Reject before collecting references to its values.
            let minimum = object
                .len()
                .checked_mul(4)
                .and_then(|members| n.checked_add(members))
                .ok_or(JsonError::Size)?;
            if minimum > remaining {
                return Err(JsonError::Size);
            }
            for (key, _) in object.iter() {
                n = n
                    .checked_add(string_length(key).ok_or(JsonError::Size)?)
                    .and_then(|n| n.checked_add(1))
                    .ok_or(JsonError::Size)?;
                if n.checked_add(object.len())
                    .is_none_or(|minimum| minimum > remaining)
                {
                    return Err(JsonError::Size);
                }
            }
            pending.extend(object.iter().map(|(_, value)| value));
            n
        } else if let Some(array) = node.as_array() {
            let n = 2usize
                .checked_add(array.len().saturating_sub(1))
                .ok_or(JsonError::Size)?;
            if n.checked_add(array.len())
                .is_none_or(|minimum| minimum > remaining)
            {
                return Err(JsonError::Size);
            }
            pending.extend(array.iter());
            n
        } else if let Some(text) = node.as_str() {
            string_length(text).ok_or(JsonError::Size)?
        } else if node.is_null() {
            4
        } else if let Some(b) = node.as_bool() {
            if b { 4 } else { 5 }
        } else if let Some(number) = node.as_raw_number() {
            // Public JsonValueTrait accessor preserves the exact lexeme. Sonic
            // may copy DOM-backed raw numbers into this owned RawNumber, so
            // this is an output-byte cap, not a total-allocation/RSS guarantee.
            number.as_str().len()
        } else {
            // Native machine numbers have bounded-size textual representations.
            number_text(node)?.len()
        };
        total = total
            .checked_add(count)
            .filter(|n| *n <= maximum_bytes)
            .ok_or(JsonError::Size)?;
    }
    struct Output {
        bytes: Vec<u8>,
        maximum: usize,
        exceeded: bool,
    }
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(std::io::Error::other("JSON output limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Output {
        bytes: Vec::new(),
        maximum: maximum_bytes,
        exceeded: false,
    };
    let result = {
        // Public checked adapter for an ordinary std::io::Write sink.
        let mut buffered = sonic_rs::writer::BufferedWriter::new(&mut out);
        let result = sonic_rs::to_writer(&mut buffered, value);
        let flushed = std::io::Write::flush(&mut buffered);
        result
            .map_err(|_| JsonError::Type)
            .and_then(|_| flushed.map_err(|_| JsonError::Type))
    };
    if out.exceeded {
        return Err(JsonError::Size);
    }
    result.map_err(|_| JsonError::Type)?;
    Ok(out.bytes)
}
