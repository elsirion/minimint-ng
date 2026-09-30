use super::{DecodeError, Reader, bigsize};
use std::collections::{BTreeMap, BTreeSet};

pub trait ConsensusEncode {
    fn consensus_encode(&self) -> Vec<u8>;
}
pub trait ConsensusDecode: Sized {
    fn consensus_decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError>;
}
pub fn decode_whole<T: ConsensusDecode>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut reader = Reader::new(bytes);
    let value = T::consensus_decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
}
macro_rules! integer {
    ($t:ty, $method:ident) => {
        impl ConsensusEncode for $t {
            fn consensus_encode(&self) -> Vec<u8> {
                bigsize(u64::from(*self))
            }
        }
        impl ConsensusDecode for $t {
            fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.$method()
            }
        }
    };
}
integer!(u16, u16);
integer!(u32, u32);
integer!(u64, u64);
impl ConsensusEncode for u8 {
    fn consensus_encode(&self) -> Vec<u8> {
        vec![*self]
    }
}
impl ConsensusDecode for u8 {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.byte()
    }
}
impl ConsensusEncode for bool {
    fn consensus_encode(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }
}
impl ConsensusDecode for bool {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.boolean()
    }
}
impl<const N: usize> ConsensusEncode for [u8; N] {
    fn consensus_encode(&self) -> Vec<u8> {
        self.to_vec()
    }
}
impl<const N: usize> ConsensusDecode for [u8; N] {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array()
    }
}
impl ConsensusEncode for str {
    fn consensus_encode(&self) -> Vec<u8> {
        super::encode_string(self)
    }
}
impl ConsensusEncode for String {
    fn consensus_encode(&self) -> Vec<u8> {
        self.as_str().consensus_encode()
    }
}
impl ConsensusDecode for String {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(r.string()?.to_owned())
    }
}
impl<T: ConsensusEncode> ConsensusEncode for [T] {
    fn consensus_encode(&self) -> Vec<u8> {
        let mut out = bigsize(self.len() as u64);
        for value in self {
            out.extend(value.consensus_encode());
        }
        out
    }
}
impl<T: ConsensusEncode> ConsensusEncode for Vec<T> {
    fn consensus_encode(&self) -> Vec<u8> {
        self.as_slice().consensus_encode()
    }
}
impl<T: ConsensusDecode> ConsensusDecode for Vec<T> {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.sequence(T::consensus_decode)
    }
}
impl<T: ConsensusEncode> ConsensusEncode for Option<T> {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            None => vec![0],
            Some(v) => [vec![1], v.consensus_encode()].concat(),
        }
    }
}
impl<T: ConsensusDecode> ConsensusDecode for Option<T> {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.optional(T::consensus_decode)
    }
}
impl<T: ConsensusEncode, E: ConsensusEncode> ConsensusEncode for Result<T, E> {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Ok(v) => [vec![1], v.consensus_encode()].concat(),
            Err(e) => [vec![0], e.consensus_encode()].concat(),
        }
    }
}
impl<T: ConsensusDecode, E: ConsensusDecode> ConsensusDecode for Result<T, E> {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        if r.boolean()? {
            Ok(Ok(T::consensus_decode(r)?))
        } else {
            Ok(Err(E::consensus_decode(r)?))
        }
    }
}
impl<K: Ord + ConsensusEncode, V: ConsensusEncode> ConsensusEncode for BTreeMap<K, V> {
    fn consensus_encode(&self) -> Vec<u8> {
        let mut out = bigsize(self.len() as u64);
        for (k, v) in self {
            out.extend(k.consensus_encode());
            out.extend(v.consensus_encode());
        }
        out
    }
}
impl<K: Ord + ConsensusDecode, V: ConsensusDecode> ConsensusDecode for BTreeMap<K, V> {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(r.ordered_map(K::consensus_decode, V::consensus_decode)?
            .into_iter()
            .collect())
    }
}
impl<T: Ord + ConsensusEncode> ConsensusEncode for BTreeSet<T> {
    fn consensus_encode(&self) -> Vec<u8> {
        let mut out = bigsize(self.len() as u64);
        for v in self {
            out.extend(v.consensus_encode());
        }
        out
    }
}
impl<T: Ord + ConsensusDecode> ConsensusDecode for BTreeSet<T> {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(r.ordered_map(T::consensus_decode, |_| Ok(()))?
            .into_iter()
            .map(|(k, ())| k)
            .collect())
    }
}
