use super::*;
use crate::codec::{decode_whole, encode_enum, text};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}
impl BitcoinNetwork {
    pub fn magic(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Self::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Self::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Self::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Self::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }
}
impl ConsensusEncode for BitcoinNetwork {
    fn consensus_encode(&self) -> Vec<u8> {
        self.magic().to_vec()
    }
}
impl ConsensusDecode for BitcoinNetwork {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let bytes = r.array::<4>()?;
        [
            Self::Mainnet,
            Self::Testnet3,
            Self::Testnet4,
            Self::Signet,
            Self::Regtest,
        ]
        .into_iter()
        .find(|n| n.magic() == bytes)
        .ok_or(DecodeError::InvalidValue)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SetupEndpoints {
    Tcp {
        api_url: CanonicalUrl,
        p2p_url: CanonicalUrl,
        certificate: Vec<u8>,
    },
    Iroh {
        api_key: [u8; 32],
        p2p_key: [u8; 32],
    },
}
impl ConsensusEncode for SetupEndpoints {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::Tcp {
                api_url,
                p2p_url,
                certificate,
            } => encode_enum(
                0,
                &[
                    api_url.consensus_encode(),
                    p2p_url.consensus_encode(),
                    certificate.consensus_encode(),
                ]
                .concat(),
            ),
            Self::Iroh { api_key, p2p_key } => {
                encode_enum(1, &[api_key.to_vec(), p2p_key.to_vec()].concat())
            }
        }
    }
}
impl ConsensusDecode for SetupEndpoints {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let value = match tag {
            0 => Self::Tcp {
                api_url: CanonicalUrl::consensus_decode(&mut b)?,
                p2p_url: CanonicalUrl::consensus_decode(&mut b)?,
                certificate: Vec::consensus_decode(&mut b)?,
            },
            1 => Self::Iroh {
                api_key: b.array()?,
                p2p_key: b.array()?,
            },
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SetupRecord {
    pub name: String,
    pub endpoints: SetupEndpoints,
    pub federation_name: Option<String>,
    pub disable_base_fees: Option<bool>,
    pub enabled_modules: Option<BTreeSet<String>>,
    pub federation_size: Option<u32>,
    pub network: BitcoinNetwork,
    pub release: String,
}
record!(
    SetupRecord,
    name,
    endpoints,
    federation_name,
    disable_base_fees,
    enabled_modules,
    federation_size,
    network,
    release
);
impl SetupRecord {
    pub fn to_code(&self) -> String {
        format!("fedimint{}", text::base32_encode(&self.consensus_encode()))
    }
    pub fn from_code(code: &str) -> Result<Self, ConfigError> {
        let lower = code.to_ascii_lowercase();
        let body = lower.strip_prefix("fedimint").ok_or(ConfigError::Text)?;
        Ok(decode_whole(
            &text::base32_decode(body).map_err(|_| ConfigError::Text)?,
        )?)
    }
    pub fn validate_local_parameters(&self) -> Result<(), ConfigError> {
        if self.name.is_empty()
            || self.federation_name.as_ref().is_some_and(String::is_empty)
            || self.federation_name.is_some() && self.federation_size.is_none()
            || self.federation_size.is_some_and(|n| n != 1 && n < 4)
        {
            return Err(ConfigError::InvalidSetup);
        }
        Ok(())
    }
    pub fn compatible_peer(&self, other: &Self) -> bool {
        self.network == other.network
            && normalize_release(&self.release) == normalize_release(&other.release)
            && std::mem::discriminant(&self.endpoints) == std::mem::discriminant(&other.endpoints)
    }
}
/// Assigns IDs by typed field order, not encoded bytes or textual setup codes.
/// Driver is responsible for local-code exclusion and repeated-code idempotence.
pub fn assign_peer_ids(
    records: impl IntoIterator<Item = SetupRecord>,
) -> Result<BTreeMap<PeerId, SetupRecord>, ConfigError> {
    let mut sorted: Vec<_> = records.into_iter().collect();
    sorted.sort();
    if sorted.len() > u16::MAX as usize + 1 || sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(ConfigError::InvalidSetup);
    }
    Ok(sorted
        .into_iter()
        .enumerate()
        .map(|(i, r)| (PeerId(i as u16), r))
        .collect())
}
/// SET-005 commits the record map (setup-code newtype E), not base32 display text.
pub fn setup_checksum(records: &BTreeMap<PeerId, SetupRecord>) -> [u8; 32] {
    sha256(&records.consensus_encode())
}

/// Pure SET-003/004 checks once the driver has collected the local and peer codes.
/// Local parameter creation and repeated-add idempotence remain driver operations.
pub fn validate_setup_set(records: &BTreeMap<PeerId, SetupRecord>) -> Result<(), ConfigError> {
    let n = records.len();
    if n != 1 && n < 4 {
        return Err(ConfigError::InvalidSetup);
    }
    let first = records.values().next().ok_or(ConfigError::InvalidSetup)?;
    if records
        .values()
        .zip(records.values().skip(1))
        .any(|(a, b)| a >= b)
    {
        return Err(ConfigError::InvalidSetup);
    }
    let (mut names, mut fees, mut modules, mut sizes) = (0, 0, 0, 0);
    for (expected, (peer, record)) in records.iter().enumerate() {
        if usize::from(peer.0) != expected || !first.compatible_peer(record) {
            return Err(ConfigError::InvalidSetup);
        }
        names += usize::from(record.federation_name.is_some());
        fees += usize::from(record.disable_base_fees.is_some());
        modules += usize::from(record.enabled_modules.is_some());
        sizes += usize::from(record.federation_size.is_some());
        if record
            .federation_size
            .is_some_and(|size| size as usize != n)
        {
            return Err(ConfigError::InvalidSetup);
        }
    }
    if names != 1 || fees > 1 || modules > 1 || sizes > 1 {
        return Err(ConfigError::InvalidSetup);
    }
    Ok(())
}
