use super::*;
use crate::codec::{decode_whole, encode_enum, text};
#[derive(Clone, PartialEq, Eq)]
pub enum InviteRecord {
    Endpoint { url: CanonicalUrl, peer: PeerId },
    FederationId([u8; 32]),
    ApiSecret(String),
    Unknown { tag: u64, payload: Vec<u8> },
}
// Invites can carry access secrets; no derived Debug or Display.
impl ConsensusEncode for InviteRecord {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::Endpoint { url, peer } => encode_enum(
                0,
                &[url.consensus_encode(), peer.consensus_encode()].concat(),
            ),
            Self::FederationId(id) => encode_enum(1, id),
            Self::ApiSecret(s) => encode_enum(2, &s.consensus_encode()),
            Self::Unknown { tag, payload } => encode_enum(*tag, payload),
        }
    }
}
impl ConsensusDecode for InviteRecord {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let value = match tag {
            0 => Self::Endpoint {
                url: CanonicalUrl::consensus_decode(&mut b)?,
                peer: PeerId::consensus_decode(&mut b)?,
            },
            1 => Self::FederationId(b.array()?),
            2 => Self::ApiSecret(b.string()?.to_owned()),
            _ => Self::Unknown {
                tag,
                payload: b.take(b.remaining())?.to_vec(),
            },
        };
        b.finish()?;
        Ok(value)
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    records: Vec<InviteRecord>,
}
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invite([redacted])")
    }
}
impl ConsensusEncode for Invite {
    fn consensus_encode(&self) -> Vec<u8> {
        self.records.consensus_encode()
    }
}
impl ConsensusDecode for Invite {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Self::new(Vec::consensus_decode(r)?).map_err(|_| DecodeError::InvalidValue)
    }
}
impl Invite {
    pub fn new(records: Vec<InviteRecord>) -> Result<Self, ConfigError> {
        if !records
            .iter()
            .any(|r| matches!(r, InviteRecord::Endpoint { .. }))
            || !records
                .iter()
                .any(|r| matches!(r, InviteRecord::FederationId(_)))
        {
            return Err(ConfigError::InvalidInvite);
        }
        Ok(Self { records })
    }
    pub fn records(&self) -> &[InviteRecord] {
        &self.records
    }
    pub fn federation_id(&self) -> [u8; 32] {
        self.records
            .iter()
            .find_map(|r| {
                if let InviteRecord::FederationId(id) = r {
                    Some(*id)
                } else {
                    None
                }
            })
            .expect("constructor requires ID")
    }
    pub fn api_secret(&self) -> Option<&str> {
        self.records.iter().find_map(|r| {
            if let InviteRecord::ApiSecret(s) = r {
                Some(s.as_str())
            } else {
                None
            }
        })
    }
    pub fn endpoints(&self) -> BTreeMap<PeerId, CanonicalUrl> {
        self.records
            .iter()
            .filter_map(|r| {
                if let InviteRecord::Endpoint { url, peer } = r {
                    Some((*peer, url.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn compact(
        endpoints: &BTreeMap<PeerId, Endpoint>,
        id: [u8; 32],
        secret: Option<String>,
    ) -> Result<Self, ConfigError> {
        let f = endpoints.len().saturating_sub(1) / 3;
        let mut records: Vec<_> = endpoints
            .iter()
            .take(f + 1)
            .map(|(peer, endpoint)| InviteRecord::Endpoint {
                url: endpoint.url.clone(),
                peer: *peer,
            })
            .collect();
        records.push(InviteRecord::FederationId(id));
        if let Some(s) = secret {
            records.push(InviteRecord::ApiSecret(s));
        }
        Self::new(records)
    }
    pub fn to_base32(&self) -> String {
        format!("fedimint{}", text::base32_encode(&self.consensus_encode()))
    }
    pub fn to_bech32m(&self) -> String {
        bech32m(&self.consensus_encode())
    }
    pub fn from_text(input: &str) -> Result<Self, ConfigError> {
        if let Some(s) = input.to_ascii_lowercase().strip_prefix("fedimint")
            && let Ok(bytes) = text::base32_decode(s)
            && let Ok(invite) = decode_whole(&bytes)
        {
            return Ok(invite);
        }
        Ok(decode_whole(&decode_bech32(input)?)?)
    }
}
// BIP173/BIP350 checksum and MSB-first groups. Invite encodings are not Bitcoin
// addresses and exceed the address-oriented 90-character limit (CFG-004 fixture).
const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut state = 1u32;
    for value in values {
        let top = state >> 25;
        state = ((state & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (i, g) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            .iter()
            .enumerate()
        {
            if top & (1 << i) != 0 {
                state ^= g;
            }
        }
    }
    state
}
fn hrp() -> Vec<u8> {
    b"fed1"
        .iter()
        .map(|b| b >> 5)
        .chain([0])
        .chain(b"fed1".iter().map(|b| b & 31))
        .collect()
}
fn bech32m(bytes: &[u8]) -> String {
    let mut groups = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for b in bytes {
        acc = ((acc << 8) | u32::from(*b)) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            groups.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        groups.push(((acc << (5 - bits)) & 31) as u8);
    }
    let checksum = polymod(
        hrp()
            .into_iter()
            .chain(groups.iter().copied())
            .chain([0; 6]),
    ) ^ 0x2bc830a3;
    for i in (0..6).rev() {
        groups.push(((checksum >> (i * 5)) & 31) as u8);
    }
    let mut out = String::from("fed11");
    out.extend(groups.into_iter().map(|g| ALPHABET[g as usize] as char));
    out
}
fn decode_bech32(input: &str) -> Result<Vec<u8>, ConfigError> {
    if input.bytes().any(|b| b.is_ascii_lowercase())
        && input.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(ConfigError::Text);
    }
    let lower = input.to_ascii_lowercase();
    let data = lower.strip_prefix("fed11").ok_or(ConfigError::Text)?;
    let groups: Vec<u8> = data
        .bytes()
        .map(|b| {
            ALPHABET
                .iter()
                .position(|c| *c == b)
                .map(|i| i as u8)
                .ok_or(ConfigError::Text)
        })
        .collect::<Result<_, _>>()?;
    if groups.len() < 6
        || !matches!(
            polymod(hrp().into_iter().chain(groups.iter().copied())),
            1 | 0x2bc830a3
        )
    {
        return Err(ConfigError::Text);
    }
    let (mut acc, mut bits) = (0u32, 0);
    let mut out = Vec::new();
    for g in &groups[..groups.len() - 6] {
        acc = ((acc << 5) | u32::from(*g)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || ((acc << (8 - bits)) & 255) != 0 {
        return Err(ConfigError::Text);
    }
    Ok(out)
}
