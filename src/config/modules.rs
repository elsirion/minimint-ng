use super::*;
use crate::codec::encode_enum;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fee {
    pub base: u64,
    pub parts_per_million: u64,
}
record!(Fee, base, parts_per_million);
impl Fee {
    pub fn mint(base: u64, parts_per_million: u64) -> Result<Self, ConfigError> {
        Self::with_limit(base, parts_per_million, 1_000)
    }
    pub fn wallet(base: u64, parts_per_million: u64) -> Result<Self, ConfigError> {
        Self::with_limit(base, parts_per_million, 10_000)
    }
    fn with_limit(base: u64, parts_per_million: u64, limit: u64) -> Result<Self, ConfigError> {
        if parts_per_million > limit {
            return Err(ConfigError::InvalidProfile);
        }
        Ok(Self {
            base,
            parts_per_million,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMintConfig {
    pub aggregate_keys: BTreeMap<u8, [u8; 96]>,
    pub public_shares: BTreeMap<u8, BTreeMap<PeerId, [u8; 96]>>,
    pub fee: Fee,
    pub amount_unit: u64,
}
record!(
    RawMintConfig,
    aggregate_keys,
    public_shares,
    fee,
    amount_unit
);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorKind {
    Wsh,
}
impl ConsensusEncode for DescriptorKind {
    fn consensus_encode(&self) -> Vec<u8> {
        encode_enum(0, &[])
    }
}
impl ConsensusDecode for DescriptorKind {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, b) = r.variant()?;
        if tag != 0 {
            return Err(DecodeError::UnknownVariant);
        }
        b.finish()?;
        Ok(Self::Wsh)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWalletConfig {
    pub bitcoin_pks: BTreeMap<PeerId, [u8; 33]>,
    pub descriptor: DescriptorKind,
    pub send_tx_vbytes: u64,
    pub receive_tx_vbytes: u64,
    pub feerate_base: u64,
    pub dust_limit: u64,
    pub fee_consensus: Fee,
    pub network: BitcoinNetwork,
}
record!(
    RawWalletConfig,
    bitcoin_pks,
    descriptor,
    send_tx_vbytes,
    receive_tx_vbytes,
    feerate_base,
    dust_limit,
    fee_consensus,
    network
);
/// Ordinary generated descriptor sizes for Bitcoin's supported <=20-key multisig.
pub fn wallet_vbytes(n: u16) -> Result<(u64, u64), ConfigError> {
    if n == 0 || n > 20 {
        return Err(ConfigError::InvalidProfile);
    }
    let n = u64::from(n);
    let q = n - (n - 1) / 3;
    let push = |x: u64| if x <= 16 { 1 } else { 2 };
    let compact = |x: u64| crate::codec::boundary::compact_size(x).len() as u64;
    let script = push(q) + 34 * n + push(n) + 1;
    let witness = compact(q + 2) - compact(0) + compact(script) + script + 1 + 73 * q;
    Ok((
        (42 + 164 + witness + 2 * 172).div_ceil(4),
        (42 + 2 * (164 + witness) + 172).div_ceil(4),
    ))
}

impl RawMintConfig {
    /// Public shape/point checks only, not local scalar-share validation or a
    /// reconstruction of aggregate keys from the share map (MINT-012).
    pub fn check_public_points(&self) -> Result<(), ConfigError> {
        if self.amount_unit != 0 {
            return Err(ConfigError::InvalidProfile);
        }
        for key in self.aggregate_keys.values().chain(
            self.public_shares
                .values()
                .flat_map(|shares| shares.values()),
        ) {
            crate::crypto::bls::G2::from_bytes(key).map_err(|_| ConfigError::InvalidProfile)?;
        }
        Ok(())
    }
}
impl RawWalletConfig {
    /// Defaults are generation choices, not extra fee/size admission predicates.
    pub fn check_public_keys(&self) -> Result<(), ConfigError> {
        for key in self.bitcoin_pks.values() {
            crate::crypto::secp::validate_public_key(key)
                .map_err(|_| ConfigError::InvalidProfile)?;
        }
        Ok(())
    }
}
impl RawServerConfig {
    /// Closed daemon profile check, before local private-share and transport
    /// identity checks can construct a fully validated runtime configuration.
    pub fn check_two_module_profile(&self) -> Result<(), ConfigError> {
        if self.consensus_version != CORE_CONSENSUS
            || self.code_release != normalize_release(&self.code_release)
            || self.code_release != "0.13.0"
            || self.modules.len() != 2
            || !self.iroh_endpoints.is_empty()
        {
            return Err(ConfigError::InvalidProfile);
        }
        if self.api_endpoints.len() != 4
            || self.api_endpoints.keys().copied().ne((0..4).map(PeerId))
            || self
                .api_endpoints
                .keys()
                .ne(self.broadcast_public_keys.keys())
            || self.api_endpoints.keys().ne(self.tls_certificates.keys())
        {
            return Err(ConfigError::InvalidProfile);
        }
        for key in self.broadcast_public_keys.values() {
            crate::crypto::secp::validate_public_key(key)
                .map_err(|_| ConfigError::InvalidProfile)?;
        }
        for certificate in self.tls_certificates.values() {
            let bytes = crate::codec::text::hex_decode(certificate)
                .map_err(|_| ConfigError::InvalidProfile)?;
            if bytes.is_empty() || crate::codec::text::hex_encode(&bytes) != *certificate {
                return Err(ConfigError::InvalidProfile);
            }
        }
        let (mut mint, mut wallet) = (false, false);
        for module in self.modules.values() {
            if module.version != MODULE_CONSENSUS {
                return Err(ConfigError::InvalidProfile);
            }
            match module.kind.as_str() {
                "mintv2" if !mint => {
                    let config: RawMintConfig = crate::codec::decode_whole(&module.config)?;
                    config.check_public_points()?;
                    mint = true;
                }
                "walletv2" if !wallet => {
                    let config: RawWalletConfig = crate::codec::decode_whole(&module.config)?;
                    config.check_public_keys()?;
                    wallet = true;
                }
                _ => return Err(ConfigError::InvalidProfile),
            }
        }
        if !mint || !wallet {
            return Err(ConfigError::InvalidProfile);
        }
        Ok(())
    }
}
