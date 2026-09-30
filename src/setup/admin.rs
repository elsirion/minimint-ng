//! Typed setup administration; API authentication and JSON belong to API layer.
use crate::{
    config::{self, BitcoinNetwork, CanonicalUrl, SetupEndpoints, SetupRecord},
    net::{TransportIdentity, iroh::IrohIdentity, tls::Identity},
    protocol::PeerId,
};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalParams {
    pub name: String,
    pub federation_name: Option<String>,
    pub disable_base_fees: Option<bool>,
    pub enabled_modules: Option<BTreeSet<String>>,
    pub federation_size: Option<u32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    MissingLocalParams,
    ParametersAlreadySet,
    InvalidParameters,
    RestoreInProgress,
    InvalidPeerCode,
    LocalCode,
    IncompatiblePeer,
    DuplicateOptionalField,
    InvalidGeneration,
    TransportIdentity,
}
impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingLocalParams => "local setup parameters required",
            Self::ParametersAlreadySet => "local setup parameters already set",
            Self::InvalidParameters => "invalid local setup parameters",
            Self::RestoreInProgress => "guardian restore in progress",
            Self::InvalidPeerCode => "invalid peer setup code",
            Self::LocalCode => "cannot add local setup code",
            Self::IncompatiblePeer => "incompatible peer setup code",
            Self::DuplicateOptionalField => "setup option supplied by more than one guardian",
            Self::InvalidGeneration => "invalid federation setup parameters",
            Self::TransportIdentity => "transport identity generation failed",
        })
    }
}
impl std::error::Error for AdminError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStatus {
    AwaitingLocalParams,
    SharingConnectionCodes,
}
impl SetupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingLocalParams => "AwaitingLocalParams",
            Self::SharingConnectionCodes => "SharingConnectionCodes",
        }
    }
}
pub struct GenerationInputs {
    pub peer: PeerId,
    pub records: std::collections::BTreeMap<PeerId, SetupRecord>,
}
/// Transport of the local setup code. An optional Iroh preset lets an operator
/// supply the endpoint secrets (e.g. to pre-share direct addresses); otherwise
/// they are generated when local parameters are first set.
enum SetupTransportKind {
    Tcp {
        api_url: CanonicalUrl,
        p2p_url: CanonicalUrl,
    },
    Iroh {
        preset: Option<IrohIdentity>,
    },
}
pub struct SetupState {
    transport: SetupTransportKind,
    network: BitcoinNetwork,
    release: String,
    params: Option<LocalParams>,
    local: Option<SetupRecord>,
    identity: Option<TransportIdentity>,
    peers: BTreeSet<SetupRecord>,
    restoring: bool,
}
impl SetupState {
    /// TCP profile: the setup code carries both advertised URLs and a TLS certificate.
    pub fn new(
        api_url: CanonicalUrl,
        p2p_url: CanonicalUrl,
        network: BitcoinNetwork,
        release: String,
    ) -> Self {
        Self::with_transport(
            SetupTransportKind::Tcp { api_url, p2p_url },
            network,
            release,
        )
    }
    /// Iroh profile: the setup code carries the API and P2P endpoint public keys
    /// (endpoint variant 1). No URL is advertised.
    pub fn new_iroh(
        network: BitcoinNetwork,
        release: String,
        preset: Option<IrohIdentity>,
    ) -> Self {
        Self::with_transport(SetupTransportKind::Iroh { preset }, network, release)
    }
    fn with_transport(
        transport: SetupTransportKind,
        network: BitcoinNetwork,
        release: String,
    ) -> Self {
        Self {
            transport,
            network,
            release,
            params: None,
            local: None,
            identity: None,
            peers: BTreeSet::new(),
            restoring: false,
        }
    }
    pub fn status(&self) -> SetupStatus {
        if self.local.is_some() {
            SetupStatus::SharingConnectionCodes
        } else {
            SetupStatus::AwaitingLocalParams
        }
    }
    pub fn get_setup_code(&self) -> Option<String> {
        self.local.as_ref().map(SetupRecord::to_code)
    }
    pub fn identity(&self) -> Option<&TransportIdentity> {
        self.identity.as_ref()
    }
    /// Restore archive handling is outside the daemon profile. This flag only
    /// lets an operator-local owner enforce SET-002/003's exclusion if supplied.
    pub fn set_restore_in_progress(&mut self, value: bool) {
        self.restoring = value;
    }
    pub fn set_local_params(&mut self, params: LocalParams) -> Result<String, AdminError> {
        if self.restoring {
            return Err(AdminError::RestoreInProgress);
        }
        if let Some(existing) = &self.params {
            if existing == &params {
                return self.get_setup_code().ok_or(AdminError::MissingLocalParams);
            }
            return Err(AdminError::ParametersAlreadySet);
        }
        let mut record = SetupRecord {
            name: params.name.clone(),
            endpoints: match &self.transport {
                SetupTransportKind::Tcp { api_url, p2p_url } => SetupEndpoints::Tcp {
                    api_url: api_url.clone(),
                    p2p_url: p2p_url.clone(),
                    certificate: Vec::new(),
                },
                SetupTransportKind::Iroh { .. } => SetupEndpoints::Iroh {
                    api_key: [0; 32],
                    p2p_key: [0; 32],
                },
            },
            federation_name: params.federation_name.clone(),
            disable_base_fees: params.disable_base_fees,
            enabled_modules: params.enabled_modules.clone(),
            federation_size: params.federation_size,
            network: self.network,
            release: self.release.clone(),
        };
        record
            .validate_local_parameters()
            .map_err(|_| AdminError::InvalidParameters)?;
        let identity: TransportIdentity = match &self.transport {
            SetupTransportKind::Tcp { .. } => Identity::generate(&params.name)
                .map_err(|_| AdminError::TransportIdentity)?
                .into(),
            SetupTransportKind::Iroh {
                preset: Some(preset),
            } => preset.clone().into(),
            SetupTransportKind::Iroh { preset: None } => IrohIdentity::generate()
                .map_err(|_| AdminError::TransportIdentity)?
                .into(),
        };
        match (&mut record.endpoints, &identity) {
            (SetupEndpoints::Tcp { certificate, .. }, TransportIdentity::Tls(tls)) => {
                *certificate = tls
                    .certificate_der()
                    .map_err(|_| AdminError::TransportIdentity)?;
            }
            (SetupEndpoints::Iroh { api_key, p2p_key }, TransportIdentity::Iroh(iroh)) => {
                *api_key = iroh.api_public();
                *p2p_key = iroh.p2p_public();
            }
            _ => return Err(AdminError::TransportIdentity),
        }
        let code = record.to_code();
        self.params = Some(params);
        self.local = Some(record);
        self.identity = Some(identity);
        Ok(code)
    }
    pub fn add_peer_setup_code(&mut self, code: &str) -> Result<String, AdminError> {
        let record = SetupRecord::from_code(code).map_err(|_| AdminError::InvalidPeerCode)?;
        if self.peers.contains(&record) {
            return Ok(record.name);
        }
        if self.restoring {
            return Err(AdminError::RestoreInProgress);
        }
        let local = self.local.as_ref().ok_or(AdminError::MissingLocalParams)?;
        if local == &record {
            return Err(AdminError::LocalCode);
        }
        if !local.compatible_peer(&record) {
            return Err(AdminError::IncompatiblePeer);
        }
        for previous in std::iter::once(local).chain(self.peers.iter()) {
            if previous.federation_name.is_some() && record.federation_name.is_some()
                || previous.disable_base_fees.is_some() && record.disable_base_fees.is_some()
                || previous.enabled_modules.is_some() && record.enabled_modules.is_some()
                || previous.federation_size.is_some() && record.federation_size.is_some()
            {
                return Err(AdminError::DuplicateOptionalField);
            }
        }
        let name = record.name.clone();
        self.peers.insert(record);
        Ok(name)
    }
    pub fn reset_peer_setup_codes(&mut self) {
        self.peers.clear();
    }
    /// API start_dkg enqueues this snapshot to the setup driver. Returning it
    /// does not indicate DKG completion and does not invent a DKG status value.
    pub fn generation_inputs(&self) -> Result<GenerationInputs, AdminError> {
        if self.restoring {
            return Err(AdminError::RestoreInProgress);
        }
        let local = self.local.as_ref().ok_or(AdminError::MissingLocalParams)?;
        let records = config::assign_peer_ids(
            self.peers
                .iter()
                .cloned()
                .chain(std::iter::once(local.clone())),
        )
        .map_err(|_| AdminError::InvalidGeneration)?;
        config::validate_setup_set(&records).map_err(|_| AdminError::InvalidGeneration)?;
        let peer = *records
            .iter()
            .find(|(_, r)| *r == local)
            .ok_or(AdminError::InvalidGeneration)?
            .0;
        Ok(GenerationInputs { peer, records })
    }
}
