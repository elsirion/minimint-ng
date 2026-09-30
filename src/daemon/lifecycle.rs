//! Setup-to-runtime ownership boundary for the regtest/signet TCP/WS profile.
//! DNS is a caller responsibility; advertised URLs are validated, never rewritten.
use super::config::{RuntimeConfig, RuntimeConfigError, tcp_authority};
use crate::{
    api::setup::GenerationJob,
    config::{self, BitcoinNetwork, CanonicalUrl, SetupEndpoints, SetupRecord},
    net::{
        PeerNetwork, TransportError,
        tls::{PeerCertificate, TlsConfig},
    },
    protocol::PeerId,
    setup::{self, PeerSetupTransport, PersistenceError, SetupDefaults, SetupError},
    storage::Store,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

#[derive(Clone)]
pub struct AdvertisedEndpoints {
    pub api: CanonicalUrl,
    pub p2p: CanonicalUrl,
}
#[derive(Debug)]
pub enum LifecycleError {
    Setup(SetupError),
    Persistence(PersistenceError),
    Config(RuntimeConfigError),
    Transport(TransportError),
    Cancelled,
    InvalidProfile,
    InvalidAddresses,
    WorkerFailed,
}
impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Setup(_) => "guardian setup failed",
            Self::Persistence(_) => "guardian setup storage failed",
            Self::Config(_) => "guardian runtime configuration invalid",
            Self::Transport(_) => "guardian setup transport failed",
            Self::Cancelled => "guardian setup cancelled",
            Self::InvalidProfile => "unsupported guardian deployment profile",
            Self::InvalidAddresses => "invalid resolved guardian membership",
            Self::WorkerFailed => "guardian setup worker failed",
        })
    }
}
impl std::error::Error for LifecycleError {}
impl From<PersistenceError> for LifecycleError {
    fn from(e: PersistenceError) -> Self {
        Self::Persistence(e)
    }
}
impl From<TransportError> for LifecycleError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}
fn profile(
    records: &BTreeMap<PeerId, SetupRecord>,
    local: PeerId,
    expected: &AdvertisedEndpoints,
) -> Result<BTreeMap<PeerId, CanonicalUrl>, LifecycleError> {
    config::validate_setup_set(records).map_err(|_| LifecycleError::InvalidProfile)?;
    if !(records.len() == 1 || (4..=20).contains(&records.len())) {
        return Err(LifecycleError::InvalidProfile);
    }
    let modules = BTreeSet::from(["mintv2".to_owned(), "walletv2".to_owned()]);
    let mut remote = BTreeMap::new();
    let mut found_local = false;
    for (peer, record) in records {
        let SetupEndpoints::Tcp {
            api_url, p2p_url, ..
        } = &record.endpoints
        else {
            return Err(LifecycleError::InvalidProfile);
        };
        if !matches!(
            record.network,
            BitcoinNetwork::Regtest | BitcoinNetwork::Signet
        ) || !api_url.as_str().starts_with("ws://")
            || tcp_authority(p2p_url).is_err()
            || config::normalize_release(&record.release) != "0.13.0"
            || record
                .enabled_modules
                .as_ref()
                .is_some_and(|m| m != &modules)
        {
            return Err(LifecycleError::InvalidProfile);
        }
        if *peer == local {
            found_local = true;
            if api_url != &expected.api || p2p_url != &expected.p2p {
                return Err(LifecycleError::InvalidProfile);
            }
        } else {
            remote.insert(*peer, p2p_url.clone());
        }
    }
    if !found_local {
        return Err(LifecycleError::InvalidProfile);
    }
    Ok(remote)
}
fn exact_addresses(
    urls: &BTreeMap<PeerId, CanonicalUrl>,
    resolved: &BTreeMap<PeerId, SocketAddr>,
) -> Result<(), LifecycleError> {
    if urls.keys().ne(resolved.keys()) {
        return Err(LifecycleError::InvalidAddresses);
    }
    for (peer, url) in urls {
        let port = tcp_authority(url)
            .ok()
            .and_then(|authority| authority.rsplit_once(':'))
            .and_then(|(_, port)| port.parse::<u16>().ok());
        if port != Some(resolved[peer].port()) {
            return Err(LifecycleError::InvalidAddresses);
        }
    }
    Ok(())
}
/// Pure validated endpoint collection plus confidential generation input. No DNS,
/// sockets, persistence, or worker starts occur until start(). No Debug on secrets.
pub struct SetupPlan {
    job: GenerationJob,
    tls: TlsConfig,
    remote: BTreeMap<PeerId, CanonicalUrl>,
    expected: AdvertisedEndpoints,
}
impl SetupPlan {
    pub fn new(job: GenerationJob, expected: &AdvertisedEndpoints) -> Result<Self, LifecycleError> {
        let remote = profile(&job.inputs.records, job.inputs.peer, expected)?;
        let mut certificates = BTreeMap::new();
        for (peer, record) in &job.inputs.records {
            let SetupEndpoints::Tcp { certificate, .. } = &record.endpoints else {
                return Err(LifecycleError::InvalidProfile);
            };
            if *peer == job.inputs.peer && job.identity.certificate_der()? != *certificate {
                return Err(LifecycleError::InvalidProfile);
            }
            certificates.insert(
                *peer,
                PeerCertificate {
                    name: record.name.clone(),
                    certificate_der: certificate.clone(),
                },
            );
        }
        let tls = TlsConfig::new(&job.identity, certificates)?;
        Ok(Self {
            job,
            tls,
            remote,
            expected: expected.clone(),
        })
    }
    pub fn peer_urls(&self) -> &BTreeMap<PeerId, CanonicalUrl> {
        &self.remote
    }
    /// The caller resolves each returned advertised authority and supplies exactly
    /// its remote peer IDs. Listener binding is independent of advertised addresses.
    /// There is no resolver thread to detach or hide an unbounded DNS operation.
    pub fn start(
        self,
        store: Store,
        listener: TcpListener,
        resolved: BTreeMap<PeerId, SocketAddr>,
        queue_capacity: usize,
    ) -> Result<Generation, LifecycleError> {
        exact_addresses(&self.remote, &resolved)?;
        if setup::load_generated(&store)?.is_some() {
            return Err(LifecycleError::Persistence(PersistenceError::AlreadyStored));
        }
        let network = Arc::new(PeerNetwork::start(
            self.job.inputs.peer,
            self.tls,
            resolved,
            listener,
            queue_capacity,
        )?);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_network = network.clone();
        let worker_cancelled = cancelled.clone();
        let worker = thread::Builder::new()
            .name("guardian-setup-generation".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut transport =
                        PeerSetupTransport::new(&worker_network, self.remote.keys().copied());
                    let generated = setup::generate(
                        self.job.inputs.peer,
                        &self.job.inputs.records,
                        &SetupDefaults::default(),
                        &mut transport,
                    )
                    .map_err(LifecycleError::Setup)?;
                    if worker_cancelled.load(Ordering::Acquire) {
                        return Err(LifecycleError::Cancelled);
                    }
                    setup::persist_generated(&store, &generated, &self.job.identity)?;
                    // Validate the durable record we are actually handing to startup.
                    // Cancellation racing this atomic commit leaves a valid restore
                    // record; it never deletes durable configuration or publishes running.
                    let restored =
                        load(&store, &self.expected)?.ok_or(LifecycleError::WorkerFailed)?;
                    Ok(restored.config)
                }))
                .unwrap_or(Err(LifecycleError::WorkerFailed));
                if worker_cancelled.load(Ordering::Acquire)
                    && matches!(
                        result,
                        Err(LifecycleError::Setup(
                            SetupError::Transport | SetupError::Aborted
                        ))
                    )
                {
                    Err(LifecycleError::Cancelled)
                } else {
                    result
                }
            });
        match worker {
            Ok(worker) => Ok(Generation {
                network: Some(network),
                worker: Some(worker),
                cancelled,
            }),
            Err(_) => {
                network.request_shutdown();
                Arc::try_unwrap(network)
                    .map_err(|_| LifecycleError::WorkerFailed)?
                    .shutdown()?;
                Err(LifecycleError::WorkerFailed)
            }
        }
    }
}
/// Successful finish transfers the same authenticated queues after the sole DKG
/// consumer has joined. The caller may now start agreement and publish running.
pub struct ReadyRuntime {
    pub config: Arc<RuntimeConfig>,
    pub network: Arc<PeerNetwork>,
}
pub struct Generation {
    network: Option<Arc<PeerNetwork>>,
    worker: Option<JoinHandle<Result<Arc<RuntimeConfig>, LifecycleError>>>,
    cancelled: Arc<AtomicBool>,
}
impl Generation {
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn request_shutdown(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(network) = &self.network {
            network.request_shutdown();
        }
    }
    fn join(&mut self) -> Result<Arc<RuntimeConfig>, LifecycleError> {
        self.worker
            .take()
            .ok_or(LifecycleError::WorkerFailed)?
            .join()
            .map_err(|_| LifecycleError::WorkerFailed)?
    }
    fn close_network(&mut self) -> Result<(), LifecycleError> {
        if let Some(network) = self.network.take() {
            network.request_shutdown();
            Arc::try_unwrap(network)
                .map_err(|_| LifecycleError::WorkerFailed)?
                .shutdown()?;
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<ReadyRuntime, LifecycleError> {
        let result = self.join();
        match result {
            Ok(_) if self.cancelled.load(Ordering::Acquire) => {
                self.close_network()?;
                Err(LifecycleError::Cancelled)
            }
            Ok(config) => Ok(ReadyRuntime {
                config,
                network: self.network.take().ok_or(LifecycleError::WorkerFailed)?,
            }),
            Err(error) => {
                self.close_network()?;
                Err(error)
            }
        }
    }
    /// Cancel, join DKG, then join its network. Cancellation itself is successful;
    /// other worker/transport failures remain errors. Durable completed setup stays.
    pub fn shutdown(mut self) -> Result<(), LifecycleError> {
        self.request_shutdown();
        let generated = self.join();
        let closed = self.close_network();
        match generated {
            Ok(_) | Err(LifecycleError::Cancelled) => closed,
            Err(e) => {
                closed?;
                Err(e)
            }
        }
    }
}
impl Drop for Generation {
    fn drop(&mut self) {
        self.request_shutdown();
        if self.worker.is_some() {
            let _ = self.join();
        }
        let _ = self.close_network();
    }
}
pub struct RestoredSetup {
    config: Arc<RuntimeConfig>,
}
impl RestoredSetup {
    pub fn config(&self) -> &Arc<RuntimeConfig> {
        &self.config
    }
    pub fn peer_urls(&self) -> &BTreeMap<PeerId, CanonicalUrl> {
        self.config.remote_peer_urls()
    }
    pub fn connect(
        self,
        listener: TcpListener,
        resolved: BTreeMap<PeerId, SocketAddr>,
        queue_capacity: usize,
    ) -> Result<ReadyRuntime, LifecycleError> {
        exact_addresses(self.peer_urls(), &resolved)?;
        let network = PeerNetwork::start(
            self.config.peer(),
            self.config.tls_config(),
            resolved,
            listener,
            queue_capacity,
        )?;
        Ok(ReadyRuntime {
            config: self.config,
            network: Arc::new(network),
        })
    }
}
pub fn load(
    store: &Store,
    expected: &AdvertisedEndpoints,
) -> Result<Option<RestoredSetup>, LifecycleError> {
    let Some(persisted) = setup::load_generated(store)? else {
        return Ok(None);
    };
    profile(
        &persisted.generated.setup_records,
        persisted.generated.peer,
        expected,
    )?;
    let config = RuntimeConfig::from_persisted(persisted).map_err(LifecycleError::Config)?;
    Ok(Some(RestoredSetup {
        config: Arc::new(config),
    }))
}
