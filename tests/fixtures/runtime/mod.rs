#![allow(dead_code)]
//! Shared typed guardian configurations and a cancellable observation fixture.
use minimint_ng::{
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, text::hex_encode},
    config::{
        self, BitcoinNetwork, CanonicalUrl, DescriptorKind, Endpoint, Fee, RawMintConfig,
        RawServerConfig, RawWalletConfig, ServerModuleConfig, SetupEndpoints, SetupRecord,
    },
    crypto::{
        bls::{G2, Scalar},
        secp::SecretKey,
    },
    daemon::{config::RuntimeConfig, consensus::RuntimeBackend},
    net::tls::Identity,
    protocol::{ModuleId, PeerId},
    setup::{GeneratedConfig, GeneratedSecrets, PersistedSetup},
};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[byte; 32]).unwrap()
}
pub fn url(s: &str) -> CanonicalUrl {
    CanonicalUrl::simple(s).unwrap()
}
pub fn configs(n: u16, rounds: u16, listeners: &[TcpListener]) -> Vec<Arc<RuntimeConfig>> {
    let identities: Vec<_> = (0..n)
        .map(|p| Identity::generate(&format!("Guardian {p:02}")).unwrap())
        .collect();
    let mut endpoints = BTreeMap::new();
    let mut certificates = BTreeMap::new();
    let mut records = BTreeMap::new();
    for p in 0..n {
        let peer = PeerId(p);
        let name = format!("Guardian {p:02}");
        let api_url = url(&format!("ws://127.0.0.1:{}/", 10000 + p));
        let certificate = identities[p as usize].certificate_der().unwrap();
        endpoints.insert(
            peer,
            Endpoint {
                url: api_url.clone(),
                name: name.clone(),
            },
        );
        certificates.insert(peer, hex_encode(&certificate));
        records.insert(
            peer,
            SetupRecord {
                name,
                endpoints: SetupEndpoints::Tcp {
                    api_url,
                    p2p_url: url(&format!(
                        "fedimint://{}/",
                        listeners[p as usize].local_addr().unwrap()
                    )),
                    certificate,
                },
                federation_name: (p == 0).then(|| "Federation".into()),
                disable_base_fees: None,
                enabled_modules: None,
                federation_size: (p == 0).then_some(u32::from(n)),
                network: BitcoinNetwork::Regtest,
                release: "0.13.0-test".into(),
            },
        );
    }
    let point = G2::generator().to_bytes();
    let mint = RawMintConfig {
        aggregate_keys: (0..42).map(|d| (d, point)).collect(),
        public_shares: (0..42)
            .map(|d| (d, (0..n).map(|p| (PeerId(p), point)).collect()))
            .collect(),
        fee: Fee::mint(100, 0).unwrap(),
        amount_unit: 0,
    };
    let wallet = RawWalletConfig {
        bitcoin_pks: (0..n)
            .map(|p| (PeerId(p), key(p as u8 + 101).public_key()))
            .collect(),
        descriptor: DescriptorKind::Wsh,
        send_tx_vbytes: 228,
        receive_tx_vbytes: 316,
        feerate_base: 250,
        dust_limit: 10000,
        fee_consensus: Fee::wallet(100000, 0).unwrap(),
        network: BitcoinNetwork::Regtest,
    };
    let server = RawServerConfig {
        code_release: "0.13.0".into(),
        consensus_version: config::CORE_CONSENSUS,
        broadcast_public_keys: (0..n)
            .map(|p| (PeerId(p), key(p as u8 + 1).public_key()))
            .collect(),
        rounds_per_session: rounds,
        api_endpoints: endpoints,
        iroh_endpoints: BTreeMap::new(),
        tls_certificates: certificates,
        modules: BTreeMap::from([
            (
                ModuleId(0),
                ServerModuleConfig {
                    kind: "mintv2".into(),
                    version: config::MODULE_CONSENSUS,
                    config: mint.consensus_encode(),
                },
            ),
            (
                ModuleId(1),
                ServerModuleConfig {
                    kind: "walletv2".into(),
                    version: config::MODULE_CONSENSUS,
                    config: wallet.consensus_encode(),
                },
            ),
        ]),
        meta: BTreeMap::from([("federation_name".into(), "Federation".into())]),
    };
    identities
        .into_iter()
        .enumerate()
        .map(|(p, identity)| {
            Arc::new(
                RuntimeConfig::from_persisted(PersistedSetup {
                    generated: GeneratedConfig {
                        server: server.clone(),
                        setup_records: records.clone(),
                        peer: PeerId(p as u16),
                        secrets: GeneratedSecrets {
                            broadcast: key(p as u8 + 1),
                            wallet: key(p as u8 + 101),
                            mint: (0..42).map(|d| (d, Scalar::from_u64(1))).collect(),
                        },
                    },
                    identity,
                })
                .unwrap(),
            )
        })
        .collect()
}
pub struct Backend {
    pub panic_poll: AtomicBool,
    pub panic_scan: AtomicBool,
    pub block_scan: AtomicBool,
    pub scan: AtomicBool,
    pub stopped: AtomicBool,
    pub attempts: std::sync::atomic::AtomicUsize,
    pub block: bitcoin::Block,
}
impl Backend {
    pub fn new() -> Self {
        Self {
            panic_poll: AtomicBool::new(false),
            panic_scan: AtomicBool::new(false),
            block_scan: AtomicBool::new(false),
            scan: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            attempts: std::sync::atomic::AtomicUsize::new(0),
            block: bitcoin::Block {
                header: [0; 80],
                transactions: vec![],
            },
        }
    }
}
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        assert!(
            !self.panic_poll.load(Ordering::SeqCst),
            "injected wallet poll panic"
        );
        Err(BackendError)
    }
    fn wait_for_count(&self, _: u64) -> Result<(), BackendError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_scan.load(Ordering::SeqCst),
            "injected ordered scan panic"
        );
        while self.block_scan.load(Ordering::SeqCst) && !self.stopped.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if self.stopped.load(Ordering::SeqCst) {
            return Err(BackendError);
        }
        if self.scan.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(BackendError)
        }
    }
    fn block_hash(&self, _: u64) -> Result<[u8; 32], BackendError> {
        Ok(self.block.hash())
    }
    fn block(&self, _: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        Ok(self.block.clone())
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Err(BackendError)
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        Ok(())
    }
}
impl RuntimeBackend for Backend {
    fn request_shutdown(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}
