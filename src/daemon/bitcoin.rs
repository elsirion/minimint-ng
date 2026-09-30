//! Daemon selection between the supported Bitcoin backend adapters.
use super::consensus::RuntimeBackend;
use crate::bitcoin::{
    BackendError, BitcoinBackend, Block, Transaction, esplora::Esplora, rpc::CoreRpc,
};
use std::time::Duration;

pub enum Backend {
    Core(CoreRpc),
    Esplora(Esplora),
}
impl Backend {
    /// Interval between Wallet backend polls. A shared remote service is
    /// polled less often than a local node; this only delays local proposals.
    pub fn poll_interval(&self) -> Duration {
        match self {
            Self::Core(_) => Duration::from_secs(1),
            Self::Esplora(_) => crate::bitcoin::esplora::POLL_INTERVAL,
        }
    }
    fn get(&self) -> &dyn BitcoinBackend {
        match self {
            Self::Core(core) => core,
            Self::Esplora(esplora) => esplora,
        }
    }
}
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        self.get().block_count()
    }
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError> {
        self.get().wait_for_count(count)
    }
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError> {
        self.get().block_hash(height)
    }
    fn block(&self, hash: [u8; 32]) -> Result<Block, BackendError> {
        self.get().block(hash)
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        self.get().fee_rate()
    }
    fn broadcast(&self, transaction: &Transaction) -> Result<(), BackendError> {
        self.get().broadcast(transaction)
    }
}
impl RuntimeBackend for Backend {
    fn request_shutdown(&self) {
        match self {
            Self::Core(core) => core.request_shutdown(),
            Self::Esplora(esplora) => esplora.request_shutdown(),
        }
    }
}
