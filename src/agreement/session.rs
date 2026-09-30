use super::{
    AgreementError, BatchProvider, Data, FinalizedUnit, GuardianKeychain, Outbound, ProtocolHasher,
    backup::SessionBackup, network, runtime::TrackedSpawner, session_config,
};
use crate::{protocol::PeerId, storage::Store};
use fedimint_aleph_bft::{FinalizationHandler, LocalIO, NodeIndex, Terminator};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc as standard,
    },
    thread,
};
pub struct EngineIo {
    pub inbound: mpsc::Sender<Vec<u8>>,
    pub outbound: mpsc::Receiver<Outbound>,
    pub finalized: standard::Receiver<FinalizedUnit>,
}
struct Finalizer(standard::Sender<FinalizedUnit>);
impl FinalizationHandler<Data> for Finalizer {
    fn data_finalized(&mut self, _data: Data) {
        panic!("agreement engine omitted creator/round metadata");
    }
    fn unit_finalized(&mut self, creator: NodeIndex, round: u16, data: Option<Data>) {
        let creator = PeerId(
            u16::try_from(creator.0).expect("agreement finalized invalid guardian identifier"),
        );
        // Losing finalized units would change session boundaries. A closed receiver
        // is therefore fatal, unlike explicitly lossy network queues.
        self.0
            .send(FinalizedUnit {
                creator,
                round,
                data,
            })
            .expect("agreement finalized-unit receiver closed");
    }
}
pub struct EngineSession {
    requested: Arc<AtomicBool>,
    stop: Option<oneshot::Sender<()>>,
    root: Option<thread::JoinHandle<Result<(), AgreementError>>>,
}
impl EngineSession {
    pub fn start(
        keychain: GuardianKeychain,
        store: Store,
        session: u64,
        rounds_per_session: u16,
        round_delay_ms: u64,
        provider: BatchProvider,
        queue_capacity: usize,
    ) -> Result<(Self, EngineIo), AgreementError> {
        if queue_capacity == 0 {
            return Err(AgreementError::InvalidConfig);
        }
        let config = session_config(
            keychain.count(),
            keychain.local_id(),
            session,
            rounds_per_session,
            round_delay_ms,
        )?;
        let (network, inbound, outbound) = network::channels(queue_capacity, keychain.count());
        let (finalized_sender, finalized) = standard::channel();
        let (stop, exit) = oneshot::channel();
        let requested = Arc::new(AtomicBool::new(false));
        let requested_in_root = requested.clone();
        let backup = SessionBackup::new(store, session);
        let observer = backup.clone();
        let local_io = LocalIO::new(
            provider,
            Finalizer(finalized_sender),
            backup.clone(),
            backup,
        );
        let root = thread::Builder::new()
            .name(format!(
                "guardian-agreement-{}-{}",
                keychain.local_id().0,
                session
            ))
            .spawn(move || {
                let spawner = TrackedSpawner::default();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    block_on(fedimint_aleph_bft::run_session::<
                        ProtocolHasher,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                    >(
                        config,
                        local_io,
                        network,
                        keychain,
                        spawner.clone(),
                        Terminator::create_root(exit, "guardian-agreement"),
                    ))
                }));
                let joined = spawner.join_all();
                if result.is_err()
                    || observer.has_failed()
                    || !requested_in_root.load(Ordering::SeqCst)
                {
                    Err(AgreementError::Failed)
                } else {
                    joined
                }
            })
            .map_err(|_| AgreementError::Failed)?;
        Ok((
            Self {
                requested,
                stop: Some(stop),
                root: Some(root),
            },
            EngineIo {
                inbound,
                outbound,
                finalized,
            },
        ))
    }
    /// Reports unexpected root completion so the application can abort its session.
    pub fn is_finished(&self) -> bool {
        self.root
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }
    /// Only success permits clearing backups after application completion.
    /// Signals native termination, joins its root, then all component threads.
    pub fn shutdown(mut self) -> Result<(), AgreementError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<(), AgreementError> {
        self.requested.store(true, Ordering::SeqCst);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.root.take() {
            Some(root) => root.join().map_err(|_| AgreementError::Failed)?,
            None => Ok(()),
        }
    }
}
impl Drop for EngineSession {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
