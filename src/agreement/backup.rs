use crate::storage::Store;
use fedimint_aleph_bft::{BackupReader, BackupWriter};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Exact engine bytes, separate from accepted application history. The engine
/// must stop before the session clears these records in its completion commit.
#[derive(Clone)]
pub struct SessionBackup {
    store: Store,
    session: u64,
    failed: Arc<AtomicBool>,
}
impl SessionBackup {
    pub fn new(store: Store, session: u64) -> Self {
        Self {
            store,
            session,
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub(super) fn has_failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }
}
impl BackupWriter for SessionBackup {
    fn append<'a, 'b, 'f>(
        &'a mut self,
        data: &'b [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'f>>
    where
        Self: 'f,
        'a: 'f,
        'b: 'f,
    {
        Box::pin(async move {
            // The synchronous store call returns only after SyncAll. This runs
            // on the engine task's dedicated thread, not a shared I/O executor.
            self.store
                .append_agreement(self.session, data)
                .map_err(|error| {
                    self.failed.store(true, Ordering::SeqCst);
                    io::Error::other(error)
                })?;
            Ok(())
        })
    }
}
impl BackupReader for SessionBackup {
    fn read<'a, 'f>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'f>>
    where
        Self: 'f,
        'a: 'f,
    {
        Box::pin(async move {
            self.store.read_agreement(self.session).map_err(|error| {
                self.failed.store(true, Ordering::SeqCst);
                io::Error::other(error)
            })
        })
    }
}
