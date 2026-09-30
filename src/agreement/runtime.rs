use fedimint_aleph_bft::SpawnHandle;
use futures::{channel::oneshot, executor::block_on};
use std::{future::Future, pin::Pin, thread};

/// One OS thread per engine component, driven by the already-required futures
/// executor. The engine's Terminator is responsible for orderly task shutdown.
#[derive(Clone, Copy, Default)]
pub struct ThreadSpawner;
impl SpawnHandle for ThreadSpawner {
    fn spawn(&self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || block_on(task))
            .expect("unable to start agreement task");
    }
    fn spawn_essential(
        &self,
        name: &'static str,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send>> {
        let (complete, receiver) = oneshot::channel();
        // On panic the sender drops without signaling success. Spawn failure
        // also drops it. Only a normally completed task sends the acknowledgment.
        let _ = thread::Builder::new().name(name.to_owned()).spawn(move || {
            block_on(task);
            let _ = complete.send(());
        });
        Box::pin(async move { receiver.await.map_err(|_| ()) })
    }
}

/// Tracks every spawned thread so successful session shutdown means no backup
/// callback or detached component can keep running after the root returns.
#[derive(Clone, Default)]
pub(super) struct TrackedSpawner(std::sync::Arc<TrackedState>);
#[derive(Default)]
struct TrackedState {
    threads: std::sync::Mutex<Vec<thread::JoinHandle<()>>>,
    failed: std::sync::atomic::AtomicBool,
}
impl TrackedSpawner {
    fn launch(
        &self,
        name: &'static str,
        task: impl Future<Output = ()> + Send + 'static,
        complete: Option<oneshot::Sender<Result<(), ()>>>,
    ) {
        let state = self.0.clone();
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(task)))
                        .map_err(|_| ());
                if result.is_err() {
                    state
                        .failed
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if let Some(complete) = complete {
                    let _ = complete.send(result);
                }
            })
            .expect("unable to start tracked agreement task");
        self.0
            .threads
            .lock()
            .expect("agreement task registry poisoned")
            .push(handle);
    }
    pub(super) fn join_all(&self) -> Result<(), super::AgreementError> {
        loop {
            let threads = std::mem::take(
                &mut *self
                    .0
                    .threads
                    .lock()
                    .map_err(|_| super::AgreementError::Failed)?,
            );
            if threads.is_empty() {
                break;
            }
            for handle in threads {
                if handle.join().is_err() {
                    self.0
                        .failed
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        if self.0.failed.load(std::sync::atomic::Ordering::SeqCst) {
            Err(super::AgreementError::Failed)
        } else {
            Ok(())
        }
    }
}
impl SpawnHandle for TrackedSpawner {
    fn spawn(&self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        self.launch(name, task, None)
    }
    fn spawn_essential(
        &self,
        name: &'static str,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send>> {
        let (complete, receiver) = oneshot::channel();
        self.launch(name, task, Some(complete));
        Box::pin(async move { receiver.await.map_err(|_| ())? })
    }
}
