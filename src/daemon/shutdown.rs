//! Linux process termination boundary. Install before spawning any workers.
//! Keep this owner outside all daemon resources and finish it only after their
//! cleanup. The watchdog does not depend on the thread performing blocking I/O
//! or joins. This is not a hard OS scheduling or kernel execution guarantee.
use signal_hook::{
    SigId,
    consts::{SIGINT, SIGTERM},
    flag, low_level,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownError {
    InvalidDuration,
    SignalRegistration,
    Worker,
    ActiveDeadline,
}
impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidDuration => "Invalid shutdown deadline",
            Self::SignalRegistration => "Cannot register shutdown signals",
            Self::Worker => "Shutdown watchdog failed",
            Self::ActiveDeadline => "Startup deadline already active",
        })
    }
}
impl std::error::Error for ShutdownError {}
struct State {
    next: u64,
    operation: Option<(u64, Instant)>,
}
struct Shared {
    requested: Arc<AtomicBool>,
    finished: AtomicBool,
    state: Mutex<State>,
}
/// Owns signal registrations and the joined watchdog. No daemon state or secret
/// material enters the signal handler: the library only sets an atomic flag.
pub struct Shutdown {
    shared: Arc<Shared>,
    registrations: Vec<SigId>,
    worker: Option<JoinHandle<()>>,
}
/// A local startup-I/O deadline, independent of consensus liveness. Drop before
/// finishing Shutdown. Overlapping operation scopes are rejected.
pub struct DeadlineGuard<'a> {
    shared: &'a Shared,
    token: u64,
}
impl Drop for DeadlineGuard<'_> {
    fn drop(&mut self) {
        let Ok(mut state) = self.shared.state.lock() else {
            low_level::exit(2)
        };
        if let Some((token, end)) = state.operation
            && token == self.token
        {
            if Instant::now() >= end {
                low_level::exit(2);
            }
            state.operation = None;
        }
    }
}
impl Shutdown {
    pub fn install(grace: Duration) -> Result<Self, ShutdownError> {
        checked_deadline(grace)?;
        let requested = Arc::new(AtomicBool::new(false));
        let mut registrations = Vec::new();
        for signal in [SIGINT, SIGTERM] {
            match flag::register(signal, requested.clone()) {
                Ok(id) => registrations.push(id),
                Err(_) => {
                    for id in registrations {
                        low_level::unregister(id);
                    }
                    return Err(ShutdownError::SignalRegistration);
                }
            }
        }
        let shared = Arc::new(Shared {
            requested,
            finished: AtomicBool::new(false),
            state: Mutex::new(State {
                next: 0,
                operation: None,
            }),
        });
        let watched = shared.clone();
        let worker = match thread::Builder::new()
            .name("guardian-shutdown-watchdog".into())
            .spawn(move || {
                let mut termination = None;
                while !watched.finished.load(Ordering::Acquire) {
                    let now = Instant::now();
                    if watched.requested.load(Ordering::Acquire) && termination.is_none() {
                        termination =
                            Some(now.checked_add(grace).unwrap_or_else(|| low_level::exit(2)));
                    }
                    let operation = match watched.state.lock() {
                        Ok(state) => state.operation.map(|(_, end)| end),
                        Err(_) => low_level::exit(2),
                    };
                    if termination.is_some_and(|end| now >= end)
                        || operation.is_some_and(|end| now >= end)
                    {
                        // No destructors, database cleanup, buffered logging, or core
                        // dump: successful durable commits are the recovery boundary.
                        low_level::exit(2);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }) {
            Ok(worker) => worker,
            Err(_) => {
                for id in registrations {
                    low_level::unregister(id);
                }
                return Err(ShutdownError::Worker);
            }
        };
        Ok(Self {
            shared,
            registrations,
            worker: Some(worker),
        })
    }
    /// Share the request with lifecycle workers. Only set it to true; shutdown
    /// is irreversible and the watchdog never resets an armed grace deadline.
    pub fn flag(&self) -> Arc<AtomicBool> {
        self.shared.requested.clone()
    }
    pub fn request(&self) {
        self.shared.requested.store(true, Ordering::Release);
    }
    pub fn is_requested(&self) -> bool {
        self.shared.requested.load(Ordering::Acquire)
    }
    /// Guard a startup operation, such as DNS, with an explicit local deadline.
    /// The lifecycle uses 15 seconds; this never times out agreement progress.
    pub fn deadline(&self, duration: Duration) -> Result<DeadlineGuard<'_>, ShutdownError> {
        let end = checked_deadline(duration)?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| ShutdownError::Worker)?;
        if state.operation.is_some() {
            return Err(ShutdownError::ActiveDeadline);
        }
        state.next = state.next.checked_add(1).ok_or(ShutdownError::Worker)?;
        let token = state.next;
        state.operation = Some((token, end));
        Ok(DeadlineGuard {
            shared: &self.shared,
            token,
        })
    }
    /// Call only after daemon owners have cancelled and joined their resources.
    pub fn finish(mut self) -> Result<(), ShutdownError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<(), ShutdownError> {
        self.shared.finished.store(true, Ordering::Release);
        let result = self.worker.take().map(|worker| worker.join());
        for id in self.registrations.drain(..) {
            low_level::unregister(id);
        }
        match result {
            Some(Err(_)) => Err(ShutdownError::Worker),
            _ => Ok(()),
        }
    }
}
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
fn checked_deadline(duration: Duration) -> Result<Instant, ShutdownError> {
    if duration.is_zero() {
        return Err(ShutdownError::InvalidDuration);
    }
    Instant::now()
        .checked_add(duration)
        .ok_or(ShutdownError::InvalidDuration)
}
