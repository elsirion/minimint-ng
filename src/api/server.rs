//! Bounded WebSocket API listener. One read owner continues processing control
//! frames while at most eight request-message workers run per connection (local
//! policy). A batch stays one worker and produces one complete response array.
//! Handlers must cooperate with deadline/cancellation; all workers are joined.
use super::{
    rpc::{self, Request, RpcError},
    websocket::{Limits, Message, WebSocket, WebSocketWriter},
};
use crate::json;
use sonic_rs::{JsonValueTrait, Value, json as value};
use std::{
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_IN_FLIGHT: usize = 8;
const TIMEOUT: RpcError = RpcError {
    code: 500,
    message: "Request timed out",
};
pub struct CallContext<'a> {
    pub deadline: Instant,
    cancelled: &'a AtomicBool,
    disconnected: &'a AtomicBool,
}
impl<'a> CallContext<'a> {
    /// For transports other than the WebSocket listener (Iroh API streams).
    pub(crate) fn new(
        deadline: Instant,
        cancelled: &'a AtomicBool,
        disconnected: &'a AtomicBool,
    ) -> Self {
        Self {
            deadline,
            cancelled,
            disconnected,
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self.disconnected.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
    }
}
/// Internal daemon boundary, not a dynamically loaded module interface.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    Configuration,
    Io,
    Worker,
}
impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API server failed: {self:?}")
    }
}
impl std::error::Error for ServerError {}
struct Shared {
    stop: AtomicBool,
    failed: AtomicBool,
    sockets: Mutex<Vec<(u64, TcpStream)>>,
}
pub struct Server {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<Result<(), ServerError>>>,
}
impl Server {
    pub fn start(
        listener: TcpListener,
        handler: Arc<impl Handler>,
        access_secret: Option<Zeroizing<String>>,
        limits: Limits,
        max_connections: usize,
    ) -> Result<Self, ServerError> {
        if max_connections == 0
            || limits.max_message_bytes == 0
            || limits.max_header_bytes == 0
            || limits.handshake_timeout.is_zero()
            || limits.operation_timeout.is_zero()
        {
            return Err(ServerError::Configuration);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_| ServerError::Io)?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            sockets: Mutex::new(Vec::new()),
        });
        let running = shared.clone();
        let worker = thread::Builder::new()
            .name("api-listener".into())
            .spawn(move || {
                let mut tasks: Vec<JoinHandle<()>> = Vec::new();
                let mut next = 0u64;
                let outcome = (|| {
                    while !running.stop.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                let mut sockets =
                                    running.sockets.lock().map_err(|_| ServerError::Worker)?;
                                if sockets.len() >= max_connections {
                                    let _ = socket.shutdown(Shutdown::Both);
                                } else {
                                    let id = next;
                                    next = next.checked_add(1).ok_or(ServerError::Worker)?;
                                    sockets.push((
                                        id,
                                        socket.try_clone().map_err(|_| ServerError::Io)?,
                                    ));
                                    let handler = handler.clone();
                                    let state = running.clone();
                                    let secret = access_secret
                                        .as_ref()
                                        .map(|s| Zeroizing::new(s.to_string()));
                                    tasks.push(
                                        thread::Builder::new()
                                            .name(format!("api-{id}"))
                                            .spawn(move || {
                                                if connection(
                                                    socket,
                                                    handler,
                                                    secret.as_deref().map(|s| s.as_str()),
                                                    limits,
                                                    state.clone(),
                                                )
                                                .is_err()
                                                {
                                                    state.failed.store(true, Ordering::Release);
                                                    cancel(&state);
                                                }
                                                // Connection joins all request workers before releasing its slot.
                                                if let Ok(mut sockets) = state.sockets.lock() {
                                                    sockets.retain(|(key, _)| *key != id);
                                                }
                                            })
                                            .map_err(|_| ServerError::Worker)?,
                                    );
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                            Err(_) => return Err(ServerError::Io),
                        }
                        let mut i = 0;
                        while i < tasks.len() {
                            if tasks[i].is_finished() {
                                tasks
                                    .swap_remove(i)
                                    .join()
                                    .map_err(|_| ServerError::Worker)?;
                            } else {
                                i += 1;
                            }
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Ok(())
                })();
                cancel(&running);
                let mut failed = running.failed.load(Ordering::Acquire);
                for task in tasks {
                    failed |= task.join().is_err();
                }
                failed |= running.failed.load(Ordering::Acquire);
                if failed {
                    Err(ServerError::Worker)
                } else {
                    outcome
                }
            })
            .map_err(|_| ServerError::Worker)?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }
    pub fn request_shutdown(&self) {
        cancel(&self.shared);
    }
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(|worker| worker.is_finished())
    }
    pub fn shutdown(mut self) -> Result<(), ServerError> {
        self.stop_join()
    }
    fn stop_join(&mut self) -> Result<(), ServerError> {
        self.request_shutdown();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ServerError::Worker)??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop_join();
    }
}
fn cancel(shared: &Shared) {
    shared.stop.store(true, Ordering::Release);
    if let Ok(sockets) = shared.sockets.lock() {
        for (_, socket) in sockets.iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}
fn connection(
    socket: TcpStream,
    handler: Arc<impl Handler>,
    secret: Option<&str>,
    limits: Limits,
    shared: Arc<Shared>,
) -> Result<(), ServerError> {
    let Ok(mut websocket) = WebSocket::accept(socket, secret, limits) else {
        return Ok(());
    };
    let writer = websocket.writer();
    let disconnected = Arc::new(AtomicBool::new(false));
    let mut tasks: Vec<JoinHandle<Result<(), ServerError>>> = Vec::new();
    let result = (|| {
        while !shared.stop.load(Ordering::Acquire) && !disconnected.load(Ordering::Acquire) {
            let bytes = match websocket.receive() {
                Ok(Message::Text(text)) => Zeroizing::new(text.into_bytes()),
                Ok(Message::Binary(bytes)) => Zeroizing::new(bytes),
                _ => break,
            };
            let mut i = 0;
            while i < tasks.len() {
                if tasks[i].is_finished() {
                    tasks
                        .swap_remove(i)
                        .join()
                        .map_err(|_| ServerError::Worker)??;
                } else {
                    i += 1;
                }
            }
            if tasks.len() >= MAX_IN_FLIGHT {
                break;
            }
            let Some(deadline) = Instant::now().checked_add(limits.operation_timeout) else {
                break;
            };
            let handler = handler.clone();
            let state = shared.clone();
            let stopped = disconnected.clone();
            let output = writer.clone();
            tasks.push(
                thread::Builder::new()
                    .name("api-request".into())
                    .spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let context = CallContext {
                                deadline,
                                cancelled: &state.stop,
                                disconnected: &stopped,
                            };
                            process(
                                &bytes,
                                handler.as_ref(),
                                &context,
                                &output,
                                limits.max_message_bytes,
                            )
                        }));
                        match result {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(())) => {
                                stopped.store(true, Ordering::Release);
                                output.abort();
                                Ok(())
                            }
                            Err(_) => {
                                stopped.store(true, Ordering::Release);
                                output.abort();
                                Err(ServerError::Worker)
                            }
                        }
                    })
                    .map_err(|_| ServerError::Worker)?,
            );
        }
        Ok(())
    })();
    disconnected.store(true, Ordering::Release);
    writer.abort();
    let mut failed = false;
    for task in tasks {
        failed |= !matches!(task.join(), Ok(Ok(())));
    }
    if failed {
        Err(ServerError::Worker)
    } else {
        result
    }
}
fn process(
    bytes: &[u8],
    handler: &impl Handler,
    context: &CallContext<'_>,
    writer: &WebSocketWriter,
    maximum: usize,
) -> Result<(), ()> {
    let mut replies = Vec::new();
    let mut batch = false;
    match rpc::decode(bytes, maximum) {
        Err(error) => {
            if let Some(reply) = error.response() {
                replies.push(reply);
            }
        }
        Ok(message) => {
            batch = message.batch;
            let mut budget = if batch { 2usize } else { 0 }; // array delimiters
            for request in message.requests {
                let reply = match request {
                    Err(error) => error.response(),
                    Ok(request) => {
                        let mut result = if context.is_cancelled() {
                            Err(TIMEOUT)
                        } else {
                            handler.handle(&request, context)
                        };
                        // A handler is never trusted to enforce its own completion deadline.
                        if context.is_cancelled() {
                            result = Err(TIMEOUT);
                        }
                        request.response(result)
                    }
                };
                if let Some(reply) = reply {
                    if batch && !replies.is_empty() {
                        budget = budget.checked_add(1).ok_or(())?; // comma
                    }
                    let remaining = maximum.checked_sub(budget).ok_or(())?;
                    let encoded =
                        Zeroizing::new(json::encode_bounded(&reply, remaining).map_err(|_| ())?);
                    budget = budget.checked_add(encoded.len()).ok_or(())?;
                    if budget > maximum {
                        return Err(());
                    }
                    replies.push(reply);
                }
            }
        }
    }
    if replies.is_empty() {
        return Ok(());
    }
    if context.cancelled.load(Ordering::Acquire) || context.disconnected.load(Ordering::Acquire) {
        return Err(());
    }
    // An earlier successful batch member must not leak through if a later member
    // consumed the shared message deadline before the aggregate could be sent.
    if Instant::now() >= context.deadline {
        for reply in &mut replies {
            if reply.get("result").is_some() {
                let id = reply.get("id").cloned().ok_or(())?;
                *reply = rpc::response(id, Err(TIMEOUT));
            }
        }
    }
    let has_success = replies.iter().any(|r| r.get("result").is_some());
    let reply = if batch {
        value!(replies)
    } else {
        replies.pop().ok_or(())?
    };
    let bytes = Zeroizing::new(json::encode_bounded(&reply, maximum).map_err(|_| ())?);
    let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
    if has_success {
        writer
            .send_text_before(text, context.deadline)
            .map_err(|_| ())
    } else {
        writer.send_text(text).map_err(|_| ())
    }
}
