//! API-002 over Iroh 0.35.0: one request per bidirectional stream. The client
//! sends `{"method": M, "request": {"auth": A, "params": P}}` and finishes its
//! side; the server answers `{"Ok": value}` or `{"Err": {"code", "message"}}`
//! and finishes. `M` is `{"Core": name}` or `{"Module": [instance, name]}`.
//! There is no JSON-RPC identifier, batch, or transport access secret here;
//! administrator credentials remain request fields. A malformed request is
//! dropped without an envelope, as the baseline permits.
//!
//! Local policy (not consensus constants): at most 128 connections and 32
//! concurrent streams per connection, 10s handshake and request-read deadlines,
//! the WebSocket profile's 60s operation deadline and 16 MiB response bound.
//! Handlers run on the runtime's blocking pool and observe cancellation through
//! `CallContext`; a peer's STOP_SENDING cancels only that request.
use super::{
    rpc::{Request, RpcError},
    server::{CallContext, Handler, ServerError},
};
use crate::{
    json,
    net::iroh::{
        API_ALPN, IrohIdentity, IrohOptions, MAX_API_REQUEST_BYTES, api_node_addr, bind_api,
        runtime,
    },
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

const HANDSHAKE: Duration = Duration::from_secs(10);
const READ: Duration = Duration::from_secs(10);
const OPERATION: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(20);
const MAX_CONNECTIONS: usize = 128;
const MAX_STREAMS: usize = 32;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Parses one API-002 request envelope into the internal method naming used by
/// the WebSocket profile (`name` or `module_<instance>_<name>`).
pub fn decode_request(bytes: &[u8]) -> Option<Request> {
    let value = json::parse(bytes, MAX_API_REQUEST_BYTES, 64).ok()?;
    let object = value.as_object()?;
    if object.len() != 2 {
        return None;
    }
    let method = value.get("method")?.as_object()?;
    if method.len() != 1 {
        return None;
    }
    let method = if let Some(name) = method.get(&"Core") {
        name.as_str()?.to_owned()
    } else {
        let parts = method.get(&"Module")?.as_array()?;
        if parts.len() != 2 {
            return None;
        }
        let instance = u16::try_from(json::unsigned(&parts[0]).ok()?).ok()?;
        format!("module_{instance}_{}", parts[1].as_str()?)
    };
    let request = value.get("request")?;
    if !request.is_object() {
        return None;
    }
    let auth = match request.get("auth") {
        None => None,
        Some(auth) if auth.is_null() => None,
        Some(auth) => Some(Zeroizing::new(auth.as_str()?.to_owned())),
    };
    let params = request.get("params")?.clone();
    Some(Request::new(method, auth, params))
}
/// Serde's external `Result` tagging, independent of implementation language.
pub fn encode_response(result: Result<Value, RpcError>) -> Value {
    match result {
        Ok(value) => json!({"Ok": value}),
        Err(error) => json!({"Err": {"code": error.code, "message": error.message}}),
    }
}

/// Owned Iroh API listener. The endpoint is bound before `start` returns.
pub struct IrohApiServer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), ServerError>>>,
}
impl IrohApiServer {
    pub fn start(
        identity: &IrohIdentity,
        bind: SocketAddr,
        options: &IrohOptions,
        handler: Arc<impl Handler>,
    ) -> Result<Self, ServerError> {
        let runtime = runtime("api-iroh").map_err(|_| ServerError::Io)?;
        let endpoint = runtime
            .block_on(bind_api(identity.api_secret(), Some(bind), options, true))
            .map_err(|_| ServerError::Io)?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let worker = thread::Builder::new()
            .name("api-iroh-listener".into())
            .spawn(move || {
                let result = runtime.block_on(serve(endpoint, handler, running.clone()));
                running.store(true, Ordering::Release);
                // Blocking handlers observe the stop flag through CallContext.
                runtime.shutdown_timeout(Duration::from_secs(5));
                result
            })
            .map_err(|_| ServerError::Worker)?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
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
impl Drop for IrohApiServer {
    fn drop(&mut self) {
        let _ = self.stop_join();
    }
}

async fn serve(
    endpoint: iroh::Endpoint,
    handler: Arc<impl Handler>,
    stop: Arc<AtomicBool>,
) -> Result<(), ServerError> {
    let mut connections = JoinSet::new();
    let result = loop {
        if stop.load(Ordering::Acquire) {
            break Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break if stop.load(Ordering::Acquire) { Ok(()) } else { Err(ServerError::Io) };
                };
                if connections.len() >= MAX_CONNECTIONS {
                    incoming.refuse();
                    continue;
                }
                let handler = handler.clone();
                let stop = stop.clone();
                connections.spawn(async move {
                    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE, incoming).await else {
                        return;
                    };
                    serve_connection(&connection, handler, stop).await;
                    connection.close(0u32.into(), b"API connection retired");
                });
            }
        }
    };
    stop.store(true, Ordering::Release);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    endpoint.close().await;
    result
}

async fn serve_connection(
    connection: &iroh::endpoint::Connection,
    handler: Arc<impl Handler>,
    stop: Arc<AtomicBool>,
) {
    let mut requests = JoinSet::new();
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _ = connection.closed() => break,
            _ = tokio::time::sleep(POLL) => {}
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
            streams = connection.accept_bi(), if requests.len() < MAX_STREAMS => {
                let Ok((send, recv)) = streams else { break };
                requests.spawn(serve_request(send, recv, handler.clone(), stop.clone()));
            }
        }
    }
    requests.abort_all();
    while requests.join_next().await.is_some() {}
}

async fn serve_request(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    handler: Arc<impl Handler>,
    stop: Arc<AtomicBool>,
) {
    let Ok(Ok(bytes)) = tokio::time::timeout(READ, recv.read_to_end(MAX_API_REQUEST_BYTES)).await
    else {
        return;
    };
    let bytes = Zeroizing::new(bytes);
    let Some(request) = decode_request(&bytes) else {
        return;
    };
    drop(bytes);
    let Some(deadline) = Instant::now().checked_add(OPERATION) else {
        return;
    };
    let disconnected = Arc::new(AtomicBool::new(false));
    let task = {
        let disconnected = disconnected.clone();
        let stop = stop.clone();
        tokio::task::spawn_blocking(move || {
            let context = CallContext::new(deadline, &stop, &disconnected);
            let result = if context.is_cancelled() {
                Err(RpcError::INTERNAL)
            } else {
                handler.handle(&request, &context)
            };
            // A handler is never trusted to enforce its own completion deadline.
            if context.is_cancelled() {
                Err(RpcError {
                    code: 500,
                    message: "Request timed out",
                })
            } else {
                result
            }
        })
    };
    tokio::pin!(task);
    let result = tokio::select! {
        result = &mut task => result,
        _ = send.stopped() => {
            disconnected.store(true, Ordering::Release);
            let _ = task.await;
            return;
        }
    };
    let Ok(result) = result else {
        return;
    };
    let Ok(body) = json::encode_bounded(&encode_response(result), MAX_RESPONSE_BYTES) else {
        return;
    };
    let body = Zeroizing::new(body);
    let _ = tokio::time::timeout(READ, async {
        send.write_all(&body).await.ok()?;
        send.finish().ok()
    })
    .await;
}

/// Outcome of an Iroh API call that reached a guardian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    Transport,
    Timeout,
    Cancelled,
    InvalidResponse,
    /// The guardian answered with an `Err` envelope.
    Rejected,
}

/// Dial-only Iroh 0.35 client with an ephemeral identity, used for guardian
/// history catch-up. One cached connection per guardian API key.
pub struct IrohApiClient {
    runtime: tokio::runtime::Runtime,
    endpoint: iroh::Endpoint,
    options: IrohOptions,
    connections: Mutex<BTreeMap<[u8; 32], iroh::endpoint::Connection>>,
}
impl IrohApiClient {
    pub fn new(options: IrohOptions) -> Result<Self, CallError> {
        let runtime = runtime("api-iroh-client").map_err(|_| CallError::Transport)?;
        let secret = crate::crypto::random_bytes::<32>()
            .map(Zeroizing::new)
            .map_err(|_| CallError::Transport)?;
        let endpoint = runtime
            .block_on(bind_api(
                iroh::SecretKey::from_bytes(&secret),
                None,
                &options,
                false,
            ))
            .map_err(|_| CallError::Transport)?;
        Ok(Self {
            runtime,
            endpoint,
            options,
            connections: Mutex::new(BTreeMap::new()),
        })
    }
    /// Calls `method` (internal naming) on the guardian with API key `key`.
    /// Blocks the calling (non-runtime) thread until the response, `deadline`,
    /// or `cancelled()` becomes true (checked every 20 ms).
    pub fn call(
        &self,
        key: &[u8; 32],
        method: &str,
        params: Value,
        deadline: Instant,
        max_response_bytes: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value, CallError> {
        let method = match method
            .strip_prefix("module_")
            .and_then(|rest| rest.split_once('_'))
            .and_then(|(id, name)| id.parse::<u16>().ok().map(|id| (id, name)))
        {
            Some((id, name)) => json!({"Module": [id, name]}),
            None => json!({"Core": method}),
        };
        let body =
            json::encode(&json!({"method": method, "request": {"auth": null, "params": params}}))
                .map_err(|_| CallError::InvalidResponse)?;
        let target = api_node_addr(key, &self.options).map_err(|_| CallError::Transport)?;
        let cached = self
            .connections
            .lock()
            .map_err(|_| CallError::Transport)?
            .get(key)
            .filter(|connection| connection.close_reason().is_none())
            .cloned();
        let exchange = async {
            let connection = match cached {
                Some(connection) => connection,
                None => {
                    let connection = self
                        .endpoint
                        .connect(target, API_ALPN)
                        .await
                        .map_err(|_| CallError::Transport)?;
                    if let Ok(mut connections) = self.connections.lock() {
                        connections.insert(*key, connection.clone());
                    }
                    connection
                }
            };
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|_| CallError::Transport)?;
            send.write_all(&body)
                .await
                .map_err(|_| CallError::Transport)?;
            send.finish().map_err(|_| CallError::Transport)?;
            recv.read_to_end(max_response_bytes)
                .await
                .map_err(|_| CallError::Transport)
        };
        let response = self.runtime.block_on(async {
            tokio::pin!(exchange);
            loop {
                if cancelled() {
                    return Err(CallError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(CallError::Timeout);
                }
                tokio::select! {
                    result = &mut exchange => return result,
                    _ = tokio::time::sleep(POLL) => {}
                }
            }
        });
        let response = match response {
            Ok(response) => Zeroizing::new(response),
            Err(error) => {
                if let Ok(mut connections) = self.connections.lock() {
                    connections.remove(key);
                }
                return Err(error);
            }
        };
        let value = json::parse(&response, max_response_bytes, 64)
            .map_err(|_| CallError::InvalidResponse)?;
        let object = value.as_object().ok_or(CallError::InvalidResponse)?;
        if object.len() != 1 {
            return Err(CallError::InvalidResponse);
        }
        if let Some(ok) = value.get("Ok") {
            return Ok(ok.clone());
        }
        match value.get("Err") {
            Some(error) if error.get("code").is_some() => Err(CallError::Rejected),
            _ => Err(CallError::InvalidResponse),
        }
    }
    /// Closes cached connections and the endpoint, then stops the runtime.
    pub fn close(self) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.clear();
        }
        self.runtime.block_on(self.endpoint.close());
        self.runtime.shutdown_timeout(Duration::from_secs(5));
    }
}
