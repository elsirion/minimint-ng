//! Bounded local TCP peer manager. Only the lower ID initiates connections.
//! Regtest timing: 250ms TCP connect, 500ms total TLS handshake, 100ms reconnect,
//! 2ms worker tick. These are local scheduling choices, not consensus constants.
//! Successful send means queued, with no acknowledgement or replay guarantee.
use super::{
    MAX_FRAME_LEN, TransportError,
    envelope::Envelope,
    tls::{AuthenticatedStream, TlsConfig},
};
use crate::protocol::PeerId;
use openssl::ssl::{ErrorCode, SslStream};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const TICK: Duration = Duration::from_millis(2);
type Frame = Zeroizing<Vec<u8>>;
#[derive(Default)]
struct Slot {
    generation: u64,
    connected: bool,
    outgoing: VecDeque<Frame>,
    outstanding: usize,
    incoming: VecDeque<Envelope>,
}
struct State {
    slots: BTreeMap<PeerId, Slot>,
    cursor: Option<PeerId>,
}
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    stop: AtomicBool,
    capacity: usize,
}
/// Owns the listener/controller and all connection workers. Both receive methods
/// consume the same per-peer FIFO. Disconnect retains already received envelopes,
/// but drops queued and partially written outbound messages. Replacement performs
/// the same outbound drop; generation checks prevent old workers from publishing
/// messages or disconnecting the new connection.
pub struct PeerNetwork {
    shared: Arc<Shared>,
    controller: Option<JoinHandle<Result<(), TransportError>>>,
}
impl PeerNetwork {
    pub fn start(
        local: PeerId,
        tls: TlsConfig,
        addresses: BTreeMap<PeerId, SocketAddr>,
        listener: TcpListener,
        queue_capacity: usize,
    ) -> Result<Self, TransportError> {
        if queue_capacity == 0 || !tls.validate_manager(local, addresses.keys().copied()) {
            return Err(TransportError::InvalidIdentity);
        }
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                slots: addresses.keys().map(|p| (*p, Slot::default())).collect(),
                cursor: None,
            }),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            capacity: queue_capacity,
        });
        let worker = shared.clone();
        let controller = thread::Builder::new()
            .name(format!("peer-controller-{}", local.0))
            .spawn(move || control(local, tls, addresses, listener, worker))?;
        Ok(Self {
            shared,
            controller: Some(controller),
        })
    }
    pub fn send(&self, peer: PeerId, message: Envelope) -> Result<(), TransportError> {
        let body = Zeroizing::new(
            message
                .encode_legacy()
                .map_err(|_| TransportError::InvalidEnvelope)?,
        );
        if body.len() > MAX_FRAME_LEN {
            return Err(TransportError::FrameTooLarge);
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| TransportError::Closed)?;
        let slot = state
            .slots
            .get_mut(&peer)
            .ok_or(TransportError::UnknownPeer)?;
        if self.shared.stop.load(Ordering::Acquire) || !slot.connected {
            return Err(TransportError::Closed);
        }
        if slot.outstanding >= self.shared.capacity {
            return Err(TransportError::QueueFull);
        }
        let mut frame = Zeroizing::new(Vec::with_capacity(8 + body.len()));
        frame.extend_from_slice(&(body.len() as u64).to_be_bytes());
        frame.extend_from_slice(&body);
        slot.outgoing.push_back(frame);
        slot.outstanding += 1;
        Ok(())
    }
    pub fn try_recv(&self, peer: PeerId) -> Result<Option<Envelope>, TransportError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| TransportError::Closed)?;
        Ok(state
            .slots
            .get_mut(&peer)
            .ok_or(TransportError::UnknownPeer)?
            .incoming
            .pop_front())
    }
    /// Round-robin across nonempty peers; FIFO within each peer. None is timeout.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(PeerId, Envelope)>, TransportError> {
        let start = Instant::now();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| TransportError::Closed)?;
        loop {
            let next = state
                .slots
                .iter()
                .filter(|(_, s)| !s.incoming.is_empty())
                .map(|(p, _)| *p)
                .find(|p| state.cursor.is_none_or(|c| *p > c))
                .or_else(|| {
                    state
                        .slots
                        .iter()
                        .find(|(_, s)| !s.incoming.is_empty())
                        .map(|(p, _)| *p)
                });
            if let Some(peer) = next {
                let message = state
                    .slots
                    .get_mut(&peer)
                    .ok_or(TransportError::Closed)?
                    .incoming
                    .pop_front()
                    .ok_or(TransportError::Closed)?;
                state.cursor = Some(peer);
                return Ok(Some((peer, message)));
            }
            if self.shared.stop.load(Ordering::Acquire) {
                return Err(TransportError::Closed);
            }
            let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                return Ok(None);
            };
            let (guard, _) = self
                .shared
                .wake
                .wait_timeout(state, remaining)
                .map_err(|_| TransportError::Closed)?;
            state = guard;
        }
    }
    pub fn connected(&self, peer: PeerId) -> bool {
        !self.shared.stop.load(Ordering::Acquire)
            && self
                .shared
                .state
                .lock()
                .is_ok_and(|s| s.slots.get(&peer).is_some_and(|s| s.connected))
    }
    pub fn shutdown(mut self) -> Result<(), TransportError> {
        self.stop_and_join()
    }
    /// Requests cancellation from shared users. The owner must still call
    /// shutdown (or drop the manager) to join all controller/connection threads.
    pub fn request_shutdown(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.notify_all();
    }
    pub fn is_closed(&self) -> bool {
        self.shared.stop.load(Ordering::Acquire)
    }
    fn stop_and_join(&mut self) -> Result<(), TransportError> {
        self.request_shutdown();
        if let Some(handle) = self.controller.take() {
            handle.join().map_err(|_| TransportError::Closed)??;
        }
        Ok(())
    }
}
impl Drop for PeerNetwork {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn control(
    local: PeerId,
    tls: TlsConfig,
    addresses: BTreeMap<PeerId, SocketAddr>,
    listener: TcpListener,
    shared: Arc<Shared>,
) -> Result<(), TransportError> {
    // At most one unauthenticated handshake, performed by this controller. The OS
    // listener backlog is bounded by the caller's listener; no handshake threads.
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut retry = Instant::now();
    let result = (|| {
        while !shared.stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((tcp, _)) => {
                    if let Ok(stream) = tls.managed_handshake(tcp, None, &shared.stop)
                        && stream.peer_id() < local
                        && addresses.contains_key(&stream.peer_id())
                    {
                        install(stream, &shared, &mut workers)?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(e) => return Err(e.into()),
            }
            if Instant::now() >= retry {
                for (peer, address) in addresses.iter().filter(|(p, _)| **p > local) {
                    if shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if shared
                        .state
                        .lock()
                        .map_err(|_| TransportError::Closed)?
                        .slots[peer]
                        .connected
                    {
                        continue;
                    }
                    if let Ok(tcp) = TcpStream::connect_timeout(address, Duration::from_millis(250))
                        && let Ok(stream) = tls.managed_handshake(tcp, Some(*peer), &shared.stop)
                    {
                        install(stream, &shared, &mut workers)?;
                    }
                }
                retry = Instant::now() + Duration::from_millis(100);
            }
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    workers
                        .swap_remove(index)
                        .join()
                        .map_err(|_| TransportError::Closed)?;
                } else {
                    index += 1;
                }
            }
            thread::sleep(TICK);
        }
        Ok(())
    })();
    shared.stop.store(true, Ordering::Release);
    shared.wake.notify_all();
    let mut worker_failed = false;
    for handle in workers {
        worker_failed |= handle.join().is_err();
    }
    if worker_failed {
        return Err(TransportError::Closed);
    }
    result
}
fn install(
    stream: AuthenticatedStream,
    shared: &Arc<Shared>,
    workers: &mut Vec<JoinHandle<()>>,
) -> Result<(), TransportError> {
    let peer = stream.peer_id();
    let mut state = shared.state.lock().map_err(|_| TransportError::Closed)?;
    let slot = state
        .slots
        .get_mut(&peer)
        .ok_or(TransportError::UnknownPeer)?;
    slot.generation = slot
        .generation
        .checked_add(1)
        .ok_or(TransportError::Closed)?;
    let generation = slot.generation;
    slot.connected = true;
    slot.outgoing.clear();
    slot.outstanding = 0;
    let shared = shared.clone();
    // Holding the slot lock through spawn makes publication atomic to senders.
    let handle = thread::Builder::new()
        .name(format!("peer-{}-{generation}", peer.0))
        .spawn(move || connection(stream.into_stream(), peer, generation, shared))?;
    workers.push(handle);
    Ok(())
}
fn current(slot: &Slot, generation: u64) -> bool {
    slot.connected && slot.generation == generation
}
fn disconnect(shared: &Shared, peer: PeerId, generation: u64) {
    if let Ok(mut state) = shared.state.lock() {
        let Some(slot) = state.slots.get_mut(&peer) else {
            return;
        };
        if current(slot, generation) {
            slot.connected = false;
            slot.outgoing.clear();
            slot.outstanding = 0;
        }
    }
}
fn retryable(e: &openssl::ssl::Error) -> bool {
    matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
}
fn connection(
    mut stream: SslStream<TcpStream>,
    peer: PeerId,
    generation: u64,
    shared: Arc<Shared>,
) {
    let mut parser = FrameReader::default();
    let mut outgoing: Option<(Frame, usize)> = None;
    let mut buffer = Zeroizing::new([0; 16_384]);
    let _ = (|| -> Result<(), TransportError> {
        loop {
            if shared.stop.load(Ordering::Acquire) {
                return Ok(());
            }
            {
                let mut state = shared.state.lock().map_err(|_| TransportError::Closed)?;
                let slot = state.slots.get_mut(&peer).ok_or(TransportError::Closed)?;
                if !current(slot, generation) {
                    return Ok(());
                }
                if outgoing.is_none() {
                    outgoing = slot.outgoing.pop_front().map(|f| (f, 0));
                }
            }
            // Retry a pending write with the identical slice until SSL reports
            // progress. The allocation and offset remain unchanged on WANT_*.
            if let Some((frame, offset)) = &mut outgoing {
                match stream.ssl_write(&frame[*offset..]) {
                    Ok(0) => return Err(TransportError::Closed),
                    Ok(n) => {
                        *offset += n;
                        if *offset == frame.len() {
                            outgoing = None;
                            let mut state =
                                shared.state.lock().map_err(|_| TransportError::Closed)?;
                            let slot = state.slots.get_mut(&peer).ok_or(TransportError::Closed)?;
                            if !current(slot, generation) {
                                return Ok(());
                            }
                            slot.outstanding -= 1;
                        }
                    }
                    Err(e) if retryable(&e) => (),
                    Err(_) => return Err(TransportError::Tls),
                }
            }
            match stream.ssl_read(&mut buffer[..]) {
                Ok(0) => return Err(TransportError::Closed),
                Ok(n) => parser.feed(&buffer[..n], |message| {
                    let mut state = shared.state.lock().map_err(|_| TransportError::Closed)?;
                    let slot = state.slots.get_mut(&peer).ok_or(TransportError::Closed)?;
                    if !current(slot, generation) {
                        return Err(TransportError::Closed);
                    }
                    if slot.incoming.len() >= shared.capacity {
                        return Err(TransportError::QueueFull);
                    }
                    slot.incoming.push_back(message);
                    shared.wake.notify_all();
                    Ok(())
                })?,
                Err(e) if retryable(&e) => (),
                Err(_) => return Err(TransportError::Tls),
            }
            thread::sleep(TICK);
        }
    })();
    let _ = stream.get_ref().shutdown(Shutdown::Both);
    disconnect(&shared, peer, generation);
}
#[derive(Default)]
struct FrameReader {
    header: [u8; 8],
    used: usize,
    length: Option<usize>,
    body: Frame,
}
impl FrameReader {
    fn feed(
        &mut self,
        mut input: &[u8],
        mut deliver: impl FnMut(Envelope) -> Result<(), TransportError>,
    ) -> Result<(), TransportError> {
        while !input.is_empty() {
            if self.length.is_none() {
                let n = (8 - self.used).min(input.len());
                self.header[self.used..self.used + n].copy_from_slice(&input[..n]);
                self.used += n;
                input = &input[n..];
                if self.used < 8 {
                    continue;
                }
                let length = u64::from_be_bytes(self.header);
                if length > MAX_FRAME_LEN as u64 {
                    return Err(TransportError::FrameTooLarge);
                }
                self.length = Some(length as usize);
                // Allocation happens only after the complete validated length.
                self.body = Zeroizing::new(Vec::with_capacity(length as usize));
            }
            let length = self.length.ok_or(TransportError::InvalidEnvelope)?;
            let n = (length - self.body.len()).min(input.len());
            self.body.extend_from_slice(&input[..n]);
            input = &input[n..];
            if self.body.len() == length {
                let message =
                    Envelope::decode(&self.body).map_err(|_| TransportError::InvalidEnvelope)?;
                deliver(message)?;
                self.body = Zeroizing::new(Vec::new());
                self.used = 0;
                self.length = None;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incremental_frame_fragmentation_coalescing_and_length_before_allocation() {
        let bodies: Vec<_> = [7, 8, 9]
            .into_iter()
            .map(|n| Envelope::SessionIndex(n).encode_legacy().unwrap())
            .collect();
        let frames: Vec<_> = bodies
            .iter()
            .flat_map(|body| {
                let mut f = (body.len() as u64).to_be_bytes().to_vec();
                f.extend_from_slice(body);
                f
            })
            .collect();
        for fragment in [1, 2, 7, 8, 9, 13, frames.len()] {
            let mut reader = FrameReader::default();
            let mut received = Vec::new();
            for chunk in frames.chunks(fragment) {
                reader
                    .feed(chunk, |message| {
                        let Envelope::SessionIndex(n) = message else {
                            panic!("unexpected envelope");
                        };
                        received.push(n);
                        Ok(())
                    })
                    .unwrap();
            }
            assert_eq!(received, [7, 8, 9]);
            assert_eq!(reader.used, 0);
            assert!(reader.length.is_none());
        }
        let mut reader = FrameReader::default();
        let huge = (MAX_FRAME_LEN as u64 + 1).to_be_bytes();
        reader
            .feed(&huge[..7], |_| panic!("no complete frame"))
            .unwrap();
        assert_eq!(reader.body.capacity(), 0);
        assert!(matches!(
            reader.feed(&huge[7..], |_| panic!("invalid frame")),
            Err(TransportError::FrameTooLarge)
        ));
        assert_eq!(reader.body.capacity(), 0);
        let mut reader = FrameReader::default();
        assert!(matches!(
            reader.feed(&[0; 8], |_| panic!("empty envelope")),
            Err(TransportError::InvalidEnvelope)
        ));
    }
}
