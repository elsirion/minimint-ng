//! NET-002 guardian connections over Iroh 1.0.3. Each message body travels in
//! its own unidirectional stream, finished after the body; there is no inner
//! length field. Streams are accepted and read to completion in order, so the
//! per-peer FIFO matches the sender's stream order. NET-004 applies unchanged:
//! only the lower identifier dials, an accepted replacement supersedes the
//! current connection, and decode/send failures disconnect without replay.
//!
//! Local scheduling policy (not consensus constants): 10s dial and handshake
//! deadlines, 500ms redial interval, 50ms stop/replacement observation, at most
//! 16 concurrent inbound handshakes.
use super::{
    TransportError,
    envelope::Envelope,
    iroh::{IrohOptions, MAX_P2P_MESSAGE_BYTES, P2P_ALPN, p2p_endpoint_addr},
    peer::{Frame, Shared, current, disconnect},
};
use crate::protocol::PeerId;
use iroh_next::{Endpoint, endpoint::Connection};
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::task::JoinSet;
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REDIAL: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_millis(50);
const MAX_HANDSHAKES: usize = 16;

fn stopped(shared: &Shared) -> bool {
    shared.stop.load(Ordering::Acquire)
}

pub(super) async fn control(
    local: PeerId,
    endpoint: Endpoint,
    peers: BTreeMap<PeerId, [u8; 32]>,
    options: IrohOptions,
    shared: Arc<Shared>,
) -> Result<(), TransportError> {
    let mut tasks = JoinSet::new();
    for (peer, key) in peers.iter().filter(|(peer, _)| **peer > local) {
        let target = p2p_endpoint_addr(key, &options)?;
        tasks.spawn(dial(endpoint.clone(), *peer, target, shared.clone()));
    }
    let known = peers
        .iter()
        .map(|(peer, key)| {
            iroh_next::EndpointId::from_bytes(key)
                .map(|id| (id, *peer))
                .map_err(|_| TransportError::InvalidIdentity)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    tasks.spawn(accept(local, endpoint.clone(), known, shared.clone()));
    let mut result = Ok(());
    while !stopped(&shared) {
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            finished = tasks.join_next() => {
                // Dialers and the acceptor only return on stop or a closed endpoint.
                if !stopped(&shared) {
                    result = match finished {
                        Some(Ok(Ok(()))) | None => Err(TransportError::Closed),
                        Some(Ok(Err(error))) => Err(error),
                        Some(Err(_)) => Err(TransportError::Closed),
                    };
                    break;
                }
            }
        }
    }
    shared.stop.store(true, Ordering::Release);
    shared.wake.notify_all();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.close().await;
    result
}

async fn dial(
    endpoint: Endpoint,
    peer: PeerId,
    target: iroh_next::EndpointAddr,
    shared: Arc<Shared>,
) -> Result<(), TransportError> {
    let expected = target.id;
    while !stopped(&shared) {
        if let Ok(Ok(connection)) =
            tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(target.clone(), P2P_ALPN)).await
        {
            // The QUIC handshake authenticated the dialed key; check it anyway.
            if connection.remote_id() == expected {
                if let Some(generation) = install(&shared, peer) {
                    run(connection, peer, generation, shared.clone()).await;
                }
            } else {
                connection.close(0u32.into(), b"unexpected guardian");
            }
        }
        tokio::time::sleep(REDIAL).await;
    }
    Ok(())
}

async fn accept(
    local: PeerId,
    endpoint: Endpoint,
    known: BTreeMap<iroh_next::EndpointId, PeerId>,
    shared: Arc<Shared>,
) -> Result<(), TransportError> {
    let mut handshakes = JoinSet::new();
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return if stopped(&shared) { Ok(()) } else { Err(TransportError::Closed) };
                };
                if handshakes.len() >= MAX_HANDSHAKES {
                    incoming.refuse();
                    continue;
                }
                handshakes.spawn(async move {
                    tokio::time::timeout(CONNECT_TIMEOUT, incoming).await.ok()?.ok()
                });
            }
            Some(done) = handshakes.join_next(), if !handshakes.is_empty() => {
                let Ok(Some(connection)) = done else { continue };
                match known.get(&connection.remote_id()) {
                    Some(peer) if *peer < local => {
                        if let Some(generation) = install(&shared, *peer) {
                            connections.spawn(run(connection, *peer, generation, shared.clone()));
                        }
                    }
                    _ => connection.close(0u32.into(), b"unexpected guardian"),
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Publishes a new connection generation, replacing and dropping any queued
/// messages of the previous connection (NET-004).
fn install(shared: &Shared, peer: PeerId) -> Option<u64> {
    let mut state = shared.state.lock().ok()?;
    let slot = state.slots.get_mut(&peer)?;
    slot.generation = slot.generation.checked_add(1)?;
    slot.connected = true;
    slot.outgoing.clear();
    slot.outstanding = 0;
    Some(slot.generation)
}

async fn run(connection: Connection, peer: PeerId, generation: u64, shared: Arc<Shared>) {
    let queued = match shared.state.lock() {
        Ok(state) => state.slots.get(&peer).map(|slot| slot.queued.clone()),
        Err(_) => None,
    };
    if let Some(queued) = queued {
        tokio::select! {
            _ = receive(&connection, peer, generation, &shared) => {}
            _ = transmit(&connection, peer, generation, &shared, &queued) => {}
            _ = supervise(peer, generation, &shared) => {}
        }
    }
    connection.close(0u32.into(), b"guardian connection retired");
    disconnect(&shared, peer, generation);
}

async fn receive(
    connection: &Connection,
    peer: PeerId,
    generation: u64,
    shared: &Shared,
) -> Result<(), TransportError> {
    loop {
        let mut stream = connection
            .accept_uni()
            .await
            .map_err(|_| TransportError::Closed)?;
        let body = Zeroizing::new(
            stream
                .read_to_end(MAX_P2P_MESSAGE_BYTES)
                .await
                .map_err(|_| TransportError::FrameTooLarge)?,
        );
        let message = Envelope::decode(&body).map_err(|_| TransportError::InvalidEnvelope)?;
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
    }
}

async fn transmit(
    connection: &Connection,
    peer: PeerId,
    generation: u64,
    shared: &Shared,
    queued: &tokio::sync::Notify,
) -> Result<(), TransportError> {
    loop {
        let next: Option<Frame> = {
            let mut state = shared.state.lock().map_err(|_| TransportError::Closed)?;
            let slot = state.slots.get_mut(&peer).ok_or(TransportError::Closed)?;
            if !current(slot, generation) {
                return Ok(());
            }
            slot.outgoing.pop_front()
        };
        let Some(body) = next else {
            tokio::select! {
                _ = queued.notified() => {}
                _ = tokio::time::sleep(POLL) => {}
            }
            continue;
        };
        let mut stream = connection
            .open_uni()
            .await
            .map_err(|_| TransportError::Closed)?;
        stream
            .write_all(&body)
            .await
            .map_err(|_| TransportError::Closed)?;
        stream.finish().map_err(|_| TransportError::Closed)?;
        let mut state = shared.state.lock().map_err(|_| TransportError::Closed)?;
        let slot = state.slots.get_mut(&peer).ok_or(TransportError::Closed)?;
        if !current(slot, generation) {
            return Ok(());
        }
        slot.outstanding = slot.outstanding.saturating_sub(1);
    }
}

async fn supervise(peer: PeerId, generation: u64, shared: &Shared) {
    loop {
        tokio::time::sleep(POLL).await;
        if stopped(shared) {
            return;
        }
        let still = shared.state.lock().is_ok_and(|state| {
            state
                .slots
                .get(&peer)
                .is_some_and(|slot| current(slot, generation))
        });
        if !still {
            return;
        }
    }
}
