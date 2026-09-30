use super::{SetupError, SetupTransport};
use crate::{
    net::{PeerNetwork, TransportError, envelope::Envelope},
    protocol::PeerId,
};
use std::{collections::BTreeSet, thread, time::Duration};

/// Exclusive setup consumer of a network's authenticated per-peer queues.
/// `remote_peers` must be the same remote membership used to start the network.
/// The runtime must not run an agreement consumer until setup has completed.
pub struct PeerSetupTransport<'a> {
    network: &'a PeerNetwork,
    remote_peers: BTreeSet<PeerId>,
}
impl<'a> PeerSetupTransport<'a> {
    pub fn new(network: &'a PeerNetwork, remote_peers: impl IntoIterator<Item = PeerId>) -> Self {
        Self {
            network,
            remote_peers: remote_peers.into_iter().collect(),
        }
    }
    fn check_peer(&self, peer: PeerId) -> Result<(), SetupError> {
        if self.remote_peers.contains(&peer) {
            Ok(())
        } else {
            Err(SetupError::UnknownPeer)
        }
    }
    fn check_open(&self) -> Result<(), SetupError> {
        if self.network.is_closed() {
            Err(SetupError::Transport)
        } else {
            Ok(())
        }
    }
}
fn transport_error(error: TransportError) -> SetupError {
    match error {
        TransportError::UnknownPeer => SetupError::UnknownPeer,
        _ => SetupError::Transport,
    }
}
impl SetupTransport for PeerSetupTransport<'_> {
    fn wait_for_all(&mut self, peers: &[PeerId]) -> Result<(), SetupError> {
        for peer in peers {
            self.check_peer(*peer)?;
        }
        loop {
            self.check_open()?;
            if peers.iter().all(|peer| self.network.connected(*peer)) {
                return Ok(());
            }
            // Local scheduling tick, without a protocol deadline.
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn send(&mut self, peer: PeerId, message: Envelope) -> Result<(), SetupError> {
        self.check_peer(peer)?;
        self.check_open()?;
        self.network.send(peer, message).map_err(transport_error)
    }
    fn receive_from(&mut self, peer: PeerId) -> Result<Envelope, SetupError> {
        self.check_peer(peer)?;
        loop {
            self.check_open()?;
            if let Some(message) = self.network.try_recv(peer).map_err(transport_error)? {
                return Ok(message);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}
