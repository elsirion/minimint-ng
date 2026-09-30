use super::{SetupError, SetupTransport};
use crate::{
    codec::ConsensusEncode,
    crypto::{
        bls::{self, G2, Scalar},
        sha256,
    },
    net::envelope::{DkgMessage, Envelope},
    protocol::PeerId,
};
use std::collections::BTreeMap;
pub struct DkgAction {
    pub recipient: PeerId,
    pub message: DkgMessage<G2>,
}
pub struct DkgResult {
    pub secret_share: Scalar,
    pub public_coefficients: Vec<G2>,
}
pub struct G2Dkg {
    local: PeerId,
    n: usize,
    q: usize,
    coefficients: Vec<Scalar>,
    hashes: BTreeMap<PeerId, [u8; 32]>,
    commitments: BTreeMap<PeerId, Vec<G2>>,
    shares: BTreeMap<PeerId, Scalar>,
    failed: bool,
}
fn commitment_hash(points: &[G2]) -> [u8; 32] {
    sha256(
        &points
            .iter()
            .map(G2::to_bytes)
            .collect::<Vec<_>>()
            .consensus_encode(),
    )
}
impl G2Dkg {
    pub fn random(local: PeerId, n: usize) -> Result<(Self, Vec<DkgAction>), SetupError> {
        validate_participants(local, n)?;
        let q = n - (n - 1) / 3;
        let coefficients = (0..q)
            .map(|_| Scalar::random().map_err(|_| SetupError::Crypto))
            .collect::<Result<_, _>>()?;
        Self::from_coefficients(local, n, coefficients)
    }
    /// Explicit coefficients support reproducible protocol tests; fresh setup
    /// calls random(), which samples every coefficient independently from the OS.
    pub fn from_coefficients(
        local: PeerId,
        n: usize,
        coefficients: Vec<Scalar>,
    ) -> Result<(Self, Vec<DkgAction>), SetupError> {
        validate_participants(local, n)?;
        let q = n - (n - 1) / 3;
        if coefficients.len() != q {
            return Err(SetupError::WrongCoefficientCount);
        }
        let commitments: Vec<_> = coefficients
            .iter()
            .map(|s| G2::generator().mul(s))
            .collect();
        let hash = commitment_hash(&commitments);
        let mut state = Self {
            local,
            n,
            q,
            coefficients,
            hashes: BTreeMap::from([(local, hash)]),
            commitments: BTreeMap::from([(local, commitments)]),
            shares: BTreeMap::new(),
            failed: false,
        };
        if n == 1 {
            state.shares.insert(
                local,
                bls::evaluate_polynomial(&state.coefficients, local.0)
                    .map_err(|_| SetupError::Crypto)?,
            );
        }
        let actions = state.broadcast(DkgMessage::Hash(hash));
        Ok((state, actions))
    }
    fn broadcast(&self, message: DkgMessage<G2>) -> Vec<DkgAction> {
        (0..self.n)
            .map(|i| PeerId(i as u16))
            .filter(|peer| *peer != self.local)
            .map(|recipient| DkgAction {
                recipient,
                message: message.clone(),
            })
            .collect()
    }
    pub fn receive(
        &mut self,
        sender: PeerId,
        message: DkgMessage<G2>,
    ) -> Result<Vec<DkgAction>, SetupError> {
        if self.failed {
            return Err(SetupError::Aborted);
        }
        let result = self.receive_inner(sender, message);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn receive_inner(
        &mut self,
        sender: PeerId,
        message: DkgMessage<G2>,
    ) -> Result<Vec<DkgAction>, SetupError> {
        if usize::from(sender.0) >= self.n || sender == self.local {
            return Err(SetupError::UnknownPeer);
        }
        match message {
            DkgMessage::Hash(hash) => {
                if self.hashes.contains_key(&sender) {
                    return Err(SetupError::Duplicate);
                }
                self.hashes.insert(sender, hash);
                if self.hashes.len() == self.n {
                    return Ok(self.broadcast(DkgMessage::Commitments(
                        self.commitments[&self.local].clone(),
                    )));
                }
            }
            DkgMessage::Commitments(points) => {
                let expected = self
                    .hashes
                    .get(&sender)
                    .ok_or(SetupError::MissingPrerequisite)?;
                if commitment_hash(&points) != *expected {
                    return Err(SetupError::CommitmentMismatch);
                }
                if points.len() != self.q {
                    return Err(SetupError::WrongCoefficientCount);
                }
                if self.commitments.contains_key(&sender) {
                    return Err(SetupError::Duplicate);
                }
                self.commitments.insert(sender, points);
                if self.commitments.len() == self.n {
                    let mut actions = Vec::new();
                    for index in 0..self.n {
                        let peer = PeerId(index as u16);
                        let share = bls::evaluate_polynomial(&self.coefficients, peer.0)
                            .map_err(|_| SetupError::Crypto)?;
                        if peer == self.local {
                            self.shares.insert(peer, share);
                        } else {
                            actions.push(DkgAction {
                                recipient: peer,
                                message: DkgMessage::Share(share),
                            });
                        }
                    }
                    return Ok(actions);
                }
            }
            DkgMessage::Share(share) => {
                let points = self
                    .commitments
                    .get(&sender)
                    .ok_or(SetupError::MissingPrerequisite)?;
                let public = bls::evaluate_commitments(points, self.local.0)
                    .map_err(|_| SetupError::Crypto)?;
                if G2::generator().mul(&share).to_bytes() != public.to_bytes() {
                    return Err(SetupError::InvalidShare);
                }
                if self.shares.contains_key(&sender) {
                    return Err(SetupError::Duplicate);
                }
                self.shares.insert(sender, share);
            }
        }
        Ok(Vec::new())
    }
    pub fn is_complete(&self) -> bool {
        !self.failed && self.shares.len() == self.n
    }
    pub fn finish(self) -> Result<DkgResult, SetupError> {
        if self.failed {
            return Err(SetupError::Aborted);
        }
        if !self.is_complete() {
            return Err(SetupError::Incomplete);
        }
        let secret_share = self
            .shares
            .values()
            .fold(Scalar::from_u64(0), |sum, s| sum.add(s));
        let public_coefficients = (0..self.q)
            .map(|k| {
                self.commitments
                    .values()
                    .fold(G2::identity(), |sum, points| sum.add(&points[k]))
            })
            .collect();
        Ok(DkgResult {
            secret_share,
            public_coefficients,
        })
    }
}
fn validate_participants(local: PeerId, n: usize) -> Result<(), SetupError> {
    if n == 0 || n > 65_536 || (n != 1 && n < 4) || usize::from(local.0) >= n {
        Err(SetupError::InvalidConfiguration)
    } else {
        Ok(())
    }
}
pub fn run_g2_dkg(
    local: PeerId,
    n: usize,
    transport: &mut impl SetupTransport,
) -> Result<DkgResult, SetupError> {
    let (mut state, actions) = G2Dkg::random(local, n)?;
    send_actions(transport, actions)?;
    while !state.is_complete() {
        for peer in (0..n)
            .map(|i| PeerId(i as u16))
            .filter(|peer| *peer != local)
        {
            let Envelope::DkgG2(message) = transport.receive_from(peer)? else {
                return Err(SetupError::UnexpectedEnvelope);
            };
            let actions = state.receive(peer, message)?;
            send_actions(transport, actions)?;
        }
    }
    state.finish()
}
fn send_actions(
    transport: &mut impl SetupTransport,
    actions: Vec<DkgAction>,
) -> Result<(), SetupError> {
    for action in actions {
        transport.send(action.recipient, Envelope::DkgG2(action.message))?;
    }
    Ok(())
}
