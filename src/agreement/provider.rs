use super::{AgreementError, Data};
use crate::{codec::ConsensusEncode, crypto::sha256, protocol::ConsensusItem};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
struct Pending {
    bytes: Vec<u8>,
    transaction: Option<[u8; 32]>,
}
struct State {
    pending: VecDeque<Pending>,
    proposed: BTreeSet<[u8; 32]>,
    signature: Option<[u8; 64]>,
    capacity: usize,
}
#[derive(Clone)]
pub struct ProposalQueue(Arc<Mutex<State>>);
pub struct BatchProvider(Arc<Mutex<State>>);
impl ProposalQueue {
    pub fn new(capacity: usize) -> Result<(Self, BatchProvider), AgreementError> {
        if capacity == 0 {
            return Err(AgreementError::InvalidConfig);
        }
        let state = Arc::new(Mutex::new(State {
            pending: VecDeque::new(),
            proposed: BTreeSet::new(),
            signature: None,
            capacity,
        }));
        Ok((Self(state.clone()), BatchProvider(state)))
    }
    pub fn push(&self, item: ConsensusItem) -> Result<(), AgreementError> {
        let bytes = item.consensus_encode();
        if bytes.len() > 50_000 - 9 {
            return Err(AgreementError::OversizedData);
        }
        let transaction = match item {
            ConsensusItem::Transaction(tx) => Some(sha256(&tx.commitment_bytes())),
            _ => None,
        };
        let mut state = self.0.lock().map_err(|_| AgreementError::Failed)?;
        if state.signature.is_some() {
            return Err(AgreementError::SignaturePhase);
        }
        if state.pending.len() >= state.capacity {
            return Err(AgreementError::QueueFull);
        }
        state.pending.push_back(Pending { bytes, transaction });
        Ok(())
    }
    pub fn set_signature(&self, signature: [u8; 64]) -> Result<(), AgreementError> {
        self.0.lock().map_err(|_| AgreementError::Failed)?.signature = Some(signature);
        Ok(())
    }
}
impl fedimint_aleph_bft::DataProvider<Data> for BatchProvider {
    fn get_data<'a, 'f>(&'a mut self) -> Pin<Box<dyn Future<Output = Option<Data>> + Send + 'f>>
    where
        'a: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            let mut state = self.0.lock().expect("agreement proposal state poisoned");
            if let Some(signature) = state.signature {
                return Some(Data::Signature(signature));
            }
            let mut bytes = Vec::new();
            let mut count = 0u64;
            while let Some(front) = state.pending.front() {
                if front
                    .transaction
                    .is_some_and(|id| state.proposed.contains(&id))
                {
                    state.pending.pop_front();
                    continue;
                }
                if 9 + bytes.len() + front.bytes.len() > 50_000 {
                    break;
                }
                let next = state.pending.pop_front().expect("proposal front existed");
                if let Some(id) = next.transaction {
                    state.proposed.insert(id);
                }
                bytes.extend(next.bytes);
                count += 1;
            }
            if count == 0 {
                None
            } else {
                Some(Data::Batch([count.consensus_encode(), bytes].concat()))
            }
        })
    }
}
