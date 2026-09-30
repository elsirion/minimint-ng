//! Opaque engine payload routing. Transport authenticates the connected peer;
//! the engine verifies nested signatures independently of that connection ID.
use super::{AgreementError, Data, ProtocolHasher};
use crate::protocol::PeerId;
use fedimint_aleph_bft::{Network, NetworkData, Recipient, SignatureSet};
use futures::{StreamExt, channel::mpsc};
use parity_scale_codec::{Decode, Encode};
use std::{future::Future, pin::Pin, sync::Mutex};
pub type EngineNetworkData = NetworkData<ProtocolHasher, Data, [u8; 64], SignatureSet<[u8; 64]>>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    pub recipient: Option<PeerId>,
    pub payload: Vec<u8>,
}
pub fn decode_payload(bytes: &[u8]) -> Result<EngineNetworkData, AgreementError> {
    // NET-009 intentionally permits a SCALE suffix after a valid payload.
    let payload =
        EngineNetworkData::decode(&mut &bytes[..]).map_err(|_| AgreementError::MalformedPayload)?;
    // Use the public engine traversal: fork-proof units omitted by that traversal
    // must not acquire an extra application-level batch-size rejection.
    if !payload.included_data().iter().all(Data::within_limit) {
        return Err(AgreementError::OversizedData);
    }
    Ok(payload)
}
pub(super) struct NetworkAdapter {
    incoming: mpsc::Receiver<Vec<u8>>,
    outgoing: Mutex<mpsc::Sender<Outbound>>,
    count: usize,
}
pub(super) fn channels(
    capacity: usize,
    count: usize,
) -> (
    NetworkAdapter,
    mpsc::Sender<Vec<u8>>,
    mpsc::Receiver<Outbound>,
) {
    let (input, incoming) = mpsc::channel(capacity);
    let (outgoing, output) = mpsc::channel(capacity);
    (
        NetworkAdapter {
            incoming,
            outgoing: Mutex::new(outgoing),
            count,
        },
        input,
        output,
    )
}
impl Network<EngineNetworkData> for NetworkAdapter {
    fn send(&self, data: EngineNetworkData, recipient: Recipient) {
        let recipient = match recipient {
            Recipient::Everyone => None,
            Recipient::Node(index) => {
                let Ok(id) = u16::try_from(index.0) else {
                    return;
                };
                if index.0 >= self.count {
                    return;
                }
                Some(PeerId(id))
            }
        };
        // Never block the engine. Full or disconnected transport queues drop packets;
        // Aleph's own retransmission mechanisms, not this adapter, recover them.
        let _ = self
            .outgoing
            .lock()
            .expect("agreement outgoing queue poisoned")
            .try_send(Outbound {
                recipient,
                payload: data.encode(),
            });
    }
    fn next_event<'a, 'f>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Option<EngineNetworkData>> + Send + 'f>>
    where
        'a: 'f,
        Self: 'f,
    {
        Box::pin(async move {
            while let Some(bytes) = self.incoming.next().await {
                if let Ok(payload) = decode_payload(&bytes) {
                    return Some(payload);
                }
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fedimint_aleph_bft::NodeIndex;
    use futures::{FutureExt, executor::block_on};
    fn coordinate_request() -> EngineNetworkData {
        // NET006: top-level unit message, coordinate request, requester 0, round 0,
        // creator 0. Requests carry no signature and no attached Data.
        let mut bytes = vec![0, 1];
        bytes.extend([0; 8]);
        bytes.extend([0; 2]);
        bytes.extend([0; 8]);
        decode_payload(&bytes).unwrap()
    }
    #[test]
    fn network_drops_invalid_destinations_and_full_queues() {
        let (adapter, _input, mut output) = channels(1, 4);
        adapter.send(coordinate_request(), Recipient::Node(NodeIndex(65536)));
        adapter.send(coordinate_request(), Recipient::Node(NodeIndex(4)));
        assert!(output.next().now_or_never().is_none());
        for _ in 0..10 {
            adapter.send(coordinate_request(), Recipient::Everyone);
        }
        let first = block_on(output.next()).unwrap();
        assert_eq!(first.recipient, None);
        assert!(decode_payload(&first.payload).is_ok());
        // Futures bounded mpsc reserves one extra slot for the sole sender.
        assert!(block_on(output.next()).is_some());
        assert!(output.next().now_or_never().is_none());
    }
    #[test]
    fn network_discards_malformed_incoming_then_delivers_valid_payload() {
        let (mut adapter, mut input, _output) = channels(4, 4);
        input.try_send(vec![255]).unwrap();
        let valid = coordinate_request();
        input.try_send(valid.encode()).unwrap();
        assert_eq!(
            block_on(adapter.next_event()).unwrap().encode(),
            valid.encode()
        );
    }
}
