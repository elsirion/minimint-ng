use super::{schema::record, *};
#[derive(Default)]
pub(super) struct State {
    pub block_votes: BTreeMap<PeerId, u64>,
    pub fee_votes: BTreeMap<PeerId, Option<u64>>,
    pub block_count: u64,
    pub wallet: Option<FederationWallet>,
    pub discoveries: Vec<Discovery>,
    pub chain: Vec<ChainRecord>,
    pub pending: BTreeMap<bitcoin::Txid, Pending>,
    pub withdrawals: BTreeMap<Vec<u8>, bitcoin::Txid>,
}
record!(
    State,
    block_votes,
    fee_votes,
    block_count,
    wallet,
    discoveries,
    chain,
    pending,
    withdrawals
);
pub(super) struct Pending {
    pub bytes: Vec<u8>,
    pub inputs: Vec<FederationWallet>,
    pub fee_sat: u64,
    pub vbytes: u64,
    pub signatures: BTreeMap<PeerId, Vec<[u8; 64]>>,
    pub signed: bool,
}
record!(Pending, bytes, inputs, fee_sat, vbytes, signatures, signed);
impl Wallet {
    pub(super) fn key(&self, scope: &[u8]) -> Vec<u8> {
        [
            b"wallet/v1/".as_slice(),
            self.module.0.to_be_bytes().as_slice(),
            b"/",
            scope,
        ]
        .concat()
    }
    pub(super) fn read(&self, tx: &WriteTransaction<'_>) -> Result<State, WalletError> {
        self.decode_state(tx.get(Namespace::Replicated, &self.key(b"state"))?)
    }
    pub(super) fn view_state(&self, snapshot: &Snapshot) -> Result<State, WalletError> {
        self.decode_state(snapshot.get(Namespace::Replicated, &self.key(b"state"))?)
    }
    fn decode_state(&self, bytes: Option<Vec<u8>>) -> Result<State, WalletError> {
        match bytes {
            None => Ok(State::default()),
            Some(bytes) => {
                decode_whole(&bytes).map_err(|_| WalletError::Invariant("wallet-state-decode"))
            }
        }
    }
    pub(super) fn save(
        &self,
        tx: &mut WriteTransaction<'_>,
        state: &State,
    ) -> Result<(), WalletError> {
        Ok(tx.put(
            Namespace::Replicated,
            &self.key(b"state"),
            &state.consensus_encode(),
        )?)
    }
}
