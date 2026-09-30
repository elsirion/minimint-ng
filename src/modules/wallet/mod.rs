//! Wallet v2 transitions. Every mutation uses the caller's tentative writer.
//! Failed transitions require dropping that writer. Bitcoin broadcast is an outbox effect.
use crate::{
    bitcoin::{self, BitcoinBackend},
    codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole, encode_enum},
    config::{BitcoinNetwork, RawWalletConfig},
    core::transaction::{InputMeta, OutputMeta, TransitionError},
    crypto::{
        secp::{self, SecretKey},
        sha256,
    },
    protocol::{ModuleId, OutPoint, PeerId},
    storage::{Namespace, Snapshot, Store, StoreError, WriteTransaction},
};
use std::collections::BTreeMap;
mod schema;
mod state;
pub use schema::*;
use state::{Pending, State};
#[derive(Debug)]
pub enum WalletError {
    Storage(StoreError),
    Backend(bitcoin::BackendError),
    Rejected(&'static str),
    Module(Vec<u8>),
    Invariant(&'static str),
    StaleScan,
    UnsupportedArithmeticDomain,
}
impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "wallet storage error",
            Self::Backend(_) => "wallet backend unavailable",
            Self::Rejected(_) => "wallet consensus item rejected",
            Self::Module(_) => "wallet transaction rejected",
            Self::Invariant(_) => "wallet invariant failure",
            Self::StaleScan => "wallet scan preparation requires retry",
            Self::UnsupportedArithmeticDomain => {
                "wallet arithmetic outside supported accounting domain"
            }
        })
    }
}
impl std::error::Error for WalletError {}
impl From<StoreError> for WalletError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
impl From<bitcoin::BackendError> for WalletError {
    fn from(e: bitcoin::BackendError) -> Self {
        Self::Backend(e)
    }
}
impl From<WalletError> for TransitionError {
    fn from(e: WalletError) -> Self {
        match e {
            WalletError::Storage(e) => Self::Storage(e),
            WalletError::Module(e) => Self::Module(e),
            WalletError::Invariant(name) => Self::FatalInvariant(name),
            WalletError::UnsupportedArithmeticDomain => {
                Self::FatalInvariant("wallet-unsupported-arithmetic-domain")
            }
            _ => Self::FatalInvariant("wallet-transition-unexpected-error"),
        }
    }
}
pub struct Wallet {
    module: ModuleId,
    peer: PeerId,
    config: RawWalletConfig,
    secret: SecretKey,
    threshold: usize,
    filter_key: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub from: u64,
    pub to: u64,
    pub skip_scan: bool,
}
#[derive(Debug, Clone)]
pub struct ScanBatch {
    request: ScanRequest,
    blocks: Vec<(u64, [u8; 32], bitcoin::Block)>,
}
/// Backend work occurs before opening the consensus writer. No storage is mutated.
pub fn prepare_scan(
    backend: &impl BitcoinBackend,
    request: ScanRequest,
) -> Result<ScanBatch, WalletError> {
    backend.wait_for_count(
        request
            .to
            .checked_add(6)
            .ok_or(WalletError::UnsupportedArithmeticDomain)?,
    )?;
    let mut blocks = Vec::new();
    if !request.skip_scan {
        for height in request.from..request.to {
            let hash = backend.block_hash(height)?;
            let block = backend.block(hash)?;
            if block.hash() != hash {
                return Err(WalletError::Backend(bitcoin::BackendError));
            }
            blocks.push((height, hash, block));
        }
    }
    Ok(ScanBatch { request, blocks })
}
impl Wallet {
    pub fn new(
        module: ModuleId,
        peer: PeerId,
        config: RawWalletConfig,
        secret: SecretKey,
    ) -> Result<Self, WalletError> {
        let n = config.bitcoin_pks.len();
        if n == 0
            || n > 20
            || (n != 1 && n < 4)
            || config.bitcoin_pks.get(&peer) != Some(&secret.public_key())
        {
            return Err(WalletError::Invariant("wallet-private-key-config"));
        }
        for key in config.bitcoin_pks.values() {
            secp::validate_public_key(key)
                .map_err(|_| WalletError::Invariant("wallet-public-key-config"))?;
        }
        let filter_key = sha256(&config.bitcoin_pks.consensus_encode());
        Ok(Self {
            module,
            peer,
            config,
            secret,
            threshold: n - (n - 1) / 3,
            filter_key,
        })
    }
    pub fn config(&self) -> &RawWalletConfig {
        &self.config
    }
    pub fn module_id(&self) -> ModuleId {
        self.module
    }
    pub fn matches_filter(&self, script: &[u8]) -> bool {
        sha256(
            &[
                [
                    crate::codec::boundary::compact_size(script.len() as u64),
                    script.to_vec(),
                ]
                .concat(),
                self.filter_key.to_vec(),
            ]
            .concat(),
        )
        .starts_with(&[0, 0])
    }
    pub fn witness_script(&self, tweak: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
        let mut keys = self.tweaked_keys(tweak)?;
        keys.sort_by_key(|(key, _)| *key);
        let mut script = script_number(self.threshold);
        for (key, _) in keys {
            script.push(33);
            script.extend(key);
        }
        script.extend(script_number(self.config.bitcoin_pks.len()));
        script.push(0xae);
        Ok(script)
    }
    fn tweaked_keys(&self, tweak: &[u8; 32]) -> Result<Vec<([u8; 33], PeerId)>, WalletError> {
        self.config
            .bitcoin_pks
            .iter()
            .map(|(peer, key)| {
                Ok((
                    secp::add_tweak(key, tweak)
                        .map_err(|_| WalletError::Invariant("wallet-tweak-key"))?,
                    *peer,
                ))
            })
            .collect()
    }
    pub fn script_for_tweak(&self, tweak: &[u8; 32]) -> Result<Vec<u8>, WalletError> {
        Ok([vec![0, 32], sha256(&self.witness_script(tweak)?).to_vec()].concat())
    }
    pub fn deposit_script(&self, claimant: &[u8; 33]) -> Result<Vec<u8>, WalletError> {
        secp::validate_public_key(claimant)
            .map_err(|_| WalletError::Invariant("wallet-claimant-key"))?;
        self.script_for_tweak(&sha256(claimant))
    }
    pub fn block_proposal(
        &self,
        snapshot: &Snapshot,
        backend_count: u64,
    ) -> Result<ConsensusItem, WalletError> {
        let current = self.view_state(snapshot)?.block_count;
        let mut value = backend_count.saturating_sub(6);
        if current != 0 {
            value = value.min(current.saturating_add(5));
        }
        Ok(ConsensusItem::BlockCount(value))
    }
    pub fn fee_proposal(rate: Option<u64>) -> ConsensusItem {
        ConsensusItem::FeeRate(rate.map(|v| v.max(1000)))
    }
    fn agreed_count(&self, state: &State) -> u64 {
        let mut votes: Vec<_> = state.block_votes.values().copied().collect();
        votes.sort_unstable_by(|a, b| b.cmp(a));
        votes.get(self.threshold - 1).copied().unwrap_or(0)
    }
    fn agreed_rate(&self, state: &State) -> Option<u64> {
        let mut votes: Vec<_> = state.fee_votes.values().filter_map(|v| *v).collect();
        votes.sort_unstable();
        votes.get(self.threshold - 1).copied()
    }
    fn scan_request(
        &self,
        state: &State,
        peer: PeerId,
        value: u64,
    ) -> Result<Option<ScanRequest>, WalletError> {
        if !self.config.bitcoin_pks.contains_key(&peer) {
            return Err(WalletError::Rejected("unknown-peer"));
        }
        if value <= state.block_votes.get(&peer).copied().unwrap_or(0) {
            return Err(WalletError::Rejected("non-increasing-block-vote"));
        }
        let mut votes = state.block_votes.clone();
        votes.insert(peer, value);
        let mut counts: Vec<_> = votes.values().copied().collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));
        let to = counts.get(self.threshold - 1).copied().unwrap_or(0);
        Ok((to > state.block_count).then_some(ScanRequest {
            from: state.block_count,
            to,
            skip_scan: state.block_count == 0 && self.config.network != BitcoinNetwork::Regtest,
        }))
    }
    pub fn required_scan(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        item: &ConsensusItem,
    ) -> Result<Option<ScanRequest>, WalletError> {
        match item {
            ConsensusItem::BlockCount(v) => {
                self.scan_request(&self.view_state(snapshot)?, peer, *v)
            }
            _ => Ok(None),
        }
    }
    pub fn process_consensus(
        &self,
        tx: &mut WriteTransaction<'_>,
        peer: PeerId,
        item: &ConsensusItem,
        prepared: Option<&ScanBatch>,
    ) -> Result<(), WalletError> {
        if !self.config.bitcoin_pks.contains_key(&peer) {
            return Err(WalletError::Rejected("unknown-peer"));
        }
        let mut state = self.read(tx)?;
        match item {
            ConsensusItem::BlockCount(value) => {
                let request = self.scan_request(&state, peer, *value)?;
                if prepared.is_some_and(|batch| request.as_ref() != Some(&batch.request)) {
                    return Err(WalletError::StaleScan);
                }
                if let Some(request) = request {
                    let batch = prepared
                        .filter(|b| b.request == request)
                        .ok_or(WalletError::StaleScan)?;
                    let expected = if request.skip_scan {
                        0
                    } else {
                        request.to - request.from
                    };
                    if batch.blocks.len() as u64 != expected {
                        return Err(WalletError::StaleScan);
                    }
                    for (offset, (height, hash, block)) in batch.blocks.iter().enumerate() {
                        if *height != request.from + offset as u64 || *hash != block.hash() {
                            return Err(WalletError::StaleScan);
                        }
                        self.scan_block(tx, &mut state, block)?;
                    }
                    state.block_count = request.to;
                }
                state.block_votes.insert(peer, *value);
                debug_assert_eq!(state.block_count, self.agreed_count(&state));
            }
            ConsensusItem::FeeRate(rate) => {
                if state.fee_votes.get(&peer) == Some(rate) {
                    return Err(WalletError::Rejected("unchanged-fee-vote"));
                }
                state.fee_votes.insert(peer, *rate);
            }
            ConsensusItem::Signatures { txid, signatures } => {
                self.accept_signatures(tx, &mut state, peer, *txid, signatures)?
            }
            ConsensusItem::Unknown { .. } => {
                return Err(WalletError::Rejected("unknown-consensus-variant"));
            }
        }
        self.save(tx, &state)
    }
    fn scan_block(
        &self,
        tx: &mut WriteTransaction<'_>,
        state: &mut State,
        block: &bitcoin::Block,
    ) -> Result<(), WalletError> {
        for transaction in &block.transactions {
            let txid = transaction.txid();
            if state.pending.get(&txid).is_some_and(|p| p.signed) {
                state.pending.remove(&txid);
                tx.delete(Namespace::Outbox, &self.outbox_key(txid))?;
            }
            for (vout, output) in transaction.outputs.iter().enumerate() {
                if self.matches_filter(&output.script_pubkey) {
                    let index = state.discoveries.len() as u64;
                    state.discoveries.push(Discovery {
                        index,
                        script: output.script_pubkey.clone(),
                        value_sat: output.value_sat,
                        spent: false,
                        outpoint: Some(bitcoin::OutPoint {
                            txid,
                            vout: u32::try_from(vout)
                                .map_err(|_| WalletError::Invariant("bitcoin-vout-overflow"))?,
                        }),
                    });
                }
            }
        }
        Ok(())
    }
    fn quote(&self, state: &State, vbytes: u64) -> Result<Option<u64>, WalletError> {
        let n = state.pending.len();
        if n > 32 {
            return Err(WalletError::Invariant("wallet-pending-count-exceeds-32"));
        }
        let Some(rate) = self.agreed_rate(state) else {
            return Ok(None);
        };
        let rate = rate.max(
            self.config
                .feerate_base
                .checked_mul(1_u64 << n)
                .ok_or(WalletError::UnsupportedArithmeticDomain)?,
        );
        let (mut size, mut fees) = (vbytes, 0_u64);
        for pending in state.pending.values() {
            size = size
                .checked_add(pending.vbytes)
                .ok_or(WalletError::UnsupportedArithmeticDomain)?;
            fees = fees
                .checked_add(pending.fee_sat)
                .ok_or(WalletError::UnsupportedArithmeticDomain)?;
        }
        let individual = vbytes.saturating_mul(rate) / 1000;
        let package = size.saturating_mul(rate) / 1000;
        Ok(Some(individual.max(package.saturating_sub(fees))))
    }
    fn module_fee(&self, amount: u64) -> Result<u64, WalletError> {
        self.config
            .fee_consensus
            .base
            .checked_add(
                amount.saturating_mul(self.config.fee_consensus.parts_per_million) / 1_000_000,
            )
            .ok_or(WalletError::UnsupportedArithmeticDomain)
    }
    pub fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        input: &Input,
        _point: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        self.input_inner(tx, input).map_err(Into::into)
    }
    fn input_inner(
        &self,
        tx: &mut WriteTransaction<'_>,
        input: &Input,
    ) -> Result<InputMeta, WalletError> {
        let (index, claimant, fee) = match input {
            Input::V0 {
                output_index,
                claimant,
                mining_fee_sat,
            } => (*output_index, *claimant, *mining_fee_sat),
            Input::Unknown { version, .. } => return Err(module_error(0, Some(*version))),
        };
        let mut state = self.read(tx)?;
        let discovery = state
            .discoveries
            .get(usize::try_from(index).map_err(|_| module_error(2, None))?)
            .cloned();
        if discovery.as_ref().is_some_and(|d| d.spent) {
            return Err(module_error(1, None));
        }
        let discovery = discovery.ok_or_else(|| module_error(2, None))?;
        let tweak = sha256(&claimant);
        if discovery.script != self.script_for_tweak(&tweak)? {
            return Err(module_error(3, None));
        }
        let required = self
            .quote(&state, self.config.receive_tx_vbytes)?
            .ok_or_else(|| module_error(4, None))?;
        if fee < required {
            return Err(module_error(5, None));
        }
        let credited = discovery
            .value_sat
            .checked_sub(fee)
            .ok_or_else(|| module_error(6, None))?;
        let deposit = FederationWallet {
            value_sat: discovery.value_sat,
            outpoint: discovery
                .outpoint
                .ok_or(WalletError::Invariant("discovery-missing-outpoint"))?,
            tweak,
        };
        if let Some(old) = state.wallet.clone() {
            let value = old
                .value_sat
                .checked_add(deposit.value_sat)
                .and_then(|v| v.checked_sub(fee))
                .ok_or_else(|| module_error(6, None))?;
            self.construct(
                &mut state,
                vec![old, deposit],
                value,
                None,
                fee,
                self.config.receive_tx_vbytes,
            )?;
        } else {
            state.wallet = Some(deposit);
        }
        state.discoveries[index as usize].spent = true;
        let amount = credited
            .checked_mul(1000)
            .ok_or_else(|| module_error(6, None))?;
        let fee_msat = self.module_fee(amount)?;
        self.save(tx, &state)?;
        Ok(InputMeta {
            amount_msat: amount,
            fee_msat,
            public_key: claimant,
        })
    }
    pub fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        output: &Output,
        point: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        self.output_inner(tx, output, point).map_err(Into::into)
    }
    fn output_inner(
        &self,
        tx: &mut WriteTransaction<'_>,
        output: &Output,
        point: OutPoint,
    ) -> Result<OutputMeta, WalletError> {
        let (destination, value, fee) = match output {
            Output::V0 {
                destination,
                value_sat,
                mining_fee_sat,
            } => (destination, *value_sat, *mining_fee_sat),
            Output::Unknown { version, .. } => return Err(module_error(0, Some(*version))),
        };
        if value < self.config.dust_limit {
            return Err(module_error(1, None));
        }
        let mut state = self.read(tx)?;
        let old = state.wallet.clone().ok_or_else(|| module_error(2, None))?;
        let required = self
            .quote(&state, self.config.send_tx_vbytes)?
            .ok_or_else(|| module_error(3, None))?;
        if fee < required {
            return Err(module_error(4, None));
        }
        let total = value
            .checked_add(fee)
            .ok_or_else(|| module_error(6, None))?;
        let change = old
            .value_sat
            .checked_sub(total)
            .ok_or_else(|| module_error(6, None))?;
        if change < self.config.dust_limit {
            return Err(module_error(5, None));
        }
        let script = destination
            .script_pubkey()
            .ok_or_else(|| module_error(7, None))?;
        let txid = self.construct(
            &mut state,
            vec![old],
            change,
            Some(bitcoin::TxOut {
                value_sat: value,
                script_pubkey: script,
            }),
            fee,
            self.config.send_tx_vbytes,
        )?;
        state.withdrawals.insert(point.consensus_encode(), txid);
        let amount = total
            .checked_mul(1000)
            .ok_or_else(|| module_error(6, None))?;
        let fee_msat = self.module_fee(amount)?;
        self.save(tx, &state)?;
        Ok(OutputMeta {
            amount_msat: amount,
            fee_msat,
        })
    }
    fn construct(
        &self,
        state: &mut State,
        inputs: Vec<FederationWallet>,
        change: u64,
        destination: Option<bitcoin::TxOut>,
        fee: u64,
        vbytes: u64,
    ) -> Result<bitcoin::Txid, WalletError> {
        let previous = inputs
            .first()
            .ok_or(WalletError::Invariant("wallet-empty-inputs"))?;
        let tweak = sha256(&previous.consensus_encode());
        let mut outputs = vec![bitcoin::TxOut {
            value_sat: change,
            script_pubkey: self.script_for_tweak(&tweak)?,
        }];
        if let Some(destination) = destination {
            outputs.push(destination);
        }
        let transaction = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            inputs: inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.outpoint,
                    script_sig: vec![],
                    sequence: 0xffff_fffd,
                    witness: vec![],
                })
                .collect(),
            outputs,
        };
        let txid = transaction.txid();
        let record = ChainRecord {
            index: state.chain.len() as u64,
            txid,
            input_sat: previous.value_sat,
            output_sat: change,
            fee_sat: fee,
            vbytes,
            created: state.block_count,
        };
        if state.pending.contains_key(&txid) {
            return Err(WalletError::Invariant("wallet-duplicate-transaction"));
        }
        state.pending.insert(
            txid,
            Pending {
                bytes: transaction.encode(),
                inputs,
                fee_sat: fee,
                vbytes,
                signatures: BTreeMap::new(),
                signed: false,
            },
        );
        state.chain.push(record);
        state.wallet = Some(FederationWallet {
            value_sat: change,
            outpoint: bitcoin::OutPoint { txid, vout: 0 },
            tweak,
        });
        Ok(txid)
    }
    pub fn audit(&self, tx: &WriteTransaction<'_>) -> Result<i64, WalletError> {
        let value = self.read(tx)?.wallet.map(|v| v.value_sat).unwrap_or(0);
        i64::try_from(value)
            .ok()
            .and_then(|v| v.checked_mul(1000))
            .ok_or(WalletError::UnsupportedArithmeticDomain)
    }
    pub fn local_signatures(&self, snapshot: &Snapshot) -> Result<Vec<ConsensusItem>, WalletError> {
        let state = self.view_state(snapshot)?;
        let mut items = Vec::new();
        for record in &state.chain {
            let Some(pending) = state
                .pending
                .get(&record.txid)
                .filter(|p| !p.signed && !p.signatures.contains_key(&self.peer))
            else {
                continue;
            };
            let transaction = bitcoin::Transaction::decode(&pending.bytes)
                .map_err(|_| WalletError::Invariant("wallet-pending-decode"))?;
            let mut signatures = Vec::new();
            for (index, input) in pending.inputs.iter().enumerate() {
                let hash = transaction
                    .sighash_all(index, &self.witness_script(&input.tweak)?, input.value_sat)
                    .map_err(|_| WalletError::Invariant("wallet-sighash"))?;
                let key = self
                    .secret
                    .add_tweak(&input.tweak)
                    .map_err(|_| WalletError::Invariant("wallet-secret-tweak"))?;
                signatures.push(
                    key.ecdsa_sign(&hash)
                        .map_err(|_| WalletError::Invariant("wallet-signature"))?,
                );
            }
            items.push(ConsensusItem::Signatures {
                txid: record.txid,
                signatures,
            });
        }
        Ok(items)
    }
    fn accept_signatures(
        &self,
        tx: &mut WriteTransaction<'_>,
        state: &mut State,
        peer: PeerId,
        txid: bitcoin::Txid,
        signatures: &[[u8; 64]],
    ) -> Result<(), WalletError> {
        let pending = state
            .pending
            .get_mut(&txid)
            .filter(|p| !p.signed)
            .ok_or(WalletError::Rejected("missing-unsigned-transaction"))?;
        if signatures.len() != pending.inputs.len() {
            return Err(WalletError::Rejected("signature-count"));
        }
        let mut transaction = bitcoin::Transaction::decode(&pending.bytes)
            .map_err(|_| WalletError::Invariant("wallet-pending-decode"))?;
        for (index, (input, signature)) in pending.inputs.iter().zip(signatures).enumerate() {
            let hash = transaction
                .sighash_all(index, &self.witness_script(&input.tweak)?, input.value_sat)
                .map_err(|_| WalletError::Invariant("wallet-sighash"))?;
            let public = secp::add_tweak(&self.config.bitcoin_pks[&peer], &input.tweak)
                .map_err(|_| WalletError::Invariant("wallet-tweak-key"))?;
            secp::ecdsa_verify(&public, &hash, signature)
                .map_err(|_| WalletError::Rejected("invalid-signature"))?;
        }
        if pending.signatures.contains_key(&peer) {
            return Err(WalletError::Rejected("duplicate-signature-list"));
        }
        pending.signatures.insert(peer, signatures.to_vec());
        if pending.signatures.len() == self.threshold {
            for (index, input) in pending.inputs.iter().enumerate() {
                let mut keys = self.tweaked_keys(&input.tweak)?;
                keys.sort_by_key(|(key, _)| *key);
                let mut witness = vec![vec![]];
                for (_, peer) in keys {
                    if let Some(list) = pending.signatures.get(&peer) {
                        let mut signature = secp::ecdsa_compact_to_der(&list[index])
                            .map_err(|_| WalletError::Invariant("wallet-der"))?;
                        signature.push(1);
                        witness.push(signature);
                    }
                }
                witness.push(self.witness_script(&input.tweak)?);
                transaction.inputs[index].witness = witness;
            }
            pending.bytes = transaction.encode();
            pending.signed = true;
            pending.signatures.clear();
            tx.put(Namespace::Outbox, &self.outbox_key(txid), &pending.bytes)?;
        }
        Ok(())
    }
    fn outbox_key(&self, txid: bitcoin::Txid) -> Vec<u8> {
        [self.key(b"broadcast/"), txid.0.to_vec()].concat()
    }
    pub fn broadcast_pending(
        &self,
        store: &Store,
        backend: &impl BitcoinBackend,
    ) -> Result<(), WalletError> {
        let snapshot = store.snapshot()?;
        // Attempt every entry in ancestor order. A backend may reject an already
        // confirmed parent while its child still needs broadcasting.
        let mut first_error = None;
        for record in self.view_state(&snapshot)?.chain {
            if let Some(bytes) = snapshot.get(Namespace::Outbox, &self.outbox_key(record.txid))? {
                let transaction = bitcoin::Transaction::decode(&bytes)
                    .map_err(|_| WalletError::Invariant("wallet-outbox-decode"))?;
                if let Err(error) = backend.broadcast(&transaction) {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), |error| Err(WalletError::Backend(error)))
    }
    pub fn send_fee(&self, snapshot: &Snapshot) -> Result<Option<u64>, WalletError> {
        self.quote(&self.view_state(snapshot)?, self.config.send_tx_vbytes)
    }
    pub fn receive_fee(&self, snapshot: &Snapshot) -> Result<Option<u64>, WalletError> {
        self.quote(&self.view_state(snapshot)?, self.config.receive_tx_vbytes)
    }
    pub fn snapshot(&self, snapshot: &Snapshot) -> Result<WalletView, WalletError> {
        let state = self.view_state(snapshot)?;
        let pending_chain = state
            .chain
            .iter()
            .rev()
            .take(state.pending.len())
            .cloned()
            .collect();
        let consensus_fee_rate = self.agreed_rate(&state);
        Ok(WalletView {
            block_count: state.block_count,
            consensus_fee_rate,
            wallet: state.wallet,
            discoveries: state.discoveries,
            chain: state.chain,
            pending_chain,
            withdrawals: state.withdrawals,
        })
    }
}
fn script_number(n: usize) -> Vec<u8> {
    if n <= 16 {
        vec![0x50 + n as u8]
    } else {
        vec![1, n as u8]
    }
}
fn module_error(tag: u64, version: Option<u64>) -> WalletError {
    WalletError::Module(encode_enum(
        tag,
        &version.map(|v| v.consensus_encode()).unwrap_or_default(),
    ))
}
#[derive(Debug)]
pub struct WalletView {
    pub block_count: u64,
    pub consensus_fee_rate: Option<u64>,
    pub wallet: Option<FederationWallet>,
    discoveries: Vec<Discovery>,
    pub chain: Vec<ChainRecord>,
    pub pending_chain: Vec<ChainRecord>,
    withdrawals: BTreeMap<Vec<u8>, bitcoin::Txid>,
}
impl WalletView {
    pub fn output_info_slice(&self, start: u64, end: u64) -> Vec<Discovery> {
        self.discoveries
            .iter()
            .filter(|d| {
                d.index >= start
                    && d.index < end
                    && d.script.len() == 34
                    && d.script.starts_with(&[0, 32])
            })
            .cloned()
            .collect()
    }
    pub fn transaction_id(&self, point: OutPoint) -> Option<bitcoin::Txid> {
        self.withdrawals.get(&point.consensus_encode()).copied()
    }
}

impl crate::protocol::ModuleRegistry for Wallet {
    fn decode_payload(
        &self,
        id: ModuleId,
        kind: crate::protocol::ModuleValueKind,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        use crate::protocol::ModuleValueKind;
        if id != self.module {
            return Err(DecodeError::UnknownModule);
        }
        match kind {
            ModuleValueKind::Input => {
                Input::consensus_decode(r)?;
            }
            ModuleValueKind::Output => {
                Output::consensus_decode(r)?;
            }
            ModuleValueKind::ConsensusItem => {
                ConsensusItem::consensus_decode(r)?;
            }
            ModuleValueKind::InputError => {
                InputError::consensus_decode(r)?;
            }
            ModuleValueKind::OutputError => {
                OutputError::consensus_decode(r)?;
            }
            ModuleValueKind::Outcome => return Err(DecodeError::UnknownVariant),
        }
        Ok(())
    }
}
impl Wallet {
    fn routed<T: ConsensusDecode>(
        &self,
        value: &crate::protocol::DynamicValue,
    ) -> Result<T, TransitionError> {
        if value.module_id != self.module {
            return Err(TransitionError::FatalInvariant("wallet-dispatch-instance"));
        }
        decode_whole(&value.payload)
            .map_err(|_| TransitionError::FatalInvariant("wallet-dispatch-schema"))
    }
}
impl crate::core::transaction::ModuleTransitions for Wallet {
    fn stateless_input(
        &self,
        value: &crate::protocol::DynamicValue,
    ) -> Result<(), TransitionError> {
        self.routed::<Input>(value).map(|_| ())
    }
    fn submission_input(
        &self,
        _tx: &mut WriteTransaction<'_>,
        value: &crate::protocol::DynamicValue,
        _point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.routed::<Input>(value).map(|_| ())
    }
    fn submission_output(
        &self,
        _tx: &mut WriteTransaction<'_>,
        value: &crate::protocol::DynamicValue,
        _point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.routed::<Output>(value).map(|_| ())
    }
    fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &crate::protocol::DynamicValue,
        point: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        Wallet::input(self, tx, &self.routed(value)?, point)
    }
    fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &crate::protocol::DynamicValue,
        point: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        Wallet::output(self, tx, &self.routed(value)?, point)
    }
}
