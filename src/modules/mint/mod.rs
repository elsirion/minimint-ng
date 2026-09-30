//! Guardian Mint state. Every mutation stays inside the caller's writer.
//! Counter invariant failures require dropping that writer and stopping execution.
mod wire;
use crate::{
    codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole},
    config::RawMintConfig,
    core::transaction::{InputMeta, ModuleTransitions, OutputMeta, TransitionError},
    crypto::{
        bls::{self, G2, Scalar},
        hash160, sha256,
    },
    protocol::{DynamicValue, ModuleId, ModuleRegistry, ModuleValueKind, OutPoint, PeerId},
    storage::{Namespace, Snapshot, StoreError, WriteTransaction},
};
use std::{collections::BTreeMap, ops::Range};
pub use wire::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintConfigError;
impl std::fmt::Display for MintConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid Mint configuration")
    }
}
impl std::error::Error for MintConfigError {}
#[derive(Debug)]
pub enum ReadError {
    Storage(StoreError),
    CorruptState,
    InvalidRange,
    MissingShare,
}
impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "Mint storage failure",
            Self::CorruptState => "corrupt Mint state",
            Self::InvalidRange => "invalid Mint range",
            Self::MissingShare => "No blinded signature share found",
        })
    }
}
impl std::error::Error for ReadError {}
impl From<StoreError> for ReadError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
/// No Debug: contains private signing scalars.
pub struct Mint {
    instance: ModuleId,
    config: RawMintConfig,
    signing_keys: BTreeMap<u8, Scalar>,
    aggregate_keys: BTreeMap<u8, G2>,
}
impl Mint {
    pub fn new(
        instance: ModuleId,
        peer: PeerId,
        config: RawMintConfig,
        signing_keys: BTreeMap<u8, Scalar>,
    ) -> Result<Self, MintConfigError> {
        config.check_public_points().map_err(|_| MintConfigError)?;
        for d in 0..42 {
            let secret = signing_keys.get(&d).ok_or(MintConfigError)?;
            let expected = config
                .public_shares
                .get(&d)
                .and_then(|shares| shares.get(&peer))
                .ok_or(MintConfigError)?;
            if G2::generator().mul(secret).to_bytes() != *expected {
                return Err(MintConfigError);
            }
            if !config.aggregate_keys.contains_key(&d) {
                return Err(MintConfigError);
            }
        }
        let aggregate_keys = config
            .aggregate_keys
            .iter()
            .map(|(d, bytes)| {
                G2::from_bytes(bytes)
                    .map(|key| (*d, key))
                    .map_err(|_| MintConfigError)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            instance,
            config,
            signing_keys,
            aggregate_keys,
        })
    }
    pub fn instance(&self) -> ModuleId {
        self.instance
    }
    fn key(&self, kind: u8, suffix: &[u8]) -> Vec<u8> {
        [
            b"mint/v1/".as_slice(),
            self.instance.0.to_be_bytes().as_slice(),
            &[kind],
            suffix,
        ]
        .concat()
    }
    pub fn stateless_input(&self, _: &Input) -> Result<(), TransitionError> {
        Ok(())
    }
    pub fn submission_input(
        &self,
        _: &mut WriteTransaction<'_>,
        _: &Input,
        _: OutPoint,
    ) -> Result<(), TransitionError> {
        Ok(())
    }
    pub fn submission_output(
        &self,
        _: &mut WriteTransaction<'_>,
        _: &Output,
        _: OutPoint,
    ) -> Result<(), TransitionError> {
        Ok(())
    }
    pub fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        input: &Input,
        _: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        let note = match input {
            Input::V0(note) => note,
            Input::Unknown { version, .. } => {
                return Err(reject(InputError::UnknownInputVariant(*version)));
            }
        };
        let public = self
            .aggregate_keys
            .get(&note.denomination)
            .ok_or_else(|| reject(InputError::InvalidDenomination))?;
        let message = bls::message_sha256(&note.nonce.to_bytes())
            .map_err(|_| fatal("Mint message mapping failed"))?;
        bls::verify_share(&message, public, &note.signature.point())
            .map_err(|_| reject(InputError::InvalidSignature))?;
        let spent_key = self.key(SPENT, &note.nonce.to_bytes());
        if tx.get(Namespace::Replicated, &spent_key)?.is_some() {
            return Err(reject(InputError::SpentCoin));
        }
        tx.put(Namespace::Replicated, &spent_key, &[])?;
        let count = self
            .counter(tx, note.denomination)?
            .checked_sub(1)
            .ok_or_else(|| fatal("Mint counter underflow"))?;
        tx.put(
            Namespace::Replicated,
            &self.key(COUNTER, &[note.denomination]),
            &count.to_be_bytes(),
        )?;
        self.append_recovery(
            tx,
            RecoveryItem::Input {
                nonce_hash: hash160(&note.nonce.to_bytes())
                    .map_err(|_| fatal("Mint HASH160 failed"))?,
            },
        )?;
        let amount = amount(note.denomination)?;
        Ok(InputMeta {
            amount_msat: amount,
            fee_msat: fee(
                amount,
                self.config.fee.base,
                self.config.fee.parts_per_million,
            )?,
            public_key: note.nonce.to_bytes(),
        })
    }
    pub fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        output: &Output,
        outpoint: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        let output = match output {
            Output::V0(output) => output,
            Output::Unknown { version, .. } => {
                return Err(reject(OutputError::UnknownOutputVariant(*version)));
            }
        };
        let secret = self
            .signing_keys
            .get(&output.denomination)
            .ok_or_else(|| reject(OutputError::InvalidDenomination))?;
        let share = bls::sign_share(&output.blinded_message.point(), secret).to_bytes();
        tx.put(
            Namespace::Replicated,
            &self.key(SHARE_LOCATION, &location(outpoint)),
            &share,
        )?;
        tx.put(
            Namespace::Replicated,
            &self.key(SHARE_BLINDED, &output.blinded_message.to_bytes()),
            &share,
        )?;
        let count = self
            .counter(tx, output.denomination)?
            .checked_add(1)
            .ok_or_else(|| fatal("Mint counter overflow"))?;
        tx.put(
            Namespace::Replicated,
            &self.key(COUNTER, &[output.denomination]),
            &count.to_be_bytes(),
        )?;
        self.append_recovery(
            tx,
            RecoveryItem::Output {
                denomination: output.denomination,
                nonce_hash: hash160(&output.blinded_message.to_bytes())
                    .map_err(|_| fatal("Mint HASH160 failed"))?,
                tweak: output.tweak,
            },
        )?;
        let amount = amount(output.denomination)?;
        Ok(OutputMeta {
            amount_msat: amount,
            fee_msat: fee(
                amount,
                self.config.fee.base,
                self.config.fee.parts_per_million,
            )?,
        })
    }
    fn counter(&self, tx: &WriteTransaction<'_>, d: u8) -> Result<u64, TransitionError> {
        read_u64(tx.get(Namespace::Replicated, &self.key(COUNTER, &[d]))?)
            .map_err(|_| fatal("corrupt Mint counter"))
    }
    fn append_recovery(
        &self,
        tx: &mut WriteTransaction<'_>,
        item: RecoveryItem,
    ) -> Result<(), TransitionError> {
        let key = self.key(RECOVERY_COUNT, &[]);
        let index = read_u64(tx.get(Namespace::Replicated, &key)?)
            .map_err(|_| fatal("corrupt Mint recovery count"))?;
        let count = index
            .checked_add(1)
            .ok_or_else(|| fatal("Mint recovery count overflow"))?;
        tx.put(
            Namespace::Replicated,
            &self.key(RECOVERY, &index.to_be_bytes()),
            &item.consensus_encode(),
        )?;
        tx.put(Namespace::Replicated, &key, &count.to_be_bytes())?;
        Ok(())
    }
    /// Only the spec's intended signed64 accounting domain is supported. Outside
    /// it, stop rather than claim portable equivalence to unchecked baseline math.
    pub fn audit(&self, tx: &WriteTransaction<'_>) -> Result<i64, TransitionError> {
        let prefix = self.key(COUNTER, &[]);
        let mut total = 0i64;
        for (key, value) in tx.scan_prefix(Namespace::Replicated, &prefix)? {
            let [d] = key
                .get(prefix.len()..)
                .ok_or_else(|| fatal("corrupt Mint audit key"))?
            else {
                return Err(fatal("corrupt Mint audit key"));
            };
            let count = read_u64(Some(value)).map_err(|_| fatal("corrupt Mint counter"))?;
            let liability = amount(*d)?
                .checked_mul(count)
                .and_then(|n| i64::try_from(n).ok())
                .ok_or_else(|| fatal("Mint audit outside supported arithmetic domain"))?;
            total = total
                .checked_sub(liability)
                .ok_or_else(|| fatal("Mint audit outside supported arithmetic domain"))?;
        }
        Ok(total)
    }
    pub fn signature_shares(
        &self,
        snapshot: &Snapshot,
        txid: [u8; 32],
        range: Range<u64>,
    ) -> Result<Vec<G1Bytes>, ReadError> {
        if range.end < range.start {
            return Err(ReadError::InvalidRange);
        }
        let prefix = self.key(SHARE_LOCATION, &txid);
        let mut shares = Vec::new();
        for (key, value) in snapshot.scan_prefix(Namespace::Replicated, &prefix)? {
            let index = u64::from_be_bytes(
                key.get(prefix.len()..)
                    .ok_or(ReadError::CorruptState)?
                    .try_into()
                    .map_err(|_| ReadError::CorruptState)?,
            );
            if range.contains(&index) {
                shares.push(decode_whole(&value).map_err(|_| ReadError::CorruptState)?);
            }
        }
        Ok(shares)
    }
    pub fn recovery_signature_shares(
        &self,
        snapshot: &Snapshot,
        messages: &[G1Bytes],
    ) -> Result<Vec<G1Bytes>, ReadError> {
        messages
            .iter()
            .map(|message| {
                let value = snapshot
                    .get(
                        Namespace::Replicated,
                        &self.key(SHARE_BLINDED, &message.to_bytes()),
                    )?
                    .ok_or(ReadError::MissingShare)?;
                decode_whole(&value).map_err(|_| ReadError::CorruptState)
            })
            .collect()
    }
    pub fn recovery_count(&self, snapshot: &Snapshot) -> Result<u64, ReadError> {
        read_u64(snapshot.get(Namespace::Replicated, &self.key(RECOVERY_COUNT, &[]))?)
    }
    pub fn recovery_slice(
        &self,
        snapshot: &Snapshot,
        range: Range<u64>,
    ) -> Result<Vec<RecoveryItem>, ReadError> {
        if range.end < range.start {
            return Err(ReadError::InvalidRange);
        }
        let prefix = self.key(RECOVERY, &[]);
        let mut items = Vec::new();
        for (key, value) in snapshot.scan_prefix(Namespace::Replicated, &prefix)? {
            let index = u64::from_be_bytes(
                key.get(prefix.len()..)
                    .ok_or(ReadError::CorruptState)?
                    .try_into()
                    .map_err(|_| ReadError::CorruptState)?,
            );
            if range.contains(&index) {
                items.push(decode_whole(&value).map_err(|_| ReadError::CorruptState)?);
            }
        }
        Ok(items)
    }
    pub fn recovery_slice_hash(
        &self,
        snapshot: &Snapshot,
        range: Range<u64>,
    ) -> Result<[u8; 32], ReadError> {
        Ok(sha256(
            &self.recovery_slice(snapshot, range)?.consensus_encode(),
        ))
    }
    fn routed_input(&self, value: &DynamicValue) -> Result<Input, TransitionError> {
        self.require_instance(value)?;
        decode_whole(&value.payload).map_err(|_| fatal("Mint input bypassed schema gate"))
    }
    fn routed_output(&self, value: &DynamicValue) -> Result<Output, TransitionError> {
        self.require_instance(value)?;
        decode_whole(&value.payload).map_err(|_| fatal("Mint output bypassed schema gate"))
    }
    fn require_instance(&self, value: &DynamicValue) -> Result<(), TransitionError> {
        if value.module_id != self.instance {
            Err(fatal("Mint dispatch instance mismatch"))
        } else {
            Ok(())
        }
    }
}
impl ModuleRegistry for Mint {
    fn decode_payload(
        &self,
        id: ModuleId,
        kind: ModuleValueKind,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        if id != self.instance {
            return Err(DecodeError::UnknownModule);
        }
        match kind {
            ModuleValueKind::Input => {
                Input::consensus_decode(r)?;
            }
            ModuleValueKind::Output => {
                Output::consensus_decode(r)?;
            }
            ModuleValueKind::InputError => {
                InputError::consensus_decode(r)?;
            }
            ModuleValueKind::OutputError => {
                OutputError::consensus_decode(r)?;
            }
            ModuleValueKind::ConsensusItem | ModuleValueKind::Outcome => {
                return Err(DecodeError::UnknownVariant);
            }
        }
        Ok(())
    }
}
impl ModuleTransitions for Mint {
    fn stateless_input(&self, value: &DynamicValue) -> Result<(), TransitionError> {
        Mint::stateless_input(self, &self.routed_input(value)?)
    }
    fn submission_input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        p: OutPoint,
    ) -> Result<(), TransitionError> {
        Mint::submission_input(self, tx, &self.routed_input(value)?, p)
    }
    fn submission_output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        p: OutPoint,
    ) -> Result<(), TransitionError> {
        Mint::submission_output(self, tx, &self.routed_output(value)?, p)
    }
    fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        p: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        Mint::input(self, tx, &self.routed_input(value)?, p)
    }
    fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        p: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        Mint::output(self, tx, &self.routed_output(value)?, p)
    }
}
const SPENT: u8 = 0;
const COUNTER: u8 = 1;
const SHARE_LOCATION: u8 = 2;
const SHARE_BLINDED: u8 = 3;
const RECOVERY: u8 = 4;
const RECOVERY_COUNT: u8 = 5;
fn location(point: OutPoint) -> Vec<u8> {
    [point.txid.to_vec(), point.out_idx.to_be_bytes().to_vec()].concat()
}
fn read_u64(value: Option<Vec<u8>>) -> Result<u64, ReadError> {
    match value {
        None => Ok(0),
        Some(bytes) => Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| ReadError::CorruptState)?,
        )),
    }
}
fn amount(d: u8) -> Result<u64, TransitionError> {
    1u64.checked_shl(u32::from(d))
        .ok_or_else(|| fatal("Mint denomination outside supported u64 domain"))
}
/// MINT-005: multiplication saturates before division; base addition is checked.
pub fn fee(amount: u64, base: u64, ppm: u64) -> Result<u64, TransitionError> {
    base.checked_add(amount.saturating_mul(ppm) / 1_000_000)
        .ok_or_else(|| fatal("Mint fee exceeds u64"))
}
fn fatal(message: &'static str) -> TransitionError {
    TransitionError::FatalInvariant(message)
}
fn reject(error: impl ConsensusEncode) -> TransitionError {
    TransitionError::Module(error.consensus_encode())
}
