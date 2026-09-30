//! Statically registered BTC-only guardian modules.
pub mod mint;
pub mod wallet;

use crate::{
    codec::{DecodeError, Reader},
    core::{
        audit::{AuditError, require_nonnegative},
        transaction::{InputMeta, ModuleTransitions, OutputMeta, TransitionError},
    },
    protocol::{DynamicValue, ModuleId, ModuleRegistry, ModuleValueKind, OutPoint},
    storage::WriteTransaction,
};

/// Exactly the two built-in module kinds. Instance IDs remain configured values.
pub struct Modules {
    mint: mint::Mint,
    wallet: wallet::Wallet,
}
impl Modules {
    pub fn new(mint: mint::Mint, wallet: wallet::Wallet) -> Result<Self, DecodeError> {
        if mint.instance() == wallet.module_id() {
            return Err(DecodeError::InvalidValue);
        }
        Ok(Self { mint, wallet })
    }
    pub fn mint(&self) -> &mint::Mint {
        &self.mint
    }
    pub fn wallet(&self) -> &wallet::Wallet {
        &self.wallet
    }
    fn transition_module(&self, id: ModuleId) -> Result<&dyn ModuleTransitions, TransitionError> {
        if id == self.mint.instance() {
            Ok(&self.mint)
        } else if id == self.wallet.module_id() {
            Ok(&self.wallet)
        } else {
            Err(TransitionError::FatalInvariant(
                "unconfigured-module-dispatch",
            ))
        }
    }
    pub fn audit(&self, tx: &WriteTransaction<'_>) -> Result<i64, ModuleAuditError> {
        let mint = self.mint.audit(tx).map_err(ModuleAuditError::Mint)?;
        let wallet = self.wallet.audit(tx).map_err(ModuleAuditError::Wallet)?;
        let values = if self.mint.instance() < self.wallet.module_id() {
            [mint, wallet]
        } else {
            [wallet, mint]
        };
        require_nonnegative(values).map_err(ModuleAuditError::Aggregate)
    }
}
#[derive(Debug)]
pub enum ModuleAuditError {
    Mint(TransitionError),
    Wallet(wallet::WalletError),
    Aggregate(AuditError),
}
impl ModuleRegistry for Modules {
    fn decode_payload(
        &self,
        id: ModuleId,
        kind: ModuleValueKind,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        if id == self.mint.instance() {
            self.mint.decode_payload(id, kind, r)
        } else if id == self.wallet.module_id() {
            self.wallet.decode_payload(id, kind, r)
        } else {
            Err(DecodeError::UnknownModule)
        }
    }
}
impl ModuleTransitions for Modules {
    fn stateless_input(&self, value: &DynamicValue) -> Result<(), TransitionError> {
        self.transition_module(value.module_id)?
            .stateless_input(value)
    }
    fn submission_input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.transition_module(value.module_id)?
            .submission_input(tx, value, point)
    }
    fn submission_output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.transition_module(value.module_id)?
            .submission_output(tx, value, point)
    }
    fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        self.transition_module(value.module_id)?
            .input(tx, value, point)
    }
    fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        self.transition_module(value.module_id)?
            .output(tx, value, point)
    }
}
