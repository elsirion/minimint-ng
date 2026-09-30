//! Configured broadcast-key domain and native signature-map multisignatures.
use super::AgreementError;
use crate::{
    codec::ConsensusEncode,
    crypto::{
        secp::{self, SecretKey},
        sha256,
    },
    protocol::PeerId,
};
use fedimint_aleph_bft::{Index, Keychain, MultiKeychain, NodeCount, NodeIndex, SignatureSet};
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone)]
pub struct GuardianKeychain {
    local: PeerId,
    secret: Arc<SecretKey>,
    keys: Arc<BTreeMap<PeerId, [u8; 33]>>,
    tag: [u8; 32],
}
impl GuardianKeychain {
    pub fn new(
        local: PeerId,
        secret: SecretKey,
        keys: BTreeMap<PeerId, [u8; 33]>,
    ) -> Result<Self, AgreementError> {
        if keys.is_empty()
            || keys.len() > 65_536
            || keys.len() == 2
            || keys.len() == 3
            || keys.iter().enumerate().any(|(i, (id, key))| {
                usize::from(id.0) != i || secp::validate_public_key(key).is_err()
            })
            || keys.get(&local) != Some(&secret.public_key())
        {
            return Err(AgreementError::InvalidConfig);
        }
        let tag = sha256(&keys.consensus_encode());
        Ok(Self {
            local,
            secret: Arc::new(secret),
            keys: Arc::new(keys),
            tag,
        })
    }
    pub fn local_id(&self) -> PeerId {
        self.local
    }
    pub fn count(&self) -> usize {
        self.keys.len()
    }
    pub fn quorum(&self) -> usize {
        self.count() * 2 / 3 + 1
    }
    fn digest(&self, message: &[u8]) -> [u8; 32] {
        let mut hash = openssl::sha::Sha256::new();
        hash.update(&self.tag);
        hash.update(message);
        hash.finish()
    }
}
impl Index for GuardianKeychain {
    fn index(&self) -> NodeIndex {
        NodeIndex(usize::from(self.local.0))
    }
}
impl Keychain for GuardianKeychain {
    type Signature = [u8; 64];
    fn node_count(&self) -> NodeCount {
        NodeCount(self.count())
    }
    fn sign(&self, message: &[u8]) -> Self::Signature {
        self.secret
            .schnorr_sign(&self.digest(message))
            .expect("validated guardian key failed agreement signing")
    }
    fn verify(&self, message: &[u8], signature: &Self::Signature, index: NodeIndex) -> bool {
        let Ok(id) = u16::try_from(index.0) else {
            return false;
        };
        let Some(key) = self.keys.get(&PeerId(id)) else {
            return false;
        };
        secp::x_only(key)
            .and_then(|public| secp::schnorr_verify(&public, &self.digest(message), signature))
            .is_ok()
    }
}
impl MultiKeychain for GuardianKeychain {
    type PartialMultisignature = SignatureSet<[u8; 64]>;
    fn bootstrap_multi(
        &self,
        signature: &Self::Signature,
        index: NodeIndex,
    ) -> Self::PartialMultisignature {
        let mut set = SignatureSet::with_size(self.node_count());
        if index.0 < self.count() {
            set.insert(index, *signature);
        }
        set
    }
    fn is_complete(&self, message: &[u8], partial: &Self::PartialMultisignature) -> bool {
        // This is the generic q-or-more engine verifier. Exact-q history validation
        // is a distinct application-session predicate. Validate every extra signer.
        partial.item_count() >= self.quorum()
            && partial
                .iter()
                .all(|(id, sig)| self.verify(message, sig, id))
    }
}
