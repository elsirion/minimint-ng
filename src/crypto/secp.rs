//! Compressed secp256k1 keys, BIP340 and low-S compact ECDSA.
use super::{CryptoError, random_bytes};
use k256::elliptic_curve::{PrimeField, sec1::ToSec1Point};
use k256::schnorr::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::{ProjectivePoint, PublicKey, Scalar};
use zeroize::Zeroizing;

/// Private guardian key. The library erases the contained scalar on drop.
/// No Debug or Copy; explicit export is for private durable configuration only.
pub struct SecretKey(k256::SecretKey);
impl SecretKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        k256::SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| CryptoError)
    }
    pub fn random() -> Result<Self, CryptoError> {
        loop {
            let bytes = Zeroizing::new(random_bytes()?);
            if let Ok(key) = Self::from_bytes(&bytes) {
                return Ok(key);
            }
        }
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }
    pub fn public_key(&self) -> [u8; 33] {
        let encoded = self.0.public_key().to_sec1_point(true);
        let mut result = [0; 33];
        result.copy_from_slice(encoded.as_bytes());
        result
    }
    pub fn schnorr_sign(&self, message: &[u8; 32]) -> Result<[u8; 64], CryptoError> {
        let key = k256::schnorr::SigningKey::from(&self.0);
        let sig: k256::schnorr::Signature = key.sign_prehash(message).map_err(|_| CryptoError)?;
        Ok(sig.to_bytes())
    }
    pub fn ecdsa_sign(&self, message: &[u8; 32]) -> Result<[u8; 64], CryptoError> {
        let key = k256::ecdsa::SigningKey::from(&self.0);
        let sig: k256::ecdsa::Signature = key.sign_prehash(message).map_err(|_| CryptoError)?;
        Ok(sig.normalize_s().to_bytes().into())
    }
    /// Add a canonical scalar; reject a zero resulting secret.
    pub fn add_tweak(&self, tweak: &[u8; 32]) -> Result<Self, CryptoError> {
        let tweak = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_repr((*tweak).into())).ok_or(CryptoError)?,
        );
        let sum = Zeroizing::new(*self.0.to_nonzero_scalar().as_ref() + *tweak);
        let encoded = Zeroizing::new(sum.to_repr());
        k256::SecretKey::from_bytes(&encoded)
            .map(Self)
            .map_err(|_| CryptoError)
    }
}
pub fn validate_public_key(bytes: &[u8; 33]) -> Result<(), CryptoError> {
    if !matches!(bytes[0], 2 | 3) {
        return Err(CryptoError);
    }
    PublicKey::from_sec1_bytes(bytes)
        .map(|_| ())
        .map_err(|_| CryptoError)
}
pub fn x_only(bytes: &[u8; 33]) -> Result<[u8; 32], CryptoError> {
    validate_public_key(bytes)?;
    let mut result = [0; 32];
    result.copy_from_slice(&bytes[1..]);
    Ok(result)
}
pub fn schnorr_verify(
    public: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = k256::schnorr::VerifyingKey::from_bytes(public.into()).map_err(|_| CryptoError)?;
    let sig = k256::schnorr::Signature::try_from(signature.as_slice()).map_err(|_| CryptoError)?;
    key.verify_prehash(message, &sig).map_err(|_| CryptoError)
}
pub fn ecdsa_verify(
    public: &[u8; 33],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    validate_public_key(public)?;
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public).map_err(|_| CryptoError)?;
    let sig = k256::ecdsa::Signature::from_slice(signature).map_err(|_| CryptoError)?;
    if sig.normalize_s() != sig {
        return Err(CryptoError);
    }
    key.verify_prehash(message, &sig).map_err(|_| CryptoError)
}
/// Add a scalar times G to a full public key, without BIP341 parity adjustment.
pub fn add_tweak(public: &[u8; 33], tweak: &[u8; 32]) -> Result<[u8; 33], CryptoError> {
    validate_public_key(public)?;
    let key = PublicKey::from_sec1_bytes(public).map_err(|_| CryptoError)?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr((*tweak).into())).ok_or(CryptoError)?;
    let point = ProjectivePoint::from(*key.as_affine()) + ProjectivePoint::GENERATOR * scalar;
    let key = PublicKey::from_affine(point.to_affine()).map_err(|_| CryptoError)?;
    key.to_sec1_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError)
}

/// Encode a canonical low-S compact signature as strict Bitcoin DER.
pub fn ecdsa_compact_to_der(signature: &[u8; 64]) -> Result<Vec<u8>, CryptoError> {
    let sig = k256::ecdsa::Signature::from_slice(signature).map_err(|_| CryptoError)?;
    if sig.normalize_s() != sig {
        return Err(CryptoError);
    }
    Ok(sig.to_der().as_bytes().to_vec())
}
/// Decode strict DER, rejecting high-S values and noncanonical/trailing bytes.
/// The Bitcoin sighash byte is a separate protocol field, not part of DER.
pub fn ecdsa_der_to_compact(signature: &[u8]) -> Result<[u8; 64], CryptoError> {
    let sig = k256::ecdsa::Signature::from_der(signature).map_err(|_| CryptoError)?;
    if sig.normalize_s() != sig || sig.to_der().as_bytes() != signature {
        return Err(CryptoError);
    }
    Ok(sig.to_bytes().into())
}
