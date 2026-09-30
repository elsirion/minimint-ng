//! Guardian cryptography. Signature messages are exact, already-hashed 32-byte values.
pub mod bls;
mod bls_ffi;
pub mod secp;

/// Deliberately carries no input bytes or native error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;
impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid cryptographic value or operation")
    }
}
impl std::error::Error for CryptoError {}
impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self
    }
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(bytes)
}
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let key = openssl::pkey::PKey::hmac(key)?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha512(), &key)?;
    signer.update(message)?;
    signer.sign_to_vec()?.try_into().map_err(|_| CryptoError)
}
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0; N];
    openssl::rand::rand_priv_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Bitcoin HASH160: RIPEMD160 of the exact SHA256 digest.
pub fn hash160(bytes: &[u8]) -> Result<[u8; 20], CryptoError> {
    openssl::hash::hash(openssl::hash::MessageDigest::ripemd160(), &sha256(bytes))?
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError)
}
