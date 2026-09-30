//! Canonical BLS12-381 guardian objects and Mint's specified seeded mapping.
//! Shared objects permit zero/infinity; callers enforce module-specific policy.
use super::{CryptoError, bls_ffi as native, random_bytes};
use openssl::{
    bn::{BigNum, BigNumContext},
    symm::{Cipher, Crypter, Mode},
};
use zeroize::Zeroizing;

/// A canonical little-endian scalar modulo r, erased on drop.
/// Explicit byte export is only for private configuration/share transport.
#[derive(Clone)]
pub struct Scalar(native::ScalarValue);
impl Scalar {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        native::ScalarValue::parse(bytes).map(Self)
    }
    pub fn from_u64(value: u64) -> Self {
        Self(native::ScalarValue::from_u64(value))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.bytes()
    }
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    pub fn random() -> Result<Self, CryptoError> {
        // Uniform rejection sampling for private DKG coefficients. Zero is
        // permitted here; the module decides whether it needs a nonzero key.
        loop {
            let mut bytes = Zeroizing::new(random_bytes::<32>()?);
            bytes[31] &= 0x7f;
            if let Ok(value) = Self::from_bytes(&bytes) {
                return Ok(value);
            }
        }
    }
    /// CRY-005: consume 64 ChaCha20 bytes and reduce the LE integer modulo r.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let mut rng = SeedStream::new(seed)?;
        let bytes = Zeroizing::new(rng.read::<64>()?);
        Ok(Self(native::ScalarValue::reduce(&bytes)))
    }
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0.arithmetic(&other.0, native::Arithmetic::Add))
    }
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0.arithmetic(&other.0, native::Arithmetic::Sub))
    }
    pub fn mul(&self, other: &Self) -> Self {
        Self(self.0.arithmetic(&other.0, native::Arithmetic::Mul))
    }
    pub fn inverse(&self) -> Result<Self, CryptoError> {
        self.0.inverse().map(Self)
    }
}

#[derive(Clone)]
pub struct G1(native::Point1);
#[derive(Clone)]
pub struct G2(native::Point2);
macro_rules! point_methods {
    ($point:ident,$native:ident,$size:literal) => {
        impl $point {
            pub fn from_bytes(bytes: &[u8; $size]) -> Result<Self, CryptoError> {
                native::$native::parse(bytes).map(Self)
            }
            pub fn to_bytes(&self) -> [u8; $size] {
                self.0.bytes()
            }
            pub fn generator() -> Self {
                Self(native::$native::generator())
            }
            pub fn identity() -> Self {
                Self(native::$native::identity())
            }
            pub fn is_identity(&self) -> bool {
                self.0.is_identity()
            }
            pub fn add(&self, other: &Self) -> Self {
                Self(self.0.add(&other.0))
            }
            pub fn mul(&self, scalar: &Scalar) -> Self {
                Self(self.0.mul(&scalar.0))
            }
        }
    };
}
point_methods!(G1, Point1, 48);
point_methods!(G2, Point2, 96);

pub fn sign_share(message: &G1, secret: &Scalar) -> G1 {
    message.mul(secret)
}
/// Pairing equality only. Threshold, key-set provenance and nonidentity
/// restrictions belong to the calling module.
pub fn verify_share(message: &G1, public: &G2, signature: &G1) -> Result<(), CryptoError> {
    if native::pairing_equal(&message.0, &public.0, &signature.0, &G2::generator().0) {
        Ok(())
    } else {
        Err(CryptoError)
    }
}
/// Evaluate ascending polynomial coefficients at guardian coordinate id+1.
pub fn evaluate_polynomial(coefficients: &[Scalar], id: u16) -> Result<Scalar, CryptoError> {
    if coefficients.is_empty() {
        return Err(CryptoError);
    }
    let x = Scalar::from_u64(u64::from(id) + 1);
    Ok(coefficients
        .iter()
        .rev()
        .fold(Scalar::from_u64(0), |acc, c| acc.mul(&x).add(c)))
}
/// Evaluate G2 coefficient commitments at the same guardian coordinate.
pub fn evaluate_commitments(coefficients: &[G2], id: u16) -> Result<G2, CryptoError> {
    if coefficients.is_empty() {
        return Err(CryptoError);
    }
    let x = Scalar::from_u64(u64::from(id) + 1);
    Ok(coefficients
        .iter()
        .rev()
        .fold(G2::identity(), |acc, c| acc.mul(&x).add(c)))
}
fn lagrange(ids: &[u16], threshold: usize) -> Result<Vec<Scalar>, CryptoError> {
    if threshold == 0 || ids.len() < threshold {
        return Err(CryptoError);
    }
    let distinct: std::collections::BTreeSet<_> = ids.iter().copied().collect();
    if distinct.len() != ids.len() {
        return Err(CryptoError);
    }
    let coordinates: Vec<_> = ids
        .iter()
        .map(|id| Scalar::from_u64(u64::from(*id) + 1))
        .collect();
    coordinates
        .iter()
        .enumerate()
        .map(|(j, xj)| {
            let mut numerator = Scalar::from_u64(1);
            let mut denominator = Scalar::from_u64(1);
            for (k, xk) in coordinates.iter().enumerate() {
                if j != k {
                    numerator = numerator.mul(xk);
                    denominator = denominator.mul(&xk.sub(xj));
                }
            }
            Ok(numerator.mul(&denominator.inverse()?))
        })
        .collect()
}
/// Require a nonzero caller threshold and distinct IDs; signatures must already
/// have been validated against shares of the same key set by the caller.
pub fn interpolate_g1(shares: &[(u16, G1)], threshold: usize) -> Result<G1, CryptoError> {
    let ids: Vec<_> = shares.iter().map(|(id, _)| *id).collect();
    let weights = lagrange(&ids, threshold)?;
    Ok(shares
        .iter()
        .zip(weights)
        .fold(G1::identity(), |acc, ((_, p), w)| acc.add(&p.mul(&w))))
}
pub fn interpolate_g2(shares: &[(u16, G2)], threshold: usize) -> Result<G2, CryptoError> {
    let ids: Vec<_> = shares.iter().map(|(id, _)| *id).collect();
    let weights = lagrange(&ids, threshold)?;
    Ok(shares
        .iter()
        .zip(weights)
        .fold(G2::identity(), |acc, ((_, p), w)| acc.add(&p.mul(&w))))
}

/// Mint mapping selected by the containing protocol; this is not hash-to-curve.
pub fn message_sha256(message: &[u8]) -> Result<G1, CryptoError> {
    let mut hash = openssl::sha::Sha256::new();
    hash.update(b"FEDIMINT_TBS_BLS12_381_MESSAGE");
    hash.update(message);
    sample_g1(&hash.finish())
}
pub fn message_original(message: &[u8]) -> Result<G1, CryptoError> {
    let mut hash = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha3_256())?;
    hash.update(b"TBS_BLS12-381_")?;
    hash.update(message)?;
    let seed: [u8; 32] = hash
        .finish()?
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError)?;
    sample_g1(&seed)
}

/// EVP_chacha20 is the original 64-bit counter/64-bit nonce form. Both are
/// initialized to zero, exactly as CRY-005 requires; updates preserve the byte
/// position across block boundaries. This is not ChaCha20-Poly1305/IETF AEAD.
struct SeedStream(Crypter);
impl SeedStream {
    fn new(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self(Crypter::new(
            Cipher::chacha20(),
            Mode::Encrypt,
            seed,
            Some(&[0; 16]),
        )?))
    }
    fn read<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let mut result = [0; N];
        // ChaCha20 is a stream cipher, block_size=1, so no padding bytes are
        // produced and each update returns exactly the input length.
        let len = self.0.update(&[0; N], &mut result)?;
        if len != N {
            return Err(CryptoError);
        }
        Ok(result)
    }
}

/// All BigNum arithmetic below operates on public message-derived field values.
/// Secret scalar/point arithmetic is exclusively handled by blst, never BNs.
fn sample_g1(seed: &[u8; 32]) -> Result<G1, CryptoError> {
    let p = BigNum::from_hex_str(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    )?;
    let mut exponent = p.to_owned()?;
    exponent.add_word(1)?;
    let mut root_exponent = BigNum::new()?;
    root_exponent.rshift(&exponent, 2)?;
    let four = BigNum::from_u32(4)?;
    let zero = BigNum::from_u32(0)?;
    let mut ctx = BigNumContext::new()?;
    let mut rng = SeedStream::new(seed)?;
    loop {
        let sample = rng.read::<96>()?;
        // CRY-005: halves are BE integers but the second half is more significant.
        let mut wide = [0; 96];
        wide[..48].copy_from_slice(&sample[48..]);
        wide[48..].copy_from_slice(&sample[..48]);
        let integer = BigNum::from_slice(&wide)?;
        let mut x = BigNum::new()?;
        x.nnmod(&integer, &p, &mut ctx)?;
        let negate = u32::from_le_bytes(rng.read::<4>()?) & 1 != 0;
        let mut x2 = BigNum::new()?;
        x2.mod_sqr(&x, &p, &mut ctx)?;
        let mut x3 = BigNum::new()?;
        x3.mod_mul(&x2, &x, &p, &mut ctx)?;
        let mut rhs = BigNum::new()?;
        rhs.mod_add(&x3, &four, &p, &mut ctx)?;
        let mut root = BigNum::new()?;
        root.mod_exp(&rhs, &root_exponent, &p, &mut ctx)?;
        let mut check = BigNum::new()?;
        check.mod_sqr(&root, &p, &mut ctx)?;
        if check != rhs {
            continue;
        }
        let mut opposite = BigNum::new()?;
        opposite.mod_sub(&zero, &root, &p, &mut ctx)?;
        let larger = if negate {
            opposite > root
        } else {
            root > opposite
        };
        let mut compressed: [u8; 48] = x.to_vec_padded(48)?.try_into().map_err(|_| CryptoError)?;
        compressed[0] |= 0x80 | if larger { 0x20 } else { 0 };
        let point = G1(native::clear_g1_cofactor(&compressed)?);
        if !point.is_identity() {
            return Ok(point);
        }
    }
}
