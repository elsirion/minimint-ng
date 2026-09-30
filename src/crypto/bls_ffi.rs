//! The only native BLS boundary. Public callers cannot construct native values.
//!
//! Audit invariants: all native objects below are initialized, correctly aligned
//! Rust values, live for the whole synchronous call; output objects are distinct
//! from borrowed inputs. Fixed arrays have exactly the byte lengths required by
//! blst (32 scalar, 48 G1, 96 G2). No native call retains a pointer. Generator
//! pointers refer to immutable process-lifetime library constants. Decoding
//! checks native status before using results, then subgroup and re-encoding.
//! Scalar multiplication receives 32 little-endian bytes and exactly 255 bits.
//! The sole non-subgroup multiplication uses an on-curve point and a 64-bit
//! public effective cofactor, before subgroup validation.
#![allow(unsafe_code)]
use super::CryptoError;
use blst::*;
use zeroize::{Zeroize, Zeroizing};

// blst_scalar zeroizes its bytes on drop; unlike its raw representation this
// wrapper deliberately has neither Debug nor Copy.
#[derive(Clone)]
pub(super) struct ScalarValue(blst_scalar);
impl ScalarValue {
    pub(super) fn parse(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let mut out = blst_scalar::default();
        // SAFETY: fixed input is 32 bytes; out is initialized and disjoint.
        unsafe {
            blst_scalar_from_lendian(&mut out, bytes.as_ptr());
            if !blst_scalar_fr_check(&out) {
                return Err(CryptoError);
            }
        }
        Ok(Self(out))
    }
    pub(super) fn reduce(bytes: &[u8; 64]) -> Self {
        let mut out = blst_scalar::default();
        // SAFETY: input contains len=64 bytes; out is disjoint and live.
        // The return indicates nonzero, which shared scalar parsing permits.
        unsafe {
            blst_scalar_from_le_bytes(&mut out, bytes.as_ptr(), bytes.len());
        }
        Self(out)
    }
    pub(super) fn from_u64(value: u64) -> Self {
        let mut out = blst_scalar::default();
        let limbs = [value, 0, 0, 0];
        // SAFETY: uint64 conversion reads exactly four initialized limbs.
        unsafe {
            blst_scalar_from_uint64(&mut out, limbs.as_ptr());
        }
        Self(out)
    }
    pub(super) fn bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        // SAFETY: exact output length, live scalar, disjoint buffers.
        unsafe {
            blst_lendian_from_scalar(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }
    pub(super) fn is_zero(&self) -> bool {
        self.0.b.iter().fold(0u8, |a, b| a | b) == 0
    }
    pub(super) fn arithmetic(&self, other: &Self, operation: Arithmetic) -> Self {
        let mut a = blst_fr::default();
        let mut b = blst_fr::default();
        let mut result = blst_fr::default();
        let mut out = blst_scalar::default();
        // SAFETY: all scalar inputs are canonical; field conversions and
        // operations use separate initialized stack outputs and live inputs.
        unsafe {
            blst_fr_from_scalar(&mut a, &self.0);
            blst_fr_from_scalar(&mut b, &other.0);
            match operation {
                Arithmetic::Add => blst_fr_add(&mut result, &a, &b),
                Arithmetic::Sub => blst_fr_sub(&mut result, &a, &b),
                Arithmetic::Mul => blst_fr_mul(&mut result, &a, &b),
            }
            blst_scalar_from_fr(&mut out, &result);
        }
        a.l.zeroize();
        b.l.zeroize();
        result.l.zeroize();
        Self(out)
    }
    pub(super) fn inverse(&self) -> Result<Self, CryptoError> {
        if self.is_zero() {
            return Err(CryptoError);
        }
        let mut a = blst_fr::default();
        let mut inverse = blst_fr::default();
        let mut out = blst_scalar::default();
        // SAFETY: nonzero canonical input; disjoint initialized outputs. The
        // fixed-time inverse is used, not blst_fr_eucl_inverse.
        unsafe {
            blst_fr_from_scalar(&mut a, &self.0);
            blst_fr_inverse(&mut inverse, &a);
            blst_scalar_from_fr(&mut out, &inverse);
        }
        a.l.zeroize();
        inverse.l.zeroize();
        Ok(Self(out))
    }
}
pub(super) enum Arithmetic {
    Add,
    Sub,
    Mul,
}

#[derive(Clone)]
pub(super) struct Point1(blst_p1);
#[derive(Clone)]
pub(super) struct Point2(blst_p2);

impl Point1 {
    pub(super) fn parse(bytes: &[u8; 48]) -> Result<Self, CryptoError> {
        let mut affine = blst_p1_affine::default();
        let mut out = blst_p1::default();
        // SAFETY: fixed 48-byte input; initialized disjoint outputs. Native
        // decoding status and subgroup membership precede conversion/use.
        unsafe {
            if blst_p1_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS
                || !blst_p1_affine_in_g1(&affine)
            {
                return Err(CryptoError);
            }
            blst_p1_from_affine(&mut out, &affine);
        }
        let point = Self(out);
        if point.bytes() != *bytes {
            return Err(CryptoError);
        }
        Ok(point)
    }
    pub(super) fn bytes(&self) -> [u8; 48] {
        let mut bytes = [0; 48];
        // SAFETY: exact output length and valid live native point.
        unsafe {
            blst_p1_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }
    pub(super) fn generator() -> Self {
        // SAFETY: blst provides a non-null pointer to an immutable, aligned,
        // process-lifetime generator; copying it creates an owned point.
        Self(unsafe { *blst_p1_generator() })
    }
    pub(super) fn identity() -> Self {
        Self(blst_p1::default())
    }
    pub(super) fn is_identity(&self) -> bool {
        // SAFETY: self owns an initialized native point.
        unsafe { blst_p1_is_inf(&self.0) }
    }
    pub(super) fn add(&self, other: &Self) -> Self {
        let mut out = blst_p1::default();
        // SAFETY: disjoint initialized output and valid live subgroup inputs;
        // add_or_double handles equal points and infinity.
        unsafe {
            blst_p1_add_or_double(&mut out, &self.0, &other.0);
        }
        Self(out)
    }
    pub(super) fn mul(&self, scalar: &ScalarValue) -> Self {
        let mut out = blst_p1::default();
        let bytes = Zeroizing::new(scalar.bytes());
        // SAFETY: exactly 32 little-endian scalar bytes, 255 bits, subgroup
        // point and disjoint initialized output; no pointers escape.
        unsafe {
            blst_p1_mult(&mut out, &self.0, bytes.as_ptr(), 255);
        }
        Self(out)
    }
}

impl Point2 {
    pub(super) fn parse(bytes: &[u8; 96]) -> Result<Self, CryptoError> {
        let mut affine = blst_p2_affine::default();
        let mut out = blst_p2::default();
        // SAFETY: fixed 96-byte input; initialized disjoint outputs. Native
        // decoding status and subgroup membership precede conversion/use.
        unsafe {
            if blst_p2_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS
                || !blst_p2_affine_in_g2(&affine)
            {
                return Err(CryptoError);
            }
            blst_p2_from_affine(&mut out, &affine);
        }
        let point = Self(out);
        if point.bytes() != *bytes {
            return Err(CryptoError);
        }
        Ok(point)
    }
    pub(super) fn bytes(&self) -> [u8; 96] {
        let mut bytes = [0; 96];
        // SAFETY: exact output length and valid live native point.
        unsafe {
            blst_p2_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }
    pub(super) fn generator() -> Self {
        // SAFETY: blst provides a non-null pointer to an immutable, aligned,
        // process-lifetime generator; copying it creates an owned point.
        Self(unsafe { *blst_p2_generator() })
    }
    pub(super) fn identity() -> Self {
        Self(blst_p2::default())
    }
    pub(super) fn is_identity(&self) -> bool {
        // SAFETY: self owns an initialized native point.
        unsafe { blst_p2_is_inf(&self.0) }
    }
    pub(super) fn add(&self, other: &Self) -> Self {
        let mut out = blst_p2::default();
        // SAFETY: disjoint initialized output and valid live subgroup inputs;
        // add_or_double handles equal points and infinity.
        unsafe {
            blst_p2_add_or_double(&mut out, &self.0, &other.0);
        }
        Self(out)
    }
    pub(super) fn mul(&self, scalar: &ScalarValue) -> Self {
        let mut out = blst_p2::default();
        let bytes = Zeroizing::new(scalar.bytes());
        // SAFETY: exactly 32 little-endian scalar bytes, 255 bits, subgroup
        // point and disjoint initialized output; no pointers escape.
        unsafe {
            blst_p2_mult(&mut out, &self.0, bytes.as_ptr(), 255);
        }
        Self(out)
    }
}

/// Convert a compressed on-curve G1 sample into the prime subgroup using
/// CRY-005's effective cofactor. This is private and never exposes the raw point.
pub(super) fn clear_g1_cofactor(bytes: &[u8; 48]) -> Result<Point1, CryptoError> {
    let mut affine = blst_p1_affine::default();
    let mut point = blst_p1::default();
    let mut out = blst_p1::default();
    let cofactor = 0xd201000000010001u64.to_le_bytes();
    // SAFETY: decoder reads 48 bytes and succeeds before affine conversion;
    // public scalar buffer is exactly 8 bytes for nbits=64. Points and outputs
    // are initialized and disjoint. The input is on-curve but not yet subgroup.
    unsafe {
        if blst_p1_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
            return Err(CryptoError);
        }
        blst_p1_from_affine(&mut point, &affine);
        blst_p1_mult(&mut out, &point, cofactor.as_ptr(), 64);
        if !blst_p1_in_g1(&out) {
            return Err(CryptoError);
        }
    }
    Ok(Point1(out))
}
/// e(a,b) == e(c,d), including the algebraic identity cases permitted by CRY-008.
pub(super) fn pairing_equal(a: &Point1, b: &Point2, c: &Point1, d: &Point2) -> bool {
    let mut aa = blst_p1_affine::default();
    let mut bb = blst_p2_affine::default();
    let mut cc = blst_p1_affine::default();
    let mut dd = blst_p2_affine::default();
    let mut left = blst_fp12::default();
    let mut right = blst_fp12::default();
    // SAFETY: inputs are validated subgroup points; affine and pairing outputs
    // are initialized, live, aligned, and disjoint. finalverify compares the
    // final-exponentiated Miller loops, not raw intermediate values.
    unsafe {
        blst_p1_to_affine(&mut aa, &a.0);
        blst_p2_to_affine(&mut bb, &b.0);
        blst_p1_to_affine(&mut cc, &c.0);
        blst_p2_to_affine(&mut dd, &d.0);
        blst_miller_loop(&mut left, &bb, &aa);
        blst_miller_loop(&mut right, &dd, &cc);
        blst_fp12_finalverify(&left, &right)
    }
}
