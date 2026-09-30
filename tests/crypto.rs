use minimint_ng::crypto::{
    self,
    bls::{self, G1, G2, Scalar},
    secp::{self, SecretKey},
};
fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}
#[test]
fn published_hash_and_hmac() {
    assert_eq!(
        crypto::sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(crypto::hmac_sha512(&[0x0b;20],b"Hi There").unwrap(),hex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854".replace(' ',"").as_str()));
    assert_ne!(
        crypto::random_bytes::<32>().unwrap(),
        crypto::random_bytes::<32>().unwrap()
    );
}
#[test]
fn bip340_vector_zero_and_exact_prehash() {
    let secret = SecretKey::from_bytes(&hex(
        "0000000000000000000000000000000000000000000000000000000000000003",
    ))
    .unwrap();
    let public = hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
    let sig = hex(
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    );
    assert_eq!(secp::x_only(&secret.public_key()).unwrap(), public);
    secp::schnorr_verify(&public, &[0; 32], &sig).unwrap();
    secp::schnorr_verify(&public, &[0; 32], &secret.schnorr_sign(&[0; 32]).unwrap()).unwrap();
    assert!(secp::schnorr_verify(&public, &[1; 32], &sig).is_err());
}
#[test]
fn secp_keys_ecdsa_and_tweaks() {
    assert!(SecretKey::from_bytes(&[0; 32]).is_err());
    assert!(SecretKey::from_bytes(&[255; 32]).is_err());
    assert!(secp::validate_public_key(&[0; 33]).is_err());
    let key = SecretKey::random().unwrap();
    let msg = crypto::sha256(b"guardian");
    let sig = key.ecdsa_sign(&msg).unwrap();
    secp::ecdsa_verify(&key.public_key(), &msg, &sig).unwrap();
    assert!(secp::ecdsa_verify(&key.public_key(), &[0; 32], &sig).is_err());
    let mut tweak = [0; 32];
    tweak[31] = 1;
    assert_eq!(
        key.add_tweak(&tweak).unwrap().public_key(),
        secp::add_tweak(&key.public_key(), &tweak).unwrap()
    );
    assert!(key.add_tweak(&[255; 32]).is_err());
}
#[test]
fn published_mint_mappings_and_threshold_pairing() {
    assert_eq!(
        bls::message_original(b"fedimint-spec").unwrap().to_bytes(),
        hex(
            "902e33c27ebc0af6afabafaee329447ac99f5c4763f96093ccbd6a4763e51c8dd4a6d7a1af0a14e543dd8680a1c988aa"
        )
    );
    let msg = bls::message_sha256(b"fedimint-spec").unwrap();
    assert_eq!(
        msg.to_bytes(),
        hex(
            "81f5c40cf3d7b3fed4b87647767c57f1514a8c88dfa371fa73dde0f8f9fdda5c41b76ef6bbe411e8e2b697873521cf9a"
        )
    );
    let pk=G2::from_bytes(&hex("80fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688")).unwrap();
    let sig=G1::from_bytes(&hex("99a87974b81bb8927e94d76168cbb312cd39adffb1fcdb356506445f5695b1e42b55f69691a7077d58758b28dfd9186f")).unwrap();
    bls::verify_share(&msg, &pk, &sig).unwrap();
    assert!(bls::verify_share(&G1::generator(), &pk, &sig).is_err());
}
#[test]
fn canonical_bls_objects() {
    assert_eq!(
        G1::generator().to_bytes(),
        hex(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        )
    );
    for id in [G1::identity().to_bytes()] {
        assert!(G1::from_bytes(&id).unwrap().is_identity());
    }
    assert!(
        G2::from_bytes(&G2::identity().to_bytes())
            .unwrap()
            .is_identity()
    );
    assert!(Scalar::from_bytes(&[0; 32]).unwrap().is_zero());
    assert!(
        Scalar::from_bytes(&hex(
            "01000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"
        ))
        .is_err()
    );
    assert!(Scalar::from_bytes(&[255; 32]).is_err());
    assert!(G1::from_bytes(&[0; 48]).is_err());
    assert!(G2::from_bytes(&[0; 96]).is_err());
    let mut inf = G1::identity().to_bytes();
    inf[0] |= 32;
    assert!(G1::from_bytes(&inf).is_err());
    inf[0] = 0xc0;
    inf[47] = 1;
    assert!(G1::from_bytes(&inf).is_err());
    // (0,2) is on the curve but outside the prime subgroup.
    let mut torsion = [0; 48];
    torsion[0] = 0x80;
    assert!(G1::from_bytes(&torsion).is_err());
    assert!(Scalar::from_u64(0).inverse().is_err());
}
#[test]
fn all_four_three_of_four_subsets() {
    let fixed: Vec<[u8; 96]> = include_str!("fixtures/crypto/dkg-three-of-four.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| hex(line.split_once(' ').unwrap().1))
        .collect();
    let coefficients = [
        Scalar::from_u64(5),
        Scalar::from_u64(7),
        Scalar::from_u64(11),
    ];
    let commitments: Vec<_> = coefficients
        .iter()
        .map(|s| G2::generator().mul(s))
        .collect();
    let message = bls::message_sha256(b"threshold fixture").unwrap();
    for omitted in 0..4 {
        let mut signatures = Vec::new();
        let mut publics = Vec::new();
        for id in (0..4).filter(|id| *id != omitted) {
            let secret = bls::evaluate_polynomial(&coefficients, id).unwrap();
            let public = bls::evaluate_commitments(&commitments, id).unwrap();
            assert_eq!(public.to_bytes(), G2::generator().mul(&secret).to_bytes());
            assert_eq!(public.to_bytes(), fixed[usize::from(id) + 1]);
            let sig = bls::sign_share(&message, &secret);
            bls::verify_share(&message, &public, &sig).unwrap();
            signatures.push((id, sig));
            publics.push((id, public));
        }
        let sig = bls::interpolate_g1(&signatures, 3).unwrap();
        let pk = bls::interpolate_g2(&publics, 3).unwrap();
        assert_eq!(pk.to_bytes(), commitments[0].to_bytes());
        assert_eq!(sig.to_bytes(), message.mul(&coefficients[0]).to_bytes());
        assert_eq!(pk.to_bytes(), fixed[0]);
        bls::verify_share(&message, &pk, &sig).unwrap();
        assert!(bls::interpolate_g1(&signatures[..2], 3).is_err());
    }
    assert!(bls::interpolate_g1(&[], 0).is_err());
    assert!(bls::interpolate_g1(&[(0, G1::generator()), (0, G1::generator())], 2).is_err());
    assert_eq!(
        bls::interpolate_g1(&[(u16::MAX, G1::generator())], 1)
            .unwrap()
            .to_bytes(),
        G1::generator().to_bytes()
    );
}

#[test]
fn ecdsa_der_and_high_s_rejection() {
    let key = SecretKey::from_bytes(&hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    ))
    .unwrap();
    let msg = crypto::sha256(b"DER boundary");
    let sig = key.ecdsa_sign(&msg).unwrap();
    let der = secp::ecdsa_compact_to_der(&sig).unwrap();
    assert_eq!(secp::ecdsa_der_to_compact(&der).unwrap(), sig);
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(secp::ecdsa_der_to_compact(&trailing).is_err());
    assert!(secp::ecdsa_der_to_compact(&[0x30, 0]).is_err());
    assert!(secp::ecdsa_compact_to_der(&[0; 64]).is_err());
    let order = openssl::bn::BigNum::from_hex_str(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    )
    .unwrap();
    let low_s = openssl::bn::BigNum::from_slice(&sig[32..]).unwrap();
    let mut high_s = openssl::bn::BigNum::new().unwrap();
    high_s.checked_sub(&order, &low_s).unwrap();
    let mut malleated = sig;
    malleated[32..].copy_from_slice(&high_s.to_vec_padded(32).unwrap());
    assert!(secp::ecdsa_verify(&key.public_key(), &msg, &malleated).is_err());
    assert!(secp::ecdsa_compact_to_der(&malleated).is_err());
    let native = k256::ecdsa::Signature::from_slice(&malleated).unwrap();
    assert!(secp::ecdsa_der_to_compact(native.to_der().as_bytes()).is_err());
}
#[test]
fn scalar_field_and_identity_edges() {
    let zero = Scalar::from_u64(0);
    let one = Scalar::from_u64(1);
    let five = Scalar::from_u64(5);
    assert_eq!(
        five.mul(&five.inverse().unwrap()).to_bytes(),
        one.to_bytes()
    );
    assert!(five.sub(&five).is_zero());
    assert_eq!(five.sub(&one).to_bytes(), Scalar::from_u64(4).to_bytes());
    assert!(G1::generator().mul(&zero).is_identity());
    assert!(G2::generator().mul(&zero).is_identity());
    assert!(G1::identity().mul(&five).is_identity());
    assert!(G2::identity().mul(&five).is_identity());
    assert_eq!(
        G1::generator().add(&G1::generator()).to_bytes(),
        G1::generator().mul(&Scalar::from_u64(2)).to_bytes()
    );
    assert_eq!(
        G2::generator().add(&G2::generator()).to_bytes(),
        G2::generator().mul(&Scalar::from_u64(2)).to_bytes()
    );
    bls::verify_share(&G1::identity(), &G2::generator(), &G1::identity()).unwrap();
    bls::verify_share(&G1::generator(), &G2::identity(), &G1::identity()).unwrap();
    assert!(bls::verify_share(&G1::generator(), &G2::generator(), &G1::identity()).is_err());
    assert!(bls::evaluate_polynomial(&[], 0).is_err());
    assert!(bls::evaluate_commitments(&[], 0).is_err());
    let mut modulus = hex::<32>("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    modulus.reverse();
    assert!(Scalar::from_bytes(&modulus).is_err());
    modulus[0] -= 1;
    let minus_one = Scalar::from_bytes(&modulus).unwrap();
    assert!(minus_one.add(&one).is_zero());
    assert_eq!(minus_one.mul(&minus_one).to_bytes(), one.to_bytes());
    assert!(
        G1::generator()
            .add(&G1::generator().mul(&minus_one))
            .is_identity()
    );
    assert!(
        G2::generator()
            .add(&G2::generator().mul(&minus_one))
            .is_identity()
    );
    assert!(bls::interpolate_g2(&[(1, G2::generator()), (1, G2::generator())], 2).is_err());
}
#[test]
fn secp_noncanonical_and_zero_tweaks() {
    let key = SecretKey::from_bytes(&hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    ))
    .unwrap();
    let cancellation = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    assert!(key.add_tweak(&cancellation).is_err());
    assert!(secp::add_tweak(&key.public_key(), &cancellation).is_err());
    assert_eq!(
        key.add_tweak(&[0; 32]).unwrap().public_key(),
        key.public_key()
    );
    assert_eq!(
        secp::add_tweak(&key.public_key(), &[0; 32]).unwrap(),
        key.public_key()
    );
    let mut badkey = key.public_key();
    badkey[0] = 4;
    assert!(secp::validate_public_key(&badkey).is_err());
    assert!(secp::schnorr_verify(&[255; 32], &[0; 32], &[0; 64]).is_err());
    let pubkey = secp::x_only(&key.public_key()).unwrap();
    let mut sig = key.schnorr_sign(&[0; 32]).unwrap();
    sig[..32].copy_from_slice(&hex::<32>(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    ));
    assert!(secp::schnorr_verify(&pubkey, &[0; 32], &sig).is_err());
    let mut sig = key.schnorr_sign(&[0; 32]).unwrap();
    sig[32..].copy_from_slice(&hex::<32>(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ));
    assert!(secp::schnorr_verify(&pubkey, &[0; 32], &sig).is_err());
}
#[test]
fn seeded_scalar_and_bls_malformed_coordinates() {
    // Original ChaCha20 all-zero key/IV first block, reduced LE modulo r with
    // independent Python integer arithmetic (CRY-005).
    assert_eq!(
        Scalar::from_seed(&[0; 32]).unwrap().to_bytes(),
        hex("722b8ec1cd5676c4ef0d4e3c131a2e63f65fe4f67c862445d7c61b561aef712d")
    );
    let random = Scalar::random().unwrap();
    assert_eq!(
        Scalar::from_bytes(&random.to_bytes()).unwrap().to_bytes(),
        random.to_bytes()
    );
    let mut torsion = [0; 96];
    torsion[0] = 0x80;
    torsion[95] = 2;
    assert!(G2::from_bytes(&torsion).is_err());
    let modulus = hex::<48>(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    );
    let mut g1 = modulus;
    g1[0] |= 0x80;
    assert!(G1::from_bytes(&g1).is_err());
    let mut g2 = G2::generator().to_bytes();
    g2[..48].copy_from_slice(&modulus);
    g2[0] |= 0x80;
    assert!(G2::from_bytes(&g2).is_err());
    let mut g2 = G2::generator().to_bytes();
    g2[48..].copy_from_slice(&modulus);
    assert!(G2::from_bytes(&g2).is_err());
    let mut infinity = G2::identity().to_bytes();
    infinity[0] |= 0x20;
    assert!(G2::from_bytes(&infinity).is_err());
    infinity[0] = 0xc0;
    infinity[95] = 1;
    assert!(G2::from_bytes(&infinity).is_err());
    let mut uncompressed = G1::generator().to_bytes();
    uncompressed[0] &= 0x7f;
    assert!(G1::from_bytes(&uncompressed).is_err());
    let mut uncompressed = G2::generator().to_bytes();
    uncompressed[0] &= 0x7f;
    assert!(G2::from_bytes(&uncompressed).is_err());
}
#[test]
fn published_two_share_interpolation() {
    let share0=G1::from_bytes(&hex("821e8fe764c05dde6d84d8a26d5b3d07ab0ada08d5ffd934f15730ee721521e4fdd8845fb2803188d85831dab98c0e87")).unwrap();
    let share1=G1::from_bytes(&hex("b351151c9fca6c52f3baa14ac02ce901fd8961bbb967df3b185b933e1e97497d41028aaa739dfbb1d33bd7d6fbc0532a")).unwrap();
    assert_eq!(
        bls::interpolate_g1(&[(0, share0), (1, share1)], 2)
            .unwrap()
            .to_bytes(),
        hex(
            "99fd0c4099f1dbf29179aca7b16d2ad3588312f13db9974e030b8f459b0a33b4737d069edcec0eb1e0fda880e7ee1c15"
        )
    );
}
#[test]
fn bitcoin_hash160_known_answers() {
    assert_eq!(
        crypto::hash160(b"").unwrap(),
        hex("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
    );
    assert_eq!(
        crypto::hash160(b"hello").unwrap(),
        hex("b6a9c8c230722b7c748331a8b450f05566dc7d0f")
    );
}
