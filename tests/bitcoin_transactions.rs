use minimint_ng::{
    bitcoin::{self, Transaction},
    codec::{
        DecodeError,
        text::{hex_decode, hex_encode},
    },
};
const UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
const SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
#[test]
fn independent_bip143_native_witness_vector() {
    // Public-domain BIP143 Native P2WPKH example, https://bips.dev/143/.
    // The same scriptCode serialization/hash algorithm underlies Wallet P2WSH.
    let bytes = hex_decode(UNSIGNED).unwrap();
    let transaction = Transaction::decode(&bytes).unwrap();
    assert_eq!(transaction.encode(), bytes);
    let script = hex_decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac").unwrap();
    assert_eq!(
        hex_encode(&transaction.sighash_all(1, &script, 600_000_000).unwrap()),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    assert_ne!(
        transaction.sighash_all(1, &script, 600_000_001).unwrap(),
        transaction.sighash_all(1, &script, 600_000_000).unwrap()
    );
    assert!(transaction.sighash_all(2, &script, 0).is_err());
}
#[test]
fn independent_signed_bytes_and_txid_witness_separation() {
    let bytes = hex_decode(SIGNED).unwrap();
    let mut transaction = Transaction::decode(&bytes).unwrap();
    assert_eq!(transaction.encode(), bytes);
    assert!(transaction.inputs[0].witness.is_empty());
    assert_eq!(transaction.inputs[1].witness.len(), 2);
    let txid = transaction.txid();
    let wtxid = transaction.wtxid();
    transaction.inputs[1].witness[0][0] ^= 1;
    assert_eq!(transaction.txid(), txid);
    assert_ne!(transaction.wtxid(), wtxid);
    let mut raw = txid.0;
    raw.reverse();
    assert_eq!(txid.display_hex(), hex_encode(&raw));
    assert_eq!(
        transaction.weight(),
        (transaction.encode_without_witness().len() * 3 + transaction.encode().len()) as u64
    );
}
#[test]
fn finite_parser_rejects_truncation_nonminimal_counts_flags_and_suffix() {
    let bytes = hex_decode(SIGNED).unwrap();
    for end in 0..bytes.len() {
        assert!(Transaction::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Transaction::decode(&trailing),
        Err(DecodeError::TrailingBytes)
    );
    let mut flag = bytes;
    flag[5] = 3;
    assert!(Transaction::decode(&flag).is_err());
    let bytes = hex_decode(UNSIGNED).unwrap();
    let mut nonminimal = bytes[..4].to_vec();
    nonminimal.extend([253, 2, 0]);
    nonminimal.extend(&bytes[5..]);
    assert_eq!(
        Transaction::decode(&nonminimal),
        Err(DecodeError::NonCanonical)
    );
}
#[test]
fn block_parser_preserves_transaction_order_and_exact_header_hash() {
    let header = [3_u8; 80];
    let mut bytes = header.to_vec();
    bytes.push(2);
    bytes.extend(hex_decode(UNSIGNED).unwrap());
    bytes.extend(hex_decode(SIGNED).unwrap());
    let block = bitcoin::Block::decode(&bytes).unwrap();
    assert_eq!(block.header, header);
    assert_eq!(block.hash(), bitcoin::double_sha256(&header));
    assert_eq!(
        block.transactions[0].encode(),
        hex_decode(UNSIGNED).unwrap()
    );
    assert_eq!(block.transactions[1].encode(), hex_decode(SIGNED).unwrap());
    bytes.push(0);
    assert!(bitcoin::Block::decode(&bytes).is_err());
}
