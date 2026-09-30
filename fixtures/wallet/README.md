# Wallet fixture provenance

All keys here are public test scalars. No production secrets or funds are used.

- `filter.json`: Python `hashlib` plus OpenSSL's public EC arithmetic, independent of the Rust k256 Wallet implementation. `generate_filter_fixture.py` searches a deterministic claimant key for guardian scalars 1–4 and records the exact tweaked script and discovery-filter hash.
- `long-script-filter.json`: `generate_long_script.py` demonstrates that a 253-byte Bitcoin script must use CompactSize, not common BigSize, for the discovery filter commitment.
- `transactions.json`, `consolidation.hex`, `withdrawal.hex`: `generate_transactions.py` independently uses Python `struct`/`hashlib` and OpenSSL EC to apply WAL-002/005–008 to the public filter fixture. These are specification-calculated fixtures; they are not Bitcoin Core acceptance or baseline execution evidence.
- `tests/bitcoin_transactions.rs` also embeds the public-domain [BIP143 Native P2WPKH example](https://bips.dev/143/), including its published signed bytes and SIGHASH_ALL digest. The same v0 scriptCode framing/hash algorithm is used for the Wallet's P2WSH scripts, which contain no OP_CODESEPARATOR.

Generators run inside the repository's `nix-shell`. OpenSSL's [public EC operations](https://docs.openssl.org/3.0/man3/EC_POINT_add/) are used only by these offline fixture generators; the daemon has no added raw EC FFI.
