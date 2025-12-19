# Silent Payments

A rust implementation of BIP352: Silent Payments.

## About

**Warning: both this crate and BIP352 are still quite new.
Review this library carefully before using it with mainnet funds.**

This library supports creating and sending to silent payment addresses,
building on [`secp256k1`](https://docs.rs/secp256k1/latest/secp256k1)
`PublicKey` and `SecretKey` structs for the interface.
In the future, the library will probably be expanded to rely on structs from rust-bitcoin as well.

The library is split up in two parts: sending and receiving.

## Feature Flags

This library offers granular feature flags to minimize dependencies for different use cases:

- **default**: Enables all features (`encode`, `sending`, `receiving`)
- **encode**: Enables string encoding/decoding for `SilentPaymentAddress` (adds `bech32` dependency)
- **serde**: Enables serde serialization/deserialization for types (adds `serde` dependency)
- **sending**: Enables sending functionality (adds `bitcoin_hashes`, `hex` dependencies)
- **receiving**: Enables receiving functionality (adds `bitcoin_hashes`, `hex`, `bimap`, `serde` dependencies)

### Minimal Usage

If you only need the type definitions (`Network` and `SilentPaymentAddress`) without any protocol functionality:

```toml
[dependencies]
silentpayments = { version = "0.4", default-features = false }
```

This configuration only pulls in `secp256k1` as a dependency, significantly reducing the dependency tree for applications that only need to work with silent payment addresses without implementing the full protocol.

**Bring Your Own Parser**: Even without the `encode` feature, you can construct a `SilentPaymentAddress` using `SilentPaymentAddress::new()` if you parse the bech32 yourself. This is useful if your application already has a bech32 parser and you want to avoid duplicate dependencies. The constructor documentation includes the complete bech32 format specification.

### Custom Feature Combinations

You can enable only the features you need:

```toml
# Just types and string encoding (no protocol implementation)
silentpayments = { version = "0.4", default-features = false, features = ["encode"] }

# Types with serde support (no protocol or encoding)
silentpayments = { version = "0.4", default-features = false, features = ["serde"] }

# Only sending capability
silentpayments = { version = "0.4", default-features = false, features = ["sending"] }

# Only receiving capability
silentpayments = { version = "0.4", default-features = false, features = ["receiving"] }
```

## Sending

For sending to a silent payment address, you can call the `sender::generate_recipient_pubkeys` function.
This function takes a list of silent payment recipients, as well as a `partial_secret`.

The `partial_secret` represents the sum of all input private keys multiplied with the input hash.
To compute the `partial_secret`, the `utils::sending::compute_partial_secret` function can be used,
although this requires exposing secret data to this library.
Other methods for calculating the `partial_secret` will be added later.

## Recipient

For receiving silent payments, we use the `receiving::Receiver` struct.
This `Receiver` struct implements a `scan_transaction` function that can be used to scan an incoming transaction for newly received payments.

The library also supports labels.
The change label (label for generating change addresses) is included by default.
You can add additional labels before scanning by using the `add_label` function.

## Examples

Check out the `examples` folder for some simple sending and receiving examples.
These examples are still very elementary, and will be expanded later.
In the meantime, you can look at `tests/vector_tests.rs` to see how sending and receiving works in more detail.

We are also working on another project called [SPDK](https://github.com/cygnet3/spdk)
(Silent Payments Development Kit) which builds on this library.
SPDK can be used as a basis for building a silent payments wallet.
It allows for scanning for incoming payments, as well as sending.
Even if SPDK itself doesn't seem interesting to you, it could still be a good resource
for showing how this library can be integrated with wallets.

## Tests

The `tests/resources` folder contains a copy of the test vectors as of May 1st 2024.

You can test the code using the test vectors by running `cargo test`.
