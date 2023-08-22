# Silent Payments

A rust implementation of BIP352: Silent Payments.

Although this library passes all the tests provided in the silent payment BIP,
it is still very new, so be careful when using this with real funds.

There are two parts to this library: a sender part and a recipient part.

## Sender

For sending to a silent payment address, you can call the `sender::generate_recipient_pubkeys` function.
This function takes a `recipient: Vec<String>` as an argument, where the `String` is a bech32m encoded silent payment address (`sp1q...` or `tsp1q...`).

This function additionally takes a `ecdh_shared_secrets: HashMap<PublicKey, PublicKey>` argument, which maps a Spend key to a shared secret.
Since this shared secret derivation requires secret data, this library expects the user to provide the pre-computed result.

See the `tests/vector_tests.rs` and `tests/common/utils.rs` files for an example of how to compute the shared secrets.

## Recipient

For receiving silent payments. We have use a struct called `recipient::SilentPayment`.
After creating this struct with a spending and scanning secret key,
you can call the `scan_transaction` function to look for any outputs in a transaction belonging to you.

The library also supports labels. You can optionally add labels before scanning by using the `add_label` function.

## Tests

The `tests/resources` folder contains a copy of the test vectors as of August 4th 2023.

You can test the code using the test vectors by running `cargo test`.
