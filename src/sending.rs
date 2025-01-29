//! The sending component of silent payments.
//!
//! The [`generate_recipient_pubkeys`] function can be used to create outputs for a list of silent payment recipients.
//!
//! Using [`generate_recipient_pubkeys`] will require calculating a
//! `partial_secret` beforehand.
//! To do this, you can use [`calculate_partial_secret`](crate::utils::sending::calculate_partial_secret) from the `utils` module.
//! See the [tests on github](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! for a concrete example.

use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::collections::HashMap;

use crate::utils::common::calculate_t_n;
use crate::utils::sending::calculate_ecdh_shared_secret;
use crate::Result;
use crate::SilentPaymentAddress;

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
///
/// This function should only be used once per transaction! If used multiple times, address reuse may occur.
///
/// # Arguments
///
/// * `recipients` - A [Vec] of silent payment addresses strings to be paid.
/// * `partial_secret` - A [SecretKey] that represents the sum of the private keys of eligible inputs of the transaction multiplied by the input hash.
///
/// # Returns
///
/// If successful, the function returns a [Result] wrapping a [HashMap] of silent payment addresses to a [Vec].
/// The [Vec] contains all the outputs that are associated with the silent payment address.
///
/// # Errors
///
/// This function will return an error if:
///
/// * The recipients [Vec] contains a silent payment address with an incorrect format.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: Vec<SilentPaymentAddress>,
    partial_secret: SecretKey,
) -> Result<HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (PublicKey, Vec<SilentPaymentAddress>)> =
        HashMap::new();
    for address in recipients {
        let B_scan = address.get_scan_key();

        if let Some((_, payments)) = silent_payment_groups.get_mut(&B_scan) {
            payments.push(address);
        } else {
            let ecdh_shared_secret = calculate_ecdh_shared_secret(&B_scan, &partial_secret);

            silent_payment_groups.insert(B_scan, (ecdh_shared_secret, vec![address]));
        }
    }

    let mut result: HashMap<SilentPaymentAddress, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let mut n = 0;

        let (ecdh_shared_secret, recipients) = group;

        for addr in recipients {
            let t_n = calculate_t_n(&ecdh_shared_secret, n)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&addr.get_spend_key())?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(addr.into()).or_default();
            entry.push(reskey_xonly);
            n += 1;
        }
    }
    Ok(result)
}
