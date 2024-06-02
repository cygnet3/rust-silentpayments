//! Sending utility functions.
use crate::{Error, Result};
use secp256k1::{ecdh::shared_secret_point, PublicKey, Secp256k1, SecretKey};

use super::hash::calculate_input_hash;

/// Calculate the partial secret that is needed for generating the recipient pubkeys.
///
/// # Arguments
///
/// * `input_keys` - A reference to a list of tuples, each tuple containing a [SecretKey] and [bool]. The [SecretKey] is the private key used in the input, and the [bool] indicates whether this was from a taproot address.
/// * `outpoints_data` - The prevout outpoints used as input for this transaction. Note that the txid is given in [String] format, which is displayed in reverse order from the inner byte array.
///
/// # Returns
///
/// This function returns the partial secret, which represents the sum of all (eligible) input keys multiplied with the input hash.
///
/// # Errors
///
/// This function will error if:
///
/// * The input keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints_data is of length zero, or invalid.
pub fn calculate_partial_secret(
    input_keys: &[(SecretKey, bool)],
    outpoints_data: &[(String, u32)],
) -> Result<SecretKey> {
    let a_sum = get_a_sum_secret_keys(input_keys)?;

    let secp = Secp256k1::signing_only();
    let A_sum = a_sum.public_key(&secp);

    let input_hash = calculate_input_hash(outpoints_data, A_sum)?;

    Ok(a_sum.mul_tweak(&input_hash)?)
}

/// Calculate the shared secret of a transaction.
///
/// Since [generate_recipient_pubkeys](crate::sending::generate_recipient_pubkeys) calls this function internally, it is not needed for the default sending flow.
///
/// # Arguments
///
/// * `B_scan` - The scan public key used by the wallet.
/// * `partial_secret` - the sum of all (eligible) input keys multiplied with the input hash, see [calculate_partial_secret].
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to generate output keys for the recipient.
pub fn calculate_ecdh_shared_secret(B_scan: &PublicKey, partial_secret: &SecretKey) -> PublicKey {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Using `shared_secret_point` to ensure the multiplication is constant time
    ss_bytes[1..].copy_from_slice(&shared_secret_point(B_scan, partial_secret));

    PublicKey::from_slice(&ss_bytes).expect("guaranteed to be a point on the curve")
}

fn get_a_sum_secret_keys(input: &[(SecretKey, bool)]) -> Result<SecretKey> {
    if input.is_empty() {
        return Err(Error::GenericError("No input provided".to_owned()));
    }

    let secp = secp256k1::Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, is_taproot) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_taproot && parity == secp256k1::Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(*key);
        }
    }

    let (head, tail) = negated_keys.split_first().expect("input is non-empty");

    let result: SecretKey = tail
        .iter()
        .try_fold(*head, |acc, &item| acc.add_tweak(&item.into()))?;

    Ok(result)
}
