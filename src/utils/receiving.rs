use crate::{utils::calculate_input_hash, Result};
use secp256k1::{PublicKey, SecretKey};

/// Calculate the tweak data of a transaction.
/// This is useful in combination with the `calculate_shared_secret` function, but can also be used
/// by indexing servers that don't have access to the recipient scan key.
///
/// # Arguments
///
/// * `input_pub_keys` - The list of public keys that are used as input for this transaction. Only the public keys for inputs that are silent payment eligible should be given.
/// * `outpoints_data` - All prevout outpoints used as input for this transaction. Note that the txid is given in String format, which is displayed in reverse order from the inner byte array.
///
/// # Returns
///
/// This function returns the tweak data for this transaction. The tweak data is an intermediary result that can be used to calculate the final shared secret.
///
/// # Errors
///
/// This function will error if:
///
/// * The input public keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints_data is of length zero, or invalid.
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_tweak_data(
    input_pub_keys: &[&PublicKey],
    outpoints_data: &[(String, u32)],
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();
    let A_sum = PublicKey::combine_keys(input_pub_keys)?;
    let input_hash = calculate_input_hash(outpoints_data, A_sum)?;

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

/// Calculate the shared secret of a transaction.
///
/// # Arguments
///
/// * `tweak_data` - The tweak data of the transaction, see `calculate_tweak_data`.
/// * `b_scan` - The scan private key used by the wallet.
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See `receiving::scan_transaction`.
///
/// # Errors
///
/// This function will error if:
///
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_shared_secret(tweak_data: PublicKey, b_scan: SecretKey) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();

    Ok(tweak_data.mul_tweak(&secp, &b_scan.into())?)
}
