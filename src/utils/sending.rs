use crate::Result;
use secp256k1::{Scalar, SecretKey};

pub fn sender_calculate_partial_secret(
    a_sum: SecretKey,
    outpoints_hash: Scalar,
) -> Result<SecretKey> {
    Ok(a_sum.mul_tweak(&outpoints_hash)?)
}
