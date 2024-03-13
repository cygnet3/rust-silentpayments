use crate::{utils::calculate_input_hash, Result};
use secp256k1::{PublicKey, SecretKey};

pub fn calculate_tweak_data(
    input_pub_keys: &[&PublicKey],
    outpoints_data: &[(String, u32)],
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();
    let A_sum = PublicKey::combine_keys(input_pub_keys)?;
    let input_hash = calculate_input_hash(outpoints_data, A_sum)?;

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

pub fn calculate_shared_secret(tweak_data: PublicKey, b_scan: SecretKey) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();

    Ok(tweak_data.mul_tweak(&secp, &b_scan.into())?)
}
