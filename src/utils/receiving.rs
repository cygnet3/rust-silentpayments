use crate::{utils::hash_outpoints, Result};
use secp256k1::{PublicKey, SecretKey};

pub fn recipient_calculate_tweak_data(
    input_pub_keys: &Vec<PublicKey>,
    outpoints: &Vec<(String, u32)>,
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::new();
    let A_sum = recipient_get_A_sum_public_keys(input_pub_keys);
    let outpoints_hash = hash_outpoints(outpoints, A_sum)?;

    Ok(A_sum.mul_tweak(&secp, &outpoints_hash)?)
}

pub fn recipient_calculate_shared_secret(
    tweak_data: PublicKey,
    b_scan: SecretKey,
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::new();

    Ok(tweak_data.mul_tweak(&secp, &b_scan.into())?)
}

fn recipient_get_A_sum_public_keys(input: &Vec<PublicKey>) -> PublicKey {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs).unwrap()
}
