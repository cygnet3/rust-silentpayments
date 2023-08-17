
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::{Result, utils::ser_uint32};

pub fn get_A_sum_public_keys(
    input: &Vec<PublicKey>,
) -> std::result::Result<PublicKey, secp256k1::Error> {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs)
}


pub fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}

pub(crate) fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> Result<Scalar> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(ecdh_shared_secret);
    bytes.extend_from_slice(&ser_uint32(n));

    Ok(Scalar::from_be_bytes(crate::utils::sha256(&bytes))?)
}

pub(crate) fn calculate_ecdh_secret(
    A_sum: &PublicKey,
    b_scan: SecretKey,
    outpoints_hash: [u8; 32],
) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();

    let intermediate = A_sum.mul_tweak(&secp, &b_scan.into())?;
    let scalar = Scalar::from_be_bytes(outpoints_hash)?;
    let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar)?.serialize();

    Ok(ecdh_shared_secret)
}
