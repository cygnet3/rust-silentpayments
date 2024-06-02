use crate::utils::hash::SharedSecretHash;
use crate::Result;
use bitcoin_hashes::Hash;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

pub(crate) fn calculate_t_n(ecdh_shared_secret: &PublicKey, k: u32) -> Result<SecretKey> {
    let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}
