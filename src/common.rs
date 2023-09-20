use secp256k1::{
    hashes::{sha256, Hash},
    PublicKey, Scalar, Secp256k1, SecretKey,
};
use crate::Result;

pub(crate) fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> Result<SecretKey> {
    let mut bytes = [0u8; 37];
    bytes[..33].copy_from_slice(ecdh_shared_secret);
    bytes[33..].copy_from_slice(&n.to_be_bytes());

    let hash = sha256::Hash::hash(&bytes).into_inner();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}
