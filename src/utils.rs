use crate::Result;
use secp256k1::{
    hashes::{sha256, Hash},
    PublicKey, Scalar, Secp256k1,
};

pub(crate) fn sha256(message: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(message).into_inner()
}

pub(crate) fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}

pub(crate) fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> Result<Scalar> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(ecdh_shared_secret);
    bytes.extend_from_slice(&ser_uint32(n));

    Ok(Scalar::from_be_bytes(sha256(&bytes))?)
}
