use std::collections::{HashMap, HashSet};

#[cfg(feature = "receiving")]
use crate::receiving::{Label, NULL_LABEL};

use crate::{Error, Result};
use secp256k1::{
    hashes::{sha256, Hash},
    PublicKey, Scalar, Secp256k1, SecretKey,
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

pub(crate) fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> Result<SecretKey> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(ecdh_shared_secret);
    bytes.extend_from_slice(&ser_uint32(n));

    let sk = SecretKey::from_slice(&sha256(&bytes))?;

    Ok(sk)
}

#[cfg(feature = "receiving")]
pub(crate) fn insert_new_key(
    mut new_privkey: SecretKey,
    my_outputs: &mut HashMap<Label, HashSet<SecretKey>>,
    label: Option<&Label>,
) -> Result<()> {
    let label: &Label = match label {
        Some(l) => {
            new_privkey = new_privkey.add_tweak(l.as_inner())?;
            l
        }
        None => &NULL_LABEL,
    };

    let res = my_outputs
        .entry(label.to_owned())
        .or_insert_with(HashSet::new)
        .insert(new_privkey.into());

    if res {
        Ok(())
    } else {
        Err(Error::GenericError("Duplicate key found".to_owned()))
    }
}
