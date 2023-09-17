use std::io::Write;

use crate::Result;
use secp256k1::{
    hashes::{sha256, Hash},
    Scalar,
};

pub mod receiving;
pub mod sending;

pub fn hash_outpoints(sending_data: &Vec<(String, u32)>) -> Result<Scalar> {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for outpoint in sending_data {
        let mut bytes: Vec<u8> = hex::decode(outpoint.0.as_str())?;

        // txid in string format is big endian and we need little endian
        bytes.reverse();

        bytes.extend_from_slice(&outpoint.1.to_le_bytes());
        outpoints.push(bytes);
    }

    // sort outpoints
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v)?;
    }

    Ok(Scalar::from_be_bytes(
        sha256::Hash::from_engine(engine).into_inner(),
    )?)
}
