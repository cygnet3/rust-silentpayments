use std::io::Write;

use secp256k1::hashes::{sha256, Hash};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn sha256(message: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(message).to_byte_array()
}

pub fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

pub fn hash_outpoints(sending_data: &Vec<([u8; 32], u32)>) -> Result<[u8; 32]> {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for (txid, vout) in sending_data {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(txid);
        bytes.reverse();
        bytes.extend_from_slice(&vout.to_le_bytes());
        outpoints.push(bytes);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v)?;
    }

    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}
