use std::io::Write;

use hex::FromHex;
use secp256k1::hashes::{sha256, Hash};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn sha256(message: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(message).to_byte_array()
}

pub fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

pub fn hash_outpoints(sending_data: &Vec<(String, u32)>) -> Result<[u8; 32]> {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for (txid_str, vout) in sending_data {
        let mut txid = Vec::from_hex(txid_str)?;
        txid.reverse();
        let mut vout_bytes = vout.to_le_bytes().to_vec();
        txid.append(&mut vout_bytes);
        outpoints.push(txid);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v)?;
    }

    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}
