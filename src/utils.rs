use std::{collections::HashSet, io::Write};

use secp256k1::hashes::{sha256, Hash};


use crate::{Result, structs::Outpoint};

pub fn sha256(message: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(message).into_inner()
}

pub fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

pub fn hash_outpoints(sending_data: &HashSet<Outpoint>) -> Result<[u8; 32]> {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for outpoint in sending_data {
        let txid = outpoint.txid;
        let vout = outpoint.vout;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&txid);
        bytes.reverse();
        bytes.extend_from_slice(&vout.to_le_bytes());
        outpoints.push(bytes);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v).unwrap();
    }

    Ok(sha256::Hash::from_engine(engine).into_inner())
}
