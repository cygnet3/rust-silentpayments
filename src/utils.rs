use std::io::Write;

use crate::Error;
use bitcoin_hashes::{sha256t_hash_newtype, sha256, Hash, HashEngine};
use secp256k1::{
    PublicKey,
    Scalar,
    SecretKey,
};

pub mod receiving;
pub mod sending;

sha256t_hash_newtype! {
    pub struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub struct InputsHash(_);

    pub struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub struct LabelHash(_);

    pub struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub struct SharedSecretHash(_);
}

impl InputsHash {
    pub fn from_outpoint_and_A_sum(
        smallest_outpoint: &Vec<u8>,
        A_sum: &PublicKey,
    ) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint);
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub fn from_b_scan_and_m(
        b_scan: SecretKey,
        m: u32,
    ) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub fn from_ecdh_and_k(
        ecdh: &PublicKey,
        k: u32,
    ) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub fn hash_outpoints(sending_data: &Vec<(String, u32)>) -> Result<Scalar, Error> {
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
        sha256::Hash::from_engine(engine).to_byte_array(),
    )?)
}
