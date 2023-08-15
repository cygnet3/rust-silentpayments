use serde::Deserialize;

#[derive(Debug)]
pub struct ScannedOutput {
    pub pub_key: String,
    pub priv_key_tweak: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct OutputWithSignature {
    pub pub_key: String,
    pub priv_key_tweak: String,
    pub signature: String,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}
