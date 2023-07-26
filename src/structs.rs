use serde::Deserialize;

use crate::sending::SilentPaymentAddress;

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

pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

pub struct Recipient {
    pub payment_address: SilentPaymentAddress,
    pub amount: f32,
}
