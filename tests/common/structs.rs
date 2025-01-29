#![allow(non_snake_case)]
use serde::Deserialize;
use silentpayments::SilentPaymentAddress;

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingKeyMaterial {
    pub scan_priv_key: String,
    pub spend_priv_key: String,
}

#[derive(Debug, Deserialize)]
pub struct HexStr {
    pub hex: String,
}

#[derive(Debug, Deserialize)]
pub struct ScriptPubKey {
    pub scriptPubKey: HexStr,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingVinData {
    pub txid: String,
    pub vout: u32,
    pub scriptSig: String,
    pub txinwitness: String,
    pub prevout: ScriptPubKey,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub vin: Vec<ReceivingVinData>,
    pub key_material: ReceivingKeyMaterial,
    pub labels: Vec<u32>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub addresses: Vec<SilentPaymentAddress>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub vin: Vec<SendingVinData>,
    pub recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendingVinData {
    pub txid: String,
    pub vout: u32,
    pub scriptSig: String,
    pub txinwitness: String,
    pub prevout: ScriptPubKey,
    pub private_key: String,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct OutputWithSignature {
    pub pub_key: String,
    pub priv_key_tweak: String,
    pub signature: String,
}
