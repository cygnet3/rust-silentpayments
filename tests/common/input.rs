#![allow(non_snake_case)]
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;
use serde_json::from_str;
use silentpayments::structs::OutputWithSignature;

use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::{collections::HashMap, fs::File, io::Read};

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
pub struct ReceivingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_pub_keys: Vec<String>,
    pub bip32_seed: String,
    pub labels: HashMap<String, String>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub addresses: Vec<String>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_priv_keys: Vec<(String, bool)>,
    pub recipients: Vec<(String, f32)>,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<HashMap<String, f32>>,
}

#[derive(Debug)]
pub struct ComparableHashMap {
    pub inner: HashMap<String, f32>,
}

impl From<HashMap<String, f32>> for ComparableHashMap {
    fn from(map: HashMap<String, f32>) -> Self {
        ComparableHashMap { inner: map }
    }
}

impl PartialEq for ComparableHashMap {
    fn eq(&self, other: &Self) -> bool {
        if self.inner.len() != other.inner.len() {
            return false;
        }

        self.inner.iter().all(|(key, val)| {
            other
                .inner
                .get(key)
                .map_or(false, |other_val| (val - other_val).abs() < 0.0001)
        })
    }
}

impl Eq for ComparableHashMap {}

impl Hash for ComparableHashMap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.inner.keys().collect();
        keys.sort(); // ensure consistent order
        for key in keys {
            key.hash(state);
        }
    }
}

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("tests/resources/send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}

// Note: this function is only temporary.
// The format for keys from the test vector will be changed soon.
// Until then, this method is used.
pub fn get_testing_silent_payment_key_pair(
    bytes: &str,
) -> (SecretKey, SecretKey, PublicKey, PublicKey) {
    let secp = Secp256k1::new();

    // test vector key input will change soon

    let (b_scan_str, b_spend_str) = match bytes {
        "0x01" => (
            "a6dba5c9af3ee645c2287c6b1d558d3ea968502ef5343398f48715e624ddd183",
            "d96b8703387c5ffec5d256f80d4dc9f39152b2150fd05e469b011215251aa259",
        ),
        "0x00" => (
            "59984d7f53ff7e0ee345c6e9f5d5e47ae957abf3b55f2272152561db7e700255",
            "d41394c1c9dc1745c50028dc550765dfad87e50b3fdfb15a3e4290ec59ce34c6",
        ),
        "0x02" => (
            "34c45d7dc16b07aba41463fd5437fad2dd05e3da8afd1805ae13062882d4f7c4",
            "944d675e840f52af695d1415564912173b7a4ca740dc946875f9f64b97f8090c",
        ),
        _ => ("", ""),
    };

    let b_scan = SecretKey::from_str(b_scan_str).unwrap();
    let b_spend = SecretKey::from_str(b_spend_str).unwrap();

    let B_scan = b_scan.public_key(&secp);
    let B_spend = b_spend.public_key(&secp);
    (b_scan, b_spend, B_scan, B_spend)
}
