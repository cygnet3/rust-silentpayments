use std::{fs::File, io::Read, str::FromStr};

use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::from_str;

use super::structs::TestData;

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

pub fn decode_outpoints(outpoints: &Vec<(String, u32)>) -> Vec<([u8; 32], u32)> {
    outpoints
        .iter()
        .map(|(txid_str, vout)| {
            (
                hex::decode(txid_str)
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
                *vout,
            )
        })
        .collect()
}

pub fn decode_priv_keys(input_priv_keys: &Vec<(String, bool)>) -> Vec<(SecretKey, bool)> {
    input_priv_keys
        .iter()
        .map(|(keystr, x_only)| (SecretKey::from_str(&keystr).unwrap(), *x_only))
        .collect()
}

pub fn decode_input_pub_keys(input_pub_keys: &Vec<String>) -> Vec<PublicKey> {
    input_pub_keys
        .iter()
        .map(|x| match PublicKey::from_str(&x) {
            Ok(key) => key,
            Err(_) => {
                // we always assume even pairing for input public keys if they are omitted
                let x_only_public_key = XOnlyPublicKey::from_str(&x).unwrap();
                PublicKey::from_x_only_public_key(x_only_public_key, secp256k1::Parity::Even)
            }
        })
        .collect()
}

pub fn decode_outputs_to_check(outputs: &Vec<String>) -> Vec<XOnlyPublicKey> {
    outputs
        .iter()
        .map(|x| XOnlyPublicKey::from_str(x).unwrap())
        .collect()
}
