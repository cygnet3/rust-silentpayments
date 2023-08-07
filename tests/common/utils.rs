use std::{collections::HashSet, fs::File, io::Read, str::FromStr};

use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use serde_json::from_str;
use silentpayments::structs::Outpoint;

use super::structs::TestData;

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("tests/resources/send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}

pub fn decode_outpoints(outpoints: &Vec<(String, u32)>) -> HashSet<Outpoint> {
    outpoints
        .iter()
        .map(|(txid_str, vout)| Outpoint {
            txid: hex::decode(txid_str)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
            vout: *vout,
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

pub fn decode_recipients(recipients: &Vec<(String, f32)>) -> Vec<String> {
    recipients
        .iter()
        .map(|(sp_addr_str, _)| sp_addr_str.to_owned())
        .collect()
}

pub fn get_a_sum_secret_keys(input: &Vec<(SecretKey, bool)>) -> SecretKey {
    let secp = secp256k1::Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, is_xonly) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_xonly && parity == secp256k1::Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(key.clone());
        }
    }

    let (head, tail) = negated_keys.split_first().unwrap();

    let result: SecretKey = tail
        .iter()
        .fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

    result
}

pub fn compute_diffie_hellman(k: SecretKey, X: PublicKey) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();

    X.mul_tweak(&secp, &k.into()).unwrap()
}
