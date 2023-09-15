use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    str::FromStr,
};

use secp256k1::{
    hashes::{sha256, Hash},
    Message, PublicKey, Scalar, SecretKey, XOnlyPublicKey,
};
use serde_json::from_str;

use super::structs::{Outpoint, OutputWithSignature, TestData};

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

pub fn get_A_sum_public_keys(input: &Vec<PublicKey>) -> PublicKey {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs).unwrap()
}

pub fn calculate_tweak_data_for_recipient(
    input_pub_keys: &Vec<PublicKey>,
    outpoints: &HashSet<Outpoint>,
) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();
    let A_sum = get_A_sum_public_keys(input_pub_keys);
    let outpoints_hash = hash_outpoints(outpoints);

    A_sum.mul_tweak(&secp, &outpoints_hash).unwrap()
}

pub fn sender_calculate_shared_secret(
    a_sum: SecretKey,
    B_scan: PublicKey,
    outpoints_hash: Scalar,
) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();

    let diffie_hellman = B_scan.mul_tweak(&secp, &a_sum.into()).unwrap();
    diffie_hellman.mul_tweak(&secp, &outpoints_hash).unwrap()
}

pub fn receiver_calculate_shared_secret(
    tweak_data: PublicKey,
    b_scan: SecretKey,
) -> PublicKey {
    let secp = secp256k1::Secp256k1::new();

    tweak_data.mul_tweak(&secp, &b_scan.into()).unwrap()
}

pub fn hash_outpoints(sending_data: &HashSet<Outpoint>) -> Scalar {
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

    Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap()
}

pub fn verify_and_calculate_signatures(
    privkeys: Vec<Scalar>,
    b_spend: SecretKey,
) -> Result<Vec<OutputWithSignature>, secp256k1::Error> {
    let secp = secp256k1::Secp256k1::new();

    let msg = Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(b"message");
    let aux = secp256k1::hashes::sha256::Hash::hash(b"random auxiliary data").into_inner();

    let mut res: Vec<OutputWithSignature> = vec![];
    for tweak in privkeys {
        // Add the tweak to the b_spend to get the final key
        let k = b_spend.add_tweak(&tweak)?;

        // get public key
        let P = k.x_only_public_key(&secp).0;

        // Sign the message with schnorr
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &k.keypair(&secp), &aux);

        // Verify the message is correct
        secp.verify_schnorr(&sig, &msg, &P)?;

        // Push result to list
        res.push(OutputWithSignature {
            pub_key: P.to_string(),
            priv_key_tweak: hex::encode(tweak.to_be_bytes()),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
