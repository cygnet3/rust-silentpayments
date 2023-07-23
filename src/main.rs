#![allow(non_snake_case, dead_code)]
mod input;
mod receiving;
mod sending;

use hex::FromHex;
use secp256k1::{
    hashes::{sha256, Hash}, PublicKey,
};
use std::str::FromStr;
use std::{collections::HashSet, io::Write};

use crate::{
    input::ComparableHashMap,
    receiving::{
        derive_silent_payment_key_pair, encode_silent_payment_address, get_A_sum_public_keys,
        scanning, verify_and_calculate_signatures,
    },
    sending::create_outputs,
};

fn sha256(message: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(message).to_byte_array()
}

fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

fn hash_outpoints(sending_data: &Vec<(String, u32)>) -> [u8; 32] {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    for (txid_str, vout) in sending_data {
        let mut txid = Vec::from_hex(txid_str).unwrap();
        txid.reverse();
        let mut vout_bytes = vout.to_le_bytes().to_vec();
        txid.append(&mut vout_bytes);
        outpoints.push(txid);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v).unwrap();
    }

    sha256::Hash::from_engine(engine).to_byte_array()
}

fn main() {
    let testdata = input::read_file();

    let receiving = &testdata[0].receiving[0];
    let given = &receiving.given;
    let expected = &receiving.expected;

    let bip32_seed_str = &given.bip32_seed;
    let bip32_seed = hex::decode(&bip32_seed_str[2..]).unwrap();

    let (b_scan, b_spend, B_scan, B_spend) = derive_silent_payment_key_pair(bip32_seed);

    let mut receiving_addresses: Vec<String> = vec![];
    receiving_addresses.push(encode_silent_payment_address(B_scan, B_spend, None, None));
    eprintln!("receiving_addresses = {:?}", receiving_addresses);

    // todo labels

    let outputs_to_check: Vec<PublicKey> = given
        .outputs
        .iter()
        .map(|x| PublicKey::from_str(format!("03{}", &x).as_str()).unwrap())
        .collect();

    let outpoints_hash = hash_outpoints(&given.outpoints);
    let A_sum = get_A_sum_public_keys(&given.input_pub_keys);
    let labels = &given.labels;

    let mut add_to_wallet = scanning(
        b_scan,
        B_spend,
        A_sum,
        outpoints_hash,
        outputs_to_check,
        labels,
    );

    let res = verify_and_calculate_signatures(&mut add_to_wallet, b_spend).unwrap();
    if res.eq(&expected.outputs) {
        println!("succeeded");
    } else {
        println!("failed");
    }

    // todo: check that sending outputs are equal to sending test

    for test in testdata {
        eprintln!("test.comment = {:?}", test.comment);
        for sendingtest in test.sending {
            let given = sendingtest.given;

            let expected = sendingtest.expected;
            let expected_comparable: HashSet<ComparableHashMap> =
                expected.outputs.into_iter().map(|x| x.into()).collect();

            let outputs = create_outputs(&given);
            let outputs_comparable: HashSet<ComparableHashMap> =
                outputs.into_iter().map(|x| x.into()).collect();

            if outputs_comparable == expected_comparable {
                println!("succeeded");
            } else {
                eprintln!("expected = {:#?}", expected_comparable);
                eprintln!("outputs = {:#?}", outputs_comparable);
            }
        }
    }
}
