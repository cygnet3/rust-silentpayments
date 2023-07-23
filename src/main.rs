#![allow(non_snake_case, dead_code)]
mod input;
mod receiving;
mod sending;
mod utils;

use secp256k1::{hashes::sha256, XOnlyPublicKey};
use std::collections::HashSet;
use std::str::FromStr;

use crate::{
    input::ComparableHashMap,
    receiving::{
        derive_silent_payment_key_pair, get_A_sum_public_keys, get_receiving_addresses, scanning,
        verify_and_calculate_signatures,
    },
    sending::create_outputs,
    utils::hash_outpoints,
};

fn main() {
    let testdata = input::read_file();

    for test in testdata {
        let mut sending_outputs: HashSet<String> = HashSet::new();
        eprintln!("test.comment = {:?}", test.comment);
        for sendingtest in test.sending {
            let given = sendingtest.given;

            let expected = sendingtest.expected;
            let expected_comparable: HashSet<ComparableHashMap> =
                expected.outputs.into_iter().map(|x| x.into()).collect();

            let outputs = create_outputs(&given);

            for map in &outputs {
                for key in map.keys() {
                    sending_outputs.insert(key.clone());
                }
            }

            let outputs_comparable: HashSet<ComparableHashMap> =
                outputs.into_iter().map(|x| x.into()).collect();

            if outputs_comparable == expected_comparable {
                println!("sending succeeded");
            } else {
                eprintln!("sending expected = {:#?}", expected_comparable);
                eprintln!("sending outputs = {:#?}", outputs_comparable);
                std::process::exit(0);
            }
        }

        for receivingtest in test.receiving {
            let given = &receivingtest.given;
            let expected = &receivingtest.expected;

            let receiving_outputs: HashSet<String> = given.outputs.iter().cloned().collect();
            if !sending_outputs.is_subset(&receiving_outputs) {
                eprintln!("receivingOutputs = {:#?}", receiving_outputs);
                eprintln!("sending_outputs = {:#?}", sending_outputs);
                std::process::exit(0);
            }

            // todo fix seed?
            // let bip32_seed = hex::decode(&bip32_seed_str[2..]).unwrap();
            let bip32_seed_str = &given.bip32_seed;
            let (b_scan, b_spend, B_scan, B_spend) = derive_silent_payment_key_pair(bip32_seed_str);

            let receiving_addresses = get_receiving_addresses(B_scan, B_spend, &given.labels);

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();
            if !set1.eq(&set2) {
                println!("receiving addressess failed");
                eprintln!("receiving_addresses = {:#?}", receiving_addresses);
                eprintln!("expected.addresses = {:#?}", expected.addresses);
                std::process::exit(0);
            }

            // can be even or odd !
            let outputs_to_check: Vec<XOnlyPublicKey> = given
                .outputs
                .iter()
                .map(|x| XOnlyPublicKey::from_str(x).unwrap())
                .collect();

            let outpoints_hash = hash_outpoints(&given.outpoints);
            let A_sum = get_A_sum_public_keys(&given.input_pub_keys);
            let labels = match &given.labels.len() {
                0 => None,
                _ => Some(&given.labels),
            };

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
                println!("receiving succeeded");
            } else {
                eprintln!("res = {:#?}", res);
                eprintln!("expected.outputs = {:#?}", expected.outputs);
                println!("receiving failed");
                std::process::exit(0);
            }
        }
    }
}
