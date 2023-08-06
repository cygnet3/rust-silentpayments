#![allow(non_snake_case)]
mod common;

use silentpayments::receiving;
use silentpayments::sending;
use silentpayments::utils;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

    use crate::{
        common::input::{self, TestData},
        receiving::{
            get_A_sum_public_keys, get_receiving_addresses, scanning,
            verify_and_calculate_signatures,
        },
        sending::create_outputs,
        utils::hash_outpoints,
    };

    #[test]
    fn test_with_test_vectors() {
        let testdata = input::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        let mut sending_outputs: HashSet<String> = HashSet::new();
        eprintln!("test.comment = {:?}", test_case.comment);
        for sendingtest in test_case.sending {
            let given = sendingtest.given;

            let expected = sendingtest.expected.outputs;

            let expected_output_addresses: HashSet<String> =
                expected.iter().map(|(x, _)| x.into()).collect();

            let input_priv_keys: Vec<(SecretKey, bool)> = given
                .input_priv_keys
                .iter()
                .map(|(keystr, x_only)| (SecretKey::from_str(&keystr).unwrap(), *x_only))
                .collect();

            let outputs =
                create_outputs(&given.outpoints, &input_priv_keys, &given.recipients).unwrap();

            for map in &outputs {
                for key in map.keys() {
                    sending_outputs.insert(key.clone());
                }
            }

            assert_eq!(sending_outputs, expected_output_addresses);
        }

        for receivingtest in &test_case.receiving {
            let given = &receivingtest.given;
            let expected = &receivingtest.expected;

            let receiving_outputs: HashSet<String> = given.outputs.iter().cloned().collect();

            // assert that the sending outputs generated are equal
            // to the expected receiving outputs
            assert!(sending_outputs.is_subset(&receiving_outputs));

            let b_scan = SecretKey::from_str(&given.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.spend_priv_key).unwrap();
            let secp = secp256k1::Secp256k1::new();
            let B_scan: PublicKey = b_scan.public_key(&secp);
            let B_spend: PublicKey = b_spend.public_key(&secp);

            let receiving_addresses =
                get_receiving_addresses(B_scan, B_spend, &given.labels).unwrap();

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            assert_eq!(set1, set2);

            // can be even or odd !
            let outputs_to_check: Vec<XOnlyPublicKey> = given
                .outputs
                .iter()
                .map(|x| XOnlyPublicKey::from_str(x).unwrap())
                .collect();

            let outpoints_hash = hash_outpoints(&given.outpoints).unwrap();

            let input_pub_keys: Vec<PublicKey> = given
                .input_pub_keys
                .iter()
                .map(|x| match PublicKey::from_str(&x) {
                    Ok(key) => key,
                    Err(_) => {
                        // we always assume even pairing for input public keys if they are omitted
                        let x_only_public_key = XOnlyPublicKey::from_str(&x).unwrap();
                        PublicKey::from_x_only_public_key(
                            x_only_public_key,
                            secp256k1::Parity::Even,
                        )
                    }
                })
                .collect();

            let A_sum = get_A_sum_public_keys(&input_pub_keys).unwrap();

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
            )
            .unwrap();

            let res = verify_and_calculate_signatures(&mut add_to_wallet, b_spend).unwrap();
            assert_eq!(res, expected.outputs);
        }
    }
}
