#![allow(non_snake_case)]
mod common;

use silentpayments::receiving;
use silentpayments::sending;
use silentpayments::utils;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use secp256k1::{SecretKey, XOnlyPublicKey};

    use crate::{
        common::input::{self, get_testing_silent_payment_key_pair, ComparableHashMap, TestData},
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

            let expected = sendingtest.expected;
            let expected_comparable: HashSet<ComparableHashMap> =
                expected.outputs.into_iter().map(|x| x.into()).collect();

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

            let outputs_comparable: HashSet<ComparableHashMap> =
                outputs.into_iter().map(|x| x.into()).collect();

            assert_eq!(outputs_comparable, expected_comparable);
        }

        for receivingtest in &test_case.receiving {
            let given = &receivingtest.given;
            let expected = &receivingtest.expected;

            let receiving_outputs: HashSet<String> = given.outputs.iter().cloned().collect();

            // assert that the sending outputs generated are equal
            // to the expected receiving outputs
            assert!(sending_outputs.is_subset(&receiving_outputs));

            let (b_scan, b_spend, B_scan, B_spend) =
                get_testing_silent_payment_key_pair(&given.bip32_seed);

            let receiving_addresses = get_receiving_addresses(B_scan, B_spend, &given.labels);

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            assert_eq!(set1, set2);

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
            assert_eq!(res, expected.outputs);
        }
    }
}
