#![allow(non_snake_case)]
use silentpayments::receiving;
use silentpayments::sending;
use silentpayments::utils;
use silentpayments::input;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::{
        input::{self, ComparableHashMap, TestData},
        receiving::{
            get_A_sum_public_keys, get_receiving_addresses, scanning,
            verify_and_calculate_signatures,
        },
        sending::create_outputs,
        utils::hash_outpoints,
    };

    // Note: this function is only temporary.
    // The format for keys from the test vector will be changed soo.
    // Until then, this method is used.
    fn get_testing_silent_payment_key_pair(
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

            let outputs =
                create_outputs(&given.outpoints, &given.input_priv_keys, &given.recipients);

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
