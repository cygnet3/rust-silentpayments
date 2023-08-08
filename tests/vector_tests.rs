#![allow(non_snake_case)]
mod common;

use silentpayments::receiving;

#[cfg(test)]
mod tests {
    use std::{collections::{HashSet, HashMap}, str::FromStr};

    use secp256k1::{SecretKey, PublicKey, Scalar};
    use silentpayments::sending::{decode_scan_pubkey, generate_recipient_pubkeys};

    use crate::{
        common::{
            structs::TestData,
            utils::{
                self, decode_input_pub_keys, decode_outpoints,
                decode_outputs_to_check, decode_priv_keys, decode_recipients,
                get_a_sum_secret_keys, hash_outpoints, compute_ecdh_shared_secret,
            },
        },
        receiving::{
            get_A_sum_public_keys, get_receiving_addresses, scanning,
            verify_and_calculate_signatures,
        },
    };

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

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

            let input_priv_keys = decode_priv_keys(&given.input_priv_keys);

            let outpoints = decode_outpoints(&given.outpoints);

            let outpoints_hash = Scalar::from_be_bytes(hash_outpoints(&outpoints)).unwrap();

            let silent_addresses = decode_recipients(&given.recipients);

            let a_sum = get_a_sum_secret_keys(&input_priv_keys);

            let mut ecdh_shared_secrets: HashMap<PublicKey, PublicKey> = HashMap::new();
            for addr in &silent_addresses {
                let B_scan = decode_scan_pubkey(addr.to_owned()).unwrap();
                let ecdh_shared_secret = compute_ecdh_shared_secret(a_sum, B_scan, outpoints_hash);
                ecdh_shared_secrets.insert(B_scan, ecdh_shared_secret);
            }
            let outputs = generate_recipient_pubkeys(silent_addresses, ecdh_shared_secrets).unwrap();

            for output_pubkeys in &outputs {
                for pubkey in output_pubkeys.1 {
                    // TODO check if this is always true
                    sending_outputs.insert(hex::encode(pubkey.serialize()));
                }
            }

            assert_eq!(sending_outputs, expected_output_addresses);
        }

        for receivingtest in &test_case.receiving {
            let given = &receivingtest.given;
            let expected = &receivingtest.expected;

            let receiving_outputs: HashSet<String> = given.outputs.iter().cloned().collect();

            // assert that the generated sending outputs are a subset
            // of the expected receiving outputs
            // i.e. all the generated outputs are present
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

            // check that the receiving addresses generated are equal
            // to the expected addresses
            assert_eq!(set1, set2);

            // can be even or odd !
            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            let outpoints = decode_outpoints(&given.outpoints);

            let input_pub_keys = decode_input_pub_keys(&given.input_pub_keys);

            let A_sum = get_A_sum_public_keys(&input_pub_keys).unwrap();

            let labels = match &given.labels.len() {
                0 => None,
                _ => Some(&given.labels),
            };

            let mut add_to_wallet =
                scanning(b_scan, B_spend, A_sum, outpoints, outputs_to_check, labels).unwrap();

            let res = verify_and_calculate_signatures(&mut add_to_wallet, b_spend).unwrap();
            assert_eq!(res, expected.outputs);
        }
    }
}
