#![allow(non_snake_case)]
mod common;
#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
    use silentpayments::{
        receiving::Label,
        utils::{
            get_pubkey_from_input, is_p2tr,
            receiving::{calculate_shared_secret, calculate_tweak_data},
            sending::calculate_partial_secret,
        },
    };
    use std::{collections::HashSet, io::Cursor, str::FromStr};

    #[cfg(feature = "receiving")]
    use silentpayments::receiving::Receiver;

    #[cfg(feature = "sending")]
    use silentpayments::sending::generate_recipient_pubkeys;

    use crate::common::{
        structs::TestData,
        utils::{
            self, decode_outputs_to_check, decode_recipients, deser_string_vector,
            verify_and_calculate_signatures,
        },
    };

    const IS_TESTNET: bool = false;

    #[test]
    fn test_with_test_vectors() {
        let testdata = utils::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: TestData) {
        println!("test: {}", test_case.comment);
        let secp = Secp256k1::new();

        let mut sending_outputs: HashSet<String> = HashSet::new();

        #[cfg(feature = "sending")]
        for sendingtest in test_case.sending {
            let given = sendingtest.given;
            let expected = sendingtest.expected.outputs;
            let expected_output_addresses: HashSet<String> =
                expected.iter().map(|(x, _)| x.into()).collect();
            let outpoints: Vec<(String, u32)> = given
                .vin
                .iter()
                .map(|vin| (vin.txid.clone(), vin.vout))
                .collect();
            let mut input_priv_keys = Vec::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(_pubkey)) => input_priv_keys.push((
                        SecretKey::from_str(&input.private_key).unwrap(),
                        is_p2tr(&script_pub_key),
                    )),
                    Ok(None) => (),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }

            // we drop the amounts from the test here, since we don't work with amounts
            // the wallet should make sure the amount sent are correct
            let silent_addresses = decode_recipients(&given.recipients);

            // as an alternative, we could first multiply each input priv key with the input hash
            // that way, we never expose the sk to our library
            let partial_secret = calculate_partial_secret(&input_priv_keys, &outpoints).unwrap();
            let outputs = generate_recipient_pubkeys(silent_addresses, partial_secret).unwrap();

            for output_pubkeys in &outputs {
                for pubkey in output_pubkeys.1 {
                    sending_outputs.insert(hex::encode(pubkey.serialize()));
                }
            }

            assert_eq!(sending_outputs, expected_output_addresses);
        }

        #[cfg(feature = "receiving")]
        for receivingtest in test_case.receiving {
            let given = receivingtest.given;
            let mut expected = receivingtest.expected;

            let receiving_outputs: HashSet<String> = given.outputs.iter().cloned().collect();

            #[cfg(feature = "sending")]
            // assert that the generated sending outputs are a subset
            // of the expected receiving outputs
            // i.e. all the generated outputs are present
            assert!(sending_outputs.is_subset(&receiving_outputs));

            let b_scan = SecretKey::from_str(&given.key_material.scan_priv_key).unwrap();
            let b_spend = SecretKey::from_str(&given.key_material.spend_priv_key).unwrap();
            let B_spend = b_spend.public_key(&secp);
            let B_scan = b_scan.public_key(&secp);

            let change_label = Label::new(b_scan, 0);
            let mut sp_receiver =
                Receiver::new(0, B_scan, B_spend, change_label, IS_TESTNET).unwrap();

            let outputs_to_check = decode_outputs_to_check(&given.outputs);

            let outpoints: Vec<(String, u32)> = given
                .vin
                .iter()
                .map(|vin| (vin.txid.clone(), vin.vout))
                .collect();
            let mut input_pub_keys = Vec::new();
            for input in given.vin {
                let script_sig = hex::decode(&input.scriptSig).unwrap();
                let txinwitness_bytes = hex::decode(&input.txinwitness).unwrap();
                let mut cursor = Cursor::new(&txinwitness_bytes);
                let txinwitness = deser_string_vector(&mut cursor).unwrap();
                let script_pub_key = hex::decode(&input.prevout.scriptPubKey.hex).unwrap();

                match get_pubkey_from_input(&script_sig, &txinwitness, &script_pub_key) {
                    Ok(Some(pubkey)) => input_pub_keys.push(pubkey),
                    Ok(None) => (),
                    Err(e) => panic!("Problem parsing the input: {:?}", e),
                }
            }

            let input_pub_keys: Vec<&PublicKey> = input_pub_keys.iter().collect();

            for label_int in &given.labels {
                let label = Label::new(b_scan, *label_int);
                sp_receiver.add_label(label).unwrap();
            }

            let mut receiving_addresses: HashSet<String> = HashSet::new();
            // get receiving address for no label
            receiving_addresses.insert(sp_receiver.get_receiving_address());

            // get receiving addresses for every label
            let labels = sp_receiver.list_labels();
            for label in &labels {
                receiving_addresses
                    .insert(sp_receiver.get_receiving_address_for_label(label).unwrap());
            }

            if !&given.labels.iter().any(|l| *l == 0) {
                receiving_addresses.remove(&sp_receiver.get_change_address());
            }

            let set1: HashSet<_> = receiving_addresses.iter().collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            // check that the receiving addresses generated are equal
            // to the expected addresses
            assert_eq!(set1, set2);

            let tweak_data = calculate_tweak_data(&input_pub_keys, &outpoints).unwrap();
            let shared_secret = calculate_shared_secret(tweak_data, b_scan).unwrap();

            let scanned_outputs_received = sp_receiver
                .scan_transaction(&shared_secret, outputs_to_check)
                .unwrap();

            let key_tweaks: Vec<Scalar> = scanned_outputs_received
                .into_iter()
                .flat_map(|(_, map)| {
                    let mut ret: Vec<Scalar> = vec![];
                    for l in map.into_values() {
                        ret.push(l);
                    }
                    ret
                })
                .collect();

            let mut res = verify_and_calculate_signatures(key_tweaks, b_spend).unwrap();

            res.sort_by_key(|output| output.pub_key.clone());
            expected
                .outputs
                .sort_by_key(|output| output.pub_key.clone());

            assert_eq!(res, expected.outputs);
        }
    }
}
