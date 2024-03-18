use std::{env, error::Error, str::FromStr};

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::{Network, PrivateKey, ScriptBuf, Transaction};
use bitcoin_hashes::hex::FromHex;

use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{
    calculate_shared_secret, calculate_tweak_data, get_pubkey_from_input,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<String> = env::args().collect();

    // we take the mnemonic returned by create_wallet to recreate the receiver
    let m = Mnemonic::from_str(&args.get(1).unwrap())?;
    // the tx we scan for our outputs
    let tx_hex = args.get(2).unwrap();
    // the scriptpubkey corresponding to each input of the tx
    // we fail if the number of scriptpubkeys doesn't match the number of inputs
    // they also need to be in the same order than the inputs of the transaction
    let spks: Vec<&str> = args.get(3).unwrap().split_whitespace().collect();

    let tx: Transaction = deserialize(Vec::from_hex(&tx_hex)?.as_slice())?;

    assert!(tx.input.len() == spks.len());

    let master_key = Xpriv::new_master(bitcoin::Network::Signet, &m.to_seed(""))?;

    let scan_path = DerivationPath::from_str("m/352h/1h/0h/1h/0").unwrap();
    let spend_path = DerivationPath::from_str("m/352h/1h/0h/0h/0").unwrap();

    let secp = Secp256k1::signing_only();
    let scan_privkey = master_key.derive_priv(&secp, &scan_path)?.private_key;
    let spend_privkey = master_key.derive_priv(&secp, &spend_path)?.private_key;
    let change_label = Label::new(scan_privkey, 0);

    let receiver = Receiver::new(
        0,
        scan_privkey.public_key(&secp),
        spend_privkey.public_key(&secp),
        change_label,
        true,
    )?;

    let outpoints: Vec<(String, u32)> = tx
        .input
        .iter()
        .map(|i| {
            let outpoint = i.previous_output;
            (outpoint.txid.to_string(), outpoint.vout)
        })
        .collect();

    // we look at each input and assert if it contains an eligible pubkey
    let mut input_pubkeys: Vec<PublicKey> = vec![];
    for (i, input) in tx.input.iter().enumerate() {
        let spk = ScriptBuf::from_hex(spks.get(i).unwrap())?;
        if let Some(pubkey) = get_pubkey_from_input(
            input.script_sig.as_bytes(),
            &input.witness.to_vec(),
            spk.as_bytes(),
        )? {
            input_pubkeys.push(pubkey);
        }
    }

    let pubkeys_ref: Vec<&PublicKey> = input_pubkeys.iter().collect();
    let tweak_data = calculate_tweak_data(&pubkeys_ref, &outpoints)?;
    let ecdh_shared_secret = calculate_shared_secret(tweak_data, scan_privkey)?;

    let pubkeys_to_check: Vec<_> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| {
            XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..])
                .expect("P2tr output should have a valid xonly key")
        })
        .collect();

    let my_outputs = receiver.scan_transaction(&ecdh_shared_secret, pubkeys_to_check)?;

    println!("Found {} outputs", my_outputs.len());

    for (label, key_map) in my_outputs {
        println!("Found {} output(s) with label {:?}", key_map.len(), label);
        for (xonly, sk) in key_map {
            let spending_key = spend_privkey.clone().add_tweak(&sk).unwrap();
            println!(
                "Private key to spend output with key {}: {}",
                xonly,
                PrivateKey::from_slice(&spending_key.secret_bytes(), Network::Signet)
                    .unwrap()
                    .to_wif()
            );
        }
    }

    Ok(())
}
