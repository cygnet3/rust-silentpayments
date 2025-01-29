use std::{env, error::Error, str::FromStr};

// Import necessary libraries and modules
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::{Network, PrivateKey, ScriptBuf, Transaction};
use bitcoin_hashes::hex::FromHex;

// Import types from the silentpayments library
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, calculate_tweak_data, get_pubkey_from_input,
};

fn main() -> Result<(), Box<dyn Error>> {
    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    // Parse the mnemonic phrase from the first command-line argument
    let m = Mnemonic::from_str(&args.get(1).unwrap())?;

    // Get the transaction hex string from the second command-line argument
    let tx_hex = args.get(2).unwrap();

    // Parse the scriptpubkeys from the third command-line argument, split by whitespace and store them in a vector
    let spks: Vec<&str> = args.get(3).unwrap().split_whitespace().collect();

    // Deserialize the transaction hex string into a Transaction object
    let tx: Transaction = deserialize(Vec::from_hex(&tx_hex)?.as_slice())?;

    // Assert that the number of inputs in the transaction matches the number of scriptpubkeys provided
    assert!(tx.input.len() == spks.len());

    let master_key = Xpriv::new_master(bitcoin::Network::Signet, &m.to_seed(""))?;

    // Define the scan and spend paths for the wallet
    let scan_path = DerivationPath::from_str("m/352h/1h/0h/1h/0").unwrap();
    let spend_path = DerivationPath::from_str("m/352h/1h/0h/0h/0").unwrap();

    // Create a new instance of Secp256k1 for cryptographic operations
    let secp = Secp256k1::signing_only();

    // Get the private keys for both scan and spend paths
    let scan_privkey = master_key.derive_priv(&secp, &scan_path)?.private_key;
    let spend_privkey = master_key.derive_priv(&secp, &spend_path)?.private_key;

    // Create a change label for the wallet
    let change_label = Label::new(scan_privkey, 0);

    // Create a new Receiver object with the private and public keys, along with the change label
    let receiver = Receiver::new(
        0,
        scan_privkey.public_key(&secp),
        spend_privkey.public_key(&secp),
        change_label,
        silentpayments::Network::Testnet,
    )?;

    // Extract outpoints (previous transaction outputs) from the transaction inputs and store them in a vector
    let outpoints: Vec<(String, u32)> = tx
        .input
        .iter()
        .map(|i| {
            let outpoint = i.previous_output;
            (outpoint.txid.to_string(), outpoint.vout)
        })
        .collect();

    // Iterate through each input of the transaction and assert if it contains an eligible pubkey
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

    // Get the reference to a vector of public keys for further calculations
    let pubkeys_ref: Vec<&PublicKey> = input_pubkeys.iter().collect();

    // Calculate the tweak data based on the public keys and outpoints
    let tweak_data = calculate_tweak_data(&pubkeys_ref, &outpoints)?;

    // Calculate the ECDH shared secret between the scan private key and the tweak data
    let ecdh_shared_secret = calculate_ecdh_shared_secret(&tweak_data, &scan_privkey);

    // Filter the transaction outputs that have a valid P2TR scriptpubkey
    let pubkeys_to_check: Vec<_> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| {
            XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..])
                .expect("P2tr output should have a valid xonly key")
        })
        .collect();

    // Scan the transaction for eligible outputs and store them in a vector with their corresponding labels and key maps
    let my_outputs = receiver.scan_transaction(&ecdh_shared_secret, pubkeys_to_check)?;

    println!("Found {} output(s)", my_outputs.len());

    // Iterate through each found output and print the private key required to spend it along with its descriptor for importing into Bitcoin Core
    for (label, key_map) in my_outputs {
        println!("Found {} output(s) with label {:?}", key_map.len(), label);
        for (xonly, sk) in key_map {
            let spending_key = spend_privkey.clone().add_tweak(&sk).unwrap();
            let wif = PrivateKey::from_slice(&spending_key.secret_bytes(), Network::Signet)
                .unwrap()
                .to_wif();
            println!("Private key to spend output with key {}: {}", xonly, wif);
            println!("Descriptor to import in Bitcoin Core: rawtr({})", wif);
        }
    }

    Ok(())
}
