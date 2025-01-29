use std::{error::Error, str::FromStr};

// Import necessary libraries and modules
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;

// Import types from the silentpayments library
use silentpayments::receiving::{Label, Receiver};
use silentpayments::Network;

fn main() -> Result<(), Box<dyn Error>> {
    // Create a new instance of Secp256k1 for cryptographic operations
    let secp = Secp256k1::new();

    // Generate a 12-word mnemonic phrase using bip39 module and store it in the variable 'm'
    let m = Mnemonic::generate(12).expect("mnemonic generation failed");
    let passphrase = "".to_owned();

    // Print the generated mnemonic phrase to the console
    println!("Mnemonic phrase: {}", m.to_string());

    // Convert the mnemonic phrase into a seed for cryptographic operations
    let master_key = Xpriv::new_master(bitcoin::Network::Signet, &m.to_seed(passphrase))?;

    // Define the scan and spend paths for the wallet
    let scan_path = DerivationPath::from_str("m/352h/1h/0h/1h/0").unwrap();
    let spend_path = DerivationPath::from_str("m/352h/1h/0h/0h/0").unwrap();

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
        Network::Testnet,
    )?;

    // Print the receiving address to the console
    println!("Receiving address: {}", receiver.get_receiving_address());

    Ok(())
}
