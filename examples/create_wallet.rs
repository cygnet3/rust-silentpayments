use std::{error::Error, str::FromStr};

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;

use silentpayments::receiving::{Label, Receiver};
use silentpayments::Network;

fn main() -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();

    let m = Mnemonic::generate(12).expect("mnemonic generation failed");
    let passphrase = "".to_owned();

    println!("Mnemonic phrase: {}", m.to_string());

    let master_key = Xpriv::new_master(bitcoin::Network::Signet, &m.to_seed(passphrase))?;

    let scan_path = DerivationPath::from_str("m/352h/1h/0h/1h/0").unwrap();
    let spend_path = DerivationPath::from_str("m/352h/1h/0h/0h/0").unwrap();

    let scan_privkey = master_key.derive_priv(&secp, &scan_path)?.private_key;
    let spend_privkey = master_key.derive_priv(&secp, &spend_path)?.private_key;
    let change_label = Label::new(scan_privkey, 0);

    let receiver = Receiver::new(
        0,
        scan_privkey.public_key(&secp),
        spend_privkey.public_key(&secp),
        change_label,
        Network::Testnet,
    )?;

    println!("Receiving address: {}", receiver.get_receiving_address());

    Ok(())
}
