/// Example showing how to construct a SilentPaymentAddress without the `encode` feature.
///
/// This is useful if your application already has a bech32 parser and you want to
/// avoid duplicate dependencies. You can parse the address yourself and then
/// construct the type using the public constructor.
///
/// To run this example:
/// ```bash
/// cargo run --example custom_parser --no-default-features
/// ```

fn main() {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use silentpayments::{Network, SilentPaymentAddress};

    // Example: Simulating what you'd get after parsing bech32 yourself
    // In a real application, you would:
    // 1. Parse the bech32m string (e.g., "sp1...")
    // 2. Extract the HRP to determine the network
    // 3. Decode the data part to get version + 33-byte scan key + 33-byte spend key
    // 4. Deserialize the pubkeys from those bytes
    // 5. Construct the SilentPaymentAddress using the constructor

    // For this example, we'll generate valid pubkeys
    let secp = Secp256k1::new();
    let scan_secret = SecretKey::from_slice(&[0x01; 32]).expect("valid key");
    let spend_secret = SecretKey::from_slice(&[0x02; 32]).expect("valid key");

    let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_secret);
    let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_secret);

    // Construct the SilentPaymentAddress without needing the `encode` feature
    let address = SilentPaymentAddress::new(
        scan_pubkey,
        spend_pubkey,
        Network::Mainnet,
        0, // version
    )
    .expect("Failed to create address");

    println!("Successfully created SilentPaymentAddress without encode feature!");
    println!("Network: {:?}", address.get_network());
    println!("Version: {}", address.get_version());
    println!("Scan key: {:?}", address.get_scan_key());
    println!("Spend key: {:?}", address.get_spend_key());

    println!("\n✅ This example compiled and ran with ZERO features enabled!");
    println!("   Only dependencies: secp256k1, rand, rand_core, secp256k1-sys");
}
