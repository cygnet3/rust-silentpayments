use bech32::ToBase32;

use secp256k1::{hashes::Hash, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
};

use crate::{
    error::Error,
    structs::{Outpoint, OutputWithSignature, ScannedOutput},
    utils::{hash_outpoints, ser_uint32, Result},
};

pub fn get_receiving_addresses(
    B_scan: PublicKey,
    B_spend: PublicKey,
    labels: &HashMap<String, String>,
) -> Result<Vec<String>> {
    let mut receiving_addresses: Vec<String> = vec![];
    receiving_addresses.push(encode_silent_payment_address(B_scan, B_spend, None, None)?);
    for (_, label) in labels {
        receiving_addresses.push(create_labeled_silent_payment_address(
            B_scan, B_spend, label, None, None,
        )?);
    }

    Ok(receiving_addresses)
}

pub fn get_A_sum_public_keys(
    input: &Vec<PublicKey>,
) -> std::result::Result<PublicKey, secp256k1::Error> {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs)
}

fn encode_silent_payment_address(
    B_scan: PublicKey,
    B_m: PublicKey,
    hrp: Option<&str>,
    version: Option<u8>,
) -> Result<String> {
    let hrp = hrp.unwrap_or("sp");
    let version = bech32::u5::try_from_u8(version.unwrap_or(0))?;

    let B_scan_bytes = B_scan.serialize();
    let B_m_bytes = B_m.serialize();

    let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

    data.insert(0, version);

    Ok(bech32::encode(hrp, data, bech32::Variant::Bech32m)?)
}

fn create_labeled_silent_payment_address(
    B_scan: PublicKey,
    B_spend: PublicKey,
    m: &String,
    hrp: Option<&str>,
    version: Option<u8>,
) -> Result<String> {
    let bytes: [u8; 32] = hex::decode(m)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::GenericError("Wrong byte length".to_owned()))?;

    let scalar = Scalar::from_be_bytes(bytes)?;
    let secp = Secp256k1::new();
    let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())?.public_key(&secp);
    let intermediate = G.mul_tweak(&secp, &scalar)?;
    let B_m = intermediate.combine(&B_spend)?;

    encode_silent_payment_address(B_scan, B_m, hrp, version)
}

fn calculate_P_n(B_spend: &PublicKey, t_n: [u8; 32]) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())?.public_key(&secp);
    let intermediate = G.mul_tweak(&secp, &Scalar::from_be_bytes(t_n)?)?;
    let P_n = intermediate.combine(&B_spend)?;

    Ok(P_n)
}

fn calculate_t_n(ecdh_shared_secret: &[u8; 33], n: u32) -> [u8; 32] {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(ecdh_shared_secret);
    bytes.extend_from_slice(&ser_uint32(n));
    crate::utils::sha256(&bytes)
}

fn calculate_ecdh_secret(
    A_sum: &PublicKey,
    b_scan: SecretKey,
    outpoints_hash: [u8; 32],
) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();

    let intermediate = A_sum.mul_tweak(&secp, &b_scan.into())?;
    let scalar = Scalar::from_be_bytes(outpoints_hash)?;
    let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar)?.serialize();

    Ok(ecdh_shared_secret)
}

pub fn scanning(
    b_scan: SecretKey,
    B_spend: PublicKey,
    A_sum: PublicKey,
    outpoints: HashSet<Outpoint>,
    outputs_to_check: Vec<XOnlyPublicKey>,
    labels: Option<&HashMap<String, String>>,
) -> Result<Vec<ScannedOutput>> {
    let secp = secp256k1::Secp256k1::new();

    let outpoints_hash = hash_outpoints(&outpoints)?;

    let ecdh_shared_secret = calculate_ecdh_secret(&A_sum, b_scan, outpoints_hash)?;
    let mut n = 0;
    let mut wallet: Vec<ScannedOutput> = vec![];

    let mut found = true;
    while found {
        found = false;
        let t_n = calculate_t_n(&ecdh_shared_secret, n);
        let P_n = calculate_P_n(&B_spend, t_n)?;
        let (P_n_xonly, _) = P_n.x_only_public_key();
        if outputs_to_check.iter().any(|&output| output.eq(&P_n_xonly)) {
            let pub_key = hex::encode(P_n_xonly.serialize());
            let priv_key_tweak = hex::encode(t_n);
            wallet.push(ScannedOutput {
                pub_key,
                priv_key_tweak,
            });
            n += 1;
            found = true;
        } else if let Some(labels) = labels {
            let P_n_negated = P_n.negate(&secp);
            for output in &outputs_to_check {
                let output_even = output.public_key(secp256k1::Parity::Even);
                let output_odd = output.public_key(secp256k1::Parity::Odd);

                let m_G_sub_even = output_even.combine(&P_n_negated)?;
                let m_G_sub_odd = output_odd.combine(&P_n_negated)?;
                let keys: Vec<PublicKey> = vec![m_G_sub_even, m_G_sub_odd];
                for labelkeystr in labels.keys() {
                    let labelkey = PublicKey::from_str(labelkeystr)?;
                    if keys.iter().any(|x| x.eq(&labelkey)) {
                        let P_nm = hex::encode(output.serialize());
                        let label = labels.get(labelkeystr).unwrap();
                        let label_bytes = hex::decode(label)?
                            .as_slice()
                            .try_into()
                            .map_err(|_| Error::GenericError("Wrong byte length".to_owned()))?;
                        let label_scalar = Scalar::from_be_bytes(label_bytes)?;
                        let t_n_as_secret_key = SecretKey::from_slice(&t_n)?;
                        let priv_key_tweak =
                            hex::encode(t_n_as_secret_key.add_tweak(&label_scalar)?.secret_bytes());
                        wallet.push(ScannedOutput {
                            pub_key: P_nm,
                            priv_key_tweak,
                        });
                        n += 1;
                        found = true;
                    }
                }
            }
        }
    }
    Ok(wallet)
}

pub fn verify_and_calculate_signatures(
    add_to_wallet: &mut Vec<ScannedOutput>,
    b_spend: SecretKey,
) -> Result<Vec<OutputWithSignature>> {
    let secp = secp256k1::Secp256k1::new();
    let msg = Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(b"message");
    let aux = secp256k1::hashes::sha256::Hash::hash(b"random auxiliary data").into_inner();

    let mut res: Vec<OutputWithSignature> = vec![];
    for output in add_to_wallet {
        let pubkey = XOnlyPublicKey::from_str(&output.pub_key)?;
        let tweak: [u8; 32] = hex::decode(&output.priv_key_tweak)?
            .as_slice()
            .try_into()
            .map_err(|_| Error::GenericError("Wrong byte length".to_owned()))?;
        let scalar = Scalar::from_be_bytes(tweak)?;
        let mut full_priv_key = b_spend.add_tweak(&scalar)?;

        let (_, parity) = full_priv_key.x_only_public_key(&secp);

        if parity == secp256k1::Parity::Odd {
            full_priv_key = full_priv_key.negate();
        }

        let sig = secp.sign_schnorr_with_aux_rand(&msg, &full_priv_key.keypair(&secp), &aux);

        secp.verify_schnorr(&sig, &msg, &pubkey)?;

        res.push(OutputWithSignature {
            pub_key: output.pub_key.to_string(),
            priv_key_tweak: output.priv_key_tweak.clone(),
            signature: sig.to_string(),
        });
    }
    Ok(res)
}
