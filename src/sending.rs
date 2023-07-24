use bech32::FromBase32;

use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use std::collections::HashMap;

use crate::utils::{hash_outpoints, ser_uint32, sha256, Result};

fn get_a_sum_secret_keys(input: &Vec<(SecretKey, bool)>) -> Result<SecretKey> {
    let secp = Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, x_only) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *x_only && parity == Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(*key);
        }
    }

    let (head, tail) = negated_keys.split_first().ok_or("Empty input list")?;

    let result: Result<SecretKey> = tail
        .iter()
        .fold(Ok(*head), |acc: Result<SecretKey>, &item| {
            Ok(acc?.add_tweak(&item.into())?)
        });

    result
}

fn decode_silent_payment_address(addr: &str) -> Result<(PublicKey, PublicKey)> {
    let (_hrp, data, _variant) = bech32::decode(&addr)?;

    let data = Vec::<u8>::from_base32(&data[1..])?;

    let B_scan = PublicKey::from_slice(&data[..33])?;
    let B_spend = PublicKey::from_slice(&data[33..])?;

    Ok((B_scan, B_spend))
}

pub fn create_outputs(
    outpoints: &Vec<(String, u32)>,
    input_priv_keys: &Vec<(SecretKey, bool)>,
    recipients: &Vec<(String, f32)>,
) -> Result<Vec<HashMap<String, f32>>> {
    let secp = Secp256k1::new();

    let outpoints_hash = hash_outpoints(outpoints)?;

    let a_sum = get_a_sum_secret_keys(input_priv_keys)?;

    let mut silent_payment_groups: HashMap<PublicKey, Vec<(PublicKey, f32)>> = HashMap::new();
    for (payment_address, amount) in recipients {
        let (B_scan, B_m) = decode_silent_payment_address(&payment_address)?;

        if let Some(payments) = silent_payment_groups.get_mut(&B_scan) {
            payments.push((B_m, *amount));
        } else {
            silent_payment_groups.insert(B_scan, vec![(B_m, *amount)]);
        }
    }

    let mut result: Vec<HashMap<String, f32>> = vec![];
    for (B_scan, B_m_values) in silent_payment_groups.into_iter() {
        let mut n = 0;

        //calculate shared secret
        let intermediate = B_scan.mul_tweak(&secp, &a_sum.into())?;
        let scalar = Scalar::from_be_bytes(outpoints_hash)?;
        let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar)?.serialize();

        for (B_m, amount) in B_m_values {
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&ecdh_shared_secret);
            bytes.extend_from_slice(&ser_uint32(n));

            let t_n = sha256(&bytes);

            let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes())?.public_key(&secp);
            let res = G.mul_tweak(&secp, &Scalar::from_be_bytes(t_n)?)?;
            let reskey = res.combine(&B_m)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let mut toAdd: HashMap<String, f32> = HashMap::new();

            toAdd.insert(reskey_xonly.to_string(), amount);

            result.push(toAdd);
            n += 1;
        }
    }
    Ok(result)
}
