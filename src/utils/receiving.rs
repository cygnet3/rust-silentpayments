//! Receiving utility functions.
use crate::{
    utils::{
        OP_0, OP_1, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHBYTES_20,
        OP_PUSHBYTES_32,
    },
    Error, Result,
};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::{Parity::Even, XOnlyPublicKey};
use secp256k1::{PublicKey, SecretKey};

#[cfg(feature = "bitcoin")]
use bitcoin::{ScriptBuf, TxIn};

use super::{hash::calculate_input_hash, COMPRESSED_PUBKEY_SIZE, NUMS_H};

/// Calculate the tweak data of a transaction.
/// This is useful in combination with the `calculate_shared_secret` function, but can also be used
/// by indexing servers that don't have access to the recipient scan key.
///
/// # Arguments
///
/// * `input_pub_keys` - The list of public keys that are used as input for this transaction. Only the public keys for inputs that are silent payment eligible should be given.
/// * `outpoints_data` - All prevout outpoints used as input for this transaction. Note that the txid is given in String format, which is displayed in reverse order from the inner byte array.
///
/// # Returns
///
/// This function returns the tweak data for this transaction. The tweak data is an intermediary result that can be used to calculate the final shared secret.
///
/// # Errors
///
/// This function will error if:
///
/// * The input public keys array is of length zero, or the summing results in an invalid key.
/// * The outpoints_data is of length zero, or invalid.
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_tweak_data(
    input_pub_keys: &[&PublicKey],
    outpoints_data: &[(String, u32)],
) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();
    let A_sum = PublicKey::combine_keys(input_pub_keys)?;
    let input_hash = calculate_input_hash(outpoints_data, A_sum)?;

    Ok(A_sum.mul_tweak(&secp, &input_hash)?)
}

/// Calculate the shared secret of a transaction.
///
/// # Arguments
///
/// * `tweak_data` - The tweak data of the transaction, see `calculate_tweak_data`.
/// * `b_scan` - The scan private key used by the wallet.
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See `receiving::scan_transaction`.
///
/// # Errors
///
/// This function will error if:
///
/// * Elliptic curve computation results in an invalid public key.
pub fn calculate_shared_secret(tweak_data: PublicKey, b_scan: SecretKey) -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::verification_only();

    Ok(tweak_data.mul_tweak(&secp, &b_scan.into())?)
}

/// Get the public keys from a set of input data.
///
/// # Arguments
///
/// * `script_sig` - The script signature as a byte array.
/// * `txinwitness` - The witness data.
/// * `script_pub_key` - The scriptpubkey from the output spent. This requires looking up the previous output.
///
/// # Returns
///
/// If no errors occur, this function will optionally return a PublicKey if this input is silent payment-eligible.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided Vin data is incorrect.
pub fn get_pubkey_from_input(
    script_sig: &[u8],
    txinwitness: &Vec<Vec<u8>>,
    script_pub_key: &[u8],
) -> Result<Option<PublicKey>> {
    if is_p2pkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (true, false) => {
                let spk_hash = &script_pub_key[3..23];
                for i in (COMPRESSED_PUBKEY_SIZE..=script_sig.len()).rev() {
                    if let Some(pubkey_bytes) = script_sig.get(i - COMPRESSED_PUBKEY_SIZE..i) {
                        let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
                        if pubkey_hash.to_byte_array() == spk_hash {
                            return Ok(Some(PublicKey::from_slice(pubkey_bytes)?));
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2pkh".to_owned(),
                ))
            }
            (false, _) => {
                return Err(Error::InvalidVin(
                    "non empty witness for spending a p2pkh".to_owned(),
                ))
            }
        }
    } else if is_p2sh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, false) => {
                let redeem_script = &script_sig[1..];
                if is_p2wpkh(redeem_script) {
                    if let Some(value) = txinwitness.last() {
                        match (
                            PublicKey::from_slice(value),
                            value.len() == COMPRESSED_PUBKEY_SIZE,
                        ) {
                            (Ok(pubkey), true) => {
                                return Ok(Some(pubkey));
                            }
                            (_, false) => {
                                return Ok(None);
                            }
                            // Not sure how we could get an error here, so just return none for now
                            // if the pubkey cant be parsed
                            (Err(_), _) => {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
            (_, true) => {
                return Err(Error::InvalidVin(
                    "Empty script_sig for spending a p2sh".to_owned(),
                ))
            }
            (true, false) => return Ok(None),
        }
    } else if is_p2wpkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                if let Some(value) = txinwitness.last() {
                    match (
                        PublicKey::from_slice(value),
                        value.len() == COMPRESSED_PUBKEY_SIZE,
                    ) {
                        (Ok(pubkey), true) => {
                            return Ok(Some(pubkey));
                        }
                        (_, false) => {
                            return Ok(None);
                        }
                        // Not sure how we could get an error here, so just return none for now
                        // if the pubkey cant be parsed
                        (Err(_), _) => {
                            return Ok(None);
                        }
                    }
                } else {
                    return Err(Error::InvalidVin("Empty witness".to_owned()));
                }
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    } else if is_p2tr(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                // check for the optional annex
                let annex = match txinwitness.last().and_then(|value| value.first()) {
                    Some(&0x50) => 1,
                    Some(_) => 0,
                    None => return Err(Error::InvalidVin("Empty or invalid witness".to_owned())),
                };

                // Check for script path
                let stack_size = txinwitness.len();
                if stack_size > annex && txinwitness[stack_size - annex - 1][1..33] == NUMS_H {
                    return Ok(None);
                }

                // Return the pubkey from the script pubkey
                return XOnlyPublicKey::from_slice(&script_pub_key[2..34])
                    .map_err(Error::Secp256k1Error)
                    .map(|x_only_public_key| {
                        Some(PublicKey::from_x_only_public_key(x_only_public_key, Even))
                    });
            }
            (_, false) => {
                return Err(Error::InvalidVin(
                    "Non empty script sig for spending a segwit output".to_owned(),
                ))
            }
            (true, _) => {
                return Err(Error::InvalidVin(
                    "Empty witness for spending a segwit output".to_owned(),
                ))
            }
        }
    }
    Ok(None)
}

// script templates for inputs allowed in BIP352 shared secret derivation
/// Check if a script_pub_key is taproot.
pub fn is_p2tr(spk: &[u8]) -> bool {
    matches!(spk, [OP_1, OP_PUSHBYTES_32, ..] if spk.len() == 34)
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_0, OP_PUSHBYTES_20, ..] if spk.len() == 22)
}

fn is_p2sh(spk: &[u8]) -> bool {
    matches!(spk, [OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUAL] if spk.len() == 23)
}

fn is_p2pkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_DUP, OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUALVERIFY, OP_CHECKSIG] if spk.len() == 25)
}

/// Get the public keys from a set of input data, using rust-bitcoin structs.
///
/// # Arguments
///
/// * `inputs` - A Vec that contains the transaction inputs (TxIn) along with the ScriptPubKey from the previous output
///
/// # Returns
///
/// On success, this function returns a list of all eligible public keys from a transaction as a `Vec`. If the `Vec` is of length 0, this transaction is not eligible to be a silent payment.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided Vin data is incorrect. This shouldn't occur if the provided input from a valid transaction.
#[cfg(feature = "bitcoin")]
pub fn get_pubkeys_from_transaction(inputs: Vec<(TxIn, ScriptBuf)>) -> Result<Vec<PublicKey>> {
    let mut res = vec![];
    for (txin, spk) in inputs {
        let script_sig = txin.script_sig.as_bytes();
        let witness = txin.witness.to_vec();

        if let Some(pk) = get_pubkey_from_input(script_sig, &witness, spk.as_bytes())? {
            res.push(pk);
        }
    }
    Ok(res)
}

#[cfg(test)]
#[cfg(feature = "bitcoin")]
mod tests {
    use std::str::FromStr;

    use bitcoin::{ScriptBuf, Transaction};
    use secp256k1::PublicKey;

    use crate::utils::receiving::get_pubkeys_from_transaction;

    #[test]
    fn test_single_wpkh_input_transaction() {
        let tx_str = "02000000000101a9b9e18ab45fd7b9a6243a72972ced5af6aef816016c30576e525beda66bb4980200000000fdffffff014a0b0000000000001600143626f103c551124f501c8008d875e4d8a19b8d7e0247304402203d9e3bda11a1f0c2f0b4b51100b175ca1795e92ad391f1e9b898269a4db8196a02201faaf2157f859d4e2b92ebd4005d3cb2afc5dbf0b986f85520768f32bccf3f0e012103680d29bfc0deb1161e0e4d934dea1d0712ee0785a1e1c16ff3f55751b19afaa1ede40200";
        let spk_str = "00149cfa9f8a1430e25658d1dda0b9fbccbf09f54002";
        let expected_public_key_str =
            "03680d29bfc0deb1161e0e4d934dea1d0712ee0785a1e1c16ff3f55751b19afaa1";

        let tx: Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(tx_str).unwrap()).unwrap();
        let spk = ScriptBuf::from_hex(spk_str).unwrap();
        let zipped = tx.input.into_iter().zip([spk]).collect();

        let res = get_pubkeys_from_transaction(zipped).unwrap();

        assert!(res.len() == 1);

        let expected_pk = PublicKey::from_str(expected_public_key_str).unwrap();
        assert_eq!(res[0], expected_pk);
    }

    #[test]
    fn test_multiple_wpkh_input_transaction() {
        let tx_str = "02000000000102a9b9e18ab45fd7b9a6243a72972ced5af6aef816016c30576e525beda66bb4980100000000fdffffffa9b9e18ab45fd7b9a6243a72972ced5af6aef816016c30576e525beda66bb4980200000000fdffffff01d6120000000000001600143626f103c551124f501c8008d875e4d8a19b8d7e02473044022020754e5abf07a0219d21a1aaa544395d224b9daa36fce2090e533c2643fa667402201b2b1f28fd74e88626f340c28e65eb9294ca8d643dc1e0837098070b16406a67012102ccb119249f240f96ce9b71dd1ac41e09e56315ee9624bd7caaeb34f81729dca502473044022026e7ca9f134586fa9429f678c1e6e7e9d87b1b233545f2b34c47547a74c4525d022040b682dff5a1951496eca61c52c5ded13c79e9e0bef519ae4996f48bc27d1c8b012103680d29bfc0deb1161e0e4d934dea1d0712ee0785a1e1c16ff3f55751b19afaa1f2e40200";
        let spk_str_1 = "0014478024d034d5289c849f2868758a65b436ead84f";
        let spk_str_2 = "00149cfa9f8a1430e25658d1dda0b9fbccbf09f54002";
        let expected_public_key_str_1 =
            "02ccb119249f240f96ce9b71dd1ac41e09e56315ee9624bd7caaeb34f81729dca5";
        let expected_public_key_str_2 =
            "03680d29bfc0deb1161e0e4d934dea1d0712ee0785a1e1c16ff3f55751b19afaa1";

        let tx: Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(tx_str).unwrap()).unwrap();
        let spk_1 = ScriptBuf::from_hex(spk_str_1).unwrap();
        let spk_2 = ScriptBuf::from_hex(spk_str_2).unwrap();
        let zipped = tx.input.into_iter().zip([spk_1, spk_2]).collect();

        let res = get_pubkeys_from_transaction(zipped).unwrap();

        assert!(res.len() == 2);

        let expected_pk_1 = PublicKey::from_str(expected_public_key_str_1).unwrap();
        let expected_pk_2 = PublicKey::from_str(expected_public_key_str_2).unwrap();
        assert_eq!(res[0], expected_pk_1);
        assert_eq!(res[1], expected_pk_2);
    }
}
