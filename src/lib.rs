#![allow(dead_code, non_snake_case)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
};

use bech32::ToBase32;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use structs::Outpoint;
use utils::hash_outpoints;

use crate::receiving::{
    calculate_P_n, calculate_ecdh_secret, calculate_t_n, get_A_sum_public_keys,
};

pub mod error;
pub mod receiving;
pub mod sending;
pub mod structs;
pub mod utils;

pub type Result<T> = std::result::Result<T, Error>;

use crate::error::Error;

const NULL_LABEL: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Eq, PartialEq)]
struct Label {
    s: Scalar,
}

impl Label {
    pub fn into_inner(self) -> Scalar {
        self.s
    }

    pub fn as_inner(&self) -> &Scalar {
        &self.s
    }

    pub fn as_string(&self) -> String {
        hex::encode(self.as_inner().to_be_bytes())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        todo!();
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let bytes = self.s.to_be_bytes();
        bytes.hash(state);
    }
}

impl From<Scalar> for Label {
    fn from(s: Scalar) -> Self {
        Label { s }
    }
}

impl TryFrom<String> for Label {
    type Error = Error;

    fn try_from(s: String) -> Result<Label> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::InvalidLabel("Label must be 32 bytes (256 bits) long".to_owned())
        })?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl TryFrom<&str> for Label {
    type Error = Error;

    fn try_from(s: &str) -> Result<Label> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::InvalidLabel("Label must be 32 bytes (256 bits) long".to_owned())
        })?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl From<Label> for Scalar {
    fn from(l: Label) -> Self {
        l.s
    }
}

// #[derive(Debug)]
pub struct SilentPayment {
    version: u8,
    scan_privkey: SecretKey,
    spend_privkey: SecretKey,
    labels: HashMap<PublicKey, Label>,
    is_testnet: bool,
}

impl SilentPayment {
    pub fn new(
        version: u32,
        scan_privkey: SecretKey,
        spend_privkey: SecretKey,
        is_testnet: bool,
    ) -> Result<Self> {
        let labels: HashMap<PublicKey, Label> = HashMap::new();

        // Check version, we just refuse anything other than 0 for now
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        Ok(SilentPayment {
            version: version as u8,
            scan_privkey,
            spend_privkey,
            labels,
            is_testnet,
        })
    }

    /// Takes an hexstring that must be exactly 32B and must be on the order of the curve
    /// Returns a bool on success, `true` if the label was new, `false` if it already existed in our list
    pub fn add_label(&mut self, label: String) -> Result<bool> {
        let secp = Secp256k1::new();

        let m: Label = label.try_into()?;
        let secret = SecretKey::from_slice(&m.as_inner().to_be_bytes())?;
        let old_value = self.labels.insert(secret.public_key(&secp), m);
        Ok(old_value.is_none())
    }

    fn encode_silent_payment_address(
        &self,
        hrp: Option<&str>,
        m_pubkey: Option<PublicKey>,
    ) -> String {
        let secp = Secp256k1::new();
        let hrp = hrp.unwrap_or("sp");
        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_privkey.public_key(&secp).serialize();
        let B_m_bytes: [u8; 33];
        if let Some(spend_pubkey) = m_pubkey {
            B_m_bytes = spend_pubkey.serialize();
        } else {
            B_m_bytes = self.spend_privkey.public_key(&secp).serialize();
        }

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }

    fn create_labeled_silent_payment_address(&self, m: Label, hrp: Option<&str>) -> Result<String> {
        let secp = Secp256k1::new();
        let base_spend_key = self.spend_privkey.clone();
        let b_m = base_spend_key.add_tweak(m.as_inner())?;

        Ok(self.encode_silent_payment_address(hrp, Some(b_m.public_key(&secp))))
    }

    pub fn get_receiving_addresses(
        &mut self,
        labels: Vec<String>,
    ) -> Result<HashMap<String, String>> {
        let mut receiving_addresses: HashMap<String, String> = HashMap::new();

        let hrp = match self.is_testnet {
            false => "sp",
            true => "tsp",
        };

        receiving_addresses.insert(
            NULL_LABEL.to_owned(),
            self.encode_silent_payment_address(Some(hrp), None),
        );
        for label in labels {
            let _is_new_label = self.add_label(label.clone())?;
            receiving_addresses.insert(
                label.clone(),
                self.create_labeled_silent_payment_address(label.try_into()?, Some(hrp))?,
            );
        }

        Ok(receiving_addresses)
    }

    /// Scans for outputs by iterating through a set of public keys to check for matches.
    ///
    /// It first calculates a shared secret using the outpoints, input keys, and the scanning private key.
    /// Then, it creates a loop, where for each iteration, it computes a new tweak based on the shared secret and the iteration number.
    /// The tweaked spend private key is then used to derive a new public key.
    ///
    /// The function checks if this public key matches any of the public keys to check. If a match is found,
    /// the tweaked private key is added to the value to return.
    ///
    /// If we have registered labels then we compute the diff between the new public key and each output, and see if
    /// any of those diffs match one of the labels. If that's the case we tweak the new private key with the label
    /// and add it the our return value.
    ///
    /// The function stops iterating when one loop doesn't found any match with the public keys to scan.
    ///
    /// # Arguments
    ///
    /// * `outpoints` - A `HashSet` of outpoints (a transaction hash and an index) to be included in the computation of the shared secret.
    /// * `input_keys` - A `Vec` of input keys used to calculate the sum of public keys, which is then used in the computation of the shared secret.
    /// * `pubkeys_to_check` - A `HashSet` of public keys to check for matches with the public key derived from the tweaked private key.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `HashMap` of labels and a list of private keys (since the same label can have been paid many outputs in one transaction). If the length of the `HashMap` is 0, it simply means there are no outputs that belongs to us in this transaction.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * The calculation of the tweak, the addition of the tweak to the spend private key, or the derivation of the new public key fails.
    /// * One of the public keys to scan can't be parsed into a valid x only public key.
    /// * The computation of the difference between a public key to check and the new public key fails.
    pub fn scan_for_outputs(
        &self,
        outpoints: HashSet<Outpoint>,
        input_keys: Vec<PublicKey>,
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let secp = secp256k1::Secp256k1::new();

        let outpoints_hash = hash_outpoints(&outpoints).unwrap();
        let A_sum = get_A_sum_public_keys(&input_keys).unwrap();

        let ecdh_shared_secret = calculate_ecdh_secret(&A_sum, self.scan_privkey, outpoints_hash)?;

        // for p in &pubkeys_to_check {
        //     println!("{}", p);
        // }

        fn insert_new_key(
            mut new_privkey: SecretKey,
            my_outputs: &mut HashMap<String, Vec<String>>,
            label: Option<&Label>,
        ) -> Result<SecretKey> {
            let label_string: String = match label {
                Some(l) => {
                    new_privkey = new_privkey.add_tweak(l.as_inner())?;
                    l.as_string()
                }
                None => NULL_LABEL.to_owned(),
            };

            my_outputs
                .entry(label_string)
                .or_insert_with(Vec::new)
                .push(hex::encode(&new_privkey.secret_bytes()));

            Ok(new_privkey)
        }

        let mut my_outputs: HashMap<String, Vec<String>> = HashMap::new();
        let mut n: u32 = 0;
        while my_outputs.len() == n as usize {
            let t_n: Scalar = calculate_t_n(&ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_privkey.public_key(&secp), t_n)?;
            println!("{}", P_n.x_only_public_key().0);
            if pubkeys_to_check
                .iter()
                .any(|p| p.eq(&P_n.x_only_public_key().0))
            {
                insert_new_key(self.spend_privkey.add_tweak(&t_n)?, &mut my_outputs, None)?;
            } else if !self.labels.is_empty() {
                // We need to take the negation of P_n, adding it is equivalent to substracting P_n
                let P_n_negated: PublicKey = P_n.negate(&secp);
                // then we substract P_n from each outputs to check and see if match a public key in our label list
                pubkeys_to_check.iter().find_map(|p| {
                    let even_output = p.public_key(Parity::Even);
                    let odd_output = p.public_key(Parity::Odd);
                    let even_diff = even_output.combine(&P_n_negated).ok()?;
                    let odd_diff = odd_output.combine(&P_n_negated).ok()?;

                    for diff in vec![even_diff, odd_diff] {
                        if let Some(hit) = self.labels.get(&diff) {
                            insert_new_key(
                                self.spend_privkey.add_tweak(&t_n).ok()?,
                                &mut my_outputs,
                                Some(hit),
                            )
                            .ok()?;
                            return Some(());
                        }
                    }
                    None
                });
            }
            n += 1;
        }
        Ok(my_outputs)
    }
}

#[cfg(test)]
mod tests {
    use crate::Label;

    #[test]
    fn string_to_label() {
        // Invalid characters
        let s: String = "deadbeef?:{+!&".to_owned();
        Label::try_from(s).unwrap_err();
        // Invalid length
        let s: String = "deadbee".to_owned();
        Label::try_from(s).unwrap_err();
        // Not 32B
        let s: String = "deadbeef".to_owned();
        Label::try_from(s).unwrap_err();
    }
}
