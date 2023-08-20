use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
};

use crate::{
    utils::{calculate_P_n, calculate_t_n},
    Error,
};
use bech32::ToBase32;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::Result;

const NULL_LABEL: Label = Label { s: Scalar::ZERO };

#[derive(Eq, PartialEq, Clone)]
pub struct Label {
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
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
        Label::try_from(&s[..])
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

#[derive(Debug)]
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

    /// Takes a Label and adds it to the list of labels that this recipient uses.
    /// Returns a bool on success, `true` if the label was new, `false` if it already existed in our list.
    pub fn add_label(&mut self, label: Label) -> Result<bool> {
        let secp = Secp256k1::new();

        let secret = SecretKey::from_slice(&label.as_inner().to_be_bytes())?;
        let old_value = self.labels.insert(secret.public_key(&secp), label);
        Ok(old_value.is_none())
    }

    /// List all currently known labels used by this recipient.
    pub fn list_labels(&self) -> HashSet<Label> {
        self.labels.values().cloned().collect()
    }

    fn encode_silent_payment_address(&self, m_pubkey: PublicKey) -> String {
        let hrp = match self.is_testnet {
            false => "sp",
            true => "tsp",
        };

        let secp = Secp256k1::new();
        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_privkey.public_key(&secp).serialize();
        let B_m_bytes = m_pubkey.serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }

    /// Get the bech32m-encoded silent payment address, optionally for a specific label.
    ///
    /// # Arguments
    ///
    /// * `label` - An `Option` that wraps a reference to a Label. If the Option is None, then no label is being used.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a String, which is the bech32m encoded silent payment address.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * If the label is not known for this recipient.
    /// * If key addition results in an invalid key.
    pub fn get_receiving_address(&mut self, label: Option<&Label>) -> Result<String> {
        let secp = Secp256k1::new();
        let base_spend_key = self.spend_privkey;
        let b_m = match label {
            Some(label) => {
                if self.labels.values().any(|l| l.eq(label)) {
                    base_spend_key.add_tweak(label.as_inner())?
                } else {
                    return Err(Error::InvalidLabel("Label not known".to_owned()));
                }
            }
            None => base_spend_key,
        };

        Ok(self.encode_silent_payment_address(b_m.public_key(&secp)))
    }

    /// Helper function that can be used to calculate the elliptic curce shared secret.
    ///
    /// # Arguments
    ///
    /// * `tweak_data` -  The tweak data given as a PublicKey, the result of elliptic-curve multiplication of the outpoints_hash and `A_sum` (the sum of all input public keys).
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping an 33-byte array, which is the shared secret that only the sender and the recipient of a silent payment can derive. This result can be used in the scan_for_outputs function.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * If key multiplication with the scan private key returns an invalid result.
    pub fn calculate_shared_secret(&self, tweak_data: PublicKey) -> Result<[u8; 33]> {
        let secp = Secp256k1::new();

        let ecdh_shared_secret = tweak_data
            .mul_tweak(&secp, &self.scan_privkey.into())?
            .serialize();

        Ok(ecdh_shared_secret)
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
    /// * `ecdh_shared_secret` -  A reference to a 33 byte array computed shared secret, the result of `outpoints_hash * b_{scan} * A`.
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
    /// * One of the public keys to scan can't be parsed into a valid x only public key.
    /// * The computation of the difference between a public key to check and the new public key fails.
    pub fn scan_for_outputs(
        &self,
        ecdh_shared_secret: &[u8; 33],
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashMap<String, Vec<String>>> {
        let secp = secp256k1::Secp256k1::new();

        fn insert_new_key(
            mut new_privkey: SecretKey,
            my_outputs: &mut HashMap<String, Vec<String>>,
            label: Option<&Label>,
        ) -> Result<SecretKey> {
            let label: &Label = match label {
                Some(l) => {
                    new_privkey = new_privkey.add_tweak(l.as_inner())?;
                    l
                }
                None => &NULL_LABEL,
            };

            my_outputs
                .entry(label.as_string())
                .or_insert_with(Vec::new)
                .push(hex::encode(&new_privkey.secret_bytes()));

            Ok(new_privkey)
        }

        let mut my_outputs: HashMap<String, Vec<String>> = HashMap::new();
        let mut n: u32 = 0;
        while my_outputs.len() == n as usize {
            let t_n: Scalar = calculate_t_n(&ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_privkey.public_key(&secp), t_n)?;
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
    use super::Label;

    #[test]
    fn string_to_label_success() {
        let s: String =
            "8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b".to_owned();
        Label::try_from(s).unwrap();
    }

    #[test]
    fn string_to_label_failure() {
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
