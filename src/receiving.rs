use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
};

use crate::{
    utils::{calculate_P_n, calculate_t_n, insert_new_key},
    Error,
};
use bech32::ToBase32;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::Result;

pub const NULL_LABEL: Label = Label { s: Scalar::ZERO };

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

/// A struct representing a silent payment recipient.
/// It can be used to scan for transaction outputs belonging to us by using the scan_transaction function.
/// It optionally supports labels, which it manages internally.
/// Labels can be added with the add_label function.
#[derive(Debug)]
pub struct Receiver {
    version: u8,
    scan_privkey: SecretKey,
    spend_privkey: SecretKey,
    labels: HashMap<PublicKey, Label>,
    is_testnet: bool,
}

impl Receiver {
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

        Ok(Receiver {
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

    /// Get the bech32m-encoded silent payment address for a specific label.
    ///
    /// # Arguments
    ///
    /// * `label` - A reference to a Label.
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
    pub fn get_receiving_address_for_label(&self, label: &Label) -> Result<String> {
        let secp = Secp256k1::new();

        let b_m = if self.labels.values().any(|l| l.eq(label)) {
            self.spend_privkey.add_tweak(label.as_inner())?
        } else {
            return Err(Error::InvalidLabel("Label not known".to_owned()));
        };

        Ok(self.encode_silent_payment_address(b_m.public_key(&secp)))
    }

    /// Get the bech32m-encoded silent payment address.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `String`, which is the bech32m encoded silent payment address.
    pub fn get_receiving_address(&self) -> String {
        let secp = Secp256k1::new();

        self.encode_silent_payment_address(self.spend_privkey.public_key(&secp))
    }

    /// Scans a transaction for outputs belonging to us.
    ///
    /// # Arguments
    ///
    /// * `tweak_data` -  The tweak data for the transaction as a PublicKey, the result of elliptic-curve multiplication of `outpoints_hash * A`.
    /// * `pubkeys_to_check` - A `HashSet` of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `HashMap` of labels to a set of private keys (since the same label may have been paid multiple times in one transaction). A resulting `HashMap` of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious. (?)
    pub fn scan_transaction_with_labels(
        &self,
        tweak_data: &PublicKey,
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashMap<Label, HashSet<SecretKey>>> {
        let secp = secp256k1::Secp256k1::new();
        let B_spend = &self.spend_privkey.public_key(&secp);
        let ecdh_shared_secret = self.calculate_shared_secret(tweak_data)?;

        let mut my_outputs: HashMap<Label, HashSet<SecretKey>> = HashMap::new();
        let mut n: u32 = 0;
        while my_outputs.len() == n as usize {
            let t_n: Scalar = calculate_t_n(&ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&B_spend, t_n)?;
            if pubkeys_to_check
                .iter()
                .any(|p| p.eq(&P_n.x_only_public_key().0))
            {
                insert_new_key(self.spend_privkey.add_tweak(&t_n)?, &mut my_outputs, None)?;
            } else if !self.labels.is_empty() {
                // We subtract P_n from each outputs to check and see if match a public key in our label list
                'outer: for p in &pubkeys_to_check {
                    let even_output = p.public_key(Parity::Even);
                    let odd_output = p.public_key(Parity::Odd);
                    let even_diff = even_output.combine(&P_n.negate(&secp))?;
                    let odd_diff = odd_output.combine(&P_n.negate(&secp))?;

                    for diff in vec![even_diff, odd_diff] {
                        if let Some(label) = self.labels.get(&diff) {
                            insert_new_key(
                                self.spend_privkey.add_tweak(&t_n)?,
                                &mut my_outputs,
                                Some(label),
                            )?;
                            break 'outer;
                        }
                    }
                }
            }
            n += 1;
        }
        Ok(my_outputs)
    }

    /// Scans a transaction for outputs belonging to us.
    /// Note: this function is only for wallets that don't use labels!
    /// If this silent payment wallet uses labels, use `scan_transaction_with_labels` instead.
    ///
    /// # Arguments
    ///
    /// * `tweak_data` -  The tweak data for the transaction as a PublicKey, the result of elliptic-curve multiplication of `outpoints_hash * A`.
    /// * `pubkeys_to_check` - A `HashSet` of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `HashSet` of private keys. A resulting `HashSet` of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious. (?)
    pub fn scan_transaction(
        &self,
        tweak_data: &PublicKey,
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashSet<SecretKey>> {
        if !self.labels.is_empty() {
            return Err(Error::GenericError(
                "This function should only be used by wallets without labels; use scan_transaction_with_labels instead".to_owned(),
            ));
        }

        // re-use scan_transaction_with_labels function
        let mut map = self.scan_transaction_with_labels(tweak_data, pubkeys_to_check)?;

        match map.remove(&NULL_LABEL) {
            Some(res) => Ok(res),
            None => Ok(HashSet::new()),
        }
    }

    /// Get a taproot output from a transaction's tweak data.
    /// Using the tweak data, this function will calculate the resulting taproot output, given the assumption that this transaction is a payment to us.
    /// This function can be useful BIP158 block filters, to create script pubkeys to look for.
    /// Important note: this function does not support labels!
    ///
    /// # Arguments
    ///
    /// * `tweak_data` -  The tweak data for the transaction as a PublicKey, the result of elliptic-curve multiplication of `outpoints_hash * A`.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `XOnlyPublicKey`, which is the calculated taproot output.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious. (?)
    pub fn get_taproot_output_from_tweak_data(
        &self,
        tweak_data: &PublicKey,
        n: u32,
    ) -> Result<XOnlyPublicKey> {
        let secp = secp256k1::Secp256k1::new();
        let B_spend = &self.spend_privkey.public_key(&secp);
        let ecdh_shared_secret = self.calculate_shared_secret(tweak_data)?;
        let t_n: Scalar = calculate_t_n(&ecdh_shared_secret, n)?;
        let P_n: PublicKey = calculate_P_n(&B_spend, t_n)?;

        Ok(P_n.x_only_public_key().0)
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
    fn calculate_shared_secret(&self, tweak_data: &PublicKey) -> Result<[u8; 33]> {
        let secp = Secp256k1::new();

        let ecdh_shared_secret = tweak_data
            .mul_tweak(&secp, &self.scan_privkey.into())?
            .serialize();

        Ok(ecdh_shared_secret)
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
