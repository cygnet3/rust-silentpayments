use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{Error, Result, common::{calculate_t_n, calculate_P_n}};
use bech32::ToBase32;
use bimap::BiMap;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Serialize, ser::{SerializeStruct, SerializeTuple}, Deserializer, Deserialize, de::{Visitor, SeqAccess, self}};

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

impl std::hash::Hash for Label {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
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
#[derive(Debug, Clone, PartialEq)]
pub struct Receiver {
    version: u8,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    labels: BiMap<Label, PublicKey>,
    pub is_testnet: bool,
}

struct SerializablePubkey([u8;33]);

struct SerializableBiMap(BiMap<Label, PublicKey>);

impl Serialize for SerializablePubkey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for element in self.0.as_ref() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SerializablePubkey {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SerializablePubkeyVisitor;

        impl<'de> Visitor<'de> for SerializablePubkeyVisitor {
            type Value = SerializablePubkey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 33 bytes")
            }

            fn visit_seq<V>(self, mut seq: V) -> std::prelude::v1::Result<SerializablePubkey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut arr = [0u8; 33];
                for i in 0..33 {
                    arr[i] = seq.next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(SerializablePubkey(arr))
            }
        }

        deserializer.deserialize_tuple(33, SerializablePubkeyVisitor)
    }
}

impl Serialize for SerializableBiMap {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer 
    {
        let pairs: Vec<(String, SerializablePubkey)> = self.0.iter()
            .map(|(label, pubkey)| {
                (label.as_string(), SerializablePubkey(pubkey.serialize()))
            })
            .collect();
        // Now serialize `pairs` as a vector of tuples
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableBiMap {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs: Vec<(String, SerializablePubkey)> = Deserialize::deserialize(deserializer)?;
        let mut bimap: BiMap<Label, PublicKey> = BiMap::new();
        for (string, ser_pubkey) in pairs {
            bimap.insert(Label::try_from(string).unwrap(), PublicKey::from_slice(&ser_pubkey.0).unwrap());
        }
        Ok(SerializableBiMap(bimap))
    }
}

impl Serialize for Receiver {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer 
    {
        let mut state = serializer.serialize_struct("Receiver", 5)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("is_testnet", &self.is_testnet)?;
        state.serialize_field("scan_pubkey", &SerializablePubkey(self.scan_pubkey.serialize()))?;
        state.serialize_field("spend_pubkey", &SerializablePubkey(self.spend_pubkey.serialize()))?;
        state.serialize_field("labels", &SerializableBiMap(self.labels.clone()))?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ReceiverHelper {
    version: u8,
    is_testnet: bool,
    scan_pubkey: SerializablePubkey,
    spend_pubkey: SerializablePubkey,
    labels: SerializableBiMap,
}

impl<'de> Deserialize<'de> for Receiver {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = ReceiverHelper::deserialize(deserializer)?;
        Ok(Receiver {
            version: helper.version,
            is_testnet: helper.is_testnet,
            scan_pubkey: PublicKey::from_slice(&helper.scan_pubkey.0).unwrap(),
            spend_pubkey: PublicKey::from_slice(&helper.spend_pubkey.0).unwrap(),
            labels: helper.labels.0, 
        })
    }
}

impl Receiver {
    pub fn new(
        version: u32,
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        is_testnet: bool,
    ) -> Result<Self> {
        let labels: BiMap<Label, PublicKey> = BiMap::new();

        // Check version, we just refuse anything other than 0 for now
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        Ok(Receiver {
            version: version as u8,
            scan_pubkey,
            spend_pubkey,
            labels,
            is_testnet,
        })
    }

    /// Takes a Label and adds it to the list of labels that this recipient uses.
    /// Returns a bool on success, `true` if the label was new, `false` if it already existed in our list.
    pub fn add_label(&mut self, label: Label) -> Result<bool> {
        let secp = Secp256k1::new();

        let m = SecretKey::from_slice(&label.as_inner().to_be_bytes())?;
        let mG = m.public_key(&secp);

        let old = self.labels.insert(label, mG);

        Ok(!old.did_overwrite())
    }

    /// List all currently known labels used by this recipient.
    pub fn list_labels(&self) -> HashSet<Label> {
        self.labels.left_values().cloned().collect()
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
        match self.labels.get_by_left(label) {
            Some(mG) => {
                let B_m = mG.combine(&self.spend_pubkey)?;
                Ok(self.encode_silent_payment_address(B_m))
            }
            None => Err(Error::InvalidLabel("Label not known".to_owned())),
        }
    }

    /// Get the bech32m-encoded silent payment address.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `String`, which is the bech32m encoded silent payment address.
    pub fn get_receiving_address(&self) -> String {
        self.encode_silent_payment_address(self.spend_pubkey)
    }

    /// Scans a transaction for outputs belonging to us.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient as a PublicKey, the result of elliptic-curve multiplication of `(outpoints_hash * sum_inputs_pubkeys) * scan_private_key`.
    /// * `pubkeys_to_check` - A `HashSet` of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `HashMap` of labels to a map of outputs to key tweaks (since the same label may have been paid multiple times in one transaction). The key tweaks can be added to the wallet's spending private key to produce a key that can spend the utxo. A resulting `HashMap` of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious. (?)
    pub fn scan_transaction_with_labels(
        &self,
        ecdh_shared_secret: &PublicKey,
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashMap<Label, HashMap<XOnlyPublicKey, Scalar>>> {
        let secp = secp256k1::Secp256k1::new();

        let mut found: HashMap<Label, HashMap<XOnlyPublicKey, Scalar>> = HashMap::new();
        let mut n_found: u32 = 0;
        let mut n: u32 = 0;
        while n_found == n {
            let t_n: SecretKey = calculate_t_n(&ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_pubkey, t_n.into())?;
            let P_n_xonly = P_n.x_only_public_key().0;
            if pubkeys_to_check
                .iter()
                .any(|p| p.eq(&P_n_xonly))
            {
                n_found += 1;
                found.entry(NULL_LABEL)
                    .or_insert_with(HashMap::new)
                    .insert(P_n_xonly, t_n.into());
            } else if !self.labels.is_empty() {
                // We subtract P_n from each outputs to check and see if match a public key in our label list
                'outer: for p in &pubkeys_to_check {
                    let even_output = p.public_key(Parity::Even);
                    let odd_output = p.public_key(Parity::Odd);
                    let even_diff = even_output.combine(&P_n.negate(&secp))?;
                    let odd_diff = odd_output.combine(&P_n.negate(&secp))?;

                    for diff in [even_diff, odd_diff] {
                        if let Some(label) = self.labels.get_by_right(&diff) {
                            n_found += 1;
                            let t_n_label = t_n.add_tweak(label.as_inner())?;
                            found.entry(label.clone())
                                .or_insert_with(HashMap::new)
                                .insert(*p, t_n_label.into());
                            break 'outer;
                        }
                    }
                }
            }
            n += 1;
        }
        Ok(found)
    }

    /// Scans a transaction for outputs belonging to us.
    /// Note: this function is only for wallets that don't use labels!
    /// If this silent payment wallet uses labels, use `scan_transaction_with_labels` instead.
    ///
    /// # Arguments
    ///
    /// * `tweak_data` -  The tweak data for the transaction as a PublicKey, the result of elliptic-curve multiplication of `outpoints_hash * A`.
    /// * `pubkeys_to_check` - A `Vec` of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a `HashMap` that maps the given outputs to private key tweaks. A resulting `HashMap` of length 0 implies none of the outputs are owned by us.
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
    ) -> Result<HashMap<XOnlyPublicKey, Scalar>> {
        if !self.labels.is_empty() {
            return Err(Error::GenericError(
                "This function should only be used by wallets without labels; use scan_transaction_with_labels instead".to_owned(),
            ));
        }

        // re-use scan_transaction_with_labels function
        let mut map = self.scan_transaction_with_labels(tweak_data, pubkeys_to_check)?;

        match map.remove(&NULL_LABEL) {
            Some(res) => Ok(res),
            None => Ok(HashMap::new()),
        }
    }

    /// Get the Script byte vector from a transaction's tweak data.
    /// Using the tweak data, this function will calculate the resulting script, given the assumption that this transaction is a payment to us.
    /// This Script can be useful for BIP158 block filters.
    /// Important note: this function does not support labels!
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient as a PublicKey, the result of elliptic-curve multiplication of `(outpoints_hash * sum_inputs_pubkeys) * scan_private_key`.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a `Result` wrapping a Script as a 34-byte vector. This has the following format: `OP_PUSHNUM_1 OP_PUSHBYTES_32 taproot_output`
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious. (?)
    pub fn get_script_bytes_from_shared_secret(
        &self,
        ecdh_shared_secret: &PublicKey,
    ) -> Result<[u8; 34]> {
        let t_n: SecretKey = calculate_t_n(&ecdh_shared_secret, 0)?;
        let P_n: PublicKey = calculate_P_n(&self.spend_pubkey, t_n.into())?;
        let output_key_bytes = P_n.x_only_public_key().0.serialize();

        // hardcoded opcode values for OP_PUSHNUM_1 and OP_PUSHBYTES_32
        let mut result = [0u8; 34];
        result[..2].copy_from_slice(&[0x51, 0x20]);

        result[2..].copy_from_slice(&output_key_bytes);

        Ok(result)
    }

    fn encode_silent_payment_address(&self, m_pubkey: PublicKey) -> String {
        let hrp = match self.is_testnet {
            false => "sp",
            true => "tsp",
        };

        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_pubkey.serialize();
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
