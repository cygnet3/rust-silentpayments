//! The receiving component of silent payments.
//!
//! For receiving, we use the [`Receiver`] struct.
//! This struct does not contain any private key information,
//! so as to avoid having access to secret data.
//!
//! After creating a [`Receiver`] object, you can call [`scan_transaction`](Receiver::scan_transaction),
//! to scan a specific transaction for outputs belonging to this receiver.
//! For this, you need to have calculated the `ecdh_shared_secret` beforehand.
//! To do so, you can use [`calculate_ecdh_shared_secret`](`crate::utils::receiving::calculate_ecdh_shared_secret`) from the `utils` module.
//!
//! For a concrete example, have a look at the [test vectors](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs).
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{
    utils::{
        common::{calculate_P_n, calculate_t_n},
        hash::LabelHash,
    },
    Error, Network, Result, SilentPaymentAddress,
};
use bimap::BiMap;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{SerializeStruct, SerializeTuple},
    Deserialize, Deserializer, Serialize,
};

/// A Silent payment receiving label.
#[derive(Eq, PartialEq, Clone)]
pub struct Label {
    s: Scalar,
}

impl Label {
    pub fn new(b_scan: SecretKey, m: u32) -> Label {
        Label {
            s: LabelHash::from_b_scan_and_m(b_scan, m).to_scalar(),
        }
    }

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

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        value.try_into().map_err(serde::de::Error::custom)
    }
}

/// A struct representing a silent payment recipient.
///
/// It can be used to scan for transaction outputs belonging to us by using the [`scan_transaction`](Receiver::scan_transaction) function.
/// It optionally supports labels, which it manages internally.
/// Labels can be added with [`add_label`](Receiver::add_label).
#[derive(Debug, Clone, PartialEq)]
pub struct Receiver {
    version: u8,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    change_label: Label, // To be able to tell which label is the change
    labels: BiMap<Label, PublicKey>,
    pub network: Network,
}

struct SerializablePubkey([u8; 33]);

struct SerializableBiMap(BiMap<Label, PublicKey>);

impl Serialize for SerializablePubkey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for element in &self.0[..] {
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

            fn visit_seq<V>(
                self,
                mut seq: V,
            ) -> std::prelude::v1::Result<SerializablePubkey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut arr = [0u8; 33];
                for i in 0..33 {
                    arr[i] = seq
                        .next_element()?
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
        S: serde::Serializer,
    {
        let pairs: Vec<(Label, SerializablePubkey)> = self
            .0
            .iter()
            .map(|(label, pubkey)| (label.to_owned(), SerializablePubkey(pubkey.serialize())))
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
        let pairs: Vec<(Label, SerializablePubkey)> = Deserialize::deserialize(deserializer)?;
        let mut bimap: BiMap<Label, PublicKey> = BiMap::new();
        for (label, ser_pubkey) in pairs {
            bimap.insert(label, PublicKey::from_slice(&ser_pubkey.0).unwrap());
        }
        Ok(SerializableBiMap(bimap))
    }
}

impl Serialize for Receiver {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Receiver", 5)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field(
            "scan_pubkey",
            &SerializablePubkey(self.scan_pubkey.serialize()),
        )?;
        state.serialize_field(
            "spend_pubkey",
            &SerializablePubkey(self.spend_pubkey.serialize()),
        )?;
        state.serialize_field("change_label", &self.change_label)?;
        state.serialize_field("labels", &SerializableBiMap(self.labels.clone()))?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ReceiverHelper {
    version: u8,
    network: Network,
    scan_pubkey: SerializablePubkey,
    spend_pubkey: SerializablePubkey,
    change_label: String,
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
            network: helper.network,
            scan_pubkey: PublicKey::from_slice(&helper.scan_pubkey.0).unwrap(),
            spend_pubkey: PublicKey::from_slice(&helper.spend_pubkey.0).unwrap(),
            change_label: Label::try_from(helper.change_label).unwrap(),
            labels: helper.labels.0,
        })
    }
}

impl Receiver {
    pub fn new(
        version: u32,
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        change_label: Label,
        network: Network,
    ) -> Result<Self> {
        let labels: BiMap<Label, PublicKey> = BiMap::new();

        // Check version, we just refuse anything other than 0 for now
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        let mut receiver = Receiver {
            version: version as u8,
            scan_pubkey,
            spend_pubkey,
            change_label: change_label.clone(),
            labels,
            network,
        };

        // This checks that the change_label produces a valid key at each step
        receiver.add_label(change_label)?;

        Ok(receiver)
    }

    /// Takes a [Label] and adds it to the list of labels that this recipient uses.
    /// Returns a bool on success, [true] if the label was new, [false] if it already existed in our list.
    pub fn add_label(&mut self, label: Label) -> Result<bool> {
        let secp = Secp256k1::signing_only();

        let m = SecretKey::from_slice(&label.as_inner().to_be_bytes())?;
        let mG = m.public_key(&secp);

        // check that the combined key with spend_key is valid
        mG.combine(&self.spend_pubkey)?;

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
    /// * `label` - A reference to a [Label].
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [SilentPaymentAddress] struct.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * If the label is not known for this recipient.
    /// * If key addition results in an invalid key.
    pub fn get_receiving_address_for_label(&self, label: &Label) -> Result<SilentPaymentAddress> {
        match self.labels.get_by_left(label) {
            Some(mG) => {
                let B_m = mG.combine(&self.spend_pubkey)?;
                Ok(self.get_silent_payment_address(B_m))
            }
            None => Err(Error::InvalidLabel("Label not known".to_owned())),
        }
    }

    /// Get the silent payment change address for this Receiver. This is the
    /// static address associated with the change label, as described
    /// in the BIP. Wallets can create silent payment-native change addresses
    /// by sending to this static change address, much like sending to a normal
    /// silent payment address.
    /// Important note: this address should never be shown to the user!
    pub fn get_change_address(&self) -> SilentPaymentAddress {
        let sk = SecretKey::from_slice(&self.change_label.as_inner().to_be_bytes())
            .expect("Unexpected invalid change label");
        let pk = sk.public_key(&Secp256k1::signing_only());
        let B_m = pk
            .combine(&self.spend_pubkey)
            .expect("Unexpected invalid pubkey");
        self.get_silent_payment_address(B_m)
    }

    /// Get the default, no-label silent payment address.
    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
        self.get_silent_payment_address(self.spend_pubkey)
    }

    /// Scans a transaction for outputs belonging to us.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient as a [PublicKey], the result of elliptic-curve multiplication of `(input_hash * sum_inputs_pubkeys) * scan_private_key`.
    /// * `pubkeys_to_check` - A [HashSet] of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] of labels to a map of outputs to key tweaks (since the same label may have been paid multiple times in one transaction). The key tweaks can be added to the wallet's spending private key to produce a key that can spend the utxo. A resulting [HashMap] of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn scan_transaction(
        &self,
        ecdh_shared_secret: &PublicKey,
        pubkeys_to_check: Vec<XOnlyPublicKey>,
    ) -> Result<HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>>> {
        let secp = secp256k1::Secp256k1::new();

        let mut found: HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>> = HashMap::new();
        let mut n_found: u32 = 0;
        let mut n: u32 = 0;
        while n_found == n {
            let t_n: SecretKey = calculate_t_n(ecdh_shared_secret, n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_pubkey, t_n.into())?;
            let P_n_xonly = P_n.x_only_public_key().0;
            if pubkeys_to_check.iter().any(|p| p.eq(&P_n_xonly)) {
                n_found += 1;
                found.entry(None).or_default().insert(P_n_xonly, t_n.into());
            } else {
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
                            found
                                .entry(Some(label.clone()))
                                .or_default()
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

    /// Get the possible ScriptPubKeys from a transaction's tweak data.
    /// Using the tweak data, this function will calculate the resulting script, given the assumption that this transaction is a payment to us.
    /// This Script can be useful for BIP158 block filters.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` -  The ECDH shared secret between sender and recipient as a PublicKey, the result of elliptic-curve multiplication of `(input_hash * sum_inputs_pubkeys) * scan_private_key`.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] that maps an optional [Label] to a Script as a 34-byte vector. The script has the following format: `OP_PUSHNUM_1 OP_PUSHBYTES_32 taproot_output`
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn get_spks_from_shared_secret(
        &self,
        ecdh_shared_secret: &PublicKey,
    ) -> Result<HashMap<Option<Label>, [u8; 34]>> {
        let t_0: SecretKey = calculate_t_n(ecdh_shared_secret, 0)?;
        let P_0: PublicKey = calculate_P_n(&self.spend_pubkey, t_0.into())?;
        let output_key_bytes = P_0.x_only_public_key().0.serialize();

        let mut res = HashMap::new();

        let mut spk = [0u8; 34];
        // hardcoded opcode values for OP_PUSHNUM_1 and OP_PUSHBYTES_32
        spk[..2].copy_from_slice(&[0x51, 0x20]);
        spk[2..].copy_from_slice(&output_key_bytes);

        res.insert(None, spk);

        for (label, mG) in &self.labels {
            let B_m = mG.combine(&self.spend_pubkey)?;
            let P_m0 = calculate_P_n(&B_m, t_0.into())?;
            let output_key_bytes = P_m0.x_only_public_key().0.serialize();

            let mut spk = [0u8; 34];
            spk[..2].copy_from_slice(&[0x51, 0x20]);
            spk[2..].copy_from_slice(&output_key_bytes);

            res.insert(Some(label.clone()), spk);
        }
        Ok(res)
    }

    fn get_silent_payment_address(&self, m_pubkey: PublicKey) -> SilentPaymentAddress {
        SilentPaymentAddress::new(self.scan_pubkey, m_pubkey, self.network, 0)
            .expect("only fails if version != 0")
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
    fn deserialize_label() {
        let s: String =
            "\"8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b\"".to_owned();

        let label: Label = serde_json::from_str(&s).unwrap();

        let label_str = serde_json::to_string(&label).unwrap();

        assert_eq!(label_str, s);
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
