//! The sending component of silent payments.
//!
//! The most relevant function is `generate_recipient_pubkeys`,
//! which can be used to create outputs for a list of silent payment receipients.
//!
//! Using `generate_recipient_pubkeys` will require calculating a
//! `partial_secret` beforehand.
//! To do this, you can use the function from `utils::sending::calculate_partial_secret`.
//! See the [tests on github](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! for a concrete example.
use bech32::{FromBase32, ToBase32};

use core::fmt;
use secp256k1::{ecdh::shared_secret_point, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::collections::HashMap;

use crate::{common::calculate_t_n, error::Error, Network, Result};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

impl SilentPaymentAddress {
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: u8,
    ) -> Result<Self> {
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        Ok(SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            network,
            version,
        })
    }

    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    pub fn get_network(&self) -> Network {
        self.network
    }
}

impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <SilentPaymentAddress as Into<String>>::into(*self))
    }
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(addr)?;

        if data.len() != 107 {
            return Err(Error::GenericError("Address length is wrong".to_owned()));
        }

        let version = data[0].to_u8();

        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            "sprt" => Network::Regtest,
            _ => {
                return Err(Error::InvalidAddress(format!(
                    "Wrong prefix, expected \"sp\", \"tsp\", or \"sprt\", got \"{}\"",
                    &hrp
                )))
            }
        };

        let data = Vec::<u8>::from_base32(&data[1..])?;

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, network, version)
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

impl From<SilentPaymentAddress> for String {
    fn from(val: SilentPaymentAddress) -> Self {
        let hrp = match val.network {
            Network::Testnet => "tsp",
            Network::Regtest => "sprt",
            Network::Mainnet => "sp",
        };

        let version = bech32::u5::try_from_u8(val.version).unwrap();

        let B_scan_bytes = val.scan_pubkey.serialize();
        let B_m_bytes = val.m_pubkey.serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }
}

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
/// When creating the outputs for a transaction, this function should be used to generate the output keys.
/// This function should only be used once per transaction! If used multiple times, address reuse may occur.
///
/// # Arguments
///
/// * `recipients` - A `Vec` of silent payment addresses to be paid.
/// * `partial_secret` - A `SecretKey` that represents the sum of the private keys of eligible inputs of the transaction multiplied by the input hash.
///
/// # Returns
///
/// If successful, the function returns a `Result` wrapping a `HashMap` of silent payment addresses to a `Vec`.
/// The `Vec` contains all the outputs that are associated with the silent payment address.
///
/// # Errors
///
/// This function will return an error if:
///
/// * The recipients Vec contains a silent payment address with an incorrect format.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys(
    recipients: Vec<String>,
    partial_secret: SecretKey,
) -> Result<HashMap<String, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (PublicKey, Vec<SilentPaymentAddress>)> =
        HashMap::new();
    for address in recipients {
        let address: SilentPaymentAddress = address.try_into()?;
        let B_scan = address.scan_pubkey;

        if let Some((_, payments)) = silent_payment_groups.get_mut(&B_scan) {
            payments.push(address);
        } else {
            // Since PublicKey::from_slice expects an uncompressed public key (0x04<64 bytes>),
            // we first initialize a 65 byte array and add 0x04 as the first byte
            let mut ss_bytes = [0u8; 65];
            ss_bytes[0] = 0x04;

            // Using `shared_secret_point` to ensure the multiplication is constant time
            ss_bytes[1..].copy_from_slice(&shared_secret_point(&B_scan, &partial_secret));
            let ecdh_shared_secret = PublicKey::from_slice(&ss_bytes)?;

            silent_payment_groups.insert(B_scan, (ecdh_shared_secret, vec![address]));
        }
    }

    let mut result: HashMap<String, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let mut n = 0;

        let (ecdh_shared_secret, recipients) = group;

        for addr in recipients {
            let t_n = calculate_t_n(&ecdh_shared_secret, n)?;

            let res = t_n.public_key(&secp);
            let reskey = res.combine(&addr.m_pubkey)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(addr.into()).or_default();
            entry.push(reskey_xonly);
            n += 1;
        }
    }
    Ok(result)
}
