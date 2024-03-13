use bech32::{FromBase32, ToBase32};

use core::fmt;
use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::collections::HashMap;

use crate::{common::calculate_t_n, error::Error, Result};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    is_testnet: bool,
}

impl SilentPaymentAddress {
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        is_testnet: bool,
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
            is_testnet,
            version,
        })
    }

    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    pub fn is_testnet(&self) -> bool {
        self.is_testnet
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

        let is_testnet = match hrp.as_str() {
            "sp" => false,
            "tsp" => true,
            _ => {
                return Err(Error::InvalidAddress(format!(
                    "Wrong prefix, expected \"sp\" or \"tsp\", got \"{}\"",
                    &hrp
                )))
            }
        };

        let data = Vec::<u8>::from_base32(&data[1..])?;

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, is_testnet, version)
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
        let hrp = match val.is_testnet {
            true => "tsp",
            false => "sp",
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
            let ecdh_shared_secret: PublicKey = B_scan.mul_tweak(&secp, &partial_secret.into())?;

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
