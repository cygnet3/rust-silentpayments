use bech32::{FromBase32, ToBase32};

use secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use std::collections::HashMap;

use crate::{
    error::Error,
    utils::{ser_uint32, sha256, Result},
};

struct SilentPaymentAddress {
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
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(&addr)?;

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

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, is_testnet, version.into())
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

impl Into<String> for SilentPaymentAddress {
    fn into(self) -> String {
        let hrp = match self.is_testnet {
            true => "tsp",
            false => "sp",
        };

        let version = bech32::u5::try_from_u8(self.version).unwrap();

        let B_scan_bytes = self.scan_pubkey.serialize();
        let B_m_bytes = self.m_pubkey.serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).unwrap()
    }
}

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// # Arguments
///
/// * `recipients` - A `Vec` of silent payment addresses to be paid.
/// * `ecdh_shared_secrets` - A HashMap that maps every scan key to a shared secret created with this scan key.
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
/// * The ecdh_shared_secrets does not contain a secret for every B_scan that are being paid to.
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn create_outputs(
    recipients: Vec<String>,
    ecdh_shared_secrets: HashMap<PublicKey, PublicKey>,
) -> Result<HashMap<String, Vec<XOnlyPublicKey>>> {
    let secp = Secp256k1::new();

    let mut silent_payment_groups: HashMap<PublicKey, (PublicKey, Vec<SilentPaymentAddress>)> =
        HashMap::new();
    for recipient in recipients {
        let recipient: SilentPaymentAddress = recipient.try_into()?;
        let B_scan = recipient.scan_pubkey;

        if let Some((_, payments)) = silent_payment_groups.get_mut(&B_scan) {
            payments.push(recipient);
        } else {
            let ecdh_shared_secret = ecdh_shared_secrets
                .get(&B_scan)
                .ok_or(Error::InvalidSharedSecret(
                    "Shared secret for this B_scan not found".to_owned(),
                ))?
                .to_owned();
            silent_payment_groups.insert(B_scan, (ecdh_shared_secret, vec![recipient]));
        }
    }

    let mut result: HashMap<String, Vec<XOnlyPublicKey>> = HashMap::new();
    for group in silent_payment_groups.into_values() {
        let mut n = 0;

        let (ecdh_shared_secret, recipients) = group;

        for recipient in recipients {
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&ecdh_shared_secret.serialize());
            bytes.extend_from_slice(&ser_uint32(n));

            let t_n = sha256(&bytes);

            let res = SecretKey::from_slice(&t_n)?.public_key(&secp);
            let reskey = res.combine(&recipient.m_pubkey)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let entry = result.entry(recipient.into()).or_insert_with(Vec::new);
            entry.push(reskey_xonly);
            n += 1;
        }
    }
    Ok(result)
}

pub fn decode_scan_pubkey(silent_payment_address: String) -> Result<PublicKey> {
    let address: SilentPaymentAddress = silent_payment_address.try_into()?;
    Ok(address.scan_pubkey)
}
