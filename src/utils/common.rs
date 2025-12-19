#[cfg(feature = "encode")]
use core::fmt;

#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::utils::hash::SharedSecretHash;
use crate::Error;
use crate::Result;
#[cfg(feature = "encode")]
use bech32::{FromBase32, ToBase32};
#[cfg(any(feature = "sending", feature = "receiving"))]
use bitcoin_hashes::Hash;
use secp256k1::PublicKey;
#[cfg(any(feature = "sending", feature = "receiving"))]
use secp256k1::{Scalar, Secp256k1, SecretKey};
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::ser::Serializer;
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::Deserializer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_t_n(ecdh_shared_secret: &PublicKey, k: u32) -> Result<SecretKey> {
    let hash = SharedSecretHash::from_ecdh_and_k(ecdh_shared_secret, k).to_byte_array();
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}

/// The network format used for this silent payment address.
///
/// There are three network types: Mainnet (`sp1..`), Testnet (`tsp1..`), and Regtest (`sprt1..`).
/// Signet uses the same network type as Testnet.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for &str {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "bitcoin", // we use the same string as rust-bitcoin for compatibility
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = crate::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let res = match value {
            "bitcoin" | "main" => Self::Mainnet, // We also take the core style argument
            "regtest" => Self::Regtest,
            "testnet" | "signet" | "test" => Self::Testnet, // core arg
            _ => return Err(Error::InvalidNetwork(value.to_string())),
        };
        Ok(res)
    }
}

/// A silent payment address struct that can be used to deserialize a silent payment address string.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

#[cfg(all(feature = "serde", feature = "encode"))]
impl Serialize for SilentPaymentAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = self.clone().into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(all(feature = "serde", feature = "encode"))]
impl<'de> Deserialize<'de> for SilentPaymentAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr_str: String = Deserialize::deserialize(deserializer)?;

        SilentPaymentAddress::try_from(addr_str.as_str()).map_err(serde::de::Error::custom)
    }
}

impl SilentPaymentAddress {
    /// Construct a `SilentPaymentAddress` from its component parts.
    ///
    /// This constructor is always available, even without the `encode` feature.
    /// If you have your own bech32 parser, you can use it to extract the components
    /// and then construct the address using this method.
    ///
    /// # Bech32 Format (for external parsers)
    ///
    /// Silent payment addresses use bech32m encoding with the following structure:
    /// - **HRP (Human Readable Part)**:
    ///   - Mainnet: `"sp"`
    ///   - Testnet/Signet: `"tsp"`
    ///   - Regtest: `"sprt"`
    /// - **Data**: version (1 byte) + scan_pubkey (33 bytes) + spend_pubkey (33 bytes)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use secp256k1::PublicKey;
    /// use silentpayments::{SilentPaymentAddress, Network};
    ///
    /// // After parsing bech32 yourself and extracting the pubkeys:
    /// let scan_pubkey = PublicKey::from_slice(&scan_bytes)?;
    /// let spend_pubkey = PublicKey::from_slice(&spend_bytes)?;
    ///
    /// let address = SilentPaymentAddress::new(
    ///     scan_pubkey,
    ///     spend_pubkey,
    ///     Network::Mainnet,
    ///     0  // version
    /// )?;
    /// ```
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

    /// Get the scan public key.
    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    /// Get the spend public key.
    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    /// Get the network.
    pub fn get_network(&self) -> Network {
        self.network
    }

    /// Get the version byte.
    pub fn get_version(&self) -> u8 {
        self.version
    }
}

#[cfg(feature = "encode")]
impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <SilentPaymentAddress as Into<String>>::into(*self))
    }
}

#[cfg(feature = "encode")]
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

#[cfg(feature = "encode")]
impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self> {
        addr.as_str().try_into()
    }
}

#[cfg(feature = "encode")]
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
