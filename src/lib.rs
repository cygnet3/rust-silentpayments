//! A rust implementation of BIP352: Silent Payments. This library
//! can be used to add silent payment support to wallets.
//!
//! This library is split up in two parts: sending and receiving.
//! Either of these can be implemented independently using
//! the `sending` or `receiving` features.
//!
//! ## Examples
//!
//! Will be added soon.
//! In the meantime, have a look at the [test vectors from the BIP](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs)
//! to see how to do a simple implementation.
//!
//! Alternatively, have a look at [Sp client](https://github.com/cygnet3/sp-client/tree/master),
//! which is a WIP wallet client for building silent payment wallets.
#![allow(dead_code, non_snake_case)]

#[cfg(not(any(feature = "secp_28", feature = "secp_29")))]
compile_error!("You must select one version of secp256k1 via feature flag");
#[cfg(all(feature = "secp_28", not(feature = "secp_29")))]
pub use secp_28 as secp256k1;
#[cfg(feature = "secp_29")]
pub use secp_29 as secp256k1;

mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
pub mod utils;

pub use bitcoin_hashes;

pub use crate::error::Error;
pub use utils::common::Network;
pub use utils::common::SilentPaymentAddress;

pub type Result<T> = std::result::Result<T, Error>;
