#![allow(dead_code, non_snake_case)]
mod common;
mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
pub mod utils;

pub use bitcoin_hashes;
pub use secp256k1;

pub use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;
