#![allow(dead_code, non_snake_case)]
mod common;
mod error;

#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;
#[cfg(feature = "utils")]
pub mod utils;

pub use secp256k1;

pub use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;
