#![allow(dead_code, non_snake_case)]

mod error;
mod utils;
#[cfg(feature = "receiving")]
pub mod receiving;
#[cfg(feature = "sending")]
pub mod sending;

pub use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;
