#![allow(dead_code, non_snake_case)]

mod error;
pub mod receiving;
pub mod sending;
mod utils;

pub use crate::error::Error;

pub type Result<T> = std::result::Result<T, Error>;
