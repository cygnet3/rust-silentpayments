#![allow(dead_code, non_snake_case)]

pub mod error;
pub mod receiving;
pub mod sending;
pub mod structs;
pub mod utils;

pub type Result<T> = std::result::Result<T, Error>;

use crate::error::Error;

