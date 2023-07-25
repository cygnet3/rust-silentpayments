#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidLabel(String),
    Secp256k1Error(secp256k1::Error),
    OutOfRangeError(secp256k1::scalar::OutOfRangeError),
    Bech32ParseError(bech32::Error),
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidLabel(e.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp256k1Error(e)
    }
}

impl From<secp256k1::scalar::OutOfRangeError> for Error {
    fn from(e: secp256k1::scalar::OutOfRangeError) -> Self {
        Error::OutOfRangeError(e)
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Error::Bech32ParseError(e)
    }
}
