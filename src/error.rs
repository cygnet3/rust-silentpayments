#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidLabel(String),
    InvalidAddress(String),
    Secp256k1Error(secp256k1::Error),
    OutOfRangeError(secp256k1::scalar::OutOfRangeError),
    IOError(std::io::Error),
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidLabel(e.to_string())
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Error::InvalidAddress(e.to_string())
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

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}
