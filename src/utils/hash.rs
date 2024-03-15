use crate::Error;
use bitcoin_hashes::{sha256t_hash_newtype, Hash, HashEngine};
use secp256k1::{PublicKey, Scalar, SecretKey};

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);

    pub(crate) struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    pub(crate) struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

impl InputsHash {
    pub(crate) fn from_outpoint_and_A_sum(
        smallest_outpoint: &[u8; 36],
        A_sum: PublicKey,
    ) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(smallest_outpoint);
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub(crate) fn from_b_scan_and_m(b_scan: SecretKey, m: u32) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &PublicKey, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub(crate) fn calculate_input_hash(
    outpoints_data: &[(String, u32)],
    A_sum: PublicKey,
) -> Result<Scalar, Error> {
    if outpoints_data.is_empty() {
        return Err(Error::GenericError("No outpoints provided".to_owned()));
    }

    let mut outpoints: Vec<[u8; 36]> = Vec::with_capacity(outpoints_data.len());

    // should probably just use an OutPoints type properly at some point
    for (txid, vout) in outpoints_data {
        let mut bytes: Vec<u8> = hex::decode(txid.as_str())?;

        if bytes.len() != 32 {
            return Err(Error::GenericError(format!(
                "Invalid outpoint hex representation: {}",
                txid
            )));
        }

        // txid in string format is big endian and we need little endian
        bytes.reverse();

        let mut buffer = [0u8; 36];

        buffer[..32].copy_from_slice(&bytes);
        buffer[32..].copy_from_slice(&vout.to_le_bytes());
        outpoints.push(buffer);
    }

    // sort outpoints
    outpoints.sort_unstable();

    if let Some(smallest_outpoint) = outpoints.first() {
        Ok(InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum).to_scalar())
    } else {
        // This should never happen
        Err(Error::GenericError(
            "Unexpected empty outpoints vector".to_owned(),
        ))
    }
}
