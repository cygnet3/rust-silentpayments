#![allow(non_snake_case)]
use std::{fs::File, collections::{HashMap, HashSet}, str::FromStr, io::Read};
use std::hash::{Hash, Hasher};

use bech32::FromBase32;
use hex::FromHex;
use secp256k1::{SecretKey, PublicKey, Secp256k1, Scalar, Parity};
use serde::Deserialize;
use serde_json::from_str;
use sha2::{Sha256, Digest};


#[derive(Debug, Deserialize)]
struct TestData {
    comment: String,
    sending: Vec<SendingData>,
}

#[derive(Debug, Deserialize)]
struct SendingData {
    given: SendingDataGiven,
    expected: SendingDataExpected,

}

#[derive(Debug, Deserialize)]
struct SendingDataGiven {
    outpoints: Vec<(String, u32)>,
    input_priv_keys: Vec<(String, bool)>,
    recipients: Vec<(String, f32)>,
}

#[derive(Debug, Deserialize)]
struct SendingDataExpected {
    outputs: Vec<HashMap<String, f32>>,
}

#[derive(Debug)]
struct ComparableHashMap {
    inner: HashMap<String, f32>
}

impl From<HashMap<String, f32>> for ComparableHashMap {
    fn from(map: HashMap<String, f32>) -> Self {
        ComparableHashMap { inner: map }
    }
}

impl PartialEq for ComparableHashMap {
    fn eq(&self, other: &Self) -> bool {
        if self.inner.len() != other.inner.len() {
            return false;
        }

        self.inner.iter().all(|(key, val)| {
            other.inner.get(key).map_or(false, |other_val| (val - other_val).abs() < 0.0001)
        })
    }
}

impl Eq for ComparableHashMap {}

impl Hash for ComparableHashMap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.inner.keys().collect();
        keys.sort(); // ensure consistent order
        for key in keys {
            key.hash(state);
        }
    }
}

fn read_file() -> Vec<TestData> {
    let mut file = File::open("send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}

fn sha256(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

fn ser_uint32(u: u32) -> Vec<u8> {
    u.to_be_bytes().into()
}

fn hash_outpoints(sending_data: &Vec<(String,u32)>) -> [u8; 32] {

    let mut outpoints: Vec<Vec<u8>> = vec![];

    for (txid_str, vout) in sending_data {
        let mut txid = Vec::from_hex(txid_str).unwrap();
        txid.reverse();
        let mut vout_bytes = vout.to_le_bytes().to_vec();
        txid.append(&mut vout_bytes);
        outpoints.push(txid);
    }
    outpoints.sort();

    let mut hasher = Sha256::new();
    for v in outpoints {
        hasher.update(&v[..]);
    }

    let result = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}



fn get_a_sum(input: &Vec<(String, bool)>) -> SecretKey {
    let secp = Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (keystr, is_xonly) in input {
        let key = SecretKey::from_str(&keystr).unwrap();
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_xonly && parity == Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(key);
        }
    }

    let (head, tail) = negated_keys.split_first().unwrap();

    let result: SecretKey = tail.iter().fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

    result
}


fn decode_silent_payment_address(addr: &str) -> (PublicKey, PublicKey) {
    let (_hrp, data, _variant) = bech32::decode(&addr).unwrap();

    let data = Vec::<u8>::from_base32(&data[1..]).unwrap();

    let b_scan = PublicKey::from_slice(&data[..33]).unwrap();
    let b_spend = PublicKey::from_slice(&data[33..]).unwrap();

    (b_scan, b_spend)
}

fn create_outputs(given: &SendingDataGiven) -> Vec<HashMap<String, f32>> {
    let secp = Secp256k1::new();
    // let G = 

    let outpoints: &Vec<(String, u32)> = &given.outpoints;
    let outpoints_hash = hash_outpoints(outpoints);


    let input_priv_keys = &given.input_priv_keys;
    let a_sum = get_a_sum(input_priv_keys);

    let recipients = &given.recipients;

    let mut silent_payment_groups: HashMap<PublicKey, Vec<(PublicKey, f32)>> = HashMap::new();
    for (payment_address, amount) in recipients {
        let (B_scan, B_m) = decode_silent_payment_address(&payment_address);

        if silent_payment_groups.contains_key(&B_scan) {
            silent_payment_groups.get_mut(&B_scan).unwrap().push((B_m, *amount));
        } else {
            silent_payment_groups.insert(B_scan, vec![(B_m, *amount)]);
        }
    }

    let mut result: Vec<HashMap<String, f32>> = vec![];
    for (B_scan, B_m_values) in silent_payment_groups.into_iter() {
        let mut n = 0;

        //calculate shared secret
        let intermediate = B_scan.mul_tweak(&secp, &a_sum.into()).unwrap();
        let scalar = Scalar::from_be_bytes(outpoints_hash).unwrap();
        let ecdh_shared_secret = intermediate.mul_tweak(&secp, &scalar).unwrap().serialize();

        for (B_m, amount) in B_m_values {
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend_from_slice(&ecdh_shared_secret);
            bytes.extend_from_slice(&ser_uint32(n));

            let t_n = sha256(&bytes);
            // eprintln!("t_n = {:?}", hex::encode(t_n));

            let G: PublicKey = SecretKey::from_slice(&Scalar::ONE.to_be_bytes()).unwrap().public_key(&secp);
            let res = G.mul_tweak(&secp, &Scalar::from_be_bytes(t_n).unwrap()).unwrap();
            let reskey = res.combine(&B_m).unwrap();

            let mut resstr: String = reskey.to_string();
            resstr.drain(..2);
            

            let mut toAdd: HashMap<String, f32> = HashMap::new();

            toAdd.insert(resstr, amount);

            result.push(toAdd);

            n += 1;
        }
        // n += 1;
    }
    result
}


fn main() {
    let testdata = read_file();

    for test in testdata {
        eprintln!("test.comment = {:?}", test.comment);
        for sendingtest in test.sending {
            let given = sendingtest.given;

            let expected = sendingtest.expected;
            let expected_comparable: HashSet<ComparableHashMap> = expected.outputs.into_iter().map(|x| x.into() ).collect();

            let outputs = create_outputs(&given);
            let outputs_comparable : HashSet<ComparableHashMap> = outputs.into_iter().map(|x| x.into()).collect();

            if outputs_comparable == expected_comparable {
                println!("succeeded");
            } else {
                eprintln!("expected = {:#?}", expected_comparable);
                eprintln!("outputs = {:#?}", outputs_comparable);
            }
        }
    }
}
