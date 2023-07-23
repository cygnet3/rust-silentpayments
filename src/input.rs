use serde::Deserialize;
use serde_json::{from_str, Value};
use std::hash::{Hash, Hasher};
use std::{collections::HashMap, fs::File, io::Read, str::FromStr};

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_pub_keys: Vec<String>,
    pub bip32_seed: String,
    // #[serde(deserialize_with = "empty_array_as_map")]
    pub labels: HashMap<String, u32>,
    pub outputs: Vec<String>,
}

fn empty_array_as_map<'de, D>(deserializer: D) -> Result<HashMap<String, u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;

    match v {
        Value::Array(array) => {
            if array.is_empty() {
                Ok(HashMap::new())
            } else {
                Err(serde::de::Error::custom("Expected map or empty array"))
            }
        }
        Value::Object(map) => {
            let result: HashMap<String, u32> = map
                .into_iter()
                .map(|(k, v)| {
                    if let Value::Number(num) = v {
                        num.as_i64()
                            .and_then(|n| u32::from_str(&n.to_string()).ok())
                            .map(|n| (k, n))
                    } else {
                        None
                    }
                })
                .collect::<Option<_>>()
                .ok_or(serde::de::Error::custom(
                    "Failed to parse map values as u32",
                ))?;

            Ok(result)
        }
        _ => Err(serde::de::Error::custom("Expected map or empty array")),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub addresses: Vec<String>,
    pub outputs: Vec<ReceivingDataOutputs>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct ReceivingDataOutputs {
    pub pub_key: String,
    pub priv_key_tweak: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_priv_keys: Vec<(String, bool)>,
    pub recipients: Vec<(String, f32)>,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<HashMap<String, f32>>,
}

#[derive(Debug)]
pub struct ComparableHashMap {
    pub inner: HashMap<String, f32>,
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
            other
                .inner
                .get(key)
                .map_or(false, |other_val| (val - other_val).abs() < 0.0001)
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

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}
