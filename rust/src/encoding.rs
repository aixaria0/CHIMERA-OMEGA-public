use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_BYTES: usize = 1_048_576;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded JSON with unique keys and safe unsigned integers")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                if v > MAX_INTEGER {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                if v.len() > 4096 {
                    return Err(E::custom("string exceeds 4096 bytes"));
                }
                Ok(Strict(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut result = Vec::new();
                while let Some(value) = seq.next_element::<Strict>()? {
                    result.push(value.0);
                }
                Ok(Strict(Value::Array(result)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut result = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !key.is_ascii() || key.len() > 128 {
                        return Err(de::Error::custom("invalid object key"));
                    }
                    if result.contains_key(&key) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    result.insert(key, map.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(result)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

pub fn parse(input: &[u8]) -> Result<Value, String> {
    if input.len() > MAX_BYTES {
        return Err("package exceeds 1 MiB".into());
    }
    // Bound depth before recursive parsing, including for syntactically invalid input.
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for &byte in input {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 32 {
                        return Err("JSON depth exceeds 32".into());
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let result = Strict::deserialize(&mut deserializer).map_err(|e| e.to_string())?;
    deserializer.end().map_err(|e| e.to_string())?;
    Ok(result.0)
}

/// OMEGA's restricted encoding profile; deliberately not a full RFC 8785 implementation.
pub fn canonical_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) => v
            .as_u64()
            .filter(|n| *n <= MAX_INTEGER)
            .map(|n| n.to_string())
            .ok_or_else(|| "unsupported number".into()),
        Value::String(v) => serde_json::to_string(v).map_err(|e| e.to_string()),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            let mut pairs = Vec::new();
            for key in keys {
                if !key.is_ascii() {
                    return Err("non-ASCII object key".into());
                }
                pairs.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|e| e.to_string())?,
                    canonical_json(&values[key])?
                ));
            }
            Ok(format!("{{{}}}", pairs.join(",")))
        }
    }
}

pub fn digest(domain: &str, value: &Value) -> Result<String, String> {
    if domain.contains('\0') {
        return Err("NUL in hash domain".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"CHIMERA-OMEGA\0");
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(canonical_json(value)?.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
