use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde_json::{Map, Value};

/// Main args of tlv-tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Tool {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Encodes TLV-stream into hex.
    Encode {
        /// Json encoded data to encode into hex TLV-stream.
        data: String,
    },
    /// Decodes TLV-stream from hex.
    Decode {
        /// Hex-encoded String.
        data: String,
    },
}

struct TlvRecord {
    type_: u64,
    length: u64,
    value: Vec<u8>,
}

fn main() {
    let tool = Tool::parse();

    let r = match tool.command {
        Commands::Encode { data } => encode_json_to_tlv(&data),
        Commands::Decode { data } => decode_tlv_to_json(&data),
    };

    match r {
        Ok(s) => {
            println!("{}", s)
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn encode_json_to_tlv(json_str: &str) -> Result<String> {
    let value: Value = serde_json::from_str(json_str)?;
    let mut tlv_bytes = Vec::new();

    match value {
        Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.parse::<u64>().unwrap_or(0));

            for (type_str, value) in sorted {
                let type_num: u64 = type_str
                    .parse()
                    .context(format!("Invalid type key {}", type_str))?;

                let value_bytes = encode_value(value)?;
                let record = TlvRecord {
                    type_: type_num,
                    length: value_bytes.len() as u64,
                    value: value_bytes,
                };

                encode_tlv_record(&record, &mut tlv_bytes);
            }
        }
        _ => {
            return Err(anyhow!("JSON must be an object"));
        }
    }

    Ok(hex::encode(tlv_bytes))
}

fn decode_tlv_to_json(hex_str: &str) -> Result<String> {
    let bytes = hex::decode(hex_str)?;
    let records = parse_tlv_stream(&bytes)?;

    let mut map = Map::new();
    for record in records {
        let value = decode_value(&record.value)?;
        map.insert(record.type_.to_string(), value);
    }

    let json = Value::Object(map);
    Ok(serde_json::to_string_pretty(&json)?)
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::String(s) => {
            // Try hex encoding first
            let hex_str = s.strip_prefix("0x").unwrap_or(s);
            if hex_str.len() % 2 == 0
                && !hex_str.is_empty()
                && hex_str.chars().all(|c| c.is_ascii_hexdigit())
            {
                if let Ok(bytes) = hex::decode(hex_str) {
                    return Ok(bytes);
                }
            }

            // Fall back to UTF-8
            Ok(s.as_bytes().to_vec())
        }
        _ => Err(anyhow!("Unsupported value type, only string is allowed")),
    }
}

fn decode_value(bytes: &[u8]) -> Result<Value> {
    // Try to decode as UTF-8 string
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.chars()
            .all(|c| !c.is_ascii_control() || c.is_ascii_whitespace())
        {
            return Ok(Value::String(s.to_string()));
        }
    }

    // Fall back to hex
    Ok(Value::String(format!("{}", hex::encode(bytes))))
}

fn parse_tlv_stream(bytes: &[u8]) -> Result<Vec<TlvRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let (type_, type_len) = decode_bigsize(&bytes[offset..])?;
        offset += type_len;

        let (length, length_len) = decode_bigsize(&bytes[offset..])?;
        offset += length_len;

        if offset + length as usize > bytes.len() {
            return Err(anyhow!("Invalid TLV: length exceeds remaining bytes"));
        }

        let value = bytes[offset..offset + length as usize].to_vec();
        offset += length as usize;

        records.push(TlvRecord {
            type_,
            length,
            value,
        })
    }

    Ok(records)
}

fn encode_tlv_record(record: &TlvRecord, output: &mut Vec<u8>) {
    output.extend_from_slice(&encode_bigsize(record.type_));
    output.extend_from_slice(&encode_bigsize(record.length));
    output.extend_from_slice(&record.value);
}

fn encode_bigsize(value: u64) -> Vec<u8> {
    match value {
        value if value < 0xfd => {
            vec![value as u8]
        }
        value if value < 0x10000 => {
            let mut bytes = Vec::with_capacity(3);
            bytes.push(0xfd);
            bytes.extend_from_slice(&(value as u16).to_be_bytes());
            bytes
        }
        value if value < 0x100000000 => {
            let mut bytes = Vec::with_capacity(5);
            bytes.push(0xfe);
            bytes.extend_from_slice(&(value as u32).to_be_bytes());
            bytes
        }
        _ => {
            let mut bytes = Vec::with_capacity(9);
            bytes.push(0xff);
            bytes.extend_from_slice(&value.to_be_bytes());
            bytes
        }
    }
}

fn decode_bigsize(bytes: &[u8]) -> Result<(u64, usize)> {
    if bytes.is_empty() {
        return Err(anyhow!("Empty bytes for bigsize"));
    }

    match bytes[0] {
        0..=0xfc => Ok((bytes[0] as u64, 1)),
        0xfd => {
            if bytes.len() < 3 {
                return Err(anyhow!("Insufficient bytes for bigsize fd"));
            }
            let value = u16::from_be_bytes([bytes[1], bytes[2]]) as u64;
            if value < 0xfd {
                return Err(anyhow!("Non-canonical bigsize encoding"));
            }
            Ok((value, 3))
        }
        0xfe => {
            if bytes.len() < 5 {
                return Err(anyhow!("Insufficient bytes for bigsize fe"));
            }
            let value = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            if value < 0x10000 {
                return Err(anyhow!("Non-canonical bigsize encoding"));
            }
            Ok((value, 5))
        }
        0xff => {
            if bytes.len() < 9 {
                return Err(anyhow!("Insufficient bytes for bigsize ff"));
            }
            let value = u64::from_be_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
            ]);
            if value < 0x100000000 {
                return Err(anyhow!("Non-canonical bigsize encoding"));
            }
            Ok((value, 9))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bigsize_encoding_spec_vectors() {
        // Test vectors from BOLT01 specification
        let test_cases: [(u64, &str); 8] = [
            (0, "00"),
            (252, "fc"),
            (253, "fd00fd"),
            (65535, "fdffff"),
            (65536, "fe00010000"),
            (4294967295, "feffffffff"),
            (4294967296, "ff0000000100000000"),
            (18446744073709551615, "ffffffffffffffffff"),
        ];

        for (value, expected_hex) in test_cases {
            let encoded = encode_bigsize(value);
            let actual_hex = hex::encode(encoded);
            assert_eq!(actual_hex, expected_hex, "Failed encoding {}", value);
        }
    }

    #[test]
    fn test_bigsize_decoding_spec_vectors() {
        // Test vectors from BOLT01 specification
        let test_cases: [(u64, &str); 8] = [
            (0, "00"),
            (252, "fc"),
            (253, "fd00fd"),
            (65535, "fdffff"),
            (65536, "fe00010000"),
            (4294967295, "feffffffff"),
            (4294967296, "ff0000000100000000"),
            (18446744073709551615, "ffffffffffffffffff"),
        ];

        for (expected, value) in test_cases {
            let bytes = hex::decode(value).unwrap();
            let (decoded, _) = decode_bigsize(&bytes).unwrap();
            assert_eq!(decoded, expected, "Failed decoding {}", value);
        }
    }

    #[test]
    fn test_bigsize_decoding_spec_errors() {
        // All error cases from BOLT specification test vectors
        let error_test_cases = [
            // Non-cannonical encodings
            ("fd00fc", "canonical"),             // two byte not canonical
            ("fe0000ffff", "canonical"),         // four byte not canonical
            ("ff00000000ffffffff", "canonical"), // eight byte not canonical
            // Short reads
            ("fd00", "insufficient"),       // two byte short read
            ("feffff", "insufficient"),     // four byte short read
            ("ffffffffff", "insufficient"), // eight byte short read
            // No reads
            ("", "empty"),          // one byte no read
            ("fd", "insufficient"), // two byte no read
            ("fe", "insufficient"), // four byte no read
            ("ff", "insufficient"), // eight byte no read
        ];

        for (value, expected_keyword) in error_test_cases {
            let bytes = if value.is_empty() {
                vec![]
            } else {
                hex::decode(value).unwrap()
            };
            let result = decode_bigsize(&bytes);
            assert!(
                result.is_err(),
                "Test {} should have failed, but succeded",
                value
            );
            let err_msg = result.unwrap_err().to_string().to_lowercase();
            assert!(
                err_msg.contains(expected_keyword),
                "Expected error message {} to contain {}",
                err_msg,
                expected_keyword
            )
        }
    }

    #[test]
    fn test_tlv_roundtrip() {
        let json = r#"{
            "0": "0",
            "252": "hello world",
            "65553": "02ffffff"
        }"#;

        let hex = encode_json_to_tlv(json).unwrap();
        let decoded = decode_tlv_to_json(&hex).unwrap();

        let round_trip: Value = serde_json::from_str(&decoded).unwrap();
        let obj = round_trip.as_object().unwrap();

        assert_eq!(obj["0"], "0");
        assert_eq!(obj["252"], "hello world");
        assert_eq!(obj["65553"], "02ffffff");
    }
}
