use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde_json::{Value, from_str};

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

fn main() {
    let tool = Tool::parse();

    match tool.command {
        Commands::Encode { data } => println!("encode {data}"),
        Commands::Decode { data } => println!("decode {data}"),
    }
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

fn decode_bigsize(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Err(anyhow!("Empty bytes for bigsize"));
    }

    match bytes[0] {
        0..=0xfc => Ok(bytes[0] as u64),
        0xfd => {
            if bytes.len() < 3 {
                return Err(anyhow!("Insufficient bytes for bigsize fd"));
            }
            let value = u16::from_be_bytes([bytes[1], bytes[2]]) as u64;
            if value < 0xfd {
                return Err(anyhow!("Non-canonical bigsize encoding"));
            }
            Ok(value)
        }
        0xfe => {
            if bytes.len() < 5 {
                return Err(anyhow!("Insufficient bytes for bigsize fe"));
            }
            let value = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            if value < 0x10000 {
                return Err(anyhow!("Non-canonical bigsize encoding"));
            }
            Ok(value)
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
            Ok(value)
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
            let decoded = decode_bigsize(&bytes).unwrap();
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
}
