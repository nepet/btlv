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
}
