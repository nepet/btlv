use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde_json::{Map, Value};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    process,
};

/// btlv - decode and encode Lightnin Network TLV-streams
#[derive(Parser, Debug)]
#[command(version, author = "Peter Neuroth <pet.v.ne@gmail.com>")]
#[command(about = "btlv decodes and encodes Lightnin Network TLV-streams")]
#[command(arg_required_else_help = true)]
#[command(
    help_template = "{before-help}{name} {version}\n{author-with-newline}\n{about-with-newline}\n{usage-heading}\n  {usage}\n\n{all-args}{after-help}"
)]
struct Btlv {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Encode JSON to TLV hex stream
    Encode(CommonArgs),
    /// Decode TLV hex stream to JSON
    Decode(CommonArgs),
}

#[derive(Parser, Debug, Clone)]
struct CommonArgs {
    /// Input data, file path, or '-' for stdin. If not provided, reads from stdin if available.
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    /// Output file path or '-' for stdout (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    output: Option<String>,

    /// Read input from file.
    #[arg(short, long)]
    file: bool,
}

struct TlvRecord {
    type_: u64,
    length: u64,
    value: Vec<u8>,
}

fn main() {
    let app = Btlv::parse();

    if let Err(e) = run(&app) {
        eprintln!("Error: {e}");
        if app.verbose {
            // Print the full chain of causes
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("  Caused by: {}", err);
                source = err.source();
            }
        }
        process::exit(1);
    }
}

fn run(app: &Btlv) -> Result<()> {
    match &app.command {
        Commands::Encode(args) => {
            let input = read_input(&args)?;
            let output = encode_json_to_tlv(&input)?;
            write_output(&args, &output)?;
        }
        Commands::Decode(args) => {
            let input = read_input(&args)?;
            let output = decode_tlv_to_json(&input.trim())?;
            write_output(&args, &output)?;
        }
    };

    Ok(())
}

fn read_input(args: &CommonArgs) -> Result<String> {
    match &args.input {
        Some(path) if path == "-" => read_stdin(),
        Some(input) => {
            if args.file {
                fs::read_to_string(input).with_context(|| format!("Failed to read file: {}", input))
            } else {
                Ok(input.clone())
            }
        }
        None => {
            if io::stdin().is_terminal() {
                return Err(anyhow!(
                    "No input provided. Please provide input as an argument, pipe data to stdin, or use '-' to read from stdin."
                ));
            }
            read_stdin()
        }
    }
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("Failed to read from stdin")?;

    if buffer.is_empty() {
        return Err(anyhow!("No input provided"));
    }

    Ok(buffer)
}

fn write_output(args: &CommonArgs, content: &str) -> Result<()> {
    match &args.output {
        // No output file specified - write to stdout
        None => {
            println!("{}", content);
            io::stdout().flush().context("Failed to flush stdout")?;
        }

        // Expicit stdout
        Some(path) if path == "-" => {
            println!("{}", content);
            io::stdout().flush().context("Failed to flush stdout")?;
        }

        // Write to file
        Some(path) => {
            fs::write(path, content)
                .with_context(|| format!("Failed to write to file: {}", path))?;
        }
    }

    Ok(())
}

fn encode_json_to_tlv(json_str: &str) -> Result<String> {
    let value: Value = serde_json::from_str(json_str).context("Failed to parse JSON input")?;
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
    let bytes = hex::decode(hex_str).context("Invalid hex string")?;
    let records = parse_tlv_stream(&bytes).context("Invalid TLV stream")?;

    let mut map = Map::new();
    for record in records {
        let value = decode_value(&record.value);
        map.insert(record.type_.to_string(), value);
    }

    let json = Value::Object(map);
    Ok(serde_json::to_string_pretty(&json).context("Failed to serialize JSON")?)
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

fn decode_value(bytes: &[u8]) -> Value {
    // Try to decode as UTF-8 string
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.chars()
            .all(|c| !c.is_ascii_control() || c.is_ascii_whitespace())
        {
            return Value::String(s.to_string());
        }
    }

    // Fall back to hex
    Value::String(format!("{}", hex::encode(bytes)))
}

fn parse_tlv_stream(bytes: &[u8]) -> Result<Vec<TlvRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let (type_, type_len) =
            decode_bigsize(&bytes[offset..]).context("Failed to decode type from bigsize")?;
        offset += type_len;

        let (length, length_len) =
            decode_bigsize(&bytes[offset..]).context("Failed to decode length from bigsize")?;
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
