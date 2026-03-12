//! BOLT #1 specification test vectors.
//!
//! Test data lives in `tests/vectors/*.json` and is loaded at test time.
//! https://github.com/lightning/bolts/blob/master/01-messaging.md

use btlv::_macro_support::{bigsize, encoding};
use btlv::TlvStream;
use serde::Deserialize;
use std::fs;

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BigSizeVectors {
    valid: Vec<BigSizeValid>,
    invalid: Vec<BigSizeInvalid>,
}

#[derive(Deserialize)]
struct BigSizeValid {
    name: String,
    value: u64,
    hex: String,
}

#[derive(Deserialize)]
struct BigSizeInvalid {
    name: String,
    hex: String,
    error: String,
}

#[derive(Deserialize)]
struct Tu64Vectors {
    valid: Vec<Tu64Valid>,
    invalid_leading_zero: Vec<Tu64Invalid>,
    invalid_overflow: Vec<Tu64Invalid>,
}

#[derive(Deserialize)]
struct Tu64Valid {
    name: String,
    value: u64,
    hex: String,
}

#[derive(Deserialize)]
struct Tu64Invalid {
    name: String,
    hex: String,
}

#[derive(Deserialize)]
struct TlvStreamVectors {
    valid: Vec<TlvValid>,
    invalid: Vec<TlvInvalid>,
}

#[derive(Deserialize)]
struct TlvValid {
    name: String,
    hex: String,
    records: Vec<TlvRecordExpected>,
}

#[derive(Deserialize)]
struct TlvRecordExpected {
    #[serde(rename = "type")]
    type_: u64,
    value: String,
}

#[derive(Deserialize)]
struct TlvInvalid {
    name: String,
    hex: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load<T: serde::de::DeserializeOwned>(filename: &str) -> T {
    let path = format!("{}/tests/vectors/{}", env!("CARGO_MANIFEST_DIR"), filename);
    let data = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

// ---------------------------------------------------------------------------
// BigSize
// ---------------------------------------------------------------------------

#[test]
fn bolt_bigsize_encode() {
    let vectors: BigSizeVectors = load("bigsize.json");
    for v in &vectors.valid {
        let encoded = hex::encode(bigsize::encode(v.value));
        assert_eq!(encoded, v.hex, "encode failed: {}", v.name);
    }
}

#[test]
fn bolt_bigsize_decode_valid() {
    let vectors: BigSizeVectors = load("bigsize.json");
    for v in &vectors.valid {
        let bytes = hex_to_bytes(&v.hex);
        let (decoded, consumed) = bigsize::decode(&bytes).unwrap_or_else(|e| {
            panic!("decode failed for '{}': {e}", v.name)
        });
        assert_eq!(decoded, v.value, "value mismatch: {}", v.name);
        assert_eq!(consumed, bytes.len(), "consumed mismatch: {}", v.name);
    }
}

#[test]
fn bolt_bigsize_decode_invalid() {
    let vectors: BigSizeVectors = load("bigsize.json");
    for v in &vectors.invalid {
        let bytes = hex_to_bytes(&v.hex);
        let result = bigsize::decode(&bytes);
        assert!(result.is_err(), "should fail: {}", v.name);

        let err = format!("{}", result.unwrap_err());
        let expected_substr = match v.error.as_str() {
            "non_canonical" => "non-canonical",
            "truncated" => "truncated",
            other => panic!("unknown error class '{other}' in {}", v.name),
        };
        assert!(
            err.contains(expected_substr),
            "'{}': expected '{}' in error, got: {}",
            v.name,
            expected_substr,
            err,
        );
    }
}

// ---------------------------------------------------------------------------
// tu64
// ---------------------------------------------------------------------------

#[test]
fn bolt_tu64_encode_decode_valid() {
    let vectors: Tu64Vectors = load("tu64.json");
    for v in &vectors.valid {
        let expected_bytes = hex_to_bytes(&v.hex);

        let encoded = encoding::encode_tu64(v.value);
        assert_eq!(encoded, expected_bytes, "encode failed: {}", v.name);

        let decoded = encoding::decode_tu64(&expected_bytes)
            .unwrap_or_else(|e| panic!("decode failed for '{}': {e}", v.name));
        assert_eq!(decoded, v.value, "decode value mismatch: {}", v.name);
    }
}

#[test]
fn bolt_tu64_reject_leading_zero() {
    let vectors: Tu64Vectors = load("tu64.json");
    for v in &vectors.invalid_leading_zero {
        let bytes = hex_to_bytes(&v.hex);
        assert!(
            encoding::decode_tu64(&bytes).is_err(),
            "should reject leading zero: {}",
            v.name,
        );
    }
}

#[test]
fn bolt_tu64_reject_overflow() {
    let vectors: Tu64Vectors = load("tu64.json");
    for v in &vectors.invalid_overflow {
        let bytes = hex_to_bytes(&v.hex);
        assert!(
            encoding::decode_tu64(&bytes).is_err(),
            "should reject overflow: {}",
            v.name,
        );
    }
}

// ---------------------------------------------------------------------------
// TLV stream
// ---------------------------------------------------------------------------

#[test]
fn bolt_tlv_stream_decode_valid() {
    let vectors: TlvStreamVectors = load("tlv_stream.json");
    for v in &vectors.valid {
        let bytes = hex_to_bytes(&v.hex);
        let stream = TlvStream::from_bytes(&bytes).unwrap_or_else(|e| {
            panic!("decode failed for '{}': {e}", v.name)
        });

        assert_eq!(
            stream.len(),
            v.records.len(),
            "'{}': record count mismatch",
            v.name,
        );

        let recs: Vec<_> = stream.iter().collect();
        for (i, expected) in v.records.iter().enumerate() {
            assert_eq!(
                recs[i].type_, expected.type_,
                "'{}' record {i}: type mismatch",
                v.name,
            );
            assert_eq!(
                hex::encode(&recs[i].value),
                expected.value,
                "'{}' record {i}: value mismatch",
                v.name,
            );
        }
    }
}

#[test]
fn bolt_tlv_stream_decode_valid_roundtrip() {
    let vectors: TlvStreamVectors = load("tlv_stream.json");
    for v in &vectors.valid {
        let bytes = hex_to_bytes(&v.hex);
        let stream = TlvStream::from_bytes(&bytes).unwrap();
        let reencoded = stream.to_bytes().unwrap();
        assert_eq!(
            hex::encode(&reencoded),
            v.hex,
            "'{}': roundtrip mismatch",
            v.name,
        );
    }
}

#[test]
fn bolt_tlv_stream_decode_invalid() {
    let vectors: TlvStreamVectors = load("tlv_stream.json");
    for v in &vectors.invalid {
        let bytes = hex_to_bytes(&v.hex);
        assert!(
            TlvStream::from_bytes(&bytes).is_err(),
            "should fail: {}",
            v.name,
        );
    }
}
