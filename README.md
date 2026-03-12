# btlv

[![Crates.io](https://img.shields.io/crates/v/btlv.svg)](https://crates.io/crates/btlv)
[![Documentation](https://docs.rs/btlv/badge.svg)](https://docs.rs/btlv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust library for encoding and decoding Lightning Network TLV (Type-Length-Value) streams, compliant with [BOLT #1](https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format).

## Features

- **BOLT-compliant** bigsize and TLV encoding with canonical-form validation
- **`TlvStream`** container with sorted, deduplicated records and typed accessors
- **`tlv_struct!`** macro for declarative struct-to-TLV mapping
- **`tu64`** truncated unsigned integer encoding/decoding
- **Serde support** (feature-gated) — serialize/deserialize `TlvStream` as hex strings
- **Spec test vectors** from BOLT #1 appendices A and B

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
btlv = "0.1"
```

Serde support is enabled by default. To disable it:

```toml
[dependencies]
btlv = { version = "0.1", default-features = false }
```

With serde enabled, `tlv_struct!` structs are directly serializable (they delegate to `TlvStream`'s hex-string encoding):

```rust
let payload = OnionPayload {
    amt_to_forward: 1000,
    outgoing_cltv_value: 800_000,
    short_channel_id: None,
};

let json = serde_json::to_string(&payload).unwrap();
let decoded: OnionPayload = serde_json::from_str(&json).unwrap();
```

## Usage

### Working with TlvStream directly

```rust
use btlv::TlvStream;

// Build a stream
let mut stream = TlvStream::default();
stream.set_tu64(2, 1000);       // tu64-encoded amount
stream.set_tu64(4, 800_000);    // tu64-encoded CLTV
stream.insert(6, vec![0x00, 0x73, 0x00, 0x0f, 0x2c, 0x00, 0x07, 0x00]);

// Serialize to wire format
let bytes = stream.to_bytes().unwrap();

// Parse back
let decoded = TlvStream::from_bytes(&bytes).unwrap();
assert_eq!(decoded.get_tu64(2).unwrap(), Some(1000));
```

### Declarative struct mapping with `tlv_struct!`

```rust
btlv::tlv_struct! {
    pub struct OnionPayload {
        #[tlv(2, tu64)]
        pub amt_to_forward: u64,
        #[tlv(4, tu64)]
        pub outgoing_cltv_value: u32,
        #[tlv(6, bytes)]
        pub short_channel_id: Option<[u8; 8]>,
    }
}

let payload = OnionPayload {
    amt_to_forward: 1000,
    outgoing_cltv_value: 800_000,
    short_channel_id: None,
};

// Serialize to TLV bytes and back
let bytes = payload.to_tlv_bytes().unwrap();
let decoded = OnionPayload::from_tlv_bytes(&bytes).unwrap();
assert_eq!(decoded.amt_to_forward, 1000);
```

The macro supports three encoding tags:

| Tag | Wire format | Rust types |
|-------|------------------------------------------|-------------------------------|
| `tu64` | Variable-length minimal big-endian int | `u64`, `u32` |
| `u64` | Fixed 8-byte big-endian | `u64` |
| `bytes` | Raw bytes | `Vec<u8>`, `[u8; N]` |

Fields wrapped in `Option<T>` are automatically optional — omitted when `None`, decoded as `None` when absent.

## Core types

| Type | Description |
|------------|----------------------------------------------------------------------|
| `TlvStream` | Sorted, deduplicated record container with typed get/set accessors |
| `TlvRecord` | A single type-value pair |
| `TlvError` | Error enum covering duplicate types, ordering, truncation, overflow |

### Bigsize encoding

Implements the BOLT #1 variable-length integer format:

| Value range | Wire encoding |
|------------------------------|-------------------|
| `0` to `252` | 1 byte |
| `253` to `65535` | `0xfd` + 2 bytes |
| `65536` to `4294967295` | `0xfe` + 4 bytes |
| `4294967296` to `2^64 - 1` | `0xff` + 8 bytes |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

```bash
cargo test
```

The test suite includes BOLT #1 specification test vectors for bigsize, tu64, and TLV stream encoding.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
