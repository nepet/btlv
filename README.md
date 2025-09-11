# btlv

[![Crates.io](https://img.shields.io/crates/v/btlv.svg)](https://crates.io/crates/btlv)
[![Documentation](https://docs.rs/btlv/badge.svg)](https://docs.rs/btlv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast and reliable command-line tool for encoding and decoding Lightning Network TLV (Type-Length-Value) streams.

## What is TLV?

TLV (Type-Length-Value) is a data encoding format used extensively in the Lightning Network protocol. Each record consists of:
- **Type**: A `bigsize` encoded identifier
- **Length**: A `bigsize` encoded length of the value
- **Value**: The actual data bytes

This tool implements the TLV specification from [BOLT #1](https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format) including proper `bigsize` encoding/decoding.

## Features

- ✅ **BOLT-compliant**: Implements Lightning Network TLV specification exactly
- ✅ **Bidirectional**: Encode JSON to TLV hex streams and decode back
- ✅ **Flexible I/O**: Read from files, stdin, or command arguments
- ✅ **Smart value handling**: Automatic detection of hex strings vs UTF-8 text
- ✅ **Robust error handling**: Detailed error messages with optional verbose output

## Installation

### From crates.io

```bash
cargo install btlv
```

### From source

```bash
git clone https://github.com/yourusername/btlv.git
cd btlv
cargo install --path .
```

## Usage

### Basic Commands

```bash
# Encode JSON to TLV hex
btlv encode '{"0": "hello", "1": "0x48656c6c6f"}'

# Decode TLV hex to JSON
btlv decode "000568656c6c6f01054865c6c6c6f"

# Use files
btlv encode -f input.json -o output.hex
btlv decode -f tlv_data.hex -o decoded.json
```

### Input/Output Options

```bash
# Read from stdin
echo '{"252": "hello world"}' | btlv encode

# Write to file
btlv encode '{"0": "test"}' -o output.hex

# Read from file
btlv encode input.json --file

# Explicit stdin/stdout
btlv decode - < data.hex
btlv encode data.json -o -
```

### Examples

#### Encoding JSON to TLV

```bash
$ btlv encode '{"0": "hello", "252": "world", "65536": "0xdeadbeef"}'
000568656c6c6f016c776f726c64fe00010000048deadbeef
```

#### Decoding TLV to JSON

```bash
$ btlv decode "fc0568656c6c6f"
{
  "252": "hello"
}
```

#### Working with Files

```bash
# Create a JSON file
echo '{"1": "Lightning", "1000": "Network"}' > message.json

# Encode to TLV
btlv encode message.json --file -o message.tlv

# Decode back
btlv decode message.tlv --file
```

### Value Handling

The tool intelligently handles different value types:

- **Hex strings**: Strings starting with `0x` or valid hex are encoded as bytes
- **UTF-8 text**: Regular strings are encoded as UTF-8 bytes
- **Auto-detection**: On decode, tries UTF-8 first, falls back to hex display

```bash
# These produce the same TLV output:
btlv encode '{"0": "0x48656c6c6f"}'  # Hex input
btlv encode '{"0": "Hello"}'         # UTF-8 input (if "Hello" = 0x48656c6c6f)
```

### Error Handling

Use `--verbose` for detailed error information:

```bash
$ btlv decode "invalid_hex" --verbose
Error: Invalid hex string
  Caused by: Odd number of digits
```

## JSON Format

Input JSON must be an object where:
- **Keys**: String representations of type numbers (`"0"`, `"252"`, `"65536"`)
- **Values**: Strings containing either UTF-8 text or hex data

```json
{
  "0": "hello world",
  "1": "0xdeadbeef",
  "252": "Lightning Network",
  "65535": "0x012345"
}
```

## Lightning Network Context

This tool is useful for:
- **Debugging Lightning messages**: Inspect TLV fields in BOLT messages
- **Protocol development**: Test TLV encoding/decoding
- **Data analysis**: Convert between human-readable JSON and wire format
- **Learning**: Understand how Lightning Network encodes data

## Technical Details

### Bigsize Encoding

Implements the Lightning Network `bigsize` variable-length integer encoding:

| Value Range | Encoding |
|-------------|----------|
| `0` to `252` | 1 byte |
| `253` to `65535` | `0xfd` + 2 bytes |
| `65536` to `4294967295` | `0xfe` + 4 bytes |
| `4294967296` to `18446744073709551615` | `0xff` + 8 bytes |

### TLV Record Structure

```
[type: bigsize][length: bigsize][value: length bytes]
```

Records are concatenated in ascending type order.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

### Running Tests

```bash
cargo test
```

The test suite includes official BOLT specification test vectors for bigsize encoding.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
