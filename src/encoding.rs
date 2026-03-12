use crate::error::{Result, TlvError};

/// Encode a BOLT #1 `tu64`: big-endian, minimal length (no leading 0x00).
/// Value 0 is encoded as zero-length.
pub fn encode_tu64(v: u64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap(); // safe: v != 0
    bytes[first..].to_vec()
}

/// Decode a BOLT #1 `tu64`, enforcing minimal form.
/// Empty slice -> 0. Leading 0x00 or >8 bytes is invalid.
pub fn decode_tu64(raw: &[u8]) -> Result<u64> {
    if raw.is_empty() {
        return Ok(0);
    }
    if raw.len() > 8 {
        return Err(TlvError::Overflow);
    }
    if raw[0] == 0 {
        return Err(TlvError::LeadingZero);
    }
    let mut buf = [0u8; 8];
    buf[8 - raw.len()..].copy_from_slice(raw);
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tu64_zero_is_empty() {
        assert!(encode_tu64(0).is_empty());
        assert_eq!(decode_tu64(&[]).unwrap(), 0);
    }

    #[test]
    fn tu64_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 256, 65535, 0xffffff, u64::MAX] {
            let enc = encode_tu64(v);
            let dec = decode_tu64(&enc).unwrap();
            assert_eq!(dec, v, "roundtrip failed for {}", v);
        }
    }

    #[test]
    fn tu64_minimal_encoding() {
        // 256 = 0x0100, should be 2 bytes not 8
        let enc = encode_tu64(256);
        assert_eq!(enc, vec![0x01, 0x00]);
    }

    #[test]
    fn tu64_rejects_leading_zero() {
        assert!(decode_tu64(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn tu64_rejects_too_long() {
        assert!(decode_tu64(&[1; 9]).is_err());
    }

}
