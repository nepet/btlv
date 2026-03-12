use crate::error::{Result, TlvError};

/// Encode a value as a BOLT #1 BigSize.
pub fn encode(x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if x < 0xfd {
        out.push(x as u8);
    } else if x <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(x as u16).to_be_bytes());
    } else if x <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(x as u32).to_be_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&x.to_be_bytes());
    }
    out
}

/// Decode a BOLT #1 BigSize from the front of `input`.
/// Returns `(value, bytes_consumed)`.
pub fn decode(input: &[u8]) -> Result<(u64, usize)> {
    if input.is_empty() {
        return Err(TlvError::Truncated);
    }
    match input[0] {
        n @ 0x00..=0xfc => Ok((n as u64, 1)),
        0xfd => {
            if input.len() < 3 {
                return Err(TlvError::Truncated);
            }
            let v = u16::from_be_bytes([input[1], input[2]]) as u64;
            if v < 0xfd {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((v, 3))
        }
        0xfe => {
            if input.len() < 5 {
                return Err(TlvError::Truncated);
            }
            let v = u32::from_be_bytes([input[1], input[2], input[3], input[4]]) as u64;
            if v <= 0xffff {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((v, 5))
        }
        0xff => {
            if input.len() < 9 {
                return Err(TlvError::Truncated);
            }
            let v = u64::from_be_bytes([
                input[1], input[2], input[3], input[4], input[5], input[6], input[7], input[8],
            ]);
            if v <= 0xffff_ffff {
                return Err(TlvError::NonCanonicalBigSize);
            }
            Ok((v, 9))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0u64, 1, 252, 253, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            let enc = encode(v);
            let (dec, consumed) = decode(&enc).unwrap();
            assert_eq!(dec, v);
            assert_eq!(consumed, enc.len());
        }
    }
}
