use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TlvError {
    #[error("duplicate tlv type {0}")]
    DuplicateType(u64),
    #[error("tlv types are not strictly increasing")]
    NotSorted,
    #[error("length mismatch type {0}: expected {1}, got {2}")]
    LengthMismatch(u64, usize, usize),
    #[error("truncated input")]
    Truncated,
    #[error("non-canonical bigsize encoding")]
    NonCanonicalBigSize,
    #[error("trailing bytes after parsing")]
    TrailingBytes,
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("length overflow")]
    Overflow,
    #[error("tu64 is not minimal, got a leading zero")]
    LeadingZero,
    #[error("failed to parse bytes to u64")]
    BytesToU64,
    #[error("missing required tlv type {0}")]
    MissingRequired(u64),
    #[error("invalid length for tlv type {type_}: expected {expected}, got {actual}")]
    InvalidLength {
        type_: u64,
        expected: usize,
        actual: usize,
    },
}

pub type Result<T> = std::result::Result<T, TlvError>;
