use std::convert::TryFrom;

use crate::bigsize;
use crate::encoding::{decode_tu64, encode_tu64};
use crate::error::{Result, TlvError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlvRecord {
    pub type_: u64,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlvStream(pub Vec<TlvRecord>);

impl TlvStream {
    /// Serialize the stream to wire-format bytes.
    ///
    /// Records must already be in sorted order (maintained by `insert`).
    /// Returns an error if duplicates are found.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        for w in self.0.windows(2) {
            if w[0].type_ == w[1].type_ {
                return Err(TlvError::DuplicateType(w[0].type_));
            }
            if w[0].type_ > w[1].type_ {
                return Err(TlvError::NotSorted);
            }
        }
        let mut out = Vec::new();
        for rec in &self.0 {
            out.extend(bigsize::encode(rec.type_));
            out.extend(bigsize::encode(rec.value.len() as u64));
            out.extend(&rec.value);
        }
        Ok(out)
    }

    /// Parse a TLV stream from raw bytes.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self> {
        let mut recs = Vec::new();
        let mut last_type: Option<u64> = None;

        while !bytes.is_empty() {
            let (t, n1) = bigsize::decode(bytes)?;
            bytes = &bytes[n1..];
            let (len, n2) = bigsize::decode(bytes)?;
            bytes = &bytes[n2..];

            let l = usize::try_from(len).map_err(|_| TlvError::Overflow)?;
            if bytes.len() < l {
                return Err(TlvError::Truncated);
            }
            let v = bytes[..l].to_vec();
            bytes = &bytes[l..];

            if let Some(prev) = last_type {
                if t == prev {
                    return Err(TlvError::DuplicateType(t));
                }
                if t < prev {
                    return Err(TlvError::NotSorted);
                }
            }
            last_type = Some(t);
            recs.push(TlvRecord { type_: t, value: v });
        }
        Ok(TlvStream(recs))
    }

    /// Parse a TLV stream that is prefixed with a BigSize length.
    pub fn from_bytes_with_length_prefix(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(TlvError::Truncated);
        }

        let (length, length_bytes) = bigsize::decode(bytes)?;
        let remaining = &bytes[length_bytes..];

        let length_usize = usize::try_from(length).map_err(|_| TlvError::Overflow)?;

        if remaining.len() != length_usize {
            return Err(TlvError::LengthMismatch(0, length_usize, remaining.len()));
        }

        Self::from_bytes(remaining)
    }

    /// Auto-detect whether input has a length prefix, trying prefixed first.
    pub fn from_bytes_auto(bytes: &[u8]) -> Result<Self> {
        if let Ok(stream) = Self::from_bytes_with_length_prefix(bytes) {
            return Ok(stream);
        }
        Self::from_bytes(bytes)
    }

    /// Get a reference to the value of a TLV record by type.
    pub fn get(&self, type_: u64) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|rec| rec.type_ == type_)
            .map(|rec| rec.value.as_slice())
    }

    /// Insert a TLV record (replaces if type already exists), maintaining sorted order.
    pub fn insert(&mut self, type_: u64, value: Vec<u8>) {
        if let Some(rec) = self.0.iter_mut().find(|rec| rec.type_ == type_) {
            rec.value = value;
            return;
        }
        self.0.push(TlvRecord { type_, value });
        self.0.sort_by_key(|r| r.type_);
    }

    /// Remove a record by type, returning its value if it existed.
    pub fn remove(&mut self, type_: u64) -> Option<Vec<u8>> {
        if let Some(pos) = self.0.iter().position(|rec| rec.type_ == type_) {
            Some(self.0.remove(pos).value)
        } else {
            None
        }
    }

    /// Check if a type exists.
    pub fn contains(&self, type_: u64) -> bool {
        self.0.iter().any(|rec| rec.type_ == type_)
    }

    /// Insert or override a `tu64` value for `type_`.
    pub fn set_tu64(&mut self, type_: u64, value: u64) {
        self.insert(type_, encode_tu64(value));
    }

    /// Read a `tu64` if present, validating minimal encoding.
    pub fn get_tu64(&self, type_: u64) -> Result<Option<u64>> {
        if let Some(rec) = self.0.iter().find(|r| r.type_ == type_) {
            Ok(Some(decode_tu64(&rec.value)?))
        } else {
            Ok(None)
        }
    }

    /// Insert or override a fixed `u64` (8-byte big-endian) value.
    pub fn set_u64(&mut self, type_: u64, value: u64) {
        self.insert(type_, value.to_be_bytes().to_vec());
    }

    /// Read a fixed `u64` if present.
    pub fn get_u64(&self, type_: u64) -> Result<Option<u64>> {
        if let Some(rec) = self.0.iter().find(|r| r.type_ == type_) {
            let value =
                u64::from_be_bytes(rec.value[..].try_into().map_err(|_| TlvError::BytesToU64)?);
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Iterate over records.
    pub fn iter(&self) -> impl Iterator<Item = &TlvRecord> {
        self.0.iter()
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<&[u8]> for TlvStream {
    type Error = TlvError;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        TlvStream::from_bytes(value)
    }
}

impl From<Vec<TlvRecord>> for TlvStream {
    fn from(v: Vec<TlvRecord>) -> Self {
        TlvStream(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(type_: u64, value: &[u8]) -> TlvRecord {
        TlvRecord {
            type_,
            value: value.to_vec(),
        }
    }

    fn build_bytes(type_: u64, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(bigsize::encode(type_));
        v.extend(bigsize::encode(value.len() as u64));
        v.extend(value);
        v
    }

    #[test]
    fn encode_then_decode_roundtrip() {
        let stream = TlvStream(vec![rec(1, &[0x01, 0x02]), rec(5, &[0xaa])]);
        let bytes = stream.to_bytes().unwrap();
        assert_eq!(hex::encode(&bytes), "010201020501aa");

        let decoded = TlvStream::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.0.len(), 2);
        assert_eq!(decoded.0[0].type_, 1);
        assert_eq!(decoded.0[0].value, vec![0x01, 0x02]);
        assert_eq!(decoded.0[1].type_, 5);
        assert_eq!(decoded.0[1].value, vec![0xaa]);
    }

    #[test]
    fn decode_with_len_prefix() {
        let payload = "1202039896800401760608000073000f2c0007";
        let stream =
            TlvStream::from_bytes_with_length_prefix(&hex::decode(payload).unwrap()).unwrap();
        assert!(!stream.is_empty());
    }

    #[test]
    fn bigsize_boundary_minimal_encodings() {
        let stream = TlvStream(vec![
            rec(0x00fc, &[0x11]),
            rec(0x00fd, &[0x22]),
            rec(0x0001_0000, &[0x33]),
        ]);

        let bytes = stream.to_bytes().unwrap();
        let back = TlvStream::from_bytes(&bytes).unwrap();
        assert_eq!(back.0[0].type_, 0x00fc);
        assert_eq!(back.0[1].type_, 0x00fd);
        assert_eq!(back.0[2].type_, 0x0001_0000);
    }

    #[test]
    fn decode_rejects_non_canonical_bigsize() {
        // 0xfd 00 fc encodes 0xfc but should be a single byte
        let mut bytes = Vec::new();
        bytes.extend([0xfd, 0x00, 0xfc]);
        bytes.extend([0x01]);
        bytes.extend([0x00]);
        let err = TlvStream::from_bytes(&bytes).unwrap_err();
        assert!(format!("{}", err).contains("non-canonical"));

        // 0xfe 00 00 00 ff encodes 0xff but should be 0xfd-form
        let mut bytes = Vec::new();
        bytes.extend([0xfe, 0x00, 0x00, 0x00, 0xff]);
        bytes.extend([0x01]);
        bytes.extend([0x00]);
        let err = TlvStream::from_bytes(&bytes).unwrap_err();
        assert!(format!("{}", err).contains("non-canonical"));

        // 0xff 00..01 encodes 1, which should be single byte
        let mut bytes = Vec::new();
        bytes.extend([0xff, 0, 0, 0, 0, 0, 0, 0, 1]);
        bytes.extend([0x01]);
        bytes.extend([0x00]);
        let err = TlvStream::from_bytes(&bytes).unwrap_err();
        assert!(format!("{}", err).contains("non-canonical"));
    }

    #[test]
    fn decode_rejects_out_of_order_types() {
        let mut bad = Vec::new();
        bad.extend(build_bytes(5, &[0xaa]));
        bad.extend(build_bytes(1, &[0x00]));

        let err = TlvStream::from_bytes(&bad).unwrap_err();
        assert!(
            format!("{}", err).contains("increasing") || format!("{}", err).contains("sorted"),
            "expected ordering error, got: {err}"
        );
    }

    #[test]
    fn decode_rejects_duplicate_types() {
        let mut bad = Vec::new();
        bad.extend(build_bytes(1, &[0x01]));
        bad.extend(build_bytes(1, &[0x02]));
        let err = TlvStream::from_bytes(&bad).unwrap_err();
        assert!(
            format!("{}", err).contains("duplicate"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn encode_rejects_duplicate_types() {
        let s = TlvStream(vec![rec(1, &[0x01]), rec(1, &[0x02])]);
        let err = s.to_bytes().unwrap_err();
        assert!(
            format!("{}", err).contains("duplicate"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn decode_truncated_value() {
        let mut bytes = Vec::new();
        bytes.extend(bigsize::encode(1));
        bytes.extend(bigsize::encode(2));
        bytes.push(0x00);
        let err = TlvStream::from_bytes(&bytes).unwrap_err();
        assert!(
            format!("{}", err).contains("truncated"),
            "expected truncated error, got: {err}"
        );
    }

    #[test]
    fn set_and_get_u64_basic() {
        let mut s = TlvStream::default();
        s.set_u64(42, 123456789);
        assert_eq!(s.get_u64(42).unwrap(), Some(123456789));
    }

    #[test]
    fn set_u64_overwrite_keeps_order() {
        let mut s = TlvStream(vec![rec(1, &[0xaa]), rec(10, &[0xbb])]);

        s.set_u64(5, 7);
        assert_eq!(
            s.0.iter().map(|r| r.type_).collect::<Vec<_>>(),
            vec![1, 5, 10]
        );
        assert_eq!(s.get_u64(5).unwrap(), Some(7));

        s.set_u64(5, 9);
        let types: Vec<u64> = s.0.iter().map(|r| r.type_).collect();
        assert_eq!(types, vec![1, 5, 10]);
        assert_eq!(s.0.iter().filter(|r| r.type_ == 5).count(), 1);
        assert_eq!(s.get_u64(5).unwrap(), Some(9));
    }

    #[test]
    fn set_and_get_tu64_basic() {
        let mut s = TlvStream::default();
        s.set_tu64(42, 123456789);
        assert_eq!(s.get_tu64(42).unwrap(), Some(123456789));
    }

    #[test]
    fn get_u64_missing_returns_none() {
        let s = TlvStream::default();
        assert_eq!(s.get_u64(999).unwrap(), None);
    }

    #[test]
    fn set_tu64_overwrite_keeps_order() {
        let mut s = TlvStream(vec![rec(1, &[0xaa]), rec(10, &[0xbb])]);

        s.set_tu64(5, 7);
        assert_eq!(
            s.0.iter().map(|r| r.type_).collect::<Vec<_>>(),
            vec![1, 5, 10]
        );
        assert_eq!(s.get_tu64(5).unwrap(), Some(7));

        s.set_tu64(5, 9);
        let types: Vec<u64> = s.0.iter().map(|r| r.type_).collect();
        assert_eq!(types, vec![1, 5, 10]);
        assert_eq!(s.0.iter().filter(|r| r.type_ == 5).count(), 1);
        assert_eq!(s.get_tu64(5).unwrap(), Some(9));
    }

    #[test]
    fn tu64_zero_encodes_empty_and_roundtrips() {
        let mut s = TlvStream::default();
        s.set_tu64(3, 0);

        let rec = s.0.iter().find(|r| r.type_ == 3).unwrap();
        assert!(rec.value.is_empty());

        let bytes = s.to_bytes().unwrap();
        let s2 = TlvStream::from_bytes(&bytes).unwrap();
        assert_eq!(s2.get_tu64(3).unwrap(), Some(0));
    }

    #[test]
    fn get_tu64_missing_returns_none() {
        let s = TlvStream::default();
        assert_eq!(s.get_tu64(999).unwrap(), None);
    }

    #[test]
    fn get_tu64_rejects_non_minimal_and_too_long() {
        let mut s = TlvStream::default();
        s.0.push(TlvRecord {
            type_: 9,
            value: vec![0x00, 0x01],
        });
        assert!(s.get_tu64(9).is_err());

        let mut s2 = TlvStream::default();
        s2.0.push(TlvRecord {
            type_: 9,
            value: vec![0; 9],
        });
        assert!(s2.get_tu64(9).is_err());
    }

    #[test]
    fn tu64_multi_roundtrip() {
        let mut s = TlvStream::default();
        s.set_tu64(42, 0);
        s.set_tu64(7, 256);

        let bytes = s.to_bytes().unwrap();
        let s2 = TlvStream::from_bytes(&bytes).unwrap();
        assert_eq!(s2.get_tu64(42).unwrap(), Some(0));
        assert_eq!(s2.get_tu64(7).unwrap(), Some(256));
    }

    #[test]
    fn insert_get_remove_contains() {
        let mut s = TlvStream::default();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);

        s.insert(5, vec![0xaa]);
        s.insert(1, vec![0xbb]);
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
        assert!(s.contains(5));
        assert!(s.contains(1));
        assert!(!s.contains(99));

        assert_eq!(s.get(5), Some([0xaa].as_slice()));
        assert_eq!(s.get(1), Some([0xbb].as_slice()));
        assert_eq!(s.get(99), None);

        // Verify sorted order
        let types: Vec<u64> = s.iter().map(|r| r.type_).collect();
        assert_eq!(types, vec![1, 5]);

        assert_eq!(s.remove(5), Some(vec![0xaa]));
        assert!(!s.contains(5));
        assert_eq!(s.len(), 1);

        assert_eq!(s.remove(5), None);
    }

    #[test]
    fn from_vec() {
        let stream = TlvStream::from(vec![rec(1, &[0x01]), rec(5, &[0x05])]);
        assert_eq!(stream.len(), 2);
    }

    #[test]
    fn try_from_bytes() {
        let s = TlvStream(vec![rec(1, &[0xaa])]);
        let bytes = s.to_bytes().unwrap();
        let s2 = TlvStream::try_from(bytes.as_slice()).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn empty_stream_roundtrip() {
        let s = TlvStream::default();
        let bytes = s.to_bytes().unwrap();
        assert!(bytes.is_empty());
        let s2 = TlvStream::from_bytes(&bytes).unwrap();
        assert!(s2.is_empty());
    }

}
