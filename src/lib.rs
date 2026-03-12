pub mod bigsize;
pub mod encoding;
pub mod error;
pub mod stream;

pub use error::{Result, TlvError};
pub use stream::{TlvRecord, TlvStream};

// Helper traits used by the tlv_struct! macro. Not part of the public API.
#[doc(hidden)]
pub mod _macro_support {
    use crate::error::{Result, TlvError};

    pub trait TlvTu64Encode {
        fn to_tu64_value(&self) -> u64;
    }
    impl TlvTu64Encode for u64 {
        fn to_tu64_value(&self) -> u64 {
            *self
        }
    }
    impl TlvTu64Encode for u32 {
        fn to_tu64_value(&self) -> u64 {
            *self as u64
        }
    }

    pub trait TlvTu64Decode: Sized {
        fn from_tu64_value(v: u64) -> Self;
    }
    impl TlvTu64Decode for u64 {
        fn from_tu64_value(v: u64) -> Self {
            v
        }
    }
    impl TlvTu64Decode for u32 {
        fn from_tu64_value(v: u64) -> Self {
            v as u32
        }
    }

    pub trait TlvBytesEncode {
        fn to_tlv_vec(&self) -> Vec<u8>;
    }
    impl TlvBytesEncode for Vec<u8> {
        fn to_tlv_vec(&self) -> Vec<u8> {
            self.clone()
        }
    }
    impl<const N: usize> TlvBytesEncode for [u8; N] {
        fn to_tlv_vec(&self) -> Vec<u8> {
            self.to_vec()
        }
    }

    pub trait TlvBytesDecode: Sized {
        fn from_tlv_raw(raw: &[u8], type_num: u64) -> Result<Self>;
    }
    impl TlvBytesDecode for Vec<u8> {
        fn from_tlv_raw(raw: &[u8], _type_num: u64) -> Result<Self> {
            Ok(raw.to_vec())
        }
    }
    impl<const N: usize> TlvBytesDecode for [u8; N] {
        fn from_tlv_raw(raw: &[u8], type_num: u64) -> Result<Self> {
            raw.try_into().map_err(|_| TlvError::InvalidLength {
                type_: type_num,
                expected: N,
                actual: raw.len(),
            })
        }
    }
}

/// Declare a Rust struct that maps to/from a TLV stream.
///
/// # Encoding tags
/// - `tu64` — variable-length minimal big-endian integer (field type: `u64` or `u32`)
/// - `u64`  — fixed 8-byte big-endian (field type: `u64`)
/// - `bytes` — raw bytes (field type: `Vec<u8>`, `[u8; N]`, or `Option` variants)
///
/// Fields typed as `Option<T>` are automatically optional: omitted when `None`,
/// decoded as `None` when absent from the stream.
///
/// # Example
/// ```
/// btlv::tlv_struct! {
///     pub struct OnionPayload {
///         #[tlv(2, tu64)]
///         pub amt_to_forward: u64,
///         #[tlv(4, tu64)]
///         pub outgoing_cltv_value: u32,
///         #[tlv(6, bytes)]
///         pub short_channel_id: Option<[u8; 8]>,
///     }
/// }
///
/// let payload = OnionPayload {
///     amt_to_forward: 1000,
///     outgoing_cltv_value: 800000,
///     short_channel_id: None,
/// };
/// let bytes = payload.to_tlv_bytes().unwrap();
/// let decoded = OnionPayload::from_tlv_bytes(&bytes).unwrap();
/// assert_eq!(decoded.amt_to_forward, 1000);
/// assert_eq!(decoded.outgoing_cltv_value, 800000);
/// assert_eq!(decoded.short_channel_id, None);
/// ```
#[macro_export]
macro_rules! tlv_struct {
    // Top-level entry point: start the tt-muncher to classify fields
    (
        $(#[$struct_meta:meta])*
        $vis:vis struct $name:ident {
            $($rest:tt)*
        }
    ) => {
        $crate::tlv_struct!(@munch
            [$(#[$struct_meta])* $vis struct $name]
            []
            $($rest)*
        );
    };

    // tt-muncher: optional field (Option<T>)
    (@munch
        [$($header:tt)*]
        [$($acc:tt)*]
        $(#[doc = $doc:literal])*
        #[tlv($type_num:expr, $enc:ident)]
        $field_vis:vis $field:ident : Option<$inner_ty:ty>,
        $($rest:tt)*
    ) => {
        $crate::tlv_struct!(@munch
            [$($header)*]
            [$($acc)*
                $(#[doc = $doc])*
                ($type_num, $enc, optional)
                $field_vis $field : Option<$inner_ty>,
            ]
            $($rest)*
        );
    };

    // tt-muncher: required field (non-Option)
    (@munch
        [$($header:tt)*]
        [$($acc:tt)*]
        $(#[doc = $doc:literal])*
        #[tlv($type_num:expr, $enc:ident)]
        $field_vis:vis $field:ident : $field_ty:ty,
        $($rest:tt)*
    ) => {
        $crate::tlv_struct!(@munch
            [$($header)*]
            [$($acc)*
                $(#[doc = $doc])*
                ($type_num, $enc, required)
                $field_vis $field : $field_ty,
            ]
            $($rest)*
        );
    };

    // tt-muncher: done — emit @impl_struct
    (@munch
        [$(#[$struct_meta:meta])* $vis:vis struct $name:ident]
        [$($acc:tt)*]
    ) => {
        $crate::tlv_struct!(@impl_struct
            $(#[$struct_meta])*
            $vis struct $name {
                $($acc)*
            }
        );
    };

    // Internal: struct definition + impls
    (@impl_struct
        $(#[$struct_meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[doc = $doc:literal])*
                ($type_num:expr, $enc:ident, $optionality:ident)
                $field_vis:vis $field:ident : $field_ty:ty,
            )*
        }
    ) => {
        $(#[$struct_meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        $vis struct $name {
            $(
                $(#[doc = $doc])*
                $field_vis $field : $field_ty,
            )*
        }

        impl $name {
            /// Serialize this struct to TLV wire-format bytes.
            pub fn to_tlv_bytes(&self) -> $crate::Result<Vec<u8>> {
                let stream: $crate::TlvStream = self.into();
                stream.to_bytes()
            }

            /// Deserialize from TLV wire-format bytes.
            pub fn from_tlv_bytes(bytes: &[u8]) -> $crate::Result<Self> {
                let stream = $crate::TlvStream::from_bytes(bytes)?;
                Self::try_from(&stream)
            }
        }

        impl From<&$name> for $crate::TlvStream {
            fn from(val: &$name) -> Self {
                let mut stream = $crate::TlvStream::default();
                $(
                    $crate::tlv_struct!(@encode_field stream, val, $field, $type_num, $enc, $optionality);
                )*
                stream
            }
        }

        impl TryFrom<&$crate::TlvStream> for $name {
            type Error = $crate::TlvError;

            fn try_from(stream: &$crate::TlvStream) -> std::result::Result<Self, Self::Error> {
                Ok($name {
                    $(
                        $field: $crate::tlv_struct!(@decode_field stream, $type_num, $enc, $optionality),
                    )*
                })
            }
        }
    };

    // === Encode: tu64 required ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, tu64, required) => {
        $stream.set_tu64($type_num, $crate::_macro_support::TlvTu64Encode::to_tu64_value(&$val.$field));
    };
    // === Encode: tu64 optional ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, tu64, optional) => {
        if let Some(ref v) = $val.$field {
            $stream.set_tu64($type_num, $crate::_macro_support::TlvTu64Encode::to_tu64_value(v));
        }
    };
    // === Encode: u64 required ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, u64, required) => {
        $stream.set_u64($type_num, $val.$field);
    };
    // === Encode: u64 optional ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, u64, optional) => {
        if let Some(v) = $val.$field {
            $stream.set_u64($type_num, v);
        }
    };
    // === Encode: bytes required ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, bytes, required) => {
        $stream.insert($type_num, $crate::_macro_support::TlvBytesEncode::to_tlv_vec(&$val.$field));
    };
    // === Encode: bytes optional ===
    (@encode_field $stream:ident, $val:ident, $field:ident, $type_num:expr, bytes, optional) => {
        if let Some(ref v) = $val.$field {
            $stream.insert($type_num, $crate::_macro_support::TlvBytesEncode::to_tlv_vec(v));
        }
    };

    // === Decode: tu64 required ===
    (@decode_field $stream:ident, $type_num:expr, tu64, required) => {{
        let v = $stream.get_tu64($type_num)?
            .ok_or($crate::TlvError::MissingRequired($type_num))?;
        $crate::_macro_support::TlvTu64Decode::from_tu64_value(v)
    }};
    // === Decode: tu64 optional ===
    (@decode_field $stream:ident, $type_num:expr, tu64, optional) => {{
        $stream.get_tu64($type_num)?.map($crate::_macro_support::TlvTu64Decode::from_tu64_value)
    }};
    // === Decode: u64 required ===
    (@decode_field $stream:ident, $type_num:expr, u64, required) => {{
        $stream.get_u64($type_num)?
            .ok_or($crate::TlvError::MissingRequired($type_num))?
    }};
    // === Decode: u64 optional ===
    (@decode_field $stream:ident, $type_num:expr, u64, optional) => {{
        $stream.get_u64($type_num)?
    }};
    // === Decode: bytes required ===
    (@decode_field $stream:ident, $type_num:expr, bytes, required) => {{
        let raw = $stream.get($type_num)
            .ok_or($crate::TlvError::MissingRequired($type_num))?;
        $crate::_macro_support::TlvBytesDecode::from_tlv_raw(raw, $type_num)?
    }};
    // === Decode: bytes optional ===
    (@decode_field $stream:ident, $type_num:expr, bytes, optional) => {{
        match $stream.get($type_num) {
            Some(raw) => Some($crate::_macro_support::TlvBytesDecode::from_tlv_raw(raw, $type_num)?),
            None => None,
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mixed required and optional fields — use @impl_struct directly
    tlv_struct!(@impl_struct
        /// An onion payload for testing.
        pub struct OnionPayload {
            /// Amount to forward in msat
            (2, tu64, required)
            pub amt_to_forward: u64,
            /// Outgoing CLTV value
            (4, tu64, required)
            pub outgoing_cltv_value: u32,
            /// Short channel ID
            (6, bytes, optional)
            pub short_channel_id: Option<[u8; 8]>,
            /// Payment secret
            (8, bytes, optional)
            pub payment_secret: Option<[u8; 32]>,
        }
    );

    #[test]
    fn onion_payload_roundtrip_all_fields() {
        let scid = [0x00, 0x73, 0x00, 0x0f, 0x2c, 0x00, 0x07, 0x00];
        let secret = [0xab; 32];
        let payload = OnionPayload {
            amt_to_forward: 1000,
            outgoing_cltv_value: 800000,
            short_channel_id: Some(scid),
            payment_secret: Some(secret),
        };

        let bytes = payload.to_tlv_bytes().unwrap();
        let decoded = OnionPayload::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn onion_payload_roundtrip_optional_none() {
        let payload = OnionPayload {
            amt_to_forward: 500,
            outgoing_cltv_value: 144,
            short_channel_id: None,
            payment_secret: None,
        };

        let bytes = payload.to_tlv_bytes().unwrap();
        let decoded = OnionPayload::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn onion_payload_missing_required_field() {
        let mut stream = TlvStream::default();
        stream.set_tu64(2, 1000);
        let bytes = stream.to_bytes().unwrap();

        let err = OnionPayload::from_tlv_bytes(&bytes).unwrap_err();
        assert!(matches!(err, TlvError::MissingRequired(4)));
    }

    #[test]
    fn onion_payload_wrong_length_bytes() {
        let mut stream = TlvStream::default();
        stream.set_tu64(2, 1000);
        stream.set_tu64(4, 144);
        stream.insert(6, vec![0x00; 5]);
        let bytes = stream.to_bytes().unwrap();

        let err = OnionPayload::from_tlv_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            TlvError::InvalidLength {
                type_: 6,
                expected: 8,
                actual: 5,
            }
        ));
    }

    #[test]
    fn onion_payload_to_stream_and_back() {
        let payload = OnionPayload {
            amt_to_forward: 42,
            outgoing_cltv_value: 100,
            short_channel_id: None,
            payment_secret: None,
        };

        let stream: TlvStream = (&payload).into();
        let back = OnionPayload::try_from(&stream).unwrap();
        assert_eq!(back, payload);
    }

    // All-required struct
    tlv_struct! {
        pub struct SimplePayload {
            #[tlv(2, tu64)]
            pub amount: u64,
            #[tlv(4, tu64)]
            pub cltv: u32,
        }
    }

    #[test]
    fn simple_payload_roundtrip() {
        let p = SimplePayload {
            amount: 999,
            cltv: 800000,
        };
        let bytes = p.to_tlv_bytes().unwrap();
        let d = SimplePayload::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(d, p);
    }

    // All-optional struct
    tlv_struct! {
        pub struct OptionalOnly {
            #[tlv(1, tu64)]
            pub a: Option<u64>,
            #[tlv(3, bytes)]
            pub b: Option<Vec<u8>>,
        }
    }

    #[test]
    fn optional_only_empty() {
        let p = OptionalOnly { a: None, b: None };
        let bytes = p.to_tlv_bytes().unwrap();
        assert!(bytes.is_empty());
        let d = OptionalOnly::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn optional_only_with_values() {
        let p = OptionalOnly {
            a: Some(42),
            b: Some(vec![0xde, 0xad]),
        };
        let bytes = p.to_tlv_bytes().unwrap();
        let d = OptionalOnly::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(d, p);
    }

    // Struct with required Vec<u8> bytes
    tlv_struct!(@impl_struct
        pub struct WithRequiredBytes {
            (1, bytes, required)
            pub data: Vec<u8>,
            (3, tu64, required)
            pub count: u64,
        }
    );

    #[test]
    fn required_bytes_roundtrip() {
        let p = WithRequiredBytes {
            data: vec![0x01, 0x02, 0x03],
            count: 7,
        };
        let bytes = p.to_tlv_bytes().unwrap();
        let d = WithRequiredBytes::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(d, p);
    }

    // Fixed u64 encoding
    tlv_struct!(@impl_struct
        pub struct FixedU64Struct {
            (65537, u64, required)
            pub extra_fee: u64,
            (65539, u64, optional)
            pub optional_fee: Option<u64>,
        }
    );

    #[test]
    fn fixed_u64_roundtrip() {
        let p = FixedU64Struct {
            extra_fee: 1000,
            optional_fee: Some(500),
        };
        let bytes = p.to_tlv_bytes().unwrap();
        let d = FixedU64Struct::from_tlv_bytes(&bytes).unwrap();
        assert_eq!(d, p);

        let p2 = FixedU64Struct {
            extra_fee: 42,
            optional_fee: None,
        };
        let bytes2 = p2.to_tlv_bytes().unwrap();
        let d2 = FixedU64Struct::from_tlv_bytes(&bytes2).unwrap();
        assert_eq!(d2, p2);
    }
}
