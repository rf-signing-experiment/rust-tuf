//! Concrete types for the binary and string fields of a [DSSE
//! envelope](crate::DsseEnvelope).
//!
//! Each type knows how it is encoded, so callers hand around raw bytes and
//! never have to remember which field is base64 and which is not.

use {
    data_encoding::BASE64,
    serde::{Deserialize, Serialize},
    std::fmt,
};

use crate::error::{Error, Result};

macro_rules! base64_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Create from raw bytes.
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            /// Create from a byte slice.
            pub fn from_bytes(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }

            /// Create from a base64 encoded string.
            pub fn from_base64(s: &str) -> Result<Self> {
                let bytes = BASE64
                    .decode(s.as_bytes())
                    .map_err(|err| Error::InvalidEncoding(format!("invalid base64: {}", err)))?;
                Ok(Self(bytes))
            }

            /// Encode as a base64 string.
            pub fn to_base64(&self) -> String {
                BASE64.encode(&self.0)
            }

            /// Return the raw bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Consume this value and return the raw bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }

            /// Return the length in bytes.
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Return whether or not there are any bytes.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<Vec<u8>> for $name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&[u8]> for $name {
            fn from(bytes: &[u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_base64())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                ser.serialize_str(&self.to_base64())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(de)?;
                Self::from_base64(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

base64_newtype!(
    /// The payload of a [DSSE envelope](crate::DsseEnvelope).
    ///
    /// Serializes as base64 in JSON.
    PayloadBytes
);

base64_newtype!(
    /// The raw bytes of a cryptographic signature.
    ///
    /// Serializes as base64 in JSON.
    SignatureBytes
);

/// A hint identifying which key produced a [signature](crate::DsseSignature).
///
/// DSSE does not assign any meaning to the contents of a key id, so this is an
/// opaque string that serializes as-is. It is nonetheless ordered, so that a
/// producer can sort an envelope's signatures and get the same bytes every time.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new key id.
    pub fn new(s: String) -> Self {
        KeyId(s)
    }

    /// Return the key id as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume this value and return the inner `String`.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Return whether or not this key id is the empty string.
    ///
    /// An empty key id is treated as "no hint was given", and is omitted when
    /// an envelope is serialized.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        KeyId::new(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn payload_bytes_roundtrip() {
        let payload = PayloadBytes::from_bytes(b"hello world");
        assert_eq!(payload.to_base64(), "aGVsbG8gd29ybGQ=");

        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(json, r#""aGVsbG8gd29ybGQ=""#);

        let decoded: PayloadBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let sig = SignatureBytes::from_bytes(&[0x00, 0x01, 0x02, 0x03]);
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: SignatureBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(decoded.into_bytes(), vec![0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn base64_decoding_rejects_garbage() {
        assert!(PayloadBytes::from_base64("not valid base64!").is_err());
    }

    #[test]
    fn empty_values() {
        assert!(PayloadBytes::from_bytes(b"").is_empty());
        assert_eq!(PayloadBytes::from_bytes(b"abc").len(), 3);
        assert!(KeyId::default().is_empty());
        assert!(!KeyId::new("abc".into()).is_empty());
    }
}
