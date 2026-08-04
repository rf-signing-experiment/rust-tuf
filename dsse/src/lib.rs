//! An implementation of the [Dead Simple Signing
//! Envelope](https://github.com/secure-systems-lab/dsse) (DSSE).
//!
//! DSSE is a signature envelope that wraps an arbitrary payload alongside the
//! signatures over that payload. DSSE signs the *Pre-Authentication Encoding* (PAE)
//! of the payload.
//!
//! ```text
//! PAE(type, body) = "DSSEv1" ‖ SP ‖ LEN(type) ‖ SP ‖ type ‖ SP ‖ LEN(body) ‖ SP ‖ body
//! ```
//!
//! This crate does not actually perform any signing operations. The signing function
//! must be externally provided.
//!
//! # Example
//! ```
//! use dsse::{DsseEnvelope, DsseSignature, KeyId, PayloadBytes, SignatureBytes, pae};
//!
//! let payload = br#"{"hello":"world"}"#;
//! let payload_type = "application/example+json";
//!
//! // This is the byte string that is handed to the signing key.
//! let to_sign = pae(payload_type, payload);
//! # let sign = |msg: &[u8]| msg.to_vec();
//! let signature = sign(&to_sign);
//!
//! let envelope = DsseEnvelope::new(
//!     payload_type.into(),
//!     PayloadBytes::from_bytes(payload),
//!     vec![DsseSignature::new(
//!         SignatureBytes::new(signature),
//!         KeyId::new("my-key".into()),
//!     )],
//! );
//!
//! assert_eq!(envelope.pae(), to_sign);
//! ```

#![deny(missing_docs)]

mod encoding;
mod error;

pub use crate::encoding::{KeyId, PayloadBytes, SignatureBytes};
pub use crate::error::{Error, Result};

use serde::{Deserialize, Serialize};

/// A DSSE envelope containing a payload and the signatures over it.
///
/// The signatures are over the envelope's [Pre-Authentication
/// Encoding](DsseEnvelope::pae), not over the payload directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// The type URI describing how to interpret `payload`.
    pub payload_type: String,

    /// The payload bytes. Serialized as base64.
    pub payload: PayloadBytes,

    /// The signatures over the Pre-Authentication Encoding of the payload.
    pub signatures: Vec<DsseSignature>,
}

/// A signature in a [`DsseEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// The signature bytes. Serialized as base64.
    pub sig: SignatureBytes,

    /// An optional hint about which key produced this signature. Omitted when
    /// serializing if it is empty.
    #[serde(default, skip_serializing_if = "KeyId::is_empty")]
    pub keyid: KeyId,
}

impl DsseEnvelope {
    /// Create a new DSSE envelope.
    pub fn new(
        payload_type: String,
        payload: PayloadBytes,
        signatures: Vec<DsseSignature>,
    ) -> Self {
        Self {
            payload_type,
            payload,
            signatures,
        }
    }

    /// Return this envelope's Pre-Authentication Encoding, which is the byte
    /// string that each of the envelope's signatures is computed over.
    ///
    /// ```
    /// # use dsse::{DsseEnvelope, PayloadBytes};
    /// let envelope = DsseEnvelope::new(
    ///     "application/example".into(),
    ///     PayloadBytes::from_bytes(b"hello world"),
    ///     vec![],
    /// );
    ///
    /// assert_eq!(envelope.pae(), b"DSSEv1 19 application/example 11 hello world");
    /// ```
    pub fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, self.payload.as_bytes())
    }

    /// Return a copy of the payload bytes.
    pub fn decode_payload(&self) -> Vec<u8> {
        self.payload.as_bytes().to_vec()
    }
}

impl DsseSignature {
    /// Create a new DSSE signature.
    pub fn new(sig: SignatureBytes, keyid: KeyId) -> Self {
        Self { sig, keyid }
    }
}

/// Compute the Pre-Authentication Encoding (PAE) of a payload.
///
/// ```text
/// PAE(type, body) = "DSSEv1" ‖ SP ‖ LEN(type) ‖ SP ‖ type ‖ SP ‖ LEN(body) ‖ SP ‖ body
/// ```
///
/// where `LEN` is the length in bytes written out in ASCII decimal.
///
/// ```
/// # use dsse::pae;
/// assert_eq!(
///     pae("application/example", b"hello world"),
///     b"DSSEv1 19 application/example 11 hello world",
/// );
/// ```
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();

    let mut buf = Vec::new();
    buf.extend_from_slice(b"DSSEv1 ");
    buf.extend_from_slice(payload_type.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload_type);
    buf.push(b' ');
    buf.extend_from_slice(payload.len().to_string().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(payload);

    buf
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pae_matches_the_spec_test_vector() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
        );
    }

    #[test]
    fn pae_handles_empty_values() {
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
    }

    #[test]
    fn pae_is_not_confused_by_a_payload_that_looks_like_a_pae() {
        // The lengths are what make the encoding unambiguous, so a payload that
        // embeds spaces cannot be re-split into different fields.
        let a = pae("application/example", b"hello world");
        let b = pae("application/example hello", b" world");
        assert_ne!(a, b);
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let envelope = DsseEnvelope::new(
            "application/vnd.tuf+json".into(),
            PayloadBytes::from_bytes(br#"{"_type":"root"}"#),
            vec![DsseSignature::new(
                SignatureBytes::from_bytes(&[0xde, 0xad, 0xbe, 0xef]),
                KeyId::new("abcd".into()),
            )],
        );

        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(
            json,
            r#"{"payloadType":"application/vnd.tuf+json","payload":"eyJfdHlwZSI6InJvb3QifQ==","signatures":[{"sig":"3q2+7w==","keyid":"abcd"}]}"#,
        );

        let decoded: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.decode_payload(), br#"{"_type":"root"}"#);
    }

    #[test]
    fn empty_keyid_is_omitted_and_optional() {
        let envelope = DsseEnvelope::new(
            "application/example".into(),
            PayloadBytes::from_bytes(b"payload"),
            vec![DsseSignature::new(
                SignatureBytes::from_bytes(b"sig"),
                KeyId::default(),
            )],
        );

        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("keyid"), "{}", json);

        let decoded: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, envelope);
    }
}
