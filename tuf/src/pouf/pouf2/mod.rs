use {
    dsse::{DsseEnvelope, DsseSignature, PayloadBytes, SignatureBytes, pae},
    serde::{Serialize, de::DeserializeOwned},
    std::{fmt, str::FromStr},
};

use crate::Result;
use crate::crypto::{KeyId, KeyType, PublicKey, Signature, SignatureScheme, SignatureValue};
use crate::error::Error;
use crate::pouf::{Pouf, fall_back_to_opaque, opaque_key, opaque_public_key};

/// The DSSE payload type of TUF metadata encoded with [Pouf2].
pub const PAYLOAD_TYPE: &str = "application/vnd.tuf+json";

/// TUF POUF-2 implementation.
///
/// POUF-2 is JSON metadata wrapped in a [Dead Simple Signing
/// Envelope](https://github.com/secure-systems-lab/dsse) (DSSE). It differs from [Pouf1] in two
/// ways:
///
/// * Signatures are computed over the DSSE Pre-Authentication Encoding of the metadata rather than
///   over a canonicalized rewrite of it. A verifier therefore signs and checks the payload
///   byte-for-byte and never has to agree with the producer on a canonical JSON dialect.
/// * Public keys are always PEM encoded, never raw key bytes, whatever their type.
///
/// [Pouf1]: crate::pouf::Pouf1
///
/// # Schema
///
/// ## Common Entities
///
/// `NATURAL_NUMBER` is an integer in the range `[1, 2**32)`.
///
/// `EXPIRES` is an ISO-8601 date time in format `YYYY-MM-DD'T'hh:mm:ss'Z'`.
///
/// `KEY_ID` is an opaque string that names a `PUB_KEY`. Nothing may be inferred from its contents.
///
/// `PUB_KEY` is the following:
///
/// ```bash
/// {
///   "keytype": KEY_TYPE,
///   "scheme": SCHEME,
///   "keyval": {
///     "public": PUBLIC
///   }
/// }
/// ```
///
/// `PUBLIC` is a PEM encoded `SubjectPublicKeyInfo` DER public key, using the `PUBLIC KEY` label.
///
/// `KEY_TYPE` is a string (such as `ed25519`, `ecdsa`, or `rsa`).
///
/// `SCHEME` is a string (such as `ed25519`, `ecdsa-sha2-nistp256`, or `rsassa-pss-sha256`).
///
/// `HASH_VALUE` is a hex encoded hash value.
///
/// `BASE64` is a standard (padded) base64 encoded string.
///
/// `METADATA_DESCRIPTION` is the following:
///
/// ```bash
/// {
///   "version": NATURAL_NUMBER,
///   "length": NATURAL_NUMBER,
///   "hashes": {
///     HASH_ALGORITHM: HASH_VALUE
///     ...
///   }
/// }
/// ```
///
/// ## `SignedMetadata`
///
/// Signed metadata is a DSSE envelope:
///
/// ```bash
/// {
///   "payloadType": "application/vnd.tuf+json",
///   "payload": BASE64,
///   "signatures": [SIGNATURE]
/// }
/// ```
///
/// `payload` is the base64 encoding of the JSON serialization of one of:
///
/// - `RootMetadata`
/// - `SnapshotMetadata`
/// - `TargetsMetadata`
/// - `TimestampMetadata`
///
/// `SIGNATURE` is:
///
/// ```bash
/// {
///   "sig": BASE64,
///   "keyid": KEY_ID
/// }
/// ```
///
/// where `sig` is a signature over:
///
/// ```bash
/// "DSSEv1" ‖ SP ‖ LEN(payloadType) ‖ SP ‖ payloadType ‖ SP ‖ LEN(payload) ‖ SP ‖ payload
/// ```
///
/// with `payload` being the *decoded* payload bytes, and `LEN` being the length in bytes written
/// out in ASCII decimal.
///
/// The elements of `signatures` must have unique `keyid`s.
///
/// ## `RootMetadata`
///
/// ```bash
/// {
///   "_type": "root",
///   "spec_version": SPEC_VERSION,
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "consistent_snapshot": BOOLEAN,
///   "keys": {
///     KEY_ID: PUB_KEY,
///     ...
///   },
///   "roles": {
///     "root": ROLE_DESCRIPTION,
///     "snapshot": ROLE_DESCRIPTION,
///     "targets": ROLE_DESCRIPTION,
///     "timestamp": ROLE_DESCRIPTION
///   }
/// }
/// ```
///
/// `ROLE_DESCRIPTION` is the following:
///
/// ```bash
/// {
///   "threshold": NATURAL_NUMBER,
///   "keyids": [KEY_ID, ...]
/// }
/// ```
///
/// ## `SnapshotMetadata`
///
/// ```bash
/// {
///   "_type": "snapshot",
///   "spec_version": SPEC_VERSION,
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "meta": {
///     META_PATH: METADATA_DESCRIPTION
///   }
/// }
/// ```
///
/// `META_PATH` is a string.
///
/// ## `TargetsMetadata`
///
/// ```bash
/// {
///   "_type": "targets",
///   "spec_version": SPEC_VERSION,
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "targets": {
///     TARGET_PATH: TARGET_DESCRIPTION
///     ...
///   },
///   "delegations": DELEGATIONS
/// }
/// ```
///
/// `DELEGATIONS` is optional and is described by the following:
///
/// ```bash
/// {
///   "keys": {
///     KEY_ID: PUB_KEY,
///     ...
///   },
///   "roles": [DELEGATION, ...]
/// }
/// ```
///
/// `DELEGATION` is:
///
/// ```bash
/// {
///   "name": ROLE,
///   "threshold": NATURAL_NUMBER,
///   "terminating": BOOLEAN,
///   "keyids": [KEY_ID, ...],
///   "paths": [PATH, ...]
/// }
/// ```
///
/// `ROLE` is a string,
///
/// `PATH` is a string.
///
/// ## `TimestampMetadata`
///
/// ```bash
/// {
///   "_type": "timestamp",
///   "spec_version": SPEC_VERSION,
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "meta": {
///     "snapshot.json": METADATA_DESCRIPTION
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pouf2;

impl Pouf for Pouf2 {
    type RawData = Payload;

    /// ```
    /// # use tuf::pouf::{Pouf, Pouf2};
    /// assert_eq!(Pouf2::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        "json"
    }

    /// Return the DSSE Pre-Authentication Encoding of the payload, which is the byte string the
    /// metadata's signatures are computed over.
    fn signing_input(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        Ok(pae(PAYLOAD_TYPE, raw_data.as_bytes()))
    }

    /// Read the payload, which is where its bytes are parsed as JSON for the first time.
    fn from_raw_data<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(serde_json::from_slice(raw_data.as_bytes())?)
    }

    fn to_raw_data<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Payload::from_value(serde_json::to_value(data)?)
    }

    /// Write every public key this crate understands as a PEM block.
    ///
    /// ```
    /// # use tuf::crypto::{Ed25519PrivateKey, PrivateKey};
    /// # use tuf::pouf::{Pouf, Pouf2};
    /// # let pk8: &[u8] = include_bytes!("../../../tests/ed25519/ed25519-1.pk8.der");
    /// let key = Ed25519PrivateKey::from_pkcs8(pk8).unwrap();
    ///
    /// assert_eq!(
    ///     Pouf2::encode_public_key(key.public()).unwrap(),
    ///     "-----BEGIN PUBLIC KEY-----\n\
    ///      MCowBQYDK2VwAyEA64rCa1ye8CeeO+PoImKpO84W/ljuQiUA04yvRhxlo7Y=\n\
    ///      -----END PUBLIC KEY-----\n",
    /// );
    /// ```
    fn encode_public_key(public_key: &PublicKey) -> Result<String> {
        // A key this crate never made sense of is handed back exactly as it was read, because
        // there is nothing else it could honestly be written as.
        if public_key.is_opaque() {
            return opaque_public_key(public_key);
        }

        match public_key.typ() {
            KeyType::Ed25519 | KeyType::Ecdsa | KeyType::Rsa => public_key.to_pem(),
            KeyType::Unknown(_) => opaque_public_key(public_key),
        }
    }

    fn decode_public_key(
        key_type: KeyType,
        scheme: SignatureScheme,
        public: &str,
    ) -> Result<PublicKey> {
        let decoded = match key_type {
            KeyType::Ed25519 | KeyType::Ecdsa | KeyType::Rsa => {
                PublicKey::from_pem(public, key_type.clone(), scheme.clone())
            }
            KeyType::Unknown(_) => {
                return Ok(opaque_key(key_type, scheme, public));
            }
        };

        Ok(decoded.unwrap_or_else(|err| fall_back_to_opaque(key_type, scheme, public, err)))
    }

    /// Write the metadata and its signatures out as a DSSE envelope.
    fn serialize_signed(signatures: &[Signature], raw_data: &Self::RawData) -> Result<Vec<u8>> {
        let envelope = DsseEnvelope::new(
            PAYLOAD_TYPE.into(),
            PayloadBytes::from_bytes(raw_data.as_bytes()),
            signatures
                .iter()
                .map(|sig| {
                    DsseSignature::new(
                        SignatureBytes::from_bytes(sig.value().as_bytes()),
                        dsse::KeyId::new(sig.key_id().to_string()),
                    )
                })
                .collect(),
        );

        Ok(serde_json::to_vec(&envelope)?)
    }

    /// Read the metadata and its signatures out of a DSSE envelope.
    ///
    /// The payload is kept exactly as it was received so that the signatures can be checked
    /// against the bytes that were actually signed.
    fn deserialize_signed(slice: &[u8]) -> Result<(Vec<Signature>, Self::RawData)> {
        let envelope: DsseEnvelope = serde_json::from_slice(slice)?;

        if envelope.payload_type != PAYLOAD_TYPE {
            return Err(Error::Encoding(format!(
                "expected DSSE payload type {:?}, found {:?}",
                PAYLOAD_TYPE, envelope.payload_type,
            )));
        }

        let signatures = envelope
            .signatures
            .iter()
            .map(|sig| {
                Ok(Signature::new(
                    KeyId::from_str(sig.keyid.as_str())?,
                    SignatureValue::new(sig.sig.as_bytes().to_vec()),
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok((
            signatures,
            Payload::from_slice(envelope.payload.into_bytes()),
        ))
    }
}

/// The signed portion of [Pouf2] metadata, which is the payload of a DSSE envelope.
///
/// This holds on to the payload's exact bytes. DSSE signs the bytes as they appear on the wire,
/// so they must survive a round trip through this crate untouched, even if this crate would have
/// written them out differently itself.
#[derive(Clone, Debug)]
pub struct Payload {
    bytes: Vec<u8>,
}

impl Payload {
    /// Create a `Payload` from the exact bytes it is encoded as.
    ///
    /// The bytes are not looked at. A payload arrives unverified, and reading it before its
    /// signatures have been checked would be running a parser over whatever an attacker sent.
    pub fn from_slice(bytes: Vec<u8>) -> Self {
        Payload { bytes }
    }

    /// Create a `Payload` from parsed JSON.
    ///
    /// The payload's bytes are the compact serialization of `value`, which writes object keys out
    /// in sorted order.
    pub fn from_value(value: serde_json::Value) -> Result<Self> {
        Ok(Payload {
            bytes: serde_json::to_vec(&value)?,
        })
    }

    /// The payload's bytes, as they appear inside the DSSE envelope.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

/// Two payloads are equal when their bytes are equal. Payloads that parse to the same JSON but
/// were encoded differently have different signatures, so they are not interchangeable.
impl PartialEq for Payload {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Payload {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{
        EcdsaPrivateKey, Ed25519PrivateKey, PrivateKey, PublicKey, RsaPrivateKey, SignatureScheme,
    };
    use assert_matches::assert_matches;
    use data_encoding::HEXLOWER;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    const PK8_1: &[u8] = include_bytes!("../../../tests/ed25519/ed25519-1.pk8.der");
    const ECDSA_P256_PK8_1: &[u8] = include_bytes!("../../../tests/ecdsa/ecdsa-p256-1.pk8.der");
    const RSA_PK8_1: &[u8] = include_bytes!("../../../tests/rsa/rsa-2048-1.pk8.der");

    #[test]
    fn payload_keeps_the_bytes_it_was_built_from() {
        // Note the whitespace and the unsorted keys, neither of which we would have written.
        let bytes = br#"{ "b": 1, "a": 2 }"#.to_vec();
        let payload = Payload::from_slice(bytes.clone());

        assert_eq!(payload.as_bytes(), bytes);
        assert_eq!(
            Pouf2::from_raw_data::<serde_json::Value>(&payload).unwrap(),
            json!({"a": 2, "b": 1}),
        );

        // The same JSON, encoded differently, is a different payload.
        let other = Payload::from_value(json!({"a": 2, "b": 1})).unwrap();
        assert_eq!(other.as_bytes(), br#"{"a":2,"b":1}"#);
        assert_ne!(payload, other);
    }

    /// A payload arrives unverified, so nothing looks at it until its signatures have been
    /// checked. Reading a document does not parse it; interpreting one does.
    #[test]
    fn a_payload_that_is_not_json_is_only_rejected_when_it_is_read() {
        let envelope = json!({
            "payloadType": PAYLOAD_TYPE,
            "payload": "bG9s",
            "signatures": [],
        });

        let (_, payload) =
            Pouf2::deserialize_signed(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(payload.as_bytes(), b"lol");

        assert_matches!(
            Pouf2::from_raw_data::<serde_json::Value>(&payload),
            Err(Error::Json(_))
        );
    }

    #[test]
    fn public_keys_are_always_pem() {
        let key = Ed25519PrivateKey::from_pkcs8(PK8_1).unwrap();
        let public_key = key.public();

        let pem = Pouf2::encode_public_key(public_key).unwrap();
        assert_eq!(pem, public_key.to_pem().unwrap());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{}", pem);

        // The raw key bytes never appear in the encoded form.
        assert!(!pem.contains(&HEXLOWER.encode(public_key.as_bytes())));

        let decoded =
            Pouf2::decode_public_key(KeyType::Ed25519, SignatureScheme::Ed25519, &pem).unwrap();

        assert_eq!(&decoded, public_key);
        assert_eq!(decoded.key_id(), public_key.key_id());
    }

    /// Every key type this pouf understands is written as PEM, not just ed25519.
    #[test]
    fn ecdsa_and_rsa_public_keys_are_pem_too() {
        for public_key in [
            EcdsaPrivateKey::from_pkcs8(ECDSA_P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
                .unwrap()
                .public()
                .clone(),
            RsaPrivateKey::from_pkcs8(RSA_PK8_1, SignatureScheme::RsassaPssSha256)
                .unwrap()
                .public()
                .clone(),
        ] {
            let public_key = &public_key;

            let pem = Pouf2::encode_public_key(public_key).unwrap();
            assert_eq!(pem, public_key.to_pem().unwrap());
            assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{}", pem);

            let decoded = Pouf2::decode_public_key(
                public_key.typ().clone(),
                public_key.scheme().clone(),
                &pem,
            )
            .unwrap();

            assert_eq!(&decoded, public_key);
            assert_eq!(decoded.key_id(), public_key.key_id());
        }
    }

    /// A key type this crate does not understand cannot be re-encoded as anything, so it is left
    /// exactly as it was written. That way a repository can start using a new key type without
    /// older clients failing to read the metadata that carries it.
    #[test]
    fn unknown_public_keys_are_left_alone() {
        let key_type = KeyType::Unknown("unknown-keytype".into());
        let scheme = SignatureScheme::Unknown("unknown-scheme".into());
        let public_key =
            PublicKey::new(key_type.clone(), scheme.clone(), b"unknown-key".to_vec()).unwrap();

        let encoded = Pouf2::encode_public_key(&public_key).unwrap();
        assert_eq!(encoded, "unknown-key");

        assert_eq!(
            Pouf2::decode_public_key(key_type, scheme, &encoded).unwrap(),
            public_key,
        );
    }

    /// A key of a type this crate knows, written in some way it does not, is kept exactly as it
    /// was written rather than taking the surrounding metadata down with it.
    #[test]
    fn a_key_that_cannot_be_decoded_is_kept_opaque() {
        let key = Ed25519PrivateKey::from_pkcs8(PK8_1).unwrap();
        let written = HEXLOWER.encode(key.public().as_bytes());

        let decoded =
            Pouf2::decode_public_key(KeyType::Ed25519, SignatureScheme::Ed25519, &written).unwrap();

        assert!(decoded.is_opaque());
        assert_ne!(&decoded, key.public());

        // It goes back out byte for byte as it came in...
        assert_eq!(Pouf2::encode_public_key(&decoded).unwrap(), written);

        // ... and it can never be used for anything.
        assert_matches!(decoded.to_pem(), Err(Error::UnknownKeyType(_)));
        assert_matches!(
            decoded.verify(
                &crate::metadata::MetadataPath::root(),
                b"test",
                &key.sign(b"test").unwrap(),
            ),
            Err(Error::UnknownKeyType(_))
        );
    }

    #[test]
    fn deserialize_signed_rejects_the_wrong_payload_type() {
        let envelope = json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "e30=",
            "signatures": [],
        });

        assert_matches!(
            Pouf2::deserialize_signed(&serde_json::to_vec(&envelope).unwrap()),
            Err(Error::Encoding(msg))
            if msg.contains("application/vnd.in-toto+json")
        );
    }

    #[test]
    fn signed_metadata_round_trips_through_a_dsse_envelope() {
        let key = Ed25519PrivateKey::from_pkcs8(PK8_1).unwrap();

        let payload = Payload::from_slice(br#"{ "unsorted": true, "a": 1 }"#.to_vec());
        let sig = key.sign(&Pouf2::signing_input(&payload).unwrap()).unwrap();

        let bytes = Pouf2::serialize_signed(std::slice::from_ref(&sig), &payload).unwrap();

        let envelope: DsseEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope.payload_type, PAYLOAD_TYPE);
        assert_eq!(envelope.decode_payload(), payload.as_bytes());
        assert_eq!(envelope.signatures.len(), 1);
        assert_eq!(
            envelope.signatures[0].keyid.as_str(),
            key.public().key_id().to_string()
        );

        let (signatures, decoded) = Pouf2::deserialize_signed(&bytes).unwrap();
        assert_eq!(signatures, vec![sig]);

        // The payload's bytes survived the round trip untouched, so the signature still checks out
        // against them.
        assert_eq!(decoded, payload);
        assert_eq!(decoded.as_bytes(), br#"{ "unsorted": true, "a": 1 }"#);
    }

    #[test]
    fn deserialize_signed_requires_a_keyid() {
        let envelope = json!({
            "payloadType": PAYLOAD_TYPE,
            "payload": "e30=",
            "signatures": [{ "sig": "3q2+7w==" }],
        });

        assert_matches!(
            Pouf2::deserialize_signed(&serde_json::to_vec(&envelope).unwrap()),
            Err(Error::IllegalArgument(_))
        );
    }
}
