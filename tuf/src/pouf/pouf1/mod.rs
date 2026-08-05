use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::collections::BTreeMap;

use data_encoding::HEXLOWER;

use crate::Result;
use crate::crypto::{KeyType, PublicKey, Signature, SignatureScheme};
use crate::error::Error;
use crate::pouf::{
    Pouf, SignedDocument, SignedDocumentOwned, fall_back_to_opaque, opaque_key, opaque_public_key,
};

/// TUF POUF-1 implementation.
///
/// # Schema
///
/// ## Common Entities
///
/// `NATURAL_NUMBER` is an integer in the range `[1, 2**32)`.
///
/// `EXPIRES` is an ISO-8601 date time in format `YYYY-MM-DD'T'hh:mm:ss'Z'`.
///
/// `KEY_ID` is an opaque identifier that names a key within the metadata.
///
/// `PUB_KEY` is the following:
///
/// ```bash
/// {
///   "type": KEY_TYPE,
///   "scheme": SCHEME,
///   "value": PUBLIC
/// }
/// ```
///
/// `PUBLIC` is the public key. An `ed25519` key is written as the hex encoding of its raw bytes;
/// every other key type is written as a PEM encoded `SubjectPublicKeyInfo`.
///
/// `KEY_TYPE` is a string (`ed25519`, `ecdsa`, and `rsa` are currently supported).
///
/// `SCHEME` is a string (`ed25519`, `ecdsa-sha2-nistp256`, and `rsassa-pss-sha256` are currently
/// supported).
///
/// `HASH_VALUE` is a hex encoded hash value.
///
/// `SIG_VALUE` is a hex encoded signature value.
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
/// ```bash
/// {
///   "signatures": [SIGNATURE],
///   "signed": SIGNED
/// }
/// ```
///
/// `SIGNATURE` is:
///
/// ```bash
/// {
///   "keyid": KEY_ID,
///   "signature": SIG_VALUE
/// }
/// ```
///
/// `SIGNED` is one of:
///
/// - `RootMetadata`
/// - `SnapshotMetadata`
/// - `TargetsMetadata`
/// - `TimestampMetadata`
///
/// The the elements of `signatures` must have unique `key_id`s.
///
/// ## `RootMetadata`
///
/// ```bash
/// {
///   "_type": "root",
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "keys": [PUB_KEY, ...]
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
///
/// ## `TargetsMetadata`
///
/// ```bash
/// {
///   "_type": "timestamp",
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
///   "keys": [PUB_KEY, ...]
///   "roles": {
///     ROLE: DELEGATION,
///     ...
///   }
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
///   "version": NATURAL_NUMBER,
///   "expires": EXPIRES,
///   "snapshot": METADATA_DESCRIPTION
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pouf1;

impl Pouf for Pouf1 {
    type RawData = serde_json::Value;

    /// ```
    /// # use tuf::pouf::{Pouf, Pouf1};
    /// assert_eq!(Pouf1::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        "json"
    }

    /// ```
    /// # use tuf::pouf::{Pouf, Pouf1};
    /// let raw = serde_json::json!({"foo": "bar", "baz": "quux"});
    /// let out = Pouf1::signing_input(&raw).unwrap();
    /// assert_eq!(out, br#"{"baz":"quux","foo":"bar"}"#);
    /// ```
    fn signing_input(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        canonicalize(raw_data).map_err(Error::Opaque)
    }

    /// ```
    /// # use serde::Deserialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::{Pouf, Pouf1};
    /// #
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let de: Thing = Pouf1::from_raw_data(&jsn).unwrap();
    /// assert_eq!(de, thing);
    /// ```
    fn from_raw_data<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(serde_json::from_value(raw_data.clone())?)
    }

    /// ```
    /// # use serde::Serialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::pouf::{Pouf, Pouf1};
    /// #
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let se: serde_json::Value = Pouf1::to_raw_data(&thing).unwrap();
    /// assert_eq!(se, jsn);
    /// ```
    fn to_raw_data<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Ok(serde_json::to_value(data)?)
    }

    /// Write out ordinary JSON, with the object keys in sorted order.
    ///
    /// This is deliberately not the canonical JSON that [`signing_input`](Pouf1::signing_input)
    /// produces. Canonical JSON escapes only `"` and `\`, so a string holding a control
    /// character - the newlines in a PEM encoded public key, say - comes out as something no JSON
    /// parser will read back. The two encodings agree on every string that has none.
    ///
    /// ```
    /// # use serde_json::json;
    /// # use tuf::pouf::{Pouf, Pouf1};
    /// let jsn = json!({"foo": "bar", "baz": "a\nb"});
    ///
    /// assert_eq!(Pouf1::serialize_signed(&[], &jsn).unwrap(), br#"{"signatures":[],"signed":{"baz":"a\nb","foo":"bar"}}"#);
    /// assert_eq!(Pouf1::signing_input(&jsn).unwrap(), b"{\"baz\":\"a\nb\",\"foo\":\"bar\"}");
    /// ```
    fn serialize_signed(signatures: &[Signature], raw_data: &Self::RawData) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&SignedDocument {
            signatures,
            signed: raw_data,
        })?)
    }

    fn deserialize_signed(slice: &[u8]) -> Result<(Vec<Signature>, Self::RawData)> {
        let document: SignedDocumentOwned<Self::RawData> = serde_json::from_slice(slice)?;

        Ok((document.signatures, document.signed))
    }

    /// Write an ed25519 key as hex bytes, other keys as PEM.
    fn encode_public_key(public_key: &PublicKey) -> Result<String> {
        // A key this crate never made sense of is handed back exactly as it was read, because
        // there is nothing else it could honestly be written as.
        if public_key.is_opaque() {
            return opaque_public_key(public_key);
        }

        match public_key.typ() {
            KeyType::Ed25519 => Ok(HEXLOWER.encode(public_key.as_bytes())),
            // Every other TUF implementation spells an ECDSA or RSA key as a PEM encoded
            // `SubjectPublicKeyInfo`, so this one does too.
            KeyType::Ecdsa | KeyType::Rsa => public_key.to_pem(),
            KeyType::Unknown(_) => opaque_public_key(public_key),
        }
    }

    fn decode_public_key(
        key_type: KeyType,
        scheme: SignatureScheme,
        public: &str,
    ) -> Result<PublicKey> {
        let decoded = match key_type {
            KeyType::Ed25519 => HEXLOWER
                .decode(public.as_bytes())
                .map_err(|err| {
                    Error::Encoding(format!("could not parse public key as hex: {}", err))
                })
                .and_then(|bytes| PublicKey::new(key_type.clone(), scheme.clone(), bytes)),
            KeyType::Ecdsa | KeyType::Rsa => {
                PublicKey::from_pem(public, key_type.clone(), scheme.clone())
            }
            KeyType::Unknown(_) => {
                return Ok(opaque_key(key_type, scheme, public));
            }
        };

        Ok(decoded.unwrap_or_else(|err| fall_back_to_opaque(key_type, scheme, public, err)))
    }
}

fn canonicalize(jsn: &serde_json::Value) -> std::result::Result<Vec<u8>, String> {
    let converted = convert(jsn)?;
    let mut buf = Vec::new();
    let _ = converted.write(&mut buf); // Vec<u8> impl always succeeds (or panics).
    Ok(buf)
}

enum Value {
    Array(Vec<Value>),
    Bool(bool),
    Null,
    Number(Number),
    Object(BTreeMap<String, Value>),
    String(String),
}

impl Value {
    fn write(&self, buf: &mut Vec<u8>) -> std::result::Result<(), String> {
        match *self {
            Value::Null => {
                buf.extend(b"null");
            }
            Value::Bool(true) => {
                buf.extend(b"true");
            }
            Value::Bool(false) => {
                buf.extend(b"false");
            }
            Value::Number(Number::I64(n)) => {
                buf.extend(itoa::Buffer::new().format(n).bytes());
            }
            Value::Number(Number::U64(n)) => {
                buf.extend(itoa::Buffer::new().format(n).bytes());
            }
            Value::String(ref s) => {
                escape_canonical_string(s, buf);
            }
            Value::Array(ref arr) => {
                buf.push(b'[');
                let mut first = true;
                for a in arr.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    a.write(buf)?;
                    first = false;
                }
                buf.push(b']');
            }
            Value::Object(ref obj) => {
                buf.push(b'{');
                let mut first = true;
                for (k, v) in obj.iter() {
                    if !first {
                        buf.push(b',');
                    }
                    first = false;

                    escape_canonical_string(k, buf);
                    buf.push(b':');
                    v.write(buf)?;
                }
                buf.push(b'}');
            }
        }
        Ok(())
    }
}

fn escape_canonical_string(s: &str, buf: &mut Vec<u8>) {
    buf.reserve(s.len() + 2);
    buf.push(b'"');
    let mut bytes = s.as_bytes();
    while let Some(i) = bytes.iter().position(|&b| matches!(b, b'\\' | b'"')) {
        buf.extend_from_slice(&bytes[..i]);
        buf.push(b'\\');
        buf.push(bytes[i]);
        bytes = &bytes[i + 1..];
    }
    buf.extend_from_slice(bytes);
    buf.push(b'"');
}

enum Number {
    I64(i64),
    U64(u64),
}

fn convert(jsn: &serde_json::Value) -> std::result::Result<Value, String> {
    match *jsn {
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Bool(b) => Ok(Value::Bool(b)),
        serde_json::Value::Number(ref n) => n
            .as_i64()
            .map(Number::I64)
            .or_else(|| n.as_u64().map(Number::U64))
            .map(Value::Number)
            .ok_or_else(|| String::from("only i64 and u64 are supported")),
        serde_json::Value::Array(ref arr) => {
            let mut out = Vec::new();
            for res in arr.iter().map(convert) {
                out.push(res?)
            }
            Ok(Value::Array(out))
        }
        serde_json::Value::Object(ref obj) => {
            let mut out = BTreeMap::new();
            for (k, v) in obj.iter() {
                let _ = out.insert(k.clone(), convert(v)?);
            }
            Ok(Value::Object(out))
        }
        serde_json::Value::String(ref s) => Ok(Value::String(s.clone())),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{EcdsaPrivateKey, Ed25519PrivateKey, PrivateKey, PublicKey, RsaPrivateKey};
    use assert_matches::assert_matches;

    const PK8_1: &[u8] = include_bytes!("../../../tests/ed25519/ed25519-1.pk8.der");
    const ECDSA_P256_PK8_1: &[u8] = include_bytes!("../../../tests/ecdsa/ecdsa-p256-1.pk8.der");
    const RSA_PK8_1: &[u8] = include_bytes!("../../../tests/rsa/rsa-2048-1.pk8.der");

    #[test]
    fn ed25519_public_keys_are_hex() {
        let key = Ed25519PrivateKey::from_pkcs8(PK8_1).unwrap();
        let public_key = key.public();

        let encoded = Pouf1::encode_public_key(public_key).unwrap();
        assert_eq!(encoded, HEXLOWER.encode(public_key.as_bytes()));

        let decoded =
            Pouf1::decode_public_key(KeyType::Ed25519, SignatureScheme::Ed25519, &encoded).unwrap();

        assert_eq!(&decoded, public_key);
        assert_eq!(decoded.key_id(), public_key.key_id());
    }

    /// Unlike ed25519, which TUF has always spelled as raw hex, every other key type this crate
    /// understands is written the way the rest of the ecosystem writes it: as a PEM encoded
    /// `SubjectPublicKeyInfo`.
    #[test]
    fn ecdsa_and_rsa_public_keys_are_pem() {
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

            let encoded = Pouf1::encode_public_key(public_key).unwrap();
            assert_eq!(encoded, public_key.to_pem().unwrap());
            assert!(
                encoded.starts_with("-----BEGIN PUBLIC KEY-----\n"),
                "{}",
                encoded,
            );

            let decoded = Pouf1::decode_public_key(
                public_key.typ().clone(),
                public_key.scheme().clone(),
                &encoded,
            )
            .unwrap();

            assert_eq!(&decoded, public_key);
            assert_eq!(decoded.key_id(), public_key.key_id());
        }
    }

    /// A key of a type this crate knows, written in some way it does not, is kept exactly as it
    /// was written rather than taking the surrounding metadata down with it.
    #[test]
    fn a_key_that_cannot_be_decoded_is_kept_opaque() {
        let key = EcdsaPrivateKey::from_pkcs8(ECDSA_P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
            .unwrap();
        let written = HEXLOWER.encode(key.public().as_bytes());

        let decoded =
            Pouf1::decode_public_key(KeyType::Ecdsa, SignatureScheme::EcdsaSha2NistP256, &written)
                .unwrap();

        assert!(decoded.is_opaque());
        assert_ne!(&decoded, key.public());

        // It goes back out byte for byte as it came in...
        assert_eq!(Pouf1::encode_public_key(&decoded).unwrap(), written);

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

    /// A key type this crate does not understand is left exactly as it was written, because this
    /// crate has no idea what it is looking at.
    #[test]
    fn unknown_public_keys_are_left_alone() {
        let key_type = KeyType::Unknown("unknown-keytype".into());
        let scheme = SignatureScheme::Unknown("unknown-scheme".into());
        let public_key =
            PublicKey::new(key_type.clone(), scheme.clone(), b"unknown-key".to_vec()).unwrap();

        let encoded = Pouf1::encode_public_key(&public_key).unwrap();
        assert_eq!(encoded, "unknown-key");

        assert_eq!(
            Pouf1::decode_public_key(key_type, scheme, &encoded).unwrap(),
            public_key,
        );
    }

    /// An ed25519 key written as PEM rather than as hex is not the ed25519 key it claims to be,
    /// so it is kept opaque rather than quietly read in the other pouf's encoding.
    #[test]
    fn an_ed25519_public_key_that_is_not_hex_is_kept_opaque() {
        let key = Ed25519PrivateKey::from_pkcs8(PK8_1).unwrap();
        let written = key.public().to_pem().unwrap();

        let decoded =
            Pouf1::decode_public_key(KeyType::Ed25519, SignatureScheme::Ed25519, &written).unwrap();

        assert!(decoded.is_opaque());
        assert_ne!(&decoded, key.public());
        assert_eq!(Pouf1::encode_public_key(&decoded).unwrap(), written);
    }

    #[test]
    fn write_str() {
        let jsn = Value::String(String::from("wat"));
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, b"\"wat\"");
    }

    #[test]
    fn write_arr() {
        let jsn = Value::Array(vec![
            Value::String(String::from("wat")),
            Value::String(String::from("lol")),
            Value::String(String::from("no")),
        ]);
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, b"[\"wat\",\"lol\",\"no\"]");
    }

    #[test]
    fn write_obj() {
        let mut map = BTreeMap::new();
        let arr = Value::Array(vec![
            Value::String(String::from("haha")),
            Value::String(String::from("new\nline")),
        ]);
        let _ = map.insert(String::from("lol"), arr);
        let jsn = Value::Object(map);
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, &b"{\"lol\":[\"haha\",\"new\nline\"]}");
    }

    #[test]
    fn write_str_edge_cases() {
        let cases = [
            ("", b"\"\"".as_slice()),
            ("wat", b"\"wat\"".as_slice()),
            (
                "hello 🦀 world",
                b"\"hello \xF0\x9F\xA6\x80 world\"".as_slice(),
            ),
            (
                "quote\"and\\backslash",
                b"\"quote\\\"and\\\\backslash\"".as_slice(),
            ),
            ("\"\\\"\\", b"\"\\\"\\\\\\\"\\\\\"".as_slice()),
            ("ctrl \x00 \t \r \n", b"\"ctrl \x00 \t \r \n\"".as_slice()),
        ];

        for (input, expected) in cases {
            let mut out = Vec::new();
            Value::String(input.to_string()).write(&mut out).unwrap();
            assert_eq!(&out, &expected, "Failed on input: {:?}", input);
        }
    }

    #[test]
    fn write_obj_key_edge_cases() {
        let mut map = BTreeMap::new();
        map.insert(
            String::from("key\"with\\slash"),
            Value::Number(Number::I64(1)),
        );
        map.insert(String::from("ctrl\nkey"), Value::Number(Number::I64(2)));
        let jsn = Value::Object(map);
        let mut out = Vec::new();
        jsn.write(&mut out).unwrap();
        assert_eq!(&out, &b"{\"ctrl\nkey\":2,\"key\\\"with\\\\slash\":1}");
    }
}
