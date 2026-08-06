//! Cryptographic structures and functions.

use {
    data_encoding::HEXLOWER,
    futures_io::AsyncRead,
    futures_util::AsyncReadExt as _,
    ring::{
        digest::{self, SHA256, SHA512},
        rand::SystemRandom,
        signature::{ED25519, Ed25519KeyPair, KeyPair},
    },
    serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeserializeError},
    spki::{
        AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
        SubjectPublicKeyInfoRef,
        der::{
            Decode as _, Encode as _,
            asn1::BitString,
            pem::{self, LineEnding, PemLabel as _},
        },
    },
    std::{
        cmp::Ordering,
        collections::HashMap,
        fmt::{self, Debug, Display},
        str::FromStr,
    },
};

use crate::error::{Error, Result};
use crate::metadata::MetadataPath;

const HASH_ALG_PREFS: &[HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha256];

/// `id-Ed25519` as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The PEM label public keys are written with, per
/// [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468#section-13).
pub(crate) const PUBLIC_KEY_PEM_LABEL: &str = SubjectPublicKeyInfoRef::PEM_LABEL;

/// The length of an ed25519 private key in bytes
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an ed25519 public key in bytes
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an ed25519 keypair in bytes
const ED25519_KEYPAIR_LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH + ED25519_PUBLIC_KEY_LENGTH;

fn spki_error(err: impl Display) -> Error {
    Error::Encoding(format!("SPKI: {}", err))
}

fn pem_error(err: impl Display) -> Error {
    Error::Encoding(format!("PEM: {}", err))
}

/// Given a map of hash algorithms and their values and retains the supported
/// hashes. Returns an `Err` if there is no match.
///
/// ```
/// use std::collections::HashMap;
/// use tuf::crypto::{retain_supported_hashes, HashValue, HashAlgorithm};
///
/// let mut map = HashMap::new();
/// assert!(retain_supported_hashes(&map).is_empty());
///
/// let sha512_value = HashValue::new(vec![0x00, 0x01]);
/// let _ = map.insert(HashAlgorithm::Sha512, sha512_value.clone());
/// assert_eq!(
///     retain_supported_hashes(&map),
///     vec![
///         (&HashAlgorithm::Sha512, sha512_value.clone()),
///     ],
/// );
///
/// let sha256_value = HashValue::new(vec![0x02, 0x03]);
/// let _ = map.insert(HashAlgorithm::Sha256, sha256_value.clone());
/// assert_eq!(
///     retain_supported_hashes(&map),
///     vec![
///         (&HashAlgorithm::Sha512, sha512_value.clone()),
///         (&HashAlgorithm::Sha256, sha256_value.clone()),
///     ],
/// );
///
/// let md5_value = HashValue::new(vec![0x04, 0x05]);
/// let _ = map.insert(HashAlgorithm::Unknown("md5".into()), md5_value);
/// assert_eq!(
///     retain_supported_hashes(&map),
///     vec![
///         (&HashAlgorithm::Sha512, sha512_value),
///         (&HashAlgorithm::Sha256, sha256_value),
///     ],
/// );
/// ```
pub fn retain_supported_hashes(
    hashes: &HashMap<HashAlgorithm, HashValue>,
) -> Vec<(&'static HashAlgorithm, HashValue)> {
    let mut data = vec![];
    for alg in HASH_ALG_PREFS {
        if let Some(value) = hashes.get(alg) {
            data.push((alg, value.clone()));
        }
    }

    data
}

#[cfg(test)]
pub(crate) fn calculate_hash(data: &[u8], hash_alg: &HashAlgorithm) -> HashValue {
    let mut context = hash_alg.digest_context().unwrap();
    context.update(data);
    HashValue::new(context.finish().as_ref().to_vec())
}

/// Calculate the size and hash digest from a given `AsyncRead`.
pub fn calculate_hashes_from_slice(
    buf: &[u8],
    hash_algs: &[HashAlgorithm],
) -> Result<HashMap<HashAlgorithm, HashValue>> {
    if hash_algs.is_empty() {
        return Err(Error::IllegalArgument(
            "Cannot provide empty set of hash algorithms".into(),
        ));
    }

    let mut hashes = HashMap::new();
    for alg in hash_algs {
        let mut context = alg.digest_context()?;
        context.update(buf);

        hashes.insert(
            alg.clone(),
            HashValue::new(context.finish().as_ref().to_vec()),
        );
    }

    Ok(hashes)
}

/// Calculate the size and hash digest from a given `AsyncRead`.
pub async fn calculate_hashes_from_reader<R>(
    mut read: R,
    hash_algs: &[HashAlgorithm],
) -> Result<(u64, HashMap<HashAlgorithm, HashValue>)>
where
    R: AsyncRead + Unpin,
{
    if hash_algs.is_empty() {
        return Err(Error::IllegalArgument(
            "Cannot provide empty set of hash algorithms".into(),
        ));
    }

    let mut size = 0;
    let mut hashes = HashMap::new();
    for alg in hash_algs {
        let _ = hashes.insert(alg, alg.digest_context()?);
    }

    let mut buf = vec![0; 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(read_bytes) => {
                if read_bytes == 0 {
                    break;
                }

                size += read_bytes as u64;

                for context in hashes.values_mut() {
                    context.update(&buf[0..read_bytes]);
                }
            }
            e @ Err(_) => e.map(|_| ())?,
        }
    }

    let hashes = hashes
        .drain()
        .map(|(k, v)| (k.clone(), HashValue::new(v.finish().as_ref().to_vec())))
        .collect();
    Ok((size, hashes))
}

/// Derive a key id from the key material itself.
///
/// This is the SHA-256 digest of the key's `SubjectPublicKeyInfo`, which is the same fingerprint
/// [RFC 7469](https://datatracker.ietf.org/doc/html/rfc7469#section-2.4) defines. Key types this
/// crate cannot write a `SubjectPublicKeyInfo` for are digested as-is.
fn calculate_key_id(key_type: &KeyType, public_key: &[u8]) -> Result<KeyId> {
    let bytes = match key_type.oid() {
        Some(_) => write_spki(public_key, key_type)?,
        None => public_key.to_vec(),
    };

    let mut context = digest::Context::new(&SHA256);
    context.update(&bytes);

    Ok(KeyId(HEXLOWER.encode(context.finish().as_ref())))
}

/// Wrapper type for a public key's ID.
///
/// A key id is an opaque identifier that names a key within some metadata. Nothing may be
/// inferred from its contents: two repositories are free to identify the same key differently,
/// and a key id read out of metadata is preserved exactly as it was written.
///
/// If this library needs to calculate a new key id, it uses a SHA-256 digest of the
/// key's `SubjectPublicKeyInfo`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl FromStr for KeyId {
    type Err = Error;

    /// Parse a key ID from a string.
    fn from_str(string: &str) -> Result<Self> {
        if string.is_empty() {
            return Err(Error::IllegalArgument("key ID must not be empty".into()));
        }
        Ok(KeyId(string.to_owned()))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        KeyId::from_str(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Cryptographic signature schemes.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    Ed25519,

    /// Placeholder for an unknown scheme.
    Unknown(String),
}

impl SignatureScheme {
    /// Construct a signature scheme from a `&str`.
    pub fn new(name: &str) -> Self {
        match name {
            "ed25519" => SignatureScheme::Ed25519,
            scheme => SignatureScheme::Unknown(scheme.to_string()),
        }
    }

    /// Return the signature scheme as a `&str`.
    pub fn as_str(&self) -> &str {
        match *self {
            SignatureScheme::Ed25519 => "ed25519",
            SignatureScheme::Unknown(ref s) => s,
        }
    }
}

impl Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SignatureScheme {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SignatureScheme {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        Ok(Self::new(&string))
    }
}

/// Wrapper type for the value of a cryptographic signature.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignatureValue(#[serde(with = "crate::format_hex")] Vec<u8>);

impl SignatureValue {
    /// Create a new `SignatureValue` from the given bytes.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    /// Return the signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SignatureValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

/// Types of public keys.
#[non_exhaustive]
#[derive(Clone, PartialEq, Debug, Eq, Hash)]
pub enum KeyType {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    Ed25519,

    /// Placeholder for an unknown key type.
    Unknown(String),
}

impl KeyType {
    /// Construct a key type from a `&str`.
    pub fn new(name: &str) -> Self {
        match name {
            "ed25519" => KeyType::Ed25519,
            keytype => KeyType::Unknown(keytype.to_string()),
        }
    }

    /// Return the key type as a `&str`.
    pub fn as_str(&self) -> &str {
        match *self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Unknown(ref s) => s,
        }
    }

    /// Return the algorithm identifier this key type is written with inside a
    /// `SubjectPublicKeyInfo`, if this crate knows one.
    fn oid(&self) -> Option<ObjectIdentifier> {
        match *self {
            KeyType::Ed25519 => Some(ED25519_OID),
            KeyType::Unknown(_) => None,
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        Ok(Self::new(&string))
    }
}

/// A structure containing information about a private key.
pub trait PrivateKey {
    /// Sign a message.
    fn sign(&self, msg: &[u8]) -> Result<Signature>;

    /// Return the public component of the key.
    fn public(&self) -> &PublicKey;
}

/// A structure containing information about an Ed25519 private key.
pub struct Ed25519PrivateKey {
    private: Ed25519KeyPair,
    public: PublicKey,
}

impl Ed25519PrivateKey {
    /// Generate Ed25519 key bytes in pkcs8 format.
    pub fn pkcs8() -> Result<Vec<u8>> {
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map(|bytes| bytes.as_ref().to_vec())
            .map_err(|_| Error::Opaque("Failed to generate Ed25519 key".into()))
    }

    /// Create a new `PrivateKey` from an ed25519 keypair. The keypair is a 64 byte slice, where the
    /// first 32 bytes are the ed25519 seed, and the second 32 bytes are the public key.
    pub fn from_ed25519(key: &[u8]) -> Result<Self> {
        if key.len() != ED25519_KEYPAIR_LENGTH {
            return Err(Error::Encoding(
                "ed25519 private keys must be 64 bytes long".into(),
            ));
        }

        let private_key_bytes = &key[..ED25519_PRIVATE_KEY_LENGTH];
        let public_key_bytes = &key[ED25519_PUBLIC_KEY_LENGTH..];

        let private = Ed25519KeyPair::from_seed_and_public_key(private_key_bytes, public_key_bytes)
            .map_err(|err| Error::Encoding(err.to_string()))?;
        Self::from_keypair(private)
    }

    /// Create a private key from PKCS#8v2 DER bytes.
    ///
    /// # Generating Keys
    ///
    /// ```bash
    /// $ touch ed25519-private-key.pk8
    /// $ chmod 0600 ed25519-private-key.pk8
    /// ```
    ///
    /// ```no_run
    /// # use ring::rand::SystemRandom;
    /// # use ring::signature::Ed25519KeyPair;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// #
    /// let mut file = File::open("ed25519-private-key.pk8").unwrap();
    /// let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    /// file.write_all(key.as_ref()).unwrap()
    /// ```
    pub fn from_pkcs8(der_key: &[u8]) -> Result<Self> {
        Self::from_keypair(
            Ed25519KeyPair::from_pkcs8(der_key)
                .map_err(|_| Error::Encoding("Could not parse key as PKCS#8v2".into()))?,
        )
    }

    fn from_keypair(private: Ed25519KeyPair) -> Result<Self> {
        let public = PublicKey::new(
            KeyType::Ed25519,
            SignatureScheme::Ed25519,
            private.public_key().as_ref().to_vec(),
        )?;

        Ok(Ed25519PrivateKey { private, public })
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn sign(&self, msg: &[u8]) -> Result<Signature> {
        debug_assert!(self.public.scheme == SignatureScheme::Ed25519);

        let value = SignatureValue(self.private.sign(msg).as_ref().into());
        Ok(Signature {
            key_id: self.public.key_id().clone(),
            value,
        })
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// A structure containing information about a public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    typ: KeyType,
    key_id: KeyId,
    scheme: SignatureScheme,
    value: PublicKeyValue,
}

impl PublicKey {
    /// Create a public key from a key type, a signing scheme, and the key's raw bytes.
    ///
    /// The key is named by [deriving a key id](KeyId) from its own bytes. Use
    /// [`with_key_id`](Self::with_key_id) to name it something else.
    pub fn new(typ: KeyType, scheme: SignatureScheme, value: Vec<u8>) -> Result<Self> {
        if typ == KeyType::Ed25519 && value.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(Error::IllegalArgument(
                "ed25519 keys must be 32 bytes long".into(),
            ));
        }

        let key_id = calculate_key_id(&typ, &value)?;
        let value = PublicKeyValue(value);
        Ok(PublicKey {
            typ,
            key_id,
            scheme,
            value,
        })
    }

    /// Name this key with the given key id.
    ///
    /// Key ids are opaque, so metadata is free to identify a key however it likes.
    pub fn with_key_id(mut self, key_id: KeyId) -> Self {
        self.key_id = key_id;
        self
    }

    /// Parse DER bytes as a `SubjectPublicKeyInfo` key.
    pub fn from_spki(der_bytes: &[u8], scheme: SignatureScheme) -> Result<Self> {
        let typ = match scheme {
            SignatureScheme::Ed25519 => KeyType::Ed25519,
            SignatureScheme::Unknown(s) => {
                return Err(Error::UnknownSignatureScheme(s));
            }
        };

        let value = read_spki(der_bytes, &typ)?;

        Self::new(typ, scheme, value)
    }

    /// Parse a PEM encoded `SubjectPublicKeyInfo` key.
    ///
    /// Returns [`Error::UnknownKeyType`] for a key type this crate cannot read a
    /// `SubjectPublicKeyInfo` for.
    pub fn from_pem(pem: &str, typ: KeyType, scheme: SignatureScheme) -> Result<Self> {
        if typ.oid().is_none() {
            return Err(Error::UnknownKeyType(typ.to_string()));
        }

        let (label, der) = pem::decode_vec(pem.as_bytes()).map_err(pem_error)?;

        if label != PUBLIC_KEY_PEM_LABEL {
            return Err(Error::Encoding(format!(
                "PEM: expected a {:?} block, found {:?}",
                PUBLIC_KEY_PEM_LABEL, label,
            )));
        }

        let value = read_spki(&der, &typ)?;

        Self::new(typ, scheme, value)
    }

    /// Write the public key as `SubjectPublicKeyInfo` DER bytes.
    pub fn as_spki(&self) -> Result<Vec<u8>> {
        write_spki(&self.value.0, &self.typ)
    }

    /// Write the public key as a PEM encoded `SubjectPublicKeyInfo`.
    ///
    /// Returns [`Error::UnknownKeyType`] for a key type this crate cannot write a
    /// `SubjectPublicKeyInfo` for.
    pub fn to_pem(&self) -> Result<String> {
        pem::encode_string(PUBLIC_KEY_PEM_LABEL, LineEnding::LF, &self.as_spki()?)
            .map_err(pem_error)
    }

    /// Parse ED25519 bytes as a public key.
    pub fn from_ed25519<T: Into<Vec<u8>>>(bytes: T) -> Result<Self> {
        Self::new(KeyType::Ed25519, SignatureScheme::Ed25519, bytes.into())
    }

    /// An immutable reference to the key's type.
    pub fn typ(&self) -> &KeyType {
        &self.typ
    }

    /// An immutable referece to the key's authorized signing scheme.
    pub fn scheme(&self) -> &SignatureScheme {
        &self.scheme
    }

    /// An immutable reference to the key's ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Return the public key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value.0
    }

    /// Use this key to verify a message with a signature.
    pub fn verify(&self, role: &MetadataPath, msg: &[u8], sig: &Signature) -> Result<()> {
        let alg: &dyn ring::signature::VerificationAlgorithm = match self.scheme {
            SignatureScheme::Ed25519 => &ED25519,
            SignatureScheme::Unknown(ref s) => {
                return Err(Error::UnknownSignatureScheme(s.to_string()));
            }
        };

        let key = ring::signature::UnparsedPublicKey::new(alg, &self.value.0);
        key.verify(msg, &sig.value.0)
            .map_err(|_| Error::BadSignature(role.clone()))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_id.cmp(&other.key_id)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Hash, Eq)]
struct PublicKeyValue(Vec<u8>);

impl Debug for PublicKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("PublicKeyValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

/// A structure that contains a `Signature` and associated data for verifying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename = "keyid")]
    key_id: KeyId,
    #[serde(rename = "sig")]
    value: SignatureValue,
}

impl Signature {
    /// Create a new `Signature` from a `KeyId` and a `SignatureValue`.
    ///
    /// Note: It is unlikely that you ever want to do this manually. This exists so that
    /// [Pouf](crate::pouf::Pouf) implementations can reconstruct the signatures they read out of
    /// their wire format.
    pub fn new(key_id: KeyId, value: SignatureValue) -> Self {
        Signature { key_id, value }
    }

    /// An immutable reference to the `KeyId` of the key that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn value(&self) -> &SignatureValue {
        &self.value
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.key_id, &self.value).cmp(&(&other.key_id, &other.value))
    }
}

/// The available hash algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA256 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA512 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha512")]
    Sha512,
    /// Placeholder for an unknown hash algorithm.
    Unknown(String),
}

impl HashAlgorithm {
    /// Create a new `digest::Context` suitable for computing the hash of some data using this hash
    /// algorithm.
    pub(crate) fn digest_context(&self) -> Result<digest::Context> {
        match self {
            HashAlgorithm::Sha256 => Ok(digest::Context::new(&SHA256)),
            HashAlgorithm::Sha512 => Ok(digest::Context::new(&SHA512)),
            HashAlgorithm::Unknown(s) => Err(Error::IllegalArgument(format!(
                "Unknown hash algorithm: {}",
                s
            ))),
        }
    }
}

/// Wrapper for the value of a hash digest.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HashValue(#[serde(with = "crate::format_hex")] Vec<u8>);

impl HashValue {
    /// Create a new `HashValue` from the given digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        HashValue(bytes)
    }

    /// An immutable reference to the bytes of the hash value.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("HashValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

/// Write a key's raw bytes as `SubjectPublicKeyInfo` DER bytes.
pub(crate) fn write_spki(public: &[u8], key_type: &KeyType) -> Result<Vec<u8>> {
    let Some(oid) = key_type.oid() else {
        return Err(Error::UnknownKeyType(key_type.to_string()));
    };

    let spki = SubjectPublicKeyInfoOwned {
        // RFC 8410 §3: for the id-Ed25519 algorithm the parameters must be absent.
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        },
        subject_public_key: BitString::new(0, public).map_err(spki_error)?,
    };

    spki.to_der().map_err(spki_error)
}

/// Read a key's raw bytes out of `SubjectPublicKeyInfo` DER bytes.
pub(crate) fn read_spki(der_bytes: &[u8], key_type: &KeyType) -> Result<Vec<u8>> {
    let Some(oid) = key_type.oid() else {
        return Err(Error::UnknownKeyType(key_type.to_string()));
    };

    let spki = SubjectPublicKeyInfoRef::from_der(der_bytes).map_err(spki_error)?;

    if spki.algorithm.oid != oid {
        return Err(Error::Encoding(format!(
            "SPKI: expected a {} key ({}), found {}",
            key_type, oid, spki.algorithm.oid,
        )));
    }

    // Older versions of this crate wrote out an explicit NULL for the ed25519 algorithm's
    // parameters, which RFC 8410 §3 says must be absent, so both spellings are accepted here.

    spki.subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Encoding("SPKI: public key is not a whole number of bytes".into()))
        .map(|bytes| bytes.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
    use serde_json::{self, json};

    mod ed25519 {
        pub(super) const PRIVATE_KEY: &[u8] = include_bytes!("../tests/ed25519/ed25519-1");
        pub(super) const PUBLIC_KEY: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pub");
        pub(super) const PK8_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
        pub(super) const SPKI_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.spki.der");
        pub(super) const PK8_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    }

    #[test]
    fn parse_public_ed25519_spki() {
        let key = PublicKey::from_spki(ed25519::SPKI_1, SignatureScheme::Ed25519).unwrap();
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
        assert_eq!(key.as_bytes(), ed25519::PUBLIC_KEY);
    }

    /// Earlier versions of this crate wrote an explicit NULL for the ed25519 algorithm's
    /// parameters, which RFC 8410 says must be absent. Keys written that way must still parse.
    #[test]
    fn parse_public_ed25519_spki_with_null_parameters() {
        let mut der = vec![
            0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(ed25519::PUBLIC_KEY);

        let key = PublicKey::from_spki(&der, SignatureScheme::Ed25519).unwrap();
        assert_eq!(key.as_bytes(), ed25519::PUBLIC_KEY);

        // ... but they are rewritten without it.
        assert_ne!(key.as_spki().unwrap(), der);
        assert_eq!(
            key.as_spki().unwrap(),
            PublicKey::from_ed25519(ed25519::PUBLIC_KEY)
                .unwrap()
                .as_spki()
                .unwrap(),
        );
    }

    #[test]
    fn parse_public_ed25519() {
        let key = PublicKey::from_ed25519(ed25519::PUBLIC_KEY).unwrap();
        assert_eq!(
            key.key_id(),
            &KeyId::from_str("061627f2f863b7d4437ba1abe099d9732b19b961e8d7550f799ac77c1c0c589f")
                .unwrap()
        );
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn parse_public_ed25519_rejects_the_wrong_length() {
        assert_matches!(
            PublicKey::from_ed25519(vec![0; 31]),
            Err(Error::IllegalArgument(_))
        );
    }

    /// A key that is not named by the metadata that carries it is named by the digest of its
    /// `SubjectPublicKeyInfo`.
    #[test]
    fn key_id_is_derived_from_the_key_material() {
        let key = PublicKey::from_ed25519(ed25519::PUBLIC_KEY).unwrap();

        let mut context = digest::Context::new(&SHA256);
        context.update(&key.as_spki().unwrap());

        assert_eq!(
            key.key_id(),
            &KeyId::from_str(&HEXLOWER.encode(context.finish().as_ref())).unwrap(),
        );

        // Reading the same key back out of any encoding names it the same way.
        assert_eq!(
            PublicKey::from_pem(
                &key.to_pem().unwrap(),
                KeyType::Ed25519,
                SignatureScheme::Ed25519
            )
            .unwrap()
            .key_id(),
            key.key_id(),
        );
    }

    /// Key ids are opaque, so metadata is free to call a key whatever it likes.
    #[test]
    fn key_id_can_be_overridden() {
        let key = PublicKey::from_ed25519(ed25519::PUBLIC_KEY).unwrap();
        let derived = key.key_id().clone();

        let legacy = KeyId::from_str("legacy_key_id_that_can_be_an_arbitrary_value").unwrap();
        let renamed = key.clone().with_key_id(legacy.clone());

        assert_ne!(derived, legacy);
        assert_eq!(renamed.key_id(), &legacy);

        // It is still the same key, though.
        assert_eq!(renamed.value, key.value);
    }

    #[test]
    fn ed25519_read_pkcs8_and_sign() {
        let key = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_1).unwrap();
        let msg = b"test";

        let sig = key.sign(msg).unwrap();

        let pub_key =
            PublicKey::from_spki(&key.public.as_spki().unwrap(), SignatureScheme::Ed25519).unwrap();

        let role = MetadataPath::root();
        assert_matches!(pub_key.verify(&role, msg, &sig), Ok(()));

        // Make sure we match what ring expects.
        let ring_key = ring::signature::Ed25519KeyPair::from_pkcs8(ed25519::PK8_1).unwrap();
        assert_eq!(key.public().as_bytes(), ring_key.public_key().as_ref());
        assert_eq!(sig.value().as_bytes(), ring_key.sign(msg).as_ref());

        // Make sure verification fails with the wrong key.
        let bad_pub_key = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_2)
            .unwrap()
            .public()
            .clone();

        assert_matches!(
            bad_pub_key.verify(&role, msg, &sig),
            Err(Error::BadSignature(r))
            if r == role
        );
    }

    #[test]
    fn ed25519_read_keypair_and_sign() {
        let key = Ed25519PrivateKey::from_ed25519(ed25519::PRIVATE_KEY).unwrap();
        let pub_key = PublicKey::from_ed25519(ed25519::PUBLIC_KEY).unwrap();
        assert_eq!(key.public(), &pub_key);

        let role = MetadataPath::root();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        assert_matches!(pub_key.verify(&role, msg, &sig), Ok(()));

        // Make sure we match what ring expects.
        let ring_key = ring::signature::Ed25519KeyPair::from_pkcs8(ed25519::PK8_1).unwrap();
        assert_eq!(key.public().as_bytes(), ring_key.public_key().as_ref());
        assert_eq!(sig.value().as_bytes(), ring_key.sign(msg).as_ref());

        // Make sure verification fails with the wrong key.
        let bad_pub_key = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_2)
            .unwrap()
            .public()
            .clone();

        assert_matches!(
            bad_pub_key.verify(&role, msg, &sig),
            Err(Error::BadSignature(r))
            if r == role
        );
    }

    #[test]
    fn unknown_keytype_cannot_verify() {
        let pub_key = PublicKey::new(
            KeyType::Unknown("unknown-keytype".into()),
            SignatureScheme::Unknown("unknown-scheme".into()),
            b"unknown-key".to_vec(),
        )
        .unwrap();
        let role = MetadataPath::root();
        let msg = b"test";
        let sig = Signature {
            key_id: KeyId("key-id".into()),
            value: SignatureValue(b"sig-value".to_vec()),
        };

        assert_matches!(
            pub_key.verify(&role, msg, &sig),
            Err(Error::UnknownSignatureScheme(s))
            if s == "unknown-scheme"
        );
    }

    #[test]
    fn serde_key_id() {
        let s = "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db";
        let jsn = json!(s);
        let parsed: KeyId = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, KeyId::from_str(s).unwrap());
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    #[test]
    fn serde_key_type() {
        let jsn = json!("ed25519");
        let parsed: KeyType = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, KeyType::Ed25519);

        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);

        let jsn = json!("unknown");
        let parsed: KeyType = serde_json::from_value(jsn).unwrap();
        assert_eq!(parsed, KeyType::Unknown("unknown".into()));
    }

    #[test]
    fn serde_signature_scheme() {
        let jsn = json!("ed25519");
        let parsed: SignatureScheme = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, SignatureScheme::Ed25519);

        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);

        let jsn = json!("unknown");
        let parsed: SignatureScheme = serde_json::from_value(jsn).unwrap();
        assert_eq!(parsed, SignatureScheme::Unknown("unknown".into()));
    }

    #[test]
    fn serde_signature_value() {
        let s = "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db";
        let jsn = json!(s);
        let parsed: SignatureValue = serde_json::from_str(&format!("\"{}\"", s)).unwrap();
        assert_eq!(
            parsed,
            SignatureValue(HEXLOWER.decode(s.as_bytes()).unwrap())
        );
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    /// There is no `SubjectPublicKeyInfo` this crate can write for a key type it does not
    /// understand, and inventing one would misrepresent bytes it cannot read.
    #[test]
    fn pem_rejects_an_unknown_key_type() {
        let key_type = KeyType::Unknown("unknown-keytype".into());
        let scheme = SignatureScheme::Unknown("unknown-scheme".into());
        let pub_key =
            PublicKey::new(key_type.clone(), scheme.clone(), b"unknown-key".to_vec()).unwrap();

        assert_matches!(pub_key.to_pem(), Err(Error::UnknownKeyType(t)) if t == "unknown-keytype");
        assert_matches!(
            PublicKey::from_pem("unknown-key", key_type, scheme),
            Err(Error::UnknownKeyType(t)) if t == "unknown-keytype"
        );
    }

    #[test]
    fn from_pem_rejects_a_block_that_is_not_a_public_key() {
        assert_matches!(
            PublicKey::from_pem(
                "-----BEGIN PRIVATE KEY-----\nbG9s\n-----END PRIVATE KEY-----\n",
                KeyType::Ed25519,
                SignatureScheme::Ed25519,
            ),
            Err(Error::Encoding(_))
        );
    }

    #[test]
    fn serde_signature() {
        let key = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_1).unwrap();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        let encoded = serde_json::to_value(&sig).unwrap();
        let jsn = json!({
            "keyid": key.public().key_id().to_string(),
            "sig": "fe4d13b2a73c033a1de7f5107b205fc7ba0e1566cb95b92349cae6aa453\
                8956013bfe0f7bf977cb072bb65e8782b5f33a0573fe78816299a017ca5ba55\
                9e390c",
        });
        assert_eq!(encoded, jsn);

        let decoded: Signature = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn new_ed25519_key() {
        let bytes = Ed25519PrivateKey::pkcs8().unwrap();
        let _ = Ed25519PrivateKey::from_pkcs8(&bytes).unwrap();
    }

    #[test]
    fn test_ed25519_public_key_eq() {
        let key1 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_1).unwrap();
        let key2 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_2).unwrap();

        assert_eq!(key1.public(), key1.public());
        assert_ne!(key1.public(), key2.public());
    }

    fn check_public_key_hash(key1: &PublicKey, key2: &PublicKey) {
        use std::hash::BuildHasher;

        let state = std::collections::hash_map::RandomState::new();

        assert_ne!(state.hash_one(key1), state.hash_one(key2));
    }

    #[test]
    fn test_ed25519_public_key_hash() {
        let key1 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_1).unwrap();
        let key2 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_2).unwrap();

        check_public_key_hash(key1.public(), key2.public());
    }
}
