//! Cryptographic structures and functions.

use {
    data_encoding::HEXLOWER,
    futures_io::AsyncRead,
    futures_util::AsyncReadExt as _,
    ring::{
        digest::{self, SHA256, SHA512},
        signature::VerificationAlgorithm,
    },
    serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeserializeError},
    spki::{
        AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
        SubjectPublicKeyInfoRef,
        der::{
            Decode as _, Encode as _,
            asn1::{Any, BitString, Null},
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

mod ecdsa;
mod ed25519;
mod rsa;

pub use ecdsa::EcdsaPrivateKey;
pub use ed25519::Ed25519PrivateKey;
pub use rsa::RsaPrivateKey;

const HASH_ALG_PREFS: &[HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha256];

/// The PEM label public keys are written with, per
/// [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468#section-13).
pub(crate) const PUBLIC_KEY_PEM_LABEL: &str = SubjectPublicKeyInfoRef::PEM_LABEL;

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

/// A way of writing key material.
///
/// This names how a key's bytes are encoded - and so how it is recognized, checked, and written
/// back out - which is a separate question from which signatures it can check. A single algorithm
/// may sign under several schemes, and adding one of those does not touch this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum KeyAlgorithm {
    Ed25519,
    NistP256,
    Rsa,
}

/// Every key algorithm this crate implements.
///
/// Adding one means adding its module, its spec, and an entry here. Nothing else dispatches on
/// the algorithm.
const ALL_KEY_ALGORITHMS: &[KeyAlgorithm] = &[
    KeyAlgorithm::Ed25519,
    KeyAlgorithm::NistP256,
    KeyAlgorithm::Rsa,
];

impl KeyAlgorithm {
    /// The algorithm a `SubjectPublicKeyInfo` says its key is, or `None` if this crate does not
    /// implement it.
    ///
    /// A `SubjectPublicKeyInfo` names its own algorithm, so nothing has to be assumed about what
    /// a key of some TUF key type looks like: two ECDSA curves, or two RSA variants, are told
    /// apart by what the key itself says.
    fn for_spki(oid: ObjectIdentifier, parameters: Option<ObjectIdentifier>) -> Option<Self> {
        ALL_KEY_ALGORITHMS
            .iter()
            .copied()
            .find(|algorithm| algorithm.oids() == (oid, parameters))
    }

    /// The algorithm that raw key material of the given type, signing under the given scheme, is
    /// written as.
    ///
    /// This is for the encodings that are not self describing, such as the bare ed25519 bytes
    /// POUF-1 writes. Where a key type has more than one encoding the scheme is what tells them
    /// apart, and where it has only one that is the answer whatever the scheme says - so a scheme
    /// this crate has not implemented still leaves the key readable, and merely unusable.
    fn for_key_material(key_type: &KeyType, scheme: &SignatureScheme) -> Option<Self> {
        let of_type = || {
            ALL_KEY_ALGORITHMS
                .iter()
                .copied()
                .filter(|algorithm| algorithm.spec().key_type == key_type.as_str())
        };

        if let Some(algorithm) = of_type().find(|a| a.verification_algorithm(scheme).is_some()) {
            return Some(algorithm);
        }

        let mut candidates = of_type();

        match (candidates.next(), candidates.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        }
    }

    /// Everything this crate knows about how keys of this algorithm are written and checked.
    fn spec(self) -> &'static AlgorithmSpec {
        match self {
            KeyAlgorithm::Ed25519 => &ed25519::SPEC,
            KeyAlgorithm::NistP256 => &ecdsa::NIST_P256_SPEC,
            KeyAlgorithm::Rsa => &rsa::SPEC,
        }
    }

    /// The algorithm OID, and the parameters OID if this algorithm takes one, that name keys of
    /// this algorithm inside a `SubjectPublicKeyInfo`.
    ///
    /// This is the form used to recognize a key that has been read. The `NULL` parameters that
    /// [`algorithm_identifier`](Self::algorithm_identifier) writes for an RSA key read back as
    /// absent, which is how they are spelled here.
    fn oids(self) -> (ObjectIdentifier, Option<ObjectIdentifier>) {
        let spec = self.spec();

        (spec.oid, spec.parameters.oid())
    }

    /// The `AlgorithmIdentifier` that names keys of this algorithm inside a
    /// `SubjectPublicKeyInfo`.
    fn algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned> {
        let spec = self.spec();

        Ok(AlgorithmIdentifierOwned {
            oid: spec.oid,
            parameters: spec.parameters.encode()?,
        })
    }

    /// The algorithm a signature made by this key under `scheme` is checked with, or `None` if
    /// this crate cannot check that pairing.
    fn verification_algorithm(
        self,
        scheme: &SignatureScheme,
    ) -> Option<&'static dyn VerificationAlgorithm> {
        (self.spec().verification)(scheme)
    }

    /// Check that `public` is shaped like a public key of this algorithm.
    ///
    /// This rejects the mistakes that are worth catching early, such as a key on the wrong curve
    /// or a key that was written in some encoding other than the one the metadata claims. It is
    /// not a substitute for the validation the verification algorithm does.
    fn check_public_key(self, public: &[u8]) -> Result<()> {
        (self.spec().check_public_key)(public)
    }

    fn name(self) -> &'static str {
        self.spec().name
    }
}

/// What this crate needs to know about one key algorithm.
///
/// Each algorithm this crate implements lives in its own module and describes itself with one of
/// these, so that the parts that are common to all of them - naming a key, writing it as a
/// `SubjectPublicKeyInfo`, checking a signature with it - have nothing algorithm specific in them.
struct AlgorithmSpec {
    /// What this algorithm is called in error messages.
    name: &'static str,

    /// The TUF key type that keys of this algorithm are spelled with.
    ///
    /// Several algorithms may share one, as two ECDSA curves would: the key type says what kind
    /// of key it is, not how it is parameterized.
    key_type: &'static str,

    /// The OID that names keys of this algorithm inside a `SubjectPublicKeyInfo`.
    oid: ObjectIdentifier,

    /// How that algorithm identifier spells its parameters.
    parameters: AlgorithmParameters,

    /// The algorithm a signature made under some scheme is checked with, if these keys can sign
    /// that way. Teaching an algorithm a further scheme is a matter for this function alone.
    verification: fn(&SignatureScheme) -> Option<&'static dyn VerificationAlgorithm>,

    /// Check that some bytes are shaped like a public key of this algorithm.
    check_public_key: fn(&[u8]) -> Result<()>,
}

/// The parameters of a key algorithm's `AlgorithmIdentifier`.
///
/// Which of these an algorithm uses is fixed by its own specification, and getting it wrong
/// produces a key that other implementations will not read.
enum AlgorithmParameters {
    /// The parameters must be absent.
    Absent,

    /// The parameters must be present, and must be `NULL`.
    Null,

    /// The parameters name something, such as the curve an elliptic curve key lies on.
    Oid(ObjectIdentifier),
}

impl AlgorithmParameters {
    /// The parameters as they are compared when reading a key.
    ///
    /// An explicit `NULL` reads back the same as absent parameters, so both are `None` here.
    fn oid(&self) -> Option<ObjectIdentifier> {
        match *self {
            AlgorithmParameters::Absent | AlgorithmParameters::Null => None,
            AlgorithmParameters::Oid(oid) => Some(oid),
        }
    }

    /// The parameters as they are written out.
    fn encode(&self) -> Result<Option<Any>> {
        match *self {
            AlgorithmParameters::Absent => Ok(None),
            AlgorithmParameters::Null => Any::encode_from(&Null).map(Some).map_err(spki_error),
            AlgorithmParameters::Oid(oid) => Any::encode_from(&oid).map(Some).map_err(spki_error),
        }
    }
}

/// Derive a key id from the key material itself.
///
/// This is the SHA-256 digest of the key's `SubjectPublicKeyInfo`, which is the same fingerprint
/// [RFC 7469](https://datatracker.ietf.org/doc/html/rfc7469#section-2.4) defines. A key this
/// crate cannot write a `SubjectPublicKeyInfo` for is named by [`PublicKey::opaque`] instead.
fn calculate_key_id(algorithm: KeyAlgorithm, public_key: &[u8]) -> Result<KeyId> {
    let bytes = write_spki(public_key, algorithm)?;

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

impl KeyId {
    /// Return the key ID as a `&str`.
    ///
    /// A key id is written into metadata verbatim and compared verbatim, so callers need to
    /// reach the string itself and not only a formatted copy of it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

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

    /// ECDSA over NIST P-256 with SHA-256, signature values encoded as an ASN.1
    /// `Ecdsa-Sig-Value`.
    EcdsaSha2NistP256,

    /// RSASSA-PSS with SHA-256 as both the message digest and the MGF1 digest, and a salt as
    /// long as that digest.
    RsassaPssSha256,

    /// Placeholder for an unknown scheme.
    Unknown(String),
}

impl SignatureScheme {
    /// Construct a signature scheme from a `&str`.
    pub fn new(name: &str) -> Self {
        match name {
            "ed25519" => SignatureScheme::Ed25519,
            "ecdsa-sha2-nistp256" => SignatureScheme::EcdsaSha2NistP256,
            "rsassa-pss-sha256" => SignatureScheme::RsassaPssSha256,
            scheme => SignatureScheme::Unknown(scheme.to_string()),
        }
    }

    /// Return the signature scheme as a `&str`.
    pub fn as_str(&self) -> &str {
        match *self {
            SignatureScheme::Ed25519 => "ed25519",
            SignatureScheme::EcdsaSha2NistP256 => "ecdsa-sha2-nistp256",
            SignatureScheme::RsassaPssSha256 => "rsassa-pss-sha256",
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

    /// [ECDSA](https://csrc.nist.gov/pubs/fips/186-5/final) over a NIST prime curve.
    ///
    /// The curve is named by the [`SignatureScheme`] the key is used with, not by the key type.
    Ecdsa,

    /// [RSA](https://datatracker.ietf.org/doc/html/rfc8017).
    ///
    /// How the key signs is named by the [`SignatureScheme`] it is used with.
    Rsa,

    /// Placeholder for an unknown key type.
    Unknown(String),
}

impl KeyType {
    /// Construct a key type from a `&str`.
    pub fn new(name: &str) -> Self {
        match name {
            "ed25519" => KeyType::Ed25519,
            "ecdsa" => KeyType::Ecdsa,
            "rsa" => KeyType::Rsa,
            // Older TUF metadata spelled an ECDSA key type with the curve baked into it. It names
            // the same kind of key, and the curve is carried by the scheme either way, so such a
            // key is read as an ordinary `ecdsa` key. Note that this crate then writes the key
            // back out under the modern spelling.
            "ecdsa-sha2-nistp256" => KeyType::Ecdsa,
            keytype => KeyType::Unknown(keytype.to_string()),
        }
    }

    /// Return the key type as a `&str`.
    pub fn as_str(&self) -> &str {
        match *self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Ecdsa => "ecdsa",
            KeyType::Rsa => "rsa",
            KeyType::Unknown(ref s) => s,
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
        // A key this crate cannot place is one whose bytes it cannot interpret, so it can only be
        // carried through opaquely.
        let Some(algorithm) = KeyAlgorithm::for_key_material(&typ, &scheme) else {
            return Ok(Self::opaque(typ, scheme, value));
        };

        Self::known(algorithm, typ, scheme, value)
    }

    /// Create a key whose algorithm has already been settled.
    fn known(
        algorithm: KeyAlgorithm,
        typ: KeyType,
        scheme: SignatureScheme,
        value: Vec<u8>,
    ) -> Result<Self> {
        algorithm.check_public_key(&value)?;

        Ok(PublicKey {
            key_id: calculate_key_id(algorithm, &value)?,
            typ,
            scheme,
            value: PublicKeyValue::Known {
                algorithm,
                bytes: value,
            },
        })
    }

    /// Create a key this crate cannot interpret from the bytes the metadata carried.
    ///
    /// The key is named by the digest of those bytes, is handed back by
    /// [`as_bytes`](Self::as_bytes) exactly as it came in, and can never verify a signature. This
    /// is how a [pouf](crate::pouf::Pouf) carries a key whose type or encoding it does not
    /// understand without making the rest of the metadata unreadable.
    pub fn opaque(typ: KeyType, scheme: SignatureScheme, value: Vec<u8>) -> Self {
        let mut context = digest::Context::new(&SHA256);
        context.update(&value);

        PublicKey {
            typ,
            key_id: KeyId(HEXLOWER.encode(context.finish().as_ref())),
            scheme,
            value: PublicKeyValue::Opaque(value),
        }
    }

    /// Whether this crate failed to make sense of this key when it was read.
    ///
    /// Such a key is inert: it cannot verify a signature, and it cannot be written as anything
    /// other than the bytes it arrived as.
    pub fn is_opaque(&self) -> bool {
        matches!(self.value, PublicKeyValue::Opaque(_))
    }

    /// Name this key with the given key id.
    ///
    /// Key ids are opaque, so metadata is free to identify a key however it likes.
    pub fn with_key_id(mut self, key_id: KeyId) -> Self {
        self.key_id = key_id;
        self
    }

    /// Parse DER bytes as a `SubjectPublicKeyInfo` key.
    ///
    /// The key type is whatever the encoded key says it is; `scheme` only records how the key is
    /// authorized to sign.
    pub fn from_spki(der_bytes: &[u8], scheme: SignatureScheme) -> Result<Self> {
        let (algorithm, value) = read_spki(der_bytes)?;
        let typ = KeyType::new(algorithm.spec().key_type);

        Self::known(algorithm, typ, scheme, value)
    }

    /// Parse a PEM encoded `SubjectPublicKeyInfo` key.
    ///
    /// Returns [`Error::UnknownKeyType`] for a key type this crate cannot read a
    /// `SubjectPublicKeyInfo` for.
    pub fn from_pem(pem: &str, typ: KeyType, scheme: SignatureScheme) -> Result<Self> {
        // A key type this crate has never heard of is one no encoded key can be read as.
        if matches!(typ, KeyType::Unknown(_)) {
            return Err(Error::UnknownKeyType(typ.to_string()));
        }

        let (label, der) = pem::decode_vec(pem.as_bytes()).map_err(pem_error)?;

        if label != PUBLIC_KEY_PEM_LABEL {
            return Err(Error::Encoding(format!(
                "PEM: expected a {:?} block, found {:?}",
                PUBLIC_KEY_PEM_LABEL, label,
            )));
        }

        let (algorithm, value) = read_spki(&der)?;

        // The metadata says what kind of key this is meant to be, and the key itself says what it
        // is. Where they disagree, one of the two is wrong, and neither is worth guessing at.
        if algorithm.spec().key_type != typ.as_str() {
            return Err(Error::Encoding(format!(
                "SPKI: metadata calls this a {} key, but it is {}",
                typ,
                algorithm.name(),
            )));
        }

        Self::known(algorithm, typ, scheme, value)
    }

    /// Write the public key as `SubjectPublicKeyInfo` DER bytes.
    ///
    /// Returns [`Error::UnknownKeyType`] for an [opaque](Self::is_opaque) key, whose bytes this
    /// crate never understood well enough to re-encode.
    pub fn as_spki(&self) -> Result<Vec<u8>> {
        match self.value {
            PublicKeyValue::Known {
                algorithm,
                ref bytes,
            } => write_spki(bytes, algorithm),
            PublicKeyValue::Opaque(_) => Err(Error::UnknownKeyType(self.typ.to_string())),
        }
    }

    /// Write the public key as a PEM encoded `SubjectPublicKeyInfo`.
    ///
    /// Returns [`Error::UnknownKeyType`] for a key type this crate cannot write a
    /// `SubjectPublicKeyInfo` for.
    pub fn to_pem(&self) -> Result<String> {
        pem::encode_string(PUBLIC_KEY_PEM_LABEL, LineEnding::LF, &self.as_spki()?)
            .map_err(pem_error)
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
        self.value.as_bytes()
    }

    /// Use this key to verify a message with a signature.
    pub fn verify(&self, role: &MetadataPath, msg: &[u8], sig: &Signature) -> Result<()> {
        self.verify_bytes(msg, &sig.value.0).map_err(|err| match err {
            // The caller knows which role this was, and the error should say so.
            Error::SignatureVerificationFailed => Error::BadSignature(role.clone()),
            other => other,
        })
    }

    /// Use this key to verify a detached signature over `msg`.
    ///
    /// [`verify`](Self::verify) is the same check for a signature that came out of
    /// metadata, where there is a role to name in the error.
    pub fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        // A key that was never understood cannot check anything, whatever it claims to be.
        let PublicKeyValue::Known {
            algorithm,
            ref bytes,
        } = self.value
        else {
            return Err(Error::UnknownKeyType(self.typ.to_string()));
        };

        // Whether this key can check this signature is a question about the scheme it is
        // authorized to sign with, so an unusable pairing is reported as an unusable scheme.
        let Some(verification) = algorithm.verification_algorithm(&self.scheme) else {
            return Err(match self.scheme {
                SignatureScheme::Unknown(ref s) => Error::UnknownSignatureScheme(s.clone()),
                ref scheme => Error::IllegalArgument(format!(
                    "a {} key cannot verify a {} signature",
                    self.typ, scheme,
                )),
            });
        };

        ring::signature::UnparsedPublicKey::new(verification, bytes)
            .verify(msg, sig)
            .map_err(|_| Error::SignatureVerificationFailed)
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

/// The key material of a [`PublicKey`].
#[derive(Clone, PartialEq, Hash, Eq)]
enum PublicKeyValue {
    /// Key material this crate understands, in the form its algorithm defines.
    ///
    /// The algorithm is settled once, when the key is read, and carried along with the bytes. It
    /// is never re-derived from the key type, which could not tell two ECDSA curves apart.
    Known {
        algorithm: KeyAlgorithm,
        bytes: Vec<u8>,
    },

    /// A key this crate could not interpret, exactly as the metadata wrote it.
    Opaque(Vec<u8>),
}

impl PublicKeyValue {
    fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKeyValue::Known { bytes, .. } | PublicKeyValue::Opaque(bytes) => bytes,
        }
    }
}

impl Debug for PublicKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            PublicKeyValue::Known { .. } => "PublicKeyValue",
            PublicKeyValue::Opaque(_) => "OpaquePublicKeyValue",
        };

        f.debug_tuple(name)
            .field(&HEXLOWER.encode(self.as_bytes()))
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
fn write_spki(public: &[u8], algorithm: KeyAlgorithm) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: algorithm.algorithm_identifier()?,
        subject_public_key: BitString::new(0, public).map_err(spki_error)?,
    };

    spki.to_der().map_err(spki_error)
}

/// Read a key out of `SubjectPublicKeyInfo` DER bytes, along with the algorithm it says it is.
fn read_spki(der_bytes: &[u8]) -> Result<(KeyAlgorithm, Vec<u8>)> {
    let spki = SubjectPublicKeyInfoRef::from_der(der_bytes).map_err(spki_error)?;

    // `oids` reads the parameters as the curve name they are for an elliptic curve key, and
    // reports an explicit NULL as absent. Older versions of this crate wrote out that NULL for
    // the ed25519 algorithm, which RFC 8410 §3 says must be absent, so both spellings are
    // accepted here.
    let (oid, parameters) = spki.algorithm.oids().map_err(spki_error)?;

    let algorithm = KeyAlgorithm::for_spki(oid, parameters).ok_or_else(|| {
        Error::Encoding(format!(
            "SPKI: no support for keys of algorithm {}",
            DisplayAlgorithm((oid, parameters)),
        ))
    })?;

    let public = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Encoding("SPKI: public key is not a whole number of bytes".into()))?;

    algorithm.check_public_key(public)?;

    Ok((algorithm, public.to_vec()))
}

/// Render an algorithm identifier's OIDs for an error message.
struct DisplayAlgorithm((ObjectIdentifier, Option<ObjectIdentifier>));

impl Display for DisplayAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            (oid, Some(parameters)) => write!(f, "{} {}", oid, parameters),
            (oid, None) => write!(f, "{}", oid),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
    use serde_json::{self, json};

    use super::ecdsa::test_data as ecdsa;
    use super::ed25519::test_data as ed25519;
    use super::rsa::test_data as rsa;

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

        assert!(pub_key.is_opaque());
        assert_matches!(
            pub_key.verify(&role, msg, &sig),
            Err(Error::UnknownKeyType(t))
            if t == "unknown-keytype"
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

    pub(super) fn check_public_key_hash(key1: &PublicKey, key2: &PublicKey) {
        use std::hash::BuildHasher;

        let state = std::collections::hash_map::RandomState::new();

        assert_ne!(state.hash_one(key1), state.hash_one(key2));
    }

    /// Reading a key as the wrong algorithm must fail rather than silently produce a key that
    /// cannot verify anything.
    #[test]
    fn pem_rejects_a_key_of_another_algorithm() {
        assert_matches!(
            PublicKey::from_pem(
                ecdsa::P256_PEM_1,
                KeyType::Rsa,
                SignatureScheme::RsassaPssSha256
            ),
            Err(Error::Encoding(_))
        );
        assert_matches!(
            PublicKey::from_pem(
                rsa::PEM_1,
                KeyType::Ecdsa,
                SignatureScheme::EcdsaSha2NistP256
            ),
            Err(Error::Encoding(_))
        );
    }

    /// Keys of different algorithms are different keys, and are named differently.
    #[test]
    fn keys_of_different_algorithms_are_not_equal() {
        let ecdsa =
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
                .unwrap();
        let rsa = RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::RsassaPssSha256).unwrap();

        assert_ne!(ecdsa.public(), rsa.public());
        assert_ne!(ecdsa.public().key_id(), rsa.public().key_id());
        check_public_key_hash(ecdsa.public(), rsa.public());
    }

    /// A key whose scheme this crate cannot use is still a key whose material it can read and
    /// write, because the key type is what says what that material looks like. Such a key simply
    /// cannot verify anything.
    #[test]
    fn a_key_with_an_unusable_scheme_still_round_trips() {
        let plain = PublicKey::from_ed25519(ed25519::PUBLIC_KEY).unwrap();

        for scheme in [
            // A scheme belonging to a different kind of key entirely...
            SignatureScheme::EcdsaSha2NistP256,
            // ... and one this crate has simply not implemented.
            SignatureScheme::Unknown("ed25519ph".into()),
        ] {
            let key =
                PublicKey::new(KeyType::Ed25519, scheme, ed25519::PUBLIC_KEY.to_vec()).unwrap();

            // It is named, and written out, exactly like the ed25519 key that it is.
            assert_eq!(key.key_id(), plain.key_id());
            assert_eq!(key.to_pem().unwrap(), plain.to_pem().unwrap());

            // ... but it cannot check a signature.
            assert_matches!(
                key.verify(
                    &MetadataPath::root(),
                    b"test",
                    &Signature {
                        key_id: key.key_id().clone(),
                        value: SignatureValue(b"sig".to_vec()),
                    }
                ),
                Err(Error::IllegalArgument(_)) | Err(Error::UnknownSignatureScheme(_))
            );
        }
    }
}
