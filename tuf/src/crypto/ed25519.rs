//! Ed25519 keys, as defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).

use {
    ring::{
        rand::SystemRandom,
        signature::{ED25519, Ed25519KeyPair, KeyPair, VerificationAlgorithm},
    },
    spki::ObjectIdentifier,
};

use super::{
    AlgorithmParameters, AlgorithmSpec, KeyType, PrivateKey, PublicKey, Signature, SignatureScheme,
    SignatureValue,
};
use crate::error::{Error, Result};

/// `id-Ed25519` as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The length of an ed25519 private key in bytes
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an ed25519 public key in bytes
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an ed25519 keypair in bytes
const ED25519_KEYPAIR_LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH + ED25519_PUBLIC_KEY_LENGTH;

pub(super) static SPEC: AlgorithmSpec = AlgorithmSpec {
    name: "ed25519",
    key_type: "ed25519",
    oid: ED25519_OID,
    // RFC 8410 §3: for the id-Ed25519 algorithm the parameters must be absent.
    parameters: AlgorithmParameters::Absent,
    verification,
    check_public_key,
};

/// Ed25519 keys sign under one scheme, the one they are named for.
fn verification(scheme: &SignatureScheme) -> Option<&'static dyn VerificationAlgorithm> {
    match *scheme {
        SignatureScheme::Ed25519 => Some(&ED25519),
        _ => None,
    }
}

/// An ed25519 public key is the raw 32 byte key, with nothing wrapped around it.
fn check_public_key(public: &[u8]) -> Result<()> {
    if public.len() != ED25519_PUBLIC_KEY_LENGTH {
        return Err(Error::IllegalArgument(format!(
            "ed25519 public keys must be {} bytes long, got {}",
            ED25519_PUBLIC_KEY_LENGTH,
            public.len(),
        )));
    }

    Ok(())
}

impl PublicKey {
    /// Parse ED25519 bytes as a public key.
    pub fn from_ed25519<T: Into<Vec<u8>>>(bytes: T) -> Result<Self> {
        Self::new(KeyType::Ed25519, SignatureScheme::Ed25519, bytes.into())
    }
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

    /// Read a `PrivateKey` from an ed25519 keypair. The keypair is a 64 byte slice, where the
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

    /// Read a private key from PKCS#8v2 DER bytes.
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

#[cfg(test)]
pub(super) mod test_data {
    pub(crate) const PRIVATE_KEY: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1");
    pub(crate) const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1.pub");
    pub(crate) const PK8_1: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1.pk8.der");
    pub(crate) const SPKI_1: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1.spki.der");
    pub(crate) const PK8_2: &[u8] = include_bytes!("../../tests/ed25519/ed25519-2.pk8.der");
}

#[cfg(test)]
mod test {
    use super::super::test::check_public_key_hash;
    use super::super::*;
    use super::test_data as ed25519;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
    use ring::signature::KeyPair as _;

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

    #[test]
    fn test_ed25519_public_key_hash() {
        let key1 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_1).unwrap();
        let key2 = Ed25519PrivateKey::from_pkcs8(ed25519::PK8_2).unwrap();

        check_public_key_hash(key1.public(), key2.public());
    }
}
