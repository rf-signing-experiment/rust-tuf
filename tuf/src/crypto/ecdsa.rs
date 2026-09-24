//! ECDSA keys over the NIST prime curves.

use {
    getrandom::SysRng,
    p256::{
        ecdsa::{DerSignature, SigningKey, VerifyingKey},
        elliptic_curve::Generate as _,
        pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _},
    },
    signature::{RandomizedSigner as _, SignatureEncoding as _, Verifier as _},
    spki::ObjectIdentifier,
};

use super::{
    AlgorithmParameters, AlgorithmSpec, KeyType, PrivateKey, PublicKey, Signature, SignatureScheme,
    SignatureValue, VerificationAlgorithm,
};
use crate::error::{Error, Result};

/// `id-ecPublicKey` as defined in
/// [RFC 5480 §2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1).
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// `secp256r1`, the curve NIST calls P-256, as named in
/// [RFC 5480 §2.1.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1).
const NIST_P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The tag [SEC 1](https://www.secg.org/sec1-v2.pdf) §2.3.3 gives an uncompressed elliptic curve
/// point, which is how a public key is carried inside a `SubjectPublicKeyInfo`.
const SEC1_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// The width of a P-256 field element in bytes.
const NIST_P256_FIELD_LENGTH: usize = 32;

pub(super) static NIST_P256_SPEC: AlgorithmSpec = AlgorithmSpec {
    name: "nistp256",
    // Every curve shares the `ecdsa` key type; it is the parameters, not the key type, that say
    // which curve a key lies on.
    key_type: "ecdsa",
    oid: EC_PUBLIC_KEY_OID,
    // RFC 5480 §2.1.1: for id-ecPublicKey the parameters name the curve.
    parameters: AlgorithmParameters::Oid(NIST_P256_OID),
    verification: p256_verification,
    check_public_key: check_p256_public_key,
};

fn p256_verification(scheme: &SignatureScheme) -> Option<VerificationAlgorithm> {
    match *scheme {
        SignatureScheme::EcdsaSha2NistP256 => Some(verify_p256_sha256_asn1),
        _ => None,
    }
}

/// TUF writes an ECDSA signature as the ASN.1 `Ecdsa-Sig-Value` of RFC 3279 §2.2.3, not as the
/// fixed width concatenation of `r` and `s`.
fn verify_p256_sha256_asn1(public: &[u8], msg: &[u8], sig: &[u8]) -> signature::Result<()> {
    let public = VerifyingKey::from_sec1_bytes(public)?;
    let sig = DerSignature::from_bytes(sig)?;

    public.verify(msg, &sig)
}

/// An elliptic curve public key is the uncompressed point of SEC 1 §2.3.3: the tag byte, then `x`
/// and `y`, each padded out to the width of the curve's field.
fn check_p256_public_key(public: &[u8]) -> Result<()> {
    let expected = 1 + 2 * NIST_P256_FIELD_LENGTH;

    if public.len() != expected {
        return Err(Error::IllegalArgument(format!(
            "nistp256 public keys must be {} bytes long, got {}",
            expected,
            public.len(),
        )));
    }

    if public[0] != SEC1_UNCOMPRESSED_POINT_TAG {
        return Err(Error::IllegalArgument(
            "nistp256 public keys must be an uncompressed curve point".into(),
        ));
    }

    Ok(())
}

impl PublicKey {
    /// Parse the uncompressed curve point of an ECDSA key as a public key.
    ///
    /// The curve is the one named by `scheme`, which must be an ECDSA scheme.
    pub fn from_ecdsa<T: Into<Vec<u8>>>(bytes: T, scheme: SignatureScheme) -> Result<Self> {
        Self::new(KeyType::Ecdsa, scheme, bytes.into())
    }
}

/// A structure containing information about an ECDSA private key.
pub struct EcdsaPrivateKey {
    private: SigningKey,
    public: PublicKey,
}

impl EcdsaPrivateKey {
    /// Generate ECDSA key bytes in pkcs8 format for the given signature scheme.
    ///
    /// The scheme names the curve the key is generated on, and must be an ECDSA scheme.
    pub fn pkcs8(scheme: &SignatureScheme) -> Result<Vec<u8>> {
        check_scheme(scheme)?;

        let key = SigningKey::try_generate_from_rng(&mut SysRng)
            .map_err(|_| Error::Opaque(format!("Failed to generate {} key", scheme)))?;

        key.to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|err| Error::Encoding(format!("Could not write key as PKCS#8v1: {}", err)))
    }

    /// Create a private key from PKCS#8v1 DER bytes.
    ///
    /// The document must name the same curve that `scheme` does. If it carries the public key
    /// alongside the private one, the two must match.
    ///
    /// # Generating Keys
    ///
    /// ```bash
    /// $ openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 \
    ///       -outform der -out ecdsa-private-key.pk8
    /// ```
    pub fn from_pkcs8(der_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        check_scheme(&scheme)?;

        let private = SigningKey::from_pkcs8_der(der_key)
            .map_err(|err| Error::Encoding(format!("Could not parse key as PKCS#8v1: {}", err)))?;

        let public = PublicKey::new(
            KeyType::Ecdsa,
            scheme,
            private
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        )?;

        Ok(EcdsaPrivateKey { private, public })
    }
}

impl PrivateKey for EcdsaPrivateKey {
    fn sign(&self, msg: &[u8]) -> Result<Signature> {
        // Signing with fresh randomness mixed into the RFC 6979 nonce keeps signatures randomized,
        // as other implementations produce them.
        let value: DerSignature = self
            .private
            .try_sign_with_rng(&mut SysRng, msg)
            .map_err(|_| Error::Opaque("Failed to sign message".into()))?;

        Ok(Signature {
            key_id: self.public.key_id().clone(),
            value: SignatureValue(value.to_vec()),
        })
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

/// Check that `scheme` is one this crate can sign with using an ECDSA key.
fn check_scheme(scheme: &SignatureScheme) -> Result<()> {
    match *scheme {
        SignatureScheme::EcdsaSha2NistP256 => Ok(()),
        SignatureScheme::Unknown(ref s) => Err(Error::UnknownSignatureScheme(s.clone())),
        ref scheme => Err(Error::IllegalArgument(format!(
            "{} is not an ECDSA signature scheme",
            scheme,
        ))),
    }
}

#[cfg(test)]
pub(super) mod test_data {
    pub(crate) const P256_PK8_1: &[u8] = include_bytes!("../../tests/ecdsa/ecdsa-p256-1.pk8.der");
    pub(crate) const P256_PEM_1: &str = include_str!("../../tests/ecdsa/ecdsa-p256-1.spki.pem");
    pub(crate) const P256_PK8_2: &[u8] = include_bytes!("../../tests/ecdsa/ecdsa-p256-2.pk8.der");
}

#[cfg(test)]
mod test {
    use super::super::*;
    use super::test_data as ecdsa;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    fn ecdsa_round_trip(pk8: &[u8], scheme: SignatureScheme, other_pk8: &[u8]) {
        let key = EcdsaPrivateKey::from_pkcs8(pk8, scheme.clone()).unwrap();
        assert_eq!(key.public().typ(), &KeyType::Ecdsa);
        assert_eq!(key.public().scheme(), &scheme);

        let role = MetadataPath::root();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();

        // The key is the same key however it is written down.
        let pub_key =
            PublicKey::from_spki(&key.public().as_spki().unwrap(), scheme.clone()).unwrap();
        assert_eq!(&pub_key, key.public());
        assert_matches!(pub_key.verify(&role, msg, &sig), Ok(()));

        // ECDSA is randomized, so a second signature over the same message differs from the
        // first, and both verify.
        let sig2 = key.sign(msg).unwrap();
        assert_ne!(sig.value(), sig2.value());
        assert_matches!(pub_key.verify(&role, msg, &sig2), Ok(()));

        assert_matches!(
            pub_key.verify(&role, b"other", &sig),
            Err(Error::BadSignature(r)) if r == role
        );

        let other = EcdsaPrivateKey::from_pkcs8(other_pk8, scheme).unwrap();
        assert_matches!(
            other.public().verify(&role, msg, &sig),
            Err(Error::BadSignature(r)) if r == role
        );
    }

    #[test]
    fn ecdsa_p256_read_pkcs8_and_sign() {
        ecdsa_round_trip(
            ecdsa::P256_PK8_1,
            SignatureScheme::EcdsaSha2NistP256,
            ecdsa::P256_PK8_2,
        );
    }

    /// TUF writes an ECDSA signature as an ASN.1 `Ecdsa-Sig-Value`, which is what every other
    /// implementation reads, rather than as the fixed width concatenation of `r` and `s`.
    #[test]
    fn ecdsa_signatures_are_asn1() {
        let key =
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
                .unwrap();
        let sig = key.sign(b"test").unwrap();
        let bytes = sig.value().as_bytes();

        // A SEQUENCE, whose length covers the rest of the signature, of two INTEGERs.
        assert_eq!(bytes[0], 0x30);
        assert_eq!(usize::from(bytes[1]), bytes.len() - 2);
        assert_eq!(bytes[2], 0x02);
    }

    /// A key written by another implementation reads back as the same key, and is written out
    /// again byte for byte the way that implementation wrote it.
    #[test]
    fn ecdsa_public_keys_round_trip_through_pem() {
        let scheme = SignatureScheme::EcdsaSha2NistP256;
        let key = PublicKey::from_pem(ecdsa::P256_PEM_1, KeyType::Ecdsa, scheme.clone()).unwrap();

        assert_eq!(
            &key,
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, scheme)
                .unwrap()
                .public()
        );
        assert_eq!(key.to_pem().unwrap(), ecdsa::P256_PEM_1);
    }

    #[test]
    fn ecdsa_rejects_key_material_that_is_not_an_uncompressed_point() {
        let key =
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
                .unwrap();

        // The x coordinate alone, tagged as a compressed point, is the right length for neither
        // curve...
        let mut compressed = key.public().as_bytes()[..33].to_vec();
        compressed[0] = 0x02;
        assert_matches!(
            PublicKey::from_ecdsa(compressed, SignatureScheme::EcdsaSha2NistP256),
            Err(Error::IllegalArgument(_))
        );

        // ... and neither is a point with the right length but no tag.
        let mut untagged = key.public().as_bytes().to_vec();
        untagged[0] = 0x00;
        assert_matches!(
            PublicKey::from_ecdsa(untagged, SignatureScheme::EcdsaSha2NistP256),
            Err(Error::IllegalArgument(_))
        );
    }

    #[test]
    fn ecdsa_key_id_is_derived_from_the_key_material() {
        let key =
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, SignatureScheme::EcdsaSha2NistP256)
                .unwrap();

        assert_eq!(
            key.public().key_id(),
            &KeyId::from_str(&HEXLOWER.encode(&Sha256::digest(key.public().as_spki().unwrap())))
                .unwrap(),
        );
    }

    #[test]
    fn new_ecdsa_key() {
        let scheme = SignatureScheme::EcdsaSha2NistP256;
        let bytes = EcdsaPrivateKey::pkcs8(&scheme).unwrap();
        let _ = EcdsaPrivateKey::from_pkcs8(&bytes, scheme).unwrap();
    }

    #[test]
    fn ecdsa_private_keys_reject_a_scheme_that_is_not_ecdsa() {
        assert_matches!(
            EcdsaPrivateKey::from_pkcs8(ecdsa::P256_PK8_1, SignatureScheme::Ed25519)
                .err()
                .unwrap(),
            Error::IllegalArgument(_)
        );
        assert_matches!(
            EcdsaPrivateKey::pkcs8(&SignatureScheme::Unknown("rsassa-pss-sha256".into())),
            Err(Error::UnknownSignatureScheme(s)) if s == "rsassa-pss-sha256"
        );
    }

    /// Older TUF metadata named an ECDSA key type with the curve baked into it. Both spellings
    /// name the same kind of key, and the curve is carried by the scheme either way.
    #[test]
    fn the_legacy_ecdsa_key_type_is_understood() {
        assert_eq!(KeyType::new("ecdsa-sha2-nistp256"), KeyType::Ecdsa);

        let legacy: KeyType = serde_json::from_value(json!("ecdsa-sha2-nistp256")).unwrap();
        assert_eq!(legacy, KeyType::Ecdsa);

        // ... but it is written back out under the modern spelling.
        assert_eq!(serde_json::to_value(&legacy).unwrap(), json!("ecdsa"));
    }

    #[test]
    fn serde_key_type_and_scheme() {
        let jsn = json!("ecdsa");
        let parsed: KeyType = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, KeyType::Ecdsa);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), jsn);

        let jsn = json!("ecdsa-sha2-nistp256");
        let parsed: SignatureScheme = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, SignatureScheme::EcdsaSha2NistP256);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), jsn);
    }
}
