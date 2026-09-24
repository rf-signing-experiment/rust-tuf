//! RSA keys, as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).

use {
    getrandom::SysRng,
    rsa::{
        RsaPublicKey,
        pkcs1::{DecodeRsaPublicKey as _, EncodeRsaPublicKey as _},
        pkcs8::DecodePrivateKey as _,
        pss,
        traits::PublicKeyParts as _,
    },
    sha2::Sha256,
    signature::{RandomizedSigner as _, SignatureEncoding as _, Verifier as _},
    spki::{
        ObjectIdentifier,
        der::{Decode as _, Tag, Tagged as _, asn1::Any},
    },
};

use super::{
    AlgorithmParameters, AlgorithmSpec, KeyType, PrivateKey, PublicKey, Signature, SignatureScheme,
    SignatureValue, VerificationAlgorithm,
};
use crate::error::{Error, Result};

/// `rsaEncryption` as defined in
/// [RFC 4055 §1.2](https://datatracker.ietf.org/doc/html/rfc4055#section-1.2).
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The smallest modulus, in bits, this crate will sign or verify a signature with.
const MIN_MODULUS_BITS: u32 = 2048;

/// The largest modulus, in bits, this crate will verify a signature with.
const MAX_MODULUS_BITS: u32 = 8192;

pub(super) static SPEC: AlgorithmSpec = AlgorithmSpec {
    name: "rsa",
    key_type: "rsa",
    oid: RSA_ENCRYPTION_OID,
    // RFC 4055 §1.2: unlike the other algorithms this crate writes, the rsaEncryption parameters
    // must be present, and must be NULL.
    parameters: AlgorithmParameters::Null,
    verification,
    check_public_key,
};

/// RSA keys sign under a family of schemes, of which this crate implements one. The others differ
/// only in padding and digest, and cost an arm here rather than a key algorithm of their own.
fn verification(scheme: &SignatureScheme) -> Option<VerificationAlgorithm> {
    match *scheme {
        SignatureScheme::RsassaPssSha256 => Some(verify_pss_sha256),
        _ => None,
    }
}

/// RSASSA-PSS with SHA-256 throughout, and a salt as long as the digest, which is what the rest
/// of the TUF ecosystem produces for this scheme.
fn verify_pss_sha256(public: &[u8], msg: &[u8], sig: &[u8]) -> signature::Result<()> {
    let public = RsaPublicKey::from_pkcs1_der(public).map_err(signature::Error::from_source)?;

    let bits = public.n().bits();
    if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
        return Err(signature::Error::new());
    }

    let sig = pss::Signature::try_from(sig)?;

    pss::VerifyingKey::<Sha256>::new(public).verify(msg, &sig)
}

/// An RSA public key is a PKCS#1 `RSAPublicKey`, whose length depends on the size of the modulus.
/// The verification algorithm is what holds that to 2048 to 8192 bits.
fn check_public_key(public: &[u8]) -> Result<()> {
    let any = Any::from_der(public).map_err(|err| {
        Error::IllegalArgument(format!(
            "rsa public keys must be a DER RSAPublicKey: {}",
            err,
        ))
    })?;

    if any.tag() != Tag::Sequence {
        return Err(Error::IllegalArgument(format!(
            "rsa public keys must be a DER RSAPublicKey, found {}",
            any.tag(),
        )));
    }

    Ok(())
}

/// A structure containing information about an RSA private key.
pub struct RsaPrivateKey {
    private: pss::BlindedSigningKey<Sha256>,
    public: PublicKey,
}

impl RsaPrivateKey {
    /// Create a private key from PKCS#8v1 DER bytes.
    ///
    /// The key must be at least 2048 bits, which is the smallest modulus this crate will verify a
    /// signature from.
    ///
    /// # Generating Keys
    ///
    /// ```bash
    /// $ openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:3072 \
    ///       -outform der -out rsa-private-key.pk8
    /// ```
    pub fn from_pkcs8(der_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        match scheme {
            SignatureScheme::RsassaPssSha256 => {}
            SignatureScheme::Unknown(s) => return Err(Error::UnknownSignatureScheme(s)),
            scheme => {
                return Err(Error::IllegalArgument(format!(
                    "{} is not an RSA signature scheme",
                    scheme,
                )));
            }
        }

        let private = rsa::RsaPrivateKey::from_pkcs8_der(der_key)
            .map_err(|err| Error::Encoding(format!("Could not parse key as PKCS#8v1: {}", err)))?;

        let bits = private.n().bits();
        if bits < MIN_MODULUS_BITS {
            return Err(Error::IllegalArgument(format!(
                "rsa private keys must be at least {} bits, got {}",
                MIN_MODULUS_BITS, bits,
            )));
        }

        let public_bytes = private
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|err| Error::Encoding(format!("Could not write RSAPublicKey: {}", err)))?;

        let public = PublicKey::new(KeyType::Rsa, scheme, public_bytes.into_vec())?;

        Ok(RsaPrivateKey {
            // Blinding keeps the time signing takes from depending on the private key.
            private: pss::BlindedSigningKey::new(private),
            public,
        })
    }
}

impl PrivateKey for RsaPrivateKey {
    fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let value = self
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

#[cfg(test)]
pub(super) mod test_data {
    pub(crate) const PK8_1: &[u8] = include_bytes!("../../tests/rsa/rsa-2048-1.pk8.der");
    pub(crate) const PEM_1: &str = include_str!("../../tests/rsa/rsa-2048-1.spki.pem");
    pub(crate) const PK8_2: &[u8] = include_bytes!("../../tests/rsa/rsa-2048-2.pk8.der");
}

#[cfg(test)]
mod test {
    use super::super::*;
    use super::RSA_ENCRYPTION_OID;
    use super::test_data as rsa;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn rsa_read_pkcs8_and_sign() {
        let key = RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::RsassaPssSha256).unwrap();
        assert_eq!(key.public().typ(), &KeyType::Rsa);
        assert_eq!(key.public().scheme(), &SignatureScheme::RsassaPssSha256);

        let role = MetadataPath::root();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();

        // A PSS signature is as wide as the modulus.
        assert_eq!(sig.value().as_bytes().len(), 2048 / 8);

        let pub_key = PublicKey::from_spki(
            &key.public().as_spki().unwrap(),
            SignatureScheme::RsassaPssSha256,
        )
        .unwrap();
        assert_eq!(&pub_key, key.public());
        assert_matches!(pub_key.verify(&role, msg, &sig), Ok(()));

        // PSS salts the digest, so signing the same message twice gives two different signatures,
        // and both verify.
        let sig2 = key.sign(msg).unwrap();
        assert_ne!(sig.value(), sig2.value());
        assert_matches!(pub_key.verify(&role, msg, &sig2), Ok(()));

        assert_matches!(
            pub_key.verify(&role, b"other", &sig),
            Err(Error::BadSignature(r)) if r == role
        );

        let other =
            RsaPrivateKey::from_pkcs8(rsa::PK8_2, SignatureScheme::RsassaPssSha256).unwrap();
        assert_matches!(
            other.public().verify(&role, msg, &sig),
            Err(Error::BadSignature(r)) if r == role
        );
    }

    /// An RSA key written by another implementation reads back as the same key, and is written
    /// out again byte for byte the way that implementation wrote it.
    #[test]
    fn rsa_public_keys_round_trip_through_pem() {
        let key = PublicKey::from_pem(rsa::PEM_1, KeyType::Rsa, SignatureScheme::RsassaPssSha256)
            .unwrap();

        assert_eq!(
            &key,
            RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::RsassaPssSha256)
                .unwrap()
                .public()
        );
        assert_eq!(key.to_pem().unwrap(), rsa::PEM_1);
    }

    /// RFC 4055 §1.2 requires the rsaEncryption parameters to be present and NULL, unlike the
    /// other algorithms this crate writes.
    #[test]
    fn rsa_spki_carries_null_parameters() {
        let key = RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::RsassaPssSha256).unwrap();
        let der = key.public().as_spki().unwrap();

        let spki = SubjectPublicKeyInfoRef::from_der(&der).unwrap();
        assert_eq!(spki.algorithm.oid, RSA_ENCRYPTION_OID);
        assert!(spki.algorithm.parameters.unwrap().is_null());

        // A key written without them is still read, because `oids` treats a NULL as absent.
        assert_eq!(
            PublicKey::from_spki(&der, SignatureScheme::RsassaPssSha256).unwrap(),
            *key.public(),
        );
    }

    #[test]
    fn rsa_rejects_key_material_that_is_not_an_rsa_public_key() {
        assert_matches!(
            PublicKey::new(
                KeyType::Rsa,
                SignatureScheme::RsassaPssSha256,
                b"not der at all".to_vec(),
            ),
            Err(Error::IllegalArgument(_))
        );

        // A well formed DER value that is not a SEQUENCE is not an `RSAPublicKey` either.
        assert_matches!(
            PublicKey::new(
                KeyType::Rsa,
                SignatureScheme::RsassaPssSha256,
                vec![0x02, 0x01, 0x2a],
            ),
            Err(Error::IllegalArgument(_))
        );
    }

    #[test]
    fn rsa_private_keys_reject_a_scheme_that_is_not_rsa() {
        assert_matches!(
            RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::Ed25519)
                .err()
                .unwrap(),
            Error::IllegalArgument(_)
        );
        assert_matches!(
            RsaPrivateKey::from_pkcs8(rsa::PK8_1, SignatureScheme::Unknown("rsa-pkcs1".into()))
                .err()
                .unwrap(),
            Error::UnknownSignatureScheme(s) if s == "rsa-pkcs1"
        );
    }

    #[test]
    fn serde_key_type_and_scheme() {
        let jsn = json!("rsa");
        let parsed: KeyType = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, KeyType::Rsa);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), jsn);

        let jsn = json!("rsassa-pss-sha256");
        let parsed: SignatureScheme = serde_json::from_value(jsn.clone()).unwrap();
        assert_eq!(parsed, SignatureScheme::RsassaPssSha256);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), jsn);
    }
}
