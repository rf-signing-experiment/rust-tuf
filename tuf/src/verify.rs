//! The `verify` module performs signature verification.

use log::{debug, warn};
use std::collections::{HashMap, HashSet};

use crate::crypto::{KeyId, PublicKey, Signature};
use crate::error::Error;
use crate::metadata::{Metadata, MetadataPath, RawSignedMetadata};
use crate::pouf::Pouf;

/// `Verified` is a wrapper type that signifies the inner type has had it's signature verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified<T> {
    value: T,
}

impl<T> Verified<T> {
    // Create a new `Verified` around some type. This must be kept private to this module in order
    // to guarantee the `V` can only be created through signature verification.
    fn new(value: T) -> Self {
        Verified { value }
    }
}

impl<T> std::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Verify this metadata.
///
/// ```
/// # use chrono::prelude::*;
/// # use tuf::crypto::{Ed25519PrivateKey, PrivateKey, SignatureScheme, HashAlgorithm};
/// # use tuf::pouf::Pouf1;
/// # use tuf::metadata::{MetadataPath, SnapshotMetadataBuilder, SignedMetadata};
/// # use tuf::verify::verify_signatures;
///
/// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
/// let key_1 = Ed25519PrivateKey::from_pkcs8(&key_1).unwrap();
///
/// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
/// let key_2 = Ed25519PrivateKey::from_pkcs8(&key_2).unwrap();
///
/// let raw_snapshot = SnapshotMetadataBuilder::new()
///     .signed::<Pouf1>(&key_1)
///     .unwrap()
///     .to_raw()
///     .unwrap();
///
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     1,
///     vec![key_1.public()],
/// ).is_ok());
///
/// // fail with increased threshold
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     2,
///     vec![key_1.public()],
/// ).is_err());
///
/// // fail when the keys aren't authorized
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     1,
///     vec![key_2.public()],
/// ).is_err());
///
/// // fail when the keys don't exist
/// assert!(verify_signatures(
///     &MetadataPath::snapshot(),
///     &raw_snapshot,
///     1,
///     &[],
/// ).is_err());
pub fn verify_signatures<'a, D, M, I>(
    role: &MetadataPath,
    raw_metadata: &RawSignedMetadata<D, M>,
    threshold: u32,
    authorized_keys: I,
) -> Result<Verified<M>, Error>
where
    D: Pouf,
    M: Metadata,
    I: IntoIterator<Item = &'a PublicKey>,
{
    if threshold < 1 {
        return Err(Error::MetadataThresholdMustBeGreaterThanZero(role.clone()));
    }

    let authorized_keys = authorized_keys
        .into_iter()
        .map(|k| (k.key_id(), k))
        .collect::<HashMap<&KeyId, &PublicKey>>();

    // Extract the signatures and the byte string the signatures are computed over.
    let (signatures, signed) = D::deserialize_signed(raw_metadata.as_bytes())?;
    let signing_input = D::signing_input(&signed)?;

    let mut signatures_needed = threshold;

    // Create a key_id->signature map to deduplicate the key_ids.
    let signatures = signatures
        .iter()
        .map(|sig| (sig.key_id(), sig))
        .collect::<HashMap<&KeyId, &Signature>>();

    // Deduplicating by key id is not enough. A key id only names a key, and nothing stops
    // metadata from giving one key several names, so a single private key could otherwise sign
    // once under each name and meet a threshold on its own. The spec puts it directly: "When
    // computing the THRESHOLD each KEY MUST only contribute one SIGNATURE". Count the keys that
    // signed, rather than the names they signed under.
    let mut keys_that_signed: HashSet<&[u8]> = HashSet::new();

    for (key_id, sig) in signatures {
        match authorized_keys.get(key_id) {
            Some(pub_key) => match pub_key.verify(role, &signing_input, sig) {
                Ok(()) => {
                    if keys_that_signed.insert(pub_key.as_bytes()) {
                        debug!("Good signature from key ID {:?}", pub_key.key_id());
                        signatures_needed -= 1;
                    } else {
                        warn!(
                            "Key ID {:?} is another name for a key that has already signed; it \
                             does not count towards the threshold again.",
                            key_id,
                        );
                    }
                }
                Err(e) => {
                    warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                }
            },
            None => {
                warn!(
                    "Key ID {:?} was not found in the set of authorized keys.",
                    sig.key_id()
                );
            }
        }
        if signatures_needed == 0 {
            break;
        }
    }

    if signatures_needed > 0 {
        return Err(Error::MetadataMissingSignatures {
            role: role.clone(),
            number_of_valid_signatures: threshold - signatures_needed,
            threshold,
        });
    }

    // Everything looks good so deserialize the metadata.
    let verified_metadata = M::from_raw_data::<D>(&signed)?;

    Ok(Verified::new(verified_metadata))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{Ed25519PrivateKey, PrivateKey};
    use crate::metadata::{RawSignedMetadata, SnapshotMetadata, SnapshotMetadataBuilder};
    use crate::pouf::Pouf1;
    use assert_matches::assert_matches;
    use std::str::FromStr;

    const ED25519_1_PK8: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");

    /// Give one key two names, and label the signature it produced under both of them.
    fn signed_twice_under_two_names(
        key: &Ed25519PrivateKey,
        first: &KeyId,
        second: &KeyId,
    ) -> RawSignedMetadata<Pouf1, SnapshotMetadata> {
        let raw = SnapshotMetadataBuilder::new()
            .signed::<Pouf1>(key)
            .unwrap()
            .to_raw()
            .unwrap();

        let mut doc: serde_json::Value = serde_json::from_slice(raw.as_bytes()).unwrap();
        let sig = doc["signatures"][0].clone();

        let mut a = sig.clone();
        a["keyid"] = serde_json::json!(first.to_string());
        let mut b = sig;
        b["keyid"] = serde_json::json!(second.to_string());
        doc["signatures"] = serde_json::json!([a, b]);

        RawSignedMetadata::new(serde_json::to_vec(&doc).unwrap())
    }

    /// A key id names a key; it does not make one. Since metadata is free to call a key whatever
    /// it likes, one key may appear under several names, and must still only count once towards a
    /// threshold.
    #[test]
    fn one_key_under_two_names_counts_once() {
        let key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();

        let first =
            KeyId::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let second =
            KeyId::from_str("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();

        let raw = signed_twice_under_two_names(&key, &first, &second);
        let under_first = key.public().clone().with_key_id(first);
        let under_second = key.public().clone().with_key_id(second);

        // One signature from one key is still one signature, however it is labelled ...
        assert_matches!(
            verify_signatures(
                &MetadataPath::snapshot(),
                &raw,
                2,
                vec![&under_first, &under_second],
            ),
            Err(Error::MetadataMissingSignatures {
                number_of_valid_signatures: 1,
                threshold: 2,
                ..
            })
        );

        // ... and it does meet a threshold of one.
        assert_matches!(
            verify_signatures(
                &MetadataPath::snapshot(),
                &raw,
                1,
                vec![&under_first, &under_second],
            ),
            Ok(_)
        );
    }
}
