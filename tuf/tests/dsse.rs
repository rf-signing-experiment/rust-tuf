//! End to end tests for [Pouf2], the DSSE data pouf.

use assert_matches::assert_matches;
use dsse::{DsseEnvelope, pae};
use futures_executor::block_on;
use futures_util::io::Cursor;
use serde_json::Value;
use tuf::Result;
use tuf::client::{Client, Config};
use tuf::crypto::{Ed25519PrivateKey, PrivateKey, PublicKey};
use tuf::metadata::{
    Delegation, MetadataPath, MetadataVersion, RawSignedMetadata, RootMetadata, TargetPath,
};
use tuf::pouf::{PAYLOAD_TYPE, Pouf2};
use tuf::repo_builder::RepoBuilder;
use tuf::repository::EphemeralRepository;
use tuf::verify::verify_signatures;

const ED25519_1_PK8: &[u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &[u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &[u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &[u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");
const ED25519_5_PK8: &[u8] = include_bytes!("./ed25519/ed25519-5.pk8.der");

const TARGET_PATH: &str = "foo-bar";
const TARGET_FILE: &[u8] = b"things fade, alternatives exclude";

async fn init_server(
    remote: &mut EphemeralRepository<Pouf2>,
    consistent_snapshot: bool,
) -> Result<(Vec<PublicKey>, RawSignedMetadata<Pouf2, RootMetadata>)> {
    // In real life, you wouldn't want these keys on the same machine ever.
    let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8)?;
    let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8)?;
    let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8)?;
    let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8)?;
    let delegation_key = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8)?;

    let metadata = RepoBuilder::create(&mut *remote)
        .trusted_root_keys(&[&root_key])
        .trusted_snapshot_keys(&[&snapshot_key])
        .trusted_targets_keys(&[&targets_key])
        .trusted_timestamp_keys(&[&timestamp_key])
        .stage_root_with_builder(|builder| builder.consistent_snapshot(consistent_snapshot))
        .unwrap()
        // Delegate to a role so that the targets metadata carries a public key too.
        .add_delegation_key(delegation_key.public().clone())
        .add_delegation_role(
            Delegation::builder(MetadataPath::new("delegation").unwrap())
                .key(delegation_key.public())
                .delegate_path(TargetPath::new("foo").unwrap())
                .build()
                .unwrap(),
        )
        .add_target(TargetPath::new(TARGET_PATH)?, Cursor::new(TARGET_FILE))
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();

    let root = metadata.root().unwrap().clone();

    Ok((vec![root_key.public().clone()], root))
}

async fn init_client(
    root_public_keys: &[PublicKey],
    remote: EphemeralRepository<Pouf2>,
) -> Result<()> {
    let local = EphemeralRepository::new();
    let mut client = Client::with_trusted_root_keys(
        Config::default(),
        MetadataVersion::Number(1),
        1,
        root_public_keys,
        local,
        remote,
    )
    .await?;

    let _ = client.update().await?;

    client
        .fetch_target_to_local(&TargetPath::new(TARGET_PATH)?)
        .await
}

/// A repository written with [Pouf2] can be published and then consumed by a client, all the way
/// through to fetching a target.
#[test]
fn consistent_snapshot_false() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, _) = init_server(&mut remote, false).await.unwrap();
        init_client(&root_public_keys, remote).await.unwrap();
    })
}

#[test]
fn consistent_snapshot_true() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, _) = init_server(&mut remote, true).await.unwrap();
        init_client(&root_public_keys, remote).await.unwrap();
    })
}

#[test]
fn metadata_is_written_as_a_dsse_envelope() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, root) = init_server(&mut remote, false).await.unwrap();

        let envelope: DsseEnvelope = serde_json::from_slice(root.as_bytes()).unwrap();
        assert_eq!(envelope.payload_type, "application/vnd.tuf+json");
        assert_eq!(envelope.payload_type, PAYLOAD_TYPE);

        // The payload is the metadata itself, not a canonicalized rewrite of it.
        let payload: Value = serde_json::from_slice(&envelope.decode_payload()).unwrap();
        assert_eq!(payload["_type"], "root");
        assert_eq!(payload["version"], 1);

        // Every signature is over the payload's Pre-Authentication Encoding.
        let to_sign = pae(&envelope.payload_type, &envelope.decode_payload());
        assert_eq!(to_sign, envelope.pae());
        assert!(!envelope.signatures.is_empty());

        for signature in &envelope.signatures {
            let public_key = root_public_keys
                .iter()
                .find(|key| key.key_id().to_string() == signature.keyid.as_str())
                .unwrap();

            let signature = tuf::crypto::Signature::new(
                public_key.key_id().clone(),
                tuf::crypto::SignatureValue::new(signature.sig.as_bytes().to_vec()),
            );

            public_key
                .verify(&MetadataPath::root(), &to_sign, &signature)
                .unwrap();
        }
    })
}

#[test]
fn public_keys_are_pem_encoded() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, root) = init_server(&mut remote, false).await.unwrap();

        let envelope: DsseEnvelope = serde_json::from_slice(root.as_bytes()).unwrap();
        let payload = String::from_utf8(envelope.decode_payload()).unwrap();
        let keys: Value = serde_json::from_str(&payload).unwrap();

        let keys = keys["keys"].as_object().unwrap();
        assert!(!keys.is_empty());

        for key in keys.values() {
            let public = key["keyval"]["public"].as_str().unwrap();
            assert!(
                public.starts_with("-----BEGIN PUBLIC KEY-----\n"),
                "{}",
                public,
            );
            assert!(public.ends_with("-----END PUBLIC KEY-----\n"), "{}", public);
        }

        // The raw key bytes are never written out.
        for key in &root_public_keys {
            assert!(!payload.contains(&data_encoding::HEXLOWER.encode(key.as_bytes())));
        }

        // ... and the metadata still parses back into the keys we started with.
        let root = verify_signatures(&MetadataPath::root(), &root, 1, &root_public_keys).unwrap();

        for key in &root_public_keys {
            assert_eq!(root.keys().get(key.key_id()), Some(key));
        }
    })
}

/// The signatures cover the payload byte for byte, so any edit at all invalidates them, even one
/// that leaves the metadata's meaning unchanged.
#[test]
fn tampering_with_the_payload_is_detected() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, root) = init_server(&mut remote, false).await.unwrap();

        let mut envelope: DsseEnvelope = serde_json::from_slice(root.as_bytes()).unwrap();

        // Re-indenting the payload does not change what it says, but it does change what was
        // signed.
        let payload: Value = serde_json::from_slice(&envelope.decode_payload()).unwrap();
        envelope.payload = serde_json::to_vec_pretty(&payload).unwrap().into();

        let tampered =
            RawSignedMetadata::<Pouf2, RootMetadata>::new(serde_json::to_vec(&envelope).unwrap());

        assert_matches!(
            verify_signatures(&MetadataPath::root(), &tampered, 1, &root_public_keys),
            Err(tuf::Error::MetadataMissingSignatures { .. })
        );
    })
}

/// An envelope claiming some other payload type is rejected, so a signature over some other kind
/// of DSSE payload can never be replayed as TUF metadata.
#[test]
fn a_foreign_payload_type_is_rejected() {
    block_on(async {
        let mut remote = EphemeralRepository::new();
        let (root_public_keys, root) = init_server(&mut remote, false).await.unwrap();

        let mut envelope: DsseEnvelope = serde_json::from_slice(root.as_bytes()).unwrap();
        envelope.payload_type = "application/vnd.in-toto+json".into();

        let tampered =
            RawSignedMetadata::<Pouf2, RootMetadata>::new(serde_json::to_vec(&envelope).unwrap());

        assert_matches!(
            verify_signatures(&MetadataPath::root(), &tampered, 1, &root_public_keys),
            Err(tuf::Error::Encoding(_))
        );
    })
}
