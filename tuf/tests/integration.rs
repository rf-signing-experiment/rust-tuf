use assert_matches::assert_matches;
use chrono::offset::Utc;
use futures_executor::block_on;
use futures_util::io::Cursor;
use serde_json::Value;
use tuf::Database;
use tuf::Error;
use tuf::Result;
use tuf::client::{Client, Config};
use tuf::crypto::{
    EcdsaPrivateKey, Ed25519PrivateKey, HashAlgorithm, KeyType, PrivateKey, PublicKey,
    RsaPrivateKey, SignatureScheme,
};
use tuf::metadata::{
    Delegation, Delegations, Metadata, MetadataDescription, MetadataPath, MetadataVersion,
    RawSignedMetadata, RootMetadata, TargetPath, TargetsMetadataBuilder,
};
use tuf::pouf::{Pouf, Pouf1, Pouf2};
use tuf::repo_builder::RepoBuilder;
use tuf::repository::EphemeralRepository;

const ED25519_1_PK8: &[u8] = include_bytes!("./ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &[u8] = include_bytes!("./ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &[u8] = include_bytes!("./ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &[u8] = include_bytes!("./ed25519/ed25519-4.pk8.der");
const ED25519_5_PK8: &[u8] = include_bytes!("./ed25519/ed25519-5.pk8.der");
const ED25519_6_PK8: &[u8] = include_bytes!("./ed25519/ed25519-6.pk8.der");

const ECDSA_1_PK8: &[u8] = include_bytes!("./ecdsa/ecdsa-p256-1.pk8.der");
const ECDSA_2_PK8: &[u8] = include_bytes!("./ecdsa/ecdsa-p256-2.pk8.der");
const ECDSA_3_PK8: &[u8] = include_bytes!("./ecdsa/ecdsa-p256-3.pk8.der");
const ECDSA_4_PK8: &[u8] = include_bytes!("./ecdsa/ecdsa-p256-4.pk8.der");

const RSA_1_PK8: &[u8] = include_bytes!("./rsa/rsa-2048-1.pk8.der");
const RSA_2_PK8: &[u8] = include_bytes!("./rsa/rsa-2048-2.pk8.der");
const RSA_3_PK8: &[u8] = include_bytes!("./rsa/rsa-2048-3.pk8.der");
const RSA_4_PK8: &[u8] = include_bytes!("./rsa/rsa-2048-4.pk8.der");
const RSA_5_PK8: &[u8] = include_bytes!("./rsa/rsa-2048-5.pk8.der");

#[test]
fn simple_delegation() {
    block_on(async {
        let now = Utc::now();

        let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
        let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
        let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();
        let delegation_key = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();

        let mut repo = EphemeralRepository::new();
        let metadata = RepoBuilder::create(&mut repo)
            .trusted_root_keys(&[&root_key])
            .trusted_snapshot_keys(&[&snapshot_key])
            .trusted_targets_keys(&[&targets_key])
            .trusted_timestamp_keys(&[&timestamp_key])
            .stage_root()
            .unwrap()
            .add_delegation_key(delegation_key.public().clone())
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation").unwrap())
                    .key(delegation_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder.insert_metadata_description(
                    MetadataPath::new("delegation").unwrap(),
                    MetadataDescription::from_slice(&[0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
                )
            })
            .unwrap()
            .commit()
            .await
            .unwrap();

        let mut tuf = Database::<Pouf1>::from_trusted_metadata(&metadata).unwrap();

        //// build the targets ////
        //// build the delegation ////
        let target_file: &[u8] = b"bar";
        let delegation = TargetsMetadataBuilder::new()
            .insert_target_from_slice(
                TargetPath::new("foo").unwrap(),
                target_file,
                &[HashAlgorithm::Sha256],
            )
            .unwrap()
            .signed::<Pouf1>(&delegation_key)
            .unwrap();
        let raw_delegation = delegation.to_raw().unwrap();

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::targets(),
            &MetadataPath::new("delegation").unwrap(),
            &raw_delegation,
        )
        .unwrap();

        assert!(
            tuf.target_description(&TargetPath::new("foo").unwrap())
                .is_ok()
        );
    })
}

#[test]
fn nested_delegation() {
    block_on(async {
        let now = Utc::now();

        let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
        let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
        let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();
        let delegation_a_key = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();
        let delegation_b_key = Ed25519PrivateKey::from_pkcs8(ED25519_6_PK8).unwrap();

        let mut repo = EphemeralRepository::new();
        let metadata = RepoBuilder::create(&mut repo)
            .trusted_root_keys(&[&root_key])
            .trusted_snapshot_keys(&[&snapshot_key])
            .trusted_targets_keys(&[&targets_key])
            .trusted_timestamp_keys(&[&timestamp_key])
            .stage_root()
            .unwrap()
            .add_delegation_key(delegation_a_key.public().clone())
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation-a").unwrap())
                    .key(delegation_a_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder
                    .insert_metadata_description(
                        MetadataPath::new("delegation-a").unwrap(),
                        MetadataDescription::from_slice(&[0u8], 1, &[HashAlgorithm::Sha256])
                            .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-b").unwrap(),
                        MetadataDescription::from_slice(&[0u8], 1, &[HashAlgorithm::Sha256])
                            .unwrap(),
                    )
            })
            .unwrap()
            .commit()
            .await
            .unwrap();

        let mut tuf = Database::<Pouf1>::from_trusted_metadata(&metadata).unwrap();

        //// build delegation B ////

        let delegations = Delegations::builder()
            .key(delegation_b_key.public().clone())
            .role(
                Delegation::builder(MetadataPath::new("delegation-b").unwrap())
                    .key(delegation_b_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let delegation = TargetsMetadataBuilder::new()
            .delegations(delegations)
            .signed::<Pouf1>(&delegation_a_key)
            .unwrap();
        let raw_delegation = delegation.to_raw().unwrap();

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::targets(),
            &MetadataPath::new("delegation-a").unwrap(),
            &raw_delegation,
        )
        .unwrap();

        //// build delegation B ////

        let target_file: &[u8] = b"bar";

        let delegation = TargetsMetadataBuilder::new()
            .insert_target_from_slice(
                TargetPath::new("foo").unwrap(),
                target_file,
                &[HashAlgorithm::Sha256],
            )
            .unwrap()
            .signed::<Pouf1>(&delegation_b_key)
            .unwrap();
        let raw_delegation = delegation.to_raw().unwrap();

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::new("delegation-a").unwrap(),
            &MetadataPath::new("delegation-b").unwrap(),
            &raw_delegation,
        )
        .unwrap();

        assert!(
            tuf.target_description(&TargetPath::new("foo").unwrap())
                .is_ok()
        );
    })
}

#[test]
fn rejects_bad_delegation_signatures() {
    block_on(async {
        let now = Utc::now();

        let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
        let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
        let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();
        let delegation_key = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();
        let bad_delegation_key = Ed25519PrivateKey::from_pkcs8(ED25519_6_PK8).unwrap();

        let mut repo = EphemeralRepository::new();
        let metadata = RepoBuilder::create(&mut repo)
            .trusted_root_keys(&[&root_key])
            .trusted_snapshot_keys(&[&snapshot_key])
            .trusted_targets_keys(&[&targets_key])
            .trusted_timestamp_keys(&[&timestamp_key])
            .stage_root()
            .unwrap()
            .add_delegation_key(delegation_key.public().clone())
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation").unwrap())
                    .key(delegation_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder.insert_metadata_description(
                    MetadataPath::new("delegation").unwrap(),
                    MetadataDescription::from_slice(&[0u8], 1, &[HashAlgorithm::Sha256]).unwrap(),
                )
            })
            .unwrap()
            .commit()
            .await
            .unwrap();

        let mut tuf = Database::<Pouf1>::from_trusted_metadata(&metadata).unwrap();

        //// build the delegation ////
        let target_file: &[u8] = b"bar";
        let delegation = TargetsMetadataBuilder::new()
            .insert_target_from_slice(
                TargetPath::new("foo").unwrap(),
                target_file,
                &[HashAlgorithm::Sha256],
            )
            .unwrap()
            .signed::<Pouf1>(&bad_delegation_key)
            .unwrap();
        let raw_delegation = delegation.to_raw().unwrap();

        assert_matches!(
            tuf.update_delegated_targets(
                &now,
                &MetadataPath::targets(),
                &MetadataPath::new("delegation").unwrap(),
                &raw_delegation
            ),
            Err(Error::MetadataMissingSignatures {
                role,
                number_of_valid_signatures: 0,
                threshold: 1,
            })
            if role == MetadataPath::new("delegation").unwrap()
        );

        let target_path = TargetPath::new("foo").unwrap();
        assert_matches!(
            tuf.target_description(&target_path),
            Err(Error::TargetNotFound(p)) if p == target_path
        );
    })
}

#[test]
fn diamond_delegation() {
    block_on(async {
        let now = Utc::now();

        let etc_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();
        let delegation_a_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8).unwrap();
        let delegation_b_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8).unwrap();
        let delegation_c_key = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();

        // Given delegations a, b, and c, targets delegates "foo" to delegation-a and "bar" to
        // delegation-b.
        //
        //             targets
        //              /  \
        //   delegation-a  delegation-b
        //              \  /
        //          delegation-c
        //
        // if delegation-a delegates "foo" to delegation-c, and
        //    delegation-b delegates "bar" to delegation-c, but
        //    delegation-b's signature is invalid, then delegation-c
        // can contain target "bar" which is unaccessible and target "foo" which is.
        //
        // Verify tuf::Database handles this situation correctly.

        //// build delegation A ////

        let delegations_a = Delegations::builder()
            .key(delegation_c_key.public().clone())
            .role(
                Delegation::builder(MetadataPath::new("delegation-c").unwrap())
                    .key(delegation_c_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let delegation_a = TargetsMetadataBuilder::new()
            .delegations(delegations_a)
            .signed::<Pouf1>(&delegation_a_key)
            .unwrap();
        let raw_delegation_a = delegation_a.to_raw().unwrap();

        //// build delegation B ////

        let delegations_b = Delegations::builder()
            .key(delegation_c_key.public().clone())
            .role(
                Delegation::builder(MetadataPath::new("delegation-c").unwrap())
                    // oops, wrong key.
                    .key(delegation_b_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let delegation_b = TargetsMetadataBuilder::new()
            .delegations(delegations_b)
            .signed::<Pouf1>(&delegation_b_key)
            .unwrap();
        let raw_delegation_b = delegation_b.to_raw().unwrap();

        //// build delegation C ////

        let foo_target_file: &[u8] = b"foo contents";
        let bar_target_file: &[u8] = b"bar contents";

        let delegation_c = TargetsMetadataBuilder::new()
            .insert_target_from_slice(
                TargetPath::new("foo").unwrap(),
                foo_target_file,
                &[HashAlgorithm::Sha256],
            )
            .unwrap()
            .insert_target_from_slice(
                TargetPath::new("bar").unwrap(),
                bar_target_file,
                &[HashAlgorithm::Sha256],
            )
            .unwrap()
            .signed::<Pouf1>(&delegation_c_key)
            .unwrap();
        let raw_delegation_c = delegation_c.to_raw().unwrap();

        //// construct the database ////

        let mut repo = EphemeralRepository::new();
        let metadata = RepoBuilder::create(&mut repo)
            .trusted_root_keys(&[&etc_key])
            .trusted_snapshot_keys(&[&etc_key])
            .trusted_targets_keys(&[&targets_key])
            .trusted_timestamp_keys(&[&etc_key])
            .stage_root()
            .unwrap()
            .add_delegation_key(delegation_a_key.public().clone())
            .add_delegation_key(delegation_b_key.public().clone())
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation-a").unwrap())
                    .key(delegation_a_key.public())
                    .delegate_path(TargetPath::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation-b").unwrap())
                    .key(delegation_b_key.public())
                    .delegate_path(TargetPath::new("bar").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder
                    .insert_metadata_description(
                        MetadataPath::new("delegation-a").unwrap(),
                        MetadataDescription::from_slice(
                            raw_delegation_a.as_bytes(),
                            1,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-b").unwrap(),
                        MetadataDescription::from_slice(
                            raw_delegation_b.as_bytes(),
                            1,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-c").unwrap(),
                        MetadataDescription::from_slice(
                            raw_delegation_c.as_bytes(),
                            1,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
            })
            .unwrap()
            .commit()
            .await
            .unwrap();

        let mut tuf = Database::<Pouf1>::from_trusted_metadata(&metadata).unwrap();

        //// Verify we can trust delegation-a and delegation-b..

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::targets(),
            &MetadataPath::new("delegation-a").unwrap(),
            &raw_delegation_a,
        )
        .unwrap();

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::targets(),
            &MetadataPath::new("delegation-b").unwrap(),
            &raw_delegation_b,
        )
        .unwrap();

        //// Verify delegation-c is valid, but only when updated through delegation-a.

        assert_matches!(
            tuf.update_delegated_targets(
                &now,
                &MetadataPath::new("delegation-b").unwrap(),
                &MetadataPath::new("delegation-c").unwrap(),
                &raw_delegation_c
            ),
            Err(Error::MetadataMissingSignatures {
                role,
                number_of_valid_signatures: 0,
                threshold: 1,
            })
            if role == MetadataPath::new("delegation-c").unwrap()
        );

        tuf.update_delegated_targets(
            &now,
            &MetadataPath::new("delegation-a").unwrap(),
            &MetadataPath::new("delegation-c").unwrap(),
            &raw_delegation_c,
        )
        .unwrap();

        assert!(
            tuf.target_description(&TargetPath::new("foo").unwrap())
                .is_ok()
        );

        let target_path = TargetPath::new("bar").unwrap();
        assert_matches!(
            tuf.target_description(&target_path),
            Err(Error::TargetNotFound(p)) if p == target_path
        );
    })
}

// ---------------------------------------------------------------------------------------------
// Repositories signed with key types other than ed25519.
// ---------------------------------------------------------------------------------------------

const TARGET_PATH: &str = "foo-bar";
const TARGET_FILE: &[u8] = b"things fade, alternatives exclude";

/// Which key type a repository is built out of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keys {
    Ecdsa,
    Rsa,
}

impl Keys {
    /// The four top level role keys, and the delegation key.
    ///
    /// The delegation key is always RSA, so an ECDSA repository exercises both key types at once
    /// and shows that one piece of metadata can carry a mix of them.
    fn roles(self) -> (Vec<Box<dyn PrivateKey>>, Box<dyn PrivateKey>) {
        let pk8s = match self {
            Keys::Ecdsa => [ECDSA_1_PK8, ECDSA_2_PK8, ECDSA_3_PK8, ECDSA_4_PK8],
            Keys::Rsa => [RSA_1_PK8, RSA_2_PK8, RSA_3_PK8, RSA_4_PK8],
        };

        let roles = pk8s
            .into_iter()
            .map(|pk8| -> Box<dyn PrivateKey> {
                match self {
                    Keys::Ecdsa => Box::new(
                        EcdsaPrivateKey::from_pkcs8(pk8, SignatureScheme::EcdsaSha2NistP256)
                            .unwrap(),
                    ),
                    Keys::Rsa => Box::new(
                        RsaPrivateKey::from_pkcs8(pk8, SignatureScheme::RsassaPssSha256).unwrap(),
                    ),
                }
            })
            .collect();

        let delegation =
            RsaPrivateKey::from_pkcs8(RSA_5_PK8, SignatureScheme::RsassaPssSha256).unwrap();

        (roles, Box::new(delegation))
    }

    fn key_type(self) -> KeyType {
        match self {
            Keys::Ecdsa => KeyType::Ecdsa,
            Keys::Rsa => KeyType::Rsa,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Keys::Ecdsa => SignatureScheme::EcdsaSha2NistP256,
            Keys::Rsa => SignatureScheme::RsassaPssSha256,
        }
    }
}

/// Publish a repository whose every role is held by a key of the given type.
async fn init_server<D: Pouf + Clone>(
    remote: &mut EphemeralRepository<D>,
    keys: Keys,
    consistent_snapshot: bool,
) -> Result<(Vec<PublicKey>, RawSignedMetadata<D, RootMetadata>)> {
    let (roles, delegation_key) = keys.roles();
    let [root_key, snapshot_key, targets_key, timestamp_key] = &roles[..] else {
        unreachable!()
    };

    let metadata = RepoBuilder::create(&mut *remote)
        .trusted_root_keys(&[root_key.as_ref()])
        .trusted_snapshot_keys(&[snapshot_key.as_ref()])
        .trusted_targets_keys(&[targets_key.as_ref()])
        .trusted_timestamp_keys(&[timestamp_key.as_ref()])
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

async fn init_client<D: Pouf + Clone>(
    root_public_keys: &[PublicKey],
    remote: EphemeralRepository<D>,
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

/// A repository signed with these keys can be published and then consumed by a client, all the
/// way through to fetching a target.
async fn round_trip<D: Pouf + Clone>(keys: Keys, consistent_snapshot: bool) {
    let mut remote = EphemeralRepository::<D>::new();
    let (root_public_keys, _) = init_server(&mut remote, keys, consistent_snapshot)
        .await
        .unwrap();
    init_client(&root_public_keys, remote).await.unwrap();
}

#[test]
fn ecdsa_pouf1() {
    block_on(round_trip::<Pouf1>(Keys::Ecdsa, false));
    block_on(round_trip::<Pouf1>(Keys::Ecdsa, true));
}

#[test]
fn ecdsa_pouf2() {
    block_on(round_trip::<Pouf2>(Keys::Ecdsa, false));
    block_on(round_trip::<Pouf2>(Keys::Ecdsa, true));
}

#[test]
fn rsa_pouf1() {
    block_on(round_trip::<Pouf1>(Keys::Rsa, false));
    block_on(round_trip::<Pouf1>(Keys::Rsa, true));
}

#[test]
fn rsa_pouf2() {
    block_on(round_trip::<Pouf2>(Keys::Rsa, false));
    block_on(round_trip::<Pouf2>(Keys::Rsa, true));
}

/// Whatever else it does with them, pouf1 has to write out metadata that is valid JSON. Canonical
/// JSON is not: it leaves the newlines inside a PEM block unescaped, which no JSON parser accepts.
#[test]
fn metadata_carrying_pem_keys_is_still_json() {
    block_on(async {
        for keys in [Keys::Ecdsa, Keys::Rsa] {
            let mut remote = EphemeralRepository::<Pouf1>::new();
            let (_, root) = init_server(&mut remote, keys, false).await.unwrap();

            let parsed: Value = serde_json::from_slice(root.as_bytes()).unwrap();
            let written = parsed["signed"]["keys"].as_object().unwrap();
            assert_eq!(written.len(), 4);

            for key in written.values() {
                assert_eq!(key["keytype"], keys.key_type().as_str());
                assert_eq!(key["scheme"], keys.scheme().as_str());

                let public = key["keyval"]["public"].as_str().unwrap();
                assert!(
                    public.starts_with("-----BEGIN PUBLIC KEY-----\n"),
                    "{}",
                    public,
                );
            }
        }
    })
}

/// The client keeps the keys it read out of the metadata, so a key that arrived over the wire has
/// to be the same key that signed the metadata.
#[test]
fn keys_read_from_metadata_verify_signatures() {
    block_on(async {
        for keys in [Keys::Ecdsa, Keys::Rsa] {
            let mut remote = EphemeralRepository::<Pouf1>::new();
            let (_, raw_root) = init_server(&mut remote, keys, false).await.unwrap();

            let root = raw_root.parse_untrusted().unwrap().assume_valid().unwrap();
            let (roles, _) = keys.roles();
            let root_key = &roles[0];

            let key = root.keys().get(root_key.public().key_id()).unwrap();
            assert_eq!(key, root_key.public());
            assert_eq!(key.typ(), &keys.key_type());
            assert_eq!(key.scheme(), &keys.scheme());

            let signing_input =
                Pouf1::signing_input(&root.to_raw_data::<Pouf1>().unwrap()).unwrap();
            let signature = root_key.sign(&signing_input).unwrap();

            key.verify(&MetadataPath::root(), &signing_input, &signature)
                .unwrap();
        }
    })
}
