use assert_matches::assert_matches;
use chrono::offset::Utc;
use futures_executor::block_on;
use futures_util::io::Cursor;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tuf::Database;
use tuf::Error;
use tuf::Result;
use tuf::client::{Client, Config};
use tuf::crypto::{
    EcdsaPrivateKey, Ed25519PrivateKey, HashAlgorithm, KeyType, PrivateKey, PublicKey,
    SignatureScheme,
};
use tuf::metadata::MetadataThreshold;
use tuf::metadata::{
    Delegation, Delegations, Metadata, MetadataDescription, MetadataPath, MetadataVersion,
    PathPattern, RawSignedMetadata, RootMetadata, TargetDescription, TargetPath,
    TargetsMetadataBuilder,
};
use tuf::pouf::{Pouf, Pouf1};
use tuf::repo_builder::RepoBuilder;
use tuf::repository::{EphemeralRepository, RepositoryStorage};

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
                    .delegate_path(PathPattern::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder.insert_metadata_description(
                    MetadataPath::new("delegation").unwrap(),
                    MetadataDescription::from_slice(
                        &[0u8],
                        MetadataVersion::ONE,
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
                    .delegate_path(PathPattern::new("foo").unwrap())
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
                            &[0u8],
                            MetadataVersion::ONE,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-b").unwrap(),
                        MetadataDescription::from_slice(
                            &[0u8],
                            MetadataVersion::ONE,
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

        //// build delegation B ////

        let delegations = Delegations::builder()
            .key(delegation_b_key.public().clone())
            .role(
                Delegation::builder(MetadataPath::new("delegation-b").unwrap())
                    .key(delegation_b_key.public())
                    .delegate_path(PathPattern::new("foo").unwrap())
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
                    .delegate_path(PathPattern::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .stage_targets()
            .unwrap()
            .stage_snapshot_with_builder(|builder| {
                builder.insert_metadata_description(
                    MetadataPath::new("delegation").unwrap(),
                    MetadataDescription::from_slice(
                        &[0u8],
                        MetadataVersion::ONE,
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
                threshold: MetadataThreshold::ONE,
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
                    .delegate_path(PathPattern::new("foo").unwrap())
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
                    .delegate_path(PathPattern::new("foo").unwrap())
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
                    .delegate_path(PathPattern::new("foo").unwrap())
                    .build()
                    .unwrap(),
            )
            .add_delegation_role(
                Delegation::builder(MetadataPath::new("delegation-b").unwrap())
                    .key(delegation_b_key.public())
                    .delegate_path(PathPattern::new("bar").unwrap())
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
                            MetadataVersion::ONE,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-b").unwrap(),
                        MetadataDescription::from_slice(
                            raw_delegation_b.as_bytes(),
                            MetadataVersion::ONE,
                            &[HashAlgorithm::Sha256],
                        )
                        .unwrap(),
                    )
                    .insert_metadata_description(
                        MetadataPath::new("delegation-c").unwrap(),
                        MetadataDescription::from_slice(
                            raw_delegation_c.as_bytes(),
                            MetadataVersion::ONE,
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
                threshold: MetadataThreshold::ONE,
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
// Searching delegated roles for a target, with both a client and a database.
// ---------------------------------------------------------------------------------------------

/// A targets role in a test repository: its name, the targets it lists, and the delegations it
/// makes, in order, as `(role, paths, terminating)`.
type TestRole = (
    &'static str,
    &'static [&'static str],
    &'static [(&'static str, &'static [&'static str], bool)],
);

/// The description of the target at `path` that `role` lists. Each target's contents name the
/// role that lists it, so that it's clear which role a description came from.
fn description(role: &str, path: &str) -> TargetDescription {
    TargetDescription::from_slice(
        format!("{role}:{path}").as_bytes(),
        &[HashAlgorithm::Sha256],
    )
    .unwrap()
}

/// Add the targets that `role` lists to `builder`.
fn insert_targets(
    mut builder: TargetsMetadataBuilder,
    (name, targets, _): &TestRole,
) -> TargetsMetadataBuilder {
    for target in targets.iter() {
        builder = builder.insert_target_description(
            TargetPath::new(*target).unwrap(),
            description(name, target),
        );
    }
    builder
}

/// Look up `path` with both a client and a database, in a repository with the given targets
/// roles, which start with the top-level `targets`, and list each role after one that delegates
/// to it. A role that's delegated to but not listed is in the snapshot, but its metadata can't be
/// fetched or loaded.
fn lookup_target(
    roles: &[TestRole],
    path: &str,
) -> (Result<TargetDescription>, Result<TargetDescription>) {
    lookup_target_with_config(Config::default(), roles, path)
}

/// Like [lookup_target], but with a client that uses `config`.
fn lookup_target_with_config(
    config: Config,
    roles: &[TestRole],
    path: &str,
) -> (Result<TargetDescription>, Result<TargetDescription>) {
    block_on(async {
        let key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8).unwrap();
        let delegation_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8).unwrap();

        let delegation = |(role, paths, terminating): &(&'static str, &[&str], bool)| {
            Delegation::new(
                MetadataPath::new(*role).unwrap(),
                *terminating,
                MetadataThreshold::ONE,
                HashSet::from([delegation_key.public().key_id().clone()]),
                paths
                    .iter()
                    .map(|path| PathPattern::new(*path).unwrap())
                    .collect(),
            )
            .unwrap()
        };
        let (top_level, delegated_roles) = roles.split_first().unwrap();
        assert_eq!(top_level.0, "targets");

        let mut signed = HashMap::new();
        for role @ (name, _, delegations) in delegated_roles {
            let mut builder = insert_targets(TargetsMetadataBuilder::new(), role);
            if !delegations.is_empty() {
                let mut delegations_builder =
                    Delegations::builder().key(delegation_key.public().clone());
                for d in delegations.iter() {
                    delegations_builder = delegations_builder.role(delegation(d));
                }
                builder = builder.delegations(delegations_builder.build().unwrap());
            }
            signed.insert(*name, builder.signed::<Pouf1>(&delegation_key).unwrap());
        }

        // Each role that's delegated to, along with the first role that delegates to it.
        let mut parents: Vec<(&str, &str)> = Vec::new();
        for (parent, _, delegations) in roles {
            for (role, _, _) in delegations.iter() {
                if !parents.iter().any(|(r, _)| r == role) {
                    parents.push((role, parent));
                }
            }
        }

        let mut remote = EphemeralRepository::<Pouf1>::new();
        let mut builder = RepoBuilder::create(&mut remote)
            .trusted_root_keys(&[&key])
            .trusted_targets_keys(&[&key])
            .trusted_snapshot_keys(&[&key])
            .trusted_timestamp_keys(&[&key])
            .stage_root()
            .unwrap()
            .add_delegation_key(delegation_key.public().clone());
        for d in top_level.2.iter() {
            builder = builder.add_delegation_role(delegation(d));
        }
        let metadata = builder
            .stage_targets_with_builder(|builder| insert_targets(builder, top_level))
            .unwrap()
            .stage_snapshot_with_builder(|mut builder| {
                for (role, _) in &parents {
                    builder = match signed.get(role) {
                        Some(targets) => builder
                            .insert_metadata_with_path(*role, targets, &[HashAlgorithm::Sha256])
                            .unwrap(),
                        None => builder.insert_metadata_description(
                            MetadataPath::new(*role).unwrap(),
                            MetadataDescription::from_slice(
                                &[],
                                MetadataVersion::ONE,
                                &[HashAlgorithm::Sha256],
                            )
                            .unwrap(),
                        ),
                    };
                }
                builder
            })
            .unwrap()
            .commit()
            .await
            .unwrap();

        let mut database = Database::<Pouf1>::from_trusted_metadata(&metadata).unwrap();
        for (role, parent) in &parents {
            if let Some(targets) = signed.get(role) {
                let raw = targets.to_raw().unwrap();
                remote
                    .store_metadata(
                        &MetadataPath::new(*role).unwrap(),
                        Some(MetadataVersion::ONE),
                        &mut raw.as_bytes(),
                    )
                    .await
                    .unwrap();
                database
                    .update_delegated_targets(
                        &Utc::now(),
                        &MetadataPath::new(*parent).unwrap(),
                        &MetadataPath::new(*role).unwrap(),
                        &raw,
                    )
                    .unwrap();
            }
        }

        let target = TargetPath::new(path).unwrap();

        let mut client = Client::with_trusted_root(
            config,
            metadata.root().unwrap(),
            EphemeralRepository::new(),
            remote,
        )
        .await
        .unwrap();
        client.update().await.unwrap();

        (
            client.fetch_target_description(&target).await,
            database.target_description(&target),
        )
    })
}

/// Assert that both a client and a database find the description of `path` that `role` lists.
fn assert_found(roles: &[TestRole], path: &str, role: &str) {
    let expected = description(role, path);
    let (client, database) = lookup_target(roles, path);
    assert_matches!(client, Ok(d) if d == expected, "client looking up {path}");
    assert_matches!(database, Ok(d) if d == expected, "database looking up {path}");
}

/// Assert that neither a client nor a database finds `path`.
fn assert_not_found(roles: &[TestRole], path: &str) {
    let (client, database) = lookup_target(roles, path);
    assert_matches!(
        client,
        Err(Error::TargetNotFound(_)),
        "client looking up {path}"
    );
    assert_matches!(
        database,
        Err(Error::TargetNotFound(_)),
        "database looking up {path}"
    );
}

#[test]
fn search_follows_matching_delegations_in_order() {
    let roles: &[TestRole] = &[
        (
            "targets",
            &["x/foo"],
            &[
                ("a", &["a/*"], false),
                ("b", &["b/v-?.tgz"], false),
                ("c", &["*/*"], false),
            ],
        ),
        ("a", &["a/foo"], &[]),
        ("b", &["b/v-1.tgz", "b/v-10.tgz"], &[]),
        (
            "c",
            &["x/foo", "a/foo", "b/v-10.tgz", "c/foo", "c/bar/foo"],
            &[],
        ),
    ];

    // A role's own targets come before those of the roles it delegates to, which come in the
    // order it delegates to them.
    assert_found(roles, "x/foo", "targets");
    assert_found(roles, "a/foo", "a");
    assert_found(roles, "b/v-1.tgz", "b");
    assert_found(roles, "c/foo", "c");

    // `?` matches one character, so b isn't trusted for b/v-10.tgz, and `*` doesn't match a `/`,
    // so no role is trusted for c/bar/foo.
    assert_found(roles, "b/v-10.tgz", "c");
    assert_not_found(roles, "c/bar/foo");
}

#[test]
fn search_only_trusts_roles_for_their_paths() {
    // A target is only trusted if it matches the paths of every delegation on the way to the role
    // that lists it.
    let roles: &[TestRole] = &[
        ("targets", &[], &[("a", &["foo/*"], false)]),
        (
            "a",
            &["foo/1", "bar/1"],
            &[("b", &["foo/2", "bar/2"], false)],
        ),
        ("b", &["foo/2", "bar/2", "foo/3"], &[]),
    ];

    assert_found(roles, "foo/1", "a");
    assert_found(roles, "foo/2", "b");
    for path in ["bar/1", "bar/2", "foo/3"] {
        assert_not_found(roles, path);
    }
}

#[test]
fn terminating_delegation_ends_search() {
    let roles: &[TestRole] = &[
        (
            "targets",
            &[],
            &[
                ("x", &["x/*"], true),
                ("a", &["a/*"], true),
                ("p", &["p/*"], false),
                ("b", &["*/*"], false),
            ],
        ),
        ("x", &[], &[]),
        ("a", &["a/foo"], &[]),
        ("p", &[], &[("q", &["p/*"], true)]),
        ("q", &[], &[]),
        ("b", &["a/foo", "a/bar", "p/foo", "b/foo"], &[]),
    ];

    // A terminating delegation that the target doesn't match doesn't end the search.
    assert_found(roles, "b/foo", "b");
    assert_found(roles, "a/foo", "a");

    // One that it does match does, even if its role doesn't list the target, and even if it's
    // under a delegation that isn't terminating.
    assert_not_found(roles, "a/bar");
    assert_not_found(roles, "p/foo");
}

#[test]
fn search_skips_visited_roles() {
    // a delegates to itself, and both a and b delegate to c. Getting to d means going on past both
    // the roles that were visited before.
    let roles: &[TestRole] = &[
        (
            "targets",
            &[],
            &[("a", &["*"], false), ("b", &["*"], false)],
        ),
        ("a", &[], &[("c", &["*"], false), ("a", &["*"], false)]),
        ("b", &[], &[("c", &["*"], false), ("d", &["*"], false)]),
        ("c", &[], &[]),
        ("d", &["foo"], &[]),
    ];

    assert_found(roles, "foo", "d");
}

#[test]
fn search_ends_at_metadata_it_cannot_load() {
    // The metadata of m is missing, and since m could have listed foo, b can't be trusted for it.
    let roles: &[TestRole] = &[
        (
            "targets",
            &[],
            &[("a", &["*"], false), ("b", &["*"], false)],
        ),
        ("a", &[], &[("m", &["*"], false)]),
        ("b", &["foo"], &[]),
    ];

    let (client, database) = lookup_target(roles, "foo");
    assert_matches!(
        client,
        Err(Error::MetadataNotFound { path, .. }) if path == MetadataPath::new("m").unwrap()
    );
    assert_matches!(database, Err(Error::TargetNotFound(_)));
}

#[test]
fn search_ends_at_max_delegation_depth() {
    // With a maximum depth of 1, a client can't search c, and so can't trust b for foo either. A
    // database has no maximum depth.
    let roles: &[TestRole] = &[
        (
            "targets",
            &[],
            &[("a", &["*"], false), ("b", &["*"], false)],
        ),
        ("a", &[], &[("c", &["*"], false)]),
        ("b", &["foo"], &[]),
        ("c", &["foo"], &[]),
    ];
    let config = Config::build().max_delegation_depth(1).finish().unwrap();

    let (client, database) = lookup_target_with_config(config, roles, "foo");
    assert_matches!(client, Err(Error::TargetNotFound(_)));
    assert_eq!(database.unwrap(), description("c", "foo"));
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
}

impl Keys {
    /// The four top level role keys, and the delegation key.
    ///
    /// The delegation key is always ed25519, so a repository exercises two key types at once and
    /// shows that one piece of metadata can carry a mix of them.
    fn roles(self) -> (Vec<Box<dyn PrivateKey>>, Box<dyn PrivateKey>) {
        let pk8s = match self {
            Keys::Ecdsa => [ECDSA_1_PK8, ECDSA_2_PK8, ECDSA_3_PK8, ECDSA_4_PK8],
        };

        let roles = pk8s
            .into_iter()
            .map(|pk8| -> Box<dyn PrivateKey> {
                match self {
                    Keys::Ecdsa => Box::new(
                        EcdsaPrivateKey::from_pkcs8(pk8, SignatureScheme::EcdsaSha2NistP256)
                            .unwrap(),
                    ),
                }
            })
            .collect();

        let delegation = Ed25519PrivateKey::from_pkcs8(ED25519_5_PK8).unwrap();

        (roles, Box::new(delegation))
    }

    fn key_type(self) -> KeyType {
        match self {
            Keys::Ecdsa => KeyType::Ecdsa,
        }
    }

    fn scheme(self) -> SignatureScheme {
        match self {
            Keys::Ecdsa => SignatureScheme::EcdsaSha2NistP256,
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
                .delegate_path(PathPattern::new("foo").unwrap())
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
        MetadataVersion::ONE,
        MetadataThreshold::ONE,
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

/// Whatever else it does with them, pouf1 has to write out metadata that is valid JSON. Canonical
/// JSON is not: it leaves the newlines inside a PEM block unescaped, which no JSON parser accepts.
#[test]
fn metadata_carrying_pem_keys_is_still_json() {
    block_on(async {
        for keys in [Keys::Ecdsa] {
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
        for keys in [Keys::Ecdsa] {
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
