//! Isolated, test-only public identity comparison slice.
//!
//! Source-connected inputs use `DestinationId::canonicalize` and the ledger's
//! canonical genesis hash / boot verification helpers. The expected
//! association, its authenticated status, public-key bytes, and identity
//! comparison policy are synthetic test fixtures. This does not invoke CLI
//! startup, load a signer, or grant production authority.
//!
//! Pinned source references:
//! - `restore_completion.rs:148-179` (`DestinationId::canonicalize`)
//! - `genesis.rs:1576-1630` (`compute_canonical_genesis_hash`)
//! - `genesis.rs:1797-1855` (`verify_boot_time_genesis`)
//! - `main.rs:2404-2449` (retained boot hash can be `None`)
//!
//! Temporary directories/files are created only by fixture helpers and are
//! removed by `tempfile::TempDir` cleanup, outside the pure comparator.

use qbind_crypto::ConsensusSigSuiteId;
use qbind_ledger::{
    compute_canonical_genesis_hash, verify_boot_time_genesis, GenesisAllocation, GenesisConfig,
    GenesisCouncilConfig, GenesisHash, GenesisMonetaryConfig, GenesisValidator,
    NetworkEnvironmentPolicy,
};
use qbind_node::restore_completion::DestinationId;
use qbind_types::NetworkEnvironment;
use std::path::Path;

const SYNTHETIC_PUBLIC_KEY: &[u8] = &[0xA5; 64];
const SYNTHETIC_SUITE: ConsensusSigSuiteId = ConsensusSigSuiteId::new(100);
const SYNTHETIC_VALIDATOR_ID: u64 = 7;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicIdentity {
    environment: Evidence<NetworkEnvironment>,
    numeric_chain_id: Evidence<u64>,
    genesis_hash: Evidence<GenesisHash>,
    destination_id: Evidence<String>,
    validator_id: Evidence<u64>,
    suite_id: Evidence<ConsensusSigSuiteId>,
    signer_public_key: Evidence<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Evidence<T> {
    Present(T),
    Missing,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedAssociation(PublicIdentity);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedSource {
    SyntheticAuthenticated(ExpectedAssociation),
    Missing,
    Untrusted(ExpectedAssociation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingKind {
    Missing,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityField {
    Environment,
    NumericChainId,
    GenesisHash,
    DestinationId,
    ValidatorId,
    SuiteId,
    SignerPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AcquisitionFailure {
    Unreadable,
    Malformed,
    Ambiguous,
    MissingRetainedBootHash,
    RetainedBootHashMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Refusal {
    MissingExpectedAssociation,
    UntrustedExpectedAssociation,
    Acquisition(AcquisitionFailure),
    Missing(IdentityField),
    Unavailable(IdentityField),
    Mismatch(IdentityField),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Comparison {
    Match,
    Refuse(Refusal),
}

fn synthetic_expected() -> ExpectedAssociation {
    ExpectedAssociation(PublicIdentity {
        environment: Evidence::Present(NetworkEnvironment::Devnet),
        numeric_chain_id: Evidence::Present(NetworkEnvironment::Devnet.chain_id().as_u64()),
        genesis_hash: Evidence::Present([0x31; 32]),
        destination_id: Evidence::Present("/synthetic/qbind-destination".to_string()),
        validator_id: Evidence::Present(SYNTHETIC_VALIDATOR_ID),
        suite_id: Evidence::Present(SYNTHETIC_SUITE),
        signer_public_key: Evidence::Present(SYNTHETIC_PUBLIC_KEY.to_vec()),
    })
}

fn compare(observed: &PublicIdentity, expected: ExpectedSource) -> Comparison {
    compare_with_test_bypass(observed, expected, None, false)
}

/// Test-only mutation seam: bypassing one selected equality or the synthetic
/// authority guard must make its negative control report Match. This helper is
/// not production code and cannot confer authority.
fn compare_with_test_bypass(
    observed: &PublicIdentity,
    expected: ExpectedSource,
    bypass_field: Option<IdentityField>,
    bypass_expected_authentication: bool,
) -> Comparison {
    let expected = match expected {
        ExpectedSource::Missing => return Comparison::Refuse(Refusal::MissingExpectedAssociation),
        ExpectedSource::Untrusted(_) if !bypass_expected_authentication => {
            return Comparison::Refuse(Refusal::UntrustedExpectedAssociation)
        }
        ExpectedSource::Untrusted(association)
        | ExpectedSource::SyntheticAuthenticated(association) => association,
    };

    let checks = [
        (
            IdentityField::Environment,
            compare_field(
                IdentityField::Environment,
                &observed.environment,
                &expected.0.environment,
            ),
        ),
        (
            IdentityField::NumericChainId,
            compare_field(
                IdentityField::NumericChainId,
                &observed.numeric_chain_id,
                &expected.0.numeric_chain_id,
            ),
        ),
        (
            IdentityField::GenesisHash,
            compare_field(
                IdentityField::GenesisHash,
                &observed.genesis_hash,
                &expected.0.genesis_hash,
            ),
        ),
        (
            IdentityField::DestinationId,
            compare_field(
                IdentityField::DestinationId,
                &observed.destination_id,
                &expected.0.destination_id,
            ),
        ),
        (
            IdentityField::ValidatorId,
            compare_field(
                IdentityField::ValidatorId,
                &observed.validator_id,
                &expected.0.validator_id,
            ),
        ),
        (
            IdentityField::SuiteId,
            compare_field(
                IdentityField::SuiteId,
                &observed.suite_id,
                &expected.0.suite_id,
            ),
        ),
        (
            IdentityField::SignerPublicKey,
            compare_field(
                IdentityField::SignerPublicKey,
                &observed.signer_public_key,
                &expected.0.signer_public_key,
            ),
        ),
    ];

    for (field, result) in checks {
        if bypass_field != Some(field) {
            if let Some(refusal) = result {
                return Comparison::Refuse(refusal);
            }
        }
    }

    Comparison::Match
}

fn compare_field<T: PartialEq>(
    field: IdentityField,
    actual: &Evidence<T>,
    expected: &Evidence<T>,
) -> Option<Refusal> {
    match (actual, expected) {
        (Evidence::Missing, _) => Some(Refusal::Missing(field)),
        (Evidence::Unavailable, _)
        | (Evidence::Present(_), Evidence::Missing | Evidence::Unavailable) => {
            Some(Refusal::Unavailable(field))
        }
        (Evidence::Present(actual), Evidence::Present(wanted)) if actual != wanted => {
            Some(Refusal::Mismatch(field))
        }
        (Evidence::Present(_), Evidence::Present(_)) => None,
    }
}

fn synthetic_observed_from_helpers(root: &Path) -> (PublicIdentity, GenesisHash) {
    let destination = root.join("destination");
    std::fs::create_dir(&destination).expect("create synthetic destination");
    let destination_id =
        DestinationId::canonicalize(&destination).expect("canonicalize synthetic destination");

    let genesis_path = root.join("genesis.json");
    let genesis = synthetic_devnet_genesis();
    std::fs::write(
        &genesis_path,
        serde_json::to_vec(&genesis).expect("serialize synthetic genesis"),
    )
    .expect("write synthetic genesis");

    // Read exactly once, parse into an owned value, and derive both the
    // identity fields and canonical hash from that same parse.
    let bytes = std::fs::read(&genesis_path).expect("read synthetic genesis");
    let parsed: GenesisConfig = serde_json::from_slice(&bytes).expect("parse synthetic genesis");
    let policy = NetworkEnvironmentPolicy::Devnet;
    let canonical_hash = compute_canonical_genesis_hash(&parsed, policy);
    let verified = verify_boot_time_genesis(policy, &parsed, Some(&canonical_hash))
        .expect("verify synthetic genesis against its same-parse hash");
    assert_eq!(verified.canonical_hash, canonical_hash);

    (
        PublicIdentity {
            environment: Evidence::Present(NetworkEnvironment::Devnet),
            numeric_chain_id: Evidence::Present(NetworkEnvironment::Devnet.chain_id().as_u64()),
            genesis_hash: Evidence::Present(canonical_hash),
            destination_id: Evidence::Present(destination_id.as_str().to_string()),
            validator_id: Evidence::Present(SYNTHETIC_VALIDATOR_ID),
            suite_id: Evidence::Present(SYNTHETIC_SUITE),
            signer_public_key: Evidence::Present(SYNTHETIC_PUBLIC_KEY.to_vec()),
        },
        canonical_hash,
    )
}

fn external_genesis_observation(
    path: &Path,
    retained_boot_hash: Option<&GenesisHash>,
) -> Result<(String, GenesisHash), AcquisitionFailure> {
    let retained = retained_boot_hash.ok_or(AcquisitionFailure::MissingRetainedBootHash)?;
    let bytes = std::fs::read(path).map_err(|_| AcquisitionFailure::Unreadable)?;
    let parsed: GenesisConfig =
        serde_json::from_slice(&bytes).map_err(|_| AcquisitionFailure::Malformed)?;
    let policy = NetworkEnvironmentPolicy::Devnet;
    let actual = compute_canonical_genesis_hash(&parsed, policy);
    if &actual != retained {
        return Err(AcquisitionFailure::RetainedBootHashMismatch);
    }
    let verified = verify_boot_time_genesis(policy, &parsed, Some(retained))
        .map_err(|_| AcquisitionFailure::RetainedBootHashMismatch)?;
    if verified.canonical_hash != actual {
        return Err(AcquisitionFailure::RetainedBootHashMismatch);
    }
    Ok((parsed.chain_id, actual))
}

fn synthetic_devnet_genesis() -> GenesisConfig {
    GenesisConfig::new(
        "qbind-devnet-v0",
        1_738_000_000_000,
        vec![GenesisAllocation::new(
            "0x1111111111111111111111111111111111111111",
            1_000_000u128,
        )],
        vec![GenesisValidator::new(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "synthetic-public-key-not-used-for-signing",
            100_000u128,
        )],
        GenesisCouncilConfig::new(
            vec![
                "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
            ],
            2,
        ),
        GenesisMonetaryConfig::mainnet_default(),
    )
}

fn set_missing(identity: &mut PublicIdentity, field: IdentityField, kind: MissingKind) {
    match field {
        IdentityField::Environment => identity.environment = evidence_state(kind),
        IdentityField::NumericChainId => identity.numeric_chain_id = evidence_state(kind),
        IdentityField::GenesisHash => identity.genesis_hash = evidence_state(kind),
        IdentityField::DestinationId => identity.destination_id = evidence_state(kind),
        IdentityField::ValidatorId => identity.validator_id = evidence_state(kind),
        IdentityField::SuiteId => identity.suite_id = evidence_state(kind),
        IdentityField::SignerPublicKey => identity.signer_public_key = evidence_state(kind),
    }
}

fn evidence_state<T>(kind: MissingKind) -> Evidence<T> {
    match kind {
        MissingKind::Missing => Evidence::Missing,
        MissingKind::Unavailable => Evidence::Unavailable,
    }
}

fn set_mismatch(identity: &mut PublicIdentity, field: IdentityField) {
    match field {
        IdentityField::Environment => {
            identity.environment = Evidence::Present(NetworkEnvironment::Testnet)
        }
        IdentityField::NumericChainId => identity.numeric_chain_id = Evidence::Present(u64::MAX),
        IdentityField::GenesisHash => identity.genesis_hash = Evidence::Present([0x32; 32]),
        IdentityField::DestinationId => {
            identity.destination_id = Evidence::Present("/synthetic/other-destination".to_string())
        }
        IdentityField::ValidatorId => {
            identity.validator_id = Evidence::Present(SYNTHETIC_VALIDATOR_ID + 1)
        }
        IdentityField::SuiteId => {
            identity.suite_id = Evidence::Present(ConsensusSigSuiteId::new(101))
        }
        IdentityField::SignerPublicKey => {
            let mut key = SYNTHETIC_PUBLIC_KEY.to_vec();
            *key.last_mut().expect("non-empty synthetic key") ^= 1;
            identity.signer_public_key = Evidence::Present(key);
        }
    }
}

const FIELDS: [IdentityField; 7] = [
    IdentityField::Environment,
    IdentityField::NumericChainId,
    IdentityField::GenesisHash,
    IdentityField::DestinationId,
    IdentityField::ValidatorId,
    IdentityField::SuiteId,
    IdentityField::SignerPublicKey,
];

#[test]
fn matching_synthetic_association_is_comparison_only() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let (observed, retained_hash) = synthetic_observed_from_helpers(temp.path());
    let mut expected = synthetic_expected();
    expected.0.genesis_hash = Evidence::Present(retained_hash);
    expected.0.destination_id = observed.destination_id.clone();

    assert_eq!(
        compare(&observed, ExpectedSource::SyntheticAuthenticated(expected)),
        Comparison::Match
    );
    // The test result is a pure comparison enum; there are no authority,
    // startup, signer, participation, recovery, or restart capabilities.
}

#[test]
fn every_field_rejects_missing_unavailable_and_mismatched_values() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let (baseline, retained_hash) = synthetic_observed_from_helpers(temp.path());
    let mut expected = synthetic_expected();
    expected.0.genesis_hash = Evidence::Present(retained_hash);
    expected.0.destination_id = baseline.destination_id.clone();

    for field in FIELDS {
        let mut missing = baseline.clone();
        set_missing(&mut missing, field, MissingKind::Missing);
        assert_eq!(
            compare(
                &missing,
                ExpectedSource::SyntheticAuthenticated(expected.clone())
            ),
            Comparison::Refuse(Refusal::Missing(field)),
            "missing {field:?} must refuse"
        );
        assert_eq!(
            compare_with_test_bypass(
                &missing,
                ExpectedSource::SyntheticAuthenticated(expected.clone()),
                Some(field),
                false,
            ),
            Comparison::Match,
            "bypassing the {field:?} missing-value guard must invalidate the negative control"
        );

        let mut unavailable = baseline.clone();
        set_missing(&mut unavailable, field, MissingKind::Unavailable);
        assert_eq!(
            compare(
                &unavailable,
                ExpectedSource::SyntheticAuthenticated(expected.clone())
            ),
            Comparison::Refuse(Refusal::Unavailable(field)),
            "unavailable {field:?} must refuse"
        );
        assert_eq!(
            compare_with_test_bypass(
                &unavailable,
                ExpectedSource::SyntheticAuthenticated(expected.clone()),
                Some(field),
                false,
            ),
            Comparison::Match,
            "bypassing the {field:?} unavailable-value guard must invalidate the negative control"
        );

        let mut mismatched = baseline.clone();
        set_mismatch(&mut mismatched, field);
        assert_eq!(
            compare(
                &mismatched,
                ExpectedSource::SyntheticAuthenticated(expected.clone())
            ),
            Comparison::Refuse(Refusal::Mismatch(field)),
            "mismatched {field:?} must refuse"
        );
        assert_eq!(
            compare_with_test_bypass(
                &mismatched,
                ExpectedSource::SyntheticAuthenticated(expected.clone()),
                Some(field),
                false,
            ),
            Comparison::Match,
            "bypassing the {field:?} equality must invalidate the negative control"
        );
    }
}

#[test]
fn full_key_mismatch_with_same_short_prefix_is_rejected() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let (mut observed, retained_hash) = synthetic_observed_from_helpers(temp.path());
    let mut expected = synthetic_expected();
    expected.0.genesis_hash = Evidence::Present(retained_hash);
    expected.0.destination_id = observed.destination_id.clone();
    let mut different_key = SYNTHETIC_PUBLIC_KEY.to_vec();
    *different_key.last_mut().expect("non-empty synthetic key") ^= 1;
    observed.signer_public_key = Evidence::Present(different_key.clone());
    assert_eq!(
        &different_key[..4],
        &SYNTHETIC_PUBLIC_KEY[..4],
        "negative control uses an identical short display prefix"
    );
    assert_eq!(
        compare(
            &observed,
            ExpectedSource::SyntheticAuthenticated(expected.clone())
        ),
        Comparison::Refuse(Refusal::Mismatch(IdentityField::SignerPublicKey))
    );
    assert_eq!(
        compare_with_test_bypass(
            &observed,
            ExpectedSource::SyntheticAuthenticated(expected),
            Some(IdentityField::SignerPublicKey),
            false,
        ),
        Comparison::Match,
        "bypassing full-byte comparison must invalidate the negative control"
    );
}

#[test]
fn absent_and_untrusted_expected_associations_never_match() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let (observed, retained_hash) = synthetic_observed_from_helpers(temp.path());
    let mut association = synthetic_expected();
    association.0.genesis_hash = Evidence::Present(retained_hash);
    association.0.destination_id = observed.destination_id.clone();

    assert_eq!(
        compare(&observed, ExpectedSource::Missing),
        Comparison::Refuse(Refusal::MissingExpectedAssociation)
    );
    assert_eq!(
        compare(&observed, ExpectedSource::Untrusted(association.clone())),
        Comparison::Refuse(Refusal::UntrustedExpectedAssociation)
    );
    assert_eq!(
        compare_with_test_bypass(
            &observed,
            ExpectedSource::Untrusted(association),
            None,
            true,
        ),
        Comparison::Match,
        "bypassing expected-association authentication must invalidate the negative control"
    );
}

#[test]
fn acquisition_and_parsing_failures_refuse_before_comparison() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let (baseline, retained_hash) = synthetic_observed_from_helpers(temp.path());
    let mut expected = synthetic_expected();
    expected.0.genesis_hash = Evidence::Present(retained_hash);
    expected.0.destination_id = baseline.destination_id.clone();

    let missing_path = temp.path().join("unreadable-missing-genesis.json");
    let unreadable = external_genesis_observation(&missing_path, Some(&retained_hash));
    assert_eq!(unreadable, Err(AcquisitionFailure::Unreadable));
    assert_eq!(
        compare_acquisition(
            unreadable.clone().map(|_| ()),
            &baseline,
            ExpectedSource::SyntheticAuthenticated(expected.clone()),
            false,
        ),
        Comparison::Refuse(Refusal::Acquisition(AcquisitionFailure::Unreadable))
    );

    let malformed_path = temp.path().join("malformed-genesis.json");
    std::fs::write(&malformed_path, b"{not-json").expect("write malformed synthetic fixture");
    let malformed = external_genesis_observation(&malformed_path, Some(&retained_hash));
    assert_eq!(malformed, Err(AcquisitionFailure::Malformed));
    assert_eq!(
        compare_acquisition(
            malformed.clone().map(|_| ()),
            &baseline,
            ExpectedSource::SyntheticAuthenticated(expected.clone()),
            false,
        ),
        Comparison::Refuse(Refusal::Acquisition(AcquisitionFailure::Malformed))
    );

    // Ambiguous resolution is not produced by these helpers. Exercise its
    // refusal as an explicitly simulated acquisition error.
    let simulated_errors = [
        AcquisitionFailure::Unreadable,
        AcquisitionFailure::Malformed,
        AcquisitionFailure::Ambiguous,
    ];
    for failure in simulated_errors {
        let result = compare_acquisition(
            Err::<(), _>(failure.clone()),
            &baseline,
            ExpectedSource::SyntheticAuthenticated(expected.clone()),
            false,
        );
        assert_eq!(
            result,
            Comparison::Refuse(Refusal::Acquisition(failure.clone()))
        );
        assert_eq!(
            compare_acquisition(
                Err::<(), _>(failure),
                &baseline,
                ExpectedSource::SyntheticAuthenticated(expected.clone()),
                true,
            ),
            Comparison::Match,
            "bypassing the pre-comparator acquisition guard must invalidate the negative control"
        );
    }
}

fn compare_acquisition<T>(
    acquisition: Result<T, AcquisitionFailure>,
    observed: &PublicIdentity,
    expected: ExpectedSource,
    bypass_acquisition_guard: bool,
) -> Comparison {
    match acquisition {
        Ok(_) => compare(observed, expected),
        Err(failure) if bypass_acquisition_guard => {
            let _ = failure;
            compare(observed, expected)
        }
        Err(failure) => Comparison::Refuse(Refusal::Acquisition(failure)),
    }
}

#[test]
fn external_genesis_uses_same_owned_parse_and_requires_retained_boot_hash() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let genesis_path = temp.path().join("external-genesis.json");
    let genesis = synthetic_devnet_genesis();
    std::fs::write(
        &genesis_path,
        serde_json::to_vec(&genesis).expect("serialize synthetic genesis"),
    )
    .expect("write synthetic genesis");

    // The retained value is computed from an owned fixture value here, then
    // the acquisition helper independently reads once and parses once.
    let retained = compute_canonical_genesis_hash(&genesis, NetworkEnvironmentPolicy::Devnet);
    let (chain_name, actual) =
        external_genesis_observation(&genesis_path, Some(&retained)).expect("same-parse identity");
    assert_eq!(chain_name, "qbind-devnet-v0");
    assert_eq!(actual, retained);
    assert_eq!(
        external_genesis_observation(&genesis_path, None),
        Err(AcquisitionFailure::MissingRetainedBootHash),
        "this synthetic profile refuses None; it selects no production policy"
    );

    let wrong_retained = [0x99; 32];
    assert_eq!(
        external_genesis_observation(&genesis_path, Some(&wrong_retained)),
        Err(AcquisitionFailure::RetainedBootHashMismatch)
    );
}

#[test]
fn identity_comparator_has_positive_and_per_field_sensitivity_controls() {
    let expected = synthetic_expected();
    let observed = expected.0.clone();
    assert_eq!(
        compare(
            &observed,
            ExpectedSource::SyntheticAuthenticated(expected.clone())
        ),
        Comparison::Match,
        "positive control prevents an always-refuse checker from passing"
    );

    for field in FIELDS {
        let mut changed = observed.clone();
        set_mismatch(&mut changed, field);
        let negative = compare(
            &changed,
            ExpectedSource::SyntheticAuthenticated(expected.clone()),
        );
        assert_eq!(negative, Comparison::Refuse(Refusal::Mismatch(field)));
        assert_eq!(
            compare_with_test_bypass(
                &changed,
                ExpectedSource::SyntheticAuthenticated(expected.clone()),
                Some(field),
                false,
            ),
            Comparison::Match,
            "sensitivity control for {field:?}"
        );
    }
}

#[test]
fn helper_failures_and_synthetic_errors_are_distinguished() {
    let temp = tempfile::tempdir().expect("temporary fixture directory");
    let missing_destination = temp.path().join("missing-destination");
    assert!(
        DestinationId::canonicalize(&missing_destination).is_err(),
        "actual helper refuses a missing destination path"
    );

    let malformed_path = temp.path().join("not-genesis.json");
    std::fs::write(&malformed_path, b"{").expect("write malformed JSON");
    assert_eq!(
        external_genesis_observation(&malformed_path, Some(&[1; 32])),
        Err(AcquisitionFailure::Malformed),
        "malformed parse is an observed serde failure"
    );

    // This ambiguity is synthetic: canonicalization and the external-genesis
    // helpers do not report an ambiguous association/source category.
    assert_eq!(
        compare_acquisition(
            Err::<(), _>(AcquisitionFailure::Ambiguous),
            &synthetic_expected().0,
            ExpectedSource::SyntheticAuthenticated(synthetic_expected()),
            false,
        ),
        Comparison::Refuse(Refusal::Acquisition(AcquisitionFailure::Ambiguous))
    );
}
