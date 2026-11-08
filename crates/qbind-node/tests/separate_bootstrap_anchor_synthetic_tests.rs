//! Isolated synthetic bootstrap-anchor association verification tests.
//!
//! This test-only model uses ephemeral ML-DSA-44 keys through the existing
//! qbind_crypto implementation. It does not select ML-DSA-44, an encoding,
//! or a file format for production. No live signer, startup hook, operational
//! key, or authority-bearing callback is used.

use qbind_crypto::MlDsa44Backend;
use std::cell::Cell;

const SYNTHETIC_ASSOCIATION_SUITE: u16 = 100;
const SYNTHETIC_VALIDATOR_SUITE: u16 = 700;
const SYNTHETIC_PURPOSE: &str = "qbind.synthetic.validator-association";
const SYNTHETIC_VERSION: u32 = 1;
const SYNTHETIC_DEPLOYMENT: &str = "synthetic-initial-devnet-A";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    environment: String,
    numeric_chain_id: u64,
    genesis_identity: [u8; 32],
    destination_identity: String,
    validator_id: u64,
    validator_suite: u16,
    validator_public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedDomain {
    environment: String,
    numeric_chain_id: u64,
    genesis_identity: [u8; 32],
    destination_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedAssociation {
    purpose: String,
    version: u32,
    association_suite: u16,
    deployment_binding: String,
    identity: Identity,
    signature: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ExpectedAnchor {
    public_key: Vec<u8>,
    key_suite: u16,
    provenance_authenticated: bool,
    deployment_binding: String,
}

#[derive(Clone, Debug)]
struct AuthenticatedVerifierPolicy {
    purpose: String,
    version: u32,
    permitted_association_suite: u16,
    deployment_binding: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Environment,
    NumericChainId,
    GenesisIdentity,
    DestinationIdentity,
    ValidatorId,
    ValidatorSuite,
    ValidatorPublicKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DomainField {
    Environment,
    NumericChainId,
    GenesisIdentity,
    DestinationIdentity,
}

const ALL_FIELDS: [Field; 7] = [
    Field::Environment,
    Field::NumericChainId,
    Field::GenesisIdentity,
    Field::DestinationIdentity,
    Field::ValidatorId,
    Field::ValidatorSuite,
    Field::ValidatorPublicKey,
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Evidence<T> {
    Present(T),
    Missing,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    environment: Evidence<String>,
    numeric_chain_id: Evidence<u64>,
    genesis_identity: Evidence<[u8; 32]>,
    destination_identity: Evidence<String>,
    validator_id: Evidence<u64>,
    validator_suite: Evidence<u16>,
    validator_public_key: Evidence<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Authenticity {
    Verified,
    Refused(VerifyFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VerifyFailure {
    AnchorProvenance,
    AnchorSuite,
    DeploymentBinding,
    Purpose,
    Version,
    UnsupportedSuite,
    InvalidSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DomainFailure {
    Mismatch(DomainField),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Equality {
    Equal,
    Mismatch(Field),
    Missing(Field),
    Unavailable(Field),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Currentness {
    Unresolved,
}

#[derive(Clone, Copy, Debug, Default)]
struct VerifyBypass {
    signature: bool,
    anchor_provenance: bool,
    anchor_suite: bool,
    deployment_binding: bool,
    purpose: bool,
    version: bool,
    suite_policy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AcquisitionFailure {
    Missing,
    MissingAssociation,
    MissingSignature,
    MissingAnchor,
    Unreadable,
    Malformed,
    Truncated,
    Ambiguous,
    UnsupportedSchema,
}

enum RawInput {
    Failure(AcquisitionFailure),
    Parsed(SignedAssociation),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PipelineResult {
    AcquisitionRefused(AcquisitionFailure),
    VerificationRefused(VerifyFailure),
    DomainRefused(DomainFailure),
    Compared(Authenticity, Equality, Currentness),
}

struct Fixture {
    anchor: ExpectedAnchor,
    policy: AuthenticatedVerifierPolicy,
    expected_domain: ExpectedDomain,
    bootstrap_secret: Vec<u8>,
    identity: Identity,
}

fn fixture() -> Fixture {
    let (public_key, secret_key) =
        MlDsa44Backend::generate_keypair().expect("generate disposable bootstrap key");
    Fixture {
        // These are fixed test inputs, established before and independently
        // of constructing the signed association.
        anchor: ExpectedAnchor {
            public_key,
            key_suite: SYNTHETIC_ASSOCIATION_SUITE,
            provenance_authenticated: true,
            deployment_binding: SYNTHETIC_DEPLOYMENT.to_owned(),
        },
        policy: AuthenticatedVerifierPolicy {
            purpose: SYNTHETIC_PURPOSE.to_owned(),
            version: SYNTHETIC_VERSION,
            permitted_association_suite: SYNTHETIC_ASSOCIATION_SUITE,
            deployment_binding: SYNTHETIC_DEPLOYMENT.to_owned(),
        },
        // This profile is an independent fixed checker input, not copied from
        // the association or the observations being evaluated.
        expected_domain: ExpectedDomain {
            environment: "Devnet".to_owned(),
            numeric_chain_id: 0xD3_01,
            genesis_identity: [0x31; 32],
            destination_identity: "synthetic-destination-A".to_owned(),
        },
        bootstrap_secret: secret_key,
        identity: Identity {
            environment: "Devnet".to_owned(),
            numeric_chain_id: 0xD3_01,
            genesis_identity: [0x31; 32],
            destination_identity: "synthetic-destination-A".to_owned(),
            validator_id: 41,
            validator_suite: SYNTHETIC_VALIDATOR_SUITE,
            // Synthetic bytes only; no validator private key exists.
            validator_public_key: vec![0xA5; 64],
        },
    }
}

fn signed_association(fixture: &Fixture, identity: Identity) -> SignedAssociation {
    signed_association_with_omit(fixture, identity, None)
}

fn signed_association_with_omit(
    fixture: &Fixture,
    identity: Identity,
    omit: Option<Field>,
) -> SignedAssociation {
    let mut association = SignedAssociation {
        purpose: fixture.policy.purpose.clone(),
        version: fixture.policy.version,
        association_suite: fixture.policy.permitted_association_suite,
        deployment_binding: fixture.policy.deployment_binding.clone(),
        identity,
        signature: Vec::new(),
    };
    association.signature = MlDsa44Backend::sign(
        &fixture.bootstrap_secret,
        &canonical_signed_bytes(&association, omit),
    )
    .expect("sign disposable synthetic association");
    association
}

fn append_bytes(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

fn append_u64(out: &mut Vec<u8>, tag: u8, value: u64) {
    out.push(tag);
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_field(out: &mut Vec<u8>, field: Field, identity: &Identity) {
    match field {
        Field::Environment => append_bytes(out, 1, identity.environment.as_bytes()),
        Field::NumericChainId => append_u64(out, 2, identity.numeric_chain_id),
        Field::GenesisIdentity => append_bytes(out, 3, &identity.genesis_identity),
        Field::DestinationIdentity => {
            append_bytes(out, 4, identity.destination_identity.as_bytes())
        }
        Field::ValidatorId => append_u64(out, 5, identity.validator_id),
        Field::ValidatorSuite => {
            out.push(6);
            out.extend_from_slice(&identity.validator_suite.to_le_bytes());
        }
        Field::ValidatorPublicKey => append_bytes(out, 7, &identity.validator_public_key),
    }
}

fn canonical_signed_bytes(association: &SignedAssociation, omit: Option<Field>) -> Vec<u8> {
    let mut out = b"QBIND-SYNTHETIC-ASSOCIATION-v1\0".to_vec();
    append_bytes(&mut out, 0x10, association.purpose.as_bytes());
    out.extend_from_slice(&association.version.to_le_bytes());
    out.extend_from_slice(&association.association_suite.to_le_bytes());
    append_bytes(&mut out, 0x11, association.deployment_binding.as_bytes());
    for field in ALL_FIELDS {
        if omit != Some(field) {
            append_field(&mut out, field, &association.identity);
        }
    }
    out
}

fn verify(
    association: &SignedAssociation,
    anchor: &ExpectedAnchor,
    policy: &AuthenticatedVerifierPolicy,
    bypass: VerifyBypass,
) -> Authenticity {
    verify_with_encoding_omit(association, anchor, policy, bypass, None)
}

fn verify_with_encoding_omit(
    association: &SignedAssociation,
    anchor: &ExpectedAnchor,
    policy: &AuthenticatedVerifierPolicy,
    bypass: VerifyBypass,
    omit: Option<Field>,
) -> Authenticity {
    if !anchor.provenance_authenticated && !bypass.anchor_provenance {
        return Authenticity::Refused(VerifyFailure::AnchorProvenance);
    }
    if !bypass.anchor_suite && anchor.key_suite != policy.permitted_association_suite {
        return Authenticity::Refused(VerifyFailure::AnchorSuite);
    }
    if !bypass.deployment_binding
        && (anchor.deployment_binding != policy.deployment_binding
            || association.deployment_binding != policy.deployment_binding)
    {
        return Authenticity::Refused(VerifyFailure::DeploymentBinding);
    }
    if !bypass.purpose && association.purpose != policy.purpose {
        return Authenticity::Refused(VerifyFailure::Purpose);
    }
    if !bypass.version && association.version != policy.version {
        return Authenticity::Refused(VerifyFailure::Version);
    }
    if !bypass.suite_policy && association.association_suite != policy.permitted_association_suite {
        return Authenticity::Refused(VerifyFailure::UnsupportedSuite);
    }

    // The test verifier implementation is fixed to this synthetic primitive;
    // the association header never selects a verifier algorithm.
    if !bypass.signature
        && MlDsa44Backend::verify(
            &anchor.public_key,
            &canonical_signed_bytes(association, omit),
            &association.signature,
        )
        .is_err()
    {
        return Authenticity::Refused(VerifyFailure::InvalidSignature);
    }
    Authenticity::Verified
}

fn compare(observed: &Observation, expected: &Identity, bypass: Option<Field>) -> Equality {
    macro_rules! check {
        ($field:expr, $observed:expr, $expected:expr) => {
            if bypass != Some($field) {
                match $observed {
                    Evidence::Missing => return Equality::Missing($field),
                    Evidence::Unavailable => return Equality::Unavailable($field),
                    Evidence::Present(value) if value != $expected => {
                        return Equality::Mismatch($field)
                    }
                    Evidence::Present(_) => {}
                }
            }
        };
    }

    check!(
        Field::Environment,
        &observed.environment,
        &expected.environment
    );
    check!(
        Field::NumericChainId,
        &observed.numeric_chain_id,
        &expected.numeric_chain_id
    );
    check!(
        Field::GenesisIdentity,
        &observed.genesis_identity,
        &expected.genesis_identity
    );
    check!(
        Field::DestinationIdentity,
        &observed.destination_identity,
        &expected.destination_identity
    );
    check!(
        Field::ValidatorId,
        &observed.validator_id,
        &expected.validator_id
    );
    check!(
        Field::ValidatorSuite,
        &observed.validator_suite,
        &expected.validator_suite
    );
    check!(
        Field::ValidatorPublicKey,
        &observed.validator_public_key,
        &expected.validator_public_key
    );
    Equality::Equal
}

fn observation(identity: &Identity) -> Observation {
    Observation {
        environment: Evidence::Present(identity.environment.clone()),
        numeric_chain_id: Evidence::Present(identity.numeric_chain_id),
        genesis_identity: Evidence::Present(identity.genesis_identity),
        destination_identity: Evidence::Present(identity.destination_identity.clone()),
        validator_id: Evidence::Present(identity.validator_id),
        validator_suite: Evidence::Present(identity.validator_suite),
        validator_public_key: Evidence::Present(identity.validator_public_key.clone()),
    }
}

fn mutate_identity(identity: &mut Identity, field: Field) {
    match field {
        Field::Environment => identity.environment.push_str("-changed"),
        Field::NumericChainId => identity.numeric_chain_id ^= 1,
        Field::GenesisIdentity => identity.genesis_identity[0] ^= 1,
        Field::DestinationIdentity => identity.destination_identity.push_str("-changed"),
        Field::ValidatorId => identity.validator_id += 1,
        Field::ValidatorSuite => identity.validator_suite += 1,
        Field::ValidatorPublicKey => identity.validator_public_key[63] ^= 1,
    }
}

fn compare_mutated_observation(identity: &Identity, field: Field, state: u8) -> Observation {
    let mut result = observation(identity);
    macro_rules! mutate {
        ($member:ident) => {
            result.$member = match state {
                0 => Evidence::Present({
                    let mut changed = match &result.$member {
                        Evidence::Present(value) => value.clone(),
                        _ => unreachable!(),
                    };
                    mutate_value(&mut changed);
                    changed
                }),
                1 => Evidence::Missing,
                _ => Evidence::Unavailable,
            }
        };
    }
    match field {
        Field::Environment => mutate!(environment),
        Field::NumericChainId => mutate!(numeric_chain_id),
        Field::GenesisIdentity => mutate!(genesis_identity),
        Field::DestinationIdentity => mutate!(destination_identity),
        Field::ValidatorId => mutate!(validator_id),
        Field::ValidatorSuite => mutate!(validator_suite),
        Field::ValidatorPublicKey => mutate!(validator_public_key),
    }
    result
}

fn mutate_value<T: Mutate>(value: &mut T) {
    value.mutate();
}

trait Mutate {
    fn mutate(&mut self);
}

impl Mutate for String {
    fn mutate(&mut self) {
        self.push_str("-changed");
    }
}

impl Mutate for u64 {
    fn mutate(&mut self) {
        *self ^= 1;
    }
}

impl Mutate for u16 {
    fn mutate(&mut self) {
        *self += 1;
    }
}

impl Mutate for [u8; 32] {
    fn mutate(&mut self) {
        self[0] ^= 1;
    }
}

impl Mutate for Vec<u8> {
    fn mutate(&mut self) {
        self[63] ^= 1;
    }
}

fn acquire(input: RawInput) -> Result<SignedAssociation, AcquisitionFailure> {
    match input {
        RawInput::Failure(failure) => Err(failure),
        RawInput::Parsed(association) => Ok(association),
    }
}

fn run_pipeline(
    input: RawInput,
    anchor: Option<&ExpectedAnchor>,
    policy: &AuthenticatedVerifierPolicy,
    expected_domain: &ExpectedDomain,
    observed: &Observation,
    verifier_calls: &Cell<usize>,
    domain_bypass: Option<DomainField>,
) -> PipelineResult {
    let anchor = match anchor {
        Some(anchor) => anchor,
        None => return PipelineResult::AcquisitionRefused(AcquisitionFailure::MissingAnchor),
    };
    let association = match acquire(input) {
        Ok(association) => association,
        Err(failure) => return PipelineResult::AcquisitionRefused(failure),
    };
    verifier_calls.set(verifier_calls.get() + 1);
    match verify(&association, anchor, policy, VerifyBypass::default()) {
        Authenticity::Refused(failure) => PipelineResult::VerificationRefused(failure),
        authenticity @ Authenticity::Verified => {
            if let Some(field) = domain_mismatch(
                observed,
                &association.identity,
                expected_domain,
                domain_bypass,
            ) {
                return PipelineResult::DomainRefused(DomainFailure::Mismatch(field));
            }
            PipelineResult::Compared(
                authenticity,
                compare(observed, &association.identity, None),
                evaluate_currentness(&association),
            )
        }
    }
}

fn domain_mismatch(
    observed: &Observation,
    signed_identity: &Identity,
    expected: &ExpectedDomain,
    bypass: Option<DomainField>,
) -> Option<DomainField> {
    macro_rules! check {
        ($field:expr, $observed:expr, $signed:expr, $expected:expr) => {
            if bypass != Some($field)
                && ($observed != &Evidence::Present($expected.clone()) || $signed != &$expected)
            {
                return Some($field);
            }
        };
    }

    check!(
        DomainField::Environment,
        &observed.environment,
        &signed_identity.environment,
        expected.environment
    );
    check!(
        DomainField::NumericChainId,
        &observed.numeric_chain_id,
        &signed_identity.numeric_chain_id,
        expected.numeric_chain_id
    );
    check!(
        DomainField::GenesisIdentity,
        &observed.genesis_identity,
        &signed_identity.genesis_identity,
        expected.genesis_identity
    );
    check!(
        DomainField::DestinationIdentity,
        &observed.destination_identity,
        &signed_identity.destination_identity,
        expected.destination_identity
    );
    None
}

fn evaluate_currentness(_association: &SignedAssociation) -> Currentness {
    // No currentness authority or mechanism is selected in this test slice.
    Currentness::Unresolved
}

#[test]
fn matching_synthetic_association_has_only_separate_non_authorizing_results() {
    let fixture = fixture();
    let association = signed_association(&fixture, fixture.identity.clone());
    let observed = observation(&fixture.identity);

    assert_eq!(
        verify(
            &association,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Verified
    );
    assert_eq!(
        compare(&observed, &association.identity, None),
        Equality::Equal
    );
    assert_eq!(evaluate_currentness(&association), Currentness::Unresolved);
    // The result enums contain no permission/admission capability.
}

#[test]
fn acquisition_failures_are_simulated_and_never_invoke_verification() {
    let fixture = fixture();
    let observed = observation(&fixture.identity);
    for failure in [
        AcquisitionFailure::Missing,
        AcquisitionFailure::Unreadable,
        AcquisitionFailure::Malformed,
        AcquisitionFailure::Truncated,
        AcquisitionFailure::Ambiguous,
        AcquisitionFailure::UnsupportedSchema,
    ] {
        let verifier_calls = Cell::new(0);
        let result = run_pipeline(
            RawInput::Failure(failure.clone()),
            Some(&fixture.anchor),
            &fixture.policy,
            &fixture.expected_domain,
            &observed,
            &verifier_calls,
            None,
        );
        assert!(matches!(result, PipelineResult::AcquisitionRefused(actual) if actual == failure));
        assert_eq!(
            verifier_calls.get(),
            0,
            "acquisition failure reached verifier"
        );
    }
}

#[test]
fn anchor_provenance_substitution_and_deployment_binding_refuse_sensitively() {
    let fixture = fixture();
    let (substitute_pk, substitute_sk) =
        MlDsa44Backend::generate_keypair().expect("generate substituted bootstrap key");
    let mut substitute_anchor = ExpectedAnchor {
        public_key: substitute_pk,
        key_suite: SYNTHETIC_ASSOCIATION_SUITE,
        provenance_authenticated: false,
        deployment_binding: SYNTHETIC_DEPLOYMENT.to_owned(),
    };
    let attacker_signed = SignedAssociation {
        signature: Vec::new(),
        ..signed_association(&fixture, fixture.identity.clone())
    };
    let mut attacker_signed = attacker_signed;
    attacker_signed.signature = MlDsa44Backend::sign(
        &substitute_sk,
        &canonical_signed_bytes(&attacker_signed, None),
    )
    .unwrap();

    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::AnchorProvenance)
    );
    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass {
                anchor_provenance: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "provenance-bypass mutation did not break its negative control"
    );
    substitute_anchor.provenance_authenticated = true;
    substitute_anchor.key_suite = 999;
    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::AnchorSuite)
    );
    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass {
                anchor_suite: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "anchor-suite bypass mutation did not break its negative control"
    );
    substitute_anchor.provenance_authenticated = true;
    substitute_anchor.key_suite = SYNTHETIC_ASSOCIATION_SUITE;
    substitute_anchor.deployment_binding = "substituted-deployment".to_owned();
    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::DeploymentBinding)
    );
    assert_eq!(
        verify(
            &attacker_signed,
            &substitute_anchor,
            &fixture.policy,
            VerifyBypass {
                deployment_binding: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "deployment-bypass mutation did not break its negative control"
    );
}

#[test]
fn invalid_signature_wrong_purpose_version_and_suite_refuse_sensitively() {
    let fixture = fixture();
    let valid = signed_association(&fixture, fixture.identity.clone());
    let mut invalid_signature = valid.clone();
    invalid_signature.signature[0] ^= 1;
    assert_eq!(
        verify(
            &invalid_signature,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::InvalidSignature)
    );
    assert_eq!(
        verify(
            &invalid_signature,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                signature: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "signature-bypass mutation did not break its negative control"
    );

    let mut wrong_purpose = valid.clone();
    wrong_purpose.purpose = "qbind.bundle-signing".to_owned();
    wrong_purpose.signature = MlDsa44Backend::sign(
        &fixture.bootstrap_secret,
        &canonical_signed_bytes(&wrong_purpose, None),
    )
    .unwrap();
    assert_eq!(
        verify(
            &wrong_purpose,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::Purpose)
    );
    assert_eq!(
        verify(
            &wrong_purpose,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                purpose: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "purpose-bypass mutation did not break its negative control"
    );

    let mut wrong_version = valid.clone();
    wrong_version.version += 1;
    wrong_version.signature = MlDsa44Backend::sign(
        &fixture.bootstrap_secret,
        &canonical_signed_bytes(&wrong_version, None),
    )
    .unwrap();
    assert_eq!(
        verify(
            &wrong_version,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::Version)
    );
    assert_eq!(
        verify(
            &wrong_version,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                version: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "version-bypass mutation did not break its negative control"
    );

    let mut wrong_suite = valid.clone();
    wrong_suite.association_suite = 999;
    wrong_suite.signature = MlDsa44Backend::sign(
        &fixture.bootstrap_secret,
        &canonical_signed_bytes(&wrong_suite, None),
    )
    .unwrap();
    assert_eq!(
        verify(
            &wrong_suite,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::UnsupportedSuite)
    );
    assert_eq!(
        verify(
            &wrong_suite,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                suite_policy: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "suite-policy bypass mutation did not break its negative control"
    );

    let mut tampered_suite_header = valid.clone();
    tampered_suite_header.association_suite = 999;
    assert_eq!(
        verify(
            &tampered_suite_header,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::UnsupportedSuite)
    );
    assert_eq!(
        verify(
            &tampered_suite_header,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                suite_policy: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Refused(VerifyFailure::InvalidSignature),
        "association suite metadata was not covered by the signed bytes"
    );
    assert_eq!(
        verify(
            &tampered_suite_header,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass {
                suite_policy: true,
                signature: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "suite/signature bypass mutant did not break its negative control"
    );

    let mut wrong_suite_anchor = fixture.anchor.clone();
    wrong_suite_anchor.key_suite = 999;
    assert_eq!(
        verify(
            &valid,
            &wrong_suite_anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::AnchorSuite)
    );
    assert_eq!(
        verify(
            &valid,
            &wrong_suite_anchor,
            &fixture.policy,
            VerifyBypass {
                anchor_suite: true,
                ..VerifyBypass::default()
            }
        ),
        Authenticity::Verified,
        "wrong-suite anchor-key bypass did not break its negative control"
    );

    let (_, wrong_signer_secret) =
        MlDsa44Backend::generate_keypair().expect("generate non-anchor signer fixture");
    let mut wrong_key = valid;
    wrong_key.signature = MlDsa44Backend::sign(
        &wrong_signer_secret,
        &canonical_signed_bytes(&wrong_key, None),
    )
    .unwrap();
    assert_eq!(
        verify(
            &wrong_key,
            &fixture.anchor,
            &fixture.policy,
            VerifyBypass::default()
        ),
        Authenticity::Refused(VerifyFailure::InvalidSignature)
    );
}

#[test]
fn every_identity_field_is_signed_compared_and_individually_sensitive() {
    let fixture = fixture();
    let baseline = signed_association(&fixture, fixture.identity.clone());

    for field in ALL_FIELDS {
        let mut changed = fixture.identity.clone();
        mutate_identity(&mut changed, field);

        let mut altered_without_resigning = baseline.clone();
        altered_without_resigning.identity = changed.clone();
        assert_eq!(
            verify(
                &altered_without_resigning,
                &fixture.anchor,
                &fixture.policy,
                VerifyBypass::default()
            ),
            Authenticity::Refused(VerifyFailure::InvalidSignature),
            "field {field:?} was not authenticated"
        );

        // Shared signing/verification encoding mutant: omit this field from
        // both sides, sign the original fixture tuple, then change only the
        // omitted value while retaining the signature. Verification now
        // accepts, proving the field-specific negative assertion is sensitive.
        let omitted_signature =
            signed_association_with_omit(&fixture, fixture.identity.clone(), Some(field));
        let mut omitted_field_changed = omitted_signature.clone();
        mutate_identity(&mut omitted_field_changed.identity, field);
        assert_eq!(
            verify_with_encoding_omit(
                &omitted_field_changed,
                &fixture.anchor,
                &fixture.policy,
                VerifyBypass::default(),
                Some(field),
            ),
            Authenticity::Verified,
            "encoding-omission mutant for {field:?} failed to demonstrate sensitivity"
        );

        let changed_observation = compare_mutated_observation(&fixture.identity, field, 0);
        assert_eq!(
            compare(&changed_observation, &fixture.identity, None),
            Equality::Mismatch(field)
        );
        assert_eq!(
            compare(&changed_observation, &fixture.identity, Some(field)),
            Equality::Equal,
            "comparator-bypass mutant for {field:?} failed to demonstrate sensitivity"
        );
        for state in [1, 2] {
            let missing = compare_mutated_observation(&fixture.identity, field, state);
            let expected = if state == 1 {
                Equality::Missing(field)
            } else {
                Equality::Unavailable(field)
            };
            assert_eq!(compare(&missing, &fixture.identity, None), expected);
            assert_eq!(
                compare(&missing, &fixture.identity, Some(field)),
                Equality::Equal,
                "missing/unavailable bypass mutant for {field:?} failed"
            );
        }
    }
}

#[test]
fn parsed_association_pipeline_preserves_distinct_result_stages() {
    let fixture = fixture();
    let association = signed_association(&fixture, fixture.identity.clone());
    let verifier_calls = Cell::new(0);
    let result = run_pipeline(
        RawInput::Parsed(association),
        Some(&fixture.anchor),
        &fixture.policy,
        &fixture.expected_domain,
        &observation(&fixture.identity),
        &verifier_calls,
        None,
    );
    assert_eq!(verifier_calls.get(), 1);
    match result {
        PipelineResult::Compared(authenticity, equality, currentness) => {
            assert_eq!(authenticity, Authenticity::Verified);
            assert_eq!(equality, Equality::Equal);
            assert_eq!(currentness, Currentness::Unresolved);
        }
        PipelineResult::AcquisitionRefused(_)
        | PipelineResult::VerificationRefused(_)
        | PipelineResult::DomainRefused(_) => {
            panic!("valid synthetic fixture was refused")
        }
    }

    let mut invalid = signed_association(&fixture, fixture.identity.clone());
    invalid.signature[0] ^= 1;
    let verifier_calls = Cell::new(0);
    let result = run_pipeline(
        RawInput::Parsed(invalid),
        Some(&fixture.anchor),
        &fixture.policy,
        &fixture.expected_domain,
        &observation(&fixture.identity),
        &verifier_calls,
        None,
    );
    assert_eq!(verifier_calls.get(), 1);
    assert!(matches!(
        result,
        PipelineResult::VerificationRefused(VerifyFailure::InvalidSignature)
    ));
}

#[test]
fn valid_equal_association_without_currentness_evidence_remains_unresolved() {
    let fixture = fixture();
    let association = signed_association(&fixture, fixture.identity.clone());
    let observed = observation(&fixture.identity);

    let authenticity = verify(
        &association,
        &fixture.anchor,
        &fixture.policy,
        VerifyBypass::default(),
    );
    let equality = compare(&observed, &association.identity, None);
    // No harness-only age/supersession label is passed to verification,
    // comparison, or currentness evaluation.
    let currentness = evaluate_currentness(&association);

    assert_eq!(authenticity, Authenticity::Verified);
    assert_eq!(equality, Equality::Equal);
    assert_eq!(currentness, Currentness::Unresolved);
}

#[test]
fn independently_expected_domain_refuses_each_signed_foreign_field_sensitively() {
    let fixture = fixture();
    let expected_association = signed_association(&fixture, fixture.identity.clone());
    for field in [
        DomainField::Environment,
        DomainField::NumericChainId,
        DomainField::GenesisIdentity,
        DomainField::DestinationIdentity,
    ] {
        let verifier_calls = Cell::new(0);
        assert!(matches!(
            run_pipeline(
                RawInput::Parsed(expected_association.clone()),
                Some(&fixture.anchor),
                &fixture.policy,
                &fixture.expected_domain,
                &observation(&fixture.identity),
                &verifier_calls,
                None,
            ),
            PipelineResult::Compared(
                Authenticity::Verified,
                Equality::Equal,
                Currentness::Unresolved
            )
        ));

        let mut foreign_identity = fixture.identity.clone();
        match field {
            DomainField::Environment => foreign_identity.environment.push_str("-foreign"),
            DomainField::NumericChainId => foreign_identity.numeric_chain_id ^= 1,
            DomainField::GenesisIdentity => foreign_identity.genesis_identity[0] ^= 1,
            DomainField::DestinationIdentity => {
                foreign_identity.destination_identity.push_str("-foreign")
            }
        }
        let foreign_association = signed_association(&fixture, foreign_identity.clone());
        let foreign_observation = observation(&foreign_identity);
        let verifier_calls = Cell::new(0);
        assert_eq!(
            run_pipeline(
                RawInput::Parsed(foreign_association.clone()),
                Some(&fixture.anchor),
                &fixture.policy,
                &fixture.expected_domain,
                &foreign_observation,
                &verifier_calls,
                None,
            ),
            PipelineResult::DomainRefused(DomainFailure::Mismatch(field)),
            "foreign domain {field:?} was not refused"
        );
        assert_eq!(verifier_calls.get(), 1);

        let verifier_calls = Cell::new(0);
        assert!(
            matches!(
                run_pipeline(
                    RawInput::Parsed(foreign_association),
                    Some(&fixture.anchor),
                    &fixture.policy,
                    &fixture.expected_domain,
                    &foreign_observation,
                    &verifier_calls,
                    Some(field),
                ),
                PipelineResult::Compared(
                    Authenticity::Verified,
                    Equality::Equal,
                    Currentness::Unresolved
                )
            ),
            "domain-guard bypass for {field:?} did not defeat the refusal"
        );
        assert_eq!(verifier_calls.get(), 1);
    }
}

#[test]
fn missing_anchor_association_and_signature_are_distinct_acquisition_refusals() {
    let fixture = fixture();
    let association = signed_association(&fixture, fixture.identity.clone());
    let observation = observation(&fixture.identity);

    let verifier_calls = Cell::new(0);
    assert!(matches!(
        run_pipeline(
            RawInput::Parsed(association.clone()),
            None,
            &fixture.policy,
            &fixture.expected_domain,
            &observation,
            &verifier_calls,
            None,
        ),
        PipelineResult::AcquisitionRefused(AcquisitionFailure::MissingAnchor)
    ));
    assert_eq!(verifier_calls.get(), 0);

    for failure in [
        AcquisitionFailure::MissingAssociation,
        AcquisitionFailure::MissingSignature,
    ] {
        let verifier_calls = Cell::new(0);
        assert!(matches!(
            run_pipeline(
                RawInput::Failure(failure.clone()),
                Some(&fixture.anchor),
                &fixture.policy,
                &fixture.expected_domain,
                &observation,
                &verifier_calls,
                None,
            ),
            PipelineResult::AcquisitionRefused(actual) if actual == failure
        ));
        assert_eq!(verifier_calls.get(), 0);
    }
}
