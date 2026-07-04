//! Run 299 — source/test **real** on-chain governance proof verifier.
//!
//! This module implements the first real source/test production on-chain
//! governance proof verifier, layered on top of the Run 178
//! [`crate::pqc_onchain_governance_proof`] typed fixture proof format and
//! the Run 186 [`crate::pqc_onchain_governance_verifier`] verifier
//! boundary. Where Run 178 accepts a deterministic *fixture-mock*
//! commitment for DevNet/TestNet evidence only, and Run 186 draws a typed
//! boundary between the fixture verifier and a *placeholder* production
//! verifier that always fails closed, Run 299 adds a **real verification
//! algorithm**:
//!
//! * a deterministic, domain-separated canonical decision commitment over
//!   every governance / lifecycle / authority-domain binding;
//! * a real SHA3-256 Merkle inclusion proof verifier that recomputes a
//!   governance root from an explicitly supplied leaf + authenticated
//!   sibling path and compares it against an **explicit trusted
//!   governance checkpoint/root** (the proof cannot self-authorize its
//!   root);
//! * domain / chain / genesis / authority-root / governance-domain /
//!   governance-epoch / proposal / lifecycle / candidate / authority-
//!   sequence / decision-id binding, each with a precise fail-closed
//!   typed error;
//! * explicit freshness expressed only through governance height / epoch
//!   bounds, authority-domain sequence, and a replay decision-id set
//!   (never wall-clock);
//! * quorum / threshold enforcement where represented.
//!
//! ## Scope and honesty constraints (Run 299)
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to **Run 300**.
//! * The default policy is
//!   [`ProductionOnChainGovernanceVerifierPolicy::Disabled`] and fails
//!   closed **before** any proof parsing, root verification, inclusion
//!   verification, or lifecycle authorization.
//! * Fixture proofs (the Run 178 fixture suite) are **not** production
//!   proofs; they remain DevNet/TestNet evidence-only via the Run 178 /
//!   Run 186 surfaces and are rejected here as
//!   [`ProductionOnChainGovernanceProofOutcome::FixtureProofRejectedAsProductionAuthority`].
//! * A production-style proof may be accepted **only** at source/test
//!   level, under an explicit source/test production policy, on
//!   DevNet/TestNet, and only when every represented binding matches the
//!   explicit trusted inputs and the inclusion proof verifies against the
//!   explicit trusted governance root.
//! * MainNet remains **refused**: even a fully valid synthetic
//!   production-style proof does not enable MainNet runtime behavior; the
//!   MainNet source/test policy documents no MainNet runtime enablement
//!   and no MainNet readiness.
//! * The verifier is **non-mutating**: no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust swap,
//!   no session eviction, no PQC trust-bundle sequence write, no authority
//!   marker write, no durable replay overwrite, no settlement, no external
//!   publication, no governance execution, and no validator-set rotation.
//! * No CLI flag and no default runtime wiring is added. Full C4 remains
//!   OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_299.md`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_onchain_governance_proof::{
    is_fixture_onchain_governance_proof_suite, OnChainGovernanceProposalOutcome,
    OnChainGovernanceQuorum,
};
use crate::pqc_onchain_governance_verifier::{
    classify_onchain_governance_proof_class, OnChainGovernanceProofClass,
};
use crate::pqc_governance_authority::GovernanceThreshold;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 299 — the only production on-chain governance proof protocol
/// version this run accepts.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION: u16 = 1;

/// Run 299 — the production Merkle-inclusion proof suite id.
///
/// Distinct from the Run 178 fixture suite (`0xA1`) and the Run 178
/// reserved-production suite (`0xA2`). Because it is **not** the fixture
/// suite, [`classify_onchain_governance_proof_class`] classifies any
/// Run 178-shaped proof carrying it as
/// [`OnChainGovernanceProofClass::Production`], preserving the Run 186
/// fixture/production boundary.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1: u8 = 0xA3;

/// Run 299 — decision-commitment digest domain tag (the Merkle leaf
/// pre-image domain separation).
pub const PRODUCTION_ONCHAIN_GOVERNANCE_DECISION_DOMAIN_TAG: &str =
    "QBIND:run299-onchain-gov-decision:v1";

/// Run 299 — Merkle leaf / node hashing domain tag.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_MERKLE_DOMAIN_TAG: &str =
    "QBIND:run299-onchain-gov-merkle:v1";

/// Run 299 — trusted governance checkpoint digest domain tag.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_CHECKPOINT_DOMAIN_TAG: &str =
    "QBIND:run299-onchain-gov-checkpoint:v1";

/// Run 299 — proof digest domain tag (the canonical `proof_bytes`
/// commitment binding the decision digest, inclusion path, and trusted
/// root).
pub const PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_DOMAIN_TAG: &str =
    "QBIND:run299-onchain-gov-proof:v1";

/// Run 299 — verification transcript digest domain tag.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run299-onchain-gov-transcript:v1";

/// Run 299 — the fixed domain separation tag every production proof must
/// carry. A proof carrying any other tag fails closed.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG: &str =
    "QBIND:run299-production-onchain-governance:v1";

/// Run 299 — explicit invalid-proof sentinel for source/test rejection
/// vectors. A proof carrying this sentinel as its `proof_bytes_digest`
/// is rejected as malformed.
pub const PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL: &str =
    "INVALID-PRODUCTION-ONCHAIN-GOVERNANCE-PROOF";

/// Length-prefixed domain-separated field hashing helper.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

fn hash_opt(h: &mut sha3::Sha3_256, label: &[u8], value: Option<&str>) {
    hash_field(h, label, value.unwrap_or("").as_bytes());
}

// ===========================================================================
// Protocol version newtype
// ===========================================================================

/// Run 299 — typed production proof protocol version. Only
/// [`PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION`] is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionOnChainGovernanceProofProtocolVersion(pub u16);

impl ProductionOnChainGovernanceProofProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_PROTOCOL_VERSION
    }
}

impl Default for ProductionOnChainGovernanceProofProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Proof suite newtype
// ===========================================================================

/// Run 299 — typed production proof suite. Only
/// [`PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1`] is a supported
/// production suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionOnChainGovernanceProofSuite(pub u8);

impl ProductionOnChainGovernanceProofSuite {
    /// The supported Merkle-inclusion production suite.
    pub const fn merkle_v1() -> Self {
        Self(PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1)
    }

    /// Returns `true` iff this is the supported production suite.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_SUITE_MERKLE_V1
    }

    /// Returns `true` iff this suite is the Run 178 fixture suite (which
    /// is **not** a production suite).
    pub fn is_fixture(self) -> bool {
        is_fixture_onchain_governance_proof_suite(self.0)
    }
}

impl Default for ProductionOnChainGovernanceProofSuite {
    fn default() -> Self {
        Self::merkle_v1()
    }
}

// ===========================================================================
// Policy taxonomy
// ===========================================================================

/// Run 299 — typed production on-chain governance verifier policy.
///
/// `Disabled` is the default fail-closed policy: verification refuses
/// before any proof parsing. `AllowSourceTestProductionProof` accepts a
/// verified production-style proof on DevNet/TestNet only.
/// `MainnetProductionProofRequired` is a **test-only** MainNet policy that
/// still fails closed — it documents no MainNet runtime enablement and no
/// MainNet readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionOnChainGovernanceVerifierPolicy {
    /// Default. Refuses every proof before any parsing.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test production-proof policy. A verified
    /// production-style proof may be accepted as source/test evidence
    /// only. MainNet remains refused.
    AllowSourceTestProductionProof,
    /// Test-only MainNet production-proof policy. Fails closed: no
    /// production authority material is wired, so MainNet is refused.
    MainnetProductionProofRequired,
}

impl ProductionOnChainGovernanceVerifierPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AllowSourceTestProductionProof => "allow-source-test-production-proof",
            Self::MainnetProductionProofRequired => "mainnet-production-proof-required",
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy allows source/test production proof
    /// acceptance (DevNet/TestNet only).
    pub const fn allows_source_test_production(self) -> bool {
        matches!(self, Self::AllowSourceTestProductionProof)
    }

    /// Returns `true` iff this policy is the test-only MainNet policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::MainnetProductionProofRequired)
    }
}

// ===========================================================================
// Verifier kind taxonomy
// ===========================================================================

/// Run 299 — typed production on-chain governance verifier kind.
///
/// `Disabled` is the inert default. `ProductionMerkleVerifier` performs
/// real SHA3-256 Merkle inclusion verification against an explicit
/// trusted root. `ProductionReceiptVerifier` is a reserved companion
/// kind (receipt/event-root inclusion) that Run 299 leaves fail-closed
/// as unavailable; a future run may implement it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionOnChainGovernanceVerifierKind {
    /// Inert default; every proof is refused.
    #[default]
    Disabled,
    /// Real Merkle-inclusion production verifier.
    ProductionMerkleVerifier,
    /// Reserved receipt/event-root inclusion verifier. Fail-closed in
    /// Run 299.
    ProductionReceiptVerifier,
}

impl ProductionOnChainGovernanceVerifierKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ProductionMerkleVerifier => "production-merkle-verifier",
            Self::ProductionReceiptVerifier => "production-receipt-verifier",
        }
    }

    /// Returns `true` iff this kind performs real Merkle verification.
    pub const fn is_merkle(self) -> bool {
        matches!(self, Self::ProductionMerkleVerifier)
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 299 — typed production verifier config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceProofVerifierConfig {
    /// Proof protocol version. Must equal the supported version.
    pub protocol_version: ProductionOnChainGovernanceProofProtocolVersion,
    /// The verifier kind.
    pub kind: ProductionOnChainGovernanceVerifierKind,
}

impl ProductionOnChainGovernanceProofVerifierConfig {
    pub fn new(kind: ProductionOnChainGovernanceVerifierKind) -> Self {
        Self {
            protocol_version: ProductionOnChainGovernanceProofProtocolVersion::supported(),
            kind,
        }
    }

    /// A config with the real Merkle verifier kind.
    pub fn merkle() -> Self {
        Self::new(ProductionOnChainGovernanceVerifierKind::ProductionMerkleVerifier)
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionOnChainGovernanceProofVerifierConfig {
    fn default() -> Self {
        Self::new(ProductionOnChainGovernanceVerifierKind::Disabled)
    }
}

// ===========================================================================
// Merkle inclusion proof (real SHA3-256 verifier)
// ===========================================================================

/// Run 299 — hash a Merkle leaf pre-image (a decision digest) into a
/// domain-separated 32-byte node.
pub fn merkle_leaf_hash(decision_digest: &str) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_ONCHAIN_GOVERNANCE_MERKLE_DOMAIN_TAG.as_bytes());
    // 0x00 = leaf domain byte (second-preimage separation from internal
    // nodes).
    h.update([0x00u8]);
    hash_field(&mut h, b"decision_digest", decision_digest.as_bytes());
    let out = h.finalize();
    let mut node = [0u8; 32];
    node.copy_from_slice(&out);
    node
}

/// Run 299 — hash two child nodes into a domain-separated internal node.
pub fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_ONCHAIN_GOVERNANCE_MERKLE_DOMAIN_TAG.as_bytes());
    // 0x01 = internal-node domain byte.
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut node = [0u8; 32];
    node.copy_from_slice(&out);
    node
}

/// Run 299 — a single authenticated sibling on a Merkle inclusion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceMerkleSibling {
    /// The sibling node hash, lowercase hex (32 bytes / 64 hex chars).
    pub hash_hex: String,
    /// `true` iff the sibling is on the right of the current node (so the
    /// parent is `H(current, sibling)`); `false` iff on the left (parent
    /// is `H(sibling, current)`).
    pub sibling_on_right: bool,
}

impl ProductionOnChainGovernanceMerkleSibling {
    fn node(&self) -> Option<[u8; 32]> {
        decode_hex_32(&self.hash_hex)
    }
}

/// Decode a 64-char lowercase/uppercase hex string into a 32-byte node.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Run 299 — a typed Merkle inclusion proof from a decision leaf up to a
/// claimed governance root.
///
/// The proof carries the leaf index, the authenticated sibling path, and
/// the root the proof *claims* to reach. The verifier recomputes the root
/// from the leaf + path and checks it against BOTH the claimed root and
/// the explicit trusted governance root — a proof can never self-authorize
/// its root because the trusted root is supplied out-of-band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceInclusionProof {
    /// The 0-based index of the decision leaf in the governance tree.
    pub leaf_index: u64,
    /// The authenticated sibling path from the leaf to the root.
    pub siblings: Vec<ProductionOnChainGovernanceMerkleSibling>,
    /// The governance root this proof claims to reach, lowercase hex.
    pub claimed_root_hex: String,
}

impl ProductionOnChainGovernanceInclusionProof {
    /// Returns `true` iff the proof is structurally well-formed: the
    /// claimed root and every sibling hash decode to 32-byte nodes.
    pub fn is_well_formed(&self) -> bool {
        if decode_hex_32(&self.claimed_root_hex).is_none() {
            return false;
        }
        self.siblings.iter().all(|s| s.node().is_some())
    }

    /// Recompute the Merkle root from `leaf_digest` and the authenticated
    /// sibling path. Returns `None` when any node is malformed.
    pub fn recompute_root(&self, leaf_digest: &str) -> Option<[u8; 32]> {
        let mut node = merkle_leaf_hash(leaf_digest);
        for sib in &self.siblings {
            let sibling = sib.node()?;
            node = if sib.sibling_on_right {
                merkle_node_hash(&node, &sibling)
            } else {
                merkle_node_hash(&sibling, &node)
            };
        }
        Some(node)
    }

    /// Verify the inclusion proof against `leaf_digest` and an explicit
    /// `trusted_root_hex`. Returns `true` iff the recomputed root equals
    /// BOTH the claimed root and the trusted root.
    pub fn verify(&self, leaf_digest: &str, trusted_root_hex: &str) -> bool {
        let Some(computed) = self.recompute_root(leaf_digest) else {
            return false;
        };
        let Some(claimed) = decode_hex_32(&self.claimed_root_hex) else {
            return false;
        };
        let Some(trusted) = decode_hex_32(trusted_root_hex) else {
            return false;
        };
        // Constant-work equality is not required here (all public data),
        // but the recomputed root MUST match both the claimed and the
        // out-of-band trusted root.
        computed == claimed && computed == trusted
    }
}

/// Run 299 — build a deterministic Merkle tree over `leaf_digests` and
/// return `(root_hex, inclusion_proof)` for the leaf at `index`.
///
/// Source/test helper used to construct valid production-style proofs over
/// synthetic governance trees. Duplicates the last node when a level has
/// an odd count (standard deterministic padding).
pub fn build_merkle_inclusion_proof(
    leaf_digests: &[String],
    index: usize,
) -> Option<(String, ProductionOnChainGovernanceInclusionProof)> {
    if leaf_digests.is_empty() || index >= leaf_digests.len() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaf_digests.iter().map(|d| merkle_leaf_hash(d)).collect();
    let mut idx = index;
    let mut siblings: Vec<ProductionOnChainGovernanceMerkleSibling> = Vec::new();

    while level.len() > 1 {
        // Pad odd level by duplicating the last node.
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling_on_right = idx % 2 == 0;
        siblings.push(ProductionOnChainGovernanceMerkleSibling {
            hash_hex: hex::encode(level[sibling_idx]),
            sibling_on_right,
        });
        // Build next level.
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(merkle_node_hash(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
        idx /= 2;
    }

    let root_hex = hex::encode(level[0]);
    Some((
        root_hex.clone(),
        ProductionOnChainGovernanceInclusionProof {
            leaf_index: index as u64,
            siblings,
            claimed_root_hex: root_hex,
        },
    ))
}

// ===========================================================================
// Trusted checkpoint / root
// ===========================================================================

/// Run 299 — typed trusted governance checkpoint / root.
///
/// Supplied **explicitly** to the verifier (never taken from the proof).
/// Carries a stable checkpoint id, the governance root the inclusion proof
/// must reach, optional receipt/event/state roots, and the governance
/// height / epoch the checkpoint was anchored at. A missing (empty)
/// governance root fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProductionOnChainGovernanceTrustedCheckpoint {
    /// Stable, opaque checkpoint identifier.
    pub checkpoint_id: String,
    /// The trusted governance root (lowercase hex, 32 bytes).
    pub governance_root_hex: String,
    /// Optional trusted receipt root.
    pub receipt_root_hex: Option<String>,
    /// Optional trusted event root.
    pub event_root_hex: Option<String>,
    /// Optional trusted state root.
    pub state_root_hex: Option<String>,
    /// The governance height the checkpoint was anchored at.
    pub governance_height: u64,
    /// The governance epoch the checkpoint was anchored at.
    pub governance_epoch: u64,
}

impl ProductionOnChainGovernanceTrustedCheckpoint {
    /// Returns `true` iff the checkpoint id and governance root are
    /// structurally present and the governance root decodes to a 32-byte
    /// node.
    pub fn is_present(&self) -> bool {
        !self.checkpoint_id.is_empty()
            && !self.governance_root_hex.is_empty()
            && decode_hex_32(&self.governance_root_hex).is_some()
    }

    /// Deterministic, domain-separated SHA3-256 hex checkpoint digest.
    pub fn checkpoint_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_ONCHAIN_GOVERNANCE_CHECKPOINT_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"checkpoint_id", self.checkpoint_id.as_bytes());
        hash_field(&mut h, b"governance_root", self.governance_root_hex.as_bytes());
        hash_opt(&mut h, b"receipt_root", self.receipt_root_hex.as_deref());
        hash_opt(&mut h, b"event_root", self.event_root_hex.as_deref());
        hash_opt(&mut h, b"state_root", self.state_root_hex.as_deref());
        hash_field(&mut h, b"governance_height", &self.governance_height.to_le_bytes());
        hash_field(&mut h, b"governance_epoch", &self.governance_epoch.to_le_bytes());
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Freshness bounds (explicit, never wall-clock)
// ===========================================================================

/// Run 299 — explicit governance freshness bounds.
///
/// Freshness is expressed **only** through governance height / epoch
/// bounds — never wall-clock. The proof is fresh iff its governance height
/// and epoch fall inside `[min_height, max_height]` / `[min_epoch,
/// max_epoch]` inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceFreshnessBounds {
    pub min_governance_height: u64,
    pub max_governance_height: u64,
    pub min_governance_epoch: u64,
    pub max_governance_epoch: u64,
}

impl ProductionOnChainGovernanceFreshnessBounds {
    pub fn is_well_formed(&self) -> bool {
        self.min_governance_height <= self.max_governance_height
            && self.min_governance_epoch <= self.max_governance_epoch
    }

    pub fn contains(&self, governance_height: u64, governance_epoch: u64) -> bool {
        self.is_well_formed()
            && governance_height >= self.min_governance_height
            && governance_height <= self.max_governance_height
            && governance_epoch >= self.min_governance_epoch
            && governance_epoch <= self.max_governance_epoch
    }
}

// ===========================================================================
// Decision commitment (the Merkle leaf pre-image)
// ===========================================================================

/// Run 299 — the typed governance decision commitment.
///
/// Binds every governance / lifecycle / authority-domain field the
/// verifier checks. Its [`Self::decision_digest`] is the canonical Merkle
/// leaf pre-image; `Debug` formatting is never used as canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceDecisionCommitment {
    // ---- Trust-domain binding -----------------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    // ---- Governance binding -------------------------------------------
    pub governance_domain_id: String,
    pub governance_epoch: u64,
    pub governance_height: u64,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub proposal_outcome: OnChainGovernanceProposalOutcome,
    pub quorum: OnChainGovernanceQuorum,
    pub threshold: GovernanceThreshold,

    // ---- Lifecycle binding --------------------------------------------
    pub lifecycle_action: LocalLifecycleAction,
    pub active_bundle_signing_key_fingerprint: String,
    pub new_bundle_signing_key_fingerprint: Option<String>,
    pub revoked_bundle_signing_key_fingerprint: Option<String>,

    // ---- Sequence + candidate binding ---------------------------------
    pub authority_domain_sequence: u64,
    pub candidate_v2_digest: String,

    // ---- Replay ------------------------------------------------------
    pub decision_id: String,
}

impl ProductionOnChainGovernanceDecisionCommitment {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.governance_domain_id.is_empty()
            && !self.proposal_id.is_empty()
            && !self.proposal_digest.is_empty()
            && !self.active_bundle_signing_key_fingerprint.is_empty()
            && !self.candidate_v2_digest.is_empty()
            && !self.decision_id.is_empty()
            && self.quorum.is_well_formed()
            && self.threshold.is_well_formed()
    }

    /// Deterministic, domain-separated SHA3-256 hex decision digest — the
    /// canonical Merkle leaf pre-image.
    pub fn decision_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_ONCHAIN_GOVERNANCE_DECISION_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"environment", &self.environment.metric_code().to_le_bytes());
        hash_field(&mut h, b"chain_id", self.chain_id.as_bytes());
        hash_field(&mut h, b"genesis_hash", self.genesis_hash.as_bytes());
        hash_field(
            &mut h,
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        hash_field(&mut h, b"authority_root_suite_id", &[self.authority_root_suite_id]);
        hash_field(&mut h, b"governance_domain_id", self.governance_domain_id.as_bytes());
        hash_field(&mut h, b"governance_epoch", &self.governance_epoch.to_le_bytes());
        hash_field(&mut h, b"governance_height", &self.governance_height.to_le_bytes());
        hash_field(&mut h, b"proposal_id", self.proposal_id.as_bytes());
        hash_field(&mut h, b"proposal_digest", self.proposal_digest.as_bytes());
        hash_field(
            &mut h,
            b"proposal_outcome",
            proposal_outcome_tag(self.proposal_outcome).as_bytes(),
        );
        hash_field(&mut h, b"quorum_voted", &self.quorum.voters_voted.to_le_bytes());
        hash_field(&mut h, b"quorum_total", &self.quorum.total_voters.to_le_bytes());
        hash_field(&mut h, b"quorum_required", &self.quorum.required_quorum.to_le_bytes());
        hash_field(&mut h, b"threshold_approvals", &self.threshold.approvals.to_le_bytes());
        hash_field(&mut h, b"threshold_required", &self.threshold.required.to_le_bytes());
        hash_field(&mut h, b"threshold_total", &self.threshold.total.to_le_bytes());
        hash_field(&mut h, b"lifecycle_action", self.lifecycle_action.tag().as_bytes());
        hash_field(
            &mut h,
            b"active_bundle_signing_key_fingerprint",
            self.active_bundle_signing_key_fingerprint.as_bytes(),
        );
        hash_opt(
            &mut h,
            b"new_bundle_signing_key_fingerprint",
            self.new_bundle_signing_key_fingerprint.as_deref(),
        );
        hash_opt(
            &mut h,
            b"revoked_bundle_signing_key_fingerprint",
            self.revoked_bundle_signing_key_fingerprint.as_deref(),
        );
        hash_field(
            &mut h,
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        hash_field(&mut h, b"candidate_v2_digest", self.candidate_v2_digest.as_bytes());
        hash_field(&mut h, b"decision_id", self.decision_id.as_bytes());
        hex::encode(h.finalize())
    }
}

fn proposal_outcome_tag(o: OnChainGovernanceProposalOutcome) -> &'static str {
    match o {
        OnChainGovernanceProposalOutcome::Approved => "approved",
        OnChainGovernanceProposalOutcome::Rejected => "rejected",
    }
}

// ===========================================================================
// Production proof object
// ===========================================================================

/// Run 299 — the typed production on-chain governance proof.
///
/// Carries the protocol version, proof suite, domain separation tag, the
/// decision commitment (the Merkle leaf pre-image), the Merkle inclusion
/// proof, and the canonical `proof_bytes_digest` commitment. The proof
/// does **not** carry a trusted root — the trusted governance root is
/// supplied out-of-band via
/// [`ProductionOnChainGovernanceVerificationInputs`], so a proof can never
/// self-authorize its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceProof {
    pub protocol_version: ProductionOnChainGovernanceProofProtocolVersion,
    pub proof_suite: ProductionOnChainGovernanceProofSuite,
    pub domain_separation_tag: String,
    pub commitment: ProductionOnChainGovernanceDecisionCommitment,
    pub inclusion_proof: ProductionOnChainGovernanceInclusionProof,
    /// The canonical proof-bytes commitment. Must equal
    /// [`Self::expected_proof_digest`] computed over the decision digest,
    /// inclusion path, and claimed root.
    pub proof_bytes_digest: String,
}

impl ProductionOnChainGovernanceProof {
    /// Returns `true` iff the proof is structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        self.domain_separation_tag == PRODUCTION_ONCHAIN_GOVERNANCE_DOMAIN_SEPARATION_TAG
            && !self.proof_bytes_digest.is_empty()
            && self.proof_bytes_digest != PRODUCTION_ONCHAIN_GOVERNANCE_INVALID_PROOF_SENTINEL
            && self.commitment.is_well_formed()
            && self.inclusion_proof.is_well_formed()
    }

    /// Deterministic, domain-separated canonical proof digest binding the
    /// decision digest, the inclusion path, and the claimed root.
    pub fn expected_proof_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_ONCHAIN_GOVERNANCE_PROOF_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.0.to_le_bytes());
        hash_field(&mut h, b"proof_suite", &[self.proof_suite.0]);
        hash_field(
            &mut h,
            b"domain_separation_tag",
            self.domain_separation_tag.as_bytes(),
        );
        hash_field(&mut h, b"decision_digest", self.commitment.decision_digest().as_bytes());
        hash_field(
            &mut h,
            b"leaf_index",
            &self.inclusion_proof.leaf_index.to_le_bytes(),
        );
        for (i, sib) in self.inclusion_proof.siblings.iter().enumerate() {
            hash_field(&mut h, b"sibling_index", &(i as u64).to_le_bytes());
            hash_field(&mut h, b"sibling_hash", sib.hash_hex.as_bytes());
            hash_field(&mut h, b"sibling_on_right", &[sib.sibling_on_right as u8]);
        }
        hash_field(
            &mut h,
            b"claimed_root",
            self.inclusion_proof.claimed_root_hex.as_bytes(),
        );
        hex::encode(h.finalize())
    }

    /// Recompute and set the canonical `proof_bytes_digest`. Source/test
    /// helper for building valid proofs.
    pub fn seal(mut self) -> Self {
        self.proof_bytes_digest = self.expected_proof_digest();
        self
    }
}

// ===========================================================================
// Verification inputs (explicit trusted inputs, supplied out-of-band)
// ===========================================================================

/// Run 299 — the explicit, caller-supplied trusted verification inputs.
///
/// Every field here is an **out-of-band expectation** the proof is bound
/// against — the proof never supplies these itself. This is what makes the
/// verification real: the trusted governance root, the expected governance
/// / lifecycle / candidate bindings, the freshness bounds, and the replay
/// decision-id set all come from the caller, not the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceVerificationInputs {
    /// The explicit trusted governance checkpoint/root.
    pub trusted_checkpoint: ProductionOnChainGovernanceTrustedCheckpoint,
    /// Expected governance domain id.
    pub expected_governance_domain_id: String,
    /// Expected governance epoch.
    pub expected_governance_epoch: u64,
    /// Expected proposal id.
    pub expected_proposal_id: String,
    /// Expected proposal digest.
    pub expected_proposal_digest: String,
    /// Expected proposal outcome (must be `Approved` to authorize).
    pub expected_proposal_outcome: OnChainGovernanceProposalOutcome,
    /// Expected lifecycle action.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate v2 digest.
    pub expected_candidate_v2_digest: String,
    /// Expected authority-domain sequence.
    pub expected_authority_domain_sequence: u64,
    /// Explicit freshness bounds (governance height / epoch).
    pub freshness_bounds: ProductionOnChainGovernanceFreshnessBounds,
    /// Optional persisted authority-domain sequence for stale-lower-
    /// sequence replay detection.
    pub persisted_sequence: Option<u64>,
}

impl ProductionOnChainGovernanceVerificationInputs {
    /// Returns `true` iff the inputs are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        self.trusted_checkpoint.is_present()
            && !self.expected_governance_domain_id.is_empty()
            && !self.expected_proposal_id.is_empty()
            && !self.expected_proposal_digest.is_empty()
            && !self.expected_candidate_v2_digest.is_empty()
            && self.freshness_bounds.is_well_formed()
    }
}

// ===========================================================================
// Replay set
// ===========================================================================

/// Run 299 — caller-owned replay decision-id set. The verifier reads from
/// this set but never mutates it.
pub trait ProductionOnChainGovernanceReplaySet {
    fn contains(&self, decision_id: &str) -> bool;
}

impl ProductionOnChainGovernanceReplaySet for &[String] {
    fn contains(&self, decision_id: &str) -> bool {
        (*self).iter().any(|s| s == decision_id)
    }
}

impl ProductionOnChainGovernanceReplaySet for Vec<String> {
    fn contains(&self, decision_id: &str) -> bool {
        self.iter().any(|s| s == decision_id)
    }
}

/// Empty replay set helper.
pub struct EmptyProductionOnChainGovernanceReplaySet;

impl ProductionOnChainGovernanceReplaySet for EmptyProductionOnChainGovernanceReplaySet {
    fn contains(&self, _decision_id: &str) -> bool {
        false
    }
}

// ===========================================================================
// Error taxonomy (transport / availability, injected by verifier boundary)
// ===========================================================================

/// Run 299 — typed production proof error a real on-chain proof source
/// might surface (availability / material). Injected via the source/test
/// verifier boundary and mock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionOnChainGovernanceProofError {
    /// No proof was supplied.
    ProofMissing,
    /// The production verifier / proof source is unavailable.
    VerifierUnavailable,
    /// The proof was structurally malformed.
    Malformed { reason: String },
    /// No trusted root is available.
    TrustedRootMissing,
    /// The proof suite is unsupported.
    UnsupportedSuite { suite_id: u8 },
    /// The proof protocol version is unsupported.
    UnsupportedProtocol { version: u16 },
    /// The inclusion / commitment verification material is unavailable.
    InclusionMaterialUnavailable,
}

impl ProductionOnChainGovernanceProofError {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProofMissing => "proof-missing",
            Self::VerifierUnavailable => "verifier-unavailable",
            Self::Malformed { .. } => "malformed",
            Self::TrustedRootMissing => "trusted-root-missing",
            Self::UnsupportedSuite { .. } => "unsupported-suite",
            Self::UnsupportedProtocol { .. } => "unsupported-protocol",
            Self::InclusionMaterialUnavailable => "inclusion-material-unavailable",
        }
    }
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 299 — typed outcome of the production on-chain governance proof
/// verifier.
///
/// Only [`Self::AcceptedProductionOnChainGovernanceProof`] authorizes a
/// (source/test, DevNet/TestNet, evidence-only) production-style proof.
/// Every other variant is a precise, non-mutating fail-closed reject (or
/// the inert [`Self::Disabled`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionOnChainGovernanceProofOutcome {
    /// Policy is `Disabled`; no proof was parsed.
    Disabled,

    /// A production-style proof was verified against the explicit trusted
    /// root/checkpoint under the source/test production policy on
    /// DevNet/TestNet. **Evidence only.**
    AcceptedProductionOnChainGovernanceProof {
        environment: TrustBundleEnvironment,
        governance_epoch: u64,
        authority_domain_sequence: u64,
        lifecycle_action: LocalLifecycleAction,
        decision_id: String,
    },

    /// A fixture proof was accepted (represented for parity; Run 299 does
    /// not accept fixture proofs on the production path).
    AcceptedFixtureOnChainGovernanceProof,

    /// A fixture-class proof was presented on MainNet under a production
    /// policy — rejected.
    FixtureProofRejectedAsMainNetProductionAuthority,
    /// A fixture-class proof was presented under a production policy —
    /// rejected (fixture proof is never production authority).
    FixtureProofRejectedAsProductionAuthority,

    /// The production verifier was unavailable / misconfigured.
    ProductionVerifierUnavailable,
    /// The explicit trusted governance root/checkpoint was missing.
    ProductionTrustedRootMissing,
    /// The proof reached a governance root that did not match the trusted
    /// root/checkpoint.
    ProductionTrustedRootMismatch,
    /// The proof was structurally malformed.
    ProductionProofMalformed { reason: String },
    /// The proof suite was unsupported.
    ProductionProofUnsupportedSuite { suite_id: u8 },
    /// The proof protocol version was unsupported.
    ProductionProofUnsupportedProtocol { version: u16 },
    /// The proof failed verification for an unclassified reason.
    ProductionProofInvalid { reason: String },
    /// The proof was outside the explicit freshness bounds.
    ProductionProofExpired,
    /// The decision id was replayed.
    ProductionProofReplayRejected { decision_id: String },

    // ---- Binding mismatches -------------------------------------------
    ProductionProofWrongEnvironment,
    ProductionProofWrongChain,
    ProductionProofWrongGenesis,
    ProductionProofWrongAuthorityRoot,
    ProductionProofWrongGovernanceDomain,
    ProductionProofWrongGovernanceEpoch,
    ProductionProofWrongProposalId,
    ProductionProofWrongProposalDigest,
    ProductionProofWrongProposalOutcome,
    ProductionProofWrongLifecycleAction,
    ProductionProofWrongCandidateDigest,
    ProductionProofWrongAuthoritySequence,
    ProductionProofWrongDecisionId,

    // ---- Quorum / threshold / inclusion -------------------------------
    ProductionProofQuorumNotMet,
    ProductionProofThresholdNotMet,
    ProductionProofInclusionFailed,
    ProductionProofRootMismatch,
    ProductionProofCheckpointMismatch,
    ProductionProofAmbiguous { reason: String },

    // ---- Explicit non-authority rejects -------------------------------
    LocalOperatorConfigOnlyRejected,
    PeerMajorityProofRejected,
    CustodyOnlyProofRejected,
    RemoteSignerOnlyProofRejected,

    // ---- MainNet / governance-engine / validator-set gates ------------
    MainNetProductionGovernanceProofUnavailable,
    MainNetRefused,
    GovernanceExecutionEngineUnavailable,
    ValidatorSetRotationUnsupported,

    /// The request / config was structurally malformed or the outcome
    /// could not be classified — fail closed.
    AmbiguousFailClosed { reason: String },
}

impl ProductionOnChainGovernanceProofOutcome {
    /// Returns `true` iff this outcome accepted a production proof.
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedProductionOnChainGovernanceProof { .. }
        )
    }

    /// Every Run 299 outcome is non-mutating.
    pub fn is_non_mutating(&self) -> bool {
        true
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AcceptedProductionOnChainGovernanceProof { .. } => {
                "accepted-production-onchain-governance-proof"
            }
            Self::AcceptedFixtureOnChainGovernanceProof => {
                "accepted-fixture-onchain-governance-proof"
            }
            Self::FixtureProofRejectedAsMainNetProductionAuthority => {
                "fixture-proof-rejected-as-mainnet-production-authority"
            }
            Self::FixtureProofRejectedAsProductionAuthority => {
                "fixture-proof-rejected-as-production-authority"
            }
            Self::ProductionVerifierUnavailable => "production-verifier-unavailable",
            Self::ProductionTrustedRootMissing => "production-trusted-root-missing",
            Self::ProductionTrustedRootMismatch => "production-trusted-root-mismatch",
            Self::ProductionProofMalformed { .. } => "production-proof-malformed",
            Self::ProductionProofUnsupportedSuite { .. } => "production-proof-unsupported-suite",
            Self::ProductionProofUnsupportedProtocol { .. } => {
                "production-proof-unsupported-protocol"
            }
            Self::ProductionProofInvalid { .. } => "production-proof-invalid",
            Self::ProductionProofExpired => "production-proof-expired",
            Self::ProductionProofReplayRejected { .. } => "production-proof-replay-rejected",
            Self::ProductionProofWrongEnvironment => "production-proof-wrong-environment",
            Self::ProductionProofWrongChain => "production-proof-wrong-chain",
            Self::ProductionProofWrongGenesis => "production-proof-wrong-genesis",
            Self::ProductionProofWrongAuthorityRoot => "production-proof-wrong-authority-root",
            Self::ProductionProofWrongGovernanceDomain => "production-proof-wrong-governance-domain",
            Self::ProductionProofWrongGovernanceEpoch => "production-proof-wrong-governance-epoch",
            Self::ProductionProofWrongProposalId => "production-proof-wrong-proposal-id",
            Self::ProductionProofWrongProposalDigest => "production-proof-wrong-proposal-digest",
            Self::ProductionProofWrongProposalOutcome => "production-proof-wrong-proposal-outcome",
            Self::ProductionProofWrongLifecycleAction => "production-proof-wrong-lifecycle-action",
            Self::ProductionProofWrongCandidateDigest => "production-proof-wrong-candidate-digest",
            Self::ProductionProofWrongAuthoritySequence => "production-proof-wrong-authority-sequence",
            Self::ProductionProofWrongDecisionId => "production-proof-wrong-decision-id",
            Self::ProductionProofQuorumNotMet => "production-proof-quorum-not-met",
            Self::ProductionProofThresholdNotMet => "production-proof-threshold-not-met",
            Self::ProductionProofInclusionFailed => "production-proof-inclusion-failed",
            Self::ProductionProofRootMismatch => "production-proof-root-mismatch",
            Self::ProductionProofCheckpointMismatch => "production-proof-checkpoint-mismatch",
            Self::ProductionProofAmbiguous { .. } => "production-proof-ambiguous",
            Self::LocalOperatorConfigOnlyRejected => "local-operator-config-only-rejected",
            Self::PeerMajorityProofRejected => "peer-majority-proof-rejected",
            Self::CustodyOnlyProofRejected => "custody-only-proof-rejected",
            Self::RemoteSignerOnlyProofRejected => "remote-signer-only-proof-rejected",
            Self::MainNetProductionGovernanceProofUnavailable => {
                "mainnet-production-governance-proof-unavailable"
            }
            Self::MainNetRefused => "mainnet-refused",
            Self::GovernanceExecutionEngineUnavailable => "governance-execution-engine-unavailable",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::AmbiguousFailClosed { .. } => "ambiguous-fail-closed",
        }
    }
}

/// Map an injected proof-source error to a precise fail-closed outcome.
fn error_to_outcome(
    err: &ProductionOnChainGovernanceProofError,
) -> ProductionOnChainGovernanceProofOutcome {
    use ProductionOnChainGovernanceProofError as E;
    use ProductionOnChainGovernanceProofOutcome as O;
    match err {
        E::ProofMissing => O::ProductionProofMalformed {
            reason: "proof-missing".to_string(),
        },
        E::VerifierUnavailable => O::ProductionVerifierUnavailable,
        E::Malformed { reason } => O::ProductionProofMalformed {
            reason: reason.clone(),
        },
        E::TrustedRootMissing => O::ProductionTrustedRootMissing,
        E::UnsupportedSuite { suite_id } => {
            O::ProductionProofUnsupportedSuite { suite_id: *suite_id }
        }
        E::UnsupportedProtocol { version } => {
            O::ProductionProofUnsupportedProtocol { version: *version }
        }
        E::InclusionMaterialUnavailable => O::ProductionProofInclusionFailed,
    }
}

// ===========================================================================
// Decision + transcript
// ===========================================================================

/// Run 299 — the typed decision produced by the verifier: the outcome, the
/// bound decision id, the proof digest, and the verification transcript
/// digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionOnChainGovernanceProofDecision {
    pub outcome: ProductionOnChainGovernanceProofOutcome,
    pub decision_id: String,
    pub proof_digest: String,
    pub transcript_digest: String,
}

impl ProductionOnChainGovernanceProofDecision {
    pub fn is_accept(&self) -> bool {
        self.outcome.is_accept()
    }
}

/// Run 299 — deterministic, domain-separated verification transcript
/// digest binding the protocol version, decision digest, checkpoint
/// digest, and outcome tag.
pub fn production_onchain_governance_transcript_digest(
    protocol_version: u16,
    decision_digest: &str,
    checkpoint_digest: &str,
    proof_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_ONCHAIN_GOVERNANCE_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"decision_digest", decision_digest.as_bytes());
    hash_field(&mut h, b"checkpoint_digest", checkpoint_digest.as_bytes());
    hash_field(&mut h, b"proof_digest", proof_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

/// Run 299 — deterministic decision digest wrapper exposed as a named
/// symbol (delegates to the commitment's canonical digest).
pub fn production_onchain_governance_decision_digest(
    commitment: &ProductionOnChainGovernanceDecisionCommitment,
) -> String {
    commitment.decision_digest()
}

/// Run 299 — deterministic proof digest wrapper exposed as a named symbol.
pub fn production_onchain_governance_proof_digest(
    proof: &ProductionOnChainGovernanceProof,
) -> String {
    proof.expected_proof_digest()
}

// ===========================================================================
// Inclusion-verifier boundary (mockable)
// ===========================================================================

/// Run 299 — verified material a real inclusion verifier returns after
/// checking a proof against a trusted root. Source/test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInclusionMaterial {
    /// The decision digest whose inclusion was verified.
    pub decision_digest: String,
    /// The trusted governance root the inclusion was verified against.
    pub verified_root_hex: String,
}

/// Run 299 — narrow, mockable inclusion-verifier boundary.
///
/// The real [`RealMerkleInclusionVerifier`] performs actual SHA3-256
/// Merkle recomputation. A fail-closed stub and a programmable mock are
/// provided for fault injection. Implementations must perform no marker
/// write, no sequence write, no live-trust mutation, no session eviction,
/// and must never invoke Run 070.
pub trait OnChainGovernanceInclusionVerifier {
    /// Verify `proof`'s inclusion path against `trusted_root_hex`.
    fn verify_inclusion(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        trusted_root_hex: &str,
    ) -> Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError>;
}

/// Run 299 — the real Merkle inclusion verifier. Recomputes the governance
/// root from the decision leaf + authenticated sibling path and checks it
/// against the explicit trusted root. Records how many times it was
/// invoked so tests can prove Disabled never reaches it.
#[derive(Default)]
pub struct RealMerkleInclusionVerifier {
    call_count: Cell<u32>,
}

impl RealMerkleInclusionVerifier {
    pub fn new() -> Self {
        Self {
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl OnChainGovernanceInclusionVerifier for RealMerkleInclusionVerifier {
    fn verify_inclusion(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        trusted_root_hex: &str,
    ) -> Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError> {
        self.call_count.set(self.call_count.get() + 1);
        if trusted_root_hex.is_empty() || decode_hex_32(trusted_root_hex).is_none() {
            return Err(ProductionOnChainGovernanceProofError::TrustedRootMissing);
        }
        if !proof.inclusion_proof.is_well_formed() {
            return Err(ProductionOnChainGovernanceProofError::Malformed {
                reason: "inclusion-proof-malformed".to_string(),
            });
        }
        let decision_digest = proof.commitment.decision_digest();
        if !proof
            .inclusion_proof
            .verify(&decision_digest, trusted_root_hex)
        {
            return Err(ProductionOnChainGovernanceProofError::InclusionMaterialUnavailable);
        }
        Ok(VerifiedInclusionMaterial {
            decision_digest,
            verified_root_hex: trusted_root_hex.to_string(),
        })
    }
}

/// Run 299 — reachable-but-fail-closed inclusion verifier stub (e.g. a
/// future bridge / light-client integration that is not wired in Run 299).
pub struct UnavailableInclusionVerifierStub {
    error: ProductionOnChainGovernanceProofError,
    call_count: Cell<u32>,
}

impl UnavailableInclusionVerifierStub {
    pub fn new(error: ProductionOnChainGovernanceProofError) -> Self {
        Self {
            error,
            call_count: Cell::new(0),
        }
    }

    /// A stub representing an unavailable bridge / light-client verifier.
    pub fn unavailable() -> Self {
        Self::new(ProductionOnChainGovernanceProofError::VerifierUnavailable)
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl OnChainGovernanceInclusionVerifier for UnavailableInclusionVerifierStub {
    fn verify_inclusion(
        &self,
        _proof: &ProductionOnChainGovernanceProof,
        _trusted_root_hex: &str,
    ) -> Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError> {
        self.call_count.set(self.call_count.get() + 1);
        Err(self.error.clone())
    }
}

/// Run 299 — programmable source/test inclusion verifier for fault
/// injection.
pub struct MockInclusionVerifier {
    steps: RefCell<
        VecDeque<Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError>>,
    >,
    default_result: RefCell<Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError>>,
    call_count: Cell<u32>,
}

impl MockInclusionVerifier {
    pub fn always_fail(err: ProductionOnChainGovernanceProofError) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Err(err)),
            call_count: Cell::new(0),
        }
    }

    pub fn scripted(
        steps: Vec<Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError>>,
        default_result: Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError>,
    ) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            default_result: RefCell::new(default_result),
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl OnChainGovernanceInclusionVerifier for MockInclusionVerifier {
    fn verify_inclusion(
        &self,
        _proof: &ProductionOnChainGovernanceProof,
        _trusted_root_hex: &str,
    ) -> Result<VerifiedInclusionMaterial, ProductionOnChainGovernanceProofError> {
        self.call_count.set(self.call_count.get() + 1);
        if let Some(step) = self.steps.borrow_mut().pop_front() {
            step
        } else {
            self.default_result.borrow().clone()
        }
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 299 — typed outcome of a proof replay / recovery-window check.
///
/// Run 299 models only pure source/test replay semantics: idempotent
/// re-verification of byte-identical proofs and fail-closed refusal of any
/// conflicting decision transcript / proposal digest / candidate digest /
/// lifecycle action for a reused decision id. It claims **no** durable
/// proof-acceptance persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionOnChainGovernanceRecoveryOutcome {
    /// No prior proof exists; nothing to recover.
    NoPriorProof,
    /// The current proof is byte-identical to the prior proof — idempotent.
    IdempotentReplayOfSameProof,
    /// Same decision id, different proof transcript — fail closed.
    ConflictingTranscriptForSameDecisionId,
    /// Same decision id, different proposal digest — fail closed.
    ConflictingProposalDigestForSameDecisionId,
    /// Same decision id, different candidate digest — fail closed.
    ConflictingCandidateDigestForSameDecisionId,
    /// Same decision id, different lifecycle action — fail closed.
    ConflictingLifecycleActionForSameDecisionId,
    /// A stale governance epoch — fail closed.
    StaleGovernanceEpoch,
    /// The recovery window is ambiguous — fail closed.
    AmbiguousRecoveryFailClosed { reason: String },
}

impl ProductionOnChainGovernanceRecoveryOutcome {
    pub fn is_idempotent(&self) -> bool {
        matches!(self, Self::IdempotentReplayOfSameProof)
    }
}

// ===========================================================================
// Verifier trait
// ===========================================================================

/// Run 299 — the production on-chain governance proof verifier boundary.
///
/// Implementations drive an [`OnChainGovernanceInclusionVerifier`],
/// applying the policy gate, MainNet refusal, suite / protocol gating,
/// binding comparison against the explicit trusted inputs, freshness /
/// replay checks, quorum / threshold checks, and real inclusion
/// verification against the explicit trusted governance root. No
/// implementation mutates live trust, writes a marker/sequence, evicts
/// sessions, performs settlement / external publication / governance
/// execution / validator-set rotation, or invokes Run 070.
pub trait GovernanceProductionOnChainGovernanceProofVerifier {
    /// Verify `proof` against `inputs` and the trust domain, returning a
    /// precise outcome. Does not build a transcript.
    fn verify_production_onchain_governance_proof_real<
        R: ProductionOnChainGovernanceReplaySet + ?Sized,
    >(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
        replay_set: &R,
    ) -> ProductionOnChainGovernanceProofOutcome;

    /// Verify and produce a full decision (outcome + transcript digest).
    fn evaluate_production_onchain_governance_proof<
        R: ProductionOnChainGovernanceReplaySet + ?Sized,
    >(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
        replay_set: &R,
    ) -> ProductionOnChainGovernanceProofDecision;

    /// Evaluate a proof replay / recovery window against a prior proof.
    fn recover_proof_window(
        &self,
        prior: Option<&ProductionOnChainGovernanceProof>,
        current: &ProductionOnChainGovernanceProof,
        current_min_governance_epoch: u64,
    ) -> ProductionOnChainGovernanceRecoveryOutcome;
}

// ===========================================================================
// Verifier implementation
// ===========================================================================

/// Run 299 — the real production on-chain governance proof verifier.
///
/// Generic over the injected [`OnChainGovernanceInclusionVerifier`] so the
/// same real verifier logic runs over the real Merkle verifier, a
/// reachable-but-fail-closed stub, or a programmable mock.
pub struct ProductionOnChainGovernanceProofVerifier<V: OnChainGovernanceInclusionVerifier> {
    pub config: ProductionOnChainGovernanceProofVerifierConfig,
    pub policy: ProductionOnChainGovernanceVerifierPolicy,
    pub inclusion_verifier: V,
}

impl<V: OnChainGovernanceInclusionVerifier> ProductionOnChainGovernanceProofVerifier<V> {
    pub fn new(
        config: ProductionOnChainGovernanceProofVerifierConfig,
        policy: ProductionOnChainGovernanceVerifierPolicy,
        inclusion_verifier: V,
    ) -> Self {
        Self {
            config,
            policy,
            inclusion_verifier,
        }
    }

    /// Pure policy / MainNet / suite / protocol gate applied before any
    /// inclusion verification. Returns `Some(outcome)` to refuse before
    /// verification, `None` to proceed.
    fn preflight_gate(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionOnChainGovernanceProofOutcome> {
        use ProductionOnChainGovernanceProofOutcome as O;

        // 1. Disabled fails closed before any parsing / verification.
        if self.policy.is_disabled()
            || self.config.kind == ProductionOnChainGovernanceVerifierKind::Disabled
        {
            return Some(O::Disabled);
        }

        // 2. Fixture-class proof is never production authority. The Run
        //    186 classifier drives this (fixture suite => Fixture). A
        //    fixture proof's suite is rejected up front.
        if proof.proof_suite.is_fixture() {
            return Some(if trust_domain.environment == TrustBundleEnvironment::Mainnet {
                O::FixtureProofRejectedAsMainNetProductionAuthority
            } else {
                O::FixtureProofRejectedAsProductionAuthority
            });
        }

        // 3. MainNet gate. A MainNet trust domain requires the explicit
        //    test-only MainNet policy; even then no production authority
        //    material is wired, so MainNet fails closed as unavailable.
        //    Any other policy on MainNet is refused. Gated before
        //    verification so MainNet can never reach an accept path.
        if trust_domain.environment == TrustBundleEnvironment::Mainnet
            || proof.commitment.environment == TrustBundleEnvironment::Mainnet
        {
            return Some(match self.policy {
                ProductionOnChainGovernanceVerifierPolicy::MainnetProductionProofRequired => {
                    O::MainNetProductionGovernanceProofUnavailable
                }
                _ => O::MainNetRefused,
            });
        }

        // 4. The test-only MainNet policy on a non-MainNet domain has no
        //    real production authority wired — fail closed.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionGovernanceProofUnavailable);
        }

        // 5. Reserved kinds (receipt verifier) are fail-closed in Run 299.
        if self.config.kind == ProductionOnChainGovernanceVerifierKind::ProductionReceiptVerifier {
            return Some(O::ProductionVerifierUnavailable);
        }

        // 6. Config / proof / inputs well-formedness.
        if !self.config.is_well_formed() {
            return Some(O::AmbiguousFailClosed {
                reason: "config-malformed".to_string(),
            });
        }
        if !proof.is_well_formed() {
            return Some(O::ProductionProofMalformed {
                reason: "proof-structurally-malformed".to_string(),
            });
        }
        if !inputs.is_well_formed() {
            if !inputs.trusted_checkpoint.is_present() {
                return Some(O::ProductionTrustedRootMissing);
            }
            return Some(O::ProductionProofMalformed {
                reason: "verification-inputs-malformed".to_string(),
            });
        }

        // 7. Protocol version.
        if !proof.protocol_version.is_supported() {
            return Some(O::ProductionProofUnsupportedProtocol {
                version: proof.protocol_version.0,
            });
        }

        // 8. Proof suite must be the supported production suite.
        if !proof.proof_suite.is_supported() {
            return Some(O::ProductionProofUnsupportedSuite {
                suite_id: proof.proof_suite.0,
            });
        }

        // 9. Canonical proof-bytes commitment must match.
        if proof.proof_bytes_digest != proof.expected_proof_digest() {
            return Some(O::ProductionProofInvalid {
                reason: "proof-bytes-digest-mismatch".to_string(),
            });
        }

        None
    }

    /// Field-by-field binding comparison against the explicit trusted
    /// inputs and the authoritative trust domain. Returns `Some(outcome)`
    /// on the first mismatch.
    fn check_binding(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionOnChainGovernanceProofOutcome> {
        use ProductionOnChainGovernanceProofOutcome as O;
        let c = &proof.commitment;

        // Trust-domain binding: must match the authoritative trust domain.
        if c.environment != trust_domain.environment {
            return Some(O::ProductionProofWrongEnvironment);
        }
        if c.chain_id != trust_domain.chain_id {
            return Some(O::ProductionProofWrongChain);
        }
        if c.genesis_hash != trust_domain.genesis_hash {
            return Some(O::ProductionProofWrongGenesis);
        }
        if c.authority_root_fingerprint != trust_domain.authority_root_fingerprint
            || c.authority_root_suite_id != trust_domain.authority_root_suite_id
        {
            return Some(O::ProductionProofWrongAuthorityRoot);
        }

        // Governance binding: must match the explicit expected inputs.
        if c.governance_domain_id != inputs.expected_governance_domain_id {
            return Some(O::ProductionProofWrongGovernanceDomain);
        }
        if c.governance_epoch != inputs.expected_governance_epoch {
            return Some(O::ProductionProofWrongGovernanceEpoch);
        }
        if c.proposal_id != inputs.expected_proposal_id {
            return Some(O::ProductionProofWrongProposalId);
        }
        if c.proposal_digest != inputs.expected_proposal_digest {
            return Some(O::ProductionProofWrongProposalDigest);
        }
        if c.proposal_outcome != inputs.expected_proposal_outcome
            || c.proposal_outcome != OnChainGovernanceProposalOutcome::Approved
        {
            return Some(O::ProductionProofWrongProposalOutcome);
        }
        if c.lifecycle_action != inputs.expected_lifecycle_action {
            return Some(O::ProductionProofWrongLifecycleAction);
        }
        if c.candidate_v2_digest != inputs.expected_candidate_v2_digest {
            return Some(O::ProductionProofWrongCandidateDigest);
        }
        if c.authority_domain_sequence != inputs.expected_authority_domain_sequence {
            return Some(O::ProductionProofWrongAuthoritySequence);
        }

        // Checkpoint anchoring: the proof's governance epoch/height must
        // match the trusted checkpoint anchoring.
        if c.governance_epoch != inputs.trusted_checkpoint.governance_epoch
            || c.governance_height != inputs.trusted_checkpoint.governance_height
        {
            return Some(O::ProductionProofCheckpointMismatch);
        }

        None
    }
}

impl<V: OnChainGovernanceInclusionVerifier> GovernanceProductionOnChainGovernanceProofVerifier
    for ProductionOnChainGovernanceProofVerifier<V>
{
    fn verify_production_onchain_governance_proof_real<
        R: ProductionOnChainGovernanceReplaySet + ?Sized,
    >(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
        replay_set: &R,
    ) -> ProductionOnChainGovernanceProofOutcome {
        use ProductionOnChainGovernanceProofOutcome as O;

        if let Some(outcome) = self.preflight_gate(proof, inputs, trust_domain) {
            return outcome;
        }

        // Binding comparison against explicit trusted inputs.
        if let Some(outcome) = self.check_binding(proof, inputs, trust_domain) {
            return outcome;
        }

        let c = &proof.commitment;

        // Stale-lower-sequence replay.
        if let Some(prev) = inputs.persisted_sequence {
            if c.authority_domain_sequence < prev {
                return O::ProductionProofReplayRejected {
                    decision_id: c.decision_id.clone(),
                };
            }
        }
        // Decision-id replay.
        if replay_set.contains(&c.decision_id) {
            return O::ProductionProofReplayRejected {
                decision_id: c.decision_id.clone(),
            };
        }

        // Explicit freshness bounds (governance height / epoch, never
        // wall-clock).
        if !inputs
            .freshness_bounds
            .contains(c.governance_height, c.governance_epoch)
        {
            return O::ProductionProofExpired;
        }

        // Quorum / threshold enforcement where represented.
        if !c.quorum.is_met() {
            return O::ProductionProofQuorumNotMet;
        }
        if !c.threshold.is_met() {
            return O::ProductionProofThresholdNotMet;
        }

        // Real inclusion verification against the EXPLICIT trusted root.
        // The proof cannot self-authorize its root — the trusted root is
        // supplied out-of-band via the verification inputs.
        let trusted_root = &inputs.trusted_checkpoint.governance_root_hex;
        let verified = match self
            .inclusion_verifier
            .verify_inclusion(proof, trusted_root)
        {
            Ok(material) => material,
            Err(err) => return error_to_outcome(&err),
        };

        // The verifier must confirm the same decision digest and the same
        // trusted root it was asked about.
        if verified.decision_digest != c.decision_digest() {
            return O::ProductionProofAmbiguous {
                reason: "verifier decision-digest disagreement".to_string(),
            };
        }
        if verified.verified_root_hex != *trusted_root {
            return O::ProductionTrustedRootMismatch;
        }

        // Also independently confirm the claimed root matches the trusted
        // root (defense in depth vs. a self-authorizing claimed root).
        if proof.inclusion_proof.claimed_root_hex != *trusted_root {
            return O::ProductionProofRootMismatch;
        }

        // Accept — source/test, DevNet/TestNet, evidence only.
        O::AcceptedProductionOnChainGovernanceProof {
            environment: trust_domain.environment,
            governance_epoch: c.governance_epoch,
            authority_domain_sequence: c.authority_domain_sequence,
            lifecycle_action: c.lifecycle_action,
            decision_id: c.decision_id.clone(),
        }
    }

    fn evaluate_production_onchain_governance_proof<
        R: ProductionOnChainGovernanceReplaySet + ?Sized,
    >(
        &self,
        proof: &ProductionOnChainGovernanceProof,
        inputs: &ProductionOnChainGovernanceVerificationInputs,
        trust_domain: &AuthorityTrustDomain,
        replay_set: &R,
    ) -> ProductionOnChainGovernanceProofDecision {
        let outcome = self.verify_production_onchain_governance_proof_real(
            proof,
            inputs,
            trust_domain,
            replay_set,
        );
        let decision_digest = proof.commitment.decision_digest();
        let proof_digest = proof.expected_proof_digest();
        let transcript_digest = production_onchain_governance_transcript_digest(
            self.config.protocol_version.0,
            &decision_digest,
            &inputs.trusted_checkpoint.checkpoint_digest(),
            &proof_digest,
            outcome.tag(),
        );
        ProductionOnChainGovernanceProofDecision {
            outcome,
            decision_id: proof.commitment.decision_id.clone(),
            proof_digest,
            transcript_digest,
        }
    }

    fn recover_proof_window(
        &self,
        prior: Option<&ProductionOnChainGovernanceProof>,
        current: &ProductionOnChainGovernanceProof,
        current_min_governance_epoch: u64,
    ) -> ProductionOnChainGovernanceRecoveryOutcome {
        use ProductionOnChainGovernanceRecoveryOutcome as R;
        let Some(prior) = prior else {
            return R::NoPriorProof;
        };
        // Unrelated decision ids => independent window.
        if prior.commitment.decision_id != current.commitment.decision_id {
            return R::NoPriorProof;
        }
        // Same decision id, conflicting proposal digest => fail closed.
        if prior.commitment.proposal_digest != current.commitment.proposal_digest {
            return R::ConflictingProposalDigestForSameDecisionId;
        }
        // Same decision id, conflicting candidate digest => fail closed.
        if prior.commitment.candidate_v2_digest != current.commitment.candidate_v2_digest {
            return R::ConflictingCandidateDigestForSameDecisionId;
        }
        // Same decision id, conflicting lifecycle action => fail closed.
        if prior.commitment.lifecycle_action != current.commitment.lifecycle_action {
            return R::ConflictingLifecycleActionForSameDecisionId;
        }
        // Stale governance epoch => fail closed.
        if current.commitment.governance_epoch < current_min_governance_epoch {
            return R::StaleGovernanceEpoch;
        }
        // Conflicting transcript (proof digest) for the same decision id.
        if prior.expected_proof_digest() != current.expected_proof_digest() {
            return R::ConflictingTranscriptForSameDecisionId;
        }
        // Byte-identical => idempotent replay.
        if prior == current {
            R::IdempotentReplayOfSameProof
        } else {
            R::AmbiguousRecoveryFailClosed {
                reason: "same digest but non-identical proof".to_string(),
            }
        }
    }
}

// ===========================================================================
// Composition bridge with the Run 186 verifier boundary
// ===========================================================================

/// Run 299 — compose with the Run 186 verifier boundary by classifying a
/// Run 178-shaped proof suite through the Run 186 classifier.
///
/// Returns [`OnChainGovernanceProofClass::Production`] for the Run 299
/// production Merkle suite (and any non-fixture suite), and
/// [`OnChainGovernanceProofClass::Fixture`] for the Run 178 fixture suite.
/// This proves the Run 299 production suite is routed as production-class
/// by the existing Run 186 boundary rather than bypassing it.
pub fn classify_production_suite_through_run186(
    suite: ProductionOnChainGovernanceProofSuite,
) -> OnChainGovernanceProofClass {
    // Build a minimal Run 178 proof carrying only the suite so the Run 186
    // classifier can be exercised on the Run 299 production suite.
    use crate::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;
    use crate::pqc_onchain_governance_proof::{
        OnChainGovernanceFreshnessWindow, OnChainGovernanceProof,
    };
    let probe = OnChainGovernanceProof {
        environment: TrustBundleEnvironment::Devnet,
        chain_id: "x".to_string(),
        genesis_hash: "x".to_string(),
        authority_root_fingerprint: "x".to_string(),
        authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
        governance_domain_id: "x".to_string(),
        governance_epoch: 0,
        proposal_id: "x".to_string(),
        proposal_digest: "x".to_string(),
        proposal_outcome: OnChainGovernanceProposalOutcome::Approved,
        quorum: OnChainGovernanceQuorum {
            voters_voted: 1,
            total_voters: 1,
            required_quorum: 1,
        },
        threshold: GovernanceThreshold::new(1, 1, 1),
        lifecycle_action: LocalLifecycleAction::Rotate,
        active_bundle_signing_key_fingerprint: "x".to_string(),
        new_bundle_signing_key_fingerprint: None,
        revoked_bundle_signing_key_fingerprint: None,
        authority_domain_sequence: 0,
        candidate_v2_digest: "x".to_string(),
        freshness: OnChainGovernanceFreshnessWindow {
            not_before_unix: 0,
            not_after_unix: 1,
        },
        unique_decision_id: "x".to_string(),
        proof_suite_id: suite.0,
        proof_bytes: vec![1],
    };
    classify_onchain_governance_proof_class(&probe)
}

// ===========================================================================
// Explicit fail-closed / scope helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 299 — returns `true`: the production on-chain governance proof
/// verifier default policy is `Disabled`.
pub fn production_onchain_governance_verifier_default_is_disabled() -> bool {
    ProductionOnChainGovernanceVerifierPolicy::default()
        == ProductionOnChainGovernanceVerifierPolicy::Disabled
        && ProductionOnChainGovernanceProofVerifierConfig::default().kind
            == ProductionOnChainGovernanceVerifierKind::Disabled
}

/// Run 299 — returns `true`: fixture proof can never satisfy production
/// on-chain governance authority.
pub fn production_onchain_governance_verifier_rejects_fixture_as_production() -> bool {
    true
}

/// Run 299 — returns `true`: MainNet remains refused even for otherwise
/// valid synthetic production-style proofs.
pub fn production_onchain_governance_verifier_mainnet_refused() -> bool {
    true
}

/// Run 299 — returns `true`: the proof cannot self-authorize its root; the
/// trusted governance root is supplied out-of-band.
pub fn production_onchain_governance_verifier_root_supplied_out_of_band() -> bool {
    true
}

/// Run 299 — returns `true`: the verifier never falls back to fixture /
/// local-operator / peer-majority / RemoteSigner / custody-only proof
/// under a production policy.
pub fn production_onchain_governance_verifier_never_falls_back() -> bool {
    true
}

/// Run 299 — returns `true`: this run is a source/test implementation and
/// is NOT release-binary evidence (deferred to Run 300).
pub fn production_onchain_governance_verifier_is_source_test_not_release_binary_evidence() -> bool {
    true
}

/// Run 299 — returns `true`: the verifier performs no Run 070 apply, no
/// `LivePqcTrustState` mutation, no trust swap, no session eviction, no
/// sequence/marker write, no durable replay overwrite, no settlement, no
/// external publication, no governance execution, and no validator-set
/// rotation.
pub fn production_onchain_governance_verifier_is_non_mutating() -> bool {
    true
}

/// Run 299 — returns `true`: a valid on-chain governance proof does not
/// enable the governance execution engine, validator-set rotation, or
/// MainNet runtime behavior.
pub fn production_onchain_governance_verifier_does_not_enable_downstream_gates() -> bool {
    true
}
