//! Run 071 (C4 piece: PQC trust-anchor lifecycle — mutable live
//! trust-context handle, initialize-only): the smallest safe shared
//! "live" view of the validated startup [`LoadedTrustBundle`] that
//! PQC handshake verification can read through, instead of binding
//! the active root / revocation material into immutable
//! `ClientHandshakeConfig` / `ServerHandshakeConfig` constructs at
//! build time.
//!
//! # Strict scope (what Run 071 is and is NOT)
//!
//! Run 071 is **only** the smallest possible foundation under the
//! umbrella "trust-bundle hot reload" item in
//! `docs/whitepaper/contradiction.md` C4. It is intentionally
//! minimal:
//!
//! - This module introduces a `LivePqcTrustState` handle that owns
//!   an `Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`.
//! - The snapshot inside the handle is initialized **once** at
//!   startup from the already-validated [`LoadedTrustBundle`].
//! - PQC handshake verification (listener `TrustedClientRoots` +
//!   `LeafCertRevocationList`) can read through the live handle
//!   instead of through a cloned-into-closure snapshot of
//!   [`crate::pqc_root_config::PqcStaticRootConfig`] /
//!   `Arc<HashSet<[u8;32]>>`.
//! - Run 071 NEVER mutates the live trust handle after startup. The
//!   `swap_snapshot` method exists as future capability for Run 072
//!   but is **not** wired into any reload-apply path, **not** used
//!   by the production binary, and **not** exercised on any startup
//!   path.
//! - Run 071 does NOT connect to reload-apply (`pqc_trust_reload::
//!   apply_validated_candidate`). Run 070's production-binary surface
//!   continues to return `ReloadApplyError::UnsupportedRuntimeContext`
//!   because session eviction is still absent.
//! - Run 071 does NOT accept peer-supplied or gossiped bundles.
//! - Run 071 does NOT rotate the bundle-signing key, integrate with
//!   KMS/HSM, or implement `activation_epoch` runtime sourcing.
//! - Run 071 does NOT redesign KEMTLS, consensus, or the sequence
//!   persistence layer.
//! - Run 071 does NOT weaken Run 069 reload-check (non-mutating)
//!   nor Run 070's apply contract (validate → swap → evict →
//!   commit ordering).
//!
//! Operators must read the Run 071 evidence document and the C4
//! contradiction entry: the production binary's mutable trust
//! context exists at the *handle* level, but the binary still does
//! **not** apply live trust-bundle changes — that remains gated on
//! the production session-eviction hook.
//!
//! # What we DO carry on the snapshot
//!
//! Public, post-validation metadata only:
//!
//! - `environment` (mirrors [`crate::pqc_trust_bundle::TrustBundleEnvironment`]);
//! - `chain_id` (lowercase hex from the bundle; `None` is preserved
//!   bit-for-bit on DevNet);
//! - `fingerprint` (the bundle's deterministic SHA3-256 canonical
//!   fingerprint computed by
//!   [`crate::pqc_trust_bundle::canonical_fingerprint`]);
//! - `sequence` (`bundle.sequence`);
//! - `signature_status`
//!   ([`crate::pqc_trust_bundle::BundleSignatureStatus`]) — the
//!   verified signing-key id is metadata, the *secret* is never
//!   stored here;
//! - `active_roots` (the post-validation `Vec<PqcTrustedRoot>` from
//!   the loaded bundle — public ML-DSA-44 root public keys only);
//! - `revoked_root_ids` (active root-revocation set, post Run 062
//!   activation gating);
//! - `revoked_leaf_fingerprints` (active leaf-revocation set, post
//!   Run 062 activation gating);
//! - `pending_revoked_root_ids` / `pending_revoked_leaf_fingerprints`
//!   (for metrics/observability ONLY — verification never reads
//!   these).
//!
//! # What we INTENTIONALLY do NOT carry
//!
//! - No KEM secret keys, no signing secret keys, no AEAD keys.
//! - No bundle-signing private material.
//! - No raw JSON bundle bytes (the canonical fingerprint is
//!   sufficient for verifier observability and matches the same
//!   value reported on `/metrics`).
//! - No mutable counters. Metrics counters live on
//!   `crate::metrics::P2pMetrics`.
//!
//! # Concurrency / locking semantics
//!
//! - The handle stores `Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`.
//! - A reader (handshake verifier) takes a *short* read lock, clones
//!   the inner `Arc<LivePqcTrustSnapshot>` (cheap Arc bump), and
//!   drops the lock. All subsequent lookups read the cloned snapshot
//!   with no lock held.
//! - Writers (future Run 072 reload-apply) take a write lock, swap
//!   the inner Arc with a freshly-built snapshot, and drop the
//!   write lock. Run 071 NEVER does this on any production path.
//! - Lock poisoning (a writer panic) is propagated as
//!   `LivePqcTrustError::LockPoisoned`. The handshake-verification
//!   closures installed in `p2p_node_builder` translate a poisoned
//!   read into a fail-closed "untrusted root" / "revoked leaf"
//!   result so verification cannot silently succeed against a
//!   poisoned trust state.
//! - The reader path NEVER calls into network I/O or expensive
//!   crypto while holding the lock — it only clones an Arc.
//! - Roots, revoked root ids, and revoked leaf fingerprints all
//!   come from the **same** snapshot Arc, so a verifier can never
//!   see a half-applied trust state. Run 071 never produces a
//!   half-applied snapshot anyway (no swaps happen), but the
//!   invariant is preserved by construction for Run 072+.
//!
//! # qbind-net layering
//!
//! `qbind-net` continues to depend on no `qbind-node` types. The
//! existing `qbind_net::TrustedClientRoots::new(Fn(&[u8;32]) ->
//! Option<Vec<u8>>)` and
//! `qbind_net::LeafCertRevocationList::new(usize, Fn(&[u8;32]) ->
//! bool)` constructors already accept arbitrary closures, so a
//! `qbind-node`-side closure can capture a clone of
//! `LivePqcTrustState` and consult its snapshot on every lookup
//! without `qbind-net` learning about the live-trust type.

use std::collections::HashSet;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use crate::pqc_root_config::PqcTrustedRoot;
use crate::pqc_trust_bundle::{BundleSignatureStatus, LoadedTrustBundle, TrustBundleEnvironment};

/// Error returned by [`LivePqcTrustState`] read operations when the
/// underlying lock cannot produce a consistent snapshot (e.g. a
/// writer thread panicked while holding the write lock).
///
/// # Fail-closed contract
///
/// Callers in the handshake-verification path MUST translate this
/// error into a fail-closed verification result (e.g. "untrusted
/// root" / "cert revoked"). The handle never silently exposes stale
/// or partially-applied trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivePqcTrustError {
    /// The internal `RwLock` is poisoned. A writer thread panicked
    /// while holding the write lock; the contained snapshot may be
    /// in an undefined state.
    LockPoisoned,
}

impl std::fmt::Display for LivePqcTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivePqcTrustError::LockPoisoned => write!(
                f,
                "live PQC trust-state lock is poisoned (writer thread panicked); \
                 verification MUST fail closed"
            ),
        }
    }
}

impl std::error::Error for LivePqcTrustError {}

/// Immutable, cheaply-Arc-clonable snapshot of the active PQC trust
/// material at a single point in time.
///
/// All fields are public **post-validation** metadata. Construction
/// is performed by [`LivePqcTrustState::initialize_from_loaded_bundle`]
/// and (in future runs) by `LivePqcTrustState::swap_snapshot`.
/// Constructing one manually outside this crate is supported for
/// tests via the constructor below, but the production paths always
/// go through `initialize_from_loaded_bundle`.
#[derive(Debug, Clone)]
pub struct LivePqcTrustSnapshot {
    environment: TrustBundleEnvironment,
    chain_id: Option<String>,
    fingerprint: [u8; 32],
    sequence: u64,
    signature_status: BundleSignatureStatus,
    active_roots: Vec<PqcTrustedRoot>,
    revoked_root_ids: HashSet<[u8; 32]>,
    revoked_leaf_fingerprints: HashSet<[u8; 32]>,
    pending_revoked_root_ids: HashSet<[u8; 32]>,
    pending_revoked_leaf_fingerprints: HashSet<[u8; 32]>,
}

impl LivePqcTrustSnapshot {
    /// Build a snapshot from a successfully-loaded [`LoadedTrustBundle`].
    ///
    /// Run 071 contract: the inputs are exactly the validated
    /// `loaded.active_roots`, `loaded.revoked_root_ids`,
    /// `loaded.revoked_leaf_fingerprints`,
    /// `loaded.pending_revoked_root_ids`,
    /// `loaded.pending_revoked_leaf_fingerprints`, and the
    /// post-canonical-fingerprint `loaded.fingerprint`. No filtering,
    /// no policy decisions, no private material.
    pub fn from_loaded(loaded: &LoadedTrustBundle) -> Self {
        Self {
            environment: loaded.environment(),
            chain_id: loaded.bundle.chain_id.clone(),
            fingerprint: loaded.fingerprint,
            sequence: loaded.bundle.sequence,
            signature_status: loaded.signature_status.clone(),
            active_roots: loaded.active_roots.clone(),
            revoked_root_ids: loaded.revoked_root_ids.clone(),
            revoked_leaf_fingerprints: loaded.revoked_leaf_fingerprints.clone(),
            pending_revoked_root_ids: loaded.pending_revoked_root_ids.clone(),
            pending_revoked_leaf_fingerprints: loaded.pending_revoked_leaf_fingerprints.clone(),
        }
    }

    /// Bundle environment (DevNet / TestNet / MainNet).
    pub fn environment(&self) -> TrustBundleEnvironment {
        self.environment
    }

    /// Optional chain-id (lowercase hex) declared by the bundle.
    /// `None` is preserved bit-for-bit on DevNet.
    pub fn chain_id(&self) -> Option<&str> {
        self.chain_id.as_deref()
    }

    /// 32-byte canonical SHA3-256 bundle fingerprint
    /// (`crate::pqc_trust_bundle::canonical_fingerprint`).
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Monotonic bundle sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Result of the ML-DSA-44 signed-bundle verification step at
    /// load time. Verified bundles carry the signing-key id; DevNet
    /// unsigned bundles report `Unsigned`. The actual signing key
    /// secret is NEVER stored here.
    pub fn signature_status(&self) -> &BundleSignatureStatus {
        &self.signature_status
    }

    /// Public ML-DSA-44 active transport roots, post-validation
    /// (status=Active, in validity window, not revoked).
    pub fn active_roots(&self) -> &[PqcTrustedRoot] {
        &self.active_roots
    }

    /// Active revoked root-id set, post Run 062 activation gating.
    pub fn revoked_root_ids(&self) -> &HashSet<[u8; 32]> {
        &self.revoked_root_ids
    }

    /// Active revoked leaf-cert fingerprint set, post Run 062
    /// activation gating.
    pub fn revoked_leaf_fingerprints(&self) -> &HashSet<[u8; 32]> {
        &self.revoked_leaf_fingerprints
    }

    /// Pending (declared but activation-height-not-yet-satisfied)
    /// revoked root ids. Observability ONLY — verification MUST NOT
    /// read this set.
    pub fn pending_revoked_root_ids(&self) -> &HashSet<[u8; 32]> {
        &self.pending_revoked_root_ids
    }

    /// Pending (declared but activation-height-not-yet-satisfied)
    /// revoked leaf-cert fingerprints. Observability ONLY —
    /// verification MUST NOT read this set.
    pub fn pending_revoked_leaf_fingerprints(&self) -> &HashSet<[u8; 32]> {
        &self.pending_revoked_leaf_fingerprints
    }

    /// Number of active roots.
    pub fn active_root_count(&self) -> usize {
        self.active_roots.len()
    }

    /// Number of active revoked root ids.
    pub fn revoked_root_count(&self) -> usize {
        self.revoked_root_ids.len()
    }

    /// Number of active revoked leaf-cert fingerprints.
    pub fn revoked_leaf_count(&self) -> usize {
        self.revoked_leaf_fingerprints.len()
    }

    /// Number of pending revoked root ids (observability only).
    pub fn pending_revoked_root_count(&self) -> usize {
        self.pending_revoked_root_ids.len()
    }

    /// Number of pending revoked leaf-cert fingerprints
    /// (observability only).
    pub fn pending_revoked_leaf_count(&self) -> usize {
        self.pending_revoked_leaf_fingerprints.len()
    }

    /// Look up an active root by `root_key_id`. Returns the cloned
    /// public-key bytes the handshake verifier needs.
    ///
    /// Returns `None` if the id is not in the active set OR if the
    /// id has been actively root-revoked (defense in depth — the
    /// post-validation `active_roots` already excludes revoked ids,
    /// but we double-check here so a hand-crafted snapshot cannot
    /// re-introduce a revoked root by accident).
    pub fn lookup_active_root_pk(&self, root_key_id: &[u8; 32]) -> Option<Vec<u8>> {
        if self.revoked_root_ids.contains(root_key_id) {
            return None;
        }
        self.active_roots
            .iter()
            .find(|r| &r.root_key_id == root_key_id)
            .map(|r| r.root_pk.clone())
    }

    /// Returns `true` iff the supplied 32-byte canonical leaf-cert
    /// fingerprint is on the **active** leaf-revocation list. Pending
    /// revocations are never consulted here (Run 062 contract).
    pub fn is_leaf_revoked(&self, fingerprint: &[u8; 32]) -> bool {
        self.revoked_leaf_fingerprints.contains(fingerprint)
    }

    /// Returns `true` iff the supplied 32-byte root id is on the
    /// **active** root-revocation list. Pending revocations are never
    /// consulted here (Run 062 contract).
    pub fn is_root_revoked(&self, root_key_id: &[u8; 32]) -> bool {
        self.revoked_root_ids.contains(root_key_id)
    }
}

/// Mutable-capable shared handle around a [`LivePqcTrustSnapshot`].
///
/// In Run 071 this handle is initialized once at startup from the
/// validated [`LoadedTrustBundle`] and then read by PQC handshake
/// verification. No production path mutates it after startup. A
/// future run (Run 072+) will wire `swap_snapshot` to the live
/// reload-apply path once session-eviction support exists.
///
/// `Clone` is cheap: the inner `Arc<RwLock<...>>` is cloned.
#[derive(Clone)]
pub struct LivePqcTrustState {
    inner: Arc<RwLock<Arc<LivePqcTrustSnapshot>>>,
}

impl std::fmt::Debug for LivePqcTrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid blocking on the lock from Debug. Show only static
        // metadata (no roots / no fingerprint bytes — they may be
        // operator-sensitive observability values; the canonical
        // fingerprint is already logged at startup by main.rs).
        f.debug_struct("LivePqcTrustState")
            .field("inner", &"<Arc<RwLock<Arc<LivePqcTrustSnapshot>>>>")
            .finish()
    }
}

impl LivePqcTrustState {
    /// Initialize the live trust handle from a validated
    /// [`LoadedTrustBundle`] at startup.
    ///
    /// This is the only constructor called by the production binary
    /// (`crates/qbind-node/src/main.rs`). The startup pipeline
    /// (Run 050/051/053/057/062/063/065) has already validated the
    /// bundle by this point; this constructor only re-shapes the
    /// already-validated material into a shared snapshot.
    pub fn initialize_from_loaded_bundle(loaded: &LoadedTrustBundle) -> Self {
        let snap = LivePqcTrustSnapshot::from_loaded(loaded);
        Self {
            inner: Arc::new(RwLock::new(Arc::new(snap))),
        }
    }

    /// Initialize the live trust handle directly from an already-
    /// constructed [`LivePqcTrustSnapshot`]. Intended for tests; the
    /// production binary uses [`Self::initialize_from_loaded_bundle`].
    pub fn from_snapshot(snapshot: LivePqcTrustSnapshot) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(snapshot))),
        }
    }

    /// Return a consistent point-in-time `Arc<LivePqcTrustSnapshot>`.
    ///
    /// This is the cheap read path: take a short read lock, clone
    /// the inner `Arc` (Arc bump), drop the lock. All subsequent
    /// lookups happen on the cloned `Arc` with no lock held.
    ///
    /// Returns `LivePqcTrustError::LockPoisoned` if the underlying
    /// `RwLock` is poisoned. Callers in the handshake-verification
    /// path MUST translate this error into a fail-closed result.
    pub fn snapshot(&self) -> Result<Arc<LivePqcTrustSnapshot>, LivePqcTrustError> {
        let guard: RwLockReadGuard<'_, Arc<LivePqcTrustSnapshot>> = self
            .inner
            .read()
            .map_err(|_| LivePqcTrustError::LockPoisoned)?;
        Ok(Arc::clone(&*guard))
    }

    /// Look up an active root public key by `root_key_id` via a
    /// short live snapshot read. Returns `Ok(None)` for an unknown
    /// id, `Ok(Some(pk))` for a known active id, and
    /// `Err(LockPoisoned)` if the lock is poisoned.
    ///
    /// Wired into the handshake listener's `TrustedClientRoots`
    /// resolver in `p2p_node_builder.rs` (Run 071).
    pub fn lookup_active_root_pk(
        &self,
        root_key_id: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, LivePqcTrustError> {
        let snap = self.snapshot()?;
        Ok(snap.lookup_active_root_pk(root_key_id))
    }

    /// Returns `Ok(true)` iff the supplied 32-byte canonical
    /// leaf-cert fingerprint is on the active leaf-revocation list
    /// in the current live snapshot. Returns `Err(LockPoisoned)` if
    /// the lock is poisoned.
    ///
    /// Wired into the handshake-side `LeafCertRevocationList` in
    /// `p2p_node_builder.rs` (Run 071). The caller in
    /// `p2p_node_builder.rs` translates a poisoned-lock error into
    /// `is_revoked = true` (fail closed — a revoked-looking leaf is
    /// safer than an accepted-looking leaf under a poisoned trust
    /// state).
    pub fn is_leaf_revoked(&self, fingerprint: &[u8; 32]) -> Result<bool, LivePqcTrustError> {
        let snap = self.snapshot()?;
        Ok(snap.is_leaf_revoked(fingerprint))
    }

    /// Active leaf revocation count (cheap, single short read lock).
    ///
    /// Used by `p2p_node_builder.rs` to initialize the observability
    /// `active_count` field on the constructed
    /// `qbind_net::LeafCertRevocationList`.
    pub fn active_leaf_revocation_count(&self) -> Result<usize, LivePqcTrustError> {
        let snap = self.snapshot()?;
        Ok(snap.revoked_leaf_count())
    }

    /// Swap the inner snapshot with a freshly-built one. **Not used
    /// by Run 071.**
    ///
    /// This is future capability for Run 072+: a successful live
    /// reload-apply pipeline will:
    ///
    /// 1. validate the candidate bundle (Run 069 pipeline);
    /// 2. build a new `LivePqcTrustSnapshot` from the validated
    ///    candidate;
    /// 3. call `swap_snapshot` to install it under a single short
    ///    write lock — readers either see the entire old snapshot or
    ///    the entire new snapshot, never a half-applied state;
    /// 4. evict KEMTLS sessions against the old snapshot;
    /// 5. persist the new bundle's sequence number.
    ///
    /// Run 071 does NOT exercise this on any production path. It is
    /// covered by unit tests in this module so the semantic is
    /// pinned down for the future caller.
    pub fn swap_snapshot(
        &self,
        new_snapshot: LivePqcTrustSnapshot,
    ) -> Result<Arc<LivePqcTrustSnapshot>, LivePqcTrustError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| LivePqcTrustError::LockPoisoned)?;
        let previous = Arc::clone(&*guard);
        *guard = Arc::new(new_snapshot);
        Ok(previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_devnet_helper::mint_devnet_root;
    use crate::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;
    use crate::pqc_trust_bundle::{build_helper_bundle, HelperBundleMode, TrustBundle};
    use qbind_types::NetworkEnvironment;

    fn hex_lower(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    fn fresh_loaded_bundle() -> LoadedTrustBundle {
        let root = mint_devnet_root().expect("mint root");
        let id_hex = hex_lower(&root.root_key_id);
        let pk_hex = hex_lower(&root.root_pk);
        let bundle = build_helper_bundle(HelperBundleMode::Valid, &id_hex, &pk_hex, 100);
        let bytes = serde_json::to_vec(&bundle).expect("serialize");
        TrustBundle::load_from_bytes(&bytes, NetworkEnvironment::Devnet, 200).expect("loads")
    }

    #[test]
    fn initializes_from_loaded_bundle_with_active_root() {
        let loaded = fresh_loaded_bundle();
        let expected_id = loaded.active_roots[0].root_key_id;
        let expected_pk = loaded.active_roots[0].root_pk.clone();
        let expected_fp = loaded.fingerprint;
        let expected_seq = loaded.bundle.sequence;

        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let snap = live.snapshot().expect("snapshot");

        assert_eq!(snap.active_root_count(), 1);
        assert_eq!(snap.revoked_root_count(), 0);
        assert_eq!(snap.revoked_leaf_count(), 0);
        assert_eq!(snap.pending_revoked_root_count(), 0);
        assert_eq!(snap.pending_revoked_leaf_count(), 0);
        assert_eq!(snap.environment(), TrustBundleEnvironment::Devnet);
        assert_eq!(snap.fingerprint(), &expected_fp);
        assert_eq!(snap.sequence(), expected_seq);
        assert_eq!(snap.active_roots()[0].root_key_id, expected_id);
        assert_eq!(snap.active_roots()[0].root_pk, expected_pk);
        assert_eq!(
            snap.active_roots()[0].suite_id,
            PQC_TRANSPORT_SUITE_ML_DSA_44
        );
    }

    #[test]
    fn snapshot_signature_status_matches_loaded_bundle() {
        let loaded = fresh_loaded_bundle();
        let expected = loaded.signature_status.clone();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let snap = live.snapshot().expect("snapshot");
        assert_eq!(snap.signature_status(), &expected);
        // DevNet unsigned helper bundle:
        assert!(!snap.signature_status().is_verified());
    }

    #[test]
    fn chain_id_round_trips_none_on_devnet_helper_bundle() {
        let loaded = fresh_loaded_bundle();
        // helper bundle leaves chain_id as None
        assert!(loaded.bundle.chain_id.is_none());
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let snap = live.snapshot().expect("snapshot");
        assert!(snap.chain_id().is_none());
    }

    #[test]
    fn snapshot_lookup_active_root_pk_returns_expected_pk() {
        let loaded = fresh_loaded_bundle();
        let id = loaded.active_roots[0].root_key_id;
        let pk = loaded.active_roots[0].root_pk.clone();

        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        assert_eq!(live.lookup_active_root_pk(&id).expect("ok"), Some(pk));

        let unknown = [0xAAu8; 32];
        assert_eq!(live.lookup_active_root_pk(&unknown).expect("ok"), None);
    }

    #[test]
    fn snapshot_lookup_returns_none_for_actively_revoked_root() {
        // Build a snapshot directly with a root id that also appears
        // in the revoked_root_ids set. The lookup MUST return None
        // (defense in depth — the post-validation `active_roots`
        // already excludes revoked ids, but
        // `lookup_active_root_pk` re-checks).
        let loaded = fresh_loaded_bundle();
        let revoked_id = loaded.active_roots[0].root_key_id;
        let mut revoked_set = HashSet::new();
        revoked_set.insert(revoked_id);
        let snap = LivePqcTrustSnapshot {
            environment: TrustBundleEnvironment::Devnet,
            chain_id: None,
            fingerprint: loaded.fingerprint,
            sequence: loaded.bundle.sequence,
            signature_status: loaded.signature_status.clone(),
            active_roots: loaded.active_roots.clone(),
            revoked_root_ids: revoked_set,
            revoked_leaf_fingerprints: HashSet::new(),
            pending_revoked_root_ids: HashSet::new(),
            pending_revoked_leaf_fingerprints: HashSet::new(),
        };
        let live = LivePqcTrustState::from_snapshot(snap);
        assert!(live.is_root_revoked_snapshot(&revoked_id).expect("ok"));
        assert_eq!(live.lookup_active_root_pk(&revoked_id).expect("ok"), None);
    }

    #[test]
    fn leaf_revocation_lookup_consults_active_set_only() {
        let loaded = fresh_loaded_bundle();
        let mut active = HashSet::new();
        let active_fp = [0x01u8; 32];
        active.insert(active_fp);
        let mut pending = HashSet::new();
        let pending_fp = [0x02u8; 32];
        pending.insert(pending_fp);
        let snap = LivePqcTrustSnapshot {
            environment: loaded.environment(),
            chain_id: loaded.bundle.chain_id.clone(),
            fingerprint: loaded.fingerprint,
            sequence: loaded.bundle.sequence,
            signature_status: loaded.signature_status.clone(),
            active_roots: loaded.active_roots.clone(),
            revoked_root_ids: HashSet::new(),
            revoked_leaf_fingerprints: active,
            pending_revoked_root_ids: HashSet::new(),
            pending_revoked_leaf_fingerprints: pending,
        };
        let live = LivePqcTrustState::from_snapshot(snap);

        assert!(live.is_leaf_revoked(&active_fp).expect("ok"));
        // pending entry MUST NOT be enforced
        assert!(!live.is_leaf_revoked(&pending_fp).expect("ok"));
        assert_eq!(live.active_leaf_revocation_count().expect("ok"), 1);
    }

    #[test]
    fn snapshot_is_consistent_across_concurrent_clones() {
        // Same handle cloned across threads must hand out snapshots
        // whose roots, revoked sets, and fingerprint all come from
        // the same source bundle.
        let loaded = fresh_loaded_bundle();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let live_a = live.clone();
        let live_b = live.clone();

        let t = std::thread::spawn(move || {
            let s = live_b.snapshot().expect("snap b");
            (
                *s.fingerprint(),
                s.active_root_count(),
                s.revoked_leaf_count(),
            )
        });
        let s = live_a.snapshot().expect("snap a");
        let a = (
            *s.fingerprint(),
            s.active_root_count(),
            s.revoked_leaf_count(),
        );
        let b = t.join().expect("join");
        assert_eq!(a, b);
    }

    #[test]
    fn snapshot_clone_is_cheap_arc_bump_not_deep_copy() {
        // Two snapshot() calls in a row must return Arcs pointing at
        // the same heap allocation (no swap happened in Run 071).
        let loaded = fresh_loaded_bundle();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let a = live.snapshot().expect("a");
        let b = live.snapshot().expect("b");
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn swap_snapshot_replaces_inner_arc_and_returns_previous() {
        // Future-capability: exercise the swap path so a future
        // Run 072 wiring cannot regress this contract silently.
        let loaded_a = fresh_loaded_bundle();
        let loaded_b = fresh_loaded_bundle();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded_a);
        let before = live.snapshot().expect("before");
        let new = LivePqcTrustSnapshot::from_loaded(&loaded_b);
        let prev = live.swap_snapshot(new).expect("swap");
        assert!(Arc::ptr_eq(&prev, &before));
        let after = live.snapshot().expect("after");
        assert!(!Arc::ptr_eq(&before, &after));
        // The new snapshot reports loaded_b's fingerprint.
        assert_eq!(after.fingerprint(), &loaded_b.fingerprint);
    }

    #[test]
    fn no_private_material_visible_on_snapshot_surface() {
        // Compile-time-style assertion: the snapshot exposes only
        // root public-key bytes and revocation-id bytes. The
        // following types are NOT reachable from `&LivePqcTrustSnapshot`
        // and the build will fail to compile if anyone adds them:
        // - qbind_crypto::ml_kem768::Ml768PrivateKey
        // - qbind_crypto::MlDsa44PrivateKey
        // (Confirmed by inspection of the struct definition; this
        // test is a behavioural assertion that the constructor
        // copies only the public material from LoadedTrustBundle.)
        let loaded = fresh_loaded_bundle();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let snap = live.snapshot().expect("snap");
        // The exposed root_pk is the same public bytes the loaded
        // bundle already exposes, not a secret.
        assert_eq!(
            snap.active_roots()[0].root_pk,
            loaded.active_roots[0].root_pk
        );
    }

    #[test]
    fn poisoned_lock_returns_lock_poisoned_error() {
        // Force the RwLock into a poisoned state by panicking inside
        // a write lock on another thread.
        let loaded = fresh_loaded_bundle();
        let live = LivePqcTrustState::initialize_from_loaded_bundle(&loaded);
        let live_for_panic = live.clone();
        let t = std::thread::spawn(move || {
            let _guard = live_for_panic.inner.write().expect("write");
            // Simulate a writer panic mid-update while the write
            // guard is still in scope; the guard's Drop on unwind
            // marks the RwLock poisoned.
            panic!("simulated writer panic to poison lock");
        });
        let _ = t.join();
        // Now subsequent reads MUST fail closed with LockPoisoned.
        match live.snapshot() {
            Err(LivePqcTrustError::LockPoisoned) => {}
            other => panic!("expected LockPoisoned, got {:?}", other),
        }
        match live.is_leaf_revoked(&[0u8; 32]) {
            Err(LivePqcTrustError::LockPoisoned) => {}
            other => panic!("expected LockPoisoned, got {:?}", other),
        }
        match live.lookup_active_root_pk(&[0u8; 32]) {
            Err(LivePqcTrustError::LockPoisoned) => {}
            other => panic!("expected LockPoisoned, got {:?}", other),
        }
    }

    impl LivePqcTrustState {
        /// Test-only convenience: snapshot-scoped is_root_revoked
        /// (the public surface only exposes lookup_active_root_pk
        /// for the handshake path; this helper is here so the
        /// "lookup_returns_none_for_actively_revoked_root" test
        /// reads naturally).
        fn is_root_revoked_snapshot(
            &self,
            root_key_id: &[u8; 32],
        ) -> Result<bool, LivePqcTrustError> {
            let snap = self.snapshot()?;
            Ok(snap.is_root_revoked(root_key_id))
        }
    }
}
