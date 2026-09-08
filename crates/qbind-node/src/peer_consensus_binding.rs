//! Run 418 — Authenticated KEMTLS peer → consensus sender binding (F6).
//!
//! This module closes the F6 defect: the deployed consensus ingress path
//! derived the message sender from the *self-declared*
//! `BlockProposal::header.proposer_index` / `Vote::validator_index` fields,
//! so an authenticated peer could impersonate any validator index it liked.
//!
//! The fix introduces an **in-process, non-wire** authenticated-origin type
//! ([`AuthenticatedConsensusOrigin`]) that carries the full 32-byte
//! authenticated `NodeId` and the authenticated `ValidatorId` established by
//! the successful KEMTLS secure session — never from the consensus payload.
//! A validated one-to-one [`PeerConsensusBindingMap`] and the
//! [`PeerConsensusBindingGate`] enforce, at consensus ingress, that the
//! validator a message *claims* to come from matches the validator the
//! transport *authenticated*.
//!
//! Scope discipline (see `task/RUN_418_TASK.txt`):
//! * This is transport-session-to-consensus-sender binding / accountability
//!   only. It does **not** make consensus signatures meaningful (F3/F4/F5),
//!   and must not be represented as fixing F3, F4, F5, F7, F8, RS1, C4 or C5.
//! * The origin is deliberately **not** `Serialize`/`Deserialize` — it is
//!   never placed on the wire and a peer can never self-assert or overwrite
//!   it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use qbind_consensus::ids::ValidatorId;

use crate::p2p::NodeId;

/// In-process, non-wire authenticated origin of an inbound consensus frame.
///
/// Both fields come exclusively from the successfully authenticated KEMTLS
/// secure session (the verified client certificate on inbound sessions, or
/// the verified server certificate on outbound sessions). Neither field is
/// ever derived from, or overwritten by, the consensus payload.
///
/// This type intentionally does **not** derive `serde::Serialize` /
/// `serde::Deserialize`: it is a purely in-process value and must never be
/// serialized onto the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedConsensusOrigin {
    /// The full 32-byte authenticated peer `NodeId` (cert-derived on the
    /// production `MutualAuthMode::Required` + `pqc-static-root` path).
    node_id: NodeId,
    /// The authenticated peer `ValidatorId` established by the same session.
    validator_id: ValidatorId,
}

impl AuthenticatedConsensusOrigin {
    /// Construct an authenticated origin from a verified session identity.
    ///
    /// Callers must only build this from a *successfully authenticated*
    /// secure session — never from self-asserted `client_random`,
    /// self-asserted `ClientInit.validator_id`, or any consensus payload
    /// field.
    pub fn new(node_id: NodeId, validator_id: ValidatorId) -> Self {
        Self {
            node_id,
            validator_id,
        }
    }

    /// The full 32-byte authenticated peer `NodeId`.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The authenticated peer `ValidatorId`.
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// A short, public 8-hex-char prefix of the authenticated `NodeId`, safe
    /// for bounded diagnostic logging. Never exposes keys, certificates,
    /// secrets, or paths.
    pub fn node_id_prefix(&self) -> String {
        let b = self.node_id.as_bytes();
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3]
        )
    }
}

/// Typed, bounded, non-secret errors returned while building a
/// [`PeerConsensusBindingMap`]. Diagnostic wording never contains full
/// `NodeId`s, validator strings, certificate bytes, keys, or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerBindingMapError {
    /// The same `ValidatorId` was supplied more than once.
    DuplicateValidator,
    /// The same `NodeId` was supplied more than once (potentially assigned
    /// to different validators).
    DuplicateNodeId,
    /// An insertion would silently overwrite an existing, conflicting
    /// mapping (one NodeId already bound to a different validator, or one
    /// validator already bound to a different NodeId).
    ConflictingMapping,
    /// A validator identity was malformed or out of range.
    MalformedValidator,
}

impl std::fmt::Display for PeerBindingMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PeerBindingMapError::DuplicateValidator => "duplicate validator entry",
            PeerBindingMapError::DuplicateNodeId => "duplicate node id entry",
            PeerBindingMapError::ConflictingMapping => "conflicting node/validator mapping",
            PeerBindingMapError::MalformedValidator => "malformed or out-of-range validator",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PeerBindingMapError {}

/// A validated one-to-one mapping between authenticated full 32-byte
/// `NodeId`s and `ValidatorId`s for a single node's configuration.
///
/// Invariants (all enforced at build time, fail-closed):
/// * one full `NodeId` maps to exactly one `ValidatorId`;
/// * one `ValidatorId` maps to exactly one authorized `NodeId`;
/// * duplicate validator entries fail;
/// * duplicate `NodeId`s assigned to different validators fail;
/// * no insertion may silently overwrite an existing conflicting mapping.
///
/// The mapping keys on the **complete 32-byte `NodeId`** — it never uses the
/// legacy first-eight-byte `NodeId → PeerId(u64)` truncation as a security
/// decision.
#[derive(Clone, Debug, Default)]
pub struct PeerConsensusBindingMap {
    node_to_validator: HashMap<NodeId, ValidatorId>,
    validator_to_node: HashMap<ValidatorId, NodeId>,
}

impl PeerConsensusBindingMap {
    /// Build a validated one-to-one mapping from `(NodeId, ValidatorId)`
    /// entries, rejecting any duplicate or conflicting insertion.
    pub fn build(
        entries: impl IntoIterator<Item = (NodeId, ValidatorId)>,
    ) -> Result<Self, PeerBindingMapError> {
        let mut map = PeerConsensusBindingMap::default();
        for (node_id, validator_id) in entries {
            map.insert(node_id, validator_id)?;
        }
        Ok(map)
    }

    /// Insert a single `(NodeId, ValidatorId)` binding, fail-closed on any
    /// duplicate or conflict. Never silently overwrites.
    pub fn insert(
        &mut self,
        node_id: NodeId,
        validator_id: ValidatorId,
    ) -> Result<(), PeerBindingMapError> {
        match (
            self.node_to_validator.get(&node_id),
            self.validator_to_node.get(&validator_id),
        ) {
            // Exact identical binding already present: a duplicate entry.
            (Some(existing_vid), Some(existing_nid))
                if *existing_vid == validator_id && *existing_nid == node_id =>
            {
                // Distinguish duplicate-validator from duplicate-nodeid for
                // clearer, still-bounded diagnostics.
                return Err(PeerBindingMapError::DuplicateValidator);
            }
            // NodeId already bound to a different validator.
            (Some(existing_vid), _) if *existing_vid != validator_id => {
                return Err(PeerBindingMapError::DuplicateNodeId);
            }
            // Validator already bound to a different NodeId.
            (_, Some(existing_nid)) if *existing_nid != node_id => {
                return Err(PeerBindingMapError::ConflictingMapping);
            }
            _ => {}
        }
        self.node_to_validator.insert(node_id, validator_id);
        self.validator_to_node.insert(validator_id, node_id);
        Ok(())
    }

    /// Look up the authorized `ValidatorId` for a full 32-byte `NodeId`.
    pub fn validator_for_node(&self, node_id: &NodeId) -> Option<ValidatorId> {
        self.node_to_validator.get(node_id).copied()
    }

    /// Look up the authorized `NodeId` for a `ValidatorId`.
    pub fn node_for_validator(&self, validator_id: &ValidatorId) -> Option<NodeId> {
        self.validator_to_node.get(validator_id).copied()
    }

    /// Number of one-to-one bindings.
    pub fn len(&self) -> usize {
        self.node_to_validator.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.node_to_validator.is_empty()
    }
}

/// The fixed, low-cardinality reasons a consensus binding decision can
/// resolve to. Each maps to exactly one bounded metric label; none carries a
/// high-cardinality or private value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusBindingReject {
    /// No authenticated origin accompanied the frame (fail-closed).
    MissingOrigin,
    /// The authenticated peer `NodeId` is not in the authorized mapping.
    UnknownPeer,
    /// The claimed sender validator is not a known/authorized validator.
    UnknownValidator,
    /// The claimed sender validator does not match the authenticated one.
    ClaimedSenderMismatch,
    /// The authenticated peer's `NodeId`/`ValidatorId` disagree with the
    /// configured one-to-one mapping (ambiguous / conflicting).
    AmbiguousMapping,
}

impl ConsensusBindingReject {
    /// The fixed metric label for this reject reason.
    pub fn metric_label(&self) -> &'static str {
        match self {
            ConsensusBindingReject::MissingOrigin => "missing_origin",
            ConsensusBindingReject::UnknownPeer => "unknown_peer",
            ConsensusBindingReject::UnknownValidator => "unknown_validator",
            ConsensusBindingReject::ClaimedSenderMismatch => "claimed_sender_mismatch",
            ConsensusBindingReject::AmbiguousMapping => "ambiguous_mapping",
        }
    }
}

impl std::fmt::Display for ConsensusBindingReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.metric_label())
    }
}

impl std::error::Error for ConsensusBindingReject {}

/// Bounded metrics for the consensus binding gate. All counters use fixed
/// labels only; no IP address, full `NodeId`, validator string, certificate
/// byte, or other high-cardinality/private value is ever used as a label.
#[derive(Debug, Default)]
pub struct ConsensusBindingMetrics {
    accepted: AtomicU64,
    missing_origin: AtomicU64,
    unknown_peer: AtomicU64,
    unknown_validator: AtomicU64,
    claimed_sender_mismatch: AtomicU64,
    ambiguous_mapping: AtomicU64,
}

impl ConsensusBindingMetrics {
    /// A fresh metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    fn record_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    fn record_reject(&self, reason: ConsensusBindingReject) {
        let c = match reason {
            ConsensusBindingReject::MissingOrigin => &self.missing_origin,
            ConsensusBindingReject::UnknownPeer => &self.unknown_peer,
            ConsensusBindingReject::UnknownValidator => &self.unknown_validator,
            ConsensusBindingReject::ClaimedSenderMismatch => &self.claimed_sender_mismatch,
            ConsensusBindingReject::AmbiguousMapping => &self.ambiguous_mapping,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Accepted-binding count.
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Count for a specific reject reason.
    pub fn reject_count(&self, reason: ConsensusBindingReject) -> u64 {
        let c = match reason {
            ConsensusBindingReject::MissingOrigin => &self.missing_origin,
            ConsensusBindingReject::UnknownPeer => &self.unknown_peer,
            ConsensusBindingReject::UnknownValidator => &self.unknown_validator,
            ConsensusBindingReject::ClaimedSenderMismatch => &self.claimed_sender_mismatch,
            ConsensusBindingReject::AmbiguousMapping => &self.ambiguous_mapping,
        };
        c.load(Ordering::Relaxed)
    }

    /// Render the bounded Prometheus family for this gate. Fixed labels only.
    pub fn format_metrics(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP qbind_consensus_binding_total Authenticated peer→consensus sender binding decisions (Run 418, F6).\n",
        );
        out.push_str("# TYPE qbind_consensus_binding_total counter\n");
        out.push_str(&format!(
            "qbind_consensus_binding_total{{result=\"accepted\"}} {}\n",
            self.accepted()
        ));
        for reason in [
            ConsensusBindingReject::MissingOrigin,
            ConsensusBindingReject::UnknownPeer,
            ConsensusBindingReject::UnknownValidator,
            ConsensusBindingReject::ClaimedSenderMismatch,
            ConsensusBindingReject::AmbiguousMapping,
        ] {
            out.push_str(&format!(
                "qbind_consensus_binding_total{{result=\"{}\"}} {}\n",
                reason.metric_label(),
                self.reject_count(reason)
            ));
        }
        out
    }
}

/// The consensus binding gate: the authoritative decision point that binds an
/// authenticated transport origin to the validator a consensus message claims
/// to be from.
#[derive(Debug)]
pub struct PeerConsensusBindingGate {
    map: PeerConsensusBindingMap,
    metrics: std::sync::Arc<ConsensusBindingMetrics>,
}

impl PeerConsensusBindingGate {
    /// Build a gate from a validated mapping, minting a fresh metrics
    /// instance. Use [`PeerConsensusBindingGate::with_metrics`] to share a
    /// metrics handle with the `/metrics` scrape path.
    pub fn new(map: PeerConsensusBindingMap) -> Self {
        Self {
            map,
            metrics: std::sync::Arc::new(ConsensusBindingMetrics::new()),
        }
    }

    /// Build a gate from a validated mapping and a shared metrics handle so
    /// the bounded family is visible on the live `/metrics` endpoint.
    pub fn with_metrics(
        map: PeerConsensusBindingMap,
        metrics: std::sync::Arc<ConsensusBindingMetrics>,
    ) -> Self {
        Self { map, metrics }
    }

    /// Access the bounded metrics for scrape/export.
    pub fn metrics(&self) -> &ConsensusBindingMetrics {
        &self.metrics
    }

    /// The authoritative one-to-one mapping.
    pub fn map(&self) -> &PeerConsensusBindingMap {
        &self.map
    }

    /// Whether `(node_id, validator_id)` is a configured one-to-one binding.
    ///
    /// Used by the inbound transport origin resolver to only surface an
    /// authenticated origin the authoritative map recognizes; a verified but
    /// unconfigured leaf NodeId (e.g. an alternate root-valid certificate for
    /// the same validator) is not a member and yields `false`, so the ingress
    /// gate later fails closed with a precise reason.
    pub fn validate_pair(&self, node_id: &NodeId, validator_id: ValidatorId) -> bool {
        self.map.validator_for_node(node_id) == Some(validator_id)
            && self.map.node_for_validator(&validator_id) == Some(*node_id)
    }

    /// Authorize a consensus message.
    ///
    /// * `origin` — the authenticated transport origin (or `None` when the
    ///   session did not establish an authenticated identity).
    /// * `claimed_validator` — the sender the *decoded* consensus payload
    ///   claims to be from.
    ///
    /// On success returns the **authenticated** `ValidatorId` (never a newly
    /// trusted payload-derived value). On any failure returns a typed
    /// [`ConsensusBindingReject`]; the caller must not invoke the consensus
    /// engine or perform any consensus side effect on rejection.
    ///
    /// Every decision increments exactly one bounded metric.
    pub fn authorize(
        &self,
        origin: Option<&AuthenticatedConsensusOrigin>,
        claimed_validator: ValidatorId,
    ) -> Result<ValidatorId, ConsensusBindingReject> {
        // Fail-closed: an absent authenticated origin can never be accepted.
        let origin = match origin {
            Some(o) => o,
            None => {
                self.metrics
                    .record_reject(ConsensusBindingReject::MissingOrigin);
                return Err(ConsensusBindingReject::MissingOrigin);
            }
        };

        // The authenticated peer's full 32-byte NodeId must be authorized.
        let mapped_validator = match self.map.validator_for_node(&origin.node_id()) {
            Some(v) => v,
            None => {
                self.metrics
                    .record_reject(ConsensusBindingReject::UnknownPeer);
                return Err(ConsensusBindingReject::UnknownPeer);
            }
        };

        // The authenticated peer's NodeId and ValidatorId must agree with the
        // configured one-to-one mapping. An alternate root-valid certificate
        // for the same validator but with an unconfigured leaf NodeId, or any
        // other disagreement, is ambiguous/conflicting and fails closed.
        if mapped_validator != origin.validator_id() {
            self.metrics
                .record_reject(ConsensusBindingReject::AmbiguousMapping);
            return Err(ConsensusBindingReject::AmbiguousMapping);
        }

        // The claimed sender must be a known/authorized validator.
        if self.map.node_for_validator(&claimed_validator).is_none() {
            self.metrics
                .record_reject(ConsensusBindingReject::UnknownValidator);
            return Err(ConsensusBindingReject::UnknownValidator);
        }

        // The claimed sender must equal the authenticated validator.
        if claimed_validator != origin.validator_id() {
            self.metrics
                .record_reject(ConsensusBindingReject::ClaimedSenderMismatch);
            return Err(ConsensusBindingReject::ClaimedSenderMismatch);
        }

        self.metrics.record_accepted();
        Ok(origin.validator_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(first: u8) -> NodeId {
        let mut b = [0u8; 32];
        b[0] = first;
        b[31] = 0xAB;
        NodeId::new(b)
    }

    fn nid_full(bytes: [u8; 32]) -> NodeId {
        NodeId::new(bytes)
    }

    #[test]
    fn map_builds_one_to_one() {
        let map = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(2), ValidatorId::new(2)),
        ])
        .expect("valid map");
        assert_eq!(map.len(), 2);
        assert_eq!(map.validator_for_node(&nid(1)), Some(ValidatorId::new(1)));
        assert_eq!(map.node_for_validator(&ValidatorId::new(2)), Some(nid(2)));
    }

    #[test]
    fn duplicate_validator_fails() {
        let err = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(2), ValidatorId::new(1)),
        ])
        .unwrap_err();
        assert_eq!(err, PeerBindingMapError::ConflictingMapping);
    }

    #[test]
    fn duplicate_nodeid_different_validator_fails() {
        let err = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(1), ValidatorId::new(2)),
        ])
        .unwrap_err();
        assert_eq!(err, PeerBindingMapError::DuplicateNodeId);
    }

    #[test]
    fn exact_duplicate_entry_fails() {
        let err = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(1), ValidatorId::new(1)),
        ])
        .unwrap_err();
        assert_eq!(err, PeerBindingMapError::DuplicateValidator);
    }

    #[test]
    fn gate_accepts_matching_origin_and_claim() {
        let map = PeerConsensusBindingMap::build([(nid(1), ValidatorId::new(1))]).unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        let origin = AuthenticatedConsensusOrigin::new(nid(1), ValidatorId::new(1));
        let got = gate.authorize(Some(&origin), ValidatorId::new(1));
        assert_eq!(got, Ok(ValidatorId::new(1)));
        assert_eq!(gate.metrics().accepted(), 1);
    }

    #[test]
    fn gate_rejects_claimed_sender_mismatch() {
        let map = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(2), ValidatorId::new(2)),
        ])
        .unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        // Peer B (validator 2) claims to be validator 1.
        let origin = AuthenticatedConsensusOrigin::new(nid(2), ValidatorId::new(2));
        let got = gate.authorize(Some(&origin), ValidatorId::new(1));
        assert_eq!(got, Err(ConsensusBindingReject::ClaimedSenderMismatch));
        assert_eq!(
            gate.metrics()
                .reject_count(ConsensusBindingReject::ClaimedSenderMismatch),
            1
        );
        assert_eq!(gate.metrics().accepted(), 0);
    }

    #[test]
    fn gate_fails_closed_on_missing_origin() {
        let map = PeerConsensusBindingMap::build([(nid(1), ValidatorId::new(1))]).unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        let got = gate.authorize(None, ValidatorId::new(1));
        assert_eq!(got, Err(ConsensusBindingReject::MissingOrigin));
        assert_eq!(
            gate.metrics()
                .reject_count(ConsensusBindingReject::MissingOrigin),
            1
        );
    }

    #[test]
    fn gate_rejects_unknown_peer() {
        let map = PeerConsensusBindingMap::build([(nid(1), ValidatorId::new(1))]).unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        let origin = AuthenticatedConsensusOrigin::new(nid(9), ValidatorId::new(9));
        let got = gate.authorize(Some(&origin), ValidatorId::new(1));
        assert_eq!(got, Err(ConsensusBindingReject::UnknownPeer));
    }

    #[test]
    fn gate_rejects_unknown_validator_claim() {
        let map = PeerConsensusBindingMap::build([(nid(1), ValidatorId::new(1))]).unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        let origin = AuthenticatedConsensusOrigin::new(nid(1), ValidatorId::new(1));
        // Claims validator 7 which is not in the map.
        let got = gate.authorize(Some(&origin), ValidatorId::new(7));
        assert_eq!(got, Err(ConsensusBindingReject::UnknownValidator));
    }

    #[test]
    fn gate_rejects_ambiguous_mapping() {
        // Authenticated NodeId maps to validator 1, but the origin carries a
        // conflicting validator 2 (e.g. an alternate cert for the same
        // validator with an unconfigured leaf NodeId).
        let map = PeerConsensusBindingMap::build([
            (nid(1), ValidatorId::new(1)),
            (nid(2), ValidatorId::new(2)),
        ])
        .unwrap();
        let gate = PeerConsensusBindingGate::new(map);
        let origin = AuthenticatedConsensusOrigin::new(nid(1), ValidatorId::new(2));
        let got = gate.authorize(Some(&origin), ValidatorId::new(2));
        assert_eq!(got, Err(ConsensusBindingReject::AmbiguousMapping));
    }

    #[test]
    fn full_32_byte_nodeids_compared_first_eight_collide() {
        // Two NodeIds whose first eight bytes are identical but which differ
        // in a later byte must be treated as distinct: the legacy
        // first-eight-byte truncation must NOT be the security decision.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        for i in 0..8 {
            a[i] = i as u8;
            b[i] = i as u8;
        }
        a[16] = 0x01;
        b[16] = 0x02;
        let map = PeerConsensusBindingMap::build([
            (nid_full(a), ValidatorId::new(1)),
            (nid_full(b), ValidatorId::new(2)),
        ])
        .expect("distinct full NodeIds must build");
        assert_eq!(map.len(), 2);
        let gate = PeerConsensusBindingGate::new(map);
        // Peer with full NodeId `b` (validator 2) claims validator 1.
        let origin = AuthenticatedConsensusOrigin::new(nid_full(b), ValidatorId::new(2));
        assert_eq!(
            gate.authorize(Some(&origin), ValidatorId::new(1)),
            Err(ConsensusBindingReject::ClaimedSenderMismatch)
        );
        // And the honest claim from `b` is accepted.
        assert_eq!(
            gate.authorize(Some(&origin), ValidatorId::new(2)),
            Ok(ValidatorId::new(2))
        );
    }

    #[test]
    fn metrics_labels_are_fixed_and_bounded() {
        let m = ConsensusBindingMetrics::new();
        m.record_accepted();
        m.record_reject(ConsensusBindingReject::ClaimedSenderMismatch);
        let rendered = m.format_metrics();
        assert!(rendered.contains("result=\"accepted\""));
        assert!(rendered.contains("result=\"claimed_sender_mismatch\""));
        // No high-cardinality label keys.
        assert!(!rendered.contains("node_id"));
        assert!(!rendered.contains("addr"));
        assert!(!rendered.contains("validator=\""));
    }
}