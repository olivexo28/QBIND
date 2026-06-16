//! Node-local block pipeline for the qbind post-quantum blockchain.
//!
//! This crate integrates:
//!  - qbind-wire (BlockProposal, Transaction, WireDecode)
//!  - qbind-consensus (ValidatorSet, HotStuffState, BlockVerifyConfig, hotstuff_decide_and_maybe_record_vote)
//!  - qbind-runtime (BlockExecutor, BlockExecutionResult)
//!  - qbind-ledger (AccountStore)
//!  - qbind-crypto (CryptoProvider)
//!
//! Given a BlockProposal, validator set, HotStuffState, CryptoProvider, AccountStore, and BlockExecutor:
//!  1. Verify the block under consensus rules (structural + HotStuff safety).
//!  2. Decode transactions from the proposal.
//!  3. Execute them sequentially using BlockExecutor.
//!  4. Return a structured outcome.
//!
//! # Async Runtime (T85)
//!
//! The `async_runner` module provides `AsyncNodeRunner`, a Tokio-driven async wrapper
//! around the synchronous consensus loop. This allows the node's "heart" to be an
//! async event loop driven by `tokio::time::interval`, while keeping the consensus
//! core synchronous and deterministic.
//!
//! # Async Consensus Network Worker (T87)
//!
//! The `consensus_net_worker` module provides `ConsensusNetWorker`, an async worker
//! that bridges the existing network stack to the `AsyncNodeRunner` via the
//! `ConsensusEventSender` channel. This establishes a clear separation:
//! - Network worker(s): async tasks managing sockets, KEMTLS, and producing events
//! - Runtime: `AsyncNodeRunner` consuming events and driving the harness
//! - Consensus core: synchronous HotStuff logic
//!
//! # Observability (T89)
//!
//! The `metrics` module provides lightweight atomic counter-based metrics for
//! monitoring the async node runtime and consensus networking layer:
//! - Inbound/outbound message counts by type
//! - Channel health (drops, backpressure)
//! - Runtime event processing rates
//! - spawn_blocking usage and latency buckets
//!
//! # Async Peer Manager (T90.1)
//!
//! The `async_peer_manager` module provides `AsyncPeerManager` trait and
//! `AsyncPeerManagerImpl`, a fully async implementation using Tokio networking
//! primitives. This is the new path for consensus networking that replaces the
//! blocking `PeerManager` + `spawn_blocking` bridge.
//!
//! Enable with the `async-peer-manager` feature flag:
//! - When enabled: uses `AsyncPeerManagerImpl` for fully async networking
//! - When disabled (legacy): uses the blocking `PeerManager` + `spawn_blocking` path
//!
//! The async peer manager is currently the default for development and testing,
//! while the legacy path exists as a fallback until parity is proven.
//!
//! # Channel Capacity Configuration (T90.2)
//!
//! The `channel_config` module provides `ChannelCapacityConfig` for tuning
//! async channel capacities via configuration or environment variables:
//! - `QBIND_CONSENSUS_EVENT_CHANNEL_CAPACITY`: ConsensusEvent channel
//! - `QBIND_OUTBOUND_COMMAND_CHANNEL_CAPACITY`: Outbound command channel
//! - `QBIND_ASYNC_PEER_INBOUND_CAPACITY`: AsyncPeerManager inbound channel
//! - `QBIND_ASYNC_PEER_OUTBOUND_CAPACITY`: AsyncPeerManager per-peer outbound
//!
//! No networking, no DAG, no signing or IO.
//!
//! # DAG Mempool (T158)
//!
//! The `dag_mempool` module provides the core data structures and implementation
//! for a DAG-based mempool. This is an alternative to the FIFO mempool that:
//! - Organizes transactions into signed batches
//! - Forms a DAG structure via parent references
//! - Provides deterministic frontier selection for proposals
//!
//! See `dag_mempool` module documentation for details.

pub mod async_peer_manager;
pub mod async_runner;
pub mod binary_consensus_loop;
pub mod block_store;
pub mod channel_config;
pub mod cli;
pub mod commit_index;
pub mod consensus_net;
pub mod consensus_net_p2p;
pub mod consensus_net_worker;
pub mod consensus_network_facade;
pub mod consensus_node;
pub mod consensus_sim;
pub mod dag_mempool;
pub mod evm_commit;
pub mod evm_state_store;
pub mod execution_adapter;
pub mod forged_injection;
pub mod hotstuff_node_sim;
pub mod identity_map;
pub mod keystore;
pub mod ledger_bridge;
pub mod load_harness;
pub mod mempool;
pub mod metrics;
pub mod metrics_http;
pub mod monetary_telemetry;
pub mod net_service;
pub mod node_config;
pub mod p2p;
pub mod p2p_inbound;
pub mod p2p_node_builder;
/// Run 072 — production-honest internal P2P session-eviction hook.
pub mod p2p_session_eviction;
pub mod p2p_tcp;
pub mod peer_key_provider;// Run 037 — production-honest PQC KEMTLS root-key distribution config.
pub mod pqc_root_config;
// Run 037 — DevNet-only helper to mint real ML-DSA-44-signed delegation certs.
pub mod pqc_devnet_helper;
// Run 102 — release-binary boot-time canonical genesis verification
// wiring. Loads the external GenesisConfig JSON (when configured),
// dispatches into Run 101's `verify_boot_time_genesis`, fails closed on
// MainNet missing/mismatched/malformed expected hash and missing/
// malformed authority. Also powers the canonical `--print-genesis-hash`
// operator surface. See `pqc_boot_genesis.rs` and
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md`.
pub mod pqc_boot_genesis;
// Run 105 — operator-supplied bundle-signing-key ratification sidecar
// JSON loader. Wraps `qbind_ledger::BundleSigningRatification` parsing
// with operator-friendly typed I/O / parse errors. Pure read-only,
// local-file-only loader; verification happens via
// `qbind_ledger::enforce_bundle_signing_key_ratification`.
pub mod pqc_ratification_input;
// Run 106 — per-environment ratification-gate invocation policy.
// Decides, for a given `NetworkEnvironment` and the operator
// `--p2p-trust-bundle-ratification-enforcement-enabled` flag, whether
// the Run 105 ratification gate must be invoked on a trust-bundle
// validation surface. MainNet/TestNet are strict-by-default; DevNet
// remains operator-opt-in to preserve developer ergonomics.
// Pure / no-I/O / no-crypto. See module docs.
pub mod pqc_ratification_policy;
// Run 050 — production-honest PQC transport trust-anchor bundle
// (environment binding, root status + window, revocation entries,
// canonical fingerprint, DevNet-unsigned scaffolding boundary).
pub mod pqc_trust_bundle;
// Run 055 — anti-rollback persistence for signed PQC trust bundles
// (highest accepted bundle sequence per (environment, chain_id) trust
// domain; atomic JSON record under `<data_dir>/`; fail-closed on
// rollback / equivocation / corrupt persistence).
pub mod pqc_trust_sequence;
// Run 117 — persistent authority anti-rollback marker for ratified
// bundle-signing authority state. Distinct from the Run 055
// `pqc_trust_sequence` module: this layer anchors on the
// **genesis-bound** `GenesisAuthorityConfig::authority_sequence`
// (Run 101) plus the SHA3-256 `canonical_ratification_digest`
// (Run 103) of the most recently accepted `BundleSigningRatification`
// object, not on the per-bundle `sequence` field. Run 117 lands the
// storage / snapshot primitive (record type, canonical digest,
// typed compare semantics, atomic persistence, load helper) only;
// surface wiring into startup-load / reload-apply / SIGHUP / peer-
// candidate / live `0x05` paths is staged for Run 118. See
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md`,
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 116
// update, and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_authority_state;
// Run 119 — shared mutating-surface accept-and-persist helper for the
// Run 117/118 authority anti-rollback marker. Composes Run 118
// `derive_authority_state_from_ratification` + `prepare_marker_for_acceptance`
// with Run 117 `persist_authority_state_atomic` into a single typed
// accept-or-reject decision (no disk writes) + a post-commit-boundary
// persist step. Wired into the process-start reload-apply path only in
// Run 119; startup `--p2p-trust-bundle` acceptance and SIGHUP live
// reload remain deferred to Run 120/121. See
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md`,
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 119 update,
// and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_authority_marker_acceptance;
// Run 127 — offline-only authority-state reset CLI skeleton with typed
// refusal cases and deterministic audit records. Implements the Run 126
// reset/recovery specification: allows DevNet/TestNet reset under strict
// ceremony inputs; refuses MainNet local reset by default; emits a typed
// refusal audit record on every failed attempt; never writes the marker on
// any refusal path. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_127.md`,
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 127 update,
// and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_authority_state_reset;
// Run 159 — typed pure transition validator for the v2 bundle-signing-key
// lifecycle (ActivateInitial / Rotate / Retire / Revoke / EmergencyRevoke).
// Source/test only. No release-binary evidence in this run; release-binary
// lifecycle evidence is deferred to Run 160. No MainNet apply enablement,
// no governance, no KMS/HSM, no validator-set rotation. See
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_159.md`,
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 159 update,
// and `docs/whitepaper/contradiction.md` Run 159 update.
pub mod pqc_authority_lifecycle;
// Run 163 — typed pure governance ratification authority verifier for
// v2 bundle-signing-key lifecycle transitions. Source/test only. No
// MainNet apply enablement, no governance execution, no on-chain
// governance integration, no KMS/HSM, no validator-set rotation.
// Release-binary governance verifier evidence is deferred to Run 164.
// See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_163.md`,
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` Run 163 update,
// and `docs/whitepaper/contradiction.md` Run 163 update.
pub mod pqc_governance_authority;
// Run 167 — additive, source/test wire-safe governance-proof carrier
// for v2 ratification sidecars. Defines `GovernanceAuthorityProofWire`,
// the optional `governance_authority_proof` sibling field on the v2
// ratification sidecar JSON, and the `GovernanceProofLoadStatus` typed
// loader result that the Run 165 governance gate consumes via
// `GovernanceProofContext`. Source/test only — no MainNet enablement,
// no on-chain governance, no KMS/HSM, no validator-set rotation, no
// release-binary proof-carrying enforcement (deferred to Run 168).
pub mod pqc_governance_proof_wire;
// Run 169 — production marker-decision surface integration for the
// Run 167 governance-proof loader. Single library shim that lets the
// reload-check / reload-apply / startup `--p2p-trust-bundle` / SIGHUP
// live reload / live inbound `0x05` / peer-driven drain
// (`ProductionV2MarkerCoordinator`) callers consume a typed
// `GovernanceProofLoadStatus` and pass it to the Run 165 governance
// gate. Source/test integration only — release-binary proof-carrying
// production-surface evidence is deferred to Run 170. MainNet
// peer-driven apply remains refused; `OnChainGovernance` remains
// unsupported / fail-closed.
pub mod pqc_governance_proof_surface;
// Run 178 — source/test-only typed `OnChainGovernance` proof format and
// fail-closed verifier boundary. Adds `OnChainGovernanceProof`, the
// `OnChainGovernanceProofPolicy` (default Disabled), and a pure
// `verify_onchain_governance_proof` returning typed
// `AcceptedOnChainGovernanceFixture` / `UnsupportedProductionOnChainGovernance`
// / `MainNetProductionProofUnavailable` / wrong-domain / wrong-proposal /
// expired / replay / quorum / threshold / invalid-proof / malformed /
// unsupported-suite outcomes. Source/test only — no MainNet apply, no
// governance execution, no real on-chain proof verification, no
// KMS/HSM, no validator-set rotation. Release-binary OnChainGovernance
// evidence is deferred to Run 179.
pub mod pqc_onchain_governance_proof;
// Run 180 — source/test production marker-decision composition for the
// Run 178 typed `OnChainGovernance` proof verifier. Adds a hidden
// `OnChainGovernanceProofPolicy` selector
// (`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
// `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`),
// composes anti-rollback marker decision + Run 159 v2 lifecycle +
// Run 163 governance authority verification + Run 178
// `OnChainGovernance` fixture verifier into a single typed shared
// helper, and exposes named per-surface preflight wrappers
// (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
// local peer-candidate-check, live inbound `0x05`, peer-driven
// drain) so each production surface reaches the Run 178 verifier
// through a grep-verifiable name. Default policy remains
// `OnChainGovernanceProofPolicy::Disabled`. Source/test only — no
// MainNet apply, no governance execution, no real on-chain proof
// verification, no KMS/HSM, no validator-set rotation. Release-
// binary OnChainGovernance production-surface evidence is deferred
// to Run 181.
pub mod pqc_onchain_governance_proof_surface;
// Run 182 — source/test production call-site wiring for the Run 178
// typed `OnChainGovernance` fixture proof verifier. Exposes seven
// named call-site entries (one per Run 180 per-surface wrapper) that
// are invoked from the actual production v2 marker-decision call
// sites (`pqc_trust_reload`, `pqc_live_trust_reload`,
// `pqc_trust_peer_candidate`, `pqc_peer_candidate_wire`,
// `pqc_peer_candidate_drain`, `pqc_peer_candidate_apply`, and
// `main`). Default policy remains
// `OnChainGovernanceProofPolicy::Disabled`. Source/test only — no
// MainNet apply, no governance execution, no real on-chain proof
// verification, no KMS/HSM, no validator-set rotation. Release-
// binary OnChainGovernance production-surface evidence is deferred
// to Run 183.
pub mod pqc_onchain_governance_callsite_wiring;
// Run 184 — source/test OnChainGovernance proof-carrying production
// payload/context layer. Adds a strictly additive optional
// `onchain_governance_proof` sibling on the v2 ratification sidecar
// JSON (alongside the Run 167 `governance_authority_proof` sibling),
// reuses the Run 178 `OnChainGovernanceProofWire` schema, exposes a
// typed `OnChainGovernanceProofLoadStatus` (`Absent` / `Available` /
// `Malformed`), pure non-mutating loaders for path / bytes /
// `serde_json::Value` envelopes (so the live inbound `0x05` peer-
// candidate path can extend its existing optional-sibling envelope
// safely), and seven Run 182 per-surface routing helpers that drive
// the existing call-site entries with a typed
// `MalformedOnChainGovernanceProofPayload` short-circuit placed in
// front of the Run 182 outcome. Default policy remains
// `OnChainGovernanceProofPolicy::Disabled`. Source/test only — no
// MainNet apply, no governance execution, no real on-chain proof
// verification, no KMS/HSM, no validator-set rotation. Release-binary
// OnChainGovernance accepted-proof evidence is deferred to Run 185.
pub mod pqc_onchain_governance_payload_carrying;
// Run 186 — source/test production OnChainGovernance verifier
// boundary and fail-closed MainNet policy. Adds a typed
// `OnChainGovernanceVerifierKind` (`Disabled` /
// `FixtureSourceTest` / `ProductionUnavailable` / `ProductionVerifier`
// placeholder), a typed `OnChainGovernanceProofClass` (`Fixture` /
// `Production`) derived from `proof_suite_id`, a typed
// `OnChainGovernanceVerifierPolicy` bundle, a typed
// `OnChainGovernanceVerifierBoundaryOutcome`, an
// `OnChainGovernanceVerifier` trait + four concrete
// implementations, pure typed entry points
// `verify_fixture_onchain_governance_proof` /
// `verify_production_onchain_governance_proof`, and a pure
// dispatcher
// `dispatch_onchain_governance_proof_through_verifier_boundary`.
// Default kind remains `Disabled`. Source/test only — no MainNet
// apply, no governance execution, no real on-chain proof
// verification, no KMS/HSM, no validator-set rotation. Release-
// binary verifier-boundary evidence is deferred to Run 187.
pub mod pqc_onchain_governance_verifier;
// Run 188 — source/test-only KMS/HSM custody boundary for bundle-
// signing authority and governance authority operations. Defines the
// typed `AuthorityCustodyClass` (`FixtureLocalKey` / `LocalOperatorKey`
// / `RemoteSigner` / `Kms` / `Hsm` / `Unknown`), the typed
// `AuthorityCustodyPolicy` (`Disabled` / `FixtureOnly` /
// `DevnetLocalAllowed` / `TestnetLocalAllowed` /
// `ProductionCustodyRequired` / `MainnetProductionCustodyRequired`),
// the typed `AuthorityCustodyAttestation` binding, the typed
// `AuthorityCustodyValidationOutcome` surface, the pure validator
// `validate_authority_custody_attestation`, the pure composition
// helper `validate_lifecycle_governance_and_custody`, and the typed
// `LifecycleGovernanceCustodyOutcome`. RemoteSigner / Kms / Hsm
// remain placeholder symbols only — Run 188 has no real KMS/HSM
// backend and fails them closed. Source/test only — no MainNet apply
// enablement, no real KMS/HSM, no governance execution, no
// validator-set rotation. Release-binary custody-boundary evidence is
// deferred to Run 189.
pub mod pqc_authority_custody;
// Run 190 — source/test authority-custody metadata carrying and
// production call-site wiring. Adds a strictly additive optional
// `authority_custody_attestation` sibling on the v2 ratification
// sidecar JSON (alongside the Run 167 `governance_authority_proof`
// and Run 184 `onchain_governance_proof` siblings), exposes a typed
// `AuthorityCustodyAttestationWire` with explicit `schema_version`,
// a typed `AuthorityCustodyLoadStatus` (`Absent` / `Available` /
// `Malformed`), pure non-mutating loaders, a typed
// `AuthorityCustodyCallsiteContext`, and seven per-surface routing
// helpers that drive the Run 188 lifecycle + governance + custody
// validator with typed `MalformedAuthorityCustodyAttestationPayload`,
// `CustodyAttestationRequiredButAbsent`, `NoCustodyAttestationSupplied`,
// and `MainNetPeerDrivenApplyRefused` short-circuits placed in front
// of the Run 188 outcome. Default policy remains
// `AuthorityCustodyPolicy::Disabled`. Source/test only — no MainNet
// apply, no real KMS/HSM/cloud-KMS/PKCS#11/remote-signer backend, no
// governance execution, no real on-chain proof verification, no
// validator-set rotation. Release-binary custody-metadata evidence is
// deferred to Run 191.
pub mod pqc_authority_custody_payload_carrying;
// Run 192 — source/test hidden authority-custody policy selector and
// production preflight integration. Adds typed selector parsers
// (`authority_custody_policy_from_selector`,
// `authority_custody_policy_env_selector`,
// `authority_custody_policy_from_cli_or_env`) that resolve the hidden
// CLI flag (`--p2p-trust-bundle-authority-custody-policy`, `hide =
// true`) and the equivalent
// `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` environment
// variable into a Run 188 `AuthorityCustodyPolicy`, plus seven thin
// per-surface preflight wrappers
// (`preflight_v2_marker_authority_custody_for_*`) that bind the
// resolved policy into the Run 190 callsite context for each of the
// seven production v2 marker-decision preflight contexts (reload-
// check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
// peer-candidate-check, live inbound `0x05`, peer-driven drain).
// Default policy remains `AuthorityCustodyPolicy::Disabled`. Source/
// test only — no MainNet apply enablement, no real KMS/HSM/cloud-KMS/
// PKCS#11/remote-signer backend, no governance execution, no real
// on-chain proof verification, no validator-set rotation. Release-
// binary custody-policy selector evidence is deferred to Run 193.
pub mod pqc_authority_custody_policy_surface;
// Run 194 — source/test RemoteSigner production-custody interface
// boundary. Replaces the vague Run 188
// `AuthorityCustodyClass::RemoteSigner` placeholder with a precise,
// typed remote-signer custody boundary: `RemoteSignerIdentity`,
// `RemoteSignerRequest` (with a deterministic SHA3-256
// `canonical_digest`), `RemoteSignerResponse`, a `RemoteSignerPolicy`
// (`Disabled` default / `FixtureLoopbackAllowed` /
// `ProductionRemoteSignerRequired` /
// `MainnetProductionRemoteSignerRequired`), a precise
// `RemoteSignerOutcome` reject taxonomy, a pure `RemoteAuthoritySigner`
// trait with a DevNet/TestNet-only `FixtureLoopbackRemoteSigner` and a
// fail-closed `ProductionRemoteSigner`, a pure `validate_remote_signer`
// verifier, custody-class routing
// (`validate_remote_signer_for_custody_class`), and a pure
// `validate_lifecycle_governance_custody_and_remote_signer` composition
// helper. Default policy is `RemoteSignerPolicy::Disabled`. Source/test
// only — no real remote signer backend, no networked signer service, no
// real KMS/HSM/cloud-KMS/PKCS#11 backend, no MainNet apply enablement,
// no governance execution, no real on-chain proof verification, no
// validator-set rotation. Release-binary RemoteSigner boundary evidence
// is deferred to Run 195.
pub mod pqc_remote_authority_signer;
// Run 196 — source/test RemoteSigner attestation payload carrying and
// production-context custody composition wiring. Adds an additive,
// optional `remote_signer_attestation` sibling on the v2 ratification
// sidecar JSON (alongside the Run 167 / 184 / 190 siblings) carrying
// wire forms of the Run 194 `RemoteSignerIdentity` / `RemoteSignerRequest`
// / `RemoteSignerResponse`, a typed `RemoteSignerLoadStatus`
// (`Absent` / `Available` / `Malformed`), a pure sibling extractor, a
// combined v2 sidecar loader, a `RemoteSignerCallsiteContext`, and seven
// per-surface routing helpers that bind a parsed carrier into the
// Run 194 `validate_lifecycle_governance_custody_and_remote_signer`
// composition. Default policy is `RemoteSignerPolicy::Disabled`.
// Source/test only — no real remote signer backend, no networked signer
// service, no real KMS/HSM/cloud-KMS/PKCS#11 backend, no MainNet apply
// enablement, no governance execution, no real on-chain proof
// verification, no validator-set rotation. Release-binary RemoteSigner
// payload/carrying evidence is deferred to Run 197.
pub mod pqc_remote_signer_payload_carrying;
// Run 198 — source/test hidden RemoteSigner policy selector and
// production preflight integration. Adds a hidden, disabled-by-default
// selector (CLI `--p2p-trust-bundle-remote-signer-policy` +
// `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var) with typed
// parsers (`remote_signer_policy_from_selector` /
// `remote_signer_policy_env_selector` /
// `remote_signer_policy_from_cli_or_env`), CLI-over-env precedence, and
// seven per-surface preflight wrappers
// (`preflight_v2_marker_remote_signer_for_*`) that bind the resolved
// `RemoteSignerPolicy` into the Run 196 `RemoteSignerCallsiteContext`
// for each production v2 marker-decision surface. Default remains
// `RemoteSignerPolicy::Disabled`. Fixture loopback remains
// DevNet/TestNet evidence-only and cannot satisfy MainNet production
// RemoteSigner; production RemoteSigner remains unavailable/fail-closed;
// MainNet peer-driven apply remains refused. Source/test only — no real
// RemoteSigner/KMS/HSM/cloud-KMS/PKCS#11 backend, no governance
// execution, no real on-chain proof verification, no validator-set
// rotation. Release-binary RemoteSigner-policy selector evidence is
// deferred to Run 199.
pub mod pqc_remote_signer_policy_surface;
// Run 201 — source/test production RemoteSigner transport boundary. Adds
// a typed transport identity/endpoint config
// (`RemoteSignerTransportConfig` with endpoint, signer id, custody key
// id, authority root / bundle-signing key fingerprints, environment,
// chain id, genesis hash, suite id, expected signer identity digest,
// optional transport-attestation placeholder, and a
// `TransportTimeoutRetryPolicy`), typed request/response envelopes
// (`RemoteSignerTransportRequestEnvelope` /
// `RemoteSignerTransportResponseEnvelope`) wrapping the Run 194
// `RemoteSignerRequest` / `RemoteSignerResponse`, deterministic
// domain-separated transcript-binding digests
// (`envelope_digest` + `transport_transcript_digest`), a pure/mockable
// `RemoteSignerTransport` trait (`call_remote_signer` /
// `send_remote_signer_request`) with a DevNet/TestNet-only
// `FixtureLoopbackRemoteSignerTransport` and a fail-closed
// `ProductionRemoteSignerTransport`, a typed `RemoteSignerTransportOutcome`,
// a pure verifier `validate_remote_signer_transport`, and a
// `validate_lifecycle_custody_remote_signer_and_transport` composition.
// Default policy is `RemoteSignerPolicy::Disabled`. Source/test only — no
// real remote signer backend, no networked signer daemon, no real
// KMS/HSM/cloud-KMS/PKCS#11 backend, no MainNet apply enablement, no
// governance execution, no real on-chain proof verification, no
// validator-set rotation. Production transport remains
// unavailable/fail-closed. Release-binary RemoteSigner transport-boundary
// evidence is deferred to Run 202.
pub mod pqc_remote_signer_transport;
// Run 203 — source/test KMS/HSM backend abstraction boundary for
// production authority custody. Defines provider-neutral typed
// interfaces for a future KMS/HSM backend: a `BackendKind` (`Disabled`,
// `FixtureKms`, `FixtureHsm`, `CloudKmsUnavailable`,
// `Pkcs11HsmUnavailable`, `ProductionKmsUnavailable`,
// `ProductionHsmUnavailable`, `Unknown`), a `BackendPolicy` (`Disabled`
// default, `FixtureKmsAllowed`, `FixtureHsmAllowed`,
// `ProductionKmsRequired`, `ProductionHsmRequired`,
// `MainnetProductionCustodyRequired`), a `BackendIdentity` config, a
// `BackendRequest` / `BackendResponse`, deterministic domain-separated
// `identity_digest` / `request_digest` / `response_digest` /
// `backend_transcript_digest` helpers, a pure/mockable
// `AuthorityCustodyBackend` trait (`sign_authority_lifecycle_request`)
// with DevNet/TestNet-only `FixtureKmsBackend` / `FixtureHsmBackend` and
// fail-closed `ProductionKmsBackend` / `ProductionHsmBackend` /
// `CloudKmsBackend` / `Pkcs11HsmBackend`, a typed `BackendOutcome`, a
// pure verifier `verify_authority_custody_backend_response`, a
// custody-class router `validate_backend_for_custody_class` composing the
// Run 188 `AuthorityCustodyClass::{Kms, Hsm}` classes, and a
// `validate_lifecycle_governance_custody_and_backend` composition.
// Default policy is `BackendPolicy::Disabled`. Source/test only — no real
// KMS backend, no real HSM backend, no cloud-KMS integration, no PKCS#11
// integration, no networked signer daemon, no real RemoteSigner backend,
// no MainNet apply enablement, no governance execution, no real on-chain
// proof verification, no validator-set rotation. The RemoteSigner path
// (Runs 194–202) remains a separate, unchanged custody option. Production
// KMS/HSM remain unavailable/fail-closed. Release-binary KMS/HSM
// backend-boundary evidence is deferred to Run 204.
pub mod pqc_authority_kms_hsm_backend;
// Run 205 — source/test production custody attestation verifier skeleton.
// Defines a typed `CustodyAttestationClass` (`Disabled`,
// `FixtureAttestation`, `RemoteSignerAttestation`, `KmsAttestation`,
// `HsmAttestation`, `CloudKmsAttestationUnavailable`,
// `Pkcs11HsmAttestationUnavailable`, `ProductionAttestationUnavailable`,
// `Unknown`), a typed `CustodyAttestationPolicy` (`Disabled` default,
// `FixtureAttestationAllowed`, `RemoteSignerAttestationRequired`,
// `KmsAttestationRequired`, `HsmAttestationRequired`,
// `ProductionAttestationRequired`, `MainnetProductionAttestationRequired`),
// a `CustodyAttestationEvidence`, a `CustodyAttestationInput`,
// deterministic domain-separated `evidence_digest` / `input_digest` /
// `attestation_transcript_digest` / `provider_identity_digest` helpers, a
// pure/mockable `CustodyAttestationVerifier` trait
// (`verify_custody_attestation`) with a DevNet/TestNet-only
// `FixtureCustodyAttestationVerifier` and fail-closed
// `RemoteSignerAttestationVerifier` / `KmsAttestationVerifier` /
// `HsmAttestationVerifier` / `CloudKmsAttestationVerifier` /
// `Pkcs11HsmAttestationVerifier` / `ProductionAttestationVerifier`, a typed
// `CustodyAttestationOutcome`, a pure verifier `verify_custody_attestation`,
// and composition helpers `validate_custody_metadata_and_attestation` /
// `validate_lifecycle_custody_and_attestation` layering attestation on top
// of the Run 188 custody validator while preserving the MainNet
// peer-driven-apply refusal. Default policy is
// `CustodyAttestationPolicy::Disabled`. Source/test only — no real cloud-KMS
// attestation verifier, no real PKCS#11 attestation verifier, no real HSM
// vendor attestation verifier, no real RemoteSigner attestation verifier, no
// MainNet apply enablement, no governance execution, no real on-chain proof
// verification, no validator-set rotation. RemoteSigner (Runs 194–202) and
// KMS/HSM (Runs 203–204) remain separate, unchanged backend-boundary
// options. Production attestation remains unavailable/fail-closed.
// Release-binary custody-attestation verifier-boundary evidence is deferred
// to Run 206.
pub mod pqc_custody_attestation_verifier;
// Run 207 — source/test custody-attestation payload carrying and
// production-context preflight wiring. Adds an additive, optional
// `custody_attestation` sibling on the v2 ratification sidecar JSON carrying
// the Run 205 `CustodyAttestationEvidenceWire` / `CustodyAttestationInputWire`
// (combined as `CustodyAttestationPayloadWire`), a typed
// `CustodyAttestationLoadStatus` (Absent/Available/Malformed), a sibling-
// extraction parser, a combined v2 sidecar loader, a typed
// `CustodyAttestationCallsiteContext`, and seven per-surface routing helpers
// binding the parsed carrier into the Run 205
// `validate_custody_metadata_and_attestation` /
// `validate_lifecycle_custody_and_attestation` / `verify_custody_attestation`
// boundary. Legacy no-attestation payloads remain compatible under the default
// `CustodyAttestationPolicy::Disabled`; malformed/absent-required carriers
// fail closed; fixture attestation reaches the production-context path on
// DevNet/TestNet only; production/cloud-KMS/PKCS#11/HSM/RemoteSigner
// attestation reaches the verifier and fails closed as unavailable. Source/test
// only — no real cloud-KMS/PKCS#11/HSM-vendor attestation verifier, no real
// RemoteSigner backend, no MainNet apply enablement, no governance execution,
// no real on-chain proof verification, no validator-set rotation. The routing
// helpers are pure: no marker write, no sequence write, no live trust swap, no
// session eviction, no Run 070 call. Release-binary custody-attestation
// payload/carrying evidence is deferred to Run 208.
pub mod pqc_custody_attestation_payload_carrying;
// Run 209 — source/test hidden custody-attestation policy selector and
// production preflight integration. Adds the hidden env-var name
// `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`, a typed
// `CustodyAttestationPolicySelectorParseError`, pure selector parsers
// (`custody_attestation_policy_from_selector` /
// `custody_attestation_policy_env_selector` /
// `custody_attestation_policy_from_cli_or_env`), and seven per-surface
// preflight wrappers (`preflight_v2_marker_custody_attestation_for_*`) that
// bind the resolved Run 205 `CustodyAttestationPolicy` into the Run 207
// `CustodyAttestationCallsiteContext` and dispatch to the matching Run 207
// `route_loaded_custody_attestation_to_*_callsite_decision` routing helper for
// each of the seven production v2 marker-decision preflight contexts
// (reload-check / reload-apply / startup `--p2p-trust-bundle` / SIGHUP / local
// peer-candidate-check / live inbound `0x05` / peer-driven drain). Default
// remains `CustodyAttestationPolicy::Disabled`; legacy no-attestation payloads
// remain compatible. Fixture attestation is DevNet/TestNet evidence-only and
// cannot satisfy MainNet production attestation;
// production/cloud-KMS/PKCS#11/HSM/RemoteSigner attestation reaches the Run 205
// verifier and fails closed as unavailable; MainNet peer-driven apply remains
// refused. CLI flag wins over env var. The wrappers are pure: no marker write,
// no sequence write, no live trust swap, no session eviction, no Run 070 call.
// Source/test only — no real cloud-KMS/PKCS#11/HSM-vendor attestation verifier,
// no real KMS/HSM backend, no real RemoteSigner backend, no networked signer
// daemon, no MainNet apply enablement, no governance execution, no real
// on-chain proof verification, no validator-set rotation. Release-binary
// custody-attestation policy selector evidence is deferred to Run 210.
pub mod pqc_custody_attestation_policy_surface;
// Run 211 — source/test governance execution policy boundary. Adds a typed
// `GovernanceExecutionClass` (Disabled default / FixtureGovernance /
// EmergencyCouncilFixture / OnChainGovernanceUnavailable /
// ProductionGovernanceUnavailable / MainnetGovernanceUnavailable / Unknown), a
// typed `GovernanceExecutionPolicy` (Disabled default / FixtureGovernanceAllowed
// / EmergencyCouncilFixtureAllowed / ProductionGovernanceRequired /
// MainnetGovernanceRequired), a typed `GovernanceAction` (lifecycle activate/
// rotate/retire/revoke/emergency-revoke plus policy-change, custody-policy,
// remote-signer-policy, custody-attestation-policy, and validator-set-rotation
// request placeholders and unknown), a typed `GovernanceExecutionInput`,
// `GovernanceExecutionDecision`, and `GovernanceExecutionExpectations`,
// deterministic domain-separated digest helpers (`input_digest`,
// `decision_digest`, `governance_execution_transcript_digest`, optional
// `governance_execution_policy_digest`), a pure/mockable
// `GovernanceExecutionEvaluator` trait with `evaluate_governance_execution_policy`,
// a DevNet/TestNet source/test-only `FixtureGovernanceExecutionEvaluator`, and
// production/on-chain/MainNet evaluators that are callable but fail closed as
// unavailable, plus a typed `GovernanceExecutionOutcome` distinguishing every
// accept/reject case and a peer-driven-apply guard composition helper. Default
// remains `GovernanceExecutionPolicy::Disabled`; fixture governance execution is
// DevNet/TestNet evidence-only and cannot run on MainNet;
// production/on-chain/MainNet governance execution fails closed as unavailable;
// MainNet peer-driven apply remains refused even with fixture governance
// approval; validator-set rotation remains unsupported. Source/test only — no
// real governance execution engine, no real on-chain governance proof verifier,
// no MainNet governance enablement, no MainNet apply enablement, no real
// KMS/HSM backend, no real RemoteSigner backend, no production signing-key
// custody. The boundary is pure: no marker write, no sequence write, no live
// trust swap, no session eviction, no Run 070 call. Release-binary governance
// execution policy-boundary evidence is deferred to Run 212.
pub mod pqc_governance_execution_policy;
// Run 213 — source/test governance-execution payload carrying and
// production-context preflight wiring. Adds an additive optional
// `governance_execution` sibling on the v2 ratification sidecar JSON
// (alongside the Run 167/184/190/196/207 siblings) carrying wire-form
// `GovernanceExecutionInputWire` + `GovernanceExecutionDecisionWire`
// behind a `schema_version`, a typed `GovernanceExecutionLoadStatus`
// (Absent/Available/Malformed), a pure sibling-extraction parser and v2
// sidecar loaders, a `GovernanceExecutionCallsiteContext`, and seven
// per-surface routing helpers
// (`route_loaded_governance_execution_to_*_callsite_decision`) plus
// reachability helpers that route carried material into the Run 211
// `evaluate_governance_execution_policy` /
// `evaluate_governance_execution_with_peer_driven_guard` evaluators.
// Legacy no-governance-execution payloads remain accepted under the
// default `GovernanceExecutionPolicy::Disabled`; malformed/absent-required
// carriers fail closed; fixture governance execution stays DevNet/TestNet
// source/test only; production/on-chain/MainNet governance execution
// reaches the evaluator and fails closed as unavailable; MainNet
// peer-driven apply remains refused even with fixture governance approval.
// Source/test only — no real governance execution engine, no real on-chain
// governance proof verifier, no validator-set rotation, no MainNet
// enablement. The routing helpers are pure: no marker write, no sequence
// write, no live trust swap, no session eviction, no Run 070 call.
// Release-binary governance-execution payload/carrying evidence is deferred
// to Run 214.
pub mod pqc_governance_execution_payload_carrying;
// Run 215 — source/test hidden governance-execution policy selector and
// production preflight integration. Adds a hidden, disabled-by-default
// CLI flag (`--p2p-trust-bundle-governance-execution-policy`) plus the
// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var, pure
// selector parsers, and seven per-surface preflight wrappers that bind
// the resolved `GovernanceExecutionPolicy` into the Run 213
// per-surface routing helpers. Default remains
// `GovernanceExecutionPolicy::Disabled`; fixture governance execution is
// DevNet/TestNet evidence-only; production/on-chain/MainNet governance
// execution remains fail-closed as unavailable; MainNet peer-driven
// apply remains refused. No real governance execution engine, on-chain
// proof verifier, KMS/HSM backend, RemoteSigner backend, or validator-set
// rotation. Release-binary governance-execution-policy selector evidence
// is deferred to Run 216.
pub mod pqc_governance_execution_policy_surface;
// Run 217 — source/test governance-execution runtime policy arming
// wiring. Introduces `GovernanceExecutionRuntimeArmingConfig`, a typed
// `Copy` runtime-config carrier that resolves the Run 215 hidden
// governance-execution policy selector (CLI/env, fail-closed on invalid)
// and routes the resolved `GovernanceExecutionPolicy` into all seven Run
// 213 / Run 215 per-surface preflight wrappers (reload-check,
// reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
// peer-candidate-check, live inbound `0x05`, peer-driven drain). It is
// embedded into the long-running `LiveReloadConfig` SIGHUP runtime config
// and consumed by the binary's reload-check / reload-apply / startup /
// peer-candidate-check / SIGHUP runtime contexts. Default remains
// `GovernanceExecutionPolicy::Disabled`; fixture governance execution is
// DevNet/TestNet evidence-only; production/on-chain/MainNet governance
// execution remains fail-closed as unavailable; MainNet peer-driven apply
// remains refused. No real governance execution engine, on-chain proof
// verifier, KMS/HSM backend, RemoteSigner backend, or validator-set
// rotation. Release-binary runtime-arming evidence is deferred to Run 218.
pub mod pqc_governance_execution_runtime_arming;
// Run 222 — source/test production governance execution evaluator
// interface boundary. Introduces the typed
// `ProductionGovernanceExecutionEvaluator` trait and its
// `evaluate_governance_decision_source` / `verify_governance_evaluator_response`
// methods, the `EvaluatorSourceKind` / `EvaluatorPolicy` selectors, the
// `DecisionSourceIdentity` / `EvaluatorRequest` / `EvaluatorResponse`
// typed records, deterministic domain-separated digest helpers, and a
// typed `EvaluatorOutcome`. Models how a future governance engine supplies
// decisions from a decision source, validates provenance, tracks replay,
// checks proposal/decision state, and returns fail-closed production
// outcomes — WITHOUT implementing a real governance execution engine or
// on-chain proof verifier. Composes with the Run 211 governance-execution
// input/decision types and the Run 220 runtime consumption as a future
// production evaluator target without changing runtime behaviour. Default
// remains fail-closed; fixture evaluators are DevNet/TestNet source/test
// only; the emergency fixture evaluator is explicit and non-production;
// production/on-chain/MainNet evaluators remain unavailable/fail-closed;
// MainNet peer-driven apply remains refused; validator-set rotation
// remains unsupported. No real KMS/HSM/RemoteSigner/custody backend.
// Release-binary evaluator-interface evidence is deferred to Run 223.
pub mod pqc_governance_execution_evaluator;
// Run 224 — source/test governance evaluator-runtime integration.
// Composes the Run 220 runtime consumption, the Run 222 evaluator
// request/response/interface, the Run 211 governance execution decision
// validation, and the Run 213 governance-execution payload material into a
// single ordered pipeline (selector resolution -> sidecar/load-status
// derivation -> runtime consumption -> evaluator request construction ->
// evaluator evaluation -> governance execution decision validation ->
// lifecycle/governance/custody checks -> mutation only after all checks
// pass). The Run 222 evaluator interface is now the production evaluation
// target inside the runtime-consumption path at the source/test level.
// Production/on-chain/MainNet evaluators remain callable but fail closed as
// unavailable; the fixture evaluator remains DevNet/TestNet source/test
// only; the emergency fixture evaluator is explicit and non-production;
// MainNet peer-driven apply remains refused even with fixture evaluator
// approval; validator-set rotation remains unsupported. Pure: no marker,
// no sequence, no live trust swap, no session eviction, no Run 070 call.
// Release-binary evidence is deferred to Run 225. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_execution_evaluator_runtime_integration;
// Run 228 — source/test evaluator-context representation boundary for live
// inbound `0x05` and peer-driven drain. Adds a typed, local-only evaluator
// peer context that can carry/reference evaluator context for those two
// previously-limited surfaces in source/test plumbing where representable,
// classifies the carrier status (Absent / Present / Malformed /
// UnsupportedSurface / WireSchemaUnavailable / PeerMajorityUnsupported /
// MainNetRefused), and routes a representable Present context through the Run
// 226 call-site wiring into the Run 224 integration layer. Local-only: it
// invents no `0x05` wire format and changes no wire/trust-bundle/marker/
// sequence schema. A missing/unsupported carrier is typed and fail-closed
// under an explicit evaluator policy (never a silent approval). MainNet
// peer-driven apply remains refused; production/on-chain/MainNet evaluators
// remain unavailable/fail-closed; fixture/emergency fixture evaluators remain
// non-production; validator-set rotation remains unsupported. Pure: no marker,
// no sequence, no live trust swap, no session eviction, no Run 070 call.
// Release-binary evidence is deferred to Run 229. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_evaluator_peer_context;
// Run 230 — source/test governance evaluator replay and freshness state
// boundary. Adds a typed, pure, fail-closed state boundary that decides whether
// an evaluator decision is Fresh / FreshButNotYetEffective / Expired / Stale /
// ReplayDetected / AlreadyConsumed / Superseded / wrong-binding / unavailable
// BEFORE any lifecycle mutation can happen. Defines typed replay/freshness
// inputs + expectations, the state classification and outcome enums,
// deterministic digest helpers (state key / observation / consumed / freshness
// transcript), and the GovernanceEvaluatorReplayStateReader/Writer boundary
// traits. A DevNet/TestNet in-memory FixtureReplayStateStore is the only store
// that records anything; the Production/MainNet readers/writers are callable
// but always unavailable/fail-closed. No real governance engine, on-chain
// proof verifier, or RocksDB/file/schema/migration/storage-format change is
// implemented. MainNet peer-driven apply remains refused even when state is
// fresh; validator-set rotation and policy-change actions remain unsupported.
// Pure: no marker, no sequence, no live trust swap, no session eviction, no Run
// 070 call. Release-binary replay/freshness evidence is deferred to Run 231.
// Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_state;
// Run 232 — source/test governance evaluator replay/freshness runtime
// integration. Composes the Run 224 evaluator-runtime integration, the Run 226
// runtime call-site wiring, the Run 228 peer evaluator context (where
// relevant), and the Run 230 replay/freshness state boundary into a single
// integration layer that applies replay/freshness validation as a mandatory
// pre-mutation gate. Adds a typed outcome (ProceedLegacyBypass /
// ProceedDeferred / ProceedFresh / ReplayFreshnessFailClosed /
// RuntimeIntegrationFailClosed / MainNetPeerDrivenApplyRefused). Fresh is
// required before mutation authorization; Deferred is not approval;
// expired/stale/replayed/consumed/superseded decisions fail closed before
// mutation. Read-only validation never marks consumed; explicit consume remains
// fixture-only and is performed by the caller after a fresh authorization.
// Production/MainNet replay state remains unavailable/fail-closed; MainNet
// peer-driven apply remains refused even when state is fresh; validator-set
// rotation and policy-change actions remain unsupported. Pure: no marker, no
// sequence, no live trust swap, no session eviction, no Run 070 call. No
// RocksDB/file/schema/migration/storage-format change. Release-binary evidence
// is deferred to Run 233. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_runtime_integration;
// Run 234 — source/test governance evaluator post-mutation replay consume
// boundary. Models a pure boundary that separates pre-mutation freshness
// validation, mutation authorization, successful mutation completion, and an
// explicit replay-state consume after success only. Adds typed consume inputs /
// expectations, a MutationAuthorizationOutcome / MutationCompletionStatus phase
// taxonomy, and a ConsumeBoundaryOutcome (DoNotConsume{LegacyBypass, Deferred,
// ValidationOnly, BeforeApply, ApplyFailed, RolledBack, UnsupportedSurface,
// MainNetRefused} / ConsumeFixtureAfterSuccess / FailClosed{ConsumeUnavailable,
// ProductionConsumeUnavailable, MainNetConsumeUnavailable, WrongBinding}). Only
// ConsumeFixtureAfterSuccess (after AppliedSuccessfully) authorizes a fixture
// consume; deferred / validation-only / failed-apply / rolled-back /
// unsupported-surface / MainNet-refused outcomes never consume. Composes with
// the Run 230 reader/writer traits: the DevNet/TestNet fixture writer records
// consumed only after success; production/MainNet writers are callable but
// fail-closed unavailable. Pure: no marker, no sequence, no live trust swap, no
// session eviction, no Run 070 call; no RocksDB/file/schema/migration/storage-
// format change. MainNet peer-driven apply remains refused and never consumes;
// validator-set rotation and policy-change actions remain unsupported.
// Release-binary consume-boundary evidence is deferred to Run 235. Full C4
// remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_consume_boundary;
// Run 236 — source/test governance evaluator replay consume runtime
// integration. Composes the Run 232 replay/freshness runtime integration with
// the Run 234 post-mutation consume boundary as a modeled after-success-only
// post-mutation step, modeling the full source/test lifecycle: validate
// replay/freshness, authorize mutation only on fresh, model mutation
// completion, and consume only after successful mutation completion. Adds a
// typed ReplayConsumeRuntimeIntegrationInput (Run 232 context + Run 234 consume
// input/expectations + consume-writer policy) and a ReplayConsumeRuntimeOutcome
// (ProceedLegacyBypassNoConsume / ProceedDeferredNoConsume /
// ProceedValidationOnlyNoConsume / ProceedFreshMutationAuthorized /
// ConsumeFixtureAfterMutationSuccess / DoNotConsume{BeforeApply, ApplyFailed,
// RolledBack, UnsupportedSurface, MainNetRefused} / ReplayRuntimeFailClosed /
// ConsumeFailClosed / ProductionConsumeUnavailable / MainNetConsumeUnavailable /
// MainNetPeerDrivenApplyRefused). Only ConsumeFixtureAfterMutationSuccess
// (Run 232 ProceedFresh + AppliedSuccessfully + wired DevNet/TestNet fixture
// writer) authorizes a consume; deferred / validation-only / before-apply /
// failed-apply / rolled-back / unsupported-surface / MainNet-refused outcomes
// never consume; production/MainNet consume remains unavailable/fail-closed.
// Pure: no marker, no sequence, no live trust swap, no session eviction, no Run
// 070 call; no RocksDB/file/schema/migration/storage-format change. MainNet
// peer-driven apply remains refused and never consumes even when fresh and
// modeled successful; validator-set rotation and policy-change actions remain
// unsupported. Release-binary consume-runtime-integration evidence is deferred
// to Run 237. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_consume_runtime_integration;
// Run 238 — source/test governance evaluator durable replay state backend
// boundary. Defines a typed, pure durable backend contract for replay/freshness
// and consume state persistence — before any real storage is implemented. Adds
// a typed DurableBackendDecisionInput/Expectations key binding, a
// DurableRecordState classification (Missing / ObservedFresh / ObservedDeferred
// / ObservedExpired / ObservedStale / Consumed / ReplayDetected / Superseded /
// MalformedRecord / BackendUnavailable / Production/MainNetBackendUnavailable),
// a DurableBackendOutcome (ProceedFirstSeen / ProceedKnownFresh /
// ProceedDeferred / FailClosed{Expired, Stale, Replay, Consumed, Superseded,
// MalformedRecord, BackendUnavailable, ProductionUnavailable,
// MainNetUnavailable}), a DurableConsumeOutcome (ConsumedAfterSuccess plus typed
// non-consuming rejections), an atomic operation boundary
// (observe_decision_if_absent / mark_consumed_after_success / read_decision_state
// / compare_and_mark_consumed) over GovernanceEvaluatorReplayDurableBackend
// Reader/Writer/Atomic traits, a CrashWindow classification (BeforeObserve /
// AfterObserveBeforeMutation / AfterMutationBeforeConsume / AfterConsume /
// RollbackAfterObserve / ApplyFailedAfterObserve / UnknownCrashWindow /
// Production/MainNetCrashWindowUnavailable), and deterministic digest helpers
// (durable backend key / record / operation transcript / crash-window
// transcript). Restart durability is modeled only through the DevNet/TestNet
// FixtureDurableReplayBackend restart_snapshot/from_snapshot value clone — no
// file format, database, or migration. Production/MainNet durable backends are
// callable but always unavailable/fail-closed. Pure: no marker, no sequence, no
// live trust swap, no session eviction, no Run 070 call; no
// RocksDB/file/schema/migration/storage-format change. MainNet peer-driven apply
// remains refused even when the fixture reads fresh; validator-set rotation and
// policy-change actions remain unsupported. Release-binary durable-backend
// evidence is deferred to Run 239. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_durable_backend;
// Run 240 — source/test governance evaluator durable replay backend runtime
// integration. Composes the Run 238 durable backend boundary with the Run 236
// replay consume runtime integration, Run 234 consume boundary, Run 232
// replay/freshness runtime integration, and Run 230 replay/freshness state
// boundary so the durable backend becomes the typed runtime state provider.
// Defines DurableReplayRuntimeIntegrationInput (durable kind/input/expectations
// + Run 230 replay/freshness input/expectations + replay policy + mutation
// completion) and DurableReplayRuntimeOutcome (ProceedLegacyBypassNoDurableWrite
// / ProceedDeferredObserved / ProceedFreshObserved / ProceedKnownFresh /
// ProceedMutationAuthorized / ConsumeDurableAfterMutationSuccess /
// DoNotConsume{BeforeApply,ApplyFailed,RolledBack} / CrashWindowFailClosed /
// DurableReplayFailClosed / ReplayRuntimeFailClosed / ConsumeRuntimeFailClosed /
// Production/MainNetDurableUnavailable / MainNetPeerDrivenApplyRefused). Enforces
// ordering: selector/env/chain/genesis binding -> durable read/observe ->
// replay/freshness classification -> evaluator runtime authorization -> mutation
// authorization only on fresh -> mutation completion -> compare-and-mark-consumed
// only after AppliedSuccessfully -> crash-window classification ->
// production/MainNet durable unavailable fail-closed. Read-only validation and
// observe-only never consume; deferred never authorizes mutation; failed apply /
// rollback / ambiguous crash window never consume and fail closed; MainNet
// peer-driven apply remains refused even when durable state is fresh. Pure: no
// marker, no sequence, no live trust swap, no session eviction, no Run 070 call;
// no RocksDB/file/schema/migration/storage-format change. Restart snapshot
// durability remains the Run 238 fixture source/test-only value clone.
// Release-binary durable-runtime integration evidence is deferred to Run 241.
// Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_evaluator_replay_durable_runtime_integration;
// Run 242 — source/test governance execution mutation-engine boundary. Makes the
// hand-off of an already-authorized governance evaluator decision to a future
// mutation executor explicit and typed, instead of leaving Run 240/241 to rely
// only on a modeled mutation-completion enum. Defines the typed input/context
// structures (GovernanceMutationEngineInput / Expectations / Candidate / Surface
// / Policy / EnvironmentBinding / RuntimeBinding), the engine kinds
// (Disabled / FixtureDevNet / FixtureTestNet / ProductionUnavailable /
// MainNetUnavailable), the mutation outcomes (ProceedLegacyBypassNoMutation /
// MutationAuthorized / MutationAppliedSuccessfully / MutationRejectedBeforeApply
// / MutationApplyFailed / MutationRolledBack / MutationAmbiguousFailClosed /
// Production/MainNetMutationUnavailable / MainNetPeerDrivenApplyRefused /
// ValidatorSetRotationUnsupported / PolicyChangeUnsupported), a pure/mockable
// GovernanceMutationExecutor trait (execute_authorized_mutation /
// recover_mutation_window) with DevNet/TestNet fixture + production/MainNet
// unavailable executors, and a composition helper that projects mutation-engine
// outcomes into the Run 240 durable runtime's DurableMutationCompletion semantics
// (success -> after-success-only consume; failed apply / rollback never consume;
// ambiguous / refusal / unavailable / unsupported fail closed before durable
// observe/consume). Source/test only: introduces a typed mutation-engine
// boundary, NOT a real production mutation engine. No real governance execution
// engine, on-chain proof verifier, persistent replay backend, KMS/HSM/
// RemoteSigner backend, validator-set rotation, or RocksDB/file/schema/migration/
// storage-format change. MainNet governance and peer-driven apply remain
// refused; rejected paths are non-mutating and never invoke Run 070. Full C4
// remains OPEN; C5 remains OPEN.
pub mod pqc_governance_execution_mutation_engine;
// Run 244 — source/test governance modeled trust-state mutation applier
// boundary. Adds the smallest in-memory model of what a future governance
// mutation applier would do after every Run 242 mutation-engine gate has already
// passed: it snapshots a modeled trust state (ModeledGovernanceTrustState /
// Snapshot / Root), applies a modeled trust-state update
// (ModeledGovernanceTrustMutation with AddTrustRoot / RetireTrustRoot /
// RevokeTrustRoot / EmergencyRevokeTrustRoot / Noop and unsupported
// validator-set-rotation / policy-change actions), reports a typed outcome
// (ModeledMutationNotAttempted / Applied / RejectedBeforeSnapshot /
// RejectedBeforeApply / ApplyFailed / RolledBack / RollbackFailedFatal /
// AmbiguousFailClosed / Production/MainNetModeledMutationUnavailable /
// MainNetPeerDrivenApplyRefused / ValidatorSetRotationUnsupported /
// PolicyChangeUnsupported), and projects the result back through the Run 242
// mutation outcome into the Run 240 durable completion semantics so a durable
// consume can only follow a modeled successful apply. Defines a pure/mockable
// ModeledGovernanceTrustMutationApplier trait with DevNet/TestNet fixture +
// production/MainNet unavailable appliers; the fixture applier exposes an
// invocation counter so tests prove rejected-before-snapshot paths never invoke
// it. Source/test only: the modeled applier mutates ONLY the in-memory
// ModeledGovernanceTrustState in DevNet/TestNet fixture tests. It does NOT mutate
// LivePqcTrustState, call Run 070, perform a real trust swap, evict sessions,
// write sequence files, write authority markers, perform a durable consume by
// itself, or touch RocksDB/file/schema/migration/storage-format. No real
// governance execution engine, production mutation engine, on-chain proof
// verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend. MainNet
// governance, MainNet peer-driven apply, and validator-set rotation remain
// refused/unsupported; rejected paths are non-mutating. Full C4 remains OPEN;
// C5 remains OPEN.
pub mod pqc_governance_modeled_trust_mutation_applier;
// Run 246 — source/test governance modeled END-TO-END pipeline boundary.
// Composes the already-landed typed boundaries (Run 226 evaluator call-site
// wiring, Run 240 durable replay-state runtime integration, Run 242
// mutation-engine boundary, Run 244 modeled trust-state mutation applier) into
// ONE typed source/test end-to-end pipeline that orders MainNet peer-driven
// refusal -> legacy bypass -> evaluator/call-site authorization -> durable replay
// freshness observation -> mutation-engine authorization -> modeled applier
// success -> durable consume decision. Proves durable consume is gated
// end-to-end on a modeled SUCCESSFUL applier outcome, not merely a
// mutation-completion enum; evaluator success, durable replay freshness, and
// mutation-engine authorization are each individually insufficient. It is an
// ordering/composition layer, NOT a replacement for any existing module.
// Source/test only: no production runtime mutation, no real governance execution
// engine, production mutation engine, on-chain proof verifier, persistent replay
// backend, or KMS/HSM/RemoteSigner backend. It does NOT call Run 070, mutate
// LivePqcTrustState, perform a real trust swap, evict sessions, write sequence
// files, write authority markers, perform a durable consume by itself, or touch
// RocksDB/file/schema/migration/storage-format. MainNet governance, MainNet
// peer-driven apply, and validator-set rotation remain refused/unsupported;
// rejected paths are non-mutating. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_modeled_end_to_end_pipeline;
// Run 248 — source/test governance modeled DURABLE-CONSUME PROJECTION SINK
// boundary. Extends the Run 246 modeled end-to-end pipeline with a mockable,
// in-memory consume-receipt sink that models how a future production call site
// would record an after-success-only durable consume receipt once the Run 246
// pipeline has authorized consume. Only the Run 246
// ModeledApplierAppliedAndDurableConsumeAuthorized outcome creates a sink intent;
// every other pipeline outcome, every record failure / rollback / rollback-failed
// / ambiguous window, every production / MainNet unavailable path, and every
// unsupported action fails closed with no receipt and no consume. The
// DevNet/TestNet fixture sink mutates only the in-memory
// ModeledDurableConsumeReceiptLedger and exposes an invocation counter so tests
// prove non-success paths never invoke it. Source/test only: no real persistent
// replay backend, no real durable consume backend, no real production mutation
// engine, no real governance execution engine, no real on-chain proof verifier,
// no KMS/HSM/RemoteSigner backend. It does NOT call Run 070, mutate
// LivePqcTrustState, perform a real trust swap, evict sessions, write sequence
// files, write authority markers, or touch RocksDB/file/schema/migration/
// storage-format. MainNet governance, MainNet peer-driven apply, and validator-set
// rotation remain refused/unsupported; rejected paths are non-mutating. Full C4
// remains OPEN; C5 remains OPEN.
pub mod pqc_governance_modeled_durable_consume_projection_sink;
// Run 250 — source/test governance modeled DURABLE-CONSUME RECEIPT-ACKNOWLEDGEMENT
// / COMPLETION REPORTER boundary. Extends the Run 248 modeled durable-consume
// projection sink with a mockable, in-memory completion reporter that models how a
// future production call site would report an after-record-only consume
// acknowledgement back to the Run 240 durable completion semantics. Only the Run
// 248 ConsumeReceiptRecorded sink outcome creates a completion-report intent;
// ConsumeReceiptDuplicateIdempotent may only match an already-recorded completion
// report and never creates a new one. Every other sink outcome, every report
// record failure / rollback / rollback-failed / ambiguous window, every production
// / MainNet unavailable path, and every unsupported action fails closed with no
// acknowledgement and no completion. The DevNet/TestNet fixture reporter mutates
// only the in-memory ModeledDurableConsumeCompletionReportLedger and exposes an
// invocation counter so tests prove non-recording sink paths never invoke it.
// Source/test only: no real persistent replay backend, no real durable consume
// backend, no real completion-report backend, no real production mutation engine,
// no real governance execution engine, no real on-chain proof verifier, no
// KMS/HSM/RemoteSigner backend. It does NOT call Run 070, mutate LivePqcTrustState,
// perform a real trust swap, evict sessions, write sequence files, write authority
// markers, or touch RocksDB/file/schema/migration/storage-format. MainNet
// governance, MainNet peer-driven apply, and validator-set rotation remain
// refused/unsupported; rejected paths are non-mutating. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_modeled_durable_consume_completion_reporter;
// Run 252 — source/test governance modeled DURABLE-COMPLETION FINALIZATION
// PROJECTION boundary. Extends the Run 250 modeled durable-consume completion
// reporter with a mockable, in-memory finalization projection layer that models
// how a future production call site would project an after-completion-report-only
// acknowledgement into a terminal modeled durable-completion-finalized state under
// the Run 240 durable completion semantics. Only the Run 250 CompletionReportRecorded
// reporter outcome creates a finalization intent; CompletionReportDuplicateIdempotent
// may only match an already-finalized record and never creates a new one. Every
// other reporter outcome, every finalization record failure / rollback /
// rollback-failed / ambiguous window, every production / MainNet unavailable path,
// and every unsupported action fails closed with no finalization. The
// DevNet/TestNet fixture finalizer mutates only the in-memory
// ModeledDurableCompletionFinalizationLedger and exposes an invocation counter so
// tests prove non-recording reporter paths never invoke it. Source/test only: no
// real persistent replay backend, no real durable consume backend, no real
// completion-report backend, no real finalization backend, no real production
// mutation engine, no real governance execution engine, no real on-chain proof
// verifier, no KMS/HSM/RemoteSigner backend. It does NOT call Run 070, mutate
// LivePqcTrustState, perform a real trust swap, evict sessions, write sequence
// files, write authority markers, or touch RocksDB/file/schema/migration/storage-
// format. MainNet governance, MainNet peer-driven apply, and validator-set rotation
// remain refused/unsupported; rejected paths are non-mutating. Full C4 remains
// OPEN; C5 remains OPEN.
pub mod pqc_governance_modeled_durable_completion_finalization_projection;
// Run 254 — source/test governance modeled DURABLE-COMPLETION FINALIZATION
// ATTESTATION PROJECTION boundary. Extends the Run 252 modeled durable-completion
// finalization projection with a mockable, in-memory attestation / ledger-commit
// acknowledgement layer that models how a future production call site would emit an
// after-finalization-only durable-completion attestation for auditability. Only the
// Run 252 DurableCompletionFinalized finalization outcome creates an attestation
// intent; DurableCompletionDuplicateIdempotent may only match an already-attested
// record and never creates a new one. Every other finalization outcome, every
// attestation record failure / rollback / rollback-failed / ambiguous window, every
// production / MainNet unavailable path, and every unsupported action fails closed
// with no attestation. The DevNet/TestNet fixture attestor mutates only the
// in-memory ModeledDurableCompletionAttestationLedger and exposes an invocation
// counter so tests prove non-finalizing finalization paths never invoke it.
// Source/test only: no real persistent replay backend, no real durable consume
// backend, no real completion-report backend, no real finalization backend, no real
// attestation backend, no real audit ledger backend, no real settlement ledger
// backend, no real production mutation engine, no real governance execution engine,
// no real on-chain proof verifier, no KMS/HSM/RemoteSigner backend. It does NOT call
// Run 070, mutate LivePqcTrustState, perform a real trust swap, evict sessions,
// write sequence files, write authority markers, or touch RocksDB/file/schema/
// migration/storage-format. MainNet governance, MainNet peer-driven apply, and
// validator-set rotation remain refused/unsupported; rejected paths are
// non-mutating. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_modeled_durable_completion_attestation_projection;
// Run 256 — source/test production DURABLE-COMPLETION ATTESTATION BACKEND
// INTERFACE BOUNDARY. Defines the first typed interface a future production call
// site would use to submit or record a durable-completion attestation after the
// Run 254 modeled attestation stage produced DurableCompletionAttested. Interface
// boundary only: production / MainNet / external-publication backends are reachable
// but deliberately unavailable / fail-closed, and the only positive backend
// implementation is a DevNet/TestNet fixture that records into an in-memory fixture
// ledger for source/test evidence only. Only the Run 254 DurableCompletionAttested
// outcome creates a backend request; DurableCompletionAttestationDuplicateIdempotent
// may only match an already-recorded backend submission and never creates one. Every
// other attestation outcome, every backend record failure / rollback / rollback-failed
// / ambiguous window, every production / MainNet / external-publication unavailable
// path, and every unsupported action fails closed with no backend submission. The
// DevNet/TestNet fixture backend mutates only the in-memory
// DurableCompletionAttestationBackendLedger and exposes an invocation counter so tests
// prove non-attesting attestation paths and pre-backend rejections never invoke it.
// Source/test only: no real production attestation backend, no real audit ledger
// backend, no real external publication backend, no real persistent replay backend, no
// real durable consume backend, no real completion-report backend, no real
// finalization backend, no real governance execution engine, no real production
// mutation engine, no real on-chain proof verifier, no KMS/HSM/RemoteSigner backend. It
// does NOT call Run 070, mutate LivePqcTrustState, perform a real trust swap, evict
// sessions, write sequence files, write authority markers, perform external
// publication, or touch RocksDB/file/schema/migration/storage-format. MainNet
// governance, MainNet peer-driven apply, and validator-set rotation remain
// refused/unsupported; rejected paths are non-mutating. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_durable_completion_attestation_backend;
// Run 258 — modeled durable-completion audit/publication receipt boundary. SOURCE/
// TEST-ONLY INTERFACE BOUNDARY. Defines the first typed interface a future production
// call site would use to record an audit-ledger / external-publication receipt after
// the Run 256 modeled attestation-backend stage produced BackendSubmissionRecorded.
// Interface boundary only: production / MainNet audit-ledger / external-publication
// receipt sinks are reachable but deliberately unavailable / fail-closed, and the only
// positive receipt implementation is a DevNet/TestNet fixture that records into an
// in-memory fixture ledger for source/test evidence only. Only the Run 256
// BackendSubmissionRecorded outcome creates a receipt request;
// BackendSubmissionDuplicateIdempotent may only match an already-recorded receipt and
// never creates one. Every other backend outcome, every receipt record failure /
// rollback / rollback-failed / ambiguous window, every production / MainNet /
// external-publication unavailable path, and every unsupported action fails closed
// with no audit receipt. The DevNet/TestNet fixture receipt sink mutates only the
// in-memory DurableCompletionAuditPublicationReceiptLedger and exposes an invocation
// counter so tests prove non-submitting backend paths and pre-receipt rejections never
// invoke it. Source/test only: no real audit ledger, no real external publication, no
// real production receipt sink, no real persistent backend. It does NOT call Run 070,
// mutate LivePqcTrustState, perform a real trust swap, evict sessions, write sequence
// files, write authority markers, perform external publication, or touch
// RocksDB/file/schema/migration/storage-format. MainNet governance, MainNet peer-driven
// apply, and validator-set rotation remain refused/unsupported; rejected paths are
// non-mutating. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_durable_completion_audit_publication_receipt;
// Run 260 — modeled durable-completion audit-receipt acknowledgement / external-
// publication confirmation boundary. SOURCE/TEST-ONLY INTERFACE BOUNDARY. Defines the
// first typed interface a future production audit ledger or external-publication system
// would use to acknowledge / confirm a receipt after the Run 258 modeled audit-ledger /
// external-publication receipt stage produced AuditReceiptRecorded. Interface boundary
// only: production / MainNet audit-ledger acknowledgement and external-publication
// confirmation sinks are reachable but deliberately unavailable / fail-closed, and the
// only positive acknowledgement implementation is a DevNet/TestNet fixture that records
// into an in-memory fixture ledger for source/test evidence only. Only the Run 258
// AuditReceiptRecorded outcome creates an acknowledgement request;
// AuditReceiptDuplicateIdempotent may only match an already-recorded acknowledgement and
// never creates one. Every other receipt outcome, every acknowledgement record failure /
// rollback / rollback-failed / ambiguous window, every production / MainNet /
// external-publication unavailable path, and every unsupported action fails closed with
// no acknowledgement. The DevNet/TestNet fixture acknowledgement sink mutates only the
// in-memory DurableCompletionAuditReceiptAcknowledgementLedger and exposes an invocation
// counter so tests prove non-recording receipt paths and pre-acknowledgement rejections
// never invoke it. Source/test only: no real audit ledger acknowledgement, no real
// external-publication confirmation, no real external publication, no real persistent
// backend. It does NOT call Run 070, mutate LivePqcTrustState, perform a real trust swap,
// evict sessions, write sequence files, write authority markers, perform external
// publication, or touch RocksDB/file/schema/migration/storage-format. MainNet governance,
// MainNet peer-driven apply, and validator-set rotation remain refused/unsupported;
// rejected paths are non-mutating. Full C4 remains OPEN; C5 remains OPEN.
pub mod pqc_governance_durable_completion_audit_receipt_acknowledgement;
// Run 262 — modeled durable-completion acknowledgement consumer / post-acknowledgement
// settlement interface boundary. SOURCE/TEST-ONLY INTERFACE BOUNDARY. Defines the first
// typed interface a future production settlement or downstream durable-completion
// subsystem would use to consume a durable-completion acknowledgement and prepare a
// post-acknowledgement settlement intent after the Run 260 modeled audit-receipt
// acknowledgement stage produced AcknowledgementRecorded. Interface boundary only:
// production / MainNet / external settlement consumers are reachable but deliberately
// unavailable / fail-closed, and the only positive consumer implementation is a
// DevNet/TestNet fixture that records into an in-memory fixture ledger for source/test
// evidence only. Only the Run 260 AcknowledgementRecorded outcome creates a consumer
// request; AcknowledgementDuplicateIdempotent may only match an already-recorded consumer
// record and never creates one. Every other acknowledgement outcome, every consumer record
// failure / rollback / rollback-failed / ambiguous window, every production / MainNet /
// external settlement unavailable path, and every unsupported action fails closed with no
// consumer. The DevNet/TestNet fixture consumer mutates only the in-memory
// DurableCompletionAcknowledgementConsumerLedger and exposes an invocation counter so tests
// prove non-recording acknowledgement paths and pre-consumer rejections never invoke it.
// Source/test only: no real settlement, no real external publication, no real audit-ledger
// acknowledgement, no real persistent backend. It does NOT call Run 070, mutate
// LivePqcTrustState, perform a real trust swap, evict sessions, write sequence files, write
// authority markers, perform external publication, or touch RocksDB/file/schema/migration/
// storage-format. MainNet governance, MainNet peer-driven apply, and validator-set rotation
// remain refused/unsupported; rejected paths are non-mutating. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_durable_completion_acknowledgement_consumer;
// Run 264 — modeled durable-completion consumer settlement-projection / post-consumer
// settlement-projection interface boundary. SOURCE/TEST-ONLY INTERFACE BOUNDARY. Defines the
// first typed interface a future production settlement-projection or downstream
// durable-completion subsystem would use to consume a durable-completion acknowledgement
// consumer record and prepare a post-consumer settlement-projection record after the Run 262
// modeled acknowledgement-consumer stage produced AcknowledgementConsumed. Interface boundary
// only: production / MainNet / external settlement-projection consumers are reachable but
// deliberately unavailable / fail-closed, and the only positive settlement-projection
// implementation is a DevNet/TestNet fixture that records into an in-memory fixture ledger for
// source/test evidence only. Only the Run 262 AcknowledgementConsumed outcome creates a
// settlement-projection request; AcknowledgementConsumerDuplicateIdempotent may only match an
// already-recorded settlement-projection record and never creates one. Every other consumer
// outcome, every settlement-projection record failure / rollback / rollback-failed / ambiguous
// window, every production / MainNet / external settlement-projection unavailable path, and
// every unsupported action fails closed with no settlement projection. The DevNet/TestNet
// fixture settlement-projection sink mutates only the in-memory
// DurableCompletionConsumerSettlementProjectionLedger and exposes an invocation counter so tests
// prove non-recording consumer paths and pre-settlement-projection rejections never invoke it.
// Source/test only: no real settlement, no real external publication, no real audit-ledger
// acknowledgement, no real persistent backend. It does NOT call Run 070, mutate
// LivePqcTrustState, perform a real trust swap, evict sessions, write sequence files, write
// authority markers, perform external publication, or touch RocksDB/file/schema/migration/
// storage-format. MainNet governance, MainNet peer-driven apply, and validator-set rotation
// remain refused/unsupported; rejected paths are non-mutating. Full C4 remains OPEN; C5
// remains OPEN.
pub mod pqc_governance_durable_completion_consumer_settlement_projection;
// Run 057 — trust-bundle activation epoch/height gating. Enforces
// optional `activation_height` / `activation_epoch` fields on a
// freshly validated trust bundle so a structurally valid, signed,
// anti-rollback-checked bundle is not accepted before its declared
// activation condition is satisfied. Runs AFTER signature/env/
// chain_id/revocation/window validation and BEFORE sequence
// persistence + root merge.
pub mod pqc_trust_activation;
// Run 069 — disabled-by-default trust-bundle hot-reload validation/
// staging boundary. Reuses every Run 050–065 startup security check
// (bundle parse + ML-DSA-44 signature + environment + chain_id +
// activation gate + min-activation-margin policy + revocation
// activation gate + Run 055 anti-rollback peek + Run 061/063 local
// self-checks) but applies NO live trust changes and never burns a
// sequence number. The active P2P trust state, active revocation
// sets, peer sessions, and KEMTLS sessions are untouched. See module
// docs and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_trust_reload;
// Run 071 — mutable live PQC trust-context handle (initialize-only).
// Replaces the immutable startup-only PQC trust material used by
// handshake verification with a safe shared live trust context that
// initially contains the exact same trust state as startup. NOT a
// hot-reload path; the handle is NEVER mutated after startup in
// Run 071. The handle exists so a future Run 072+ live reload-apply
// path can swap the inner snapshot under a write lock without
// redesigning the builder or handshake configs. See module docs and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_live_trust;
// Run 073 — production-honest concrete `LiveTrustApplyContext` adapter.
// Composes Run 071 `LivePqcTrustState` (`swap_snapshot`),
// Run 072 `P2pSessionEvictor` (`evict_all_sessions`), and Run 055
// `pqc_trust_sequence::check_and_update_sequence` into the smallest
// safe concrete implementation of
// `pqc_trust_reload::LiveTrustApplyContext`, so the Run 070 apply
// pipeline can run end-to-end against the production trust + session
// + sequence layers without redesigning Run 069 / Run 070. Also
// hosts `NoActiveSessionsEvictor`, the truthful zero-session evictor
// used by the binary's at-startup-time reload-apply hook. See module
// docs and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_live_trust_apply;

// Run 074 — long-running local operator-triggered live trust-bundle
// reload-apply trigger. Builds on Run 073's
// `ProductionLiveTrustApplyContext` adapter and the running node's
// live `LivePqcTrustState` + live `TcpKemTlsP2pService` session-
// evictor to expose a SIGHUP-driven trigger that an operator can
// fire on a long-running node without restarting the process. The
// node continues running after a successful apply; an invalid
// candidate leaves live trust state, sessions, and the on-disk
// sequence record unchanged. Local file only; disabled by default;
// hidden CLI flags. See module docs and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_live_trust_reload;

// Run 076 — disabled-by-default peer/gossiped trust-bundle candidate
// validation boundary. Library-level surface that can parse and
// validate a peer-supplied trust-bundle candidate using the same
// Run 069 pipeline used by startup, the local reload-check, the
// Run 073 process-start apply, and the Run 074 SIGHUP live reload-
// apply. NOT an apply path: the module exposes no `apply` function
// and never mutates `LivePqcTrustState`, P2P sessions, or the
// on-disk sequence record. Disabled by default; no CLI / wire
// integration in this run. See module docs and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_trust_peer_candidate;

// Run 077 (C4 piece: production-binary-facing, disabled-by-default
// peer-candidate validation **local check** surface). Wires the
// Run 076 `PeerCandidateValidator` into a hidden, opt-in, two-flag
// required-together qbind-node CLI surface so an operator can run
// the same Run 069/076 fail-closed pipeline against a peer-supplied
// envelope fixture from the release binary, without starting the
// node and without any live trust-state apply / sequence persistence
// / session eviction / propagation. See module docs and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_peer_candidate_binary;

// Run 078 (C4 piece: production-binary-facing, disabled-by-default
// **P2P wire** receive path for peer-candidate validation only).
// Defines the typed/versioned/bounded wire envelope
// `PeerCandidateWireEnvelopeV1`, the dedicated frame discriminator
// `DISCRIMINATOR_PEER_CANDIDATE_WIRE = 0x05` (distinct from the
// existing `p2p_tcp.rs` consensus / DAG / control discriminators),
// the strict frame-layer decoder `decode_peer_candidate_wire_frame`,
// and the `PeerCandidateWireReceiver` that wraps a Run 076
// `PeerCandidateValidator` one-to-one. Disabled by default; even
// when armed, the receiver has no apply / propagation / session-
// eviction / `LivePqcTrustState` handle by construction. Reuses
// the SAME seven Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
// metric counters (no new metric family; no `_applied_total`).
// See module docs and `docs/whitepaper/contradiction.md` C4.
pub mod pqc_peer_candidate_wire;

// Run 145 (C4 piece: peer-driven trust-bundle apply, staged candidate
// queue — source/test scaffold only, NON-applying). Bounded,
// deduplicated, TTL-bounded, disabled-by-default, environment-gated,
// per-peer-bounded, in-memory queue of `StagedPeerCandidate` entries
// derived from the upstream Run 142/143 live inbound `0x05`
// validation-only path. The module exposes **no** `apply` /
// `apply_validated_candidate` / `apply_validated_candidate_with_previous`
// entry point, never mutates `LivePqcTrustState`, never writes
// `pqc_trust_bundle_sequence.json`, never writes
// `pqc_authority_state.json`, never evicts P2P / KEMTLS sessions, and
// never invokes Run 070 apply / SIGHUP reload-apply / process-start
// apply. MainNet staging is refused unconditionally for now —
// peer-driven trust-bundle apply on MainNet requires a future
// governance / ratification / KMS-HSM authority that does not yet
// exist. Disabled by default on every environment; not wired to the
// live inbound dispatcher in Run 145 (the future Run 146 binary hook
// is documented in the module docs). See module docs,
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_145.md`, and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_peer_candidate_staging;

// Run 148 — peer-driven trust-bundle apply controller (source/test-only,
// DevNet/TestNet only, disabled-by-default, local-policy gated). Strictly
// reuses the existing Run 070 apply contract
// (`apply_validated_candidate_with_previous`) and the existing Run 134/138
// v2 authority marker post-commit persistence discipline; introduces no
// new apply algorithm, no MainNet bypass, no governance/KMS-HSM/signing-
// key lifecycle, no new wire format, and no schema change. See module
// docs, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_148.md`, and
// `docs/whitepaper/contradiction.md` C4. Release-binary DevNet/TestNet
// peer-driven apply evidence is deferred to Run 149.
pub mod pqc_peer_candidate_apply;

// Run 150 — explicit local DevNet/TestNet-only drain trigger that
// wires the Run 145/146 staged peer-candidate queue into the Run 148
// peer-driven apply controller and through it the existing Run 070
// apply contract. **Source/test only**, disabled-by-default,
// concurrency-guarded, deterministic-selection, at-most-one apply per
// trigger. MainNet refused unconditionally. Introduces no new apply
// algorithm, no autonomous background drain, no new wire format, no
// schema change. Release-binary operator trigger evidence is deferred
// to Run 151. See module docs,
// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_150.md`, and
// `docs/whitepaper/contradiction.md` C4.
pub mod pqc_peer_candidate_drain;

// T183 DAG Fetch-on-Miss modules
pub mod dag_fetch_handler;
pub mod dag_net_p2p;

// T205 P2P Dynamic Discovery + Liveness modules
pub mod p2p_discovery;
pub mod p2p_liveness;

// T206 P2P Anti-Eclipse Diversity module
pub mod p2p_diversity;

// T211 HSM/PKCS#11 signer adapter
pub mod hsm_pkcs11;

// T213 Key Rotation CLI helper
pub mod key_rotation_cli;

// T230 Ledger Slashing Backend
pub mod ledger_slashing_backend;

pub mod peer;
pub mod peer_manager;
pub mod peer_rate_limiter;
pub mod remote_signer;
pub mod secure_channel;
pub mod signer_loader;
pub mod snapshot_restore;
pub mod startup_validation;
pub mod storage;
pub mod production_consensus_storage;
// Run 098 — canonical activation epoch source helper. Wires the
// Run 093 production `ConsensusStorage` `meta:current_epoch` value
// into `ActivationContext.current_epoch` at all production trust-
// bundle activation call sites. Preserves fail-closed
// `CurrentEpochUnavailable` when no committed epoch is available.
// See module docs and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md`.
pub mod pqc_trust_activation_epoch;
pub mod timeout_verification_bridge;
pub mod validator_config;
pub mod validator_signer;
pub mod verify_pool;
pub mod vm_v0_runtime;

pub use async_runner::{
    AsyncNodeError, AsyncNodeRunner, ConsensusEvent, ConsensusEventReceiver, ConsensusEventSender,
    DEFAULT_EVENT_CHANNEL_CAPACITY,
};
pub use block_store::{BlockStore, BlockStoreError, SharedProposal, StoredBlock};
pub use channel_config::ChannelCapacityConfig;
pub use commit_index::{CommitIndex, CommitIndexError};
pub use consensus_net::{ConsensusNetAdapter, ConsensusNetError, ConsensusNetEvent};
pub use consensus_net_worker::{
    process_outbound_command_blocking, spawn_critical_outbound_worker,
    spawn_critical_outbound_worker_with_metrics, spawn_inbound_processor,
    spawn_inbound_processor_with_metrics, spawn_outbound_processor,
    spawn_outbound_processor_with_metrics, AsyncConsensusNetAdapter, AsyncNetSender,
    ConsensusMsgPriority, ConsensusNetSender, ConsensusNetService, ConsensusNetWorker,
    ConsensusNetWorkerError, CriticalCommandReceiver, InboundEventSender, OutboundCommand,
    OutboundCommandReceiver,
};
pub use consensus_node::{
    ConsensusNode, ConsensusNodeError as NetConsensusNodeError, NodeCommitInfo, NodeCommittedBlock,
};
pub use consensus_sim::{NodeConsensusSim, NodeConsensusSimError};
pub use hotstuff_node_sim::{
    DagCouplingBlockCheckResult, DagCouplingValidationResult, NodeHotstuffHarness,
    NodeHotstuffHarnessError, ProposerSource,
};
pub use identity_map::PeerValidatorMap;
pub use ledger_bridge::{InMemoryNodeLedgerHarness, NodeLedgerError, NodeLedgerHarness};

// EVM execution bridge exports (T151)
pub use evm_commit::{
    init_evm_account, init_evm_contract, EvmCommitError, EvmCommitResult, EvmExecutionBridge,
};

// EVM state storage exports (T153)
pub use evm_state_store::FileEvmStateStorage;

// T150 Execution Adapter exports
pub use execution_adapter::{
    ExecutionAdapter, ExecutionAdapterError, InMemoryExecutionAdapter, QbindBlock,
};

// T155 Async Execution Service exports
pub use execution_adapter::{
    AsyncExecError, AsyncExecutionService, SingleThreadExecutionService,
    SingleThreadExecutionServiceConfig,
};

// T151 Mempool exports
pub use mempool::{
    BalanceProvider, InMemoryBalanceProvider, InMemoryKeyProvider, InMemoryMempool, KeyProvider,
    KeyProviderError, Mempool, MempoolConfig, MempoolError,
};

// T158 DAG Mempool exports
pub use dag_mempool::{
    batch_signing_preimage, compute_batch_id, compute_tx_id, BatchError, BatchId, BatchRef,
    BatchSignature, DagMempool, DagMempoolConfig, DagMempoolError, DagMempoolMetrics,
    DagMempoolStats, InMemoryDagMempool, QbindBatch, SenderLoad, TxId, BATCH_DOMAIN_TAG,
};

// T165 DAG Availability exports
pub use dag_mempool::{
    BatchAck, BatchAckResult, BatchAckTracker, BatchCertificate, SignatureBytes,
};

// T182 DAG Batch Fetch-on-Miss exports
pub use dag_mempool::MissingBatchInfo;

// T190 DAG Coupling exports
pub use dag_mempool::{CertifiedFrontier, CertifiedFrontierEntry};

// T183 DAG Fetch-on-Miss exports
pub use dag_fetch_handler::{DagFetchHandler, DagFetchMetrics};
pub use dag_mempool::{decode_batch, decode_batch_ref, encode_batch, encode_batch_ref};
pub use dag_net_p2p::DagP2pClient;

// T162 Node Config exports
pub use node_config::{
    parse_environment, NodeConfig, ParseEnvironmentError, DEFAULT_ENVIRONMENT, VALID_ENVIRONMENTS,
};

// T163 Execution Profile exports
pub use node_config::{
    parse_execution_profile, ExecutionProfile, DEFAULT_EXECUTION_PROFILE, VALID_EXECUTION_PROFILES,
};

// T165 DAG Availability Config exports
pub use node_config::DagAvailabilityConfig;

// T170 Network Transport Config exports
pub use node_config::NetworkTransportConfig;

// T173 Network Mode exports
pub use node_config::{parse_network_mode, NetworkMode};

// T180 Configuration Profile and Mempool Mode exports
pub use node_config::{parse_config_profile, parse_mempool_mode, ConfigProfile, MempoolMode};

// T185 MainNet Safety Rails exports
pub use node_config::MainnetConfigError;

// T189/T190 DAG Coupling Mode exports
pub use node_config::{parse_dag_coupling_mode, DagCouplingMode, VALID_DAG_COUPLING_MODES};

// T206 P2P Anti-Eclipse Diversity exports
pub use p2p_diversity::{
    parse_diversity_mode, DiversityCheckResult, DiversityClassifier, DiversityConfig,
    DiversityEnforcementMode, DiversityMetrics, DiversityState, PeerBucketId,
    VALID_DIVERSITY_MODES,
};

// T231 P2P Anti-Eclipse Enforcement exports
pub use p2p_diversity::{AntiEclipseCheckResult, AntiEclipseMetrics, PeerDiversityState};

// T208 State Retention exports
pub use node_config::{
    parse_state_retention_mode, StateRetentionConfig, StateRetentionMode,
    VALID_STATE_RETENTION_MODES,
};

// M8 Mutual Auth Config exports
pub use node_config::{parse_mutual_auth_mode, MutualAuthConfig, MutualAuthMode};

// T210 Signer Mode exports
pub use node_config::{
    is_production_signer_mode, parse_signer_mode, SignerMode, VALID_SIGNER_MODES,
};

// M10.1 Signer Mode Validation exports
pub use node_config::{
    validate_signer_mode_for_devnet, validate_signer_mode_for_mainnet,
    validate_signer_mode_for_testnet,
};

// T214 Signer Failure Mode exports
pub use node_config::{parse_signer_failure_mode, SignerFailureMode, VALID_SIGNER_FAILURE_MODES};

// T218 Mempool DoS Config exports
pub use node_config::MempoolDosConfig;

// T219 Mempool Eviction Rate Limiting exports
pub use node_config::{
    parse_eviction_rate_mode, EvictionRateMode, MempoolEvictionConfig, VALID_EVICTION_RATE_MODES,
};

// T213 Key Rotation CLI exports
pub use key_rotation_cli::{
    init_key_rotation, log_dual_key_validation, log_rotation_committed, log_rotation_event_applied,
    parse_key_role, read_public_key_file, KeyRotationInitArgs, KeyRotationInitError,
    KeyRotationInitResult, KeyRotationMetrics,
};

// T230 Ledger Slashing Backend exports
pub use ledger_slashing_backend::LedgerSlashingBackend;

// T197 Monetary Mode exports (re-exported from qbind-ledger)
pub use qbind_ledger::{
    parse_monetary_mode, MonetaryAccounts, MonetaryMode, SeigniorageSplit,
    SEIGNIORAGE_SPLIT_MAINNET_DEFAULT, VALID_MONETARY_MODES,
};

// T230 Slashing Ledger exports (re-exported from qbind-ledger)
// M1: Persistent RocksDB-backed slashing ledger
pub use qbind_ledger::{
    EpochNumber, InMemorySlashingLedger, RocksDbSlashingLedger, SlashingLedger,
    SlashingLedgerError, SlashingRecord, StakeAmount, ValidatorLedgerId, ValidatorSlashingState,
};

// T170 P2P Service exports
pub use p2p::{
    ConsensusNetMsg, ControlMsg, DagNetMsg, NodeId, NullP2pService, P2pMessage, P2pService,
    PeerInfo,
};

// T174 P2P Inbound exports
pub use p2p_inbound::{
    ChannelConsensusHandler, ChannelDagHandler, ConsensusInboundHandler, ControlInboundHandler,
    DagInboundHandler, NullConsensusHandler, NullControlHandler, NullDagHandler, P2pInboundDemuxer,
};

// T175 CLI exports
pub use cli::{CliArgs, CliError};

// T175 P2P Node Builder exports
pub use p2p_node_builder::{P2pNodeBuilder, P2pNodeContext, P2pNodeError};

// T175 Address parsing exports
pub use node_config::{
    parse_socket_addr, ParseAddrError, DEFAULT_NETWORK_MODE, DEFAULT_P2P_LISTEN_ADDR,
    VALID_NETWORK_MODES,
};

pub use load_harness::{
    run_load_harness, LoadGenerator, LoadHarnessConfig, LoadHarnessError, LoadHarnessResult,
    LoopbackNetService,
};
pub use metrics::{
    CommitMetrics, ConsensusProgressMetrics, ConsensusT154Metrics, DagCouplingMetrics,
    DisconnectReason, EnvironmentMetrics, ExecutionErrorReason, ExecutionMetrics, InboundMsgKind,
    KeystoreBackendKind, MempoolMetrics, MempoolRejectReason, MonetaryMetrics, NetworkMetrics,
    NodeMetrics, OutboundMsgKind, P2pMetrics, PeerCounters, PeerNetworkMetrics, RuntimeMetrics,
    SignRequestKind, SignerHealth, SignerIsolationMetrics, SignerKeystoreMetrics, SignerModeKind,
    SlashingMetrics, SpawnBlockingMetrics, StorageMetrics, StorageOp, ValidatorEquivocationMetrics,
    ValidatorVoteCounters, ValidatorVoteMetrics, ViewLagMetrics, MAX_TRACKED_PEERS,
    MAX_TRACKED_VALIDATORS,
};

// Metrics HTTP server exports (T126)
pub use metrics_http::{
    spawn_metrics_http_server, spawn_metrics_http_server_with_addr,
    spawn_metrics_http_server_with_crypto, CryptoMetricsRefs, MetricsHttpConfig, MetricsHttpError,
    METRICS_HTTP_ADDR_ENV,
};
pub use net_service::{NetService, NetServiceConfig, NetServiceError};
pub use peer::{Peer, PeerId};
pub use peer_manager::{PeerManager, PeerManagerError};
pub use peer_rate_limiter::{
    PeerRateLimiter, PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE,
    DEFAULT_MAX_MESSAGES_PER_SECOND,
};
pub use startup_validation::{
    ConsensusStartupValidator, StartupValidationError, SuitePolicy, ValidatorEnumerator,
};
pub use storage::{
    ensure_compatible_schema, ConsensusStorage, EpochTransitionBatch, EpochTransitionMarker,
    InMemoryConsensusStorage, RocksDbConsensusStorage, StorageError, CURRENT_SCHEMA_VERSION,
};
pub use validator_config::{
    build_net_config_and_id_map_for_tests, derive_validator_public_key,
    make_local_validator_config_from_keystore, make_local_validator_config_with_identity_check,
    make_local_validator_config_with_keystore,
    make_local_validator_config_with_keystore_and_identity_check,
    verify_signing_key_matches_identity, IdentityMismatchError, KeystoreWithIdentityError,
    LocalValidatorConfig, LocalValidatorIdentity, NodeValidatorConfig, RemoteValidatorConfig,
    SignerBackend, ValidatorKeystoreConfig, ValidatorSignerConfig, EXPECTED_SUITE_ID,
};

// Validator signer abstraction exports (T148)
pub use validator_signer::{
    make_local_validator_signer, LocalKeySigner, SignError, ValidatorSigner,
};

// Remote signer exports (T149, T212, M10)
pub use remote_signer::{
    message_type, LoopbackSignerTransport, RemoteSignError, RemoteSignRequest,
    RemoteSignRequestKind, RemoteSignResponse, RemoteSignerClient, RemoteSignerMetrics,
    RemoteSignerTransport, TcpKemTlsSignerTransport, DEFAULT_REMOTE_SIGNER_TIMEOUT_MS,
    MAX_PREIMAGE_SIZE, REMOTE_SIGNER_DOMAIN_TAG,
};

// Verification pool exports (T147)
pub use verify_pool::{
    ConsensusVerifyPool, ConsensusVerifyPoolConfig, SubmitError, VerifyPoolMetrics,
};

// Keystore exports (T144)
pub use keystore::{
    FsValidatorKeystore, KeystoreConfig, KeystoreError, LocalKeystoreEntryId, ValidatorKeystore,
};

// Async peer manager exports (T90.1, T91, T120)
pub use async_peer_manager::{
    AsyncPeerManager, AsyncPeerManagerConfig, AsyncPeerManagerError, AsyncPeerManagerImpl,
    KemtlsHandshakeFailureReason, KemtlsMetrics, KemtlsRole, SharedAsyncPeerManager,
    TransportSecurityMode,
};

// Secure channel exports (T92)
pub use secure_channel::{
    accept_kemtls_async, connect_kemtls_async, AsyncChannelError, ChannelError, SecureChannel,
    SecureChannelAsync,
};

// Consensus network facade exports (T96)
pub use consensus_network_facade::{
    AsyncNetworkFacade, BlockingNetworkFacade, ConsensusNetworkFacade, DirectAsyncNetworkFacade,
    IdentityValidatorPeerMapping, NullNetworkFacade, ValidatorPeerMapping,
};

// T173: P2P consensus network exports
pub use consensus_net_p2p::{
    P2pConsensusNetwork, SimpleValidatorNodeMapping, ValidatorNodeMapping,
};

// T196: Monetary engine telemetry exports
pub use monetary_telemetry::{
    default_monetary_engine_config_for_testnet, MonetaryTelemetry, MonetaryTelemetryConfig,
    MonetaryTelemetryState,
};

use std::sync::Arc;

use qbind_consensus::{
    hotstuff_decide_and_maybe_record_vote, BlockVerifyConfig, ConsensusNodeError, HotStuffState,
    ValidatorSet, VoteDecision,
};
use qbind_crypto::CryptoProvider;
use qbind_ledger::AccountStore;
use qbind_runtime::{BlockExecutionResult, BlockExecutor};
use qbind_wire::consensus::BlockProposal;
use qbind_wire::io::WireDecode;
use qbind_wire::tx::Transaction;

/// Node-level errors that can occur when processing a block.
#[derive(Debug)]
pub enum NodeError {
    /// Consensus verification or HotStuff safety failed.
    Consensus(ConsensusNodeError),

    /// Wire-level decoding of transactions failed.
    Wire(String),

    /// Execution of one or more transactions failed in a fatal way.
    ///
    /// Note: BlockExecutionResult already records per-tx failures. This error
    /// variant is for global, unrecoverable execution errors (e.g., internal
    /// invariants).
    Execution(String),
}

impl From<ConsensusNodeError> for NodeError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeError::Consensus(e)
    }
}

/// Result of applying a single block to local state.
#[derive(Debug)]
pub struct BlockApplyOutcome {
    /// Block height.
    pub height: u64,
    /// Block round.
    pub round: u64,
    /// Block payload hash (used as the block identifier).
    pub block_id: [u8; 32],
    /// Outcome of executing all transactions.
    pub exec_result: BlockExecutionResult,
    /// Whether this node decided it *should* vote for this block.
    pub vote_decision: VoteDecision,
}

/// A minimal node-core that can verify and execute blocks locally.
///
/// This struct does NOT handle networking, leader selection, or DAG.
/// It only provides a deterministic pipeline:
///   BlockProposal -> consensus checks -> transaction decode -> execution.
pub struct Node<S: AccountStore> {
    validator_set: ValidatorSet,
    consensus_state: HotStuffState,
    verify_cfg: BlockVerifyConfig,
    block_executor: BlockExecutor<S>,
    crypto: Arc<dyn CryptoProvider>,
}

impl<S: AccountStore> Node<S> {
    /// Create a new Node with the given validator set, HotStuffState, config, crypto provider,
    /// and a default BlockExecutor.
    pub fn new(
        validator_set: ValidatorSet,
        consensus_state: HotStuffState,
        verify_cfg: BlockVerifyConfig,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Self {
        Node {
            validator_set,
            consensus_state,
            verify_cfg,
            block_executor: BlockExecutor::new(),
            crypto,
        }
    }

    /// Accessors for tests or external code.
    pub fn consensus_state(&self) -> &HotStuffState {
        &self.consensus_state
    }

    pub fn consensus_state_mut(&mut self) -> &mut HotStuffState {
        &mut self.consensus_state
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Apply a block locally: verify under consensus rules, decode txs, execute them.
    ///
    /// Semantics:
    ///  1) Use HotStuff consensus to decide if this node *would* vote for the block.
    ///     - hotstuff_decide_and_maybe_record_vote(..., record = false)
    ///  2) Decode each tx blob into a Transaction.
    ///  3) Execute the txs sequentially via BlockExecutor.
    ///  4) Return a BlockApplyOutcome with height, round, block_id, execution result, and vote decision.
    ///
    /// This function does NOT:
    ///  - send any network messages,
    ///  - sign votes,
    ///  - update locks or commit heights.
    pub fn apply_block(
        &mut self,
        store: &mut S,
        proposal: &BlockProposal,
    ) -> Result<BlockApplyOutcome, NodeError> {
        // 1) Consensus check: structural + HotStuff safety, but do NOT record vote.
        let vote_decision = hotstuff_decide_and_maybe_record_vote(
            &self.validator_set,
            self.crypto.as_ref(),
            &self.verify_cfg,
            &mut self.consensus_state,
            proposal,
            /* record = */ false,
        )
        .map_err(NodeError::Consensus)?;

        // 2) Decode txs into Transactions.
        let mut txs = Vec::with_capacity(proposal.txs.len());
        for blob in &proposal.txs {
            let mut slice: &[u8] = blob;
            let tx = Transaction::decode(&mut slice)
                .map_err(|e| NodeError::Wire(format!("failed to decode transaction: {:?}", e)))?;
            if !slice.is_empty() {
                return Err(NodeError::Wire(
                    "extra bytes after transaction decode".to_string(),
                ));
            }
            txs.push(tx);
        }

        // 3) Execute block via BlockExecutor.
        let exec_result = self
            .block_executor
            .execute_block(store, self.crypto.clone(), &txs);

        // 4) Build outcome.
        let outcome = BlockApplyOutcome {
            height: proposal.header.height,
            round: proposal.header.round,
            block_id: proposal.header.payload_hash,
            exec_result,
            vote_decision,
        };

        Ok(outcome)
    }
}