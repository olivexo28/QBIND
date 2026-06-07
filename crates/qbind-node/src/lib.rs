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