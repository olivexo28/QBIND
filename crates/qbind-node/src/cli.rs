//! T175: CLI argument parsing for qbind-node binary.
//!
//! This module provides the command-line interface for running a QBIND node.
//! It supports configuration of:
//! - Network environment (DevNet/TestNet/MainNet)
//! - Execution profile (nonce-only/vm-v0)
//! - Network mode (local-mesh/p2p)
//! - P2P settings (listen address, advertised address, static peers)
//!
//! # Usage
//!
//! ```bash
//! # DevNet with default settings
//! qbind-node --env devnet
//!
//! # TestNet Alpha with P2P enabled
//! qbind-node \
//!   --env testnet \
//!   --execution-profile vm-v0 \
//!   --network-mode p2p \
//!   --enable-p2p \
//!   --p2p-listen-addr 0.0.0.0:19000 \
//!   --p2p-peer 127.0.0.1:19001 \
//!   --p2p-peer 127.0.0.1:19002 \
//!   --validator-id 0
//! ```
//!
//! # DevNet v0 Freeze
//!
//! DevNet defaults remain `LocalMesh` + `enable_p2p = false` to preserve
//! the DevNet v0 freeze. P2P mode is opt-in for TestNet Alpha experimentation.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use crate::node_config::{
    parse_config_profile, parse_dag_coupling_mode, parse_environment, parse_eviction_rate_mode,
    parse_execution_profile, parse_mempool_mode, parse_network_mode, parse_signer_mode,
    parse_state_retention_mode, DagCouplingMode, FastSyncConfig, GenesisSourceConfig,
    MempoolDosConfig, MempoolEvictionConfig, MempoolMode, NetworkMode, NetworkTransportConfig,
    NodeConfig, P2pAntiEclipseConfig, P2pDiscoveryConfig, P2pLivenessConfig, ParseEnvironmentError,
    SignerFailureMode, SignerMode, SlashingConfig, SnapshotConfig, StateRetentionConfig,
    StaticPeerConsensusKey, ValidatorStakeConfig,
};
use crate::p2p_diversity::parse_diversity_mode;
use qbind_ledger::{
    parse_genesis_hash, parse_monetary_mode, FeeDistributionPolicy, MonetaryMode, SeigniorageSplit,
};

// ============================================================================
// CLI Arguments
// ============================================================================

/// QBIND Node - Post-Quantum Blockchain Node
///
/// A validator or full node for the QBIND blockchain network.
/// Supports DevNet, TestNet, and MainNet environments with optional
/// P2P networking for multi-process deployments.
#[derive(Parser, Debug, Clone)]
#[command(name = "qbind-node")]
#[command(version = "0.1.0")]
#[command(about = "QBIND blockchain node with PQC consensus", long_about = None)]
pub struct CliArgs {
    // ========================================================================
    // T180/T185: Configuration Profile (takes precedence over individual settings)
    // ========================================================================
    /// Configuration profile: devnet-v0, testnet-alpha, testnet-beta, or mainnet.
    ///
    /// When specified, provides a canonical configuration preset.
    /// Individual settings below can still override specific values.
    ///
    /// - devnet-v0: Frozen DevNet (NonceOnly, FIFO, LocalMesh)
    /// - testnet-alpha: TestNet Alpha (VmV0, gas off, FIFO, LocalMesh)
    /// - testnet-beta: TestNet Beta (VmV0, gas on, DAG, P2P)
    /// - mainnet: MainNet v0 (VmV0, gas required, DAG required, P2P required)
    ///
    /// If not specified, falls back to building config from individual flags.
    ///
    /// NOTE: MainNet profile enforces strict invariants. See validate_mainnet_invariants().
    #[arg(long = "profile", short = 'P')]
    pub profile: Option<String>,

    // ========================================================================
    // Environment & Execution
    // ========================================================================
    /// Network environment: devnet, testnet, or mainnet.
    ///
    /// Determines the chain ID and domain scope for signing operations.
    /// Default: devnet
    #[arg(long = "env", short = 'e', default_value = "devnet")]
    pub environment: String,

    /// Execution profile: nonce-only or vm-v0.
    ///
    /// - nonce-only: DevNet default, nonce-based execution
    /// - vm-v0: TestNet Alpha, VM with account balances
    /// Default: nonce-only
    #[arg(long = "execution-profile", default_value = "nonce-only")]
    pub execution_profile: String,

    // ========================================================================
    // T180: Gas & Fee Priority
    // ========================================================================
    /// Enable gas enforcement.
    ///
    /// When true, transactions are validated and executed with gas metering.
    /// Default: false (DevNet/Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-gas")]
    pub enable_gas: Option<bool>,

    /// Enable fee-priority mempool ordering.
    ///
    /// When true, transactions are ordered by max_fee_per_gas and effective_fee.
    /// Requires gas enforcement to be meaningful.
    /// Default: false (DevNet/Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-fee-priority")]
    pub enable_fee_priority: Option<bool>,

    // ========================================================================
    // T180: Mempool Mode
    // ========================================================================
    /// Mempool mode: fifo or dag.
    ///
    /// - fifo: Traditional FIFO queue (DevNet/Alpha default)
    /// - dag: DAG-based mempool with batches (TestNet Beta default)
    #[arg(long = "mempool-mode")]
    pub mempool_mode: Option<String>,

    /// Enable DAG availability certificates.
    ///
    /// Only meaningful when mempool-mode is 'dag'.
    /// Default: false (Alpha default). TestNet Beta preset enables this.
    #[arg(long = "enable-dag-availability")]
    pub enable_dag_availability: Option<bool>,

    // ========================================================================
    // T186: Stage B Parallel Execution
    // ========================================================================
    /// Enable Stage B parallel execution.
    ///
    /// When enabled, uses conflict-graph-based parallel execution for VM v0.
    /// Produces identical results as sequential execution but with improved throughput.
    ///
    /// Default: false (DevNet/Alpha/Beta default). MainNet preset enables this.
    #[arg(long = "enable-stage-b")]
    pub enable_stage_b: Option<bool>,

    // ========================================================================
    // T189: DAG Coupling Mode
    // ========================================================================
    /// DAG–consensus coupling mode: off, warn, or enforce.
    ///
    /// Controls how the consensus layer interacts with DAG availability certificates:
    /// - off: No coupling; consensus ignores DAG certificates (DevNet/TestNet default)
    /// - warn: Log warnings for uncertified batches but don't reject (testing)
    /// - enforce: Reject proposals with uncertified batches (MainNet required)
    ///
    /// MainNet profile requires `enforce` mode.
    #[arg(long = "dag-coupling-mode")]
    pub dag_coupling_mode: Option<String>,

    // ========================================================================
    // T197: Monetary Mode
    // ========================================================================
    /// Monetary engine mode: off, shadow, or active.
    ///
    /// Controls the monetary engine's behavior:
    /// - off: No decisions, no metrics, no issuance (DevNet default)
    /// - shadow: Decisions + metrics only, no state changes (TestNet default)
    /// - active: Decisions + metrics + minting + seigniorage split
    ///
    /// MainNet profile requires at least `shadow` mode (cannot be `off`).
    #[arg(long = "monetary-mode")]
    pub monetary_mode: Option<String>,

    // ========================================================================
    // Network Mode & P2P
    // ========================================================================
    /// Network mode: local-mesh or p2p.
    ///
    /// - local-mesh: Existing local/loopback networking (default)
    /// - p2p: P2P transport via TcpKemTlsP2pService
    /// Default: local-mesh
    #[arg(long = "network-mode", default_value = "local-mesh")]
    pub network_mode: String,

    /// Enable P2P networking.
    ///
    /// When true and network-mode is p2p, starts the P2P transport service.
    /// Default: false (DevNet freeze preserved)
    #[arg(long = "enable-p2p", default_value = "false")]
    pub enable_p2p: bool,

    /// P2P listen address (host:port).
    ///
    /// The address to bind the P2P listener to.
    /// Default: 127.0.0.1:0 (OS-assigned port)
    #[arg(long = "p2p-listen-addr", default_value = "127.0.0.1:0")]
    pub p2p_listen_addr: String,

    /// P2P advertised address (host:port).
    ///
    /// The address to advertise to peers. If not specified, uses listen_addr.
    /// Useful when behind NAT or load balancers.
    #[arg(long = "p2p-advertised-addr")]
    pub p2p_advertised_addr: Option<String>,

    /// Static peer addresses (host:port).
    ///
    /// Peers to connect to at startup. Can be specified multiple times.
    /// Example: --p2p-peer 192.168.1.10:19000 --p2p-peer 192.168.1.11:19000
    #[arg(long = "p2p-peer", action = clap::ArgAction::Append)]
    pub p2p_peers: Vec<String>,

    /// B12 — mutual KEMTLS authentication mode for the binary path.
    ///
    /// Accepts `required`, `optional`, `disabled` (and aliases handled
    /// by `parse_mutual_auth_mode`). When set to `required`, the
    /// listener requires a v2 `ClientInit` carrying a verified client
    /// `NetworkDelegationCert`, and accepted-session identity is
    /// derived from the cert's `validator_id` field rather than from
    /// the dialer's self-asserted `client_random`. Defaults to
    /// `disabled` to preserve pre-B12 test-grade DevNet behaviour.
    ///
    /// Also readable from `QBIND_MUTUAL_AUTH` (the env var only takes
    /// effect when this flag is left unset). See
    /// `docs/whitepaper/contradiction.md` C4 / B12.
    #[arg(long = "p2p-mutual-auth")]
    pub p2p_mutual_auth: Option<String>,

    /// Run 031: require timeout-verification activation under
    /// `--p2p-mutual-auth required` multi-validator deployments.
    ///
    /// When set, `qbind-node` refuses to start if a real
    /// `TimeoutVerificationContext` cannot be honestly built from
    /// existing production components (validator keystore, peer
    /// pubkey distribution, suite-aware key provider, backend
    /// registry, local signer). When unset, activation is
    /// best-effort: if production pieces are missing, the binary
    /// logs a precise reason and continues with
    /// `verification_ctx: None` (Run 030 semantics, bit-equivalent
    /// to today's path).
    ///
    /// See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_031.md` and
    /// `docs/whitepaper/contradiction.md` C5.
    #[arg(long = "require-timeout-verification", default_value_t = false)]
    pub require_timeout_verification: bool,

    /// Run 033: explicit per-validator consensus public key for
    /// timeout-verification activation.
    ///
    /// Format: `VID:SUITE:HEXPK` where
    /// - `VID` is the validator id (decimal `u64`),
    /// - `SUITE` is the signature suite id (decimal `u16`; today
    ///   only `100` = ML-DSA-44),
    /// - `HEXPK` is the lowercase hex-encoded public key bytes
    ///   (no `0x` prefix, even length).
    ///
    /// Can be specified multiple times; one entry per active
    /// validator (local + every `--p2p-peer vid@addr` peer).
    /// Required for `--require-timeout-verification` to honestly
    /// activate `TimeoutVerificationContext`. Without these
    /// entries, the binary path keeps the Run 032 disabled
    /// behaviour with `SignerPresentKeyProviderUnavailable`.
    ///
    /// This is **consensus** timeout-verification key
    /// distribution, not transport-level KEMTLS root-key
    /// distribution. See `docs/whitepaper/contradiction.md` C4/C5.
    ///
    /// Example:
    /// `--validator-consensus-key 0:100:abcd... --validator-consensus-key 1:100:1234...`
    #[arg(long = "validator-consensus-key", action = clap::ArgAction::Append)]
    pub validator_consensus_keys: Vec<String>,

    /// Run 037 (C4 piece (c)): production-honest PQC KEMTLS root-key
    /// distribution mode for the binary path.
    ///
    /// Accepted values:
    /// - `test-grade-dummy-sig` (aliases: `test-grade`, `dummy`,
    ///   `test`) — pre-Run-037 B12 wiring with `DummySig` +
    ///   deterministic `TrustedClientRoots`. Available on DevNet only.
    /// - `pqc-static-root` (aliases: `pqc-static`, `pqc`,
    ///   `static-root`) — real `MlDsa44SignatureSuite` registered;
    ///   `TrustedClientRoots` consults `--p2p-trusted-root`; dialer
    ///   presents the real ML-DSA-44-signed `NetworkDelegationCert`
    ///   loaded from `--p2p-leaf-cert*`. Required for any
    ///   production-honest claim.
    ///
    /// Defaults to `test-grade-dummy-sig` to preserve every existing
    /// DevNet test-grade evidence run bit-for-bit.
    ///
    /// See `docs/whitepaper/contradiction.md` C4 piece (c) and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_037.md`.
    #[arg(long = "p2p-pqc-root-mode")]
    pub p2p_pqc_root_mode: Option<String>,

    /// Run 037: trusted PQC transport root public key, repeatable.
    ///
    /// Format: `ROOT_KEY_ID_HEX:SUITE:ROOT_PK_HEX` where
    /// - `ROOT_KEY_ID_HEX` is exactly 64 lowercase hex chars
    ///   (32 bytes), the stable identifier embedded in the cert
    ///   `root_key_id` field;
    /// - `SUITE` is the decimal signature suite id; today only
    ///   `100` (ML-DSA-44) is accepted;
    /// - `ROOT_PK_HEX` is the lowercase hex of the root public key
    ///   (for ML-DSA-44, must decode to
    ///   `qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE` bytes).
    ///
    /// Strict parsing: malformed entries / duplicate `root_key_id` /
    /// unsupported suite all fail closed at startup. Required
    /// (non-empty) under `--p2p-mutual-auth required` +
    /// `--p2p-pqc-root-mode pqc-static-root`.
    #[arg(long = "p2p-trusted-root", action = clap::ArgAction::Append)]
    pub p2p_trusted_roots: Vec<String>,

    /// Run 037: path to a file containing this node's encoded
    /// `NetworkDelegationCert` (the bytes produced by
    /// `qbind_node::pqc_devnet_helper::encode_cert`). Required under
    /// `--p2p-mutual-auth required` + `--p2p-pqc-root-mode pqc-static-root`.
    #[arg(long = "p2p-leaf-cert")]
    pub p2p_leaf_cert: Option<PathBuf>,

    /// Run 037: path to a file containing this node's KEM secret key
    /// bytes corresponding to the `leaf_kem_pk` bound by
    /// `--p2p-leaf-cert`. Required under `--p2p-mutual-auth required` +
    /// `--p2p-pqc-root-mode pqc-static-root`.
    ///
    /// **Discipline**: this file must be readable by the qbind-node
    /// process only. The binary never logs the bytes it loads.
    #[arg(long = "p2p-leaf-cert-key")]
    pub p2p_leaf_cert_key: Option<PathBuf>,

    /// Run 039: peer leaf certificate mapping for `pqc-static-root`.
    ///
    /// Format: `VID:PATH`, repeated once per static peer whose certified
    /// ML-KEM-768 public key must be known before the KEMTLS ClientInit.
    #[arg(long = "p2p-peer-leaf-cert", action = clap::ArgAction::Append)]
    pub p2p_peer_leaf_certs: Vec<String>,

    /// Run 050: path to a JSON PQC transport trust-anchor bundle.
    ///
    /// When supplied with `--p2p-pqc-root-mode pqc-static-root`, the
    /// bundle's per-environment, status- and validity-window-checked,
    /// non-revoked roots are merged into the trust set (in addition to
    /// any `--p2p-trusted-root` CLI roots, which are accepted only on
    /// DevNet; TestNet/MainNet fail closed if both are supplied).
    ///
    /// The bundle is validated at load time (environment binding,
    /// validity window, root status, root window, duplicates,
    /// unsupported suite, revocation list consistency, signature
    /// model). Any failure aborts startup with a precise reason.
    ///
    /// **Run 051 update**: signed bundles are now verified with
    /// ML-DSA-44 against the `--p2p-trust-bundle-signing-key` list.
    /// DevNet still accepts unsigned bundles for development
    /// convenience; TestNet and MainNet REFUSE unsigned bundles and
    /// REFUSE signed bundles whose signature does not verify.
    #[arg(long = "p2p-trust-bundle")]
    pub p2p_trust_bundle: Option<PathBuf>,

    /// Run 051: bundle-signing verification public key, repeatable.
    ///
    /// Format: `KEYID:SUITE:PK` where
    /// - `KEYID` is exactly 64 lowercase hex chars (32 bytes), the
    ///   stable identifier of the bundle-signing key. MUST NOT
    ///   collide with any transport root id (either from
    ///   `--p2p-trusted-root` or from the bundle's `roots[]`).
    /// - `SUITE` is the decimal signature suite id; today only
    ///   `100` (ML-DSA-44) is accepted.
    /// - `PK` is the lowercase hex of the bundle-signing public key
    ///   (for ML-DSA-44, must decode to
    ///   `qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE` bytes).
    ///
    /// Strict parsing: malformed entries / duplicate `KEYID` /
    /// unsupported suite all fail closed at startup. This flag is
    /// REQUIRED when `--p2p-trust-bundle` is supplied on
    /// TestNet/MainNet (those environments require a verified
    /// signed bundle). On DevNet it is optional (unsigned DevNet
    /// bundles still load) but, when both an unsigned bundle and
    /// signing keys are supplied, the unsigned bundle still loads
    /// and the signing-key list has no effect.
    #[arg(
        long = "p2p-trust-bundle-signing-key",
        action = clap::ArgAction::Append
    )]
    pub p2p_trust_bundle_signing_keys: Vec<String>,

    /// Run 069 — disabled-by-default trust-bundle hot-reload
    /// **validation-only** check.
    ///
    /// When supplied, the binary runs the full Run 050–065 trust-bundle
    /// validation pipeline against the candidate JSON bundle at
    /// `<PATH>` using the same security checks as startup
    /// (parse + ML-DSA-44 signature verification + environment +
    /// chain_id + bundle activation_height + Run 065 minimum
    /// activation-height policy + per-entry revocation activation +
    /// Run 055 anti-rollback peek against the persisted sequence
    /// record + Run 061 local-leaf revocation self-check +
    /// Run 063 local-issuer-root revocation self-check), prints the
    /// verdict to stderr, and exits with `0` on a valid candidate or
    /// `1` on any failure. The node does **not** start in this mode.
    ///
    /// **This is NOT hot reload.** No live trust state, no peer
    /// sessions, no KEMTLS sessions, and no on-disk sequence record
    /// are modified. The candidate is **never applied**. A rejected
    /// candidate **never** burns a sequence number. Peer-supplied /
    /// gossiped bundles are **not** accepted. KMS/HSM custody,
    /// bundle-signing-key ratification, and `activation_epoch`
    /// runtime sourcing remain open under
    /// `docs/whitepaper/contradiction.md` C4.
    ///
    /// Use cases (evidence / operator dry-run):
    /// - prove a new candidate signed bundle would be accepted on
    ///   this node before rolling it out to production;
    /// - prove a rotated bundle-signing-key configuration is
    ///   correctly distributed before activating the new key on the
    ///   live path;
    /// - prove a candidate's `activation_height` margin satisfies
    ///   the Run 065 per-environment minimum policy at the current
    ///   local committed height.
    ///
    /// This flag is hidden because it is evidence-only. Operators
    /// who use it MUST read `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md`
    /// for the staging-vs-apply boundary.
    #[arg(long = "p2p-trust-bundle-reload-check", hide = true)]
    pub p2p_trust_bundle_reload_check: Option<PathBuf>,

    /// Run 070 — disabled-by-default operator opt-in flag for the
    /// `--p2p-trust-bundle-reload-apply-path` candidate. Without
    /// this flag, supplying `--p2p-trust-bundle-reload-apply-path`
    /// is refused as a configuration error so the operator can
    /// never accidentally trigger a live trust swap by typing the
    /// path flag alone. With this flag, the validation pipeline
    /// runs; whether the live apply itself proceeds depends on
    /// whether the running binary has a mutable trust-context
    /// handle to swap against — see
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md` and the
    /// `ReloadApplyError::UnsupportedRuntimeContext` boundary in
    /// `crates/qbind-node/src/pqc_trust_reload.rs`. This flag is
    /// hidden because Run 070 is evidence-only.
    ///
    /// **This is NOT peer-supplied / gossiped bundle acceptance,
    /// NOT KMS / HSM, NOT activation_epoch runtime sourcing, NOT
    /// signing-key ratification, NOT a filesystem watcher.** It is
    /// the smallest safe local-operator-triggered apply primitive
    /// the library supports, exposed on the binary surface for
    /// evidence. See `docs/whitepaper/contradiction.md` C4.
    #[arg(long = "p2p-trust-bundle-reload-apply-enabled", hide = true)]
    pub p2p_trust_bundle_reload_apply_enabled: bool,

    /// Run 070 — operator-supplied local file path of a candidate
    /// trust bundle to apply live. Requires
    /// `--p2p-trust-bundle-reload-apply-enabled`. Disabled by
    /// default. The candidate is validated using the exact Run 069
    /// pipeline; on the production-honest path the live apply is
    /// then attempted. The current `qbind-node` binary surfaces
    /// `ReloadApplyError::UnsupportedRuntimeContext` honestly
    /// because no mutable runtime trust handle exists yet — see
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md`. The node
    /// does **not** start in this mode (the process exits with
    /// `0` on a successful apply and `1` on any failure or
    /// unsupported-context boundary).
    ///
    /// **No peer / gossip input. No automatic apply. No remote
    /// unauthenticated endpoint.** Local file only, operator-
    /// triggered only.
    #[arg(long = "p2p-trust-bundle-reload-apply-path", hide = true)]
    pub p2p_trust_bundle_reload_apply_path: Option<PathBuf>,

    /// Run 074 — disabled-by-default operator opt-in flag for the
    /// **long-running-node** live trust-bundle reload-apply trigger.
    /// Without this flag, supplying
    /// `--p2p-trust-bundle-live-reload-path` is refused as a
    /// configuration error so the operator can never accidentally
    /// "arm" the trigger by typing the path flag alone. With this
    /// flag, the running node installs a SIGHUP handler that, on
    /// each signal, validates the configured candidate path through
    /// the SAME Run 069 pipeline and applies it through the SAME
    /// Run 073 `ProductionLiveTrustApplyContext` against the running
    /// node's live `LivePqcTrustState` + live `TcpKemTlsP2pService`
    /// session-evictor. Disabled by default. Hidden because Run 074
    /// is evidence-only.
    ///
    /// **This is NOT peer-supplied / gossiped bundle acceptance,
    /// NOT a remote unauthenticated endpoint, NOT KMS / HSM, NOT
    /// activation_epoch runtime sourcing, NOT signing-key
    /// ratification, NOT a filesystem watcher.** It is the smallest
    /// safe long-running-node trigger built on top of the Run 073
    /// adapter. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md`
    /// and `docs/whitepaper/contradiction.md` C4.
    #[arg(long = "p2p-trust-bundle-live-reload-enabled", hide = true)]
    pub p2p_trust_bundle_live_reload_enabled: bool,

    /// Run 074 — operator-supplied local file path of a candidate
    /// trust bundle to apply live on each SIGHUP. Requires
    /// `--p2p-trust-bundle-live-reload-enabled`. Disabled by
    /// default. Local file only — no peer / gossip input. The
    /// candidate is re-read from disk on every trigger, validated
    /// through the same Run 069 pipeline, and applied through the
    /// Run 073 `ProductionLiveTrustApplyContext` against the
    /// running node's live trust handle and live session-evictor.
    ///
    /// Concurrent triggers (e.g. two SIGHUPs arriving while an
    /// apply is in progress) are rejected via an in-process
    /// "in progress" flag — they do NOT queue and do NOT cause
    /// re-entry. An invalid candidate logs `VERDICT=invalid` and
    /// leaves the live trust state, the persisted sequence
    /// record, and all P2P sessions UNCHANGED. A successful
    /// apply logs `VERDICT=applied`, swaps the live trust state,
    /// evicts all P2P sessions via the Run 072 hook, and commits
    /// the new sequence. The node continues running afterwards.
    #[arg(long = "p2p-trust-bundle-live-reload-path", hide = true)]
    pub p2p_trust_bundle_live_reload_path: Option<PathBuf>,

    /// Run 077 — disabled-by-default operator opt-in flag for the
    /// **production-binary-facing local peer-candidate validation
    /// check mode**. Without this flag, supplying
    /// `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>` is
    /// refused as a configuration error so the operator can never
    /// accidentally "arm" the check by typing the path flag alone.
    /// With this flag plus a path, the binary parses the local
    /// JSON envelope fixture, runs the **same** Run 076
    /// `PeerCandidateValidator::try_accept` (which itself reuses
    /// the **same** Run 069 `validate_candidate_bundle_full`
    /// pipeline used at startup, by the Run 069 reload-check, by
    /// the Run 073 process-start apply, and by the Run 074 SIGHUP
    /// live reload-apply), bumps the seven existing Run 076
    /// `qbind_p2p_pqc_trust_bundle_peer_candidate_*` metric
    /// counters (no `_applied_total` family — none exists by
    /// design), prints the canonical `VERDICT=...` log line, and
    /// exits (`0` only on `Validated`; `1` on every fail-closed
    /// outcome including partial-config / I/O / parse refusal).
    /// The node does **not** start in this mode. Hidden because
    /// Run 077 is evidence-only.
    ///
    /// **This is NOT peer-driven live apply, NOT gossip
    /// propagation, NOT a peer/network listener, NOT a P2P wire
    /// integration, NOT an admin-API endpoint, NOT a filesystem
    /// watcher, NOT KMS/HSM, NOT `activation_epoch` runtime
    /// sourcing, NOT signing-key ratification, NOT fast-sync
    /// restore parity.** It is the smallest safe production-
    /// binary surface that exercises the Run 076 validator from
    /// the release `qbind-node` binary. See
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md` and
    /// `docs/whitepaper/contradiction.md` C4.
    #[arg(long = "p2p-trust-bundle-peer-candidate-validation-enabled", hide = true)]
    pub p2p_trust_bundle_peer_candidate_validation_enabled: bool,

    /// Run 077 — operator-supplied local file path of a
    /// `PeerCandidateEnvelope` JSON fixture to validate. Requires
    /// `--p2p-trust-bundle-peer-candidate-validation-enabled`.
    /// Disabled by default. Local file only — no peer / gossip
    /// input, no network listener, no remote unauthenticated
    /// endpoint. The fixture is parsed once, the validator runs
    /// once, and the binary exits. The on-disk anti-rollback
    /// sequence record at `--data-dir`/`pqc_trust_sequence` is
    /// **never** modified (sequence persistence is consulted only
    /// via the read-only Run 055 peek inherited from Run 069).
    /// The validator holds no live `LivePqcTrustState` handle, no
    /// `P2pSessionEvictor`, no `LiveReloadController`, and no
    /// `ProductionLiveTrustApplyContext`; it cannot apply the
    /// candidate, propagate it, persist its sequence, or evict
    /// sessions by construction. See module docs in
    /// `crates/qbind-node/src/pqc_peer_candidate_binary.rs` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md`.
    #[arg(long = "p2p-trust-bundle-peer-candidate-check", hide = true)]
    pub p2p_trust_bundle_peer_candidate_check: Option<PathBuf>,

    /// Run 078 — disabled-by-default operator opt-in flag for the
    /// **production-binary-facing P2P wire receive path** for
    /// peer-candidate validation **only**. Without this flag, the
    /// Run 078 wire receiver is constructed in the `Disabled`
    /// state — even if a peer-candidate frame ever reached the
    /// receiver (no production gossip subscription publishes such
    /// frames today; see module docs), the disabled receiver
    /// would short-circuit BEFORE any decode / crypto / scratch
    /// file / validator call. With this flag, the receiver is
    /// armed for **validation-only** acceptance of well-formed
    /// peer-candidate frames: the candidate is routed through the
    /// **same** Run 076 `PeerCandidateValidator::try_accept`
    /// (which itself reuses the **same** Run 069
    /// `validate_candidate_bundle_full` pipeline used at startup,
    /// by the Run 069 reload-check, by the Run 073 process-start
    /// apply, by the Run 074 SIGHUP live reload-apply, and by the
    /// Run 077 binary-facing local check), bumps the seven
    /// existing Run 076
    /// `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters (no
    /// `_applied_total` family — none exists by design), and is
    /// end-of-line. Hidden because Run 078 is evidence-only.
    ///
    /// **This is NOT peer-driven live apply, NOT gossip
    /// propagation, NOT a new network listener, NOT an admin-API
    /// endpoint, NOT a filesystem watcher, NOT KMS/HSM, NOT
    /// `activation_epoch` runtime sourcing, NOT signing-key
    /// ratification, NOT fast-sync restore parity.** The receiver
    /// holds no `LivePqcTrustState` handle, no `P2pSessionEvictor`,
    /// no `LiveReloadController`, no `ProductionLiveTrustApplyContext`,
    /// and no `P2pService` broadcast handle; by construction it
    /// cannot apply the candidate, propagate it, persist its
    /// sequence number, evict P2P / KEMTLS sessions, or
    /// re-broadcast the frame. See
    /// `crates/qbind-node/src/pqc_peer_candidate_wire.rs`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_078.md`, and
    /// `docs/whitepaper/contradiction.md` C4.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-wire-validation-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_wire_validation_enabled: bool,

    /// Run 080 — disabled-by-default operator opt-in master switch
    /// for publishing one local peer-candidate envelope over live
    /// authenticated P2P sessions as a real `0x05` frame.
    ///
    /// Required-together with
    /// `--p2p-trust-bundle-peer-candidate-wire-publish-path`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-wire-publish-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_wire_publish_enabled: bool,

    /// Run 080 — local operator-supplied Run 076
    /// `PeerCandidateEnvelope` JSON fixture path to publish as a
    /// Run 078 wire envelope over live P2P sessions.
    ///
    /// Required-together with
    /// `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-wire-publish-path",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_wire_publish_path: Option<PathBuf>,

    /// Run 080 — publish exactly one candidate frame and continue
    /// normal node runtime; no automatic resend loop.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-wire-publish-once",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_wire_publish_once: bool,

    /// Run 177 — hidden, **disabled-by-default**, harness-only path to a
    /// `GovernanceAuthorityProofWire` JSON file (Run 167 / Run 176 wire
    /// schema) that is attached to the live `0x05`
    /// [`PeerCandidateWireEnvelopeV1`] published by the Run 080
    /// publish-once path. **Strictly additive carrier** on the existing
    /// Run 176 optional `governance_authority_proof` wire field — no
    /// schema change, no domain-tag change, no envelope-version bump,
    /// no marker / sequence-file / trust-bundle drift.
    ///
    /// When this flag is **absent**, the publish path is bit-for-bit
    /// identical to pre-Run-177 behaviour: the wire envelope's
    /// `governance_authority_proof` field stays `None`. When present,
    /// the JSON file is parsed as a `GovernanceAuthorityProofWire`
    /// (structural validation only — the issuer signature is verified
    /// at the receiver by the Run 163 verifier, not here) and embedded
    /// on the wire envelope before [`encode_peer_candidate_wire_frame`]
    /// runs. Parse failures are fail-closed: the publish-once attempt
    /// aborts without sending any frame.
    ///
    /// This carrier flag is required-together with
    /// `--p2p-trust-bundle-peer-candidate-wire-publish-enabled` and
    /// `--p2p-trust-bundle-peer-candidate-wire-publish-path`.
    ///
    /// See `task/RUN_177_TASK.txt`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md`, and
    /// `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_wire_publish_governance_proof_path: Option<PathBuf>,

    /// Run 088 — disabled-by-default validation-before-rebroadcast
    /// propagation prototype for peer-candidate `0x05` frames. This
    /// is propagation-only: candidates are rebroadcast only after the
    /// existing Run 076/078 validation path succeeds, and the path
    /// never applies, persists sequence, mutates live trust, evicts
    /// sessions, or invokes SIGHUP reload.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-propagation-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_propagation_enabled: bool,

    /// Run 147 — hidden, **disabled-by-default** operator opt-in flag
    /// that arms the Run 146 [`LivePeerCandidateWireDispatcher`]
    /// non-applying [`PeerCandidateStagingQueue`] hook on the live
    /// inbound `0x05` validation-only receive path.
    ///
    /// **Strictly non-authoritative.** Setting this flag does NOT
    /// imply propagation, does NOT imply apply, does NOT mutate
    /// `LivePqcTrustState`, does NOT write
    /// `pqc_trust_bundle_sequence.json`, does NOT write
    /// `pqc_authority_state.json`, does NOT evict sessions, and
    /// does NOT invoke SIGHUP / reload-apply. The flag only
    /// installs a bounded in-memory queue that records
    /// `PeerCandidateOutcome::Validated(_)` outcomes already
    /// produced by the Run 142 v2 (or Run 109 v1) validation path,
    /// after both the Run 142 v2 and Run 123 v1 authority-marker
    /// conflict checks have passed, and **before** any Run 088
    /// propagation rebroadcast.
    ///
    /// Requires `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
    /// at the binary level (a queue with no upstream validation
    /// pipeline would never receive any candidate). MainNet is
    /// **refused unconditionally** at startup even when this flag
    /// is set: the binary aborts with a fatal `[binary] Run 147:
    /// FATAL` line and exit code 1; the P2P transport is never
    /// brought up. The refusal is enforced both at the CLI gate
    /// and again at the queue's
    /// [`PeerDrivenStagingPolicy::permitted`] layer.
    ///
    /// See `task/RUN_147_TASK.txt`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`, and
    /// `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-staging-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_staging_enabled: bool,

    /// Run 149 — hidden, **disabled-by-default** DevNet/TestNet-only
    /// operator opt-in flag that arms the Run 148 source/test
    /// peer-driven apply controller
    /// (`pqc_peer_candidate_apply::try_apply_staged_peer_candidate`)
    /// for invocation by the release `qbind-node` binary. The flag
    /// is the minimal hidden source delta introduced by Run 149
    /// after its feasibility gate ("can the real
    /// `target/release/qbind-node` arm and invoke the Run 148
    /// peer-driven apply controller through an existing runtime
    /// path?") answered **NO** against the Run 148 state.
    ///
    /// **Strictly delegated apply.** Setting this flag does NOT
    /// add a new apply algorithm; it does NOT bypass the Run 142
    /// v2 / Run 109 v1 validation path; it does NOT bypass the
    /// Run 145 / Run 146 / Run 147 staging queue; it does NOT
    /// bypass the Run 130 v2 verifier; it does NOT bypass the
    /// Run 132 / Run 142 v2 marker pre-apply check; it does NOT
    /// bypass Run 055 anti-rollback; it does NOT bypass the
    /// Run 065 / Run 091 activation gates; it does NOT imply
    /// propagation. When the controller is reached (by a future
    /// drain caller — see `pqc_peer_candidate_apply.rs` and the
    /// Run 148 source/test coverage), it delegates apply to the
    /// existing Run 070 `apply_validated_candidate_with_previous`
    /// pipeline verbatim (validate → snapshot previous → swap →
    /// evict_sessions → commit_sequence), and only persists the
    /// v2 authority marker **after** the sequence commit succeeds
    /// via the existing
    /// `V2MarkerCoordinator` / `persist_accepted_v2_marker_after_commit_boundary`
    /// post-commit boundary.
    ///
    /// Requires
    /// `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
    /// at the binary level (without the upstream validation path
    /// the controller would never receive a validated candidate
    /// to apply) and requires
    /// `--p2p-trust-bundle-peer-candidate-staging-enabled` at the
    /// binary level (apply consumes only already-staged candidates
    /// per Run 144 §3 Phase 2 / Run 145 staging contract — apply
    /// without staging is refused fail-closed rather than silently
    /// inventing an apply path that bypasses staging).
    ///
    /// MainNet is **refused unconditionally** at startup even
    /// when this flag is set: the binary aborts with a fatal
    /// `[binary] Run 149: FATAL` line and exit code 1; the P2P
    /// transport is never brought up. Local peer majority is NOT
    /// authority on MainNet. The refusal is enforced at the
    /// top-level CLI gate, and the Run 148
    /// `PeerDrivenApplyPolicy::mainnet_attempted()` continues to
    /// return `PeerDrivenApplyOutcome::RefusedMainNet` defensively
    /// at the controller layer even if the gate is ever loosened.
    ///
    /// See `task/RUN_149_TASK.txt`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`, and
    /// `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-apply-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_apply_enabled: bool,

    /// Run 171 — hidden, **disabled-by-default** DevNet/TestNet-safe
    /// governance-proof Required-policy selector for the production
    /// v2 marker-decision preflights wired by Run 169 (reload-check
    /// validation-only, reload-apply, startup `--p2p-trust-bundle`,
    /// SIGHUP live reload, peer-driven `ProductionV2MarkerCoordinator`,
    /// live `0x05` / local peer-candidate validation-only).
    ///
    /// **Default behavior unchanged:** when this flag and the
    /// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` environment
    /// variable are both absent, every production marker-decision
    /// preflight runs under
    /// [`qbind_node::pqc_governance_authority::GovernanceProofPolicy::NotRequired`]
    /// — old no-proof v2 sidecars remain bit-for-bit compatible
    /// (Runs 134/136/138/142/148/150/152/161/165/167/169/170 invariants).
    ///
    /// **When set:** the preflights run under
    /// [`qbind_node::pqc_governance_authority::GovernanceProofPolicy::RequiredForLifecycleSensitive`]
    /// so `Rotate` / `Retire` / `Revoke` / `EmergencyRevoke` lifecycle
    /// transitions require a valid Run 167 governance authority proof
    /// sibling on the v2 ratification sidecar; missing or invalid
    /// proofs fail closed with the typed
    /// `GovernanceAuthorityRequiredButMissing` /
    /// `GovernanceAuthorityRejected` reason BEFORE any Run 070 apply,
    /// live-trust swap, session eviction, sequence write, or marker
    /// persist (mutation contract preserved per Run 165 / Run 169 /
    /// Run 170).
    ///
    /// **NOT** a governance execution engine, **NOT** an on-chain
    /// governance proof, **NOT** a KMS/HSM custody claim, **NOT** a
    /// validator-set rotation primitive, **NOT** sufficient to enable
    /// MainNet peer-driven apply. MainNet peer-driven apply remains
    /// refused unconditionally regardless of this flag (Run 148/149
    /// gate, Run 152 binary-reachable refusal). Validation-only
    /// MainNet parsing of v2 sidecars carrying a Run 167 proof is
    /// permitted only insofar as the existing per-environment
    /// validation-only policy already permits parsing (this flag adds
    /// no MainNet apply path).
    ///
    /// May also be enabled by the equivalent environment variable
    /// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` (operator
    /// convenience for systemd-style overrides). Either source is
    /// sufficient; the flag and env-var are OR-combined.
    ///
    /// Run 171 is source/test selector wiring only. Release-binary
    /// Required-policy production-surface evidence is deferred to
    /// Run 172. See `task/RUN_171_TASK.txt` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_171.md`.
    #[arg(
        long = "p2p-trust-bundle-governance-proof-required",
        hide = true
    )]
    pub p2p_trust_bundle_governance_proof_required: bool,

    /// Run 180 — hidden, **disabled-by-default** DevNet/TestNet-safe
    /// `OnChainGovernance` fixture-proof selector for the production
    /// v2 marker-decision composition path wired by Run 180
    /// ([`crate::pqc_onchain_governance_proof_surface::compose_onchain_governance_marker_decision`]
    /// and the seven per-surface named wrappers it exposes for
    /// reload-check, reload-apply, startup `--p2p-trust-bundle`,
    /// SIGHUP, local peer-candidate-check, live inbound `0x05`, and
    /// the Run 150 peer-driven apply drain coordinator).
    ///
    /// **Default behavior unchanged:** when this flag and the
    /// `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
    /// environment variable are both absent, the resolved policy is
    /// [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`]
    /// — every `OnChainGovernance` proof (fixture or otherwise) is
    /// refused as `UnsupportedProductionOnChainGovernance` exactly
    /// as in Run 178/179.
    ///
    /// **When set:** the resolved policy is
    /// [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::AllowFixtureSourceTest`]
    /// and DevNet/TestNet fixture `OnChainGovernance` proofs may pass
    /// at source/test marker-decision level when every binding
    /// matches (chain / genesis / authority-root / governance domain
    /// / governance epoch / proposal / outcome / lifecycle action /
    /// candidate digest / sequence / freshness / replay-id / quorum
    /// / threshold / suite / proof bytes). MainNet remains refused
    /// as `MainNetProductionProofUnavailable` regardless of this
    /// flag, and the Run 147/Run 148/Run 152 MainNet peer-driven-
    /// apply refusal at the calling surface is unchanged.
    ///
    /// **NOT** a governance execution engine, **NOT** a real
    /// on-chain governance proof, **NOT** a KMS/HSM custody claim,
    /// **NOT** a validator-set rotation primitive, **NOT** sufficient
    /// to enable MainNet peer-driven apply, **NOT** an autonomous-
    /// apply / apply-on-receipt / peer-majority authority claim, and
    /// **NOT** a marker / sequence-file / trust-bundle-core / wire /
    /// schema change.
    ///
    /// May also be enabled by the equivalent environment variable
    /// `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1`
    /// (operator convenience for systemd-style overrides). Either
    /// source is sufficient; the flag and env-var are OR-combined.
    ///
    /// Run 180 is source/test selector wiring only. Release-binary
    /// `OnChainGovernance` production-surface evidence is deferred
    /// to Run 181. See `task/RUN_180_TASK.txt` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.
    #[arg(
        long = "p2p-trust-bundle-onchain-governance-fixture-allowed",
        hide = true
    )]
    pub p2p_trust_bundle_onchain_governance_fixture_allowed: bool,

    /// Run 192 — hidden, **disabled-by-default** authority-custody
    /// policy selector for the seven production v2 marker-decision
    /// preflight contexts (reload-check / reload-apply / startup
    /// `--p2p-trust-bundle` / SIGHUP / local peer-candidate-check /
    /// live inbound `0x05` / peer-driven drain).
    ///
    /// Recognized values (case-insensitive):
    ///
    /// * `disabled` — default. Refuses every custody class. Old
    ///   no-custody payloads remain accepted exactly as before
    ///   Run 192.
    /// * `fixture-only` — DevNet/TestNet evidence only. MainNet
    ///   rejects fixture custody before it can satisfy production
    ///   custody.
    /// * `devnet-local-allowed` — DevNet only.
    /// * `testnet-local-allowed` — TestNet only.
    /// * `production-custody-required` — fails closed because no
    ///   real KMS/HSM/RemoteSigner backend is implemented.
    /// * `mainnet-production-custody-required` — fails closed; in
    ///   addition, MainNet peer-driven apply remains the
    ///   Run 147/148/152 FATAL refusal regardless of this selector.
    ///
    /// **Default behavior unchanged:** when this flag and the
    /// `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` environment
    /// variable are both absent, the resolved policy is
    /// [`qbind_node::pqc_authority_custody::AuthorityCustodyPolicy::Disabled`]
    /// — old no-custody v2 ratification sidecars remain bit-for-bit
    /// compatible (Runs 134/136/138/142/148/150/152/161/165/167/169/
    /// 170/178/180/184/186/188/190 invariants).
    ///
    /// **Precedence:** when both this CLI flag and the env var are
    /// supplied, the CLI flag wins. Either source is sufficient.
    /// Invalid / unknown values are surfaced as a typed
    /// [`qbind_node::pqc_authority_custody_policy_surface::AuthorityCustodyPolicySelectorParseError`]
    /// — the resolver never silently falls back to `Disabled` when an
    /// explicit value is present but invalid.
    ///
    /// **NOT** a real KMS/HSM/cloud-KMS/PKCS#11/remote-signer backend,
    /// **NOT** a governance execution engine, **NOT** a real on-chain
    /// proof verifier, **NOT** a validator-set rotation primitive,
    /// **NOT** an autonomous-apply / apply-on-receipt / peer-majority
    /// authority claim, and **NOT** sufficient to enable MainNet peer-
    /// driven apply.
    ///
    /// Run 192 is source/test selector wiring only. Release-binary
    /// custody-policy selector evidence is deferred to Run 193. See
    /// `task/RUN_192_TASK.txt` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_192.md`.
    #[arg(
        long = "p2p-trust-bundle-authority-custody-policy",
        value_name = "POLICY",
        hide = true
    )]
    pub p2p_trust_bundle_authority_custody_policy: Option<String>,

    /// Run 198 — hidden, **disabled-by-default** RemoteSigner policy
    /// selector for the seven production v2 marker-decision preflight
    /// contexts (reload-check / reload-apply / startup
    /// `--p2p-trust-bundle` / SIGHUP / local peer-candidate-check /
    /// live inbound `0x05` / peer-driven drain).
    ///
    /// Recognized values (case-insensitive):
    ///
    /// * `disabled` — default. Refuses every RemoteSigner attempt. Old
    ///   no-RemoteSigner payloads remain accepted exactly as before
    ///   Run 198 (Run 196 compatibility).
    /// * `fixture-loopback-allowed` — DevNet/TestNet evidence only.
    ///   MainNet rejects fixture loopback material before it can satisfy
    ///   production RemoteSigner.
    /// * `production-remote-signer-required` — fails closed because no
    ///   real RemoteSigner backend is implemented.
    /// * `mainnet-production-remote-signer-required` — fails closed; in
    ///   addition, MainNet peer-driven apply remains the
    ///   Run 147/148/152 FATAL refusal regardless of this selector.
    ///
    /// **Default behavior unchanged:** when this flag and the
    /// `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` environment
    /// variable are both absent, the resolved policy is
    /// [`qbind_node::pqc_remote_authority_signer::RemoteSignerPolicy::Disabled`]
    /// — old no-RemoteSigner v2 ratification sidecars remain bit-for-bit
    /// compatible (Run 196 invariants).
    ///
    /// **Precedence:** when both this CLI flag and the env var are
    /// supplied, the CLI flag wins. Either source is sufficient.
    /// Invalid / unknown values are surfaced as a typed
    /// [`qbind_node::pqc_remote_signer_policy_surface::RemoteSignerPolicySelectorParseError`]
    /// — the resolver never silently falls back to `Disabled` when an
    /// explicit value is present but invalid.
    ///
    /// **NOT** a real RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11
    /// backend, **NOT** a networked signer service, **NOT** a governance
    /// execution engine, **NOT** a real on-chain proof verifier, **NOT**
    /// a validator-set rotation primitive, **NOT** an autonomous-apply /
    /// apply-on-receipt / peer-majority authority claim, and **NOT**
    /// sufficient to enable MainNet peer-driven apply.
    ///
    /// Run 198 is source/test selector wiring only. Release-binary
    /// RemoteSigner-policy selector evidence is deferred to Run 199. See
    /// `task/RUN_198_TASK.txt` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_198.md`.
    #[arg(
        long = "p2p-trust-bundle-remote-signer-policy",
        value_name = "POLICY",
        hide = true
    )]
    pub p2p_trust_bundle_remote_signer_policy: Option<String>,

    /// Run 151 — hidden, **disabled-by-default** DevNet/TestNet-only
    /// **explicit local one-shot drain trigger** for the Run 150
    /// peer-driven apply drain controller
    /// (`pqc_peer_candidate_drain::PeerDrivenApplyDrain`). When this
    /// flag is present, the binary arms the Run 150 drain controller
    /// alongside the Run 148 peer-driven apply controller already
    /// armed by `--p2p-trust-bundle-peer-candidate-apply-enabled` and
    /// declares — via the
    /// `[run-151] live peer-driven apply drain trigger ARMED` banner
    /// — that the binary is prepared to drain at most one eligible
    /// staged peer candidate per trigger fire into the Run 148
    /// controller and through it the existing Run 070 apply contract.
    ///
    /// **Strictly explicit / local / operator-controlled.** The flag
    /// is the smallest hidden source delta Run 151 adds in order to
    /// make the Run 150 source/test drain trigger reachable from the
    /// release binary at all. It introduces NO autonomous background
    /// drain task, NO automatic apply on receipt, NO peer-majority
    /// authority, NO new apply algorithm, NO new wire format, NO new
    /// trust-bundle / ratification-sidecar / authority-marker /
    /// sequence-file / peer-candidate-envelope schema change, NO new
    /// metric family, and NO bypass of any Run 142 v2 validation /
    /// Run 145 staging / Run 130 verifier / Run 132/142 marker
    /// pre-apply / Run 055 anti-rollback / Run 065/091 activation
    /// gate.
    ///
    /// **Requires `--p2p-trust-bundle-peer-candidate-apply-enabled`**
    /// at the binary level, which itself transitively requires
    /// `--p2p-trust-bundle-peer-candidate-staging-enabled` and
    /// `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`.
    /// Without the Run 148 apply arming flag the drain controller
    /// would have nothing to delegate to; supplying this Run 151 flag
    /// without the Run 148 flag is refused fail-closed at startup
    /// with the `[binary] Run 151: FATAL` line and exit code 1, and
    /// the P2P transport is never brought up.
    ///
    /// **MainNet is refused unconditionally** even when this flag is
    /// set: the binary aborts with a fatal `[binary] Run 151: FATAL`
    /// line and exit code 1; the P2P transport is never brought up.
    /// Local peer majority is NOT authority on MainNet. The refusal
    /// is enforced at the top-level CLI gate (before the Run 149
    /// apply gate is consulted) and the Run 150
    /// `PeerDrivenDrainPolicy::mainnet_attempted()` continues to
    /// return `PeerDrivenDrainOutcome::MainNetRefused` defensively at
    /// the drain controller layer even if the gate is ever loosened.
    ///
    /// **Concurrency-guarded.** The Run 150
    /// `PeerDrivenApplyDrain` controller carries an
    /// `Arc<AtomicBool>` in-progress flag (RAII-released). At most
    /// one trigger may enter the drain pipeline; concurrent triggers
    /// observe `AlreadyInProgress` and short-circuit. No double
    /// apply, no double sequence write, no double marker write, no
    /// double session eviction is possible.
    ///
    /// **At most one candidate per trigger.** The trigger drains a
    /// single eligible staged candidate; bulk / autonomous /
    /// background drains are explicitly out of scope.
    ///
    /// **Never calls Run 070 directly from `main.rs`.** The trigger
    /// routes through the Run 150 drain → Run 148 controller → Run
    /// 070 `apply_validated_candidate_with_previous` pipeline only.
    /// The v2 authority marker is persisted strictly **after** Run
    /// 055 `commit_sequence` succeeds via the existing
    /// `V2MarkerCoordinator` post-commit boundary, matching Run
    /// 134/136/138 discipline.
    ///
    /// See `task/RUN_151_TASK.txt`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`, and
    /// `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    #[arg(
        long = "p2p-trust-bundle-peer-candidate-drain-once",
        hide = true
    )]
    pub p2p_trust_bundle_peer_candidate_drain_once: bool,

    /// Run 105 — disabled-by-default operator opt-in flag for the
    /// **non-mutating bundle-signing-key ratification enforcement**
    /// layer. Without this flag, supplying `--p2p-trust-bundle-ratification
    /// <PATH>` is refused as a configuration error so the operator
    /// can never accidentally "arm" enforcement by typing the path
    /// flag alone.
    ///
    /// With this flag plus a path, the binary loads the sidecar
    /// JSON ratification, calls
    /// `qbind_ledger::enforce_bundle_signing_key_ratification`, and
    /// fails closed BEFORE any mutation side effect on the three
    /// non-mutating validation surfaces (Run 050/051/053/057/062/065
    /// startup preflight, Run 069 reload-check, Run 077 peer-candidate
    /// check). On MainNet/TestNet, supplying this flag without a
    /// `--p2p-trust-bundle-ratification` path is fatal.
    ///
    /// **This is NOT live propagation, NOT reload-apply, NOT
    /// SIGHUP, NOT a network listener.** It is the smallest safe
    /// non-mutating enforcement primitive. See
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md`.
    #[arg(
        long = "p2p-trust-bundle-ratification-enforcement-enabled",
        hide = true
    )]
    pub p2p_trust_bundle_ratification_enforcement_enabled: bool,

    /// Run 105 — operator-supplied local file path of a
    /// [`qbind_ledger::BundleSigningRatification`] sidecar JSON
    /// document binding the candidate trust bundle's signing key to a
    /// genesis-bound bundle-signing authority root.
    ///
    /// Requires `--p2p-trust-bundle-ratification-enforcement-enabled`.
    /// Disabled by default. Local file only — no network input, no
    /// peer / gossip input. The file is read once, parsed, passed to
    /// the Run 103/105 verifier, and the binary either proceeds or
    /// fails closed with a typed reason. The file is NEVER written;
    /// no on-disk persistence is touched.
    ///
    /// Used by:
    ///   * `--p2p-trust-bundle` (startup preflight),
    ///   * `--p2p-trust-bundle-reload-check` (Run 069 validation-only),
    ///   * `--p2p-trust-bundle-peer-candidate-check` (Run 077
    ///     validation-only).
    ///
    /// On MainNet under enforcement-enabled, this flag is REQUIRED;
    /// on TestNet it is REQUIRED unless
    /// `--p2p-trust-bundle-allow-unratified-testnet` is also
    /// supplied; on DevNet it is OPTIONAL.
    #[arg(long = "p2p-trust-bundle-ratification", hide = true)]
    pub p2p_trust_bundle_ratification: Option<PathBuf>,

    /// Run 105 — DevNet/TestNet-only escape hatch that permits an
    /// unratified bundle-signing key when no
    /// `--p2p-trust-bundle-ratification` sidecar is supplied. Refused
    /// on MainNet (the enforcer itself refuses the legacy policy on
    /// MainNet, defense in depth).
    ///
    /// When this flag is supplied AND no ratification path is set,
    /// the enforcement layer returns
    /// `RatificationEnforcementOutcome::LegacyUnratifiedAccepted`
    /// rather than failing — the verdict is logged loudly and is
    /// explicitly NOT a "passed" outcome.
    #[arg(
        long = "p2p-trust-bundle-allow-unratified-testnet-devnet",
        hide = true
    )]
    pub p2p_trust_bundle_allow_unratified_testnet_devnet: bool,

    // ========================================================================
    // Node Identity & Storage
    // ========================================================================
    /// Validator ID (0-based index).
    ///
    /// The validator's index in the validator set.
    #[arg(long = "validator-id", short = 'v')]
    pub validator_id: Option<u64>,

    /// Data directory for persistent state.
    ///
    /// When specified, enables persistent storage (e.g., RocksDB for VM v0).
    /// When not specified, uses in-memory state only.
    #[arg(long = "data-dir", short = 'd')]
    pub data_dir: Option<PathBuf>,

    /// B3: Restore-from-snapshot startup path.
    ///
    /// When specified, the node will validate the snapshot directory at
    /// `<PATH>` (expected to contain `meta.json` + `state/` per the
    /// `StateSnapshotter` format) and materialize its `state/` checkpoint
    /// into `<data-dir>/state_vm_v0` before starting consensus.
    ///
    /// Requires `--data-dir` to be set. Fails clearly and loudly (non-zero
    /// exit) if the snapshot is missing, has the wrong chain id, has the
    /// wrong layout, or if the target state directory is already populated.
    ///
    /// See `crates/qbind-node/src/snapshot_restore.rs` and
    /// `docs/whitepaper/contradiction.md` C4 (B3).
    #[arg(long = "restore-from-snapshot")]
    pub restore_from_snapshot: Option<PathBuf>,

    // ========================================================================
    // P2P Tuning
    // ========================================================================
    /// Maximum outbound P2P connections.
    ///
    /// Default: 16
    #[arg(long = "p2p-max-outbound", default_value = "16")]
    pub p2p_max_outbound: usize,

    /// Maximum inbound P2P connections.
    ///
    /// Default: 64
    #[arg(long = "p2p-max-inbound", default_value = "64")]
    pub p2p_max_inbound: usize,

    /// P2P gossip fanout.
    ///
    /// Number of peers to forward gossip messages to.
    /// Default: 6
    #[arg(long = "p2p-gossip-fanout", default_value = "6")]
    pub p2p_gossip_fanout: usize,

    // ========================================================================
    // T206: P2P Diversity Mode (Anti-Eclipse)
    // ========================================================================
    /// P2P diversity enforcement mode: off, warn, or enforce (T206).
    ///
    /// Controls anti-eclipse IP-prefix diversity constraints:
    /// - off: No diversity checks (DevNet, TestNet Alpha default)
    /// - warn: Log warnings but allow connections (TestNet Beta default)
    /// - enforce: Reject connections that violate limits (MainNet required)
    ///
    /// MainNet profile requires `enforce` mode.
    #[arg(long = "p2p-diversity-mode")]
    pub p2p_diversity_mode: Option<String>,

    // ========================================================================
    // T208: State Retention Configuration
    // ========================================================================
    /// State retention mode: disabled or height (T208).
    ///
    /// Controls how the node manages historical state data:
    /// - disabled: Retain all historical state (DevNet, TestNet Alpha default)
    /// - height: Prune state below `current_height - retain_height` (TestNet Beta, MainNet default)
    ///
    /// MainNet profile requires `height` mode for disk space management.
    #[arg(long = "state-retention-mode")]
    pub state_retention_mode: Option<String>,

    /// Number of blocks of history to retain when state-retention-mode is 'height' (T208).
    ///
    /// State data below `current_height - retain_height` may be pruned.
    ///
    /// Recommended values:
    /// - TestNet Beta: 100_000 (~6 days at 5s blocks)
    /// - MainNet: 500_000 (~30 days at 5s blocks)
    #[arg(long = "state-retain-height")]
    pub state_retain_height: Option<u64>,

    /// Interval (in committed blocks) between state pruning runs (T208).
    ///
    /// Pruning is triggered every N blocks to amortize the cost.
    ///
    /// Default: 1_000 blocks (~83 minutes at 5s blocks)
    #[arg(long = "state-prune-interval")]
    pub state_prune_interval: Option<u64>,

    // ========================================================================
    // T215/B15: State Snapshot Configuration
    // ========================================================================
    /// Directory where in-process VM-v0 snapshots are written.
    ///
    /// When set with `--execution-profile vm-v0 --data-dir <DIR>`, the running
    /// validator installs the bounded SIGUSR1 snapshot trigger and, when
    /// `--snapshot-interval-blocks` is non-zero, the committed-height periodic
    /// trigger. Both write snapshots to `<PATH>/<committed_height>/` using the
    /// opened `<data-dir>/state_vm_v0` RocksDB handle.
    #[arg(long = "snapshot-dir")]
    pub snapshot_dir: Option<PathBuf>,

    /// Committed-block interval for snapshot configuration.
    ///
    /// When paired with `--snapshot-dir`, the binary checks committed anchors
    /// and creates a VM-v0 snapshot at positive interval heights.
    #[arg(long = "snapshot-interval-blocks")]
    pub snapshot_interval_blocks: Option<u64>,

    /// Maximum number of numeric snapshot directories to retain.
    #[arg(long = "snapshot-max-snapshots")]
    pub snapshot_max_snapshots: Option<u32>,

    // ========================================================================
    // T210: Signer Mode Configuration
    // ========================================================================
    /// Signer mode for validator key management (T210).
    ///
    /// Controls how the validator signing key is stored and accessed:
    /// - loopback-testing: In-memory keys for testing (DevNet only, forbidden on MainNet)
    /// - encrypted-fs: Encrypted filesystem keystore (recommended for TestNet/MainNet)
    /// - remote-signer: External signer service via gRPC/Unix socket
    /// - hsm-pkcs11: Hardware Security Module via PKCS#11 interface
    ///
    /// MainNet profile forbids 'loopback-testing' mode.
    #[arg(long = "signer-mode")]
    pub signer_mode: Option<String>,

    /// Path to the encrypted keystore directory (T210).
    ///
    /// Required when signer-mode is 'encrypted-fs'.
    /// The keystore stores validator signing keys encrypted at rest.
    ///
    /// Example: /data/qbind/keystore
    #[arg(long = "signer-keystore-path")]
    pub signer_keystore_path: Option<PathBuf>,

    /// URL for the remote signer service (T210).
    ///
    /// Required when signer-mode is 'remote-signer'.
    /// Supports grpc://, http://, or unix:// schemes.
    ///
    /// Examples:
    /// - grpc://localhost:50051
    /// - unix:///var/run/qbind-signer.sock
    #[arg(long = "remote-signer-url")]
    pub remote_signer_url: Option<String>,

    /// Path to the HSM/PKCS#11 configuration file (T210).
    ///
    /// Required when signer-mode is 'hsm-pkcs11'.
    /// Contains PKCS#11 library path, slot ID, and key label.
    ///
    /// Example: /etc/qbind/hsm.toml
    #[arg(long = "hsm-config-path")]
    pub hsm_config_path: Option<PathBuf>,

    // ========================================================================
    // T232: Genesis Configuration
    // ========================================================================
    /// Path to the external genesis configuration file (T232).
    ///
    /// Required for MainNet. Optional for DevNet/TestNet (uses embedded genesis if not provided).
    /// The file must be a valid JSON file conforming to the GenesisConfig schema.
    ///
    /// Example: /etc/qbind/genesis.json
    #[arg(long = "genesis-path")]
    pub genesis_path: Option<PathBuf>,

    // ========================================================================
    // T233 / Run 102: Genesis Hash Commitment & Verification
    // ========================================================================
    /// Print the canonical Run 101 genesis hash of the parsed genesis file and exit.
    ///
    /// Run 102 update: this flag now computes the **canonical Run 101 genesis
    /// hash** over the *parsed* `GenesisConfig` — that is, a SHA3-256 over a
    /// length-prefixed canonical encoding of `chain_id`, `genesis_time_unix_ms`,
    /// the validator set, allocations, council config, monetary config, and the
    /// `authority` block — under the environment policy resolved from `--env`
    /// (DEV / TST / MAIN). It is **not** a hash over the exact file bytes; two
    /// JSON files that differ only in whitespace or key ordering produce the
    /// same canonical hash, while two files that differ in any authority,
    /// chain_id, or validator field produce different canonical hashes.
    ///
    /// Requires `--genesis-path` to be specified. Malformed genesis files are
    /// rejected with a clear error and a non-zero exit code; there is no
    /// raw-file-byte fallback.
    ///
    /// The printed value is a `0x`-prefixed 64-char lowercase hex string and
    /// can be pasted verbatim into `--expect-genesis-hash` to pin the
    /// canonical hash for subsequent startups.
    ///
    /// Example:
    /// ```bash
    /// qbind-node --print-genesis-hash --genesis-path /etc/qbind/genesis.json --env mainnet
    /// ```
    ///
    /// See `crates/qbind-node/src/pqc_boot_genesis.rs`,
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md`, and
    /// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
    #[arg(long = "print-genesis-hash")]
    pub print_genesis_hash: bool,

    /// Expected canonical Run 101 genesis hash (T233 + Run 102).
    ///
    /// When set, qbind-node loads the configured `--genesis-path`, parses it
    /// as a `GenesisConfig`, computes the canonical Run 101 genesis hash
    /// under the resolved environment policy, and compares it against this
    /// expected value. On mismatch, malformed genesis, missing authority
    /// (on MainNet/TestNet), or any other Run 101 verification failure the
    /// release binary refuses to start with a precise typed error — before
    /// any trust-bundle / network / consensus startup begins.
    ///
    /// Accepts hex string with or without `0x` prefix (64 hex characters).
    ///
    /// **Required for MainNet**: MainNet validators MUST specify this flag.
    /// The T233 `MainnetConfigError::ExpectedGenesisHashMissing` shield in
    /// `validate_mainnet_invariants` composes with the Run 102 canonical
    /// verification — the shield refuses MainNet startup if the flag is
    /// absent, and the Run 102 verifier refuses startup if the flag's value
    /// does not match the parsed canonical hash.
    ///
    /// Example:
    /// ```bash
    /// qbind-node --profile mainnet \
    ///   --genesis-path /etc/qbind/genesis.json \
    ///   --expect-genesis-hash 0xabc123...
    /// ```
    #[arg(long = "expect-genesis-hash")]
    pub expect_genesis_hash: Option<String>,

    // ========================================================================
    // T219: Mempool Eviction Rate Limiting Configuration
    // ========================================================================
    /// Mempool eviction rate limiting mode: off, warn, or enforce (T219).
    ///
    /// Controls how the mempool handles eviction rate limiting:
    /// - off: No rate limiting (DevNet default)
    /// - warn: Log warnings but still evict (TestNet Alpha)
    /// - enforce: Reject incoming txs instead of exceeding limit (MainNet required)
    ///
    /// MainNet profile requires `enforce` mode.
    #[arg(long = "mempool-eviction-mode")]
    pub mempool_eviction_mode: Option<String>,

    /// Maximum evictions allowed per interval (T219).
    ///
    /// When the eviction count reaches this limit within the interval,
    /// behavior depends on the eviction mode.
    ///
    /// Recommended values:
    /// - DevNet: 10,000 (very loose)
    /// - TestNet Alpha: 5,000 (moderate)
    /// - TestNet Beta: 2,000 (tighter)
    /// - MainNet: 1,000 (conservative)
    #[arg(long = "mempool-eviction-max-per-interval")]
    pub mempool_eviction_max_per_interval: Option<u32>,

    /// Eviction rate measurement interval in seconds (T219).
    ///
    /// The eviction counter is reset when this interval elapses.
    ///
    /// Default: 10 seconds
    #[arg(long = "mempool-eviction-interval-secs")]
    pub mempool_eviction_interval_secs: Option<u32>,

    /// Run 035 — opt-in dev/test-only forged Timeout/NewView injection harness.
    ///
    /// Hidden, dev/test-only. The harness is **disabled by default**.
    /// Activation requires THREE concurrent signals:
    ///
    /// 1. `--env devnet` (this binary refuses activation on Testnet/Mainnet),
    /// 2. environment variable `QBIND_DEVNET_FORGED_INJECTION=1` (an
    ///    affirmative second step the operator must take outside the
    ///    CLI), and
    /// 3. one or more `--devnet-forged-inject CASE` flags listing the
    ///    forged cases to inject.
    ///
    /// Valid CASE tokens: `malformed-timeout`, `unsigned-timeout`,
    /// `bad-signature-timeout`, `wrong-suite-timeout`,
    /// `unknown-validator-timeout`, `malformed-newview`,
    /// `missing-evidence-newview`, `duplicate-signer-newview`,
    /// `insufficient-quorum-newview`, `mixed-view-newview`,
    /// `bad-signature-newview`, `high-qc-mismatch-newview`.
    ///
    /// Each invocation injects a single crafted frame into the same
    /// inbound `mpsc<ConsensusNetMsg>` channel real P2P traffic uses;
    /// frames traverse the same binary-loop verification gate as live
    /// inbound network frames (`verify_timeout_msg` /
    /// `verify_timeout_certificate_with_evidence` BEFORE
    /// `engine.on_timeout_msg` / `engine.on_timeout_certificate`).
    /// The harness never calls into the engine and never fabricates
    /// metrics. See
    /// `crates/qbind-node/src/forged_injection.rs` and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md`.
    #[arg(long = "devnet-forged-inject", action = clap::ArgAction::Append, hide = true)]
    pub devnet_forged_inject: Vec<String>,

    /// Run 096 — disabled-by-default local-operator-gated canonical
    /// reconfig proposal trigger (DevNet/TestNet only; refused on
    /// MainNet).
    ///
    /// When set to a non-zero value N strictly greater than the
    /// engine's current epoch, the binary's underlying
    /// `BasicHotStuffEngine` arms a single-shot reconfig proposal
    /// intent: the next leader-step tick that produces a proposal
    /// will emit a canonical `BlockHeader { payload_kind:
    /// PAYLOAD_KIND_RECONFIG, next_epoch: N, .. }` block instead of a
    /// normal block, using the same proposal construction path,
    /// block-id derivation, signing path, and HotStuff structures.
    /// After that single emission the intent is cleared and the node
    /// returns to normal proposals — Run 096 is intentionally
    /// one-shot. If the reconfig block then commits through the
    /// existing HotStuff commit rule, the Run 095 detector fires
    /// `engine.transition_to_epoch(...)` and the Run 094 persistence
    /// hook writes `meta:current_epoch = CommittedEpoch(N)`.
    ///
    /// **What this flag is NOT.** It is not a parallel reconfig wire
    /// format (it uses the existing canonical
    /// `(payload_kind, next_epoch)` header fields); not a redesign
    /// of HotStuff commit rules; not a redesign of epoch semantics;
    /// not a validator-set rotation primitive (the existing
    /// `transition_to_epoch` machinery does that); not peer-driven
    /// live apply; not a height/view/wall-clock-derived epoch (the
    /// value is exactly the operator-supplied N); not a
    /// `pqc_trust_activation::ActivationContext` change; not a
    /// trust-bundle wire-format or peer-propagation surface; not
    /// KMS/HSM custody; not a filesystem watcher.
    ///
    /// **Preconditions** (fail-closed):
    /// - `N` must be `>= 1`. `N == 0` is refused at startup.
    /// - `N` must be strictly greater than the engine's current
    ///   epoch at intent-arm time (the engine re-validates).
    /// - The environment must NOT be MainNet — MainNet refuses
    ///   this flag at startup with a clear error.
    /// - The flag is hidden because it is evidence-only.
    ///
    /// Operators who use it MUST read
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_096.md` for the
    /// staging-vs-commit boundary.
    #[arg(long = "devnet-reconfig-proposal-next-epoch", hide = true)]
    pub devnet_reconfig_proposal_next_epoch: Option<u64>,

    // ========================================================================
    // Run 127 — offline authority-state reset
    // ========================================================================
    /// Run 127 — trigger the offline authority-state reset ceremony.
    ///
    /// When this flag is present the binary exits BEFORE any normal node
    /// startup (networking, consensus, metrics, SIGHUP handlers, reload
    /// tasks, and peer-candidate dispatch are never installed).
    ///
    /// **Required companion flags:**
    ///   * `--data-dir` — resolved marker path.
    ///   * `--genesis-path` — external genesis JSON file.
    ///   * `--expect-genesis-hash` — canonical Run 101 genesis hash.
    ///   * `--p2p-trust-bundle` — candidate signed trust-bundle.
    ///   * `--p2p-trust-bundle-ratification` — ratification sidecar.
    ///   * `--authority-state-reset-output-audit` — audit record path.
    ///
    /// **Environment policy:** DevNet/TestNet allowed; MainNet REFUSED.
    ///
    /// Hidden because it is an operator ceremony command.
    #[arg(long = "authority-state-reset", hide = true)]
    pub authority_state_reset: bool,

    /// Run 127 — output path for the authority-state-reset audit record.
    ///
    /// Required when `--authority-state-reset` is present.
    #[arg(long = "authority-state-reset-output-audit", hide = true)]
    pub authority_state_reset_output_audit: Option<PathBuf>,

    /// Run 127 — optional operator ceremony note for the audit record.
    ///
    /// When supplied, its SHA3-256 fingerprint is embedded in the audit
    /// record (raw text is never stored).
    #[arg(long = "authority-state-reset-operator-note", hide = true)]
    pub authority_state_reset_operator_note: Option<String>,
}

// ============================================================================
// CLI Error Types
// ============================================================================

/// Errors that can occur during CLI argument parsing and validation.
#[derive(Debug, Clone)]
pub enum CliError {
    /// Invalid environment string.
    InvalidEnvironment(ParseEnvironmentError),
    /// Invalid socket address.
    InvalidAddress {
        field: String,
        value: String,
        reason: String,
    },
    /// Configuration validation error.
    ConfigValidation(String),
    /// Invalid profile string (T180, T185).
    InvalidProfile(String),
    /// MainNet configuration invariant violation (T185).
    MainnetConfigInvalid(String),
    /// Invalid DAG coupling mode string (T189).
    InvalidDagCouplingMode(String),
    /// Invalid monetary mode string (T197).
    InvalidMonetaryMode(String),
    /// Invalid diversity mode string (T206).
    InvalidDiversityMode(String),
    /// Invalid state retention mode string (T208).
    InvalidStateRetentionMode(String),
    /// Invalid signer mode string (T210).
    InvalidSignerMode(String),
    /// Invalid eviction rate mode string (T219).
    InvalidEvictionRateMode(String),
    /// Invalid genesis hash string (T233).
    InvalidGenesisHash(String),
    /// Genesis path required but not provided (T233).
    GenesisPathRequired(String),
    /// Run 033: invalid `--validator-consensus-key` spec.
    InvalidValidatorConsensusKey(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::InvalidEnvironment(e) => write!(f, "invalid environment: {}", e),
            CliError::InvalidAddress {
                field,
                value,
                reason,
            } => {
                write!(f, "invalid {} '{}': {}", field, value, reason)
            }
            CliError::ConfigValidation(msg) => write!(f, "config validation error: {}", msg),
            CliError::InvalidProfile(s) => {
                write!(
                    f,
                    "invalid profile '{}': expected 'devnet-v0', 'testnet-alpha', 'testnet-beta', or 'mainnet'",
                    s
                )
            }
            CliError::MainnetConfigInvalid(msg) => {
                write!(f, "MainNet configuration invalid: {}", msg)
            }
            CliError::InvalidDagCouplingMode(s) => {
                write!(
                    f,
                    "invalid dag-coupling-mode '{}': expected 'off', 'warn', or 'enforce'",
                    s
                )
            }
            CliError::InvalidMonetaryMode(s) => {
                write!(
                    f,
                    "invalid monetary-mode '{}': expected 'off', 'shadow', or 'active'",
                    s
                )
            }
            CliError::InvalidDiversityMode(s) => {
                write!(
                    f,
                    "invalid p2p-diversity-mode '{}': expected 'off', 'warn', or 'enforce'",
                    s
                )
            }
            CliError::InvalidStateRetentionMode(s) => {
                write!(
                    f,
                    "invalid state-retention-mode '{}': expected 'disabled' or 'height'",
                    s
                )
            }
            CliError::InvalidSignerMode(s) => {
                write!(
                    f,
                    "invalid signer-mode '{}': expected 'loopback-testing', 'encrypted-fs', 'remote-signer', or 'hsm-pkcs11'",
                    s
                )
            }
            CliError::InvalidEvictionRateMode(s) => {
                write!(
                    f,
                    "invalid mempool-eviction-mode '{}': expected 'off', 'warn', or 'enforce'",
                    s
                )
            }
            CliError::InvalidGenesisHash(msg) => {
                write!(f, "invalid genesis hash: {}", msg)
            }
            CliError::GenesisPathRequired(msg) => {
                write!(f, "genesis path required: {}", msg)
            }
            CliError::InvalidValidatorConsensusKey(msg) => {
                write!(
                    f,
                    "invalid --validator-consensus-key: {} (expected 'VID:SUITE:HEXPK')",
                    msg
                )
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<ParseEnvironmentError> for CliError {
    fn from(e: ParseEnvironmentError) -> Self {
        CliError::InvalidEnvironment(e)
    }
}

// ============================================================================
// CLI Argument Processing
// ============================================================================

impl CliArgs {
    /// Parse CLI arguments from the command line.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parse a socket address from a string.
    pub fn parse_addr(s: &str, field: &str) -> Result<SocketAddr, CliError> {
        s.parse().map_err(|e| CliError::InvalidAddress {
            field: field.to_string(),
            value: s.to_string(),
            reason: format!("{}", e),
        })
    }

    /// Build a NodeConfig from CLI arguments.
    ///
    /// This method parses and validates all CLI arguments, building a complete
    /// NodeConfig suitable for node startup.
    ///
    /// # T180: Profile-Based Configuration
    ///
    /// If `--profile` is specified, the base configuration comes from the
    /// corresponding preset (devnet-v0, testnet-alpha, testnet-beta).
    /// Individual flags then override specific values.
    ///
    /// # Returns
    ///
    /// `Ok(NodeConfig)` if all arguments are valid.
    /// `Err(CliError)` if any argument is invalid.
    pub fn to_node_config(&self) -> Result<NodeConfig, CliError> {
        // T180: If a profile is specified, start from the preset
        let mut config = if let Some(ref profile_str) = self.profile {
            match parse_config_profile(profile_str) {
                Some(profile) => {
                    let preset = NodeConfig::from_profile(profile);
                    // Log that we're using a profile
                    eprintln!(
                        "[T180] Using configuration profile: {} (gas={}, fee-priority={}, mempool={}, network={})",
                        profile,
                        if preset.gas_enabled { "on" } else { "off" },
                        if preset.enable_fee_priority { "on" } else { "off" },
                        preset.mempool_mode,
                        preset.network_mode
                    );
                    preset
                }
                None => {
                    return Err(CliError::InvalidProfile(profile_str.clone()));
                }
            }
        } else {
            // No profile specified, build from individual flags (legacy behavior)
            // Parse environment
            let environment = parse_environment(&self.environment)?;

            // Parse execution profile
            let execution_profile = parse_execution_profile(&self.execution_profile);

            // Parse network mode
            let network_mode = parse_network_mode(&self.network_mode);

            // Parse P2P listen address
            let listen_addr = if self.enable_p2p && network_mode == NetworkMode::P2p {
                Some(self.p2p_listen_addr.clone())
            } else {
                None
            };

            // Parse P2P advertised address
            let advertised_addr = self.p2p_advertised_addr.clone();

            // Collect static peers
            let static_peers = self.p2p_peers.clone();

            // Build NetworkTransportConfig
            let network = NetworkTransportConfig {
                enable_p2p: self.enable_p2p,
                max_outbound: self.p2p_max_outbound,
                max_inbound: self.p2p_max_inbound,
                gossip_fanout: self.p2p_gossip_fanout,
                listen_addr,
                advertised_addr,
                static_peers,
                static_peer_consensus_keys: Vec::new(),
                // T205: Discovery defaults (disabled for legacy path)
                discovery_enabled: false,
                discovery_interval_secs: 30,
                max_known_peers: 200,
                target_outbound_peers: 8,
                // T205: Liveness defaults
                liveness_probe_interval_secs: 30,
                liveness_failure_threshold: 3,
                liveness_min_score: 30,
                // T206: Diversity defaults (Off for legacy path)
                diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Off,
                max_peers_per_ipv4_prefix24: 2,
                max_peers_per_ipv4_prefix16: 8,
                min_outbound_diversity_buckets: 4,
                max_single_bucket_fraction_bps: 2500,
            };

            NodeConfig {
                environment,
                execution_profile,
                data_dir: self.data_dir.clone(),
                network,
                network_mode,
                gas_enabled: false,
                enable_fee_priority: false,
                mempool_mode: MempoolMode::Fifo,
                dag_availability_enabled: false,
                dag_coupling_mode: DagCouplingMode::Off,
                stage_b_enabled: false,
                fee_distribution_policy: FeeDistributionPolicy::burn_only(), // T193
                // T197: Default to Off for backward compatibility
                monetary_mode: MonetaryMode::Off,
                monetary_accounts: None,
                seigniorage_split: SeigniorageSplit::default(),
                // T208: State retention disabled by default for legacy path
                state_retention: StateRetentionConfig::disabled(),
                // T215: Snapshots disabled for legacy path
                snapshot_config: SnapshotConfig::disabled(),
                fast_sync_config: FastSyncConfig::disabled(),
                // T210: Loopback signer for legacy path (testing default)
                signer_mode: SignerMode::LoopbackTesting,
                signer_keystore_path: None,
                remote_signer_url: None,
                // M10.1: Remote signer KEMTLS cert paths
                remote_signer_cert_path: None,
                remote_signer_client_cert_path: None,
                remote_signer_client_key_path: None,
                hsm_config_path: None,
                // T214: Exit on failure is the default
                signer_failure_mode: SignerFailureMode::ExitOnFailure,
                // T218: DevNet-style loose limits for legacy path
                mempool_dos: MempoolDosConfig::devnet_default(),
                // T219: DevNet-style loose limits for legacy path
                mempool_eviction: MempoolEvictionConfig::devnet_default(),
                // T226: DevNet discovery and liveness defaults for legacy path
                p2p_discovery: P2pDiscoveryConfig::devnet_default(),
                p2p_liveness: P2pLivenessConfig::devnet_default(),
                // T231: DevNet anti-eclipse defaults for legacy path
                p2p_anti_eclipse: Some(P2pAntiEclipseConfig::devnet_default()),
                // T229: DevNet slashing defaults for legacy path
                slashing: SlashingConfig::devnet_default(),
                // M2: DevNet validator stake defaults for legacy path
                validator_stake: ValidatorStakeConfig::devnet_default(),
                // T232: DevNet genesis source defaults for legacy path
                genesis_source: GenesisSourceConfig::devnet_default(),
                // T233: No expected genesis hash by default
                expected_genesis_hash: None,
            }
        };

        // Apply CLI overrides on top of the base config (profile or legacy)
        // Only override if the flag was explicitly provided
        if let Some(gas) = self.enable_gas {
            if self.profile.is_some() {
                eprintln!("[T180] CLI override: gas_enabled = {}", gas);
            }
            config.gas_enabled = gas;
        }

        if let Some(fee_priority) = self.enable_fee_priority {
            if self.profile.is_some() {
                eprintln!(
                    "[T180] CLI override: enable_fee_priority = {}",
                    fee_priority
                );
            }
            config.enable_fee_priority = fee_priority;
        }

        if let Some(ref mempool_mode_str) = self.mempool_mode {
            let mode = parse_mempool_mode(mempool_mode_str);
            if self.profile.is_some() {
                eprintln!("[T180] CLI override: mempool_mode = {}", mode);
            }
            config.mempool_mode = mode;
        }

        if let Some(dag_avail) = self.enable_dag_availability {
            if self.profile.is_some() {
                eprintln!(
                    "[T180] CLI override: dag_availability_enabled = {}",
                    dag_avail
                );
            }
            config.dag_availability_enabled = dag_avail;
        }

        // T189: Apply DAG coupling mode override
        if let Some(ref coupling_mode_str) = self.dag_coupling_mode {
            match parse_dag_coupling_mode(coupling_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T189] CLI override: dag_coupling_mode = {}", mode);
                    }
                    config.dag_coupling_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidDagCouplingMode(coupling_mode_str.clone()));
                }
            }
        }

        // T197: Apply monetary mode override
        if let Some(ref monetary_mode_str) = self.monetary_mode {
            match parse_monetary_mode(monetary_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T197] CLI override: monetary_mode = {}", mode);
                    }
                    config.monetary_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidMonetaryMode(monetary_mode_str.clone()));
                }
            }
        }

        // T186: Apply Stage B override
        if let Some(stage_b) = self.enable_stage_b {
            if self.profile.is_some() {
                eprintln!("[T186] CLI override: stage_b_enabled = {}", stage_b);
            }
            config.stage_b_enabled = stage_b;
        }

        // T206: Apply diversity mode override
        if let Some(ref diversity_mode_str) = self.p2p_diversity_mode {
            match parse_diversity_mode(diversity_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T206] CLI override: diversity_mode = {}", mode);
                    }
                    config.network.diversity_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidDiversityMode(diversity_mode_str.clone()));
                }
            }
        }

        // T208: Apply state retention mode override
        if let Some(ref retention_mode_str) = self.state_retention_mode {
            match parse_state_retention_mode(retention_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T208] CLI override: state_retention.mode = {}", mode);
                    }
                    config.state_retention.mode = mode;
                }
                None => {
                    return Err(CliError::InvalidStateRetentionMode(
                        retention_mode_str.clone(),
                    ));
                }
            }
        }

        // T208: Apply state retain height override
        if let Some(retain_height) = self.state_retain_height {
            if self.profile.is_some() {
                eprintln!(
                    "[T208] CLI override: state_retention.retain_height = {}",
                    retain_height
                );
            }
            config.state_retention.retain_height = Some(retain_height);
        }

        // T208: Apply state prune interval override
        if let Some(prune_interval) = self.state_prune_interval {
            if self.profile.is_some() {
                eprintln!(
                    "[T208] CLI override: state_retention.prune_interval_blocks = {}",
                    prune_interval
                );
            }
            config.state_retention.prune_interval_blocks = prune_interval;
        }

        // T215/B15: Apply snapshot trigger/output configuration.
        if let Some(ref snapshot_dir) = self.snapshot_dir {
            if self.profile.is_some() {
                eprintln!(
                    "[T215] CLI override: snapshot_config.snapshot_dir = {}",
                    snapshot_dir.display()
                );
            }
            config.snapshot_config.enabled = true;
            config.snapshot_config.snapshot_dir = Some(snapshot_dir.clone());
        }
        if let Some(interval) = self.snapshot_interval_blocks {
            if self.profile.is_some() {
                eprintln!(
                    "[T215] CLI override: snapshot_config.snapshot_interval_blocks = {}",
                    interval
                );
            }
            config.snapshot_config.snapshot_interval_blocks = interval;
        }
        if let Some(max_snapshots) = self.snapshot_max_snapshots {
            if self.profile.is_some() {
                eprintln!(
                    "[T215] CLI override: snapshot_config.max_snapshots = {}",
                    max_snapshots
                );
            }
            config.snapshot_config.max_snapshots = max_snapshots.max(1);
        }

        // T210: Apply signer mode override
        if let Some(ref signer_mode_str) = self.signer_mode {
            match parse_signer_mode(signer_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T210] CLI override: signer_mode = {}", mode);
                    }
                    config.signer_mode = mode;
                }
                None => {
                    return Err(CliError::InvalidSignerMode(signer_mode_str.clone()));
                }
            }
        }

        // T210: Apply signer keystore path override
        if let Some(ref path) = self.signer_keystore_path {
            if self.profile.is_some() {
                eprintln!(
                    "[T210] CLI override: signer_keystore_path = {}",
                    path.display()
                );
            }
            config.signer_keystore_path = Some(path.clone());
        }

        // T210: Apply remote signer URL override
        if let Some(ref url) = self.remote_signer_url {
            if self.profile.is_some() {
                eprintln!("[T210] CLI override: remote_signer_url = {}", url);
            }
            config.remote_signer_url = Some(url.clone());
        }

        // T210: Apply HSM config path override
        if let Some(ref path) = self.hsm_config_path {
            if self.profile.is_some() {
                eprintln!("[T210] CLI override: hsm_config_path = {}", path.display());
            }
            config.hsm_config_path = Some(path.clone());
        }

        // T219: Apply mempool eviction mode override
        if let Some(ref eviction_mode_str) = self.mempool_eviction_mode {
            match parse_eviction_rate_mode(eviction_mode_str) {
                Some(mode) => {
                    if self.profile.is_some() {
                        eprintln!("[T219] CLI override: mempool_eviction.mode = {}", mode);
                    }
                    config.mempool_eviction.mode = mode;
                }
                None => {
                    return Err(CliError::InvalidEvictionRateMode(eviction_mode_str.clone()));
                }
            }
        }

        // T219: Apply mempool eviction max per interval override
        if let Some(max_evictions) = self.mempool_eviction_max_per_interval {
            if self.profile.is_some() {
                eprintln!(
                    "[T219] CLI override: mempool_eviction.max_evictions_per_interval = {}",
                    max_evictions
                );
            }
            config.mempool_eviction.max_evictions_per_interval = max_evictions;
        }

        // T219: Apply mempool eviction interval secs override
        if let Some(interval_secs) = self.mempool_eviction_interval_secs {
            if self.profile.is_some() {
                eprintln!(
                    "[T219] CLI override: mempool_eviction.interval_secs = {}",
                    interval_secs
                );
            }
            config.mempool_eviction.interval_secs = interval_secs;
        }

        // T232: Apply genesis path override
        if let Some(ref path) = self.genesis_path {
            if self.profile.is_some() {
                eprintln!(
                    "[T232] CLI override: genesis_source.genesis_path = {}",
                    path.display()
                );
            }
            config.genesis_source = GenesisSourceConfig::external(path.clone());
        }

        // T233: Apply expected genesis hash override
        if let Some(ref hash_str) = self.expect_genesis_hash {
            match parse_genesis_hash(hash_str) {
                Ok(hash) => {
                    if self.profile.is_some() {
                        eprintln!(
                            "[T233] CLI override: expected_genesis_hash = 0x{}...{}",
                            &hash_str.replace("0x", "")[..8],
                            &hash_str.replace("0x", "")[56..]
                        );
                    }
                    config.expected_genesis_hash = Some(hash);
                }
                Err(e) => {
                    return Err(CliError::InvalidGenesisHash(e));
                }
            }
        }

        // Apply data_dir if specified
        if let Some(ref data_dir) = self.data_dir {
            config.data_dir = Some(data_dir.clone());
        }

        // B3: Apply --restore-from-snapshot. We model this as a
        // `FastSyncConfig::from_snapshot(...)` so the existing config shape
        // is reused (no second config surface invented). The actual restore
        // is performed at startup by `snapshot_restore::apply_snapshot_restore_if_requested`.
        if let Some(ref snap_path) = self.restore_from_snapshot {
            config.fast_sync_config =
                crate::node_config::FastSyncConfig::from_snapshot(snap_path.clone());
        }

        // If not using a profile, network flags apply directly.
        // If using a profile, still allow network-level overrides.
        if self.profile.is_some() {
            // For profile mode, check if user explicitly overrode network settings.
            // Detection logic:
            // - If --network-mode is anything other than the default "local-mesh", user explicitly set it
            // - If --enable-p2p is true (non-default), user explicitly set it
            //
            // This allows: `--profile testnet-beta --network-mode local-mesh` to override
            // Beta's P2P default back to LocalMesh for CI testing.
            let cli_network_mode = parse_network_mode(&self.network_mode);
            let user_explicitly_set_network =
                cli_network_mode != NetworkMode::LocalMesh || self.enable_p2p;

            if user_explicitly_set_network {
                // User explicitly set network flags - override the profile's defaults
                config.network_mode = cli_network_mode;
                config.network.enable_p2p = self.enable_p2p;

                if self.enable_p2p && cli_network_mode == NetworkMode::P2p {
                    config.network.listen_addr = Some(self.p2p_listen_addr.clone());
                }
            }

            // Always allow P2P tuning overrides (these have no "detection" default issue)
            config.network.max_outbound = self.p2p_max_outbound;
            config.network.max_inbound = self.p2p_max_inbound;
            config.network.gossip_fanout = self.p2p_gossip_fanout;

            // Apply peer list if provided
            if !self.p2p_peers.is_empty() {
                config.network.static_peers = self.p2p_peers.clone();
            }

            if self.p2p_advertised_addr.is_some() {
                config.network.advertised_addr = self.p2p_advertised_addr.clone();
            }
        }

        // Run 033: parse `--validator-consensus-key` entries into
        // `network.static_peer_consensus_keys`. This is the smallest
        // additive shape the binary path needs to honestly construct
        // a `SuiteAwareValidatorKeyProvider`. Backward-compatible:
        // when no flag is supplied, the field stays empty and Run 032
        // disabled behaviour is preserved.
        if !self.validator_consensus_keys.is_empty() {
            let parsed = parse_validator_consensus_keys(&self.validator_consensus_keys)?;
            // Merge: CLI overrides any prior profile/file value.
            config.network.static_peer_consensus_keys = parsed;
        }

        // Validate P2P configuration
        config.validate_p2p_config();

        Ok(config)
    }

    /// Get the validator ID as a string for logging.
    pub fn validator_id_str(&self) -> String {
        self.validator_id
            .map(|id| format!("V{}", id))
            .unwrap_or_else(|| "none".to_string())
    }
}

// ============================================================================
// Run 033: --validator-consensus-key parsing
// ============================================================================

/// Parse a single `VID:SUITE:HEXPK` spec into a
/// [`StaticPeerConsensusKey`].
///
/// Strict parsing:
/// - exactly two `:` separators (HEXPK is forbidden from containing
///   `:` because it must be hex anyway);
/// - VID parses as `u64`;
/// - SUITE parses as `u16`;
/// - HEXPK is non-empty hex (validated by `decode_strict_hex_pk` at
///   activation time; here we only assert non-empty + length parity
///   so malformed flags fail at CLI parse rather than activation).
fn parse_validator_consensus_key_spec(spec: &str) -> Result<StaticPeerConsensusKey, String> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!("spec '{}' does not match VID:SUITE:HEXPK", spec));
    }
    let vid: u64 = parts[0]
        .parse()
        .map_err(|e| format!("invalid validator id '{}': {}", parts[0], e))?;
    let suite: u16 = parts[1]
        .parse()
        .map_err(|e| format!("invalid suite id '{}': {}", parts[1], e))?;
    let hex = parts[2].to_string();
    if hex.is_empty() {
        return Err(format!("empty public_key_hex in spec '{}'", spec));
    }
    if hex.len() % 2 != 0 {
        return Err(format!(
            "public_key_hex in spec '{}' must have even length",
            spec
        ));
    }
    Ok(StaticPeerConsensusKey {
        validator_id: vid,
        suite_id: suite,
        public_key_hex: hex,
    })
}

/// Parse all `--validator-consensus-key` specs into a vector. Bubbles
/// the first error up as [`CliError::InvalidValidatorConsensusKey`].
fn parse_validator_consensus_keys(
    specs: &[String],
) -> Result<Vec<StaticPeerConsensusKey>, CliError> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let parsed = parse_validator_consensus_key_spec(spec)
            .map_err(CliError::InvalidValidatorConsensusKey)?;
        out.push(parsed);
    }
    Ok(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_types::NetworkEnvironment;

    // ------------------------------------------------------------------
    // Run 033: --validator-consensus-key parser tests
    // ------------------------------------------------------------------

    #[test]
    fn run_033_parse_consensus_key_valid() {
        let parsed = parse_validator_consensus_key_spec("1:100:abcd0102").expect("valid");
        assert_eq!(parsed.validator_id, 1);
        assert_eq!(parsed.suite_id, 100);
        assert_eq!(parsed.public_key_hex, "abcd0102");
    }

    #[test]
    fn run_033_parse_consensus_key_rejects_missing_parts() {
        assert!(parse_validator_consensus_key_spec("1:100").is_err());
        assert!(parse_validator_consensus_key_spec("1").is_err());
        assert!(parse_validator_consensus_key_spec("").is_err());
    }

    #[test]
    fn run_033_parse_consensus_key_rejects_bad_vid() {
        assert!(parse_validator_consensus_key_spec("notanid:100:abcd").is_err());
    }

    #[test]
    fn run_033_parse_consensus_key_rejects_bad_suite() {
        assert!(parse_validator_consensus_key_spec("1:notasuite:abcd").is_err());
    }

    #[test]
    fn run_033_parse_consensus_key_rejects_empty_hex() {
        assert!(parse_validator_consensus_key_spec("1:100:").is_err());
    }

    #[test]
    fn run_033_parse_consensus_key_rejects_odd_length_hex() {
        assert!(parse_validator_consensus_key_spec("1:100:abc").is_err());
    }

    #[test]
    fn run_033_consensus_key_propagates_into_config() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--validator-consensus-key",
            "0:100:aabb",
            "--validator-consensus-key",
            "1:100:ccdd",
        ])
        .expect("parse");
        let cfg = args.to_node_config().expect("to_node_config");
        assert_eq!(cfg.network.static_peer_consensus_keys.len(), 2);
        assert_eq!(cfg.network.static_peer_consensus_keys[0].validator_id, 0);
        assert_eq!(
            cfg.network.static_peer_consensus_keys[0].public_key_hex,
            "aabb"
        );
    }

    #[test]
    fn run_033_consensus_key_invalid_hex_is_caller_error() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--validator-consensus-key", "0:100:abc"])
                .expect("clap-level parse ok");
        let res = args.to_node_config();
        assert!(res.is_err(), "must error on odd hex");
        match res.unwrap_err() {
            CliError::InvalidValidatorConsensusKey(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn run_033_consensus_key_default_is_empty() {
        let args = CliArgs::try_parse_from(["qbind-node"]).expect("parse");
        assert!(args.validator_consensus_keys.is_empty());
        let cfg = args.to_node_config().expect("config");
        assert!(cfg.network.static_peer_consensus_keys.is_empty());
    }

    #[test]
    fn run_033_existing_p2p_peer_vid_at_addr_unchanged() {
        // Regression: the new flag must not affect existing
        // `--p2p-peer vid@addr` parsing.
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--enable-p2p",
            "--network-mode",
            "p2p",
            "--p2p-peer",
            "1@127.0.0.1:19001",
        ])
        .expect("parse");
        assert_eq!(args.p2p_peers, vec!["1@127.0.0.1:19001".to_string()]);
        assert!(args.validator_consensus_keys.is_empty());
    }

    #[test]
    fn test_cli_args_default_values() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert_eq!(args.environment, "devnet");
        assert_eq!(args.execution_profile, "nonce-only");
        assert_eq!(args.network_mode, "local-mesh");
        assert!(!args.enable_p2p);
        assert_eq!(args.p2p_listen_addr, "127.0.0.1:0");
        assert!(args.p2p_advertised_addr.is_none());
        assert!(args.p2p_peers.is_empty());
        assert!(args.validator_id.is_none());
        assert!(args.data_dir.is_none());
        assert!(args.snapshot_dir.is_none());
        assert!(args.snapshot_interval_blocks.is_none());
        assert!(args.snapshot_max_snapshots.is_none());
    }

    #[test]
    fn test_cli_args_testnet_p2p() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--execution-profile",
            "vm-v0",
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--p2p-listen-addr",
            "0.0.0.0:19000",
            "--p2p-advertised-addr",
            "203.0.113.10:19000",
            "--p2p-peer",
            "127.0.0.1:19001",
            "--p2p-peer",
            "127.0.0.1:19002",
            "--validator-id",
            "0",
        ])
        .unwrap();

        assert_eq!(args.environment, "testnet");
        assert_eq!(args.execution_profile, "vm-v0");
        assert_eq!(args.network_mode, "p2p");
        assert!(args.enable_p2p);
        assert_eq!(args.p2p_listen_addr, "0.0.0.0:19000");
        assert_eq!(
            args.p2p_advertised_addr,
            Some("203.0.113.10:19000".to_string())
        );
        assert_eq!(args.p2p_peers, vec!["127.0.0.1:19001", "127.0.0.1:19002"]);
        assert_eq!(args.validator_id, Some(0));
    }

    #[test]
    fn test_cli_args_to_node_config() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--network-mode",
            "p2p",
            "--enable-p2p",
            "--p2p-listen-addr",
            "127.0.0.1:19000",
            "--p2p-peer",
            "127.0.0.1:19001",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert_eq!(config.network_mode, NetworkMode::P2p);
        assert!(config.network.enable_p2p);
        assert_eq!(
            config.network.listen_addr,
            Some("127.0.0.1:19000".to_string())
        );
        assert_eq!(config.network.static_peers, vec!["127.0.0.1:19001"]);
    }

    #[test]
    fn test_cli_snapshot_dir_enables_snapshot_config() {
        let temp = tempfile::TempDir::new().unwrap();
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--execution-profile",
            "vm-v0",
            "--data-dir",
            temp.path().join("data").to_str().unwrap(),
            "--snapshot-dir",
            temp.path().join("snapshots").to_str().unwrap(),
            "--snapshot-interval-blocks",
            "123",
            "--snapshot-max-snapshots",
            "2",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        assert_eq!(
            config.execution_profile,
            crate::node_config::ExecutionProfile::VmV0
        );
        assert_eq!(config.snapshot_config.snapshot_dir, args.snapshot_dir);
        assert!(config.snapshot_config.enabled);
        assert_eq!(config.snapshot_config.snapshot_interval_blocks, 123);
        assert_eq!(config.snapshot_config.max_snapshots, 2);
    }

    #[test]
    fn test_cli_help_exposes_snapshot_flags() {
        use clap::CommandFactory;

        let mut help = Vec::new();
        CliArgs::command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("--snapshot-dir"));
        assert!(help.contains("--snapshot-interval-blocks"));
        assert!(help.contains("--snapshot-max-snapshots"));
    }

    /// Run 037 (C4 piece (c)): the new PQC root-distribution CLI
    /// flags are wired into clap and visible in help.
    #[test]
    fn test_cli_help_exposes_run_037_pqc_flags() {
        use clap::CommandFactory;
        let mut help = Vec::new();
        CliArgs::command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("--p2p-pqc-root-mode"));
        assert!(help.contains("--p2p-trusted-root"));
        assert!(help.contains("--p2p-leaf-cert"));
        assert!(help.contains("--p2p-leaf-cert-key"));
        // Anti-overclaim discipline: the help text must point operators at
        // the contradiction document so they can see the trust boundary
        // before relying on these flags.
        assert!(help.contains("contradiction.md"));
    }

    /// Run 037: minimal parse with the new flags set produces the
    /// expected fields. Repeatable `--p2p-trusted-root` accumulates.
    #[test]
    fn test_cli_args_parse_run_037_pqc_flags() {
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--p2p-pqc-root-mode",
            "pqc-static-root",
            "--p2p-trusted-root",
            "00000000000000000000000000000000000000000000000000000000000000aa:100:dead",
            "--p2p-trusted-root",
            "00000000000000000000000000000000000000000000000000000000000000bb:100:beef",
            "--p2p-leaf-cert",
            "/tmp/leaf-cert.bin",
            "--p2p-leaf-cert-key",
            "/tmp/leaf-kem-sk.bin",
        ])
        .expect("clap parse");
        assert_eq!(args.p2p_pqc_root_mode.as_deref(), Some("pqc-static-root"));
        assert_eq!(args.p2p_trusted_roots.len(), 2);
        assert!(args.p2p_leaf_cert.is_some());
        assert!(args.p2p_leaf_cert_key.is_some());
    }

    #[test]
    fn test_cli_args_parse_addr_valid() {
        let addr = CliArgs::parse_addr("127.0.0.1:8080", "test").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_cli_args_parse_addr_invalid() {
        let result = CliArgs::parse_addr("invalid:addr:here", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_id_str() {
        let mut args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert_eq!(args.validator_id_str(), "none");

        args.validator_id = Some(5);
        assert_eq!(args.validator_id_str(), "V5");
    }

    // ========================================================================
    // T180: Profile Flag Tests
    // ========================================================================

    #[test]
    fn test_cli_profile_testnet_beta() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "testnet-beta"]).unwrap();

        assert_eq!(args.profile, Some("testnet-beta".to_string()));

        let config = args.to_node_config().unwrap();

        // Verify Beta defaults
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(config.gas_enabled, "Beta profile should enable gas");
        assert!(
            config.enable_fee_priority,
            "Beta profile should enable fee priority"
        );
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Dag,
            "Beta profile should use DAG mempool"
        );
        assert!(
            config.dag_availability_enabled,
            "Beta profile should enable DAG availability"
        );
        assert_eq!(
            config.network_mode,
            NetworkMode::P2p,
            "Beta profile should use P2P network mode"
        );
        assert!(config.network.enable_p2p, "Beta profile should enable P2P");
    }

    #[test]
    fn test_cli_profile_testnet_alpha() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "testnet-alpha"]).unwrap();

        let config = args.to_node_config().unwrap();

        // Verify Alpha defaults
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(
            !config.gas_enabled,
            "Alpha profile should have gas disabled"
        );
        assert!(
            !config.enable_fee_priority,
            "Alpha profile should have fee priority disabled"
        );
        assert_eq!(
            config.mempool_mode,
            MempoolMode::Fifo,
            "Alpha profile should use FIFO mempool"
        );
        assert_eq!(
            config.network_mode,
            NetworkMode::LocalMesh,
            "Alpha profile should use LocalMesh"
        );
    }

    #[test]
    fn test_cli_profile_devnet_v0() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "devnet-v0"]).unwrap();

        let config = args.to_node_config().unwrap();

        // Verify DevNet defaults
        assert_eq!(config.environment, NetworkEnvironment::Devnet);
        assert!(!config.gas_enabled);
        assert!(!config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Fifo);
        assert_eq!(config.network_mode, NetworkMode::LocalMesh);
    }

    #[test]
    fn test_cli_profile_with_override() {
        // Start with Beta profile but override gas to false
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--profile",
            "testnet-beta",
            "--enable-gas",
            "false",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        // Gas should be overridden to false
        assert!(!config.gas_enabled, "CLI override should disable gas");
        // But other Beta defaults should remain
        assert!(config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Dag);
    }

    #[test]
    fn test_cli_profile_invalid() {
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "invalid-profile"]).unwrap();

        let result = args.to_node_config();
        assert!(result.is_err());
        match result {
            Err(CliError::InvalidProfile(s)) => {
                assert_eq!(s, "invalid-profile");
            }
            _ => panic!("Expected InvalidProfile error"),
        }
    }

    #[test]
    fn test_cli_profile_short_flag() {
        let args = CliArgs::try_parse_from(["qbind-node", "-P", "beta"]).unwrap();

        let config = args.to_node_config().unwrap();

        // "beta" should be parsed as testnet-beta
        assert!(config.gas_enabled);
        assert!(config.enable_fee_priority);
    }

    #[test]
    fn test_cli_default_values_include_t180_fields() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();

        // New T180 fields should have None as default (not specified)
        assert!(args.profile.is_none());
        assert!(args.enable_gas.is_none());
        assert!(args.enable_fee_priority.is_none());
        assert!(args.mempool_mode.is_none());
        assert!(args.enable_dag_availability.is_none());
    }

    #[test]
    fn test_cli_legacy_mode_without_profile() {
        // Without --profile, the legacy behavior should still work
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--env",
            "testnet",
            "--execution-profile",
            "vm-v0",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();

        // Should have DevNet-like defaults (gas off, fee off, FIFO)
        assert_eq!(config.environment, NetworkEnvironment::Testnet);
        assert!(!config.gas_enabled);
        assert!(!config.enable_fee_priority);
        assert_eq!(config.mempool_mode, MempoolMode::Fifo);
    }

    // ========================================================================
    // T189: DAG Coupling Mode CLI Tests
    // ========================================================================

    #[test]
    fn test_cli_dag_coupling_mode_flag() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "enforce"]).unwrap();

        assert_eq!(args.dag_coupling_mode, Some("enforce".to_string()));
    }

    #[test]
    fn test_cli_dag_coupling_mode_off() {
        let args = CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "off"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Off);
    }

    #[test]
    fn test_cli_dag_coupling_mode_warn() {
        let args = CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "warn"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Warn);
    }

    #[test]
    fn test_cli_dag_coupling_mode_enforce() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "enforce"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Enforce);
    }

    #[test]
    fn test_cli_dag_coupling_mode_invalid() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "invalid"]).unwrap();

        let result = args.to_node_config();
        assert!(result.is_err());
        match result {
            Err(CliError::InvalidDagCouplingMode(s)) => {
                assert_eq!(s, "invalid");
            }
            _ => panic!("Expected InvalidDagCouplingMode error"),
        }
    }

    #[test]
    fn test_cli_dag_coupling_mode_case_insensitive() {
        let args =
            CliArgs::try_parse_from(["qbind-node", "--dag-coupling-mode", "ENFORCE"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(config.dag_coupling_mode, DagCouplingMode::Enforce);
    }

    #[test]
    fn test_cli_dag_coupling_mode_with_profile() {
        // Profile mainnet sets Enforce by default
        let args = CliArgs::try_parse_from(["qbind-node", "--profile", "mainnet"]).unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Enforce,
            "MainNet profile should default to Enforce"
        );
    }

    #[test]
    fn test_cli_dag_coupling_mode_override_profile() {
        // Start with testnet-beta profile (Off) and override to Warn
        let args = CliArgs::try_parse_from([
            "qbind-node",
            "--profile",
            "testnet-beta",
            "--dag-coupling-mode",
            "warn",
        ])
        .unwrap();

        let config = args.to_node_config().unwrap();
        assert_eq!(
            config.dag_coupling_mode,
            DagCouplingMode::Warn,
            "CLI override should set dag_coupling_mode to Warn"
        );
    }

    #[test]
    fn test_cli_default_dag_coupling_mode_none() {
        let args = CliArgs::try_parse_from(["qbind-node"]).unwrap();
        assert!(args.dag_coupling_mode.is_none());
    }
}