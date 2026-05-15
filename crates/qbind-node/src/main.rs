//! QBIND Node Binary Entry Point.
//!
//! Parses CLI arguments, validates configuration, spawns observability and
//! consensus components, and waits for shutdown.
//!
//! # Usage
//!
//! ```bash
//! # DevNet single-node smoke (LocalMesh, real consensus loop, metrics on)
//! QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
//! qbind-node --env devnet --validator-id 0
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
//!
//! # MainNet v0 (requires all invariants satisfied)
//! qbind-node \
//!   --profile mainnet \
//!   --data-dir /data/qbind \
//!   --p2p-listen-addr 0.0.0.0:9000 \
//!   --p2p-peer mainnet-bootstrap-1.qbind.network:9000 \
//!   --validator-id 0
//! ```
//!
//! # DevNet v0 Freeze
//!
//! DevNet defaults remain `LocalMesh` + `enable_p2p = false` to preserve
//! the DevNet v0 freeze. P2P mode is opt-in for TestNet Alpha experimentation.
//!
//! # MainNet Safety Rails (T185)
//!
//! When `--profile mainnet` is specified, the node validates all MainNet
//! invariants before startup. If any invariant is violated (e.g., gas disabled,
//! P2P disabled, no data directory), the node refuses to start with a clear
//! error message.
//!
//! # Operability (B1, B2 — see
//! `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` §9 and
//! `docs/whitepaper/contradiction.md` C4)
//!
//! - **B1 — real consensus loop**: After CLI/profile validation the binary
//!   spawns [`binary_consensus_loop::run_binary_consensus_loop`], which drives
//!   the existing `BasicHotStuffEngine`. Single-validator runs commit blocks
//!   honestly each tick; multi-validator runs propose when leader and
//!   advance views (full multi-node interconnect to `P2pConsensusNetwork`
//!   remains future work and is not silently faked here).
//! - **B2 — `/metrics` endpoint**: When `QBIND_METRICS_HTTP_ADDR` is set, the
//!   binary spawns the existing `metrics_http` server. When unset the server
//!   stays disabled (default-off) and startup logs say so.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;

use qbind_consensus::ids::ValidatorId;
use qbind_node::binary_consensus_loop::{
    spawn_binary_consensus_loop, spawn_binary_consensus_loop_with_io, BinaryConsensusLoopConfig,
    BinaryConsensusLoopIo, BinaryPeriodicSnapshotConfig, RestoreBaseline,
};
use qbind_node::cli::CliArgs;
use qbind_node::consensus_net_p2p::P2pConsensusNetwork;
use qbind_node::metrics::NodeMetrics;
use qbind_node::metrics_http::{
    spawn_metrics_http_server_with_crypto, CryptoMetricsRefs, MetricsHttpConfig,
};
use qbind_node::node_config::{ConfigProfile, NetworkMode};
use qbind_node::p2p_inbound::ChannelConsensusHandler;
use qbind_node::p2p_node_builder::P2pNodeBuilder;
use qbind_node::snapshot_restore::RestoreOutcome;
use qbind_node::vm_v0_runtime::{SnapshotAnchor, VmV0RuntimeState};

fn binary_periodic_snapshot_config(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
    runtime: Option<Arc<VmV0RuntimeState>>,
) -> BinaryPeriodicSnapshotConfig {
    let mut snapshot_config = config.snapshot_config.clone();
    if args.snapshot_interval_blocks.unwrap_or(0) == 0 {
        snapshot_config.snapshot_interval_blocks = 0;
    }
    BinaryPeriodicSnapshotConfig::new(snapshot_config, runtime, config.chain_id().as_u64())
}

/// Main entry point for qbind-node binary.
#[tokio::main]
async fn main() {
    // Parse CLI arguments
    let args = CliArgs::parse_args();

    // Build NodeConfig from CLI args
    let mut config = match args.to_node_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // T185: Validate MainNet invariants if using MainNet profile
    if let Some(ref profile_str) = args.profile {
        if let Some(ConfigProfile::MainNet) =
            qbind_node::node_config::parse_config_profile(profile_str)
        {
            if let Err(e) = config.validate_mainnet_invariants() {
                eprintln!("[T185] ERROR: MainNet configuration validation failed!");
                eprintln!("[T185] {}", e);
                eprintln!("[T185] MainNet nodes must satisfy all invariants.");
                eprintln!(
                    "[T185] See docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md and \
                     docs/protocol/QBIND_PROTOCOL_REPORT.md for requirements."
                );
                std::process::exit(1);
            }
            eprintln!("[T185] MainNet invariants validated successfully.");
        }
    }

    // ------------------------------------------------------------------
    // B3: Restore-from-snapshot startup path.
    //
    // If `--restore-from-snapshot <path>` was passed, the node validates
    // and materializes the snapshot into the configured data dir before
    // doing anything else. Failures here are non-zero exits with a clear
    // reason — we never silently degrade to "no restore".
    // See `crates/qbind-node/src/snapshot_restore.rs` and
    // `docs/whitepaper/contradiction.md` C4 (B3).
    //
    // B5: the resulting `RestoreOutcome` (when present) is threaded into
    // the binary-path consensus startup so the engine begins from the
    // restored height/view baseline rather than from view 0. See
    // `binary_consensus_loop::RestoreBaseline`.
    // ------------------------------------------------------------------
    let restore_outcome: Option<RestoreOutcome> =
        match qbind_node::snapshot_restore::apply_snapshot_restore_if_requested(&config) {
            Ok(None) => {
                eprintln!("[restore] no --restore-from-snapshot requested; normal startup.");
                None
            }
            Ok(Some(outcome)) => {
                eprintln!(
                    "[restore] OK: restored from snapshot height={} chain_id=0x{:016x}",
                    outcome.meta.height, outcome.meta.chain_id,
                );
                Some(outcome)
            }
            Err(e) => {
                eprintln!("[restore] ERROR: {}", e);
                eprintln!(
                    "[restore] qbind-node refuses to start because the requested snapshot \
                     restore could not be honestly applied. See \
                     docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md and \
                     docs/whitepaper/contradiction.md C4 (B3)."
                );
                std::process::exit(1);
            }
        };

    // Translate the (optional) restore outcome into a consensus baseline.
    // Today this uses only `meta.height` (as the consensus monotonicity
    // anchor) and `meta.block_hash` (as an opaque parent identifier in the
    // engine's block tree). It does NOT claim to reconstruct any
    // pre-snapshot consensus QC / vote history.
    let restore_baseline: Option<RestoreBaseline> =
        restore_outcome.as_ref().map(|o| RestoreBaseline {
            snapshot_height: o.meta.height,
            snapshot_block_id: o.meta.block_hash,
        });
    if let Some(b) = restore_baseline {
        eprintln!(
            "[binary] B5: restore-aware consensus start enabled \
             (snapshot_height={}, starting_view={})",
            b.snapshot_height,
            b.snapshot_height.saturating_add(1),
        );
    }

    // Run 069 — disabled-by-default trust-bundle hot-reload
    // **validation-only** check (positioned BEFORE the network-mode
    // dispatch so it fires for any startup invocation, not only for
    // `--network-mode p2p`).
    //
    // When `--p2p-trust-bundle-reload-check <PATH>` is supplied, run
    // the full Run 050–065 trust-bundle validation pipeline against
    // the candidate bundle at `<PATH>` (same checks as startup) but
    // perform NO live trust apply, NO sequence persistence write,
    // NO peer/session mutation, and NO `/metrics` mutation; print
    // the verdict to stderr and exit (`0` valid, `1` invalid). The
    // node does NOT start in this mode.
    //
    // See `crates/qbind-node/src/pqc_trust_reload.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md`, and
    // `docs/whitepaper/contradiction.md` C4.
    if let Some(candidate_path) = args.p2p_trust_bundle_reload_check.as_ref() {
        use qbind_node::pqc_root_config::PqcLeafCredentialPaths;
        use qbind_types::NetworkEnvironment;
        // Same signing-key parse as the live `--p2p-trust-bundle`
        // path inside `run_p2p_node` (no fallback; identical fail-
        // closed errors).
        let bundle_signing_keys =
            match qbind_node::pqc_trust_bundle::BundleSigningKeySet::parse_specs(
                &args.p2p_trust_bundle_signing_keys,
            ) {
                Ok(set) => set,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: --p2p-trust-bundle-signing-key parse error: {}. See \
                         docs/whitepaper/contradiction.md C4.",
                        e
                    );
                    std::process::exit(1);
                }
            };
        // TestNet/MainNet require an explicit signing-key set, mirroring
        // the live `--p2p-trust-bundle` startup precondition.
        if !matches!(config.environment, NetworkEnvironment::Devnet)
            && bundle_signing_keys.is_empty()
        {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-reload-check {} on environment={} requires at \
                 least one --p2p-trust-bundle-signing-key (TestNet/MainNet refuse unsigned \
                 bundles). No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.",
                candidate_path.display(),
                config.environment
            );
            std::process::exit(1);
        }
        // Optional local-leaf bytes drive the Run 061 / Run 063 self-
        // checks. Same loader as the live path so the verdict matches.
        let leaf_credentials_opt = match (
            args.p2p_leaf_cert.as_ref(),
            args.p2p_leaf_cert_key.as_ref(),
        ) {
            (Some(cert), Some(sk)) => {
                let paths = PqcLeafCredentialPaths {
                    cert_path: cert.clone(),
                    kem_sk_path: sk.clone(),
                };
                match paths.load() {
                    Ok(creds) => Some(creds),
                    Err(e) => {
                        eprintln!(
                            "[binary] FATAL: --p2p-trust-bundle-reload-check {} could not load \
                             local PQC leaf credentials for the Run 061/063 self-checks: {}. \
                             See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.",
                            candidate_path.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                }
            }
            (None, None) => None,
            _ => {
                eprintln!(
                    "[binary] FATAL: --p2p-leaf-cert and --p2p-leaf-cert-key must be set \
                     together (--p2p-trust-bundle-reload-check inherits the same precondition)."
                );
                std::process::exit(1);
            }
        };
        // Anti-rollback persistence parity with startup: TestNet/MainNet
        // require --data-dir so the candidate's sequence can be peeked
        // against the persisted record.
        let seq_path_buf = config
            .data_dir
            .as_ref()
            .map(|d| qbind_node::pqc_trust_sequence::sequence_file_path(d));
        let seq_path_ref = seq_path_buf.as_deref();
        if seq_path_ref.is_none()
            && !matches!(config.environment, NetworkEnvironment::Devnet)
        {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-reload-check {} on environment={} requires \
                 --data-dir so the candidate's sequence can be peeked against the persisted \
                 record. No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.",
                candidate_path.display(),
                config.environment
            );
            std::process::exit(1);
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let activation_current_height: u64 = restore_baseline
            .as_ref()
            .map(|b| b.snapshot_height)
            .unwrap_or(0);
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: None,
        };
        let local_leaf_bytes_opt =
            leaf_credentials_opt.as_ref().map(|c| c.cert_bytes.as_slice());
        let inputs = qbind_node::pqc_trust_reload::ReloadCheckInputs {
            candidate_path: candidate_path.as_path(),
            environment: config.environment,
            chain_id: config.chain_id(),
            validation_time_secs: now_secs,
            signing_keys: &bundle_signing_keys,
            activation_ctx,
            sequence_persistence_path: seq_path_ref,
            local_leaf_cert_bytes: local_leaf_bytes_opt,
        };
        match qbind_node::pqc_trust_reload::validate_candidate_bundle(inputs) {
            Ok(candidate) => {
                eprintln!("{}", candidate.staged_metadata_log_line());
                eprintln!(
                    "[binary] Run 069: VERDICT=valid (validation-only; no live trust apply; \
                     no sequence persistence write; no peer/session mutation; no /metrics \
                     mutation). Candidate path={}. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.",
                    candidate_path.display()
                );
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!(
                    "[binary] Run 069: VERDICT=invalid (candidate rejected; no live trust apply; \
                     no sequence persistence write; no peer/session mutation; no /metrics \
                     mutation). Candidate path={}. Reason: {}. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.",
                    candidate_path.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    }

    // Run 077 — disabled-by-default production-binary-facing local
    // peer-candidate validation check mode (positioned AFTER the
    // Run 069 reload-check hook and BEFORE the Run 073 process-start
    // reload-apply hook so it fires for any startup invocation,
    // mirroring the same staging-before-apply layering).
    //
    // When BOTH `--p2p-trust-bundle-peer-candidate-validation-enabled`
    // AND `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>`
    // are supplied, the binary parses the local JSON envelope
    // fixture and runs the same Run 076
    // `PeerCandidateValidator::try_accept` against it. The validator
    // reuses the same Run 069 `validate_candidate_bundle_full`
    // pipeline used at startup, the local reload-check, the Run 073
    // process-start apply, and the Run 074 SIGHUP live reload-apply.
    // The hook bumps the seven existing Run 076
    // `qbind_p2p_pqc_trust_bundle_peer_candidate_*` Prometheus
    // counters (no new metric family; no `_applied_total` family),
    // prints the canonical `VERDICT=...` operator-log line, and
    // exits (`0` only on `Validated`; `1` on every fail-closed
    // outcome including partial-config / I/O / parse refusal). The
    // node does NOT start in this mode.
    //
    // **What this hook is NOT.** It is not peer-driven live apply;
    // it is not gossip propagation; it is not a peer/network
    // listener; it is not a P2P wire integration; it is not an
    // admin-API endpoint; it is not a filesystem watcher; it is not
    // KMS/HSM custody; it is not `activation_epoch` runtime sourcing;
    // it is not signing-key ratification; it is not fast-sync
    // restore parity. The validator holds no `LivePqcTrustState`
    // handle, no `P2pSessionEvictor`, no `LiveReloadController`, and
    // no `ProductionLiveTrustApplyContext`; by construction it
    // cannot apply the candidate, propagate it, persist its sequence
    // number, or evict P2P / KEMTLS sessions.
    //
    // **Preconditions** (same as Run 069, fail-closed):
    // - both flags required-together (top-level partial-config
    //   refusal — typing one alone never arms the check);
    // - TestNet / MainNet require at least one
    //   `--p2p-trust-bundle-signing-key`;
    // - TestNet / MainNet require `--data-dir`;
    // - `--p2p-leaf-cert` and `--p2p-leaf-cert-key` must be set
    //   together when supplied;
    // - no implicit fallback to `--p2p-trusted-root`;
    // - no `DummySig` / `DummyKem` / `DummyAead` reactivation.
    //
    // See `crates/qbind-node/src/pqc_peer_candidate_binary.rs`,
    // `crates/qbind-node/src/pqc_trust_peer_candidate.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md`, and
    // `docs/whitepaper/contradiction.md` C4.
    if qbind_node::pqc_peer_candidate_binary::run077_hook_active(
        args.p2p_trust_bundle_peer_candidate_check.as_deref(),
        args.p2p_trust_bundle_peer_candidate_validation_enabled,
    ) {
        use qbind_node::pqc_peer_candidate_binary::{
            run_local_check, Run077Inputs, Run077RefusalReason, Run077Result,
        };
        use qbind_node::pqc_root_config::PqcLeafCredentialPaths;
        use qbind_types::NetworkEnvironment;

        // Top-level partial-config refusal BEFORE we touch any
        // signing-key / leaf-cert / data-dir / fixture file. Mirrors
        // the Run 074 partial-config discipline.
        match (
            args.p2p_trust_bundle_peer_candidate_check.as_ref(),
            args.p2p_trust_bundle_peer_candidate_validation_enabled,
        ) {
            (Some(_), true) => {
                // Valid pair — proceed below.
            }
            (Some(_), false) => {
                eprintln!(
                    "[binary] FATAL: {}",
                    Run077RefusalReason::EnabledFlagMissing
                );
                std::process::exit(1);
            }
            (None, true) => {
                eprintln!(
                    "[binary] FATAL: {}",
                    Run077RefusalReason::EnvelopePathMissing
                );
                std::process::exit(1);
            }
            (None, false) => unreachable!("run077_hook_active guards this branch"),
        }

        // Parse signing keys (same parser as Run 069).
        let bundle_signing_keys =
            match qbind_node::pqc_trust_bundle::BundleSigningKeySet::parse_specs(
                &args.p2p_trust_bundle_signing_keys,
            ) {
                Ok(set) => set,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: {}",
                        Run077RefusalReason::SigningKeyParseError {
                            message: e.to_string(),
                        }
                    );
                    std::process::exit(1);
                }
            };
        // TestNet/MainNet require an explicit signing-key set
        // (matches Run 069). No fallback.
        if !matches!(config.environment, NetworkEnvironment::Devnet)
            && bundle_signing_keys.is_empty()
        {
            eprintln!(
                "[binary] FATAL: {}",
                Run077RefusalReason::UnsignedRequiredOnEnvironment {
                    environment: config.environment,
                }
            );
            std::process::exit(1);
        }

        // Optional local-leaf bytes drive the Run 061 / Run 063 self-
        // checks. Same loader as the live path so the verdict matches.
        let leaf_credentials_opt = match (
            args.p2p_leaf_cert.as_ref(),
            args.p2p_leaf_cert_key.as_ref(),
        ) {
            (Some(cert), Some(sk)) => {
                let paths = PqcLeafCredentialPaths {
                    cert_path: cert.clone(),
                    kem_sk_path: sk.clone(),
                };
                match paths.load() {
                    Ok(creds) => Some(creds),
                    Err(e) => {
                        eprintln!(
                            "[binary] FATAL: {}",
                            Run077RefusalReason::LeafCredentialLoadError {
                                message: e.to_string(),
                            }
                        );
                        std::process::exit(1);
                    }
                }
            }
            (None, None) => None,
            _ => {
                eprintln!(
                    "[binary] FATAL: {}",
                    Run077RefusalReason::LeafCredentialFlagsUnpaired
                );
                std::process::exit(1);
            }
        };

        // Anti-rollback persistence parity with Run 069: TestNet /
        // MainNet require `--data-dir`. The on-disk sequence record
        // is only peeked (read-only) by the reused loader.
        let seq_path_buf = config
            .data_dir
            .as_ref()
            .map(|d| qbind_node::pqc_trust_sequence::sequence_file_path(d));
        let seq_path_ref = seq_path_buf.as_deref();
        if seq_path_ref.is_none()
            && !matches!(config.environment, NetworkEnvironment::Devnet)
        {
            eprintln!(
                "[binary] FATAL: {}",
                Run077RefusalReason::DataDirRequiredOnEnvironment {
                    environment: config.environment,
                }
            );
            std::process::exit(1);
        }

        // Scratch directory for the validator's temp file. Prefer
        // the operator-controlled `--data-dir` when available so the
        // scratch never lives in a world-writable location. Fall
        // back to the OS temp dir only when `--data-dir` is unset
        // (DevNet only — TestNet/MainNet refused above).
        let scratch_dir_buf: PathBuf = config
            .data_dir
            .clone()
            .map(|d| d.join("run077-peer-candidate-scratch"))
            .unwrap_or_else(std::env::temp_dir);
        if let Err(e) = std::fs::create_dir_all(&scratch_dir_buf) {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-peer-candidate-check could not create \
                 scratch dir {}: {}. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.",
                scratch_dir_buf.display(),
                e
            );
            std::process::exit(1);
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let activation_current_height: u64 = restore_baseline
            .as_ref()
            .map(|b| b.snapshot_height)
            .unwrap_or(0);
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: None,
        };
        let local_leaf_bytes_opt =
            leaf_credentials_opt.as_ref().map(|c| c.cert_bytes.as_slice());

        // No real `/metrics` HTTP server is bound at this point —
        // the process exits before `metrics::serve_metrics_http` is
        // called — but we still need a `P2pMetrics` so the existing
        // Run 076 recorders can run. Using a process-local instance
        // is honest: the Run 077 binary surface never publishes
        // these counters over HTTP (it exits before binding the
        // metrics listener), matching the same discipline as the
        // Run 069 / Run 073 process-start hooks.
        let metrics = qbind_node::metrics::P2pMetrics::default();

        let envelope_path = args
            .p2p_trust_bundle_peer_candidate_check
            .as_deref()
            .expect("partial-config refusal above guarantees Some(...)");
        let inputs = Run077Inputs {
            validation_enabled_flag: args.p2p_trust_bundle_peer_candidate_validation_enabled,
            envelope_path: Some(envelope_path),
            environment: config.environment,
            chain_id: config.chain_id(),
            validation_time_secs: now_secs,
            signing_keys: &bundle_signing_keys,
            activation_ctx,
            sequence_persistence_path: seq_path_ref,
            local_leaf_cert_bytes: local_leaf_bytes_opt,
            scratch_dir: &scratch_dir_buf,
            now_ms,
        };

        match run_local_check(inputs, &metrics) {
            Run077Result::Refused { reason } => {
                eprintln!("[binary] FATAL: {}", reason);
                std::process::exit(1);
            }
            Run077Result::Ran {
                outcome,
                verdict_line,
                observed_log_line,
            } => {
                if let Some(line) = observed_log_line {
                    eprintln!("{}", line);
                }
                if !matches!(
                    outcome,
                    qbind_node::pqc_trust_peer_candidate::PeerCandidateOutcome::Validated(_)
                ) {
                    // Surface the rejection reason for operator audit
                    // (safe: no private keys, no raw bundle bytes —
                    // the existing `Display` impls are log-safe by
                    // construction; see Run 076 module docs).
                    eprintln!("[binary] Run 077: outcome detail: {:?}", outcome);
                }
                eprintln!("{}", verdict_line);
                let code = Run077Result::Ran {
                    outcome,
                    verdict_line,
                    observed_log_line: None,
                }
                .exit_code();
                std::process::exit(code);
            }
        }
    }


    // Run 073 — production adapter wiring (composes Run 069
    // validation + Run 070 apply contract + Run 071
    // `LivePqcTrustState` + Run 072 `P2pSessionEvictor` +
    // `pqc_trust_sequence::check_and_update_sequence`) into a
    // production-honest local operator-triggered live-apply path
    // (positioned BEFORE the network-mode dispatch so it fires for
    // any startup invocation, immediately after the Run 069
    // validation-only hook). When
    // `--p2p-trust-bundle-reload-apply-path <PATH>` is supplied
    // with `--p2p-trust-bundle-reload-apply-enabled`, the binary:
    //
    //   1. Loads the BASELINE bundle from `--p2p-trust-bundle`
    //      using the SAME loader the normal startup path uses (so
    //      validation parity with startup is preserved by
    //      construction).
    //   2. Initializes a Run 071 `LivePqcTrustState` from the
    //      baseline.
    //   3. Constructs a Run 072 `NoActiveSessionsEvictor` because
    //      the binary's reload-apply hook runs at process-start
    //      time before any P2P listener / dialer is created — the
    //      session registry is genuinely empty, so a truthful
    //      zero-eviction report is the honest answer (Run 072
    //      invariant trivially holds).
    //   4. Builds a Run 073 `ProductionLiveTrustApplyContext` from
    //      (2), (3), and the on-disk sequence file path.
    //   5. Calls the same `apply_validated_candidate_with_previous`
    //      entry point Run 070 tests drive against the in-memory
    //      `FakeLiveTrustApplyContext`.
    //
    // Because `--p2p-trust-bundle` is REQUIRED for the production
    // adapter (no baseline → no mutable trust state to swap
    // against), the hook refuses cleanly with a config error when
    // it is absent. `ReloadApplyError::UnsupportedRuntimeContext`
    // is no longer surfaced on the local-operator-triggered path —
    // that variant remains in the library only as a fail-closed
    // boundary for callers that omit the apply context entirely.
    //
    // The node does NOT start in this mode (the binary exits with
    // `0` on apply success and `1` on any failure or boundary).
    // No /metrics family is bound by this hook — the process exits
    // before `/metrics` would be served — matching the discipline
    // documented in `crates/qbind-node/src/pqc_trust_reload.rs`
    // module comment. Session-eviction counters
    // (`qbind_p2p_session_eviction_*`) are also untouched in this
    // mode because the `NoActiveSessionsEvictor` performs zero
    // session work; this is the truthful answer for the
    // at-startup-time scope.
    //
    // What remains open (deferred to a future run, recorded in
    // `docs/whitepaper/contradiction.md` C4): operator-triggered
    // live apply ON A RUNNING NODE (SIGHUP / admin-API trigger
    // that calls the same `ProductionLiveTrustApplyContext`
    // against the live `TcpKemTlsP2pService` evictor instead of
    // `NoActiveSessionsEvictor`). Wiring that surface does NOT
    // change the Run 073 adapter or its tests.
    //
    // See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md` and
    // `docs/whitepaper/contradiction.md` C4 for the exact
    // boundaries that remain open.
    if args.p2p_trust_bundle_reload_apply_path.is_some()
        || args.p2p_trust_bundle_reload_apply_enabled
    {
        use qbind_node::p2p_session_eviction::P2pSessionEvictor;
        use qbind_node::pqc_live_trust::LivePqcTrustState;
        use qbind_node::pqc_live_trust_apply::{
            NoActiveSessionsEvictor, ProductionLiveTrustApplyContext,
        };
        use qbind_node::pqc_root_config::PqcLeafCredentialPaths;
        use qbind_node::pqc_trust_reload::{
            apply_validated_candidate_with_previous, ApplyMode, ReloadApplyError,
            ReloadCheckInputs,
        };
        use qbind_types::NetworkEnvironment;
        use std::sync::Arc;

        // Operator confusion preventer: either both flags or
        // neither. Refuse the partial-config shapes explicitly so
        // an operator cannot mistakenly "arm" the apply path by
        // setting only one of them.
        let candidate_path = match (
            args.p2p_trust_bundle_reload_apply_path.as_ref(),
            args.p2p_trust_bundle_reload_apply_enabled,
        ) {
            (Some(p), true) => p,
            (Some(_), false) => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-reload-apply-path requires \
                     --p2p-trust-bundle-reload-apply-enabled. Live reload-apply is \
                     disabled by default. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md."
                );
                std::process::exit(1);
            }
            (None, true) => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-reload-apply-enabled requires \
                     --p2p-trust-bundle-reload-apply-path <PATH>. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md."
                );
                std::process::exit(1);
            }
            (None, false) => unreachable!(),
        };

        // Reuse the EXACT same preconditions the Run 069
        // validation hook applies — same signing-key parse, same
        // TestNet/MainNet refuse-unsigned policy, same data-dir
        // requirement for the sequence peek, same local leaf
        // self-check inputs. Any divergence would let an operator
        // accidentally apply a candidate that the live startup
        // path would reject (or vice versa) — that would be a
        // silent regression on Run 069's "apply parity with
        // startup" invariant.
        let bundle_signing_keys =
            match qbind_node::pqc_trust_bundle::BundleSigningKeySet::parse_specs(
                &args.p2p_trust_bundle_signing_keys,
            ) {
                Ok(set) => set,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: --p2p-trust-bundle-signing-key parse error: {}. \
                         See docs/whitepaper/contradiction.md C4.",
                        e
                    );
                    std::process::exit(1);
                }
            };
        if !matches!(config.environment, NetworkEnvironment::Devnet)
            && bundle_signing_keys.is_empty()
        {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-reload-apply-path {} on environment={} \
                 requires at least one --p2p-trust-bundle-signing-key (TestNet/MainNet refuse \
                 unsigned bundles). No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md.",
                candidate_path.display(),
                config.environment
            );
            std::process::exit(1);
        }
        let leaf_credentials_opt = match (
            args.p2p_leaf_cert.as_ref(),
            args.p2p_leaf_cert_key.as_ref(),
        ) {
            (Some(cert), Some(sk)) => {
                let paths = PqcLeafCredentialPaths {
                    cert_path: cert.clone(),
                    kem_sk_path: sk.clone(),
                };
                match paths.load() {
                    Ok(creds) => Some(creds),
                    Err(e) => {
                        eprintln!(
                            "[binary] FATAL: --p2p-trust-bundle-reload-apply-path {} could not \
                             load local PQC leaf credentials for the Run 061/063 self-checks: \
                             {}. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md.",
                            candidate_path.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                }
            }
            (None, None) => None,
            _ => {
                eprintln!(
                    "[binary] FATAL: --p2p-leaf-cert and --p2p-leaf-cert-key must be set \
                     together (--p2p-trust-bundle-reload-apply-path inherits the same \
                     precondition)."
                );
                std::process::exit(1);
            }
        };
        let seq_path_buf = config
            .data_dir
            .as_ref()
            .map(|d| qbind_node::pqc_trust_sequence::sequence_file_path(d));
        let seq_path_ref = seq_path_buf.as_deref();
        if seq_path_ref.is_none()
            && !matches!(config.environment, NetworkEnvironment::Devnet)
        {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-reload-apply-path {} on environment={} \
                 requires --data-dir so the candidate's sequence can be peeked against the \
                 persisted record. No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md.",
                candidate_path.display(),
                config.environment
            );
            std::process::exit(1);
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let activation_current_height: u64 = restore_baseline
            .as_ref()
            .map(|b| b.snapshot_height)
            .unwrap_or(0);
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: None,
        };
        let local_leaf_bytes_opt =
            leaf_credentials_opt.as_ref().map(|c| c.cert_bytes.as_slice());
        let inputs = ReloadCheckInputs {
            candidate_path: candidate_path.as_path(),
            environment: config.environment,
            chain_id: config.chain_id(),
            validation_time_secs: now_secs,
            signing_keys: &bundle_signing_keys,
            activation_ctx,
            sequence_persistence_path: seq_path_ref,
            local_leaf_cert_bytes: local_leaf_bytes_opt,
        };

        // Run 073 — production adapter: load baseline, build live
        // state, build zero-session evictor, build adapter, run
        // apply pipeline through the same Run 070 entry point the
        // integration tests use. `--p2p-trust-bundle` MUST be set
        // because we need a baseline to seed the mutable live
        // trust handle (no implicit fallback to `--p2p-trusted-root`
        // — Run 073 only applies on the strict signed-bundle path).
        let baseline_path = match args.p2p_trust_bundle.as_ref() {
            Some(p) => p,
            None => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-reload-apply-path requires \
                     --p2p-trust-bundle <BASELINE-PATH> so the Run 073 adapter can seed \
                     the mutable live trust handle from the same signed-bundle path the \
                     normal startup loader validates. No fallback. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md."
                );
                std::process::exit(1);
            }
        };
        let baseline_activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: None,
        };
        let baseline_loaded = match qbind_node::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
            baseline_path,
            config.environment,
            config.chain_id(),
            now_secs,
            &bundle_signing_keys,
            baseline_activation_ctx,
        ) {
            Ok((loaded, _activation_outcome)) => loaded,
            Err(e) => {
                eprintln!(
                    "[binary] FATAL: Run 073 adapter could not load the baseline bundle \
                     from --p2p-trust-bundle {}: {}. The same validator the normal \
                     startup path uses refused the baseline; no live trust handle \
                     constructed; no live apply performed. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.",
                    baseline_path.display(),
                    e
                );
                std::process::exit(1);
            }
        };
        let live = Arc::new(LivePqcTrustState::initialize_from_loaded_bundle(
            &baseline_loaded,
        ));
        let evictor: Arc<dyn P2pSessionEvictor> = Arc::new(NoActiveSessionsEvictor::new());
        let mut apply_ctx = ProductionLiveTrustApplyContext::new(
            live.clone(),
            evictor,
            config.environment,
            config.chain_id(),
            seq_path_buf.clone(),
            now_secs,
        );
        let (prev_fp_prefix, prev_seq) = apply_ctx.snapshot_previous_metadata();

        match apply_validated_candidate_with_previous(
            inputs,
            ApplyMode::ApplyLive,
            Some(&mut apply_ctx),
            prev_fp_prefix.clone(),
            prev_seq,
        ) {
            Ok(applied) => {
                // Canonical operator-log line — single source of
                // truth via `AppliedCandidate::applied_log_line`
                // (Run 070).
                eprintln!("{}", applied.applied_log_line());
                eprintln!(
                    "[binary] Run 073: VERDICT=applied (baseline={} candidate={} \
                     live trust state swapped; session_evictions={} (no-active-sessions \
                     at startup-time); sequence committed). See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.",
                    baseline_path.display(),
                    candidate_path.display(),
                    applied.session_evictions
                );
                std::process::exit(0);
            }
            Err(ReloadApplyError::UnsupportedRuntimeContext(msg)) => {
                // Should not happen on the Run 073 path because we
                // always supply a real `ProductionLiveTrustApplyContext`,
                // but surface it honestly if the apply pipeline ever
                // produces it on this code path.
                eprintln!(
                    "[binary] Run 073: VERDICT=unsupported-runtime-context (unexpected on \
                     the production adapter path; candidate path={}; reason: {}). See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.",
                    candidate_path.display(),
                    msg
                );
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!(
                    "[binary] Run 073: VERDICT=invalid (candidate rejected at validation, \
                     swap, eviction, or commit stage; live trust state rolled back to \
                     baseline where applicable; on-disk sequence record preserved on \
                     fail-closed branches). Candidate path={}. Reason: {}. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.",
                    candidate_path.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    }

    // Run 074 — top-level partial-config refusal for the long-
    // running-node live trust-bundle reload-apply trigger.
    //
    // The actual SIGHUP handler is spawned later, inside
    // `run_p2p_node` (the only mode where a live
    // `LivePqcTrustState` + live `TcpKemTlsP2pService` evictor
    // exist). This top-level check fires in every mode so an
    // operator who supplies `--p2p-trust-bundle-live-reload-path`
    // on `--p2p-mode local-mesh` (or with no `--p2p-mode` flag at
    // all) gets a clean fail-closed startup error instead of a
    // silent no-op.
    //
    // - `--p2p-trust-bundle-live-reload-path <PATH>` without
    //   `--p2p-trust-bundle-live-reload-enabled` → refused (the
    //   operator-confusion preventer);
    // - `--p2p-trust-bundle-live-reload-enabled` without
    //   `--p2p-trust-bundle-live-reload-path <PATH>` → refused
    //   (the trigger has nothing to read on each SIGHUP);
    // - either flag without `--p2p-trust-bundle <BASELINE-PATH>`
    //   → refused (the running node needs a baseline to seed the
    //   live trust handle; the same precondition the Run 073 hook
    //   enforces);
    // - either flag without `--p2p-mode p2p` → refused (LocalMesh
    //   has no live `TcpKemTlsP2pService` to evict sessions on).
    //
    // See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md` and
    // `docs/whitepaper/contradiction.md` C4.
    if args.p2p_trust_bundle_live_reload_path.is_some()
        || args.p2p_trust_bundle_live_reload_enabled
    {
        match (
            args.p2p_trust_bundle_live_reload_path.as_ref(),
            args.p2p_trust_bundle_live_reload_enabled,
        ) {
            (Some(_), true) => {
                // Valid pair — defer to in-P2P wiring below.
            }
            (Some(_), false) => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-live-reload-path requires \
                     --p2p-trust-bundle-live-reload-enabled. The Run 074 \
                     long-running-node live trust-bundle reload-apply trigger is \
                     disabled by default. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md."
                );
                std::process::exit(1);
            }
            (None, true) => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-live-reload-enabled requires \
                     --p2p-trust-bundle-live-reload-path <PATH> (the trigger needs a \
                     candidate path to re-read on each SIGHUP). See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md."
                );
                std::process::exit(1);
            }
            (None, false) => unreachable!(),
        }
        if args.p2p_trust_bundle.is_none() {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-live-reload-enabled requires \
                 --p2p-trust-bundle <BASELINE-PATH> (the long-running-node trigger needs \
                 a baseline to seed the live trust handle; no implicit fallback to \
                 --p2p-trusted-root is introduced). See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md."
            );
            std::process::exit(1);
        }
    }

    // Validate P2P configuration (may modify config)
    let p2p_enabled = config.validate_p2p_config();

    // Run 035 — universal forged-injection startup gate. Refuses
    // startup in ANY mode (LocalMesh or P2P) when `--devnet-forged-inject`
    // is supplied without `--env devnet` and `QBIND_DEVNET_FORGED_INJECTION=1`.
    // This prevents the harness from being silently accepted on
    // Testnet/Mainnet even on code paths that don't have the inbound
    // P2P channel. The actual injection task is spawned only on the
    // P2P path inside `run_p2p_node`; non-P2P modes refuse the flag
    // outright because the harness has no inbound channel to push
    // frames into.
    if !args.devnet_forged_inject.is_empty() {
        use qbind_node::forged_injection::{
            ForgedInjectionCase, ForgedInjectionGateError, ForgedInjectionHarness,
            FORGED_INJECTION_ENV_VAR,
        };
        // Validate every CASE token first.
        let mut cases: Vec<ForgedInjectionCase> = Vec::new();
        for raw in args.devnet_forged_inject.iter() {
            match ForgedInjectionCase::parse(raw) {
                Ok(c) => cases.push(c),
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: --devnet-forged-inject parse error: {}. \
                         Refusing startup. See \
                         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md.",
                        e
                    );
                    std::process::exit(1);
                }
            }
        }
        // Validate environment + env var. The actual harness handle
        // gets re-created inside `run_p2p_node` against the P2P
        // inbound channel; this top-level call just enforces the
        // safety gate so non-P2P modes can't slip past it.
        let env_var = std::env::var(FORGED_INJECTION_ENV_VAR).ok();
        if let Err(e) =
            ForgedInjectionHarness::try_activate(config.environment, cases, env_var.as_deref())
        {
            match e {
                ForgedInjectionGateError::NotDevnet { .. }
                | ForgedInjectionGateError::MissingEnvVar { .. }
                | ForgedInjectionGateError::UnknownCase(_) => {
                    eprintln!("[binary] FATAL: {}", e);
                    std::process::exit(1);
                }
                // Disabled cannot occur because we just validated
                // non-empty cases above, but keep this defensive
                // arm so the match is exhaustive without unreachable!.
                ForgedInjectionGateError::Disabled => {
                    eprintln!(
                        "[binary] FATAL: Run 035 forged-injection harness gate returned \
                         Disabled despite non-empty case list; refusing to start. \
                         This indicates a logic bug in the gate."
                    );
                    std::process::exit(1);
                }
            }
        }
        // The harness is also rejected on non-P2P modes, since it
        // requires the P2P inbound channel.
        if !p2p_enabled
            || !matches!(
                config.network_mode,
                qbind_node::node_config::NetworkMode::P2p
            )
        {
            eprintln!(
                "[binary] FATAL: --devnet-forged-inject requires --network-mode p2p (the \
                 harness pushes frames through the P2P inbound channel). LocalMesh has \
                 no inbound channel; refusing to start."
            );
            std::process::exit(1);
        }
    }

    // Log startup information
    let validator_id_str = args.validator_id_str();
    config.log_startup_info(Some(&validator_id_str));

    // ------------------------------------------------------------------
    // B2: Metrics HTTP endpoint (gated by QBIND_METRICS_HTTP_ADDR)
    //
    // `node_metrics` is shared with the metrics HTTP server *and* with the
    // binary-path consensus loop (DevNet Run 002 enabler): consensus-class
    // counters (ticks, proposals, commits, current view, view changes) are
    // updated from the loop directly so `/metrics` reflects live progress.
    // See `binary_consensus_loop::run_binary_consensus_loop`.
    // ------------------------------------------------------------------
    let node_metrics = Arc::new(NodeMetrics::new());
    let metrics_cfg = MetricsHttpConfig::from_env();
    if metrics_cfg.is_enabled() {
        eprintln!(
            "[metrics] Spawning metrics HTTP server on {} (set via QBIND_METRICS_HTTP_ADDR)",
            metrics_cfg.bind_addr
        );
    } else {
        eprintln!(
            "[metrics] Metrics HTTP server disabled (set QBIND_METRICS_HTTP_ADDR=host:port to enable)"
        );
    }
    let (metrics_shutdown_tx, metrics_shutdown_rx) = watch::channel(());
    let metrics_handle = spawn_metrics_http_server_with_crypto(
        node_metrics.clone(),
        metrics_cfg,
        CryptoMetricsRefs::new(),
        metrics_shutdown_rx,
    );

    let vm_v0_runtime = match VmV0RuntimeState::open_from_config(&config) {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("[T164] ERROR: {}", e);
            eprintln!(
                "[T164] qbind-node refuses to start because VM-v0 persistent state \
                 could not be honestly opened."
            );
            std::process::exit(1);
        }
    };

    // Branch based on network mode for transport / wiring.
    match config.network_mode {
        NetworkMode::LocalMesh => {
            run_local_mesh_node(
                &config,
                &args,
                Arc::clone(&node_metrics),
                restore_baseline,
                vm_v0_runtime.clone(),
            )
            .await;
        }
        NetworkMode::P2p => {
            if p2p_enabled {
                run_p2p_node(
                    &config,
                    &args,
                    Arc::clone(&node_metrics),
                    restore_baseline,
                    vm_v0_runtime.clone(),
                )
                .await;
            } else {
                // P2P mode requested but not enabled by config.
                // Fail clearly rather than silently degrading: an operator
                // who asked for P2P should not be running on a LocalMesh
                // pretending to be P2P.
                eprintln!("[binary] ERROR: --network-mode p2p was requested but enable_p2p=false.");
                eprintln!(
                    "[binary] Pass --enable-p2p (or set network.enable_p2p=true) to actually \
                     start P2P, or use --network-mode local-mesh for single-host devnet."
                );
                std::process::exit(1);
            }
        }
    }

    // Tear down the metrics HTTP server on shutdown.
    eprintln!("[binary] Stopping metrics HTTP server...");
    drop(metrics_shutdown_tx);
    let _ = metrics_handle.await;
    eprintln!("[binary] Shutdown complete.");
}

/// Run a node in LocalMesh mode.
///
/// This spawns the binary consensus loop (`BasicHotStuffEngine` driven by
/// tokio interval). For a single-validator DevNet (the common bring-up
/// shape) the loop self-quorums and commits blocks each tick. For a
/// multi-validator LocalMesh the loop still proposes when leader; full
/// multi-node consensus interconnect over the in-process LocalMesh remains
/// covered by `NodeHotstuffHarness`-based integration tests.
async fn run_local_mesh_node(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
    node_metrics: Arc<NodeMetrics>,
    restore_baseline: Option<RestoreBaseline>,
    vm_v0_runtime: Option<Arc<VmV0RuntimeState>>,
) {
    eprintln!(
        "[binary] LocalMesh mode: starting consensus loop. environment={} profile={}",
        config.environment, config.execution_profile
    );

    // Default validator id 0 if unspecified (DevNet single-node smoke).
    let local_validator_id = ValidatorId::new(args.validator_id.unwrap_or(0));

    // Validator-set size: in LocalMesh we use the count of static peers + 1
    // (for the local node) when peers are configured, else 1 (single-node).
    let num_validators = (config.network.static_peers.len() as u64).saturating_add(1);

    let mut cfg = BinaryConsensusLoopConfig::new(local_validator_id, num_validators);
    if let Some(b) = restore_baseline {
        cfg = cfg.with_restore_baseline(b);
    }
    cfg = cfg.with_periodic_snapshot(binary_periodic_snapshot_config(
        config,
        args,
        vm_v0_runtime.clone(),
    ));
    eprintln!(
        "[binary] Consensus loop config: local_validator_id={:?} num_validators={} restore_baseline={}",
        local_validator_id,
        num_validators,
        restore_baseline.is_some(),
    );
    if num_validators == 1 {
        eprintln!(
            "[binary] Single-validator LocalMesh: leader self-quorum will commit a block per tick."
        );
    } else {
        eprintln!(
            "[binary] Multi-validator LocalMesh ({} validators): the binary drives leader \
             proposal; multi-node message ingestion is not yet wired into the binary path \
             (covered by NodeHotstuffHarness integration tests).",
            num_validators
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let snapshot_handle = spawn_vm_v0_snapshot_signal_task(
        vm_v0_runtime,
        Arc::clone(&node_metrics),
        config.chain_id().as_u64(),
        shutdown_rx.clone(),
    );
    let (consensus_handle, _progress) = spawn_binary_consensus_loop(cfg, shutdown_rx, node_metrics);

    eprintln!("[binary] Consensus loop running. Press Ctrl+C to exit.");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[binary] Shutdown signal received, stopping consensus loop...");
    drop(shutdown_tx);
    let _ = consensus_handle.await;
    if let Some(handle) = snapshot_handle {
        let _ = handle.await;
    }
    eprintln!("[binary] LocalMesh node stopped.");
}

/// Run a node in P2P mode.
///
/// Builds the P2P transport via `P2pNodeBuilder` and wires the binary
/// consensus loop to it via [`BinaryConsensusLoopIo`] (C4/B6):
///
/// - inbound `ConsensusNetMsg` frames are forwarded by a
///   [`ChannelConsensusHandler`] (registered with the P2P inbound demuxer)
///   into the consensus loop, where they are decoded and routed into the
///   running engine via `on_proposal_event` / `on_vote_event`;
/// - the engine's `ConsensusEngineAction`s flow back out through the
///   real `P2pConsensusNetwork` (which wraps the same `TcpKemTlsP2pService`).
///
/// Multi-validator P2P binary-path interconnect is now real: peers can
/// actually move each other's engines forward without `NodeHotstuffHarness`
/// scaffolding. Caveats and remaining gaps (validator/node-id mapping,
/// real PQC handshake, multi-validator restore catchup) are tracked in
/// `docs/whitepaper/contradiction.md` C4.
async fn run_p2p_node(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
    node_metrics: Arc<NodeMetrics>,
    restore_baseline: Option<RestoreBaseline>,
    vm_v0_runtime: Option<Arc<VmV0RuntimeState>>,
) {
    eprintln!(
        "[binary] P2P mode: starting transport + consensus loop. environment={} profile={}",
        config.environment, config.execution_profile
    );

    let validator_id = args.validator_id.unwrap_or(0);
    let local_validator_id = ValidatorId::new(validator_id);

    // Validator-set size: peers + self.
    let num_validators = (config.network.static_peers.len() as u64).saturating_add(1);

    // C4/B6: build the inbound P2P → engine event channel. The handler is
    // registered with the demuxer via `with_consensus_handler(...)`; the
    // receiver is threaded into the binary consensus loop. Capacity 256 is
    // the same default used by the underlying transport's inbound queue,
    // so we don't introduce a tighter bottleneck here.
    let (consensus_handler, consensus_inbound_rx) = ChannelConsensusHandler::new(256);
    // Run 035: clone the sender BEFORE handing the handler to the P2P
    // builder, so an opt-in dev/test-only forged-injection harness can
    // push crafted frames through the same inbound channel real P2P
    // traffic uses. Production paths never use this clone (the harness
    // refuses to activate outside `--env devnet` + the explicit
    // `QBIND_DEVNET_FORGED_INJECTION=1` env var). See
    // `crates/qbind-node/src/forged_injection.rs`.
    let consensus_inbound_tx_for_run035 = consensus_handler.sender_clone();

    // B12 — opt-in to mutual-auth hardened mode. CLI flag wins; if
    // absent, fall back to the QBIND_MUTUAL_AUTH env var; if still
    // absent or unparseable, default to `Disabled` to preserve
    // pre-B12 test-grade behaviour bit-for-bit.
    let mutual_auth_mode = {
        use qbind_node::node_config::{parse_mutual_auth_mode, MutualAuthMode as NodeMam};
        let raw = args
            .p2p_mutual_auth
            .clone()
            .or_else(|| std::env::var("QBIND_MUTUAL_AUTH").ok());
        let node_mode = raw
            .as_deref()
            .and_then(parse_mutual_auth_mode)
            .unwrap_or(NodeMam::Disabled);
        // Map the node-config-level enum to the qbind-net-level enum.
        match node_mode {
            NodeMam::Required => qbind_net::MutualAuthMode::Required,
            NodeMam::Optional => qbind_net::MutualAuthMode::Optional,
            NodeMam::Disabled => qbind_net::MutualAuthMode::Disabled,
        }
    };
    eprintln!(
        "[binary] B12: mutual_auth_mode={:?} (source: {})",
        mutual_auth_mode,
        if args.p2p_mutual_auth.is_some() {
            "--p2p-mutual-auth"
        } else if std::env::var("QBIND_MUTUAL_AUTH").is_ok() {
            "QBIND_MUTUAL_AUTH"
        } else {
            "default"
        }
    );

    // B12 — fail-loud guard: the cert-verified identity binding
    // installed by `P2pNodeBuilder` under `Required`/`Optional` mode
    // is wired through a deterministic *test-grade* `TrustedClientRoots`
    // resolver and the test-grade DummySig signature suite, so it is
    // explicitly NOT a substitute for production PQC root-key
    // distribution and per-validator cert lifecycle (see
    // `docs/whitepaper/contradiction.md` C4 — production PQC remains
    // out of scope for B12). We refuse to silently allow this stub
    // wiring to be enabled on MainNet, where the operator's intent
    // is unambiguously production-grade. TestNet is treated as a
    // pre-production environment and only generates a warning.
    //
    // Run 037 (C4 piece (c)): when the operator opts into
    // `--p2p-pqc-root-mode pqc-static-root`, the signature suite is
    // the real `MlDsa44SignatureSuite` and the trust roots are
    // operator-configured ML-DSA-44 public keys. That removes the
    // primary reason this guard refused MainNet startup, so the
    // guard is relaxed for the PQC-static-root path while keeping
    // the test-grade DummySig path strictly DevNet-only. Note that
    // the KEM/AEAD primitives on the binary path are still
    // test-grade today (separate C4 piece, NOT C4(c)) so MainNet
    // remains gated on additional pieces — but the cert-verification
    // / root-distribution surface is now production-honest.
    use qbind_node::node_config::MutualAuthMode as NodeMam;
    use qbind_node::pqc_root_config::PqcRootMode as PqcMode;
    use qbind_types::NetworkEnvironment;
    let configured_mode = match mutual_auth_mode {
        qbind_net::MutualAuthMode::Required => NodeMam::Required,
        qbind_net::MutualAuthMode::Optional => NodeMam::Optional,
        qbind_net::MutualAuthMode::Disabled => NodeMam::Disabled,
    };
    // Re-parse the PQC root mode purely for the guard message; the
    // actual config is built below.
    let configured_pqc_root_mode = args
        .p2p_pqc_root_mode
        .as_deref()
        .and_then(qbind_node::pqc_root_config::parse_pqc_root_mode)
        .unwrap_or_default();
    if matches!(configured_mode, NodeMam::Required | NodeMam::Optional) {
        match (config.environment, configured_pqc_root_mode) {
            (NetworkEnvironment::Mainnet, PqcMode::TestGradeDummySig) => {
                eprintln!(
                    "[binary] FATAL: --p2p-mutual-auth={} is wired through B12's test-grade \
                     TrustedClientRoots/DummySig stack and is not a substitute for production \
                     PQC root-key distribution; refusing to start on environment=mainnet \
                     without --p2p-pqc-root-mode pqc-static-root. \
                     See docs/whitepaper/contradiction.md C4(c).",
                    configured_mode
                );
                std::process::exit(1);
            }
            (NetworkEnvironment::Mainnet, PqcMode::PqcStaticRoot) => {
                eprintln!(
                    "[binary] Run 037: --p2p-mutual-auth={} on environment=mainnet is using the \
                     production-honest PQC static-root cert-verification path. NOTE: KEM/AEAD \
                     primitives on the binary path are still test-grade and remain a separate \
                     C4 piece (not C4(c)); MainNet readiness is therefore not yet implied. See \
                     docs/whitepaper/contradiction.md C4.",
                    configured_mode
                );
            }
            (NetworkEnvironment::Testnet, PqcMode::TestGradeDummySig) => {
                eprintln!(
                    "[binary] WARNING: --p2p-mutual-auth={} is enabled with the B12 test-grade \
                     TrustedClientRoots/DummySig stack. The cert verification path is exercised \
                     structurally but production PQC root-key distribution is not. \
                     See docs/whitepaper/contradiction.md C4(c).",
                    configured_mode
                );
            }
            (NetworkEnvironment::Testnet, PqcMode::PqcStaticRoot) => {
                eprintln!(
                    "[binary] Run 037: --p2p-mutual-auth={} on TestNet is using the \
                     production-honest PQC static-root cert-verification path.",
                    configured_mode
                );
            }
            (NetworkEnvironment::Devnet, _) => {
                // DevNet is the intended target for the first
                // mutual-auth binary-path evidence run; no extra
                // warning beyond the banner above.
            }
        }
    }

    // Build the P2P transport with the inbound consensus handler installed.
    //
    // Run 043: share the same `Arc<P2pMetrics>` between the live P2P
    // transport (where `qbind_p2p_pqc_*` cert-verify / per-reason
    // rejection counters are incremented) and the live `/metrics` HTTP
    // endpoint (served from `NodeMetrics::format_metrics`, which since
    // Run 043 includes `self.p2p.format_metrics()`). Without this, the
    // builder would mint a fresh local `Arc<P2pMetrics>` that never
    // reaches the scrape path, so the family on `/metrics` would stay
    // at zero under `pqc-static-root` operation.
    let builder = P2pNodeBuilder::new()
        .with_num_validators(num_validators as usize)
        .with_consensus_handler(Arc::new(consensus_handler))
        .with_mutual_auth_mode(mutual_auth_mode)
        .with_p2p_metrics(node_metrics.p2p_arc());

    // Run 037 (C4 piece (c)): production-honest PQC KEMTLS root-key
    // distribution. Default mode is `test-grade-dummy-sig` (preserves
    // pre-Run-037 B12 wiring bit-for-bit). The operator opts into
    // `pqc-static-root` via `--p2p-pqc-root-mode pqc-static-root`,
    // which in combination with `--p2p-mutual-auth required` requires
    // a non-empty `--p2p-trusted-root` list AND a loadable
    // `--p2p-leaf-cert` + `--p2p-leaf-cert-key` pair. Any deviation
    // fails the binary closed at startup — no silent downgrade to
    // DummySig.
    use qbind_node::pqc_root_config::{
        parse_pqc_peer_leaf_cert_spec, parse_pqc_root_mode, parse_pqc_trusted_root_specs,
        PqcLeafCredentialPaths, PqcRootMode, PqcStaticRootConfig,
    };
    let pqc_root_mode = args
        .p2p_pqc_root_mode
        .as_deref()
        .map(|s| {
            parse_pqc_root_mode(s).unwrap_or_else(|| {
                eprintln!(
                    "[binary] FATAL: unrecognized --p2p-pqc-root-mode value {:?}; \
                     accepted: test-grade-dummy-sig | pqc-static-root",
                    s
                );
                std::process::exit(1);
            })
        })
        .unwrap_or(PqcRootMode::TestGradeDummySig);

    let pqc_required = matches!(pqc_root_mode, PqcRootMode::PqcStaticRoot)
        && matches!(mutual_auth_mode, qbind_net::MutualAuthMode::Required);

    // Run 050: when a trust bundle is supplied, the CLI `--p2p-trusted-root`
    // list is allowed to be empty (the bundle provides the trust set);
    // otherwise we keep the Run 037 requirement that Required-mode
    // operators must configure at least one CLI root. This is the
    // smallest change that supports bundle-only operation without
    // weakening the pre-bundle invariant.
    let cli_trusted_roots_required = pqc_required && args.p2p_trust_bundle.is_none();

    let mut trusted_roots = match parse_pqc_trusted_root_specs(
        &args.p2p_trusted_roots,
        cli_trusted_roots_required,
    ) {
        Ok(roots) => roots,
        Err(e) => {
            eprintln!(
                "[binary] FATAL: --p2p-trusted-root parse error: {}. See \
                 docs/whitepaper/contradiction.md C4(c).",
                e
            );
            std::process::exit(1);
        }
    };

    let leaf_credentials = match (args.p2p_leaf_cert.as_ref(), args.p2p_leaf_cert_key.as_ref()) {
        (Some(cert), Some(sk)) => {
            let paths = PqcLeafCredentialPaths {
                cert_path: cert.clone(),
                kem_sk_path: sk.clone(),
            };
            match paths.load() {
                Ok(creds) => Some(creds),
                Err(e) => {
                    eprintln!("[binary] FATAL: failed to load PQC leaf credentials: {}", e);
                    std::process::exit(1);
                }
            }
        }
        (None, None) => None,
        _ => {
            eprintln!(
                "[binary] FATAL: --p2p-leaf-cert and --p2p-leaf-cert-key must be set together"
            );
            std::process::exit(1);
        }
    };

    if pqc_required && leaf_credentials.is_none() {
        eprintln!(
            "[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root \
             requires --p2p-leaf-cert and --p2p-leaf-cert-key (production-honest mode must \
             not silently fall back to test-grade certs). See \
             docs/whitepaper/contradiction.md C4(c)."
        );
        std::process::exit(1);
    }

    let peer_leaf_certs = match args
        .p2p_peer_leaf_certs
        .iter()
        .map(|s| parse_pqc_peer_leaf_cert_spec(s))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(certs) => certs,
        Err(e) => {
            eprintln!("[binary] FATAL: --p2p-peer-leaf-cert parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Run 050 (C4 piece: PQC transport trust-anchor lifecycle —
    // foundation layer) + Run 051 (signed-bundle ML-DSA-44
    // verification): if `--p2p-trust-bundle <PATH>` was supplied,
    // load + validate the bundle, then merge its active, non-revoked,
    // in-window roots into the trust set. Failures here fail closed
    // (the binary refuses to start) — there is NO silent fallback to
    // the `--p2p-trusted-root` CLI path on bundle failure.
    //
    // Static-roots + bundle conflict policy (Run 050):
    //   DevNet           — both allowed, deduplicated by `root_key_id`.
    //   TestNet/MainNet  — both supplied is a configuration error and
    //                      fails closed; the operator must use the
    //                      bundle alone.
    //
    // Signature policy (Run 051; enforced inside
    // `TrustBundle::validate_at_with_signing_keys`):
    //   DevNet           — unsigned bundle accepted; signed bundle
    //                      verified against the configured
    //                      `--p2p-trust-bundle-signing-key` set;
    //                      any failure (missing key, bad signature,
    //                      malformed, unsupported suite) fails closed.
    //   TestNet/MainNet  — unsigned bundle REFUSED; signed bundle
    //                      verified or fails closed.
    //
    // Trust-separation: the signing-key id MUST NOT collide with any
    // configured transport root id, from either source. Collisions
    // fail closed before the bundle is loaded.

    // Run 051: parse the bundle-signing key list once up front so we
    // can both enforce trust separation against `trusted_roots` and
    // surface the gauge for the configured-keys count.
    let bundle_signing_keys =
        match qbind_node::pqc_trust_bundle::BundleSigningKeySet::parse_specs(
            &args.p2p_trust_bundle_signing_keys,
        ) {
            Ok(set) => set,
            Err(e) => {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-signing-key parse error: {}. \
                     See docs/whitepaper/contradiction.md C4 (signed root distribution).",
                    e
                );
                std::process::exit(1);
            }
        };

    // Trust-separation between bundle-signing keys and transport
    // root IDs (CLI `--p2p-trusted-root` set). A separate check
    // against bundle `roots[]` is performed inside
    // `TrustBundle::validate_at_with_signing_keys` (Run 050
    // invariant). Both directions fail closed: a transport-root key
    // MUST NOT also be a bundle-signing key.
    {
        let cli_root_ids: std::collections::HashSet<[u8; 32]> =
            trusted_roots.iter().map(|r| r.root_key_id).collect();
        for key in bundle_signing_keys.iter() {
            if cli_root_ids.contains(&key.key_id_bytes) {
                eprintln!(
                    "[binary] FATAL: --p2p-trust-bundle-signing-key {} collides with a \
                     configured --p2p-trusted-root id. Bundle-signing authority MUST be \
                     trust-separated from transport roots. See \
                     docs/whitepaper/contradiction.md C4 (signed root distribution).",
                    key.key_id_hex()
                );
                std::process::exit(1);
            }
        }
    }

    // Run 051: TestNet/MainNet + bundle => require a signing-key
    // configuration. This rule encodes "production bundle layer
    // cannot operate without a verified signature path".
    if let Some(path) = args.p2p_trust_bundle.as_ref() {
        use qbind_types::NetworkEnvironment;
        if !matches!(config.environment, NetworkEnvironment::Devnet)
            && bundle_signing_keys.is_empty()
        {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle {} on environment={} requires at least one \
                 --p2p-trust-bundle-signing-key (TestNet/MainNet refuse unsigned bundles, and \
                 cannot verify a signed bundle without a configured signing key). See \
                 docs/whitepaper/contradiction.md C4 (signed root distribution).",
                path.display(),
                config.environment
            );
            std::process::exit(1);
        }
    } else if !bundle_signing_keys.is_empty() {
        // Documented behavior: signing keys without a bundle is a
        // no-op. We warn so operators notice the misconfiguration,
        // but do not fail closed (the live trust set is unchanged).
        eprintln!(
            "[binary] WARNING: --p2p-trust-bundle-signing-key supplied without \
             --p2p-trust-bundle; signing keys have no effect and will be ignored."
        );
    }

    // Run 069 — disabled-by-default trust-bundle hot-reload
    // **validation-only** check executes in `main()` BEFORE the
    // network-mode dispatch (so it fires regardless of LocalMesh /
    // P2P selection). When the flag is supplied the process exits
    // before reaching this point, so no additional wiring is needed
    // here. See `main.rs` reload-check block and
    // `crates/qbind-node/src/pqc_trust_reload.rs`.

    let trust_bundle_loaded: Option<qbind_node::pqc_trust_bundle::LoadedTrustBundle> = match args
        .p2p_trust_bundle
        .as_ref()
    {
        Some(path) => {
            use qbind_types::NetworkEnvironment;
            // Wall-clock used for the bundle/root validity-window
            // checks. Same operational-freshness scope as Run 045
            // `verify_delegation_cert` — NOT a consensus time source.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Run 057: build the activation runtime context.
            //
            //   current_height = restore_baseline.snapshot_height when
            //     the node was started with --restore-from-snapshot,
            //     else 0 (fresh-from-genesis local committed height).
            //     This is the only safe height source available pre-
            //     consensus — see
            //     crates/qbind-node/src/pqc_trust_activation.rs
            //     module docs.
            //   current_epoch  = None. There is no safe pre-consensus
            //     epoch source today (epoch transitions only happen
            //     after consensus begins committing blocks). A bundle
            //     that declares `activation_epoch` therefore fails
            //     closed here; epoch gating recorded as remaining-open
            //     in docs/whitepaper/contradiction.md C4.
            let activation_current_height: u64 = restore_baseline
                .as_ref()
                .map(|b| b.snapshot_height)
                .unwrap_or(0);
            let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
                current_height: Some(activation_current_height),
                current_epoch: None,
            };
            match qbind_node::pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
                path,
                config.environment,
                config.chain_id(),
                now_secs,
                &bundle_signing_keys,
                activation_ctx,
            ) {
                Ok((loaded, activation_outcome)) => {
                    // Enforce static-roots + bundle conflict policy.
                    if !trusted_roots.is_empty()
                        && !matches!(config.environment, NetworkEnvironment::Devnet)
                    {
                        eprintln!(
                            "[binary] FATAL: --p2p-trust-bundle and --p2p-trusted-root cannot be \
                             combined on environment={} (only DevNet allows the operator \
                             override). Use the bundle alone, or omit `--p2p-trusted-root`. \
                             See docs/whitepaper/contradiction.md C4 (signed root distribution).",
                            config.environment
                        );
                        std::process::exit(1);
                    }

                    // Run 057: surface the activation observability
                    // gauges immediately on a satisfied gate. Values
                    // are stable for the rest of the process lifetime
                    // unless a future run reloads the bundle.
                    {
                        let p2p = node_metrics.p2p();
                        p2p.set_pqc_trust_bundle_activation_height_required(
                            activation_outcome.required_height.unwrap_or(0),
                        );
                        p2p.set_pqc_trust_bundle_activation_height_current(
                            activation_outcome.current_height.unwrap_or(0),
                        );
                        p2p.set_pqc_trust_bundle_activation_epoch_required(
                            activation_outcome.required_epoch.unwrap_or(0),
                        );
                        p2p.set_pqc_trust_bundle_activation_epoch_current(
                            activation_outcome.current_epoch.unwrap_or(0),
                        );
                    }
                    eprintln!(
                        "[binary] Run 057: trust-bundle activation gate satisfied \
                         (required_height={:?} current_height={:?} required_epoch={:?} \
                         current_epoch={:?})",
                        activation_outcome.required_height,
                        activation_outcome.current_height,
                        activation_outcome.required_epoch,
                        activation_outcome.current_epoch,
                    );

                    // Run 055: anti-rollback persistence check. MUST run
                    // AFTER all existing bundle validation (schema, env,
                    // chain_id, validity window, root status / windows,
                    // revocation consistency, ML-DSA-44 signature, AND
                    // Run 057 activation gate) and BEFORE we merge
                    // bundle roots into `trusted_roots`, so a rejected
                    // rollback / equivocation / corrupt persistence
                    // state cannot leak new trust anchors into the live
                    // PQC trust set. Fail-closed on any error. Never
                    // silently falls back to `--p2p-trusted-root` and
                    // never resets / deletes corrupted persistence
                    // state silently.
                    if let Some(data_dir) = config.data_dir.as_ref() {
                        let seq_path =
                            qbind_node::pqc_trust_sequence::sequence_file_path(data_dir);
                        match qbind_node::pqc_trust_sequence::check_and_update_sequence(
                            &seq_path,
                            config.environment,
                            config.chain_id(),
                            loaded.bundle.sequence,
                            &loaded.fingerprint,
                            now_secs,
                        ) {
                            Ok(outcome) => {
                                use qbind_node::pqc_trust_sequence::SequenceCheckOutcome;
                                node_metrics
                                    .p2p()
                                    .set_pqc_trust_bundle_sequence_highest(
                                        outcome.persisted_sequence(),
                                    );
                                let detail = match &outcome {
                                    SequenceCheckOutcome::FirstLoad {
                                        persisted_sequence,
                                        ..
                                    } => format!(
                                        "first-load persisted_sequence={}",
                                        persisted_sequence
                                    ),
                                    SequenceCheckOutcome::Upgraded {
                                        previous_sequence,
                                        new_sequence,
                                        ..
                                    } => format!(
                                        "upgraded previous_sequence={} -> new_sequence={}",
                                        previous_sequence, new_sequence
                                    ),
                                    SequenceCheckOutcome::EqualSequenceSameFingerprint {
                                        sequence,
                                        ..
                                    } => format!(
                                        "equal-sequence same-fingerprint (no write) sequence={}",
                                        sequence
                                    ),
                                };
                                eprintln!(
                                    "[binary] Run 055: trust-bundle sequence persistence \
                                     env={} chain_id={} path={} {} fp={}",
                                    qbind_node::pqc_trust_bundle::TrustBundleEnvironment::from_runtime(
                                        config.environment
                                    ),
                                    qbind_node::pqc_trust_sequence::chain_id_hex(
                                        config.chain_id()
                                    ),
                                    seq_path.display(),
                                    detail,
                                    &loaded.fingerprint_hex()[..8],
                                );
                            }
                            Err(e) => {
                                use qbind_node::pqc_trust_sequence::TrustBundleSequenceError as SE;
                                let p2p = node_metrics.p2p();
                                match &e {
                                    SE::SequenceRollback { .. } => {
                                        p2p.inc_pqc_trust_bundle_sequence_rollback_rejected();
                                    }
                                    SE::EqualSequenceFingerprintMismatch { .. } => {
                                        p2p.inc_pqc_trust_bundle_sequence_equal_fingerprint_mismatch();
                                    }
                                    SE::PersistFailure(_) => {
                                        p2p.inc_pqc_trust_bundle_sequence_persist_failures();
                                    }
                                    SE::Io(_)
                                    | SE::Malformed(_)
                                    | SE::UnsupportedRecordVersion(_)
                                    | SE::WrongEnvironment { .. }
                                    | SE::WrongChainId { .. } => {}
                                }
                                eprintln!(
                                    "[binary] FATAL: --p2p-trust-bundle sequence anti-rollback \
                                     check failed for path={} (sequence persistence file={}): \
                                     {}. No fallback to --p2p-trusted-root on bundle failure \
                                     (production-honest lifecycle must not silently downgrade or \
                                     silently reset persistence state). See \
                                     docs/whitepaper/contradiction.md C4 (signed root \
                                     distribution).",
                                    path.display(),
                                    seq_path.display(),
                                    e
                                );
                                std::process::exit(1);
                            }
                        }
                    } else if matches!(config.environment, NetworkEnvironment::Devnet) {
                        // DevNet convenience: a `--p2p-trust-bundle`
                        // run without `--data-dir` is permitted (this
                        // preserves the Run 050/051/054 DevNet smoke
                        // shape) but anti-rollback persistence is NOT
                        // active. Document this honestly so operators
                        // are not surprised.
                        eprintln!(
                            "[binary] Run 055 WARNING: --p2p-trust-bundle supplied without \
                             --data-dir on environment=devnet; trust-bundle sequence \
                             anti-rollback persistence is NOT active for this run (DevNet \
                             convenience; TestNet/MainNet would fail closed). See \
                             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_055.md."
                        );
                    } else {
                        // Production-honest: a TestNet/MainNet bundle
                        // load with no `--data-dir` cannot persist the
                        // anti-rollback record, so we refuse the bundle
                        // rather than silently degrade to a path that
                        // would accept rollback on the next restart.
                        eprintln!(
                            "[binary] FATAL: --p2p-trust-bundle {} on environment={} requires \
                             --data-dir so the bundle's sequence number can be persisted across \
                             restarts. Without persistence, an older signed bundle could be \
                             replayed after a restart (anti-rollback regression). See \
                             docs/whitepaper/contradiction.md C4 (signed root distribution).",
                            path.display(),
                            config.environment
                        );
                        std::process::exit(1);
                    }

                    // Merge active bundle roots into the trust set,
                    // deduplicating by `root_key_id`. The bundle's
                    // active_roots list has already been filtered by
                    // `validate_at` to status=Active, in-window, not
                    // on the revocation list.
                    let mut seen: std::collections::HashSet<[u8; 32]> = trusted_roots
                        .iter()
                        .map(|r| r.root_key_id)
                        .collect();
                    for r in &loaded.active_roots {
                        if seen.insert(r.root_key_id) {
                            trusted_roots.push(r.clone());
                        }
                    }
                    let signed_status = match &loaded.signature_status {
                        qbind_node::pqc_trust_bundle::BundleSignatureStatus::Unsigned => {
                            "unsigned".to_string()
                        }
                        qbind_node::pqc_trust_bundle::BundleSignatureStatus::Verified {
                            signing_key_id,
                        } => format!("verified(signing_key_id={}..)", &signing_key_id[..8]),
                    };
                    eprintln!(
                        "[binary] Run 050/051: trust bundle loaded path={} env={} fp={} \
                         active_roots={} revoked_roots={} sequence={} valid_from={} \
                         valid_until={} signature={} signing_keys_configured={}. \
                         Bundle root IDs: [{}]",
                        path.display(),
                        loaded.environment(),
                        loaded.fingerprint_hex(),
                        loaded.active_root_count(),
                        loaded.revoked_root_count(),
                        loaded.bundle.sequence,
                        loaded.bundle.valid_from,
                        loaded.bundle.valid_until,
                        signed_status,
                        bundle_signing_keys.len(),
                        loaded
                            .active_roots
                            .iter()
                            .map(|r| format!("{}..", &r.root_key_id_hex()[..8]))
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    Some(loaded)
                }
                Err(e) => {
                    // Run 051: surface signed-bundle envelope rejections
                    // on the rejected counter before exiting fail-closed.
                    // For non-signature failures (e.g. WrongEnvironment),
                    // the counter is left at zero so it remains a
                    // truthful signal of signature-specific rejection.
                    // Run 057: distinguish activation-gate rejection
                    // (future-dated or runtime-source-unavailable)
                    // so the `pqc_trust_bundle_activation_rejected_total`
                    // counter is bumped exactly once per rejected load.
                    use qbind_node::pqc_trust_bundle::TrustBundleError as E;
                    let signature_envelope_rejection = matches!(
                        &e,
                        E::MissingSigningKey { .. }
                            | E::UnsupportedSignatureSuite { .. }
                            | E::SignatureSuiteMismatch { .. }
                            | E::MalformedSignatureBytes { .. }
                            | E::BadSignature { .. }
                    );
                    if signature_envelope_rejection {
                        node_metrics
                            .p2p()
                            .inc_pqc_trust_bundle_signature_rejected();
                    }
                    if let E::Activation(act) = &e {
                        let p2p = node_metrics.p2p();
                        p2p.inc_pqc_trust_bundle_activation_rejected();
                        // Surface the runtime height we asked the gate
                        // about, so an operator-side /metrics scrape on
                        // a node that *did* manage to bind /metrics on
                        // a prior run can correlate. (Not reachable
                        // on this exact path because we exit before
                        // the metrics HTTP server binds; recorded
                        // honestly anyway for tests.)
                        p2p.set_pqc_trust_bundle_activation_height_current(
                            activation_current_height,
                        );
                        use qbind_node::pqc_trust_activation::TrustBundleActivationError as AE;
                        match act {
                            AE::ActivationHeightNotYetReached {
                                required_height, ..
                            }
                            | AE::CurrentHeightUnavailable {
                                required_height, ..
                            } => p2p.set_pqc_trust_bundle_activation_height_required(
                                *required_height,
                            ),
                            AE::ActivationEpochNotYetReached {
                                required_epoch, ..
                            }
                            | AE::CurrentEpochUnavailable {
                                required_epoch, ..
                            } => p2p.set_pqc_trust_bundle_activation_epoch_required(
                                *required_epoch,
                            ),
                            // Run 065: surface the policy's
                            // required_min_height on the
                            // `_activation_height_required` gauge so an
                            // operator who scrapes /metrics on a prior
                            // successful run can correlate the rejected
                            // value. Activation_height itself is the
                            // declared bundle/root/revocation value; the
                            // gauge represents the minimum the operator
                            // must publish at the current committed
                            // height.
                            AE::ActivationHeightBelowMinimumMargin {
                                required_min_height,
                                ..
                            }
                            | AE::RevocationActivationHeightBelowMinimumMargin {
                                required_min_height,
                                ..
                            } => p2p.set_pqc_trust_bundle_activation_height_required(
                                *required_min_height,
                            ),
                        }
                    }
                    eprintln!(
                        "[binary] FATAL: --p2p-trust-bundle load/validate failed for path={}: \
                         {}. No fallback to --p2p-trusted-root on bundle failure (production-honest \
                         lifecycle must not silently downgrade). See \
                         docs/whitepaper/contradiction.md C4 (signed root distribution).",
                        path.display(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    // Run 050: enforce Required-mode invariant. When PQC mutual-auth
    // Required is selected, *some* trusted root must be configured —
    // either via CLI flags, the bundle, or both. `parse_pqc_trusted_root_specs`
    // already enforces the no-bundle case; here we cover the
    // bundle-only-but-empty-active-set case (a valid bundle whose
    // every root is retired/revoked/expired would otherwise leave the
    // trust set empty and silently break verification).
    if pqc_required && trusted_roots.is_empty() {
        eprintln!(
            "[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root \
             requires at least one configured trusted root. The supplied trust bundle (if any) \
             contained zero active, in-window, non-revoked roots. See \
             docs/whitepaper/contradiction.md C4 (signed root distribution)."
        );
        std::process::exit(1);
    }

    // Run 050/051: surface the trust-bundle observability gauges and
    // signed-bundle counters on the shared `P2pMetrics` instance.
    // The same Arc is wired into the builder via
    // `with_p2p_metrics(node_metrics.p2p_arc())` above, so these
    // set_*/inc_* calls reach the live `/metrics` scrape path.
    {
        let p2p = node_metrics.p2p();
        p2p.set_pqc_trust_bundle_signing_keys_configured(bundle_signing_keys.len() as u64);
        if let Some(loaded) = trust_bundle_loaded.as_ref() {
            p2p.set_pqc_trust_bundle_loaded(1);
            p2p.set_pqc_trust_bundle_environment(loaded.environment().metric_code());
            p2p.set_pqc_trust_bundle_active_roots(loaded.active_root_count() as u64);
            p2p.set_pqc_trust_bundle_revoked_roots(loaded.revoked_root_count() as u64);
            // Run 062: revocation activation-gate gauges.
            // `_root_active` == `_revoked_roots` by construction (kept
            // as a separate name so the active vs. pending split is
            // symmetrical with the leaf surface).
            p2p.set_pqc_trust_bundle_revocations_configured_total(
                loaded.configured_revocations_total() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_active_total(
                loaded.active_revocations_total() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_pending_total(
                loaded.pending_revocations_total() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_root_active(
                loaded.revoked_root_count() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_root_pending(
                loaded.pending_revoked_root_count() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_leaf_active(
                loaded.revoked_leaf_fingerprint_count() as u64,
            );
            p2p.set_pqc_trust_bundle_revocations_leaf_pending(
                loaded.pending_revoked_leaf_fingerprint_count() as u64,
            );
            eprintln!(
                "[binary] Run 062: trust-bundle revocation activation \
                 (configured={} active={} pending={} \
                  root_active={} root_pending={} \
                  leaf_active={} leaf_pending={})",
                loaded.configured_revocations_total(),
                loaded.active_revocations_total(),
                loaded.pending_revocations_total(),
                loaded.revoked_root_count(),
                loaded.pending_revoked_root_count(),
                loaded.revoked_leaf_fingerprint_count(),
                loaded.pending_revoked_leaf_fingerprint_count(),
            );
            p2p.set_pqc_trust_bundle_sequence(loaded.bundle.sequence);
            // Run 051: bump the verified counter exactly once on a
            // successfully verified signed bundle. Unsigned bundles
            // leave the counter at zero.
            if loaded.signature_status.is_verified() {
                p2p.inc_pqc_trust_bundle_signature_verified();
            }
        }
    }

    // Run 061 — local revoked-leaf startup self-check.
    //
    // If the node's own `--p2p-leaf-cert` fingerprint is on the
    // loaded trust bundle's currently-active
    // `revoked_leaf_fingerprints` set, fail closed BEFORE any P2P
    // state is constructed or any peer connection is attempted. We
    // run this check AFTER:
    //   - signed-bundle ML-DSA-44 signature verification (Run 051),
    //   - environment binding (Run 050),
    //   - chain_id binding (Run 053),
    //   - activation-height gating (Run 057),
    //   - sequence anti-rollback persistence (Run 055),
    //   - root + revocation extraction (Run 050/052),
    // and BEFORE:
    //   - `pqc_config` is moved into the builder,
    //   - `P2pNodeBuilder::with_pqc_leaf_revocations` is called
    //     (which would install the peer-side
    //     `LeafCertRevocationList`),
    //   - `builder.build(...)` constructs any live P2P trust
    //     context, listener, dialer, or peer manager,
    //   - any cert-verify counter could move.
    //
    // The helper takes ONLY the public cert bytes + the public
    // revocation set + the public bundle fingerprint. The KEM
    // secret (`--p2p-leaf-cert-key`) and any bundle-signing or
    // transport-root secret are not consulted. The fingerprint
    // semantics are byte-identical to Run 052's peer-handshake
    // fingerprint (see `pqc_trust_bundle::cert_leaf_fingerprint`
    // and the regression test `run_061_self_check_fingerprint_
    // equals_run_052_handshake_fingerprint`), so the startup
    // self-check and the peer-handshake check agree by
    // construction.
    if let (Some(loaded), Some(local_leaf)) =
        (trust_bundle_loaded.as_ref(), leaf_credentials.as_ref())
    {
        if !loaded.revoked_leaf_fingerprints.is_empty() {
            match qbind_node::pqc_trust_bundle::check_local_leaf_not_revoked(
                &local_leaf.cert_bytes,
                &loaded.revoked_leaf_fingerprints,
                &loaded.fingerprint,
            ) {
                Ok(local_fp) => {
                    let local_fp_hex =
                        qbind_node::pqc_trust_bundle::cert_leaf_fingerprint_hex(&local_fp);
                    eprintln!(
                        "[binary] Run 061: local-leaf startup self-check passed \
                         (local_leaf_fp={}.. bundle_fp={}.. \
                         active_revoked_leaf_fingerprints={})",
                        &local_fp_hex[..8],
                        &loaded.fingerprint_hex()[..8],
                        loaded.revoked_leaf_fingerprint_count(),
                    );
                }
                Err(e) => {
                    use qbind_node::pqc_trust_bundle::LocalLeafSelfCheckError;
                    // We deliberately do NOT bump
                    // `qbind_p2p_pqc_cert_verify_rejected_revoked_total`
                    // here: that family is the Run 052 peer-handshake
                    // contract and must remain a handshake-only signal.
                    // A dedicated startup metric is not added in Run
                    // 061 because the node exits before `/metrics` is
                    // bound by the live HTTP path, so a counter would
                    // never be scrapeable — adding it would be
                    // misleading per task §4 (metrics/logging).
                    match &e {
                        LocalLeafSelfCheckError::Revoked {
                            leaf_fingerprint_prefix,
                            bundle_fingerprint_prefix,
                        } => {
                            eprintln!(
                                "[binary] FATAL: Run 061 local leaf certificate revoked: \
                                 the local --p2p-leaf-cert fingerprint ({}..) appears in the \
                                 active revoked_leaf_fingerprints set of the loaded trust \
                                 bundle (bundle fp {}..). Refusing to start P2P. No fallback \
                                 to --p2p-trusted-root on bundle-revoked local leaf. See \
                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_061.md and \
                                 docs/whitepaper/contradiction.md C4 (signed root \
                                 distribution).",
                                leaf_fingerprint_prefix, bundle_fingerprint_prefix,
                            );
                            std::process::exit(1);
                        }
                        LocalLeafSelfCheckError::DecodeFailed => {
                            // Unreachable on this path —
                            // `PqcLeafCredentialPaths::load` already
                            // validated the cert shape. Preserve
                            // fail-closed behaviour anyway.
                            eprintln!(
                                "[binary] FATAL: Run 061 local --p2p-leaf-cert could not be \
                                 decoded as NetworkDelegationCert during startup self-check. \
                                 Refusing to start P2P. See \
                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_061.md."
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

    // Run 063 — local revoked-issuer-root startup self-check.
    //
    // If the node's own `--p2p-leaf-cert` was issued by a transport
    // root that is on the loaded trust bundle's currently-ACTIVE
    // `revoked_root_ids` set, fail closed BEFORE any P2P state is
    // constructed or any peer connection is attempted. We use
    // `loaded.revoked_root_ids` (the ACTIVE set built by Run 062's
    // `validate_at_with_signing_keys_chain_id_and_revocation_activation`):
    // PENDING root revocations (`pending_revoked_root_ids`) MUST NOT
    // trigger startup failure.
    //
    // Ordering. This check runs:
    //   - AFTER signed-bundle ML-DSA-44 signature verification
    //     (Run 051), environment binding (Run 050), chain_id
    //     binding (Run 053), activation-height gating (Run 057),
    //     sequence anti-rollback persistence (Run 055), revocation
    //     activation filtering (Run 062), and the Run 061 local
    //     leaf-fingerprint self-check;
    //   - BEFORE `pqc_config` is moved into the builder,
    //     `P2pNodeBuilder::with_pqc_leaf_revocations` is called,
    //     `builder.build(...)` constructs any live P2P trust
    //     context, listener, dialer, or peer manager, and any
    //     cert-verify counter could move.
    //
    // Identity rule. The issuer root identity is taken from the
    // decoded `NetworkDelegationCert.root_key_id` field — byte-
    // identical to the identity the cert-verify path uses to look
    // up the trusted root pk (pinned by the unit test
    // `run063_self_check_uses_same_root_id_as_cert_verify_path`).
    //
    // Metrics/logging. No new `/metrics` family is added: the node
    // exits before `/metrics` is bound by the live HTTP path, so a
    // counter bumped here would never be scrapeable. The Run 052
    // peer-handshake counter `qbind_p2p_pqc_cert_verify_rejected_
    // revoked_total` is NOT bumped — it is a handshake metric.
    if let (Some(loaded), Some(local_leaf)) =
        (trust_bundle_loaded.as_ref(), leaf_credentials.as_ref())
    {
        match qbind_node::pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked(
            &local_leaf.cert_bytes,
            &loaded.revoked_root_ids,
            &loaded.fingerprint,
        ) {
                Ok(local_root_id) => {
                    let local_root_hex =
                        qbind_node::pqc_trust_bundle::cert_leaf_fingerprint_hex(&local_root_id);
                    eprintln!(
                        "[binary] Run 063: local-leaf issuer-root startup self-check passed \
                         (local_issuer_root_id={}.. bundle_fp={}.. \
                         active_revoked_root_ids={})",
                        &local_root_hex[..8],
                        &loaded.fingerprint_hex()[..8],
                        loaded.revoked_root_count(),
                    );
                }
                Err(e) => {
                    use qbind_node::pqc_trust_bundle::LocalLeafIssuerRootSelfCheckError;
                    // We deliberately do NOT bump
                    // `qbind_p2p_pqc_cert_verify_rejected_revoked_total`
                    // here: that family is the Run 052 peer-handshake
                    // contract and must remain a handshake-only signal.
                    // A dedicated startup metric is not added in Run
                    // 063 because the node exits before `/metrics` is
                    // bound by the live HTTP path, so a counter would
                    // never be scrapeable — adding it would be
                    // misleading per task §4 (metrics/logging).
                    match &e {
                        LocalLeafIssuerRootSelfCheckError::IssuerRootRevoked {
                            root_id_prefix,
                            leaf_fingerprint_prefix,
                            bundle_fingerprint_prefix,
                        } => {
                            eprintln!(
                                "[binary] FATAL: Run 063 local leaf certificate issuer root revoked: \
                                 the local --p2p-leaf-cert was issued by transport root id ({}..) \
                                 which appears in the active revoked_root_ids set of the loaded \
                                 trust bundle (bundle fp {}.., local leaf fp {}..). Refusing to \
                                 start P2P. No fallback to --p2p-trusted-root on bundle-revoked \
                                 local issuer root. See \
                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md and \
                                 docs/whitepaper/contradiction.md C4 (signed root \
                                 distribution).",
                                root_id_prefix, bundle_fingerprint_prefix, leaf_fingerprint_prefix,
                            );
                            std::process::exit(1);
                        }
                        LocalLeafIssuerRootSelfCheckError::DecodeFailed => {
                            // Unreachable on this path —
                            // `PqcLeafCredentialPaths::load` already
                            // validated the cert shape. Preserve
                            // fail-closed behaviour anyway.
                            eprintln!(
                                "[binary] FATAL: Run 063 local --p2p-leaf-cert could not be \
                                 decoded as NetworkDelegationCert during startup issuer-root \
                                 self-check. Refusing to start P2P. See \
                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md."
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
    }

    // Run 074: extract the local leaf cert bytes (if any) NOW,
    // before `leaf_credentials` is moved into `PqcStaticRootConfig`.
    // We can't keep a borrow because the SIGHUP task lives across
    // an await boundary; an owned `Option<Vec<u8>>` is the smallest
    // clone we can make.
    let live_reload_leaf_bytes: Option<Vec<u8>> = leaf_credentials
        .as_ref()
        .map(|c| c.cert_bytes.clone());

    let pqc_config = PqcStaticRootConfig {
        mode: pqc_root_mode,
        trusted_roots: trusted_roots.clone(),
        leaf_credentials,
        peer_leaf_certs,
    };

    eprintln!(
        "[binary] Run 039: pqc_root_mode={} transport_kem_suite=ml-kem-768 configured_roots={} \
         leaf_credentials_present={} peer_leaf_certs={} (root fingerprints: [{}])",
        pqc_config.mode,
        pqc_config.trusted_roots.len(),
        pqc_config.leaf_credentials.is_some(),
        pqc_config.peer_leaf_certs.len(),
        pqc_config
            .trusted_roots
            .iter()
            .map(|r| format!(
                "id={}.. suite={} fp={}",
                &r.root_key_id_hex()[..8],
                r.suite_id,
                r.pk_fingerprint()
            ))
            .collect::<Vec<_>>()
            .join("; "),
    );

    let builder = builder.with_pqc_root_config(pqc_config);

    // Run 052 — wire the loaded trust bundle's currently-active leaf-cert
    // revocation set into the builder. The builder will install a
    // `LeafCertRevocationList` on both client- and server-side
    // handshake configs ONLY on the production-honest PQC mutual-auth
    // path; on the test-grade DummySig / non-PQC path the set is
    // ignored. An empty active set takes the zero-cost no-op path so
    // pre-Run-052 behaviour is preserved bit-for-bit when no leaf
    // revocations are configured.
    let builder = if let Some(loaded) = trust_bundle_loaded.as_ref() {
        let revoked_leaves: std::collections::HashSet<[u8; 32]> =
            loaded.revoked_leaf_fingerprints.iter().copied().collect();
        let revoked_count = revoked_leaves.len();
        eprintln!(
            "[binary] Run 052: revoked_leaf_fingerprints={} (from trust bundle env={} sequence={})",
            revoked_count,
            loaded.environment(),
            loaded.bundle.sequence,
        );
        if revoked_count > 0 {
            builder.with_pqc_leaf_revocations(std::sync::Arc::new(revoked_leaves))
        } else {
            builder
        }
    } else {
        builder
    };

    // Run 071 — install the shared live PQC trust-state handle.
    //
    // The handle is initialized once from the already-validated
    // `LoadedTrustBundle` (the same value that drives Run 052's
    // `with_pqc_leaf_revocations` above and Run 037's
    // `with_pqc_root_config`), so the listener-side
    // `TrustedClientRoots` resolver and the bidirectional
    // `LeafCertRevocationList` continue to verify against
    // **byte-identical** trust material as before. Run 071 NEVER
    // mutates the live handle after this point on the binary path
    // — Run 074's long-running-node SIGHUP trigger (below) drives
    // mutation through `LivePqcTrustState::swap_snapshot` only on
    // explicit operator action.
    //
    // Run 074: clone the freshly-initialized `LivePqcTrustState`
    // here so the SIGHUP signal-handler task spawned below can hold
    // an `Arc` on the SAME handle the builder consumes (the inner
    // RwLock is what every handshake reads from; cloning the
    // wrapper here merely Arc-bumps the shared lock).
    let live_for_reload_apply: Option<qbind_node::pqc_live_trust::LivePqcTrustState> =
        trust_bundle_loaded.as_ref().map(|loaded| {
            let live =
                qbind_node::pqc_live_trust::LivePqcTrustState::initialize_from_loaded_bundle(
                    loaded,
                );
            eprintln!(
                "[binary] Run 071: live PQC trust-state initialized \
                 (env={} sequence={} fingerprint={} active_roots={} \
                 revoked_roots_active={} revoked_leaves_active={})",
                loaded.environment(),
                loaded.bundle.sequence,
                loaded.fingerprint_hex(),
                loaded.active_root_count(),
                loaded.revoked_root_count(),
                loaded.revoked_leaf_fingerprint_count(),
            );
            live
        });
    let builder = if let Some(live) = live_for_reload_apply.as_ref() {
        builder.with_live_pqc_trust(live.clone())
    } else {
        builder
    };

    let node_context = match builder.build(config, validator_id).await {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("[binary] ERROR: Failed to build P2P node: {:?}", e);
            std::process::exit(1);
        }
    };

    eprintln!(
        "[binary] P2P transport up. Listen address: {}, static peers: {}",
        config.network.listen_addr.as_deref().unwrap_or("unknown"),
        config.network.static_peers.len()
    );

    // C4/B6: outbound consensus path. Reuse the existing
    // `P2pConsensusNetwork` already created by the builder so that
    // outbound proposals/votes leave through the same `TcpKemTlsP2pService`
    // instance the inbound side is reading from. We do not introduce a
    // second parallel networking architecture.
    //
    // B11: wire `node_metrics` so the `consensus_net_outbound_total`
    // Prometheus family on `/metrics` honestly reflects the outbound
    // proposal / vote traffic this facade actually pushes to the
    // transport. Without this, the family stays at 0 on the real
    // binary path even when the loop-level `outbound_*` counters and
    // engine-acceptance counters report real progress (the gap
    // surfaced by DevNet Evidence Run 008/009).
    let outbound_facade: Arc<dyn qbind_node::consensus_network_facade::ConsensusNetworkFacade> =
        Arc::new(
            P2pConsensusNetwork::new(node_context.p2p_service.clone(), num_validators as usize)
                .with_local_validator(local_validator_id)
                .with_metrics(Arc::clone(&node_metrics)),
        );

    let mut consensus_cfg = BinaryConsensusLoopConfig::new(local_validator_id, num_validators);
    if let Some(b) = restore_baseline {
        consensus_cfg = consensus_cfg.with_restore_baseline(b);
    }
    consensus_cfg = consensus_cfg.with_periodic_snapshot(binary_periodic_snapshot_config(
        config,
        args,
        vm_v0_runtime.clone(),
    ));
    eprintln!(
        "[binary] Consensus loop config: local_validator_id={:?} num_validators={} \
         restore_baseline={} interconnect=p2p",
        local_validator_id,
        num_validators,
        restore_baseline.is_some(),
    );
    if num_validators == 1 {
        eprintln!(
            "[binary] Single-validator P2P: leader self-quorum will commit a block per tick. \
             Inbound P2P → engine routing is wired but no peers will exercise it."
        );
    } else {
        eprintln!(
            "[binary] Multi-validator P2P ({} validators): inbound P2P consensus messages \
             are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; \
             engine actions flow back out through P2pConsensusNetwork.",
            num_validators
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let snapshot_handle = spawn_vm_v0_snapshot_signal_task(
        vm_v0_runtime,
        Arc::clone(&node_metrics),
        config.chain_id().as_u64(),
        shutdown_rx.clone(),
    );

    // ------------------------------------------------------------------
    // Run 074 — long-running local operator-triggered live trust-bundle
    // reload-apply trigger: install SIGHUP handler against the running
    // node's live `LivePqcTrustState` + live `TcpKemTlsP2pService`
    // session-evictor + on-disk sequence persistence + `/metrics`
    // surface.
    //
    // Gating: disabled by default. The pair
    //   --p2p-trust-bundle-live-reload-enabled
    //   --p2p-trust-bundle-live-reload-path <PATH>
    // is enforced as required-together at the top of `main()` so an
    // operator cannot accidentally arm the trigger by setting only
    // one flag. This block fires only when BOTH flags are present AND
    // the runtime mode has a live `TcpKemTlsP2pService` (the P2P mode
    // — the only mode that reaches this block).
    //
    // On every SIGHUP the controller validates the candidate file
    // through the SAME Run 069 pipeline, applies it through the SAME
    // Run 073 `ProductionLiveTrustApplyContext` against the running
    // node's live trust handle, and evicts every authenticated
    // KEMTLS session via the live `TcpKemTlsP2pService` (Run 072).
    // The atomic sequence writer ensures the on-disk record advances
    // only on full success. Concurrent triggers are serialised by
    // the controller's `Arc<AtomicBool>` in-progress guard.
    //
    // Fatal-branch policy: if `SequenceCommitFailedRollbackAlsoFailed`
    // ever surfaces, the live trust state may be ahead of the
    // on-disk sequence record. This handler signals graceful shutdown
    // via `shutdown_tx` so the operator can intervene offline.
    //
    // See `crates/qbind-node/src/pqc_live_trust_reload.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md`, and
    // `docs/whitepaper/contradiction.md` C4.
    #[cfg(unix)]
    let _live_reload_handle: Option<tokio::task::JoinHandle<()>> = {
        let evictor: Arc<dyn qbind_node::p2p_session_eviction::P2pSessionEvictor> =
            node_context.p2p_service.clone();
        spawn_run074_live_reload_task(
            args,
            config,
            &bundle_signing_keys,
            live_reload_leaf_bytes,
            live_for_reload_apply.clone(),
            evictor,
            node_metrics.p2p_arc(),
            shutdown_rx.clone(),
            shutdown_tx.clone(),
        )
    };
    #[cfg(not(unix))]
    let _live_reload_handle: Option<tokio::task::JoinHandle<()>> = {
        if args.p2p_trust_bundle_live_reload_enabled {
            eprintln!(
                "[binary] Run 074: SIGHUP-driven live trust-bundle reload-apply trigger is \
                 only supported on Unix runtimes; ignoring \
                 --p2p-trust-bundle-live-reload-enabled on this platform."
            );
        }
        None
    };

    // B9: late-peer-connect proposal re-emission.
    //
    // The same `Arc<dyn P2pService>` that backs both the inbound demuxer
    // and the outbound `P2pConsensusNetwork` also serves as the
    // `PeerConnectivitySource`, so connectivity, outbound, and inbound
    // observations all come from the same transport instance — no
    // parallel networking architecture, no harness-only glue. The loop
    // uses this only to detect a `not-connected → connected` transition
    // for an expected static peer and re-emit the current view's
    // already-emitted leader proposal exactly once (boundedness rules
    // documented on `BinaryConsensusLoopIo::peer_connectivity`).
    //
    // Single-validator P2P (num_validators == 1) still wires this — it's
    // harmless because there are no other expected peers, so the
    // newly-connected set stays empty and re-emission never fires.
    let peer_connectivity: Arc<dyn qbind_node::binary_consensus_loop::PeerConnectivitySource> =
        Arc::new(
            qbind_node::binary_consensus_loop::P2pServicePeerConnectivity::new(
                node_context.p2p_service.clone(),
            ),
        );
    // ------------------------------------------------------------------
    // Run 031 + Run 032: TimeoutVerificationContext activation bridge.
    //
    // The Run 030 binary loop honours an `Arc<TimeoutVerificationContext>`
    // end-to-end. Production activation requires a real
    // `SuiteAwareValidatorKeyProvider` covering every active validator,
    // a `ConsensusSigBackendRegistry` with a backend for every governed
    // suite (today: ML-DSA-44 / suite_id 100), and an
    // `Arc<dyn ValidatorSigner>` over the local signing key.
    //
    // Run 032 lands the **signer half** honestly:
    //  * `signer_loader::load_validator_signer_from_config` reads
    //    `config.signer_keystore_path` and constructs an
    //    `Arc<dyn ValidatorSigner>` via the existing keystore
    //    primitives (no new key format, no fake keys, no key
    //    material in logs).
    //
    // The peer-side blockers remain:
    //  * `NodeConfig.network.static_peers` carries no per-peer
    //    `(suite_id, pk_bytes)`, so no `SuiteAwareValidatorKeyProvider`
    //    can be honestly constructed for the active validator set;
    //  * `--p2p-mutual-auth` itself runs on B12's test-grade
    //    `TrustedClientRoots`/`DummySig` stack (see lines 427-472).
    //
    // The Run 032 probe below therefore returns `Disabled` with the
    // narrowed reason `SignerPresentKeyProviderUnavailable` whenever
    // the signer load succeeded, and the original Run 031
    // `ProductionPiecesUnavailable` whenever it did not. Activation
    // never happens in this run — `try_build_timeout_verification_context`
    // is **not** called with empty / fake key-provider input.
    //
    // Policy:
    //  * `--require-timeout-verification` ⇒ `RequireOrFail` (refuse
    //    to start under any `Disabled` outcome — including
    //    "signer loaded but key-provider missing");
    //  * otherwise ⇒ `OptionalActivate` (log the precise reason,
    //    fall back to `verification_ctx: None`).
    // ------------------------------------------------------------------
    use qbind_node::peer_key_provider::{
        build_validator_set_and_key_provider, PeerKeyProviderError,
    };
    use qbind_node::signer_loader::{load_validator_signer_from_config, SignerLoadError};
    use qbind_node::timeout_verification_bridge::{
        enforce_policy, run_032_probe_with_signer, try_build_timeout_verification_context,
        TimeoutVerificationActivation, TimeoutVerificationBridgeInputs,
        TimeoutVerificationDisabledReason, TimeoutVerificationPolicy,
    };

    let timeout_verification_policy = if args.require_timeout_verification {
        TimeoutVerificationPolicy::RequireOrFail
    } else {
        TimeoutVerificationPolicy::OptionalActivate
    };

    // Attempt signer load. Honest "no" is reportable but does NOT
    // by itself fail closed — the `RequireOrFail` policy only
    // triggers below when the bridge outcome stays `Disabled`.
    let signer_load_result = load_validator_signer_from_config(config, local_validator_id);
    let (signer_for_bridge, local_signer_pk, signer_log_summary): (
        Option<std::sync::Arc<dyn qbind_node::validator_signer::ValidatorSigner>>,
        Option<Vec<u8>>,
        String,
    ) = match &signer_load_result {
        Ok(loaded) => {
            eprintln!(
                "[binary] Run 032: validator signer loaded — backend={} validator_id={:?} \
                 suite_id={} pk_fingerprint={} keystore_path={}",
                loaded.backend,
                loaded.validator_id,
                loaded.suite_id,
                loaded.public_key_fingerprint,
                config
                    .signer_keystore_path
                    .as_deref()
                    .map(qbind_node::signer_loader::safe_keystore_path_log)
                    .unwrap_or_else(|| "<unset>".to_string()),
            );
            (
                Some(loaded.signer.clone()),
                Some(loaded.public_key_bytes.clone()),
                format!(
                    "loaded(backend={},validator={:?},suite={})",
                    loaded.backend, loaded.validator_id, loaded.suite_id
                ),
            )
        }
        Err(SignerLoadError::KeystorePathNotConfigured) => {
            eprintln!(
                "[binary] Run 032: validator signer not loaded — \
                 config.signer_keystore_path is not set; Run 030 bit-equivalent path \
                 (no outbound timeout signing). See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md."
            );
            (
                None,
                None,
                "absent(keystore_path_not_configured)".to_string(),
            )
        }
        Err(e) => {
            eprintln!(
                "[binary] Run 032: validator signer load FAILED — {} (no key material in this \
                 message). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md.",
                e
            );
            (None, None, format!("load_failed({})", e))
        }
    };

    node_metrics.set_timeout_verification_signer_loaded(signer_for_bridge.is_some());

    // If the operator declared `--require-timeout-verification` and
    // the signer half was not even loaded, fail closed *before* we
    // ask the bridge anything: the operator's intent is unambiguous,
    // and the bridge's `SignerPresentKeyProviderUnavailable` /
    // `ProductionPiecesUnavailable` narrowing is informational. We
    // surface a precise, signer-specific error here.
    if matches!(
        timeout_verification_policy,
        TimeoutVerificationPolicy::RequireOrFail
    ) {
        if let Err(err) = &signer_load_result {
            eprintln!(
                "[binary] FATAL: --require-timeout-verification was set but the local validator \
                 signer could not be loaded: {}. qbind-node refuses to start. See \
                 docs/whitepaper/contradiction.md C5 and \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md.",
                err
            );
            std::process::exit(1);
        }
    }

    // ------------------------------------------------------------------
    // Run 033: peer-side `SuiteAwareValidatorKeyProvider` half of the
    // activation bridge.
    //
    // Build the provider + validator set from the explicit
    // `network.static_peer_consensus_keys` config (CLI:
    // `--validator-consensus-key VID:SUITE:HEXPK`). Fail-closed on
    // bad hex, unsupported suite, duplicate vid, missing peer key,
    // bare peer addr, missing local key, or signer mismatch.
    //
    // When the provider builds successfully AND the signer is
    // present, we feed the real
    // `try_build_timeout_verification_context` instead of the Run 032
    // signer-only probe — this is the activation path the rest of C5
    // has been waiting for.
    //
    // When the provider cannot be built (typically: no
    // `static_peer_consensus_keys` configured), we preserve Run 032
    // disabled behaviour bit-for-bit.
    // ------------------------------------------------------------------
    let peer_kp_result = build_validator_set_and_key_provider(
        config,
        local_validator_id,
        local_signer_pk.as_deref(),
    );
    let (loaded_kp, peer_kp_log_summary): (
        Option<qbind_node::peer_key_provider::LoadedValidatorKeyProvider>,
        String,
    ) = match peer_kp_result {
        Ok(loaded) => {
            let log = format!(
                "loaded(validators={},peer_ids={:?},suite_ids={:?},fingerprints={:?})",
                loaded.validator_count,
                loaded
                    .peer_validator_ids
                    .iter()
                    .map(|v| v.as_u64())
                    .collect::<Vec<_>>(),
                loaded
                    .suite_ids
                    .iter()
                    .map(|s| s.as_u16())
                    .collect::<Vec<_>>(),
                loaded
                    .fingerprints
                    .iter()
                    .map(|(v, s, fp)| format!("v{}:s{}:{}", v.as_u64(), s.as_u16(), fp))
                    .collect::<Vec<_>>(),
            );
            eprintln!(
                "[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly — {}",
                log
            );
            (Some(loaded), log)
        }
        Err(PeerKeyProviderError::NoConfiguredKeys) => {
            eprintln!(
                "[binary] Run 033: SuiteAwareValidatorKeyProvider NOT built — \
                 network.static_peer_consensus_keys is empty (no \
                 --validator-consensus-key entries). Preserving Run 032 \
                 SignerPresentKeyProviderUnavailable disabled behaviour. See \
                 docs/whitepaper/contradiction.md C5."
            );
            (None, "absent(no_configured_keys)".to_string())
        }
        Err(e) => {
            eprintln!(
                "[binary] Run 033: SuiteAwareValidatorKeyProvider build FAILED — {}. \
                 See docs/whitepaper/contradiction.md C5 and \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_033.md.",
                e
            );
            // Under RequireOrFail, this is fatal — fail closed now
            // with a precise reason, rather than letting the bridge
            // silently fall back to disabled.
            if matches!(
                timeout_verification_policy,
                TimeoutVerificationPolicy::RequireOrFail
            ) {
                eprintln!(
                    "[binary] FATAL: --require-timeout-verification was set but the \
                     peer-side SuiteAwareValidatorKeyProvider could not be built \
                     honestly: {}. qbind-node refuses to start.",
                    e
                );
                std::process::exit(1);
            }
            (None, format!("load_failed({})", e))
        }
    };

    node_metrics.set_timeout_verification_key_provider_loaded(loaded_kp.is_some());

    // Build the activation outcome. If both halves are present, run
    // the real `try_build_timeout_verification_context`; otherwise
    // preserve the Run 032 signer-only probe.
    let supported_suite_ids: &[u16] = &[100]; // ML-DSA-44 (SUITE_PQ_RESERVED_1)
    let timeout_verification_outcome: TimeoutVerificationActivation =
        match (signer_for_bridge.clone(), loaded_kp.as_ref()) {
            (Some(signer), Some(kp)) => {
                // Real bridge inputs — reuse existing
                // `SimpleBackendRegistry` + `MlDsa44Backend` constructors,
                // explicitly registering the supported suite. Any
                // unsupported suite reaching the bridge will fail closed
                // there.
                use qbind_consensus::crypto_verifier::SimpleBackendRegistry;
                use qbind_crypto::{ml_dsa44::MlDsa44Backend, ConsensusSigSuiteId};
                let mut registry = SimpleBackendRegistry::new();
                registry.register(
                    ConsensusSigSuiteId::new(100),
                    std::sync::Arc::new(MlDsa44Backend::new()),
                );
                let inputs = TimeoutVerificationBridgeInputs {
                    validators: kp.validators.clone(),
                    key_provider: kp.key_provider.clone(),
                    backend_registry: std::sync::Arc::new(registry),
                    chain_id: config.chain_id(),
                    signer: Some(signer),
                    local_validator_id,
                };
                try_build_timeout_verification_context(inputs)
            }
            _ => {
                // No production peer keys (or no signer) — fall back to
                // Run 032 disabled-with-precise-reason path.
                run_032_probe_with_signer(signer_for_bridge.clone(), local_validator_id)
            }
        };

    eprintln!(
        "[binary] Run 033: timeout-verification probe: active={} reason={} \
         policy={:?} validators={} chain_id={} supported_suite_ids={:?} \
         local_signer={} peer_key_provider={}",
        timeout_verification_outcome.is_active(),
        match timeout_verification_outcome.disabled_reason() {
            Some(r) => format!("{}", r),
            None => "n/a".to_string(),
        },
        timeout_verification_policy,
        loaded_kp
            .as_ref()
            .map(|kp| kp.validator_count as u64)
            .unwrap_or(num_validators),
        config.chain_id(),
        supported_suite_ids,
        signer_log_summary,
        peer_kp_log_summary,
    );
    let verification_ctx =
        match enforce_policy(timeout_verification_policy, timeout_verification_outcome) {
            Ok(opt) => opt,
            Err(e) => {
                eprintln!(
                    "[binary] FATAL: --require-timeout-verification was set but timeout \
                 verification cannot be activated honestly: {}",
                    e
                );
                eprintln!(
                    "[binary] qbind-node refuses to start under RequireOrFail policy with no \
                 production-safe context. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_031.md, \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_032.md, \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_033.md, \
                 and docs/whitepaper/contradiction.md C5/C4."
                );
                std::process::exit(1);
            }
        };
    node_metrics.set_timeout_verification_active(verification_ctx.is_some());
    node_metrics.set_timeout_verification_validator_count(if verification_ctx.is_some() {
        loaded_kp
            .as_ref()
            .map(|kp| kp.validator_count as u64)
            .unwrap_or(0)
    } else {
        0
    });
    if verification_ctx.is_some() {
        eprintln!(
            "[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext> \
             threaded into BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg / \
             NewView / TC traffic will be verified before engine ingestion; locally-emitted \
             timeouts will be signed before broadcast. signer_loaded=1 \
             key_provider_loaded=1 validator_count={}",
            loaded_kp
                .as_ref()
                .map(|kp| kp.validator_count as u64)
                .unwrap_or(0)
        );
    } else if loaded_kp.is_some() && signer_for_bridge.is_some() {
        // Both halves present but bridge still refused — surface
        // the precise reason. (Should not normally happen under
        // OptionalActivate without a deeper invariant violation;
        // RequireOrFail would have already exited above.)
        eprintln!(
            "[binary] Run 033: timeout verification DISABLED — both halves present but \
             bridge refused. See probe-line above for reason."
        );
    } else if signer_for_bridge.is_some() {
        eprintln!(
            "[binary] Run 033: timeout verification DISABLED — signer half wired honestly \
             but peer-side SuiteAwareValidatorKeyProvider not configured (set \
             --validator-consensus-key for every active validator). \
             BinaryConsensusLoopIo::verification_ctx=None. See \
             docs/whitepaper/contradiction.md C5."
        );
    } else {
        eprintln!(
            "[binary] Run 033: timeout verification DISABLED — \
             BinaryConsensusLoopIo::verification_ctx=None (Run 030 bit-equivalent path). \
             Inbound timeout/new-view crypto verification and outbound timeout signing \
             remain off until production pieces land. See \
             docs/whitepaper/contradiction.md C5."
        );
    }
    // Suppress unused-variant lint when the bridge currently can't
    // produce certain disabled reasons in this binary path.
    let _ = TimeoutVerificationDisabledReason::IntentionallyDisabled;

    let io = BinaryConsensusLoopIo {
        inbound_rx: consensus_inbound_rx,
        outbound: outbound_facade,
        peer_connectivity: Some(peer_connectivity),
        verification_ctx,
    };
    let (consensus_handle, _progress) =
        spawn_binary_consensus_loop_with_io(consensus_cfg, shutdown_rx, node_metrics, io);

    // Run 035: opt-in, dev/test-only forged Timeout/NewView injection
    // harness. Disabled by default. Activation requires THREE
    // concurrent signals (CLI cases + `--env devnet` +
    // `QBIND_DEVNET_FORGED_INJECTION=1`); any missing signal is a
    // fail-closed startup error. See
    // `crates/qbind-node/src/forged_injection.rs` and
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md`.
    let run035_handle = maybe_spawn_run035_forged_injection_harness(
        &args,
        &config,
        consensus_inbound_tx_for_run035,
        num_validators,
    );

    eprintln!("[binary] P2P node started. Press Ctrl+C to exit.");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[binary] Shutdown signal received, stopping P2P node...");

    drop(shutdown_tx);
    let _ = consensus_handle.await;
    if let Some(handle) = run035_handle {
        let _ = handle.await;
    }
    if let Some(handle) = snapshot_handle {
        let _ = handle.await;
    }

    if let Err(e) = P2pNodeBuilder::shutdown(node_context).await {
        eprintln!("[binary] Error during P2P shutdown: {:?}", e);
    }
    eprintln!("[binary] P2P node shutdown complete.");
}

/// Run 035 — opt-in dev/test-only forged Timeout/NewView injection
/// harness wiring. Returns `None` when the harness is disabled (which
/// is the default and the only outcome on Testnet/Mainnet); returns
/// `Some(handle)` when activation succeeded under
/// `--env devnet` AND `QBIND_DEVNET_FORGED_INJECTION=1` AND at least
/// one `--devnet-forged-inject CASE` flag.
///
/// On any non-fatal activation refusal the binary continues with the
/// harness inert. On a CLI parse error (unknown case token) or a
/// safety-gate violation (the operator passed cases under non-Devnet),
/// the binary refuses startup with `std::process::exit(1)` so it is
/// impossible to silently activate the harness in production.
fn maybe_spawn_run035_forged_injection_harness(
    args: &CliArgs,
    config: &qbind_node::node_config::NodeConfig,
    sender: tokio::sync::mpsc::Sender<qbind_node::p2p::ConsensusNetMsg>,
    num_validators: u64,
) -> Option<tokio::task::JoinHandle<()>> {
    use qbind_node::forged_injection::{
        ForgedInjectionCase, ForgedInjectionGateError, ForgedInjectionHarness, RuntimeFixture,
        FORGED_INJECTION_ENV_VAR,
    };

    if args.devnet_forged_inject.is_empty() {
        // Default disabled path — emit nothing so /metrics, logs, and
        // startup banner stay byte-identical to the harness-absent run.
        return None;
    }

    // Parse case tokens up front so a typo fails closed before any
    // gate evaluation.
    let mut cases: Vec<ForgedInjectionCase> = Vec::with_capacity(args.devnet_forged_inject.len());
    for raw in args.devnet_forged_inject.iter() {
        match ForgedInjectionCase::parse(raw) {
            Ok(c) => cases.push(c),
            Err(e) => {
                eprintln!(
                    "[binary] FATAL: --devnet-forged-inject parse error: {}. \
                     Refusing startup. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md.",
                    e
                );
                std::process::exit(1);
            }
        }
    }

    let env_var = std::env::var(FORGED_INJECTION_ENV_VAR).ok();
    let harness =
        match ForgedInjectionHarness::try_activate(config.environment, cases, env_var.as_deref()) {
            Ok(h) => h,
            Err(e @ ForgedInjectionGateError::NotDevnet { .. }) => {
                eprintln!("[binary] FATAL: {}", e);
                std::process::exit(1);
            }
            Err(e @ ForgedInjectionGateError::MissingEnvVar { .. }) => {
                eprintln!("[binary] FATAL: {}", e);
                std::process::exit(1);
            }
            Err(ForgedInjectionGateError::Disabled) => {
                // Already short-circuited above; defensive arm.
                return None;
            }
            Err(e @ ForgedInjectionGateError::UnknownCase(_)) => {
                eprintln!("[binary] FATAL: {}", e);
                std::process::exit(1);
            }
        };

    // Build a self-contained runtime fixture with FRESH ML-DSA-44
    // keypairs the harness uses to construct forged frames. These
    // keys are NOT registered with any production
    // `SuiteAwareValidatorKeyProvider`, so even forged frames whose
    // signatures decode correctly fail signature verification against
    // the real per-validator public keys — exactly the rejection
    // path we want to exercise.
    let mut signing_keys: std::collections::HashMap<qbind_consensus::ids::ValidatorId, Vec<u8>> =
        std::collections::HashMap::new();
    for i in 0..num_validators {
        let (_pk, sk) = match qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair() {
            Ok(kp) => kp,
            Err(e) => {
                eprintln!(
                    "[binary] FATAL: Run 035 forged-injection fixture keygen failed: {:?}. \
                     Refusing to activate harness.",
                    e
                );
                std::process::exit(1);
            }
        };
        signing_keys.insert(qbind_consensus::ids::ValidatorId(i), sk);
    }

    let fixture = std::sync::Arc::new(RuntimeFixture {
        signing_keys,
        chain_id: config.chain_id(),
        // Inject at view 0; the engine starts at view 0 and the
        // verification gate fires regardless of view (forged frames
        // never reach the engine's view-validity check).
        view: 0,
        num_validators,
    });

    eprintln!(
        "[binary] Run 035: forged-injection harness ARMED — env=devnet, {}=1, cases={:?}. \
         Frames will traverse the same binary-loop verification gate as live inbound P2P \
         traffic; the harness never calls into the engine and never fabricates metrics.",
        FORGED_INJECTION_ENV_VAR,
        harness
            .cases()
            .iter()
            .map(|c| c.label())
            .collect::<Vec<_>>()
    );

    Some(qbind_node::forged_injection::spawn_runtime_injection_task(
        harness,
        sender,
        fixture,
        std::time::Duration::from_secs(1),
    ))
}

#[cfg(unix)]
fn spawn_run074_live_reload_task(
    args: &qbind_node::cli::CliArgs,
    config: &qbind_node::NodeConfig,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
    local_leaf_cert_bytes: Option<Vec<u8>>,
    live_state: Option<qbind_node::pqc_live_trust::LivePqcTrustState>,
    p2p_service: Arc<dyn qbind_node::p2p_session_eviction::P2pSessionEvictor>,
    p2p_metrics: Arc<qbind_node::metrics::P2pMetrics>,
    mut shutdown_rx: watch::Receiver<()>,
    shutdown_tx: watch::Sender<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    use qbind_node::pqc_live_trust_reload::{LiveReloadConfig, LiveReloadController};
    use qbind_node::pqc_trust_activation::ActivationContext;

    // Disabled by default.
    if !args.p2p_trust_bundle_live_reload_enabled
        || args.p2p_trust_bundle_live_reload_path.is_none()
    {
        return None;
    }
    let candidate_path = args
        .p2p_trust_bundle_live_reload_path
        .clone()
        .expect("guarded by .is_none() check");

    // Without a baseline live state the controller would always
    // fail closed (no live handle to swap). Refuse to install the
    // handler and tell the operator explicitly. This branch is
    // also unreachable because the top-level main() validator
    // requires `--p2p-trust-bundle` whenever the live-reload flags
    // are set, but defence-in-depth.
    let live_state = match live_state {
        Some(l) => l,
        None => {
            eprintln!(
                "[binary] Run 074: SIGHUP trigger disabled — no baseline \
                 `--p2p-trust-bundle` is present on the live binary path \
                 (no `LivePqcTrustState` to drive). Refusing to install a \
                 handler that would always fail-closed. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md."
            );
            return None;
        }
    };

    let sequence_path = config
        .data_dir
        .as_ref()
        .map(|d| qbind_node::pqc_trust_sequence::sequence_file_path(d));
    let local_leaf_bytes: Option<Vec<u8>> = local_leaf_cert_bytes;
    let cfg = LiveReloadConfig {
        candidate_path: candidate_path.clone(),
        environment: config.environment,
        chain_id: config.chain_id(),
        signing_keys: bundle_signing_keys.clone(),
        // Height-only activation context: this matches the
        // startup-time `--p2p-trust-bundle` activation gate
        // because the runtime height-source for a live node is
        // not currently wired through `ActivationContext` (the
        // same scope boundary documented in
        // `docs/whitepaper/contradiction.md` C4). A future run
        // that lands a live height source can extend this without
        // changing the SIGHUP trigger surface.
        activation_ctx: ActivationContext::height_only(0),
        sequence_path: sequence_path.clone(),
        local_leaf_cert_bytes: local_leaf_bytes,
    };
    let controller = LiveReloadController::new(
        Arc::new(live_state),
        p2p_service,
        p2p_metrics,
        cfg,
    );
    eprintln!(
        "[binary] Run 074: SIGHUP-driven live trust-bundle reload-apply trigger \
         ENABLED. Candidate path: {}. Sequence persistence: {}. On each SIGHUP \
         the candidate is validated through Run 069, applied through Run 073, \
         sessions are evicted via Run 072, and the sequence record is committed \
         atomically. Local file only; no peer / gossip input; concurrent \
         triggers are rejected by an in-process guard. See \
         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md.",
        candidate_path.display(),
        sequence_path
            .as_ref()
            .map(|p: &std::path::PathBuf| p.display().to_string())
            .unwrap_or_else(|| "<no --data-dir; commit will fail-closed>".to_string()),
    );

    let mut sighup =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[binary] Run 074: ERROR installing SIGHUP signal handler: {}. \
                     Live trust-bundle reload-apply trigger is NOT active. The node \
                     continues running with the baseline trust bundle.",
                    e
                );
                return None;
            }
        };

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    eprintln!(
                        "[binary] Run 074: SIGHUP trigger task stopping (shutdown signalled)."
                    );
                    break;
                }
                sig = sighup.recv() => {
                    if sig.is_none() {
                        // Signal stream closed (shouldn't happen
                        // for unix signals on a normal runtime,
                        // but treat as graceful stop).
                        break;
                    }
                    eprintln!(
                        "[binary] Run 074: SIGHUP received — running live trust-bundle \
                         reload-apply trigger."
                    );
                    let controller_for_trigger = controller.clone();
                    let outcome = tokio::task::spawn_blocking(move || {
                        controller_for_trigger.try_trigger()
                    })
                    .await;
                    match outcome {
                        Ok(out) => {
                            eprintln!("{}", out.log_line());
                            if out.is_fatal() {
                                eprintln!(
                                    "[binary] Run 074: FATAL outcome surfaced — signalling \
                                     graceful shutdown. The live trust state may be ahead \
                                     of the on-disk sequence record; recover offline."
                                );
                                let _ = shutdown_tx.send(());
                            }
                        }
                        Err(join_err) => {
                            eprintln!(
                                "[binary] Run 074: trigger task join error: {}. Treating as \
                                 non-fatal; node continues running with current live trust state.",
                                join_err
                            );
                        }
                    }
                }
            }
        }
    });
    Some(handle)
}

#[cfg(unix)]
fn spawn_vm_v0_snapshot_signal_task(
    runtime: Option<Arc<VmV0RuntimeState>>,
    metrics: Arc<NodeMetrics>,
    chain_id: u64,
    mut shutdown_rx: watch::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    let mut sigusr1 =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
            Ok(signal) => signal,
            Err(e) => {
                eprintln!(
                    "[snapshot] ERROR: failed to install SIGUSR1 snapshot trigger: {}",
                    e
                );
                metrics.snapshot().record_failure();
                return None;
            }
        };

    if let Some(path) = runtime.as_ref().and_then(|runtime| runtime.snapshot_dir()) {
        eprintln!(
            "[snapshot] VM-v0 in-process snapshot trigger enabled: send SIGUSR1 to this process; snapshot_dir={}",
            path.display()
        );
    } else {
        eprintln!(
            "[snapshot] VM-v0 SIGUSR1 snapshot trigger disabled: --snapshot-dir not configured"
        );
    }

    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    eprintln!("[snapshot] VM-v0 snapshot trigger stopped.");
                    break;
                }
                _ = sigusr1.recv() => {
                    eprintln!("[snapshot] signal received: SIGUSR1");
                    let Some(runtime) = runtime.as_ref().cloned() else {
                        eprintln!(
                            "[snapshot] SIGUSR1 ignored: VM-v0 runtime not active"
                        );
                        continue;
                    };
                    if runtime.snapshot_dir().is_none() {
                        eprintln!(
                            "[snapshot] SIGUSR1 ignored: VM-v0 snapshot trigger disabled (--snapshot-dir not configured)"
                        );
                        continue;
                    }
                    let height = metrics.committed_anchor().height();
                    let Some(block_hash) = metrics.committed_anchor().block_id() else {
                        eprintln!(
                            "[snapshot] ERROR: SIGUSR1 snapshot requested before a committed anchor was available"
                        );
                        metrics.snapshot().record_failure();
                        continue;
                    };
                    let metrics_for_task = Arc::clone(&metrics);
                    let result = tokio::task::spawn_blocking(move || {
                        runtime.create_snapshot(
                            SnapshotAnchor { height, block_hash },
                            chain_id,
                            &metrics_for_task,
                        )
                    })
                    .await;
                    match result {
                        Ok(Ok(stats)) => {
                            eprintln!(
                                "[snapshot] success: height={} size_bytes={} duration_ms={}",
                                stats.height,
                                stats.size_bytes,
                                stats.duration_ms
                            );
                        }
                        Ok(Err(qbind_node::vm_v0_runtime::VmV0RuntimeError::SnapshotAlreadyInProgress)) => {
                            eprintln!(
                                "[snapshot] SIGUSR1 skipped: another snapshot is already in progress"
                            );
                        }
                        Ok(Err(e)) => {
                            eprintln!("[snapshot] ERROR: {}", e);
                        }
                        Err(e) => {
                            eprintln!("[snapshot] ERROR: snapshot task join failed: {}", e);
                            metrics.snapshot().record_failure();
                        }
                    }
                }
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_vm_v0_snapshot_signal_task(
    runtime: Option<Arc<VmV0RuntimeState>>,
    metrics: Arc<NodeMetrics>,
    _unsupported_chain_id: u64,
    _unsupported_shutdown_rx: watch::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if runtime.and_then(|r| r.snapshot_dir().map(|_| ())).is_some() {
        eprintln!(
            "[snapshot] ERROR: VM-v0 SIGUSR1 snapshot trigger is unsupported on this platform"
        );
        metrics.snapshot().record_failure();
    }
    None
}