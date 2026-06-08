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
use qbind_node::production_consensus_storage::{
    open_production_consensus_storage, persist_restored_snapshot_epoch,
    OpenedProductionConsensusStorage,
};
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

/// Run 096 — thin wrapper around
/// [`derive_reconfig_proposal_from_cli_flag`] that pulls the raw CLI
/// flag value and environment off of the CLI args + `NodeConfig` and
/// surfaces the typed CLI error as a `String` for the operator log
/// line in `main`. See the helper's docs for full semantics.
fn derive_run_096_reconfig_proposal(
    config: &qbind_node::node_config::NodeConfig,
    args: &CliArgs,
) -> Result<
    Option<qbind_node::binary_consensus_loop::BinaryReconfigProposalConfig>,
    String,
> {
    use qbind_node::binary_consensus_loop::derive_reconfig_proposal_from_cli_flag;
    use qbind_types::NetworkEnvironment;

    derive_reconfig_proposal_from_cli_flag(
        args.devnet_reconfig_proposal_next_epoch,
        matches!(config.environment, NetworkEnvironment::Mainnet),
    )
    .map_err(|e| e.to_string())
}

/// Run 105 — startup-only helper that applies the non-mutating
/// bundle-signing-key ratification enforcement gate to a successfully-
/// loaded trust bundle. Returns `Err(reason_string)` to fail closed
/// with an operator-log-friendly message; the caller exits non-zero
/// without writing the Run 055 sequence record and without merging
/// any new root into the live PQC trust set.
///
/// The function is intentionally pure: it neither mutates any global
/// state nor touches any file other than the operator-supplied
/// genesis JSON (re-read here to obtain the authority block; the
/// boot-time `BootGenesisOutcome` only carries the canonical hash) and
/// the operator-supplied ratification sidecar JSON. Both paths are
/// already trusted local files (same trust assumption as
/// `--p2p-trust-bundle` itself).
fn apply_run_105_ratification_gate_at_startup(
    args: &CliArgs,
    config: &qbind_node::node_config::NodeConfig,
    loaded: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
) -> Result<(), String> {
    use qbind_ledger::{
        enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
        RatificationEnforcementOutcome, RatificationEnforcementPolicy,
    };
    use qbind_node::pqc_boot_genesis::{load_external_genesis, map_environment};
    use qbind_node::pqc_ratification_input::load_ratification_from_path;
    use qbind_node::pqc_trust_bundle::BundleSignatureStatus;
    use qbind_types::NetworkEnvironment;

    // 1. Resolve genesis authority block + canonical genesis hash.
    //    The Run 102 boot-time verifier already validated these; we
    //    re-load the same operator-supplied file here to extract the
    //    authority block. No fallback to defaults: a missing or
    //    malformed file is a fatal startup error (and is unreachable
    //    anyway because Run 102 already passed).
    let genesis_path = match config.genesis_source.genesis_path.as_ref() {
        Some(p) => p.clone(),
        None => {
            // DevNet/TestNet without external genesis: there is no
            // operator-supplied authority block to bind against.
            // Under the operator-opt-in flag, we still refuse on
            // MainNet (boot would already have failed). On DevNet/
            // TestNet, fall back to the legacy unratified verdict
            // ONLY when the operator explicitly opted in via the
            // companion flag.
            if matches!(config.environment, NetworkEnvironment::Mainnet) {
                return Err(
                    "MainNet startup requires an external --genesis-path with a populated \
                     authority block; Run 105 ratification cannot be enforced without it"
                        .to_string(),
                );
            }
            if !args.p2p_trust_bundle_allow_unratified_testnet_devnet {
                return Err(format!(
                    "environment={:?} has no external genesis file configured, so the genesis \
                     authority block is not available for Run 105 ratification enforcement; \
                     pass --p2p-trust-bundle-allow-unratified-testnet-devnet to opt in to the \
                     legacy unratified verdict on this surface",
                    config.environment
                ));
            }
            eprintln!(
                "[run-105] no external genesis file configured; surface evaluated under \
                 explicit --p2p-trust-bundle-allow-unratified-testnet-devnet opt-in. \
                 Bundle-signing key {} accepted under legacy DevNet/TestNet policy; this \
                 verdict is NOT a passed ratification.",
                fingerprint_for_log(loaded, bundle_signing_keys),
            );
            return Ok(());
        }
    };

    let genesis_cfg = load_external_genesis(&genesis_path).map_err(|e| {
        format!(
            "failed to re-load external genesis file at {} for Run 105 ratification \
             enforcement: {}",
            genesis_path.display(),
            e
        )
    })?;
    let authority = genesis_cfg.authority.as_ref().ok_or_else(|| {
        format!(
            "external genesis file at {} has no authority block; Run 105 cannot enforce \
             ratification without bundle_signing_authority_roots",
            genesis_path.display()
        )
    })?;
    let env_policy = map_environment(config.environment);
    let canonical_hash =
        qbind_ledger::compute_canonical_genesis_hash(&genesis_cfg, env_policy);
    let chain_id_str =
        qbind_node::pqc_trust_sequence::chain_id_hex(config.chain_id());

    // 2. Resolve the candidate bundle's signing public-key bytes.
    //    For unsigned DevNet bundles there is no key to ratify and
    //    the gate is structurally inapplicable; we still log the
    //    verdict explicitly.
    let signing_pk_bytes: Vec<u8> = match &loaded.signature_status {
        BundleSignatureStatus::Unsigned => {
            eprintln!(
                "[run-105] candidate bundle is DevNet-unsigned; ratification gate is \
                 structurally inapplicable (no signing key to authorise). Verdict: \
                 unsigned-no-key-to-ratify."
            );
            return Ok(());
        }
        BundleSignatureStatus::Verified { signing_key_id } => {
            let mut id_bytes = [0u8; 32];
            decode_run_105_hex_into_32(signing_key_id, &mut id_bytes).map_err(|e| {
                format!(
                    "internal: BundleSignatureStatus::Verified.signing_key_id is not \
                     a 64-char lowercase hex string: {}",
                    e
                )
            })?;
            match bundle_signing_keys.lookup(&id_bytes) {
                Some(k) => k.pk_bytes.clone(),
                None => {
                    return Err(format!(
                        "internal: bundle was verified by signing_key_id {} but that key is \
                         no longer in the configured signing-key set",
                        signing_key_id
                    ));
                }
            }
        }
    };

    // 3. Resolve the operator-supplied ratification sidecar (if any).
    let ratification_obj = match args.p2p_trust_bundle_ratification.as_ref() {
        Some(path) => Some(
            load_ratification_from_path(path)
                .map_err(|e| format!("{}", e))?,
        ),
        None => None,
    };

    // 4. Pick the per-environment enforcement policy. MainNet is
    //    always Strict. TestNet/DevNet default to Strict unless the
    //    operator opted in to legacy.
    let policy = match config.environment {
        NetworkEnvironment::Mainnet => RatificationEnforcementPolicy::Strict,
        NetworkEnvironment::Testnet | NetworkEnvironment::Devnet => {
            if args.p2p_trust_bundle_allow_unratified_testnet_devnet {
                RatificationEnforcementPolicy::AllowLegacyUnratified
            } else {
                RatificationEnforcementPolicy::Strict
            }
        }
    };

    // 5. Run the gate.
    let outcome = enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: ratification_obj.as_ref(),
        authority,
        expected_chain_id: &chain_id_str,
        expected_environment: env_policy,
        expected_genesis_hash: &canonical_hash,
        candidate_bundle_signing_public_key: &signing_pk_bytes,
        policy,
    })
    .map_err(|e| format!("{}", e))?;

    match outcome {
        RatificationEnforcementOutcome::Ratified(rk) => {
            eprintln!(
                "[run-105] OK: bundle-signing key ratification verified; bundle_signing_fp={} \
                 authority_root_fp={} suite_id={} env={} chain_id={}",
                rk.fingerprint,
                rk.authority_root_fingerprint,
                rk.signature_suite_id,
                env_policy.scope(),
                chain_id_str
            );
        }
        RatificationEnforcementOutcome::LegacyUnratifiedAccepted {
            bundle_signing_public_key_fingerprint,
        } => {
            eprintln!(
                "[run-105] LEGACY-UNRATIFIED: bundle-signing key {} accepted under explicit \
                 --p2p-trust-bundle-allow-unratified-testnet-devnet opt-in (env={} \
                 chain_id={}). This is NOT a passed ratification.",
                bundle_signing_public_key_fingerprint,
                env_policy.scope(),
                chain_id_str
            );
        }
    }
    Ok(())
}

/// Helper used by the Run 105 startup gate's no-genesis branch to
/// produce a log-safe fingerprint for the candidate bundle's signing
/// key without exposing public-key bytes.
fn fingerprint_for_log(
    loaded: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
) -> String {
    use qbind_node::pqc_trust_bundle::BundleSignatureStatus;
    match &loaded.signature_status {
        BundleSignatureStatus::Unsigned => "unsigned".to_string(),
        BundleSignatureStatus::Verified { signing_key_id } => {
            let mut id_bytes = [0u8; 32];
            if decode_run_105_hex_into_32(signing_key_id, &mut id_bytes).is_ok() {
                if let Some(k) = bundle_signing_keys.lookup(&id_bytes) {
                    return qbind_ledger::pqc_public_key_fingerprint(&k.pk_bytes);
                }
            }
            signing_key_id.clone()
        }
    }
}

fn decode_run_105_hex_into_32(s: &str, out: &mut [u8; 32]) -> Result<(), String> {
    if s.len() != 64 {
        return Err(format!("expected 64-char lowercase hex, got len={}", s.len()));
    }
    let bytes = s.as_bytes();
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = match pair[0] {
            b'0'..=b'9' => pair[0] - b'0',
            b'a'..=b'f' => 10 + pair[0] - b'a',
            _ => return Err(format!("non-hex byte at position {}", i * 2)),
        };
        let lo = match pair[1] {
            b'0'..=b'9' => pair[1] - b'0',
            b'a'..=b'f' => 10 + pair[1] - b'a',
            _ => return Err(format!("non-hex byte at position {}", i * 2 + 1)),
        };
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

/// Run 105 — owned data for a [`RatificationEnforcementContext`].
///
/// Used by the reload-check and peer-candidate-check binary paths to
/// keep the ratification + authority + canonical hash + chain-id
/// string alive for the duration of the borrowed context the
/// validator consumes.
struct Run105ReloadCheckContextData {
    authority: qbind_ledger::GenesisAuthorityConfig,
    canonical_hash: qbind_ledger::GenesisHash,
    env_policy: qbind_ledger::NetworkEnvironmentPolicy,
    chain_id_str: String,
    ratification: Option<qbind_ledger::BundleSigningRatification>,
    policy: qbind_ledger::RatificationEnforcementPolicy,
    /// Run 132: optional v2 ratification sidecar. Present when the
    /// operator-supplied sidecar is schema_version=2.
    ratification_v2: Option<qbind_ledger::BundleSigningRatificationV2>,
    /// Run 169 — typed Run 167 governance-proof load status for the
    /// operator-supplied v2 ratification sidecar (when present). v1
    /// sidecars always yield
    /// [`qbind_node::pqc_governance_proof_wire::GovernanceProofLoadStatus::Absent`].
    /// This makes the `load_v2_ratification_sidecar_with_governance_proof_from_path`
    /// loader output reachable from the reload-check / reload-apply /
    /// startup `--p2p-trust-bundle` / SIGHUP / live inbound `0x05`
    /// preflights so they no longer hardcode
    /// `GovernanceProofContext::Unavailable`.
    governance_proof_load:
        qbind_node::pqc_governance_proof_wire::GovernanceProofLoadStatus,
    /// Run 171 — captured value of the hidden
    /// `--p2p-trust-bundle-governance-proof-required` CLI flag at
    /// `Run105ReloadCheckContext` build time.
    ///
    /// The Run 171 selector is OR-combined with the
    /// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` environment
    /// variable when the v2 marker-decision preflight resolves the
    /// active [`qbind_node::pqc_governance_authority::GovernanceProofPolicy`]
    /// via
    /// [`qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env`].
    /// The env-var lookup happens at preflight time so a TestNet/DevNet
    /// operator can flip the policy between the reload-check (Run 134)
    /// and reload-apply (Run 134/136) preflights without restarting.
    /// Default `false` preserves
    /// [`qbind_node::pqc_governance_authority::GovernanceProofPolicy::NotRequired`].
    governance_proof_required_selector: bool,
    /// Run 182 — captured value of the hidden
    /// `--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI
    /// flag at `Run105ReloadCheckContext` build time.
    ///
    /// The Run 180 selector is OR-combined with the
    /// `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` env
    /// var when the v2 marker-decision preflight resolves the active
    /// [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy`]
    /// via
    /// [`qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env`].
    /// Default `false` preserves
    /// [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`].
    /// Source/test only — never enables MainNet peer-driven apply.
    onchain_governance_fixture_allowed_selector: bool,
    /// Run 217 — captured value of the hidden
    /// `--p2p-trust-bundle-governance-execution-policy` CLI flag at
    /// `Run105ReloadCheckContext` build time.
    ///
    /// Resolved at preflight time (together with the
    /// `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var) into a
    /// [`qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig`]
    /// via the Run 215 resolver. Default (both sources absent) arms
    /// [`qbind_node::pqc_governance_execution_policy::GovernanceExecutionPolicy::Disabled`]
    /// and preserves the pre-Run-217 reload-check / reload-apply / startup
    /// / peer-candidate-check flow bit-for-bit. The selector is validated
    /// fail-closed at startup; storing the raw `Option<String>` lets a
    /// TestNet/DevNet operator flip the env-source policy between
    /// preflights without restarting. Source/test only — never enables
    /// MainNet peer-driven apply.
    governance_execution_policy_selector: Option<String>,
}

/// Run 105 — build the owned context the reload-check / peer-candidate-
/// check binary paths borrow from when calling
/// [`qbind_node::pqc_trust_reload::validate_candidate_bundle_full_with_ratification`].
///
/// Same fail-closed shape as
/// [`apply_run_105_ratification_gate_at_startup`]: re-loads the
/// operator-supplied genesis JSON (no fallback), pulls the authority
/// block out, computes the canonical genesis hash, picks the
/// per-environment policy, and (optionally) loads the ratification
/// sidecar JSON. Returns `Err(reason)` for any I/O / parse / structural
/// problem; the caller exits non-zero with the operator-facing
/// message.
fn build_run_105_reload_check_context(
    args: &CliArgs,
    config: &qbind_node::node_config::NodeConfig,
) -> Result<Run105ReloadCheckContextData, String> {
    use qbind_node::pqc_boot_genesis::{load_external_genesis, map_environment};
    use qbind_node::pqc_ratification_input::{
        load_versioned_ratification_with_governance_proof_from_path,
        VersionedRatificationSidecarWithGovernanceProof,
    };
    use qbind_node::pqc_governance_proof_wire::GovernanceProofLoadStatus;
    use qbind_types::NetworkEnvironment;

    let genesis_path = config.genesis_source.genesis_path.as_ref().ok_or_else(|| {
        "no external --genesis-path configured; Run 105 ratification cannot be enforced \
         on the reload-check / peer-candidate-check binary path without a populated \
         genesis authority block"
            .to_string()
    })?;
    let genesis_cfg = load_external_genesis(genesis_path).map_err(|e| {
        format!(
            "failed to load external genesis file at {}: {}",
            genesis_path.display(),
            e
        )
    })?;
    let authority = genesis_cfg.authority.clone().ok_or_else(|| {
        format!(
            "external genesis file at {} has no authority block; Run 105 cannot enforce \
             ratification without bundle_signing_authority_roots",
            genesis_path.display()
        )
    })?;
    let env_policy = map_environment(config.environment);
    let canonical_hash =
        qbind_ledger::compute_canonical_genesis_hash(&genesis_cfg, env_policy);
    let chain_id_str =
        qbind_node::pqc_trust_sequence::chain_id_hex(config.chain_id());
    // Run 132: load with versioned dispatcher to support v1 and v2 sidecars.
    // Run 169: when the operator supplies a v2 sidecar, additionally
    // attempt to parse the optional Run 167 `governance_authority_proof`
    // sibling field via
    // `load_v2_ratification_sidecar_with_governance_proof_from_path`
    // (delegated to by the versioned-with-governance-proof dispatcher)
    // so the typed load status reaches the Run 165 governance gate
    // through the binary-side preflight helpers
    // (`preflight_run_134_v2_marker_decision`,
    // `preflight_run_136_v2_marker_decision_for_startup`).
    let (ratification, ratification_v2, governance_proof_load) =
        match args.p2p_trust_bundle_ratification.as_ref() {
            Some(path) => match load_versioned_ratification_with_governance_proof_from_path(path) {
                Ok(VersionedRatificationSidecarWithGovernanceProof::V1(v1)) => (
                    Some(v1),
                    None,
                    GovernanceProofLoadStatus::Absent,
                ),
                Ok(VersionedRatificationSidecarWithGovernanceProof::V2 {
                    ratification,
                    governance_proof,
                }) => (None, Some(ratification), governance_proof),
                Err(e) => return Err(format!("{}", e)),
            },
            None => (None, None, GovernanceProofLoadStatus::Absent),
        };
    let policy = match config.environment {
        NetworkEnvironment::Mainnet => qbind_ledger::RatificationEnforcementPolicy::Strict,
        NetworkEnvironment::Testnet | NetworkEnvironment::Devnet => {
            if args.p2p_trust_bundle_allow_unratified_testnet_devnet {
                qbind_ledger::RatificationEnforcementPolicy::AllowLegacyUnratified
            } else {
                qbind_ledger::RatificationEnforcementPolicy::Strict
            }
        }
    };
    Ok(Run105ReloadCheckContextData {
        authority,
        canonical_hash,
        env_policy,
        chain_id_str,
        ratification,
        policy,
        ratification_v2,
        governance_proof_load,
        // Run 171 — capture the hidden
        // `--p2p-trust-bundle-governance-proof-required` selector
        // boolean from the CLI args. The env-var sibling is consulted
        // at preflight time inside
        // `governance_proof_policy_from_cli_or_env`.
        governance_proof_required_selector: args.p2p_trust_bundle_governance_proof_required,
        // Run 182 — capture the hidden Run 180 OnChainGovernance
        // fixture-allowed selector at context-build time. Combined
        // with the `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
        // env var inside
        // `pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env`
        // when each preflight resolves the active
        // `OnChainGovernanceProofPolicy`. Default `false` preserves
        // `OnChainGovernanceProofPolicy::Disabled` and the existing
        // pre-Run-182 reload-check / reload-apply / startup /
        // peer-candidate-check flow bit-for-bit.
        onchain_governance_fixture_allowed_selector:
            args.p2p_trust_bundle_onchain_governance_fixture_allowed,
        // Run 217 — capture the hidden governance-execution policy
        // selector at context-build time. Resolved at preflight time via
        // the Run 215 CLI/env resolver. Default (absent) arms
        // `GovernanceExecutionPolicy::Disabled`.
        governance_execution_policy_selector: args
            .p2p_trust_bundle_governance_execution_policy
            .clone(),
    })
}

/// Run 119 — pre-mutation authority-marker accept-and-persist preflight
/// for the process-start reload-apply binary path.
///
/// Composes (1) a fresh re-load of the candidate trust bundle so the
/// bundle-signing public key bytes are available, (2) a Run 105 typed
/// `enforce_bundle_signing_key_ratification` call so the verified
/// `RatifiedBundleSigningKey` is in hand, and (3)
/// [`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance`]
/// so the on-disk authority marker is compared against the candidate
/// BEFORE the existing apply pipeline runs. The Run 070 apply pipeline
/// re-validates everything internally; this helper exists so that a
/// rollback / same-sequence-equivocation / wrong-domain marker
/// fail-closes the operation without burning a sequence number or
/// mutating live trust state.
///
/// # Returns
///
/// * `Ok(None)` — preflight is not applicable on this branch:
///     * `data_dir` is `None` (DevNet-only convenience; MainNet/
///       TestNet already FATAL-exit earlier in this CLI path when
///       `--data-dir` is unset);
///     * the candidate could not be pre-loaded (deferred to the
///       apply pipeline's own precise load-error reporting);
///     * the candidate is DevNet-unsigned (no signing key to bind a
///       marker to);
///     * the ratification policy is `AllowLegacyUnratified` AND no
///       ratification object was supplied (DevNet legacy ergonomics;
///       enforcement returns `LegacyUnratifiedAccepted` which has no
///       ratified key to anchor a marker on).
/// * `Ok(Some(decision))` — preflight accepted; the caller MUST call
///   [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_marker_after_commit_boundary`]
///   AFTER the apply pipeline returns `Ok`.
/// * `Err(reason)` — preflight refused; the caller MUST NOT invoke
///   the apply pipeline and MUST surface the reason operatorially.
#[allow(clippy::too_many_arguments)]
fn preflight_run_119_marker_decision(
    candidate_path: &std::path::Path,
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    validation_time_secs: u64,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
    updated_at_unix_secs: u64,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecision>,
    qbind_node::pqc_authority_marker_acceptance::MutatingSurfaceMarkerError,
> {
    use qbind_ledger::{
        enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
        RatificationEnforcementOutcome,
    };
    use qbind_node::pqc_authority_marker_acceptance::{
        decide_marker_acceptance, MarkerAcceptanceInputs, MutatingSurfaceMarkerError,
    };
    use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};
    use qbind_node::pqc_trust_bundle::{BundleSignatureStatus, TrustBundle};

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-119] authority-marker preflight skipped: --data-dir is unset (DevNet \
             convenience only; MainNet/TestNet already require --data-dir for the \
             reload-apply path)."
        );
        return Ok(None);
    };

    // Re-load the candidate so the bundle-signing public key bytes are
    // available for the Run 105 enforcer. The apply pipeline will load
    // the candidate again internally; both loads use the same loader
    // (`load_from_path_with_signing_keys_chain_id_and_activation`) so
    // the results are bit-for-bit identical.
    let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
        current_height: None,
        current_epoch: None,
    };
    let loaded = match TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        candidate_path,
        runtime_env,
        runtime_chain_id,
        validation_time_secs,
        bundle_signing_keys,
        activation_ctx,
    ) {
        Ok((loaded, _activation)) => loaded,
        Err(e) => {
            eprintln!(
                "[run-119] authority-marker preflight skipped: candidate pre-load returned \
                 {} (the apply pipeline will surface the precise load error).",
                e
            );
            return Ok(None);
        }
    };

    let signing_key_id_hex = match &loaded.signature_status {
        BundleSignatureStatus::Verified { signing_key_id } => signing_key_id.clone(),
        BundleSignatureStatus::Unsigned => {
            eprintln!(
                "[run-119] authority-marker preflight skipped: candidate is DevNet-unsigned \
                 (no signing key to anchor a marker on)."
            );
            return Ok(None);
        }
    };

    // Convert hex signing_key_id to 32 raw bytes, then look up the
    // configured signing key to retrieve its full public-key bytes.
    let signing_key_id_bytes: [u8; 32] = match hex_decode_32(&signing_key_id_hex) {
        Some(b) => b,
        None => {
            eprintln!(
                "[run-119] authority-marker preflight skipped: candidate signing_key_id is \
                 not 64 lowercase hex chars (got {} chars). The apply pipeline will surface \
                 the precise structural error.",
                signing_key_id_hex.len()
            );
            return Ok(None);
        }
    };
    let candidate_signing_pk_bytes = match bundle_signing_keys.lookup(&signing_key_id_bytes) {
        Some(k) => k.pk_bytes.clone(),
        None => {
            eprintln!(
                "[run-119] authority-marker preflight skipped: candidate signing_key_id \
                 {}... not present in configured bundle signing keys (the apply pipeline \
                 would have already rejected the candidate)).",
                &signing_key_id_hex[..signing_key_id_hex.len().min(8)]
            );
            return Ok(None);
        }
    };

    // Run 105 enforcement — re-runs the precise verifier the apply
    // pipeline will run, so a verified ratification is in hand for the
    // marker derivation step.
    let outcome = match enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: ctx_data.ratification.as_ref(),
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
        candidate_bundle_signing_public_key: &candidate_signing_pk_bytes,
        policy: ctx_data.policy,
    }) {
        Ok(o) => o,
        Err(_e) => {
            // Defer to the apply pipeline's own typed reporting — it
            // will re-run the same enforcer and emit the precise
            // RatificationEnforcementFailure variant. We do not
            // double-report.
            eprintln!(
                "[run-119] authority-marker preflight skipped: ratification enforcement \
                 will fail in the apply pipeline (deferred to its typed error)."
            );
            return Ok(None);
        }
    };
    let ratified = match outcome {
        RatificationEnforcementOutcome::Ratified(rk) => rk,
        RatificationEnforcementOutcome::LegacyUnratifiedAccepted { .. } => {
            eprintln!(
                "[run-119] authority-marker preflight skipped: LegacyUnratifiedAccepted \
                 (DevNet/TestNet legacy ergonomics; no ratified key to anchor a marker on)."
            );
            return Ok(None);
        }
    };
    let ratification = match ctx_data.ratification.as_ref() {
        Some(r) => r,
        None => {
            // Unreachable under Strict (the enforcer would have
            // returned Missing) and under AllowLegacyUnratified the
            // LegacyUnratifiedAccepted branch above already returned.
            eprintln!(
                "[run-119] authority-marker preflight skipped: ratification context has no \
                 object (unreachable on Ratified branch)."
            );
            return Ok(None);
        }
    };

    // Compute the runtime genesis hash hex (Run 117 chain-id-hex /
    // genesis-hash-hex format).
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    let decision = decide_marker_acceptance(MarkerAcceptanceInputs {
        marker_path: &marker_path,
        runtime_env,
        runtime_chain_id,
        runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
        authority_policy_version: ctx_data.authority.authority_policy_version,
        authority_sequence: ctx_data.authority.authority_sequence,
        authority_epoch: ctx_data.authority.authority_epoch,
        ratification,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::ReloadApply,
        updated_at_unix_secs,
    })?;

    // Keep `MutatingSurfaceMarkerError` re-export in scope for the
    // explicit Result type without triggering an unused-import warning.
    let _ = std::marker::PhantomData::<MutatingSurfaceMarkerError>;

    Ok(Some(decision))
}

/// Run 134 — pre-mutation v2 authority-marker accept-and-persist preflight
/// for the process-start reload-apply binary path.
///
/// Mirrors [`preflight_run_119_marker_decision`] but for v2 ratification
/// sidecars. Composes:
///
/// 1. Run 130 [`qbind_ledger::verify_bundle_signing_key_ratification_v2`]
///    so the verified [`qbind_ledger::RatifiedBundleSigningKeyV2`] is in
///    hand for the v2 marker derivation step.
/// 2. [`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
///    so the on-disk versioned authority marker is compared against the
///    v2 candidate BEFORE any apply pipeline call.
///
/// # Returns
///
/// * `Ok(None)` — preflight not applicable:
///     * `data_dir` is unset (DevNet-only convenience; MainNet/TestNet
///       FATAL-exit earlier when `--data-dir` is unset);
///     * `ctx_data.ratification_v2` is `None` (caller must only call this
///       helper when a v2 sidecar is present).
/// * `Ok(Some(decision))` — preflight accepted; the caller MUST call
///   [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`]
///   AFTER the apply pipeline returns `Ok`.
/// * `Err(reason)` — preflight refused; the caller MUST NOT invoke the
///   apply pipeline and MUST surface the typed reason operatorially.
fn preflight_run_134_v2_marker_decision(
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
    updated_at_unix_secs: u64,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2>,
    qbind_node::pqc_authority_marker_acceptance::MutatingSurfaceMarkerV2Error,
> {
    use qbind_ledger::{verify_bundle_signing_key_ratification_v2, RatificationV2VerifierInputs};
    use qbind_node::pqc_authority_marker_acceptance::{
        MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
    };
    use qbind_node::pqc_governance_authority::{
        fixture_issuer_signature_verifier,
    };
    use qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load;
    use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};

    let Some(ratification_v2) = ctx_data.ratification_v2.as_ref() else {
        // Caller bug: this helper is only meaningful when the operator
        // supplied a v2 sidecar.
        return Ok(None);
    };

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-134] v2 authority-marker preflight skipped: --data-dir is unset (DevNet \
             convenience only; MainNet/TestNet already require --data-dir for the \
             reload-apply path)."
        );
        return Ok(None);
    };

    // Step 1: Run 130 v2 verifier.
    let ratified_v2 = verify_bundle_signing_key_ratification_v2(RatificationV2VerifierInputs {
        ratification: ratification_v2,
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
    })
    .map_err(|e| {
        // The v2 verifier already produced the precise typed failure; the
        // Run 131 derivation step does not have a v2-verifier-failure
        // variant, so we map verifier failures into the conflict bucket
        // for operator visibility. The post-commit persist call will not
        // run because we exit before that point.
        MutatingSurfaceMarkerV2Error::Conflict(
            qbind_node::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
                reason: format!("v2 ratification verifier failure: {}", e),
            },
        )
    })?;

    // Step 2: compute runtime genesis hash hex.
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    // Run 169: route through the governance-aware shared helper via the
    // Run 169 surface shim so the typed Run 167
    // `GovernanceProofLoadStatus` carried by `ctx_data` reaches the Run
    // 165 gate.
    //
    // Run 171: the policy is now selected by the hidden
    // `--p2p-trust-bundle-governance-proof-required` flag /
    // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` env var
    // (`governance_proof_policy_from_cli_or_env`). Default remains
    // `GovernanceProofPolicy::NotRequired` so old no-proof v2 sidecars
    // remain compatible. The fixture verifier is the source/test
    // issuer-signature verifier — release-binary production-surface
    // proof-carrying evidence is deferred to Run 172. MainNet
    // peer-driven apply remains refused at the calling surface
    // regardless of governance proof.
    let verifier = fixture_issuer_signature_verifier();
    let policy = qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
        ctx_data.governance_proof_required_selector,
    );
    let decision = preflight_v2_marker_decision_with_governance_proof_load(
        MarkerAcceptanceV2Inputs {
            marker_path: &marker_path,
            runtime_env,
            runtime_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            ratification: ratification_v2,
            ratified: &ratified_v2,
            update_source: AuthorityStateUpdateSource::ReloadApply,
            updated_at_unix_secs,
        },
        policy,
        &ctx_data.governance_proof_load,
        &verifier,
    )?;

    // Run 182 — production call-site reachability for the Run 180
    // OnChainGovernance per-surface preflight wrapper for the
    // `--p2p-trust-bundle-reload-apply-*` mutating-preflight path.
    // Pure / non-mutating; preserves the existing
    // `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
    // sequence-before-marker ordering bit-for-bit. See
    // `pqc_onchain_governance_callsite_wiring.rs` for the wire
    // blocker that keeps `proof: None` at this surface today.
    invoke_run_182_reload_apply_callsite_onchain_governance_marker_decision(
        &decision,
        ctx_data.onchain_governance_fixture_allowed_selector,
    );

    // Run 217 — governance-execution runtime-arming call-site reachability
    // for the `--p2p-trust-bundle-reload-apply-*` mutating-preflight path.
    // Pure / non-mutating; preserves sequence-before-marker ordering.
    invoke_run_217_callsite_governance_execution_marker_decision(
        &decision,
        ctx_data.governance_execution_policy_selector.as_deref(),
        qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface::ReloadApply,
    );

    Ok(Some(decision))
}

/// Run 182 — reload-apply production call-site reachability hook.
fn invoke_run_182_reload_apply_callsite_onchain_governance_marker_decision(
    decision: &qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    onchain_governance_fixture_allowed_selector: bool,
) {
    use qbind_node::pqc_authority_lifecycle::AuthorityTrustDomain;
    use qbind_node::pqc_onchain_governance_callsite_wiring::{
        reload_apply_callsite_onchain_governance_marker_decision,
        OnChainGovernanceCallsiteContext,
    };
    use qbind_node::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let policy = onchain_governance_proof_policy_from_cli_or_env(
        onchain_governance_fixture_allowed_selector,
    );
    let ctx = OnChainGovernanceCallsiteContext {
        persisted: None,
        candidate,
        proof: None,
        trust_domain: &trust_domain,
        policy,
        expected_governance_domain_id: "",
        expected_governance_epoch: 0,
        expected_proposal_id: "",
        expected_proposal_digest: "",
        now_unix: 0,
        replay_set: &EmptyOnChainGovernanceReplaySet,
    };
    let _outcome = reload_apply_callsite_onchain_governance_marker_decision(&ctx);
}

/// Run 217 — shared production call-site reachability hook for the Run 215
/// governance-execution per-surface preflight wrappers on the binary's
/// reload-check / reload-apply / startup `--p2p-trust-bundle` / local
/// peer-candidate-check runtime contexts.
///
/// Resolves the armed `GovernanceExecutionRuntimeArmingConfig` from the
/// captured selector (Run 215 CLI/env resolver) and routes the resolved
/// `GovernanceExecutionPolicy` into the named Run 217 runtime surface.
/// Pure / non-mutating: no marker write, no sequence write, no live trust
/// swap, no session eviction, no Run 070 invocation. The reload sidecar
/// formats do not carry a typed governance-execution payload at these
/// surfaces today (same wire blocker as the Run 182 on-chain governance
/// hooks), so the carrier is `Absent`; under the default `Disabled` policy
/// this is the legacy no-governance-execution bypass, preserving the
/// pre-Run-217 flow bit-for-bit. The selector was already validated
/// fail-closed at startup, so `from_cli_or_env` cannot error here; a
/// defensive `Disabled` fallback keeps the hook non-mutating regardless.
fn invoke_run_217_callsite_governance_execution_marker_decision(
    decision: &qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    governance_execution_policy_selector: Option<&str>,
    surface: qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface,
) {
    use qbind_node::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
    use qbind_node::pqc_governance_execution_payload_carrying::GovernanceExecutionLoadStatus;
    use qbind_node::pqc_governance_execution_policy::{
        GovernanceAction, GovernanceExecutionExpectations,
    };
    use qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let expectations = GovernanceExecutionExpectations {
        expected_environment: candidate.environment,
        expected_chain_id: candidate.chain_id.clone(),
        expected_genesis_hash: candidate.genesis_hash.clone(),
        expected_authority_root_fingerprint: candidate.authority_root_fingerprint.clone(),
        expected_proposal_id: String::new(),
        expected_decision_id: String::new(),
        expected_governance_action: GovernanceAction::Rotate,
        expected_lifecycle_action: LocalLifecycleAction::Rotate,
        expected_candidate_digest: String::new(),
        expected_authority_domain_sequence: candidate.latest_authority_domain_sequence,
        expected_governance_proof_digest: String::new(),
        expected_on_chain_proof_digest: None,
        expected_custody_attestation_digest: None,
        expected_suite_id: candidate.authority_root_suite_id,
        expected_effective_epoch: 0,
        expected_replay_nonce: String::new(),
        now_epoch: 0,
    };
    let arming = GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(
        governance_execution_policy_selector,
    )
    .unwrap_or_default();
    let _outcome = arming.arm_surface(
        surface,
        &trust_domain,
        &expectations,
        &GovernanceExecutionLoadStatus::Absent,
    );
}
///
/// Mirrors [`preflight_run_134_v2_marker_decision`] but tags the
/// persisted-record audit field with
/// [`AuthorityStateUpdateSource::StartupLoad`] (the startup-path twin of
/// [`preflight_run_120_marker_decision_for_startup`] is the v1 path; this
/// helper is its v2 twin). Composes:
///
/// 1. Run 130 [`qbind_ledger::verify_bundle_signing_key_ratification_v2`]
///    so the verified [`qbind_ledger::RatifiedBundleSigningKeyV2`] is in
///    hand for the v2 marker derivation step. v2 verification happens
///    here because the v1 startup gate
///    ([`apply_run_105_ratification_gate_at_startup`]) cannot parse a
///    v2 sidecar; the binary dispatch on the v2 sidecar SKIPS that v1
///    gate and runs the v2 verifier directly in this preflight.
/// 2. [`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`]
///    so the on-disk versioned authority marker is compared against the
///    v2 candidate BEFORE the Run 055 trust-bundle sequence write and
///    BEFORE bundle roots are merged into the live `trusted_roots`
///    set / P2P startup begins.
///
/// # Returns
///
/// * `Ok(None)` — preflight not applicable:
///     * `data_dir` is unset (DevNet-only convenience; MainNet/TestNet
///       FATAL-exit earlier when `--data-dir` is unset on the startup
///       `--p2p-trust-bundle` path for Run 055 sequence persistence);
///     * `ctx_data.ratification_v2` is `None` (caller must only call this
///       helper when a v2 sidecar is present — the dispatcher in
///       `main()` enforces this).
/// * `Ok(Some(decision))` — preflight accepted; the caller MUST call
///   [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary`]
///   AFTER the Run 055 `check_and_update_sequence` write succeeds.
/// * `Err(reason)` — preflight refused; the caller MUST NOT write the
///   Run 055 sequence record, MUST NOT merge any new bundle root into
///   the live trust set, MUST NOT start P2P, and MUST surface the
///   typed reason operatorially.
///
/// # Scope
///
/// This helper is the startup-path twin of
/// [`preflight_run_134_v2_marker_decision`]. It reuses the SAME
/// `pqc_authority_marker_acceptance` module and the SAME Run 130/131
/// verifier/derivation/compare/persist primitives — no parallel v2
/// stack. The only difference from the Run 134 helper is the
/// `AuthorityStateUpdateSource::StartupLoad` audit-only tag.
fn preflight_run_136_v2_marker_decision_for_startup(
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
    updated_at_unix_secs: u64,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2>,
    qbind_node::pqc_authority_marker_acceptance::MutatingSurfaceMarkerV2Error,
> {
    use qbind_ledger::{verify_bundle_signing_key_ratification_v2, RatificationV2VerifierInputs};
    use qbind_node::pqc_authority_marker_acceptance::{
        MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
    };
    use qbind_node::pqc_governance_authority::{
        fixture_issuer_signature_verifier,
    };
    use qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load;
    use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};

    let Some(ratification_v2) = ctx_data.ratification_v2.as_ref() else {
        // Caller bug: this helper is only meaningful when the operator
        // supplied a v2 sidecar. The dispatcher in `main()` enforces
        // this; return None defensively rather than panicking.
        return Ok(None);
    };

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-136] v2 authority-marker startup preflight skipped: --data-dir is unset \
             (DevNet convenience only; the startup `--p2p-trust-bundle` path already \
             FATAL-rejects TestNet/MainNet without --data-dir for Run 055 sequence \
             persistence)."
        );
        return Ok(None);
    };

    // Step 1: Run 130 v2 verifier. This SUBSTITUTES for the v1 startup
    // gate (`apply_run_105_ratification_gate_at_startup`) that the
    // dispatcher in `main()` skips on the v2 path.
    let ratified_v2 = verify_bundle_signing_key_ratification_v2(RatificationV2VerifierInputs {
        ratification: ratification_v2,
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
    })
    .map_err(|e| {
        // The v2 verifier already produced the precise typed failure;
        // the Run 131 derivation step does not have a v2-verifier-
        // failure variant, so we map verifier failures into the
        // conflict bucket for operator visibility. The post-commit
        // persist call will not run because we exit before that point.
        MutatingSurfaceMarkerV2Error::Conflict(
            qbind_node::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
                reason: format!("v2 ratification verifier failure: {}", e),
            },
        )
    })?;

    // Step 2: compute runtime genesis hash hex (Run 117 format — 64
    // lowercase hex chars).
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    // Run 169: route through the governance-aware shared helper via the
    // Run 169 surface shim so the typed Run 167
    // `GovernanceProofLoadStatus` carried by `ctx_data` reaches the
    // Run 165 gate at startup `--p2p-trust-bundle` time.
    //
    // Run 171: the policy is now selected by the hidden
    // `--p2p-trust-bundle-governance-proof-required` flag /
    // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` env var.
    // Default remains `GovernanceProofPolicy::NotRequired` so old
    // no-proof v2 sidecars remain compatible. The fixture verifier is
    // the source/test issuer-signature verifier — release-binary
    // production-surface proof-carrying evidence is deferred to Run
    // 172. MainNet peer-driven apply remains refused at the calling
    // surface.
    let verifier = fixture_issuer_signature_verifier();
    let policy = qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
        ctx_data.governance_proof_required_selector,
    );
    let decision = preflight_v2_marker_decision_with_governance_proof_load(
        MarkerAcceptanceV2Inputs {
            marker_path: &marker_path,
            runtime_env,
            runtime_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            ratification: ratification_v2,
            ratified: &ratified_v2,
            update_source: AuthorityStateUpdateSource::StartupLoad,
            updated_at_unix_secs,
        },
        policy,
        &ctx_data.governance_proof_load,
        &verifier,
    )?;

    // Keep `MutatingSurfaceMarkerV2Error` re-export in scope for the
    // explicit Result type without triggering an unused-import warning
    // (mirrors the Run 134 reload-apply preflight).
    let _ = std::marker::PhantomData::<MutatingSurfaceMarkerV2Error>;

    // Run 182 — production call-site reachability for the Run 180
    // OnChainGovernance per-surface preflight wrapper for the
    // startup `--p2p-trust-bundle` mutating-preflight path.
    invoke_run_182_startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(
        &decision,
        ctx_data.onchain_governance_fixture_allowed_selector,
    );

    // Run 217 — governance-execution runtime-arming call-site reachability
    // for the startup `--p2p-trust-bundle` mutating-preflight path.
    invoke_run_217_callsite_governance_execution_marker_decision(
        &decision,
        ctx_data.governance_execution_policy_selector.as_deref(),
        qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface::StartupP2pTrustBundle,
    );

    Ok(Some(decision))
}

/// Run 182 — startup `--p2p-trust-bundle` production call-site
/// reachability hook.
fn invoke_run_182_startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(
    decision: &qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    onchain_governance_fixture_allowed_selector: bool,
) {
    use qbind_node::pqc_authority_lifecycle::AuthorityTrustDomain;
    use qbind_node::pqc_onchain_governance_callsite_wiring::{
        startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision,
        OnChainGovernanceCallsiteContext,
    };
    use qbind_node::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let policy = onchain_governance_proof_policy_from_cli_or_env(
        onchain_governance_fixture_allowed_selector,
    );
    let ctx = OnChainGovernanceCallsiteContext {
        persisted: None,
        candidate,
        proof: None,
        trust_domain: &trust_domain,
        policy,
        expected_governance_domain_id: "",
        expected_governance_epoch: 0,
        expected_proposal_id: "",
        expected_proposal_digest: "",
        now_unix: 0,
        replay_set: &EmptyOnChainGovernanceReplaySet,
    };
    let _outcome =
        startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision(&ctx);
}

/// Run 120 — pre-mutation authority-marker accept-and-persist preflight
/// for the **startup `--p2p-trust-bundle`** acceptance path.
///
/// Composes:
///
/// 1. The verified ratification material the Run 105/106 startup gate
///    already accepted (re-run here against the already-loaded
///    candidate so the typed [`qbind_ledger::RatifiedBundleSigningKey`]
///    is in hand without changing the gate's signature).
/// 2. [`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance`]
///    so the on-disk authority marker is compared against the
///    candidate BEFORE the Run 055 trust-bundle sequence write and
///    BEFORE bundle roots are merged into the live `trusted_roots`
///    set / P2P startup begins.
///
/// # Returns
///
/// * `Ok(None)` — preflight is not applicable on this branch:
///     * `data_dir` is `None` (DevNet-only convenience; MainNet/TestNet
///       are already FATAL-rejected upstream when `--data-dir` is unset
///       on the startup `--p2p-trust-bundle` path);
///     * the candidate is `BundleSignatureStatus::Unsigned` (DevNet
///       unsigned bundle — no ratified signing key to anchor a marker
///       on; Run 105 already returned `Ok` for this case);
///     * the per-environment ratification policy is
///       `AllowLegacyUnratified` AND no ratification sidecar was
///       supplied (DevNet/TestNet legacy ergonomics — Run 105 already
///       logged `LegacyUnratifiedAccepted` and there is no ratified
///       key to anchor a marker on).
/// * `Ok(Some(decision))` — preflight accepted; the caller MUST call
///   [`qbind_node::pqc_authority_marker_acceptance::persist_accepted_marker_after_commit_boundary`]
///   AFTER the Run 055 `check_and_update_sequence` write succeeds.
/// * `Err(reason)` — preflight refused; the caller MUST NOT write the
///   Run 055 sequence record, MUST NOT merge any new bundle root into
///   the live trust set, MUST NOT start P2P, and MUST surface the
///   typed reason operatorially.
///
/// # Scope
///
/// This helper is the startup-path twin of
/// [`preflight_run_119_marker_decision`]. It reuses the SAME
/// `pqc_authority_marker_acceptance` module and the SAME Run 117/118
/// derivation/compare/persist primitives — no parallel marker
/// acceptance stack. The two helpers differ only in:
///
/// * `AuthorityStateUpdateSource::StartupLoad` vs
///   `AuthorityStateUpdateSource::ReloadApply` (audit-only tag);
/// * startup already holds a `LoadedTrustBundle` in scope, so the
///   helper does not need to re-load the candidate.
#[allow(clippy::too_many_arguments)]
fn preflight_run_120_marker_decision_for_startup(
    loaded: &qbind_node::pqc_trust_bundle::LoadedTrustBundle,
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
    updated_at_unix_secs: u64,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecision>,
    qbind_node::pqc_authority_marker_acceptance::MutatingSurfaceMarkerError,
> {
    use qbind_ledger::{
        enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
        RatificationEnforcementOutcome,
    };
    use qbind_node::pqc_authority_marker_acceptance::{
        decide_marker_acceptance, MarkerAcceptanceInputs, MutatingSurfaceMarkerError,
    };
    use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};
    use qbind_node::pqc_trust_bundle::BundleSignatureStatus;

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-120] authority-marker startup preflight skipped: --data-dir is unset \
             (DevNet convenience only; the startup `--p2p-trust-bundle` path already \
             FATAL-rejects TestNet/MainNet without --data-dir for Run 055 sequence \
             persistence)."
        );
        return Ok(None);
    };

    // Pull the candidate bundle's signing public-key bytes. Unsigned
    // DevNet bundles are structurally inapplicable — there is no
    // ratified signing key to anchor a marker on.
    let signing_key_id_hex = match &loaded.signature_status {
        BundleSignatureStatus::Verified { signing_key_id } => signing_key_id.clone(),
        BundleSignatureStatus::Unsigned => {
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: candidate bundle is \
                 DevNet-unsigned (no ratified signing key to anchor a marker on)."
            );
            return Ok(None);
        }
    };
    let signing_key_id_bytes: [u8; 32] = match hex_decode_32(&signing_key_id_hex) {
        Some(b) => b,
        None => {
            // Unreachable: a `Verified` status implies the loader
            // wrote a 64-char lowercase hex signing_key_id. Defer to
            // the Run 105 enforcer's typed reporting rather than
            // silently invent a new error class here.
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: candidate \
                 signing_key_id is not 64 lowercase hex chars (got {} chars; the Run 105 \
                 enforcer would have surfaced the precise structural error).",
                signing_key_id_hex.len()
            );
            return Ok(None);
        }
    };
    let candidate_signing_pk_bytes = match bundle_signing_keys.lookup(&signing_key_id_bytes) {
        Some(k) => k.pk_bytes.clone(),
        None => {
            // Unreachable: a `Verified` status implies the loader
            // matched the signing_key_id against the configured set.
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: candidate \
                 signing_key_id {}... not present in configured bundle signing keys (the \
                 Run 105 gate would have already refused this).",
                &signing_key_id_hex[..signing_key_id_hex.len().min(8)]
            );
            return Ok(None);
        }
    };

    // Re-run the Run 105 enforcer against the already-accepted gate
    // context so the typed `RatifiedBundleSigningKey` is in hand for
    // the derivation step. The verifier is pure; re-running it does
    // not double-mutate any state and matches the Run 119 reload-apply
    // preflight pattern.
    let outcome = match enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: ctx_data.ratification.as_ref(),
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
        candidate_bundle_signing_public_key: &candidate_signing_pk_bytes,
        policy: ctx_data.policy,
    }) {
        Ok(o) => o,
        Err(_e) => {
            // Unreachable on this branch — the startup gate already
            // returned Ok before this helper was called. Defer to its
            // typed error in case this helper is ever called out of
            // order.
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: ratification \
                 enforcement returned an error (the Run 105/106 startup gate would have \
                 already exited)."
            );
            return Ok(None);
        }
    };
    let ratified = match outcome {
        RatificationEnforcementOutcome::Ratified(rk) => rk,
        RatificationEnforcementOutcome::LegacyUnratifiedAccepted { .. } => {
            // Run 105 explicitly logs this as "NOT a passed
            // ratification". No ratified key exists, so no marker is
            // derivable. Preserves Run 106 DevNet/TestNet legacy
            // ergonomics — the marker is simply not written.
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: \
                 LegacyUnratifiedAccepted (DevNet/TestNet legacy ergonomics; no ratified \
                 key to anchor a marker on; marker file NOT written)."
            );
            return Ok(None);
        }
    };
    let ratification = match ctx_data.ratification.as_ref() {
        Some(r) => r,
        None => {
            // Unreachable on the Ratified branch — Strict requires a
            // ratification sidecar, and AllowLegacyUnratified with no
            // sidecar returns LegacyUnratifiedAccepted above.
            eprintln!(
                "[run-120] authority-marker startup preflight skipped: ratification \
                 context has no object (unreachable on Ratified branch)."
            );
            return Ok(None);
        }
    };

    // Compute the runtime genesis hash hex (Run 117 format — 64
    // lowercase hex chars).
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    let decision = decide_marker_acceptance(MarkerAcceptanceInputs {
        marker_path: &marker_path,
        runtime_env,
        runtime_chain_id,
        runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
        authority_policy_version: ctx_data.authority.authority_policy_version,
        authority_sequence: ctx_data.authority.authority_sequence,
        authority_epoch: ctx_data.authority.authority_epoch,
        ratification,
        ratified: &ratified,
        update_source: AuthorityStateUpdateSource::StartupLoad,
        updated_at_unix_secs,
    })?;

    // Keep `MutatingSurfaceMarkerError` re-export in scope for the
    // explicit Result type without triggering an unused-import warning
    // (mirrors the Run 119 preflight).
    let _ = std::marker::PhantomData::<MutatingSurfaceMarkerError>;

    Ok(Some(decision))
}

/// Decode a 64-char lowercase-hex string into a `[u8; 32]`. Returns
/// `None` on any structural defect.
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Run 123 — validation-only authority marker conflict check for surfaces
/// that never persist marker state (reload-check, peer-candidate-check,
/// live inbound `0x05`).
///
/// Composes:
/// 1. Re-load the candidate bundle to get the signing-key id.
/// 2. Re-run the Run 105 `enforce_bundle_signing_key_ratification` to
///    obtain a verified `RatifiedBundleSigningKey`.
/// 3. Call [`qbind_node::pqc_authority_marker_acceptance::verify_marker_for_validation_only`]
///    to derive a candidate marker and compare against the persisted marker.
///
/// # Returns
///
/// * `Ok(None)` — check is not applicable (no data-dir, DevNet-unsigned,
///   LegacyUnratifiedAccepted, or pre-load failure); validation may proceed.
/// * `Ok(Some(reason))` — marker check passed; validation may proceed.
/// * `Err(reason)` — marker conflict/corruption/wrong-domain; the surface
///   MUST reject the candidate.
///
/// # Critical guarantee: never persists marker.
#[allow(clippy::too_many_arguments)]
fn preflight_run_123_validation_only_marker_check(
    candidate_path: &std::path::Path,
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    validation_time_secs: u64,
    bundle_signing_keys: &qbind_node::pqc_trust_bundle::BundleSigningKeySet,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::ValidationOnlyMarkerAcceptReason>,
    qbind_node::pqc_authority_marker_acceptance::ValidationOnlyMarkerError,
> {
    use qbind_ledger::{
        enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
        RatificationEnforcementOutcome,
    };
    use qbind_node::pqc_authority_marker_acceptance::{
        verify_marker_for_validation_only, ValidationOnlyMarkerInputs,
    };
    use qbind_node::pqc_authority_state::authority_state_file_path;
    use qbind_node::pqc_trust_bundle::{BundleSignatureStatus, TrustBundle};

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-123] validation-only authority-marker check skipped: --data-dir is unset \
             (DevNet convenience only; MainNet/TestNet already require --data-dir)."
        );
        return Ok(None);
    };

    // Re-load the candidate to obtain signing-key identity.
    let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
        current_height: None,
        current_epoch: None,
    };
    let loaded = match TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(
        candidate_path,
        runtime_env,
        runtime_chain_id,
        validation_time_secs,
        bundle_signing_keys,
        activation_ctx,
    ) {
        Ok((loaded, _activation)) => loaded,
        Err(e) => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: candidate pre-load \
                 returned {} (the validation pipeline will surface the precise load error).",
                e
            );
            return Ok(None);
        }
    };

    let signing_key_id_hex = match &loaded.signature_status {
        BundleSignatureStatus::Verified { signing_key_id } => signing_key_id.clone(),
        BundleSignatureStatus::Unsigned => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: candidate is \
                 DevNet-unsigned (no signing key to anchor a marker on)."
            );
            return Ok(None);
        }
    };

    let signing_key_id_bytes: [u8; 32] = match hex_decode_32(&signing_key_id_hex) {
        Some(b) => b,
        None => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: candidate \
                 signing_key_id is not 64 lowercase hex chars (got {} chars).",
                signing_key_id_hex.len()
            );
            return Ok(None);
        }
    };
    let candidate_signing_pk_bytes = match bundle_signing_keys.lookup(&signing_key_id_bytes) {
        Some(k) => k.pk_bytes.clone(),
        None => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: candidate \
                 signing_key_id {}... not in configured bundle signing keys.",
                &signing_key_id_hex[..signing_key_id_hex.len().min(8)]
            );
            return Ok(None);
        }
    };

    // Re-run the Run 105 enforcer to get the typed RatifiedBundleSigningKey.
    let outcome = match enforce_bundle_signing_key_ratification(RatificationEnforcementInputs {
        ratification: ctx_data.ratification.as_ref(),
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
        candidate_bundle_signing_public_key: &candidate_signing_pk_bytes,
        policy: ctx_data.policy,
    }) {
        Ok(o) => o,
        Err(_e) => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: ratification \
                 enforcement will fail in the validation pipeline (deferred to its typed error)."
            );
            return Ok(None);
        }
    };
    let ratified = match outcome {
        RatificationEnforcementOutcome::Ratified(rk) => rk,
        RatificationEnforcementOutcome::LegacyUnratifiedAccepted { .. } => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: \
                 LegacyUnratifiedAccepted (DevNet/TestNet legacy; no ratified key to \
                 anchor a marker on)."
            );
            return Ok(None);
        }
    };
    let ratification = match ctx_data.ratification.as_ref() {
        Some(r) => r,
        None => {
            eprintln!(
                "[run-123] validation-only authority-marker check skipped: ratification \
                 context has no object (unreachable on Ratified branch)."
            );
            return Ok(None);
        }
    };

    // Compute genesis hash hex (Run 117 format).
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    let accept_reason = verify_marker_for_validation_only(ValidationOnlyMarkerInputs {
        marker_path: &marker_path,
        runtime_env,
        runtime_chain_id,
        runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
        authority_policy_version: ctx_data.authority.authority_policy_version,
        authority_sequence: ctx_data.authority.authority_sequence,
        authority_epoch: ctx_data.authority.authority_epoch,
        ratification,
        ratified: &ratified,
    })?;

    Ok(Some(accept_reason))
}

/// Run 132 — validation-only v2 authority marker conflict check for
/// validation-only surfaces (reload-check, peer-candidate-check).
///
/// This function:
/// 1. Verifies the v2 ratification sidecar using the Run 130 verifier.
/// 2. Derives a v2 marker candidate from the verified ratification.
/// 3. Compares the candidate against any persisted versioned marker.
/// 4. Returns typed accept/reject without persisting.
///
/// # Critical guarantee: never persists marker.
#[allow(clippy::too_many_arguments)]
fn preflight_run_132_validation_only_v2_marker_check(
    runtime_env: qbind_types::NetworkEnvironment,
    runtime_chain_id: qbind_types::ChainId,
    ctx_data: &Run105ReloadCheckContextData,
    data_dir: Option<&std::path::Path>,
) -> Result<
    Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2>,
    qbind_node::pqc_authority_marker_acceptance::MutatingSurfaceMarkerV2Error,
> {
    use qbind_ledger::{verify_bundle_signing_key_ratification_v2, RatificationV2VerifierInputs};
    use qbind_node::pqc_authority_marker_acceptance::{
        MarkerAcceptanceV2Inputs, MutatingSurfaceMarkerV2Error,
    };
    use qbind_node::pqc_authority_state::{authority_state_file_path, AuthorityStateUpdateSource};
    use qbind_node::pqc_governance_authority::fixture_issuer_signature_verifier;
    use qbind_node::pqc_governance_proof_surface::preflight_v2_validation_only_marker_check_with_governance_proof_load;

    let Some(ratification_v2) = ctx_data.ratification_v2.as_ref() else {
        // No v2 sidecar — this function should only be called when v2 is present.
        return Ok(None);
    };

    let Some(data_dir) = data_dir else {
        eprintln!(
            "[run-132] validation-only v2 authority-marker check skipped: --data-dir is unset \
             (DevNet convenience only; MainNet/TestNet already require --data-dir)."
        );
        return Ok(None);
    };

    // Step 1: verify the v2 ratification using the Run 130 verifier.
    // Run 173: route the v2-verifier failure into
    // `MutatingSurfaceMarkerV2Error::DerivationFailed` is not
    // appropriate (that variant is for derivation failures, not
    // verifier failures); the closest fail-closed variant for an
    // upstream v2-verifier failure on a validation-only surface is
    // the `Conflict` -> `MalformedOrUnsupportedMarkerRejected` mapping
    // already used by `preflight_run_134_v2_marker_decision`.
    let ratified_v2 = verify_bundle_signing_key_ratification_v2(RatificationV2VerifierInputs {
        ratification: ratification_v2,
        authority: &ctx_data.authority,
        expected_chain_id: &ctx_data.chain_id_str,
        expected_environment: ctx_data.env_policy,
        expected_genesis_hash: &ctx_data.canonical_hash,
    })
    .map_err(|e| {
        MutatingSurfaceMarkerV2Error::Conflict(
            qbind_node::pqc_authority_state::AuthorityMarkerV2ComparisonOutcome::MalformedOrUnsupportedMarkerRejected {
                reason: format!("v2 ratification verifier failure: {}", e),
            },
        )
    })?;

    // Compute genesis hash hex for marker derivation.
    let mut runtime_genesis_hash_hex = String::with_capacity(64);
    for b in ctx_data.canonical_hash {
        use std::fmt::Write;
        let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
    }

    let marker_path = authority_state_file_path(data_dir);

    // Run 173 — route validation-only through the governance-aware
    // shared helper via the Run 173 surface shim so the typed Run 167
    // `GovernanceProofLoadStatus` carried by `ctx_data` reaches the
    // Run 165 gate on validation-only surfaces too. The Run 171
    // selector OR-combination
    // (`--p2p-trust-bundle-governance-proof-required` /
    // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED`) drives the
    // active policy; default remains
    // `GovernanceProofPolicy::NotRequired` so old no-proof v2 sidecars
    // remain compatible.
    //
    // The validation-only invariant is enforced by THIS surface: the
    // returned decision is observed for the operator-log line and
    // VERDICT exit code only — it is never persisted, never advances
    // the bundle-signing sequence, never swaps live trust state,
    // never evicts sessions, and never invokes Run 070. The fixture
    // issuer-signature verifier is the source/test issuer-signature
    // verifier; release-binary validation-only Required-policy
    // production-surface evidence is deferred to Run 174. MainNet
    // peer-driven apply remains refused at the calling surface
    // regardless of this validation-only outcome.
    let verifier = fixture_issuer_signature_verifier();
    let policy = qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
        ctx_data.governance_proof_required_selector,
    );
    let decision = preflight_v2_validation_only_marker_check_with_governance_proof_load(
        MarkerAcceptanceV2Inputs {
            marker_path: &marker_path,
            runtime_env,
            runtime_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            ratification: ratification_v2,
            ratified: &ratified_v2,
            // `update_source` and `updated_at_unix_secs` are excluded
            // from the canonical v2 marker digest (Run 131) and are
            // never persisted from this surface — see the
            // validation-only mutation contract on the shim doc.
            update_source: AuthorityStateUpdateSource::TestOrFixture,
            updated_at_unix_secs: 0,
        },
        policy,
        &ctx_data.governance_proof_load,
        &verifier,
    )?;

    // Run 182 — production call-site reachability for the Run 180
    // OnChainGovernance per-surface preflight wrapper.
    // `--p2p-trust-bundle-reload-check` is validation-only; the
    // wiring entry is invoked here with `proof: None` and the policy
    // resolved from the Run 180 selector
    // (`--p2p-trust-bundle-onchain-governance-fixture-allowed` /
    // `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`).
    // Default `Disabled` short-circuits at the policy gate; an
    // operator-armed `AllowFixtureSourceTest` policy with `proof:
    // None` short-circuits at the no-proof gate. Either way the
    // wiring entry is pure (no marker write, no sequence write, no
    // live trust swap, no session eviction, no Run 070 invocation).
    // Wire blocker: current sidecar/wire formats do not carry a
    // typed `OnChainGovernanceProof`; documented in
    // `pqc_onchain_governance_callsite_wiring.rs`.
    invoke_run_182_reload_check_callsite_onchain_governance_marker_decision(
        &decision,
        ctx_data.onchain_governance_fixture_allowed_selector,
    );

    // Run 217 — governance-execution runtime-arming call-site reachability
    // for the `--p2p-trust-bundle-reload-check` validation-only preflight.
    // Validation-only: the returned outcome is dropped and never mutates.
    invoke_run_217_callsite_governance_execution_marker_decision(
        &decision,
        ctx_data.governance_execution_policy_selector.as_deref(),
        qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface::ReloadCheck,
    );

    Ok(Some(decision))
}

/// Run 182 — reload-check production call-site reachability hook.
///
/// Constructs the `OnChainGovernanceCallsiteContext` from the just-
/// computed validation-only decision and invokes the matching Run 180
/// per-surface wrapper through the
/// [`qbind_node::pqc_onchain_governance_callsite_wiring::reload_check_callsite_onchain_governance_marker_decision`]
/// entry. Pure: no I/O, no marker write, no sequence write, no live
/// trust swap, no session eviction, no Run 070 call. The returned
/// outcome is intentionally dropped — the validation-only invariant
/// is enforced by the calling surface, not by this hook.
fn invoke_run_182_reload_check_callsite_onchain_governance_marker_decision(
    decision: &qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    onchain_governance_fixture_allowed_selector: bool,
) {
    use qbind_node::pqc_authority_lifecycle::AuthorityTrustDomain;
    use qbind_node::pqc_onchain_governance_callsite_wiring::{
        reload_check_callsite_onchain_governance_marker_decision,
        OnChainGovernanceCallsiteContext,
    };
    use qbind_node::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let policy = onchain_governance_proof_policy_from_cli_or_env(
        onchain_governance_fixture_allowed_selector,
    );
    let ctx = OnChainGovernanceCallsiteContext {
        persisted: None,
        candidate,
        proof: None,
        trust_domain: &trust_domain,
        policy,
        expected_governance_domain_id: "",
        expected_governance_epoch: 0,
        expected_proposal_id: "",
        expected_proposal_digest: "",
        now_unix: 0,
        replay_set: &EmptyOnChainGovernanceReplaySet,
    };
    let _outcome = reload_check_callsite_onchain_governance_marker_decision(&ctx);
}

/// Run 182 — local `--p2p-trust-bundle-peer-candidate-check`
/// production call-site reachability hook. Validation-only.
fn invoke_run_182_local_peer_candidate_check_callsite_onchain_governance_marker_decision(
    decision: &qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2,
    onchain_governance_fixture_allowed_selector: bool,
) {
    use qbind_node::pqc_authority_lifecycle::AuthorityTrustDomain;
    use qbind_node::pqc_onchain_governance_callsite_wiring::{
        local_peer_candidate_check_callsite_onchain_governance_marker_decision,
        OnChainGovernanceCallsiteContext,
    };
    use qbind_node::pqc_onchain_governance_proof::EmptyOnChainGovernanceReplaySet;
    use qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env;

    let candidate = decision.candidate();
    let trust_domain = AuthorityTrustDomain::new(
        candidate.environment,
        candidate.chain_id.clone(),
        candidate.genesis_hash.clone(),
        candidate.authority_root_fingerprint.clone(),
        candidate.authority_root_suite_id,
    );
    let policy = onchain_governance_proof_policy_from_cli_or_env(
        onchain_governance_fixture_allowed_selector,
    );
    let ctx = OnChainGovernanceCallsiteContext {
        persisted: None,
        candidate,
        proof: None,
        trust_domain: &trust_domain,
        policy,
        expected_governance_domain_id: "",
        expected_governance_epoch: 0,
        expected_proposal_id: "",
        expected_proposal_digest: "",
        now_unix: 0,
        replay_set: &EmptyOnChainGovernanceReplaySet,
    };
    let _outcome =
        local_peer_candidate_check_callsite_onchain_governance_marker_decision(&ctx);
}

/// Main entry point for qbind-node binary.
#[tokio::main]
async fn main() {
    let args = CliArgs::parse_args();

    // Build NodeConfig from CLI args
    let mut config = match args.to_node_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Run 217 — resolve and validate the hidden, disabled-by-default
    // governance-execution runtime policy selector
    // (`--p2p-trust-bundle-governance-execution-policy` /
    // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`) fail-closed at
    // startup, BEFORE any runtime config is constructed or any preflight
    // mutation can occur. An empty / unknown selector value from either
    // source is rejected with exit code 1 — the resolver never silently
    // downgrades an invalid value to `Disabled`. Both sources absent
    // resolves to `GovernanceExecutionPolicy::Disabled` (Run 214
    // compatible). Source/test wiring; never enables MainNet peer-driven
    // apply, and never makes production/on-chain/MainNet governance
    // execution available. See task/RUN_217_TASK.txt and
    // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_217.md.
    let _run_217_governance_execution_runtime_arming =
        match qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(
            args.p2p_trust_bundle_governance_execution_policy.as_deref(),
        ) {
            Ok(arming) => arming,
            Err(e) => {
                eprintln!(
                    "[binary] Run 217: FATAL: invalid governance-execution policy selector: {}. \
                     No runtime config is armed; no preflight runs; no marker write; no sequence \
                     write; no live trust swap; no session eviction; no Run 070 call. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_217.md.",
                    e
                );
                std::process::exit(1);
            }
        };

    // Run 147 — early MainNet refusal for the disabled-by-default
    // Run 102 MainNet genesis-path requirement check so the operator
    // sees the precise Run 147 FATAL reason rather than a generic
    // MainNet startup error. Local peer majority is NOT authority on
    // MainNet; the flag is refused unconditionally with exit code 1
    // and the P2P transport is never brought up. See
    // `task/RUN_147_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_staging_enabled {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 147: FATAL: \
                 --p2p-trust-bundle-peer-candidate-staging-enabled is refused on MainNet \
                 unconditionally. Local peer majority is NOT authority on MainNet. No \
                 staging; no apply; no sequence write; no marker write; no session \
                 eviction; no P2P startup. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md."
            );
            std::process::exit(1);
        }
    }

    // Run 149 — early MainNet refusal for the disabled-by-default
    // peer-driven apply arming flag. Local peer majority is NOT
    // authority on MainNet under any environment. The flag is
    // refused unconditionally with exit code 1 and the P2P
    // transport is never brought up. See `task/RUN_149_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_apply_enabled {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 149: FATAL: \
                 --p2p-trust-bundle-peer-candidate-apply-enabled is refused on MainNet \
                 unconditionally. Local peer majority is NOT authority on MainNet. No \
                 apply; no staging; no sequence write; no marker write; no session \
                 eviction; no P2P startup. Governance / ratification / KMS-HSM authority \
                 is required for any MainNet bundle-signing apply and is NOT implemented. \
                 See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md."
            );
            std::process::exit(1);
        }
    }

    // Run 151 — early MainNet refusal for the disabled-by-default
    // explicit local one-shot drain trigger flag. The Run 150
    // `PeerDrivenApplyDrain` controller is forbidden from operating
    // on MainNet under any condition; local peer majority is NOT
    // authority on MainNet. The flag is refused unconditionally
    // with exit code 1 and the P2P transport is never brought up,
    // **before** the Run 149 apply-flag co-requisites gate is
    // consulted so the operator sees the precise Run 151 FATAL
    // reason. See `task/RUN_151_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_drain_once {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 151: FATAL: \
                 --p2p-trust-bundle-peer-candidate-drain-once is refused on MainNet \
                 unconditionally. Local peer majority is NOT authority on MainNet. No \
                 drain; no apply; no staging consumption; no sequence write; no marker \
                 write; no session eviction; no P2P startup. Governance / ratification / \
                 KMS-HSM authority is required for any MainNet bundle-signing apply and \
                 is NOT implemented. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md."
            );
            std::process::exit(1);
        }
    }

    // ------------------------------------------------------------------
    // Run 180 — hidden, disabled-by-default DevNet/TestNet `OnChainGovernance`
    // fixture-proof selector capture.
    //
    // Resolves the active
    // [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy`]
    // from the OR-combination of the hidden
    // `--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI
    // flag and the `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
    // environment variable, and emits a single source-reachability
    // banner. The default — both unset / falsey — preserves
    // `OnChainGovernanceProofPolicy::Disabled`, which keeps every
    // pre-Run-180 production marker-decision invariant intact:
    // `OnChainGovernance` proofs (fixture or otherwise) are refused
    // as `UnsupportedProductionOnChainGovernance` exactly as in
    // Runs 178/179.
    //
    // This block is the smallest production source-reachability
    // call site Run 180 needs in `main.rs` for
    // [`qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env`]
    // and
    // [`qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::AllowFixtureSourceTest`].
    // The composed marker-decision helper
    // [`qbind_node::pqc_onchain_governance_proof_surface::compose_onchain_governance_marker_decision`]
    // and its seven per-surface named wrappers are reached through
    // the production library surface from this same module; Run 180
    // is source/test only and does NOT introduce a binary-side
    // mutating call site here. Release-binary `OnChainGovernance`
    // production-surface evidence is deferred to Run 181.
    //
    // **Non-MainNet-enabling.** Even when the selector is enabled,
    // the resolved policy never elevates a fixture proof into a
    // MainNet apply path — the Run 178 verifier returns
    // `MainNetProductionProofUnavailable` on MainNet, and the
    // Run 147/Run 148/Run 152 MainNet peer-driven-apply refusal at
    // the calling surface remains intact.
    {
        let onchain_governance_proof_policy =
            qbind_node::pqc_onchain_governance_proof_surface::onchain_governance_proof_policy_from_cli_or_env(
                args.p2p_trust_bundle_onchain_governance_fixture_allowed,
            );
        match onchain_governance_proof_policy {
            qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled => {
                // Default — no banner so existing operator console
                // output is bit-for-bit unchanged for non-Run-180
                // operators. The selector is hidden and disabled by
                // default per Run 180 strict scope.
            }
            qbind_node::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::AllowFixtureSourceTest => {
                eprintln!(
                    "[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof \
                     policy ARMED (AllowFixtureSourceTest). Source/test only — fixture \
                     verifier never enables MainNet peer-driven apply, never implements \
                     governance execution, never implements real on-chain proof \
                     verification, never implements KMS/HSM, never implements \
                     validator-set rotation. MainNet remains refused as \
                     MainNetProductionProofUnavailable. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md."
                );
            }
        }
        // Hold the resolved policy in a binding so a future run can
        // pass it down into the per-surface wrappers without
        // changing this capture site.
        let _ = onchain_governance_proof_policy;
    }

    // ------------------------------------------------------------------
    // Run 127 — `--authority-state-reset` offline operator ceremony.
    //
    // When `--authority-state-reset` is present the binary performs the
    // Run 126 offline reset ceremony, writes a deterministic JSON audit
    // record, and exits (0 on success, 1 on refusal). The early-exit fires
    // here — before `--print-genesis-hash`, before MainNet profile
    // validation, before P2P trust-bundle startup, before networking,
    // consensus, metrics, SIGHUP handlers, reload tasks, and peer-
    // candidate dispatch. Normal node startup is never reachable through
    // this code path.
    // ------------------------------------------------------------------
    if args.authority_state_reset {
        use qbind_node::pqc_authority_state_reset::{
            AuthorityResetInputs, execute_authority_state_reset,
        };
        let validation_time_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let updated_at_unix_secs = validation_time_secs;
        let reset_inputs = AuthorityResetInputs {
            data_dir: args.data_dir.clone(),
            genesis_path: args.genesis_path.clone(),
            expected_genesis_hash: args.expect_genesis_hash.clone(),
            trust_bundle_path: args.p2p_trust_bundle.clone(),
            bundle_signing_key_specs: args.p2p_trust_bundle_signing_keys.clone(),
            ratification_path: args.p2p_trust_bundle_ratification.clone(),
            audit_output_path: args.authority_state_reset_output_audit.clone(),
            environment: config.environment,
            operator_note: args.authority_state_reset_operator_note.clone(),
            validation_time_secs,
            updated_at_unix_secs,
        };
        match execute_authority_state_reset(&reset_inputs) {
            Ok(success) => {
                eprintln!(
                    "[run-127] authority-state-reset: SUCCESS.                      marker={} new_marker_hash={} audit={}",
                    success.marker_path.display(),
                    success.new_marker_hash_hex,
                    success.audit_path.display(),
                );
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[run-127] FATAL: authority-state-reset refused: {}", e);
                std::process::exit(1);
            }
        }
    }

    // ------------------------------------------------------------------
    // Run 102 — `--print-genesis-hash` operator tooling.
    //
    // When `--print-genesis-hash` is passed, load the configured external
    // genesis file, compute the **canonical Run 101 genesis hash** under
    // the resolved environment policy, print it to stdout, and exit
    // (`0` on success, `1` on any failure). This replaces the pre-Run-101
    // "hash the exact file bytes" semantics — see the help text on
    // `CliArgs::print_genesis_hash` and the scenario_5 evidence note in
    // `docs/devnet/run_101_genesis_authority_evidence/`.
    //
    // The hash is authority-, chain_id-, and environment-sensitive and is
    // independent of JSON formatting; running this twice on two genesis
    // files that differ only in authority fields prints two different
    // values (proven by Run 102 release-binary evidence).
    //
    // No fallback to raw file-byte hashing exists. Malformed genesis,
    // missing genesis path, and I/O failures all fail closed.
    // See `crates/qbind-node/src/pqc_boot_genesis.rs` and
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md` §Scenario 1.
    // ------------------------------------------------------------------
    if args.print_genesis_hash {
        let genesis_path = match config.genesis_source.genesis_path.as_ref() {
            Some(p) => p.clone(),
            None => {
                eprintln!(
                    "[run-102] FATAL: --print-genesis-hash requires --genesis-path to be set \
                     so the canonical Run 101 hash can be computed over the parsed genesis \
                     config. No embedded fallback. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md §Scenario 1."
                );
                std::process::exit(1);
            }
        };
        let env_policy = qbind_node::pqc_boot_genesis::map_environment(config.environment);
        match qbind_node::pqc_boot_genesis::compute_print_genesis_hash(&genesis_path, env_policy) {
            Ok(hash) => {
                // stdout is the operator-pin surface; stderr carries the
                // human-readable provenance. Output format mirrors
                // `qbind_ledger::format_genesis_hash` (lowercase `0x` +
                // 64 hex chars) so the value can be pasted verbatim into
                // `--expect-genesis-hash` without trimming.
                eprintln!(
                    "[run-102] --print-genesis-hash: canonical Run 101 hash over parsed \
                     genesis (env={:?}, chain_id={}, authority={}, source={})",
                    env_policy,
                    config.chain_id().as_u64(),
                    if config
                        .genesis_source
                        .genesis_path
                        .as_ref()
                        .map(|p| p.exists())
                        .unwrap_or(false)
                    {
                        "<see genesis file>"
                    } else {
                        "<inline>"
                    },
                    genesis_path.display(),
                );
                println!("{}", qbind_node::pqc_boot_genesis::format_for_operator(&hash));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[run-102] FATAL: --print-genesis-hash failed: {}", e);
                std::process::exit(1);
            }
        }
    }

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
    // Run 102 — release-binary boot-time canonical genesis verification.
    //
    // Per `task/RUN_102_TASK.txt` "Expected ordering":
    //   load genesis
    //   → canonicalize/hash parsed genesis
    //   → verify expected genesis hash according to environment policy
    //   → validate genesis authority fields according to environment policy
    //   → only then continue to trust-bundle processing / networking / consensus startup
    //
    // This call site is positioned **after** the T185 MainNet invariants
    // validation (so MainNet still refuses on missing `--expect-genesis-hash`,
    // composing the existing T233 `MainnetConfigError::ExpectedGenesisHashMissing`
    // shield with the new Run 101 canonical verification) and **before**
    // the B3 snapshot restore, Run 069 trust-bundle reload-check,
    // Run 077 peer-candidate check, P2P startup, and the binary-path
    // consensus loop. Any failure here exits non-zero with a precise
    // operator-facing error message — there is no silent fallback to
    // defaults, no fallback authority, and no source-code production
    // anchor.
    //
    // DevNet / TestNet retain their existing embedded-genesis path when
    // no `--genesis-path` is configured (verifier returns
    // `BootGenesisOutcome::SkippedNoExternalGenesis` with a clear log
    // line). MainNet without an external genesis path is rejected here
    // belt-and-braces even if upstream shields are bypassed.
    //
    // See `crates/qbind-node/src/pqc_boot_genesis.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md`, and
    // `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
    // ------------------------------------------------------------------
    let canonical_genesis_hash_hex_for_restore: Option<String> =
        match qbind_node::pqc_boot_genesis::run_boot_time_genesis_verification(&config) {
            Ok(qbind_node::pqc_boot_genesis::BootGenesisOutcome::Verified {
                canonical_hash,
                env,
                genesis_path,
            }) => {
                eprintln!(
                    "[run-102] OK: canonical Run 101 genesis verification passed \
                     (env={:?}, genesis={}, canonical_hash={}).",
                    env,
                    genesis_path.display(),
                    qbind_node::pqc_boot_genesis::format_for_operator(&canonical_hash),
                );
                // Run 124: surface the 64-char lowercase-hex (no `0x` prefix)
                // form for the snapshot/restore authority-marker check, which
                // matches PersistentAuthorityStateRecord.genesis_hash.
                Some(canonical_hash.iter().map(|b| format!("{:02x}", b)).collect())
            }
            Ok(qbind_node::pqc_boot_genesis::BootGenesisOutcome::SkippedNoExternalGenesis {
                env,
            }) => {
                eprintln!(
                    "[run-102] no external --genesis-path configured; canonical boot \
                     verification skipped (env={:?}, embedded-genesis path). MainNet \
                     always requires --genesis-path so this branch is unreachable on MainNet.",
                    env,
                );
                None
            }
            Err(e) => {
                eprintln!("[run-102] FATAL: {}", e);
                eprintln!(
                    "[run-102] qbind-node refuses to start. No fallback authority, no fallback \
                     expected-hash, no source-code production anchor. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md and \
                     docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md."
                );
                std::process::exit(1);
            }
        };

    // ------------------------------------------------------------------
    // B3 + Run 124: Restore-from-snapshot startup path with
    // authority-marker conflict enforcement.
    //
    // If `--restore-from-snapshot <path>` was passed, the node validates
    // and materializes the snapshot into the configured data dir before
    // doing anything else. Failures here are non-zero exits with a clear
    // reason — we never silently degrade to "no restore".
    //
    // Run 124 adds the authority-marker conflict check (run BEFORE any
    // state materialization or audit-marker write): the snapshot's
    // optional `AuthorityStateSnapshotMeta` block is compared against
    // the locally persisted `<data_dir>/pqc_authority_state.json`
    // marker using the pure `verify_snapshot_authority_state_for_restore`
    // helper. A rollback / equivocation / wrong-domain / missing /
    // corrupt outcome exits non-zero BEFORE any state copy, and the
    // local marker file is never mutated or deleted by this surface.
    //
    // The authority context is only available when the canonical Run 101
    // genesis hash was computed at boot (Run 102 `Verified` branch). On
    // DevNet/TestNet without `--genesis-path` (Run 102
    // `SkippedNoExternalGenesis` branch) the legacy
    // `apply_snapshot_restore_if_requested` is used, which itself fails
    // closed if a pre-existing local marker is present
    // (`AuthorityContextMissing`) — there is no silent shadowing.
    //
    // See `crates/qbind-node/src/snapshot_restore.rs`,
    // `crates/qbind-node/src/pqc_authority_state.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_124.md`, and
    // `docs/whitepaper/contradiction.md` C4 (B3, Run 124).
    //
    // B5: the resulting `RestoreOutcome` (when present) is threaded into
    // the binary-path consensus startup so the engine begins from the
    // restored height/view baseline rather than from view 0. See
    // `binary_consensus_loop::RestoreBaseline`.
    // ------------------------------------------------------------------
    let restore_result = match canonical_genesis_hash_hex_for_restore.as_deref() {
        Some(genesis_hex) => {
            let ctx = qbind_node::snapshot_restore::RestoreAuthorityContext {
                runtime_env: config.environment,
                runtime_chain_id: config.chain_id(),
                runtime_genesis_hash_hex: genesis_hex,
            };
            qbind_node::snapshot_restore::apply_snapshot_restore_if_requested_with_authority_context(
                &config, &ctx,
            )
        }
        None => qbind_node::snapshot_restore::apply_snapshot_restore_if_requested(&config),
    };
    let restore_outcome: Option<RestoreOutcome> = match restore_result {
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
        // Run 098: open canonical production ConsensusStorage and read
        // meta:current_epoch for activation. CLI subcommand path that
        // exits via std::process::exit(0/1) — keep _opened alive until
        // exit. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
        let (activation_epoch_source, _opened_b) =
            match qbind_node::pqc_trust_activation_epoch::load_activation_current_epoch_for_cli(
                &config,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: Run 098: --p2p-trust-bundle-reload-check could not open \
                         canonical production ConsensusStorage for activation epoch: {}. \
                         Fail-closed. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.",
                        e
                    );
                    std::process::exit(1);
                }
            };
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: activation_epoch_source.as_option(),
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
        // Run 105/106 — non-mutating ratification gate.
        //
        // Run 105 wired the gate as operator-opt-in via
        // `--p2p-trust-bundle-ratification-enforcement-enabled`. Run 106
        // promotes the **invocation decision** to a per-environment
        // policy via `qbind_node::pqc_ratification_policy`:
        // MainNet/TestNet invoke the gate by default (the opt-in flag
        // can neither enable nor disable it); DevNet preserves the
        // pre-Run-106 opt-in behaviour so unsigned/legacy bundles
        // continue to work in developer workflows. The gate body
        // itself is unchanged from Run 105 — it still drives the full
        // Run 103/105 `enforce_bundle_signing_key_ratification`
        // pipeline and still uses `RatificationEnforcementPolicy::Strict`
        // on MainNet regardless of any flag. When the policy returns
        // `Skip`, the call falls through to the unchanged Run 069
        // entry point so legacy DevNet behaviour is preserved
        // bit-for-bit.
        let gate_decision = qbind_node::pqc_ratification_policy::ratification_gate_decision(
            config.environment,
            args.p2p_trust_bundle_ratification_enforcement_enabled,
        );
        let (reload_check_result, reload_check_ctx_data) = if gate_decision.should_invoke() {
            eprintln!(
                "[run-106] reload-check ratification gate INVOKED (policy={}, env={:?}).",
                gate_decision.label(),
                config.environment
            );
            match build_run_105_reload_check_context(&args, &config) {
                Ok(ctx_data) => {
                    let result = qbind_node::pqc_trust_reload::validate_candidate_bundle_with_ratification(
                        inputs,
                        &qbind_node::pqc_trust_reload::RatificationEnforcementContext {
                            authority: &ctx_data.authority,
                            expected_genesis_hash: &ctx_data.canonical_hash,
                            expected_environment_policy: ctx_data.env_policy,
                            expected_chain_id_str: &ctx_data.chain_id_str,
                            ratification: ctx_data.ratification.as_ref(),
                            policy: ctx_data.policy,
                        },
                    );
                    (result, Some(ctx_data))
                }
                Err(reason) => {
                    eprintln!(
                        "[run-105] Run 069 reload-check refused: ratification context could \
                         not be built: {}. Candidate path={}. No live trust apply, no \
                         sequence write, no session mutation, no metrics mutation. \
                         See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md.",
                        reason,
                        candidate_path.display()
                    );
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!(
                "[run-106] reload-check ratification gate SKIPPED (policy={}, env={:?}). \
                 This is NOT a passed ratification; it preserves pre-Run-105 DevNet \
                 behaviour for developer workflows. MainNet/TestNet always invoke the \
                 gate by default and never reach this branch.",
                gate_decision.label(),
                config.environment
            );
            (qbind_node::pqc_trust_reload::validate_candidate_bundle(inputs), None)
        };
        match reload_check_result {
            Ok(candidate) => {
                // Run 123 — validation-only authority marker conflict check.
                // Runs AFTER ratification succeeds, BEFORE success exit.
                // Never persists marker. Rejects conflict/corruption/wrong-domain.
                if let Some(ref ctx_data) = reload_check_ctx_data {
                    // Run 132 — v2 sidecar dispatch. If a v2 sidecar is present,
                    // run the v2 marker check; otherwise preserve v1 path unchanged.
                    if ctx_data.ratification_v2.is_some() {
                        match preflight_run_132_validation_only_v2_marker_check(
                            config.environment,
                            config.chain_id(),
                            ctx_data,
                            config.data_dir.as_deref(),
                        ) {
                            Ok(Some(decision)) => {
                                eprintln!(
                                    "[run-132] reload-check v2 authority-marker check passed: {} \
                                     (validation-only; no marker persistence; no trust mutation; \
                                     governance policy={:?}).",
                                    decision.kind(),
                                    qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
                                        ctx_data.governance_proof_required_selector,
                                    ),
                                );
                            }
                            Ok(None) => {
                                // Check not applicable (no data-dir, etc.)
                            }
                            Err(marker_err) => {
                                eprintln!(
                                    "[binary] Run 132: VERDICT=invalid (reload-check v2 authority-marker \
                                     conflict; no live trust apply; no sequence persistence write; \
                                     no marker persistence; no peer/session mutation; no /metrics \
                                     mutation). Candidate path={}. Reason: {}.",
                                    candidate_path.display(),
                                    marker_err
                                );
                                std::process::exit(1);
                            }
                        }
                    } else {
                        // v1 path — unchanged.
                        match preflight_run_123_validation_only_marker_check(
                            candidate_path,
                            config.environment,
                            config.chain_id(),
                            now_secs,
                            &bundle_signing_keys,
                            ctx_data,
                            config.data_dir.as_deref(),
                        ) {
                            Ok(Some(reason)) => {
                                eprintln!(
                                    "[run-123] reload-check authority-marker check passed: {} \
                                     (validation-only; no marker persistence; no trust mutation).",
                                    reason
                                );
                            }
                            Ok(None) => {
                                // Check not applicable (DevNet-unsigned, etc.)
                            }
                            Err(marker_err) => {
                                eprintln!(
                                    "[binary] Run 123: VERDICT=invalid (reload-check authority-marker \
                                     conflict; no live trust apply; no sequence persistence write; \
                                     no marker persistence; no peer/session mutation; no /metrics \
                                     mutation). Candidate path={}. Reason: {}.",
                                    candidate_path.display(),
                                    marker_err
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                }
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
            run_local_check, run_local_check_with_ratification, Run077Inputs, Run077RefusalReason,
            Run077Result,
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
        // Run 098: open canonical production ConsensusStorage and read
        // meta:current_epoch for activation. CLI subcommand path that
        // exits via std::process::exit(0/1) — keep _opened alive until
        // exit. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
        let (activation_epoch_source, _opened_c) =
            match qbind_node::pqc_trust_activation_epoch::load_activation_current_epoch_for_cli(
                &config,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: Run 098: --p2p-trust-bundle-peer-candidate-check could \
                         not open canonical production ConsensusStorage for activation epoch: {}. \
                         Fail-closed. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.",
                        e
                    );
                    std::process::exit(1);
                }
            };
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: activation_epoch_source.as_option(),
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

        let gate_decision = qbind_node::pqc_ratification_policy::ratification_gate_decision(
            config.environment,
            args.p2p_trust_bundle_ratification_enforcement_enabled,
        );
        let (run077_result, peer_check_ctx_data) = if gate_decision.should_invoke() {
            eprintln!(
                "[run-107] peer-candidate-check ratification gate INVOKED (policy={}, env={:?}).",
                gate_decision.label(),
                config.environment
            );
            match build_run_105_reload_check_context(&args, &config) {
                Ok(ctx_data) => {
                    let result = run_local_check_with_ratification(
                        inputs,
                        &metrics,
                        &qbind_node::pqc_trust_reload::RatificationEnforcementContext {
                            authority: &ctx_data.authority,
                            expected_genesis_hash: &ctx_data.canonical_hash,
                            expected_environment_policy: ctx_data.env_policy,
                            expected_chain_id_str: &ctx_data.chain_id_str,
                            ratification: ctx_data.ratification.as_ref(),
                            policy: ctx_data.policy,
                        },
                    );
                    (result, Some(ctx_data))
                }
                Err(reason) => {
                    eprintln!(
                        "[run-107] Run 077 peer-candidate-check refused: ratification context \
                         could not be built: {}. Envelope path={}. No live trust apply, no \
                         sequence write, no session mutation, no propagation. See \
                         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_107.md.",
                        reason,
                        envelope_path.display()
                    );
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!(
                "[run-107] peer-candidate-check ratification gate SKIPPED (policy={}, env={:?}). \
                 This preserves pre-Run-107 DevNet local-check behaviour only; MainNet/TestNet \
                 always invoke the gate by default and never reach this branch.",
                gate_decision.label(),
                config.environment
            );
            (run_local_check(inputs, &metrics), None)
        };

        match run077_result {
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
                // Run 123/132 — validation-only authority marker conflict check
                // for peer-candidate-check. Fires only on Validated outcome
                // (ratification already passed). Never persists marker.
                if matches!(
                    outcome,
                    qbind_node::pqc_trust_peer_candidate::PeerCandidateOutcome::Validated(_)
                ) {
                    if let Some(ref ctx_data) = peer_check_ctx_data {
                        // Run 132 — v2 sidecar dispatch for peer-candidate-check.
                        if ctx_data.ratification_v2.is_some() {
                            match preflight_run_132_validation_only_v2_marker_check(
                                config.environment,
                                config.chain_id(),
                                ctx_data,
                                config.data_dir.as_deref(),
                            ) {
                                Ok(Some(decision)) => {
                                    eprintln!(
                                        "[run-132] peer-candidate-check v2 authority-marker check \
                                         passed: {} (validation-only; no marker persistence; \
                                         no trust mutation; governance policy={:?}).",
                                        decision.kind(),
                                        qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
                                            ctx_data.governance_proof_required_selector,
                                        ),
                                    );
                                    // Run 182 — production call-site reachability for the
                                    // Run 180 OnChainGovernance per-surface preflight wrapper
                                    // for the local
                                    // `--p2p-trust-bundle-peer-candidate-check`
                                    // validation-only path. Pure / non-mutating.
                                    invoke_run_182_local_peer_candidate_check_callsite_onchain_governance_marker_decision(
                                        &decision,
                                        ctx_data.onchain_governance_fixture_allowed_selector,
                                    );
                                    // Run 217 — governance-execution
                                    // runtime-arming call-site reachability
                                    // for the local
                                    // `--p2p-trust-bundle-peer-candidate-check`
                                    // validation-only path. Pure /
                                    // non-mutating; outcome dropped.
                                    invoke_run_217_callsite_governance_execution_marker_decision(
                                        &decision,
                                        ctx_data.governance_execution_policy_selector.as_deref(),
                                        qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface::LocalPeerCandidateCheck,
                                    );
                                }
                                Ok(None) => {
                                    // Check not applicable
                                }
                                Err(marker_err) => {
                                    eprintln!(
                                        "[binary] Run 132: VERDICT=invalid (peer-candidate-check \
                                         v2 authority-marker conflict; no live trust apply; no \
                                         sequence persistence write; no marker persistence; no \
                                         peer/session mutation). Envelope path={}. Reason: {}.",
                                        envelope_path.display(),
                                        marker_err
                                    );
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            // v1 path — unchanged.
                            match preflight_run_123_validation_only_marker_check(
                                envelope_path,
                                config.environment,
                                config.chain_id(),
                                now_secs,
                                &bundle_signing_keys,
                                ctx_data,
                                config.data_dir.as_deref(),
                            ) {
                                Ok(Some(reason)) => {
                                    eprintln!(
                                        "[run-123] peer-candidate-check authority-marker check \
                                         passed: {} (validation-only; no marker persistence; \
                                         no trust mutation).",
                                        reason
                                    );
                                }
                                Ok(None) => {
                                    // Check not applicable
                                }
                                Err(marker_err) => {
                                    eprintln!(
                                        "[binary] Run 123: VERDICT=invalid (peer-candidate-check \
                                         authority-marker conflict; no live trust apply; no sequence \
                                         persistence write; no marker persistence; no peer/session \
                                         mutation). Envelope path={}. Reason: {}.",
                                        envelope_path.display(),
                                        marker_err
                                    );
                                    std::process::exit(1);
                                }
                            }
                        }
                    }
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


    // Run 078 — disabled-by-default P2P wire receive-path banner.
    //
    // This block is positioned AFTER the Run 077 binary-facing
    // local check hook and BEFORE the Run 073 process-start
    // reload-apply hook so the "armed / disabled" state of the
    // Run 078 receiver is recorded in operator logs at the SAME
    // place every other trust-bundle hot-reload state is recorded.
    //
    // When `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
    // is NOT supplied (the default), nothing is logged and the
    // production receiver, if it were constructed elsewhere, would
    // be in the `Disabled` state — every wire frame would be a
    // truthful no-op `received_total` + `disabled_total` bump.
    //
    // When the flag IS supplied, a single safe banner line is
    // logged so the operator audit trail records that the wire
    // receiver was armed for this run. **The banner is the ONLY
    // behaviour the flag adds to the production startup path in
    // this run.** No new network listener is bound; no new gossip
    // subscription is started; no new admin-API endpoint is
    // exposed; no filesystem watcher is spawned. The wire-receive
    // codec + `PeerCandidateWireReceiver` are library-level types
    // available to a future production gossip dispatcher under a
    // separate review once peer-driven live apply, peer/gossip
    // propagation, `activation_epoch` runtime sourcing, KMS/HSM
    // custody, and on-chain signing-key ratification all land.
    //
    // See `crates/qbind-node/src/pqc_peer_candidate_wire.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_078.md`, and
    // `docs/whitepaper/contradiction.md` C4 for the exact boundary
    // that remains open.
    if args.p2p_trust_bundle_peer_candidate_wire_validation_enabled
        || args.p2p_trust_bundle_peer_candidate_propagation_enabled
    {
        eprintln!(
            "[binary] Run 088: P2P peer-candidate wire receiver armed for \
             validation-before-propagation acceptance (propagation_enabled={}; NOT applied; sequence \
             not persisted; live trust state unchanged; sessions untouched). \
             Frame discriminator 0x{:02x}, envelope version {}, domain \
             tag {:?}). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_078.md.",
            args.p2p_trust_bundle_peer_candidate_propagation_enabled,
            qbind_node::pqc_peer_candidate_wire::DISCRIMINATOR_PEER_CANDIDATE_WIRE,
            qbind_node::pqc_peer_candidate_wire::PEER_CANDIDATE_WIRE_VERSION,
            qbind_node::pqc_peer_candidate_wire::PEER_CANDIDATE_WIRE_DOMAIN_TAG,
        );
    } else {
        // No log line in the default path so the existing operator
        // banner output is byte-for-byte unchanged for every
        // existing `qbind-node` invocation. The disabled-by-default
        // semantics are anchored entirely by
        // `PeerCandidateWireReceiverConfig::default()` returning
        // `enabled = false`.
    }

    // Run 080 — top-level partial-config refusal for the disabled-by-
    // default peer-candidate wire publisher.
    match (
        args.p2p_trust_bundle_peer_candidate_wire_publish_enabled,
        args.p2p_trust_bundle_peer_candidate_wire_publish_path.as_ref(),
    ) {
        (true, Some(_)) => {}
        (true, None) => {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-peer-candidate-wire-publish-enabled \
                 requires --p2p-trust-bundle-peer-candidate-wire-publish-path <PATH>."
            );
            std::process::exit(1);
        }
        (false, Some(_)) => {
            eprintln!(
                "[binary] FATAL: --p2p-trust-bundle-peer-candidate-wire-publish-path requires \
                 --p2p-trust-bundle-peer-candidate-wire-publish-enabled."
            );
            std::process::exit(1);
        }
        (false, None) => {}
    }
    if args.p2p_trust_bundle_peer_candidate_wire_publish_once
        && !args.p2p_trust_bundle_peer_candidate_wire_publish_enabled
    {
        eprintln!(
            "[binary] FATAL: --p2p-trust-bundle-peer-candidate-wire-publish-once requires \
             --p2p-trust-bundle-peer-candidate-wire-publish-enabled."
        );
        std::process::exit(1);
    }

    // Run 147 — top-level partial-config refusal for the
    // disabled-by-default peer-candidate staging arming flag.
    //
    //   * Refuse on MainNet unconditionally (no staging; no P2P
    //     startup). Local peer majority is NOT authority on MainNet.
    //   * Refuse unless live `0x05` validation is also enabled —
    //     a queue without an upstream validation pipeline would
    //     never receive a candidate, so the operator's request is
    //     refused fail-closed rather than silently dropped.
    //   * The flag does NOT imply propagation; the flag does NOT
    //     imply apply. Both remain orthogonal.
    //
    // See `task/RUN_147_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_staging_enabled {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 147: FATAL: \
                 --p2p-trust-bundle-peer-candidate-staging-enabled is refused on MainNet \
                 unconditionally. Local peer majority is NOT authority on MainNet. No \
                 staging; no apply; no sequence write; no marker write; no session \
                 eviction; no P2P startup. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md."
            );
            std::process::exit(1);
        }
        if !args.p2p_trust_bundle_peer_candidate_wire_validation_enabled {
            eprintln!(
                "[binary] Run 147: FATAL: \
                 --p2p-trust-bundle-peer-candidate-staging-enabled requires \
                 --p2p-trust-bundle-peer-candidate-wire-validation-enabled. The staging \
                 queue is a downstream hook of the live `0x05` validation path and is \
                 meaningless without it. No staging; no apply; no sequence write; no \
                 marker write; no session eviction; no P2P startup."
            );
            std::process::exit(1);
        }
        eprintln!(
            "[binary] Run 147: peer-candidate staging hook arming flag accepted (env={:?}). \
             A bounded, non-applying PeerCandidateStagingQueue will be installed when the \
             live `0x05` dispatcher is constructed. Staging is non-authoritative: NO apply; \
             NO sequence write; NO marker write; NO LivePqcTrustState mutation; NO session \
             eviction; NO SIGHUP / reload-apply. See \
             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md.",
            config.environment
        );
    }

    // Run 149 — disabled-by-default DevNet/TestNet-only co-requisites
    // gate for the peer-driven apply arming flag. The flag is the
    // minimum hidden source delta required to make the Run 148
    // source/test `pqc_peer_candidate_apply::try_apply_staged_peer_candidate`
    // controller reachable from a real `target/release/qbind-node`
    // operator surface honestly.
    //
    //   * Refuse on MainNet unconditionally (no P2P startup). Local
    //     peer majority is NOT authority on MainNet. The early
    //     MainNet refusal at the top of `run_node` already fired
    //     fail-closed; this block re-asserts the same refusal
    //     defensively so a future loosening of the early guard
    //     does not silently arm apply on MainNet.
    //   * Refuse unless live `0x05` validation is also enabled —
    //     the controller consumes the output of the Run 142 / Run 143
    //     validation path; an unvalidated candidate must never reach
    //     apply.
    //   * Refuse unless peer-candidate staging is also enabled —
    //     the Run 148 controller's contract is that apply consumes
    //     **only already-staged** candidates from the Run 145
    //     queue (Run 144 §3 Phase 2 → Phase 4 ordering). Apply
    //     without staging is refused fail-closed rather than
    //     silently inventing an apply path that bypasses staging.
    //   * The flag does NOT imply propagation; the flag does NOT
    //     introduce a new apply algorithm; the flag does NOT bypass
    //     the Run 130 v2 verifier; the flag does NOT bypass the
    //     Run 132 / Run 142 v2 marker pre-apply check; the flag
    //     does NOT bypass Run 055 anti-rollback; the flag does NOT
    //     bypass the Run 065 / Run 091 activation gates.
    //
    // See `task/RUN_149_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_apply_enabled {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 149: FATAL: \
                 --p2p-trust-bundle-peer-candidate-apply-enabled is refused on MainNet \
                 unconditionally (defensive second guard). Local peer majority is NOT \
                 authority on MainNet. No apply; no staging; no sequence write; no marker \
                 write; no session eviction; no P2P startup. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md."
            );
            std::process::exit(1);
        }
        if !args.p2p_trust_bundle_peer_candidate_wire_validation_enabled {
            eprintln!(
                "[binary] Run 149: FATAL: \
                 --p2p-trust-bundle-peer-candidate-apply-enabled requires \
                 --p2p-trust-bundle-peer-candidate-wire-validation-enabled. The peer-driven \
                 apply controller consumes only the output of the live `0x05` validation \
                 path; an unvalidated candidate must never reach apply. No apply; no \
                 staging; no sequence write; no marker write; no session eviction; no P2P \
                 startup."
            );
            std::process::exit(1);
        }
        if !args.p2p_trust_bundle_peer_candidate_staging_enabled {
            eprintln!(
                "[binary] Run 149: FATAL: \
                 --p2p-trust-bundle-peer-candidate-apply-enabled requires \
                 --p2p-trust-bundle-peer-candidate-staging-enabled. The Run 148 peer-driven \
                 apply controller consumes only already-staged candidates per the Run 144 \
                 §3 Phase 2 → Phase 4 ordering; apply without staging is refused \
                 fail-closed rather than silently introducing a new apply algorithm that \
                 bypasses the Run 145 staging queue. No apply; no staging; no sequence \
                 write; no marker write; no session eviction; no P2P startup."
            );
            std::process::exit(1);
        }
        eprintln!(
            "[binary] Run 149: peer-candidate apply arming flag accepted (env={:?}). \
             The Run 148 PeerDrivenApplyPolicy is selected by environment \
             (devnet_enabled / testnet_enabled); MainNet is refused unconditionally. \
             Apply, when invoked by a future drain caller, is delegated to the existing \
             Run 070 apply_validated_candidate_with_previous pipeline (validate → \
             snapshot previous → swap → evict_sessions → commit_sequence); the v2 \
             authority marker is persisted only AFTER sequence commit succeeds, via the \
             V2MarkerCoordinator post-commit boundary. NO new apply algorithm; NO bypass \
             of staging; NO bypass of v2 marker / Run 055 anti-rollback / activation \
             gates. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md.",
            config.environment
        );
        // Run 149 — defensive controller-layer arming banner. The
        // Run 148 `PeerDrivenApplyPolicy` constructor for the current
        // environment is exercised here purely so the policy matrix
        // is materialized at startup time and the operator sees the
        // exact controller-level capabilities the binary will use
        // when the future drain caller is wired. The policy object
        // itself is NOT installed anywhere yet because Run 149 does
        // not introduce a new drain task (which would be a new apply
        // algorithm, explicitly out of scope per `task/RUN_149_TASK.txt`
        // §20). End-to-end apply through the release binary therefore
        // remains under Run 148 source/test coverage; Run 149 is
        // classified honestly as **partial-positive** in
        // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`.
        {
            use qbind_node::pqc_peer_candidate_apply::PeerDrivenApplyPolicy;
            let policy = match config.environment {
                qbind_types::NetworkEnvironment::Devnet => {
                    PeerDrivenApplyPolicy::devnet_enabled()
                }
                qbind_types::NetworkEnvironment::Testnet => {
                    PeerDrivenApplyPolicy::testnet_enabled()
                }
                qbind_types::NetworkEnvironment::Mainnet => {
                    // Unreachable: MainNet was rejected above. Defensive
                    // duplicate to keep fail-closed even if the outer
                    // guard is ever loosened.
                    eprintln!(
                        "[binary] Run 149: FATAL: MainNet peer-driven apply policy \
                         refused at controller-layer arming banner (defensive guard). \
                         Aborting."
                    );
                    std::process::exit(1);
                }
            };
            eprintln!(
                "[run-149] live peer-driven apply policy ARMED \
                 (env={:?}, enabled={}, allow_devnet={}, allow_testnet={}, \
                 allow_mainnet={}). DevNet/TestNet only; MainNet refused unconditionally. \
                 Apply delegated to Run 070 apply_validated_candidate_with_previous; \
                 v2 authority marker persisted only AFTER sequence commit succeeds. \
                 NO new apply algorithm; NO bypass of validation; NO bypass of staging; \
                 NO bypass of v2 marker / Run 055 / activation gates.",
                policy.environment,
                policy.enabled,
                policy.allow_devnet,
                policy.allow_testnet,
                policy.allow_mainnet,
            );
        }
    }

    // Run 151 — hidden, disabled-by-default DevNet/TestNet-only
    // co-requisites gate + acceptance banner + Run 150
    // `PeerDrivenApplyDrain` controller-layer arming banner for the
    // explicit local one-shot drain trigger flag. This is the
    // minimum hidden source delta Run 151 adds to make the Run 150
    // source/test drain trigger reachable from the release binary
    // at all (the Run 150 task explicitly deferred the binary
    // operator trigger to Run 151).
    //
    // Co-requisites enforced here:
    //   * Refuse on MainNet unconditionally (defensive second guard
    //     after the early refusal above). Local peer majority is
    //     NOT authority on MainNet.
    //   * Refuse unless `--p2p-trust-bundle-peer-candidate-apply-enabled`
    //     is also set — the drain controller has nothing to delegate
    //     to without the Run 148 apply policy armed. The Run 149
    //     apply gate itself transitively requires
    //     `--p2p-trust-bundle-peer-candidate-staging-enabled` and
    //     `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
    //     so neither extra co-requisite is re-checked here.
    //
    // Acceptance scope (deliberately narrow): the Run 151 banners
    // declare the binary is ready to drain at most one staged
    // candidate per trigger via the Run 150 drain → Run 148
    // controller → Run 070 apply pipeline; the v2 authority marker
    // is persisted only AFTER `commit_sequence` succeeds. The flag
    // adds NO new apply algorithm, NO autonomous background drain,
    // NO automatic apply on receipt, NO peer-majority authority, NO
    // new wire format, NO schema change, and NO bypass of any
    // existing validation / staging / verifier / marker /
    // anti-rollback / activation gate.
    //
    // See `task/RUN_151_TASK.txt`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`, and
    // `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
    if args.p2p_trust_bundle_peer_candidate_drain_once {
        use qbind_types::NetworkEnvironment;
        if matches!(config.environment, NetworkEnvironment::Mainnet) {
            eprintln!(
                "[binary] Run 151: FATAL: \
                 --p2p-trust-bundle-peer-candidate-drain-once is refused on MainNet \
                 unconditionally (defensive second guard). Local peer majority is NOT \
                 authority on MainNet. No drain; no apply; no staging consumption; no \
                 sequence write; no marker write; no session eviction; no P2P startup. \
                 See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md."
            );
            std::process::exit(1);
        }
        if !args.p2p_trust_bundle_peer_candidate_apply_enabled {
            eprintln!(
                "[binary] Run 151: FATAL: \
                 --p2p-trust-bundle-peer-candidate-drain-once requires \
                 --p2p-trust-bundle-peer-candidate-apply-enabled. The Run 150 \
                 peer-driven apply drain controller delegates apply to the Run 148 \
                 peer-driven apply controller; without the Run 148 controller armed \
                 there is nothing to drain into and the trigger is refused fail-closed \
                 rather than silently introducing a new apply algorithm that bypasses \
                 the Run 148 controller. No drain; no apply; no staging consumption; \
                 no sequence write; no marker write; no session eviction; no P2P \
                 startup."
            );
            std::process::exit(1);
        }
        eprintln!(
            "[binary] Run 151: peer-candidate drain-once trigger flag accepted \
             (env={:?}). The Run 150 PeerDrivenDrainPolicy is selected by environment \
             (devnet_enabled / testnet_enabled); MainNet is refused unconditionally. \
             Drain, when fired, routes through the Run 150 \
             PeerDrivenApplyDrain::try_drain_once → Run 148 \
             try_apply_staged_peer_candidate → existing Run 070 \
             apply_validated_candidate_with_previous pipeline (validate → snapshot \
             previous → swap → evict_sessions → commit_sequence); the v2 authority \
             marker is persisted only AFTER sequence commit succeeds, via the \
             V2MarkerCoordinator post-commit boundary. At most one candidate per \
             trigger; concurrency-guarded; never calls Run 070 directly from main.rs. \
             NO autonomous background drain; NO automatic apply on receipt; NO \
             peer-majority authority; NO new apply algorithm; NO bypass of staging; \
             NO bypass of v2 marker / Run 055 anti-rollback / activation gates. See \
             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md.",
            config.environment
        );
        // Run 151 — defensive controller-layer arming banner. The
        // Run 150 `PeerDrivenDrainPolicy` constructor for the current
        // environment and a fresh `PeerDrivenApplyDrain` controller
        // object are materialized at startup so the operator sees
        // the exact drain-trigger capabilities the binary is armed
        // with and the in-progress concurrency guard is observably
        // initialized (`in_progress=false`). The drain object itself
        // is NOT yet invoked from main.rs because the production
        // `PeerDrivenDrainInvocationBuilder` and live
        // `V2MarkerCoordinator` implementations (which would thread
        // candidate paths, signing-key references, and the live
        // `LivePqcTrustState` apply context through the drain) are
        // out of scope of the "smallest possible hook" allowance in
        // `task/RUN_151_TASK.txt`. End-to-end release-binary apply
        // through the drain therefore remains under Run 150
        // source/test coverage; Run 151 is classified honestly as
        // **partial-positive (trigger-surface arming)** in
        // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md`.
        {
            use qbind_node::pqc_peer_candidate_drain::{
                PeerDrivenApplyDrain, PeerDrivenDrainPolicy,
            };
            let drain_policy = match config.environment {
                qbind_types::NetworkEnvironment::Devnet => {
                    PeerDrivenDrainPolicy::devnet_enabled()
                }
                qbind_types::NetworkEnvironment::Testnet => {
                    PeerDrivenDrainPolicy::testnet_enabled()
                }
                qbind_types::NetworkEnvironment::Mainnet => {
                    // Unreachable: MainNet was rejected above
                    // (twice). Defensive triplicate to keep
                    // fail-closed even if both outer guards are
                    // ever loosened.
                    eprintln!(
                        "[binary] Run 151: FATAL: MainNet peer-driven apply drain \
                         policy refused at controller-layer arming banner (defensive \
                         guard). Aborting."
                    );
                    std::process::exit(1);
                }
            };
            let drain = PeerDrivenApplyDrain::new();
            let in_progress = drain
                .in_progress_flag()
                .load(std::sync::atomic::Ordering::Acquire);
            eprintln!(
                "[run-151] live peer-driven apply drain trigger ARMED \
                 (env={:?}, enabled={}, allow_devnet={}, allow_testnet={}, \
                 max_candidate_age_secs={}, remove_after_apply={}, \
                 in_progress={}). DevNet/TestNet only; MainNet refused \
                 unconditionally. At most one candidate per trigger; \
                 concurrency-guarded (Arc<AtomicBool>); RAII-released. Drain \
                 delegated to Run 148 try_apply_staged_peer_candidate which \
                 delegates apply to Run 070 apply_validated_candidate_with_previous; \
                 v2 authority marker persisted only AFTER sequence commit succeeds. \
                 NO autonomous background drain; NO automatic apply on receipt; NO \
                 peer-majority authority; NO new apply algorithm; NO bypass of \
                 validation; NO bypass of staging; NO bypass of v2 marker / Run 055 \
                 / activation gates.",
                drain_policy.environment,
                drain_policy.enabled,
                drain_policy.allow_devnet,
                drain_policy.allow_testnet,
                drain_policy.max_candidate_age_secs,
                drain_policy.remove_after_apply,
                in_progress,
            );
            // Defensive: prove the controller object's typed
            // `Disabled` short-circuit is reachable from main.rs by
            // exercising the policy's enabled invariants without
            // touching any production state. The drain itself is
            // NOT invoked because the production
            // `PeerDrivenDrainInvocationBuilder` /
            // `V2MarkerCoordinator` impls are out of scope (see the
            // comment above). The `drain` and `drain_policy`
            // bindings are intentionally dropped here so no
            // production state references the drain controller
            // beyond the arming banner — exactly mirroring the
            // Run 149 controller-layer arming-only pattern.
            let _ = (drain, drain_policy);
        }

        // Run 152 — binary-reachable drain invocation plumbing
        // declaration. Run 151 left the production
        // `PeerDrivenDrainInvocationBuilder` / `V2MarkerCoordinator`
        // implementations and the cross-scope shared staging-queue
        // plumbing out of scope; Run 152 lands them in the library
        // (source/test wiring only) so the hidden drain-once hook is
        // now capable of constructing a real drain invocation from the
        // live staged peer-candidate queue and routing it through:
        //
        //   live inbound 0x05 → validation-only v2 acceptance →
        //   staging queue → hidden drain hook →
        //   ProductionDrainInvocationBuilder → ProductionV2MarkerCoordinator
        //   → Run 150 drain → Run 148 controller → Run 070 apply contract
        //
        // The same `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>`
        // installed on the `LivePeerCandidateWireDispatcher`
        // (`staging_queue()`) is the queue the drain consumes via
        // `pqc_peer_candidate_drain::try_drain_once_shared`. The marker
        // discipline reuses the Run 134/136/138 helpers through
        // `pqc_peer_candidate_apply::ProductionV2MarkerCoordinator`.
        //
        // **Run 152 remains source/test wiring only.** The release
        // binary does NOT autonomously invoke the drain here: the live
        // apply context, the verified v2 ratification, and the
        // operator-supplied previous-fingerprint metadata are threaded
        // by the Run 153 end-to-end release-binary harness, which is
        // explicitly deferred. No autonomous background drain; no
        // automatic apply on receipt; MainNet still refused at every
        // layer. The references below prove the plumbing is compiled
        // into and reachable from the release binary without invoking
        // any apply.
        {
            let _binary_reachable_plumbing: [&'static str; 3] = [
                core::any::type_name::<
                    qbind_node::pqc_peer_candidate_drain::ProductionDrainInvocationBuilder<
                        qbind_node::pqc_live_trust_apply::ProductionLiveTrustApplyContext,
                    >,
                >(),
                core::any::type_name::<
                    qbind_node::pqc_peer_candidate_apply::ProductionV2MarkerCoordinator,
                >(),
                core::any::type_name::<
                    fn(
                        &qbind_node::pqc_peer_candidate_drain::PeerDrivenApplyDrain,
                        &std::sync::Arc<
                            parking_lot::Mutex<
                                qbind_node::pqc_peer_candidate_staging::PeerCandidateStagingQueue,
                            >,
                        >,
                    ),
                >(),
            ];
            eprintln!(
                "[run-152] binary-reachable peer-driven drain invocation plumbing PRESENT \
                 (production_builder={}, production_v2_marker_coordinator={}, \
                 shared_queue_drain=pqc_peer_candidate_drain::try_drain_once_shared). \
                 Source/test wiring only; release-binary end-to-end peer-driven apply \
                 evidence is DEFERRED to Run 153. The hidden drain-once hook consumes the \
                 SAME Arc<Mutex<PeerCandidateStagingQueue>> the live inbound 0x05 \
                 dispatcher stages into; the drain routes through Run 150 \
                 PeerDrivenApplyDrain::try_drain_once → Run 148 \
                 try_apply_staged_peer_candidate → Run 070 \
                 apply_validated_candidate_with_previous; the v2 authority marker is \
                 persisted only AFTER sequence commit succeeds. NO autonomous background \
                 drain; NO automatic apply on receipt; MainNet refused unconditionally; \
                 governance / KMS / HSM unimplemented; signing-key rotation/revocation \
                 lifecycle open; full C4 open; C5 open. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_152.md.",
                _binary_reachable_plumbing[0],
                _binary_reachable_plumbing[1],
            );
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
            apply_validated_candidate_with_previous,
            apply_validated_candidate_with_previous_and_ratification, ApplyMode,
            RatificationEnforcementContext, ReloadApplyError, ReloadCheckInputs,
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
        // Run 098: open canonical production ConsensusStorage and read
        // meta:current_epoch for activation. CLI subcommand path that
        // exits via std::process::exit(0/1) — keep _opened alive until
        // exit. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
        let (activation_epoch_source, _opened_d) =
            match qbind_node::pqc_trust_activation_epoch::load_activation_current_epoch_for_cli(
                &config,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!(
                        "[binary] FATAL: Run 098: --p2p-trust-bundle-reload-apply-path could not \
                         open canonical production ConsensusStorage for activation epoch: {}. \
                         Fail-closed. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.",
                        e
                    );
                    std::process::exit(1);
                }
            };
        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: activation_epoch_source.as_option(),
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
        // Run 098: reuse the same epoch source loaded above for the
        // baseline activation context (same canonical committed
        // epoch applies to both candidate and baseline validation
        // within this CLI subcommand). See
        // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
        let baseline_activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
            current_height: Some(activation_current_height),
            current_epoch: activation_epoch_source.as_option(),
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

        // Run 112 — process-start reload-apply ratification preflight.
        //
        // Apply the same Run 106 per-environment ratification policy
        // already used by the reload-check (Run 069/106) and
        // peer-candidate-check (Run 077/107) binary paths:
        //
        //   * MainNet / TestNet : ratification gate INVOKED by
        //     default. The operator opt-in flag can neither enable
        //     nor disable the gate; the gate body still drives the
        //     full Run 103/105
        //     `enforce_bundle_signing_key_ratification` pipeline and
        //     refuses missing / malformed / wrong-chain /
        //     wrong-environment / unknown-root / transport-root /
        //     missing-key-material / malformed-key-material /
        //     unsupported-suite / bad-signature ratification.
        //   * DevNet : gate invoked only when the operator opts in
        //     via `--p2p-trust-bundle-ratification-enforcement-enabled`.
        //
        // When `Invoke`, the apply path calls the Run 112
        // `apply_validated_candidate_with_previous_and_ratification`
        // entry point, which runs the Run 105 ratification
        // preflight BEFORE any snapshot / swap / eviction / commit
        // step. Ratification refusal surfaces as
        // `ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))`
        // and triggers the existing fail-closed reporting in the
        // `Err(e) => ...` branch below — no live trust mutation, no
        // sequence write, no session eviction.
        //
        // When `Skip` (DevNet without opt-in), the apply path falls
        // through to the unchanged Run 070/073
        // `apply_validated_candidate_with_previous(...)` entry point
        // so legacy DevNet ergonomics for unsigned / legacy bundles
        // are preserved bit-for-bit; this branch is unreachable on
        // MainNet/TestNet.
        let gate_decision = qbind_node::pqc_ratification_policy::ratification_gate_decision(
            config.environment,
            args.p2p_trust_bundle_ratification_enforcement_enabled,
        );
        let apply_result = if gate_decision.should_invoke() {
            eprintln!(
                "[run-112] reload-apply ratification gate INVOKED (policy={}, env={:?}).",
                gate_decision.label(),
                config.environment
            );
            match build_run_105_reload_check_context(&args, &config) {
                Ok(ctx_data) => {
                    // Run 134 — v2 sidecar dispatch. When the operator
                    // supplied a v2 ratification sidecar, run the v2
                    // marker preflight (Run 134), apply the candidate
                    // through the existing Run 070 pipeline WITHOUT a
                    // v1 ratification context (v2 verification has
                    // already happened in the preflight), then persist
                    // the v2 marker AFTER `commit_sequence`. v1
                    // dispatch (the existing branch) is preserved
                    // unchanged.
                    if ctx_data.ratification_v2.is_some() {
                        eprintln!(
                            "[run-134] reload-apply v2 ratification path SELECTED \
                             (v2 sidecar present; v1 ratification context skipped)."
                        );

                        let v2_decision = match preflight_run_134_v2_marker_decision(
                            config.environment,
                            config.chain_id(),
                            &ctx_data,
                            config.data_dir.as_deref(),
                            now_secs,
                        ) {
                            Ok(opt) => opt,
                            Err(reason) => {
                                eprintln!(
                                    "[run-134] FATAL: reload-apply refused by v2 \
                                     authority-marker preflight: {}. Candidate path={}. \
                                     No live trust apply, no sequence write, no session \
                                     eviction, no metrics mutation, no marker write. See \
                                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md.",
                                    reason,
                                    candidate_path.display()
                                );
                                std::process::exit(1);
                            }
                        };

                        // Run 070 — apply the candidate without a v1
                        // ratification context. The candidate's
                        // structural / sequence / signature /
                        // activation checks still run inside the
                        // pipeline; only the v1 ratification preflight
                        // step is skipped (the v2 verifier already
                        // ran in `preflight_run_134_v2_marker_decision`).
                        let apply_outcome = apply_validated_candidate_with_previous(
                            inputs,
                            ApplyMode::ApplyLive,
                            Some(&mut apply_ctx),
                            prev_fp_prefix.clone(),
                            prev_seq,
                        );

                        // Run 134 — persist v2 marker AFTER
                        // `commit_sequence`. No-op when:
                        //   * preflight returned `None`;
                        //   * preflight decision was `Idempotent`;
                        //   * the apply pipeline returned `Err`.
                        //
                        // A persist failure here means the trust-bundle
                        // sequence already advanced; the on-disk v2
                        // marker is stale-by-one (safely replayable per
                        // Run 118 §D / Run 131), but the operator MUST
                        // be told.
                        if apply_outcome.is_ok() {
                            if let Some(decision) = v2_decision.as_ref() {
                                match qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(decision) {
                                    Ok(()) => {
                                        if decision.should_persist() {
                                            eprintln!(
                                                "[run-134] v2 authority-marker persisted at {} \
                                                 ({}; candidate \
                                                 latest_authority_domain_sequence={}).",
                                                decision.marker_path().display(),
                                                decision.kind(),
                                                decision.candidate().latest_authority_domain_sequence
                                            );
                                        } else {
                                            eprintln!(
                                                "[run-134] v2 authority-marker unchanged at {} \
                                                 (idempotent; no rewrite).",
                                                decision.marker_path().display()
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[run-134] FATAL: v2 authority-marker persist \
                                             failure AFTER successful apply: {}. The \
                                             trust-bundle sequence already committed; the \
                                             on-disk v2 authority marker is stale-by-one and \
                                             will be re-derived on the next accepted \
                                             mutation (Run 118 §D / Run 131 crash-window \
                                             rule). Candidate path={}. See \
                                             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md.",
                                            e,
                                            candidate_path.display()
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }

                        apply_outcome
                    } else {
                    // Run 119 — authority-marker accept-and-persist
                    // preflight. Runs BEFORE the apply pipeline so a
                    // rollback / same-sequence-equivocation / wrong-
                    // domain marker fail-closes the operation without
                    // mutating live trust state or burning a sequence
                    // number. No-op when:
                    //   * `--data-dir` is unset (DevNet-only convenience
                    //     branch — the binary already FATAL-exits if
                    //     --data-dir is unset on MainNet/TestNet for
                    //     this CLI path);
                    //   * the operator-supplied ratification is `None`
                    //     under `AllowLegacyUnratified` (DevNet
                    //     legacy ergonomics — no ratified key, so no
                    //     marker is derivable);
                    //   * the candidate cannot be pre-loaded (the
                    //     apply pipeline will surface the precise
                    //     load error itself).
                    //
                    // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md.
                    let marker_decision = match preflight_run_119_marker_decision(
                        &candidate_path,
                        config.environment,
                        config.chain_id(),
                        now_secs,
                        &bundle_signing_keys,
                        &ctx_data,
                        config.data_dir.as_deref(),
                        now_secs,
                    ) {
                        Ok(opt) => opt,
                        Err(reason) => {
                            eprintln!(
                                "[run-119] FATAL: reload-apply refused by authority-marker \
                                 preflight: {}. Candidate path={}. No live trust apply, no \
                                 sequence write, no session eviction, no metrics mutation, \
                                 no marker write. See \
                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md.",
                                reason,
                                candidate_path.display()
                            );
                            std::process::exit(1);
                        }
                    };

                    let apply_outcome = apply_validated_candidate_with_previous_and_ratification(
                        inputs,
                        &RatificationEnforcementContext {
                            authority: &ctx_data.authority,
                            expected_genesis_hash: &ctx_data.canonical_hash,
                            expected_environment_policy: ctx_data.env_policy,
                            expected_chain_id_str: &ctx_data.chain_id_str,
                            ratification: ctx_data.ratification.as_ref(),
                            policy: ctx_data.policy,
                        },
                        ApplyMode::ApplyLive,
                        Some(&mut apply_ctx),
                        prev_fp_prefix.clone(),
                        prev_seq,
                    );

                    // Run 119 — persist the previously-accepted marker
                    // AFTER the existing `commit_sequence` boundary.
                    // No-op when:
                    //   * preflight returned `None` (no marker context
                    //     applicable on this branch);
                    //   * preflight decision was `Idempotent` (the
                    //     on-disk marker is bit-for-bit identical to
                    //     the candidate; rewriting would only update
                    //     the audit-only `updated_at_unix_secs` field
                    //     for no operator benefit);
                    //   * the apply pipeline returned `Err`.
                    //
                    // A persist failure here means the trust-bundle
                    // sequence already advanced and the on-disk
                    // authority marker is stale-by-one. This is
                    // intentionally safe per Run 118 §D (the next
                    // accepted mutation will replay it as an
                    // `Upgrade`), but the operator MUST be told so we
                    // exit non-zero and surface the precise reason.
                    if apply_outcome.is_ok() {
                        if let Some(decision) = marker_decision.as_ref() {
                            match qbind_node::pqc_authority_marker_acceptance::persist_accepted_marker_after_commit_boundary(decision) {
                                Ok(()) => {
                                    if decision.should_persist() {
                                        eprintln!(
                                            "[run-119] authority-marker persisted at {} ({}; \
                                             candidate authority_sequence={}).",
                                            decision.marker_path().display(),
                                            decision.kind(),
                                            decision.candidate().authority_sequence
                                        );
                                    } else {
                                        eprintln!(
                                            "[run-119] authority-marker unchanged at {} \
                                             (idempotent; no rewrite).",
                                            decision.marker_path().display()
                                        );
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[run-119] FATAL: authority-marker persist failure \
                                         AFTER successful apply: {}. The trust-bundle sequence \
                                         already committed; the on-disk authority marker is \
                                         stale-by-one and will be re-derived on the next \
                                         accepted mutation (Run 118 §D crash-window rule). \
                                         Candidate path={}. See \
                                         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md.",
                                        e,
                                        candidate_path.display()
                                    );
                                    std::process::exit(1);
                                }
                            }
                        }
                    }

                    apply_outcome
                    }
                }
                Err(reason) => {
                    eprintln!(
                        "[run-112] FATAL: reload-apply refused — ratification context could \
                         not be built: {}. Candidate path={}. No live trust apply, no \
                         sequence write, no session eviction, no metrics mutation. See \
                         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_112.md.",
                        reason,
                        candidate_path.display()
                    );
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!(
                "[run-112] reload-apply ratification gate SKIPPED (policy={}, env={:?}). \
                 This is NOT a passed ratification; it preserves pre-Run-112 DevNet \
                 behaviour for developer workflows. MainNet/TestNet always invoke the \
                 gate by default and never reach this branch.",
                gate_decision.label(),
                config.environment
            );
            apply_validated_candidate_with_previous(
                inputs,
                ApplyMode::ApplyLive,
                Some(&mut apply_ctx),
                prev_fp_prefix.clone(),
                prev_seq,
            )
        };

        match apply_result {
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

    // ------------------------------------------------------------------
    // Run 093: open the canonical production-binary `ConsensusStorage`
    // at `<data_dir>/consensus`, run T104 schema-compat and M16
    // incomplete-epoch-transition checks, and probe the explicit
    // startup state (`NoConsensusStorage` / `PresentNoCommittedEpoch` /
    // `CommittedEpoch(u64)`).
    //
    // This is storage-lifecycle groundwork only. Run 093 does NOT
    // consume the observed epoch for PQC trust-bundle activation;
    // every activation site continues to build
    // `ActivationContext { current_epoch: None }`, preserving the
    // Run 091 fail-closed `CurrentEpochUnavailable` boundary on every
    // environment. See
    // `crates/qbind-node/src/production_consensus_storage.rs`,
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md`, and
    // `docs/whitepaper/contradiction.md` C4.
    //
    // Fail-closed on any open / schema / recovery / probe failure —
    // we never silently degrade to "no storage" when `data_dir` is
    // set.
    // ------------------------------------------------------------------
    let consensus_storage_lifecycle: OpenedProductionConsensusStorage =
        match open_production_consensus_storage(&config) {
            Ok(opened) => {
                eprintln!("{}", opened.log_summary());
                opened
            }
            Err(e) => {
                eprintln!("[binary] FATAL: Run 093 production consensus storage open failed: {}", e);
                eprintln!(
                    "[binary] qbind-node refuses to start because the canonical \
                     <data_dir>/consensus directory could not be honestly opened, \
                     schema-checked, or recovery-verified. No fallback path. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md and \
                     docs/whitepaper/contradiction.md C4."
                );
                std::process::exit(1);
            }
        };
    // ------------------------------------------------------------------
    // Run 097: snapshot epoch parity for the restore path.
    //
    // If we restored from a snapshot (B3) AND the snapshot's `meta.json`
    // carries a canonical committed epoch (`StateSnapshotMeta.epoch =
    // Some(n)`), persist that epoch into the canonical
    // `<data_dir>/consensus` `meta:current_epoch` surface we just opened.
    // This re-establishes canonical epoch parity between the restored
    // on-disk VM-v0 state and the production consensus storage so that
    // Run 094's engine-epoch persistence and (later) PQC trust-bundle
    // activation observe the same canonical epoch the snapshot was
    // taken at. Fail-closed on write failure or inconsistency with any
    // pre-existing CommittedEpoch — never silently overwrite.
    //
    // Run 097 does NOT change `ActivationContext.current_epoch`
    // construction; the Run 091/092 fail-closed
    // `CurrentEpochUnavailable` boundary remains in place for PQC
    // trust-bundle activation in this run.
    //
    // See `crates/qbind-node/src/production_consensus_storage.rs`
    // (`persist_restored_snapshot_epoch`) and
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_097.md`.
    // ------------------------------------------------------------------
    if let Some(outcome) = restore_outcome.as_ref() {
        let snapshot_epoch = outcome.meta.epoch;
        match persist_restored_snapshot_epoch(&consensus_storage_lifecycle, snapshot_epoch) {
            Ok(true) => {
                eprintln!(
                    "[binary] Run 097: snapshot canonical epoch={} persisted into \
                     <data_dir>/consensus meta:current_epoch.",
                    snapshot_epoch.expect("Ok(true) implies Some")
                );
            }
            Ok(false) => {
                eprintln!(
                    "[binary] Run 097: no snapshot epoch persistence performed \
                     (snapshot_epoch={:?}, storage_state={}).",
                    snapshot_epoch,
                    consensus_storage_lifecycle.state.tag()
                );
            }
            Err(e) => {
                eprintln!("[binary] FATAL: Run 097 snapshot epoch parity failed: {}", e);
                eprintln!(
                    "[binary] qbind-node refuses to start because the restored \
                     on-disk state cannot be honestly reconciled with the \
                     canonical <data_dir>/consensus meta:current_epoch surface. \
                     No fallback path. See \
                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_097.md."
                );
                std::process::exit(1);
            }
        }
    }
    // Branch based on network mode for transport / wiring.
    match config.network_mode {
        NetworkMode::LocalMesh => {
            run_local_mesh_node(
                &config,
                &args,
                Arc::clone(&node_metrics),
                restore_baseline,
                vm_v0_runtime.clone(),
                consensus_storage_lifecycle.handle.clone(),
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
                    consensus_storage_lifecycle.handle.clone(),
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
    // Run 093: explicitly drop the production consensus-storage handle
    // here so the RocksDB lock is released on clean shutdown rather
    // than at unwind. The handle was held continuously from open
    // (above) through consensus loop teardown (handled inside
    // `run_local_mesh_node` / `run_p2p_node`).
    eprintln!(
        "[binary] Run 093 consensus storage shutdown: state={} (releasing RocksDB lock)",
        consensus_storage_lifecycle.state.tag(),
    );
    drop(consensus_storage_lifecycle);
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
    consensus_storage: Option<Arc<qbind_node::storage::RocksDbConsensusStorage>>,
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
    // Run 094: thread the canonical production `ConsensusStorage`
    // handle (opened by Run 093's `open_production_consensus_storage`)
    // into the binary-path consensus loop so real engine epoch
    // transitions are persisted via `apply_epoch_transition_atomic`.
    // No handle (DevNet ad-hoc smoke without --data-dir) → no
    // persistence is attempted (the loop is identical to pre-Run-094).
    if let Some(storage) = consensus_storage.clone() {
        let storage_dyn: Arc<dyn qbind_node::storage::ConsensusStorage> = storage;
        cfg = cfg.with_consensus_storage(storage_dyn);
        eprintln!(
            "[binary] Run 094: binary consensus loop wired to canonical \
             production ConsensusStorage handle (LocalMesh)."
        );
    } else {
        eprintln!(
            "[binary] Run 094: no canonical production ConsensusStorage \
             handle available (data_dir unset) — no epoch persistence on \
             this LocalMesh invocation."
        );
    }
    // Run 096: install the local-operator-gated canonical reconfig
    // proposal intent (DevNet/TestNet only; MainNet refused at the
    // CLI gate). Disabled by default (the default `None` path is
    // bit-equivalent to pre-Run-096 behaviour).
    match derive_run_096_reconfig_proposal(config, args) {
        Ok(Some(rc)) => {
            cfg = cfg.with_reconfig_proposal(rc);
            eprintln!(
                "[binary] Run 096: armed canonical reconfig proposal intent \
                 (LocalMesh) — target_epoch={} (single-shot; the next \
                 leader-step proposal will be PAYLOAD_KIND_RECONFIG).",
                rc.target_epoch
            );
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("[binary] FATAL: {}", e);
            std::process::exit(1);
        }
    }
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
    // Run 097: pass the canonical production `ConsensusStorage` handle
    // into the SIGUSR1 snapshot task so the operator-triggered snapshot
    // can attach the canonical committed epoch to `meta.json`. None
    // here (no --data-dir) → snapshot meta will carry `epoch: None`
    // (explicit absence; NOT 0).
    let snapshot_consensus_storage: Option<Arc<dyn qbind_node::storage::ConsensusStorage>> =
        consensus_storage
            .clone()
            .map(|s| s as Arc<dyn qbind_node::storage::ConsensusStorage>);
    let snapshot_handle = spawn_vm_v0_snapshot_signal_task(
        vm_v0_runtime,
        Arc::clone(&node_metrics),
        config.chain_id().as_u64(),
        snapshot_consensus_storage,
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
    consensus_storage: Option<Arc<qbind_node::storage::RocksDbConsensusStorage>>,
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
            //   current_epoch  = canonical production ConsensusStorage
            //     `meta:current_epoch` via Run 098 helper. Wired from the
            //     Run 093 lifecycle's committed-epoch state. When no committed
            //     epoch exists (fresh DB, no epochs, or no storage at all),
            //     the helper returns `UnavailableNoCommittedEpoch`, which
            //     maps to `None` — preserving fail-closed semantics (a bundle
            //     that declares `activation_epoch` will fail with
            //     `CurrentEpochUnavailable`). See
            //     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
            let activation_current_height: u64 = restore_baseline
                .as_ref()
                .map(|b| b.snapshot_height)
                .unwrap_or(0);
            let activation_epoch_source = match
                qbind_node::pqc_trust_activation_epoch::activation_epoch_source_from_storage(
                    consensus_storage.as_ref(),
                ) {
                    Ok(src) => src,
                    Err(e) => {
                        eprintln!(
                            "[binary] Run 098: WARNING: failed to read canonical \
                             meta:current_epoch for startup bundle activation: {}. \
                             Proceeding with current_epoch=None (fail-closed if bundle \
                             declares activation_epoch).",
                            e
                        );
                        qbind_node::pqc_trust_activation_epoch::ActivationEpochSource::UnavailableNoCommittedEpoch
                    }
                };
            let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
                current_height: Some(activation_current_height),
                current_epoch: activation_epoch_source.as_option(),
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

                    // Run 105/106: non-mutating bundle-signing-key
                    // ratification enforcement gate. MUST run AFTER
                    // all existing Run 050/051/053/057/062/065
                    // bundle validation succeeds and the activation
                    // gate is satisfied, but BEFORE the Run 055
                    // sequence write and BEFORE bundle roots are
                    // merged into `trusted_roots`. A refused
                    // ratification fails closed without writing the
                    // sequence record and without merging any new
                    // root.
                    //
                    // Run 106: invocation is now a per-environment
                    // policy (see
                    // `qbind_node::pqc_ratification_policy`). MainNet
                    // and TestNet invoke the gate by default — the
                    // `--p2p-trust-bundle-ratification-enforcement-enabled`
                    // flag can neither enable nor disable MainNet
                    // enforcement. DevNet preserves the Run 105
                    // operator-opt-in behaviour so developer
                    // workflows keep working.
                    //
                    // On MainNet, a ratification path is REQUIRED. On
                    // TestNet/DevNet, legacy unratified is permitted
                    // only when the operator additionally supplies
                    // `--p2p-trust-bundle-allow-unratified-testnet-devnet`
                    // and is refused by the gate body on MainNet
                    // regardless. See
                    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_106.md`.
                    let startup_gate_decision =
                        qbind_node::pqc_ratification_policy::ratification_gate_decision(
                            config.environment,
                            args.p2p_trust_bundle_ratification_enforcement_enabled,
                        );
                    // Run 120 — authority-marker preflight decision
                    // produced by `decide_marker_acceptance` ONLY when
                    // the Run 105/106 startup gate accepts the bundle
                    // AND a ratified key is available. Persisted later
                    // (after the Run 055 sequence write succeeds) so
                    // the marker never advances ahead of the trust-
                    // bundle sequence record on this surface.
                    let mut startup_marker_decision:
                        Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecision> =
                        None;
                    // Run 136 — v2 startup marker decision, populated when
                    // the operator-supplied sidecar is schema_version=2.
                    // Persisted later (after the Run 055 sequence write
                    // succeeds) so the v2 marker never advances ahead of
                    // the trust-bundle sequence record on this surface.
                    // Mutually exclusive with `startup_marker_decision`:
                    // exactly one of the two carries a decision after the
                    // gate body, based on the sidecar schema_version.
                    let mut startup_marker_decision_v2:
                        Option<qbind_node::pqc_authority_marker_acceptance::MarkerAcceptDecisionV2> =
                        None;
                    if startup_gate_decision.should_invoke() {
                        eprintln!(
                            "[run-106] startup ratification gate INVOKED (policy={}, env={:?}).",
                            startup_gate_decision.label(),
                            config.environment
                        );
                        // Build the Run 105 enforcement context once
                        // so it can be reused by the Run 120 marker
                        // preflight (v1) or the Run 136 marker preflight
                        // (v2) without re-loading the operator-supplied
                        // genesis / ratification files. Run 132's
                        // versioned dispatcher inside the context builder
                        // populates either `ratification` (v1) or
                        // `ratification_v2` (v2), never both.
                        let startup_ctx_data = match build_run_105_reload_check_context(&args, &config) {
                            Ok(ctx) => Some(ctx),
                            Err(reason) => {
                                // The startup gate body re-loads these
                                // files itself, so a build failure here
                                // would also surface there. We log and
                                // let the gate body produce the
                                // operator-facing fatal message; the
                                // Run 120/136 preflight is skipped on
                                // this branch (no marker write either
                                // way).
                                eprintln!(
                                    "[run-120] authority-marker startup preflight skipped: \
                                     could not build Run 105 ratification context: {} \
                                     (the Run 105/106 gate body will surface the precise \
                                     ratification failure).",
                                    reason
                                );
                                None
                            }
                        };

                        // Run 136 — versioned-sidecar dispatch on the
                        // startup mutating surface. When the operator
                        // supplied a v2 ratification sidecar, take the
                        // v2 path (Run 130 verifier inside the Run 136
                        // preflight + Run 131 v2 marker compare). The
                        // v1 startup gate
                        // (`apply_run_105_ratification_gate_at_startup`)
                        // cannot parse a v2 sidecar and is therefore
                        // SKIPPED on this branch — the v2 verifier
                        // already runs inside
                        // `preflight_run_136_v2_marker_decision_for_startup`.
                        // This mirrors the Run 134 reload-apply v2
                        // dispatch shape and preserves all v1 startup
                        // behaviour bit-for-bit when the sidecar is
                        // v1 or absent.
                        let dispatch_v2 = startup_ctx_data
                            .as_ref()
                            .map(|c| c.ratification_v2.is_some())
                            .unwrap_or(false);

                        if dispatch_v2 {
                            // ---- Run 136 v2 startup path ----
                            eprintln!(
                                "[run-136] startup --p2p-trust-bundle v2 ratification path \
                                 SELECTED (v2 sidecar present; v1 startup gate \
                                 `apply_run_105_ratification_gate_at_startup` SKIPPED — v2 \
                                 verifier runs inside the Run 136 preflight)."
                            );
                            // SAFE: `dispatch_v2` is true only when
                            // `startup_ctx_data` is Some.
                            let ctx_data = startup_ctx_data.as_ref().unwrap();
                            // Run 136 — v2 authority-marker startup
                            // preflight. Runs BEFORE the Run 055
                            // sequence anti-rollback write, BEFORE
                            // bundle roots are merged into
                            // `trusted_roots`, and BEFORE any P2P /
                            // network startup. A v2 verifier failure
                            // / v1-after-v2 rollback / lower v2
                            // sequence / same-sequence-equivocation /
                            // wrong-domain / corrupt marker
                            // fail-closes the operation without
                            // writing the Run 055 sequence record,
                            // without merging any new trust anchor,
                            // and without starting P2P.
                            //
                            // No-op when:
                            //   * `--data-dir` is unset (DevNet
                            //     convenience; TestNet/MainNet are
                            //     already FATAL-rejected below if
                            //     --data-dir is missing on this
                            //     surface).
                            //
                            // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_136.md.
                            match preflight_run_136_v2_marker_decision_for_startup(
                                config.environment,
                                config.chain_id(),
                                ctx_data,
                                config.data_dir.as_deref(),
                                now_secs,
                            ) {
                                Ok(opt) => {
                                    startup_marker_decision_v2 = opt;
                                }
                                Err(reason) => {
                                    eprintln!(
                                        "[run-136] FATAL: startup --p2p-trust-bundle refused by \
                                         v2 authority-marker preflight: {}. Path={}. No Run 055 \
                                         sequence write, no bundle-root merge, no live trust \
                                         mutation, no P2P startup, no marker write. See \
                                         docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_136.md, \
                                         docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md \
                                         §\"Authority anti-rollback marker (Run 117–120, v2 Run \
                                         129–131, startup v2 Run 136)\".",
                                        reason,
                                        path.display()
                                    );
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            // ---- v1 startup path (unchanged) ----
                            if let Err(reason) =
                                apply_run_105_ratification_gate_at_startup(&args, &config, &loaded, &bundle_signing_keys)
                            {
                                eprintln!(
                                    "[run-105] FATAL: bundle-signing-key ratification refused at \
                                     startup; sequence record NOT written, bundle roots NOT merged \
                                     into the live PQC trust set, no live trust mutation \
                                     occurred. Reason: {}",
                                    reason
                                );
                                eprintln!(
                                    "[run-105] qbind-node refuses to start. See \
                                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md, \
                                     docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md \
                                     §\"Run 105 ratification enforcement\"."
                                );
                                std::process::exit(1);
                            }
                            // Run 120 — authority-marker startup preflight.
                            // Runs ONLY after the Run 105/106 gate accepts
                            // the bundle, BEFORE the Run 055 sequence
                            // anti-rollback write, BEFORE bundle roots are
                            // merged into `trusted_roots`, and BEFORE any
                            // P2P / network startup. A rollback / same-
                            // sequence-equivocation / wrong-domain /
                            // corrupt marker fail-closes the operation
                            // without writing the Run 055 sequence record
                            // and without merging any new trust anchor.
                            //
                            // No-op when:
                            //   * `--data-dir` is unset (DevNet
                            //     convenience; TestNet/MainNet are already
                            //     FATAL-rejected below if --data-dir is
                            //     missing on this surface);
                            //   * the candidate is `BundleSignatureStatus::
                            //     Unsigned` (DevNet unsigned bundle — no
                            //     ratified key to anchor a marker on);
                            //   * the per-environment policy is
                            //     `AllowLegacyUnratified` with no
                            //     ratification supplied (DevNet/TestNet
                            //     legacy ergonomics — Run 105 already
                            //     logged `LegacyUnratifiedAccepted`).
                            //
                            // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md.
                            if let Some(ctx_data) = startup_ctx_data.as_ref() {
                                match preflight_run_120_marker_decision_for_startup(
                                    &loaded,
                                    config.environment,
                                    config.chain_id(),
                                    &bundle_signing_keys,
                                    ctx_data,
                                    config.data_dir.as_deref(),
                                    now_secs,
                                ) {
                                    Ok(opt) => {
                                        startup_marker_decision = opt;
                                    }
                                    Err(reason) => {
                                        eprintln!(
                                            "[run-120] FATAL: startup --p2p-trust-bundle refused by \
                                             authority-marker preflight: {}. Path={}. No Run 055 \
                                             sequence write, no bundle-root merge, no live trust \
                                             mutation, no P2P startup, no marker write. See \
                                             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md, \
                                             docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md \
                                             §\"Authority anti-rollback marker (Run 117–120)\".",
                                            reason,
                                            path.display()
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                    } else {
                        eprintln!(
                            "[run-106] startup ratification gate SKIPPED (policy={}, env={:?}). \
                             This is NOT a passed ratification; it preserves pre-Run-105 DevNet \
                             behaviour for developer workflows. MainNet/TestNet always invoke \
                             the gate by default and never reach this branch.",
                            startup_gate_decision.label(),
                            config.environment
                        );
                        // Run 120 — explicitly NOT wired on the
                        // legacy-unratified DevNet branch. No ratified
                        // key exists, so no authority marker is
                        // derivable; the marker file remains untouched.
                        eprintln!(
                            "[run-120] authority-marker startup write skipped: ratification \
                             gate was not invoked (DevNet no-opt-in legacy path). The marker \
                             file is NOT written from unratified state."
                        );
                    }

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

                                // Run 120 — persist the previously-
                                // accepted authority marker AFTER the
                                // Run 055 `check_and_update_sequence`
                                // commit boundary. No-op when:
                                //   * no decision was produced (gate
                                //     SKIPPED, unsigned bundle,
                                //     LegacyUnratifiedAccepted, or
                                //     --data-dir absent — all of which
                                //     were logged at the preflight
                                //     skip site above);
                                //   * the decision is `Idempotent` (the
                                //     on-disk marker is bit-for-bit
                                //     identical; rewriting would only
                                //     bump the audit-only
                                //     `updated_at_unix_secs`).
                                //
                                // Persist failure here means the Run
                                // 055 sequence already advanced and the
                                // on-disk authority marker is stale-by-
                                // one. This is intentionally safe per
                                // Run 118 §D (the next accepted
                                // mutation replays it as an `Upgrade`),
                                // but the operator MUST be told, so we
                                // exit non-zero and surface the precise
                                // reason. See docs/devnet/
                                // QBIND_DEVNET_EVIDENCE_RUN_120.md.
                                if let Some(decision) = startup_marker_decision.as_ref() {
                                    match qbind_node::pqc_authority_marker_acceptance::persist_accepted_marker_after_commit_boundary(decision) {
                                        Ok(()) => {
                                            if decision.should_persist() {
                                                eprintln!(
                                                    "[run-120] authority-marker persisted at {} \
                                                     ({}; candidate authority_sequence={}).",
                                                    decision.marker_path().display(),
                                                    decision.kind(),
                                                    decision.candidate().authority_sequence
                                                );
                                            } else {
                                                eprintln!(
                                                    "[run-120] authority-marker unchanged at {} \
                                                     (idempotent; no rewrite).",
                                                    decision.marker_path().display()
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "[run-120] FATAL: authority-marker persist \
                                                 failure AFTER successful Run 055 sequence \
                                                 write at startup: {}. The trust-bundle \
                                                 sequence already committed; the on-disk \
                                                 authority marker is stale-by-one and will be \
                                                 re-derived on the next accepted mutation (Run \
                                                 118 §D crash-window rule). Candidate path={}. \
                                                 No bundle-root merge, no P2P startup. See \
                                                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md.",
                                                e,
                                                path.display()
                                            );
                                            std::process::exit(1);
                                        }
                                    }
                                }

                                // Run 136 — persist the previously-
                                // accepted v2 authority marker AFTER the
                                // Run 055 `check_and_update_sequence`
                                // commit boundary. Mutually exclusive
                                // with the v1 persist block above (the
                                // dispatcher populates exactly one of
                                // `startup_marker_decision` /
                                // `startup_marker_decision_v2`). No-op
                                // when:
                                //   * no decision was produced (no v2
                                //     sidecar / --data-dir absent — both
                                //     of which were logged at the
                                //     preflight skip site above);
                                //   * the decision is v2 `Idempotent`
                                //     (the on-disk marker is bit-for-bit
                                //     identical; rewriting would only
                                //     bump the audit-only
                                //     `updated_at_unix_secs`).
                                //
                                // Persist failure here means the Run 055
                                // sequence already advanced and the on-
                                // disk v2 authority marker is stale-by-
                                // one. This is intentionally safe per
                                // Run 118 §D / Run 131 (the next
                                // accepted v2 mutation replays it as a
                                // `UpgradeV2`), but the operator MUST be
                                // told, so we exit non-zero and surface
                                // the precise reason. See
                                // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_136.md.
                                if let Some(decision) = startup_marker_decision_v2.as_ref() {
                                    match qbind_node::pqc_authority_marker_acceptance::persist_accepted_v2_marker_after_commit_boundary(decision) {
                                        Ok(()) => {
                                            if decision.should_persist() {
                                                eprintln!(
                                                    "[run-136] v2 authority-marker persisted at {} \
                                                     ({}; candidate \
                                                     latest_authority_domain_sequence={}).",
                                                    decision.marker_path().display(),
                                                    decision.kind(),
                                                    decision.candidate().latest_authority_domain_sequence
                                                );
                                            } else {
                                                eprintln!(
                                                    "[run-136] v2 authority-marker unchanged at {} \
                                                     (idempotent; no rewrite).",
                                                    decision.marker_path().display()
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "[run-136] FATAL: v2 authority-marker persist \
                                                 failure AFTER successful Run 055 sequence \
                                                 write at startup: {}. The trust-bundle \
                                                 sequence already committed; the on-disk v2 \
                                                 authority marker is stale-by-one and will be \
                                                 re-derived on the next accepted mutation (Run \
                                                 118 §D / Run 131 crash-window rule). Candidate \
                                                 path={}. No bundle-root merge, no P2P startup. \
                                                 See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_136.md.",
                                                e,
                                                path.display()
                                            );
                                            std::process::exit(1);
                                        }
                                    }
                                }
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

    // Run 079 — install the live P2P peer-candidate wire frame
    // sink on the production-binary builder.
    //
    // When the hidden flag
    // `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` is
    // set:
    //
    //   * if a `--p2p-trust-bundle` baseline + `trust_bundle_loaded`
    //     is available, construct a full
    //     `LivePeerCandidateWireDispatcher` and install it on the
    //     builder via `with_peer_candidate_wire_sink`. The dispatcher
    //     wraps the Run 078 receiver one-to-one, reuses the same
    //     seven Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
    //     metric counters surfaced on `/metrics`, and the per-peer
    //     `read_loop` routes every received `0x05` frame through
    //     it (validation-only — NEVER applied / propagated / evicts);
    //   * if no baseline is loaded, install a cheap-discard sink
    //     so the read loop still recognizes the `0x05`
    //     discriminator and does not close the connection on a
    //     peer-supplied wire frame (the operator opt-in is honored
    //     truthfully even when the validation pipeline is
    //     unavailable).
    //
    // The hook MUST NOT mutate any pre-existing builder field; it
    // either calls `with_peer_candidate_wire_sink` exactly once or
    // not at all. The default path (`enabled == false`) is
    // bit-for-bit identical to pre-Run-079.
    let mut propagation_dispatcher_for_sender: Option<
        Arc<qbind_node::pqc_peer_candidate_wire::LivePeerCandidateWireDispatcher>,
    > = None;
    // Run 153 — hold a reference to the shared staging queue for the
    // drain-once hook. When the drain-once flag is armed, this is the
    // SAME `Arc<Mutex<PeerCandidateStagingQueue>>` the live inbound
    // `0x05` dispatcher stages into. No second queue, no copy.
    let mut drain_once_staging_queue: Option<
        std::sync::Arc<parking_lot::Mutex<qbind_node::pqc_peer_candidate_staging::PeerCandidateStagingQueue>>,
    > = None;
    let builder = if args.p2p_trust_bundle_peer_candidate_wire_validation_enabled
        || args.p2p_trust_bundle_peer_candidate_propagation_enabled
    {
        use qbind_node::pqc_peer_candidate_wire::{
            DiscardPeerCandidateWireSink, LivePeerCandidateWireDispatcher,
            LivePeerCandidateWireDispatcherConfig, PeerCandidatePropagationConfig,
            PeerCandidateWireFrameSink, PeerCandidateWireReceiverConfig,
        };
        use qbind_node::pqc_trust_peer_candidate::PeerCandidateConfig;
        let metrics_arc = node_metrics.p2p_arc();
        let sink: Arc<dyn PeerCandidateWireFrameSink> = match trust_bundle_loaded
            .as_ref()
        {
            Some(loaded) => {
                // Use the same scratch directory shape Run 077 /
                // Run 070 helpers use: a process-scoped temp dir.
                // The dispatcher's inner validator only writes
                // temp candidate files here; never the persistent
                // sequence file (that path is read-only on the
                // wire-receive path).
                let scratch_dir = std::env::temp_dir().join(format!(
                    "qbind-run079-wire-scratch-{}",
                    std::process::id()
                ));
                if let Err(e) = std::fs::create_dir_all(&scratch_dir) {
                    eprintln!(
                        "[binary] Run 079: FATAL: scratch dir create failed at {}: {}. \
                         Disabling wire sink (frames will be cheap-dropped at the read loop).",
                        scratch_dir.display(),
                        e
                    );
                    Arc::new(DiscardPeerCandidateWireSink::new(Arc::clone(&metrics_arc)))
                        as Arc<dyn PeerCandidateWireFrameSink>
                } else {
                    let validation_time_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    // Reuse the bundle's environment (already
                    // validated against `config.environment` by
                    // the loader) and the operator-supplied
                    // chain id from the live `config` so the
                    // wire envelope's pre-decode checks match
                    // the operator's runtime view bit-for-bit.
                    let dispatcher_cfg = LivePeerCandidateWireDispatcherConfig {
                        inner: PeerCandidateWireReceiverConfig {
                            enabled: true,
                            inner: PeerCandidateConfig::default(),
                        },
                        expected_environment: config.environment,
                        expected_chain_id: config.environment.chain_id(),
                        scratch_dir,
                        signing_keys: bundle_signing_keys.clone(),
                        activation_ctx:
                            qbind_node::pqc_trust_activation::ActivationContext::height_only(0),
                        // Run 098: pass the canonical production
                        // `ConsensusStorage` handle so the dispatcher
                        // reads `meta:current_epoch` per-frame. This
                        // ensures epoch-gated bundles activate correctly
                        // even when epoch transitions happen after the
                        // dispatcher is constructed. See
                        // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
                        consensus_storage_for_epoch: consensus_storage.clone(),
                        sequence_persistence_path: config
                            .data_dir
                            .as_ref()
                            .map(|d| {
                                qbind_node::pqc_trust_sequence::sequence_file_path(d)
                            }),
                        // Local leaf bytes are optional on the Run
                        // 076/077/078 receive path (the local-leaf
                        // self-check only fires when the operator
                        // has them configured). At this point in
                        // run_p2p_node, `leaf_credentials` has
                        // already been moved into the trust-bundle
                        // pipeline above, so we pass `None` here
                        // — the Run 079 receive path still
                        // executes Run 069 loader checks plus the
                        // Run 076 envelope / rate-limit / LRU
                        // pipeline against the peer-supplied
                        // candidate, just without the optional
                        // Run 063 local-leaf gate (the local leaf
                        // is exercised on the production *send*
                        // path via the live `LivePqcTrustState`
                        // wiring above).
                        local_leaf_cert_bytes: None,
                        validation_time_secs,
                        propagation: PeerCandidatePropagationConfig {
                            enabled: args.p2p_trust_bundle_peer_candidate_propagation_enabled,
                            ..PeerCandidatePropagationConfig::default()
                        },
                        propagation_sender: None,
                        // Run 109 — install owned ratification context
                        // for live `0x05` inbound peer-candidate frames.
                        // MainNet/TestNet are default-strict (Run 106);
                        // DevNet honours the operator opt-in. When the
                        // gate decision says invoke and the context
                        // cannot be built (no --genesis-path, no
                        // authority block, malformed sidecar), the
                        // process refuses to install the dispatcher on
                        // MainNet/TestNet — there is no fallback path.
                        // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_109.md.
                        live_ratification: {
                            let gate_decision =
                                qbind_node::pqc_ratification_policy::ratification_gate_decision(
                                    config.environment,
                                    args.p2p_trust_bundle_ratification_enforcement_enabled,
                                );
                            if gate_decision.should_invoke() {
                                match build_run_105_reload_check_context(&args, &config) {
                                    Ok(ctx_data) => {
                                        eprintln!(
                                            "[run-109] live peer-candidate wire ratification \
                                             gate INVOKED (policy={}, env={:?}). Unratified, \
                                             missing, or bad ratification candidates will be \
                                             rejected BEFORE validation success and BEFORE any \
                                             Run 088 rebroadcast.",
                                            gate_decision.label(),
                                            config.environment
                                        );
                                        Some(qbind_node::pqc_peer_candidate_wire::LiveRatificationConfig {
                                            authority: ctx_data.authority,
                                            expected_genesis_hash: ctx_data.canonical_hash,
                                            expected_environment_policy: ctx_data.env_policy,
                                            expected_chain_id_str: ctx_data.chain_id_str,
                                            ratification: ctx_data.ratification,
                                            // Run 142 — plumb the optional v2
                                            // ratification sidecar into the live
                                            // wire dispatcher. The versioned
                                            // sidecar loader produces exactly
                                            // one of v1 or v2; the dispatcher
                                            // routes accordingly and rejects
                                            // ambiguous v1+v2 fail-closed.
                                            ratification_v2: ctx_data.ratification_v2,
                                            policy: ctx_data.policy,
                                            gate_decision,
                                        })
                                    }
                                    Err(reason) => {
                                        eprintln!(
                                            "[binary] FATAL: Run 109 live peer-candidate wire \
                                             ratification context could not be built: {}. \
                                             Refusing to install the live `0x05` dispatcher; \
                                             no fallback; no apply; no sequence write; no \
                                             session eviction. See \
                                             docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_109.md.",
                                            reason
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            } else {
                                eprintln!(
                                    "[run-109] live peer-candidate wire ratification gate \
                                     SKIPPED (policy={}, env={:?}). This preserves pre-Run-109 \
                                     DevNet legacy behaviour only; MainNet/TestNet always invoke \
                                     the gate by default and never reach this branch.",
                                    gate_decision.label(),
                                    config.environment
                                );
                                None
                            }
                        },
                        // Run 123 — validation-only authority marker path
                        // for live inbound `0x05` conflict checks. Computed
                        // from --data-dir + the Run 109 ratification gate
                        // being invoked. When both are present, the
                        // dispatcher performs a marker compare on every
                        // Validated outcome BEFORE propagation. Never
                        // persists marker.
                        authority_marker_path: {
                            let gate_decision =
                                qbind_node::pqc_ratification_policy::ratification_gate_decision(
                                    config.environment,
                                    args.p2p_trust_bundle_ratification_enforcement_enabled,
                                );
                            if gate_decision.should_invoke() {
                                config.data_dir.as_ref().map(|d| {
                                    let p = qbind_node::pqc_authority_state::authority_state_file_path(d);
                                    eprintln!(
                                        "[run-123] live 0x05 authority-marker validation-only \
                                         check ARMED (marker_path={}).",
                                        p.display()
                                    );
                                    p
                                })
                            } else {
                                eprintln!(
                                    "[run-123] live 0x05 authority-marker check SKIPPED \
                                     (ratification gate not invoked; DevNet legacy path)."
                                );
                                None
                            }
                        },
                        // Run 147 — hidden, disabled-by-default operator
                        // opt-in to arm the Run 146 non-applying
                        // `PeerCandidateStagingQueue` hook on the live
                        // inbound `0x05` validation-only path. Default
                        // behaviour is bit-for-bit Run 143 (queue stays
                        // `None`). When the flag is supplied, MainNet
                        // refuses startup unconditionally; DevNet/TestNet
                        // install a bounded queue with the Run 145
                        // conservative defaults. The queue NEVER applies,
                        // NEVER persists sequence, NEVER writes the
                        // authority marker, NEVER mutates LivePqcTrustState,
                        // NEVER evicts sessions, and NEVER invokes SIGHUP /
                        // reload-apply. See `task/RUN_147_TASK.txt`,
                        // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`,
                        // and `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`.
                        staging_queue: if args
                            .p2p_trust_bundle_peer_candidate_staging_enabled
                        {
                            use qbind_node::pqc_peer_candidate_staging::{
                                PeerCandidateStagingQueue, PeerDrivenStagingPolicy,
                            };
                            use parking_lot::Mutex;
                            if matches!(
                                config.environment,
                                qbind_types::NetworkEnvironment::Mainnet
                            ) {
                                eprintln!(
                                    "[binary] Run 147: FATAL: \
                                     --p2p-trust-bundle-peer-candidate-staging-enabled \
                                     is refused on MainNet unconditionally. Local peer \
                                     majority is NOT authority on MainNet. No staging; \
                                     no apply; no sequence write; no marker write; no \
                                     session eviction; no P2P startup. See \
                                     docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md."
                                );
                                std::process::exit(1);
                            }
                            let policy = match config.environment {
                                qbind_types::NetworkEnvironment::Devnet => {
                                    PeerDrivenStagingPolicy::devnet_enabled()
                                }
                                qbind_types::NetworkEnvironment::Testnet => {
                                    PeerDrivenStagingPolicy::testnet_enabled()
                                }
                                qbind_types::NetworkEnvironment::Mainnet => {
                                    // Unreachable: MainNet was rejected
                                    // above. Defensive duplicate to keep
                                    // fail-closed even if the outer guard
                                    // is ever loosened.
                                    eprintln!(
                                        "[binary] Run 147: FATAL: MainNet staging \
                                         policy refused at queue construction \
                                         (defensive guard). Aborting."
                                    );
                                    std::process::exit(1);
                                }
                            };
                            eprintln!(
                                "[run-147] live peer-candidate staging hook ARMED \
                                 (env={:?}, enabled={}, allow_devnet={}, allow_testnet={}, \
                                 max_global={}, max_per_peer={}, ttl_secs={}). Non-applying; \
                                 non-authoritative; no sequence write; no marker write; no \
                                 session eviction; no SIGHUP / reload-apply.",
                                policy.environment,
                                policy.enabled,
                                policy.allow_devnet,
                                policy.allow_testnet,
                                policy.max_staged_candidates,
                                policy.max_candidates_per_peer,
                                policy.ttl_secs
                            );
                            Some({
                                let q = std::sync::Arc::new(Mutex::new(
                                    PeerCandidateStagingQueue::new(policy),
                                ));
                                // Run 153 — hold a clone so the
                                // drain-once hook can consume from
                                // the SAME shared queue after P2P
                                // startup.
                                if args.p2p_trust_bundle_peer_candidate_drain_once {
                                    drain_once_staging_queue = Some(std::sync::Arc::clone(&q));
                                }
                                q
                            })
                        } else {
                            None
                        },
                    };
                    eprintln!(
                        "[binary] Run 088: installing live peer-candidate wire \
                         dispatcher (env={} sequence_baseline={} signing_keys={} propagation_enabled={} \
                         consensus_storage_for_epoch={}).",
                        loaded.environment(),
                        loaded.bundle.sequence,
                        bundle_signing_keys.len(),
                        args.p2p_trust_bundle_peer_candidate_propagation_enabled,
                        consensus_storage.is_some(),
                    );
                    let dispatcher = Arc::new(LivePeerCandidateWireDispatcher::new(
                        dispatcher_cfg,
                        Arc::clone(&metrics_arc),
                    ));
                    if args.p2p_trust_bundle_peer_candidate_propagation_enabled {
                        propagation_dispatcher_for_sender = Some(Arc::clone(&dispatcher));
                    }
                    dispatcher as Arc<dyn PeerCandidateWireFrameSink>
                }
            }
            None => {
                if args.p2p_trust_bundle_peer_candidate_propagation_enabled {
                    eprintln!(
                        "[binary] FATAL: --p2p-trust-bundle-peer-candidate-propagation-enabled \
                         requires a validated --p2p-trust-bundle baseline so received 0x05 \
                         candidates can be validated before any propagation. No fallback; no \
                         apply; no sequence write; no session eviction."
                    );
                    std::process::exit(1);
                }
                eprintln!(
                    "[binary] Run 079: --p2p-trust-bundle-peer-candidate-wire-validation-enabled \
                     was supplied without a --p2p-trust-bundle baseline; installing \
                     cheap-discard sink (wire frames will be observed via the seven \
                     Run 076 peer_candidate_* counters and otherwise dropped without decode)."
                );
                Arc::new(DiscardPeerCandidateWireSink::new(Arc::clone(&metrics_arc)))
                    as Arc<dyn PeerCandidateWireFrameSink>
            }
        };
        builder.with_peer_candidate_wire_sink(sink)
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

    if let Some(dispatcher) = propagation_dispatcher_for_sender {
        use qbind_node::pqc_peer_candidate_wire::PeerCandidateWireFrameSender;
        let sender: Arc<dyn PeerCandidateWireFrameSender> = node_context.p2p_service.clone();
        dispatcher.set_propagation_sender(sender);
    }

    eprintln!(
        "[binary] P2P transport up. Listen address: {}, static peers: {}",
        config.network.listen_addr.as_deref().unwrap_or("unknown"),
        config.network.static_peers.len()
    );

    // Run 080 — disabled-by-default operator-triggered publish-once
    // send-side counterpart for peer-candidate wire frame 0x05.
    if args.p2p_trust_bundle_peer_candidate_wire_publish_enabled
        && args.p2p_trust_bundle_peer_candidate_wire_publish_once
    {
        use qbind_node::pqc_peer_candidate_wire::{
            wire_publish_log_line, LivePeerCandidateWirePublisher,
            PeerCandidateWireFrameSender, PeerCandidateWirePublishConfig,
        };
        let sender: Arc<dyn PeerCandidateWireFrameSender> = node_context.p2p_service.clone();
        let publisher =
            LivePeerCandidateWirePublisher::new(sender, Arc::clone(&node_context.metrics));
        let publish_cfg = PeerCandidateWirePublishConfig {
            enabled: true,
            envelope_path: args
                .p2p_trust_bundle_peer_candidate_wire_publish_path
                .clone(),
            publish_once: true,
            // Run 177 — optional, hidden, harness-only sibling carrier
            // path. When `None`, the publish wire envelope's
            // `governance_authority_proof` field stays `None` (bit-for-
            // bit identical to pre-Run-177 publish behaviour). When
            // present, the publisher parses the JSON as a
            // `GovernanceAuthorityProofWire` (fail-closed on parse
            // failure) and attaches it to the live `0x05` envelope
            // before encoding the Run 078 wire frame. See
            // `task/RUN_177_TASK.txt` and
            // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md`.
            governance_proof_path: args
                .p2p_trust_bundle_peer_candidate_wire_publish_governance_proof_path
                .clone(),
            ..PeerCandidateWirePublishConfig::default()
        };
        match publisher.publish_once_from_config(&publish_cfg).await {
            Ok(report) => {
                eprintln!("{}", wire_publish_log_line(&report, report.attempted()));
            }
            Err(e) => {
                eprintln!(
                    "[binary] Run 080: publish-once attempt failed closed: {} \
                     (validation-only boundary preserved; no apply; no sequence write; \
                     no live trust mutation; no session eviction).",
                    e
                );
            }
        }
    }

    // Run 153 — release-binary end-to-end peer-driven apply drain-once.
    //
    // When `--p2p-trust-bundle-peer-candidate-drain-once` is armed AND the
    // staging queue is populated from the live inbound `0x05` path, this
    // block performs exactly ONE drain through the full pipeline:
    //
    //   staging queue → ProductionDrainInvocationBuilder
    //   → ProductionV2MarkerCoordinator → Run 150 drain → Run 148
    //   controller → Run 070 apply → LivePqcTrustState swap → session
    //   eviction → sequence commit → v2 authority marker persist.
    //
    // Minimal, hidden, disabled-by-default, DevNet/TestNet-only,
    // MainNet-refused. No autonomous background drain. No automatic apply
    // on receipt. The drain fires once after a configurable delay
    // (QBIND_DRAIN_ONCE_DELAY_SECS, default 10) to give live inbound `0x05`
    // candidates time to arrive and stage.
    if args.p2p_trust_bundle_peer_candidate_drain_once {
        if let Some(shared_queue) = drain_once_staging_queue.as_ref() {
            let delay_secs: u64 = std::env::var("QBIND_DRAIN_ONCE_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10);
            eprintln!(
                "[run-153] drain-once delay: waiting {}s for live inbound 0x05 candidates \
                 to arrive and stage before triggering the explicit drain-once.",
                delay_secs
            );
            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let drain_live_state = live_for_reload_apply.as_ref().cloned();

            if let Some(drain_live_state) = drain_live_state {

            let evictor: Arc<dyn qbind_node::p2p_session_eviction::P2pSessionEvictor> =
                node_context.p2p_service.clone();

            let seq_path = config
                .data_dir
                .as_ref()
                .map(|d| qbind_node::pqc_trust_sequence::sequence_file_path(d));

            let live_arc = std::sync::Arc::new(drain_live_state);
            let apply_ctx = qbind_node::pqc_live_trust_apply::ProductionLiveTrustApplyContext::new(
                live_arc,
                evictor,
                config.environment,
                config.chain_id(),
                seq_path.clone(),
                now_secs,
            );

            // Scratch directory for the drain builder's candidate material.
            let scratch_dir = std::env::temp_dir().join(format!(
                "qbind-run153-drain-scratch-{}",
                std::process::id()
            ));
            let _ = std::fs::create_dir_all(&scratch_dir);
            let candidate_path = scratch_dir.join("drain_candidate.bundle");

            let (prev_fp_prefix, prev_seq) = {
                let snap = apply_ctx.snapshot_previous_metadata();
                snap
            };

            // Construct the production drain invocation builder.
            let mut invocation_builder = qbind_node::pqc_peer_candidate_drain::ProductionDrainInvocationBuilder::new(
                candidate_path,
                bundle_signing_keys.clone(),
                seq_path,
                config.environment,
                config.chain_id(),
                now_secs,
                qbind_node::pqc_trust_activation::ActivationContext::height_only(0),
                None, // local_leaf_cert_bytes
                apply_ctx,
                prev_fp_prefix,
                prev_seq,
                3600, // max_candidate_age_secs (1 hour)
                now_secs,
            );

            // Construct the v2 marker coordinator (or no-op if v2
            // ratification is unavailable).
            let mut marker_coordinator: Box<dyn qbind_node::pqc_peer_candidate_apply::V2MarkerCoordinator> =
                match build_run_105_reload_check_context(&args, &config) {
                    Ok(ctx_data) => {
                        if let Some(ratification_v2) = ctx_data.ratification_v2 {
                            use qbind_ledger::{
                                verify_bundle_signing_key_ratification_v2,
                                RatificationV2VerifierInputs,
                            };
                            match verify_bundle_signing_key_ratification_v2(
                                RatificationV2VerifierInputs {
                                    ratification: &ratification_v2,
                                    authority: &ctx_data.authority,
                                    expected_chain_id: &ctx_data.chain_id_str,
                                    expected_environment: ctx_data.env_policy,
                                    expected_genesis_hash: &ctx_data.canonical_hash,
                                },
                            ) {
                                Ok(ratified_v2) => {
                                    let marker_path = config
                                        .data_dir
                                        .as_ref()
                                        .map(|d| {
                                            qbind_node::pqc_authority_state::authority_state_file_path(d)
                                        })
                                        .unwrap_or_else(|| {
                                            std::path::PathBuf::from("/dev/null")
                                        });
                                    let mut genesis_hash_hex = String::with_capacity(64);
                                    for b in ctx_data.canonical_hash {
                                        use std::fmt::Write;
                                        let _ = write!(genesis_hash_hex, "{:02x}", b);
                                    }
                                    eprintln!(
                                        "[run-153] drain-once: ProductionV2MarkerCoordinator \
                                         constructed (v2 ratification verified)."
                                    );
                                    // Run 171 — attach the typed Run
                                    // 167 governance proof load and
                                    // the active Run 165 policy
                                    // (selected by the hidden
                                    // `--p2p-trust-bundle-governance-proof-required`
                                    // flag / env var). Default
                                    // remains `Absent` + `NotRequired`
                                    // so the existing Run 148/150/152/
                                    // 153 peer-driven apply test
                                    // matrix is unchanged. MainNet
                                    // peer-driven apply remains
                                    // refused at the upstream binary
                                    // gate regardless of policy.
                                    let governance_proof_load =
                                        ctx_data.governance_proof_load.clone();
                                    let governance_policy =
                                        qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
                                            ctx_data.governance_proof_required_selector,
                                        );
                                    Box::new(
                                        qbind_node::pqc_peer_candidate_apply::ProductionV2MarkerCoordinator::new(
                                            marker_path,
                                            config.environment,
                                            config.chain_id(),
                                            genesis_hash_hex,
                                            ratification_v2,
                                            ratified_v2,
                                            qbind_node::pqc_authority_state::AuthorityStateUpdateSource::ReloadApply,
                                            now_secs,
                                        )
                                        .with_governance_proof_carrier(
                                            governance_proof_load,
                                            governance_policy,
                                        )
                                        .with_onchain_governance_fixture_allowed_selector(
                                            args.p2p_trust_bundle_onchain_governance_fixture_allowed,
                                        ),
                                    )
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[run-153] drain-once: v2 ratification verification \
                                         failed: {}. Falling back to NoV2MarkerCoordinator.",
                                        e
                                    );
                                    Box::new(
                                        qbind_node::pqc_peer_candidate_apply::NoV2MarkerCoordinator,
                                    )
                                }
                            }
                        } else {
                            eprintln!(
                                "[run-153] drain-once: no v2 ratification sidecar available. \
                                 Using NoV2MarkerCoordinator."
                            );
                            Box::new(
                                qbind_node::pqc_peer_candidate_apply::NoV2MarkerCoordinator,
                            )
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[run-153] drain-once: reload-check context could not be built: \
                             {}. Using NoV2MarkerCoordinator.",
                            e
                        );
                        Box::new(
                            qbind_node::pqc_peer_candidate_apply::NoV2MarkerCoordinator,
                        )
                    }
                };

            // Construct drain policy and apply policy.
            use qbind_node::pqc_peer_candidate_drain::{
                PeerDrivenApplyDrain, PeerDrivenDrainPolicy,
            };
            use qbind_node::pqc_peer_candidate_apply::{
                PeerDrivenApplyPolicy, PeerDrivenApplyRuntimeDomain,
            };
            let drain_policy = match config.environment {
                qbind_types::NetworkEnvironment::Devnet => {
                    PeerDrivenDrainPolicy::devnet_enabled()
                }
                qbind_types::NetworkEnvironment::Testnet => {
                    PeerDrivenDrainPolicy::testnet_enabled()
                }
                qbind_types::NetworkEnvironment::Mainnet => {
                    eprintln!(
                        "[run-153] FATAL: MainNet peer-driven apply drain refused \
                         unconditionally at drain-once invocation (defensive guard)."
                    );
                    std::process::exit(1);
                }
            };
            let apply_policy = match config.environment {
                qbind_types::NetworkEnvironment::Devnet => {
                    PeerDrivenApplyPolicy::devnet_enabled()
                }
                qbind_types::NetworkEnvironment::Testnet => {
                    PeerDrivenApplyPolicy::testnet_enabled()
                }
                qbind_types::NetworkEnvironment::Mainnet => {
                    eprintln!(
                        "[run-153] FATAL: MainNet peer-driven apply policy refused \
                         unconditionally at drain-once invocation (defensive guard)."
                    );
                    std::process::exit(1);
                }
            };
            let runtime_domain = PeerDrivenApplyRuntimeDomain::new(
                config.environment,
                qbind_node::pqc_trust_sequence::chain_id_hex(config.chain_id()),
            );
            let drain = PeerDrivenApplyDrain::new();

            eprintln!(
                "[run-153] drain-once: invoking try_drain_once_shared (env={:?}, \
                 drain_enabled={}, apply_enabled={}).",
                config.environment,
                drain_policy.enabled,
                apply_policy.enabled,
            );

            let outcome = qbind_node::pqc_peer_candidate_drain::try_drain_once_shared(
                &drain,
                shared_queue,
                &mut invocation_builder,
                marker_coordinator.as_mut(),
                &drain_policy,
                &apply_policy,
                &runtime_domain,
                now_secs,
            );

            eprintln!(
                "[run-153] drain-once outcome: {:?}. No autonomous repeat drain; \
                 no automatic apply on receipt; MainNet refused unconditionally; \
                 governance / KMS / HSM unimplemented; signing-key rotation/revocation \
                 lifecycle open; full C4 open; C5 open.",
                outcome
            );
            } else {
                eprintln!(
                    "[run-153] drain-once skipped: no baseline LivePqcTrustState is \
                     available (--p2p-trust-bundle was not supplied). No drain; no apply; \
                     no mutation."
                );
            }
        } else {
            eprintln!(
                "[run-153] drain-once: no staging queue available (staging not armed). \
                 Drain skipped; no mutation."
            );
        }
    }

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
    // Run 094: thread the canonical production `ConsensusStorage`
    // handle (opened by Run 093's `open_production_consensus_storage`)
    // into the binary-path consensus loop so real engine epoch
    // transitions are persisted via `apply_epoch_transition_atomic`.
    if let Some(storage) = consensus_storage.clone() {
        let storage_dyn: Arc<dyn qbind_node::storage::ConsensusStorage> = storage;
        consensus_cfg = consensus_cfg.with_consensus_storage(storage_dyn);
        eprintln!(
            "[binary] Run 094: binary consensus loop wired to canonical \
             production ConsensusStorage handle (P2P)."
        );
    } else {
        eprintln!(
            "[binary] Run 094: no canonical production ConsensusStorage \
             handle available (data_dir unset) — no epoch persistence on \
             this P2P invocation."
        );
    }
    // Run 096: install the local-operator-gated canonical reconfig
    // proposal intent (DevNet/TestNet only; MainNet refused at the
    // CLI gate). Disabled by default (the default `None` path is
    // bit-equivalent to pre-Run-096 behaviour).
    match derive_run_096_reconfig_proposal(config, args) {
        Ok(Some(rc)) => {
            consensus_cfg = consensus_cfg.with_reconfig_proposal(rc);
            eprintln!(
                "[binary] Run 096: armed canonical reconfig proposal intent \
                 (P2P) — target_epoch={} (single-shot; the next leader-step \
                 proposal will be PAYLOAD_KIND_RECONFIG).",
                rc.target_epoch
            );
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("[binary] FATAL: {}", e);
            std::process::exit(1);
        }
    }
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
    // Run 097: pass the canonical production `ConsensusStorage` handle
    // into the SIGUSR1 snapshot task so the operator-triggered snapshot
    // can attach the canonical committed epoch to `meta.json`.
    let snapshot_consensus_storage: Option<Arc<dyn qbind_node::storage::ConsensusStorage>> =
        consensus_storage
            .clone()
            .map(|s| s as Arc<dyn qbind_node::storage::ConsensusStorage>);
    let snapshot_handle = spawn_vm_v0_snapshot_signal_task(
        vm_v0_runtime,
        Arc::clone(&node_metrics),
        config.chain_id().as_u64(),
        snapshot_consensus_storage,
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
            // Run 098: pass the canonical production ConsensusStorage
            // handle so the SIGHUP trigger can read meta:current_epoch
            // per-trigger. See
            // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
            consensus_storage.clone(),
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
    // Run 098: optional canonical production `ConsensusStorage`
    // handle used for per-trigger epoch read. When present, the
    // trigger reads `meta:current_epoch` BEFORE each trigger and
    // builds a fresh `ActivationContext` with the canonical epoch.
    // See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
    consensus_storage: Option<Arc<qbind_node::storage::RocksDbConsensusStorage>>,
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

    // Run 114 — SIGHUP live reload ratification enforcement.
    //
    // Apply the Run 106 per-environment policy already used by the
    // reload-check (Run 069/106), peer-candidate-check (Run 077/107),
    // and process-start reload-apply (Run 073/112) binary paths:
    //
    //   * MainNet / TestNet : ratification gate INVOKED by default;
    //     the operator opt-in flag can neither enable nor disable it.
    //   * DevNet : gate invoked only when the operator opts in via
    //     `--p2p-trust-bundle-ratification-enforcement-enabled`.
    //
    // When `Invoke`, the controller is constructed with a populated
    // `LiveReloadRatificationConfig` so every SIGHUP trigger:
    //   * re-reads the sidecar JSON (operator may swap it between
    //     SIGHUPs without restarting the node);
    //   * runs the full Run 105/103
    //     `enforce_bundle_signing_key_ratification` pipeline
    //     (signature / chain_id / environment / authority-root
    //     binding / canonical genesis hash / candidate key match)
    //     BEFORE any snapshot / swap / eviction / commit;
    //   * surfaces every refusal as
    //     `LiveReloadOutcome::Invalid(_)` with no live trust mutation,
    //     no session eviction, and no sequence write.
    //
    // When `Skip` (DevNet without opt-in), the controller is
    // constructed with `ratification: None` so the pre-Run-114
    // SIGHUP path is preserved bit-for-bit. MainNet/TestNet never
    // reach this branch.
    //
    // If the gate decision is `Invoke` but the ratification context
    // cannot be built (missing genesis file, missing authority
    // block, missing/unparseable sidecar at construction time), the
    // SIGHUP handler is NOT installed and a fail-closed
    // operator-facing message is printed. The node keeps running on
    // the baseline trust bundle with no SIGHUP-driven reload
    // surface, mirroring the no-fallback discipline of every other
    // Run 105/106 gate.
    let gate_decision = qbind_node::pqc_ratification_policy::ratification_gate_decision(
        config.environment,
        args.p2p_trust_bundle_ratification_enforcement_enabled,
    );
    let ratification_cfg_opt: Option<qbind_node::pqc_live_trust_reload::LiveReloadRatificationConfig> =
        if gate_decision.should_invoke() {
            match build_run_105_reload_check_context(args, config) {
                Ok(ctx_data) => {
                    eprintln!(
                        "[run-114] SIGHUP live reload ratification gate INVOKED \
                         (policy={}, env={:?}). On every SIGHUP the ratification \
                         sidecar JSON is re-read and verified BEFORE any snapshot, \
                         swap, eviction, or sequence commit.",
                        gate_decision.label(),
                        config.environment
                    );
                    Some(qbind_node::pqc_live_trust_reload::LiveReloadRatificationConfig {
                        authority: ctx_data.authority,
                        expected_genesis_hash: ctx_data.canonical_hash,
                        expected_environment_policy: ctx_data.env_policy,
                        expected_chain_id_str: ctx_data.chain_id_str,
                        policy: ctx_data.policy,
                        ratification_sidecar_path: args
                            .p2p_trust_bundle_ratification
                            .clone(),
                    })
                }
                Err(reason) => {
                    eprintln!(
                        "[run-114] FATAL: SIGHUP live reload ratification gate INVOKED \
                         (policy={}, env={:?}) but ratification context could not be \
                         built: {}. SIGHUP trigger NOT installed; the node continues \
                         running on the baseline trust bundle. No live trust apply, \
                         no sequence write, no session eviction will occur via \
                         SIGHUP. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_114.md.",
                        gate_decision.label(),
                        config.environment,
                        reason,
                    );
                    return None;
                }
            }
        } else {
            eprintln!(
                "[run-114] SIGHUP live reload ratification gate SKIPPED \
                 (policy={}, env={:?}). This is NOT a passed ratification; it \
                 preserves pre-Run-114 DevNet behaviour for developer workflows. \
                 MainNet/TestNet always invoke the gate by default and never \
                 reach this branch.",
                gate_decision.label(),
                config.environment
            );
            None
        };

    // Run 121 — SIGHUP authority anti-rollback marker
    // accept-and-persist context.
    //
    // The marker preflight + post-commit persist are wired ONLY
    // when both:
    //   * the Run 114 ratification gate is `Invoke` (i.e.
    //     `ratification_cfg_opt.is_some()`) — without verified
    //     ratification material there is no `RatifiedBundleSigningKey`
    //     to derive a marker from;
    //   * a `--data-dir` is configured — without a data dir we have
    //     nowhere to load or persist the
    //     `<data_dir>/pqc_authority_state.json` marker file.
    //
    // MainNet/TestNet always satisfy both conditions (the
    // ratification gate is default-strict per Run 106 and
    // `--data-dir` is mandatory for the Run 055 sequence file).
    // DevNet without operator opt-in falls through with
    // `authority_marker = None` and SIGHUP behaviour is byte-
    // identical to a Run-120 build. See
    // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_121.md`.
    let authority_marker_cfg_opt: Option<
        qbind_node::pqc_live_trust_reload::LiveReloadAuthorityMarkerConfig,
    > = match (ratification_cfg_opt.as_ref(), config.data_dir.as_ref()) {
        (Some(_), Some(data_dir)) => {
            let marker_path =
                qbind_node::pqc_authority_state::authority_state_file_path(data_dir);
            eprintln!(
                "[run-121] SIGHUP live reload authority-marker gate INVOKED \
                 (policy={}, env={:?}). On every SIGHUP the on-disk authority \
                 marker at {} is compared against the candidate's verified \
                 ratification BEFORE any snapshot/swap/eviction/commit, and \
                 persisted AFTER the existing Run 070 commit_sequence boundary \
                 returns Ok.",
                gate_decision.label(),
                config.environment,
                marker_path.display(),
            );
            Some(
                qbind_node::pqc_live_trust_reload::LiveReloadAuthorityMarkerConfig {
                    marker_path,
                },
            )
        }
        (Some(_), None) => {
            eprintln!(
                "[run-121] SIGHUP live reload authority-marker gate SKIPPED \
                 (policy={}, env={:?}): no --data-dir configured. The Run 114 \
                 ratification gate is invoked but the marker file cannot be \
                 located. SIGHUP marker preflight + persist are NOT wired. \
                 MainNet/TestNet require --data-dir and never reach this branch.",
                gate_decision.label(),
                config.environment,
            );
            None
        }
        (None, _) => {
            eprintln!(
                "[run-121] SIGHUP live reload authority-marker gate SKIPPED \
                 (policy={}, env={:?}): the Run 114 ratification gate is also \
                 SKIPPED on this branch, so there is no verified ratification \
                 from which a marker could be derived. This is reachable only \
                 on DevNet without operator opt-in; MainNet/TestNet never reach \
                 this branch.",
                gate_decision.label(),
                config.environment,
            );
            None
        }
    };

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
        ratification: ratification_cfg_opt,
        authority_marker: authority_marker_cfg_opt,
        // Run 171 — hidden, disabled-by-default DevNet/TestNet-safe
        // governance-proof Required-policy selector. Default
        // `NotRequired` preserves Run 138 SIGHUP behaviour bit-for-
        // bit; under `--p2p-trust-bundle-governance-proof-required`
        // (or the equivalent env var) every SIGHUP-triggered
        // marker-decision preflight runs under
        // `RequiredForLifecycleSensitive`.
        governance_proof_policy:
            qbind_node::pqc_governance_proof_surface::governance_proof_policy_from_cli_or_env(
                args.p2p_trust_bundle_governance_proof_required,
            ),
        // Run 182 — capture the hidden Run 180 OnChainGovernance
        // fixture-allowed selector so the SIGHUP preflight production
        // call-site reachability hook can resolve the active
        // `OnChainGovernanceProofPolicy` (default `Disabled`).
        onchain_governance_fixture_allowed_selector:
            args.p2p_trust_bundle_onchain_governance_fixture_allowed,
        // Run 217 — arm the SIGHUP live-reload runtime config with the
        // resolved governance-execution policy from the hidden
        // `--p2p-trust-bundle-governance-execution-policy` CLI flag /
        // `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var
        // (Run 215 resolver). The selector was already validated
        // fail-closed at startup (`resolve_run_217_governance_execution_runtime_arming`);
        // re-resolving here is pure and yields the same policy. Default
        // `Disabled` preserves the pre-Run-217 SIGHUP flow bit-for-bit and
        // never enables MainNet peer-driven apply.
        governance_execution_runtime_arming:
            qbind_node::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeArmingConfig::from_cli_or_env(
                args.p2p_trust_bundle_governance_execution_policy.as_deref(),
            )
            .unwrap_or_default(),
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
                    // Run 098: clone the optional storage handle so it
                    // can be moved into the blocking task. The per-trigger
                    // canonical epoch read happens inside the blocking
                    // closure. See
                    // docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md.
                    let storage_for_trigger = consensus_storage.clone();
                    let outcome = tokio::task::spawn_blocking(move || {
                        // Run 098: read canonical epoch before trigger.
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let activation_epoch_source = match
                            qbind_node::pqc_trust_activation_epoch::activation_epoch_source_from_storage(
                                storage_for_trigger.as_ref(),
                            ) {
                                Ok(src) => src,
                                Err(e) => {
                                    eprintln!(
                                        "[binary] Run 098: WARNING: failed to read canonical \
                                         meta:current_epoch for SIGHUP trigger: {}. Proceeding \
                                         with current_epoch=None (fail-closed if candidate \
                                         declares activation_epoch).",
                                        e
                                    );
                                    qbind_node::pqc_trust_activation_epoch::ActivationEpochSource::UnavailableNoCommittedEpoch
                                }
                            };
                        let activation_ctx = qbind_node::pqc_trust_activation::ActivationContext {
                            current_height: Some(0),
                            current_epoch: activation_epoch_source.as_option(),
                        };
                        controller_for_trigger.try_trigger_with_activation(now_secs, activation_ctx)
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
    consensus_storage: Option<Arc<dyn qbind_node::storage::ConsensusStorage>>,
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
                    // Run 097: probe canonical committed epoch from the
                    // production `ConsensusStorage` handle (Run 093/094)
                    // and attach it to the snapshot meta. Absent /
                    // probe-error → epoch=None (explicit absence; NOT
                    // coerced to 0).
                    let snapshot_epoch: Option<u64> = match consensus_storage.as_ref() {
                        Some(storage) => match storage.get_current_epoch() {
                            Ok(Some(e)) => {
                                eprintln!(
                                    "[snapshot] Run 097 SIGUSR1 epoch source: ConsensusStorage::get_current_epoch -> Some({})",
                                    e
                                );
                                Some(e)
                            }
                            Ok(None) => {
                                eprintln!(
                                    "[snapshot] Run 097 SIGUSR1 epoch source: ConsensusStorage::get_current_epoch -> None"
                                );
                                None
                            }
                            Err(e) => {
                                eprintln!(
                                    "[snapshot] Run 097 SIGUSR1 epoch source: probe error: {} — epoch=None",
                                    e
                                );
                                None
                            }
                        },
                        None => {
                            eprintln!(
                                "[snapshot] Run 097 SIGUSR1 epoch source: no ConsensusStorage handle wired — epoch=None"
                            );
                            None
                        }
                    };
                    let result = tokio::task::spawn_blocking(move || {
                        runtime.create_snapshot(
                            SnapshotAnchor { height, block_hash },
                            chain_id,
                            snapshot_epoch,
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
    _unsupported_consensus_storage: Option<Arc<dyn qbind_node::storage::ConsensusStorage>>,
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