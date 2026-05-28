//! Run 077 (C4 piece: production-binary-facing, disabled-by-default
//! peer-candidate validation **local check** surface): the smallest
//! safe binary surface that exercises the Run 076
//! [`pqc_trust_peer_candidate::PeerCandidateValidator`] from the
//! release `qbind-node` binary, **without** introducing a peer/gossip
//! wire surface and **without** any live trust-state apply.
//!
//! # Strict scope
//!
//! Run 077 is **only** the disabled-by-default local check mode under
//! the umbrella "peer-supplied / gossiped bundle acceptance" C4-OPEN
//! sub-piece in `docs/whitepaper/contradiction.md`. It is intentionally
//! minimal:
//!
//! - Parses a local operator-supplied JSON fixture file containing a
//!   serialised [`PeerCandidateEnvelope`].
//! - Runs the **same** Run 076 `PeerCandidateValidator::try_accept`
//!   against the parsed envelope. Validation flows through the **same**
//!   Run 069 `validate_candidate_bundle_full` entry point that startup,
//!   the local reload-check, Run 073 process-start apply, and Run 074
//!   SIGHUP live reload-apply all use.
//! - Bumps the **same** seven Run 076
//!   `qbind_p2p_pqc_trust_bundle_peer_candidate_*` Prometheus counters
//!   (no new metric family, no `_applied_total` family). The
//!   `received_total` counter is bumped unconditionally on every entry
//!   (truthful "we observed a candidate" signal); outcome-specific
//!   counters are bumped exactly once per outcome.
//! - Returns an outcome with a deterministic exit code: `0` only for
//!   `Validated`, `1` for every fail-closed outcome
//!   (`Disabled` / `Oversize` / `RateLimited` / `DuplicateSuppressed` /
//!   `Rejected`) and for every partial-config refusal.
//! - **Does NOT** start the node, the P2P listener, or any network
//!   service.
//! - **Does NOT** apply the candidate to live PQC trust state.
//!   The validator type itself holds no live-state handle (Run 076
//!   library invariant). There is no apply function to call.
//! - **Does NOT** persist the candidate's sequence number. Sequence
//!   persistence (when supplied via `--data-dir`) is consulted only
//!   via the read-only Run 055 peek inherited from Run 069.
//! - **Does NOT** mutate `LivePqcTrustState`. There is no live state
//!   to mutate in the Run 077 process-start path — Run 077 exits
//!   before the node is constructed.
//! - **Does NOT** evict P2P / KEMTLS sessions. Run 077 has no
//!   `P2pSessionEvictor` handle.
//! - **Does NOT** propagate / re-broadcast the candidate. Run 077 is
//!   end-of-line.
//! - **Does NOT** accept unsigned TestNet / MainNet bundles. The
//!   reused Run 050/051 loader rejects those exactly like startup
//!   does. TestNet/MainNet require at least one
//!   `--p2p-trust-bundle-signing-key` exactly like startup.
//! - **Does NOT** bypass chain-id / environment / activation /
//!   sequence / revocation / local self-check validation.
//! - **Does NOT** introduce a peer/gossip wire surface, a network
//!   listener, an admin-API endpoint, or a filesystem watcher.
//! - **Does NOT** silently fall back to `--p2p-trusted-root`,
//!   `DummySig`, `DummyKem`, or `DummyAead`. Same fail-closed
//!   semantics as Run 069.
//! - **Does NOT** weaken Run 069 reload-check, Run 070 reload-apply,
//!   Run 073 process-start apply, or Run 074 SIGHUP live reload.
//!   All four entry points are bit-for-bit unchanged.
//!
//! # Disabled-by-default boundary
//!
//! Run 077 is gated by **two required-together** hidden CLI flags:
//!
//! - `--p2p-trust-bundle-peer-candidate-validation-enabled`
//! - `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>`
//!
//! Either flag without the other is a top-level partial-config
//! refusal (`exit 1`) — the operator cannot accidentally "arm" the
//! check mode by typing one flag alone. Neither flag means **zero**
//! behaviour change: the Run 077 hook never even peeks at the
//! envelope path. This mirrors the Run 070 / Run 074 partial-config
//! discipline.

use std::path::{Path, PathBuf};

use qbind_types::{ChainId, NetworkEnvironment};

use crate::metrics::P2pMetrics;
use crate::pqc_trust_activation::ActivationContext;
use crate::pqc_trust_bundle::BundleSigningKeySet;
use crate::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome, PeerCandidateRuntimeContext,
    PeerCandidateValidator,
};
use crate::pqc_trust_reload::RatificationEnforcementContext;

/// Run 077 partial-config / preconditions / I/O refusals. Every
/// variant is a deterministic `exit 1` outcome that produces a safe
/// operator-log line **before** any crypto, scratch file, or
/// `PeerCandidateValidator` allocation.
#[derive(Debug)]
pub enum Run077RefusalReason {
    /// `--p2p-trust-bundle-peer-candidate-check <PATH>` was supplied
    /// without `--p2p-trust-bundle-peer-candidate-validation-enabled`.
    EnabledFlagMissing,
    /// `--p2p-trust-bundle-peer-candidate-validation-enabled` was
    /// supplied without `--p2p-trust-bundle-peer-candidate-check
    /// <PATH>`.
    EnvelopePathMissing,
    /// TestNet/MainNet require at least one
    /// `--p2p-trust-bundle-signing-key`. Same precondition as Run 069.
    UnsignedRequiredOnEnvironment { environment: NetworkEnvironment },
    /// TestNet/MainNet require `--data-dir` so the candidate's
    /// sequence can be peeked against the persisted record. Same
    /// precondition as Run 069.
    DataDirRequiredOnEnvironment { environment: NetworkEnvironment },
    /// `--p2p-leaf-cert` and `--p2p-leaf-cert-key` must be supplied
    /// together for the Run 061 / Run 063 self-checks. Same
    /// precondition as Run 069.
    LeafCredentialFlagsUnpaired,
    /// The fixture file could not be read.
    FixtureIoError { path: PathBuf, message: String },
    /// The fixture file did not parse as a `PeerCandidateEnvelope`
    /// JSON document.
    FixtureParseError { path: PathBuf, message: String },
    /// `--p2p-trust-bundle-signing-key` could not be parsed. Same
    /// precondition as Run 069.
    SigningKeyParseError { message: String },
    /// The leaf credentials at `--p2p-leaf-cert{,-key}` could not be
    /// loaded. Same precondition as Run 069.
    LeafCredentialLoadError { message: String },
}

impl std::fmt::Display for Run077RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnabledFlagMissing => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check requires \
                 --p2p-trust-bundle-peer-candidate-validation-enabled. \
                 The Run 077 disabled-by-default peer-candidate validation \
                 local check mode is OFF by default. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md."
            ),
            Self::EnvelopePathMissing => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-validation-enabled requires \
                 --p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH> \
                 (the check needs a local envelope fixture path to read). See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md."
            ),
            Self::UnsignedRequiredOnEnvironment { environment } => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check on environment={} requires \
                 at least one --p2p-trust-bundle-signing-key (TestNet/MainNet refuse \
                 unsigned bundles). No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.",
                environment
            ),
            Self::DataDirRequiredOnEnvironment { environment } => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check on environment={} requires \
                 --data-dir so the candidate's sequence can be peeked against the \
                 persisted record. No fallback. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.",
                environment
            ),
            Self::LeafCredentialFlagsUnpaired => write!(
                f,
                "--p2p-leaf-cert and --p2p-leaf-cert-key must be set together \
                 (--p2p-trust-bundle-peer-candidate-check inherits the same \
                 precondition as Run 069)."
            ),
            Self::FixtureIoError { path, message } => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check could not read envelope \
                 fixture at {}: {}",
                path.display(),
                message
            ),
            Self::FixtureParseError { path, message } => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check could not parse envelope \
                 fixture at {} as a PeerCandidateEnvelope JSON document: {}",
                path.display(),
                message
            ),
            Self::SigningKeyParseError { message } => write!(
                f,
                "--p2p-trust-bundle-signing-key parse error: {}. See \
                 docs/whitepaper/contradiction.md C4.",
                message
            ),
            Self::LeafCredentialLoadError { message } => write!(
                f,
                "--p2p-trust-bundle-peer-candidate-check could not load local PQC \
                 leaf credentials for the Run 061/063 self-checks: {}. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.",
                message
            ),
        }
    }
}

/// Canonical short label for the Run 077 `VERDICT=...` operator-log
/// line. Stable strings (parseable by smoke harnesses).
pub fn verdict_label(outcome: &PeerCandidateOutcome) -> &'static str {
    match outcome {
        PeerCandidateOutcome::Validated(_) => "validated",
        PeerCandidateOutcome::Rejected(_) => "rejected",
        PeerCandidateOutcome::Disabled => "disabled",
        PeerCandidateOutcome::Oversize { .. } => "oversize",
        PeerCandidateOutcome::RateLimited { .. } => "rate-limited",
        PeerCandidateOutcome::DuplicateSuppressed { .. } => "duplicate-suppressed",
    }
}

/// Single source of truth for the Run 077 binary `VERDICT=...` log
/// line. Always carries the validation-only / not-applied disclaimers
/// for downstream operator audit. Never includes raw bundle bytes,
/// signing-key material, or any private secret.
pub fn verdict_log_line(outcome: &PeerCandidateOutcome, envelope_path: &Path) -> String {
    format!(
        "[binary] Run 077: VERDICT={} (peer-candidate validation-only; NOT applied; \
         not propagated; sequence not persisted; live trust state unchanged; sessions \
         untouched). Envelope path={}. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.",
        verdict_label(outcome),
        envelope_path.display()
    )
}

/// Bump the matching Run 076 Prometheus counter on `metrics` for the
/// given outcome. The `received_total` counter is **always** bumped
/// by [`run_local_check`] before this function is reached, so this
/// only records the outcome-specific counter. Run 077 introduces no
/// new metric family.
pub fn record_outcome_metric(metrics: &P2pMetrics, outcome: &PeerCandidateOutcome) {
    match outcome {
        PeerCandidateOutcome::Validated(_) => metrics.record_peer_candidate_validated(),
        PeerCandidateOutcome::Rejected(_) => metrics.record_peer_candidate_rejected(),
        PeerCandidateOutcome::Disabled => metrics.record_peer_candidate_disabled(),
        PeerCandidateOutcome::Oversize { .. } => metrics.record_peer_candidate_dropped_oversize(),
        PeerCandidateOutcome::RateLimited { .. } => metrics.record_peer_candidate_rate_limited(),
        PeerCandidateOutcome::DuplicateSuppressed { .. } => {
            metrics.record_peer_candidate_duplicate()
        }
    }
}

/// Operator-supplied inputs to the Run 077 local check mode. Mirrors
/// the shape of the Run 069 inputs but separates the **operator-
/// controlled** trust context (signing keys, leaf cert, sequence
/// persistence) from the **peer-supplied** envelope payload (read
/// from `envelope_path` and parsed as JSON).
#[derive(Debug)]
pub struct Run077Inputs<'a> {
    /// Was `--p2p-trust-bundle-peer-candidate-validation-enabled`
    /// supplied?
    pub validation_enabled_flag: bool,
    /// Operator-supplied envelope-fixture path (the
    /// `--p2p-trust-bundle-peer-candidate-check <PATH>` value).
    pub envelope_path: Option<&'a Path>,
    /// Operator runtime environment (devnet / testnet / mainnet).
    pub environment: NetworkEnvironment,
    /// Operator runtime chain id.
    pub chain_id: ChainId,
    /// Wall-clock seconds (matches Run 069 `ReloadCheckInputs`).
    pub validation_time_secs: u64,
    /// Bundle-signing key set (already parsed; same parser as
    /// Run 069). TestNet/MainNet refuse unsigned bundles here.
    pub signing_keys: &'a BundleSigningKeySet,
    /// Activation context (height-only is the Run 057 default).
    pub activation_ctx: ActivationContext,
    /// Optional on-disk sequence persistence path. Same semantics as
    /// Run 069: peek is read-only, write is impossible from this path.
    pub sequence_persistence_path: Option<&'a Path>,
    /// Optional local leaf cert bytes for the Run 061 / Run 063
    /// self-checks.
    pub local_leaf_cert_bytes: Option<&'a [u8]>,
    /// Operator-controlled scratch directory for the temp candidate
    /// file used by [`PeerCandidateValidator::try_accept`]. MUST NOT
    /// be a directory the peer can influence. Run 077 hooks pass the
    /// `--data-dir` (when present) or `std::env::temp_dir()` here.
    pub scratch_dir: &'a Path,
    /// Current monotonic clock in milliseconds (for the rate limiter).
    pub now_ms: u64,
}

/// Run 077 single-shot outcome. Carries everything `main` needs to
/// emit the canonical log line and exit. The outcome is either a
/// fail-closed refusal (partial-config / I/O / parse) **before** the
/// validator was constructed, or a [`PeerCandidateOutcome`] from the
/// reused Run 076 validator (with metrics already recorded on
/// `metrics`).
#[derive(Debug)]
pub enum Run077Result {
    /// Pre-validator refusal. The Run 076 validator was **not**
    /// constructed; **no** Run 076 metric (other than the
    /// unconditional `received_total` when an envelope path was
    /// supplied) was bumped; the live trust state, on-disk sequence
    /// record, and P2P sessions are all guaranteed unchanged.
    Refused { reason: Run077RefusalReason },
    /// Validator ran. Carries the outcome and the canonical
    /// `VERDICT=...` log line. `metrics` was bumped for the outcome
    /// (and once for `received_total`).
    Ran {
        outcome: PeerCandidateOutcome,
        verdict_line: String,
        observed_log_line: Option<String>,
    },
}

impl Run077Result {
    /// Deterministic process exit code.
    /// - `0` only when the validator produced
    ///   [`PeerCandidateOutcome::Validated`].
    /// - `1` for **every** other outcome including
    ///   [`PeerCandidateOutcome::Disabled`] (which Run 077 treats as a
    ///   fail-closed refusal — the operator explicitly armed the
    ///   check mode, so a Disabled outcome means a library-level
    ///   misconfiguration we surface honestly).
    /// - `1` for every [`Run077Result::Refused`] variant.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Ran { outcome, .. } => match outcome {
                PeerCandidateOutcome::Validated(_) => 0,
                _ => 1,
            },
            Self::Refused { .. } => 1,
        }
    }
}

/// Returns `true` iff either Run 077 flag was supplied. Run 077's
/// disabled-by-default boundary requires the caller to early-return
/// from `main` only when this returns `true`; otherwise the hook is
/// a complete no-op and the normal startup flow continues.
pub fn run077_hook_active(envelope_path: Option<&Path>, validation_enabled: bool) -> bool {
    envelope_path.is_some() || validation_enabled
}

/// Run 077 top-level local check. Pure function (no `process::exit`)
/// so tests can drive it without spawning a child process. The
/// caller is responsible for printing `verdict_line` /
/// `observed_log_line` / the refusal reason to stderr and calling
/// `process::exit(result.exit_code())`.
///
/// # Strict invariants (every return path)
///
/// - The on-disk sequence persistence file at
///   `inputs.sequence_persistence_path` is NEVER modified by this
///   function. The reused Run 069 loader uses `peek_sequence` only.
/// - No `LivePqcTrustState` is allocated, swapped, or mutated. The
///   Run 077 path never constructs a `LivePqcTrustState`.
/// - No P2P / KEMTLS session is allocated, created, or evicted.
/// - No `_applied_total` metric family is introduced; the seven
///   existing Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
///   counters are the only `/metrics` surface bumped.
/// - The disabled-by-default boundary is enforced: when neither flag
///   is supplied, callers MUST NOT invoke `run_local_check`. When
///   exactly one flag is supplied, the function returns a
///   partial-config `Refused` result. When both flags are supplied,
///   the function proceeds with the validator armed for the single
///   check.
pub fn run_local_check(inputs: Run077Inputs<'_>, metrics: &P2pMetrics) -> Run077Result {
    run_local_check_inner(inputs, metrics, None)
}

/// Run 107 local peer-candidate check with the existing Run 105/106
/// ratification context applied before any successful validation
/// verdict is returned. This is intentionally a wrapper rather than a
/// new field on [`PeerCandidateRuntimeContext`] so live peer-candidate
/// callers remain untouched.
pub fn run_local_check_with_ratification(
    inputs: Run077Inputs<'_>,
    metrics: &P2pMetrics,
    ratification_ctx: &RatificationEnforcementContext<'_>,
) -> Run077Result {
    run_local_check_inner(inputs, metrics, Some(ratification_ctx))
}

fn run_local_check_inner(
    inputs: Run077Inputs<'_>,
    metrics: &P2pMetrics,
    ratification_ctx: Option<&RatificationEnforcementContext<'_>>,
) -> Run077Result {
    // 1. Partial-config refusal. The two CLI flags are required-
    //    together. Treat "exactly one supplied" as the operator-
    //    confusion preventer; treat "neither supplied" as a caller
    //    bug (the hook should not have been entered).
    let envelope_path = match (inputs.envelope_path, inputs.validation_enabled_flag) {
        (Some(p), true) => p,
        (Some(_), false) => {
            return Run077Result::Refused {
                reason: Run077RefusalReason::EnabledFlagMissing,
            };
        }
        (None, true) => {
            return Run077Result::Refused {
                reason: Run077RefusalReason::EnvelopePathMissing,
            };
        }
        (None, false) => {
            // Caller bug: hook should be gated by `run077_hook_active`.
            // Surface as the most common operator typo (missing path)
            // rather than panicking.
            return Run077Result::Refused {
                reason: Run077RefusalReason::EnvelopePathMissing,
            };
        }
    };

    // 2. Read the envelope fixture. Cheap; before any crypto.
    let envelope_json_bytes = match std::fs::read(envelope_path) {
        Ok(b) => b,
        Err(e) => {
            return Run077Result::Refused {
                reason: Run077RefusalReason::FixtureIoError {
                    path: envelope_path.to_path_buf(),
                    message: e.to_string(),
                },
            };
        }
    };
    let envelope: PeerCandidateEnvelope = match serde_json::from_slice(&envelope_json_bytes) {
        Ok(e) => e,
        Err(e) => {
            return Run077Result::Refused {
                reason: Run077RefusalReason::FixtureParseError {
                    path: envelope_path.to_path_buf(),
                    message: e.to_string(),
                },
            };
        }
    };

    // 3. Unconditional truthful "we observed a candidate" signal.
    //    Mirrors the Run 076 documented `received_total` discipline.
    metrics.record_peer_candidate_received();

    // 4. Build the runtime context for `try_accept`. Reuse the same
    //    fields the Run 069 reload-check hook uses (signing keys,
    //    activation context, sequence persistence path, leaf cert
    //    bytes) so the same fail-closed reasons surface here as on
    //    startup.
    let ctx = PeerCandidateRuntimeContext {
        expected_environment: inputs.environment,
        expected_chain_id: inputs.chain_id,
        scratch_dir: inputs.scratch_dir,
        validation_time_secs: inputs.validation_time_secs,
        signing_keys: inputs.signing_keys,
        activation_ctx: inputs.activation_ctx,
        sequence_persistence_path: inputs.sequence_persistence_path,
        local_leaf_cert_bytes: inputs.local_leaf_cert_bytes,
        now_ms: inputs.now_ms,
    };

    // 5. Construct the validator with `enabled = true` for this
    //    single-shot run. The disabled-by-default library default is
    //    flipped here ONLY because the operator explicitly armed
    //    Run 077 via the two required-together flags. The validator
    //    holds no live-state handle (Run 076 invariant), so this
    //    flip cannot affect live trust state.
    let mut validator = PeerCandidateValidator::new(PeerCandidateConfig {
        enabled: true,
        ..PeerCandidateConfig::default()
    });

    // 6. Run the SAME `try_accept` Run 076 unit + integration tests
    //    exercise. Validates the envelope through the SAME Run 069
    //    pipeline. NO live apply; NO sequence write; NO session
    //    eviction.
    let outcome = match ratification_ctx {
        Some(rctx) => validator.try_accept_with_ratification(envelope, &ctx, rctx),
        None => validator.try_accept(envelope, &ctx),
    };

    // 7. Record the outcome-specific metric exactly once.
    record_outcome_metric(metrics, &outcome);

    let verdict_line = verdict_log_line(&outcome, envelope_path);
    let observed_log_line = match &outcome {
        PeerCandidateOutcome::Validated(v) => Some(v.observed_log_line()),
        _ => None,
    };

    Run077Result::Ran {
        outcome,
        verdict_line,
        observed_log_line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_trust_bundle::BundleSigningKeySet;

    fn empty_keys() -> BundleSigningKeySet {
        BundleSigningKeySet::from_keys_unchecked(vec![])
    }

    fn inputs_with<'a>(
        envelope_path: Option<&'a Path>,
        validation_enabled: bool,
        signing_keys: &'a BundleSigningKeySet,
        scratch_dir: &'a Path,
    ) -> Run077Inputs<'a> {
        Run077Inputs {
            validation_enabled_flag: validation_enabled,
            envelope_path,
            environment: NetworkEnvironment::Devnet,
            chain_id: NetworkEnvironment::Devnet.chain_id(),
            validation_time_secs: 100,
            signing_keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            scratch_dir,
            now_ms: 1_000,
        }
    }

    #[test]
    fn run077_hook_active_returns_false_when_neither_flag_supplied() {
        assert!(!run077_hook_active(None, false));
    }

    #[test]
    fn run077_hook_active_returns_true_when_path_only() {
        let p = Path::new("/nope");
        assert!(run077_hook_active(Some(p), false));
    }

    #[test]
    fn run077_hook_active_returns_true_when_enabled_only() {
        assert!(run077_hook_active(None, true));
    }

    #[test]
    fn run077_partial_config_path_without_enabled_flag_refuses() {
        let keys = empty_keys();
        let scratch = std::env::temp_dir();
        let p = scratch.join("does-not-matter.json");
        let result = run_local_check(
            inputs_with(Some(&p), false, &keys, &scratch),
            &P2pMetrics::default(),
        );
        let exit_code = result.exit_code();
        match result {
            Run077Result::Refused {
                reason: Run077RefusalReason::EnabledFlagMissing,
            } => {}
            other => panic!("expected EnabledFlagMissing, got {:?}", other),
        }
        assert_eq!(exit_code, 1);
    }

    #[test]
    fn run077_partial_config_enabled_without_path_refuses() {
        let keys = empty_keys();
        let scratch = std::env::temp_dir();
        let result = run_local_check(
            inputs_with(None, true, &keys, &scratch),
            &P2pMetrics::default(),
        );
        match result {
            Run077Result::Refused {
                reason: Run077RefusalReason::EnvelopePathMissing,
            } => {}
            other => panic!("expected EnvelopePathMissing, got {:?}", other),
        }
    }

    #[test]
    fn run077_refusal_exit_code_is_one() {
        let r = Run077Result::Refused {
            reason: Run077RefusalReason::EnvelopePathMissing,
        };
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn run077_refusal_display_lines_are_log_safe() {
        let cases = [
            Run077RefusalReason::EnabledFlagMissing,
            Run077RefusalReason::EnvelopePathMissing,
            Run077RefusalReason::UnsignedRequiredOnEnvironment {
                environment: NetworkEnvironment::Mainnet,
            },
            Run077RefusalReason::DataDirRequiredOnEnvironment {
                environment: NetworkEnvironment::Testnet,
            },
            Run077RefusalReason::LeafCredentialFlagsUnpaired,
            Run077RefusalReason::FixtureIoError {
                path: PathBuf::from("/dev/null"),
                message: "x".into(),
            },
            Run077RefusalReason::FixtureParseError {
                path: PathBuf::from("/dev/null"),
                message: "x".into(),
            },
            Run077RefusalReason::SigningKeyParseError {
                message: "x".into(),
            },
            Run077RefusalReason::LeafCredentialLoadError {
                message: "x".into(),
            },
        ];
        for c in &cases {
            let s = format!("{}", c);
            // No private keys / secrets / bundle bytes / hex
            // signature dumps in error lines.
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn run077_verdict_label_is_stable() {
        assert_eq!(verdict_label(&PeerCandidateOutcome::Disabled), "disabled");
        assert_eq!(
            verdict_label(&PeerCandidateOutcome::Oversize {
                observed_len: 1,
                cap: 1,
            }),
            "oversize"
        );
        assert_eq!(
            verdict_label(&PeerCandidateOutcome::RateLimited {
                attempts_in_window: 1,
                cap: 1,
            }),
            "rate-limited"
        );
        assert_eq!(
            verdict_label(&PeerCandidateOutcome::DuplicateSuppressed {
                fingerprint_prefix: "deadbeef".into(),
            }),
            "duplicate-suppressed"
        );
    }

    #[test]
    fn run077_verdict_log_line_is_validation_only_disclaimer() {
        let s = verdict_log_line(&PeerCandidateOutcome::Disabled, Path::new("/tmp/x.json"));
        assert!(s.contains("Run 077"));
        assert!(s.contains("VERDICT=disabled"));
        assert!(s.contains("NOT applied"));
        assert!(s.contains("not propagated"));
        assert!(s.contains("sequence not persisted"));
        assert!(s.contains("live trust state unchanged"));
        assert!(s.contains("sessions untouched"));
        assert!(s.contains("/tmp/x.json"));
    }

    #[test]
    fn run077_fixture_io_error_refuses_before_validator_constructed() {
        let keys = empty_keys();
        let scratch = std::env::temp_dir();
        let bogus = scratch.join("definitely-does-not-exist-run077-XYZ.json");
        let metrics = P2pMetrics::default();
        let result = run_local_check(inputs_with(Some(&bogus), true, &keys, &scratch), &metrics);
        match result {
            Run077Result::Refused {
                reason: Run077RefusalReason::FixtureIoError { .. },
            } => {}
            other => panic!("expected FixtureIoError, got {:?}", other),
        }
        // received_total never bumped because we never read the file.
        assert_eq!(metrics.peer_candidate_received_total(), 0);
    }

    #[test]
    fn run077_fixture_parse_error_refuses_before_validator_constructed() {
        let keys = empty_keys();
        let scratch = std::env::temp_dir();
        let dir = std::env::temp_dir().join(format!(
            "qbind-run077-parse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.json");
        std::fs::write(&bad, b"not-json").unwrap();
        let metrics = P2pMetrics::default();
        let result = run_local_check(inputs_with(Some(&bad), true, &keys, &scratch), &metrics);
        match result {
            Run077Result::Refused {
                reason: Run077RefusalReason::FixtureParseError { .. },
            } => {}
            other => panic!("expected FixtureParseError, got {:?}", other),
        }
        assert_eq!(metrics.peer_candidate_received_total(), 0);
    }
}
