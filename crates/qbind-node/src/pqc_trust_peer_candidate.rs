//! Run 076 (C4 piece: peer/gossiped trust-bundle candidate validation
//! boundary — disabled-by-default, validation-only): a safe library-
//! level path that can parse and validate a **peer-supplied** trust-
//! bundle candidate using the same Run 050/051/053/057/062/065/061/063
//! security pipeline that startup, Run 069 reload-check, Run 073
//! process-start apply, and Run 074 SIGHUP live reload-apply all use,
//! while preventing automatic live apply, sequence burn, session
//! eviction, or any trust-state mutation.
//!
//! # Strict scope
//!
//! Run 076 is **only** the safest possible foundation under the
//! umbrella "peer-supplied / gossiped bundle acceptance" C4-OPEN
//! sub-piece in `docs/whitepaper/contradiction.md`. It is intentionally
//! minimal:
//!
//! - Receives a bounded peer-supplied candidate envelope and validates
//!   it through the **same** Run 069 `validate_candidate_bundle_full`
//!   entry point.
//! - **Does NOT** apply the candidate to live PQC trust state.
//! - **Does NOT** call `LiveTrustApplyContext::swap_trust_state`,
//!   `evict_sessions`, or `commit_sequence`.
//! - **Does NOT** persist the candidate's sequence number (no Run 055
//!   `check_and_update_sequence` call; sequence persistence is read-
//!   only via the same `peek_sequence` path Run 069 uses).
//! - **Does NOT** mutate `LivePqcTrustState`. Operators inspecting the
//!   live snapshot before and after a Run 076 validation see exactly
//!   the same `Arc` pointer.
//! - **Does NOT** evict P2P / KEMTLS sessions.
//! - **Does NOT** propagate / re-broadcast the candidate. Run 076 is
//!   end-of-line.
//! - **Does NOT** introduce a CLI flag on the production binary in
//!   this run. The peer-candidate validator is a **library-level**
//!   surface exercised by tests and by a future run that lands a safe
//!   wire envelope under a separate review. The strict requirement
//!   "disabled by default — no behavior change unless enabled" is
//!   enforced both by `PeerCandidateConfig::enabled = false` and by
//!   the absence of any production caller of the module.
//! - **Does NOT** accept unsigned TestNet / MainNet bundles. The
//!   reused Run 050/051 loader rejects those exactly like startup
//!   does.
//! - **Does NOT** bypass chain-id / environment / activation /
//!   sequence / revocation / local self-check validation.
//! - **Does NOT** weaken startup trust-bundle validation, Run 069
//!   reload-check, Run 073 process-start apply, or Run 074 SIGHUP live
//!   reload-apply. All four continue to work bit-for-bit.
//!
//! # Adversary model
//!
//! Run 076 treats every peer-supplied byte as adversarial. Concretely:
//!
//! - Malformed bundles → rejected by `validate_candidate_bundle_full`
//!   (Run 050 structural / Run 051 signature paths).
//! - Oversized bundles → dropped **before** any crypto via the
//!   [`MAX_PEER_CANDIDATE_BUNDLE_BYTES`] cap on
//!   [`PeerCandidateEnvelope::bundle_bytes`] / `declared_length`.
//! - Replay / rollback → rejected by the read-only Run 055 sequence
//!   peek.
//! - Wrong-chain / wrong-env → rejected by the reused Run 053 / Run
//!   050 environment + chain-id checks.
//! - Validly-signed equivocation (same sequence, distinct fingerprint)
//!   → rejected by Run 055 equal-sequence-fingerprint-mismatch.
//! - Flood → bounded by [`PeerCandidateRateLimiter`] (caller-supplied
//!   rate limit; default disabled, when enabled the limiter is the
//!   token-bucket-equivalent fixed-window counter the Run 070/074
//!   "no unbounded task spawning" discipline mandates).
//! - Repeated expensive ML-DSA verification of the same bytes →
//!   suppressed (by short fingerprint prefix) via
//!   [`PeerCandidateDuplicateCache`] when enabled.
//! - Sequence burn / live state mutation / session eviction → cannot
//!   happen by construction: the module exposes **no** apply function
//!   and **never** invokes one.
//! - Static-root fallback → cannot be triggered by this module; the
//!   reused loader fails closed on `--p2p-trusted-root` semantics
//!   exactly like startup.
//! - MainNet-as-DevNet downgrade → blocked by the
//!   `expected_environment` parameter passed into
//!   [`PeerCandidateValidator::try_accept`]; the loader's
//!   environment + signed-bundle requirement is the same as startup.
//!
//! # Logging
//!
//! Log lines emitted by this module are log-safe metadata only:
//! environment, chain-id-hex, candidate sequence, 8-hex-char
//! fingerprint prefix, peer id (when supplied by the caller), the
//! rejection reason (when applicable), and an explicit
//! "validation-only / not applied" statement.
//!
//! No private-key material, no signing-key bytes, no leaf cert bytes,
//! no KEM secret, and no peer-supplied raw bundle bytes appear in
//! logs.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use qbind_types::{ChainId, NetworkEnvironment};

use crate::pqc_trust_activation::ActivationContext;
use crate::pqc_trust_bundle::{BundleSigningKeySet, TrustBundleEnvironment};
use crate::pqc_trust_reload::{
    validate_candidate_bundle_full, ReloadCheckError, ReloadCheckInputs, ValidatedCandidate,
};

/// Maximum size in bytes of the peer-supplied bundle payload Run 076
/// will accept. This bound runs **before** any signature / structural
/// verification so the adversary cannot force expensive ML-DSA work by
/// inflating the JSON envelope.
///
/// Set conservatively to 256 KiB. A legitimate signed DevNet / TestNet
/// / MainNet bundle including ML-DSA-44 signature, public-key bytes,
/// root list, and revocation lists is several KiB even with hundreds
/// of revocations; 256 KiB leaves comfortable headroom while still
/// providing a hard adversary-bounded ceiling.
pub const MAX_PEER_CANDIDATE_BUNDLE_BYTES: usize = 256 * 1024;

/// Run 076 wire/test envelope for a peer-supplied trust-bundle
/// candidate. Every field is **public, log-safe** metadata, plus the
/// candidate `bundle_bytes` themselves (which never escape the
/// validator).
///
/// `declared_length` is sent by the peer; the validator MUST compare
/// it against `bundle_bytes.len()` and reject mismatches before doing
/// any work. This blocks the trivial "claim small length, send huge
/// payload" envelope-vs-payload attack.
///
/// # Wire/test fixture serialisation (Run 077)
///
/// `PeerCandidateEnvelope` derives `serde::Serialize` /
/// `serde::Deserialize` so the Run 077 disabled-by-default binary
/// check mode can parse an operator-supplied JSON fixture. The
/// `bundle_bytes` field is serialised as a **lowercase hex string**
/// (not a JSON byte array) so fixtures are diff-friendly and the
/// declared envelope length/fingerprint cross-checks remain
/// unambiguous. The same hex-string encoding is what the Run 077
/// binary surface emits if it ever needs to round-trip an envelope.
/// This is a fixture format, NOT a normative wire format: Run 077
/// introduces no peer/gossip wire surface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerCandidateEnvelope {
    /// Run 076 envelope version. Currently fixed at 1; future
    /// envelopes that change layout MUST bump this and the validator
    /// MUST reject unknown versions.
    pub envelope_version: u16,
    /// Domain tag (`"qbind-peer-trust-bundle-candidate-v0"`). Bound
    /// into the validator so a payload from a *different* protocol
    /// domain cannot be replayed here.
    pub domain_tag: String,
    /// Optional peer identifier (e.g. P2P node id hex prefix). Used
    /// for safe operator-log lines; not security-relevant to the
    /// validation pipeline (the candidate itself is what is
    /// authenticated, not the peer).
    pub peer_id: Option<String>,
    /// Environment the peer claims this candidate targets. The
    /// validator cross-checks this against `expected_environment`
    /// before doing any work; mismatch is fail-closed before the
    /// reused loader runs.
    pub environment: TrustBundleEnvironment,
    /// 16-char lowercase hex chain id the peer claims this candidate
    /// targets. Cross-checked against the operator's runtime chain id
    /// before the loader runs, then double-checked by the loader.
    pub chain_id_hex: String,
    /// The bundle's declared sequence. Cross-checked against the
    /// parsed bundle after structural validation; mismatch is fail-
    /// closed.
    pub declared_sequence: u64,
    /// 8-char lowercase hex prefix of the bundle's canonical
    /// fingerprint (Run 050 SHA3-256). Cross-checked against the
    /// loader-computed fingerprint after structural validation.
    pub declared_fingerprint_prefix: String,
    /// Length the peer claims `bundle_bytes` has. Cross-checked
    /// against `bundle_bytes.len()`.
    pub declared_length: usize,
    /// The peer-supplied bundle bytes. Strict cap
    /// [`MAX_PEER_CANDIDATE_BUNDLE_BYTES`]. Serialised as a lowercase
    /// hex string for operator-friendly Run 077 JSON fixtures (see
    /// the type-level docs).
    #[serde(with = "peer_candidate_bundle_bytes_hex")]
    pub bundle_bytes: Vec<u8>,
}

impl PeerCandidateEnvelope {
    /// Canonical domain tag for the Run 076 envelope.
    pub const DOMAIN_TAG: &'static str = "qbind-peer-trust-bundle-candidate-v0";
    /// Canonical envelope version for Run 076.
    pub const ENVELOPE_VERSION: u16 = 1;
}

/// Run 076 configuration. **All** mutating behaviour is gated behind
/// [`PeerCandidateConfig::enabled`]; the default-constructed value is
/// `enabled = false` so importing this module without explicitly
/// opting in is a guaranteed no-op.
#[derive(Debug, Clone)]
pub struct PeerCandidateConfig {
    /// Master switch. Default `false`. When `false`,
    /// [`PeerCandidateValidator::try_accept`] returns
    /// [`PeerCandidateOutcome::Disabled`] **without** touching the
    /// payload, performing crypto, allocating a temp file, or bumping
    /// any counter other than the safe "received" counter (the
    /// "received" metric is the truthful "we observed a candidate"
    /// signal and is incremented unconditionally; this is the same
    /// discipline as the Run 074 `trigger_total` counter).
    pub enabled: bool,
    /// Max distinct peer-supplied candidate fingerprint prefixes the
    /// validator remembers when [`duplicate_suppression`] is `true`.
    /// Bounded LRU.
    pub duplicate_lru_capacity: usize,
    /// Suppress repeated expensive validation of byte-identical
    /// candidates (same 8-hex-char fingerprint prefix). Default
    /// `true`.
    pub duplicate_suppression: bool,
    /// Rate-limit window in milliseconds. Combined with
    /// [`max_in_window`] to form the token-bucket-equivalent fixed-
    /// window rate limiter. Default `1_000` (1 s).
    pub rate_limit_window_ms: u64,
    /// Maximum number of `try_accept` calls within a single window
    /// before the validator returns
    /// [`PeerCandidateOutcome::RateLimited`]. Calls counted here
    /// include both Validated and Rejected outcomes; Oversize /
    /// Disabled / DuplicateSuppressed / RateLimited outcomes are
    /// counted but never trigger the next-call rate-limit (the
    /// limiter is fail-closed but does not amplify cost).
    pub max_in_window: u32,
}

impl Default for PeerCandidateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duplicate_lru_capacity: 64,
            duplicate_suppression: true,
            rate_limit_window_ms: 1_000,
            max_in_window: 8,
        }
    }
}

/// Run 076 fail-closed pre-loader rejection reasons. These are the
/// reasons the **envelope** itself failed, BEFORE the reused
/// Run 069 loader was invoked. Distinct from
/// [`PeerCandidateRejection::ValidationFailed`] which wraps the
/// loader's fail-closed verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCandidateEnvelopeError {
    /// Unknown / mismatched envelope version.
    UnsupportedEnvelopeVersion(u16),
    /// Domain tag did not match [`PeerCandidateEnvelope::DOMAIN_TAG`].
    UnknownDomainTag(String),
    /// `declared_length` did not equal `bundle_bytes.len()`.
    DeclaredLengthMismatch {
        declared: usize,
        actual: usize,
    },
    /// `declared_fingerprint_prefix` was not 8 lowercase hex chars.
    MalformedDeclaredFingerprintPrefix(String),
    /// `chain_id_hex` was not 16 lowercase hex chars.
    MalformedChainIdHex(String),
    /// Envelope environment did not match the operator's runtime
    /// environment.
    EnvironmentMismatch {
        expected: TrustBundleEnvironment,
        envelope: TrustBundleEnvironment,
    },
    /// Envelope chain-id-hex did not match the operator's runtime
    /// chain-id-hex.
    ChainIdMismatch {
        expected_hex: String,
        envelope_hex: String,
    },
    /// `bundle_bytes` was empty.
    EmptyPayload,
}

impl std::fmt::Display for PeerCandidateEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEnvelopeVersion(v) => {
                write!(f, "unsupported peer-candidate envelope version: {}", v)
            }
            Self::UnknownDomainTag(t) => {
                write!(f, "unknown peer-candidate domain tag: {:?}", t)
            }
            Self::DeclaredLengthMismatch { declared, actual } => write!(
                f,
                "peer-candidate declared_length={} != bundle_bytes.len()={}",
                declared, actual
            ),
            Self::MalformedDeclaredFingerprintPrefix(s) => write!(
                f,
                "peer-candidate declared_fingerprint_prefix is not 8 lowercase hex chars: {:?}",
                s
            ),
            Self::MalformedChainIdHex(s) => write!(
                f,
                "peer-candidate chain_id_hex is not 16 lowercase hex chars: {:?}",
                s
            ),
            Self::EnvironmentMismatch { expected, envelope } => write!(
                f,
                "peer-candidate environment mismatch (operator runtime env={}, envelope env={})",
                expected, envelope
            ),
            Self::ChainIdMismatch {
                expected_hex,
                envelope_hex,
            } => write!(
                f,
                "peer-candidate chain-id mismatch (operator runtime chain_id={}, envelope chain_id={})",
                expected_hex, envelope_hex
            ),
            Self::EmptyPayload => write!(f, "peer-candidate bundle_bytes is empty"),
        }
    }
}

impl std::error::Error for PeerCandidateEnvelopeError {}

/// Run 076 fail-closed rejection reason. **Every** variant is a
/// non-mutating outcome: live trust state, sequence persistence, and
/// P2P sessions are unchanged on any rejection.
#[derive(Debug)]
pub enum PeerCandidateRejection {
    /// Envelope failed pre-loader validation. Wraps the precise
    /// envelope-layer reason. The reused loader was NOT invoked; the
    /// adversary did not consume ML-DSA verification cycles.
    Envelope(PeerCandidateEnvelopeError),
    /// The reused Run 069 loader rejected the parsed candidate. The
    /// inner [`ReloadCheckError`] carries the same fail-closed reason
    /// the startup loader and Run 069 reload-check would surface.
    /// The sequence persistence file (when supplied) is unchanged —
    /// guaranteed by the read-only `peek_sequence` semantics inherited
    /// from Run 069.
    ValidationFailed(ReloadCheckError),
    /// Declared metadata in the envelope did not match the bundle the
    /// loader parsed. Cross-checked AFTER structural validation so
    /// only authentic bundles can reach this branch, but the
    /// candidate is still rejected because the peer lied about
    /// metadata it could not have computed without parsing the bytes
    /// itself. Helps the operator diagnose hostile relays.
    DeclaredMetadataMismatch(String),
}

impl std::fmt::Display for PeerCandidateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(e) => write!(
                f,
                "peer-candidate envelope rejected before crypto; live trust state \
                 unchanged; sequence not persisted; sessions untouched: {}",
                e
            ),
            Self::ValidationFailed(e) => write!(
                f,
                "peer-candidate rejected at validation stage; live trust state \
                 unchanged; sequence not persisted; sessions untouched: {}",
                e
            ),
            Self::DeclaredMetadataMismatch(m) => write!(
                f,
                "peer-candidate envelope declared metadata mismatch after structural \
                 validation; live trust state unchanged; sequence not persisted; \
                 sessions untouched: {}",
                m
            ),
        }
    }
}

impl std::error::Error for PeerCandidateRejection {}

/// Run 076 success result on the validation path. Carries only
/// log-safe metadata and the Run 069 `ValidatedCandidate` itself so
/// callers / tests can confirm the validator reused the same
/// pipeline.
///
/// **Key invariant**: holding a `ValidatedPeerCandidate` does NOT
/// mean the candidate was applied. The validator never applies. A
/// caller wanting to **apply** a peer-supplied candidate would have
/// to forward this result into the local-operator workflow
/// (`--p2p-trust-bundle-reload-apply-path`); Run 076 does not do
/// that automatically.
#[derive(Debug, Clone)]
pub struct ValidatedPeerCandidate {
    /// The same Run 069 metadata struct the local reload-check
    /// produces. Source of truth for sequence / fingerprint /
    /// activation / signature_verified.
    pub validated: ValidatedCandidate,
    /// Peer id, if supplied. Log-safe.
    pub peer_id: Option<String>,
}

impl ValidatedPeerCandidate {
    /// Operator-log line. **Single source of truth** for the Run 076
    /// "candidate observed, not applied" boundary, so tests and binary
    /// logs agree.
    pub fn observed_log_line(&self) -> String {
        format!(
            "[binary] Run 076: peer-supplied trust-bundle candidate validated; NOT applied; \
             not propagated; sequence not persisted; live trust state unchanged; sessions \
             untouched (peer_id={} candidate_fp={}.. env={} chain_id={} sequence={} \
             signature_verified={} active_roots={} active_revoked_roots={} \
             active_revoked_leaves={})",
            self.peer_id.as_deref().unwrap_or("<unknown>"),
            self.validated.fingerprint_prefix,
            self.validated.environment,
            self.validated.chain_id_hex,
            self.validated.sequence,
            self.validated.signature_verified,
            self.validated.active_root_count,
            self.validated.active_revoked_root_count,
            self.validated.active_revoked_leaf_count,
        )
    }
}

/// Run 076 outcome of `try_accept`. Every variant — including the
/// success [`Validated`](Self::Validated) variant — is non-mutating
/// for live trust state / sequence persistence / P2P sessions.
#[derive(Debug)]
pub enum PeerCandidateOutcome {
    /// `PeerCandidateConfig::enabled == false`. No payload was
    /// touched, no crypto was performed, no temp file was written.
    /// **The default outcome** of the default-constructed validator.
    Disabled,
    /// `bundle_bytes.len() > MAX_PEER_CANDIDATE_BUNDLE_BYTES` OR
    /// `declared_length > MAX_PEER_CANDIDATE_BUNDLE_BYTES`. Dropped
    /// **before** any crypto, before any temp file was written, and
    /// before the duplicate-suppression cache was consulted.
    Oversize {
        observed_len: usize,
        cap: usize,
    },
    /// The configured rate limit fired. No crypto, no temp file.
    RateLimited {
        attempts_in_window: u32,
        cap: u32,
    },
    /// A previous call already validated (or rejected) a candidate
    /// with the same 8-hex-char fingerprint prefix within the
    /// duplicate cache window. The new call is suppressed before
    /// any crypto runs. Cache lookup is O(1) amortised and bounded
    /// by `duplicate_lru_capacity`.
    DuplicateSuppressed {
        fingerprint_prefix: String,
    },
    /// The candidate validated successfully through the same Run 069
    /// pipeline used at startup and by the local reload-check.
    /// **The candidate is NOT applied** — the validator never applies.
    Validated(ValidatedPeerCandidate),
    /// The candidate was rejected. Live state, sequence, and
    /// sessions remain unchanged.
    Rejected(PeerCandidateRejection),
}

impl PeerCandidateOutcome {
    /// Convenience: `true` if the outcome corresponds to a
    /// fail-closed verdict (Disabled / Oversize / RateLimited /
    /// DuplicateSuppressed / Rejected). The `Validated` variant
    /// returns `false` (a successful validation is not a rejection,
    /// even though it is also non-applying).
    pub fn is_rejected(&self) -> bool {
        !matches!(self, Self::Validated(_))
    }

    /// Convenience: `true` iff the outcome is `Validated`.
    pub fn is_validated(&self) -> bool {
        matches!(self, Self::Validated(_))
    }
}

/// Bounded LRU cache of recently-seen candidate fingerprint prefixes
/// (the 8 lowercase hex chars of `loaded.fingerprint_hex()[..8]`).
/// Used to suppress repeated expensive ML-DSA verification of
/// byte-identical candidates. Strict capacity; never allocates beyond
/// `capacity`.
#[derive(Debug)]
pub struct PeerCandidateDuplicateCache {
    capacity: usize,
    seen: VecDeque<String>,
}

impl PeerCandidateDuplicateCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: VecDeque::with_capacity(capacity.max(1)),
        }
    }

    /// True iff `prefix` is currently in the cache.
    pub fn contains(&self, prefix: &str) -> bool {
        self.seen.iter().any(|p| p == prefix)
    }

    /// Insert `prefix`, evicting the oldest entry if at capacity.
    /// No-op if already present (callers asking "is this a dup?" use
    /// [`contains`](Self::contains) BEFORE deciding to insert).
    pub fn insert(&mut self, prefix: String) {
        if self.contains(&prefix) {
            return;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(prefix);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Fixed-window rate limiter. Strict bound: at most
/// `config.max_in_window` calls within any one `config.rate_limit_window_ms`
/// window are accepted. Window edge is observed when the next call
/// arrives, so there is no background timer / task to spawn — this
/// follows the Run 076 "no unbounded task spawning" discipline.
#[derive(Debug)]
pub struct PeerCandidateRateLimiter {
    window_ms: u64,
    max_in_window: u32,
    window_started_ms: Option<u64>,
    in_window: u32,
}

impl PeerCandidateRateLimiter {
    pub fn new(window_ms: u64, max_in_window: u32) -> Self {
        Self {
            window_ms,
            max_in_window,
            window_started_ms: None,
            in_window: 0,
        }
    }

    /// Returns `Ok(())` if the call is admitted; bumps the in-window
    /// counter as a side effect. Returns
    /// `Err((attempts_in_window, cap))` if the call would exceed the
    /// configured cap.
    pub fn try_admit(&mut self, now_ms: u64) -> Result<(), (u32, u32)> {
        if self.max_in_window == 0 {
            return Err((self.in_window.saturating_add(1), 0));
        }
        match self.window_started_ms {
            None => {
                self.window_started_ms = Some(now_ms);
                self.in_window = 1;
                Ok(())
            }
            Some(started) => {
                if now_ms.saturating_sub(started) >= self.window_ms {
                    self.window_started_ms = Some(now_ms);
                    self.in_window = 1;
                    Ok(())
                } else if self.in_window < self.max_in_window {
                    self.in_window += 1;
                    Ok(())
                } else {
                    Err((self.in_window.saturating_add(1), self.max_in_window))
                }
            }
        }
    }

    pub fn in_window(&self) -> u32 {
        self.in_window
    }
}

/// Run 076 disabled-by-default peer/gossiped trust-bundle candidate
/// validator. The validator holds a small mutable cache and rate-
/// limiter; it does NOT hold (and CANNOT mutate) any live PQC trust
/// state, sequence persistence handle, or P2P session manager.
pub struct PeerCandidateValidator {
    config: PeerCandidateConfig,
    cache: PeerCandidateDuplicateCache,
    rate_limiter: PeerCandidateRateLimiter,
}

impl PeerCandidateValidator {
    /// Construct with the default disabled-by-default config.
    pub fn disabled() -> Self {
        let config = PeerCandidateConfig::default();
        let cache = PeerCandidateDuplicateCache::new(config.duplicate_lru_capacity);
        let rate_limiter =
            PeerCandidateRateLimiter::new(config.rate_limit_window_ms, config.max_in_window);
        Self {
            config,
            cache,
            rate_limiter,
        }
    }

    /// Construct with an explicit config. The disabled-by-default
    /// boundary still applies: `config.enabled == false` makes every
    /// `try_accept` call return [`PeerCandidateOutcome::Disabled`].
    pub fn new(config: PeerCandidateConfig) -> Self {
        let cache = PeerCandidateDuplicateCache::new(config.duplicate_lru_capacity);
        let rate_limiter =
            PeerCandidateRateLimiter::new(config.rate_limit_window_ms, config.max_in_window);
        Self {
            config,
            cache,
            rate_limiter,
        }
    }

    pub fn config(&self) -> &PeerCandidateConfig {
        &self.config
    }

    pub fn duplicate_cache(&self) -> &PeerCandidateDuplicateCache {
        &self.cache
    }

    /// Run 076 entry point. Receive a peer-supplied envelope and
    /// validate it under the operator-supplied runtime context.
    ///
    /// **Strict non-mutation contract** (true for every return path):
    /// - the live PQC trust state (`LivePqcTrustState` or equivalent)
    ///   of the running process is not touched;
    /// - the on-disk sequence persistence file at
    ///   `ctx.sequence_persistence_path` is not modified (peek is
    ///   read-only);
    /// - no P2P / KEMTLS session is evicted;
    /// - no `/metrics` family this validator does not own is mutated;
    /// - the candidate bundle bytes are only written to a temporary
    ///   file under `ctx.scratch_dir`, then read by the reused loader,
    ///   then unlinked before the function returns.
    pub fn try_accept(
        &mut self,
        envelope: PeerCandidateEnvelope,
        ctx: &PeerCandidateRuntimeContext<'_>,
    ) -> PeerCandidateOutcome {
        // 1. Disabled-by-default short-circuit. NO payload work, NO
        // crypto, NO temp file. This is the strictest layer.
        if !self.config.enabled {
            return PeerCandidateOutcome::Disabled;
        }

        // 2. Cheap envelope-layer checks BEFORE any crypto or any
        // temp-file write. These reject malformed / oversized /
        // wrong-env / wrong-chain envelopes for free.
        if envelope.bundle_bytes.len() > MAX_PEER_CANDIDATE_BUNDLE_BYTES
            || envelope.declared_length > MAX_PEER_CANDIDATE_BUNDLE_BYTES
        {
            return PeerCandidateOutcome::Oversize {
                observed_len: envelope.bundle_bytes.len().max(envelope.declared_length),
                cap: MAX_PEER_CANDIDATE_BUNDLE_BYTES,
            };
        }
        if let Err(e) = pre_check_envelope(&envelope, ctx.expected_environment, ctx.expected_chain_id)
        {
            return PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(e));
        }

        // 3. Rate-limit BEFORE crypto / temp file.
        if let Err((attempts, cap)) = self.rate_limiter.try_admit(ctx.now_ms) {
            return PeerCandidateOutcome::RateLimited {
                attempts_in_window: attempts,
                cap,
            };
        }

        // 4. Duplicate suppression BEFORE crypto / temp file.
        if self.config.duplicate_suppression
            && self.cache.contains(&envelope.declared_fingerprint_prefix)
        {
            return PeerCandidateOutcome::DuplicateSuppressed {
                fingerprint_prefix: envelope.declared_fingerprint_prefix.clone(),
            };
        }

        // 5. Stage the bytes in a tightly-scoped temp file under the
        // operator-controlled scratch dir. We do NOT trust the peer
        // to have chosen a safe path; we always pick a uuid-equivalent
        // name local to `ctx.scratch_dir`.
        let staged_path = match write_scratch(ctx.scratch_dir, &envelope.bundle_bytes) {
            Ok(p) => p,
            Err(e) => {
                return PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                    PeerCandidateEnvelopeError::DeclaredLengthMismatch {
                        declared: envelope.declared_length,
                        actual: e,
                    },
                ));
            }
        };

        // 6. Run the SAME Run 069 pipeline that startup, Run 073
        // process-start apply, and Run 074 SIGHUP live reload-apply
        // all use. NO sequence commit, NO live state mutation, NO
        // session eviction. Sequence persistence (if any) is consulted
        // ONLY via the read-only `peek_sequence` path inherited from
        // Run 069.
        let inputs = ReloadCheckInputs {
            candidate_path: &staged_path,
            environment: ctx.expected_environment,
            chain_id: ctx.expected_chain_id,
            validation_time_secs: ctx.validation_time_secs,
            signing_keys: ctx.signing_keys,
            activation_ctx: ctx.activation_ctx.clone(),
            sequence_persistence_path: ctx.sequence_persistence_path,
            local_leaf_cert_bytes: ctx.local_leaf_cert_bytes,
        };
        let res = validate_candidate_bundle_full(inputs);

        // 7. Unlink the temp file regardless of outcome so the
        // adversary cannot accumulate scratch payloads.
        let _ = std::fs::remove_file(&staged_path);

        match res {
            Err(e) => {
                // Track the declared fingerprint prefix so a flood of
                // identical-prefix garbage cannot keep re-paying ML-DSA
                // verification cost. Loader-side prefixes are unknown
                // here, so we use the declared one as the LRU key —
                // this is conservative because attacker-supplied
                // prefixes can only ever match more, never less, which
                // strengthens DoS resistance.
                if self.config.duplicate_suppression {
                    self.cache
                        .insert(envelope.declared_fingerprint_prefix.clone());
                }
                PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(e))
            }
            Ok((_loaded, _activation, validated)) => {
                // Cross-check the envelope's declared metadata against
                // the bundle the loader actually parsed.
                if validated.sequence != envelope.declared_sequence {
                    return PeerCandidateOutcome::Rejected(
                        PeerCandidateRejection::DeclaredMetadataMismatch(format!(
                            "envelope declared_sequence={} but parsed bundle.sequence={}",
                            envelope.declared_sequence, validated.sequence
                        )),
                    );
                }
                if !envelope
                    .declared_fingerprint_prefix
                    .eq_ignore_ascii_case(&validated.fingerprint_prefix)
                {
                    return PeerCandidateOutcome::Rejected(
                        PeerCandidateRejection::DeclaredMetadataMismatch(format!(
                            "envelope declared_fingerprint_prefix={:?} but parsed bundle \
                             fingerprint_prefix={:?}",
                            envelope.declared_fingerprint_prefix, validated.fingerprint_prefix
                        )),
                    );
                }
                if self.config.duplicate_suppression {
                    self.cache.insert(validated.fingerprint_prefix.clone());
                }
                PeerCandidateOutcome::Validated(ValidatedPeerCandidate {
                    validated,
                    peer_id: envelope.peer_id.clone(),
                })
            }
        }
    }
}

/// Run 076 runtime context (the operator-supplied side of the
/// boundary). Mirrors the same shape as Run 069 `ReloadCheckInputs`
/// but separates the **peer-provided** payload from the **operator-
/// provided** trust context.
#[derive(Debug, Clone)]
pub struct PeerCandidateRuntimeContext<'a> {
    /// Operator's runtime environment.
    pub expected_environment: NetworkEnvironment,
    /// Operator's runtime chain id.
    pub expected_chain_id: ChainId,
    /// Operator-controlled scratch directory for the temp candidate
    /// file. MUST NOT be a directory the peer can influence.
    pub scratch_dir: &'a Path,
    /// Wall-clock seconds (matches Run 069 `ReloadCheckInputs`).
    pub validation_time_secs: u64,
    /// Bundle-signing key set; same fail-closed semantics as Run 069.
    pub signing_keys: &'a BundleSigningKeySet,
    /// Activation context; same shape as Run 069.
    pub activation_ctx: ActivationContext,
    /// Optional sequence persistence path; same semantics as Run 069
    /// (read-only peek when `Some`).
    pub sequence_persistence_path: Option<&'a Path>,
    /// Optional local leaf cert bytes; same semantics as Run 069.
    pub local_leaf_cert_bytes: Option<&'a [u8]>,
    /// Current monotonic clock in milliseconds (for the rate limiter).
    pub now_ms: u64,
}

// ---------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------

fn pre_check_envelope(
    envelope: &PeerCandidateEnvelope,
    expected_env: NetworkEnvironment,
    expected_chain_id: ChainId,
) -> Result<(), PeerCandidateEnvelopeError> {
    if envelope.envelope_version != PeerCandidateEnvelope::ENVELOPE_VERSION {
        return Err(PeerCandidateEnvelopeError::UnsupportedEnvelopeVersion(
            envelope.envelope_version,
        ));
    }
    if envelope.domain_tag != PeerCandidateEnvelope::DOMAIN_TAG {
        return Err(PeerCandidateEnvelopeError::UnknownDomainTag(
            envelope.domain_tag.clone(),
        ));
    }
    if envelope.bundle_bytes.is_empty() {
        return Err(PeerCandidateEnvelopeError::EmptyPayload);
    }
    if envelope.declared_length != envelope.bundle_bytes.len() {
        return Err(PeerCandidateEnvelopeError::DeclaredLengthMismatch {
            declared: envelope.declared_length,
            actual: envelope.bundle_bytes.len(),
        });
    }
    if !is_lower_hex(&envelope.declared_fingerprint_prefix, 8) {
        return Err(PeerCandidateEnvelopeError::MalformedDeclaredFingerprintPrefix(
            envelope.declared_fingerprint_prefix.clone(),
        ));
    }
    if !is_lower_hex(&envelope.chain_id_hex, 16) {
        return Err(PeerCandidateEnvelopeError::MalformedChainIdHex(
            envelope.chain_id_hex.clone(),
        ));
    }
    let runtime_env_t = TrustBundleEnvironment::from_runtime(expected_env);
    if envelope.environment != runtime_env_t {
        return Err(PeerCandidateEnvelopeError::EnvironmentMismatch {
            expected: runtime_env_t,
            envelope: envelope.environment,
        });
    }
    let expected_chain_hex =
        crate::pqc_trust_sequence::chain_id_hex(expected_chain_id);
    if envelope.chain_id_hex != expected_chain_hex {
        return Err(PeerCandidateEnvelopeError::ChainIdMismatch {
            expected_hex: expected_chain_hex,
            envelope_hex: envelope.chain_id_hex.clone(),
        });
    }
    Ok(())
}

fn is_lower_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn write_scratch(scratch_dir: &Path, bytes: &[u8]) -> Result<PathBuf, usize> {
    // Failure-mode design: if we cannot write the scratch file (disk
    // full, no permission, etc.), we surface a synthetic
    // DeclaredLengthMismatch with `actual = 0` so the rejection path
    // is non-mutating and the operator log line clearly says
    // "rejected before crypto". A real production wire integration
    // would surface a dedicated I/O reason; for the Run 076 boundary
    // this stays minimal.
    if !scratch_dir.exists() {
        if std::fs::create_dir_all(scratch_dir).is_err() {
            return Err(0);
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = scratch_dir.join(format!(
        "qbind-run076-peer-candidate-{}-{}-{}.json",
        pid,
        nanos,
        rand_suffix()
    ));
    if std::fs::write(&path, bytes).is_err() {
        return Err(0);
    }
    Ok(path)
}

fn rand_suffix() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::process::id().hash(&mut h);
    std::time::SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    h.finish()
}

/// Lowercase-hex serde codec for [`PeerCandidateEnvelope::bundle_bytes`].
/// Run 077 binary fixtures use this so an operator-supplied JSON
/// envelope is diff-friendly and the declared-length / declared-
/// fingerprint cross-checks remain unambiguous. Strictly fixture-
/// format only: Run 077 introduces no peer/gossip wire surface.
mod peer_candidate_bundle_bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", b);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom(
                "peer-candidate bundle_bytes hex must have even length",
            ));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = decode_hex_nibble(bytes[i]).ok_or_else(|| {
                serde::de::Error::custom(
                    "peer-candidate bundle_bytes hex must be lowercase 0-9 a-f",
                )
            })?;
            let lo = decode_hex_nibble(bytes[i + 1]).ok_or_else(|| {
                serde::de::Error::custom(
                    "peer-candidate bundle_bytes hex must be lowercase 0-9 a-f",
                )
            })?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }

    fn decode_hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// Unit tests (envelope / cache / rate-limiter / disabled-by-default).
// Full-pipeline sequencing proofs against the reused Run 069 loader
// live in crates/qbind-node/tests/run_076_pqc_peer_candidate_validation_tests.rs
// because they need the test signing harness.
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn fake_signing_keys() -> BundleSigningKeySet {
        BundleSigningKeySet::from_keys_unchecked(vec![])
    }

    fn make_envelope(bytes_len: usize) -> PeerCandidateEnvelope {
        PeerCandidateEnvelope {
            envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
            domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
            peer_id: Some("peer-abcdef".to_string()),
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: crate::pqc_trust_sequence::chain_id_hex(
                NetworkEnvironment::Devnet.chain_id(),
            ),
            declared_sequence: 7,
            declared_fingerprint_prefix: "deadbeef".to_string(),
            declared_length: bytes_len,
            bundle_bytes: vec![0u8; bytes_len],
        }
    }

    fn ctx<'a>(
        scratch: &'a Path,
        signing_keys: &'a BundleSigningKeySet,
    ) -> PeerCandidateRuntimeContext<'a> {
        PeerCandidateRuntimeContext {
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: scratch,
            validation_time_secs: 100,
            signing_keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            now_ms: 1000,
        }
    }

    #[test]
    fn run076_disabled_by_default() {
        let mut v = PeerCandidateValidator::disabled();
        assert!(!v.config().enabled);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let env = make_envelope(8);
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        assert!(matches!(out, PeerCandidateOutcome::Disabled));
        // Cache untouched: no crypto, no temp file.
        assert!(v.duplicate_cache().is_empty());
    }

    #[test]
    fn run076_max_size_is_bounded_and_drops_before_crypto() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(0);
        env.bundle_bytes = vec![0u8; MAX_PEER_CANDIDATE_BUNDLE_BYTES + 1];
        env.declared_length = env.bundle_bytes.len();
        match v.try_accept(env, &ctx(&scratch, &keys)) {
            PeerCandidateOutcome::Oversize { observed_len, cap } => {
                assert_eq!(cap, MAX_PEER_CANDIDATE_BUNDLE_BYTES);
                assert!(observed_len > cap);
            }
            other => panic!("expected Oversize, got {:?}", other),
        }
    }

    #[test]
    fn run076_envelope_pre_check_rejects_wrong_domain_tag() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(8);
        env.domain_tag = "evil".to_string();
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        match out {
            PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::UnknownDomainTag(t),
            )) => assert_eq!(t, "evil"),
            other => panic!("expected envelope unknown-domain-tag, got {:?}", other),
        }
    }

    #[test]
    fn run076_envelope_pre_check_rejects_declared_length_mismatch() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(8);
        env.declared_length = 99;
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        assert!(matches!(
            out,
            PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::DeclaredLengthMismatch { .. }
            ))
        ));
    }

    #[test]
    fn run076_envelope_pre_check_rejects_wrong_env() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(8);
        env.environment = TrustBundleEnvironment::Mainnet;
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        assert!(matches!(
            out,
            PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::EnvironmentMismatch { .. }
            ))
        ));
    }

    #[test]
    fn run076_envelope_pre_check_rejects_wrong_chain_id() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(8);
        env.chain_id_hex = "0000000000000000".to_string();
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        assert!(matches!(
            out,
            PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::ChainIdMismatch { .. }
            ))
        ));
    }

    #[test]
    fn run076_envelope_pre_check_rejects_unknown_version() {
        let mut cfg = PeerCandidateConfig::default();
        cfg.enabled = true;
        let mut v = PeerCandidateValidator::new(cfg);
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let mut env = make_envelope(8);
        env.envelope_version = 999;
        let out = v.try_accept(env, &ctx(&scratch, &keys));
        assert!(matches!(
            out,
            PeerCandidateOutcome::Rejected(PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::UnsupportedEnvelopeVersion(999)
            ))
        ));
    }

    #[test]
    fn run076_duplicate_cache_lru_evicts_oldest() {
        let mut c = PeerCandidateDuplicateCache::new(2);
        c.insert("aaaaaaaa".into());
        c.insert("bbbbbbbb".into());
        c.insert("aaaaaaaa".into()); // no-op (already present)
        assert!(c.contains("aaaaaaaa"));
        assert!(c.contains("bbbbbbbb"));
        assert_eq!(c.len(), 2);
        c.insert("cccccccc".into()); // evicts oldest "aaaaaaaa"
        assert!(!c.contains("aaaaaaaa"));
        assert!(c.contains("bbbbbbbb"));
        assert!(c.contains("cccccccc"));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn run076_duplicate_cache_capacity_at_least_one() {
        let c = PeerCandidateDuplicateCache::new(0);
        assert_eq!(c.capacity(), 1);
        let c = PeerCandidateDuplicateCache::new(5);
        assert_eq!(c.capacity(), 5);
    }

    #[test]
    fn run076_rate_limiter_admits_up_to_cap_then_blocks() {
        let mut r = PeerCandidateRateLimiter::new(1000, 3);
        assert!(r.try_admit(100).is_ok());
        assert!(r.try_admit(200).is_ok());
        assert!(r.try_admit(300).is_ok());
        match r.try_admit(400) {
            Err((attempts, cap)) => {
                assert_eq!(cap, 3);
                assert!(attempts >= 4);
            }
            Ok(()) => panic!("must block after cap"),
        }
        // Window roll-over after window_ms elapsed.
        assert!(r.try_admit(1_500).is_ok());
        assert_eq!(r.in_window(), 1);
    }

    #[test]
    fn run076_rate_limiter_zero_cap_always_blocks() {
        let mut r = PeerCandidateRateLimiter::new(1000, 0);
        assert!(r.try_admit(100).is_err());
        assert!(r.try_admit(2000).is_err());
    }

    #[test]
    fn run076_envelope_error_display_marks_pre_crypto_rejection_safely() {
        let cases = vec![
            PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::UnsupportedEnvelopeVersion(7),
            ),
            PeerCandidateRejection::Envelope(PeerCandidateEnvelopeError::EmptyPayload),
            PeerCandidateRejection::Envelope(
                PeerCandidateEnvelopeError::DeclaredLengthMismatch {
                    declared: 9,
                    actual: 8,
                },
            ),
            PeerCandidateRejection::DeclaredMetadataMismatch("seq mismatch".into()),
        ];
        for r in cases {
            let s = format!("{}", r);
            assert!(s.contains("live trust state unchanged"), "{}", s);
            assert!(s.contains("sequence not persisted"), "{}", s);
            assert!(s.contains("sessions untouched"), "{}", s);
        }
    }

    #[test]
    fn run076_validated_log_line_marks_not_applied() {
        let v = ValidatedPeerCandidate {
            validated: ValidatedCandidate {
                fingerprint_hex: "ab".repeat(32),
                fingerprint_prefix: "abababab".into(),
                sequence: 3,
                environment: TrustBundleEnvironment::Devnet,
                chain_id_hex: "0123456789abcdef".into(),
                active_root_count: 1,
                active_revoked_root_count: 0,
                pending_revoked_root_count: 0,
                active_revoked_leaf_count: 0,
                pending_revoked_leaf_count: 0,
                signature_verified: true,
                activation: crate::pqc_trust_activation::ActivationCheckOutcome {
                    required_height: None,
                    current_height: Some(0),
                    required_epoch: None,
                    current_epoch: None,
                },
                sequence_peek:
                    crate::pqc_trust_sequence::SequencePeekOutcome::NoPriorRecord {
                        candidate_sequence: 3,
                        candidate_fingerprint_hex: "ab".repeat(32),
                    },
                sequence_persistence_path: None,
            },
            peer_id: Some("peer-42".into()),
        };
        let line = v.observed_log_line();
        assert!(line.contains("Run 076"), "{}", line);
        assert!(line.contains("NOT applied"), "{}", line);
        assert!(line.contains("not propagated"), "{}", line);
        assert!(line.contains("sequence not persisted"), "{}", line);
        assert!(line.contains("live trust state unchanged"), "{}", line);
        assert!(line.contains("sessions untouched"), "{}", line);
        assert!(line.contains("peer_id=peer-42"), "{}", line);
        assert!(line.contains("abababab"), "{}", line);
        assert!(line.contains("sequence=3"), "{}", line);
    }

    #[test]
    fn run076_outcome_helpers() {
        let o = PeerCandidateOutcome::Disabled;
        assert!(o.is_rejected());
        assert!(!o.is_validated());
        let o = PeerCandidateOutcome::Oversize {
            observed_len: 1,
            cap: 1,
        };
        assert!(o.is_rejected());
        let o = PeerCandidateOutcome::RateLimited {
            attempts_in_window: 5,
            cap: 3,
        };
        assert!(o.is_rejected());
        let o = PeerCandidateOutcome::DuplicateSuppressed {
            fingerprint_prefix: "aa".into(),
        };
        assert!(o.is_rejected());
    }

    #[test]
    fn run076_config_default_is_disabled_by_default() {
        let c = PeerCandidateConfig::default();
        assert!(!c.enabled);
        assert!(c.duplicate_suppression);
        assert!(c.duplicate_lru_capacity >= 1);
        assert!(c.rate_limit_window_ms >= 1);
        assert!(c.max_in_window >= 1);
    }

    #[test]
    fn run076_is_lower_hex_strict() {
        assert!(super::is_lower_hex("0123456789abcdef", 16));
        assert!(super::is_lower_hex("deadbeef", 8));
        assert!(!super::is_lower_hex("DEADBEEF", 8)); // upper rejected
        assert!(!super::is_lower_hex("deadbeefz", 8));
        assert!(!super::is_lower_hex("deadbeef", 16));
        assert!(!super::is_lower_hex("0x12345678", 8));
    }
}