# QBIND PQC Trust Lifecycle Operator Runbook

**Run:** 090 (operator-playbook prose update for the propagation-only peer-candidate lifecycle from Runs 087–089)
**Status:** Operator playbook landed and updated for Runs 050–089; full C4 remains OPEN; C5 remains OPEN / narrowed
**Scope owner:** transport trust-anchor + bundle-signing lifecycle + peer-candidate validation-only and propagation-only lifecycle
**Date:** 2026-05-18

This runbook converts the PQC trust-bundle machinery proven by
Runs 050–074 into a concrete operator playbook for production
custody, rotation, revocation, bundle-signing-key rotation, **and
the operator-triggered hot-reload lifecycle** (§6.F), and — as of
Run 086 — also documents the **peer-candidate validation-only
lifecycle** (§6.G) added by Runs 076–085. Run 087 adds a
formal design-gate safety specification for any future peer-driven
trust-bundle propagation or apply work. Run 088 narrows that boundary
with a hidden, disabled-by-default, propagation-only prototype that
rebroadcasts only after local validation succeeds and still never
applies. Run 089 lands the release-binary **N=3 DevNet** propagation
evidence for that prototype (`scripts/devnet/run_089_peer_candidate_propagation_n3.sh`)
and proves V0 → V1 → V2 propagation occurs only after V1 validation,
that V1 excludes V0 from its rebroadcast target set, that invalid
wrong-chain and duplicate candidates do not rebroadcast, that no
propagation loop forms under a 5 s settle window, and that no apply /
sequence write / session eviction / `LivePqcTrustState` mutation /
`--p2p-trusted-root` fallback / Dummy crypto occurs on any node in
any scenario. Run 090 is this docs-only operator-playbook update that
folds Runs 087–089 into §6.G with an explicit distinction between
validation-only receive/send, propagation-only rebroadcast after
validation, local-operator SIGHUP live apply (§6.F.4), and
peer-driven live apply — which is **still not implemented**.

Run 086 is a documentation-only update of the Run 075 playbook
that incorporates Runs 076–085:

- **Run 076** — library-level disabled-by-default
  `PeerCandidateValidator` over a structured
  `PeerCandidateEnvelope`.
- **Run 077** — production-binary-facing local peer-candidate
  check mode (hidden `--p2p-trust-bundle-peer-candidate-validation-enabled`
  + `--p2p-trust-bundle-peer-candidate-check <PATH>`); node
  does not start; exits 0/1; non-mutating by construction.
- **Run 078** — bounded typed/versioned peer-candidate **wire
  envelope** with deterministic canonical bytes and size cap.
- **Run 079** — disabled-by-default **live P2P receive-loop
  dispatch** for inbound `0x05` frames (hidden
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`).
- **Run 080** — disabled-by-default **send-side publisher**
  plumbing (hidden
  `--p2p-trust-bundle-peer-candidate-wire-publish-{enabled,path,once}`);
  one-shot publish over the live authenticated P2P session.
- **Run 081** — first release-binary N=2 real `0x05` exchange
  evidence; partial due to `DummySig` ambiguity on the
  consensus signer probe path.
- **Run 082 / 083** — isolated the `DummySig` boundary as
  non-active / probe-log-only with respect to the
  peer-candidate matrix.
- **Run 084** — committed repeatable **N=2 DevNet** harness
  `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh`;
  closed the N=2 evidence gap.
- **Run 085** — committed repeatable **N=4 MainNet** harness
  `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh`;
  strongest current evidence (signed MainNet trust material;
  baseline / valid / receiver-disabled / invalid-wrong-chain /
  duplicate scenarios all pass; sequence hashes unchanged;
  live-reload-apply + session-eviction metrics stayed zero;
  no propagation; no active `DummySig` / `DummyKem` /
  `DummyAead`; no `--p2p-trusted-root` fallback).
- **Run 087** — added
  `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`;
  design-gate only, no runtime behaviour change.
- **Run 088** — adds hidden
  `--p2p-trust-bundle-peer-candidate-propagation-enabled`.
  When explicitly enabled with a validated `--p2p-trust-bundle`
  baseline, a received `0x05` peer-candidate frame is decoded and
  validated through the existing Run 078 / Run 076 path first; only a
  validated candidate may be rebroadcast to connected non-source peers.
  Loop prevention is local: candidate sequence + fingerprint seen-cache,
  source-peer exclusion, bounded target count, bounded raw-frame queues,
  and a propagation fixed-window rate limit. The wire format is
  unchanged; no TTL byte was added.

The peer-candidate `0x05` exchange added by Runs 076–085 remains
**non-applying**: a receiver observes and validates candidates.
Run 088 may optionally rebroadcast only validated frames when the
hidden propagation flag is set. It still never applies candidates,
never mutates `LivePqcTrustState`, never writes the sequence file, and
never evicts sessions. The §6.F SIGHUP path remains the only operator
surface that ever applies a candidate to a running node.
`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`
defines the safety gates: Run 088 satisfies the validation-before-
rebroadcast subset but does **not** implement peer-driven live apply,
trust-bundle synchronization, consensus ratification, activation_epoch
runtime sourcing, KMS/HSM custody, signing-key ratification, or
fast-sync restore.

Run 075 was the previous documentation-only update of the
Run 066 playbook for Runs 069–074:

- **Run 069** — disabled-by-default validation-only reload-check
  hook (`--p2p-trust-bundle-reload-check <PATH>`), non-mutating
  by construction (no live trust mutation, no sequence commit, no
  session eviction, no `/metrics` family).
- **Run 070** — apply contract (`ApplyMode`, `ReloadApplyError`,
  `LiveTrustApplyContext`, `apply_validated_candidate{,_with_previous}`,
  `AppliedCandidate`) with the strict
  `validate → snapshot → swap → evict_sessions → commit_sequence`
  ordering and per-stage rollback semantics.
- **Run 071** — mutable shared `LivePqcTrustState`
  (`Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`) initialized once at
  startup from the validated `LoadedTrustBundle`; the listener-side
  handshake verifier and the bidirectional revocation closure now
  read through this handle (no behavior change at startup).
- **Run 072** — production session-eviction hook
  (`P2pSessionEvictor` trait + `TcpKemTlsP2pService::evict_all_sessions`
  + four `qbind_p2p_session_eviction_*` counters).
- **Run 073** — `ProductionLiveTrustApplyContext` adapter composes
  Runs 069/070/071/072/055 end-to-end; the binary's
  `--p2p-trust-bundle-reload-apply-path` hook now drives a live
  apply at process-start time (the `UnsupportedRuntimeContext`
  boundary is removed from the local-operator path).
- **Run 074** — long-running local operator-triggered live reload-
  apply on a running node via SIGHUP. New hidden CLI flags
  `--p2p-trust-bundle-live-reload-enabled` +
  `--p2p-trust-bundle-live-reload-path <PATH>` (required together;
  refused without `--p2p-trust-bundle <BASELINE-PATH>`). New
  `LiveReloadController` serializes concurrent triggers via an
  `Arc<AtomicBool>` CAS guard; only the `Fatal`
  (`SequenceCommitFailedRollbackAlsoFailed`) arm signals
  shutdown. Six new `qbind_p2p_trust_bundle_live_reload_*`
  Prometheus counters/gauge. Run 114 wired the Run 105
  bundle-signing-key ratification enforcement body into this
  trigger (`--p2p-trust-bundle-ratification <PATH>`, re-read on
  every SIGHUP); Run 115 captured the release-binary evidence
  archive across 10 scenarios (valid, missing, bad-signature,
  wrong-chain, wrong-env, unknown-authority on MainNet; DevNet
  legacy / opt-in valid / opt-in missing; and 5 SIGHUPs against
  one long-running PID) under
  `docs/devnet/run_115_sighup_ratification_release_binary/` — see
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_115.md` for the canonical
  operator example.

The Run 065 per-environment minimum activation-margin policy
(DevNet 0 / TestNet 8 / MainNet 32 blocks; half-open
`[current_height, current_height + margin)` reject window;
`activation_height = None` immediate revocations remain exempt)
continues to apply at every bundle-load site, including all four
hot-reload entry points above. No runtime code, no test source,
and no helper source is changed by Run 075, Run 086, or Run 087.

It is **operator documentation**. It is **not** a redesign of any
runtime layer. It does **not** introduce new bypass flags, does
**not** weaken any fail-closed check, and does **not** advocate
any fallback that the binary already refuses. If anything in this
document appears to contradict the implementation, the
implementation wins and this runbook MUST be updated.

References to behaviour are anchored in:

- `crates/qbind-node/src/pqc_trust_bundle.rs` (envelope, canonical
  fingerprint, ML-DSA-44 signature verification — Runs 050/051/053;
  leaf-fingerprint domain separator `QBIND:pqc-trust-bundle-leaf-fp:v1`
  — Runs 052/054; sequence anti-rollback persistence — Run 055;
  per-entry revocation `activation_height` + active/pending split —
  Run 062; local-leaf startup self-check helper
  `check_local_leaf_not_revoked` — Run 061; local-issuer-root startup
  self-check helper `check_local_leaf_issuer_root_not_revoked` —
  Run 063).
- `crates/qbind-node/src/pqc_trust_sequence.rs` (sequence anti-
  rollback persistence — Run 055).
- `crates/qbind-node/src/pqc_trust_activation.rs` (bundle-level
  activation height / epoch gating — Run 057; per-environment
  minimum activation-margin constants and policy helper — Run 065:
  `MIN_DEVNET_ACTIVATION_MARGIN = 0`,
  `MIN_TESTNET_ACTIVATION_MARGIN = 8`,
  `MIN_MAINNET_ACTIVATION_MARGIN = 32`;
  `ActivationPolicy::for_environment`;
  `minimum_activation_margin_for_environment`;
  `check_min_activation_height_policy`;
  `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`;
  `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`;
  `RevocationScope`).
- `crates/qbind-node/src/pqc_root_config.rs` (root parsing,
  `PQC_TRANSPORT_SUITE_ML_DSA_44 = 100`).
- `crates/qbind-node/src/p2p_node_builder.rs::make_pqc_static_root_crypto_provider`
  (real `MlDsa44SignatureSuite`, real `MlKem768Backend`, real
  `ChaCha20Poly1305Backend` — Runs 037/039/040).
- `crates/qbind-node/src/main.rs` trust-bundle load path (calls
  `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
  then `check_and_update_sequence` BEFORE root merge; emits the
  Run 062 revocation-activation banner; runs the Run 061
  local-leaf-fingerprint and Run 063 local-issuer-root startup
  self-checks BEFORE `PqcStaticRootConfig` construction; the
  Run 065 per-environment minimum activation-margin policy is
  applied AFTER signature/chain_id/environment/revocation
  structural validation and BEFORE Run 057's future-height gate,
  Run 055's sequence persistence, and Run 050's root merge — its
  two new error variants
  `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`
  and
  `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`
  flow through the existing `TrustBundleError::Activation(..)`
  FATAL printer with the static "No fallback to
  --p2p-trusted-root" marker).
- `crates/qbind-node/examples/devnet_pqc_root_helper.rs` and
  `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`
  (DevNet evidence tooling only — not production custody).
- `crates/qbind-node/src/pqc_trust_reload.rs` (Run 069/070
  validation/staging entry points: `ValidatedCandidate`,
  `ReloadCheckError`, `ReloadCheckInputs`,
  `validate_candidate_bundle{,_full}` — non-mutating by
  construction; `ApplyMode`, `ReloadApplyError`,
  `LiveTrustApplyContext`,
  `apply_validated_candidate{,_with_previous}`,
  `AppliedCandidate::applied_log_line` — Run 070 apply contract
  with strict `validate → snapshot → swap → evict → commit`
  ordering and per-stage rollback).
- `crates/qbind-node/src/pqc_trust_sequence.rs::peek_sequence`
  (Run 069 read-only equivalent of `check_and_update_sequence`;
  never writes).
- `crates/qbind-node/src/pqc_live_trust.rs` (Run 071 mutable
  shared live trust handle: `LivePqcTrustState`,
  `LivePqcTrustSnapshot`, `initialize_from_loaded_bundle`,
  `snapshot`, `swap_snapshot`; consumed by
  `P2pNodeBuilder::with_live_pqc_trust(...)` on the
  listener-side `TrustedClientRoots` resolver and the
  bidirectional `LeafCertRevocationList` revocation closure).
- `crates/qbind-node/src/p2p_session_eviction.rs` (Run 072
  production-honest internal session-eviction hook:
  `EvictionReason::{TrustBundleReloadApply, …}`,
  `EvictionReport` with `attempted == evicted + failed`
  invariant, `EvictionError`, sync `P2pSessionEvictor` trait,
  `MockP2pSessionEvictor`).
- `crates/qbind-node/src/p2p_tcp.rs::TcpKemTlsP2pService::evict_all_sessions`
  (Run 072 concrete evictor; drains the per-peer
  `PeerConnection` registry, drops outbound `tx` channels,
  aborts per-peer read/write `JoinHandle`s; implements
  `P2pSessionEvictor`).
- `crates/qbind-node/src/pqc_live_trust_apply.rs` (Run 073
  `ProductionLiveTrustApplyContext` adapter — composes Run 069
  validation + Run 071 `swap_snapshot` + Run 072 evictor + Run
  055 `check_and_update_sequence`; `NoActiveSessionsEvictor`
  for the truthful at-startup-time zero-session report).
- `crates/qbind-node/src/pqc_live_trust_reload.rs` (Run 074
  long-running-node controller: `LiveReloadConfig`,
  `LiveReloadController`, `LiveReloadOutcome { Applied |
  AlreadyInProgress | Invalid | Fatal }`, `try_trigger() /
  try_trigger_with_now() / try_trigger_with_activation()`,
  `Arc<AtomicBool>` CAS in-progress guard).
- `crates/qbind-node/src/main.rs::spawn_run074_live_reload_task`
  (Run 074 SIGHUP signal-handler task; gated behind
  `#[cfg(unix)]`; only the `Fatal` arm sends to `shutdown_tx`).
- `crates/qbind-node/src/cli.rs` (hidden Run 069/070/074 flags:
  `--p2p-trust-bundle-reload-check <PATH>`,
  `--p2p-trust-bundle-reload-apply-enabled`,
  `--p2p-trust-bundle-reload-apply-path <PATH>`,
  `--p2p-trust-bundle-live-reload-enabled`,
  `--p2p-trust-bundle-live-reload-path <PATH>`).
- `crates/qbind-node/src/metrics.rs` (Run 072 four
  `qbind_p2p_session_eviction_*` counters; Run 074 six
  `qbind_p2p_trust_bundle_live_reload_*` counters/gauge —
  `trigger_total`, `apply_success_total`, `apply_failure_total`,
  `already_in_progress_total`, `sessions_evicted_total`,
  `last_applied_sequence`).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_050.md` through `RUN_074.md`
  (live-binary smoke evidence for every fail-closed boundary cited
  below, including reload-check / reload-apply / live-reload).

Per-environment chain ids (`crates/qbind-types/src/primitives.rs`):

- DevNet:  `0x51424E4444455600`
- TestNet: `0x51424E4454535400`
- MainNet: `0x51424E444D41494E`

---

## 1. Scope and non-goals

### 1.1 In scope

- Transport trust-anchor (ML-DSA-44 root) lifecycle: generation,
  custody, normal rotation, emergency revocation.
- Bundle-signing key lifecycle: generation, custody, distribution,
  rotation.
- Validator leaf delegation certificate rotation.
- Sequence anti-rollback persistence behaviour at rotation and
  recovery time.
- Activation-height gating policy at rotation time.
- DevNet / TestNet / MainNet per-environment policy.
- Promotion, incident, and evidence checklists operators must run
  for every production trust-bundle change.

### 1.2 Out of scope (explicit non-goals)

- Any redesign of KEMTLS, the trust-bundle envelope, the
  sequence-persistence format, the activation-gate semantics,
  consensus, NewView, timeout verification, or transport crypto.
- Any new CLI flag, environment variable, or compile-time feature
  that would let an operator bypass signed-bundle verification,
  chain_id check, sequence anti-rollback, activation gating, leaf
  revocation, or environment binding.
- A full external KMS / HSM integration. The runbook treats the
  signing-key custody surface as an **interface / runbook boundary**;
  operators MAY back this with HSM/KMS in production but the
  binary today consumes ML-DSA-44 keys via the existing
  `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` flag, which is
  a **verification** public key — see §4.
- On-chain bundle-signing-key rotation (the binary does **not**
  ratify a new signing key inside the bundle itself; the
  `signing_key_id` is verified against an out-of-band-distributed
  CLI-configured set — see §6.D).
- An epoch-gating runtime source (Run 057 boundary: bundles that
  declare `activation_epoch` continue to fail closed with
  `TrustBundleActivationError::CurrentEpochUnavailable`).
- A per-environment minimum-activation-height policy enforced by
  the binary on a **gossiped / peer-supplied** bundle path. Run 065
  enforces this policy on the binary's `--p2p-trust-bundle` load
  path and the Run 069/070/073/074 hot-reload paths reuse the same
  loader (so Run 065 holds for every hot-reload candidate, §6.F).
  The bundle is not yet gossiped between peers; when on-the-fly
  peer-supplied / gossiped trust-bundle distribution lands, the
  same `check_min_activation_height_policy` helper must be
  threaded through that path. The Run 065 helper itself is
  reusable today
  (`crates/qbind-node/src/pqc_trust_activation.rs::check_min_activation_height_policy`).
- On-the-fly **peer-supplied / gossiped** trust-bundle hot reload.
  **Local operator-triggered hot reload IS supported** as of Runs
  069 (validation-only reload-check), 073 (process-start local
  reload-apply), and 074 (long-running SIGHUP live apply on a
  running node), all driven by **operator-supplied local files**
  through the SAME loader the startup `--p2p-trust-bundle` path
  uses (§6.F). The candidate is never accepted from a peer, from
  gossip, from an admin API, or from a filesystem-watcher; the
  trigger is always an explicit operator action (CLI flag at
  start-time, or `SIGHUP` to a long-running node armed with the
  hidden Run 074 flags). Peer / gossiped bundle propagation
  remains a separate C4 piece (§10).
- Production fast-sync / consensus-storage restore (separate C4
  piece).

### 1.3 Strictly preserved invariants

This runbook MUST NOT contradict any of the following. They are
production-honest fail-closed behaviours proven by Runs 050–059
and must not be weakened by any operator procedure described here:

| Invariant | Where enforced | Proof |
|---|---|---|
| Bundle signature MUST verify against a configured `--p2p-trust-bundle-signing-key` on TestNet/MainNet. Unsigned bundle on TestNet/MainNet fails closed. | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_and_chain_id` | RUN_051, RUN_059 Smoke 2 |
| Tampered bundle (any byte of canonical preimage flipped after signing) fails closed at ML-DSA-44 verify. | same | RUN_051, RUN_059 Smoke 3 |
| Wrong signing key (`signing_key_id` not in the operator's `--p2p-trust-bundle-signing-key` set) fails closed. | same | RUN_051, RUN_059 Smoke 4 |
| Wrong `chain_id` fails closed BEFORE signature verification side-effects on the live trust set. | same | RUN_053, RUN_059 Smoke 5 |
| Wrong `environment` fails closed. | same | RUN_050 |
| Expired / not-yet-valid bundle window fails closed. | same | RUN_050 |
| Expired / not-yet-valid root window excludes that root. | same | RUN_050 |
| Revoked root (`status=revoked` OR listed in `revocations[]`) excluded from active set. | same | RUN_050 |
| `signing_key_id` MUST NOT collide with any transport `root_id` (trust separation). | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys` | RUN_051 |
| `--p2p-trust-bundle-signing-key` MUST NOT collide with any `--p2p-trusted-root` id at startup (trust separation, defence in depth). | `main.rs` startup check | RUN_051 |
| Lower-`sequence` bundle on the same trust domain fails closed (rollback). | `pqc_trust_sequence::check_and_update_sequence` | RUN_055, RUN_056 Smoke 3 |
| Equal-`sequence` different-fingerprint bundle fails closed (equivocation). | same | RUN_055, RUN_056 Smoke 5 |
| Corrupted persistence file is never silently deleted / truncated / reset; loader fails closed. | same | RUN_055, RUN_056 Smoke 6 |
| `activation_height` in the future fails closed; does NOT advance persisted sequence; does NOT merge roots. | `pqc_trust_activation::check_bundle_activation`, ordering pinned by `pqc_trust_activation::tests::future_activation_does_not_advance_sequence_persistence` and RUN_057 integration test of the same name | RUN_057, RUN_058 Smoke 2/3/4 |
| `activation_epoch` declared without a runtime epoch source fails closed (`CurrentEpochUnavailable`). | same | RUN_057 |
| On any bundle-load failure, the binary does NOT silently fall back to `--p2p-trusted-root`. FATAL message ends with the literal phrase `No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade)`. | `main.rs` | every Run 050–059 negative smoke |
| Under `--p2p-pqc-root-mode pqc-static-root`, the registered crypto provider is the real ML-DSA-44 / ML-KEM-768 / ChaCha20-Poly1305 set. No `DummySig` / `DummyKem` / `DummyAead` is registered. | `p2p_node_builder::make_pqc_static_root_crypto_provider` | RUN_037/039/040, RUN_041 |
| **Local-leaf startup self-check (Run 061).** If a configured `--p2p-leaf-cert` has a canonical leaf fingerprint (SHA3-256 of `b"QBIND:pqc-trust-bundle-leaf-fp:v1" \|\| cert.encode()`) that appears in the loaded bundle's currently-**active** `revoked_leaf_fingerprints` set, the binary emits one `[binary] FATAL: Run 061 local leaf certificate revoked …` line and exits 1 BEFORE `PqcStaticRootConfig` is built and BEFORE any peer handshake. The Run 052 peer-handshake counter `qbind_p2p_pqc_cert_verify_rejected_revoked_total` is NOT bumped. | `pqc_trust_bundle::check_local_leaf_not_revoked`, wired in `main.rs` between Run 050/051/062 banners and `pqc_config` construction | RUN_061 |
| **Per-entry revocation activation gate (Run 062).** A `revocations[]` entry with `activation_height: None` is immediate. A signature-valid entry with `activation_height > current_height` is **PENDING** — surfaced via `pending_revoked_root_ids` / `pending_revoked_leaf_fingerprints` and the `_revocations_*_pending` gauges, but NOT enforced anywhere (not in `active_roots`, not in the Run 061 startup self-check, not in the Run 052 peer-handshake context). An entry with `activation_height <= current_height` is **ACTIVE** and enforced bit-for-bit as the legacy immediate revocation. Tampering `activation_height` after signing invalidates the ML-DSA-44 bundle signature (canonical preimage coverage). | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_chain_id_and_revocation_activation`; gauges in `metrics.rs` (`qbind_p2p_pqc_trust_bundle_revocations_{configured,active,pending}_total`, `_revocations_{root,leaf}_{active,pending}`) | RUN_062 |
| **Local-issuer-root startup self-check (Run 063).** If a configured `--p2p-leaf-cert` decodes to a `root_key_id` that appears in the loaded bundle's currently-**active** `revoked_root_ids` set, the binary emits one `[binary] FATAL: Run 063 local leaf certificate issuer root revoked …` line and exits 1 BEFORE `PqcStaticRootConfig` is built. The Run 062 pending set is explicitly NOT consulted. Independent of the Run 061 check; either failing fails closed. | `pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked`, wired in `main.rs` immediately after the Run 061 call site and BEFORE `pqc_config` is moved into the builder | RUN_063 |
| **Per-environment minimum activation-margin policy (Run 065).** A bundle whose declared `activation_height` (bundle-level OR per-active-root) falls in the half-open window `[current_height, current_height + margin)` fails closed at load with `TrustBundleActivationError::ActivationHeightBelowMinimumMargin`. A scheduled per-entry revocation whose `activation_height` is `Some(h)` and falls in the same window fails closed with `TrustBundleActivationError::RevocationActivationHeightBelowMinimumMargin`. Constants: DevNet `MIN_DEVNET_ACTIVATION_MARGIN = 0`, TestNet `MIN_TESTNET_ACTIVATION_MARGIN = 8`, MainNet `MIN_MAINNET_ACTIVATION_MARGIN = 32` (strict ordering DevNet < TestNet < MainNet). The reject window is half-open: bundles whose `activation_height` equals `current_height + margin` pass Run 065 and fall through to Run 057's "not yet reached" gate; bundles whose `activation_height` is strictly less than `current_height` are already-effective and are NOT retroactively rejected (snapshot-rejoin semantics). Per-entry revocations with `activation_height = None` are immediate and NEVER subject to Run 065 (preserves the emergency-revocation path). The policy runs AFTER signature / chain_id / environment / revocation structural validation and BEFORE Run 057's future-height gate, Run 055's sequence persistence, and Run 050's root merge — a rejected too-soon bundle does NOT create `pqc_trust_bundle_sequence.json` and does NOT update `loaded.active_roots`. `required_min_height = current_height.saturating_add(margin)` defends against `u64::MAX` wrap. | `pqc_trust_activation::check_min_activation_height_policy`, `MIN_{DEVNET,TESTNET,MAINNET}_ACTIVATION_MARGIN` constants, `ActivationPolicy::for_environment`; called from `pqc_trust_bundle::TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`; errors flow through the existing `TrustBundleError::Activation(..)` FATAL printer in `main.rs` with the static "No fallback to --p2p-trusted-root" marker | RUN_065 |
| **Validation-only reload-check is non-mutating (Run 069).** The hidden `--p2p-trust-bundle-reload-check <PATH>` flag drives `pqc_trust_reload::validate_candidate_bundle_full` over the candidate using the **same** Run 050/051/053/055/057/061/062/063/065 security pipeline as startup, BUT MUST NOT mutate `LivePqcTrustState` (Run 071), MUST NOT merge roots into the active trust set, MUST NOT call `check_and_update_sequence` (uses read-only `peek_sequence`), MUST NOT call `evict_all_sessions`, MUST NOT touch any `/metrics` family, and MUST NOT burn a sequence number on rejected or unapplied candidates. The node does NOT start in this mode (validates, prints `VERDICT=valid|invalid` + staged metadata, exits 0/1). Byte-and-mtime equality on the on-disk sequence file is asserted on every positive and every negative path. | `pqc_trust_reload::validate_candidate_bundle{,_full}`, `ValidatedCandidate`, `ReloadCheckError`, `ReloadCheckInputs`, `pqc_trust_sequence::peek_sequence`, `SequencePeekOutcome`; main.rs reload-check hook positioned BEFORE network-mode dispatch | RUN_069 |
| **Strict reload-apply ordering (Run 070).** Every live-apply on the operator-triggered path (both the Run 073 process-start hook and the Run 074 SIGHUP trigger) follows EXACTLY the order `validate → snapshot previous → swap → evict_sessions → commit_sequence`. Failures roll back: (i) validation failure produces no swap, no eviction, no sequence commit; (ii) swap failure leaves the old live state in place with no eviction, no sequence commit; (iii) eviction failure rolls back the live state via `swap_snapshot(previous)`, no sequence commit; (iv) sequence-commit failure rolls back the live state; if rollback itself fails AFTER a successful swap the outcome is the distinct fatal variant `ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed` (live trust state may be ahead of the on-disk record). On the Run 074 long-running path this fatal variant is the ONLY path that sends to the graceful-shutdown `shutdown_tx`; invalid candidates, eviction partial failures, and commit failures with successful rollback are all non-fatal and the node keeps running. | `pqc_trust_reload::{ApplyMode, ReloadApplyError, LiveTrustApplyContext, apply_validated_candidate{,_with_previous}, AppliedCandidate::applied_log_line}` | RUN_070, RUN_073, RUN_074 |
| **Live trust handle = `LivePqcTrustState` (Run 071).** The listener-side handshake verifier's `TrustedClientRoots` resolver AND the bidirectional `LeafCertRevocationList` revocation closure both read through `LivePqcTrustState::snapshot()`. Writers (Run 070 apply path through Run 073's `ProductionLiveTrustApplyContext`) replace the inner `Arc<LivePqcTrustSnapshot>` under a single short write lock — readers always observe an all-or-nothing snapshot transition; no torn read of active roots vs. revoked leaves is possible. At startup the handshake-verifier surface is byte-identical to pre-Run-071. | `pqc_live_trust::{LivePqcTrustState, LivePqcTrustSnapshot, initialize_from_loaded_bundle, snapshot, swap_snapshot}`; `P2pNodeBuilder::with_live_pqc_trust(...)` | RUN_071 |
| **Session-eviction invariant (Run 072).** Every successful live-apply call invokes `P2pSessionEvictor::evict_all_sessions(EvictionReason::TrustBundleReloadApply)` and consumes an `EvictionReport` satisfying `attempted == evicted + failed`. The concrete `TcpKemTlsP2pService::evict_all_sessions` drains the per-peer `PeerConnection` registry synchronously, drops outbound `tx` channels, and aborts per-peer read/write `JoinHandle`s. The four `qbind_p2p_session_eviction_*` counters render once each on `/metrics`. Selective per-peer retention is intentionally NOT implemented — v0 evicts all conservatively because old sessions may have authenticated under old roots/leaves. | `p2p_session_eviction::{EvictionReason, EvictionReport, EvictionError, P2pSessionEvictor}`, `p2p_tcp::TcpKemTlsP2pService::evict_all_sessions`, `metrics::P2pMetrics::record_session_eviction` | RUN_072 |
| **Process-start local reload-apply (Run 073).** When `--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path <PATH>` are supplied, the binary constructs `ProductionLiveTrustApplyContext` over the live `LivePqcTrustState` (Run 071) + a `NoActiveSessionsEvictor` (truthful zero-session report because no peer has connected at this point) + the `--data-dir`-derived sequence path, runs the full Run 070 apply pipeline, prints `AppliedCandidate::applied_log_line` (or the canonical `VERDICT=invalid …` line on a fail-closed branch), and exits 0/1. `ReloadApplyError::UnsupportedRuntimeContext` is removed from the local-operator-triggered path. The library boundary still surfaces `UnsupportedRuntimeContext` for callers that omit the apply context (defence-in-depth). | `pqc_live_trust_apply::{ProductionLiveTrustApplyContext, NoActiveSessionsEvictor}`; main.rs Run 073 hook block | RUN_073 |
| **Long-running SIGHUP live reload-apply (Run 074, **+ Run 114 ratification enforcement**).** When `--p2p-trust-bundle-live-reload-enabled` + `--p2p-trust-bundle-live-reload-path <PATH>` are supplied (required together; refused without `--p2p-trust-bundle <BASELINE-PATH>`), the binary installs a `tokio::signal::unix::signal(SignalKind::hangup())` listener that on each SIGHUP calls `LiveReloadController::try_trigger()`. The controller constructs a **fresh** `ProductionLiveTrustApplyContext` over the SAME live `LivePqcTrustState` the listener-side handshake verifier reads from + the live `TcpKemTlsP2pService` (upcast to `Arc<dyn P2pSessionEvictor>`) + the same `--data-dir`-derived sequence file, runs the full Run 070 apply pipeline, and surfaces a typed `LiveReloadOutcome { Applied | AlreadyInProgress | Invalid | Fatal }`. **Under Run 106 policy, the SIGHUP trigger additionally invokes the Run 105 / Run 103 bundle-signing-key ratification verifier BEFORE any snapshot, swap, eviction, or sequence commit: MainNet/TestNet always invoke (operators MUST supply `--p2p-trust-bundle-ratification <PATH>` or every SIGHUP is refused with the typed `Missing` failure); DevNet invokes only with `--p2p-trust-bundle-ratification-enforcement-enabled`. The sidecar JSON is re-read on every SIGHUP, so an operator can rotate the sidecar in-place between triggers without restarting the node. Sidecar I/O / parse failures fail closed before any mutation. Context-build failure under `Invoke` (missing `--genesis-path`, missing genesis-authority block, malformed sidecar at construction time) is FATAL: the SIGHUP handler is NOT installed; the node continues running on the baseline trust bundle.** Concurrent SIGHUPs are serialized in-process by an `Arc<AtomicBool>` CAS guard — every second-or-later trigger returns `AlreadyInProgress` without re-entering validation. Only the `Fatal` arm (`SequenceCommitFailedRollbackAlsoFailed`) sends to `shutdown_tx`. Six `qbind_p2p_trust_bundle_live_reload_*` counters/gauge bump only on real trigger paths and render exactly once on `/metrics`. Both flags are hidden from `--help`. Disabled by default. | `pqc_live_trust_reload::{LiveReloadConfig, LiveReloadController, LiveReloadOutcome, LiveReloadRatificationConfig}`; main.rs `spawn_run074_live_reload_task` (`#[cfg(unix)]`); `metrics::P2pMetrics::live_reload_*` | RUN_074, RUN_114 |
| **Invalid hot-reload candidate never mutates state (Runs 069/070/073/074).** Across reload-check, reload-apply, and long-running live-reload paths, an invalid candidate (any failure class: signature, chain_id, environment, rollback, equivocation, too-soon activation, revoked-local-leaf, revoked-local-issuer-root, eviction partial failure when rollback succeeds) leaves the on-disk sequence file's BYTES AND mtime unchanged AND leaves `LivePqcTrustState`'s snapshot at the baseline `Arc`. The node remains running on Run 074 paths. | All Run 069/070/073/074 integration tests; `assert_seq_file_unchanged` snapshots; live-state-fingerprint equality checks | RUN_069/070/073/074 |
| **No peer-supplied / gossiped / admin-API / filesystem-watcher hot reload (Runs 069–074 boundary).** Every hot-reload candidate is read from a local file path under operator control. Run 074 ships SIGHUP only — no admin RPC, no HTTP/JSON-RPC trigger, no inode-watch on the candidate path. Bundle propagation between peers, BundleAnnounce/BundleRequest gossip, and remote admin mutation surfaces are NOT implemented and remain C4-OPEN (§10). | `cli.rs` (flags hidden, no network/admin surface); `main.rs::spawn_run074_live_reload_task` (`SignalKind::hangup()` only) | RUN_074 |

If any procedure in this runbook appears to require violating one
of the above, the procedure is wrong, not the implementation. Open
a defect and update `docs/whitepaper/contradiction.md`.

---

## 2. Trust model and roles

The trust lifecycle separates **five** distinct authorities. They
MUST be held by different keys, and operationally SHOULD be held
by different humans / hardware / environments where possible.

### 2.1 Authorities and key separation

| Authority | What it can do | What it MUST NOT also be |
|---|---|---|
| **Transport root authority** | Owns the ML-DSA-44 root signing key. Signs validator leaf delegation certs (`NetworkDelegationCert`). | A bundle-signing key. A validator leaf KEM secret. A validator consensus signing key. |
| **Bundle-signing authority** | Owns the ML-DSA-44 bundle-signing secret. Signs the canonical trust-bundle preimage. The `signing_key_id` it produces MUST NOT equal any transport `root_id`. Distinct domain separator (`QBIND:pqc-trust-bundle-signature:v1`) prevents preimage collision with transport certs. | A transport root key. A validator leaf KEM secret. A validator consensus signing key. |
| **Validator node operator** | Holds the validator's leaf delegation cert (`v<N>.cert.bin`) and the matching ML-KEM-768 leaf secret (`v<N>.kem.sk.bin`). Holds the validator consensus signing key (separate `--signer-keystore-path` ML-DSA-44 keystore). Runs the `qbind-node` binary. Consumes the trust bundle. | A transport root signing key. A bundle-signing secret. A revocation authority key. |
| **Bundle publisher / distributor** | Distributes the latest `trust-bundle.json` artifact and the current `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` lines out-of-band to validator operators. Read-only with respect to keys: never possesses the bundle-signing secret. | Bundle-signing authority. Transport root authority. |
| **Incident responder / emergency revocation authority** | Authorised to mint and publish a `sequence=N+1` bundle that revokes a compromised root or leaf fingerprint **using the existing bundle-signing authority's key**. Does NOT add new signing keys; uses the already-distributed signing authority. | A new bundle-signing key holder (would be a different rotation, not a revocation). |
| **Auditor** | Read-only access to bundles, persistence records, evidence logs, and `/metrics`. | Any signing authority. |

Helper-generated keys (`devnet_pqc_root_helper`,
`devnet_pqc_trust_bundle_helper`) are **DevNet-ephemeral** and are
generated fresh in memory; the helpers never write the root or
bundle-signing **secret** to disk. They are **not** production
custody. Production root and bundle-signing keys MUST be generated
on, and never leave, an offline / HSM-backed host (§3, §4).

### 2.2 Why this separation matters

- A transport root key signs **per-validator delegation certs**.
  Reusing it as a bundle-signing key would let the entity that
  issues a validator's transport identity also unilaterally change
  the set of trusted networks roots — that is a privilege merger
  forbidden by `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys`
  (collision check between `signing_key_id` and any `roots[].root_id`).
- A bundle-signing key authorises **policy** (which roots are
  trusted, which leaves are revoked, at what activation height).
  Reusing it as a validator consensus signing key would conflate
  consensus participation with trust-policy authority.
- A validator leaf KEM secret authorises **traffic** (this peer
  may complete KEMTLS handshakes). It is per-validator and is
  rotated independently of roots.

---

## 3. Artifact inventory

For each production artifact: where it lives, who may access it,
online/offline classification, rotation cadence, emergency
handling, backup/recovery notes, logging rules.

### 3.1 Transport root public key

- **Format:** 1312 bytes ML-DSA-44 public key, lowercase hex.
- **Where:** distributed to all validators as part of the
  signed `trust-bundle.json` under `roots[i].root_pk` AND on the
  CLI startup banner as the safe-fingerprint
  `id=<8 hex>.. suite=100 fp=<8 hex>` (see Run 037 banner).
- **Online/offline:** public; may be distributed online; HASH /
  fingerprint MUST be cross-checked against an out-of-band source
  before first install on a new validator (§7 promotion checklist).
- **Rotation cadence:** at least every 12 months; sooner under any
  cryptographic transition or operator-suspected compromise.
- **Emergency:** §6.B.
- **Backup/recovery:** any number of identical copies; the
  authoritative copy is whichever the signed bundle declares.
- **Logging:** safe to log fingerprint (`fp=<8 hex>`); never log
  the full key in raw form in production logs (the existing Run
  037 banner is the canonical safe form).

### 3.2 Transport root signing secret

- **Format:** ML-DSA-44 secret key.
- **Where:** an offline / HSM-backed host. **Never** written to a
  validator node's disk. The DevNet helpers explicitly mint this
  in memory and never persist it (`mint_devnet_root`).
- **Online/offline:** offline only. SHOULD live on a physically
  airgapped or HSM-protected host.
- **Access:** transport root authority (§2.1). Multi-party control
  (m-of-n) is RECOMMENDED but not enforced by the binary.
- **Rotation cadence:** at least every 12 months (must precede the
  validator leaf cert rotation it enables).
- **Emergency:** treat any suspected compromise as a §6.B incident
  and a §6.A rotation simultaneously.
- **Backup/recovery:** HSM-vendor-specific encrypted backups; no
  plaintext backups; recovery requires multi-party authorisation.
- **Logging:** **never** log the secret in any form. The DevNet
  helpers' "never persisted" property is the production target.

### 3.3 Bundle-signing public key

- **Format:** 1312 bytes ML-DSA-44 public key. Distributed as a
  `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` line where
  - `KEYID` is exactly 64 lowercase hex chars (32 bytes), MUST NOT
    collide with any transport root id;
  - `100` is the ML-DSA-44 suite id;
  - `HEXPK` is the lowercase hex public key.
- **Where:** distributed to all validators out-of-band; supplied
  on the `qbind-node` command line. Multiple entries are accepted
  during overlap windows.
- **Online/offline:** public; the bundle-signing public KEY is
  online.
- **Rotation cadence:** every 6–12 months, or on suspected
  compromise of the corresponding secret.
- **Emergency:** §6.D.
- **Backup/recovery:** same distribution channel as the bundle.
- **Logging:** safe to log `signing_key_id` (the verifier prints
  `signature=verified(signing_key_id=<8 hex>..)` — see Run 050/051
  banner).

### 3.4 Bundle-signing secret

- **Format:** ML-DSA-44 secret key.
- **Where:** offline / HSM-backed host. Separate from the
  transport root authority's host where operationally feasible.
- **Online/offline:** offline only. SHOULD be HSM-backed in
  MainNet.
- **Access:** bundle-signing authority + incident responder.
- **Rotation cadence:** 6–12 months; immediately on suspected
  compromise.
- **Emergency:** §6.D plus a separate §6.B revocation if the
  compromise window may have produced rogue bundles.
- **Backup/recovery:** HSM-vendor-specific encrypted backups; no
  plaintext backups.
- **Logging:** **never** log the secret in any form.

### 3.5 Validator leaf delegation certificate

- **File:** `v<N>.cert.bin` (the encoded `NetworkDelegationCert`
  produced by `pqc_devnet_helper::issue_leaf_delegation_cert` +
  `encode_cert` in DevNet; in production the same wire format
  produced by the offline transport root authority).
- **Where:** validator node disk; loaded via `--p2p-leaf-cert`.
- **Online/offline:** lives online on the validator host (the
  validator must present it on every handshake).
- **Access:** validator node operator. The corresponding KEM
  secret (§3.6) MUST share the same access boundary.
- **Rotation cadence:** every 3–12 months, AND on root rotation,
  AND on validator-host compromise.
- **Emergency:** §6.C (leaf rotation) or §6.B (root revocation
  if the compromise extends to the root).
- **Backup/recovery:** the leaf cert is public; the operator
  re-runs the issuance flow against the current transport root.
- **Logging:** safe to log the cert fingerprint (8-byte SHA3 prefix
  used by `cert_leaf_fingerprint_hex`); never log the matching KEM
  secret.

### 3.6 Validator leaf KEM secret

- **File:** `v<N>.kem.sk.bin` (mode `0o600` on the helper output;
  same discipline expected on production validator hosts).
- **Where:** validator node disk; loaded via `--p2p-leaf-cert-key`.
- **Online/offline:** online on the validator host only.
- **Access:** validator node operator only.
- **Rotation cadence:** with every leaf cert rotation.
- **Emergency:** §6.C; if a validator's KEM secret is suspected
  compromised AND the cert may still be presented by an attacker,
  also publish a `revoked_leaf_fingerprints[]` entry (§6.C).
- **Backup/recovery:** treated as a fresh-generation artifact; if
  lost, re-issue a new leaf cert + KEM secret (§6.C).
- **Logging:** **never** log raw bytes. The helper's `0o600` mode
  is the production target.

### 3.7 Trust bundle JSON

- **File:** `trust-bundle.json`, the artifact consumed by
  `--p2p-trust-bundle`. Schema pinned by
  `pqc_trust_bundle::TrustBundle` (`bundle_version = 1`).
- **Fields operators MUST set:** `bundle_version`, `environment`,
  `chain_id` (MUST equal the runtime chain id — RUN_053),
  `generated_at`, `valid_from`, `valid_until`, `sequence`,
  `roots[]`, `revocations[]`, optional `activation_height` /
  `activation_epoch` (RUN_057), `signature` (RUN_051; required on
  TestNet/MainNet).
- **Where:** distributed by the bundle publisher; consumed by
  every validator.
- **Online/offline:** public.
- **Rotation cadence:** at least one new `sequence` for every
  policy change (root added, root retired, root revoked, leaf
  fingerprint revoked, activation declared). Sequence MUST be
  strictly monotonic per `(environment, chain_id)` trust domain
  (RUN_055).
- **Logging:** safe to log canonical fingerprint and `sequence`.
  The Run 050/051 banner is the canonical form.

### 3.8 Sequence persistence file

- **File:** `<data_dir>/pqc_trust_bundle_sequence.json`, schema
  pinned by `pqc_trust_sequence` (`record_version = 1`,
  `environment`, `chain_id`, `highest_sequence`,
  `bundle_fingerprint`, `updated_at_unix_secs`).
- **Where:** per-validator node disk.
- **Online/offline:** online (state must be readable at every
  startup).
- **Lifecycle:** written ONLY by `check_and_update_sequence`
  (atomically), AFTER signature / chain_id / activation gate pass.
- **Backup/recovery:** OPERATORS MUST NOT manually edit this file.
  A corrupted file fails the node closed at startup; the **only**
  supported recovery is to investigate why it was corrupted, then
  replace the entire `--data-dir` from a clean snapshot of the
  same trust domain (i.e. another honest validator's persisted
  record at the same or higher sequence). Never roll the
  `highest_sequence` field backwards manually. Never set
  `bundle_fingerprint` manually. Run 055 explicitly never silently
  deletes or truncates this file (RUN_056 Smoke 6).
- **Logging:** safe to log `highest_sequence` and the canonical
  fingerprint. Never log the raw file path with privilege material.

### 3.9 Revocation entries

- **Where:** the `revocations[]` array on the `trust-bundle.json`,
  with `root_id`, optional `leaf_cert_fingerprint`, `reason`,
  `effective_from` (Unix seconds), and (Run 062) optional
  `activation_height` (`Option<u64>`).
- **Active vs pending (Run 062).** Resolution rule at bundle load:
  - entry is **ACTIVE** iff `effective_from <= validation_time`
    AND (`activation_height` is absent OR
    `current_height >= activation_height`);
  - entry is **PENDING** iff signature-valid + `effective_from`
    satisfied but `activation_height > current_height` (or no
    runtime height source is available);
  - entries with `effective_from > validation_time` remain neither
    active nor pending (the wall-clock validity-window layer keeps
    them off both surfaces, exactly as in Run 050).
  Pending entries are surfaced on `pending_revoked_root_ids` /
  `pending_revoked_leaf_fingerprints` and on the new
  `qbind_p2p_pqc_trust_bundle_revocations_*_pending` gauges, but
  are NOT enforced anywhere (not in `active_roots`, not in the
  Run 061 startup self-check, not in the Run 052 peer-handshake
  context, not in the Run 063 issuer-root startup self-check).
- **`current_height` source (Run 062, mirrors Run 057, consumed
  by Run 065).** If `--restore-from-snapshot` is used,
  `current_height` is the restore baseline `snapshot_height`.
  Otherwise `current_height` is `0` at startup. There is no
  production runtime epoch source; per-entry `activation_epoch`
  is intentionally NOT supported (Run 057 boundary stands). The
  same `Option<u64>` `current_height` source feeds the Run 065
  minimum-margin policy.
- **Bundle-level vs per-entry activation.** DO NOT confuse:
  - bundle-level `activation_height` (Run 057) gates whether the
    whole bundle may take effect (sequence persist + root merge);
  - per-entry revocation `activation_height` (Run 062) gates only
    whether one specific revocation is enforced once the bundle
    has already loaded and persisted.
  A bundle that does NOT pass the bundle-level activation gate
  never publishes ANY revocation (active or pending). A bundle
  that DOES pass the bundle-level gate publishes its revocations
  according to the per-entry rule above.
- **Sequence interaction (Run 055 + Run 062).** A scheduled
  revocation bundle MAY advance `highest_sequence` immediately
  (the bundle itself is active and signature-valid); its
  scheduled revocation entries remain PENDING until each entry's
  own `activation_height` is reached. The persisted sequence
  record never rolls back on activation.
- **Operational recommendation:** use `activation_height` only for
  scheduled revocations where operators can safely coordinate a
  cutover (and have already issued replacement credentials to any
  validator that would otherwise fail closed at activation).
  Emergency-compromise revocations SHOULD be immediate (omit
  `activation_height`; `activation_height = None` is exempt from
  the Run 065 minimum-margin policy and remains available on
  MainNet for emergency response). Scheduled revocations with
  `activation_height = Some(h)` on TestNet/MainNet MUST respect
  the Run 065 minimum margin (§3.10): `h >= current_height +
  minimum_activation_margin` or the bundle is rejected at load
  with `RevocationActivationHeightBelowMinimumMargin`.
- **Logging:** safe to log root_id prefix + reason; never log
  the `leaf_cert_fingerprint` of a compromised validator more
  noisily than the rest of the run log requires.

### 3.10 Activation height / epoch field

- **Where:** `activation_height` / `activation_epoch` on the bundle
  envelope and on each root entry (RUN_057). Per-entry revocations
  also carry an optional `activation_height` (RUN_062).
- **Semantics:** inclusive `current >= required`. Missing field =
  no restriction (subject to the Run 065 minimum-margin policy
  below for `activation_height`).
- **Minimum-margin policy (Run 065).** The binary enforces a
  per-environment minimum activation margin on the bundle-level
  `activation_height`, on each active root's `activation_height`,
  and on every per-entry revocation whose `activation_height` is
  `Some(_)`:
  - DevNet: `MIN_DEVNET_ACTIVATION_MARGIN = 0` blocks.
  - TestNet: `MIN_TESTNET_ACTIVATION_MARGIN = 8` blocks.
  - MainNet: `MIN_MAINNET_ACTIVATION_MARGIN = 32` blocks.
  The reject window is the half-open interval
  `[current_height, current_height + margin)`:
  `activation_height >= current_height + margin` passes Run 065
  (and then reaches Run 057's "not yet reached" gate until
  `current_height` catches up); `activation_height < current_height`
  is already-effective and not retroactively rejected (preserves
  snapshot-rejoin semantics).
- **Operator policy:** REQUIRED for every planned rotation on
  TestNet/MainNet; SET `activation_height` to a height comfortably
  past the current finalised height. `activation_height ==
  current_height` is rejected at load on TestNet/MainNet by the
  Run 065 policy (and is the intentional `--data-dir`/sequence-
  safe behaviour: a rejected too-soon bundle does not burn the
  persisted sequence number).
- **Emergency immediate revocation.** Per-entry revocations whose
  `activation_height = None` are NEVER subject to the Run 065
  minimum-margin policy and remain available on every environment,
  including MainNet, regardless of `current_height` (§6.B / §6.C
  variant 2).
- **Boundary:** `activation_epoch` was historically rejected with
  `CurrentEpochUnavailable` because no canonical runtime epoch source
  was wired into `ActivationContext.current_epoch` (Run 057 / Run 091
  boundary). **As of Run 098 this is partially resolved**: every
  production trust-bundle activation surface in `qbind-node` (startup
  `--p2p-trust-bundle` load, `--p2p-trust-bundle-reload-check`,
  `--p2p-trust-bundle-reload-apply-path`,
  `--p2p-trust-bundle-peer-candidate-check`, the SIGHUP live-reload
  trigger, and the live peer-candidate wire dispatcher) now reads
  `meta:current_epoch` from the canonical Run 093
  `<data_dir>/consensus` `ConsensusStorage` surface (via the narrow
  helper `qbind_node::pqc_trust_activation_epoch`). When that surface
  carries `CommittedEpoch(n)` — written by a real Run 094 / 095 / 096
  reconfig transition or by a Run 097 restored snapshot — a bundle
  declaring `activation_epoch ≤ n` activates honestly; a bundle
  declaring `activation_epoch > n` is rejected with
  `ActivationEpochNotYetReached`. When the surface carries no
  committed epoch (fresh genesis, old snapshot without epoch, no
  `--data-dir`, or a storage read error), bundles declaring any
  `activation_epoch` continue to be rejected fail-closed with
  `CurrentEpochUnavailable` — **missing epoch is never coerced into
  `Some(0)`**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md` and
  `crates/qbind-node/tests/run_098_activation_epoch_canonical_wiring_tests.rs`.
  Operator implications:
  - On a node that has committed at least one canonical reconfig epoch
    (or restored from a Run-097 snapshot carrying canonical epoch),
    `activation_epoch`-bearing bundles are now safe to ship.
  - On fresh genesis / pre-reconfig / restored-from-old-snapshot
    nodes, bundles MUST omit `activation_epoch` or they will be
    rejected.
  - Run 065 per-environment minimum-margin policy still applies only
    to `activation_height`. There is no minimum-margin policy on the
    epoch axis as of Run 098.
  - **Run 099 release-binary evidence.** As of Run 099, the
    fail-closed `CurrentEpochUnavailable` boundary is additionally
    proven end-to-end on the production release `qbind-node`
    binary's process logs for three of the six activation surfaces
    (startup `--p2p-trust-bundle`, `--p2p-trust-bundle-reload-check`,
    and `--p2p-trust-bundle-peer-candidate-check`) on a fresh-genesis
    DevNet `--data-dir`. See
    `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_099.md` and the harness
    `scripts/devnet/run_099_activation_epoch_release_binary_evidence.sh`.
    The other three surfaces (`--p2p-trust-bundle-reload-apply-path`,
    SIGHUP live reload on a running node, live peer-candidate wire
    dispatcher) remain harness-bound to integration tests; Run 099
    does NOT claim release-binary process-log coverage for them.
  - **Operator alert: storage read failure on `<data_dir>/consensus`.**
    A canonical storage I/O error at activation time is logged as
    `[binary] Run 098: WARNING: failed to read canonical
    meta:current_epoch for startup bundle activation: …` and mapped
    to `current_epoch = None`. For bundles declaring `activation_epoch`
    this is fail-closed (CurrentEpochUnavailable). For bundles that
    do NOT declare `activation_epoch` the warning is informational
    only — activation proceeds because the epoch axis is not
    consulted (intentional; pinned by
    `run098_bundle_without_activation_epoch_unchanged_by_canonical_wiring`).
    Operators MUST treat this warning line as an alertable event in
    production and investigate canonical storage health before the
    next bundle ratification.

### 3.11 Chain_id field

- **Where:** `chain_id` on the bundle envelope. Constants live in
  `crates/qbind-types/src/primitives.rs` and are surfaced through
  `NetworkEnvironment::chain_id()`.
- **Operator policy:** MUST be set to the correct chain_id for the
  target environment on every signed TestNet/MainNet bundle. RUN_053
  pinned the crosscheck and RUN_059 Smoke 5 proves the live
  release binary rejects a mismatched chain_id even on a validly
  signed bundle.

### 3.12 Environment field

- **Where:** `environment` on the bundle envelope. Lowercase
  string (`devnet` | `testnet` | `mainnet`).
- **Operator policy:** MUST match the runtime `--env` exactly. A
  bundle for the wrong environment fails closed (RUN_050).

---

## 4. Key generation and custody

### 4.1 Transport root key generation

1. On the offline / HSM-backed transport root host:
   - Generate an ML-DSA-44 keypair using the same primitive as
     `MlDsa44Backend::keygen` (`crates/qbind-crypto/src/ml_dsa44.rs`).
     The DevNet helper `devnet_pqc_root_helper` is the
     reproducibility reference; production replaces the in-memory
     mint with an HSM-backed mint.
   - Compute `root_key_id = sha3_256_tagged("QBIND:pqc-root-id:v1",
     root_pk)` (matches the helper's `mint_devnet_root` shape and
     the `pqc_root_config::PqcTrustedRoot.root_key_id` field).
   - Compute `fp = sha3_256(root_pk)[..8]` for the safe banner
     fingerprint.
2. Record `root_key_id`, `root_pk` (hex), and `fp` in an
   air-gapped artifact-inventory log signed by two custodians.
3. **Never** copy `root_sk` to disk; keep it inside the HSM /
   offline host. The DevNet helper's "never persisted" invariant
   is the production target.

### 4.2 Bundle-signing key generation

Identical to §4.1 but on a **different** host / HSM context so the
two authorities cannot be conflated. The resulting `signing_key_id`
MUST NOT equal any `root_id` (the binary refuses startup if they
collide — pinned by `main.rs` and
`pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys`).

### 4.3 Validator leaf cert issuance

Performed by the transport root authority for each validator:

1. Validator operator produces an ML-KEM-768 keypair on the
   validator host (`MlKem768Backend::generate_keypair`); sends the
   public key out-of-band to the root authority.
2. Root authority mints a `NetworkDelegationCert` (see
   `pqc_devnet_helper::issue_leaf_delegation_cert` for the
   reference shape) carrying:
   - `validator_id` for the target validator;
   - `root_key_id` of the issuing root;
   - `leaf_kem_pk` (the validator's KEM public key);
   - `not_before` / `not_after` validity window (Run 045
     enforced on the binary path);
   - ML-DSA-44 signature by the transport root secret.
3. Root authority returns `v<N>.cert.bin` to the validator (the
   secret never leaves the offline / HSM host).
4. Validator operator places `v<N>.cert.bin` and
   `v<N>.kem.sk.bin` (mode `0o600`) under the validator's data
   directory.

### 4.4 Custody rules

| Rule | Why |
|---|---|
| Transport root secret never on a validator host. | Prevents root compromise on a validator-host compromise. |
| Bundle-signing secret never on a validator host. | Same. |
| Bundle-signing key host distinct from transport root host where feasible. | Defence in depth: a single compromise does not yield both authorities. |
| Validator leaf KEM secret only on its own validator host, mode `0o600`. | Prevents one validator-host compromise from yielding another validator's traffic identity. |
| No private key bytes appear in any log or evidence artifact. | RUN_037 through RUN_059 invariant. The DevNet helpers' "never persisted, never logged" property is the production target. |
| Multi-party (m-of-n) authorisation for any production root or bundle-signing operation. | Operator policy; not enforced by the binary today. |

---

## 5. Per-environment policy

### 5.1 DevNet

- **Bundles:** unsigned bundles ARE allowed by the binary
  (`TrustBundle::validate_at_with_signing_keys` accepts them on
  DevNet, refuses them on TestNet/MainNet — RUN_050/051).
- **Convenience helpers:** `devnet_pqc_root_helper` and
  `devnet_pqc_trust_bundle_helper` are the supported way to mint
  ephemeral roots, leaf certs, and bundles. They are explicitly
  **NOT** production custody (they generate keys in memory and
  never persist secrets).
- **Sequence persistence:** Run 055 applies on DevNet exactly as
  on TestNet/MainNet; rollback / equivocation / corrupt-file
  fail-closed semantics are preserved (RUN_055/056).
- **Activation gating:** the `activation_height` field is
  honoured on DevNet (RUN_057/058 smokes were DevNet).
- **Minimum activation-margin (Run 065):**
  `MIN_DEVNET_ACTIVATION_MARGIN = 0` blocks. This preserves the
  DevNet immediate-cutover shape used by every Run 050–064 DevNet
  smoke: `activation_height = current_height` (and
  `activation_height = 0`) remain accepted on DevNet.
- **Operators MUST NOT** treat any DevNet helper output as
  production-safe material.

### 5.2 TestNet

- **Signed bundles required.** Unsigned bundles fail closed at
  load.
- **`--p2p-trust-bundle-signing-key` required** when
  `--p2p-trust-bundle` is supplied (`main.rs` enforces this).
- **Sequence persistence required.** Operators MUST configure
  `--data-dir` so the persistence file is written; running on
  TestNet without `--data-dir` is unsupported.
- **`chain_id` MUST match TestNet** (`0x51424E4454535400`). RUN_053
  pinned the crosscheck.
- **Activation gating SHOULD be used** for planned rotations: set
  `activation_height` to a height past the current finalised
  height so every honest validator persists the bundle before it
  takes effect.
- **Minimum activation-margin (Run 065):**
  `MIN_TESTNET_ACTIVATION_MARGIN = 8` blocks. Every bundle whose
  bundle-level `activation_height`, per-active-root
  `activation_height`, or per-entry revocation `activation_height`
  (when `Some(_)`) falls in `[current_height, current_height + 8)`
  is rejected at load with the Run 065 FATAL. Operators MUST set
  `activation_height >= current_height + 8` on TestNet; emergency
  revocations may instead omit `activation_height` (immediate).
- **`activation_epoch` MUST NOT be set** (Run 057 boundary).
- **Negative smokes expected before promotion to MainNet:** see
  §7 promotion checklist.

### 5.3 MainNet

All TestNet requirements PLUS:

- **Bundle-signing keys MUST be offline or HSM-backed.** The
  ephemeral in-memory keys used by the DevNet helpers are not
  acceptable for MainNet.
- **Authority and ratification (forward-looking, Run 100 spec).**
  The operator-supplied `--p2p-trust-bundle-signing-key` set is the
  *candidate* set today. Run 100
  (`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`) specifies
  the production-grade authority and ratification model that
  selects the *authorized* subset on MainNet once Run 102 lands:
  initial production authority comes from a genesis configuration
  file bound by a boot-time cryptographic hash (NOT from Rust
  source-code constants); bundle-signing keys are authorized by
  typed, PQC-signed, deterministically-encoded ratification
  objects bound to `(chain_id, environment, genesis_hash,
  authority_epoch)`; anti-rollback is enforced through a new
  `<data_dir>/pqc_authority_state.json` file with restore
  semantics mirroring Run 097's snapshot epoch parity; emergency
  revocations bypass Run 065 minimum margin. **Run 100 is design
  only — none of the above is implemented today.** Until Run 102
  ships, MainNet operators MUST continue to distribute the
  bundle-signing key set out-of-band and verify it against the
  chain's published canonical authority root by hand.
- **Static CLI roots MUST NOT be mixed with bundles.** `main.rs`
  rejects `--p2p-trust-bundle` and `--p2p-trusted-root` being
  supplied together on TestNet/MainNet (Run 050/051 invariant).
- **No unsigned bundle.** RUN_059 Smoke 2 proves the live release
  binary rejects this on MainNet.
- **No fallback.** Every Run 050–059 negative smoke proves the
  release binary exits before merging any root from any source on
  bundle failure.
- **Recommended minimum activation-height margin:** set
  `activation_height = last_finalised_height + N` where N is the
  expected maximum operator rollout window. Run 065 enforces a
  hard floor of `MIN_MAINNET_ACTIVATION_MARGIN = 32` blocks on
  MainNet: every bundle whose bundle-level `activation_height`,
  per-active-root `activation_height`, or per-entry revocation
  `activation_height` (when `Some(_)`) falls in
  `[current_height, current_height + 32)` is rejected at load
  with the Run 065 FATAL `pqc trust-bundle minimum activation-
  height policy violation (… environment=mainnet, …
  minimum_margin=32, required_min_height=<current+32>); …
  Reschedule the bundle with activation_height >= <current+32>`.
  Operators MAY (and SHOULD) choose `N` strictly greater than 32
  for additional operator-rollout headroom; 32 is the binary
  floor, not the operator target. Emergency revocations remain
  available without `activation_height` (immediate).

---

## 6. Workflows

Every workflow below preserves the §1.3 invariants. Each step is
either an offline / HSM action (§3.2, §3.4) or a CLI action on an
operator workstation / validator. **No step requires editing the
sequence persistence file by hand.**

### 6.A Normal transport root rotation

Goal: introduce a new transport root and retire the old one with
zero handshake outages.

Preconditions:

- Current bundle sequence = N, active root R_old, signed by
  bundle-signing key BSK.
- All validators are running on a `--data-dir` whose persistence
  record has `highest_sequence = N` and a current chain_id.

Steps:

1. **Mint R_new offline** (§4.1). Record `root_id_new`, `root_pk_new`,
   `fp_new` in the artifact-inventory log.
2. **Issue new leaf certs for every validator under R_new** (§4.3).
   Distribute each `v<N>.cert.bin` to its validator operator.
   Validators DO NOT install them on disk yet.
3. **Mint overlap bundle (sequence = N+1) signed by BSK**:
   - `roots[]` = `[R_old(status=active), R_new(status=active)]`.
   - `revocations[]` unchanged.
   - `activation_height` = current_finalised_height + safety margin
     (§5.3; MUST be `>= current_finalised_height + 8` on TestNet
     and `>= current_finalised_height + 32` on MainNet, the
     binary-enforced Run 065 floors).
   - `valid_from` / `valid_until` as policy dictates.
   - `chain_id` MUST match the runtime chain id (§3.11).
   - Sign with BSK offline.
4. **Publish bundle N+1** to all validators. Each validator restarts
   with `--p2p-trust-bundle <N+1.json>` and the unchanged
   `--p2p-trust-bundle-signing-key BSK_ID:100:BSK_PK`. The binary
   prints the Run 057 activation banner and the Run 055 sequence
   persistence banner (`upgraded previous_sequence=N -> new_sequence=N+1`).
5. **Wait until `current_height >= activation_height`** on the live
   network. The activation gate now passes; both R_old and R_new
   are in the active trust set.
6. **Roll validators to leaf certs under R_new**: each validator
   operator restarts with `--p2p-leaf-cert v<N>_new.cert.bin
   --p2p-leaf-cert-key v<N>_new.kem.sk.bin` while bundle N+1
   remains the active bundle. Existing handshakes with R_old
   leaves still verify (both roots are active).
7. **Mint retire bundle (sequence = N+2) signed by BSK**:
   - `roots[]` = `[R_old(status=retired), R_new(status=active)]`.
   - `revocations[]` unchanged.
   - `activation_height` = current_finalised_height + margin.
   - Sign with BSK offline.
8. **Publish bundle N+2.** Validators restart and persist sequence
   N+2. R_old becomes ineligible for cert verification (RUN_050:
   `RootStatus::Retired` is not acceptable for verification).
9. **Optional bundle N+3 (revoke R_old):** mint a bundle with
   `roots[]` = `[R_old(status=revoked), R_new(status=active)]` and
   a `revocations[]` entry for R_old with `effective_from = now`.
   Use this if the rotation reason was compromise rather than
   scheduled rotation. For scheduled rotation, the operator MAY
   instead set the `revocations[]` entry's `activation_height`
   (Run 062) to a future block height comfortably past the point
   by which every validator is expected to have rolled to an
   R_new leaf — until that height the entry is PENDING and not
   enforced, so the cutover is observable on the
   `qbind_p2p_pqc_trust_bundle_revocations_root_pending` gauge
   before any validator fails closed at startup.

**Run 063 interaction at root retire/revoke.** Once a bundle that
**actively** revokes R_old is loaded, any validator still booting
with a `--p2p-leaf-cert` chained to R_old will fail closed at
startup (Run 063 local-issuer-root self-check) BEFORE reaching the
peer-handshake layer. Operators MUST therefore confirm that every
validator has rolled to R_new leaf material BEFORE the R_old
revocation entry's `activation_height` becomes satisfied. PENDING
root revocations do NOT trip the Run 063 check (the helper reads
the **active** `revoked_root_ids` set only).

Rollback proofs:

- After any validator persists sequence N+1, re-loading the old
  sequence N bundle fails closed at
  `pqc_trust_sequence::check_and_update_sequence` (RUN_055,
  RUN_056 Smoke 3). The release binary refuses to start and exits
  1 BEFORE merging any root.
- Equivocation: if an attacker mints a different "sequence N+1"
  bundle with a distinct fingerprint, the persisted record's
  `bundle_fingerprint` mismatch fails closed (RUN_056 Smoke 5).

### 6.B Emergency transport root revocation

Goal: revoke a compromised root R_bad as quickly as the bundle
distribution channel allows, without silently downgrading any
fail-closed check.

Preconditions:

- Current bundle sequence = N.
- A new replacement root R_new SHOULD already be in active rotation
  (i.e. an earlier §6.A produced bundle N including R_new). If
  R_new is not yet rotated in, run §6.A in parallel; emergency
  revocation BEFORE replacement causes a liveness outage for
  validators whose only leaf cert chains to R_bad.

Steps:

1. **Mint revocation bundle (sequence = N+1) signed by BSK**:
   - `roots[]` = `[R_bad(status=revoked), R_new(status=active),
     …]`.
   - `revocations[]` += `{root_id: R_bad, reason: "compromise",
     effective_from: now, activation_height: None}`.
     `activation_height = None` (immediate) is the correct emergency
     shape and is NEVER subject to the Run 065 minimum-margin
     policy regardless of environment.
   - The bundle-level `activation_height` MAY be omitted entirely
     for the fastest emergency rotation. If set on TestNet/MainNet,
     it MUST satisfy the Run 065 floor (`>= current_finalised_height
     + 8` on TestNet, `+ 32` on MainNet); a bundle-level
     `activation_height = current_finalised_height` on MainNet is
     rejected at load by the Run 065 policy. Omitting the
     bundle-level `activation_height` (no restriction) is the
     emergency-correct shape because it makes the new bundle
     effective at every restarted validator immediately while
     preserving the per-entry immediate revocation.
   - Sign with BSK offline.
2. **Publish bundle N+1.** Validators restart with the new bundle.
   Any validator whose leaf cert chains to R_bad MUST already have
   a replacement leaf cert under R_new on disk; otherwise that
   validator stops being able to complete KEMTLS handshakes (it
   will not silently fall back — RUN_037/038/039/040).
3. **No `--p2p-trusted-root` fallback.** Operators MUST NOT add a
   `--p2p-trusted-root` line to "bridge" validators that have not
   yet rolled to R_new; that combination is refused with
   `--p2p-trust-bundle` on TestNet/MainNet, and would not bypass
   the revocation anyway.
4. **No Dummy crypto fallback.** Under
   `--p2p-pqc-root-mode pqc-static-root`, the registered crypto
   provider remains real `MlDsa44SignatureSuite` / `MlKem768Backend`
   / `ChaCha20Poly1305Backend` (RUN_037/039/040/041).
5. **Document the liveness tradeoff honestly.** If a non-trivial
   fraction of validators were chained to R_bad and had not yet
   completed the §6.A leaf rotation, emergency revocation WILL
   cause those validators to drop out until they roll to R_new
   leaves. This is the **correct** fail-closed behaviour.
   Run 063 makes this drop-out happen at **startup** (one FATAL
   line, exit 1) instead of silently at the peer-handshake layer
   — operators see the affected validator set immediately on
   restart rather than via degraded handshake counters.
6. **Scheduled vs immediate emergency revocation (Run 062).** For a
   true compromise, the revocation MUST be immediate (omit
   `activation_height` or set it to `<= current_finalised_height`).
   `activation_height` is appropriate ONLY when the rotation is
   pre-planned and replacement leaves are already provisioned. Do
   NOT use `activation_height` to "soften" a compromise revocation;
   between bundle load and activation the compromised root is
   still in `active_roots` and still issues handshake-acceptable
   certs.

### 6.C Leaf certificate rotation

Goal: rotate a single validator's leaf certificate without
touching the trust root or the bundle.

Variant 1: scheduled leaf rotation, no revocation needed.

1. Validator operator generates a new ML-KEM-768 keypair on the
   validator host.
2. Transport root authority issues a new
   `v<N>_new.cert.bin` under the current root.
3. Validator operator restarts with
   `--p2p-leaf-cert v<N>_new.cert.bin
    --p2p-leaf-cert-key v<N>_new.kem.sk.bin`.
4. **No bundle change required** — the root and the bundle layer
   are unchanged.

Variant 2: leaf compromise suspected (key may be in attacker
hands).

1. Steps 1–3 of Variant 1.
2. **Mint bundle (sequence = N+1) signed by BSK** adding the
   compromised leaf cert fingerprint to `revoked_leaf_fingerprints`
   (see `pqc_trust_bundle::revoked_leaf_fingerprints()` —
   RUN_052/054). The fingerprint is the 8-byte SHA3-256 prefix
   of the leaf cert wire encoding, as produced by
   `pqc_trust_bundle::cert_leaf_fingerprint`.
3. **Publish bundle N+1.** All validators reject inbound handshakes
   presenting the revoked fingerprint at the listener side
   (RUN_052, RUN_054).
4. **Local-leaf startup self-check (Run 061).** Beginning with
   Run 061, the binary itself fails closed at startup if the local
   `--p2p-leaf-cert` matches an **active** entry in
   `revoked_leaf_fingerprints`. The operator therefore receives an
   immediate, in-process FATAL on the compromised validator if it
   is restarted with the still-revoked credential, rather than
   relying on out-of-band verification. The check uses the same
   canonical fingerprint as the Run 052 peer-handshake layer
   (SHA3-256 of `b"QBIND:pqc-trust-bundle-leaf-fp:v1" \|\| cert.encode()`)
   and the same active set the peer-handshake layer consults.
   PENDING leaf revocations (Run 062 `activation_height` in the
   future) do NOT trip the Run 061 check; the entry must be
   active for startup to fail closed.
5. **Coordinated cutover via `activation_height` (Run 062).** For a
   scheduled leaf retirement (e.g. a planned validator-host
   migration), an operator MAY set `activation_height` on the
   leaf-revocation entry to a future block height. Until that
   height is reached the entry is PENDING and neither the Run 061
   startup self-check nor the Run 052 peer-handshake enforcement
   fires; on or after that height it becomes ACTIVE and both
   surfaces fire as in Variant 2 step 3/4. Operators MUST ensure
   the affected validator(s) have rolled to a non-revoked leaf
   BEFORE the activation height; otherwise those validators will
   fail closed at next restart (Run 061) and on every subsequent
   handshake (Run 052).
6. **Suspected-compromise revocations SHOULD be immediate.** Do not
   use `activation_height` to delay enforcement of a leaf revocation
   that arose from suspected key compromise. Between bundle load
   and activation the compromised leaf is still acceptable to
   peers; that is the wrong default for a compromise event.

### 6.D Bundle-signing key rotation

This is the most operator-load-bearing workflow because the binary
does NOT update the bundle-signing **verification** key set from
inside the bundle itself. The `--p2p-trust-bundle-signing-key` CLI
flag is the authoritative configuration.

**Honest current boundary.** A bundle is signed by the current
bundle-signing secret. The signed `signing_key_id` is then verified
at load time against the union of all
`--p2p-trust-bundle-signing-key` CLI lines on the validator's
command line. There is no on-chain ratification of a new
bundle-signing key; rotation is an operator-orchestrated overlap
of two CLI-configured verification keys. If a future runtime adds
on-chain bundle-signing-key ratification, this section MUST be
updated and any out-of-date claims here treated as a defect.

Steps:

1. **Mint BSK_new offline** (§4.2). Record `signing_key_id_new`,
   `signing_pk_new`. MUST NOT collide with any transport root id.
2. **Distribute the new
   `--p2p-trust-bundle-signing-key signing_key_id_new:100:signing_pk_new`
   line out-of-band to every validator.** Operators MUST add this
   line ALONGSIDE the existing
   `--p2p-trust-bundle-signing-key signing_key_id_old:100:signing_pk_old`
   line. The binary accepts multiple verification keys.
3. **Each validator restarts** with both `--p2p-trust-bundle-signing-key`
   entries. Bundles signed by BSK_old continue to verify (the
   currently-in-use signing key id is in the configured set).
4. **Mint the next bundle (sequence = N+1) signed by BSK_new**.
   Include `activation_height` as policy dictates.
5. **Publish bundle N+1.** Validators verify against BSK_new
   (whose verification key is now in the configured set) AND
   persist sequence N+1. The validator startup log records
   `signature=verified(signing_key_id=<new prefix>..)`.
6. **Wait for full operator rollout confirmation** (every validator
   has restarted with both signing keys AND has accepted bundle
   N+1 — confirmable via `qbind_p2p_pqc_trust_bundle_sequence_highest`
   on `/metrics`).
7. **Remove the `--p2p-trust-bundle-signing-key signing_key_id_old:...`
   line from every validator's command line.** Validators restart.
8. Optionally mint bundle N+2 with the same content under BSK_new
   to confirm the post-removal state.

Rollback safety:

- Persistence of `highest_sequence = N+1` ensures a re-introduction
  of a bundle signed by BSK_old at sequence ≤ N is rejected.
- Sequence ordering is INDEPENDENT of which signing key signed the
  bundle. The anti-rollback layer keys off `(environment, chain_id)`
  only (RUN_055).

### 6.E Scheduled revocation via per-entry `activation_height` (Run 062)

Use this workflow when an operator wants to publish a revocation
NOW but have it take effect at a known future block height (for
example, to coordinate a retirement window across all validators).
For suspected-compromise revocations, prefer §6.B (root) or §6.C
variant 2 (leaf) without `activation_height`.

Steps:

1. **Decide the target activation height.** Pick
   `activation_height_target = current_finalised_height + N` where
   N is large enough that every validator restart window
   completes before the entry becomes active. The binary enforces
   a per-environment floor (Run 065, §3.10 / §5):
   `activation_height_target >= current_finalised_height + 0` on
   DevNet, `+ 8` on TestNet, and `+ 32` on MainNet. Operators
   SHOULD pick `N` strictly greater than the floor for additional
   operator-rollout headroom; the floor is what the binary will
   refuse at load, not the operator target. A bundle with a
   per-entry revocation `activation_height` in the half-open
   reject window `[current_finalised_height, current_finalised_height
   + margin)` is rejected at load with
   `RevocationActivationHeightBelowMinimumMargin` and never
   updates the persisted sequence or merges any root.
2. **Mint the bundle (sequence = N+1)** with the revocation entry
   carrying `activation_height = activation_height_target`. Sign
   with BSK offline.
3. **Publish bundle N+1.** On every validator restart the binary
   prints `[binary] Run 062: trust-bundle revocation activation
   (configured=K active=A pending=P root_active=Ra root_pending=Rp
   leaf_active=La leaf_pending=Lp)`. The pending counters
   `qbind_p2p_pqc_trust_bundle_revocations_{leaf,root}_pending`
   confirm the scheduled entry is loaded but not yet enforced.
4. **Cutover preparation.** Before `activation_height_target` is
   reached:
   - confirm every affected validator has been issued, and has
     deployed, a non-revoked replacement credential (a new leaf
     under a non-revoked root for a leaf-revocation; a new leaf
     under R_new for a root-revocation);
   - confirm replacement KEM secrets are on every affected
     validator host with mode `0o600`;
   - if a validator cannot be migrated before
     `activation_height_target`, EITHER republish the bundle at
     `sequence = N+2` with the revocation entry's
     `activation_height` advanced further, OR accept the liveness
     consequence at activation.
5. **Activation.** At `current_height >= activation_height_target`
   the entry transitions from PENDING to ACTIVE. From the next
   validator restart onward:
   - a leaf-fingerprint entry trips the Run 061 local-leaf startup
     self-check on any validator still using the revoked cert;
   - a root entry trips the Run 063 local-issuer-root startup
     self-check on any validator still using a cert chained to
     the revoked root;
   - peer-handshake enforcement (Run 052 for leaf, Run 050 for
     root) is in effect against all peers from this point.
6. **Confirm activation.** After at least one validator has
   restarted on or after the activation height, the corresponding
   `_revocations_*_active` gauge increments and the `_pending`
   gauge decrements by one. Audit
   `qbind_p2p_pqc_trust_bundle_revocations_*` across the
   validator fleet to confirm a clean cutover.

Notes:

- A scheduled-revocation bundle MAY simultaneously advance the
  bundle-level `sequence` and the bundle-level `activation_height`.
  The two activation gates are independent: the bundle-level gate
  controls whether ANY of the bundle's roots / revocations take
  effect; the per-entry gate controls whether one specific
  revocation is enforced once the bundle has loaded.
- `activation_height` is intentionally NOT the same field as
  `effective_from`. `effective_from` is a wall-clock validity
  window (Run 050). `activation_height` is block-height-gated
  (Run 062). Both gates must pass for an entry to be active.
- There is operator-triggered hot reload **for local-file
  candidates** (§6.F: Run 069 reload-check, Run 073 process-start
  reload-apply, Run 074 long-running SIGHUP live reload-apply).
  A scheduled-revocation bundle published via §6.F applies at the
  triggering moment — but per-entry `activation_height` still
  gates whether each scheduled revocation entry transitions from
  PENDING to ACTIVE: the new bundle's `_revocations_*_pending`
  gauges replace the prior bundle's at swap time, and only
  validators whose `current_height >= entry.activation_height`
  observe an ACTIVE entry. There is no peer-gossiped propagation:
  every validator's operator must trigger reload-apply (or
  restart) for the new bundle to be loaded on that validator.

---

## 6.F Operator-triggered hot-reload lifecycle (Runs 069–074)

This section is the operator playbook for the local-file
hot-reload paths landed by Runs 069–074. **All three paths are
local-operator-controlled.** None of them accept peer-supplied,
gossiped, admin-API, or filesystem-watcher input. Peer / gossiped
trust-bundle propagation remains a separate C4 piece (§10).

### 6.F.1 Three paths at a glance

| Path | Trigger | Run | Mutates live trust? | Mutates sequence file? | Evicts sessions? | Node restarts? |
|---|---|---|---|---|---|---|
| **Reload-check** | `--p2p-trust-bundle-reload-check <PATH>` at process start (node exits without starting). | 069 | No | No | No | N/A (validator never enters P2P) |
| **Process-start reload-apply** | `--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path <PATH>` at process start (node exits after the apply). | 073 | Yes (in-process, before P2P bring-up) | Yes (atomic) | No active sessions at this point — truthful zero report. | N/A (validator never enters P2P; this run produces evidence of a clean apply) |
| **Long-running SIGHUP live reload-apply** | `--p2p-trust-bundle-live-reload-enabled` + `--p2p-trust-bundle-live-reload-path <PATH>` (required together; refused without `--p2p-trust-bundle <BASELINE-PATH>`); operator sends `SIGHUP` to the running PID. | 074 | Yes (on running node) | Yes (atomic) | Yes (`evict_all_sessions(TrustBundleReloadApply)`) | **No restart** on success or non-fatal failure; only `Fatal` (commit failed AND rollback failed) triggers graceful shutdown. |

All three paths reuse the **same** Run 050/051/053/055/057/061/
062/063/065 validation pipeline as the startup `--p2p-trust-bundle`
loader (parity by construction; see §1.3 invariants). All three
hidden flags are absent from `--help` and disabled by default.

### 6.F.2 Validation-only reload-check (Run 069)

**Purpose.** Preflight a candidate bundle on a real validator
host using the **exact** startup security pipeline, without
applying any change.

**What it does.**

- Reads the candidate from `<PATH>`.
- Calls `pqc_trust_reload::validate_candidate_bundle_full` with
  the same signing-key set, `--env`, chain-id constants,
  `--data-dir`-derived sequence path (read-only via
  `peek_sequence`), and the same optional `--p2p-leaf-cert`
  bytes used by the startup hook.
- Prints `VERDICT=valid` + staged metadata (`canonical_fingerprint`,
  `sequence`, peeked previous record, active/pending revocation
  counts) on success; `VERDICT=invalid <reason>` on any failure
  class.
- Exits 0 (valid) or 1 (invalid). **The node does not start in
  this mode.**

**What it MUST NOT do (invariants — pin every operator
expectation against §1.3):**

- MUST NOT mutate `LivePqcTrustState`.
- MUST NOT merge roots into the active trust set (there is no
  active trust set to merge into — the node does not start).
- MUST NOT call `check_and_update_sequence`. Sequence is
  inspected via the read-only `peek_sequence` helper.
- MUST NOT call `evict_all_sessions`.
- MUST NOT touch any `/metrics` family.
- MUST NOT burn a sequence number on rejected OR unapplied
  candidates. Byte-and-mtime equality on the on-disk sequence
  file is asserted on every Run 069 integration test.

**Use it for.**

- Validating a freshly-published candidate against a target
  validator's runtime configuration before kicking off the
  Run 074 SIGHUP trigger.
- Detecting a wrong-chain-id, tampered-signature, rollback-attempt,
  equivocation, too-soon-activation, locally-revoked-leaf, or
  locally-revoked-issuer-root failure class without disturbing
  the running node (run reload-check on a sibling host or as a
  pre-restart preflight).

**It is NOT.**

- Peer-supplied / gossiped bundle acceptance.
- A long-running trigger surface — reload-check is process-start
  only and exits.

### 6.F.3 Process-start reload-apply (Run 073)

**Purpose.** Apply a validated local candidate to a node that has
not yet entered P2P (typically because the operator wants to
seed the live trust state with a different bundle than the one
on `--p2p-trust-bundle`, or wants to record clean evidence of a
candidate's apply pipeline against the production binary).

**What it does.**

- Loads the `--p2p-trust-bundle <BASELINE-PATH>` baseline first
  (initializes `LivePqcTrustState` and persists the baseline
  sequence record if needed).
- Constructs `ProductionLiveTrustApplyContext` over:
  - `Arc<LivePqcTrustState>` initialized from the baseline,
  - `Arc<NoActiveSessionsEvictor>` (no peer connections exist at
    this point — truthful zero-session report; the Run 072
    invariant `attempted == evicted + failed == 0` trivially
    holds),
  - the `--data-dir`-derived sequence path,
  - a freshly-sampled `now_unix_secs`.
- Drives `apply_validated_candidate_with_previous` over the
  candidate at `--p2p-trust-bundle-reload-apply-path` using the
  Run 070 ordering `validate → snapshot → swap → evict → commit`.
- Prints `AppliedCandidate::applied_log_line` (single canonical
  format) on success; `VERDICT=invalid <reason>` on failure.
- Exits 0 (applied) or 1 (any failure).

**What changed vs. Run 070.** Run 070 surfaced
`ReloadApplyError::UnsupportedRuntimeContext` because no mutable
runtime trust handle existed. Run 071 + Run 072 + Run 073 close
that gap: the binary's local-operator path now has a
production-honest `LiveTrustApplyContext` adapter, so
`UnsupportedRuntimeContext` is removed from this path. The
library boundary still surfaces `UnsupportedRuntimeContext` for
callers that omit the apply context (defence-in-depth).

**Use it for.**

- Producing operator evidence of a clean live apply against a
  freshly-built release binary, on a staging validator.
- A "stop → reload-apply → restart" rotation workflow if the
  operator chooses NOT to arm the Run 074 SIGHUP trigger.

**It is NOT.**

- The long-running SIGHUP trigger — for that, see §6.F.4.
- Peer-supplied / gossiped bundle acceptance.

### 6.F.4 Long-running SIGHUP live reload-apply (Run 074)

**Purpose.** Apply a validated local candidate to a **running**
node without restart. This is the strongest hot-reload primitive
the runbook documents today.

**Preconditions (operator MUST satisfy all):**

1. The node is running and was started with the two hidden Run 074
   flags AND a baseline bundle:
   ```
   --p2p-trust-bundle <BASELINE-PATH>
   --p2p-trust-bundle-live-reload-enabled
   --p2p-trust-bundle-live-reload-path <CANDIDATE-PATH>
   ```
   The binary refuses partial config at startup with one of three
   `FATAL` lines (recorded in RUN_074 §6 release smokes):
   - `--p2p-trust-bundle-live-reload-enabled` without
     `--p2p-trust-bundle-live-reload-path` → FATAL exit 1.
   - `--p2p-trust-bundle-live-reload-path` without
     `--p2p-trust-bundle-live-reload-enabled` → FATAL exit 1.
   - `--p2p-trust-bundle-live-reload-enabled` without
     `--p2p-trust-bundle <BASELINE-PATH>` → FATAL exit 1 (no
     implicit `--p2p-trusted-root` fallback).
2. Each subsequent candidate is written to the SAME
   `<CANDIDATE-PATH>` (the SIGHUP handler re-reads that exact
   path on every trigger).
3. The candidate is signed by an operator-distributed
   `--p2p-trust-bundle-signing-key` on TestNet/MainNet, carries
   the runtime chain_id, and satisfies the Run 065 minimum
   activation-margin on the target environment. (All Run 050–
   065 invariants apply.)

**How the trigger fires.**

- The operator overwrites `<CANDIDATE-PATH>` with the new
  candidate (atomic rename recommended) and sends `SIGHUP` to
  the validator PID (`kill -HUP <PID>`).
- The `#[cfg(unix)]` SIGHUP handler task installed by
  `spawn_run074_live_reload_task` wakes up and calls
  `LiveReloadController::try_trigger()`.
- The controller constructs a **fresh**
  `ProductionLiveTrustApplyContext` per trigger (so each apply
  gets a fresh `now_unix_secs`), over:
  - the SAME `Arc<LivePqcTrustState>` the listener-side
    handshake verifier reads from,
  - the SAME `Arc<TcpKemTlsP2pService>` (upcast to
    `Arc<dyn P2pSessionEvictor>`),
  - the SAME `--data-dir`-derived sequence file used at startup,
  - the operator's pinned signing-key set, chain_id, env, local
    leaf bytes.
- The pipeline runs `validate → snapshot → swap → evict_all →
  commit_sequence` and produces a typed `LiveReloadOutcome`.

**Outcome semantics.**

- `Applied { evicted, new_sequence }` — success. Live trust
  state swapped; all peer sessions drained; sequence file
  advanced atomically. Counters:
  `trigger_total +=1`, `apply_success_total +=1`,
  `sessions_evicted_total += evicted`,
  `last_applied_sequence = new_sequence`.
- `AlreadyInProgress` — a previous trigger is still running.
  The CAS guard rejects this trigger without entering
  validation. No state change. Counters:
  `trigger_total += 1`, `already_in_progress_total += 1`.
- `Invalid(reason)` — validation, swap, eviction-partial, or
  commit-with-successful-rollback failure. **State is unchanged
  end-to-end**: live trust at baseline `Arc`, sequence file
  bytes AND mtime unchanged. The node **keeps running**. Counters:
  `trigger_total += 1`, `apply_failure_total += 1`.
- `Fatal(reason)` — `SequenceCommitFailedRollbackAlsoFailed`
  ONLY. Live trust state may be ahead of the on-disk record;
  the handler sends to `shutdown_tx` so the operator can
  recover offline. **This is the only outcome that touches
  `shutdown_tx`**. Counters:
  `trigger_total += 1`, `apply_failure_total += 1`.

**Concurrent triggers.** An `Arc<AtomicBool>` CAS guard
serializes triggers in-process. While an apply is in flight,
every additional SIGHUP returns `AlreadyInProgress` and does
NOT re-enter validation. A clone of the controller (held by the
SIGHUP task) shares the SAME `Arc<AtomicBool>` flag with any
other reference — there is exactly one guard process-wide.

**Session-eviction impact.** A successful apply evicts ALL
existing P2P sessions conservatively (Run 072 v0 policy). Old
sessions may have authenticated under the prior roots / leaves;
keeping them after a swap would re-validate stale credentials.
Reconnect behaviour depends on the existing dial / listener
loops:

- Outbound dials retry on B8 bounded backoff against the new
  trust set.
- Inbound listeners accept new handshakes under the new trust
  set.
- **Operators should expect a short liveness disruption during a
  successful live reload.** Do not treat reload as zero-
  disruption. Selective per-peer retention is NOT implemented
  and is a separate C4 open piece (§10).

**Operator log lines.** Every outcome surfaces a single
canonical log line:

```
[Run 074] LiveReloadOutcome::Applied { evicted=4, new_sequence=2 }
[Run 074] LiveReloadOutcome::AlreadyInProgress
[Run 074] LiveReloadOutcome::Invalid(ValidationFailed(<reason>))
[Run 074] LiveReloadOutcome::Fatal(SequenceCommitFailedRollbackAlsoFailed)
```

`Fatal` is followed by graceful shutdown via the existing
`shutdown_tx` watch channel.

**It is NOT.**

- Peer-supplied / gossiped bundle acceptance.
- A filesystem-watcher hot reload (no inode watch — only SIGHUP).
- An admin-API / HTTP / JSON-RPC trigger (no network surface
  added by Run 074).
- `activation_epoch` runtime sourcing — the controller's
  `ActivationContext` is `height_only(0)`, the same height-only
  stance the startup `--p2p-trust-bundle` path uses today.
- Selective per-peer session retention — evicts all, conservatively.

### 6.F.5 Apply pipeline and ordering (the single safe order)

Both Run 073 and Run 074 apply paths use the SAME Run 070
ordering. **Operators MUST NOT assume any other order.**

1. **Validate candidate.** Full Run 050/051/053/055/057/061/062/
   063/065 pipeline. Failure → `LiveReloadOutcome::Invalid` (or
   `VERDICT=invalid` at Run 073 process-start) with the on-disk
   sequence file and the live trust state unchanged, NO eviction.
2. **Snapshot the previous `LivePqcTrustState`.** Capture the
   current `Arc<LivePqcTrustSnapshot>` for rollback.
3. **Swap to the new `LivePqcTrustState`** under
   `LivePqcTrustState::swap_snapshot`. Readers observe an
   all-or-nothing snapshot transition under a single short
   write lock. Swap failure (rare; surfaces as
   `ReloadApplyError::ApplyStateSwap`) → old state remains, NO
   eviction, NO sequence commit.
4. **Evict all sessions** via `P2pSessionEvictor::evict_all_sessions(
   EvictionReason::TrustBundleReloadApply)`. Partial failure
   (`evicted < attempted`) → rollback live state via
   `swap_snapshot(previous)`, NO sequence commit, surface
   `Invalid(SessionEvictionFailed { rollback_ok: true, ... })`.
   The truthful Run 072 invariant `attempted == evicted + failed`
   is preserved end-to-end in the surfaced error message.
5. **Commit sequence persistence** via
   `pqc_trust_sequence::check_and_update_sequence`. Atomic
   write. Failure → rollback live state; if rollback succeeds
   surface `Invalid(SequenceCommitFailedRollbackOk)` (non-fatal,
   node keeps running); if rollback fails surface
   `Fatal(SequenceCommitFailedRollbackAlsoFailed)` (live state
   may be ahead of on-disk record; Run 074 binary sends to
   `shutdown_tx` for graceful shutdown so the operator can
   recover offline).
6. **Report success.** `AppliedCandidate::applied_log_line`
   (Run 073) or `LiveReloadOutcome::Applied { evicted,
   new_sequence }` (Run 074). Metrics bump.

**Invalid candidate never kills the node** on the Run 074 path —
only the post-rollback-failure fatal branch does, and that
branch is unreachable in normal operation against the production
`swap_snapshot` writer (its only failure mode is a panicked
lock guard, which itself is non-recoverable).

### 6.F.6 Metrics and evidence (per hot-reload trigger)

Every trigger MUST produce the following operator-visible
artifacts. Archive each into the bundle-change evidence bundle
(§9) when a SIGHUP trigger or process-start reload-apply
produces a real production change.

**Reload-check (Run 069):**

- Single `VERDICT=valid|invalid …` log line.
- For invalid: the specific failure class
  (`signature_invalid`, `chain_id_mismatch`, `rollback`,
  `equivocation`, `activation_below_min_margin`,
  `activation_height_not_yet_reached`,
  `local_leaf_revoked`, `local_issuer_root_revoked`, …).
- Filesystem confirmation that `pqc_trust_bundle_sequence.json`
  bytes AND mtime are unchanged across the reload-check run.

**Process-start reload-apply (Run 073):**

- `[binary] Run 073 reload-apply baseline loaded …`
- `[binary] Run 073 reload-apply candidate validated …`
- `AppliedCandidate::applied_log_line` with:
  - old/new canonical fingerprint prefix,
  - old/new `sequence`,
  - `session_evictions=0 (no-active-sessions at startup-time)`.
- The Run 072 `qbind_p2p_session_eviction_*` counters on
  `/metrics` if a metrics scrape was captured.

**Long-running SIGHUP live reload-apply (Run 074):**

- Single `[Run 074] LiveReloadOutcome::… …` line per trigger.
- On `Applied`: explicit `evicted=<N> new_sequence=<S>` in the
  log line.
- The six `qbind_p2p_trust_bundle_live_reload_*` counters/gauge
  on `/metrics`:
  - `qbind_p2p_trust_bundle_live_reload_trigger_total`
  - `qbind_p2p_trust_bundle_live_reload_apply_success_total`
  - `qbind_p2p_trust_bundle_live_reload_apply_failure_total`
  - `qbind_p2p_trust_bundle_live_reload_already_in_progress_total`
  - `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total`
  - `qbind_p2p_trust_bundle_live_reload_last_applied_sequence`
- Run 072 `qbind_p2p_session_eviction_*` counters AFTER the
  apply.
- On-disk `pqc_trust_bundle_sequence.json` before/after the
  apply (record canonical fingerprint and `highest_sequence`).
- Proof that no `Dummy*` primitive is registered (the Run 040
  banner from process startup, captured at the validator boot
  that armed the SIGHUP trigger).
- Proof that no `--p2p-trusted-root` line is on the validator's
  command line.
- For an Invalid outcome: byte-and-mtime equality on the
  sequence file across the trigger.
- For a concurrent-trigger test (recommended once per major
  rotation): a captured `AlreadyInProgress` log line + the
  `already_in_progress_total` counter increment.

### 6.F.7 Normal trust-bundle rotation workflow (with live reload)

When a validator is running with the Run 074 flags armed:

1. **Preflight on the candidate.** On a sibling host (or on the
   same validator host out-of-band), run the candidate through
   `--p2p-trust-bundle-reload-check <CANDIDATE-PATH>` against
   the SAME signing-key set, `--env`, and (optional)
   `--p2p-leaf-cert` as the running validator. Confirm
   `VERDICT=valid`.
2. **Copy the signed candidate to the configured local
   reload path.** Use an atomic rename
   (`mv tmp.json $CANDIDATE_PATH`) so the SIGHUP handler does
   not race a partial write.
3. **Trigger SIGHUP.** `kill -HUP <PID>`.
4. **Confirm apply success.** Inspect the
   `[Run 074] LiveReloadOutcome::Applied { evicted=<N>,
   new_sequence=<S> }` log line, the
   `qbind_p2p_trust_bundle_live_reload_apply_success_total`
   counter increment, and the
   `qbind_p2p_trust_bundle_live_reload_last_applied_sequence`
   gauge value.
5. **Confirm sequence update.** Read
   `pqc_trust_bundle_sequence.json` and verify
   `highest_sequence` equals the candidate's sequence and
   `bundle_fingerprint` matches the canonical fingerprint
   logged by the apply line.
6. **Confirm session eviction.** Inspect the Run 072
   `qbind_p2p_session_eviction_*` counters AFTER the trigger
   and confirm the per-peer reconnect behaviour returns to a
   healthy `qbind_p2p_peers_authenticated` gauge value within
   the expected B8 retry window. Operators should expect a
   short liveness disruption during this period.
7. **Archive evidence** per §6.F.6 / §9 into the bundle-change
   evidence directory.

### 6.F.8 Emergency revocation via live reload

For a §6.B or §6.C variant 2 emergency-compromise event on a
fleet that is armed with Run 074 flags:

- Use the SAME emergency-revocation bundle shape as §6.B / §6.C
  variant 2 (per-entry `activation_height = None` for immediate
  enforcement; bundle-level `activation_height` omitted for the
  fastest cutover, or satisfying the Run 065 minimum margin if
  set).
- Trigger SIGHUP on every validator armed with Run 074 flags.
  Each successful apply evicts all sessions on that validator,
  forcing every peer (including any compromised peer if the
  revocation entry is leaf-scoped) to re-handshake against the
  new trust set. Compromised peers fail closed at
  re-handshake (Run 052 leaf path or Run 050/Run 063 root
  path).
- For validators NOT armed with Run 074 flags (e.g. legacy
  configuration), use the §6.B / §6.C restart-based workflow.
- **Do NOT bypass with `--p2p-trusted-root`.** That fallback is
  refused on TestNet/MainNet when `--p2p-trust-bundle` is
  supplied; live reload preserves that refusal end-to-end.

### 6.F.9 Incident checklist (hot-reload-specific)

When a SIGHUP trigger returns `Invalid` or `Fatal`:

- **Distinguish `Invalid` from `Fatal`.** Only `Fatal`
  (`SequenceCommitFailedRollbackAlsoFailed`) should be treated
  as an operational incident — it indicates the live trust
  state may be ahead of the on-disk sequence record AND
  rollback could not restore the prior live state. The node
  has signaled graceful shutdown via `shutdown_tx`. Recover
  offline: inspect the on-disk record, confirm whether the
  prior baseline bundle still validates, and restart cleanly.
- **`Invalid` does NOT require a node restart.** Validation
  failures, eviction partial failures with successful rollback,
  and commit failures with successful rollback all leave the
  node running with the prior live trust state and the prior
  on-disk sequence record intact. Identify the failure class
  in the log line, fix the candidate (e.g. resign with the
  correct signing key, regenerate with the correct chain_id,
  pick an activation height past the Run 065 floor, etc.), and
  re-trigger SIGHUP.
- **`AlreadyInProgress` is informational.** It means a previous
  trigger is still running (typically waiting on the sequence-
  file fsync or on session-eviction drain). Wait for the
  preceding outcome line, then re-trigger.
- **A repeating `Fatal` after restart** indicates a deeper
  on-disk record / live-state divergence — escalate per
  §8 incident checklist with the live-reload-specific
  trace appended.

### 6.F.10 What hot reload is NOT (consolidated boundary)

- **Not peer-supplied / gossiped acceptance.** Local files only.
  Bundle propagation between peers is C4-OPEN (§10).
- **Not filesystem-watcher hot reload.** Operator must
  explicitly send `SIGHUP`. The handler does not watch the
  candidate path for inode changes.
- **Not admin-API trigger.** No new HTTP / JSON-RPC / gRPC
  surface is added by Runs 069–074. Only `SIGHUP`.
- **Not `activation_epoch` runtime sourcing.** The controller's
  `ActivationContext` is `height_only(0)` — the same height-only
  stance the startup `--p2p-trust-bundle` path uses today.
- **Not KMS / HSM custody integration.** Signing keys are still
  operator-supplied via `--p2p-trust-bundle-signing-key`.
- **Not bundle-signing-key on-chain / in-binary ratification.**
  Out-of-band CLI overlap per §6.D continues to apply.
- **Not fast-sync / consensus-storage restore parity.** The
  live binary does not yet replay `TrustBundleRecord` from a
  snapshot.
- **Not selective per-peer session retention.** v0 is "evict
  all on successful apply" verbatim from Run 072. Per-peer
  retention is C4-OPEN.

---

## 6.G Peer-candidate validation-only and propagation-only lifecycle (Runs 076–089)

Runs 076–085 add a **disabled-by-default, validation-only**
peer-candidate `0x05` exchange on top of the §6.F local-operator
hot-reload lifecycle. The peer-candidate path is strictly
**observation + validation**: it lets one node receive a
candidate trust-bundle envelope from a peer, run it through the
same Run 050/051/053/057/065 startup security pipeline, and emit
structured evidence about the verdict. It does **not** apply
candidates, does **not** mutate the live trust state, does
**not** persist the sequence file, does **not** evict sessions,
and does **not** propagate / rebroadcast candidates to other
peers. The only operator surface that ever applies a candidate
to a running node remains the local-file SIGHUP live reload-
apply path from Run 074 (§6.F.4).

### 6.G.1 Strict behaviour (what the path does and does not do)

The peer-candidate `0x05` exchange:

- **Is validation-only.** A candidate is run through the same
  startup pipeline (`pqc_trust_bundle` envelope + ML-DSA-44
  signature + `chain_id` crosscheck + `environment` crosscheck
  + Run 065 per-environment activation-margin policy + Run 062
  active/pending revocation split + Run 057 future-height gate
  + Run 055 sequence read-only `peek_sequence`). The verdict is
  recorded; no state changes.
- **Observes valid candidates.** A candidate that passes every
  check is logged as
  `outcome=validation-only/not-applied/not-propagated/no-sequence-write/no-session-eviction`
  (see Run 085) and increments only the receiver-side
  `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total`
  counter. Nothing else moves.
- **Rejects invalid candidates.** A candidate that fails any
  check (`chain_id` mismatch, environment mismatch, signature
  failure, sequence ≤ persisted, activation-margin too soon,
  malformed wire envelope, etc.) is logged as
  `outcome=rejected; NOT applied; not propagated; sequence not
  persisted; live trust state unchanged; sessions untouched`
  and increments only the receiver-side
  `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`
  counter.
- **Suppresses duplicates.** A candidate that re-arrives with
  the same canonical fingerprint within a bounded receiver-side
  cache is logged as
  `outcome=duplicate-suppressed; NOT applied; not propagated;
  sequence not persisted; live trust state unchanged; sessions
  untouched` and increments only the receiver-side
  `qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total`
  counter.
- **Cheap-ignores on the receiver-disabled path.** When a
  receiver has not opted in to the Run 079 dispatch (i.e. the
  receiver-side validation enabled flag is off), inbound `0x05`
  frames are dropped early with no counter motion and no log
  spam beyond the existing transport-layer accounting. Sender-
  side counters still advance on a node that has opted in to
  publishing; receiver-side counters all stay zero.
- **Never applies a candidate automatically.** No path inside
  the peer-candidate code ever calls
  `pqc_trust_reload::apply_validated_candidate{,_with_previous}`,
  `LivePqcTrustState::swap_snapshot`, `P2pSessionEvictor::*`, or
  `pqc_trust_sequence::commit_sequence` — even on a validated
  candidate. The validator pipeline and the apply pipeline are
  joined only through operator action (the §6.F.4 SIGHUP path
  reading a local file the operator has independently approved).
- **Never writes the sequence file.** Receiver-side validation
  uses `peek_sequence` (Run 055, read-only). The persisted
  sequence files on every node MUST have byte-identical sha256
  before and after every peer-candidate scenario. This is a
  Run 084 / Run 085 acceptance invariant.
- **Never mutates `LivePqcTrustState`.** The Run 071 shared
  live-trust handle is never swapped by the peer-candidate
  path. The `qbind_p2p_trust_bundle_live_reload_*` family stays
  at zero on every node in every peer-candidate scenario.
- **Never evicts sessions.** The Run 072 eviction hook is never
  invoked by the peer-candidate path. The
  `qbind_p2p_session_eviction_*` family stays at zero on every
  node in every peer-candidate scenario.
- **Never propagates / rebroadcasts.** A receiver that
  validates an inbound `0x05` candidate MUST NOT re-emit it.
  Run 084 / Run 085 assert `sent_total = 0` on every non-sender
  in every scenario. There is no `BundleAnnounce` /
  `BundleRequest` retransmission path, and there is no
  forwarding step inside the receive-loop dispatcher.

### 6.G.2 Feature evolution (Runs 076–085)

| Run | What landed | Path it exercised |
|---|---|---|
| 076 | Library-level `PeerCandidateValidator` + `try_accept` over a structured `PeerCandidateEnvelope`; disabled-by-default. | `crates/qbind-node/src/pqc_trust_peer_candidate.rs` (library tests only). |
| 077 | Production-binary-facing **local** peer-candidate check mode (`--p2p-trust-bundle-peer-candidate-validation-enabled` + `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>`). Reuses the same `PeerCandidateValidator::try_accept`; node does not start; exits 0/1. Non-mutating by construction. | `crates/qbind-node/src/pqc_peer_candidate_binary.rs` + binary main wiring. |
| 078 | Bounded typed/versioned wire envelope for `0x05` (size cap, encoded version, deterministic canonical bytes). Library-level encode/decode; not yet on the live socket. | `crates/qbind-node/src/pqc_peer_candidate_wire.rs`. |
| 079 | Disabled-by-default **live P2P receive-loop dispatch** for inbound `0x05` frames. Receiver-side flag `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` opts in to running each inbound frame through the same Run 076 validator. Counters move only when the flag is on. | `crates/qbind-node/src/p2p_tcp.rs` + `p2p_node_builder.rs`. |
| 080 | Disabled-by-default **send-side publisher** plumbing (`--p2p-trust-bundle-peer-candidate-wire-publish-enabled` + `--p2p-trust-bundle-peer-candidate-wire-publish-path <PATH>` + `--p2p-trust-bundle-peer-candidate-wire-publish-once`). Operator-supplied envelope is published once over the same authenticated P2P session as a real `0x05` frame. No auto-resend loop. | `crates/qbind-node/src/p2p_node_builder.rs` + send-side metrics. |
| 081 | First release-binary N=2 real `0x05` exchange evidence, but partial: the `DummySig` boundary on the consensus signer path left the Run 033 timeout-verification proof ambiguous. | DevNet evidence Run 081 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md`). |
| 082 / 083 | Isolated the `DummySig` boundary as **non-active / probe-log-only** with respect to the peer-candidate `0x05` matrix; the matrix is independent of the consensus signer probe path. | DevNet evidence Runs 082 / 083. |
| 084 | Committed repeatable **N=2 DevNet** harness `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh`. Closed the N=2 evidence gap with full baseline / valid / receiver-disabled / invalid-wrong-chain / duplicate scenarios; all sequence hashes unchanged; live reload apply + session eviction metrics stayed zero; no propagation; no Dummy crypto; no `--p2p-trusted-root` fallback. | DevNet evidence Run 084. |
| 085 | Committed repeatable **N=4 MainNet** harness `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh`. Strongest current evidence: signed MainNet trust material, four real release `qbind-node` processes, all five scenarios pass; sequence hashes unchanged; live reload apply + session eviction metrics stayed zero; no propagation; no active `DummySig` / `DummyKem` / `DummyAead`; no `--p2p-trusted-root` fallback. | DevNet evidence Run 085. |

### 6.G.3 What operators may use this path for

Operators MAY use the peer-candidate validation-only path to:

- **Observe** candidate bundles proposed by another node on the
  live P2P mesh (when the receiver has opted in to Run 079
  dispatch).
- **Validate** the candidate's structure, signature,
  `environment`, `chain_id`, `sequence` ordering, `activation_height`
  / activation-margin policy (Run 065), and revocation
  active/pending split (Run 062) using the exact same code path
  that gates the startup `--p2p-trust-bundle` load.
- **Produce evidence** that a particular candidate is valid or
  invalid against this node's current view (counters, logs,
  read-only `peek_sequence` baselines) — without burning the
  persisted sequence and without mutating the live trust set.
- **Decide manually**, on the basis of that evidence, whether
  to feed the same candidate file into the operator-controlled
  Run 069 reload-check (§6.F.2) or the Run 074 SIGHUP live
  reload-apply (§6.F.4). The decision and the file path are
  always operator-supplied; the peer-candidate exchange is the
  signal source, not the apply trigger.

### 6.G.4 What operators MUST NOT treat this path as

The peer-candidate validation-only path is explicitly **NOT**:

- **Not trust-bundle propagation.** A validated candidate is
  not retransmitted to other peers. The receiver-side
  `sent_total` counter MUST stay zero. Bundle propagation
  between peers remains C4-OPEN (§10).
- **Not peer-driven live apply.** No validated candidate is
  ever applied to the live trust state by the receive-loop
  dispatcher. Live apply still requires the §6.F.4 operator
  SIGHUP trigger reading a local file.
- **Not consensus ratification.** There is no on-chain
  ratification step. A candidate's validity inside this node's
  view does not bind any other node, and does not commit any
  sequence number on this node either.
- **Not automatic root rotation.** A peer announcing a new
  bundle does not cause this node to rotate its transport root.
  Root rotation still follows §6.A (with §6.F.4 as the
  zero-downtime apply trigger).
- **Not automatic revocation distribution.** A peer announcing
  a bundle with new revocation entries does not cause this
  node to enforce those revocations. The local active
  `revoked_leaf_fingerprints` / `revoked_root_ids` set only
  changes when an operator applies the bundle via §6.F.4.
- **Not a substitute for `--p2p-trust-bundle` at startup.**
  The peer-candidate path runs alongside a startup-loaded
  bundle; it does not seed an unloaded node.

### 6.G.5 Safety invariants (checklist per peer-candidate scenario)

Every peer-candidate scenario — valid, receiver-disabled,
invalid / wrong-chain, duplicate — MUST satisfy ALL of the
following. Any red item indicates the path has regressed and
MUST block promotion / merge:

- [ ] **Persisted sequence file unchanged.** sha256 of every
      node's sequence file BEFORE the scenario equals sha256
      AFTER the scenario (Run 084 / Run 085 sha256 columns).
- [ ] **`LivePqcTrustState` unchanged.** Live reload apply
      metrics remain at zero on every node:
      `qbind_p2p_trust_bundle_live_reload_trigger_total = 0`,
      `..._apply_success_total = 0`,
      `..._apply_failure_total = 0`,
      `..._already_in_progress_total = 0`,
      `..._sessions_evicted_total = 0`.
- [ ] **No session eviction.** Session eviction metrics remain
      at zero on every node:
      `qbind_p2p_session_eviction_attempt_total = 0`,
      `..._success_total = 0`,
      `..._failure_total = 0`,
      `..._sessions_evicted_total = 0`.
- [ ] **Receiver logs say NOT applied / not propagated.** Every
      validated, rejected, and duplicate verdict log line MUST
      include `NOT applied` and `not propagated`; every valid
      verdict MUST include
      `outcome=validation-only/not-applied/not-propagated/no-sequence-write/no-session-eviction`.
- [ ] **No `--p2p-trusted-root` fallback.** Neither the
      operator command line nor any log line mentions
      `--p2p-trusted-root` on TestNet/MainNet. Static-CLI roots
      MUST NOT be re-introduced as a peer-candidate fallback.
- [ ] **No active `DummySig` / `DummyKem` / `DummyAead`.**
      `[Run040]` lines show `dummy_kem_registered=false`,
      `dummy_aead_registered=false`,
      `transport_kem_suite_name=ml-kem-768`, and
      `transport_aead_suite_name=chacha20-poly1305`. Log
      archives contain no `DummySig` / `DummyKem` / `DummyAead`
      matches.
- [ ] **`qbind_p2p_pqc_cert_verify_rejected_total = 0` for
      honest traffic.** A live peer-candidate scenario must not
      cause the underlying cert-verify path to start rejecting
      honest connections. Cert-verify rejected counters MUST
      stay at zero on every node throughout the scenario.
- [ ] **Peer-candidate rejected counters move only for invalid
      candidates.** In the invalid / wrong-chain scenario, the
      receiver's
      `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`
      MUST increment exactly by the number of invalid frames
      delivered. In every other scenario, this counter MUST
      NOT move.

### 6.G.6 MainNet evidence (Run 085 — strongest current)

Run 085 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_085.md`,
harness `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh`)
is the strongest current evidence for this lifecycle and is the
canonical regression harness operators / reviewers should rerun
when evaluating peer-candidate behaviour:

- **N=4 MainNet signed-bundle cluster.** Four release
  `qbind-node` processes under `--env mainnet`, signed
  MainNet trust bundle (`chain_id = 0x51424E444D41494E`),
  explicit `--p2p-trust-bundle-signing-key`, per-node data
  dirs, explicit peer-leaf-cert mappings, no
  `--p2p-trusted-root` fallback.
- **All five scenarios pass.** baseline; valid `0x05`
  send/validate; receiver-disabled cheap-ignore;
  invalid/wrong-chain reject; duplicate suppression.
- **Sequence hashes unchanged.** Every
  `sequence/*.before.sha256` equals the matching
  `sequence/*.after.sha256` for every candidate scenario.
- **No apply / no eviction / no propagation.** All live-reload-
  apply, session-eviction, and receiver `sent_total` counters
  stay at zero across every scenario.
- **No Dummy crypto.** `[Run040]` lines confirm real
  ML-KEM-768 + ChaCha20-Poly1305; `[binary] Run 033` lines
  confirm active timeout verification with four loaded
  consensus signer keys.
- **No fallback.** `--p2p-trusted-root` is absent from every
  command line and every log line.

Run 084 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_084.md`,
harness `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh`)
remains the canonical N=2 DevNet regression and is the cheapest
harness for local re-verification.

### 6.G.7 What the peer-candidate path does NOT close

The peer-candidate validation-only path does **NOT** close any
of the following — they remain explicitly open under C4 / C5
(see §10):

- **Peer-driven live apply / propagation.** No path inside the
  binary applies a peer-supplied candidate to live trust, and
  no path retransmits a candidate to other peers.
- **`activation_epoch` runtime sourcing.** Bundle-level and
  per-entry `activation_epoch` continue to fail closed; the
  epoch axis remains height-only (Run 057 / Run 065 boundary).
- **KMS / HSM custody.** Signing keys are still operator-
  supplied via `--p2p-trust-bundle-signing-key`. The peer-
  candidate path does not change custody.
- **Signing-key ratification (in-binary / on-chain).** §6.D
  remains an out-of-band CLI overlap procedure.
- **Fast-sync / consensus-storage restore parity.** Trust-
  bundle restore from a snapshot is independent and remains
  partially open under C4.
- **Per-environment production trust-anchor operation.**
  Depends on operator custody (§4.4) and is not solved by
  documentation alone.
- **Full C4 / C5 closure.** Run 086 narrows neither. C4 and C5
  remain OPEN; C5 remains NARROWED (Runs 038 / 039) by the
  prior production-honest transport-KEM evidence, not by the
  peer-candidate path.

### 6.G.8 Future propagation/apply design gate (Run 087)

Run 087 adds the formal safety gate in
`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`. Operators and
implementers MUST treat that document as a future-work prerequisite, not as a
statement that peer-driven propagation or peer-driven live apply exists today.

The preserved operating boundary is:

- Peer-candidate `0x05` is validation-only today.
- Local SIGHUP reload (§6.F.4) remains the only running-node apply path today.
- Peer-driven apply and propagation require a future separately scoped
  implementation with its own evidence.
- No automatic trust-bundle synchronization is allowed without satisfying the
  Run 087 gates.

### 6.G.9 Propagation-only behavior (Runs 087–089)

Run 088 narrows the §6.G boundary by adding a hidden, **disabled-by-default**,
**propagation-only** prototype on top of the Run 079 receive-loop dispatch.
The path is strictly **validate → rebroadcast**. It does **not** apply
candidates, does **not** mutate `LivePqcTrustState`, does **not** persist the
sequence file, does **not** evict sessions, and does **not** assert consensus
ratification or trust-bundle synchronization. The §6.F.4 SIGHUP path
remains the only operator surface that ever applies a candidate to a
running node. Run 089 lands the release-binary **N=3 DevNet** evidence
for this prototype.

The propagation-only path:

- **Is opt-in via a single hidden flag.**
  `--p2p-trust-bundle-peer-candidate-propagation-enabled` *(hidden;
  Run 088)*. Disabled by default. Requires a validated baseline
  `--p2p-trust-bundle <PATH>` and the Run 079 receive-loop dispatch
  flag `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` to
  be effective. With the flag off (the default), receive behaviour
  is byte-identical to Run 079 / Run 085.
- **Validates before rebroadcasting (no other ordering allowed).**
  Every inbound `0x05` frame still flows through the Run 078 wire
  decode + Run 076 `PeerCandidateValidator::try_accept` pipeline
  first. Only an outcome of `PeerCandidateWireOutcome::Validated`
  may schedule rebroadcast. Invalid, oversize, malformed, duplicate,
  rate-limited, and receiver-disabled frames are **never**
  rebroadcast.
- **Excludes the source peer.** The rebroadcast target set is built
  by enumerating connected peers and removing the source connection
  ID. The source peer's receiver-side `received_total` for the
  rebroadcast copy MUST stay at zero in every propagation scenario.
- **Prevents loops locally.** Loop prevention is the combination of
  (a) a bounded local seen-cache keyed on
  `sequence:fingerprint_prefix`, (b) source-peer exclusion in the
  target-set builder, (c) a bounded `max_rebroadcast_targets`
  fanout cap, (d) a fixed-window propagation rate limit, and (e)
  the existing bounded raw-frame send queue depth. The wire
  envelope is unchanged; **no TTL byte was added**.
- **Suppresses duplicates.** A second arrival of the same canonical
  candidate (`sequence:fingerprint_prefix`) within the seen-cache
  is dropped before scheduling propagation;
  `propagation_suppressed_duplicate_total` increments;
  `propagation_sent_total` does **not** increment for the duplicate.
- **Suppresses invalid candidates.** Any candidate that fails Run
  076/078 validation does not reach the propagation stage at all;
  `propagation_suppressed_invalid_total` increments;
  `propagation_sent_total` does **not** increment for the rejected
  frame.
- **Rate-limits propagation.** When the local propagation
  fixed-window rate-limit fires, the candidate is dropped from
  the propagation stage; `propagation_rate_limited_total`
  increments; `propagation_sent_total` does **not** increment for
  the rate-limited frame.
- **Never writes the sequence file.** Receiver-side validation still
  uses `peek_sequence` (Run 055, read-only). Every node's
  `pqc_trust_bundle_sequence.json` sha256 before each scenario
  equals its sha256 after each scenario. This is a Run 089
  acceptance invariant.
- **Never mutates `LivePqcTrustState`.** The Run 071 shared
  live-trust handle is never swapped by the propagation path. The
  `qbind_p2p_trust_bundle_live_reload_*` family stays at zero on
  every node in every propagation scenario.
- **Never evicts sessions.** The Run 072 eviction hook is never
  invoked by the propagation path. The
  `qbind_p2p_session_eviction_*` family stays at zero on every
  node in every propagation scenario.
- **Never applies a candidate.** The `peer_candidate_applied_total`
  family is intentionally absent from `/metrics`. No path inside
  the propagation dispatcher ever calls
  `pqc_trust_reload::apply_validated_candidate{,_with_previous}`,
  `LivePqcTrustState::swap_snapshot`, `P2pSessionEvictor::*`, or
  `pqc_trust_sequence::commit_sequence`.
- **Is not trust-bundle synchronization.** A validated rebroadcast
  spreads observation evidence to opted-in peers; it does **not**
  cause those peers' trust state, transport root, or active
  revocation set to change. State change still requires the
  §6.F.4 operator SIGHUP trigger reading a local file.
- **Is not consensus ratification.** Propagation does not record
  any consensus vote, does not commit any sequence number on this
  node or any other node, and does not bind any other node's view.

New propagation counters added by Run 088 (all zero by default and
only move on opt-in receivers when the propagation flag is set):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_duplicate_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_rate_limited_total`

No `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` counter
or family exists. Its absence from `/metrics` is an acceptance
invariant of every propagation scenario (asserted explicitly by the
Run 089 harness).

### 6.G.10 What operators MAY and MUST NOT use propagation-only mode for

Operators MAY enable
`--p2p-trust-bundle-peer-candidate-propagation-enabled` on a node to:

- **Spread observation evidence.** A validated candidate is
  forwarded to other opted-in nodes so they can run the same
  validation against their own view and emit their own metrics /
  logs.
- **Observe validation results across nodes.** When several opted-in
  nodes each independently validate the same candidate, the per-
  node verdict counters / log lines form a multi-node evidence
  surface for that candidate.
- **Collect metrics and logs for manual operational decision-making.**
  Operators inspect the propagation attempt / sent / suppressed-
  invalid / suppressed-duplicate / rate-limited counters together
  with the receive-side validated / rejected / duplicate counters
  and the existing live-reload-apply / session-eviction families to
  decide whether to **manually** feed the same candidate file into
  the §6.F.4 SIGHUP live reload-apply path (or the §6.F.2 reload-
  check path) on the node(s) they actually want to mutate.

Operators MUST NOT treat propagation-only mode as any of the
following — these are explicit failure modes that this runbook
forbids and that the binary does not implement:

- **Not automatic root rotation.** A propagated `0x05` candidate
  does not rotate the transport root on any receiving node. Root
  rotation still follows §6.A together with §6.F.4 (operator SIGHUP)
  as the apply trigger.
- **Not automatic revocation distribution.** A propagated `0x05`
  candidate does not enforce new revocation entries on any receiving
  node. Revocation enforcement still requires §6.F.4 (operator
  SIGHUP).
- **Not peer-driven live apply.** No path inside the binary applies
  a peer-supplied candidate to the live trust state.
  Peer-driven apply remains explicitly unimplemented (§10).
- **Not a replacement for local SIGHUP live reload.** §6.F.4 remains
  the only running-node apply surface. Propagation does not
  substitute for, weaken, or short-circuit it.
- **Not consensus approval.** A candidate's propagation by N out of
  M nodes is **not** consensus ratification of that candidate. The
  binary records no on-chain ratification step. A propagated
  candidate carries the same trust weight as a manually-shared
  envelope file would.
- **Not bundle-signing-key ratification.** Propagation does not
  ratify a new bundle-signing key in-binary or on-chain. §6.D
  remains an out-of-band CLI overlap procedure.
- **Not trust-bundle synchronization.** Propagation spreads
  evidence; it does **not** synchronize trust state across the
  cluster. A node's active trust state never changes as a result
  of receiving or rebroadcasting a `0x05` frame.

### 6.G.11 Propagation-only evidence checklist (per scenario)

Every propagation-only scenario — valid, invalid / wrong-chain,
duplicate, source-exclusion settle — MUST satisfy all of the
following. Any red item indicates the path has regressed and MUST
block promotion / merge. This checklist is exercised end-to-end on
release binaries by `scripts/devnet/run_089_peer_candidate_propagation_n3.sh`:

- [ ] **Receive-side counters move.**
      `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total`
      increments on every node that received an inbound `0x05`
      frame in the scenario; `..._validated_total` increments only
      on the valid scenario; `..._rejected_total` increments only
      on the invalid scenario; `..._duplicate_total` increments only
      where a second canonical copy of an already-seen candidate
      arrived.
- [ ] **Propagation counters move only after validation.**
      `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`
      and `..._propagation_sent_total` increment on the rebroadcasting
      node ONLY in scenarios where validation succeeded; they MUST
      stay at zero on invalid and rate-limited scenarios.
- [ ] **`propagation_suppressed_invalid_total` moves for rejected
      candidates.** On the invalid / wrong-chain scenario, the
      rebroadcasting node's
      `..._propagation_suppressed_invalid_total` MUST be ≥ 1 and
      `..._propagation_sent_total` MUST be 0.
- [ ] **Duplicate counters move for repeated candidates.** On the
      duplicate scenario, the rebroadcasting node's
      `..._duplicate_total` MUST be ≥ 1 and
      `..._propagation_sent_total` MUST NOT increment a second
      time. The `..._propagation_suppressed_duplicate_total` family
      may also move depending on whether dedup fired at the
      validator stage or the propagation stage.
- [ ] **Source node `received_total` stays zero in source-exclusion
      test.** Across every propagation scenario, the source peer
      MUST observe `received_total == 0` for its own emitted
      candidate even after a wall-clock settle window (Run 089
      uses 5 s). This MUST hold even when other honest receivers
      have rebroadcast.
- [ ] **Persisted sequence hashes unchanged.** sha256 of every
      node's `pqc_trust_bundle_sequence.json` BEFORE the scenario
      equals sha256 AFTER the scenario (Run 089
      `sequence/*.{before,after}.sha256` artefacts).
- [ ] **`live_reload_apply_*` metrics zero.** On every node in
      every scenario:
      `qbind_p2p_trust_bundle_live_reload_trigger_total = 0`,
      `..._apply_success_total = 0`,
      `..._apply_failure_total = 0`,
      `..._already_in_progress_total = 0`,
      `..._sessions_evicted_total = 0`.
- [ ] **`session_eviction_*` metrics zero.** On every node in
      every scenario:
      `qbind_p2p_session_eviction_attempt_total = 0`,
      `..._success_total = 0`,
      `..._failure_total = 0`,
      `..._sessions_evicted_total = 0`.
- [ ] **`peer_candidate_applied_total` family absent.**
      `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
      MUST NOT appear in any node's `/metrics` text in any
      scenario. The Run 089 harness asserts this explicitly via
      `assert_common_invariants`.
- [ ] **No active `DummySig` / `DummyKem` / `DummyAead`.** Every
      node's `[Run040]` line shows `dummy_kem_registered=false`,
      `dummy_aead_registered=false`,
      `transport_kem_suite_name=ml-kem-768`,
      `transport_aead_suite_name=chacha20-poly1305`. Every node's
      Run 033 line shows `active=true reason=n/a` with a loaded
      local-keystore consensus signer. Log archives contain no
      `DummySig` / `DummyKem` / `DummyAead` matches.
- [ ] **No `--p2p-trusted-root` fallback.** Neither operator
      command lines nor any log line on any node references
      `--p2p-trusted-root`. Static-CLI roots MUST NOT be
      re-introduced as a propagation fallback on TestNet/MainNet.

### 6.G.12 Mapping for Runs 087–089

The propagation-only lifecycle is the joint product of three
sequential runs; each plays a distinct role and none individually
closes the gate that Run 087 specifies:

| Run | Role | Artefact |
|---|---|---|
| 087 | **Safety specification.** Defines the future-work design gate for any peer-driven trust-bundle propagation or apply work (bounded payload, validation before rebroadcast, duplicate suppression, rate limiting, loop prevention, no apply, no sequence commit, no session eviction, clear metrics). Docs-only; no runtime behaviour change. | `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`. |
| 088 | **Propagation prototype.** Adds hidden, disabled-by-default `--p2p-trust-bundle-peer-candidate-propagation-enabled`, the five `..._propagation_*` counters, validation-before-rebroadcast in `pqc_peer_candidate_wire`, source-peer exclusion, local seen-cache, rate / fanout / queue bounds, and unit/integration tests `run_088_pqc_peer_candidate_propagation_tests.rs`. Library + binary wiring only; no release-binary multi-node propagation evidence. | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_088.md`. |
| 089 | **Release-binary N=3 DevNet propagation evidence.** Repeatable harness `scripts/devnet/run_089_peer_candidate_propagation_n3.sh` runs three release `qbind-node` processes (V0/V1/V2) on loopback over mutual-auth ML-KEM-768 + ChaCha20-Poly1305 + ML-DSA-44 with real consensus signer keystores and a signed DevNet bundle. Proves on real binaries that V0 → V1 → V2 propagation succeeds only after V1 validation, V1 excludes V0 from rebroadcast (`V0.received_total == 0` after a 5 s settle window), invalid wrong-chain candidates do not rebroadcast (`propagation_suppressed_invalid_total ≥ 1`, `propagation_sent_total == 0`), duplicate candidates do not rebroadcast a second time, sequence files are byte-identical before/after on every node in every scenario, `live_reload_apply_*` / `session_eviction_*` families remain zero, the `peer_candidate_applied_total` family is absent from `/metrics`, no `--p2p-trusted-root` fallback fires, and no active Dummy crypto. Consensus progresses in the propagation-enabled topology. | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_089.md`, `scripts/devnet/run_089_peer_candidate_propagation_n3.sh`. |

Together, Runs 087/088/089 satisfy the **propagation subset** of the
Run 087 safety contract on release binaries. They do **not** satisfy
the peer-driven-apply subset, the on-chain signing-key ratification
subset, the `activation_epoch` runtime-source subset, the KMS/HSM
custody subset, or the fast-sync / consensus-storage restore subset
of Run 087. Those remain explicitly OPEN under §10 / §6.G.13.

### 6.G.13 Residual open items after Runs 087–089

The propagation-only lifecycle does **NOT** close any of the
following. They remain explicitly open under C4 / C5 (§10):

- **Peer-driven live apply.** A validated, propagated candidate is
  still **never** applied to live trust on any node. The only
  running-node apply path remains §6.F.4 SIGHUP on a local file
  under operator control.
- **`activation_epoch` runtime source.** Bundle-level and per-entry
  `activation_epoch` continue to fail closed; the epoch axis remains
  height-only (Run 057 / Run 065 boundary). Run 088 / 089 do not
  introduce an epoch runtime source.
- **KMS / HSM custody.** Signing keys remain operator-supplied via
  `--p2p-trust-bundle-signing-key`. Propagation does not change
  custody.
- **In-binary / on-chain signing-key ratification.** §6.D remains
  out-of-band CLI overlap. Propagating an envelope that names a new
  signing key does NOT ratify that key.
- **Production fast-sync / consensus-storage restore parity.**
  Trust-bundle restore from a snapshot is independent of the
  peer-candidate path and remains partially open under C4.
- **Per-environment production trust-anchor operation.** Depends on
  operator custody (§4.4) and is not solved by documentation alone.
- **Full C4 / C5 closure.** Run 090 narrows neither. C4 remains
  OPEN; C5 remains OPEN / NARROWED (Runs 038/039) by prior
  production-honest transport-KEM evidence, not by the propagation
  path.

---

## 7. Promotion checklist (every production trust-bundle change)

Run this before promoting a bundle to TestNet, and again before
promoting to MainNet. Every item must be confirmed green; any red
item blocks promotion.

- [ ] Bundle `bundle_version == 1`.
- [ ] Bundle `environment` matches the target runtime
      (`--env devnet|testnet|mainnet`).
- [ ] Bundle `chain_id` matches the runtime chain id constant
      (DevNet `0x51424E4444455600`, TestNet `0x51424E4454535400`,
      MainNet `0x51424E444D41494E`).
- [ ] Bundle `sequence` is strictly greater than the previously
      published bundle's `sequence` for this trust domain.
- [ ] Bundle `activation_height` (if set) satisfies the Run 065
      per-environment minimum margin against `current_height`
      (§3.10 / §5): `activation_height >= current_height` on
      DevNet, `>= current_height + 8` on TestNet, `>= current_height
      + 32` on MainNet. A bundle with `activation_height` in the
      half-open reject window `[current_height, current_height +
      margin)` will be refused at load and will NOT advance the
      persisted sequence file.
- [ ] Bundle `activation_epoch` is **NOT** set (Run 057 boundary).
- [ ] Bundle `valid_from <= now <= valid_until`.
- [ ] Every `roots[i]` has `suite_id == 100`, valid ML-DSA-44
      `root_pk` length, lowercase hex, and a window covering the
      activation period.
- [ ] `revocations[i].effective_from` is at most the current time
      for any entry intended to be active immediately.
- [ ] For each `revocations[i]`, `activation_height` (Run 062) is
      EITHER absent (immediate; exempt from Run 065) OR satisfies
      the Run 065 per-environment minimum margin (§3.10 / §5.3)
      against the current finalised height. Emergency compromise
      revocations MUST NOT carry an `activation_height` that
      postpones enforcement past the next validator restart — set
      `activation_height = None` for immediate compromise
      revocations. A scheduled-revocation `activation_height` in
      the half-open reject window
      `[current_height, current_height + margin)` will be refused
      at load with `RevocationActivationHeightBelowMinimumMargin`.
- [ ] `signing_key_id` does NOT equal any `roots[i].root_id`.
- [ ] Bundle ML-DSA-44 signature verifies against the operator's
      configured `--p2p-trust-bundle-signing-key` set.
- [ ] Canonical fingerprint computed by
      `pqc_trust_bundle::canonical_fingerprint` recorded in the
      artifact-inventory log. Per-entry `activation_height` is
      covered by the canonical preimage (Run 062): tampering it
      after signing must invalidate the bundle signature.
- [ ] Confirm `current_height` source for the validator fleet
      (Run 057 / Run 065): with `--restore-from-snapshot`,
      `current_height = restore_baseline.snapshot_height`; otherwise
      `current_height = 0`. Operator margin choice for
      `activation_height` MUST be computed against this value.
- [ ] Confirm the chosen `activation_height` (bundle-level,
      per-active-root, AND any per-entry scheduled revocation) is
      OUTSIDE the Run 065 half-open reject window
      `[current_height, current_height + minimum_activation_margin)`
      on the target environment, OR is `None` (immediate
      revocation only).
- [ ] Confirm a rejected too-soon bundle would NOT burn the
      persisted sequence number (Run 065 ordering: the policy
      runs BEFORE `check_and_update_sequence`; rejected bundles
      leave `pqc_trust_bundle_sequence.json` and `loaded.active_roots`
      untouched).
- [ ] If the bundle is for TestNet/MainNet, a Run 065 too-soon
      negative smoke passes for that environment (RUN_065 Smoke 2
      shape for TestNet, Smoke 4 shape for MainNet): mint a
      same-shape bundle with `activation_height = current_height +
      (margin - 1)`, attempt to load, observe the FATAL `pqc
      trust-bundle minimum activation-height policy violation
      (… environment=<env>, … minimum_margin=<8|32>, …)`, AND
      verify the data directory is NOT created.
- [ ] Sufficient-margin smoke passes: mint a same-shape bundle
      with `activation_height = current_height + margin` (exactly
      at the inclusive upper boundary); the live binary passes
      the Run 065 policy and falls through to Run 057's
      "activation height not yet reached" FATAL (RUN_065 Smoke 3
      shape for TestNet, Smoke 5 shape for MainNet). This proves
      orthogonal composition of Run 065 and Run 057.
- [ ] If immediate emergency revocation is intentional, confirm
      every `revocations[i].activation_height` is `None` (the
      Run 065 emergency-revocation-preserved boundary, pinned by
      `run065_immediate_revocation_preserved_on_signed_mainnet`).
- [ ] Negative tamper test passes (flip any byte of
      `roots[0].not_after`; the test fixture must fail closed —
      RUN_059 Smoke 3 shape).
- [ ] Wrong-chain test passes (relabel `chain_id` to a different
      environment's id; loader must fail closed — RUN_059 Smoke
      5 shape).
- [ ] Rollback test passes (after persisting sequence N+1, attempt
      to load sequence N; loader must fail closed — RUN_056 Smoke 3).
- [ ] Equivocation test passes (mint a second distinct bundle at
      the same sequence with a different fingerprint; loader must
      fail closed — RUN_056 Smoke 5).
- [ ] If a revoked root or revoked leaf is being introduced, a
      revoked-root / revoked-leaf negative test passes (RUN_052,
      RUN_054).
- [ ] If a SCHEDULED revocation entry is being introduced
      (`activation_height` set in the future), a pending-revocation
      smoke passes: the live binary reports the entry on the
      `_revocations_*_pending` gauge AND on the `Run 062: …
      pending=…` log line, AND neither the Run 061 nor the Run 063
      local startup self-check fires (RUN_062 Smokes 1/3 shape).
- [ ] If a leaf revocation is intended to be ACTIVE on a validator
      that currently uses that leaf, a Run 061 local-leaf
      startup self-check FATAL smoke passes (RUN_061 Smoke 2 shape).
- [ ] If a root revocation is intended to be ACTIVE on a validator
      whose local leaf is chained to that root, a Run 063
      local-issuer-root startup self-check FATAL smoke passes
      (RUN_063 Smoke 2 shape).
- [ ] On a clean test validator, the live binary prints the Run
      050/051/053/055/057/062/061/063 banners (in the order the
      binary emits them) with the expected fingerprints
      and ends with the Run 040 `[Run040] P2pNodeBuilder: ...
      dummy_kem_registered=false dummy_aead_registered=false ...`
      banner — confirming no fallback to test-grade primitives.
      On a too-soon TestNet/MainNet bundle the binary instead
      emits the Run 065 FATAL `pqc trust-bundle minimum
      activation-height policy violation` and exits 1 BEFORE any
      of the post-load banners.
- [ ] No `--p2p-trusted-root` line on TestNet/MainNet validators.
- [ ] **Hot-reload preflight (when an operator plans to use §6.F).**
      Run `--p2p-trust-bundle-reload-check <CANDIDATE-PATH>` on a
      validator-equivalent host with the SAME signing-key set,
      `--env`, chain-id, `--data-dir`, and (optional)
      `--p2p-leaf-cert` as the target fleet. Confirm
      `VERDICT=valid` and confirm the on-disk
      `pqc_trust_bundle_sequence.json` bytes AND mtime are
      unchanged across the reload-check run (Run 069 non-mutation
      invariant). A reload-check failure on TestNet/MainNet
      blocks promotion.
- [ ] **Live-reload trigger smoke (when a validator is armed with
      Run 074 flags).** On a staging validator, arm the Run 074
      flags, trigger SIGHUP with the candidate, confirm the
      `[Run 074] LiveReloadOutcome::Applied { evicted=…,
      new_sequence=… }` log line, confirm
      `qbind_p2p_trust_bundle_live_reload_apply_success_total`
      increments by 1, confirm
      `qbind_p2p_trust_bundle_live_reload_last_applied_sequence`
      matches the candidate's `sequence`, confirm
      `qbind_p2p_session_eviction_*` counters reflect the drain,
      and confirm `pqc_trust_bundle_sequence.json`'s
      `highest_sequence` + `bundle_fingerprint` match the
      candidate. Then trigger SIGHUP a second time with the SAME
      candidate and confirm the persistence file's bytes AND
      mtime are unchanged (idempotent re-apply at the
      `EqualSequenceSameFingerprint` branch).
- [ ] **Live-reload concurrent-trigger smoke (recommended once
      per major rotation).** On a staging validator armed with
      Run 074 flags, send two SIGHUPs in rapid succession and
      capture an `[Run 074] LiveReloadOutcome::AlreadyInProgress`
      line + the
      `qbind_p2p_trust_bundle_live_reload_already_in_progress_total`
      counter increment. Confirms the `Arc<AtomicBool>` CAS guard.
- [ ] Archive: bundle fingerprint, signing_key_id, release
      `qbind-node` `sha256` + `ELF BuildID`, helper `sha256` if
      one was used to mint the bundle.

---

## 8. Incident checklist

Run this on any of: suspected root compromise, suspected
bundle-signing key compromise, suspected validator leaf
compromise, observed rollback / equivocation attempt.

- [ ] Quarantine the suspected compromised material. Do not
      re-use any compromised key for **any** subsequent step.
- [ ] Identify which authority (§2.1) is compromised. Root,
      bundle-signing, and leaf compromises follow different
      workflows (§6.B, §6.D, §6.C). Decide explicitly whether the
      revocation is root-level or leaf-level, and whether it must
      be immediate or scheduled (§6.E). Compromise revocations
      MUST be immediate.
- [ ] Identify, for each candidate revocation entry, what
      `activation_height` (if any) is appropriate. For an
      emergency compromise event the answer is "none / immediate"
      (`activation_height = None`); per-entry `activation_height
      = None` is the only way to publish an immediate revocation
      on TestNet/MainNet within the Run 065 minimum-margin policy
      (any `Some(h)` with `h` in the half-open reject window is
      refused at load). Distinguish a planned scheduled revocation
      (`activation_height = Some(h)`, `h >= current_height +
      minimum_activation_margin`) from an emergency immediate
      revocation (`activation_height = None`); they are not
      interchangeable.
- [ ] Confirm the liveness impact BEFORE publishing an immediate
      root revocation: every validator whose local
      `--p2p-leaf-cert` is chained to the revoked root will fail
      closed at next restart (Run 063 startup self-check) and
      every handshake to that validator will fail closed (Run 050
      / Run 052 peer-handshake context). If a non-trivial
      fraction of validators are in that set, the validator drop-
      out is the correct fail-closed behaviour but it must be a
      conscious operator decision.
- [ ] If a root revocation is being scheduled (not immediate),
      confirm every affected validator has a replacement leaf
      cert chained to a non-revoked root deployed on disk BEFORE
      the entry's `activation_height` is reached. The Run 065
      minimum margin on TestNet (8 blocks) and MainNet (32
      blocks) is a hard floor, not a sufficient operator window —
      operators SHOULD use a comfortably larger margin when the
      replacement-cert distribution is operator-bound.
- [ ] Identify which validators will fail closed at startup once
      the revocation activates. For a leaf revocation: validators
      whose local `--p2p-leaf-cert` matches the revoked
      fingerprint will trip the Run 061 self-check. For a root
      revocation: validators whose local leaf cert is issued by
      the revoked root will trip the Run 063 self-check. Confirm
      that any validator that MUST stay alive has a replacement
      credential ready BEFORE the entry becomes active.
- [ ] Mint replacement material on a clean offline / HSM host
      (§4).
- [ ] Mint an `(N+1)` bundle that excludes the compromised
      material. For an emergency compromise the per-entry
      revocation MUST carry `activation_height = None` (immediate;
      exempt from Run 065). The bundle-level `activation_height`
      SHOULD be omitted (no restriction) for the fastest emergency
      rotation; if set on TestNet/MainNet it MUST satisfy the
      Run 065 minimum margin (`>= current_height + 8` on TestNet,
      `+ 32` on MainNet) or the bundle is rejected at load.
      Sign with the currently-trusted bundle-signing authority.
- [ ] Distribute the new bundle out-of-band on the same channel
      as steady-state bundles.
- [ ] Confirm every validator reports `qbind_p2p_pqc_trust_bundle_sequence_highest`
      = `N+1` on `/metrics`.
- [ ] Confirm `qbind_p2p_pqc_trust_bundle_signature_rejected_total`
      stays 0 on every validator after the change.
- [ ] Confirm the Run 062 revocation banner shows
      `active=K pending=0` for the compromise entry on every
      validator (i.e. no validator silently treats the compromise
      revocation as pending due to a stale runtime height source).
- [ ] If a bundle-signing key was compromised, follow §6.D in the
      shortened "emergency rotation" form: distribute BSK_new
      before the next steady-state bundle, mint bundle N+2 under
      BSK_new, then remove BSK_old in N+3 once rollout is
      confirmed.
- [ ] **If validators are armed with Run 074 SIGHUP live reload-
      apply flags:** trigger the emergency revocation bundle via
      SIGHUP on every armed validator INSTEAD of restarting (see
      §6.F.8). Confirm `[Run 074] LiveReloadOutcome::Applied …`
      on each trigger and confirm the
      `qbind_p2p_trust_bundle_live_reload_apply_success_total`
      counter increments by 1 on each. For un-armed validators,
      fall through to the restart-based workflow.
- [ ] **Hot-reload trigger MUST NOT return `Fatal` on a healthy
      validator.** `LiveReloadOutcome::Fatal(SequenceCommitFailedRollbackAlsoFailed)`
      indicates the live trust state may be ahead of the on-disk
      sequence record AND rollback could not restore the prior
      state. Treat as a separate incident: capture the trigger
      log line + the `pqc_trust_bundle_sequence.json` contents +
      the live `/metrics` snapshot + the running PID's
      `--p2p-trust-bundle` baseline before the graceful shutdown
      completes, then recover offline per §6.F.9.
- [ ] Update `docs/whitepaper/contradiction.md` with the incident
      narrative if the incident revealed a missing fail-closed
      check.
- [ ] Postmortem: ensure §7 promotion checklist did not pass
      under the compromised authority; if it did, fix the gap.

---

## 9. Evidence checklist (for every production trust-bundle change)

This is the artefact set the auditor MUST be able to retrieve for
every bundle change. The directory layout MAY follow the existing
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_*.md` shape.

- [ ] `bundle.json` (the artifact that was distributed).
- [ ] `bundle.fp.hex` (the canonical fingerprint).
- [ ] `signing-key.spec` (the `--p2p-trust-bundle-signing-key`
      line used to verify; verification key only, never secret).
- [ ] `signing-key.id.hex` (the 64-hex `signing_key_id`).
- [ ] `previous-bundle.fp.hex` and `previous-bundle.sequence`
      (the bundle this one replaces).
- [ ] Positive smoke transcript: a fresh validator started with
      the new bundle, with `--p2p-pqc-root-mode pqc-static-root`,
      printed the Run 050/051/053/055/057 banners, the Run 062
      `[binary] Run 062: trust-bundle revocation activation
      (configured=… active=… pending=…)` banner, the Run 061
      `local-leaf startup self-check passed` line (when a
      `--p2p-leaf-cert` is supplied), the Run 063 `local-leaf
      issuer-root startup self-check passed` line, and the Run 040
      `dummy_kem_registered=false dummy_aead_registered=false`
      banner; `/metrics` reports the expected
      `qbind_p2p_pqc_trust_bundle_*` series, including the seven
      Run 062 `_revocations_*` gauges.
- [ ] Negative tamper smoke transcript (RUN_059 Smoke 3 shape).
- [ ] Wrong-chain smoke transcript (RUN_059 Smoke 5 shape).
- [ ] Rollback smoke transcript (RUN_056 Smoke 3 shape).
- [ ] If a root was revoked (immediate): revoked-root smoke
      (RUN_050 / RUN_062 Smoke 4 shape; expects the Run 050
      "no trusted roots" FATAL if all roots are revoked, or
      successful exclusion from `active_roots` otherwise).
- [ ] If a leaf was revoked (immediate): revoked-leaf smoke
      (RUN_054 / RUN_062 Smoke 2 shape) AND a Run 061 local-leaf
      startup self-check FATAL transcript on the validator that
      still uses that leaf (RUN_061 Smoke 2 shape).
- [ ] If a root revocation is intended to affect a validator
      whose local leaf was issued by that root: a Run 063
      local-issuer-root startup self-check FATAL transcript
      (RUN_063 Smoke 2 shape).
- [ ] If any revocation is SCHEDULED (`activation_height` set):
      a pending-revocation smoke transcript (RUN_062 Smoke 1 for
      leaf-scope OR Smoke 3 for root-scope) — exit non-FATAL, the
      `_revocations_*_pending` gauge shows the entry, and NEITHER
      the Run 061 nor the Run 063 startup self-check fires.
- [ ] If the bundle targets TestNet or MainNet: a Run 065 too-soon
      negative smoke transcript (RUN_065 Smoke 2 shape for
      TestNet, Smoke 4 shape for MainNet) — exit 1; the FATAL
      contains `pqc trust-bundle minimum activation-height policy
      violation (scope=bundle, environment=<env>, current_height=<h>,
      activation_height=<a>, minimum_margin=<8|32>,
      required_min_height=<h+margin>)`; the explicit "No fallback
      to --p2p-trusted-root" marker; AND a filesystem check
      confirming `pqc_trust_bundle_sequence.json` is NOT present
      under the `--data-dir` (i.e. the rejected bundle did not
      touch the loader outcome).
- [ ] Sufficient-margin / Run-057 boundary smoke transcript
      (RUN_065 Smoke 3 shape for TestNet at `activation_height =
      current + 8`, OR RUN_065 Smoke 5 shape for MainNet at
      `activation_height = current + 32`) — exit 1; the FATAL
      contains Run 057's `activation height not yet reached
      (scope=bundle, current_height=<h>, required_height=<h+margin>)`,
      NOT the Run 065 marker phrase. This proves Run 065 passed
      at the inclusive upper boundary and Run 057 took over.
- [ ] If a SCHEDULED revocation with `activation_height = Some(h)`
      is being introduced on TestNet/MainNet: confirmation that
      `h >= current_height + minimum_activation_margin` was used
      (otherwise the bundle would have been rejected at load with
      `RevocationActivationHeightBelowMinimumMargin`).
- [ ] Confirmation that no `--p2p-trusted-root` line was supplied
      on any validator.
- [ ] Confirmation that `pqc_root_mode=pqc-static-root` and no
      `Dummy*` is registered on every validator (Run 040 banner).
- [ ] Release binary identity: `sha256` and `ELF BuildID` of the
      `qbind-node` binary that ran the smokes.
- [ ] **If the change was delivered via Run 074 live reload-apply
      (SIGHUP) on a running validator:** captured operator log
      lines for every trigger
      (`[Run 074] LiveReloadOutcome::Applied { evicted=…,
      new_sequence=… }` on success, `… AlreadyInProgress` on
      every captured concurrent trigger, `… Invalid(…)` on every
      rejected candidate). Captured `/metrics` scrape with the
      six `qbind_p2p_trust_bundle_live_reload_*` counters/gauge
      AND the four `qbind_p2p_session_eviction_*` counters,
      taken AFTER the apply settled. On-disk
      `pqc_trust_bundle_sequence.json` (`highest_sequence` +
      `bundle_fingerprint`) captured BEFORE and AFTER the
      apply. Filesystem proof that the candidate file's
      `<CANDIDATE-PATH>` and the sequence file are inside the
      validator-local `--data-dir`. Optional Run 069 reload-check
      preflight transcript on the same candidate against a
      sibling host.
- [ ] **If the change was delivered via Run 073 process-start
      reload-apply:** captured operator log line
      (`AppliedCandidate::applied_log_line` on success, or
      `VERDICT=invalid …` on a fail-closed branch). Filesystem
      proof that the on-disk `pqc_trust_bundle_sequence.json`
      reflects the new candidate's `highest_sequence` +
      `bundle_fingerprint`.
- [ ] **If a hot-reload candidate was rejected as invalid (Run
      069/070/073/074):** filesystem proof of bytes-and-mtime
      equality on `pqc_trust_bundle_sequence.json` across the
      rejection (the rejected candidate MUST NOT have advanced
      the persisted sequence record).

---

## 10. Residual risks (NOT solved by this runbook)

This runbook narrows the C4 "production CA / certificate rotation
/ signing-key rotation operator playbook" item; Runs 061–063
closed three previously-open boundaries (local-leaf-fingerprint
startup self-check, per-entry revocation `activation_height`, and
local-issuer-root startup self-check); Run 065 closed the
per-environment minimum-activation-margin boundary on the binary
`--p2p-trust-bundle` load path; and Runs 069–074 closed the
local-operator hot-reload lifecycle (validation-only reload-check,
process-start reload-apply, and long-running SIGHUP live reload-
apply on a running node — see §6.F). The following remain open
under C4:

1. **Epoch-gating runtime source.** Bundle-level `activation_epoch`
   continues to fail closed with
   `TrustBundleActivationError::CurrentEpochUnavailable` (Run 057,
   pinned by Run 091 and reconfirmed by Run 092 — see
   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_091.md`,
   `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_092.md`, and the
   `crates/qbind-node/tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`
   coverage matrix).
   Per-entry `activation_epoch` on revocations is intentionally
   NOT supported either (Run 062 boundary; pinned by Run 091's
   `run091_revocation_schema_has_no_activation_epoch_field`
   exhaustive-destructure compile-time gate). Operators MUST NOT
   set `activation_epoch` on production bundles or on revocation
   entries. Run 065 does NOT introduce a minimum-margin policy on
   the epoch axis (the epoch runtime source itself remains open).
   Run 074's `LiveReloadController` initializes its
   `ActivationContext` to `height_only(0)` — the same height-only
   stance the startup `--p2p-trust-bundle` path uses today; a
   future run that lands a live height source can extend
   `LiveReloadConfig` without changing the SIGHUP surface.
   Run 091's investigation found that `MetaStore::get_current_epoch()`
   (persisted `meta:current_epoch`) is the closest candidate for a
   canonical pre-consensus epoch source but is NOT wired today
   because (a) `main.rs` does not open RocksDB before the trust-
   bundle gate, (b) fresh-genesis returns `Ok(None)` ambiguously,
   and (c) snapshot-rejoin parity would also require an `epoch`
   field on `StateSnapshotMeta` which is out of Run 091 scope.
   **Run 092 extends this finding with a source-level
   confirmation:** the production `qbind-node` binary does NOT
   open `RocksDbConsensusStorage` (or any `ConsensusStorage`)
   anywhere under `crates/qbind-node/src/**` — every real call
   site lives under `crates/qbind-node/tests/**` or in the
   `hotstuff_node_sim::EpochAwareNodeHotstuffHarness` test
   harness. The binary therefore never writes `meta:current_epoch`
   on production runs, and the "existing persisted MetaStore
   epoch" the Run 092 task asks about does not exist on a binary-
   run node. Narrow wiring without a broad storage redesign is
   therefore not achievable; closure requires a coordinated
   future run (preliminarily Run 093) that adds the canonical
   consensus-storage on-disk location, opens `RocksDbConsensusStorage`
   in `main.rs` before the trust-bundle gate, wires the binary-
   path consensus loop into `apply_epoch_transition_atomic`,
   extends `StateSnapshotMeta` with an additive `epoch` field
   for snapshot-rejoin parity, and disambiguates fresh-genesis
   from snapshot-rejoin without silently treating fresh-genesis
   as `current_epoch = 0`. Run 092 ships no source change and
   preserves the Run 091 fail-closed boundary exactly.
   **Run 093 lands the first half of that coordinated work**: the
   production `qbind-node` binary now opens
   `RocksDbConsensusStorage` at the canonical
   `<data_dir>/consensus` path (resolved by the new
   `NodeConfig::consensus_storage_dir()` helper) on every
   production startup (LocalMesh and P2P), once per process,
   immediately after `VmV0RuntimeState::open_from_config` and
   before the network-mode dispatch — preserving every early-exit
   validation mode unchanged. It runs the T104
   `ensure_compatible_schema` and M16
   `verify_epoch_consistency_on_startup` checks before consensus
   starts, probes `meta:current_epoch` through the existing
   `ConsensusStorage::get_current_epoch` API, and surfaces an
   explicit
   `ConsensusStorageState::{NoConsensusStorage,PresentNoCommittedEpoch,CommittedEpoch(u64)}`
   distinction whose `committed_epoch()` returns plain
   `Option<u64>` and never collapses `NoConsensusStorage` or
   `PresentNoCommittedEpoch` to `Some(0)`. Open / schema /
   recovery / probe failures all fail-closed with non-zero exit;
   the `Arc<RocksDbConsensusStorage>` handle is held in `main`'s
   scope for the binary lifetime and dropped on clean shutdown.
   **Trust-bundle activation behaviour is preserved unchanged**:
   no call from `production_consensus_storage` into
   `pqc_trust_activation` exists (pinned at the type level by
   `run_093_does_not_expose_consensus_storage_state_to_activation_context`),
   every `ActivationContext` construction in `main.rs` continues
   to set `current_epoch: None`, and Run 091's
   `CurrentEpochUnavailable` fail-closed boundary stays in effect
   on every environment and every production call site. The
   second half of the closure — wiring the binary-path consensus
   loop's epoch transitions onto `apply_epoch_transition_atomic`
   using the Run 093 handle, plus `StateSnapshotMeta.epoch`
   parity, plus the trust-bundle epoch-consumption hand-off —
   remains the documented next coordinated run(s) (preliminarily
   Run 094 + a separate snapshot-format run + a separate
   trust-bundle-hand-off run).

   **Run 094 lands the first half of that closure (binary-path
   epoch transition persistence wiring).** The Run 093 opened
   `Arc<RocksDbConsensusStorage>` handle is threaded from
   `main.rs` through `run_local_mesh_node` / `run_p2p_node` into
   the binary consensus loop via a new
   `BinaryConsensusLoopConfig::with_consensus_storage(Arc<dyn
   ConsensusStorage>)` builder. The loop tracks
   `last_persisted_epoch = engine.current_epoch()` at start and
   on every tick path that may have mutated engine state calls
   the new public helper `maybe_persist_engine_epoch_transition`,
   which issues `apply_epoch_transition_atomic(EpochTransitionBatch::
   new(target, previous, reconfig_block_id))` through the threaded
   handle if and only if the engine's *canonical* `current_epoch()`
   has advanced. Persistence failure surfaces as a typed
   `EpochPersistenceFailed` error and the loop fail-closes with
   `[binary-consensus] FATAL: ...`. The trigger is exclusively
   the engine's canonical `current_epoch()` counter — Run 094
   invents no synthetic / wall-clock / view-derived /
   height-derived / fake epoch. Operators will observe at
   startup on every binary-path invocation with a `--data-dir`:

   ```text
   [binary] Run 093 consensus storage: state=present-no-committed-epoch path=<data_dir>/consensus
   [binary] Run 094: binary consensus loop wired to canonical production ConsensusStorage handle (LocalMesh|P2P).
   ```

   A successful canonical epoch transition adds:

   ```text
   [binary-consensus] Run 094: persisting canonical engine epoch transition previous_epoch=<P> target_epoch=<T> reconfig_block_id=<hex>
   [M16] Atomic epoch transition: <P> -> <T> (block_id=<hex>, elapsed=<duration>)
   [binary-consensus] Run 094: meta:current_epoch=<T> durably persisted
   ```

   After such a transition, restart observes
   `state=committed-epoch:<T>` via the existing Run 093
   open-startup log line. Fresh genesis remains
   `present-no-committed-epoch` (NOT `0`); Run 091/092
   `CurrentEpochUnavailable` fail-closed behaviour for trust-
   bundle activation is preserved unchanged — every
   `ActivationContext` in `main.rs` continues to be built with
   `current_epoch: None`, and Run 094 introduces no consumption
   of the persisted epoch by activation. The binary-path
   consensus loop does NOT yet itself produce a canonical engine
   epoch transition end-to-end (the engine's `current_epoch()`
   only advances when a committed reconfig block is processed
   into `engine.transition_to_epoch`, which is the separately
   enumerated open C4 item *"activation_epoch real runtime
   source"* and is out of scope for Run 094); the call site is
   in place and will fire automatically once the runtime
   trigger lands in a separate run (preliminarily Run 095).
   **Run 095** lands that runtime trigger: a small per-loop
   `BinaryReconfigDetector` observes every proposal the binary
   loop already sees, caches the canonical wire-level
   `(BlockHeader::payload_kind, BlockHeader::next_epoch)` tuple
   keyed by canonical block ID, and — for any committed entry in
   `engine.commit_log()` whose cached header is
   `PAYLOAD_KIND_RECONFIG` — calls the existing
   `BasicHotStuffEngine::transition_to_epoch(...)` machinery before
   the Run 094 persistence helper runs. The actual committed
   reconfig block ID is threaded into the Run 094 helper as a new
   `Option<[u8; 32]>` argument; a typed
   `EpochPersistenceFailureSource::MissingReconfigBlockId` makes
   zero fallback unreachable on real transitions. Malformed
   (`next_epoch == 0`), non-monotonic (`next_epoch <=
   current_epoch`), and engine-rejected reconfig commits fail
   closed with typed `ReconfigTransitionError` variants and
   surface in the loop-exit summary as
   `reconfig_transition_failed=true`. Trust-bundle activation
   still does not consume `current_epoch` — every production
   `ActivationContext` continues to be constructed with
   `current_epoch: None`, and Run 091/092 fail-closed
   `CurrentEpochUnavailable` activation behaviour is preserved
   verbatim. Release-binary Scenario 2 (real committed reconfig
   transition end-to-end) remains gated on a separately-tracked
   peer-driven live apply / on-chain governance path that would
   introduce a canonical `PAYLOAD_KIND_RECONFIG` proposal onto the
   binary path; the existing binary-path leader code
   (`BasicHotStuffEngine::try_propose`) still hard-codes
   `PAYLOAD_KIND_NORMAL` / `next_epoch=0` into every emitted
   proposal. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_095.md`
   for full details.
2. **Peer-supplied / gossiped trust-bundle acceptance.** Runs
   069/073/074 accept **local files only**. There is no
   `BundleAnnounce` / `BundleRequest` over the wire, no admin-API
   trigger, and no filesystem-watcher trigger. **Runs 076–085
   added a strictly observation-only peer-candidate `0x05`
   exchange** (see §6.G) that validates inbound candidates
   without applying, propagating, mutating live trust, writing
   the sequence file, or evicting sessions — but this is a
   signal source, not an apply trigger. Run 087 adds the formal
   design-gate specification for any future propagation/apply work
   (`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`).
   **Run 088** adds a hidden, disabled-by-default,
   propagation-only prototype (`--p2p-trust-bundle-peer-candidate-propagation-enabled`)
   that rebroadcasts only validated frames, excludes the source
   peer, and still never applies / writes sequence / mutates live
   trust / evicts sessions. **Run 089** lands the release-binary
   N=3 DevNet propagation evidence for that prototype (§6.G.9 /
   §6.G.12). Peer-driven live
   apply / propagation remain OPEN: peer-driven apply is **not**
   implemented in any form, and propagation today is opt-in,
   does not synchronize trust state, does not ratify consensus,
   and does not substitute for §6.F.4 SIGHUP. When peer-driven apply or
   broader propagation lands, the same Run 065
   `pqc_trust_activation::check_min_activation_height_policy`
   helper, the same Run 050/051/053 validator pipeline, and the
   same Run 070 `validate → swap → evict → commit` ordering MUST
   be threaded through the peer-input path.
3. **Selective per-peer session retention.** Runs 072/073/074
   evict all sessions conservatively on a successful live apply.
   A future run that lands per-peer policy (e.g. retain peers
   whose leaf certs are still in the new bundle's active set)
   can refine `P2pSessionEvictor` without changing the Run 074
   SIGHUP surface or its tests.
4. **Admin-API / filesystem-watcher trigger surface.** Run 074
   ships SIGHUP only. A future run can add an authenticated
   admin RPC or a filesystem-watcher trigger without changing
   the `LiveReloadController` semantics or the
   `LiveReloadOutcome` types — but until such a run lands, the
   only operator trigger surface is process-start CLI flags
   (Runs 069/073) and `SIGHUP` to a running node (Run 074).
5. **Production fast-sync / consensus-storage restore.** Separate
   C4 piece; trust-bundle persistence is independent. The
   `--restore-from-snapshot` `snapshot_height` already feeds the
   Run 057 + Run 065 `current_height` source via
   `ActivationContext::height_only`; the live binary does not
   yet replay `TrustBundleRecord` from a snapshot, and live apply
   on a partially-restored node is not separately proven.
6. **Per-environment production trust-anchor operation.** Not
   fully solved by documentation alone; depends on the operator
   actually using offline / HSM custody for the secrets in §3.2
   and §3.4.
7. **In-binary / on-chain bundle-signing-key rotation /
   ratification.** The binary does NOT ratify a new bundle-signing
   key on-chain or in-binary. §6.D is an out-of-band CLI overlap
   procedure. If a future runtime adds on-chain ratification,
   this runbook MUST be updated.
8. **Two-node / N-node MainNet release-binary peer-connection
   smoke evidence.** RUN_059 produced a single-validator MainNet
   release-binary smoke; a multi-validator MainNet
   peer-connection smoke remains on the C4 list (blocked by
   unrelated production-config items — validator keystore loading
   on startup, per-peer consensus-key distribution).
9. **External KMS / HSM integration.** This runbook treats the
   signing-key custody surface as an interface boundary; full
   KMS integration is not in scope.

**Closed by Runs 061–063, Run 065, and Runs 069–074 (no longer
in §10):**

- Local-leaf-fingerprint startup self-check — closed by Run 061
  (`pqc_trust_bundle::check_local_leaf_not_revoked` + the FATAL
  call site in `main.rs`). The binary now fails closed at startup
  if `--p2p-leaf-cert`'s canonical fingerprint is in the
  bundle's active `revoked_leaf_fingerprints`.
- Per-entry revocation activation gate — closed by Run 062
  (optional, ML-DSA-44-signature-covered `activation_height` on
  every revocation entry; deterministic active/pending split;
  seven new `qbind_p2p_pqc_trust_bundle_revocations_*` gauges).
- Local-issuer-root startup self-check — closed by Run 063
  (`pqc_trust_bundle::check_local_leaf_issuer_root_not_revoked` +
  the FATAL call site immediately after Run 061). The binary now
  fails closed at startup if the local leaf cert decodes to a
  `root_key_id` in the bundle's active `revoked_root_ids`.
- Per-environment minimum activation-margin policy on the binary
  `--p2p-trust-bundle` load path — closed by Run 065
  (`pqc_trust_activation::check_min_activation_height_policy` +
  `MIN_{DEVNET,TESTNET,MAINNET}_ACTIVATION_MARGIN` constants
  (`0` / `8` / `32`)). The binary now fails closed at load if a
  bundle's `activation_height` (bundle-level, per-active-root, or
  per-entry revocation when `Some(_)`) is in the half-open reject
  window `[current_height, current_height + margin)` on the
  configured environment. Emergency immediate revocations
  (`activation_height = None`) remain exempt.
- **Validation-only operator-triggered trust-bundle reload-check
  on a local file** — closed by Run 069
  (`--p2p-trust-bundle-reload-check <PATH>` +
  `pqc_trust_reload::validate_candidate_bundle_full` +
  `pqc_trust_sequence::peek_sequence`). Non-mutating by
  construction: no live trust mutation, no sequence commit, no
  session eviction, no `/metrics` family.
- **Apply contract + rollback semantics for live trust apply** —
  closed by Run 070 (`ApplyMode`, `ReloadApplyError`,
  `LiveTrustApplyContext`, `apply_validated_candidate{,_with_previous}`,
  `AppliedCandidate::applied_log_line`). Strict
  `validate → snapshot → swap → evict → commit` ordering;
  per-stage rollback; distinct fatal variant when post-rollback
  fails.
- **Mutable shared live trust handle** — closed by Run 071
  (`LivePqcTrustState` = `Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`;
  `P2pNodeBuilder::with_live_pqc_trust(...)` routes the
  listener-side `TrustedClientRoots` resolver and the
  bidirectional `LeafCertRevocationList` revocation closure
  through `snapshot()`).
- **Production internal P2P session-eviction hook** — closed by
  Run 072 (`P2pSessionEvictor` trait +
  `TcpKemTlsP2pService::evict_all_sessions` + four
  `qbind_p2p_session_eviction_*` counters with the truthful
  `attempted == evicted + failed` invariant).
- **Process-start operator-triggered local-file reload-apply
  against the running binary's live trust handle** — closed by
  Run 073 (`ProductionLiveTrustApplyContext` composes Runs
  069/070/071/072/055 end-to-end; the binary's
  `--p2p-trust-bundle-reload-apply-path` hook removes
  `ReloadApplyError::UnsupportedRuntimeContext` from the local-
  operator path).
- **Long-running local operator-triggered live trust-bundle
  reload-apply via SIGHUP** — closed by Run 074
  (`LiveReloadController` + `spawn_run074_live_reload_task` +
  two hidden CLI flags + `Arc<AtomicBool>` CAS in-progress
  guard + six `qbind_p2p_trust_bundle_live_reload_*`
  counters/gauge). Valid candidates apply while the node remains
  running; invalid candidates do not mutate trust state,
  sequence, or sessions; concurrent triggers serialize as
  `AlreadyInProgress`; only the fatal post-rollback-failure arm
  signals shutdown.

**Full C4 remains OPEN. C5 is NOT closed by this runbook.**

---

## 11. Mapping to Runs 050–101

| Run | What it proved | What §section of this runbook relies on it |
|---|---|---|
| 050 | Structured bundle schema, environment + chain_id + validity + revocation fail-closed boundaries. | §1.3, §3.7, §5.1–5.3, §6.A, §7. |
| 051 | ML-DSA-44 signed-bundle verification; signing-key/root-id collision check. | §1.3, §2.2, §3.3, §4.2, §6.D, §7. |
| 052 | Leaf-level revocation; listener-side fail-closed on revoked-leaf handshake. | §3.6, §3.9, §6.C, §7, §9. |
| 053 | `chain_id` crosscheck at bundle load (before signature side-effects). | §1.3, §3.11, §5.2, §5.3, §7. |
| 054 | Release-binary leaf-revocation evidence helper modes. | §3.9, §6.C, §7, §9. |
| 055 | Sequence anti-rollback persistence (rollback, equivocation, corrupt-file fail-closed). | §1.3, §3.8, §6.A, §6.B, §6.D, §7. |
| 056 | Release-binary anti-rollback evidence (positive upgrade, rollback, equal-sequence different-fp, corrupt persistence). | §3.8, §6.A, §7. |
| 057 | Bundle-level activation-height gating (`current_height` source from restore baseline or 0; future activation does NOT advance persisted sequence). | §1.3, §3.10, §6.A, §6.E, §7. |
| 058 | Release-binary activation-height evidence (positive active-now, negative future-height, positive upgrade-after-rejection). | §3.10, §6.A, §7. |
| 059 | MainNet signed-bundle release-binary smoke (positive, unsigned, tampered, wrong key, wrong chain). | §1.3, §5.3, §7, §9. |
| 060 | Operator playbook landed (this runbook). | All §sections. |
| 061 | Local-leaf-fingerprint startup self-check: binary fails closed before P2P startup if `--p2p-leaf-cert` is in the bundle's active `revoked_leaf_fingerprints`. | §1.3, §3.9, §6.C variant 2, §7, §9, §10 (closed item). |
| 062 | Per-entry revocation `activation_height`: signature-covered, active/pending split, seven new `qbind_p2p_pqc_trust_bundle_revocations_*` gauges. | §1.3, §3.9, §3.10, §6.A, §6.B, §6.C, §6.E, §7, §9, §10 (closed item). |
| 063 | Local-issuer-root startup self-check: binary fails closed before P2P startup if the local leaf cert decodes to a `root_key_id` in the bundle's active `revoked_root_ids`. Independent of Run 061. | §1.3, §6.A, §6.B, §6.E, §7, §9, §10 (closed item). |
| 064 | Operator-playbook prose update for Runs 061–063 (docs-only). | All §sections. |
| 065 | Per-environment minimum activation-margin policy on the `--p2p-trust-bundle` load path: `MIN_DEVNET_ACTIVATION_MARGIN = 0`, `MIN_TESTNET_ACTIVATION_MARGIN = 8`, `MIN_MAINNET_ACTIVATION_MARGIN = 32`. Half-open `[current_height, current_height + margin)` reject window covers bundle-level, per-active-root, and per-entry revocation `activation_height` when `Some(_)`. Already-effective bundles are NOT retroactively rejected (snapshot-rejoin). Per-entry revocations with `activation_height = None` are immediate and exempt (emergency-revocation path preserved on MainNet). Policy runs BEFORE Run 057's future-height gate, Run 055's sequence persistence, and Run 050's root merge — rejected too-soon bundles do not touch the persisted sequence or the live trust set. Proved on the live release binary by RUN_065 Smokes 1 (DevNet positive at activation_height=0), 2 (TestNet too-soon negative, Run 065 fires), 3 (TestNet at-margin = Run 057 boundary), 4 (MainNet too-soon negative, Run 065 fires with margin=32), 5 (MainNet at-margin = Run 057 boundary with required_height=32). | §1.3, §3.9, §3.10, §5.1, §5.2, §5.3, §6.A, §6.B, §6.E, §7, §8, §9, §10 (closed item). |
| 066 | Operator-playbook prose update for Run 065 (docs-only). | All §sections. |
| 069 | Validation-only operator-triggered trust-bundle reload-check on a local file: `--p2p-trust-bundle-reload-check <PATH>` (hidden) drives `pqc_trust_reload::validate_candidate_bundle_full` over the candidate using the same startup security pipeline; non-mutating by construction (no `LivePqcTrustState` mutation, no `check_and_update_sequence` call — uses read-only `peek_sequence`, no `evict_all_sessions`, no `/metrics` family, no sequence number burned on rejected or unapplied candidates). Hook positioned BEFORE network-mode dispatch; node does not start in this mode (exits 0/1). | §1.2, §1.3, §6.F.2, §6.F.5, §6.F.6, §7, §9, §10 (closed item). |
| 070 | Apply contract + rollback semantics: `ApplyMode`, `ReloadApplyError`, `LiveTrustApplyContext`, `apply_validated_candidate{,_with_previous}`, `AppliedCandidate::applied_log_line`. Strict `validate → snapshot → swap → evict → commit` ordering; per-stage rollback; distinct `SequenceCommitFailedRollbackAlsoFailed` fatal variant. Library boundary still surfaces `UnsupportedRuntimeContext` for callers omitting the apply context. | §1.3, §6.F.5, §6.F.9. |
| 071 | Mutable shared live trust handle `LivePqcTrustState = Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`; `P2pNodeBuilder::with_live_pqc_trust(...)` routes the listener-side `TrustedClientRoots` resolver + bidirectional `LeafCertRevocationList` revocation closure through `snapshot()`. Byte-identical startup behaviour. No live mutation introduced by Run 071. | §1.3, §6.F.4, §6.F.5. |
| 072 | Production internal P2P session-eviction hook: `EvictionReason`, `EvictionReport` with truthful `attempted == evicted + failed` invariant, `EvictionError`, sync `P2pSessionEvictor` trait, `TcpKemTlsP2pService::evict_all_sessions` (drains per-peer registry, drops `tx`, aborts `JoinHandle`s), four `qbind_p2p_session_eviction_*` counters. v0 policy = "evict all"; selective retention remains OPEN. | §1.3, §6.F.4, §6.F.5, §6.F.6, §6.F.10, §10 (closed item; selective retention still open). |
| 073 | `ProductionLiveTrustApplyContext` adapter composes Runs 069/070/071/072/055 end-to-end. Binary's `--p2p-trust-bundle-reload-apply-enabled` + `--p2p-trust-bundle-reload-apply-path <PATH>` hook (hidden, required-together) drives a live apply at process-start time over `NoActiveSessionsEvictor` (truthful zero-session report); `ReloadApplyError::UnsupportedRuntimeContext` removed from the local-operator path. Library boundary preserved for callers omitting apply context. | §1.2, §1.3, §6.F.3, §6.F.5, §6.F.6, §7, §9, §10 (closed item). |
| 074 | Long-running local operator-triggered live trust-bundle reload-apply via SIGHUP: hidden `--p2p-trust-bundle-live-reload-enabled` + `--p2p-trust-bundle-live-reload-path <PATH>` (required-together; refused without `--p2p-trust-bundle <BASELINE-PATH>`). `LiveReloadController` constructs a fresh `ProductionLiveTrustApplyContext` per trigger; `Arc<AtomicBool>` CAS guard serializes concurrent triggers as `AlreadyInProgress`. Six new `qbind_p2p_trust_bundle_live_reload_*` counters/gauge. Only the `Fatal` (`SequenceCommitFailedRollbackAlsoFailed`) arm signals shutdown; valid candidates apply while the node remains running; invalid candidates do not mutate trust, sequence, or sessions. | §1.2, §1.3, §6.F.4, §6.F.5, §6.F.6, §6.F.7, §6.F.8, §6.F.9, §6.F.10, §9, §10 (closed item). |
| 075 | Operator-playbook prose update for Runs 069–074 (docs-only). | All §sections (esp. §1, §6.F, §7, §9, §10, §11, §12). |
| 076 | Library-level **disabled-by-default** peer-candidate validation boundary: `PeerCandidateValidator::try_accept` runs a candidate `PeerCandidateEnvelope` through the same Run 050/051/053/057/065 startup pipeline; no live mutation, no sequence write. | §6.G.1, §6.G.2. |
| 077 | Production-binary-facing **local** peer-candidate check mode: hidden `--p2p-trust-bundle-peer-candidate-validation-enabled` + `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>`. Reuses Run 076 `PeerCandidateValidator::try_accept`. Node does not start; exits 0/1. Non-mutating by construction. | §6.G.1, §6.G.2, §12. |
| 078 | Bounded, typed, versioned peer-candidate **wire envelope** (`pqc_peer_candidate_wire`) with deterministic canonical bytes and size cap. Library-level; not yet on the live socket. | §6.G.2. |
| 079 | **Disabled-by-default live P2P receive-loop dispatch** for inbound `0x05` frames: hidden `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`. Each inbound frame is routed through the same Run 076 validator; receiver-side `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters move only when the flag is on. | §6.G.1, §6.G.2, §6.G.5, §12. |
| 080 | **Disabled-by-default send-side publisher** plumbing: hidden `--p2p-trust-bundle-peer-candidate-wire-publish-enabled` + `--p2p-trust-bundle-peer-candidate-wire-publish-path <PATH>` + `--p2p-trust-bundle-peer-candidate-wire-publish-once`. Publishes one operator-supplied envelope over a live authenticated P2P session as a real `0x05` frame; no auto-resend. | §6.G.2, §12. |
| 081 | First release-binary N=2 real `0x05` exchange evidence; partial only due to `DummySig` ambiguity on the consensus signer probe path. | §6.G.2 (history). |
| 082 / 083 | Isolated the `DummySig` boundary as non-active / probe-log-only with respect to the peer-candidate `0x05` matrix. | §6.G.2 (history). |
| 084 | Committed repeatable **N=2 DevNet** harness `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh`; closed the N=2 evidence gap: baseline / valid / receiver-disabled / invalid-wrong-chain / duplicate scenarios all pass; sequence hashes unchanged; live-reload-apply + session-eviction metrics stayed zero; no propagation; no Dummy crypto; no `--p2p-trusted-root` fallback. | §6.G.5, §6.G.6, §10 (peer-driven apply / propagation still open). |
| 085 | Committed repeatable **N=4 MainNet** harness `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh`; strongest current evidence: all five MainNet scenarios pass on four release `qbind-node` processes with signed MainNet trust material; sequence hashes unchanged; live-reload-apply + session-eviction metrics stayed zero; no propagation; no active `DummySig` / `DummyKem` / `DummyAead`; no `--p2p-trusted-root` fallback. | §6.G.1, §6.G.5, §6.G.6, §10 (peer-driven apply / propagation still open). |
| 086 | Operator-playbook prose update for Runs 076–085 (docs-only). Adds §6.G peer-candidate validation-only lifecycle, extends §10 / §11 / §12, no source changes. | All §sections (esp. §1, §6.G, §10, §11, §12). |
| 087 | Formal peer trust-bundle propagation/apply safety specification (docs-only). Defines future gates; no runtime behavior change; peer-candidate `0x05` remains validation-only. | §1, §6.G.8, §6.G.12, §10, §11. |
| 088 | Hidden, disabled-by-default propagation-only peer-candidate prototype: `--p2p-trust-bundle-peer-candidate-propagation-enabled`; validation-before-rebroadcast; source-peer exclusion; local seen-cache; bounded rate/fanout/queue. Five new `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_*` counters. No apply, no sequence write, no `LivePqcTrustState` mutation, no session eviction; the `peer_candidate_applied_total` family is intentionally absent. | §1, §6.G.9, §6.G.10, §6.G.11, §6.G.12, §6.G.13, §10, §12. |
| 089 | Release-binary **N=3 DevNet** propagation evidence: `scripts/devnet/run_089_peer_candidate_propagation_n3.sh`. V0 → V1 → V2 propagation succeeds only after V1 validation; V1 excludes V0 (`V0.received_total == 0` after 5 s settle); invalid wrong-chain not rebroadcast; duplicate not rebroadcast a second time; sequence files byte-identical before/after on every node; `live_reload_apply_*` / `session_eviction_*` zero; `peer_candidate_applied_total` family absent; no `--p2p-trusted-root` fallback; no active `DummySig` / `DummyKem` / `DummyAead`; consensus progresses in the propagation-enabled topology. | §1, §6.G.9, §6.G.11, §6.G.12, §6.G.13, §10. |
| 090 | Operator-playbook prose update for the propagation-only lifecycle from Runs 087–089 (docs-only). Adds §6.G.9 / §6.G.10 / §6.G.11 / §6.G.12 / §6.G.13; renames §6.G to "validation-only and propagation-only"; extends §10 / §11 / §12. No source changes. | All §sections (esp. §1, §6.G, §10, §11, §12). |
| 091 | **Partial-positive** boundary pin for the C4 sub-piece "`activation_epoch` runtime source": investigates and documents the available epoch sources (`MetaStore::get_current_epoch()`, `StateSnapshotMeta`, consensus engine), explains why none are wired into the trust-bundle activation gate today, and lands `crates/qbind-node/tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs` (15 integration tests) pinning fail-closed `CurrentEpochUnavailable` behaviour on DevNet/TestNet/MainNet at the bundle-level, per-active-root, startup-load, reload-check, SIGHUP, and peer-candidate surfaces, plus an exhaustive-destructure compile-time gate against per-entry revocation `activation_epoch` schema drift. No source changes; no new metric families (the existing `pqc_trust_bundle_activation_epoch_*` gauges plus the combined `_activation_rejected_total` counter remain the canonical surface); preserves every Run 050–090 invariant. | §1, §3.10, §10.1, §11. |
| 092 | **Partial-positive** follow-up to Run 091 attempting the narrow canonical pre-consensus epoch-source wiring for trust-bundle activation using the existing persisted `MetaStore` (`meta:current_epoch`) value. Source-level finding: the production `qbind-node` binary does NOT open `RocksDbConsensusStorage` (or any `ConsensusStorage`) anywhere under `crates/qbind-node/src/**` — every real call site lives under `crates/qbind-node/tests/**` or in `hotstuff_node_sim::EpochAwareNodeHotstuffHarness`. The binary therefore never writes `meta:current_epoch` on production runs, so the "existing persisted MetaStore epoch" the task asks about does not exist on a binary-run node. Wiring it requires a broad storage redesign (add canonical `<data_dir>/consensus` location to `NodeConfig`; open `RocksDbConsensusStorage` in `main.rs` before the trust-bundle gate; thread the binary-path consensus loop into `apply_epoch_transition_atomic`; extend `StateSnapshotMeta` with an additive `epoch` field for snapshot-rejoin parity; disambiguate fresh-genesis from snapshot-rejoin without silently treating fresh-genesis as `current_epoch = 0`) which is explicitly out of Run 092 scope. Run 092 preserves the Run 091 fail-closed `CurrentEpochUnavailable` boundary unchanged on every environment and production call site, preserves the Run 050–091 strict ordering exactly, and confirms by code inspection that every `ActivationContext` construction in `main.rs:296-303 / :540-547 / :898-905 / :939-942 / :1760-1767 / :2568 / :3418` continues to set `current_epoch: None`. No source-code change under `crates/**/src/**`; no test change under `crates/**/tests/**`; no new metric families; no new dependencies. Doc-only update: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_092.md` (new), `docs/whitepaper/contradiction.md` (Run 092 update), this runbook (§10.1 cross-reference + §11 row), `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` (§9 cross-reference). Recommended next: cross-cutting "Run 093 — binary `MetaStore` open + consensus-path epoch persistence + `StateSnapshotMeta` epoch parity" run scoped to the nine steps enumerated in the Run 092 evidence §"Immediate next action recommended". | §1, §3.10, §10.1, §11. |
| 093 | **Partial-positive** for the bounded scope. Lands the **minimum production binary-path `ConsensusStorage` lifecycle and durable epoch persistence groundwork**: adds `NodeConfig::consensus_storage_dir()` resolving the canonical `<data_dir>/consensus` location; adds new module `crates/qbind-node/src/production_consensus_storage.rs` with `ConsensusStorageState::{NoConsensusStorage,PresentNoCommittedEpoch,CommittedEpoch(u64)}`, `OpenedProductionConsensusStorage`, `ProductionConsensusStorageError`, and `open_production_consensus_storage(&NodeConfig)`; wires this into `crates/qbind-node/src/main.rs` immediately after `VmV0RuntimeState::open_from_config` and before the network-mode dispatch (preserving all early-exit validation modes — `--p2p-trust-bundle-reload-check`, `--p2p-trust-bundle-reload-apply`, peer-candidate check — unchanged); runs T104 `ensure_compatible_schema` and M16 `verify_epoch_consistency_on_startup` before consensus starts; probes `meta:current_epoch` through the existing `ConsensusStorage::get_current_epoch` API (no synthetic epoch, no wall-clock, no block-height-as-epoch); fail-closed with non-zero exit on any open / schema / recovery / probe error; holds the `Arc<RocksDbConsensusStorage>` handle for the binary lifetime and drops cleanly on shutdown. `ConsensusStorageState::committed_epoch()` returns plain `Option<u64>` and **never** collapses `NoConsensusStorage` or `PresentNoCommittedEpoch` to `Some(0)`. Trust-bundle activation behaviour preserved unchanged: every `ActivationContext` in `main.rs` continues to set `current_epoch: None`, and Run 091's `CurrentEpochUnavailable` fail-closed boundary stays in effect on every environment and every production call site (no call from `production_consensus_storage` into `pqc_trust_activation` exists; pinned at the type level by `run_093_does_not_expose_consensus_storage_state_to_activation_context`). 7 new unit tests + 12 new integration tests (`crates/qbind-node/tests/run_093_production_consensus_storage_lifecycle_tests.rs`) cover the canonical path, the three startup-state variants, committed-epoch persistence across simulated restart through the existing MetaStore `put_current_epoch` / `get_current_epoch` APIs, RocksDB-lock-held second-open fail-closed, unwritable-data-dir fail-closed, no parallel epoch-write path, and the type-level no-conversion-to-`ActivationContext` invariant. Run 091 (15 / 15), Run 057 (12 / 12), Run 065 (12 / 12), Run 069 (12 / 12), Run 073 (10 / 10), Run 074 (10 / 10), Run 076 (16 / 16), Run 088 (5 / 5), full `qbind-node --lib` (1070 / 1070), `qbind-net --lib` (17 / 17), `qbind-crypto --lib` (68 / 68), and the release builds (`qbind-node` binary + `devnet_pqc_trust_bundle_helper` + `devnet_pqc_root_helper` examples) all pass with no regressions. N=1 release-binary smoke evidence under `docs/devnet/run_093_smoke_n1_{first_start,restart}.{stderr,stdout}.log` shows the canonical `<data_dir>/consensus` path created on disk and re-opened cleanly across restart. End-to-end committed-epoch persistence on the release binary is NOT yet proven — the production binary-path consensus loop does not yet emit epoch transitions onto `apply_epoch_transition_atomic`, so the observed state stays `present-no-committed-epoch` end-to-end. This is the documented partial-positive boundary that closes with Run 094. No change to `pqc_trust_activation::ActivationContext`, no change to `StateSnapshotMeta` (snapshot epoch parity remains a separate run), no new metric family, no new CLI flag, no new dependency, no DummySig / DummyKem / DummyAead. Recommended next: **Run 094 — wire the binary-path consensus loop's epoch transitions onto `apply_epoch_transition_atomic` using the Run 093 storage handle**, scoped to the five steps enumerated in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_093.md` §"Exact immediate next action recommended". | §1, §3.10, §10.1, §11. |
| 094 | **Partial-positive** for the bounded scope. Lands the **smallest production-honest binary-path wiring** that makes the real `qbind-node` binary persist committed epoch transitions through the Run 093 canonical `ConsensusStorage` handle. Threads the Run 093 opened `Arc<RocksDbConsensusStorage>` from `crates/qbind-node/src/main.rs` through both `run_local_mesh_node` and `run_p2p_node` into `BinaryConsensusLoopConfig` via a new `with_consensus_storage(Arc<dyn ConsensusStorage>)` builder (a manual `Debug` impl on the config replaces the prior derive so the `ConsensusStorage` trait need not require `Debug`). Adds a new public helper `maybe_persist_engine_epoch_transition(engine, storage, &mut last_persisted_epoch) -> Result<bool, EpochPersistenceFailed>` in `crates/qbind-node/src/binary_consensus_loop.rs` that reads `engine.current_epoch()` and, if and only if it has advanced above `last_persisted_epoch`, issues `apply_epoch_transition_atomic(EpochTransitionBatch::new(target, previous, reconfig_block_id))` through the threaded handle using `engine.committed_block()` as the reconfig anchor. The binary consensus loop initialises `last_persisted_epoch = engine.current_epoch()` at start and calls the helper on every tick path that may have mutated engine state (the three existing `update_state_metrics` call sites — inbound-message handler, ticker tick in the inbound-IO branch, ticker tick in the no-inbound-IO branch). Persistence failure surfaces as a typed `EpochPersistenceFailed` error carrying `previous_epoch`, `target_epoch`, `reconfig_block_id`, and the `StorageError` source; the loop logs `[binary-consensus] FATAL: <EpochPersistenceFailed>` and breaks the tick loop (fail-closed exit), with the loop-exit summary now including `last_persisted_epoch=<N> epoch_persistence_failed=<bool>` for audit. The persistence trigger is **exclusively** the engine's own canonical `current_epoch()` counter — Run 094 invents **no** synthetic epoch, **no** wall-clock epoch, **no** view-derived epoch, **no** block-height-derived epoch, and **no** fake transition for tests. Reuses the existing M16 atomicity / T104 schema / incomplete-transition-recovery / corruption-guardrail surface unchanged. No new MetaStore key, no parallel storage open, no new CLI flag, no new metric family, no new dependency, no DummySig / DummyKem / DummyAead. Trust-bundle activation behaviour preserved unchanged: every `ActivationContext` in `main.rs` continues to be built with `current_epoch: None`; Run 091/092 `CurrentEpochUnavailable` fail-closed behaviour preserved on every environment and every production call site. Fresh genesis on the binary path remains `present-no-committed-epoch` (NOT implicit `0`). 7 new integration tests in `crates/qbind-node/tests/run_094_binary_path_epoch_transition_persistence_tests.rs` cover: no-engine-advance no-write, canonical-advance triggers atomic write, only-engine-current-epoch is the trigger, multi-step advance persists each step once, fail-closed `EpochPersistenceFailed` on injected write failure with non-advanced cursor, end-to-end restart through the Run 093 `open_production_consensus_storage` surface observing `CommittedEpoch(n)`, and the `ConsensusStorageState::committed_epoch()` three-variant `Option<u64>` shape pin. Run 091 (15 / 15), Run 093 (12 / 12), Run 094 (7 / 7), `epoch_persistence_tests` / `epoch_startup_validation_tests` (passing), `binary_path_b1_b2_b4_tests` (4 / 4), `b5_restore_aware_consensus_start_tests` (4 / 4), `c4_b6_p2p_binary_path_interconnect_tests` (5 / 5), full `qbind-node --lib` (**1070 / 1070**), and the release build (`qbind-node` binary) all pass with no regressions. N=1 release-binary smoke (`/tmp/run094_smoke/n1_{fresh,restart}.stderr.log`) shows on every observed startup `[binary] Run 093 consensus storage: state=present-no-committed-epoch path=<data_dir>/consensus` followed by `[binary] Run 094: binary consensus loop wired to canonical production ConsensusStorage handle (LocalMesh)` and `[M16] Epoch consistency check passed: current_epoch=None`, with canonical RocksDB column-family layout present on disk and re-opened cleanly across restart. Release-binary end-to-end real-epoch-transition Scenario-2 evidence is **not exercised** by Run 094 — the production binary-path consensus loop does not yet itself trigger a canonical engine epoch transition (the engine's `current_epoch()` only advances when a committed reconfig block is processed into `engine.transition_to_epoch`, which is the separately enumerated open C4 item *"activation_epoch real runtime source"* and is explicitly out of Run 094 scope per `task/RUN_094_TASK.txt` §"Strict non-goals"). The bounded honest proof landed is the source-level integration test `run_094_committed_epoch_survives_restart_via_run_093_surface`, which exercises the same `apply_epoch_transition_atomic` machinery the binary will call, through the same `open_production_consensus_storage` lifecycle the binary uses, against an engine whose `current_epoch()` has actually advanced. Recommended next: **Run 095 — wire the binary-path consensus loop's reconfig-block commit detection onto `BasicHotStuffEngine::transition_to_epoch` using the existing reconfig block schema** (Run 095 will add no new persistence code — the Run 094 call site fires automatically on engine epoch advance). | §1, §3.10, §10.1, §11. |
| 096 | **Positive** for the bounded scope. Lands the **smallest production-honest binary-path source of canonical reconfig proposals** — the residual piece Run 095 explicitly deferred (release-binary Scenario 2 / Scenario 3). Adds a single-shot, local-operator-gated reconfig proposal intent on `BasicHotStuffEngine` (`pending_reconfig_next_epoch: Option<u64>` + `set_pending_reconfig_next_epoch` / `pending_reconfig_next_epoch` / `clear_pending_reconfig_next_epoch` + typed `PendingReconfigIntentError { TargetEpochZero, NonMonotonicTarget }`) and consumes it inside the **existing** `on_leader_step` proposal construction path so that exactly one canonical `BlockHeader { payload_kind: PAYLOAD_KIND_RECONFIG, next_epoch: N, .. }` block is emitted the next time the engine is leader. The intent is **single-shot**: cleared after one emission; stale intent (`target <= current_epoch` at consume) is dropped silently and a normal block is emitted — Run 096 never emits a synthetic or regressive reconfig. The binary loop installs the intent on the engine at startup via a new `BinaryConsensusLoopConfig::with_reconfig_proposal(BinaryReconfigProposalConfig { target_epoch })` builder; the binary CLI surfaces a hidden, disabled-by-default operator flag `--devnet-reconfig-proposal-next-epoch <N>` plumbed through both `run_local_mesh_node` and `run_p2p_node` via the pure helper `derive_reconfig_proposal_from_cli_flag(raw_flag, is_mainnet) -> Result<Option<BinaryReconfigProposalConfig>, ReconfigProposalCliError>` (typed errors: `TargetEpochZero`, `MainnetRefused { target_epoch }`). The CLI gate refuses `N == 0`, refuses MainNet (no governance path authorizes operator-gated reconfig proposals on MainNet today), and the engine layer refuses non-monotonic targets at both intent-arm time and consume time — three layers of fail-closed defence. When the canonical reconfig block emitted by the engine commits through the **existing** HotStuff commit rule, the Run 095 detector classifies it via the canonical `(payload_kind, next_epoch)` header fields, calls `BasicHotStuffEngine::transition_to_epoch(EpochId::new(N), engine.validators().clone())` end-to-end, and the Run 094 persistence hook writes `meta:current_epoch = CommittedEpoch(N)` through the canonical production `ConsensusStorage` handle with the **actual** committed reconfig block ID (Run 095 `MissingReconfigBlockId` fail-closed invariant preserved). No parallel reconfig wire format (uses existing `BlockHeader.payload_kind` + `next_epoch`); no redesign of HotStuff commit rules, epoch semantics, or validator-set rotation; no peer-driven live apply; no `pqc_trust_activation::ActivationContext { current_epoch }` change; no trust-bundle wire-format change; no KMS/HSM custody; no filesystem watcher; no new metric family; no new dependency. 12 new engine-side unit tests (`basic_hotstuff_engine.rs::tests::run_096_*`) cover intent set/clear/validation, leader proposal carries canonical reconfig fields, one-shot consumption, stale-intent dropped, non-leader does not consume, and error-display fail-closed strings. 9 new integration tests in `crates/qbind-node/tests/run_096_binary_path_reconfig_proposal_source_tests.rs` cover the loop config builder, the default-no-intent path is bit-equivalent to pre-Run-096, the **end-to-end Scenario 2 + 3** path driven through `spawn_binary_consensus_loop` (armed intent → `PAYLOAD_KIND_RECONFIG` proposal → Run 095 detector classifies → Run 094 persists `CommittedEpoch(1)`), the default-no-intent path leaves storage `PresentNoCommittedEpoch`, the engine-layer zero-target refusal, and the CLI gate (default-is-none, refuses zero, refuses MainNet, accepts valid DevNet). Run 094 (7 / 7), Run 095 (11 / 11), Run 096 (9 / 9), `binary_path_b1_b2_b4_tests` (4 / 4), `b5_restore_aware_consensus_start_tests` (5 / 5), `b9_late_peer_connect_proposal_reemit_tests` (6 / 6), `b10_engine_acceptance_qc_closure_tests` (4 / 4), `b11_consensus_net_prometheus_coverage_tests` (passing), `qbind-consensus --lib` (**162 / 162**) and `qbind-node --lib` (**1070 / 1070**) all pass with no regressions. Run 091/092 `CurrentEpochUnavailable` fail-closed activation behaviour preserved verbatim; every production `ActivationContext` continues to be built with `current_epoch: None`. Fresh genesis still remains no-epoch, **not** epoch `0`. Run 096 does **not** close full C4 (peer-driven live apply, peer/gossip propagation, admin-API / filesystem-watcher triggers, MainNet authorization path, validator-set rotation primitive, `activation_epoch` runtime sourcing, snapshot epoch parity, KMS/HSM custody, on-chain signing-key ratification, production fast-sync restore, per-environment trust-anchor operation, N-node MainNet release-binary peer-connection smoke all remain OPEN) and does **not** claim C5 closure. Run 096's reconfig source is an explicitly **non-governance, DevNet/TestNet-only evidence path**: it produces honest end-to-end Scenario 2 / Scenario 3 evidence under the existing canonical reconfig representation without inventing a parallel wire format or a governance ratification path that does not yet exist. | §1, §3.10, §10.1, §11. |
| 097 | **Positive** for the bounded scope. Lands the smallest backward-compatible **snapshot epoch parity** support — the first item on the Run 092 §"Immediate next action recommended" closure list. Extends `StateSnapshotMeta` with an additive `epoch: Option<u64>` field (serialized only when `Some(n)`; omitted entirely when `None` so pre-Run-097 parsers accept new snapshots byte-for-byte unchanged; malformed/non-integer/quoted/negative values fail closed; `"epoch": null` is treated as absence; `Some(0)` is the canonical committed-epoch-0 signal and is NOT the same as absence). Populates the field on snapshot creation from the canonical Run 093/094 `ConsensusStorage::get_current_epoch()` only — `maybe_trigger_periodic_snapshot` and the SIGUSR1 `spawn_vm_v0_snapshot_signal_task` both accept and forward the `Option<Arc<dyn ConsensusStorage>>` handle, probe `get_current_epoch()`, log the resolved source, and pass the result through a new third argument to `VmV0RuntimeState::create_snapshot(anchor, chain_id, epoch, &metrics)`. The standalone `qbind_state_snapshot` example helper gains a `--epoch <N>` flag (operator-sourced from canonical surface only; explicitly NO derivation from height / view / wall-clock / timer / filename / directory). Adds new restore-time function `qbind_node::production_consensus_storage::persist_restored_snapshot_epoch(opened, snapshot_epoch) -> Result<bool, ProductionConsensusStorageError>` that the production `main.rs` calls after `apply_snapshot_restore_if_requested` materializes the VM-v0 state (B3) and after `open_production_consensus_storage` opens the canonical `<data_dir>/consensus` (Run 093); uses the existing canonical `ConsensusStorage::put_current_epoch` API to write `meta:current_epoch = CommittedEpoch(n)`; idempotent on re-restore (existing == snapshot is `Ok(false)` no-op); fail-closed with new typed `ProductionConsensusStorageError::{RestoreEpochWriteFailed, RestoreEpochInconsistent}` variants on write failure or when the pre-existing CommittedEpoch differs from the snapshot's (no silent overwrite); `main.rs` exits 1 on either, preserving restore atomicity (a partial restore where VM state is materialized but epoch metadata fails silently is impossible). Trust-bundle activation behaviour preserved unchanged: every `ActivationContext` in `main.rs` continues to be built with `current_epoch: None`, and Run 091/092 `CurrentEpochUnavailable` fail-closed boundary at every production call site remains intact (Run 097 does NOT consume the restored or current epoch for trust-bundle activation; explicit non-goal per `task/RUN_097_TASK.txt` §"Strict non-goals"). Missing snapshot epoch is **not** epoch `0` — pre-Run-097 snapshots restore cleanly and leave `<data_dir>/consensus` at `PresentNoCommittedEpoch` (pinned by `run097_restore_with_pre_run097_snapshot_leaves_storage_at_no_committed_epoch`). 7 new unit tests in `crates/qbind-ledger/src/state_snapshot.rs` (metadata roundtrip, missing/malformed/explicit-null/zero-not-none/deterministic-serialization/no-height-derivation), 6 new unit tests in `crates/qbind-node/src/production_consensus_storage.rs` (persist-none-noop, persist-some-into-fresh, idempotent-match, fail-closed inconsistency, defensive no-storage no-op, epoch-zero-as-canonical-committed-epoch-zero), and 7 new integration tests in `crates/qbind-node/tests/run_097_snapshot_epoch_parity_tests.rs` (creation parity for `Some(n)` and `None`; full restore → persist → reopen flow observing `CommittedEpoch(n)` after restart; pre-Run-097 snapshot restore preserves `PresentNoCommittedEpoch` explicitly NOT `CommittedEpoch(0)`; fail-closed inconsistency; idempotent restore; activation isolation). All 20 new tests pass; `b3_snapshot_restore_tests` (10/10), `b5_restore_aware_consensus_start_tests` (4/4), `epoch_persistence_tests` (13/13), `epoch_startup_validation_tests` (8/8), `run_091_*` (15/15), `run_093_*` (12/12), `run_094_*` (7/7), `run_095_*` (11/11), `run_096_*` (9/9), `run_097_*` (7/7), `qbind-ledger --lib` (**148/148**) and `qbind-node --lib` (**1076/1076**) all pass with no regressions. No `pqc_trust_activation::ActivationContext` change, no synthetic epoch, no wall-clock / view / height / timer / filename derivation, no snapshot-format redesign beyond additive metadata, no peer-driven apply, no KMS/HSM, no signing-key ratification, no new metric family, no new CLI flag (the new `--epoch` lives on the helper example only), no new dependency, no DummySig / DummyKem / DummyAead. Run 097 narrows the C4 sub-piece **"snapshot epoch parity (`StateSnapshotMeta.epoch`)"** from "OPEN — missing field; restore cannot re-establish canonical committed epoch" to **"snapshot `meta.json` carries canonical committed epoch from Run 093/094 source; restore re-establishes `CommittedEpoch(n)` atomically (or fails closed); restart observes it; pre-Run-097 snapshots remain compatible and leave storage at `PresentNoCommittedEpoch` (NOT `0`); malformed metadata fails closed; inconsistent epoch fails closed"**. Run 097 does **not** close full C4 (`activation_epoch` runtime consumption, peer-driven live apply, KMS/HSM custody, signing-key ratification, production fast-sync / broader consensus-storage restore, per-environment trust-anchor operation, full C4, C5 all remain OPEN). Recommended next: **Run 098 — wire the restored / persisted `<data_dir>/consensus :: meta:current_epoch` (now populated on both reconfig commit by Run 094/096 and snapshot restore by Run 097) into the production `ActivationContext.current_epoch` construction sites**, preserving `CurrentEpochUnavailable` on fresh genesis (`Ok(None)`) and explicitly setting `Some(n)` only after canonical observation. | §1, §3.10, §10.1, §11. |
| 037 / 039 / 040 / 041 | Real `MlDsa44SignatureSuite`, `MlKem768Backend`, `ChaCha20Poly1305Backend` registration; no `Dummy*` under `pqc-static-root`. | §1.3, §5.3, §6.B, §9. |
| 100 | **Positive (design / spec only)**. Lands the formal production-grade authority and ratification model for PQC trust anchors and bundle-signing keys in `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`: (i) initial production authority comes from a **genesis configuration file bound by a boot-time cryptographic hash** (NOT Rust source-code constants); (ii) bundle-signing keys are authorized by **typed, PQC-signed, deterministically-encoded ratification objects** bound to `(chain_id, environment, genesis_hash, authority_epoch)` (spec §5); (iii) per-environment policy separates DevNet (explicit local shortcuts; no silent fallback), TestNet (genesis-bound + staged ratification), MainNet (genesis-bound + ratification; no operator-only shortcuts; no fallback static roots) (spec §7); (iv) anti-rollback uses a new `<data_dir>/pqc_authority_state.json` with restore semantics mirroring Run 097's snapshot epoch parity (`AuthorityRollbackRefused`, `AuthorityStateCorrupt`, `AuthorityRestoreInconsistent` typed errors) (spec §8); (v) emergency authority defines `Retired` / `Revoked` / `EmergencyRevoked` classes; `EmergencyRevoked` bypasses Run 065 minimum margin (spec §9); (vi) peer-driven live apply remains forbidden until the ratification verifier (Run 102), anti-rollback (Run 103), KMS/HSM custody (Run 105), operator override / emergency controls (§9), and release-binary evidence (Run 104) all exist (spec §10). Future implementation runs are staged as Run 101 (additive genesis-config fields + canonical-serialization extension + boot-time `expected_genesis_hash` comparison + initial `LiveAuthorityState` derivation), Run 102 (in-binary ratification verifier + `<data_dir>/pqc_authority_state.json` + six new `qbind_p2p_pqc_trust_bundle_authority_*` counters), Run 103 (anti-rollback), Run 104 (release-binary rotation/revocation evidence), Run 105 (KMS/HSM), Run 106+ (peer-driven apply gates). **No `crates/**/src/**` source change, no `crates/**/tests/**` test change, no `Cargo.toml` change, no new dependency, no new metric family, no new CLI flag, no protocol or wire-format change.** Existing Run 050–099 behaviour preserved bit-for-bit; Run 091/092/098 `CurrentEpochUnavailable` fail-closed boundary preserved; Run 050 trust-separation invariant explicitly extended into spec §5.1; spec §11 explicitly rejects production static MainNet anchors as source-code constants, hidden fallback anchors, implicit trust roots outside genesis/config, peer-provided authority without ratification, local config as sole MainNet authority, fallback signing keys, treating majority gossip as authority, silent old-authority restore, wrong-chain/wrong-environment authority, and classical (non-PQC) signature suites. Run 100 does **not** claim full C4 closure and does **not** claim C5 closure. | §1, §2.1, §2.2, §3.3, §3.4, §4.2, §4.4, §5.3, §6.D, §7, §9, §10, §11. Spec at `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`. |

---

## 12. Glossary of operator-facing flags

- `--env devnet|testnet|mainnet` — runtime environment.
- `--p2p-pqc-root-mode pqc-static-root` — selects the production-
  honest cert-verification path. Test-grade DummySig mode is the
  default (DevNet-only) and is refused on MainNet.
- `--p2p-trust-bundle <PATH>` — path to `trust-bundle.json`.
- `--p2p-trust-bundle-signing-key KEYID:100:HEXPK` — repeatable;
  the bundle-signing verification key set.
- `--p2p-trusted-root ROOTID:100:HEXPK` — static CLI roots; on
  TestNet/MainNet, MUST NOT be combined with `--p2p-trust-bundle`.
- `--p2p-leaf-cert <PATH>` / `--p2p-leaf-cert-key <PATH>` —
  validator's leaf delegation cert and matching ML-KEM-768 secret.
- `--p2p-mutual-auth required` — production setting.
- `--data-dir <PATH>` — REQUIRED for the sequence persistence file
  on TestNet/MainNet.
- `--p2p-trust-bundle-reload-check <PATH>` *(hidden; Run 069)* —
  validates the candidate bundle at `<PATH>` against the same
  startup security pipeline; node does NOT start; prints
  `VERDICT=valid|invalid` and exits 0/1. Non-mutating by
  construction. See §6.F.2.
- `--p2p-trust-bundle-reload-apply-enabled` *(hidden; Run 073)* —
  enables the process-start local-file reload-apply path.
  Required together with `--p2p-trust-bundle-reload-apply-path`.
  TestNet/MainNet preconditions are identical to the startup
  `--p2p-trust-bundle` path (signed bundle, `--data-dir`
  required). See §6.F.3.
- `--p2p-trust-bundle-reload-apply-path <PATH>` *(hidden; Run 073)* —
  candidate bundle to apply at process start. Required together
  with `--p2p-trust-bundle-reload-apply-enabled`. See §6.F.3.
- `--p2p-trust-bundle-live-reload-enabled` *(hidden; Run 074)* —
  arms the long-running SIGHUP live reload-apply trigger.
  Required together with `--p2p-trust-bundle-live-reload-path`;
  refused without `--p2p-trust-bundle <BASELINE-PATH>`. See
  §6.F.4. Disabled by default.
- `--p2p-trust-bundle-live-reload-path <PATH>` *(hidden; Run 074)* —
  local file the SIGHUP handler re-reads on every trigger.
  Required together with `--p2p-trust-bundle-live-reload-enabled`.
  See §6.F.4.
- `--p2p-trust-bundle-peer-candidate-validation-enabled` *(hidden; Run 077)* —
  arms the local peer-candidate check mode. Required together
  with `--p2p-trust-bundle-peer-candidate-check`. Disabled by
  default. **Validation-only**: node does not start in this
  mode; exits 0/1. No live trust mutation, no sequence write,
  no session eviction. See §6.G.1, §6.G.2.
- `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>` *(hidden; Run 077)* —
  local `PeerCandidateEnvelope` JSON fixture to validate against
  this node's startup security pipeline. Required together with
  `--p2p-trust-bundle-peer-candidate-validation-enabled`. See
  §6.G.2.
- `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` *(hidden; Run 079)* —
  arms the **receiver-side** live P2P receive-loop dispatch for
  inbound `0x05` peer-candidate frames. Disabled by default.
  When off, inbound `0x05` frames are cheap-ignored and no
  receiver-side `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
  counter moves. **Validation-only**: even when on, no
  candidate is applied, propagated, or persisted. See §6.G.1,
  §6.G.5.
- `--p2p-trust-bundle-peer-candidate-wire-publish-enabled` *(hidden; Run 080)* —
  arms the **sender-side** publisher. Required together with
  `--p2p-trust-bundle-peer-candidate-wire-publish-path`.
  Disabled by default. Publishes exactly the operator-supplied
  envelope as a real `0x05` frame over live authenticated P2P
  sessions; no auto-resend loop. See §6.G.2.
- `--p2p-trust-bundle-peer-candidate-wire-publish-path <PATH>` *(hidden; Run 080)* —
  local `PeerCandidateEnvelope` JSON fixture to publish as a
  Run 078 wire envelope. Required together with
  `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`. See
  §6.G.2.
- `--p2p-trust-bundle-peer-candidate-wire-publish-once` *(hidden; Run 080)* —
  publish exactly one candidate frame and continue normal node
  runtime; no automatic resend loop. See §6.G.2.
- `--p2p-trust-bundle-peer-candidate-propagation-enabled` *(hidden; Run 088)* —
  arms the **propagation-only** rebroadcast path on the receiver
  side. Disabled by default. Requires a validated baseline
  `--p2p-trust-bundle <PATH>` and
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` to
  be effective. **Validation-before-rebroadcast**: only frames
  that pass the Run 076/078 validation pipeline may be
  rebroadcast; the source peer is excluded; a local seen-cache,
  bounded fanout, fixed-window rate limit, and bounded send-queue
  prevent loops. No candidate is applied, no sequence is
  persisted, no `LivePqcTrustState` mutation, no session eviction.
  The `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
  family is absent from `/metrics`. See §6.G.9, §6.G.10, §6.G.11,
  §6.G.12, §6.G.13.

Propagation-only counters added by Run 088 (all zero by default;
only move on opt-in receivers when the propagation flag is set):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`
  — moves only on a validated candidate that has been selected
  for rebroadcast (after dedup / rate-limit / target-set build).
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`
  — moves only when a validated candidate is actually placed on
  the outbound queue for at least one non-source peer.
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_duplicate_total`
  — moves when an already-seen candidate is dropped at the
  propagation stage.
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`
  — moves when a candidate that failed Run 076/078 validation is
  refused at the propagation stage.
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_rate_limited_total`
  — moves when the local fixed-window propagation rate limit
  fires.

---

*If anything here appears to permit a fallback that the binary
refuses, the binary wins and this runbook is the defect. Open an
issue against `docs/whitepaper/contradiction.md` immediately.*
---

## 11.1 Run 101 row (appended)

| Run | What it proved | What §section of this runbook relies on it |
|---|---|---|
| 101 | **Partial-positive (fields + canonical hash + boot helper)**. First implementation step after the Run 100 design. Lands, in `crates/qbind-ledger/src/genesis.rs` (re-exported from `crates/qbind-ledger/src/lib.rs`): (i) the additive `GenesisConfig.authority: Option<GenesisAuthorityConfig>` field with `#[serde(default)]` so existing DevNet/legacy JSON files without an `authority` key continue to parse cleanly; (ii) `GenesisAuthorityConfig { authority_policy_version, authority_sequence, authority_epoch, pqc_transport_roots, bundle_signing_authority_roots }` and `GenesisAuthorityRoot { suite_id, key_fingerprint, label, not_before_epoch }`; (iii) `compute_canonical_genesis_hash(&GenesisConfig, env)` with the project-style domain-separation tag `b"QBIND:GENESIS:v1"`, length-prefixed framing of every field including environment scope (`DEV`/`TST`/`MAIN`), `chain_id`, and the full authority block (with discriminator bytes so `None` ≠ `Some(empty)` and so the absence vs. emptiness of the authority block produce distinct hashes); (iv) `verify_boot_time_genesis(env, &GenesisConfig, Option<&GenesisHash>)` with strict, fail-closed, per-environment refusal — MainNet refuses missing expected canonical hash, mismatched hash, missing authority before the hash compare, empty `bundle_signing_authority_roots`, non-ML-DSA-44 `suite_id`, malformed fingerprints (short / non-hex / oversized / odd-length), empty labels, empty fingerprints, duplicate `(suite_id, key_fingerprint)` across the combined transport+bundle-signing set, `authority_policy_version == 0` or `> 1`, and chain_id not bound to the runtime environment; TestNet matches MainNet except that the expected-canonical-hash flag is not yet forced when absent (documented partial-positive — Run 102 will force it alongside the ratification verifier); DevNet remains permissive for legacy local tests. The existing T232 `MainnetConfigError::GenesisMisconfigured` + T233 `MainnetConfigError::ExpectedGenesisHashMissing` MainNet CLI-layer shields are preserved bit-for-bit, so MainNet operators still cannot accidentally start without a hash binding. 24 new unit tests in `crates/qbind-ledger/src/genesis.rs::tests` and 11 release-binary-facing integration tests in `crates/qbind-node/tests/run_101_genesis_authority_tests.rs` cover Scenarios 1–5 of `task/RUN_101_TASK.txt` plus duplicate/malformed/wrong-environment refusal coverage and a canonical-hash serde-json round-trip stability check. **No new dependency, no new CLI flag, no new metric family, no `Cargo.toml` change, no protocol or wire-format change.** No `Dummy*` primitive is referenced, no transport-root reuse as a bundle-signing authority is introduced (the Run 050 trust-separation invariant is preserved and is now structurally separated into `pqc_transport_roots` vs `bundle_signing_authority_roots`), no `--p2p-trusted-root` fallback path is added, and no production static MainNet root anchor exists as a source-code constant (grep audit on `crates/**/src/**` confirms only the new Run 101 type declarations and their re-exports appear). Run 101 does **not** implement the in-binary bundle-signing-key ratification verifier (Run 102), does **not** add `<data_dir>/pqc_authority_state.json` (Run 103), does **not** wire `verify_boot_time_genesis` from the release-binary `async_runner` startup (the helper is exposed and exercised through the public API path the release binary links against; the single startup call site is deferred to Run 102 alongside the ratification verifier — see §11.2 prose), does **not** introduce KMS/HSM custody (Run 105), does **not** add peer-driven live apply (Run 106+, gated by Run 100 spec §10), and does **not** weaken any Run 050–099 invariant. Run 101 does **not** claim full C4 closure and does **not** claim C5 closure. | §1.3, §2.2, §4.2, §4.4, §5.3, §6.D, §7, §11.2. Evidence at `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md`. Spec update at `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §17. |

### 11.2 Run 101 prose note

Run 101 introduces **only** the genesis-bound authority *fields* and the
*canonical-hash + boot-time-helper* surface defined by Run 100 spec §6.
Operationally this means:

- **Genesis files for MainNet/TestNet may now include an `authority`
  block.** A minimal block looks like:
  ```json
  {
    "authority": {
      "authority_policy_version": 1,
      "authority_sequence": 0,
      "authority_epoch": null,
      "pqc_transport_roots": [
        {"suite_id": 100, "key_fingerprint": "<64-hex>",
         "label": "<operator label>", "not_before_epoch": null}
      ],
      "bundle_signing_authority_roots": [
        {"suite_id": 100, "key_fingerprint": "<64-hex>",
         "label": "<operator label>", "not_before_epoch": null}
      ]
    }
  }
  ```
  `suite_id = 100` is ML-DSA-44 (the only suite MainNet/TestNet accept).
  `key_fingerprint` MUST be lowercase hex without `0x` prefix and ≥ 64
  hex characters (32 raw bytes) on MainNet/TestNet.
- **Operators MUST treat the `authority` block as part of the production
  trust surface.** It is hash-bound by `compute_canonical_genesis_hash`
  and will become the source of truth for the Run 102 bundle-signing-key
  ratification verifier. Operators MUST NOT publish or commit
  private-key material in the genesis file (only fingerprints / public
  keys are stored).
- **Until Run 102 wires the boot helper into the startup sequence,**
  the existing T233 `--expect-genesis-hash` (file-bytes hash) remains
  the operator-facing shield on MainNet; do not skip it.
- **Run 101 adds no new CLI flag, no new metric, no new persistence
  file.** Continue to follow the Run 050/055/065/069–075/076–086/087/
  088/089/090/091–099/100 lifecycle exactly as documented in this
  runbook. The single behavioural addition is the per-environment
  validation of the new `authority` block when present, plus the
  canonical-hash helper used by tests today and by Run 102 startup
  tomorrow.
- **Reference:** evidence record
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md` and spec update
  §17 of `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

*If anything in this Run 101 note appears to permit a fallback that the
binary refuses, the binary wins and this runbook is the defect. Open an
issue against `docs/whitepaper/contradiction.md` immediately.*

## 11.3 Run 102 row (appended)

| Run | Verdict + Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Cross-runbook anchors |
|-----|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| 102 | **Partial-positive (release-binary wiring + canonical `--print-genesis-hash`)**. Wires Run 101's `qbind_ledger::verify_boot_time_genesis` into `qbind-node`'s `main` after T185 MainNet invariants validation and **before** B3 restore / Run 069 trust-bundle reload-check / Run 077 peer-candidate check / P2P startup / consensus loop, via a new module `crates/qbind-node/src/pqc_boot_genesis.rs`. Replaces the pre-Run-101 raw-file-byte `--print-genesis-hash` semantics with the canonical Run 101 parsed-genesis hash under the resolved environment policy; the printed value is `0x`-prefixed 64-char lowercase hex pasteable verbatim into `--expect-genesis-hash`. MainNet refuses to start on missing/mismatched/malformed expected hash, missing/empty/malformed authority, env-mismatched `chain_id`, missing genesis file, malformed genesis JSON, and (belt-and-braces) missing `--genesis-path` — every refusal exits non-zero with a typed operator-facing `BootGenesisError` *before* any trust-bundle / network / consensus startup. DevNet/TestNet embedded-genesis path is preserved: when no external genesis is configured the verifier returns `SkippedNoExternalGenesis` with a clear log line. The existing T232/T233 `MainnetConfigError::{GenesisMisconfigured, ExpectedGenesisHashMissing}` CLI shields are preserved bit-for-bit and **compose** with the Run 102 verifier (the shields refuse MainNet startup when flags are absent; Run 102 refuses when the supplied expected hash does not match the parsed canonical hash and refuses for any caller that bypasses `--profile mainnet`). 8 new in-module unit tests in `crates/qbind-node/src/pqc_boot_genesis.rs::tests` and 14 new integration tests in `crates/qbind-node/tests/run_102_boot_genesis_wiring_tests.rs` cover every MainNet refusal scenario plus the happy path, the print→expect operator round-trip, and DevNet preservation. 10 release-binary smoke scenarios in `docs/devnet/run_102_genesis_verification_evidence/` capture the canonical hash divergence between two genesis files differing only in one byte of `authority.bundle_signing_authority_roots[0].key_fingerprint`, and prove the Run 102 OK log line precedes all `[restore]` / `[metrics]` / `[binary]` / `[binary-consensus]` / `[snapshot]` lines. **No new dependency, no new CLI flag (only doc-comment help-text update on the existing T232/T233 flags), no new metric family, no `Cargo.toml` change, no protocol or wire-format change, no admin-API surface, no filesystem watcher, no network listener / gossip subscription / publisher.** No `Dummy*` primitive is referenced; no transport-root reuse as a bundle-signing authority; no `--p2p-trusted-root` fallback; no production static MainNet root anchor as a source-code constant — the release binary reads the authority block **only** from the operator-supplied genesis file. Run 102 does **NOT** implement the bundle-signing-key ratification verifier (deferred to Run 103 per the task's explicit "no broad redesign in Run 102" scope rule), does **NOT** add `<data_dir>/pqc_authority_state.json` (Run 103), does **NOT** introduce KMS/HSM custody (Run 105), does **NOT** add peer-driven live apply (Run 106+, gated by Run 100 spec §10), and does **NOT** weaken any Run 050–101 invariant. Run 102 does **NOT** claim full C4 closure and does **NOT** claim C5 closure. | §1.3, §2.2, §4.2, §11.2, §11.4. Evidence at `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_102.md`. Spec update at `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §18. Contradiction tracker at `docs/whitepaper/contradiction.md` C4 Run 102 update. |

## 11.4 Run 102 prose note

Run 102 takes Run 101's `verify_boot_time_genesis` helper and **wires it
into the production release binary** at the spec-defined ordering
position. On MainNet, every `qbind-node` startup now:

1. Loads `--genesis-path` as a strict `GenesisConfig` JSON (no defaults
   filled, no embedded fallback consulted).
2. Computes the canonical Run 101 genesis hash over the parsed config
   under the `Mainnet` environment policy.
3. Compares against `--expect-genesis-hash`. On mismatch — refuse and
   exit non-zero.
4. Validates the `GenesisAuthorityConfig` (suite, fingerprint shape,
   labels, uniqueness, policy version, chain_id/env binding). On
   refusal — exit non-zero with a typed reason.
5. Only after the verifier returns `BootGenesisOutcome::Verified` does
   the binary proceed to B3 restore, Run 069 trust-bundle reload-check,
   trust-bundle load + activation, P2P startup, and the binary-path
   consensus loop.

The DevNet embedded-genesis path is unchanged: with no `--genesis-path`
the verifier returns `SkippedNoExternalGenesis` and the node starts
normally. TestNet matches Run 101's partial-positive policy (the
expected-hash flag is not yet forced when absent; tightening is a
TestNet operator-impact decision deferred to a later run).

**The bundle-signing-key ratification verifier is NOT in Run 102.** Per
`task/RUN_102_TASK.txt`'s explicit scope rule — *"If the skeleton cannot
be added cleanly without broad redesign, do not implement it in Run 102.
Document it as Run 103 instead."* — and because adding even a skeleton
verifier requires a new operator-supplied input (a ratification
certificate or signed bootstrap payload), a new canonical preimage, a
new typed error variant, and a new acceptance/refusal call site, Run 102
stops at the wiring step and defers the ratification verifier to
Run 103. The "matched-but-not-ratified" residual risk is recorded in
Evidence Run 102 §8.

**Operator workflow (Run 102):**

1. Run `qbind-node --print-genesis-hash --genesis-path /etc/qbind/genesis.json --env mainnet`.
2. Pin the printed `0x…` hash into `--expect-genesis-hash` on every
   MainNet validator's startup command line.
3. Subsequent `qbind-node` startups will refuse if either the genesis
   file or the expected hash diverges from the pinned value.

**Run 102 adds no new CLI flag, no new metric, no new persistence file,
no admin API, no filesystem watcher, no network listener, no gossip
subscription, no gossip publisher, no peer-driven apply, no
ratification path, no KMS/HSM custody binding, no signing-key rotation
path, no signing-key revocation path, and no source-code production
trust root.** The operator surface is bit-for-bit T232/T233 with
updated doc-comment help text.

*If anything in this Run 102 note appears to permit a fallback that the
binary refuses, the binary wins and this runbook is the defect. Open an
issue against `docs/whitepaper/contradiction.md` immediately.*
---

## Run 103 Update — Bundle-Signing-Key Ratification Verifier (library-level)

Run 103 adds the minimal bundle-signing-key ratification verifier
primitive (`qbind_ledger::verify_bundle_signing_key_ratification`).
The verifier is a pure function — it has **no** CLI flag, **no**
admin API, **no** filesystem watcher, **no** network listener, and
**no** peer-driven apply path. Run 103 does NOT change the operator
runbook surface.

What changed for operators (informational; nothing to do in Run 103):

- A new library function exists that, when given a signed
  `BundleSigningRatification` object, the parsed
  `GenesisAuthorityConfig`, the expected chain id / environment /
  canonical genesis hash, returns either a
  `RatifiedBundleSigningKey` identity or a typed `RatificationFailure`
  reason. The verifier is currently called only by tests; Run 104
  will wire it into trust-bundle acceptance paths.
- Operators who wish to start producing ratification objects in
  preparation for Run 104 should ensure their
  `genesis.authority.bundle_signing_authority_roots[*].key_fingerprint`
  entry stores the **full ML-DSA-44 public key bytes hex-encoded**
  (2624 hex characters = 1312 bytes) rather than only the 64-hex
  SHA3-256 fingerprint. Run 101 already permits this within the
  `GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX = 16 KiB` upper bound.
  Genesis-bound roots stored as a short fingerprint will continue to
  pass Run 101/102 verification, but Run 103's verifier will return
  the typed `AuthorityKeyMaterialUnavailable` reason — Run 104 will
  introduce an authority-key-material registry to lift this boundary
  without forcing the full PK into `key_fingerprint`.
- No SIGHUP, reload-check, reload-apply, or peer-candidate path is
  changed in Run 103. The Run 070 `validate → swap → evict_sessions →
  commit_sequence` ordering contract is preserved bit-for-bit. The
  Run 102 boot-time genesis verification is preserved bit-for-bit.

**Run 103 explicitly does NOT add ratification path, peer-driven
apply, KMS/HSM custody, signing-key rotation path, signing-key
revocation path, anti-rollback persistence, authority-key-material
registry, source-code production trust root, fallback authority, or
any new operator surface.** The operator surface is unchanged from
Run 102.

*If anything in this Run 103 note appears to permit a fallback that
the binary refuses, the binary wins and this runbook is the defect.
Open an issue against `docs/whitepaper/contradiction.md` immediately.*
---

# Run 104 update — Genesis-bound authority key material registry

Run 104 (`task/RUN_104_TASK.txt`) adds a structurally separate
`public_key_hex` field to `GenesisAuthorityRoot` and a verified
binding between that field and the existing `key_fingerprint` so the
Run 103 bundle-signing-key ratification verifier can verify real
ML-DSA-44 signatures using genesis-bound material — without the
Run 101 / Run 103 overloading of `key_fingerprint` as full
public-key bytes.

## MainNet operator obligation

MainNet genesis files MUST now carry `public_key_hex` for every
bundle-signing-authority root. Genesis files written before Run 104
that relied on either:

- only a 64-hex SHA3 fingerprint, or
- the Run 103 legacy 2624-hex `key_fingerprint` overload,

will be refused by boot-time genesis verification with one of these
typed errors:

- `MissingPublicKeyMaterial` — no `public_key_hex` field at all;
- `MalformedPublicKey` — `public_key_hex` is wrong length, not
  lowercase hex, or odd length;
- `PublicKeyFingerprintMismatch` — `sha3_256_hex(public_key_hex)`
  does not equal `key_fingerprint`;
- `PublicKeySuiteUnknown` — `suite_id` is not `100` (ML-DSA-44);
- `DuplicateAuthorityPublicKey` — two roots share the same
  `(suite_id, public_key_hex)`.

All MainNet failures surface through the existing
`BootGenesisVerificationError::AuthorityValidationFailed` shell with
a clear `Display` line; the operator workflow (`--print-genesis-hash`
→ pin via `--expect-genesis-hash` → start the node) is unchanged in
shape — only the content of the genesis JSON file changes.

## Regenerating a MainNet genesis file

The recommended path is to construct each bundle-signing-authority
root via the Rust API:

    GenesisAuthorityRoot::with_public_key_bytes(
        GENESIS_AUTHORITY_SUITE_ML_DSA_44,
        &pk_bytes,
        "foundation-bundle-signer-1",
    )

which derives the canonical SHA3-256 `key_fingerprint` from
`pk_bytes` automatically, guaranteeing consistency by construction.
Operators that hand-edit JSON files MUST ensure
`sha3_256_hex(decoded(public_key_hex)) == key_fingerprint` — Run 104
will refuse any mismatch on MainNet.

## TestNet / DevNet behavior (unchanged shape)

TestNet and DevNet continue to tolerate legacy short-fingerprint-only
bundle-signing-authority roots so existing local fixtures and
DevNet/TestNet workflows continue to work without modification. The
Run 103 verifier still fails closed on those roots with
`AuthorityKeyMaterialUnavailable`; this is the documented and
intended behavior.

## What Run 104 does NOT add to the operator surface

- No new CLI flag, no new config key, no new admin endpoint.
- No new metric family, no new logger target.
- No filesystem watcher, no network listener, no gossip subscription.
- No new dependency.

**Run 104 explicitly does NOT enable peer-driven live apply,
trust-bundle apply-path ratification enforcement, KMS/HSM custody,
signing-key rotation, signing-key revocation, anti-rollback
persistence, production source-code root anchors, or any fallback
authority.** The operator surface is otherwise unchanged from
Run 102/Run 103.

*If anything in this Run 104 note appears to permit a fallback that
the binary refuses, the binary wins and this runbook is the defect.
Open an issue against `docs/whitepaper/contradiction.md` immediately.*
---

## Run 106 update — MainNet/TestNet ratification enforcement is now DEFAULT-STRICT on startup and `--p2p-trust-bundle-reload-check`

### Operator-facing change

The Run 105 hidden flag
`--p2p-trust-bundle-ratification-enforcement-enabled` is **no longer
required on MainNet or TestNet** to invoke the Run 105 bundle-signing-
key ratification gate on the startup preflight or on the
`--p2p-trust-bundle-reload-check` path. The gate now runs by default
on those environments and the operator can no longer disable it by
omitting that flag. The other two Run 105 flags are unchanged in
meaning:

- `--p2p-trust-bundle-ratification <PATH>` — **REQUIRED** on MainNet
  for the startup preflight and the reload-check (a missing sidecar
  fails closed with a typed reason from
  `qbind_ledger::enforce_bundle_signing_key_ratification`).
- `--p2p-trust-bundle-allow-unratified-testnet-devnet` — DevNet/
  TestNet-only legacy escape hatch. Refused on MainNet by the gate
  body itself (Run 105 `RatificationEnforcementPolicy::Strict`
  selection on MainNet, preserved by Run 106 as defense in depth).

### Per-environment quick reference

| Environment | Default gate behaviour | Effect of opt-in flag | Effect of legacy-allow flag |
|-------------|------------------------|----------------------|----------------------------|
| MainNet     | **Invoked** (Run 106)  | Ignored (cannot enable; cannot disable) | Refused by gate body — MainNet rejects legacy unratified bundles |
| TestNet     | **Invoked** (Run 106)  | Ignored (cannot enable; cannot disable) | Allows legacy unratified verdict if no sidecar is supplied |
| DevNet      | Skipped                | When supplied: invokes the gate          | Allows legacy unratified verdict when gate is invoked        |

On the Skip branch (DevNet without opt-in) and on the Invoke branch
the operator log emits one of four stable labels:

- `[run-106] startup ratification gate INVOKED (policy=mainnet-default-strict, env=Mainnet).`
- `[run-106] startup ratification gate INVOKED (policy=testnet-default-strict, env=Testnet).`
- `[run-106] startup ratification gate INVOKED (policy=devnet-operator-opt-in, env=Devnet).`
- `[run-106] startup ratification gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet). This is NOT a passed ratification ...`

The same four labels are used by the reload-check site with the
prefix `[run-106] reload-check ratification gate ...`.

### What Run 106 explicitly does NOT change

- The four other trust-bundle validation surfaces (`--p2p-trust-
  bundle-peer-candidate-check`, live peer-candidate wire validation,
  propagation/rebroadcast, reload-apply, SIGHUP live reload) remain
  in their Run 105 state. Operators who want ratification enforcement
  on those surfaces today must still follow the Run 105 procedure
  (supply `--p2p-trust-bundle-ratification-enforcement-enabled` +
  `--p2p-trust-bundle-ratification <PATH>`). The Run 105 wiring for
  those surfaces is unchanged or absent; Run 106 did not weaken
  anything on them.
- No new CLI flag is introduced.
- No new metric family is introduced.
- No file is read, written, created, or deleted by Run 106 beyond
  what Run 105 already touched.
- No change to signing-key custody, rotation, revocation, anti-
  rollback persistence, production source-code root anchors, or any
  fallback authority. The operator surface is otherwise unchanged
  from Run 105.

*If anything in this Run 106 note appears to permit a bypass on
MainNet that the binary refuses, the binary wins and this runbook is
the defect. Open an issue against `docs/whitepaper/contradiction.md`
immediately.*
---

## Run 107 operator update — peer-candidate check ratification gate

Run 107 extends the Run 105/106 bundle-signing-key ratification gate to the local `--p2p-trust-bundle-peer-candidate-check <PATH>` CLI surface. Operators should treat this as a validation-only check: the node does not start, no candidate is applied, no sequence record is written, no live trust state is mutated, no session is evicted, and no propagation/rebroadcast occurs.

Policy:

- MainNet: ratification is required by default for peer-candidate check.
- TestNet: ratification is required by default for peer-candidate check.
- DevNet: ratification is enforced only when `--p2p-trust-bundle-ratification-enforcement-enabled` is supplied; without it, legacy unratified local-check behavior remains available for developer workflows.

Use the existing sidecar flag:

```text
--p2p-trust-bundle-ratification <PATH>
```

with the existing `BundleSigningRatification` JSON format. Do not introduce a separate peer-candidate ratification format. A missing, malformed, wrong-chain, wrong-environment, bad-signature, unknown-root, transport-root, unsupported-suite, missing-key-material, or malformed-key-material ratification fails closed before a successful peer-candidate verdict.

Run 107 does not change live peer-candidate wire validation, propagation/rebroadcast, reload-apply, SIGHUP, peer-driven live apply, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, governance, validator-set rotation, full C4, or C5.

---

## Run 108 operator update — peer-candidate check ratification release-binary evidence

Run 108 records release-binary evidence for the Run 107 local peer-candidate check. The exercised command shape is:

```text
qbind-node \
  --env <mainnet|devnet> \
  --genesis-path <genesis.json> \
  --expect-genesis-hash <0x...> \
  --data-dir <DIR> \
  --p2p-trust-bundle-signing-key <KEYID:100:PK> \
  --p2p-trust-bundle-peer-candidate-validation-enabled \
  --p2p-trust-bundle-peer-candidate-check <peer-candidate.json> \
  [--p2p-trust-bundle-ratification-enforcement-enabled] \
  [--p2p-trust-bundle-ratification <ratification.json>]
```

Expected release-binary behavior:

- MainNet: the peer-candidate-check ratification gate logs `policy=mainnet-default-strict`; valid ratification exits `0`, missing or bad ratification exits `1` with typed `RatificationRefused(...)` detail.
- TestNet: same default-strict policy shape as MainNet, though Run 108 evidence focuses on MainNet plus DevNet.
- DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled`: the gate logs `policy=devnet-no-operator-opt-in` and preserves legacy unratified local-check behavior.
- DevNet with `--p2p-trust-bundle-ratification-enforcement-enabled`: the gate logs `policy=devnet-operator-opt-in`; valid ratification exits `0`, missing or bad ratification exits `1`.

In all cases this is still validation-only. Operators should expect no sequence write, no root merge, no live trust mutation, no session eviction, no propagation/rebroadcast, no reload-apply, no SIGHUP apply, and no node startup. Evidence and exact logs are under `docs/devnet/run_108_peer_candidate_check_ratification_release_binary_evidence/`; the reusable harness is `scripts/devnet/run_108_peer_candidate_check_ratification_release_binary.sh`.

## Run 109 operator update — live inbound `0x05` peer-candidate wire validation now enforces ratification

Run 109 extends the Run 105 / 106 / 107 bundle-signing-key ratification gate to the **live inbound** `0x05` peer-candidate wire validation path inside a running node. Operators should treat this as a tightening of an existing surface: the live `0x05` validator that Runs 076 / 078 / 079 already exercise on every inbound candidate frame now ALSO consults the operator-supplied ratification sidecar before declaring the candidate validated, and the Run 088 propagation gate refuses to rebroadcast any candidate the ratification verifier refuses.

Operator obligations and the resulting log/exit behavior:

- MainNet startup with `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`: the live dispatcher logs `[run-109] live peer-candidate wire ratification gate INVOKED (policy=mainnet-default-strict, env=Mainnet)`. The operator MUST supply a populated `--genesis-path <FILE>` with a `genesis_authority` block and a `--p2p-trust-bundle-ratification <PATH>` sidecar JSON whose signing-key matches the runtime's configured bundle-signing key(s); without these the binary refuses to install the live dispatcher and exits non-zero (no fallback, no apply, no sequence write, no session eviction).
- TestNet startup: same default-strict shape as MainNet (`policy=testnet-default-strict`).
- DevNet startup without `--p2p-trust-bundle-ratification-enforcement-enabled`: the dispatcher logs `[run-109] live peer-candidate wire ratification gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet)` and preserves the pre-Run-109 unguarded behavior. This is the DevNet developer ergonomics branch and only applies on DevNet.
- DevNet startup with `--p2p-trust-bundle-ratification-enforcement-enabled`: the dispatcher logs `policy=devnet-operator-opt-in` and enforces ratification on every live `0x05` frame.

When the gate is INVOKED and an inbound frame is rejected (missing, bad-signature, wrong-chain, wrong-environment, unknown-authority-root, transport-root, unsupported-suite, missing or malformed key material), the existing Run 088 invalid-outcome path increments `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total` and the frame is NOT rebroadcast. The non-mutation invariants the Run 077 local-check operator already relies on (no sequence write, no root merge, no live trust mutation, no session eviction, no `_applied_total` family) hold identically on the live wire path. Run 109 does NOT introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, governance, validator-set rotation, or full C4 / C5 closure — all of these remain future work. Source and integration-test evidence is in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_109.md`.
## Run 110 operator update — release-binary N=3 DevNet live ratification harness

Run 110 records release-binary multi-node evidence for the Run 109 live inbound `0x05` peer-candidate wire ratification gate. The reusable harness is `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` and the supporting fixture helper is `cargo run --release -p qbind-node --example run_110_live_ratification_fixture_helper -- <material-dir> <outdir>` (model layered on top of `devnet_pqc_trust_bundle_helper` material). A single-command replay produces:

- the cluster baseline signed DevNet trust bundle (`<OUTDIR>/material/trust-bundle.json`, signed by the **R1 ratified key**);
- the Run 100 / 101 genesis with a populated `genesis_authority` block, the Run 102 canonical expected genesis hash, the Run 103 signed ratification sidecar covering R1, a tampered copy of that sidecar (`ratification.bad-signature.json`), a freshly-minted **U1 unratified key**, a U1-signed alternate bundle, and matching peer-candidate envelopes (`<OUTDIR>/fixtures/*.json`);
- the six scenario archives — `baseline_ratification`, `valid_ratified`, `missing_ratification`, `bad_ratification_startup_refuse`, `duplicate_unratified_no_promotion`, `devnet_no_opt_in_legacy` — each with metric snapshots before/after, sequence-file SHA-256 hashes, stderr logs, and a `summary.txt` line stating `pass`.

The exercised command shape per node, in the enforced-policy scenarios, is:

```text
qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:<P2P_PORT> \
  --validator-id <0|1|2> \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle <material>/trust-bundle.json \
  --p2p-trust-bundle-signing-key <R1 spec> \
  --p2p-trust-bundle-signing-key <U1 spec>           # required on V1+V2 so U1-signed alt bundles reach the Run 109 gate
  --p2p-leaf-cert <material>/v<id>.cert.bin \
  --p2p-leaf-cert-key <material>/v<id>.kem.sk.bin \
  --signer-keystore-path <signers>/v<id> \
  --data-dir <data>/v<id> \
  --p2p-peer <peer_id>@127.0.0.1:<port> \
  --p2p-peer-leaf-cert <peer_id>:<material>/v<peer_id>.cert.bin \
  --validator-consensus-key <id>:100:<pk_hex> \
  --genesis-path <fixtures>/genesis.json \           # V1+V2 only in enforced scenarios
  --expect-genesis-hash <fixtures>/expected-genesis-hash.txt
  --p2p-trust-bundle-ratification-enforcement-enabled # V1+V2 only in enforced scenarios
  --p2p-trust-bundle-ratification <fixtures>/ratification.valid.json  # V1+V2 only in enforced scenarios
  [--p2p-trust-bundle-peer-candidate-wire-validation-enabled]         # all nodes
  [--p2p-trust-bundle-peer-candidate-wire-publish-enabled \           # V0 only
   --p2p-trust-bundle-peer-candidate-wire-publish-path <envelope> \
   --p2p-trust-bundle-peer-candidate-wire-publish-once]
  [--p2p-trust-bundle-peer-candidate-propagation-enabled]             # V1 only
```

Expected release-binary behavior (one row per Run 110 scenario):

- `baseline_ratification` — V1+V2 stderr contain a Run 109 `ratification gate INVOKED` / `policy=devnet-operator-opt-in` marker; every node reaches `P2P transport up`; no peer-candidate traffic flows; `qbind_p2p_pqc_cert_verify_accepted_total >= 1` and `qbind_p2p_pqc_cert_verify_rejected_total = 0` on every node; `pqc_trust_bundle_sequence.json` is identical before and after.
- `valid_ratified` — V1: `peer_candidate_received_total=1`, `validated_total=1`, `rejected_total=0`, `propagation_attempt_total=1`, `propagation_sent_total=1`, `propagation_suppressed_invalid_total=0`. V2: `validated_total=1`, `rejected_total=0`, `propagation_sent_total=0`. V0: `received_total=0` (source-peer exclusion). Sequence-file SHA-256 identical before / after.
- `missing_ratification` — V1: `validated_total=0`, `rejected_total=1`, `propagation_attempt_total=0`, `propagation_sent_total=0`, `propagation_suppressed_invalid_total>=1`, stderr contains a `RatificationRefused` / `Missing` marker. V2: `validated_total=0`, `propagation_sent_total=0`. V0: `received_total=0`. Sequence-file SHA-256 identical before / after.
- `bad_ratification_startup_refuse` — V1 exits non-zero; stderr contains a `RatificationRefused` / `BadSignature` / `run-105.*refused` / `run-109.*FATAL` marker; the binary NEVER reaches `P2P transport up`; no `pqc_trust_bundle_sequence.json` is created under V1's data dir.
- `duplicate_unratified_no_promotion` — V1: `received_total>=2`, `validated_total=0`, `propagation_sent_total=0`, `rejected_total + duplicate_total >= 2`. V2: `validated_total=0`, `propagation_sent_total=0`. The seen-cache does NOT convert a prior rejection into acceptance on the second arrival.
- `devnet_no_opt_in_legacy` — V1 stderr contains a Run 109 `ratification gate SKIPPED` / `policy=devnet-no-operator-opt-in` marker; V1: `validated_total=1`, `propagation_sent_total=1`; V2: `validated_total=1`. This is the regression-protection that the no-opt-in DevNet path is byte-for-byte the Run 089 unguarded path.

The cross-cutting non-mutation invariants pinned by every scenario: `pqc_trust_bundle_sequence.json` byte-identical on every node before and after; no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` metric family on any `/metrics`; all `qbind_p2p_trust_bundle_live_reload_*` and `qbind_p2p_session_eviction_*` counters at zero; no `--p2p-trusted-root` fallback log line; no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true` line.

Operator obligations remain identical to Run 109: under default-strict MainNet/TestNet (and DevNet with `--p2p-trust-bundle-ratification-enforcement-enabled`) the operator MUST supply a populated `--genesis-path` with a `genesis_authority` block and a `--p2p-trust-bundle-ratification` sidecar whose `bundle_signing_public_key` matches the configured `--p2p-trust-bundle-signing-key`. Without these the binary refuses to install the live dispatcher and exits non-zero (no fallback, no apply, no sequence write, no session eviction). Run 110 does NOT introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, governance, validator-set rotation, or full C4 / C5 closure. Source and integration-test evidence is in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_110.md`; the harness is `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh`. Run 110 is **partial-positive**: the harness, fixture helper, and docs land in-tree and are repeatable end-to-end; a fresh full release-binary capture under this PR was not produced.
## Run 111 operator update — release-binary N=3 DevNet live ratification capture executed and archived

Run 111 is the evidence-only execution of the Run 110 harness; operator workflow for `--p2p-trust-bundle-ratification*` flags, `--genesis-path`, `--expect-genesis-hash`, and `--p2p-trust-bundle-signing-key` is unchanged from Run 110. The canonical replay command is unchanged:

```bash
scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh
```

This command produces the same archive that Run 111 already captured under `docs/devnet/run_110_live_peer_candidate_ratification_n3/`. An operator may use that archive as the reference release-binary multi-node baseline for live `0x05` peer-candidate ratification behaviour. Tunables (`QBIND_RUN110_NODE_TIMEOUT`, `QBIND_RUN110_P2P_BASE`, `QBIND_RUN110_METRICS_BASE`, `QBIND_RUN110_ARCHIVE_DIR`, `QBIND_RUN110_NODE_BIN`, `QBIND_RUN110_*_HELPER`) are unchanged.

Expected release-binary behaviour was verified end-to-end (all six Run 110 scenarios passed first-shot, zero retries, zero harness or production-code changes):

- `baseline_ratification` — V1+V2 log `[run-109] live peer-candidate wire ratification gate INVOKED (policy=devnet-operator-opt-in, env=Devnet)`; no peer-candidate traffic; `qbind_p2p_pqc_cert_verify_accepted_total >= 1` and `qbind_p2p_pqc_cert_verify_rejected_total == 0` on every node.
- `valid_ratified` — V1 `validated_total=1`, `propagation_attempt_total=1`, `propagation_sent_total=1`, `propagation_suppressed_invalid_total=0`; V2 `validated_total=1`, `propagation_sent_total=0`; V0 `received_total=0` (Run 088 source-peer exclusion).
- `missing_ratification` — V1 `validated_total=0`, `rejected_total=1`, `propagation_attempt_total=0`, `propagation_sent_total=0`, `propagation_suppressed_invalid_total=1`; V1 stderr contains the typed `RatificationRefused` / `Missing` marker; V2 never validates and never propagates (an at-most-one direct broadcast from V0 may reach V2 and is rejected identically).
- `bad_ratification_startup_refuse` — V1 exits non-zero with the typed Run 105 FATAL marker; `P2P transport up` never reached; no `pqc_trust_bundle_sequence.json` is created under V1's data dir; defense-in-depth proof that bad-signature ratification cannot reach the live wire path.
- `duplicate_unratified_no_promotion` — V1 `received_total >= 2`, `validated_total=0`, `propagation_sent_total=0`, `rejected_total + duplicate_total >= 2`; the seen-cache does NOT convert prior rejection into acceptance.
- `devnet_no_opt_in_legacy` — V1 logs `[run-109] live peer-candidate wire ratification gate SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet)`; Run 089 byte-for-byte behaviour preserved. **This branch is explicitly DevNet-only developer ergonomics and is not a production posture.** MainNet and TestNet default-strict policy never reach this branch.

Operator obligations remain identical to Run 110: under default-strict MainNet/TestNet (and DevNet with `--p2p-trust-bundle-ratification-enforcement-enabled`) the operator MUST supply a populated `--genesis-path` with a `genesis_authority` block and a `--p2p-trust-bundle-ratification` sidecar whose `bundle_signing_public_key` matches the configured `--p2p-trust-bundle-signing-key`. Without these the binary refuses to install the live dispatcher and exits non-zero (no fallback, no apply, no sequence write, no session eviction). Run 111 does NOT introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, KMS/HSM custody, governance, validator-set rotation, or full C4 / C5 closure. The archived release-binary multi-node evidence is `docs/devnet/run_110_live_peer_candidate_ratification_n3/`; the Run 111 evidence document is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_111.md`.

## Run 112 operator update — process-start reload-apply ratification enforcement

Run 112 extends ratification enforcement to the **process-start reload-apply path** that the Run 070 / Run 073 flags `--p2p-trust-bundle-reload-apply-enabled` and `--p2p-trust-bundle-reload-apply-path` drive. When the operator launches the binary with `--p2p-trust-bundle-reload-apply-enabled` and a path to a candidate trust bundle, the binary now consults the Run 106 per-environment policy (`ratification_gate_decision`) and, on `Invoke(_)`, requires a valid Run 105 ratification sidecar before any snapshot, swap, session eviction, or sequence commit. The Run 070 four-step `validate → snapshot → swap → evict_sessions → commit_sequence` ordering is preserved bit-for-bit; on any ratification refusal the binary reports `ReloadApplyError::ValidationFailed(ReloadCheckError::RatificationRefused(_))`, the live trust state is unchanged, and the `pqc_trust_bundle_sequence.json` persistence file is not written.

**Operator obligations for reload-apply** under Run 112 are the alignment of the reload-check / peer-candidate-check obligations already documented in Run 105 / Run 107 / Run 109:

- MainNet and TestNet: always Strict. The operator MUST supply `--genesis-config-path` (or `--genesis-path`) with a `genesis_authority` block and `--p2p-trust-bundle-ratification <sidecar-path>`. Failure to do so on a path where the policy says `Invoke` is FATAL with a `[run-112] FATAL` typed log line and non-zero exit.
- DevNet: opt-in via `--p2p-trust-bundle-ratification-enforcement-enabled`. Without the opt-in, the legacy Run 070 reload-apply behaviour is preserved bit-for-bit (this branch is explicitly DevNet-only developer ergonomics and is not a production posture).
- The ratification sidecar's `bundle_signing_public_key` MUST match the bundle-signing key the candidate bundle is actually signed with; mismatch produces `RatifiesDifferentKey` and rejects the apply.
- The ratification sidecar's `chain_id`, `environment`, and `genesis_hash` MUST match the runtime; mismatch produces the matching `Verifier(_)` variant and rejects the apply.
- The ratification's `authority_public_key` MUST be present in the genesis `bundle_signing_authority_roots`; unknown roots reject the apply.

Operators who already configure ratification for the reload-check / peer-candidate-check paths need to make no additional configuration changes for Run 112: the same flag (`--p2p-trust-bundle-ratification`) and the same sidecar file are reused. There is no new operator flag.

Source and integration-test evidence is in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_112.md`; the integration test file is `crates/qbind-node/tests/run_112_reload_apply_ratification_tests.rs` (10/10 passing). Regressions on the same build: `run_070` 13/0, `run_073` 10/0, `run_105` 6/0, `run_106` 7/0. Run 112 is **positive** for source + integration-test surface and **partial-positive** for release-binary evidence (a release-binary capture of the reload-apply ratification scenarios is deferred to a follow-up evidence-only run). Run 112 does NOT introduce SIGHUP live reload ratification, peer-driven live apply, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, validator-set rotation, or full C4 / C5 closure.
## Run 113 operator update — process-start reload-apply ratification enforcement release-binary evidence

Run 113 is evidence-only and adds no new operator flags. Operator workflow for the process-start reload-apply path documented under Run 112 is unchanged: under default-strict MainNet/TestNet (and DevNet with `--p2p-trust-bundle-ratification-enforcement-enabled`) the operator MUST supply `--p2p-trust-bundle-reload-apply-enabled`, `--p2p-trust-bundle-reload-apply-path <candidate.json>`, `--p2p-trust-bundle <baseline.json>`, `--p2p-trust-bundle-signing-key <KEYID:SUITE_ID:PK_HEX>`, `--p2p-trust-bundle-ratification <ratification.json>`, `--genesis-path <genesis.toml>`, and `--expect-genesis-hash <hex>`. On any ratification refusal the binary aborts the reload-apply pipeline before snapshot/swap/eviction/sequence-commit and exits without writing `pqc_trust_bundle_sequence.json`; on success the binary emits the Run 070 `APPLIED live (... sequence_commit=ok)` line and the Run 073 `VERDICT=applied` marker, and the `pqc_trust_bundle_sequence.json` under `--data-dir` advances by one sequence number.

The canonical Run 113 replay command, runnable from a clean checkout:

```bash
bash scripts/devnet/run_113_reload_apply_ratification_release_binary.sh
```

The harness builds `target/release/qbind-node` and the Run 113 fixture-helper example, mints per-environment ephemeral genesis-authority + ratification fixtures, runs the nine scenarios (MainNet valid / missing / bad-signature / wrong-chain / wrong-environment / unknown-authority + DevNet legacy / opt-in valid / opt-in missing) as fresh subprocesses with per-scenario `--data-dir`, and archives the full release-binary evidence under `docs/devnet/run_113_reload_apply_ratification_release_binary/`. Each scenario's expected refusal marker is listed in the harness; key reasons used by the binary are:

- missing: `bundle-signing ratification missing`
- bad signature: `bundle-signing ratification signature failed PQC verification`
- wrong chain: `bundle-signing ratification chain_id mismatch`
- wrong environment: `bundle-signing ratification environment mismatch`
- unknown authority: `authority_root_fingerprint '<hex>' not present in genesis bundle_signing_authority_roots`

The per-scenario sequence-file inventory at `docs/devnet/run_113_reload_apply_ratification_release_binary/sequence_inventory.txt` is the canonical operator-facing no-mutation witness: WRITTEN only for scenarios 1 (MainNet valid), 7 (DevNet legacy), and 8 (DevNet opt-in valid); NOT WRITTEN for the six refusal scenarios. Operators may use this archive as the reference release-binary baseline for process-start reload-apply ratification behaviour, alongside the Run 110 / Run 111 archive for live `0x05` peer-candidate ratification behaviour.

Operator obligations for SIGHUP live reload, signing-key rotation, signing-key revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, and validator-set rotation are unchanged: each remains OPEN. Run 113 does not introduce, narrow, or change any of these surfaces. The Run 113 evidence document is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_113.md`.
## Run 116 operator update — authority anti-rollback persistence model (spec-first, no operator action)

Run 116 is **spec-first** and lands the durable anti-rollback persistence model for ratified bundle-signing authority state in documentation only. **No operator action is required.** No new flag is enabled. No new file is created or expected under `<data_dir>`. No existing flag is renamed, deprecated, or changed. The Run 100–115 operator workflows for `--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`, `--p2p-trust-bundle-ratification`, `--genesis-path` / `--genesis-config-path`, `--expect-genesis-hash`, `--p2p-trust-bundle-ratification-enforcement-enabled`, `--p2p-trust-bundle-reload-apply-enabled`, `--p2p-trust-bundle-reload-apply-path`, `--p2p-trust-bundle-live-reload-enabled`, and `--p2p-trust-bundle-live-reload-path` are unchanged.

The Run 116 model document (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md` and the Run 116 update section of `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`) describes what Runs 117–120 will introduce for operators. **Advance notice** of those operator-facing changes is recorded here so that MainNet operators are not surprised by them when Run 117 ships:

1. **New persistent file under `<data_dir>`.** Run 117 will introduce `<data_dir>/pqc_authority_state.json`, a sibling of the existing Run 055 `<data_dir>/pqc_trust_bundle_sequence.json`. The file is written atomically via tmp+rename + fsync(parent-dir) on every accepted authority transition. It is schema-versioned (`record_version = 1`), bound to `(chain_id, environment, genesis_hash)`, and records the persisted `(authority_policy_version, authority_sequence, authority_epoch, authority_root_fingerprint, ratified_bundle_signing_key_fingerprint, ratification_object_hash, last_update_source, updated_at_unix_secs)`. The file never contains private keys, never contains the full ratification object (only its 32-byte SHA3-256 digest), and never contains the full ratified PK (only its 64-hex fingerprint). Operators should treat `<data_dir>/pqc_authority_state.json` exactly like the existing `pqc_trust_bundle_sequence.json` for backup, restore, and `sha256sum` audit purposes — the two files belong together and must travel together in any `<data_dir>` tar.

2. **Environment policy (Run 117 / 118).** MainNet and TestNet enforce the marker on every boot: first boot writes it via the canonical Run 070 `validate → snapshot → swap → evict_sessions → commit_sequence` pipeline extended with a final `commit_authority_state` step; subsequent boots fail closed and exit non-zero if the file is missing, corrupt, indicates a lower authority sequence, indicates a same sequence with a different ratification object hash, or indicates a different chain_id / environment / genesis_hash than the runtime. DevNet defaults to no-op (the Run 089 / Run 106 / Run 110 / Run 111 / Run 115 DevNet ergonomics are preserved bit-for-bit). DevNet opt-in via the existing `--p2p-trust-bundle-ratification-enforcement-enabled` flag activates MainNet/TestNet semantics. **Local config alone never grants MainNet authority** — the marker is the *outcome* of operator-supplied genesis + sidecar validation under Runs 102 / 105 / 106 / 112 / 114, never a standalone authority anchor; missing genesis or missing sidecar still exits non-zero on MainNet/TestNet exactly as the existing surfaces do.

3. **Snapshot / restore obligations (Run 117).** Operators taking a snapshot on a Run-117+ binary will see the snapshot metadata grow to carry `(chain_id, environment, genesis_hash, authority_policy_version, authority_sequence, authority_epoch, authority_root_fingerprint, ratification_object_hash)`. Restoring a snapshot is forward-only: a snapshot whose authority metadata is lower or conflicting than the local marker, or absent when the local marker is present (legacy / pre-Run-117 snapshot), fails closed and requires the explicit operator-recovery flag below. **MainNet operators should retake snapshots on Run-117+ binaries** before relying on snapshot-based recovery. Until they do, the asymmetric case (Run-117+ binary, pre-Run-117 snapshot) will require the recovery flag.

4. **Operator recovery flag (Run 117).** A single explicit recovery flag `--allow-authority-state-reset` with mandatory companion `--authority-state-reset-reason <string>` will be the **only** way the marker is ever deleted by the binary. It is single-shot per boot, valid on every environment including MainNet, logged as a structured `[run-117] OPERATOR-RECOVERY` line naming the path, the prior marker fingerprint, and the operator-supplied reason, and never persists "recovery acknowledged" across boots. There is no auto-prune, no time-based expiration, and no other bypass. Operators MUST treat this flag like the existing `--allow-malformed-genesis` style escape hatches in the runbook: it is for documented operational recovery only, requires a reason, and must be removed from the next boot's command line after use. **It cannot be used to grant MainNet authority** — the post-reset boot still requires a valid Run 105 sidecar + valid Run 102 genesis + valid Run 103 ratification verifier outcome to write the new marker, and any of those failing still exits non-zero.

5. **What changes today (Run 116 only).** Nothing on the operator surface. Operators on a Run-116 build see byte-identical behaviour to a Run-115 build: same flags, same files under `<data_dir>` (`pqc_trust_bundle_sequence.json` only), same FATAL log lines on ratification refusal, same Run 070 / Run 074 `VERDICT=applied` and `sequence_commit=ok` markers on the accept path, same Run 109 `0x05` peer-candidate non-mutation contract. The Run 115 SIGHUP ratification operator workflow (10 scenarios; release-binary sha256 `c9680b3cff34fc4def081bd7ec5a55650863652ccade7ec5db95e30c3b9b30b0`) remains the canonical reference for SIGHUP behaviour, and the Run 113 process-start reload-apply ratification operator workflow remains the canonical reference for reload-apply behaviour.

Operators do NOT need to change any deployment, any systemd unit, any container manifest, any backup script, or any monitoring alert in response to Run 116. Operators MAY pre-plan for the Run 117 file under `<data_dir>` by adding `pqc_authority_state.json` to their `<data_dir>` backup glob in advance, but this is optional and the file does not yet exist on a Run-116 build.

Run 116 does NOT change peer-driven live apply (`0x05` apply still intentionally non-mutating per Run 109 contract), signing-key rotation lifecycle (deferred to Run 120 schema bump), signing-key revocation lifecycle (out of scope), KMS/HSM custody (out of scope), governance (out of scope), validator-set rotation (out of scope), fast-sync / consensus-storage-restore ratification parity (out of scope), the MainNet "local-config alone is not enough" posture (still in force), or any wire format. Static production source-code anchors remain rejected. The Run 116 evidence document is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md`.