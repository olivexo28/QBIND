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

## Run 117 — Authority anti-rollback marker storage primitive landed (no operator action required)

Run 117 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_117.md`) lands the Run 116 anti-rollback persistence model at the **storage primitive level only**. Operators on a Run-117 build see **byte-identical behaviour** to a Run-116 build on every existing surface: the same flags, the same files under `<data_dir>` (`pqc_trust_bundle_sequence.json` still the only PQC-related on-disk artifact), the same FATAL log lines on ratification refusal, the same Run 070 / Run 074 `VERDICT=applied` and `sequence_commit=ok` markers on the accept path, the same Run 109 `0x05` peer-candidate non-mutation contract, the same Run 112 process-start reload-apply behaviour, the same Run 113 / 115 SIGHUP ratification operator workflows, and the same MainNet "local-config alone is not enough" posture. The new marker file `<data_dir>/pqc_authority_state.json` is **defined by Run 117 but is not yet written by any production code path** — no startup-load, no process-start reload-apply, no SIGHUP live-reload, no reload-check, no local peer-candidate check, and no live `0x05` peer-candidate validation call into the new module on a Run-117 build. The file will begin appearing under `<data_dir>` only after the Run 118 build lands the surface wiring. Operators who already pre-planned the Run 116 backup glob update (adding `pqc_authority_state.json` to their `<data_dir>` backup script) need do nothing further; operators who deferred that step may still defer it until Run 118 makes the file authoritative. Operators do **not** need to change any deployment, any systemd unit, any container manifest, any backup script, or any monitoring alert in response to Run 117. The Run 119 release-binary evidence will exercise the wired behaviour end-to-end; until then the storage primitive is unit-tested only (38 unit tests in `crates/qbind-node/src/pqc_authority_state.rs`, 10 new `run117_*` unit tests in `crates/qbind-ledger/src/state_snapshot.rs`, all 8 Run 097 unit tests preserved, all 7 Run 097 integration tests preserved, full `qbind-ledger` lib suite 222 / 222). The single operator-recovery flag `--allow-authority-state-reset` (and its mandatory companion `--authority-state-reset-reason <string>`) introduced by the Run 116 spec is **not** implemented in any binary on a Run-117 build; it arrives with the Run 118 wiring. Run 117 does **not** change peer-driven live apply (Run 109 `0x05` contract still intentionally non-mutating), signing-key rotation lifecycle (still deferred to Run 120 `BundleSigningRatification` v2 schema bump), signing-key revocation lifecycle (out of scope), KMS/HSM custody (out of scope), governance (out of scope), validator-set rotation (out of scope), fast-sync / consensus-storage-restore ratification parity (only the snapshot-metadata carrier is in scope here; restore-side conflict detection is Run 118 scope), or any wire format. Static production source-code anchors remain rejected.
## Run 118 — Authority anti-rollback marker derivation and compare-before-accept helpers landed (no operator action required; partial-positive)

Run 118 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_118.md`) is a **helper-layer-only** step toward the Run 116 wiring goal. The verdict is intentionally **partial-positive**: the run lands the bridging helpers with full unit coverage, but does **not** yet wire any production validation or apply surface. Operators on a Run-118 build see **byte-identical behaviour** to a Run-117 build on every existing surface: same flags, same files under `<data_dir>` (`<data_dir>/pqc_authority_state.json` is still defined but still **not yet written by any production code path**), same FATAL log lines on ratification refusal, same Run 070 / Run 074 `VERDICT=applied` and `sequence_commit=ok` markers on the accept path, same Run 109 `0x05` peer-candidate non-mutation contract, same Run 112 process-start reload-apply behaviour, same Run 113 / 115 SIGHUP ratification operator workflows, same MainNet "local-config alone is not enough" posture. The Run 116 operator-recovery flag `--allow-authority-state-reset` (and its mandatory companion `--authority-state-reset-reason <string>`) remains **not implemented** in any binary on a Run-118 build; it arrives with the Run 119 surface wiring.

What changed under the hood (operator-irrelevant but recorded for auditors): the `crates/qbind-node/src/pqc_authority_state.rs` module gained a `derive_authority_state_from_ratification(...)` helper that produces a `PersistentAuthorityStateRecord` from a verified `(BundleSigningRatification, RatifiedBundleSigningKey)` pair — cross-checking the verifier output for `(environment, chain_id, authority_root_fingerprint)` consistency and computing `ratification_object_hash` directly from `canonical_ratification_digest(&ratification)` — and a `prepare_marker_for_acceptance(...)` wrapper that combines the Run 117 `load_authority_state` + `validate_record_for_domain` + `compare_authority_state` pipeline into a single typed outcome (`FirstWrite`, `AlreadyPersistedIdempotent`, `Upgrade { previous_sequence, new_sequence }`, `ConflictReject(AuthorityStateComparison)`, `LoadFailedFailClosed(AuthorityStateError)`, `PersistedDomainMismatch(AuthorityStateComparison)`). The wrapper validates the **persisted** record's `(env, chain_id, genesis_hash)` against the runtime **before** the rollback / equivocation comparison, so a wrong-data-dir or wrong-snapshot-copy mismatch surfaces with a precise reason. The wrapper **never writes** the marker file — that responsibility stays with the mutating-surface wiring landing in Run 119, which will persist the marker via `persist_authority_state_atomic` immediately after the existing Run 070 `commit_sequence` step (so a crash window leaves the marker stale-by-one, never ahead of the sequence).

**Operator actions required:** none. Backups, monitoring alerts, systemd units, container manifests, and any pre-Run-118 deployment scripts continue to work bit-for-bit. The file `<data_dir>/pqc_authority_state.json` will begin appearing under `<data_dir>` only after the Run 119 build lands the surface wiring; operators who pre-planned the Run 116 backup glob update may still leave it deferred until then.

**Operator actions deferred to Run 119:** add `pqc_authority_state.json` to `<data_dir>` backup globs once the file becomes authoritative; review the Run 119 release-binary evidence for the rollback-rejection scenarios; learn the `--allow-authority-state-reset` + `--authority-state-reset-reason <string>` recovery procedure once the flag is wired in the CLI.

**Bounded protection limit (unchanged from Run 116/117).** Even after Run 119 wires the helpers, the marker cannot detect a same-sequence key-level downgrade — that requires the per-key monotonic field added to `BundleSigningRatification` in Run 120. The helpers preserve the explicit Run 117 reject variants (`SameSequenceConflictingHash`, `SameSequenceConflictingKey`) so the bounded scope is surfaced to operators rather than being hidden behind a misleading "rotation supported" claim.

Run 118 does **not** change peer-driven live apply (Run 109 contract preserved bit-for-bit), signing-key rotation lifecycle (still deferred to Run 120), signing-key revocation lifecycle (out of scope), KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, or any wire format. Static production source-code anchors remain rejected. MainNet local-config alone remains insufficient for bundle-signing authority.
## Run 119 — Authority anti-rollback marker wired into process-start reload-apply (partial-positive)

Run 119 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_119.md`) is the **first surface-wiring step** for the Run 116/117/118 authority anti-rollback marker. The verdict is intentionally **partial-positive**: the run wires the shared `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` composition into the **process-start reload-apply surface only** (`--p2p-trust-bundle-reload-apply-path`), and **does not** yet wire the startup `--p2p-trust-bundle` acceptance path or the Run 074/114 SIGHUP live-reload path. Those two are deferred to Run 120a / 120b.

**What operators see on a Run-119 build:**

* The `<data_dir>/pqc_authority_state.json` marker file is now **written** by the binary on a successful `--p2p-trust-bundle-reload-apply-path` invocation — but **only on that one surface**. Startup `--p2p-trust-bundle` loads and SIGHUP live-reload invocations remain byte-identical to a Run-118 build (no marker file appears from those paths in Run 119).
* Three new operator-facing log lines may appear on the reload-apply surface:
  * `[run-119] authority-marker preflight skipped: ...` — pre-conditions for marker derivation are not met (no `--data-dir`, candidate is DevNet-unsigned, `LegacyUnratifiedAccepted` policy outcome, signing-key lookup miss, or pre-load deferred to the apply pipeline's own typed error). Behaviour on these branches is **unchanged** byte-for-byte from a Run-118 build.
  * `[run-119] authority-marker persisted at <path> (FirstWrite|Upgrade; candidate authority_sequence=<n>).` — a clean accept persisted a new marker.
  * `[run-119] authority-marker unchanged at <path> (idempotent; no rewrite).` — the candidate matched the on-disk marker bit-for-bit; the marker file was intentionally left unchanged.
* Two new FATAL fail-closed lines may appear:
  * `[run-119] FATAL: reload-apply refused by authority-marker preflight: <reason>. Candidate path=<...>. No live trust apply, no sequence write, no session eviction, no metrics mutation, no marker write.` — the marker preflight refused the candidate (rollback, same-sequence equivocation, persisted-domain mismatch, etc.) BEFORE any apply call fired. Exit code is non-zero.
  * `[run-119] FATAL: authority-marker persist failure AFTER successful apply: <reason>. The trust-bundle sequence already committed; the on-disk authority marker is stale-by-one and will be re-derived on the next accepted mutation (Run 118 §D crash-window rule). Candidate path=<...>.` — the atomic write or fsync failed after the apply committed the trust-bundle sequence. The trust-bundle state on disk is consistent (Run 070 ordering preserved); the marker is one mutation behind and will be repaired automatically on the next accepted reload-apply. Operator action: re-issue the reload-apply against the same candidate path; the next decide call will produce an `Upgrade` outcome that re-persists the marker cleanly. No `--allow-authority-state-reset` is needed for this case.

**Operator actions required for Run 119:**

* If you back up `<data_dir>` and have not yet done so per the Run 116 spec, **add `pqc_authority_state.json` to your backup glob now** — the file is authoritative on the reload-apply path starting with Run 119. Failing to back it up means a restore on a fresh machine could accept a candidate that would have been rejected as a rollback or same-sequence equivocation against the original node's history (the C4 sub-item gives up its rollback-detection for that one boot until a new marker is re-derived from the next accepted ratification).
* If you monitor `<data_dir>` disk usage, note that the marker file is small (a few hundred bytes JSON) but its `.tmp` sibling may appear briefly during an atomic write.
* No CLI changes. No new flags. The reload-apply invocation syntax is byte-identical to a Run-118 build.

**Operator actions deferred to Run 120 / Run 121:**

* Startup `--p2p-trust-bundle` acceptance enforcement (Run 120a). The startup loader still does not check or write the marker in Run 119. An operator who restarts the node with a downgraded bundle file will not yet be rejected at startup time on a Run-119 build; the reject only fires on the next reload-apply invocation.
* SIGHUP live-reload acceptance enforcement (Run 120b). The SIGHUP path still does not check or write the marker.
* The `--allow-authority-state-reset` + `--authority-state-reset-reason <string>` operator-recovery flag remains **not implemented** in any binary on a Run-119 build; it arrives with Run 121.
* Release-binary evidence for the four rollback-rejection scenarios is deferred to Run 120c so it can be presented alongside both startup and SIGHUP wiring evidence on the same release-binary build.

**Bounded protection limit (unchanged from Run 116/117/118).** The marker cannot detect a same-sequence key-level downgrade — that requires the per-key monotonic field that arrives in `BundleSigningRatification` v2 (Run 122). The Run 119 wiring preserves the explicit `SameSequenceConflictingHash` / `SameSequenceConflictingKey` reject variants so the bounded scope is surfaced to operators rather than being hidden behind a misleading "rotation supported" claim.

Run 119 does **not** change peer-driven live apply (Run 109 contract preserved bit-for-bit; the marker helpers are not invoked from any peer-driven surface), signing-key rotation lifecycle, signing-key revocation lifecycle, KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, or any wire format. Static production source-code anchors remain rejected. MainNet local-config alone remains insufficient for bundle-signing authority.
## Run 120 — Authority anti-rollback marker on the startup `--p2p-trust-bundle` surface

Run 120 wires the same Run 119 `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` composition into the startup `--p2p-trust-bundle` acceptance path. The marker file `<data_dir>/pqc_authority_state.json` is now authoritative on **two** of the three mutating surfaces (startup acceptance and process-start reload-apply); the Run 074/114 SIGHUP live-reload surface is the only mutating surface that still does not check or write the marker, and is staged to the next sub-run.

**What operators see on a normal accepted startup with a bundle (`--p2p-trust-bundle <path>` + `--data-dir <dir>` + a verified ratification per Run 105/106):**

```
[run-106] startup ratification gate INVOKED (policy=..., env=...).
[run-105] ... (existing Run 105 log lines)
[binary] Run 055: trust-bundle sequence persistence env=... chain_id=... path=... first-load persisted_sequence=N fp=........
[run-120] authority-marker persisted at <data_dir>/pqc_authority_state.json (first-write; candidate authority_sequence=<n>).
[binary] Run 050/051: trust bundle loaded path=... env=... fp=... active_roots=...
```

On a subsequent restart with the **same** bundle and the **same** ratification, the marker compare returns `Idempotent` and the persist step is a strict no-op:

```
[run-120] authority-marker unchanged at <data_dir>/pqc_authority_state.json (idempotent; no rewrite).
```

(`updated_at_unix_secs` deliberately does NOT bump on idempotent re-accept — re-running the binary against an unchanged bundle does not churn the marker file.)

On a restart that attempts to downgrade to an older ratification (lower `authority_sequence` than what's on disk), the startup fails closed BEFORE any mutation:

```
[run-120] FATAL: startup --p2p-trust-bundle refused by authority-marker preflight:
         Run 119: authority-marker rollback rejected: attempted authority_sequence=4 is
         lower than persisted authority_sequence=7 (fail closed). Path=<bundle.bin>.
         No Run 055 sequence write, no bundle-root merge, no live trust mutation, no
         P2P startup, no marker write.
```

The node exits non-zero. The on-disk marker file, the on-disk sequence file, and the trust-anchor set are all unchanged from the previous accepted boot. Operator recovery: identify why the older ratification was supplied (wrong file, wrong snapshot copy, wrong `--data-dir` mount); restart with the correct bundle + ratification.

**Operator actions required for Run 120:**

* Continue backing up `<data_dir>/pqc_authority_state.json` (Run 119 added this requirement; Run 120 makes it apply on every accepted startup as well as every accepted reload-apply).
* When migrating a node to a new machine, ensure `<data_dir>/pqc_authority_state.json` AND the Run 055 sequence file are copied **as a pair** to the new machine. A copy of the trust bundle + sequence file without the matching marker file will produce a `[run-120] authority-marker startup preflight skipped: ...` first-write on the next boot (legitimate) and then continue normally — no operator visible regression. Copying ONE of the two files without the other and then booting will at worst force a `FirstWrite` on the marker file (safe — fails closed only if a conflicting marker is found, never on a missing one).
* When deliberately rotating to a new genesis-bound authority block (new `authority_sequence` strictly higher than the on-disk marker's), the next accepted boot logs `[run-120] authority-marker persisted at ... (upgrade <old> -> <new>; ...)`. No additional operator step is required — the upgrade is recorded transparently.
* DevNet operators who run without `--p2p-trust-bundle-ratification-enforcement-enabled` continue to see no marker activity at all (log: `[run-120] authority-marker startup write skipped: ratification gate was not invoked (DevNet no-opt-in legacy path). The marker file is NOT written from unratified state.`). This is the same legacy ergonomics behaviour pre-Run-120. To enable Run-120 marker checking on DevNet, opt in by passing `--p2p-trust-bundle-ratification-enforcement-enabled` AND supplying a ratification sidecar (`--p2p-trust-bundle-ratification` per Run 103/105).

**What is explicitly NOT changed by Run 120:**

* Run 074/114 SIGHUP live-reload acceptance enforcement. The SIGHUP path still does not check or write the marker in Run 120. An operator who SIGHUPs the node with a downgraded bundle will not yet be rejected at SIGHUP time on a Run-120 build; the reject only fires on a subsequent startup or reload-apply.
* The Run 109 peer-candidate validation contract. The marker is not consumed from any peer-driven path; peer-supplied ratifications still cannot mutate or compare against the marker.
* The Run 105/106 startup ratification gate semantics. Run 120 runs strictly AFTER the gate returns `Ok` and never bypasses, weakens, or overrides any Run 105/106 fail-closed condition.
* The Run 055 trust-bundle sequence anti-rollback file format or location. Run 055 and Run 120 maintain two distinct files at distinct purposes: Run 055 enforces monotonicity on the trust-bundle's own per-bundle `sequence` field; Run 120 enforces monotonicity on the genesis-bound `authority_sequence` of the ratification chain.
* The Run 057 / Run 062 / Run 065 activation gate. Marker compare runs AFTER all activation gates have already accepted the candidate.
* MainNet operability. MainNet has always required `--data-dir`, a verified ratification, and an enabled ratification gate — Run 120 only adds an additional fail-closed reject reason (marker rollback / same-sequence-equivocation / wrong-domain / corrupt) onto a path that was already strict.

**Bounded protection limit (unchanged from Run 116/117/118/119).** The marker cannot detect a same-sequence key-level downgrade where two distinct signing keys share the same `authority_sequence` AND the same ratification digest — that requires the per-key monotonic field staged to Run 122 (`BundleSigningRatification` v2). The Run 120 wiring preserves the explicit `SameSequenceConflictingKey` reject variant so the bounded scope is surfaced to operators on the startup surface rather than being hidden behind a misleading "rotation supported" claim.

Run 120 does **not** change peer-driven live apply (Run 109 contract preserved bit-for-bit), signing-key rotation lifecycle, signing-key revocation lifecycle, KMS/HSM custody, governance, validator-set rotation, fast-sync / consensus-storage-restore ratification parity, or any wire format. Static production source-code anchors remain rejected. MainNet local-config alone remains insufficient for bundle-signing authority.
## Run 121 — Authority anti-rollback marker on the SIGHUP live-reload surface

Run 121 wires the same Run 119 `decide_marker_acceptance` + `persist_accepted_marker_after_commit_boundary` composition into the SIGHUP live-reload acceptance path (`spawn_run074_live_reload_task` / `LiveReloadController::run_apply_pipeline`). The marker file at `<data_dir>/pqc_authority_state.json` — the same path Run 120 introduced for the startup `--p2p-trust-bundle` surface and the same path Run 119 uses for the process-start `--p2p-trust-bundle-reload-apply-path` surface — is now also compared and (when accepted) re-persisted on every SIGHUP-triggered live trust-bundle reload-apply, completing marker coverage of **all three mutating surfaces**.

**Operator actions required for Run 121:**

* Continue backing up `<data_dir>/pqc_authority_state.json` per the Run 119 / Run 120 instructions. Run 121 makes this requirement apply on every accepted SIGHUP-triggered live reload as well as every accepted startup load and every accepted process-start reload-apply. The marker file is updated atomically (write-temp + fsync + rename, per Run 117) so a partial-write window cannot leave a corrupt marker.
* When a SIGHUP is sent and the operator sees the new `[binary] Run 121: VERDICT=marker-rejected (...)` log line, the candidate has been refused fail-closed BEFORE any mutation. Live trust state, session state, the on-disk trust-bundle sequence record, and the on-disk authority-marker file are all byte-identical to the pre-SIGHUP state. Read the embedded `MutatingSurfaceMarkerError` variant to determine the precise reject reason:
  * `AuthoritySequenceRollback { … }` — the candidate's ratification-derived `authority_sequence` is strictly less than the persisted marker. An attacker (or operator-error) is attempting to roll back to an older ratification. Refuse the SIGHUP, investigate the candidate bundle and sidecar, and either correct the candidate or recover the marker offline.
  * `SameSequenceConflictingHash { … }` — the candidate carries the same `authority_sequence` but a different ratification digest than the persisted marker. Two distinct ratifications at the same authority-sequence is a same-sequence equivocation attempt. Refuse the SIGHUP and reconcile the two ratifications offline before retrying.
  * `PersistedDomainMismatch { … }` — the marker file on disk was written for a different trust domain (different `chain_id`, `environment`, or canonical genesis hash). This is typically a wrong-`--data-dir` configuration; do NOT silently overwrite the marker. Investigate which `--data-dir` belongs to which network before retrying.
  * `LoadOrCorruption(...)` — the marker file is structurally invalid. Run 121 does NOT silently overwrite a corrupt marker; the bytes remain on disk exactly as found. Recover the marker offline from a backup, then retry.
  * `DerivationFailed(...)` — the candidate's verified ratification is internally inconsistent (chain_id / environment / authority-root-fingerprint cross-check failed). Refuse the SIGHUP and re-issue the ratification correctly.
* When a SIGHUP is sent and the operator sees the new `[binary] Run 121: VERDICT=FATAL-marker-persist (...)` log line, the trust-bundle apply pipeline DID succeed (live state advanced, sessions evicted, sequence committed) but the subsequent atomic marker write failed. The node initiates graceful shutdown via the same surface the existing Run 074 `Fatal` branch uses (no parallel shutdown surface). Recover offline: copy the in-memory marker (carried in the operator log line via the embedded `applied` block) onto disk by re-running the SIGHUP after restoring writability of `<data_dir>`. The marker is safely stale-by-one and is replayable as `Upgrade` on the next accepted SIGHUP / startup / reload-apply per Run 118 §D.

**What is explicitly NOT changed by Run 121:**

* Run 050 / 051 / 055 / 057 / 061 / 063 / 065 / 069 / 070 / 071 / 072 / 073 / 074 / 076 / 077 / 087 / 088 / 089 / 091–099 / 100 / 101 / 102 / 103 / 104 / 105 / 106 / 107 / 108 / 109 / 110 / 111 / 112 / 113 / 114 / 115 / 116 / 117 / 118 / 119 / 120 invariants — all preserved bit-for-bit. Specifically, the existing Run 070 SIGHUP callback ordering (`snapshot_active → swap_trust_state → evict_sessions → commit_sequence`) is preserved because the marker persist step lives STRICTLY OUTSIDE the apply pipeline (in the controller's `run_apply_pipeline` AFTER the apply call returns Ok), and the marker preflight runs STRICTLY BEFORE any apply callback fires.
* Run 074/114 SIGHUP fatal-shutdown semantics. The existing `SequenceCommitFailedRollbackAlsoFailed` branch still signals graceful shutdown via `shutdown_tx.send(())`; Run 121's `MarkerPersistFailureAfterCommit` branch reuses the SAME single shutdown surface (because `is_fatal()` returns `true` for both), so operators have one place to look for fatal-shutdown signals across both runs.
* Validation-only surfaces (`--p2p-trust-bundle-reload-check-path`, Run 077/107 peer-candidate-check, live inbound `0x05`). Run 121 does NOT extend the validation-only surfaces with marker comparison — those surfaces remain validation-only and never persist the marker.
* DevNet without operator opt-in. When the Run 114 ratification gate is `Skip` (DevNet without `--p2p-trust-bundle-ratification-enforcement-enabled`), the marker config is `None`, the marker preflight is never invoked, and the marker file is never created or read on SIGHUP. Pre-Run-121 SIGHUP behaviour byte-identical.
* MainNet operability. MainNet has always required `--data-dir`, a verified ratification, and an enabled ratification gate — Run 121 only adds a marker compare + persist after the existing gate, never weakens it.

**Bounded protection limit (unchanged from Run 116/117/118/119/120).** The marker cannot detect a same-sequence key-level downgrade where two distinct candidates carry the same `authority_sequence` AND the persisted ratification digest somehow matches the older candidate (e.g. via deliberate operator overwrite of the marker file). The per-key monotonic `BundleSigningRatification` v2 schema bump is the long-term fix and remains deferred to a future run.

## Run 122 — Release-binary evidence for authority anti-rollback marker on mutating surfaces

**No operator action required.** Run 122 is evidence-only — no production runtime code was changed, no new flag was introduced, no existing flag was renamed or deprecated, no new file is created or expected under `<data_dir>`. The Run 117–121 operator workflows are unchanged.

**What Run 122 proves on real `target/release/qbind-node` binaries:**

Run 122 closes the release-binary evidence gap that Runs 119, 120, and 121 each deferred. The evidence harness (`scripts/devnet/run_122_authority_marker_mutating_surfaces_release_binary.sh`) exercises 10 scenarios across two surfaces:

* **Reload-apply (Run 119 wiring):** First marker persist (`first-write`); idempotent re-run (marker byte-identical, no rewrite); conflicting marker (same-sequence equivocation) rejects before mutation with `rc=1` and no trust state change; corrupt marker (non-JSON) fails closed before mutation with `rc=1` and marker bytes preserved; DevNet no-opt-in produces no marker file.
* **SIGHUP (Run 121 wiring):** First marker written at startup (Run 120) before SIGHUP handler installed; SIGHUP gate (Run 121) invoked and applied; conflicting marker (tampered post-startup) produces `Run 121: VERDICT=marker-rejected` before any live trust mutation; corrupt marker (non-JSON, tampered post-startup) fails closed with same verdict.
* **Startup (Run 120 wiring, implicit):** Proven via the SIGHUP evidence — the startup path wrote the marker with `last_update_source: "startup-load"` before the SIGHUP handler was installed.

**Evidence artifacts:** `docs/devnet/run_122_authority_marker_mutating_surfaces/` (stderr logs for each scenario, marker JSON, summary). Evidence document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_122.md`.

**What is explicitly NOT changed by Run 122:**

* No production `crates/**/src/**` change. No test change. No metric change. No wire format change. No new dependency.
* All Runs 050–121 invariants preserved bit-for-bit.
* Validation-only surfaces remain validation-only and never persist the marker.
* The bounded protection limit (same-sequence key-level downgrade) is unchanged from Run 116/117/118/119/120/121.


Run 121 does **not** change peer-driven live apply (Run 109 contract preserved bit-for-bit; the marker helpers are not invoked from any peer-driven path), signing-key rotation lifecycle, signing-key revocation lifecycle, KMS/HSM custody, governance, validator-set rotation, or fast-sync / consensus-storage-restore ratification parity (the Run 117 `AuthorityStateSnapshotMeta` carrier is present but no restore-side conflict check consumes it yet).
---

## Run 123 — Validation-Only Authority Marker Conflict Checks

**What Run 123 adds:**

Run 123 extends the authority anti-rollback marker checks to the three validation-only surfaces that never persist marker state. These surfaces now reject candidates that conflict with the persisted authority marker, providing defense-in-depth against rollback attacks even on non-mutating paths.

**Surfaces wired in Run 123:**

| Surface | Operator impact on marker conflict | Operator impact on no prior marker |
|---------|-----------------------------------|-----------------------------------|
| `--p2p-trust-bundle-reload-check` | Exit code 1; log message identifies marker conflict | No change (pass) |
| `--p2p-trust-bundle-peer-candidate-check` | Exit code 1; log message identifies marker conflict | No change (pass) |
| Live inbound `0x05` peer-candidate | Frame rejected; propagation suppressed; `peer_candidate_rejected_total` incremented | No change (pass; propagation eligible as before) |

**Operator notes:**

- No new CLI flags. The marker check activates automatically when the ratification gate is invoked (MainNet/TestNet by default, DevNet opt-in) AND `--data-dir` is configured.
- A missing marker file (no prior mutating-surface run) does NOT block validation. The marker is only compared if it exists.
- A corrupt or wrong-domain marker always fail-closes (same behavior as mutating surfaces from Runs 119–121).
- The marker file is NEVER written by validation-only surfaces. Only startup (Run 120), reload-apply (Run 119), and SIGHUP (Run 121) persist markers.
- If a reload-check or peer-candidate-check fails with a marker conflict, the operator should investigate whether the `--data-dir` state directory was copied from a different trust domain or was tampered with.

**What is explicitly NOT changed by Run 123:**

- Mutating-surface marker behavior (Runs 119/120/121) — unchanged.
- Snapshot/restore conflict enforcement — future run.
- `--allow-authority-state-reset` operator recovery — future run.
- Per-key monotonic field schema bump — future run (Run 125+).
- No new wire format changes.
- No new persistence format changes.
- No signing-key rotation/revocation lifecycle.
## Run 124 — Snapshot/restore authority anti-rollback marker conflict enforcement

**What Run 124 adds:**

Run 124 wires the authority anti-rollback marker into the **snapshot restore** surface (`--restore-from-snapshot <path>`). The restore path now compares the snapshot's optional `AuthorityStateSnapshotMeta` block (Run 117 additive metadata) against the locally persisted `<data_dir>/pqc_authority_state.json` marker BEFORE materializing any state checkpoint or writing the B3 `RESTORED_FROM_SNAPSHOT.json` audit marker. A conflict — rollback, equivocation, key conflict, policy regression, wrong-domain, corrupt local marker, or a snapshot that would silently shadow a pre-existing local marker — exits non-zero with a precise operator log line before any state mutation occurs.

**Surfaces wired in Run 124:**

| Surface | Marker check wired | On conflict / corrupt / missing-when-required | On no marker either side | Persists marker? |
|---------|-------------------|-----------------------------------------------|--------------------------|------------------|
| `--restore-from-snapshot` (B3 / B5) | After snapshot layout validation, BEFORE state materialization and audit-marker write | `exit(1)` with `[restore] FATAL: refused by Run 124 authority-marker check: ...` | Pass (legacy snapshot into fresh data dir) | Never — the marker file is the *outcome* of a mutating-surface acceptance, never synthesised from a snapshot block |

**Operator notes:**

- No new CLI flag. The marker check activates automatically when `--restore-from-snapshot` is used AND the canonical Run 101 genesis hash was computed at boot (Run 102 `Verified` branch — i.e. an external `--genesis-path` is configured, which is mandatory on MainNet and recommended on TestNet/DevNet).
- A legacy pre-Run-117 snapshot (no `authority_state` block) restoring into a fresh `--data-dir` with no local marker is **accepted** — first-time DevNet/TestNet restores still work. The next mutating surface (startup, reload-apply, SIGHUP) will write the canonical marker from the verified ratification.
- A legacy snapshot restoring into a `--data-dir` that already has a local `pqc_authority_state.json` marker is **rejected fail-closed** on every environment, including DevNet — accepting it would silently shadow the persisted ratified authority state. Operator recovery is a future flag (`--allow-authority-state-reset`); Run 124 does NOT implement it.
- A Run-117+ snapshot whose authority block matches the local marker bit-for-bit is **accepted idempotently** and the local marker bytes are NOT rewritten.
- A Run-117+ snapshot whose authority block conflicts with the local marker (lower `authority_sequence`, same `authority_sequence` with a different `ratification_object_hash` or different `ratified_bundle_signing_key_fingerprint`, `authority_policy_version` regression, wrong `chain_id` / `environment` / `genesis_hash`) is **rejected fail-closed** — no state copy, no audit-marker write, local marker bytes preserved verbatim.
- A corrupt or unsupported-version local marker fails closed; the on-disk bytes are preserved exactly.
- The legacy `apply_snapshot_restore_if_requested` entry point (used by tests that have no genesis context) refuses the restore with `AuthorityContextMissing` whenever a pre-existing local marker is on disk — there is no silent shadowing through that path either.

**What is explicitly NOT changed by Run 124:**

- Mutating-surface marker behavior (Runs 119/120/121) — unchanged.
- Validation-only marker behavior (Run 123) — unchanged.
- The B3 snapshot layout, B5 restore-aware consensus startup, Run 097 snapshot epoch parity — all preserved bit-for-bit on accept paths.
- The local `<data_dir>/pqc_authority_state.json` file is NEVER written, rewritten, or deleted by the restore surface — only mutating surfaces persist the marker.
- No new wire format changes.
- No new persistence format changes.
- No new CLI flag (no `--allow-authority-state-reset` in this run).
- No signing-key rotation/revocation lifecycle.
- No peer-driven live apply.
- Per-key monotonic ratification schema bump — future run (Run 125+).
- Full C4 / C5 closure remain open.

## Run 125 — Release-binary evidence for the Run 124 snapshot/restore authority anti-rollback marker conflict enforcement

**What Run 125 adds:**

Run 125 is **evidence-only**; it closes the release-binary evidence gap that Run 124 explicitly deferred. The harness `scripts/devnet/run_125_snapshot_restore_authority_marker_release_binary.sh` builds `target/release/qbind-node` and a new evidence-only fixture helper (`crates/qbind-node/examples/run_125_snapshot_restore_authority_marker_fixture_helper.rs`), mints an ephemeral DevNet genesis with a Run 101 authority block, and exercises the snapshot/restore surface against four real B3 snapshot directories (legacy / matching / same-sequence-conflicting / wrong-genesis-domain) and two local-marker fixtures (matching JSON / corrupt non-JSON bytes).

**Operator-visible behaviour (unchanged from Run 124; evidenced on release binary):**

| Scenario | Operator sees | Disk side-effects |
|----------|---------------|-------------------|
| Legacy snapshot into fresh data dir | `[restore] Run 124 authority-marker check: no local authority marker and no snapshot authority metadata ... proceeding with materialization` then `[restore] OK: ...` | `RESTORED_FROM_SNAPSHOT.json` + `state_vm_v0/` materialized; no `pqc_authority_state.json` invented |
| Legacy snapshot + local marker present | `[restore] FATAL: refused by Run 124 authority-marker check: ... snapshot carries no authority metadata (fail closed; accepting would silently erase or roll back the local persisted authority state)`; rc=1 | No state materialization; no audit marker; local marker bytes byte-identical (sha256 before == sha256 after) |
| Matching snapshot + matching local marker | `[restore] Run 124 authority-marker check: local authority marker matches snapshot authority metadata bit-for-bit (restore may proceed; local marker NOT rewritten)` then `[restore] OK: ...` | `RESTORED_FROM_SNAPSHOT.json` + `state_vm_v0/` materialized; local marker bytes byte-identical (never rewritten on accept either) |
| Same-sequence different `ratification_object_hash` | `[restore] FATAL: ... authority-state same-sequence equivocation rejected: authority_sequence=N persisted_ratification_hash=... attempted_ratification_hash=...`; rc=1 | No state materialization; no audit marker; local bytes preserved |
| Corrupt local marker (non-JSON) | `[restore] FATAL: ... local authority marker is corrupt or unsupported: ... (bytes preserved verbatim)`; rc=1 | No state materialization; no audit marker; corrupt bytes byte-identical (no auto-repair) |
| Wrong-domain snapshot (`genesis_hash_hex` mismatches runtime canonical Run 101 hash) | `[restore] FATAL: ... snapshot authority metadata has wrong trust domain: snapshot.genesis_hash_hex=... runtime.genesis_hash_hex=...`; rc=1 | No state materialization; no audit marker |
| Legacy no-context entry point (`--restore-from-snapshot` WITHOUT `--genesis-path`) + local marker present | `[restore] ERROR: restore-from-snapshot refused: a local pqc_authority_state.json marker exists but no runtime authority context (env, chain_id, genesis_hash) was supplied to the restore surface (fail closed). Use restore_from_snapshot_with_authority_marker_check from a binary surface that has loaded the canonical genesis.`; rc=1 | No state materialization; no audit marker; local bytes preserved |

**Operator actions:** none. No new CLI flag, no new environment variable, no new file path, no new metric family. The release binary's behavior with `--restore-from-snapshot` is unchanged by Run 125 — Run 125 only adds release-binary evidence that the Run 124 wiring behaves on a real binary the same way it behaves under unit and integration tests.

**Evidence archive:** `docs/devnet/run_125_snapshot_restore_authority_marker/` (per-scenario stderr/exit codes for all 7 scenarios, the matching marker fixture JSON, snapshot meta JSON for the matching and conflicting cases, and a summary that records the captured binary's sha256 + build-id and the before/after local marker sha256s).

**Per-scenario test counts on the same build:** `run_124_snapshot_restore_authority_marker_tests` 7/7, `b3_snapshot_restore_tests` 10/10, `run_119_authority_marker_acceptance_tests` 4/4, `run_121_sighup_authority_marker_tests` 7/7, `qbind-node --lib pqc_authority_state` 74/74. No existing test was modified.

**What is explicitly NOT changed by Run 125:**

- The Run 124 production wiring — unchanged.
- The mutating-surface marker behavior (Runs 119/120/121) — unchanged.
- The validation-only marker behavior (Run 123) — unchanged.
- The B3 snapshot layout, B5 restore-aware consensus startup, Run 097 snapshot epoch parity — all preserved bit-for-bit on accept paths.
- The local `<data_dir>/pqc_authority_state.json` file is NEVER written, rewritten, or deleted by the restore surface — only mutating surfaces persist the marker (re-evidenced on the release binary by Scenarios 2, 3, 5, 7).
- No new wire format changes.
- No new persistence format changes.
- No new CLI flag (still no `--allow-authority-state-reset`).
- No signing-key rotation/revocation lifecycle.
- No peer-driven live apply.
- Per-key monotonic ratification schema bump — future run (Run 126+).
- Full C4 / C5 closure remain open.

## Run 126 — Explicit authority-state reset/recovery procedure specification (spec-first / docs-only)

**What Run 126 adds:**

Run 126 is **spec-first / docs-only**; no production runtime code was changed, no CLI reset command was implemented, and no runtime behavior was modified. Run 126 defines the formal specification for authority-state reset/recovery after fail-closed anti-rollback events.

**Operator actions:** none in Run 126. No new CLI flag, no new environment variable, no new file path, no new metric family. The specification defines a FUTURE operator procedure (see below).

**Future operator procedure (authority-state reset ceremony):**

When a future run implements `authority-state-reset`, operators will follow this staged process:

```
STAGE 1: STOP
  1. Stop the node (SIGTERM / SIGKILL).
  2. Confirm the node process is not running.

STAGE 2: ARCHIVE
  3. Copy the current data directory to a timestamped archive.
  4. Copy <data-dir>/pqc_authority_state.json to the archive.
  5. Compute SHA-256 of the archived marker.
  6. If snapshot-related: archive snapshot metadata.

STAGE 3: VERIFY
  7. Verify the genesis file and compute canonical genesis hash:
       qbind-node --print-genesis-hash --genesis-path <GENESIS_PATH>
  8. Verify chain_id and environment match the target deployment.
  9. Verify candidate ratification under genesis authority:
       qbind-node --p2p-trust-bundle <BUNDLE> \
                  --p2p-trust-bundle-ratification <RATIFICATION> \
                  --genesis-path <GENESIS_PATH> \
                  --p2p-trust-bundle-reload-check \
                  --data-dir <TEMP_EMPTY_DIR>

STAGE 4: COMPARE
  10. Document old vs. candidate marker fields.

STAGE 5: EXECUTE (future command — NOT yet implemented)
  11. qbind-node authority-state-reset \
        --data-dir <DATA_DIR> \
        --genesis-path <GENESIS_PATH> \
        --expected-genesis-hash <HASH> \
        --p2p-trust-bundle <BUNDLE> \
        --p2p-trust-bundle-ratification <RATIFICATION> \
        --output-audit <AUDIT_PATH> \
        --environment <devnet|testnet|mainnet> \
        [--confirm]
  12. Verify audit record at <AUDIT_PATH>.

STAGE 6: RESTART AND VERIFY
  13. Start node normally with standard flags.
  14. Verify no authority-marker errors in startup logs.
  15. Verify new marker on disk: cat <DATA_DIR>/pqc_authority_state.json
  16. Verify audit record is complete and archived.
```

**Environment policy:**

| Environment | Reset allowed? | Requirements |
|-------------|---------------|--------------|
| DevNet | Yes, with ceremony | Valid ratification + genesis + audit output |
| TestNet | Yes, with ceremony | Valid ratification + genesis + audit + operator confirmation |
| MainNet | **No (default refuse)** | Requires future governance artifact (not yet designed) |

**Mandatory refusal cases (future implementation must refuse when):**

- Missing or wrong genesis hash
- Wrong chain_id or environment
- Malformed authority root
- Transport root attempting bundle-signing authorization
- Missing or invalid ratification
- Local config-only MainNet reset (no governance artifact)
- Peer-provided reset request
- Node still running
- Missing audit output path
- Marker erasure without replacement on MainNet/TestNet

**Reset safety invariants:**

1. Never runs implicitly (no auto-repair, no silent overwrite).
2. Never runs during normal startup (separate subcommand).
3. Never triggered by peer input.
4. Never persists from validation-only surfaces.
5. Never synthesizes marker from legacy snapshot.
6. Never bypasses ratification verification.
7. Never allows transport root authority.
8. Never allows local config alone as MainNet authority.
9. Always produces an audit record (even DevNet).
10. Irreversible without another explicit audited ceremony.

**Audit record schema (conceptual, 17 fields):**

```
record_version, action, environment, chain_id, genesis_hash,
old_marker_hash, old_marker_record, new_marker_hash, new_marker_record,
ratification_hash, trust_bundle_fingerprint, snapshot_metadata_hash,
operator_note_hash, binary_sha256, binary_build_id, timestamp, result
```

**What is explicitly NOT changed or implemented by Run 126:**

- No `--allow-authority-state-reset` CLI flag.
- No reset CLI command or subcommand.
- No runtime code changes.
- No `pqc_authority_state.json` deletion or rewrite.
- No snapshot restore behavior change.
- No trust-bundle wire format change.
- No signing-key rotation/revocation lifecycle.
- No peer-driven live apply.
- No KMS/HSM custody.
- No governance artifact format.
- No ratification v2 per-key monotonic schema.
- No full C4 / C5 closure.
- Static production source-code anchors remain rejected.
- Local config alone remains insufficient for MainNet authority.

**Future implementation plan:**

| Run | Scope |
|-----|-------|
| Run 127 | Implement `authority-state-reset` CLI skeleton with refusal cases |
| Run 128 | Release-binary evidence for reset refusal/allowed cases |
| Run 129+ | Ratification v2 per-key monotonic schema design |
| Future | Signing-key rotation/revocation, MainNet governance, KMS/HSM |
- Full C4 / C5 closure remain open.
---

## Run 127 — offline authority-state reset CLI skeleton

**Date:** 2026-05-23
**Evidence:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_127.md`

Run 127 implements the Run 126 specification skeleton. The `--authority-state-reset` CLI flag is now operative on DevNet and TestNet; MainNet is refused by default.

### What changed for operators

| Item | Status |
|---|---|
| `--authority-state-reset` flag | Now available (hidden) |
| `--authority-state-reset-output-audit` | Required when reset flag is set |
| `--authority-state-reset-operator-note` | Optional ceremony note (stored as hash) |
| Reset allowed on DevNet / TestNet | Yes, when all checks pass |
| Reset allowed on MainNet | **No — MainNetLocalResetUnsupported** |
| Audit record emitted | Always (success and refusal) |
| Existing corrupt marker auto-repaired | **Never — operator must remove out-of-band** |

### Operator ceremony (DevNet/TestNet)

```
qbind-node \
  --authority-state-reset \
  --env devnet \
  --data-dir <data-dir> \
  --genesis-path <genesis.json> \
  --expect-genesis-hash <hash> \
  --p2p-trust-bundle <bundle.json> \
  --p2p-trust-bundle-signing-key <keyspec> \
  --p2p-trust-bundle-ratification <ratification.json> \
  --authority-state-reset-output-audit <audit.json> \
  --authority-state-reset-operator-note "ceremony note"
```

Exit code `0` means success; exit code `1` means refused. The audit record is always written first (or best-effort on refusal).

### Typed refusal cases

See `AuthorityResetRefusal` in `crates/qbind-node/src/pqc_authority_state_reset.rs` for the full 23-variant enum. The `stable_id()` appears in `refusal_reason` of the audit record and is never renamed without a documented schema migration.

### Evidence archive

18 unit tests in `pqc_authority_state_reset::tests` cover all structural refusal cases, crash-safe audit behavior, canonical JSON determinism, and stable-id surface. All 126 prior `pqc_authority*` tests pass.

### Non-changes

- No wire format change.
- No persistence format change.
- No change to Run 117–121 mutating surfaces.
- No change to Run 123 validation-only surfaces.
- No change to Run 124–125 restore conflict enforcement.
- No peer-driven anything.
- No MainNet reset path implemented.
- Static production source-code anchors remain rejected.

## Run 128 — release-binary evidence for authority-state reset CLI

**Date:** 2026-05-24  
**Evidence:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_128.md`  
**Harness:** `scripts/devnet/run_128_authority_state_reset_release_binary.sh`

Run 128 is evidence-only and proves Run 127 reset behavior on real release binaries (`target/release/qbind-node`) with deterministic archived artifacts under `docs/devnet/run_128_authority_state_reset_release_binary/`.

### Release-binary scenario outcomes

| Scenario | Result |
|---|---|
| DevNet valid reset writes marker + audit | PASS |
| MainNet local reset refused (`MainNetLocalResetUnsupported`) | PASS |
| Missing ratification refused (`MissingRatification`) | PASS |
| Bad ratification refused (`RatificationEnforcementFailed`) | PASS |
| Wrong expected genesis hash refused (`GenesisHashMismatch`) | PASS |
| Corrupt existing marker refused (`ExistingMarkerCorrupt`) and preserved | PASS |
| Missing audit output flag refused (`AuditOutputMissing`) | PASS |
| Wrong-chain and wrong-environment ratification refused | PASS |

### Operator-visible guarantees proven by Run 128

- Marker file is written only on success.
- Every refusal preserves marker bytes (sha256 before == sha256 after).
- Reset path exits before normal startup surfaces (no P2P/consensus/metrics/SIGHUP/reload/peer-candidate startup markers).
- Refusal reasons remain typed/stable (`refusal_reason_if_any` in audit).
- Success/refusal audit records are emitted when audit path flag is supplied.

### Run 128 explicit non-changes

- No MainNet governance artifact support.
- No peer-driven reset/apply path.
- No trust-bundle wire format or peer-candidate wire format change.
- No signing-key rotation/revocation implementation.
- No KMS/HSM, governance, or validator-set rotation implementation.
- No ratification-v2 monotonic authority sequence implementation.
- No full C4 or C5 closure claim.

## Run 129 — ratification v2 monotonic schema specification (docs-only)

**Date:** 2026-05-24  
**Evidence:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_129.md`

Run 129 is spec-first/docs-only. It does not change runtime behavior. It defines the ratification v2 schema and fail-closed comparison model required for safe future signing-key rotation/revocation.

### Run 128 doc-sync checkpoint (required correction)

Run 129 confirms and synchronizes the Run 128 operator-facing facts:

- Run 128 is release-binary evidence for offline authority-state reset CLI behavior.
- DevNet valid reset writes marker + audit.
- MainNet local reset refuses.
- Missing/bad ratification, wrong expected genesis hash, corrupt marker, missing audit output flag, and wrong-chain/wrong-environment sidecars all refuse.
- Refusal paths do not write/mutate marker bytes.
- Reset exits before normal startup surfaces.
- MainNet governance artifacts remain OPEN.
- Ratification v2 monotonic schema remains OPEN until Run 129 specification and future implementation runs.
- Rotation/revocation, KMS/HSM, peer-driven live apply, full C4 closure, and C5 closure remain OPEN.

### Run 129 design decisions (operator-impact summary)

1. **Monotonic model selected:** one monotonic `authority_domain_sequence` per authority domain (`environment + chain_id + genesis_hash + authority_root_fingerprint`), not per-key counters.
2. **v2 lifecycle actions:** `ratify`, `rotate`, `revoke`, with mandatory action-linked fields (`previous_*` for rotate; revocation reason for revoke).
3. **Canonical v2 signing domain:** `QBIND:BUNDLE-SIGNING-RATIFICATION:v2` with deterministic length-prefixed preimage over all security-relevant fields.
4. **Marker v2 extension (future implementation):** track schema version, latest authority sequence, latest action, active/previous key fingerprints, latest ratification digest, and revocation accumulator digest.
5. **Compatibility/downgrade policy:** v1 after v2 marker exists is fail-closed refuse; v2 after v1 marker is migration path; same-sequence conflicting digest is fail-closed equivocation.
6. **Activation policy:** v2 enablement must be explicit and authority-policy/governance bound; MainNet cannot rely on local config alone.

### Future run staging

| Run | Scope |
|-----|-------|
| Run 130 | Implement v2 schema/types + canonical preimage + verifier tests |
| Run 131 | Implement marker v2 extension + v1→v2 marker migration |
| Run 132 | Wire v2 verifier/comparison into enforcement surfaces under compatibility gates |
| Run 133 | Release-binary v2 acceptance/rejection evidence |
| Run 134+ | Rotation lifecycle, then revocation lifecycle, then governance/KMS/HSM extensions |

### Run 129 explicit non-changes

- No v2 verifier code implementation.
- No runtime code changes.
- No trust-bundle wire format change.
- No peer-candidate wire format change.
- No reset CLI behavior change.
- No marker persistence behavior change.
- No rotation/revocation lifecycle implementation.
- No KMS/HSM implementation.
- No MainNet governance artifact implementation.
- No peer-driven live apply implementation.
- No full C4 or C5 closure claim.

## Run 130 — ratification v2 schema, canonical preimage, and verifier tests

**Type:** Implementation (additive; no production wiring).

Run 130 implements the ratification v2 schema per the Run 129 specification. It adds all new types to `crates/qbind-ledger/src/bundle_signing_ratification.rs` and passes 32 new unit tests.

Run 131 doc-sync checkpoint: Run 130 landed `RatificationV2Failure` typed failures and the v2 verifier primitive only; marker v2 migration is Run 131 scope, production v2 enforcement wiring is Run 132 scope, release-binary v2 evidence is Run 133 scope, rotation/revocation lifecycle remains future scope, and full C4/C5 closure remains open.

### Operator-visible guarantees added by Run 130

- `BundleSigningRatificationV2` objects can be constructed and signed with `v2_test_helpers::build_signed_ratification_v2`.
- `verify_bundle_signing_key_ratification_v2` is a fail-closed primitive: every error path returns a typed `RatificationV2Failure`; no `Ok` is possible unless ALL checks pass including ML-DSA-44 signature verification.
- v2 `authority_domain_sequence` is validated ≥ 1 before any signature check.
- v2 lifecycle-action fields are validated: rotation fields are required/forbidden per action; revoke requires at least one reason/scope field.
- The v2 domain tag `QBIND:BUNDLE-SIGNING-RATIFICATION:v2` is cryptographically distinct from the v1 tag; no preimage collision is possible.
- Transport roots remain rejected for v2 ratifications (`TransportRootNotAllowed`).
- v1 verifier behavior is unchanged.

### Roadmap position

| Run | Description |
|-----|-------------|
| Run 129 | Ratification v2 monotonic schema specification (docs-only) |
| **Run 130** | **v2 types + canonical preimage + verifier tests (this run)** |
| Run 131 | Authority marker v2 extension and migration |
| Run 132 | Production v2 enforcement wiring |
| Run 133 | Release-binary v2 evidence |
| Run 134+ | Rotation, then revocation lifecycle |

### Run 130 explicit non-changes

- No production enforcement wiring.
- No authority marker persistence change.
- No trust-bundle or peer-candidate wire format change.
- No reset CLI behavior change.
- No rotation/revocation lifecycle implementation.
- No KMS/HSM implementation.
- No MainNet governance artifact implementation.
- No peer-driven live apply implementation.
- No full C4 or C5 closure claim.
## Run 131 — authority marker v2 extension and migration helpers

**Type:** Implementation (additive marker types + comparison helpers; no production wiring).

Run 131 implements the authority marker v2 primitive: `PersistentAuthorityStateRecordVersioned::{V1, V2}`, `PersistentAuthorityStateRecordV2`, `derive_authority_state_v2_from_ratification`, `compare_authority_marker_v2`, `migrate_authority_marker_v1_to_v2`, and `prepare_v2_marker_for_acceptance`. v1 marker on-disk format is preserved bit-for-bit. No production v2 surface is wired in Run 131.

### Operator-visible guarantees added by Run 131

- v2 marker comparison helpers exist and are unit-tested; they cover idempotent, upgrade-compatible, lower-sequence-refused, same-sequence-different-digest-refused, and v1-after-v2-refused outcomes.
- Comparison helpers are validation-only: they never persist marker state.
- v1→v2 marker migration is a one-way helper consumed by Run 132 validation-only surfaces; it is never invoked automatically on a mutating surface in Run 131.

### Run 131 explicit non-changes

- No production v2 surface wiring (deferred to Run 132).
- No release-binary v2 evidence (deferred to Run 133).
- No CLI flag changes.
- No wire-format changes.
- No automatic v1→v2 marker migration on production surfaces.
- No rotation/revocation lifecycle.
- No KMS/HSM, MainNet governance artifact, or peer-driven live apply.

## Run 132 — v2 validation-only surface wiring

**Type:** Implementation (validation-only surface wiring; no mutating-surface wiring; no persistence).

Run 132 wires v2 ratification and v2 marker compatibility into the two validation-only binary surfaces consumed by operators: `--p2p-trust-bundle-reload-check` and the local `--p2p-peer-candidate-check`. Mutating-surface v2 wiring, live inbound `0x05` v2 wiring, and release-binary v2 evidence remain deferred.

### What Run 132 wired

| Item | Detail |
|------|--------|
| Versioned sidecar dispatch | `VersionedRatificationSidecar::{V1, V2}` + `load_versioned_ratification_from_path()` in `crates/qbind-node/src/pqc_ratification_input.rs`. Unknown/malformed schema fails closed. |
| `reload-check` v2 support | `--p2p-trust-bundle-reload-check` accepts v2 sidecars under the documented validation-only compatibility policy. |
| Local `peer-candidate-check` v2 support | `--p2p-peer-candidate-check` accepts v2 sidecars under the documented validation-only compatibility policy. |
| v2 verifier | Uses Run 130 `verify_bundle_signing_key_ratification_v2`. |
| v2 marker comparison | Uses Run 131 `derive_authority_state_v2_from_ratification` + `compare_authority_marker_v2`. |
| v1 behavior | Preserved bit-for-bit. Falls through to existing v1 preflight when sidecar is v1. |

### v2 validation-only compatibility/downgrade policy

| Case | Outcome |
|------|---------|
| valid v2, no local marker | accept (`NoPersistedMarkerYet`) |
| same-sequence + same-digest | idempotent accept (`Idempotent`) |
| higher v2 sequence | accept (`UpgradeCompatible`) |
| v2-after-v1 | accept only as explicit migration candidate (`V2AfterV1MigrationCandidate`) |
| v1-after-v2 | refuse (`V1AfterV2Rejected`) |
| lower v2 sequence | refuse (`LowerV2SequenceRefused`) |
| same-sequence + different-digest | refuse (`SameSequenceDifferentDigestRefused`) |
| unknown/malformed schema | refuse (`VersionedRatificationInputError`) |

### Persistence invariant

Validation-only surfaces never persist marker state. Enforced structurally (no `persist_authority_state_atomic` call on any validation-only path) and verified by 9 dedicated unit tests including `run132_v2_no_marker_write_occurs_in_any_case`.

### Deferred / future scope

- Live inbound `0x05` v2 wiring remains deferred.
- Mutating-surface v2 wiring (startup `--p2p-trust-bundle`, process-start reload-apply, SIGHUP live reload) remains deferred.
- Release-binary v2 evidence remains open until Run 133.
- Rotation lifecycle, revocation lifecycle, KMS/HSM custody, MainNet governance artifact support, peer-driven live apply, full C4 and C5 closure all remain future work.

### Run 132 explicit non-changes

- No mutating-surface v2 wiring.
- No v2 marker persistence from validation-only checks.
- No live inbound `0x05` v2 wiring.
- No trust-bundle wire-format change.
- No peer-candidate wire-format change.
- No reset CLI behavior change.
- No KMS/HSM, MainNet governance artifact, or peer-driven live apply implementation.
- No rotation or revocation lifecycle implementation.
- No full C4 or C5 closure claim.

Static production source-code anchors remain rejected. Local config alone remains insufficient for MainNet bundle-signing authority. v1 verifier behavior is preserved bit-for-bit.

## Run 133 — release-binary v2 validation-only evidence (operator-facing)

Run 133 is the release-binary evidence run for the Run 132 v2 validation-only wiring on the two operator surfaces below. It does not introduce any new CLI flag and does not change any operator workflow vs Run 132.

**Operator surfaces exercised**

| CLI surface                                  | Sidecar version routed by | Run 132 dispatch | Persists marker? |
|----------------------------------------------|---------------------------|------------------|------------------|
| `--p2p-trust-bundle-reload-check <FILE>`     | sidecar file content      | v1 → Run 123; v2 → Run 132 | **NO** (validation-only) |
| `--p2p-trust-bundle-peer-candidate-check <FILE>` | sidecar file content  | v1 → Run 123; v2 → Run 132 | **NO** (validation-only) |

Operators continue to pass the same `--p2p-trust-bundle-ratification <FILE>` flag; the binary detects v1 vs v2 from the file's `schema_version` / `version` field via the Run 132 versioned loader and dispatches accordingly. v1 sidecars take the unchanged Run 123 path. v2 sidecars take the new Run 132 v2 path and emit one of the typed accept reasons listed in the Run 132 section above, or a typed refusal followed by `Run 132: VERDICT=invalid` and non-zero exit.

**DevNet operator-opt-in note for pure-v2 sidecars.** Because the Run 105 v1 enforcer is reached first by the reload-check pipeline and a pure-v2 sidecar carries no v1 fields, DevNet/TestNet operators MUST add `--p2p-trust-bundle-allow-unratified-testnet-devnet` alongside `--p2p-trust-bundle-ratification-enforcement-enabled` when supplying a v2-only sidecar. This is the same DevNet/TestNet escape hatch documented in the Run 105 / Run 107 sections; MainNet does not honor it (MainNet always invokes the v1 enforcer with Strict policy).

**Release-binary evidence**

The harness `scripts/devnet/run_133_v2_validation_only_release_binary.sh` runs a 16-scenario matrix against `target/release/qbind-node`, archived under `docs/devnet/run_133_v2_validation_only_release_binary/`:

* **v1 regression (1 scenario):** v1 valid sidecar with no marker → Run 123 first-seen pass, `VERDICT=valid`.
* **v2 acceptance (6 scenarios):** v2 first-seen (no marker), v2 idempotent (same seq same digest), v2 ratify upgrade 1→2, v2 rotate upgrade 1→2, v2 revoke upgrade 1→2, v2-after-v1 migration candidate (v1 marker + v2 ratify@seq=2).
* **v2 rejection (7 scenarios):** same-sequence different-digest equivocation, lower sequence (1 vs marker 2), seq=0 (malformed), tampered signature, wrong chain, wrong environment, wrong genesis.
* **Peer-candidate-check spot-check (2 scenarios):** v2 first-seen pass, v2 bad-signature refusal.

All 16 scenarios produce the expected exit code, the expected typed accept/refusal reason verbatim on stderr, and satisfy the four-part non-mutation invariant (no `pqc_authority_state.json` created/rewritten/left as `.tmp`, no `pqc_trust_bundle_sequence.json` written, no apply / propagate / session-eviction / SIGHUP / KMS marker observed). Per-scenario stderr logs and exit codes are archived under `docs/devnet/run_133_v2_validation_only_release_binary/logs/`.

**Build hygiene**

Run 133 also fixes three pre-existing release-build warnings on `qbind-node` so that `cargo build --release -p qbind-node --bin qbind-node` is warning-free: the deprecated `bincode::config()` call is replaced by `bincode::options()` at two sites in `crates/qbind-node/src/binary_consensus_loop.rs` (wire-compatible — the binary-consensus framing tests pass unchanged), and the release-build unused `worker_id` parameter in `crates/qbind-node/src/verify_pool.rs::worker_loop` is gated by `cfg(not(debug_assertions))` so the debug-build self-check is preserved.

**Operator change required: none.** Run 133 is evidence-only; the production runbook for v2 sidecars on validation-only surfaces is unchanged from Run 132. Mutating-surface v2 wiring (startup `--p2p-trust-bundle`, process-start reload-apply, SIGHUP live reload) remains v1-only until a future Run designs and tests v2 persistence atomicity, v1→v2 marker migration, and sequence-after-marker ordering. Operators with a v2 sidecar today MUST continue to apply trust via a v1 sidecar on any mutating surface; the v2 sidecar is currently only accepted on the two validation-only surfaces listed above.

## Run 134 — v2 ratification wired into the process-start reload-apply mutating surface

Run 134 narrows the "operators with a v2 sidecar must use v1 on mutating surfaces" statement above: as of Run 134, **the process-start reload-apply mutating surface** (`--p2p-trust-bundle-reload-apply-path` + `--p2p-trust-bundle-reload-apply-enabled`) now accepts v2 sidecars and persists the v2 authority marker after `commit_sequence`. SIGHUP live reload, snapshot/restore, and startup `--p2p-trust-bundle` remain v1-only until a follow-on run lands their v2 wiring on the same pattern.

### What Run 134 wired

- v2 atomic persister `persist_authority_state_v2_atomic` in `crates/qbind-node/src/pqc_authority_state.rs` (same `tmp + rename + parent-dir fsync` durability as the v1 persister; same on-disk versioned discriminator so `load_authority_state_versioned` reads it back as V2).
- v2 mutating-surface helpers in `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`:
  - `MutatingSurfaceMarkerV2Error` (10 typed-failure variants).
  - `MarkerAcceptanceV2Inputs` / `MarkerAcceptDecisionV2` / `MarkerAcceptKindV2` (`FirstV2Write` / `Idempotent` / `UpgradeV2{prev,new}` / `V2AfterV1Migration`).
  - `decide_marker_acceptance_v2(...)` — composes Run 131 derivation + load + `compare_authority_marker_v2`; performs **no** disk writes.
  - `persist_accepted_v2_marker_after_commit_boundary(...)` — idempotent no-op when `should_persist=false`; the only v2-write path in Run 134; strictly post-`commit_sequence`.
- Binary preflight `preflight_run_134_v2_marker_decision(...)` that runs the Run 130 v2 verifier on the operator-supplied v2 sidecar carried in `Run105ReloadCheckContextData::ratification_v2`, then calls `decide_marker_acceptance_v2`.
- Reload-apply dispatch: when `ctx_data.ratification_v2.is_some()`, the binary takes the v2 path (preflight → Run 070 apply pipeline without v1 ratification context → v2 persist after commit). Otherwise the Run 119 v1 path is preserved bit-for-bit.

### Operator-visible behavior on the reload-apply path

| Sidecar version | Dispatch | Marker persisted? |
|---|---|---|
| v1 (or no sidecar with `AllowLegacyUnratified`) | Run 119 v1 path (unchanged) | v1 marker after `commit_sequence` |
| v2 | Run 134 v2 path (NEW) | v2 marker after `commit_sequence` |

Run 134 stderr markers an operator can grep for:

- `[run-134] reload-apply v2 ratification path SELECTED` — v2 dispatch chosen.
- `[run-134] v2 authority-marker persisted at <PATH> (<kind>; candidate latest_authority_domain_sequence=<N>)` — v2 marker written after commit.
- `[run-134] v2 authority-marker unchanged at <PATH> (idempotent; no rewrite)` — re-apply of identical v2 candidate.
- `[run-134] FATAL: reload-apply refused by v2 authority-marker preflight: <reason>` — fail-closed pre-mutation refusal.
- `[run-134] FATAL: v2 authority-marker persist failure AFTER successful apply: <reason>` — stale-by-one crash-window FATAL.

### Run 134 explicit non-changes

- CLI flag surface is unchanged. The same `--p2p-trust-bundle-reload-apply-path` / `--p2p-trust-bundle-reload-apply-enabled` flags accept v1 or v2 sidecars; dispatch is by file content.
- v1 reload-apply behavior is bit-for-bit unchanged (Run 119 path).
- /metrics families are unchanged (the binary exits with `0`/`1` after this subcommand; `/metrics` is never bound).
- MainNet `--data-dir` precondition is unchanged.
- No SIGHUP, snapshot/restore, peer-driven live apply, or startup `--p2p-trust-bundle` v2 wiring (all deferred).
- No signing-key rotation / revocation lifecycle (deferred).
- No KMS/HSM, no MainNet governance artifact verification (deferred).
- No release-binary v2 mutating-surface evidence harness (deferred to a follow-on run mirroring Run 133's shape).

### Status table snapshot

| Surface                                            | v1 status (today) | v2 status (today)                |
|----------------------------------------------------|-------------------|----------------------------------|
| `--p2p-trust-bundle-reload-check`                  | Run 123 (wired)   | Run 132 (wired, validation-only) |
| `--p2p-trust-bundle-peer-candidate-check`          | Run 123 (wired)   | Run 132 (wired, validation-only) |
| `--p2p-trust-bundle-reload-apply-path` (this run)  | Run 119 (wired)   | **Run 134 (wired, mutating)**    |
| `--p2p-trust-bundle` startup acceptance            | Run 120 (wired)   | deferred                         |
| SIGHUP live-reload (`--p2p-trust-bundle-live-reload-*`) | Run 121 (wired) | deferred                       |
| Snapshot/restore                                   | Run 124 (wired)   | deferred                         |

### Run 135 operator note — release-binary evidence for v2 reload-apply

Run 135 added **release-binary evidence** for the Run 134 wiring of v2
ratification into the process-start reload-apply mutating surface. It
did not change any production runtime code or CLI flag. The behaviour
operators should observe on `target/release/qbind-node` matches the
Run 134 description above and is now captured end-to-end by
`scripts/devnet/run_135_v2_reload_apply_release_binary.sh` and archived
under `docs/devnet/run_135_v2_reload_apply_release_binary/`.

For operators running a v2 reload-apply on a real release binary, the
expected stderr sequence on an accepted v2 ratify is exactly:

```
[run-112] reload-apply ratification gate INVOKED (policy=..., env=Devnet).
[run-134] reload-apply v2 ratification path SELECTED (v2 sidecar present; v1 ratification context skipped).
[binary] Run 070: trust-bundle candidate APPLIED live ... sequence_commit=ok
[binary] Run 073: VERDICT=applied (... sequence committed).
[run-134] v2 authority-marker persisted at <data_dir>/pqc_authority_state.json (<kind>; candidate latest_authority_domain_sequence=<N>).
```

On an idempotent v2 ratify the last line reads `v2 authority-marker
unchanged ... (idempotent; no rewrite)` instead.

On a v2 refusal (rollback, equivocation, bad signature, wrong
environment, etc.) the expected stderr line is:

```
[run-134] FATAL: reload-apply refused by v2 authority-marker preflight: <typed reason>. ...
   No live trust apply, no sequence write, no session eviction, no metrics mutation, no marker write.
   See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md.
```

and the process exits with code `1`. Operators can confirm
fail-closure by verifying that `pqc_authority_state.json` is
byte-identical pre/post (`cmp -s` succeeds when a marker was
pre-seeded; the file does not appear when no marker was pre-seeded)
and that no `pqc_trust_bundle_sequence.json` was written.

If a v2 persist failure occurs AFTER `commit_sequence` (the rare
mid-write FS failure on the v2 marker), the binary surfaces:

```
[run-134] FATAL: v2 authority-marker persist failure AFTER successful apply: ...
   The trust-bundle sequence already committed; the on-disk v2 authority
   marker is stale-by-one and will be re-derived on the next accepted
   mutation (Run 118 §D / Run 131 crash-window rule).
```

In this case the operator may restart the binary; the next accepted
v2 ratification re-persists the v2 marker via Run 134
`UpgradeV2{previous_sequence=stale,new_sequence=current}` and the
stale marker is replaced after the next `commit_sequence`. **Do
not** attempt to hand-edit `pqc_authority_state.json` — the Run 134
v2 atomic persister is the only supported write path.

Run 135 also confirmed (across 9 scenarios on the release binary)
that the v1 path is preserved bit-for-bit when no v2 sidecar is
supplied. Operators currently running v1 ratification sidecars
(`schema_version=1`) need not change anything; the Run 119 v1 path
continues to fire and the on-disk marker remains v1
(`record_version=1`).

Run 135 confirmed deferrals (no operator-visible change yet):

- SIGHUP-driven live trust-bundle reload-apply v2 wiring.
- `--p2p-trust-bundle` startup-acceptance v2 wiring.
- Snapshot/restore v2 marker wiring.
- Peer-driven live apply v2.
- Live inbound `0x05` v2 wiring.
- Signing-key rotation/revocation lifecycle plumbing beyond verifier-
  level enforcement.
- KMS/HSM custody.
- MainNet governance artifact verification.

For these surfaces, the v1 enforcement paths (Run 074 / Run 120 /
Run 124 / Run 105 / Run 088) remain the authoritative behaviour
until a follow-on run lands their v2 wiring.

## Run 136 — v2 ratification wired into the startup `--p2p-trust-bundle` mutating surface

Run 136 narrows the "v2 wiring remains open for startup `--p2p-trust-bundle`"
statement above: as of Run 136, **the startup `--p2p-trust-bundle` mutating
surface** (the Run 105/106 startup gate + Run 120 marker preflight + Run 055
sequence write block that runs when the operator passes `--p2p-trust-bundle`
on the `qbind-node` binary) now accepts v2 sidecars and persists the v2
authority marker after `commit_sequence`. SIGHUP live reload and snapshot/
restore remain v1-only until follow-on runs land their v2 wiring on the
same pattern.

### What Run 136 wired

- A new binary preflight
  `preflight_run_136_v2_marker_decision_for_startup` in
  `crates/qbind-node/src/main.rs` that composes the Run 130 v2 verifier
  with the Run 134 `decide_marker_acceptance_v2` helper. The audit-only
  `last_update_source` field of the resulting persisted record is
  tagged `StartupLoad` (the startup-surface analogue of Run 134's
  `ReloadApply`).
- A versioned-sidecar dispatcher inside the existing startup gate body:
  when `Run105ReloadCheckContextData::ratification_v2.is_some()`, the
  binary SKIPS the v1-only `apply_run_105_ratification_gate_at_startup`
  (it cannot parse v2 sidecars) and runs the Run 136 preflight in its
  place. When the sidecar is v1 or absent, the existing v1 path (Run
  105 gate + Run 120 preflight) runs bit-for-bit unchanged.
- A v2 post-commit persist block parallel to the existing Run 120 v1
  persist, calling `persist_accepted_v2_marker_after_commit_boundary`
  strictly AFTER the Run 055 `check_and_update_sequence` write
  succeeds. The two persist blocks are mutually exclusive by
  construction; exactly one fires per startup.

Operator-visible ordering on the v2 path:

| Step | Effect |
|------|--------|
| `[run-106] startup ratification gate INVOKED ...` | gate body entered |
| `[run-136] startup --p2p-trust-bundle v2 ratification path SELECTED ...` | v2 dispatch chosen; v1 gate skipped |
| Run 055 `check_and_update_sequence` | sequence file written (or rejected) |
| `[run-136] v2 authority-marker persisted at <data_dir>/pqc_authority_state.json (...; candidate latest_authority_domain_sequence=N)` | v2 marker persist, **strictly after** sequence commit |

On reject the binary emits one operator-actionable
`[run-136] FATAL: startup --p2p-trust-bundle refused by v2
authority-marker preflight: ...` line and exits non-zero, with no
Run 055 sequence write, no bundle-root merge into the live PQC trust
set, no live trust mutation, no P2P startup, and no marker write. On
persist-after-commit failure the binary emits
`[run-136] FATAL: v2 authority-marker persist failure AFTER successful
Run 055 sequence write at startup: ...` and exits non-zero; the
trust-bundle sequence has already advanced and the on-disk v2 marker
is stale-by-one (safely replayable as `UpgradeV2` on the next
accepted mutation per Run 118 §D / Run 131). Operators MUST investigate
that scenario via the Run 131 / Run 134 stale-by-one recovery guidance
already captured above; do not hand-edit the marker file.

### Run 136 explicit non-changes

- SIGHUP live reload (Run 074 / Run 121) — still v1-only.
- Snapshot/restore (Run 088 / Run 124) — still v1-only.
- Run 132 validation-only surfaces (reload-check, peer-candidate-check)
  — unchanged; only the mutating startup surface is touched.
- Run 134 reload-apply v2 wiring — unchanged; Run 136 reuses the same
  helpers with the `StartupLoad` audit tag and a separate dispatcher.
- Run 055 trust-bundle sequence persistence — unchanged.
- Run 105/106 v1 startup gate — unchanged structurally; it still runs
  verbatim for v1 sidecars and the no-sidecar legacy DevNet path.
- CLI flag surface — unchanged.
- /metrics families — unchanged.
- Signing-key rotation/revocation lifecycle, peer-driven live apply,
  KMS/HSM custody, MainNet governance artifact verification — still
  deferred.

### Mutating-surface v2 coverage matrix after Run 136

| Mutating surface | v1 path | v2 path |
|------------------|---------|---------|
| `--p2p-trust-bundle` (startup, this run) | Run 105/106 + Run 120 | **Run 136 (wired)** |
| `--p2p-trust-bundle-reload-apply-path`   | Run 112/119           | Run 134 (wired)      |
| SIGHUP live reload                        | Run 074/121           | OPEN — deferred       |
| snapshot/restore                          | Run 088/124           | OPEN — deferred       |

Release-binary evidence for the Run 136 wiring is **captured by
Run 137** in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_137.md` and
`scripts/devnet/run_137_v2_startup_trust_bundle_release_binary.sh`,
mirroring Run 133's / Run 135's `scripts/devnet/run_*_release_binary.sh`
shape on an 11-scenario matrix (A1 v2-first-write, A2 v2-after-v1
migration, A3 idempotent, A4 higher-sequence upgrade, R1 lower-sequence
refused, R2 same-sequence different-digest refused, R3a bad signature,
R3b wrong environment, R4 wrong chain, R5 wrong genesis, V1 v1
regression). The acceptance scenarios bound the still-running release
binary with `timeout --signal=TERM --kill-after=5s` after observing the
`[run-136] v2 authority-marker persisted ... (... candidate
latest_authority_domain_sequence=<N>)` (or `... unchanged ...
(idempotent; no rewrite)`) line strictly after the corresponding
`[binary] Run 055: trust-bundle sequence persistence` line; the
rejection scenarios exit `rc=1` BEFORE `[binary] P2P transport up`
appears and BEFORE any sequence-file or `.tmp` marker sibling is
written. Operators running DevNet preview builds today can grep for
`[run-136]` to identify the v2 startup path and `[run-120]` for the v1
startup path; the two are mutually exclusive per startup.

## Run 137 — release-binary evidence for the Run 136 startup `--p2p-trust-bundle` v2 wiring

Run 137 is **release-binary evidence only**; it changes no production
runtime source, no CLI flag, no log line, no metric, and no wire format.
The harness
`scripts/devnet/run_137_v2_startup_trust_bundle_release_binary.sh`
exercises an 11-scenario matrix on DevNet against `target/release/
qbind-node` using the mutating startup block (`--network-mode p2p
--enable-p2p --p2p-listen-addr 127.0.0.1:<port> --p2p-trust-bundle
<bundle> --p2p-trust-bundle-signing-key <ratified-spec>
--p2p-trust-bundle-ratification <sidecar>
--p2p-trust-bundle-ratification-enforcement-enabled --data-dir
<data_dir>`) and the Run 133 fixture helper to mint ephemeral v1 and v2
sidecars on DevNet's `(env, chain_id, genesis_hash, authority_root_
fingerprint)` trust domain. Every accepted v2 scenario proves the
post-`commit_sequence` ordering (Run 055 sequence persistence line
strictly precedes `[run-136] v2 authority-marker persisted` /
`unchanged`), and every rejected scenario proves the fail-closed
boundary (no sequence file, no `.tmp` marker sibling, pre-seeded marker
bytes byte-identical post-run, no `[binary] P2P transport up`). The
Run 134 §C.3 / Run 135 R4 / Run 136 §A.8 corner case (apply failure
between preflight and the Run 055 commit boundary) is not feasible to
trigger on a release binary using operator-supplied flag inputs alone
and remains test-only. After Run 137 the mutating-surface v2 coverage
matrix is updated to show **Run 136 wired + Run 137 release-binary-
evidenced** on the startup `--p2p-trust-bundle` row; the SIGHUP and
snapshot/restore rows remain OPEN.
## Run 138 — SIGHUP live-reload v2 ratification + v2 authority-marker support

**Scope**: Source/test wiring only. Release-binary SIGHUP v2 evidence is
deferred to Run 139.

**What changed**: The Run 074 SIGHUP live-reload controller now supports
the v2 bundle-signing-key ratification schema (`schema_version=2`) and
the v2 authority-marker discipline. Selection is automatic, per-trigger,
and based on the operator-supplied sidecar file:

* The controller re-reads `ratification_sidecar_path` on every SIGHUP
  (unchanged) and peeks the schema discriminator via the existing
  `load_versioned_ratification_from_path` helper.
* If the sidecar declares `schema_version=2`:
  1. The Run 130 v2 verifier runs **before** any live mutation. A
     verifier failure surfaces as `MarkerRejectedV2` — no live mutation,
     no eviction, no sequence write, no marker write.
  2. The Run 131 v2 marker decision runs **before** any live mutation.
     A pre-mutation refusal (rollback / same-seq-different-digest /
     wrong-domain / corrupt persisted marker) surfaces as
     `MarkerRejectedV2` — same pre-mutation invariants.
  3. The Run 070 apply pipeline runs unchanged.
  4. On `Ok(applied)`, the v2 marker is persisted strictly AFTER
     `sequence_commit=ok` via the same
     `persist_accepted_v2_marker_after_commit_boundary` helper Run 134
     and Run 136 use. **A v2 marker-persist failure after successful
     commit is FATAL** — the binary's SIGHUP signal-handler task
     initiates graceful shutdown, matching the Run 121 v1 fatal shape.
* If the sidecar declares `schema_version=1` (or no sidecar / no
  ratification config / no marker config), behaviour is **bit-for-bit
  identical** to the Run 121 / Run 074 v1 path. Operators do not need
  to change anything.

**Operator opt-in (unchanged from Run 121)**:

* `--p2p-trust-bundle-ratification-enforcement-enabled true` (or the
  equivalent `LiveReloadConfig.ratification = Some(_)`).
* `--p2p-trust-bundle-ratification-sidecar-path /path/to/sidecar.json`.
* `--authority-state-file /path/to/pqc_authority_state.json` (or the
  equivalent `LiveReloadConfig.authority_marker = Some(_)`).

To switch a deployment from v1 to v2 SIGHUP:

1. Generate a `schema_version=2` ratification object signed by the
   genesis-bound authority key.
2. Atomically replace the sidecar file at
   `--p2p-trust-bundle-ratification-sidecar-path`.
3. Send `kill -HUP <qbind-node-pid>` to the running daemon (no flag
   changes required).
4. The next SIGHUP will dispatch through the Run 138 v2 path. If the
   on-disk marker is a Run 121 v1 record, it will be **migrated to v2
   in place** strictly AFTER the Run 070 sequence commit succeeds
   (Run 138 A4 scenario).

**Failure modes**:

* `MarkerRejectedV2(_)` — pre-mutation refusal. No live mutation, no
  sequence write, no marker write. The binary continues running and
  serves the existing live trust state. Operator action: fix the
  sidecar / authority-state file and SIGHUP again.
* `MarkerPersistFailureAfterCommitV2 { applied, marker_error }` — the
  apply pipeline succeeded (live trust state is advanced, the
  sequence file is written, peers have been evicted), but the
  authority-state file could not be written (e.g. disk full,
  read-only FS, EACCES). **This is fatal** — the SIGHUP task
  initiates graceful shutdown. The next process start will see a
  stale-by-one marker which will be reconciled as `UpgradeV2` (the
  Run 131 crash-window discipline). Operator action: fix the
  `--authority-state-file` parent directory permissions / disk
  capacity, then restart.

**What did NOT change**:

* No new CLI flags.
* No new `/metrics` counters or labels.
* No change to the trust-bundle / peer-candidate / ratification wire
  format.
* No change to the on-disk format of the v1 authority-state marker.
* No change to v1 SIGHUP behaviour when the sidecar is v1 or absent.

## Run 139 — SIGHUP live-reload v2 release-binary evidence harness

Run 139 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_139.md`) is the
release-binary closure of the Run 138 source/test wiring. Operators
can re-run the evidence harness against any built
`target/release/qbind-node` to re-attest the SIGHUP v2 mutating-
surface invariants on their own build:

```
bash scripts/devnet/run_139_sighup_v2_live_reload_release_binary.sh \
     docs/devnet/run_139_sighup_v2_live_reload_release_binary
```

The harness builds the release binary plus the Run 133 fixture-
helper release example, mints ephemeral DevNet fixtures, drives
eleven SIGHUP scenarios (A1 first accepted v2 SIGHUP, A2
idempotent re-trigger, A3 higher-sequence upgrade, A4 v1→v2
migration, R1 lower-sequence refusal, R2 same-sequence different-
digest refusal, R3 bad-signature refusal, R4 wrong-domain refusal,
R6 v1 SIGHUP regression, R7 no-sidecar legacy DevNet regression,
R8 repeated SIGHUP serialization) against a long-running daemon
with a real `kill -HUP <pid>`, captures stdout / stderr / exit
codes / PIDs / signal timestamps / pre- and post-trigger SHA-256
hashes of the on-disk `pqc_authority_state.json` and
`pqc_trust_bundle_sequence.json`, and asserts the per-class
invariants in-line. R5 (post-commit marker-persist failure) is
release-binary-infeasible and is documented as partial-positive
in the evidence MD with citations back to the Run 138 source/test
coverage. Run 139 introduces no production runtime source
changes, no test changes, no CLI flag changes, no metric changes,
and no wire-format / schema changes.

## Run 140 — snapshot/restore v2 authority-marker parity (source/test only)

Run 140 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_140.md`) wires
source/test-level parity for the v2 authority anti-rollback marker on
the snapshot/restore surface, on top of the existing versioned marker
primitives (Run 130 `compare_authority_marker_v2`, Run 131
`load_authority_state_versioned` / `persist_authority_state_v2_atomic`)
and the existing Run 117 / 124 snapshot/restore authority-check
surface. The `StateSnapshotMeta` carrier in `qbind-ledger` is extended
additively with `authority_state_v2: Option<AuthorityStateSnapshotMetaV2>`
(JSON key omitted when `None`, so pre-Run-140 snapshots round-trip
byte-identically). `qbind-node` gains a pure
`verify_snapshot_authority_state_for_restore_v2(...)` entry point that
routes the accept/reject decision through `compare_authority_marker_v2`
and is dispatched from
`restore_from_snapshot_with_authority_marker_check` whenever the
snapshot meta carries a v2 block; otherwise the Run 124 v1 path runs
verbatim and v1 restore behavior is preserved.

**Restore-surface dispatch outcomes operators may see on the v2 path**
(typed `SnapshotRestoreAuthorityCheckV2Outcome`):

* **Accept** — `NoMarkerEitherSide`, `AcceptSnapshotV2MarkerNoLocal`,
  `AcceptMatchingV2Marker`, `AcceptHigherV2Sequence{
  persisted_sequence, candidate_sequence }`,
  `AcceptV2AfterV1Migration`.
* **Reject (fail-closed)** — `RejectMissingSnapshotMarker`,
  `RejectLocalMarkerCorrupt(_)`,
  `RejectLocalMarkerWrongDomain`, `RejectSnapshotMarkerWrongDomain`,
  `RejectAmbiguousSnapshotMarkers` (snapshot advertises both `v1` and
  `v2` blocks — refused without consulting either),
  `RejectV2Comparison(_)` (wraps the Run 130 comparison outcome:
  lower sequence, same-sequence-different-digest, wrong authority
  root, wrong active key, sequence overflow, etc.).

**Fail-closed invariants enforced by Run 140 (source/test):**

* The restore-surface check is **pure** with respect to disk: accept
  and reject paths both preserve the local marker file bytes
  verbatim. The on-disk state under `<data_dir>` is byte-identical to
  its pre-restore form on every reject path (authority check runs
  before any state checkpoint copy or `RESTORED_FROM_SNAPSHOT.json`
  audit-marker write).
* A snapshot that advertises both `authority_state` and
  `authority_state_v2` blocks is **always refused without consulting
  either block** — a single snapshot cannot advertise two
  simultaneously valid authority markers.
* A snapshot with no authority block at all against a local v2 marker
  is **refused** by the dispatched v1 path (Run 124 behavior preserved
  verbatim). A v2 marker is never fabricated when the snapshot has no
  marker.
* The local-marker domain check (`environment`, `chain_id`,
  `genesis_hash`) runs **before** any snapshot inspection on the v2
  path, so the operator log line is precise about the source of a
  reject when both sides are wrong.
* The restore surface never invokes `persist_authority_state_v2_atomic`
  — the only v2 marker writer remains the existing Run 134 / 136 / 138
  surfaces.

**Scope notice:** Run 140 is source/test wiring only. Release-binary
snapshot/restore v2 evidence is **deferred to Run 141**. Live inbound
`0x05` v2 wiring, peer-driven live apply, signing-key
rotation/revocation lifecycle, KMS / HSM custody, MainNet governance
attestation, full C4 closure, and C5 closure all remain out of scope.
## Run 141 — release-binary evidence for snapshot/restore v2 authority-marker parity (evidence only)

Run 141 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_141.md`) produces the
release-binary evidence that Run 140 explicitly deferred for the
snapshot/restore v2 authority-marker surface. **No production runtime
source code is modified.** The new artifacts are:

* `crates/qbind-node/examples/run_141_v2_snapshot_restore_fixture_helper.rs`
  (`cargo --example` only) — mints an ephemeral DevNet genesis at the
  canonical Run 101 verification path, 11 ephemeral snapshot
  directories covering every Run 140 acceptance/rejection variant
  (A1–A4 + R1–R9 + R10–R11), and three local marker fixtures (matching
  v2, matching v1 with `authority_root_fingerprint` aligned for the
  Run 140 `V2AfterV1ExplicitMigrationAllowed` path, and a deliberately
  corrupt blob for the `RejectLocalMarkerCorrupt` fail-closed path).
  The helper is opt-in via `cargo --example`; it is **not** linked
  into the `qbind-node` release binary itself.
* `scripts/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary.sh`
  — builds the real release `qbind-node` and the fixture helper,
  records build provenance (`sha256`, `build-id`, `git_commit`,
  `rustc`, `cargo`), and for each of the 11 task-mandated scenarios
  invokes the real CLI surface
  (`qbind-node --env devnet --data-dir <D> --genesis-path <G>
  --expect-genesis-hash <H> --restore-from-snapshot <S>`), captures
  stdout/stderr/exit-code, computes pre/post sha256 of the local
  marker file and pre/post inventories of the data directory, asserts
  the strict ordering of the dispatch label vs the success log line on
  every accept, asserts the expected outcome substring on every reject,
  and greps the full corpus for an explicit out-of-scope denylist.
* `docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/`
  — the committed captured artifacts: `summary.txt`, per-scenario
  stdout/stderr/exit-code logs, pre/post local-marker hashes, pre/post
  data-directory inventories, snapshot `meta.json`s, snapshot state
  inventories, in-scope and out-of-scope grep summaries.

**Operational outcomes captured for the release binary (see the table
in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_141.md`):**

* v2-dispatch accepts (A1 empty-data-dir + v2 snapshot, A2 matching
  local v2 + v2 snapshot, A3 higher v2 sequence + v2 snapshot, A4
  matching local v1 + v2 snapshot via the explicit migration path)
  all reach `[restore] OK: restored from snapshot height=…` strictly
  **after** logging `[restore] Run 140 v2 authority-marker check: …`.
* v2-dispatch rejects (R2 lower sequence, R3 same sequence different
  digest, R4 wrong `genesis_hash_hex`, R5 wrong `environment`, R6 wrong
  `chain_id_hex`, R7 corrupt local marker, R8 ambiguous snapshot
  carrying both v1 and v2 blocks, R9 different `authority_root_fingerprint`)
  all log `[restore] FATAL: refused by Run 140 v2 authority-marker
  check: …` with the expected outcome substring, exit `1`, and
  preserve the local marker bytes verbatim.
* v1/legacy regression scenarios (R1 legacy snapshot vs local v2
  marker → falls through to Run 124 v1 path and fails closed because
  the v1 verifier cannot parse the v2-schema marker; R10 matching v1
  snapshot vs matching v1 local marker → Run 124 v1 path accepts; R11
  legacy snapshot vs empty data dir → Run 124 v1 path accepts on the
  no-marker-either-side branch) all behave as before. No v1 regression.
* The restore surface is verified to be pure with respect to the local
  marker file: `sha256` of the local marker is byte-identical before
  and after invocation in every scenario where a local marker was
  seeded.
* The on-disk v1 → v2 marker swap (A4) and the higher-sequence v2
  persistence (A3) are **explicitly NOT** performed by the restore
  surface in Run 141 — both mutations remain the responsibility of
  the existing Run 134 reload-apply path on next process start, which
  is not exercised in Run 141.

**Operator implications:** when restoring from a v2-bearing snapshot
on a node that already carries a v1 local marker (A4 case) or a v2
local marker with a strictly lower sequence (A3 case), the restore
itself succeeds without rewriting the local marker. The on-disk
v1→v2 swap and the higher-sequence persistence will occur on the
subsequent process start via the existing Run 134 reload-apply path
(see the Run 134/135 sections). Operators must therefore **not** treat
A3/A4 acceptance as evidence that the local marker has been advanced.

**Scope notice:** Run 141 is release-binary evidence only for the
snapshot/restore v2 surface. Live inbound `0x05` v2 PQC trust-bundle
frame validation, peer-driven live trust-bundle apply, signing-key
rotation/revocation lifecycle, KMS/HSM authority-key custody, MainNet
governance attestation, validator-set rotation, the on-disk v1→v2
marker swap surface, the higher-sequence v2 persistence surface, full
C4 closure, and C5 closure all remain out of scope.

## Run 142 — live inbound `0x05` v2 validation-only (source/test only)

Run 142 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_142.md`) wires v2
ratification + v2 authority-marker validation into the **live inbound
P2P peer-candidate `0x05` validation-only receive path** so a running
node that receives a peer-candidate `0x05` frame validates v2 material
with the same Run 130 verifier + Run 132 marker-compare discipline that
the local peer-candidate-check binary surface (Runs 132/133) already
uses.

The wiring is additive on the `LiveRatificationConfig` already installed
in the dispatcher by Run 109/123: an optional `ratification_v2:
Option<BundleSigningRatificationV2>` slot is plumbed from
`Run105ReloadCheckContextData::ratification_v2` (the existing Run 132 v2
sidecar field) through `main.rs::run_p2p_node` into the live `0x05`
dispatcher. The versioned sidecar loader
(`load_versioned_ratification_from_path`) produces exactly one of v1 or
v2; the dispatcher routes accordingly. When **both** slots are
simultaneously `Some` (ambiguous v1+v2 authority material), the
dispatcher fails closed **before** the inner validator runs and
suppresses any rebroadcast.

**Operator behaviour:**

* Operators who supply a v2 ratification sidecar via
  `--p2p-trust-bundle-ratification <path>` get **live inbound `0x05` v2
  validation** automatically. The existing Run 106 ratification gate
  policy decides whether the gate is invoked
  (MainNet/TestNet default-strict; DevNet only with operator opt-in).
* When the gate is invoked **and** `ratification_v2` is present, every
  inbound `0x05` peer-candidate frame whose inner validation succeeds
  is then run through the Run 130 v2 verifier and the Run 132
  `verify_marker_for_validation_only_v2` helper, exactly as the local
  Run 132 peer-candidate-check binary path does.
* When `--data-dir` is unset, the v2 verifier still runs (no marker
  needed for the verifier) and on-disk marker compare is skipped with
  the log line `[run-142] live 0x05 v2 verifier passed; on-disk v2
  marker compare skipped (no --data-dir configured)`. This matches the
  Run 132 `main.rs` behaviour bit-for-bit.

**Fail-closed invariants enforced by Run 142 (source/test):**

* Ambiguous v1+v2 authority material → frame rejected before inner
  validator runs; no marker write; no propagation.
* Bad-signature v2 ratification → Run 130 verifier failure;
  `[run-142] live 0x05 v2 verifier rejected sidecar:` log; no mutation.
* Wrong-environment / wrong-chain / wrong-genesis v2 ratification →
  Run 130 verifier domain rejection; no mutation.
* Lower-sequence / same-sequence-different-digest / v1-after-v2
  downgrade v2 candidate → Run 132 marker-compare rejection;
  `[run-142] live 0x05 v2 authority-marker conflict rejected:` log; no
  marker write; no propagation.
* Corrupt local `pqc_authority_state.json` → fail-closed; corrupt bytes
  preserved verbatim; no mutation.
* Validated v2 candidate → `[run-142] live 0x05 v2 authority-marker
  check passed:` log; **no marker write**, no sequence write, no live
  trust mutation, no session eviction, no reload-apply, no SIGHUP. The
  candidate is eligible for Run 088 propagation only if propagation was
  already enabled by operator configuration; invalid v2 candidates are
  never rebroadcast.

**v1 / legacy regression preservation:**

* When the operator-supplied sidecar is v1, the dispatcher takes the
  existing Run 109/123 v1 path verbatim. The new v2 helper no-ops
  (because `ratification_v2.is_none()`) and the existing Run 123 v1
  marker check runs as before.
* When no sidecar is supplied **and** the ratification gate is
  `Skip(DevnetNoOperatorOptIn)`, the pre-Run-109 legacy unguarded path
  is preserved; no v2 helper fires; no marker is fabricated.

**Scope notice:** Run 142 is source/test wiring only. Release-binary
live inbound `0x05` v2 evidence is **deferred to Run 143**.
Peer-driven live trust-bundle apply, signing-key rotation/revocation
lifecycle, KMS/HSM authority-key custody, MainNet governance
attestation, validator-set rotation, full C4 closure, and C5 closure
all remain out of scope.
## Run 143 — release-binary evidence for live inbound `0x05` v2 validation-only

Run 143 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md`) produces the
release-binary evidence that Run 142 deferred for the **live inbound
P2P peer-candidate `0x05` v2 validation-only receive path**, and
nothing else. **No production runtime source is modified, no CLI flag
is added or renamed, no metric family is changed, no wire / on-disk /
sidecar / marker schema is changed, and no new fixture helper is
introduced** — Run 143 reuses Run 133's
`run_133_v2_validation_only_fixture_helper` verbatim.

A new release-binary harness
`scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh`
builds the real release `qbind-node` and the DevNet helper binaries,
records build provenance (`sha256`, ELF `BuildID`, `git_commit`,
`rustc --version`, `cargo --version`), and drives the N=3 DevNet
topology (V0 publisher, V1 v2 validation-only receiver, V2 second
receiver / propagation observer) used by Run 110 — same mutual-auth
Required, same signed DevNet trust bundle, same ML-KEM-768 KEM,
ML-DSA-44 signing, ChaCha20-Poly1305 AEAD, Run 033 active=true
keystores, no `DummySig` / `DummyKem` / `DummyAead` in any active
path.

**Operator behaviour validated by Run 143 on real release binaries:**

* When the operator supplies a **v2** ratification sidecar via
  `--p2p-trust-bundle-ratification` and the Run 106 gate decision
  INVOKES the dispatcher, every inbound `0x05` peer-candidate frame is
  routed through the Run 130 v2 verifier and (when `--data-dir` is
  configured) the Run 132 `verify_marker_for_validation_only_v2`
  helper.
* When the operator supplies a **v1** sidecar, the live `0x05` path
  takes the existing Run 109/123 v1 dispatcher verbatim; no v2 path is
  selected; no v2 marker is fabricated.
* When the operator supplies **no** sidecar on DevNet, the Run 106
  gate logs `SKIPPED (policy=devnet-no-operator-opt-in)` and the
  pre-Run-109 unguarded path runs; no v2 marker is fabricated.
* When the operator-supplied sidecar simultaneously carries v1 **and**
  v2 envelope material (an ambiguous document), the versioned sidecar
  loader refuses at preflight — the binary exits non-zero and the
  P2P transport never comes up. The ambiguity guard is therefore a
  release-binary preflight property as well as a per-frame dispatcher
  property.

**Release-binary non-mutation guarantees asserted by Run 143:**

* per-node `pqc_trust_bundle_sequence.json` is byte-identical before
  and after every scenario;
* per-node `pqc_authority_state.json` (when present) is byte-identical
  before and after every scenario — accept and reject paths both
  preserve marker bytes verbatim, including the deliberately corrupt
  blob in the R8 corrupted-marker scenario;
* no `pqc_authority_state.json.tmp` sibling is ever left behind;
* no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` metric
  family appears;
* `qbind_p2p_trust_bundle_live_reload_*` and
  `qbind_p2p_session_eviction_*` counters all stay at 0;
* no `--p2p-trusted-root` fallback log line fires on any node;
* no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true`
  marker fires on any node;
* invalid candidates never produce `propagation_sent_total >= 1` and
  always produce `propagation_suppressed_invalid_total >= 1` when
  propagation is enabled.

**Scope notice:** Run 143 is **release-binary evidence only**. No
production runtime source is modified, no peer-driven live apply is
added, no SIGHUP / reload-apply / snapshot/restore mutating surface
beyond Run 134/136/138/140's existing wiring is touched, no v2 marker
is persisted from the live receive path, no trust-bundle /
peer-candidate / ratification wire format is changed, no KMS/HSM is
introduced, no MainNet governance artifact is verified, and no
signing-key rotation or revocation lifecycle is implemented.
Peer-driven live trust-bundle apply, signing-key rotation/revocation
lifecycle, KMS/HSM authority-key custody, MainNet governance
attestation, validator-set rotation, full C4 closure, and C5 closure
all remain out of scope.
## Run 144 — Peer-driven live trust-bundle apply: safety specification (no
runtime change)

**Run 144 is specification / design only.** It does not change any
mutating surface, any CLI flag, any metric, or any wire/schema.

The new specification is:

* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`

Operator-visible facts:

* The live inbound peer-candidate `0x05` path **remains
  validation-only / propagation-only** on every environment (DevNet,
  TestNet, MainNet), exactly as Runs 142/143 already evidence.
  Receiving a peer-candidate frame **does not** mutate
  `LivePqcTrustState`, **does not** write the trust-bundle sequence
  file, **does not** write the authority marker, and **does not**
  evict sessions.
* **Peer-driven live trust-bundle apply is not implemented and is
  disabled by default on every environment.** No CLI flag exists today
  that enables it.
* When peer-driven apply is eventually implemented (future Run 145+),
  the mandatory per-environment policy will be:
  * **DevNet** — MAY be enabled in a future run behind an explicit
    hidden DevNet-only CLI flag; **disabled by default**; the flag
    MUST refuse to bind on TestNet or MainNet.
  * **TestNet** — MAY be enabled only with explicit operator opt-in
    **and** a ratified v2 authority on the receiving node;
    **disabled by default**.
  * **MainNet** — **BLOCKED.** Peer-driven apply MUST be refused
    until governance / ratification / KMS-HSM authority is
    separately specified and evidenced. **Local peer majority alone
    is insufficient** and will never authorize MainNet peer-driven
    apply on its own.
* When peer-driven apply is eventually implemented, it MUST reuse
  the existing Run 070 apply contract exactly
  (`validate → snapshot previous → swap LivePqcTrustState → evict
  sessions → commit_sequence → persist v2 authority marker`), with
  the v2 marker persisted **strictly after** `commit_sequence`
  returns `Ok`. The v2 marker for a peer-driven apply will carry a
  distinct `last_update_source=peer-driven-apply` audit variant so
  operator audit tooling can distinguish a peer-driven apply from a
  reload-apply, startup-load, SIGHUP-reload, or snapshot-restore.

Operator action required by Run 144: **none.** Run 144 changes no
runtime behavior. Operators should however be aware that:

* No future build will silently enable peer-driven apply. Any future
  enablement requires an explicit per-environment hidden flag and
  per-environment ratification proof (or, on MainNet, governance /
  KMS-HSM authority that does not yet exist).
* Operator-pinned authority state (a pinned `(environment, chain_id,
  genesis_hash, authority_root)` tuple, or a pinned minimum
  `latest_authority_domain_sequence`) is part of the mandatory
  Phase 2 eligibility check and will be honored fail-closed by any
  future peer-driven apply implementation.

**Scope notice:** Run 144 is **specification / design only**. No
production runtime source is modified, no peer-driven live apply is
added, no SIGHUP / reload-apply / snapshot/restore / startup /
live-inbound-`0x05` mutating surface beyond Run 134/136/138/140/142's
existing wiring is touched, no v2 marker is persisted from any new
code path, no trust-bundle / peer-candidate / ratification wire
format is changed, no CLI flag is added, no metric family is added or
changed, no KMS/HSM is introduced, no MainNet governance artifact is
verified, and no signing-key rotation or revocation lifecycle is
implemented. Peer-driven live trust-bundle apply, signing-key
rotation/revocation lifecycle, KMS/HSM authority-key custody, MainNet
governance attestation, validator-set rotation, full C4 closure, and
C5 closure all remain out of scope.
## Run 145 — Peer-driven trust-bundle apply: staged candidate queue
source/test scaffold (no live apply, no release-binary evidence)

**Run 145 is source / test scaffold only.** It lands a new
library-level, **non-applying**, disabled-by-default, environment-gated,
bounded, deduplicated, TTL-bounded, per-peer-bounded, in-memory queue
for peer-supplied trust-bundle candidates that have already passed the
existing Run 142/143 live inbound `0x05` validation-only path. The
queue does **not** apply, propagate, mutate `LivePqcTrustState`, write
`pqc_trust_bundle_sequence.json`, write `pqc_authority_state.json`, or
evict P2P / KEMTLS sessions. **No release-binary evidence is claimed
in Run 145.** Release-binary staging evidence is deferred to Run 146.

The new source is:

* `crates/qbind-node/src/pqc_peer_candidate_staging.rs` —
  `PeerCandidateStagingQueue`, `PeerDrivenStagingPolicy`,
  `StagedPeerCandidate`, `StagingOutcome`.

The new tests are:

* `crates/qbind-node/tests/run_145_peer_candidate_staging_tests.rs` —
  A1–A4 and R1–R13 from `task/RUN_145_TASK.txt`.

Operator-visible facts:

* The live inbound peer-candidate `0x05` path **remains
  validation-only / propagation-only** on every environment
  (DevNet/TestNet/MainNet), exactly as Runs 142/143 already evidence.
  Receiving a peer-candidate frame still does **not** mutate
  `LivePqcTrustState`, **does not** write the trust-bundle sequence
  file, **does not** write the authority marker, and **does not**
  evict sessions.
* **Peer-driven live trust-bundle apply remains unimplemented and
  disabled by default on every environment.** No CLI flag exists
  today that enables apply.
* The new staging queue is **library-level only** in Run 145. It is
  **not** wired to the production binary's live inbound `0x05`
  dispatcher in this run. The future Run 146 binary hook will
  introduce a hidden DevNet-only flag (refusing to bind on
  TestNet/MainNet at the flag-bind step), produce release-binary
  evidence that the queue accepts validated candidates without any
  mutation, and document the operator-visible log lines.
* MainNet peer-driven staging is **refused unconditionally** by the
  Run 145 queue, even when `enabled = true` and `allow_mainnet =
  true`. The refusal is fail-closed and intentional: MainNet
  peer-driven trust-bundle apply requires a future governance /
  ratification / KMS-HSM authority that does not yet exist. **Local
  peer majority alone is insufficient.**
* TestNet peer-driven staging is **refused** by the queue unless
  `enabled = true` AND `allow_testnet = true` AND the upstream
  Run 130 v2 verifier and Run 132/142 v2 marker validation-only check
  accepted the candidate.
* Default policy bounds: `max_staged_candidates = 16`,
  `max_candidates_per_peer = 4`, `ttl_secs = 300`. Eviction policy at
  either cap is **reject-new**.

Operator action required by Run 145: **none.** Run 145 changes no
runtime behaviour because the new module is dead code in the release
binary. Operators should however be aware that:

* No future build will silently enable peer-driven apply. Any future
  enablement requires an explicit per-environment hidden flag and,
  on TestNet, the upstream v2 ratification check; MainNet remains
  blocked.
* Operator-pinned authority state (the pinned `(environment,
  chain_id, genesis_hash, authority_root)` tuple and pinned minimum
  `latest_authority_domain_sequence`) remains the source of truth
  for authority on the operator's node. A staged peer candidate is
  **non-authoritative** and is recorded purely as metadata for future
  operator / governance decision.

**Scope notice:** Run 145 is **source / test scaffold only**. No
release-binary staging evidence is produced (deferred to Run 146); no
peer-driven live apply is implemented; no SIGHUP / reload-apply /
process-start apply / snapshot/restore / startup / live-inbound-`0x05`
mutating behaviour beyond Runs 134/136/138/140/142 existing wiring is
touched; no v2 marker is persisted from any new code path; no
trust-bundle / peer-candidate / ratification / authority-marker /
sequence-file / ratification-sidecar wire format or schema is changed;
no CLI flag is added; no metric family is added, renamed, or removed;
no KMS / HSM is introduced; no MainNet governance artifact is verified;
and no signing-key rotation or revocation lifecycle is implemented.
Peer-driven live trust-bundle apply, signing-key rotation / revocation
lifecycle, KMS / HSM authority-key custody, MainNet governance
attestation, validator-set rotation, full C4 closure, and C5 closure
all remain out of scope.
## Run 146 — Peer-driven trust-bundle apply: staging queue wired into live inbound `0x05` (source/test wiring only)

**Run 146 is source / test wiring only.** It wires the Run 145
non-applying `PeerCandidateStagingQueue` into the **live inbound
`0x05` validation-only receive path** behind an explicit
**disabled-by-default** local policy gate, so a running node can be
observed staging already-validated peer candidates without applying
them. **No release-binary staging evidence is produced in Run 146.**
Release-binary staging evidence is deferred to Run 147.

What changed in code:

* `LivePeerCandidateWireDispatcher` and
  `LivePeerCandidateWireDispatcherConfig` gained an optional
  `staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>`
  field, defaulting to `None`. When `None`, the dispatcher behaves
  bit-for-bit as it did in Run 143.
* New runtime accessors `set_staging_queue`, `staging_queue`, and
  `staging_hook_is_armed` expose the late-install path for the future
  Run 147 production wiring.
* A new private helper `maybe_stage_after_validation` is invoked
  inside `dispatch_frame_from_peer_for_test` **after** both the
  Run 142 v2-marker conflict check and the Run 123 v1-marker conflict
  check, and **before** `maybe_propagate_after_validation`. It
  forwards only `PeerCandidateOutcome::Validated(_)` outcomes to
  `PeerCandidateStagingQueue::try_stage_outcome`. Invalid / rejected /
  rate-limited / oversize / disabled / duplicate-suppressed outcomes
  are filtered to `StagingOutcome::RefusedNotValidated` by the queue
  itself and are never staged.
* The queue's own `PeerDrivenStagingPolicy` continues to enforce
  disabled-by-default semantics, **MainNet refusal even when
  `enabled = true` and `allow_mainnet = true`**, per-peer and global
  capacity bounds with reject-new eviction, deduplication by
  `(fingerprint_prefix, sequence, authority_marker_digest)`, and TTL
  expiry. Run 146 adds no enforcement at the dispatcher layer.

What operators see at runtime:

* `0x05` validation-only behaviour is bit-for-bit Run 143 unless the
  staging queue has been installed AND the
  `PeerDrivenStagingPolicy.enabled` flag is set on the active
  policy AND the environment is not MainNet.
* When staging is armed and a candidate is accepted, Run 146 emits
  a `peer-candidate staging hook` log line tagged with the
  `StagingOutcome` variant; staging never affects propagation,
  trust-bundle sequence files, authority-marker files, live
  `LivePqcTrustState`, sessions, reload-apply, or SIGHUP.

What did **not** change:

* **No CLI flag is added in Run 146.** A future Run 147 entry point
  may parse a hidden `--p2p-trust-bundle-peer-candidate-staging-*`
  family and call `set_staging_queue` at startup. No dispatcher-level
  safety logic is required at Run 147 time.
* No Run 070 apply call is made from the staging hook under any
  condition. The staged candidate sits in the in-memory queue and is
  inspectable via `PeerCandidateStagingQueue::entries`.
* No trust-bundle / peer-candidate / authority-marker / ratification
  wire format or on-disk schema is changed.
* No metric family is added, renamed, or removed.
* No KMS / HSM is introduced.
* No MainNet governance artifact is verified.
* No signing-key rotation or revocation lifecycle is implemented.

Operator action required by Run 146: **none.** Run 146 changes no
default behaviour and adds no operator-facing surface. Default-built
release binaries continue to exhibit identical behaviour to Run 143.

**Scope notice:** Run 146 is **source / test wiring only**. No
release-binary staging evidence is produced (deferred to Run 147); no
peer-driven live apply is implemented; no SIGHUP / reload-apply /
process-start apply / snapshot/restore / startup mutating behaviour
beyond Runs 134/136/138/140/142 existing wiring is touched; no
v2 marker is persisted from any new code path; no trust-bundle /
peer-candidate / ratification / authority-marker / sequence-file /
ratification-sidecar wire format or schema is changed; no CLI flag is
added; no metric family is added, renamed, or removed; no KMS / HSM
is introduced; no MainNet governance artifact is verified; and no
signing-key rotation or revocation lifecycle is implemented.
Peer-driven live trust-bundle apply, MainNet staging enablement
(refused unconditionally by the Run 145 queue and unaffected by
Run 146), signing-key rotation / revocation lifecycle, KMS / HSM
authority-key custody, MainNet governance attestation, validator-set
rotation, full C4 closure, and C5 closure all remain out of scope.
## Run 147 — Peer-driven trust-bundle apply: release-binary evidence for the live `0x05` peer-candidate staging hook (hidden opt-in arming flag)

Run 147 produces the release-binary evidence that Run 146 explicitly
deferred for the Run 145 / Run 146 non-applying
`PeerCandidateStagingQueue`. The Run 147 feasibility gate ("can a
real `target/release/qbind-node` binary arm
`LivePeerCandidateWireDispatcher::staging_queue` through an existing
runtime config path?") returned **NO** against the Run 146 state
(`main.rs` constructed `dispatcher_cfg.staging_queue = None`; the
`set_staging_queue` late-install surface was source/test only). Per
`task/RUN_147_TASK.txt`'s "preferred path if a flag is necessary"
allowance, Run 147 adds the smallest hidden, disabled-by-default
DevNet/TestNet-only arming flag:

```
--p2p-trust-bundle-peer-candidate-staging-enabled
```

* clap `hide = true` (hidden from `--help`);
* default `false`;
* **refused on MainNet unconditionally** at the top-level
  partial-config gate with exit code `1` and a `[binary] Run 147:
  FATAL ...` stderr line; the P2P transport is never brought up;
* **refused** without
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
  (same exit code, same FATAL line shape);
* does **NOT** imply propagation
  (`--p2p-trust-bundle-peer-candidate-propagation-enabled` remains
  orthogonal);
* does **NOT** imply apply;
* does **NOT** add any metric family;
* does **NOT** change any wire format / on-disk schema.

### Operator runbook delta

When the flag is supplied with valid co-requisites on
DevNet/TestNet, the operator audit trail for the run includes
exactly two new stable log lines on the receiving node:

* `[binary] Run 147: peer-candidate staging hook arming flag accepted (env={Devnet|Testnet}). A bounded, non-applying PeerCandidateStagingQueue will be installed when the live 0x05 dispatcher is constructed. Staging is non-authoritative: NO apply; NO sequence write; NO marker write; NO LivePqcTrustState mutation; NO session eviction; NO SIGHUP / reload-apply. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md.`
* `[run-147] live peer-candidate staging hook ARMED (env=Devnet|Testnet, enabled=true, allow_devnet=..., allow_testnet=..., max_global=..., max_per_peer=..., ttl_secs=...). Non-applying; non-authoritative; no sequence write; no marker write; no session eviction; no SIGHUP / reload-apply.`

Existing Run 143 / Run 146 log lines and metric counters continue
to fire exactly as before. The Run 146 `[binary] Run 146:
...STAGED ...` / `... already staged ...` / `... refused ...`
hook line fires on V1 for every Validated outcome that reaches the
hook, exactly as the Run 146 source/test wiring documented.

### Refusal scenarios (Run 147 fail-closed top-level gate)

| Scenario | Operator action | Outcome |
|---|---|---|
| `--p2p-trust-bundle-peer-candidate-staging-enabled` with `--env mainnet` | Refused | exit code 1; `[binary] Run 147: FATAL: ... refused on MainNet unconditionally`; transport not up. |
| `--p2p-trust-bundle-peer-candidate-staging-enabled` without `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` | Refused | exit code 1; `[binary] Run 147: FATAL: ... requires --p2p-trust-bundle-peer-candidate-wire-validation-enabled`; transport not up. |

### Out-of-scope invariants preserved by Run 147

Operators can rely on the following Run 147-mandated invariants
holding on every run, asserted by the harness
`scripts/devnet/run_147_live_0x05_peer_candidate_staging_release_binary.sh`:

* `pqc_trust_bundle_sequence.json` byte-identical pre/post on every
  scenario (no sequence write from the staging hook);
* `pqc_authority_state.json` byte-identical pre/post on every
  scenario (no marker write from the staging hook);
* no `pqc_authority_state.json.tmp` sibling on any node;
* no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
  metric family appears (Run 088 / Run 144 contract);
* no `qbind_p2p_trust_bundle_live_reload_apply*` counter advances;
* no `qbind_p2p_session_eviction_total` counter advances;
* no `[run-070] apply` log line fires;
* no `SIGHUP ... reload-apply` log line fires;
* no `--p2p-trusted-root` fallback log line fires;
* no `DummySig` / `DummyKem` / `DummyAead` log line fires;
* invalid candidates never stage.

Operator action required by Run 147: **none** unless the operator
wants to explicitly opt in to staging on DevNet/TestNet for
evidence purposes. In that case the operator supplies the new
flag alongside the existing
`--p2p-trust-bundle-peer-candidate-wire-validation-enabled` and
verifies the two Run 147 log lines above appear on the receiver.
MainNet operators must NOT supply the flag — startup refuses
fail-closed.

**Scope notice:** Run 147 is **source/test + release-binary evidence
for hidden opt-in staging arming.** It is NOT pure evidence-only;
the source delta is the single new hidden CLI flag, the top-level
partial-config refusal gate, and the dispatcher-construction install
branch described above. No peer-driven live apply is implemented;
no SIGHUP / reload-apply / process-start apply / snapshot/restore /
startup mutating behaviour beyond the existing Runs 134 / 136 / 138 /
140 / 142 wiring is touched; no v2 marker is persisted from any new
code path; no trust-bundle / peer-candidate / ratification /
authority-marker / sequence-file / ratification-sidecar / snapshot-
meta wire format or schema is changed; no new metric family is
added, renamed, or removed; no KMS / HSM is introduced; no MainNet
governance artifact is verified; no signing-key rotation or
revocation lifecycle is implemented. Peer-driven live trust-bundle
apply (governed by the Run 144 specification), MainNet staging
enablement (refused unconditionally), signing-key rotation /
revocation lifecycle, KMS / HSM authority-key custody, MainNet
governance attestation, validator-set rotation, full C4 closure, and
C5 closure all remain out of scope.

## Run 148 — peer-driven apply controller (source/test only)

Run 148 adds a library-only peer-driven apply controller in
`crates/qbind-node/src/pqc_peer_candidate_apply.rs`. Operators
have **no new CLI surface, no new on-disk surface, and no new
runtime behaviour** in Run 148: the controller is not wired into
the node binary's reload-apply or SIGHUP path. The node binary's
behaviour is identical to Run 147.

The controller, when invoked by a library caller, picks an
already-staged candidate out of the Run 145 `PeerCandidateStagingQueue`,
re-checks freshness, the validation-accepted flag, environment,
and chain-id, runs the v2 marker pre-apply decision, and only
then delegates to the existing Run 070
`apply_validated_candidate_with_previous` apply pipeline. The
v2 authority marker is persisted by a `V2MarkerCoordinator` only
after the Run 070 sequence commit succeeds.

Operator-actionable status:

* **MainNet:** unchanged — peer-driven apply is refused
  unconditionally
  (`PeerDrivenApplyOutcome::RefusedMainNet`), regardless of
  `allow_mainnet`. Local config alone remains insufficient for
  MainNet bundle-signing authority.
* **DevNet / TestNet:** the controller is reachable only behind
  an explicit local `PeerDrivenApplyPolicy::devnet_enabled()` or
  `PeerDrivenApplyPolicy::testnet_enabled()`. No CLI flag is
  exposed in Run 148; operator wiring is deferred to Run 149.
* **Release binary:** Run 148 produces **no** release-binary
  evidence. Release-binary DevNet/TestNet peer-driven apply
  evidence is deferred to Run 149.

Out of scope (unchanged from Run 147):

* Governance / KMS / HSM / signing-key rotation / revocation
  lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Full C4 closure.
* C5 closure.
## Run 149 — peer-driven apply arming surface (release-binary evidence; partial-positive)

Run 149 introduces the **first operator-visible release-binary
arming surface** for the Run 148 peer-driven apply controller. A
single new hidden, disabled-by-default DevNet/TestNet-only flag
is added:

```
--p2p-trust-bundle-peer-candidate-apply-enabled
```

Operator-actionable status:

* **MainNet:** the flag is **refused unconditionally** with
  `[binary] Run 149: FATAL ...` and exit code 1; the P2P
  transport never comes up. Local peer majority is NOT authority
  on MainNet. Governance / ratification / KMS-HSM authority is
  required for any MainNet bundle-signing apply and is NOT
  implemented in this run.
* **DevNet / TestNet:** the flag is accepted only when
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
  AND `--p2p-trust-bundle-peer-candidate-staging-enabled` are
  also set. Any other combination is refused with
  `[binary] Run 149: FATAL ...` and exit code 1.
* **Acceptance log evidence:** when the flag is accepted, the
  binary emits exactly two new operator-visible log lines:
  * `[binary] Run 149: peer-candidate apply arming flag accepted (env=...)`
  * `[run-149] live peer-driven apply policy ARMED (env=..., enabled=true, allow_devnet=..., allow_testnet=..., allow_mainnet=...)`
* **Partial-positive disclosure:** Run 149 does NOT wire a
  queue-to-controller drain task in the node binary. Wiring such
  a drain would be a new apply-triggering algorithm, explicitly
  out of scope per `task/RUN_149_TASK.txt` §20 ("must not create
  a new apply algorithm"). End-to-end apply through the release
  binary therefore remains under **Run 148 source/test coverage**
  (`crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`,
  20/20 green); the release-binary arming surface itself is
  evidenced under Run 149.

Invariants preserved (operator-relevant):

* When `--p2p-trust-bundle-peer-candidate-apply-enabled` is
  **absent**, the binary behaves bit-for-bit identically to
  Run 147; the entire Run 149 source delta is gated by the new
  flag.
* The Run 070 apply contract is reused verbatim (validate →
  snapshot active → swap → evict_sessions → commit_sequence);
  apply is delegated through the Run 148
  `try_apply_staged_peer_candidate` controller, not invented
  anew.
* The v2 authority marker is persisted **only after** the
  Run 070 sequence commit succeeds, via the existing Run 148
  `V2MarkerCoordinator` post-commit boundary.
* No new wire format; no new CLI flag beyond the single hidden
  arming flag above; no metric family added, renamed, or removed;
  no KMS / HSM introduced; no MainNet governance artifact
  verified; no signing-key rotation or revocation lifecycle
  implemented.

Out of scope (operator-relevant; unchanged from Run 148):

* Governance / ratification authority.
* KMS / HSM authority-key custody.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Queue-to-controller drain caller (deferred to a future run
  under a strictly specified ordering contract that is not a new
  apply algorithm — e.g. an existing SIGHUP / reload-apply
  trigger that calls the Run 148 controller with the next
  eligible staged candidate).
* Full C4 closure.
* C5 closure.

## Run 150 — Peer-driven apply drain: source/test wiring only (no operator surface yet)

Run 150 adds a source-and-test only wiring that connects the Run
145/146 staged peer-candidate queue to the Run 148 peer-driven
apply controller. **Operators have nothing to do in Run 150.**
There is no new CLI flag, no new SIGHUP behaviour, no new
reload-apply behaviour, no new metric, no new log line you must
watch, and no new on-disk artefact. The release binary's
operator-visible behaviour is byte-for-byte unchanged from Run 149.

What did change (source/test only):

* A new library module `crates/qbind-node/src/pqc_peer_candidate_drain.rs`
  exposes an explicit `PeerDrivenApplyDrain::try_drain_once(...)` entry
  point gated by a disabled-by-default `PeerDrivenDrainPolicy` and
  layered MainNet refusal.
* A new helper `PeerCandidateStagingQueue::remove_by_id(...)` lets the
  drain remove a staged entry from the in-memory queue after a
  successful apply (or after a permanently-invalid pre-apply refusal).
  No live trust state, sequence file, marker file, P2P session, or
  propagation surface is touched by this helper.
* A new integration test file
  `crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
  exercises 19 acceptance scenarios end-to-end; in-module unit tests
  cover policy / outcome classification / selector / concurrency-guard
  behaviour.

Operator-visible deferral:

* **Release-binary trigger evidence is deferred to Run 151.** The
  Run 150 module is reachable only from tests. No `main.rs` /
  `cli.rs` change has been made.

Operator runbook impact: **none in this run.** When Run 151 lands
the operator trigger, this runbook will gain a new section
describing the explicit DevNet/TestNet CLI surface, the
disabled-by-default policy, the unconditional MainNet refusal at
every layer, and the expected `PeerDrivenDrainOutcome`
classification. Until then, peer-driven apply remains a
source/test capability only.

Negative assertions reaffirmed by Run 150 (matching Run 148 / Run 149):

* No new MainNet apply path; MainNet refusal is enforced at the
  Run 150 policy gate, the runtime-domain check, and the Run 148
  controller.
* No autonomous / background / on-receipt apply.
* No new wire format, no new on-disk schema, no new metric family.
* No SIGHUP behaviour change.
* No reload-apply behaviour change.
* No live `0x05` dispatcher behaviour change.
* No Run 070 apply contract change; the drain delegates verbatim
  through the Run 148 controller to the existing Run 070
  `apply_validated_candidate_with_previous(...)` path.

Out of scope for Run 150 (carried forward from Run 149's out-of-scope
list, unchanged):

* Release-binary operator trigger (now: Run 151).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Full C4 closure; C5 closure.
## Run 151 — release-binary trigger surface for the DevNet/TestNet explicit drain

Run 151 surfaces the Run 150 explicit DevNet/TestNet-only
peer-driven apply drain trigger
(`PeerDrivenApplyDrain::try_drain_once`) on the real
`target/release/qbind-node` via the smallest hidden,
disabled-by-default DevNet/TestNet-only CLI flag:

```
--p2p-trust-bundle-peer-candidate-drain-once    (hide=true)
```

The flag is **refused on MainNet unconditionally** at three
independent layers (early-startup `main.rs` gate; co-requisites
`main.rs` gate; the Run 150 `PeerDrivenDrainPolicy` MainNet
unconditional refusal in the drain controller itself). The flag
requires `--p2p-trust-bundle-peer-candidate-apply-enabled`
(which itself transitively requires
`--p2p-trust-bundle-peer-candidate-staging-enabled` and
`--p2p-trust-bundle-peer-candidate-wire-validation-enabled`);
supplying the flag without that co-requisite chain is refused
fail-closed with one of the `[binary] Run 147 / 149 / 151:
FATAL` lines and exit code 1, and the P2P transport is never
brought up.

Operator-visible banners (DevNet / TestNet, full co-requisites
supplied):

```
[binary] Run 151: peer-candidate drain-once trigger flag accepted ...
[run-151] live peer-driven apply drain trigger ARMED
  (env=<Devnet|Testnet>, enabled=true, allow_devnet=<bool>,
   allow_testnet=<bool>, max_candidate_age_secs=<u64>,
   remove_after_apply=true, in_progress=false) ...
```

The arming banner's `in_progress=false` field observably loads
the Run 150 `PeerDrivenApplyDrain` controller's
`Arc<AtomicBool>` concurrency guard at construction time,
proving the guard is freshly initialized at the moment the
trigger surface is armed.

Operator semantics:

* **Disabled by default.** The flag is `hide=true` and defaults
  to `false`. Operators must explicitly supply the flag plus
  the Run 149 apply co-requisite (which itself transitively
  requires Run 147 staging + Run 146 wire-validation).
* **DevNet / TestNet only; MainNet refused.** Local config
  alone is insufficient for MainNet bundle-signing authority;
  the Run 151 drain-once trigger refuses MainNet at three
  independent layers (defensive triplicate).
* **At most one candidate per trigger.** The Run 150
  `try_drain_once` contract is unchanged; Run 151 does not
  introduce a bulk drain.
* **Concurrency-guarded.** The Run 150 `Arc<AtomicBool>`
  in-progress flag prevents double drains; concurrent triggers
  return `AlreadyInProgress` and do not enter the drain
  pipeline.
* **Never calls Run 070 directly from `main.rs`.** The trigger
  routes through the Run 150 drain → Run 148 controller →
  Run 070 `apply_validated_candidate_with_previous` pipeline
  only; the v2 authority marker is persisted strictly **after**
  Run 055 `commit_sequence` succeeds via the existing
  `V2MarkerCoordinator` post-commit boundary.
* **No autonomous background drain task.** The arming banner
  materializes the drain controller and policy and drops both
  at the end of the block; no timer, signal handler, or
  background task is installed.
* **No automatic apply on receipt.** Inbound `0x05` candidates
  continue to follow the Run 142 / Run 143 validation-only and
  Run 146 / Run 147 non-applying staging paths; apply requires
  an explicit operator trigger.

Verdict: **"minimal source wiring + release-binary evidence —
partial-positive (trigger-surface arming)."** End-to-end
release-binary apply through the drain (matrix rows A1, A2, A6,
A7) remains under **Run 150 source/test coverage**
(`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
19 / 19 green) because the productionization of the
`PeerDrivenDrainInvocationBuilder` + `V2MarkerCoordinator`
implementations and the cross-scope plumbing of the live
staging-queue handle into a drain caller exceed the "smallest
possible hook" allowance in `task/RUN_151_TASK.txt`.

Refusal scenarios (release-binary evidenced):

* C1 drain-once supplied without
  `--p2p-trust-bundle-peer-candidate-apply-enabled`:
  `[binary] Run 151: FATAL` + exit 1.
* C2 / R2 drain-once supplied on `--env mainnet`:
  `[binary] Run 151: FATAL` (early-startup) + exit 1.
* C3 drain-once + apply supplied without staging:
  `[binary] Run 149: FATAL` (transitive staging co-requisite
  gate) + exit 1.
* C4 drain-once + apply + staging supplied without
  wire-validation: `[binary] Run 147: FATAL` (upstream staging
  gate; staging requires wire-validation upstream of the
  Run 149 apply gate) + exit 1.

Out of scope for Run 151 (unchanged from Run 150):

* Production `PeerDrivenDrainInvocationBuilder` /
  `V2MarkerCoordinator` impls + cross-scope staging-queue
  plumbing for end-to-end release-binary apply through the
  drain (next future-run piece on the C4 closure
  decomposition).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* MainNet governance attestation.
* Validator-set rotation.
* Full C4 closure; C5 closure.

Operator instructions: see
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md` for the
canonical verdict, the source delta, the scenario matrix, the
ordering proof citations (Run 150 source/test for A1 / A2 / A6
/ A7), the negative invariants, and the release-binary harness
`scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh`.

## Run 152 — source/test wiring for binary-reachable peer-driven drain invocation plumbing

Run 152 lands the source/test wiring that Run 151 explicitly
deferred under its "smallest possible operator-local hook"
allowance: a production `ProductionDrainInvocationBuilder`, a
production `ProductionV2MarkerCoordinator`, a shared in-memory
`Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>` handle, and
a `pqc_peer_candidate_drain::try_drain_once_shared` shared-queue
drain entry point. The Run 151 hidden
`--p2p-trust-bundle-peer-candidate-drain-once` hook is now
capable of constructing a real drain invocation from the live
staged peer-candidate queue and routing it through
`live inbound 0x05 → validation-only v2 acceptance → staging
queue → hidden drain hook → ProductionDrainInvocationBuilder
→ ProductionV2MarkerCoordinator → Run 150 drain → Run 148
controller → Run 070 apply`. The v2 authority marker is
persisted only AFTER the Run 070 `commit_sequence` boundary
succeeds; a post-commit persist failure is surfaced as the
fatal/operator-actionable
`PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit` per
Run 134 §PersistFailure.

**Run 152 is source/test wiring only.** The release binary does
not autonomously invoke the drain: the live apply context, the
verified v2 ratification, and the operator-supplied
previous-fingerprint metadata are threaded by the Run 153
end-to-end release-binary harness, which is **explicitly
deferred**. Operators should treat the existing Run 151 hidden
CLI flag as trigger-surface armed only; no operational change
to the runbook is required. No autonomous background apply
exists. No automatic apply on receipt exists. MainNet remains
refused at every layer (defensive triplicate: early-startup
gate, Run 150 `PeerDrivenDrainPolicy`, Run 148 controller).
Governance remains unimplemented. KMS / HSM remains
unimplemented. Signing-key rotation / revocation lifecycle
remains open. Full C4 remains open; C5 remains open.

## Run 153 — release-binary end-to-end peer-driven apply evidence

Run 153 wires the Run 152 binary-reachable plumbing
(`ProductionDrainInvocationBuilder`, `ProductionV2MarkerCoordinator`,
`try_drain_once_shared`) into the Run 151 hidden
`--p2p-trust-bundle-peer-candidate-drain-once` hook so the full
peer-driven apply pipeline is callable from a real
`target/release/qbind-node`. **Operators who already pass the hidden
drain-once flag now get the full end-to-end pipeline**: after P2P
startup and a configurable delay (`QBIND_DRAIN_ONCE_DELAY_SECS`,
default 10s) the drain-once block constructs the production builder,
coordinator, and context from the live trust state and invokes
`try_drain_once_shared` exactly once through the full chain:

    staging queue → ProductionDrainInvocationBuilder
    → ProductionV2MarkerCoordinator → Run 150 drain
    → Run 148 controller → Run 070 apply → LivePqcTrustState swap
    → session eviction → sequence commit → v2 marker persist

New operator-visible log lines:

```
[run-153] drain-once: invoking try_drain_once_shared ...
[run-153] drain-once outcome: <PeerDrivenDrainOutcome variant>
```

Safety guarantees for operators:

* **MainNet refused unconditionally** at the drain-once invocation
  point (defensive guard on top of the Run 151 early-startup and
  co-requisites gates).
* **No new CLI flag.** The existing Run 151 hidden flag controls
  the drain-once behaviour.
* **One-shot.** `try_drain_once_shared` fires exactly once after
  the configurable delay; no autonomous background drain loop.
* **No automatic apply on receipt.** The drain fires on a delay
  after P2P startup, not automatically when a `0x05` candidate
  arrives.
* **Ordering contract.** The drain routes through Run 150 / Run
  148 / Run 070 verbatim; the Run 070 ordering invariant
  (`validate → snapshot → swap → evict → commit → marker`) is
  unchanged.

Refusal scenarios evidenced by the Run 153 release-binary harness
(`scripts/devnet/run_153_peer_driven_apply_end_to_end_release_binary.sh`):

* C1: drain-once without `--p2p-trust-bundle-peer-candidate-apply-enabled`
  → `[binary] Run 151: FATAL` exit 1.
* A5: drain-once on `--env mainnet`
  → `[binary] Run 151: FATAL` early-startup exit 1.
* C3: drain-once + apply without staging → FATAL exit 1.
* C4: drain-once + apply + staging without wire-validation → FATAL exit 1.

End-to-end accepted scenarios (A1 DevNet apply, A3 empty queue
NoCandidate, A4 disabled policy, A6 duplicate cannot double-apply,
A7 deterministic highest-sequence selection) and rejection scenarios
(R1–R10) are cited from Run 152 (23 / 23 green) and Run 150
(19 / 19 green) source/test coverage where release-binary fault
injection is infeasible.

Negative assertions reaffirmed by Run 153 (matching Run 152 /
Run 151 / Run 150):

* No autonomous background drain.
* No automatic apply on receipt.
* No peer-majority authority.
* No MainNet enablement.
* No governance / KMS / HSM implementation.
* No signing-key rotation / revocation lifecycle.

Out of scope for Run 153 (unchanged from Run 152):

* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* TestNet evidence (deferred; fixture tooling needed).
## Run 154 — TestNet fixture tooling (source/test only; no operator surface change)

Run 154 is **source/test fixture tooling only**. Operators have **no new
CLI surface and no new runtime behaviour** in this run.

What Run 154 adds for the lab/evidence workflow:

* The Run 133 v2 fixture helper
  (`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`)
  now also mints a `testnet/` fixture directory alongside `devnet/` and
  `mainnet/`. Run it the same way as before:

  ```
  cargo run -p qbind-node --example run_133_v2_validation_only_fixture_helper <OUTDIR>
  ```

  The `testnet/` directory contains TestNet genesis / runtime-domain
  metadata, a signed TestNet trust bundle (baseline + candidate), the
  ML-DSA-44 bundle-signing public key spec, v1 + v2 ratification sidecars
  bound to the TestNet environment, seeded v1/v2 markers, a valid v2
  peer-candidate `0x05` fixture, and the invalid negative peer-candidate
  fixtures (lower-sequence, same-sequence different-digest, bad-signature,
  wrong-environment, wrong-chain, duplicate).

* Every TestNet artifact is domain-bound (`environment = TestNet`,
  TestNet `chain_id`, TestNet genesis hash, minted authority-root
  fingerprint, v2 authority-domain sequence). Operators feeding these to
  a TestNet evidence harness must capture the non-deterministic fields
  per run: the ephemeral authority / bundle-signing / transport-root keys,
  all signatures, and the genesis hash (derived from the minted authority
  key).

* **DevNet helper behaviour is unchanged** (the `devnet/` output is
  byte-for-byte identical to prior runs); the `mainnet/` directory stays
  clearly fixture-only and is never production-authoritative.

Run 154 closes the fixture-tooling blocker that deferred the Run 153 A2
TestNet evidence. Release-binary TestNet end-to-end peer-driven apply
evidence is **deferred to Run 155**.

Out of scope for Run 154 (unchanged from Run 153):

* Operator CLI / runtime behaviour change.
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement (MainNet remains refused).
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* Validator-set rotation.
* Full C4 / C5 closure.
## Run 155 — release-binary TestNet end-to-end peer-driven apply evidence (no operator surface change)

Run 155 is **release-binary TestNet end-to-end peer-driven apply
evidence**. It mirrors the Run 153 DevNet end-to-end exercise but under the
**TestNet runtime domain**, using the Run 154 TestNet fixtures. Operators
have **no new CLI surface and no new runtime behaviour** in this run: the
Run 153 hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook is reused verbatim, and
its Run 150 drain / apply policies are already selected by environment
(`testnet_enabled()` under `--env testnet`) with MainNet refused
unconditionally.

What Run 155 adds for the lab/evidence workflow:

* A release-binary TestNet harness
  `scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh`
  that runs against a real `target/release/qbind-node`. Build and run it as:

  ```
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node \
      --example run_133_v2_validation_only_fixture_helper
  bash scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh
  ```

  The harness mints the Run 154 TestNet fixtures with the **real release
  helper**, records their TestNet domain binding (environment, chain id,
  genesis hash) and SHA-256s under
  `docs/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary/fixtures/`,
  and runs the TestNet fail-closed matrix on the real binary
  (A6/C2 MainNet refused; C1/C3/C4 co-requisite refusals — each exit=1 with
  a `Run 151: FATAL` / `FATAL` banner).

* The evidence archive and report
  (`docs/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_155.md`) document the full
  TestNet apply pipeline (validation-only → staging → drain-once →
  ProductionDrainInvocationBuilder → ProductionV2MarkerCoordinator →
  Run 150 drain → Run 148 controller → Run 070 apply → swap → eviction →
  sequence commit → v2 marker persist after commit) and cite the Run 154
  TestNet fixture suite and the Run 152/150/148 source/test matrices for
  the positive apply path and the reject/no-op matrix.

Run 155 closes the Run 153 A2 TestNet evidence deferral. DevNet evidence
from Run 153 remains valid and untouched.

Out of scope for Run 155 (unchanged from Run 154):

* Operator CLI / runtime behaviour change.
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement (MainNet remains refused).
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* Validator-set rotation.
* Full C4 / C5 closure.
## Run 156 — positive TestNet release-binary apply driven on real binaries; positive A1 BLOCKED, exact blocker documented (no operator surface change)

Run 156 drives the **positive** TestNet end-to-end peer-driven apply path
on a real `target/release/qbind-node` over a **live N=3 TestNet P2P
cluster** (V0 publisher of one live `0x05` candidate, V1 receiver with
wire-validation/staging/apply/drain-once armed, V2 observer), rather than
mapping the positive path to source/test coverage as Run 153/155 did.
Operators have **no new CLI surface and no new runtime behaviour**: the
Run 153 hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook is reused verbatim.

What Run 156 adds for the lab/evidence workflow:

* A release-binary live N=3 TestNet harness
  `scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh`.
  Build and run it as:

  ```
  cargo build --release -p qbind-node --bin qbind-node
  cargo build --release -p qbind-node \
      --example run_133_v2_validation_only_fixture_helper
  bash scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh
  ```

  The harness mints transport material and TestNet fixtures with the real
  release helpers, launches the three nodes, publishes one live `0x05`
  candidate from V0, waits for the explicit delayed drain-once on V1, and
  records the **actual** drain outcome under
  `docs/devnet/run_156_testnet_positive_peer_driven_apply_release_binary/`.

* The evidence archive and report
  (`docs/devnet/run_156_testnet_positive_peer_driven_apply_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_156.md`).

**Result on the fixtures shipped in this repository:** the live pipeline
runs end-to-end up to V1's wire-validation gate (P2P up; V0 publishes; V1
observes `Run 078 … outcome=rejected; NOT applied`), but the candidate is
rejected before staging, so the drain-once returns `NoCandidate` with **no
live trust mutation** (V1 logs only `first-load persisted_sequence=1`).
The **exact blocker** (recorded in the archive `a1_blocker.txt` and the
evidence report): the live P2P transport bundle / leaf credentials are
minted by `devnet_pqc_trust_bundle_helper` under one root authority, while
the only TestNet apply candidate (`run_133` helper
`testnet/peer-candidate.valid.json`) is signed under a **disjoint** root
with no matching P2P leaf credentials, so it is not a Run-070 successor of
V1's live baseline. No existing fixture tool mints a single unified
universe with both N=3 P2P leaf credentials and a self-consistent
seq1→seq2 apply pair signed by the same transport root.

**Unblock path (out of Run 156 scope):** a future fixture-tooling run can
mint the unified universe; the harness already accepts
`QBIND_RUN156_TRANSPORT_DIR` / `QBIND_RUN156_CANDIDATE_ENVELOPE` /
`QBIND_RUN156_SIDECAR` / `QBIND_RUN156_GENESIS` /
`QBIND_RUN156_GENESIS_HASH` overrides, and on a unified universe it drives
the real apply and asserts the `Applied` ordering automatically.

Run 156 also re-confirms the negative invariants on the real binary
(A6/C2 MainNet drain-once refused, exit=1 with `Run 151: FATAL`; no
autonomous drain; no automatic apply on receipt; denylist grep clean).

Out of scope for Run 156 (unchanged from Run 155):

* Operator CLI / runtime behaviour change.
* Unified fixture tooling (the unblock path above).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement (MainNet remains refused).
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.
* Validator-set rotation.
* Full C4 / C5 closure (the positive TestNet release-binary A1 apply
  remains BLOCKED pending unified fixture tooling).
## Run 157 note — unified TestNet fixture universe

Run 157 adds source/test fixture tooling only: `run_157_unified_testnet_peer_apply_fixture_helper` emits `unified_testnet_manifest.json` for a coherent TestNet fixture universe. It fixes the Run 156 disjoint-universe blocker by ensuring live transport material and baseline/candidate peer-apply material share the same TestNet domain, chain id, genesis hash, authority root, transport root, and bundle-signing authority.

Operators must not treat Run 157 output as production MainNet authority material. Release-binary positive TestNet apply evidence is deferred to Run 158. MainNet remains refused; governance, KMS/HSM, signing-key rotation/revocation lifecycle, and validator-set rotation remain open. Full C4 and C5 remain open.
## Run 158 — positive TestNet release-binary peer-driven apply evidence using the Run 157 unified fixture universe (no operator surface change)

Run 158 closes the **Run 156 disjoint-universe blocker** by driving a real `target/release/qbind-node` TestNet receiver through the **complete positive peer-driven apply path** over **live P2P**, using the **Run 157 unified TestNet fixture universe**. Run 158 introduces **no operator-visible CLI surface change**: the same hidden, disabled-by-default `--p2p-trust-bundle-peer-candidate-drain-once` hook from Run 153 / 155 / 156 drives the full Run 152 → 150 → 148 → 070 pipeline under `--env testnet`.

What Run 158 adds for the lab/evidence workflow:
- `scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh` — release-binary harness that mints the unified TestNet universe with `run_157_unified_testnet_peer_apply_fixture_helper`, mints per-validator consensus signer keystores, runs the TestNet fail-closed refusal matrix (`R2_mainnet_refused`, `C1_testnet_drain_without_apply`, `C3_testnet_drain_without_staging`, `C4_testnet_drain_without_wire_validation`), drives the live N=3 cluster for the positive A1 scenario and the R3 wrong-environment rejection scenario, captures before/after V1 sequence and v2 marker JSON + SHA-256, writes either `a1_apply_proof.txt` (positive) or `a1_blocker.txt` (blocker), and emits in-scope and out-of-scope grep summaries.
- `docs/devnet/run_158_testnet_positive_peer_driven_apply_release_binary/` — evidence archive with `README.md` + `summary.txt` tracked and per-run artifacts gitignored.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_158.md` — canonical evidence report.

Operators have **no new CLI surface** and **no new runtime behaviour** in Run 158. The harness is reproducible from a clean checkout via:

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_157_unified_testnet_peer_apply_fixture_helper
cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
bash scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh
```

Run 158 does **not** substitute source/test coverage for the positive A1 verdict: the harness asserts the canonical Run 070 ordering (`validate → snapshot previous → swap → evict_sessions → commit_sequence`), the Run 055 sequence advance (`persisted_sequence=1 → persisted_sequence=2`), and the Run 134/138 v2-marker post-commit boundary in V1's release-binary stderr; otherwise it writes a blocker documenting the exact failure mode.

Out of scope for Run 158 (unchanged from Run 157):
* MainNet enablement (refused unconditionally).
* Governance.
* KMS / HSM.
* Signing-key rotation / revocation lifecycle.
* Validator-set rotation.
* Full C4 / C5 closure.

MainNet remains refused. Governance remains unimplemented. KMS / HSM remains unimplemented. Signing-key rotation / revocation lifecycle remains open. Validator-set rotation remains open. Full C4 and C5 remain open.
## Run 159 — source/test signing-key rotation and revocation lifecycle for v2 authority state

Run 159 lands typed pure transition validation for the v2 bundle-signing-key lifecycle (`ActivateInitial`, `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke`) as a new `qbind_node::pqc_authority_lifecycle` module. The new validator is **pure** and **typed**: it performs no I/O, never writes the sequence file, never mutates the persisted authority marker, and never touches a live trust bundle. Operators have **no new CLI surface** and **no new runtime behaviour** in Run 159. The lifecycle validator is a *pre-flight typed surface* that future runs may compose into the existing Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist pipeline once a wire-level encoding for `Retire` / `EmergencyRevoke` lands; until then, the existing marker-comparison helpers remain the authoritative mutating-surface decision points and are unchanged.

Reproducing the lifecycle test matrix from a clean checkout:

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
```

The matrix covers the A1–A6 acceptance cases (initial activation, planned rotation, idempotent same record, retirement of a previous signing key under higher sequence, revocation under higher sequence, emergency revocation under higher sequence) and the R1–R17 rejection cases (lower-sequence rollback, same-sequence equivocation, wrong environment / chain / genesis / authority-root, wrong previous-key fingerprint, revoked-key reuse, retired-key reuse without overlap, emergency-revoke replay, malformed revoked metadata, non-PQC suite, unsupported lifecycle action under the current persisted state, revoked-active-key candidate rejected through the lifecycle path, persisted record bytes unchanged on rejection, Run 134/136/138/150/152 marker comparison behavior unchanged, DevNet/TestNet domain coverage with MainNet pure-validation parsing not implying MainNet apply enablement).

Out of scope for Run 159:

* Release-binary lifecycle evidence — **deferred to Run 160**.
* MainNet enablement (refused unconditionally).
* Governance.
* KMS / HSM.
* Validator-set rotation.
* Full C4 / C5 closure.

MainNet remains refused. Governance remains unimplemented. KMS / HSM remains unimplemented. Validator-set rotation remains open. Release-binary lifecycle evidence is deferred to Run 160. Full C4 and C5 remain open.
## Run 160 — release-binary evidence / boundary for the v2 signing-key lifecycle validator

Run 160 produces release-binary evidence for the Run 159 v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`). The Run 160 source-level call graph (captured by the harness) shows that the lifecycle validator has **zero** production callers today — none of the eight release-binary surfaces (startup `--p2p-trust-bundle` v2, reload-check, local peer-candidate-check, process-start reload-apply, SIGHUP, live inbound `0x05`, peer-driven staged drain-once, fixture helper / example) calls `validate_v2_lifecycle_transition`. Operators therefore have **no new CLI surface** and **no new runtime behaviour** in Run 160. The lifecycle validator remains a *pre-flight typed surface* that future runs may compose into the existing Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist pipeline; until that wiring lands (the exact next required integration run is **Run 161**), the existing marker-comparison helpers remain the authoritative mutating-surface decision points and are unchanged.

What Run 160 does add is **release-binary evidence that is honestly available today**:

* a release-built helper (`target/release/examples/run_160_authority_lifecycle_fixture_helper`) that mints the lifecycle fixture corpus covering A1–A6 (`ActivateInitial`, `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke`, idempotent same-record) and R1–R14 (lower-sequence rollback, same-sequence equivocation, wrong environment / chain / genesis / authority root, wrong previous-key fingerprint on rotate, revoked-key reuse, retired-key reuse, emergency-revoke replay, malformed revoked metadata, non-PQC suite, unsupported lifecycle action, V1-persisted-V2-candidate refusal) using the existing marker schemas without any wire / sidecar / marker / sequence-file change;
* the real `target/release/qbind-node` binary identity (sha256 + ELF Build ID) recorded in the harness's `provenance.txt`;
* the Run 159 lifecycle test suite plus the Run 134 / 138 / 142 / 148 / 150 / 152 / 157 regression suites and `cargo test -p qbind-node --lib pqc_authority` / `cargo test -p qbind-node --lib` run on the same checkout, with per-suite stdout/stderr/exit_code captured in `docs/devnet/run_160_authority_lifecycle_release_binary/test_results/`;
* a `partial_positive_proof.txt` documenting the verdict — `partial-positive: release-binary fixture/evidence boundary captured; lifecycle validator not yet production-surface reachable` — and the schema-gap analysis (Retire and EmergencyRevoke are representable on the existing wire/marker schemas via the Run 159 metadata sub-class convention; the schema is not the gap, the production wiring is).

Out of scope for Run 160:

* MainNet enablement.
* Governance / KMS / HSM implementation.
* Validator-set rotation.
* Production wiring of `validate_v2_lifecycle_transition` into any mutating surface — **deferred to Run 161**.
* Wire-level encoding of `Retire` / `EmergencyRevoke` as distinct action bytes (the existing `Ratify=0` / `Rotate=1` / `Revoke=2` byte set is preserved unchanged; Run 159's local sub-class metadata convention is sufficient).

MainNet remains refused. Governance remains unimplemented. KMS / HSM remains unimplemented. Validator-set rotation remains open. Release-binary lifecycle apply remains not enabled. The exact next required integration run is **Run 161**. Full C4 and C5 remain open.
## Run 161 — wire the v2 signing-key lifecycle validator into the shared marker-decision helper

Run 161 is **source/test integration only**. The Run 159 typed v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`) is now composed inside the shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2` that is already used by every existing v2 surface: Run 134 (process-start reload-apply), Run 136 (startup `--p2p-trust-bundle`), Run 138 (SIGHUP live-reload), Run 150 (peer-driven drain), Run 152 (`ProductionV2MarkerCoordinator`), Run 132 (reload-check), and Run 142 (live inbound `0x05` validation-only). Operators have **no new CLI surface, no new flag, and no new runtime mutation primitive**. The on-wire byte set (`Ratify=0` / `Rotate=1` / `Revoke=2`) is unchanged; the trust-bundle / authority-marker / sequence-file / peer-candidate-envelope schemas are unchanged; the Run 159 local sub-class metadata convention (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke) is reused verbatim.

What Run 161 changes for operators in practice:

* On every existing v2 mutating surface, a malformed lifecycle transition (wrong previous-key fingerprint on rotate, revoked-key reuse, retired-key reuse, malformed revoked metadata, non-PQC suite, unsupported lifecycle action under the current persisted state, emergency-revoke replay, structurally malformed v2 candidate) now fail-closed at the marker-decision step, surfaced via the new typed reject `MutatingSurfaceMarkerV2Error::LifecycleRejected(AuthorityLifecycleTransitionOutcome)`. The reject is observed before any disk write — `decide_marker_acceptance_v2` itself never touches disk and persistence remains strictly after Run 055 sequence commit.
* On every existing v2 validation-only surface (reload-check, local peer-candidate-check, live `0x05`), the same lifecycle rejects now appear in validation output without mutating local state.
* Two Run 159 reject variants are passed through to the existing comparison decision rather than escalated, by design (R20 back-compat): `InitialActivationAfterPersistedRejected` (the wire-byte `Ratify` advancement that pre-Run-161 fixtures continue to issue, where anti-rollback is already enforced by the existing v2 marker-schema compare) and `V1PersistedV2CandidateNotSupportedHere` (the Run 131 explicit v1→v2 migration boundary, which Run 159 deliberately does not validate).

Out of scope for Run 161:

* MainNet enablement.
* Governance / KMS / HSM implementation.
* Validator-set rotation.
* Release-binary lifecycle evidence — **deferred to Run 162**.
* Wire-level encoding of `Retire` / `EmergencyRevoke` as distinct action bytes (the existing `Ratify=0` / `Rotate=1` / `Revoke=2` byte set is preserved unchanged; Run 159's local sub-class metadata convention is sufficient).

## Run 162 — release-binary lifecycle ENFORCEMENT evidence on real `target/release/qbind-node`

Run 162 is **release-binary evidence only**: a new release-binary harness (`scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`), a new evidence archive (`docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/`), a canonical evidence report (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md`), and four narrow doc alignment updates. Operators have **no new CLI surface, no new flag, and no new runtime mutation primitive**. The on-wire byte set, the v2 marker schema, the sequence-file schema, and the peer-candidate envelope schema are all unchanged.

What Run 162 proves for operators:

* On real `target/release/qbind-node`, the Run 161 wiring of the Run 159 lifecycle validator into `decide_marker_acceptance_v2` is now exercised end-to-end through the existing `--p2p-trust-bundle-reload-check` (validation-only) and `--p2p-trust-bundle-reload-apply-path` (mutating) flags. The release-binary captures show:
  * `ActivateInitial` accept (no persisted marker → first v2 marker write strictly after Run 055 sequence commit);
  * `Rotate` accept (v2-seq=1 marker → v2-seq=2 marker, again strictly after Run 055 sequence commit);
  * `Idempotent` same-record accept (no rewrite; marker bytes byte-identical to seed);
  * `lower-sequence`, `same-sequence different-digest` (equivocation), `wrong environment`, `wrong chain`, `wrong genesis`, the PQC-verifier surrogate for `non-PQC suite`, and `corrupted local marker` rejected fail-closed with no live trust swap, no session eviction, no Run 055 sequence write, no v2 marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead`.
* The harness writes a source-level reachability proof (`reachability/src_grep.txt`) showing `validate_v2_lifecycle_transition` and `MutatingSurfaceMarkerV2Error::LifecycleRejected` are invoked from `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` (the Run 161 wiring); this **explicitly supersedes Run 160's "zero production caller" boundary**.
* Lifecycle scenarios that depend on the Run 159 local sub-class metadata (`02`=Retire, `03`=EmergencyRevoke) and on sub-class-prefixed persisted markers (`R6`–`R11`) remain source/test-only on the release binary today, because the persisted-marker sub-class prefix is not surfaced by the existing CLI; Run 159 source/test coverage and Run 161 source/test integration coverage continue to enforce those cases on release-built test binaries running the **same** `decide_marker_acceptance_v2` helper.

Out of scope for Run 162:

* MainNet enablement (this harness does not enable MainNet on any surface; MainNet peer-driven apply refusal is cited from Run 151 / Run 158 release-binary evidence).
* Governance / KMS / HSM implementation.
* Validator-set rotation.
* Wire-level encoding of `Retire` / `EmergencyRevoke` as distinct action bytes.
* Sub-class-metadata-driven Retire / EmergencyRevoke release-binary acceptance evidence and the sub-class-only rejection cases R6–R11.
* Full **C4** closure. **C5** remains open.

MainNet remains refused. Governance remains unimplemented. KMS / HSM remains unimplemented. Validator-set rotation remains open. Release-binary lifecycle evidence is deferred to Run 162. Full C4 and C5 remain open.
## Run 163 — source/test governance ratification authority verifier (no operator-visible CLI surface)

Run 163 is **source/test only**. It introduces a new pure typed governance ratification authority verifier module (`crates/qbind-node/src/pqc_governance_authority.rs`, `verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, `GovernanceAuthorityProof`, `GovernanceAuthorityClass {GenesisBound, EmergencyCouncil, OnChainGovernance}`, `GovernanceAuthorityVerificationOutcome`, `CombinedLifecycleGovernanceOutcome`, `GovernanceIssuerSignatureVerifier`, `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`) plus the matching test target (`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`, 32 tests). Operators have **no new CLI surface, no new flag, and no new runtime mutation primitive**. The on-wire byte set, the v2 marker schema, the sequence-file schema, the peer-candidate envelope schema, and the trust-bundle schema are all unchanged.

The verifier is **pure and non-mutating**: it performs no I/O, never reads or writes a sequence file, never touches the persisted v2 marker, never mutates a live trust bundle, and is **NOT** wired into mutating apply surfaces. The pure helper `validate_lifecycle_with_governance_authority` composes Run 159's typed v2 lifecycle validator with the new governance authority verifier into a single typed `CombinedLifecycleGovernanceOutcome` (`Accepted` / `LifecycleRejected` / `GovernanceRejected`) — also pure and non-mutating. Acceptance from this verifier carries **no side effect** and does NOT enable MainNet peer-driven apply.

The verifier models three authority classes: (1) **GenesisBound** — proof chains to the genesis-bound bundle-signing authority root; valid for DevNet/TestNet fixtures, future MainNet-compatible, but does NOT enable MainNet apply; (2) **EmergencyCouncil** — domain-bound emergency revocation authority; only authorizes `EmergencyRevoke` and does NOT bypass signature, genesis, chain, environment, lifecycle-action, candidate-digest, or sequence checks; (3) **OnChainGovernance** — placeholder, no proof format exists, **fail-closed** as `UnsupportedOnChainGovernance`. The typed reject surface explicitly carries `LocalOperatorConfigOnlyRejected` and `PeerMajorityProofRejected` so peer-majority / gossip-count and local-operator-config-only inputs are rejected as authority proofs at the type level. Run 163 does **not** enable MainNet peer-driven apply, does **not** implement a governance execution engine, does **not** integrate on-chain governance, does **not** implement KMS / HSM custody, does **not** implement validator-set rotation, and does **not** mutate any live trust state. **Release-binary governance verifier evidence is deferred to Run 164.** Operators MUST NOT interpret a Run 163 accept as authorization to enable MainNet apply or as a substitute for governance execution / on-chain attestation / KMS custody. **Full C4 is NOT claimed by Run 163; C5 remains OPEN.**
## Run 164 — release-binary EVIDENCE / BOUNDARY for the Run 163 governance authority verifier (no operator-visible CLI surface)

Run 164 is **release-binary evidence/boundary only**. Operators have **no new CLI surface, no new flag, and no new runtime behaviour**. The on-wire byte set, the v2 marker schema, the sequence-file schema, the peer-candidate envelope schema, and the trust-bundle schema are all unchanged.

Run 164 produces the strongest honest release-binary evidence currently possible for the Run 163 governance authority verifier (`qbind_node::pqc_governance_authority::verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`) and clearly determines that the verifier is **not** release-binary reachable from any production v2 surface today. The Run 164 source-level reachability proof (captured by the harness in `docs/devnet/run_164_governance_authority_release_binary/reachability/`) shows that none of the eight production release-binary v2 surfaces — startup `--p2p-trust-bundle` v2 (Run 137), reload-check validation-only (Run 132/133), local peer-candidate-check validation-only (Run 132/133), process-start reload-apply (Run 134/135/162), SIGHUP live-reload (Run 138/139), live inbound `0x05` validation-only (Run 142/143), peer-driven staged queue / drain-once (Run 148/150/151/152/153/158), and the lifecycle marker-decision path from Run 161/162 — calls the Run 163 governance verifier today. Operators therefore MUST NOT interpret any current `target/release/qbind-node` accept as a governance attestation; the v2 marker decision pipeline continues to enforce only the Run 130 v2 verifier, the Run 131/134/136/138/150/152 marker comparison primitives, and (since Run 161) the Run 159 lifecycle validator.

Run 164 captures the release-binary evidence that is honestly available: a release-built helper (`crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs`, built with `cargo build --release -p qbind-node --example run_164_governance_authority_fixture_helper`) mints the governance proof corpus covering A1 (GenesisBound Rotate), A2 (GenesisBound Revoke), A3 (GenesisBound EmergencyRevoke), A4 (EmergencyCouncil EmergencyRevoke), A5 (idempotent same proof / same candidate), and R1–R16, then invokes the verifier on every scenario. The release-binary harness `scripts/devnet/run_164_governance_authority_release_binary.sh` then asserts the expected typed-outcome class per scenario and runs the Run 163 / 161 / 159 / 157 / 152 / 150 / 148 / 142 / 134 / 138 regression suites and `cargo test -p qbind-node --lib pqc_authority` on the same checkout. The verdict is `partial-positive: release-binary fixture/evidence boundary captured; governance authority verifier not yet production-surface reachable`. The exact next required integration run is **Run 165 — compose `verify_governance_authority_proof` and `validate_lifecycle_with_governance_authority` into the existing shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`** (or an immediately-upstream typed pre-flight gate); Run 166 will then be the partner release-binary ENFORCEMENT evidence run for Run 165, mirroring the Run 161 / Run 162 partnership.

Run 164 does **not** enable MainNet peer-driven apply, does **not** implement a governance execution engine, does **not** integrate on-chain governance, does **not** implement KMS / HSM custody, does **not** implement validator-set rotation, and does **not** mutate any live trust state. The Run 161 wiring of the Run 159 lifecycle validator into `decide_marker_acceptance_v2` and Run 162's release-binary lifecycle ENFORCEMENT evidence both remain valid and untouched. MainNet peer-driven apply remains refused unconditionally (Run 151 / Run 158). Operators MUST NOT interpret a Run 164 accept as authorization to enable MainNet apply or as a substitute for governance execution / on-chain attestation / KMS custody. **Full C4 is NOT claimed by Run 164; C5 remains OPEN.**
## Run 165 — governance authority verification wired into the marker-decision path (SOURCE/TEST)

Run 165 is **source/test integration only**. Operators have **no new CLI surface, flag, or runtime behaviour change** to act on; the existing reload-apply, `--p2p-trust-bundle` startup, SIGHUP, and peer-driven drain marker preflights behave exactly as before.

What changed under the hood: the Run 163 governance authority verifier (`verify_governance_authority_proof`) is now **production-source reachable** from the shared v2 marker decision. The new helper `decide_v2_marker_acceptance_with_lifecycle_and_governance` composes, in order, (1) v2 marker anti-rollback, (2) Run 159 lifecycle validity, and (3) Run 163 governance authority validity (where the active `GovernanceProofPolicy` requires it). The decision stays pure/preflight; the marker is still persisted only after the existing `commit_sequence` boundary.

Chosen policy: `Rotate` / `Retire` / `Revoke` / `EmergencyRevoke` require a governance authority proof under `GovernanceProofPolicy::RequiredForLifecycleSensitive`; `ActivateInitial` is governance-optional. A missing required proof fails closed with `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { action }`. An invalid supplied proof fails closed with `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected(...)`. Both are non-mutating: no Run 070 apply, no live trust swap, no session eviction, no sequence write, no marker write.

**Documented wire schema-carrying gap:** the current v2 ratification / authority-marker wire material does **not** carry governance proof fields. Run 165 does **not** invent a schema. The production surfaces are therefore wired with the `NotRequired` policy + `GovernanceProofContext::Unavailable`, which is behaviour-preserving — governance verification is composed into the path and exercised whenever a proof is supplied, but a missing proof does not by itself refuse a transition. This keeps existing DevNet/TestNet peer-driven apply evidence valid with no governance-proof fixture changes. A future run that defines a proof-carrying schema (or supplies a proof out-of-band) passes `GovernanceProofContext::Supplied`.

Standing limitations (unchanged): MainNet peer-driven apply remains **refused** even with a valid governance proof; `OnChainGovernance` remains unsupported / fail-closed; governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. **Release-binary governance enforcement evidence is deferred to Run 166.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_165.md`.
## Run 166 — release-binary EVIDENCE / ENFORCEMENT for the Run 165 governance gate on real `target/release/qbind-node` (no operator-visible CLI surface)

Run 166 is the partner deliverable to Run 165: release-binary evidence / harness / release-built helper / docs only; **no production runtime source change, no new CLI flag, no new environment variable, no schema / wire / metric drift, no MainNet enablement**. Operators have no new operational surface in Run 166.

Source-level reachability (asserted by the harness): `decide_v2_marker_acceptance_with_lifecycle_and_governance`, `evaluate_governance_marker_gate`, `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing`, and `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRejected` are reachable from the four production callers `crates/qbind-node/src/pqc_live_trust_reload.rs` (SIGHUP marker pre-flight), `crates/qbind-node/src/pqc_peer_candidate_apply.rs` (peer-driven drain via `ProductionV2MarkerCoordinator`), and `crates/qbind-node/src/main.rs` (process-start reload-apply pre-flight + `--p2p-trust-bundle` startup pre-flight); the grep is recorded under `docs/devnet/run_166_governance_gate_release_binary_enforcement/reachability/`.

Release-binary `NotRequired` compatibility (live on `target/release/qbind-node`): `A1` reload-check (`--p2p-trust-bundle-reload-check`) accepts a v2 ratify@seq=1 candidate; `A2` reload-apply (`--p2p-trust-bundle-reload-apply-path`) accepts the same candidate end-to-end with Run 070 apply, Run 055 sequence commit, and a post-commit v2 marker write at `record_version=2`; `A2'` reload-apply accepts a Rotate@seq=2 candidate over a seeded v2-seq=1 marker — confirming that under the production policy a missing governance proof does NOT refuse a lifecycle-sensitive transition. Every accept asserts that no `GovernanceAuthorityRequiredButMissing` or `GovernanceAuthorityRejected` line appears on stderr.

Release-binary `RequiredButMissing` and `Rejected` fail-closed evidence (release-built helper): `crates/qbind-node/examples/run_166_governance_gate_release_binary_helper.rs` (built at `target/release/examples/run_166_governance_gate_release_binary_helper`, identity recorded in `provenance.txt`) links the same `decide_v2_marker_acceptance_with_lifecycle_and_governance` symbol `target/release/qbind-node` links and exercises seven scenarios `H1`–`H7` covering `NotRequired`+`Unavailable` accept (`H1`/`H2`), `RequiredForLifecycleSensitive`+`Unavailable` fail-closed `Err(GovernanceAuthorityRequiredButMissing { action: Rotate })` over a seeded v2-seq=1 marker with seed-marker bytes byte-for-byte unchanged after the reject (`H3`), `RequiredForLifecycleSensitive`+`Unavailable` accept on `ActivateInitial` (`H4`, governance-optional first activation), `RequiredForLifecycleSensitive`+`Supplied(GenesisBound, Rotate, good)` accept (`H5`), `RequiredForLifecycleSensitive`+`Supplied(GenesisBound, ActivateInitial, tampered)` fail-closed `Err(GovernanceAuthorityRejected(InvalidIssuerSignature ..))` with no marker write (`H6`), and a deterministic-pure-gate / non-MainNet-apply-enabling smoke (`H7`).

Operator note: `GovernanceAuthorityRequiredButMissing` is the typed error to expect under a future Run 167 schema-carrying run that flips the production policy to `RequiredForLifecycleSensitive`. Until that run lands, the four production callers continue to use `policy=NotRequired` + `context=Unavailable` and the gate is a behaviour-preserving identity on every release-binary path. Standing limitations (unchanged): MainNet apply remains refused unconditionally even with a valid governance proof; `OnChainGovernance` remains unsupported / fail-closed; governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. **The exact next required integration run is Run 167.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_166.md`, `docs/devnet/run_166_governance_gate_release_binary_enforcement/`.
## Run 167 — source/test governance-proof carrying schema for v2 authority sidecars

Operator surface: **no new CLI flag, no new runtime behaviour, no new error class on the existing release-binary surfaces**. Run 167 is **source/test schema/carrying work only** and does **not** change what `qbind-node` does at runtime today. The four production callers from Run 166 (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`, `main.rs` reload-apply preflight, `main.rs` startup `--p2p-trust-bundle` preflight) continue to invoke the Run 165 governance-aware helper at `policy=NotRequired` + `context=Unavailable`, exactly as Run 166 evidenced — no operator-visible behaviour changes.

What Run 167 adds at the schema level: an additive optional sibling field `governance_authority_proof` is now recognised on the v2 ratification sidecar JSON document. A v2 ratification sidecar without that field continues to parse exactly as before Run 167 and produces `GovernanceProofLoadStatus::Absent` from the new typed loader `qbind_node::pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`. A sidecar with a structurally well-formed sibling produces `GovernanceProofLoadStatus::Available(GovernanceAuthorityProof)`; a sidecar with a malformed sibling produces `GovernanceProofLoadStatus::Malformed(GovernanceProofWireParseError)` (typed reject variants `Json` / `UnknownSchemaVersion` / `EmptyRequiredField` / `EmptyIssuerSignature`) and the gate fails closed under any policy that requires a proof. The Run 132 dispatcher (`load_versioned_ratification_from_path`) remains unchanged — every existing operator workflow that reads v1 or v2 sidecars continues to work bit-for-bit.

Standing limitations (unchanged): MainNet peer-driven apply remains refused unconditionally even with a valid governance proof; `OnChainGovernance` remains unsupported / fail-closed; governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. **Release-binary proof-carrying enforcement evidence is deferred to Run 168.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_167.md`.
## Run 168 — release-binary evidence for the Run 167 governance-proof carrier on real `target/release/qbind-node`

Operator surface: **no new CLI flag, no new runtime behaviour, no new error class on the existing release-binary surfaces**. Run 168 is the release-binary partner of Run 167 and is **evidence/harness/release-built-helper/docs only**. The four production marker-decision callers (`pqc_live_trust_reload.rs` SIGHUP, `pqc_peer_candidate_apply.rs` peer-driven drain, `main.rs` reload-apply preflight, `main.rs` startup `--p2p-trust-bundle` preflight) continue to invoke the Run 165 governance-aware helper at `policy=GovernanceProofPolicy::NotRequired` + `context=GovernanceProofContext::Unavailable`, exactly as Run 166 evidenced — wiring those callers to consume the new typed loader is **explicitly deferred** to a follow-up wiring run. Pre-Run-167 v2 ratification sidecars (with no `governance_authority_proof` sibling) continue to load and apply bit-for-bit on real `target/release/qbind-node` (`A1` reload-check accept, `A2` reload-apply accept), proving the Run 167 strict back-compat claim end-to-end. The Run 167 typed loader's full `Absent` / `Available` / `Malformed` matrix and the Run 165 governance gate's `RequiredButMissing` / `Rejected` semantics are exercised on disk through a release-built helper that links the same production helper symbols `target/release/qbind-node` links (`crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`, 13 scenarios `H1–H13`). MainNet peer-driven apply remains refused unconditionally even with a structurally valid proof carrier. Standing limitations (unchanged): `OnChainGovernance` remains unsupported / fail-closed; governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_168.md`, `docs/devnet/run_168_governance_proof_carrier_release_binary/`.
## Run 169 — Production marker-decision callers consume the governance-proof loader (source/test)

Run 169 wires the Run 167 typed governance-proof loader (`load_v2_ratification_sidecar_with_governance_proof_from_path` plus the dispatcher `load_versioned_ratification_with_governance_proof_from_path` and the `GovernanceProofLoadStatus::{Absent, Available, Malformed}` shape) into the production v2 marker-decision callers via a single new library shim `qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`. The shim maps a `GovernanceProofLoadStatus` to a `GovernanceProofContext` (`Available → Supplied`, `Absent | Malformed → Unavailable`) and delegates to the existing Run 165 helper `decide_v2_marker_acceptance_with_lifecycle_and_governance` with no I/O. The shim is non-mutating; the Run 055 / Run 070 sequence-commit boundary continues to own persistence via `persist_accepted_v2_marker_after_commit_boundary`. Operator-visible CLI surface is unchanged: no new flag, no renamed flag, no behavior change for old no-proof v2 sidecars under the default `GovernanceProofPolicy::NotRequired`. The four updated production callers are the reload-check / reload-apply preflights (`Run105ReloadCheckContextData`, `preflight_run_134_v2_marker_decision`), the startup `--p2p-trust-bundle` preflight (`preflight_run_136_v2_marker_decision_for_startup`), the SIGHUP preflight (`preflight_sighup_v2_marker_decision`), and the peer-driven coordinator (`ProductionV2MarkerCoordinator::with_governance_proof_carrier`). Default policy remains `NotRequired` and the coordinator default load status remains `Absent`, so Runs 148 / 150 / 152 semantics are preserved bit-for-bit. The fixture verifier `fixture_issuer_signature_verifier()` remains the only verifier wired in production; KMS/HSM-backed verifier installation is deferred. The live inbound `0x05` path (Run 142) is intentionally not extended (per-peer envelopes do not carry the governance-proof sibling yet). Standing limitations (unchanged): `OnChainGovernance` remains unsupported / fail-closed; MainNet peer-driven apply remains refused; governance execution, KMS/HSM, and validator-set rotation remain unimplemented/open; release-binary production-surface proof-carrying evidence is deferred to Run 170; full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_169.md`.

## Run 170 — release-binary EVIDENCE for the Run 169 production-surface governance-proof loader wiring on real `target/release/qbind-node`

Run 170 is the release-binary counterpart to Run 169. It captures source-level reachability for the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` at each of the four production v2 marker-decision preflight call sites — reload-apply preflight in `crates/qbind-node/src/main.rs`, startup `--p2p-trust-bundle` preflight in `crates/qbind-node/src/main.rs`, SIGHUP preflight in `crates/qbind-node/src/pqc_live_trust_reload.rs`, and peer-driven coordinator in `crates/qbind-node/src/pqc_peer_candidate_apply.rs` — and evidences end-to-end that pre-Run-167 no-proof v2 sidecars continue to load and apply on real `target/release/qbind-node` (`A1` reload-check accept; `A2` reload-apply accept with sequence-before-marker preserved per Runs 055 / 070). Proof-carrying matrix coverage (valid GenesisBound Rotate accept under `Required`, idempotent re-accept, absent / malformed / wrong-authority-root / wrong-lifecycle-action / wrong-candidate-digest / wrong-authority-sequence / invalid-issuer-signature / `OnChainGovernance` / empty-issuer-signature fail-closed) is recorded through the Run 168 release-built helper replay (`H1`–`H13`) against the current checkout — the helper links the same production Run 167 loader + Run 169 dispatcher + Run 165 gate symbols `target/release/qbind-node` links — and through the Run 169 source/test integration suite (`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`, 39 tests). MainNet peer-driven apply (`R20`) remains refused on real `target/release/qbind-node` regardless of any governance-proof carrier; the surface refusal is owned by the Run 130 environment policy and unchanged by Runs 165 / 167 / 169. Honest limitation: the four production preflight call sites are wired to invoke the Run 169 shim with `GovernanceProofPolicy::NotRequired` by default; lifting the release-binary CLI to expose a configurable `RequiredForLifecycleSensitive` toggle is operator-control plumbing intentionally NOT in Run 170 scope and is deferred. No production source change in Run 170; no schema / wire / metric / sequence-file / trust-bundle drift; no MainNet enablement; no governance execution; no on-chain integration; no KMS/HSM; no validator-set rotation. Standing limitations (unchanged): `OnChainGovernance` remains unsupported / fail-closed; per-peer envelopes (Run 142 path) do not carry the governance-proof sibling and are not extended; full C4 and C5 remain open. Harness: `scripts/devnet/run_170_governance_proof_production_surface_release_binary.sh`. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_170.md` and `docs/devnet/run_170_governance_proof_production_surface_release_binary/{README.md,summary.txt}`.
## Run 171 — source/test hidden Required-policy operator selector wiring

Run 171 completes the operator-control plumbing that Run 170 declared as a deferred honest limitation, at the **source/test level only**. It adds a hidden, disabled-by-default selector for `GovernanceProofPolicy::RequiredForLifecycleSensitive`: a CLI flag `--p2p-trust-bundle-governance-proof-required` (declared with `clap` `hide = true`, so it does not appear in `--help`) OR-combined with the environment variable `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` (truthy values `1` / `true` / `yes` / `on`, case-insensitive; any other value, including empty / `0` / `false`, leaves the selector disabled). Either source alone is sufficient. The selector helpers `governance_proof_required_env_selector_enabled`, `governance_proof_policy_from_selector`, and `governance_proof_policy_from_cli_or_env` (`crates/qbind-node/src/pqc_governance_proof_surface.rs`) resolve the active policy, which is routed through the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` across the reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP (via the new `LiveReloadConfig::governance_proof_policy` consumed by `preflight_sighup_v2_marker_decision`), and peer-driven `ProductionV2MarkerCoordinator` surfaces. **Operator default remains `GovernanceProofPolicy::NotRequired`**: with neither the hidden flag nor the env var set, existing no-proof v2 sidecars continue to be accepted exactly as before. With the selector enabled, valid proof-carrying sidecars pass and missing / invalid proof sidecars fail closed; validation-only surfaces remain non-mutating and mutating surfaces persist the marker only after the Run 055 / Run 070 sequence-commit boundary. **MainNet peer-driven apply remains refused even with the Required selector enabled and a valid proof present** — the refusal is owned by the Run 130 environment policy and is unchanged by Run 171. Honest limitation: Run 171 is source/test only; release-binary Required-policy production-surface evidence is **deferred to Run 172**. Standing limitations (unchanged): governance execution remains unimplemented; `OnChainGovernance` remains unsupported / fail-closed; KMS/HSM-backed verifier installation remains deferred; validator-set rotation remains open; no wire / marker / sequence / trust-bundle / metric schema or behavior change. Full C4 and C5 remain open. Validation: Run 171 suite (35/35) and `cargo test -p qbind-node --lib` (1282) passing. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_171.md`.
Run 172 — release-binary EVIDENCE for the Run 171 hidden Required-policy selector on real `target/release/qbind-node`. Operators have **no new CLI surface and no new runtime behaviour** by default: the selector flag (`--p2p-trust-bundle-governance-proof-required`) and env var (`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) remain disabled-by-default and hidden from `--help`, and the default policy stays `GovernanceProofPolicy::NotRequired` so existing no-proof v2 ratification sidecars remain compatible. When an operator opts in to the selector (CLI or env), the mutating production preflight surfaces enforce `GovernanceProofPolicy::RequiredForLifecycleSensitive` and emit `Run 165: v2 authority-marker decision requires a governance authority proof for lifecycle action 'rotate' but none was available` on missing proof, with no `Run 070: trust-bundle candidate APPLIED`, no `[run-134] v2 authority-marker persisted`, no live trust mutation, no session eviction, no sequence write, and no marker write. Operators running on MainNet observe NO change: peer-driven apply remains refused under the Run 147 FATAL invariant even with the selector and a valid proof. Honest limitation preserved: validation-only surfaces (`--p2p-trust-bundle-reload-check`, `--p2p-trust-bundle-peer-candidate-check`) parse the proof sibling but do not gate on Required policy; Required-policy gating on validation-only is a deferred source-side task. Release-binary scope only: no production source change, no schema change, no metric change, no `OnChainGovernance` enablement (still fail-closed), no MainNet apply enablement, no autonomous apply, no apply on receipt, no peer-majority authority, no governance execution, no KMS/HSM, no validator-set rotation. Full C4 and C5 remain open. Validation: end-to-end `bash scripts/devnet/run_172_governance_required_policy_release_binary.sh` PASS; Run 171 / 169 / 167 / 165 suites and `cargo test -p qbind-node --lib pqc_authority` all passing. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_172.md`.
Run 173 — source/test wiring of the Run 171 governance-proof Required-policy selector into validation-only v2 surfaces. Operators see no new CLI surface and no new runtime behaviour by default: the Run 171 hidden flag `--p2p-trust-bundle-governance-proof-required` and env var `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` (truthy `1|true|yes|on`) remain disabled-by-default, the policy default remains `GovernanceProofPolicy::NotRequired`, and existing no-proof v2 ratification sidecars remain bit-for-bit accepted on the validation-only preflight. With the selector enabled, the validation-only `--p2p-trust-bundle-reload-check` and `--p2p-trust-bundle-peer-candidate-check` surfaces now resolve `GovernanceProofPolicy::RequiredForLifecycleSensitive` via `governance_proof_policy_from_cli_or_env(args.p2p_trust_bundle_governance_proof_required)` and route the typed `GovernanceProofLoadStatus` (already loaded by Run 169) through the new validation-only surface shim `pqc_governance_proof_surface::preflight_v2_validation_only_marker_check_with_governance_proof_load` into the Run 165 governance gate. Required-policy on validation-only: valid proof-carrying sidecars are accepted if anti-rollback, lifecycle, and governance checks pass; no-proof / malformed / invalid-proof sidecars fail closed with the typed `Run 165: ... requires a governance authority proof for lifecycle action 'rotate' but none was available` (or `... governance authority proof rejected by Run 163 verifier`) message and exit code 1. Validation-only surfaces remain strictly non-mutating: no marker write, no sequence write, no live trust swap, no session eviction, no Run 070 reload-apply call. Live inbound `0x05` continues to call `verify_marker_for_validation_only_v2` directly because the on-the-wire peer-candidate envelope schema does not carry the `governance_authority_proof` sibling; lifting live `0x05` to Required policy is documented and **deferred** because the Run 173 task explicitly forbids peer-candidate envelope schema changes. **Operator-facing default remains the Run 172 default**: existing operator runbooks for `--p2p-trust-bundle-reload-check` and `--p2p-trust-bundle-peer-candidate-check` continue to work unchanged. **Release-binary validation-only Required-policy production-surface evidence is deferred to Run 174**. MainNet peer-driven apply remains refused even with the Required selector enabled and a valid proof present. Standing limitations (unchanged): governance execution remains unimplemented; `OnChainGovernance` remains unsupported / fail-closed; KMS/HSM-backed verifier installation remains deferred; validator-set rotation remains open; no wire / marker / sequence / trust-bundle / peer-candidate-envelope schema change. Full C4 and C5 remain open. Validation: `cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests` (25/25); Run 171/169/167/165/163/161/159/157/152/150/148/142/138/134 suites all passing; `cargo test -p qbind-node --lib pqc_authority` passing. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_173.md`.
Run 174 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the validation-only v2 marker-decision production surfaces on real `target/release/qbind-node`. Operators see no new CLI surface and no new runtime behaviour by default: the validation-only `--p2p-trust-bundle-reload-check` surface continues to perform pure read-only preflight, never writes the authority-marker, never writes the persisted lifecycle sequence, never triggers Run 070 apply, never emits the `[run-134] reload-apply v2 ratification path SELECTED` line, never emits the `[run-134] v2 authority-marker persisted` line, never falls back to `--p2p-trusted-root`, never evicts sessions, and never calls into the live PQC dispatcher. Under default policy (`NotRequired`) — selector absent, env unset, env explicitly `false` / `0`, or env unrecognized — old no-proof Ratify@seq=1 sidecars and no-proof Rotate@seq=2 sidecars are accepted on `--p2p-trust-bundle-reload-check` exactly as before, with `[run-132] reload-check v2 authority-marker check passed: Accepted ... governance policy=NotRequired` and `[binary] Run 132: VERDICT=valid`, mirroring Run 174 scenarios A1 / A6a / A6b / R19. Under selector enabled (`--p2p-trust-bundle-governance-proof-required` or `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` / `=true` / `=yes` / `=on`), validation-only `--p2p-trust-bundle-reload-check` accepts a valid GenesisBound proof-carrying Rotate@seq=2 sidecar with `[run-132] reload-check v2 authority-marker check passed ... governance policy=RequiredForLifecycleSensitive` and `[binary] Run 132: VERDICT=valid`, and refuses every Required-policy violation with the typed message `Run 165: v2 authority-marker decision requires a governance authority proof for lifecycle action 'rotate' but none was available` (RequiredButMissing) or `Run 165: v2 authority-marker governance authority proof rejected by Run 163 verifier: <reason>` (Rejected — wrong-root / wrong-action / wrong-digest / wrong-sequence / invalid-signature / unsupported-suite / OnChainGovernance / malformed-proof) inside `[binary] Run 132: VERDICT=invalid (reload-check v2 authority-marker conflict; ...) Reason: <Display>`, with marker SHA pre==post, no sequence file post, no `Run 070: trust-bundle candidate APPLIED` line, no `[run-134] reload-apply v2 ratification path SELECTED` line, no `[run-134] v2 authority-marker persisted` line, no live trust mutation, no session eviction, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead` (Run 174 scenarios A2 / A3 / R1 / R2 / R3 / R4 / R8 / R9 / R10 / R11 / R-extra / R12 / R17 / R18). MainNet `--p2p-trust-bundle-peer-candidate-staging-enabled` peer-driven apply remains refused under the Run 147 FATAL invariant even with `--p2p-trust-bundle-governance-proof-required` and a valid proof-carrying Rotate sidecar (Run 174 scenario R20). Operators do not need to change any existing reload-check, reload-apply, SIGHUP, startup, or peer-driven workflow. Operators MUST NOT enable the selector on a network where governance-proof minting is not yet operational — under Required, every no-proof Rotate sidecar is rejected on validation-only with `RequiredButMissing`. The selector is hidden (`hide = true` in `cli.rs`), does not appear in `--help` output, has no default exposure, and remains opt-in. **Honest limitations preserved (Run 174 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling, so the live `0x05` proof-carrying surface remains OPEN — lifting it would require a peer-candidate envelope schema change, explicitly forbidden by `task/RUN_174_TASK.txt`; (ii) local `--p2p-trust-bundle-peer-candidate-check` release-binary scenarios (A4 / A5 / R15 / R16 in the Run 174 matrices) are deferred because the Run 172 fixture helper does not mint a peer-candidate envelope, but the validation-only peer-candidate-check production surface shares `preflight_run_132_validation_only_v2_marker_check` with reload-check by construction (Run 173 wiring), so policy resolution and gate composition are identical, and the Run 173 source-test integration suite covers both call sites at source level; (iii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first, masking the governance-gate refusal — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper. Run 174 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 055 path, no authority-marker write outside the existing post-commit boundary, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance-execution implementation, no on-chain governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. The release-binary harness is `scripts/devnet/run_174_validation_only_governance_required_policy_release_binary.sh`. The curated evidence archive is `docs/devnet/run_174_validation_only_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked; per-run logs / data / fixtures / exit_codes / hashes / inventories / grep summaries / reachability / test results / provenance / fixture manifest / scenario assertions / negative invariants are .gitignored mirroring Runs 153 / 155 / 158 / 160 / 162 / 164 / 166 / 168 / 170 / 172). Run 174 is release-binary evidence / harness / docs only and reuses the existing Run 172 release-built fixture helper without modification. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_174.md`.
Run 175 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the LOCAL `--p2p-trust-bundle-peer-candidate-check` validation-only v2 marker-decision production surface on real `target/release/qbind-node`; partner deliverable to Run 174 on the peer-candidate-check side, closing the Run 174-deferred peer-candidate-check release-binary cases (A4 / A5 / R15 / R16 in Run 174 numbering). Operators see no new CLI surface and no new runtime behaviour by default: the validation-only `--p2p-trust-bundle-peer-candidate-check` surface continues to perform pure read-only preflight (Run 077 / Run 107 envelope path → Run 132 preflight), never writes the authority-marker, never writes the persisted lifecycle sequence, never triggers Run 070 apply, never emits the `[run-134] reload-apply v2 ratification path SELECTED` line, never emits the `[run-134] v2 authority-marker persisted` line, never falls back to `--p2p-trusted-root`, never evicts sessions, and never calls into the live PQC dispatcher. Under default policy (`NotRequired`) — selector absent, env unset, env explicitly `false` / `0`, or env unrecognized — old no-proof Ratify@seq=1 sidecars and no-proof Rotate@seq=2 sidecars are accepted on local peer-candidate-check exactly as before, with `[run-132] peer-candidate-check v2 authority-marker check passed: ... governance policy=NotRequired` and `Run 077: VERDICT=validated`, mirroring Run 175 scenarios A1 / A4a / A4b / R17. Under selector enabled (`--p2p-trust-bundle-governance-proof-required` or `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` / `=true` / `=yes` / `=on`), local peer-candidate-check accepts a valid GenesisBound proof-carrying Rotate@seq=2 sidecar with `[run-132] peer-candidate-check v2 authority-marker check passed: v2-upgrade 1 -> 2 (validation-only; no marker persistence; no trust mutation; governance policy=RequiredForLifecycleSensitive)` and `Run 077: VERDICT=validated`, and refuses every Required-policy violation with the typed message `Run 165: v2 authority-marker decision requires a governance authority proof for lifecycle action 'rotate' but none was available` (RequiredButMissing) or `Run 165: v2 authority-marker governance authority proof rejected by Run 163 verifier: <reason>` (Rejected — wrong-root / wrong-action / wrong-digest / wrong-sequence / invalid-signature / unsupported-suite / OnChainGovernance / malformed-proof) inside `[binary] Run 132: VERDICT=invalid (peer-candidate-check v2 authority-marker conflict; ...) Reason: <Display>`, with marker SHA pre==post, no sequence file post, no `Run 070: trust-bundle candidate APPLIED` line, no `[run-134] reload-apply v2 ratification path SELECTED` line, no `[run-134] v2 authority-marker persisted` line, no live trust mutation, no session eviction, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead` (Run 175 scenarios A2 / A3 / A5 / R1 / R2 / R3 / R4 / R8 / R9 / R10 / R11 / R-extra / R12 / R15 / R16). MainNet `--p2p-trust-bundle-peer-candidate-staging-enabled` peer-driven apply remains refused under the Run 147 FATAL invariant even with `--p2p-trust-bundle-governance-proof-required` and a valid proof-carrying Rotate sidecar plus a valid local peer-candidate envelope (Run 175 scenario R18). The `consensus/` RocksDB sub-dir and the `run077-peer-candidate-scratch/` directory in the per-scenario data-dir are expected and benign (Run 098 ConsensusStorage open for activation epoch read + Run 077 scratch tempfile parent) and do NOT constitute marker or sequence persistence. Operators do not need to change any existing reload-check, reload-apply, SIGHUP, startup, peer-driven, or peer-candidate-check workflow. Operators MUST NOT enable the selector on a network where governance-proof minting is not yet operational — under Required, every no-proof Rotate sidecar is rejected on the local peer-candidate-check surface with `RequiredButMissing`. The selector is hidden (`hide = true` in `cli.rs`), does not appear in `--help` output, has no default exposure, and remains opt-in. **Honest limitations preserved (Run 175 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling, so the live `0x05` proof-carrying surface remains OPEN — Run 175 covers only the LOCAL `--p2p-trust-bundle-peer-candidate-check` binary surface where the proof-carrying ratification is supplied separately via `--p2p-trust-bundle-ratification`, and the live `0x05` envelope schema change is explicitly forbidden by `task/RUN_175_TASK.txt`; (ii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first, masking the governance-gate refusal — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper, mirroring the Run 174 / Run 172 deferral pattern. Run 175 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 055 path, no authority-marker write outside the existing post-commit boundary, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance-execution implementation, no on-chain governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. The release-binary harness is `scripts/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary.sh`. The new release-built fixture helper `crates/qbind-node/examples/run_175_peer_candidate_check_governance_required_policy_release_binary_helper.rs` mints the Run 172-shape ratification corpus PLUS Run 076-schema PeerCandidateEnvelope JSONs wrapping the existing candidate trust bundles, consuming only existing public APIs. The curated evidence archive is `docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked; per-run logs / data / fixtures / exit_codes / hashes / inventories / grep summaries / reachability / test results / provenance / fixture manifest / scenario assertions / negative invariants are .gitignored mirroring Runs 153 / 155 / 158 / 160 / 162 / 164 / 166 / 168 / 170 / 172 / 174). Run 175 is release-binary evidence / harness / fixture-helper / docs only. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_175.md`.
Run 176 — source/test governance-proof carrying for live inbound `0x05` peer-candidate envelopes. The live `0x05` `PeerCandidateWireEnvelopeV1` gains an additive optional `governance_authority_proof` field plus a `governance_proof_load_status()` helper. The validation-only path consumes the in-band carrier through the new library shim `preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier`, which delegates to the Run 173 validation-only shim. Operationally, no behaviour changes for operators today: the live `0x05` peer-candidate-check / peer-driven drain plumbing produced by Run 152 / 174 still consumes the Run 167 sidecar loader; the in-band carrier is purely additive. MainNet peer-driven apply remains refused unconditionally at the upstream binary gate. `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1|true|yes|on` (case-insensitive) and the `--p2p-trust-bundle-governance-proof-required` selector continue to control Required-policy on the validation-only surfaces. Run 176 is source/test only; release-binary evidence for the live `0x05` proof-carrying boundary is **deferred to Run 177**. No CLI flag added or renamed, no env var added, no marker / sequence-file / trust-bundle core / authority-marker / wire-frame / wire-domain-tag schema change. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_176.md`.
Run 178 — source/test-only typed `OnChainGovernance` proof format and fail-closed verifier boundary. Run 178 adds the new module `crates/qbind-node/src/pqc_onchain_governance_proof.rs` defining the typed `OnChainGovernanceProof` (bound to environment, chain_id, genesis_hash, authority_root_fingerprint + suite, governance_domain_id, governance_epoch, proposal_id, proposal_digest, proposal_outcome, quorum, threshold, lifecycle_action, active / new / revoked bundle-signing key fingerprints, authority_domain_sequence, candidate_v2_digest, freshness window, unique_decision_id replay nonce, proof_suite_id, proof_bytes), the policy gate `OnChainGovernanceProofPolicy::{Disabled (default), AllowFixtureSourceTest}`, the typed verifier outcome surface (`AcceptedOnChainGovernanceFixture`, `UnsupportedProductionOnChainGovernance`, `MainNetProductionProofUnavailable`, plus `WrongGovernanceDomain` / `WrongProposalDigest` / `WrongProposalOutcome` / `WrongGovernanceEpoch` / `ExpiredGovernanceProof` / `ReplayRejected` / `QuorumNotMet` / `ThresholdNotMet` / `InvalidGovernanceProof` / `UnsupportedGovernanceProofSuite` / `MalformedOnChainProof` / `LocalOperatorConfigOnlyRejected` / `PeerMajorityProofRejected` and the standard binding rejects), the pure non-mutating verifier `verify_onchain_governance_proof`, the combined lifecycle helper `validate_lifecycle_with_onchain_governance_proof`, and the additive optional wire carrier `OnChainGovernanceProofWire` with `ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION = 1` + parse errors `UnknownSchemaVersion` / `EmptyRequiredField` / `EmptyProofBytes` (all fail-closed at the wire boundary). Operator implications: (i) the default `OnChainGovernanceProofPolicy::Disabled` preserves Run 163 fail-closed behaviour — every `OnChainGovernance`-class proof on existing production surfaces continues to surface as `UnsupportedOnChainGovernance` (the Run 163 `verify_governance_authority_proof` is **not** modified); (ii) the new `AllowFixtureSourceTest` policy is wired at source/test only — Run 178 introduces no CLI flag, no environment variable, and no production caller invokes `verify_onchain_governance_proof`, so the runbook's existing `--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` selectors continue to operate exclusively on the Run 163 / 165 / 167 governance gate; (iii) MainNet `OnChainGovernance` proofs are refused as `MainNetProductionProofUnavailable` even under the `AllowFixtureSourceTest` policy — there is no policy or flag in Run 178 that can elevate a fixture proof into a MainNet apply; (iv) the wire surface is purely additive on the existing Run 167 sidecar carrier: pre-Run-178 sidecars without an `OnChainGovernance` sibling parse unchanged. The fixture proof suite `ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1` is a deterministic mock commitment over the bound fields and is **not** a real on-chain verifier; the reserved suite id `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` is rejected as `UnsupportedGovernanceProofSuite`. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, real on-chain proof verification, and MainNet enablement remain unimplemented and out of scope. Release-binary `OnChainGovernance` proof evidence is **deferred to Run 179**. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`.
Run 179 — release-binary `OnChainGovernance` proof boundary evidence for the Run 178 typed verifier. Run 179 closes the Run 178-deferred release-binary boundary by adding a release-built helper (`crates/qbind-node/examples/run_179_onchain_governance_proof_release_binary_helper.rs`, built via `cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper`) and a single-binary harness (`scripts/devnet/run_179_onchain_governance_proof_release_binary.sh`) that drives the full Run 178 A1–A7 / R1–R25 verifier corpus (incl. R6b / R11b / R12b / R16b / R17b–d / R24b / R25b–c sub-variants) end-to-end through `verify_onchain_governance_proof`, `validate_lifecycle_with_onchain_governance_proof`, and the additive `OnChainGovernanceProofWire` JSON round-trip in release mode, captures real `target/release/qbind-node --help` provenance, and records on every invocation a source-reachability proof showing the Run 178 verifier symbols have **zero** production callers under `crates/qbind-node/src/`. Operator implications: (i) Run 179 adds **no new operator-visible CLI flag, env knob, schema bump, wire shape, metric, or exit code** — the existing `--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` selectors continue to operate exclusively on the Run 163 / 165 / 167 governance gate, and the Run 178 verifier remains source/test- and helper-reachable only; (ii) the harness is **idempotent** — every invocation wipes `logs/`, `data/`, `exit_codes/`, `helper_evidence/`, `reachability/`, `test_results/`, `grep_summaries/`, `provenance.txt`, and `negative_invariants.txt` under `OUTDIR` (default: `docs/devnet/run_179_onchain_governance_proof_release_binary/`) and rewrites them, leaving only `README.md`, `summary.txt`, and `.gitignore` tracked, matching the Run 153 / 155 / 158 / 172 / 175 / 177 evidence-archive convention; (iii) the canonical `summary.txt` is a `NOT-YET-RUN` placeholder until the harness is invoked in an environment that can compile and exercise the release builds — operators should run the three reproducibility commands listed in the Run 179 README to populate it; (iv) the verdict is honestly recorded as `partial-positive: release-binary fixture/boundary evidence captured; OnChainGovernance verifier not yet production-surface reachable`, not `strongest-positive`; (v) Run 147 FATAL MainNet peer-driven apply refusal is preserved (helper R23 + binary `--help` denylist); (vi) the Run 178 additive wire shape round-trips in release mode (R24 + R24b) so pre-Run-178 Run 167 carriers without an `OnChainGovernance` sibling continue to parse exactly as before. The `qbind-node` binary surface is unchanged: no `onchain-governance` / `on-chain-governance` / `run-179` / `run_179` flag is surfaced via `--help`, and no Run 179 CLI flag exists at all (Run 179 introduces no flag — it cannot, by strict scope). KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
Run 180 — source/test-only wiring of the Run 178 typed `OnChainGovernance` proof verifier into production marker-decision composition behind a hidden DevNet/TestNet-only `AllowFixtureSourceTest` selector. Run 180 closes the Run 179-deferred source-reachability gap by adding a single new library module `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs` containing selector helpers, a typed `OnChainGovernanceMarkerDecisionOutcome` enum, the shared composed helper `compose_onchain_governance_marker_decision`, and seven named per-surface delegating wrappers (`reload_check_` / `reload_apply_` / `startup_p2p_trust_bundle_` / `sighup_` / `local_peer_candidate_check_` / `live_inbound_0x05_` / `peer_driven_drain_compose_onchain_governance_marker_decision`). Operator implications: (i) Run 180 adds exactly one **hidden** boolean CLI flag — `--p2p-trust-bundle-onchain-governance-fixture-allowed` (`hide = true`, `default_value_t = false`) — and reads exactly one environment variable — `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` (truthy: `1` / `true` / `TRUE` / `True` / `yes` / `YES` / `on` / `ON`). The flag is intentionally hidden and is reported absent from the captured `target/release/qbind-node --help` provenance from Run 179 because Run 180 is source/test only; operators **do not** see it in production help output. (ii) The production default policy on every surface is `OnChainGovernanceProofPolicy::Disabled`; when neither selector is engaged, every per-surface wrapper short-circuits with `PolicyDisabled` before any verifier work runs. (iii) The selector is **DevNet/TestNet fixture-only** by hard-coded short-circuit: any of the proof, trust-bundle environment domain, or candidate v2 record advertising `TrustBundleEnvironment::Mainnet` immediately resolves to `MainNetRefused` regardless of the policy state; Run 147 FATAL MainNet peer-driven apply refusal therefore holds unconditionally. (iv) Run 180 introduces **no schema bump, no wire shape, no metric, no exit code**, and does not change the v2 marker, sequence-file, trust-bundle core, or peer-candidate-envelope schemas. (v) The Run 180 helpers are composition-only — they perform no I/O on the production state, mutate no `LivePqcTrustState`, never extend the production replay set, never write a marker or sequence, and never invoke Run 070 apply. The selector-capture call site in `main.rs` reads the policy once at startup between the Run 151 refusal and Run 127 reset blocks and emits an audit banner only when armed. (vi) The release-binary boundary for the Run 180 wiring is **deferred to Run 181**; Run 180's verdict is honestly recorded as `partial-positive: source/test reachability captured; release-binary boundary deferred to Run 181`. The `qbind-node` binary surface in release mode is unchanged at the visible-help layer (the new flag is `hide = true`); operators should treat the Run 180 selector exactly like the Run 171 selector — explicit, hidden, DevNet/TestNet-only, never on by default. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, real on-chain proof verification on MainNet, autonomous apply, apply-on-receipt, and peer-majority authority all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.
Run 181 — release-binary `OnChainGovernance` production-surface fixture-policy selector evidence on real `target/release/qbind-node`. Run 181 adds an idempotent harness (`scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh`) and an evidence archive (`docs/devnet/run_181_onchain_governance_production_surface_release_binary/`) that exercise the real `target/release/qbind-node` binary against the hidden Run 180 selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed`, `hide = true`) and the environment variable `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` (truthy `{1, true, TRUE, True, yes, YES, on, ON}`), and capture release-mode helper evidence for the Run 178 typed verifier and the seven Run 180 per-surface named wrappers in `crates/qbind-node/src/pqc_onchain_governance_proof_surface.rs`. Operator-facing invariants captured by Run 181: (1) the production default — neither flag nor env var truthy — keeps `OnChainGovernanceProofPolicy::Disabled` on every surface and emits no banner; (2) the CLI flag and the env var both arm `AllowFixtureSourceTest` and cause `qbind-node` to emit the `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED (AllowFixtureSourceTest)` banner once on stderr at startup; (3) the selector is hidden and not surfaced via `qbind-node --help`; (4) MainNet peer-driven apply remains the Run 147 FATAL refusal even with the selector engaged. Operators should treat the armed banner as the canonical Run 180 / Run 181 selector-armed signal and continue to rely on `OnChainGovernanceProofPolicy::Disabled` as the production default; the selector is intended for DevNet / TestNet fixture evidence only and never enables MainNet peer-driven apply. Honest limitation recorded for operators: Run 180's binary-side wiring stops at the selector-capture / banner-emission site in `main.rs`; the per-surface `--p2p-trust-bundle-*` marker-decision call sites do not yet pass the resolved policy into the per-surface wrappers, so a real `qbind-node --p2p-trust-bundle-reload-check` / `--p2p-trust-bundle-reload-apply-path` invocation with the selector engaged today does NOT itself reach `compose_onchain_governance_marker_decision`. The strict next integration run identified by Run 181 will complete that wiring and capture mutating-scenario marker / sequence JSON+SHA before / after on at least one mutating surface. Reproducibility: `cargo build --release -p qbind-node --bin qbind-node && cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper && bash scripts/devnet/run_181_onchain_governance_production_surface_release_binary.sh`. The harness is idempotent and re-mints all per-run artifacts under the evidence archive on every invocation; only `README.md`, `summary.txt`, and `.gitignore` are tracked. No production source change. No MainNet apply enablement. No autonomous apply / apply-on-receipt / peer-majority authority. No real on-chain governance execution, no real on-chain proof verifier, no bridge / light-client integration, no KMS / HSM custody, no validator-set rotation. No marker / sequence-file / trust-bundle / wire / metric drift. No DummySig / DummyKem / DummyAead activation, no fallback to `--p2p-trusted-root`. Run 070 is not invoked in any Run 181 release-binary scenario. governance execution remains unimplemented, real on-chain proof verification remains unimplemented, KMS/HSM remains unimplemented, validator-set rotation remains open. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`.Run 182 — source/test production call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers. For operators, Run 182 is purely additive at the source / test layer: the new module `crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs` exposes seven named production call-site entries (one per Run 180 wrapper), and the production v2 marker-decision code path on each of the seven `--p2p-trust-bundle-*` / SIGHUP / live-`0x05` / peer-driven-drain surfaces now invokes the matching entry. Run 182 introduces zero new operator-visible CLI surface beyond the existing hidden Run 180 selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed` / `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`). Operators should continue to treat the Run 180 banner `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED (AllowFixtureSourceTest)` as the canonical selector-armed signal and continue to rely on `OnChainGovernanceProofPolicy::Disabled` as the production default. Run 182 is source/test production call-site wiring for OnChainGovernance fixture proofs. Default remains `OnChainGovernanceProofPolicy::Disabled`. `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet fixture-only. Real on-chain governance proof verification remains unimplemented. Governance execution remains unimplemented. Production MainNet OnChainGovernance remains unsupported / fail-closed. MainNet peer-driven apply remains refused. KMS/HSM remains unimplemented. Validator-set rotation remains open. Wire/schema blocker honestly recorded for operators: no current peer-candidate, SIGHUP-trigger, reload-apply trigger, startup-bundle, or live `0x05` payload format carries a typed `OnChainGovernanceProof`; adding it to any wire/schema is explicitly out of scope for Run 182. Therefore a real `qbind-node --p2p-trust-bundle-reload-check` / `--p2p-trust-bundle-reload-apply-path` / startup `--p2p-trust-bundle` / SIGHUP / live-`0x05` / peer-driven-drain invocation today, even with the selector armed, supplies `proof: None` at the wiring entry and the Run 180 wrapper returns `NoOnChainGovernanceProofSupplied` (or `PolicyDisabled` under the default), preserving the pre-Run-182 operator-visible behaviour bit-for-bit. The Run 182 acceptance / rejection matrix is captured in-process via the integration test suite `crates/qbind-node/tests/run_182_onchain_governance_production_callsite_wiring_tests.rs` (37 tests). Reproducibility: `cargo build -p qbind-node --lib && cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests`. No production source change beyond the additive call-site wiring described above. No MainNet apply enablement. No autonomous apply / apply-on-receipt / peer-majority authority. No real on-chain governance execution, no real on-chain proof verifier, no bridge / light-client integration, no KMS / HSM custody, no validator-set rotation. No marker / sequence-file / trust-bundle / wire / metric drift. No DummySig / DummyKem / DummyAead activation, no fallback to `--p2p-trusted-root`. Run 070 is not invoked in any Run 182 scenario. **Release-binary OnChainGovernance production-surface evidence covering the wired call sites is deferred to Run 183. Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`.Run 183 — release-binary evidence for the Run 182 production v2 marker-decision call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers on real `target/release/qbind-node`. Operationally, Run 183 introduces zero new operator-visible CLI surface, zero new env knob, zero new exit code, zero new metric, and zero new schema / wire / sidecar field beyond the Run 178 / 180 surface that operators already know about. Operators should continue to treat the Run 180 banner `[run-180] hidden DevNet/TestNet OnChainGovernance fixture-proof policy ARMED (AllowFixtureSourceTest)` as the canonical selector-armed signal and continue to rely on `OnChainGovernanceProofPolicy::Disabled` as the production default on every surface (`--p2p-trust-bundle-reload-check`, `--p2p-trust-bundle-reload-apply-*`, startup `--p2p-trust-bundle`, SIGHUP, `--p2p-trust-bundle-peer-candidate-check`, live `0x05`, and the Run 150 peer-driven apply drain). Run 183 reproducibility: `cargo build --release -p qbind-node --bin qbind-node`; `cargo build --release -p qbind-node --example run_179_onchain_governance_proof_release_binary_helper`; `bash scripts/devnet/run_183_onchain_governance_callsite_release_binary.sh`. The harness is idempotent (wipes and rewrites every per-run artefact under `docs/devnet/run_183_onchain_governance_callsite_release_binary/`; only `README.md`, `summary.txt`, and `.gitignore` are tracked, matching the Run 153 / 155 / 158 / 172 / 175 / 177 / 179 / 181 evidence-archive convention). Run 183 is release-binary OnChainGovernance production call-site evidence. Default remains `OnChainGovernanceProofPolicy::Disabled`. `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet fixture-only. Real on-chain governance proof verification remains unimplemented. Governance execution remains unimplemented. Production MainNet OnChainGovernance remains unsupported / fail-closed. MainNet peer-driven apply remains refused — the Run 182 peer-driven-drain callsite entry's surface-level `MainNetRefused` short-circuit fires ahead of the Run 180 verifier (Run 147 / 148 / 152 FATAL invariant). KMS/HSM remains unimplemented. Validator-set rotation remains open. Honest limitation recorded for operators: no current peer-candidate, SIGHUP-trigger, reload-apply trigger, startup-bundle, or live `0x05` payload format carries a typed `OnChainGovernanceProof`; adding such a field is explicitly out of scope for Run 183. Therefore a real `qbind-node` invocation with the selector engaged on a production CLI surface today reaches every Run 182 callsite entry with `proof: None`, the Run 180 wrapper short-circuits on `NoOnChainGovernanceProofSupplied`, and existing Run 130–182 surface behaviour is preserved bit-for-bit. The release-built helper exercises the typed-proof acceptance path A1–A9 / R1–R26 in release mode through the same library surface. **Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`.

## Run 184 update — source/test OnChainGovernance proof carrying through production v2 sidecar payload

Run 184 adds, at source/test level only, an additive optional
`onchain_governance_proof` sibling field on the existing v2 ratification
sidecar JSON wire that delivers a typed
`OnChainGovernanceProofWire` into the `proof` slot of
`OnChainGovernanceCallsiteContext` consumed by the seven Run 182
named production call-site entries. The sibling is parsed via the
same pre-extraction pattern used by Run 167's `governance_authority_proof`
carrier so unknown fields cannot poison the strict
`BundleSigningRatificationV2` parse, and legacy v2 sidecars without
the sibling continue to load identically with `proof: None`. Default
policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`; the hidden
`AllowFixtureSourceTest` policy is DevNet/TestNet fixture-only
behind the existing Run 181/183 selector. A valid carried fixture
proof reaches the production call-site context at source/test level
and is accepted only when the hidden selector is armed; an invalid
or malformed-payload sibling fails closed surface-uniformly *before*
the Run 182 entry runs, regardless of policy. MainNet peer-driven
apply remains refused even with a fully-valid DevNet fixture proof
carried through the new payload. Release-binary boundary evidence
covering the new payload-carrying surface is **deferred to Run 185**.
Real on-chain governance proof verification, governance execution,
KMS/HSM custody, validator-set rotation, bridge/light-client
integration, autonomous apply, and apply-on-receipt all remain
unimplemented. Full C4 and C5 remain open.

## Run 185 update — release-binary OnChainGovernance proof-payload-carrying accepted-proof evidence

Run 185 closes the Run 184-deferred release-binary boundary by
exercising on real `target/release/qbind-node` the additive optional
`onchain_governance_proof` sibling Run 184 introduced on the v2
ratification sidecar JSON wire and the seven Run 182 named
production call-site entries (`reload_check_callsite_`,
`reload_apply_callsite_`, `startup_p2p_trust_bundle_callsite_`,
`sighup_callsite_`, `local_peer_candidate_check_callsite_`,
`live_inbound_0x05_callsite_`,
`peer_driven_drain_callsite_onchain_governance_marker_decision`)
plus the typed argument bundle `OnChainGovernanceCallsiteContext`,
the additive selector builder
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders
`load_v2_ratification_sidecar_with_onchain_governance_proof_*` /
`parse_optional_onchain_governance_proof_sibling_from_json_value`,
the routing helpers
`route_loaded_onchain_governance_proof_to_*_callsite_decision`,
and the typed `OnChainGovernanceProofPayloadParseError` boundary.
On real `target/release/qbind-node`, Run 185 captures: the
production default — neither flag nor env var truthy — emitting no
`[run-180] ... policy ARMED (AllowFixtureSourceTest)` banner and
preserving `OnChainGovernanceProofPolicy::Disabled` on every
surface, with a v2 sidecar without the Run 184 sibling parsing
byte-for-byte identically to its pre-Run-184 form (A1 / R1); the
CLI selector arming `AllowFixtureSourceTest` exactly when supplied
(A2); the env selector arming across truthy variants
`{1, true, TRUE, True, yes, YES, on, ON}` and remaining disabled
across falsey variants `{0, false, FALSE, no, off, empty, garbage}`
(A3); real
`target/release/qbind-node --p2p-trust-bundle-reload-check
<sidecar-with-sibling>
--p2p-trust-bundle-onchain-governance-fixture-allowed --network
devnet` loading a v2 sidecar carrying a valid DevNet fixture-rotate
proof, extracting the additive Run 184 sibling, parsing the typed
`OnChainGovernanceProofWire`, and reaching the Run 182 reload-check
named callsite entry through the production
`preflight_run_132_validation_only_v2_marker_check` path with no
marker write, no sequence write, no live trust swap, no session
eviction, and no Run 070 call (A2_payload); the matching
`--p2p-trust-bundle-reload-apply-enabled
--p2p-trust-bundle-reload-apply-path <sidecar-with-sibling>`
invocation arming the selector, loading the sidecar, parsing the
sibling, and invoking the Run 182 reload-apply named callsite entry
through the production `preflight_run_134_v2_marker_decision` path
on the mutating surface, with the Run 070-honest
`ReloadApplyError::UnsupportedRuntimeContext` returned on a
non-long-running invocation and the matching accepted typed outcome
captured in release mode by the new Run 185 release-built helper
through the same library symbols, with Run 055
sequence-before-marker ordering preserved at the library layer
(A4 / A5); malformed sibling payloads (non-object, unknown_schema,
empty required field, empty proof bytes) failing closed at the
typed `OnChainGovernanceProofPayloadParseError` boundary BEFORE any
verifier or marker decision runs (R2 a–d); `qbind-node --help` not
surfacing the hidden flag (`hide = true`) and not surfacing a
`run-180` / `run-181` / `run-182` / `run-183` / `run-184` /
`run-185` / `onchain-governance-fixture` token; and MainNet
peer-driven apply remaining the Run 147 / 148 / 152 FATAL invariant
even with the selector engaged on `--network mainnet` AND a
fully-valid MainNet fixture-rotate proof carried in the v2 sidecar
via the Run 184 sibling, with the Run 182 peer-driven-drain
callsite entry's surface-level `MainNetRefused` short-circuit
layered ahead of the Run 180 verifier (R26). Through both
release-built helpers (the Run 179
`run_179_onchain_governance_proof_release_binary_helper` for the
verifier corpus and the new Run 185
`run_185_onchain_governance_payload_release_binary_helper` for the
Run 184 payload-carrying / call-site-routing corpus), Run 185
captures release-mode acceptance / rejection across the full
A1–A9 / R1–R26 matrix through the production library symbols
`verify_onchain_governance_proof`,
`validate_lifecycle_with_onchain_governance_proof`,
`compose_onchain_governance_marker_decision`, every Run 180
per-surface composed wrapper, every Run 182 named callsite entry
plus `OnChainGovernanceCallsiteContext` and
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders / routing helpers, and the typed
`OnChainGovernancePayloadCarryingDecisionOutcome::{MalformedOnChainGovernanceProofPayload,
Callsite}` boundary. Honest limitation: Run 184 added the additive
sibling on the v2 ratification sidecar JSON wire used by
reload-check / reload-apply / startup `--p2p-trust-bundle` / SIGHUP
only; the live `0x05` peer-candidate envelope and the peer-driven
drain inbound payload may not yet carry the typed OnChainGovernance
proof end-to-end on a real binary depending on tree state, and
where they do not, Run 185 captures the source-reachability for the
matching Run 182 named callsite entry through the release-built
helper in release mode AND records the boundary explicitly in the
archive's `mutation_proof.txt` / `no_mutation_proof.txt`. No
production source change. No MainNet apply enablement. No real
on-chain governance execution / no real on-chain proof verifier /
no bridge / light-client / KMS-HSM / validator-set rotation /
autonomous apply / apply-on-receipt / peer-majority authority. No
marker / sequence-file / trust-bundle / wire / metric drift beyond
Run 184's additive optional sibling. **Full C4 / C5 remain OPEN.**
Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`,
`scripts/devnet/run_185_onchain_governance_payload_release_binary.sh`,
`docs/devnet/run_185_onchain_governance_payload_release_binary/`.

## Run 186 update — source/test typed production OnChainGovernance verifier boundary

Run 186 introduces, at source/test level only, a typed verifier-kind
boundary in the new
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
module that cleanly separates fixture OnChainGovernance proof
verification (DevNet/TestNet evidence-only) from future real on-chain
governance proof verification (declared unavailable and fail-closed).
The boundary defines `OnChainGovernanceVerifierKind` (`Disabled` /
`FixtureSourceTest` / `ProductionUnavailable` /
`ProductionVerifierPlaceholder`), `OnChainGovernanceProofClass`
(`Fixture` / `Production`, derived from the proof suite ID via
`classify_onchain_governance_proof_class`),
`OnChainGovernanceVerifierPolicy` carrying the kind plus the Run 178
proof policy that the fixture path forwards to, and a typed
`OnChainGovernanceVerifierBoundaryOutcome` surface
(`AcceptedFixture(inner)` / `FixtureDisabled` /
`ProductionVerifierUnavailable` / `ProductionProofUnsupported` /
`ProductionProofMalformed{reason}` /
`MainNetProductionVerifierUnavailable` /
`FixtureProofRejectedAsMainNetProductionAuthority` /
`Run178Rejection(inner)`). The `OnChainGovernanceVerifier` trait has
four concrete implementations (`DisabledOnChainGovernanceVerifier`,
`FixtureSourceTestOnChainGovernanceVerifier`,
`ProductionUnavailableOnChainGovernanceVerifier`,
`ProductionVerifierPlaceholderOnChainGovernanceVerifier`), and the
pure entry points `verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof` are dispatched through
`dispatch_onchain_governance_proof_through_verifier_boundary`. Default
kind on every surface is `Disabled` and refuses every proof; the
fixture path is reachable only under `FixtureSourceTest` plus the
existing `AllowFixtureSourceTest` proof policy and short-circuits to
`FixtureProofRejectedAsMainNetProductionAuthority` whenever the trust
domain, candidate root, or proof environment is MainNet — so a fixture
proof can never masquerade as a production governance authority. Both
production verifier kinds always return `ProductionVerifierUnavailable`
(or `MainNetProductionVerifierUnavailable` on MainNet) regardless of
proof material. The boundary is purely additive: no wire, no v2 sidecar
JSON, no `OnChainGovernanceProofWire`, no marker, no sequence file, no
trust-bundle core schema, and no Run 070 / 130–185 invariant changes.
Source/test acceptance and rejection are exercised by
[`run_186_onchain_governance_production_verifier_boundary_tests`](
  ../../crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs)
covering the full A1–A7 / R1–R29 matrix from `task/RUN_186_TASK.txt`
plus extras for proof-class separation, all four verifier traits,
MainNet masquerade refusal, dispatcher determinism, and call-site
reachability (44 tests, all passing). MainNet peer-driven apply remains
refused (Run 147 FATAL invariant). The release-binary boundary for the
verifier kind is explicitly deferred to Run 187. Real on-chain
governance proof verification, governance execution, KMS/HSM custody,
validator-set rotation, bridge / light-client integration, autonomous
apply, apply-on-receipt, and peer-majority authority all remain
unimplemented. **Full C4 / C5 remain OPEN.** Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_186.md`,
`crates/qbind-node/src/pqc_onchain_governance_verifier.rs`,
`crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
## Run 187 update — release-binary OnChainGovernance production verifier-boundary evidence

Run 187 closes the Run 186-deferred release-binary boundary for the
typed production OnChainGovernance verifier surface added by
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs).
On real `target/release/qbind-node`, Run 187 captures: the production
default — neither `--p2p-trust-bundle-onchain-governance-fixture-allowed`
nor `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` truthy —
emitting no `[run-180]` armed banner and preserving
`OnChainGovernanceVerifierKind::Disabled` on every production surface
(A8 / R1); the CLI / env selectors each arming `AllowFixtureSourceTest`
and **not** enabling any production verifier (A1 / A2); existing Run 185
reload-check / reload-apply DevNet fixture-payload paths remaining
compatible under the Run 186 typed verifier-boundary contract (A3 /
A4); the Run 184 routing helpers continuing to short-circuit
malformed-sibling payloads at the typed
`OnChainGovernanceProofPayloadParseError` boundary BEFORE any Run 186
verifier-boundary dispatch (R20 / R22); MainNet peer-driven apply
remaining the Run 147 / 148 / 152 FATAL refusal even with the selector
engaged AND a fully-valid MainNet fixture proof carried in the v2
sidecar via the Run 184 sibling, with the Run 186
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
helper additionally encoding the rule at the typed verifier boundary
regardless of policy kind (R27); and `qbind-node --help` not surfacing
the hidden flag and not surfacing any `run-180`–`run-187` /
`onchain-governance-fixture` / `ProductionVerifier` / `KMS-HSM` /
`validator-set rotation` / `governance execution` token. Through both
release-built helpers — the Run 185
[`run_185_onchain_governance_payload_release_binary_helper`](
  ../../crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs)
for sidecar minting / payload-carrying compatibility evidence and the
new Run 187
[`run_187_onchain_governance_verifier_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs)
for the typed verifier-boundary corpus — Run 187 captures release-mode
acceptance / rejection across the full A1–A8 / R1–R29 matrix from
`task/RUN_187_TASK.txt` through the production library symbols
`pqc_onchain_governance_verifier::*`, including all four
`OnChainGovernanceVerifierKind` policy kinds dispatched against both
fixture-class and production-class proofs across DevNet/TestNet and
MainNet trust domains, all four `OnChainGovernanceVerifier` trait
impls' `kind()` / `verify(...)` surfaces, the proof-class classifier
and reserved-production-suite predicate, both pure entry points
(`verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof`), the dispatcher
(`dispatch_onchain_governance_proof_through_verifier_boundary`), and
the MainNet refusal helper, with bit-equality non-mutation evidence
captured for every rejected scenario by snapshotting candidate /
persisted state before and after a rejecting dispatch and asserting
bytewise equality. The release-binary harness
[`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`](
  ../../scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh)
records full provenance (qbind-node + helper SHA-256 / ELF Build IDs,
git commit, rustc / cargo versions), the source-reachability grep over
every Run 186 verifier-boundary symbol, the denylist invariants proven
empty (`MainNet apply ENABLED`, `production verifier enabled/active/wired`,
`autonomous apply`, `apply on receipt`, `peer-majority authority`,
`real on-chain governance proof claim`, `KMS/HSM enabled`,
`validator-set rotation claim`, `DummySig` / `DummyKem` / `DummyAead`,
`fallback to --p2p-trusted-root`, `schema/wire/metric drift`), and the
no-mutation / mutation-proof scaffolds; and re-runs the targeted
regression slice in release mode (run_186 / run_184 / run_182 /
run_180 / run_178 / run_176 / run_173 / run_171 / run_169 / run_167 /
run_165 / run_163 / run_161 / run_159 / run_157 / run_152 / run_150 /
run_148 / run_142 / run_134 / run_138, plus `--lib pqc_authority` and
`--lib pqc_onchain_governance_verifier`). Honest limitation: Run 187
still wires no real on-chain governance proof verifier — both
`OnChainGovernanceVerifierKind::ProductionUnavailable` and
`OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`
honestly route production-class proofs to
`ProductionVerifierUnavailable` on DevNet/TestNet and to
`MainNetProductionVerifierUnavailable` on MainNet, and route
fixture-class proofs to `ProductionProofUnsupported` regardless of
environment, encoding the honest unavailability and explicitly
forbidding fixture-as-MainNet-production-authority. No production
source change. No MainNet apply enablement. No real on-chain
governance execution / no real on-chain proof verifier / no bridge /
light-client / KMS-HSM / validator-set rotation / autonomous apply /
apply-on-receipt / peer-majority authority. No marker /
sequence-file / trust-bundle / wire / metric drift. No DummySig /
DummyKem / DummyAead activation, no fallback to `--p2p-trusted-root`.
No Run 050–186 invariant was changed. **Full C4 / C5 remain OPEN.**
Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`,
`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`,
`docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/`,
`crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs`.
## Run 188 — source/test KMS/HSM custody boundary

Run 188 introduces, at source/test level only, a typed authority-custody boundary
in the new `crates/qbind-node/src/pqc_authority_custody.rs` module:
`AuthorityCustodyClass` (`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
`Kms` / `Hsm` / `Unknown`), `AuthorityCustodyPolicy` (`Disabled` (default) /
`FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed` /
`ProductionCustodyRequired` / `MainnetProductionCustodyRequired`),
`AuthorityCustodyAttestation` (binds environment, chain_id, genesis_hash,
authority_root_fingerprint, bundle_signing_key_fingerprint,
governance_authority_class, lifecycle_action, candidate_digest,
authority_domain_sequence, custody_class, custody_key_id,
custody_attestation_digest, and optional freshness/expiry),
`AuthorityCustodyValidationOutcome` (typed accept-fixture /
accept-local-operator / production-custody-unavailable / KMS / HSM /
RemoteSigner unavailable / unknown / wrong-binding / malformed / expired /
key-id-mismatch / unsupported-suite / MainNet refusals / policy refusal),
the pure validator `validate_authority_custody_attestation`, and the pure
composition helper `validate_lifecycle_governance_and_custody`.

Operational rules surfaced at the typed Run 188 boundary:

* **No real KMS/HSM backend is implemented.** RemoteSigner / Kms / Hsm
  are placeholder symbols only; the validator fails them closed as
  unavailable regardless of policy or environment.
* **Fixture/local custody remains DevNet/TestNet evidence-only.** It is
  reachable only under the explicit `FixtureOnly` / `DevnetLocalAllowed` /
  `TestnetLocalAllowed` policies.
* **Fixture/local custody cannot satisfy MainNet production custody.**
  Trust-domain MainNet rejects fixture custody as
  `FixtureCustodyRejectedForMainNet` and local-operator custody as
  `LocalCustodyRejectedForMainNet`, ahead of the policy gate.
* **MainNet peer-driven apply remains refused** (Run 147 FATAL invariant)
  regardless of any custody attestation contents; encoded by the
  grep-verifiable helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`.
* **Governance execution remains unimplemented.** Run 188 does not call
  the Run 163 / 178 / 186 governance verifier; the calling surface threads
  the already-validated governance class into the composition helper.
* **Real on-chain proof verification remains unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved.
* **Validator-set rotation remains open.**
* **Release-binary custody-boundary evidence is deferred to Run 189.**
* **Full C4 remains open. C5 remains open.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_188.md` for the full A1–A8 /
R1–R29 acceptance matrix and validation-command list.
## Run 189 update — release-binary KMS/HSM authority-custody boundary evidence

Run 189 closes the Run 188-deferred release-binary boundary for the
typed authority-custody surface in
`crates/qbind-node/src/pqc_authority_custody.rs`. Run 189 is
release-binary evidence only: no production source line is changed,
no new CLI flag / env var / schema bump / wire shape / sidecar field
/ metric / exit code is introduced. Run 188 added no operator-visible
selector, so the operator-facing CLI surface from Run 187 is
preserved bit-identically — `target/release/qbind-node --help`
surfaces no `authority-custody` / `kms-hsm` / `remote-signer` /
`production custody` token, and the default
`--print-genesis-hash --env {devnet,testnet,mainnet}` invocations
emit no Run 188 custody enablement banner and no MainNet peer-driven
apply enablement claim. The existing Run 187 hidden fixture selector
`--p2p-trust-bundle-onchain-governance-fixture-allowed` (and the
matching `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
env var), armed on MainNet, still refuses MainNet peer-driven apply
and emits no Run 188 custody enablement banner.

The new release-built helper
`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`
exercises the Run 188 A1–A8 / R1–R29 corpus end-to-end in **release
mode** through the production library symbols
`pqc_authority_custody::*` —
`AuthorityCustodyClass`, `AuthorityCustodyPolicy`,
`AuthorityCustodyAttestation`, `AuthorityCustodyValidationOutcome`,
`LifecycleGovernanceCustodyOutcome`,
`validate_authority_custody_attestation`,
`validate_lifecycle_governance_and_custody`,
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`, and
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
Every `RemoteSigner` / `Kms` / `Hsm` attestation routes to the typed
`RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
outcome regardless of policy or environment; every
`ProductionCustodyRequired` / `MainnetProductionCustodyRequired`
policy routes to `ProductionCustodyUnavailable` /
`MainNetProductionCustodyUnavailable` (or the placeholder-specific
`*Unavailable`); every fixture / local-operator class on MainNet
routes to `FixtureCustodyRejectedForMainNet` /
`LocalCustodyRejectedForMainNet` ahead of the policy gate. Every
rejected scenario is captured with bit-equal candidate / persisted
snapshots before and after the rejecting custody validation; a
deterministic re-evaluation pass is asserted across the corpus.

Run 189 captures, on every run, a source-reachability proof under
`docs/devnet/run_189_authority_custody_boundary_release_binary/reachability/source_reachability.txt`
that records every production caller of every Run 188 custody symbol
under `crates/qbind-node/src/`, plus a denylist proof showing
no `KMS/HSM enabled`, no `remote signer enabled`, no `production
custody enabled/active/wired`, no `validator-set rotation`, no
`autonomous apply`, no `MainNet peer-driven apply ENABLED`, no
`apply on receipt`, no `peer-majority authority`, no `DummySig` /
`DummyKem` / `DummyAead`, and no `fallback to --p2p-trusted-root`
token is present in any captured log.

Honest limitation: Run 189 still wires no real KMS / HSM / cloud
KMS / PKCS#11 / remote-signer backend, no real on-chain governance
proof verifier, no governance execution engine, no validator-set
rotation, no autonomous apply, no apply-on-receipt, and no
peer-majority authority. The Run 147 / 148 / 152 FATAL MainNet
peer-driven apply refusal is preserved bit-identically at the
binary surface AND at the typed Run 188 boundary via the named
helper. **Full C4 is NOT claimed by Run 189; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_189.md`,
`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`,
`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`,
and `docs/devnet/run_189_authority_custody_boundary_release_binary/`
for the full release-binary scenario matrix, the regression test
slice, and the canonical PASS verdict.

## Run 190 — source/test authority-custody metadata carrying and production call-site wiring

Run 190 makes typed authority-custody attestation metadata reach
production payload / context paths and the production v2
marker-decision preflight composition at source / test level, while
preserving every Run 050–189 invariant byte-for-byte. The new module
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`
adds:

* `AuthorityCustodyAttestationWire` — an additive optional JSON
  sibling beside the existing v2 ratification sidecar material,
  bound to `AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION = 1`,
  parsed via the Run 167 / Run 184 sibling-extraction pattern so old
  no-custody payloads remain byte / parse compatible and a malformed
  custody sibling never poisons strict v2 parsing or the Run 167 /
  Run 184 sibling outcomes;
* `AuthorityCustodyLoadStatus::{Absent, Available, Malformed}` —
  the typed sibling load status returned to every call site;
* `load_v2_sidecar_with_governance_and_custody` — the combined
  Run 167 + Run 184 + Run 190 sidecar loader that returns the typed
  v2 ratification, governance-proof, OnChainGovernance, and custody
  load statuses each independently;
* `AuthorityCustodyCallsiteContext` — pairs the parsed (or absent /
  malformed) custody attestation with the active
  `AuthorityCustodyPolicy` (default `Disabled`), the expected
  lifecycle / governance class / candidate digest /
  authority-domain sequence / custody-key-id, the trust-domain
  environment, and `now_unix`;
* seven named per-surface routing helpers — reload-check,
  reload-apply preflight, startup `--p2p-trust-bundle` preflight,
  SIGHUP preflight, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain coordinator — each driving the Run 188
  `validate_lifecycle_governance_and_custody` composition;
* `AuthorityCustodyPayloadCarryingDecisionOutcome::{Accepted,
  MalformedPayload, RequiredButAbsent,
  NoCustodyAttestationSupplied, MainNetPeerDrivenApplyRefused,
  Callsite(...)}` with `is_accept()` / `is_bypassed()` /
  `is_reject()` predicates;
* grep-verifiable named helpers
  `mainnet_peer_driven_apply_remains_refused_under_run_190`,
  `peer_majority_cannot_satisfy_run_190_custody`, and
  `local_operator_config_alone_cannot_satisfy_mainnet_run_190_custody`.

Operationally the Run 190 carrier is **invisible by default**. There
is no new operator-visible CLI flag, env var, or selector. The
active `AuthorityCustodyPolicy` is supplied by the calling surface
and defaults to `Disabled` on every surface, exactly as in Run 188 /
Run 189. Old v2 ratification sidecars without an
`authority_custody_attestation` sibling continue to parse exactly as
before and produce the typed `NoCustodyAttestationSupplied` bypass,
which is deliberately distinct from `Accepted` so it cannot be
confused with a successful custody validation in operator runbooks
or audit logs.

Honest limitation: Run 190 wires no real KMS / HSM / cloud KMS /
PKCS#11 / remote-signer backend; every `RemoteSigner`, `Kms`, and
`Hsm` custody class still fails closed at the typed Run 188
validator with `RemoteSignerUnavailable` / `KmsUnavailable` /
`HsmUnavailable` regardless of attestation contents, schema
version, or sibling shape. Fixture / local-operator custody remains
DevNet/TestNet evidence-only and is rejected by symbol whenever the
trust-domain environment is MainNet, inheriting the Run 188
short-circuit. The Run 147 / 148 / 152 FATAL MainNet peer-driven
apply refusal is preserved bit-identically; the
peer-driven-drain routing helper layers a surface-level MainNet
check ahead of the Run 188 validator and returns
`MainNetPeerDrivenApplyRefused` even when a custody attestation
claims `Kms` or `Hsm`. Real on-chain governance proof verification,
governance execution, validator-set rotation, autonomous apply,
apply-on-receipt, and peer-majority authority all remain
unimplemented. **Release-binary custody-metadata evidence is
deferred to Run 191. Full C4 is NOT claimed by Run 190; C5 remains
OPEN.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_190.md` and
`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`
for the full A1–A10 / R1–R32 acceptance matrix, the serde / parse
compatibility evidence, the source-reachability invariants, and the
canonical PASS verdict.

## Run 191 update — release-binary authority-custody metadata carrying evidence

Run 191 closes the Run 190-deferred release-binary boundary for the
typed authority-custody payload-carrying surface in
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`,
composed over the Run 188 typed authority-custody boundary in
`pqc_authority_custody.rs`. Run 191 is release-binary evidence only:
no production source line is changed, no new CLI flag / env var /
schema bump / wire shape / sidecar field / metric / exit code is
introduced beyond Run 190's additive optional custody sibling. Run
190 added no operator-visible selector, so the operator-facing CLI
surface from Run 189 is preserved bit-identically —
`target/release/qbind-node --help` surfaces no `authority-custody` /
`kms-hsm` / `remote-signer` / `production custody` token, and the
default `--print-genesis-hash --env {devnet,testnet,mainnet}`
invocations emit no Run 190 custody enablement banner and no MainNet
peer-driven apply enablement claim. The existing Run 187 hidden
fixture selector `--p2p-trust-bundle-onchain-governance-fixture-allowed`
(and the matching `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
env var), armed on MainNet, still refuses MainNet peer-driven apply
and emits no Run 190 custody payload-carrying enablement banner.

The new release-built helper
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`
exercises the Run 190 A1–A10 / R1–R32 corpus end-to-end in **release
mode** through the production library symbols
`pqc_authority_custody_payload_carrying::*` —
`AuthorityCustodyAttestationWire`, `AuthorityCustodyClassWire`,
`GovernanceAuthorityClassWire`, `AuthorityCustodyLoadStatus`
(`Loaded` / `Absent` / `Malformed { … }`),
`parse_optional_authority_custody_attestation_sibling_from_json_value`,
`AuthorityCustodyCallsiteContext`,
`callsite_context_for_authority_custody`,
`AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven
per-surface routing helpers
(`route_loaded_authority_custody_attestation_to_reload_check_callsite_decision`,
`..._reload_apply_callsite_decision`,
`..._startup_p2p_trust_bundle_callsite_decision`,
`..._sighup_callsite_decision`,
`..._local_peer_candidate_check_callsite_decision`,
`..._live_inbound_0x05_callsite_decision`,
`..._peer_driven_drain_callsite_decision`),
and `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`,
composed with the Run 188 typed-boundary symbols
`validate_authority_custody_attestation`,
`validate_lifecycle_governance_and_custody`,
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`, and
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
Every `RemoteSigner` / `Kms` / `Hsm` attestation — whether
constructed in-process or wire-carried through the Run 190 sibling
and parsed back — fails closed with the typed `RemoteSignerUnavailable`
/ `KmsUnavailable` / `HsmUnavailable` outcome regardless of policy or
environment; every `ProductionCustodyRequired` /
`MainnetProductionCustodyRequired` policy fails closed with the typed
`ProductionCustodyUnavailable` / `MainNetProductionCustodyUnavailable`;
every fixture / local-operator class on MainNet routes to
`FixtureCustodyRejectedForMainNet` / `LocalCustodyRejectedForMainNet`
ahead of the policy gate even when wire-carried. Legacy / no-custody
payloads (sibling absent) under default `Disabled` route through the
seven Run 190 routing helpers without producing schema or wire drift.
Malformed sibling JSON (non-object, missing-field, unknown-class,
expired, unknown-schema) is parsed to
`AuthorityCustodyLoadStatus::Malformed { … }` and routed by every
per-surface helper to `Callsite { custody_outcome:
CustodyAttestationMalformed }` (or to peer-driven-drain
`MainNetPeerDrivenApplyRefused` where applicable) without panic,
allocation surprise, or drift. Every rejected scenario is captured
with bit-equal candidate / persisted snapshots before and after the
rejecting routing call; a deterministic re-evaluation pass is
asserted across the corpus.

Run 191 captures, on every run, a source-reachability proof under
`docs/devnet/run_191_authority_custody_payload_release_binary/reachability/source_reachability.txt`
that records every production caller of every Run 188 / Run 190
authority-custody and payload-carrying symbol under
`crates/qbind-node/src/`, plus a denylist proof showing no
`KMS/HSM enabled`, no `remote signer enabled`, no `production custody
enabled/active/wired`, no `validator-set rotation`, no `autonomous
apply`, no `MainNet peer-driven apply ENABLED`, no `apply on receipt`,
no `peer-majority authority`, no `DummySig` / `DummyKem` / `DummyAead`,
and no `fallback to --p2p-trusted-root` token is present in any
captured log.

Honest limitation: Run 191 still wires no real KMS / HSM / cloud KMS
/ PKCS#11 / remote-signer backend, no real on-chain governance proof
verifier, no governance execution engine, no validator-set rotation,
no autonomous apply, no apply-on-receipt, and no peer-majority
authority. The Run 147 / 148 / 152 FATAL MainNet peer-driven apply
refusal is preserved bit-identically at the binary surface AND at the
typed Run 190 payload-carrying boundary via
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
(which composes
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`).
**Full C4 remains OPEN; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`,
`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`,
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`,
and `docs/devnet/run_191_authority_custody_payload_release_binary/`
for the full release-binary scenario matrix, the regression test
slice, and the canonical PASS verdict.

## Run 192 — source/test hidden authority-custody policy selector and production preflight integration

Run 192 adds, at source/test level only, the smallest hidden selector
surface that lets a DevNet/TestNet evidence preflight context
explicitly choose an `AuthorityCustodyPolicy` variant and threads the
resolved policy into the seven Run 190 production v2 marker-decision
preflight contexts (reload-check, reload-apply, startup
`--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live
inbound `0x05`, peer-driven drain). The default
`AuthorityCustodyPolicy::Disabled` is preserved bit-for-bit; legacy
no-custody payloads remain accepted exactly as in Run 190 / Run 191.

The new module
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`
exposes the env-var name
`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`, the canonical
selector tags (`disabled` / `fixture-only` / `devnet-local-allowed` /
`testnet-local-allowed` / `production-custody-required` /
`mainnet-production-custody-required`), the typed
`AuthorityCustodyPolicySelectorParseError`, the pure parsers
`authority_custody_policy_from_selector` /
`authority_custody_policy_env_selector` /
`authority_custody_policy_from_cli_or_env`, and seven thin
per-surface preflight wrappers
(`preflight_v2_marker_authority_custody_for_*`) that bind the
resolved policy into the Run 190 `AuthorityCustodyCallsiteContext`
and dispatch to the matching Run 190
`route_loaded_authority_custody_attestation_to_*_callsite_decision`
helper. The matching hidden CLI flag
`--p2p-trust-bundle-authority-custody-policy <POLICY>` (clap
`hide = true`) is added on `crates/qbind-node/src/cli.rs` as
`Option<String>`. Either source is sufficient to choose a non-default
policy; CLI wins when both are present; both absent preserves
`Disabled`; invalid values are surfaced as a typed parse error and
never silently downgrade to `Disabled`.

Run 192 is **source/test only**. No real KMS / HSM / cloud-KMS /
PKCS#11 / remote-signer backend is implemented. KMS / HSM /
RemoteSigner placeholders remain fail-closed via the Run 188
validator regardless of selector. Fixture / local custody remains
DevNet/TestNet evidence-only and cannot satisfy MainNet production
custody. The Run 147 / 148 / 152 FATAL MainNet peer-driven apply
refusal at the peer-driven apply surface remains intact regardless
of selector, attestation contents, or policy — including with
`mainnet-production-custody-required` and metadata claiming
KMS/HSM/RemoteSigner. Governance execution remains unimplemented.
Real on-chain proof verification remains unimplemented. Validator-set
rotation remains open. Release-binary custody-policy selector
evidence is deferred to **Run 193**. Full C4 remains OPEN. C5
remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_192.md`,
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`, and
`crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`
for the full A1–A10 / R1–R29 source/test scenario matrix and the
canonical PASS verdict.

## Run 193 — release-binary authority-custody policy selector evidence

Run 193 closes the Run 192-deferred release-binary boundary for the
hidden authority-custody policy selector. Operators get **no new CLI
surface** in Run 193: the selector and env var were already added in
Run 192, the selector remains hidden in normal `--help`, and the
default behaviour with neither selector set remains
`AuthorityCustodyPolicy::Disabled` — bit-for-bit identical to Run
191's surface contract. What changes in Run 193 is the **evidence**
shape: real `target/release/qbind-node` is exercised across eight
release-binary scenarios (S1 hidden flag absent from `--help`; S2
default DevNet startup with neither CLI nor env selector set; S3 env
`fixture-only` on DevNet; S4 CLI `devnet-local-allowed` on DevNet; S5
CLI-over-env precedence env=`fixture-only` + CLI=`disabled` on DevNet;
S6 invalid CLI value `garbage` rejected fail-closed by clap's typed
parser; S7 env+CLI both `mainnet-production-custody-required` on
MainNet startup; S8 Run 192 selector + Run 187 hidden fixture
selector both armed on MainNet) and a new release-built helper
`crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`
drives the Run 192 A1–A12 / R1–R29 selector + preflight wrapper
corpus end-to-end in **release mode** through the production library
symbols `pqc_authority_custody_policy_surface::*` (including the env
const, the typed `AuthorityCustodyPolicySelectorParseError`, the
three parsers, and the seven `preflight_v2_marker_authority_custody_for_*`
wrappers) layered above Run 190 `pqc_authority_custody_payload_carrying::*`
and Run 188 `pqc_authority_custody::*`.

Operationally, Run 193 reaffirms: hidden CLI flag remains hidden;
either CLI or env selector activates a non-default
`AuthorityCustodyPolicy` without drifting any existing banner; CLI
wins when both selectors are present; invalid values fail closed at
the typed parser; fixture / local-operator custody remains DevNet /
TestNet evidence-only and cannot satisfy MainNet production custody;
KMS / HSM / RemoteSigner placeholders remain fail-closed under every
policy regardless of environment; MainNet peer-driven apply remains
the Run 147 / 148 / 152 FATAL refusal even with
`mainnet-production-custody-required` armed on env+CLI together with
the Run 187 fixture selector and metadata claiming KMS/HSM. Run 193
introduces no production source change, no CLI / env / sidecar /
authority-marker / sequence-file / trust-bundle core / wire / metric
/ schema change, no real KMS / HSM / cloud-KMS / PKCS#11 /
remote-signer backend, no real on-chain governance proof verifier, no
governance execution, no validator-set rotation, no MainNet
peer-driven apply enablement, no autonomous apply, no apply-on-
receipt, and no peer-majority authority. Full C4 remains OPEN. C5
remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_193.md`,
`docs/devnet/run_193_authority_custody_policy_release_binary/`,
`scripts/devnet/run_193_authority_custody_policy_release_binary.sh`,
and `crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`.

## Run 194 — source/test RemoteSigner production-custody interface boundary

Run 194 is **source/test RemoteSigner production-custody interface
boundary** work. It replaces the vague Run 188
`AuthorityCustodyClass::RemoteSigner` placeholder with a precise,
typed remote-signer custody boundary in
`crates/qbind-node/src/pqc_remote_authority_signer.rs`:
`RemoteSignerIdentity`, `RemoteSignerRequest` (deterministic
domain-separated SHA3-256 `canonical_digest`), `RemoteSignerResponse`,
a `RemoteSignerPolicy` (`Disabled` default / `FixtureLoopbackAllowed`
/ `ProductionRemoteSignerRequired` /
`MainnetProductionRemoteSignerRequired`), a precise
`RemoteSignerOutcome` reject taxonomy, a pure `RemoteAuthoritySigner`
trait, a DevNet/TestNet-only `FixtureLoopbackRemoteSigner`, a
fail-closed `ProductionRemoteSigner`, the pure `validate_remote_signer`
verifier, custody-class routing
(`validate_remote_signer_for_custody_class`), and the pure
`validate_lifecycle_governance_custody_and_remote_signer` composition
helper layered over the Run 188 boundary.

Operator-relevant invariants:

* The default policy is `RemoteSignerPolicy::Disabled`; every request
  fails closed until a policy is explicitly selected.
* **No real RemoteSigner backend is implemented.** There is no
  networked signer service, no real KMS, no real HSM, no cloud-KMS
  integration, and no PKCS#11 integration.
* The fixture loopback remote signer is **DevNet/TestNet source/test
  only**; it is rejected on a MainNet trust domain
  (`FixtureLoopbackRejectedForMainNet`).
* Production RemoteSigner remains **unavailable / fail-closed**: the
  `ProductionRemoteSigner` is callable but always returns
  `ProductionRemoteSignerUnavailable`.
* A local operator key and a peer majority can never satisfy a remote
  signer policy.
* RemoteSigner does **not** enable MainNet peer-driven apply. The
  Run 147 / 148 / 152 FATAL MainNet refusal remains intact even when a
  fixture loopback remote signer signs successfully, via
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`
  and the composition helper's MainNet preflight short-circuit.
* Validation-only and mutating-preflight rejection paths produce no
  mutation: no Run 070 call, no live trust swap, no session eviction,
  no sequence write, and no marker write.
* KMS/HSM remain unimplemented. Governance execution remains
  unimplemented. Real on-chain proof verification remains
  unimplemented. Validator-set rotation remains open.
* Release-binary RemoteSigner boundary evidence is deferred to
  **Run 195**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_194.md`,
`crates/qbind-node/src/pqc_remote_authority_signer.rs`, and
`crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`
for the full A1–A7 / R1–R31 source/test scenario matrix and the
canonical PASS verdict.

## Run 195 — release-binary RemoteSigner production-custody boundary evidence

Run 195 is **release-binary evidence** for the Run 194 RemoteSigner
production-custody interface boundary. It exercises the Run 194 typed
RemoteSigner surface on real `target/release/qbind-node` and through the
release-built helper
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`,
which drives the Run 194 A1–A7 / R1–R31 corpus end-to-end in **release
mode** through the production library symbols
`pqc_remote_authority_signer::*` layered above
`pqc_authority_custody_policy_surface::*`,
`pqc_authority_custody_payload_carrying::*`, and
`pqc_authority_custody::*`. Reproduce with:

```
bash scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh
```

Operator-relevant invariants (release-binary):

* Run 194 added **no new CLI flag and no new env var** — it is a pure
  library boundary. Real `target/release/qbind-node --help` exposes no
  `RemoteSigner enabled` / `RemoteSigner backend connected` / `remote
  signer production active` claim, no KMS/HSM active claim, no
  governance execution claim, and no validator-set rotation claim (S1).
* `--print-genesis-hash --env {devnet,testnet,mainnet}` emits no
  RemoteSigner enablement banner and no MainNet peer-driven apply
  enablement claim (S2–S4).
* The Run 193 hidden authority-custody policy selector and the
  governance fixture proof path remain compatible at the binary surface
  (S5, S6).
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with the Run 193 `mainnet-production-custody-required`
  selector and the governance fixture selector both armed (S4, S7).
* The release-built helper records `verdict: PASS` (`total_fail: 0`)
  across the scenario corpus, the canonical-digest binding table, the
  policy-mode table, the custody-class routing table, the composition
  table, the refusal-helper table, the no-mutation snapshot table, and
  the determinism re-evaluation table.
* **No real RemoteSigner backend is implemented**; no networked signer
  service; fixture loopback RemoteSigner remains DevNet/TestNet
  evidence-only; production RemoteSigner remains unavailable/fail-closed;
  local operator keys and peer-majority/gossip cannot satisfy
  RemoteSigner policy.
* KMS/HSM remain unimplemented (no cloud KMS, no PKCS#11). Governance
  execution remains unimplemented. Real on-chain proof verification
  remains unimplemented. Validator-set rotation remains open. Full C4
  remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_195.md`,
`docs/devnet/run_195_remote_authority_signer_boundary_release_binary/`,
`scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh`,
and
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`
for the captured release-binary scenarios, provenance, denylist, and the
canonical PASS verdict.

## Run 196 — source/test RemoteSigner attestation payload/carrying and production-context wiring

Run 196 is **source/test RemoteSigner attestation payload/carrying and
production-context wiring**. It adds source- and test-level support for
carrying RemoteSigner identity / request / response attestation material
through the production payload and production-context paths and routing it
into the Run 194 lifecycle + governance + custody + RemoteSigner
composition, via the new module
`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs` and the test
suite `crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.
The carrier is an **additive optional** JSON sibling
(`remote_signer_attestation`) on the v2 ratification sidecar, mirroring
the Run 190 authority-custody payload/carrying pattern. Reproduce with:

```
cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests
```

Operator-relevant invariants (source/test):

* Run 196 adds **no new CLI flag and no new env var** — it is a pure
  library boundary. Legacy no-RemoteSigner payloads remain
  byte-compatible and parse as `Absent`.
* RemoteSigner material can be carried through the production payload and
  production-context paths at source/test level and routed into the seven
  per-surface helpers (`reload_check`, `reload_apply`,
  `startup_p2p_trust_bundle`, `sighup`, `local_peer_candidate_check`,
  `live_inbound_0x05`, `peer_driven_drain`).
* Malformed / invalid / unsupported-schema RemoteSigner material fails
  closed (`RemoteSignerLoadStatus::Malformed`) in front of the verifier;
  validation-only surfaces remain non-mutating and mutating-preflight
  rejection produces no mutation.
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with fixture loopback RemoteSigner material supplied.
* **No real RemoteSigner backend is implemented**; fixture loopback
  RemoteSigner remains DevNet/TestNet source/test only; production
  RemoteSigner remains unavailable/fail-closed.
* KMS/HSM remain unimplemented. Governance execution remains
  unimplemented. Real on-chain proof verification remains unimplemented.
  Validator-set rotation remains open. Release-binary RemoteSigner
  payload/carrying evidence is deferred to **Run 197**. Full C4 remains
  OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_196.md`,
`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`, and
`crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.
## Run 197 — release-binary RemoteSigner attestation payload/carrying and production-context evidence

Run 197 is **release-binary evidence** for the Run 196 RemoteSigner
attestation payload/carrying and production-context wiring. It exercises
the Run 196 module
`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs` against real
`target/release/qbind-node` and through the release-built helper
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.
Reproduce with:

```
cargo build --release -p qbind-node --bin qbind-node
bash scripts/devnet/run_197_remote_signer_payload_release_binary.sh
```

Operator-relevant invariants (release-binary):

* Run 197 makes **no production source change** (release example helper +
  release harness + docs only) and **no new CLI flag and no new env var** —
  the `--help` surface advertises no RemoteSigner / KMS / HSM /
  governance-execution / validator-set-rotation claim and no
  `remote_signer_attestation` field. Legacy no-RemoteSigner payloads remain
  byte-compatible and parse as `Absent`.
* The release-built helper drives the Run 196 A1–A10 / R1–R34 corpus in
  release mode through the seven per-surface routing helpers and asserts a
  typed `RemoteSignerPayloadCarryingDecisionOutcome` for every scenario,
  ending in `verdict: PASS`.
* Malformed / invalid / unsupported-schema RemoteSigner material fails
  closed in front of the verifier; validation-only surfaces remain
  non-mutating and mutating-preflight rejection produces no mutation
  (no Run 070 apply, no sequence/marker write, no `.tmp` residue, no
  fallback to `--p2p-trusted-root`, no DummySig/DummyKem/DummyAead).
* Fixture loopback RemoteSigner remains DevNet/TestNet evidence-only;
  production RemoteSigner remains unavailable/fail-closed.
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with fixture loopback RemoteSigner material and with the
  Run 193 `mainnet-production-custody-required` selector armed.
* **No real RemoteSigner backend is implemented.** KMS/HSM remain
  unimplemented. Governance execution remains unimplemented. Real on-chain
  proof verification remains unimplemented. Validator-set rotation remains
  open. Existing custody/governance proof paths remain compatible. Full C4
  remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_197.md`,
`docs/devnet/run_197_remote_signer_payload_release_binary/`,
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
and `scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.
## Run 198 — source/test hidden RemoteSigner policy selector and production preflight integration

Run 198 is **source/test hidden RemoteSigner policy selector and
production preflight integration**. It adds a hidden,
disabled-by-default RemoteSigner policy selector and wires the resolved
`RemoteSignerPolicy` into all seven production v2 marker-decision
preflight contexts through the Run 196 RemoteSigner payload/call-site
routing layer. The selector module is
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` with tests in
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.

Reproduce with:

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests
cargo test -p qbind-node --lib pqc_remote_signer_policy_surface
```

Operator-relevant invariants:

* The selector is exposed via one **hidden** clap flag
  `--p2p-trust-bundle-remote-signer-policy` (`hide = true`, not shown in
  `--help`) and the `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY`
  environment variable. Recognized case-insensitive values: `disabled`,
  `fixture-loopback-allowed`, `production-remote-signer-required`,
  `mainnet-production-remote-signer-required`.
* **Default remains `RemoteSignerPolicy::Disabled`.** When both the flag
  and env var are absent, the resolved policy is `Disabled` and legacy
  no-RemoteSigner payloads remain accepted exactly as before (Run 196
  compatibility).
* **Precedence:** when both sources are supplied, the CLI flag wins. An
  invalid/unknown value is surfaced as a typed
  `RemoteSignerPolicySelectorParseError` — the resolver never silently
  falls back to `Disabled` when an explicit value is present but invalid.
* Fixture loopback RemoteSigner remains **DevNet/TestNet evidence-only**
  and cannot satisfy MainNet production RemoteSigner. Production
  RemoteSigner remains unavailable/fail-closed under
  `production-remote-signer-required` /
  `mainnet-production-remote-signer-required`.
* Missing / malformed / invalid RemoteSigner material fails closed under
  any explicit (non-`Disabled`) policy. Validation-only surfaces remain
  non-mutating; mutating-preflight rejection produces no mutation (no
  Run 070 apply, no sequence/marker write).
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with `mainnet-production-remote-signer-required` and
  fixture loopback material.
* **No real RemoteSigner backend is implemented.** No networked signer
  service. KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented.
  Governance execution remains unimplemented. Real on-chain proof
  verification remains unimplemented. Validator-set rotation remains
  open. Release-binary RemoteSigner-policy selector evidence is deferred
  to **Run 199**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_198.md`,
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`, and
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
## Run 199 — release-binary hidden RemoteSigner policy selector and production preflight routing evidence

Run 199 is **release-binary evidence** for the Run 198 hidden
RemoteSigner policy selector and production preflight routing. It
exercises the Run 198 module
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` against real
`target/release/qbind-node` and through the release-built helper
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.
Reproduce with:

```
cargo build --release -p qbind-node --bin qbind-node
bash scripts/devnet/run_199_remote_signer_policy_release_binary.sh
```

Operator-relevant invariants (release-binary):

* Run 199 makes **no production source change** (release example helper +
  release harness + docs only). The real binary accepts the hidden
  `--p2p-trust-bundle-remote-signer-policy` flag and the
  `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var, but `--help`
  advertises neither the flag nor any RemoteSigner / KMS / HSM /
  governance-execution / validator-set-rotation claim.
* **Default resolution remains `RemoteSignerPolicy::Disabled`** when both
  the flag and env var are absent.
* The release-built helper resolves the selector (default / CLI / env /
  CLI-over-env precedence / invalid fail-closed) and routes the resolved
  policy through the seven `preflight_v2_marker_remote_signer_for_*`
  wrappers into the Run 196 routing helpers, asserting a typed outcome
  for every scenario and ending in `verdict: PASS` (125/0 on this
  checkout).
* CLI-over-env precedence is deterministic; empty/unknown selector values
  fail closed with the typed `RemoteSignerPolicySelectorParseError`.
* Fixture loopback RemoteSigner remains DevNet/TestNet evidence-only and
  cannot satisfy MainNet production RemoteSigner; production RemoteSigner
  remains unavailable/fail-closed. Rejected cases produce no mutation
  (no Run 070 apply, no sequence/marker write, no `.tmp` residue, no
  fallback to `--p2p-trusted-root`, no DummySig/DummyKem/DummyAead).
* MainNet peer-driven apply remains the **Run 147 / 148 / 152 FATAL
  refusal** even with `mainnet-production-remote-signer-required` and
  fixture loopback material.
* **No real RemoteSigner backend is implemented.** KMS / HSM / cloud-KMS /
  PKCS#11 remain unimplemented. Governance execution remains
  unimplemented. Real on-chain proof verification remains unimplemented.
  Validator-set rotation remains open. Existing custody/governance proof
  paths remain compatible. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_199.md`,
`docs/devnet/run_199_remote_signer_policy_release_binary/`,
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
and `scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.
## Run 200 — authority lifecycle C4/C5 consolidation, closure criteria, and remaining-work specification

Run 200 is a **docs/spec/crosscheck-only** consolidation pass over
Runs 130–199. It introduces no operational change. It adds the
consolidation report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`, the
formal closure checklist
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and the static run
index `docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.

Operator-relevant points (no behavior change):

* Run 200 makes **no production source change** and implements **no
  backend** (no RemoteSigner, KMS, HSM, cloud-KMS, PKCS#11, governance
  execution, or on-chain proof verifier). No CLI flag, env var, marker,
  sequence-file, trust-bundle core, wire, or schema changes.
* The accepted Runs 130–199 safety properties remain in force:
  anti-rollback v2 marker enforcement, validation-only non-mutation,
  rejected-candidate no-mutation, the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal**.
* **Default custody / RemoteSigner selector resolution remains
  `Disabled`.** Fixture / local / loopback custody, governance, and
  RemoteSigner material is DevNet/TestNet evidence-only and cannot
  satisfy MainNet production authority; production material fails closed.
* C4 and C5 closure criteria, the MainNet readiness gates, and the
  negative-invariant list are now documented in
  `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. Until every MainNet
  readiness gate passes, MainNet peer-driven apply remains refused and no
  MainNet enablement claim may be made.
* **No real RemoteSigner backend is implemented.** KMS / HSM / cloud-KMS /
  PKCS#11 remain unimplemented. Governance execution remains
  unimplemented. Real on-chain proof verification remains unimplemented.
  Validator-set rotation remains open. Full C4 remains OPEN. C5 remains
  OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and
`docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.

## Run 201 — source/test production RemoteSigner transport boundary

Run 201 is a **source/test-only** pass that adds the typed transport
boundary for a future production RemoteSigner backend. It introduces no
operational change for live nodes. The only production-source change is
the additive module `crates/qbind-node/src/pqc_remote_signer_transport.rs`
plus its `lib.rs` registration; the behavior corpus lives in
`crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs`,
and the evidence report is
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_201.md`.

Operator-relevant points (no behavior change):

* Run 201 implements **no real RemoteSigner backend**, **no networked
  signer daemon/service**, and **no production signing custody**. The
  fixture loopback transport (`FixtureLoopbackRemoteSignerTransport`) is
  **DevNet/TestNet source/test evidence only** and is refused on MainNet.
* The `ProductionRemoteSignerTransport` is callable but **fail-closed**:
  it returns `ProductionTransportUnavailable` (or
  `MainNetProductionTransportUnavailable` for MainNet) and never performs
  real network or signing I/O. KMS / HSM / cloud-KMS / PKCS#11 remain
  unimplemented; governance execution and real on-chain proof
  verification remain unimplemented; validator-set rotation remains open.
* Run 201 adds **no new metric, no new exit code**, and no marker,
  sequence-file, authority-marker, trust-bundle core, ratification-sidecar
  wire, or schema change. The new module performs no network or file I/O,
  writes no marker or sequence, swaps no live trust, evicts no sessions,
  and never invokes the Run 070 ordering.
* The accepted Runs 130–200 safety properties remain in force, including
  anti-rollback v2 marker enforcement, validation-only non-mutation,
  rejected-candidate no-mutation, the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal** — Run
  201 reasserts that a MainNet peer-driven-apply preflight short-circuits
  to `MainNetPeerDrivenApplyRefused` even with a fixture loopback
  transport configured.
* Default custody / RemoteSigner selector resolution remains **Disabled**;
  Run 201 changes no default and enables no MainNet apply.
* Release-binary RemoteSigner transport-boundary evidence is deferred to
  **Run 202**. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 202 — release-binary RemoteSigner transport boundary evidence

Run 202 is a **release-binary evidence-only** pass that proves the Run 201
production RemoteSigner transport boundary behaves correctly on the real
`target/release/qbind-node` plus a release-built helper. It makes **no
production-source change** (a release example helper, a release harness,
and documentation only) and introduces no operational change for live
nodes. The deliverables are
`crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs`,
`scripts/devnet/run_202_remote_signer_transport_release_binary.sh`,
`docs/devnet/run_202_remote_signer_transport_release_binary/`, and the
evidence report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_202.md`.

Operator-relevant points (no behavior change):

* Run 202 implements **no real RemoteSigner backend**, **no networked
  signer daemon/service**, and **no production signing custody**. The
  release helper links the production library symbols
  (`pqc_remote_signer_transport::*` over `pqc_remote_authority_signer::*`)
  and exercises the Run 201 transport corpus in release mode; the fixture
  loopback transport (`FixtureLoopbackRemoteSignerTransport`) remains
  **DevNet/TestNet evidence only** and is refused on MainNet.
* The release binary keeps every Run 070 / 130–201 surface
  **RemoteSigner-transport-silent**: `--help` and the per-env
  `--print-genesis-hash` flows emit no `RemoteSigner transport active`,
  `RemoteSigner backend connected`, `networked signer daemon active`, KMS,
  HSM, governance-execution, or validator-set-rotation banner. The Run 198
  RemoteSigner policy selector, the Run 193 custody selector, and the
  governance fixture flag remain compatible with no banner drift.
* The `ProductionRemoteSignerTransport` reaches the boundary and **fails
  closed** at the release binary, returning
  `ProductionTransportUnavailable` /
  `MainNetProductionTransportUnavailable` and performing no real network
  or signing I/O. KMS / HSM / cloud-KMS / PKCS#11, governance execution,
  real on-chain proof verification, and validator-set rotation all remain
  unimplemented.
* Run 202 adds **no new metric, no new exit code**, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change. The helper performs no network or file I/O
  beyond writing evidence files under its output directory, writes no
  marker or sequence, swaps no live trust, evicts no sessions, and never
  invokes the Run 070 ordering.
* The accepted Runs 130–201 safety properties remain in force, including
  validation-only non-mutation, rejected-candidate no-mutation, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal** — Run
  202 reconfirms at the release binary that a MainNet peer-driven-apply
  preflight short-circuits to `MainNetPeerDrivenApplyRefused` even with a
  fixture loopback transport response.
* Default custody / RemoteSigner selector resolution remains **Disabled**;
  Run 202 changes no default and enables no MainNet apply. **Full C4
  remains OPEN; C5 remains OPEN.**

## Run 203 — source/test KMS/HSM backend abstraction boundary

Run 203 is a **source/test-only** pass that adds the typed,
provider-neutral KMS/HSM backend abstraction the Run 188
`AuthorityCustodyClass::{Kms, Hsm}` placeholders previously lacked. The
only production-source change is the additive new module
`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs` plus its
`lib.rs` registration; the focused tests are
`crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs` and
the evidence report is `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_203.md`.

Operator-relevant points (no behavior change):

* Run 203 implements **no real KMS backend**, **no real HSM backend**,
  **no cloud-KMS integration**, and **no PKCS#11 integration**. The
  fixture KMS/HSM backends (`FixtureKmsBackend` / `FixtureHsmBackend`)
  are **DevNet/TestNet source/test only** and are refused on a MainNet
  trust domain.
* The production / cloud / PKCS#11 backends (`ProductionKmsBackend`,
  `ProductionHsmBackend`, `CloudKmsBackend`, `Pkcs11HsmBackend`) are
  callable but **fail closed** with `ProductionKmsUnavailable` /
  `ProductionHsmUnavailable` / `CloudKmsUnavailable` /
  `Pkcs11HsmUnavailable`, performing no real network, cloud, PKCS#11, or
  hardware call.
* The **RemoteSigner path (Runs 194–202) remains a separate, unchanged
  custody option** — the KMS/HSM router refuses a `RemoteSigner` custody
  class as `NotKmsHsmCustodyClass`. KMS/HSM does not replace RemoteSigner
  and does not enable a MainNet apply.
* The default backend policy resolution is **`BackendPolicy::Disabled`**,
  which refuses every backend request regardless of contents.
* Run 203 adds **no new metric, no new exit code**, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change. Every public function and trait method performs
  no network or file I/O, writes no marker or sequence, swaps no live
  trust, evicts no sessions, and never invokes the Run 070 ordering.
* The accepted Runs 130–202 safety properties remain in force, including
  validation-only non-mutation, rejected-candidate no-mutation, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal** — a
  MainNet peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture KMS/HSM
  response. Governance execution, real on-chain proof verification, and
  validator-set rotation all remain unimplemented/open.
* Release-binary KMS/HSM backend-boundary evidence is deferred to
  **Run 204**. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 204 — release-binary KMS/HSM backend abstraction boundary evidence

Run 204 is a **release-binary evidence-only** pass that closes the
Run 203-deferred release-binary boundary for the production KMS/HSM
custody backend abstraction. It makes **no production-source change**: it
adds the release example helper
`crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs`,
the release harness
`scripts/devnet/run_204_kms_hsm_backend_release_binary.sh`, the evidence
archive `docs/devnet/run_204_kms_hsm_backend_release_binary/`, and the
canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_204.md`.

Operator-relevant points (no behavior change):

* Run 204 implements **no real KMS backend**, **no real HSM backend**,
  **no cloud-KMS integration**, and **no PKCS#11 integration**. The
  fixture KMS/HSM backends remain **DevNet/TestNet evidence-only** and are
  refused on a MainNet trust domain.
* The harness drives the **real `target/release/qbind-node`**: every
  existing Run 070 / 130–203 surface (`--help`, `--print-genesis-hash
  --env {devnet,testnet,mainnet}`, the Run 193 custody selector, the
  Run 198 RemoteSigner selector, the governance fixture flag) emits no
  KMS / HSM / cloud-KMS / PKCS#11 / RemoteSigner backend enablement
  banner and no MainNet peer-driven apply enablement — even with the
  custody and RemoteSigner selectors armed on `--env mainnet`.
* The release-built helper exercises the Run 203 A1–A15 / R1–R41 corpus
  in **release mode** through the production library symbols (six tables;
  total_pass 71, total_fail 0, verdict PASS): fixture KMS/HSM accepted on
  DevNet/TestNet only; production / cloud / PKCS#11 backends fail-closed
  as unavailable; identity / request / response / transcript digests
  deterministic and domain-bound; backend boundary composes with the
  Run 188 custody classes; rejected cases produce no mutation; MainNet
  peer-driven apply remains refused even with fixture KMS/HSM material.
* The **RemoteSigner path (Runs 194–202) remains a separate, unchanged
  custody option**. Run 204 makes no real RemoteSigner backend or
  networked signer daemon claim.
* Run 204 adds **no new metric, no new exit code**, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken Runs 070, 130–203.
* The accepted Runs 130–203 safety properties remain in force, including
  validation-only non-mutation, rejected-candidate no-mutation, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal**.
  Governance execution, real on-chain proof verification, and
  validator-set rotation all remain unimplemented/open. **Full C4 remains
  OPEN; C5 remains OPEN.**
## Run 205 — source/test production custody attestation verifier skeleton

Run 205 is a **source/test-only** pass that adds a typed, mockable
verifier skeleton for a production custody attestation chain. It makes a
single additive production-source change — the new module
`crates/qbind-node/src/pqc_custody_attestation_verifier.rs` plus its
`lib.rs` registration — and adds the tests
`crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`
and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_205.md`.

Operator-relevant points (no behavior change):

* Run 205 implements **no real cloud-KMS attestation verifier**, **no
  real PKCS#11 attestation verifier**, **no real HSM vendor attestation
  verifier**, and **no real RemoteSigner attestation verifier**. The
  fixture attestation remains **DevNet/TestNet evidence-only** and is
  refused on a MainNet trust domain.
* The new `CustodyAttestationVerifier` trait is pure and mockable: the
  `FixtureCustodyAttestationVerifier` accepts only well-formed fixture
  attestations on DevNet/TestNet, and the production / cloud-KMS /
  PKCS#11 / HSM / RemoteSigner verifiers are callable but **fail closed**
  as the matching typed unavailable outcome.
* The verifier binds the full authority tuple (environment, chain id,
  genesis hash, authority-root and bundle-signing-key fingerprints, the
  Run 188 custody class, the backend / provider / signer id, the custody
  key id, the suite id, the lifecycle action, the candidate digest, the
  authority-domain sequence, the optional governance / request / response
  / transcript digests), the attestation commitment, the anti-replay
  nonce and replay window, and the freshness/expiry window, all over
  deterministic domain-separated digests.
* The composition helpers `validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation` layer the attestation over
  the Run 188 `validate_lifecycle_governance_and_custody` composition and
  short-circuit to a MainNet peer-driven-apply refusal before consulting
  custody or attestation. **MainNet peer-driven apply remains refused
  even with a fixture attestation.**
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend
  path (Runs 203–204)** remain separate, unchanged backend-boundary
  options. Run 205 makes no real backend, networked signer daemon, or
  attestation service claim.
* Run 205 adds **no new metric, no new exit code**, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken Runs 070, 130–204.
* The accepted Runs 130–204 safety properties remain in force, including
  validation-only non-mutation, rejected-candidate no-mutation, and the
  **Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal**.
  Governance execution, real on-chain proof verification, and
  validator-set rotation all remain unimplemented/open. Release-binary
  custody-attestation verifier-boundary evidence is deferred to **Run
  206**. **Full C4 remains OPEN; C5 remains OPEN.**

## Run 206 — release-binary custody attestation verifier boundary evidence

Run 206 is a **release-binary evidence-only** pass that closes the
Run 205-deferred release-binary boundary for the production custody
attestation verifier skeleton
`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`, layered over
the Run 188 authority-custody boundary, the Run 203 KMS/HSM backend
boundary, and the Run 201 RemoteSigner transport boundary. It adds a
release example helper
`crates/qbind-node/examples/run_206_custody_attestation_release_binary_helper.rs`,
a release harness
`scripts/devnet/run_206_custody_attestation_release_binary.sh`, the
evidence archive `docs/devnet/run_206_custody_attestation_release_binary/`,
and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_206.md`. It makes **no
production-source change** (helper + harness + docs only).

Operator-relevant points (no behavior change):

* Run 206 proves on the real `target/release/qbind-node` that every
  existing Run 070 / 130–205 surface (`--help`,
  `--print-genesis-hash --env {devnet,testnet,mainnet}`, the Run 193
  custody policy selector, the Run 198 RemoteSigner policy selector, the
  governance fixture flag) stays **custody-attestation-silent**: no custody
  attestation / KMS / HSM / cloud-KMS / PKCS#11 attestation enablement
  banner, no governance-execution or validator-set-rotation claim, and no
  MainNet peer-driven apply enablement — even with the custody and
  RemoteSigner selectors armed on `--env mainnet`.
* The release-built helper exercises the Run 205 A1–A15 / R1–R40 corpus in
  release mode through the production library symbols
  (`total_pass 69, total_fail 0, verdict PASS`): fixture custody
  attestation accepted on **DevNet/TestNet only**; the production /
  cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation verifiers callable
  and **fail closed** as the matching typed unavailable outcome;
  evidence / input / transcript / provider-identity digests deterministic
  and domain-bound; the attestation boundary composes with the Run 188
  custody classes and the Run 203 / Run 201 backend / RemoteSigner
  transport evidence; rejected cases produce no mutation; and **MainNet
  peer-driven apply remains the Run 147 FATAL refusal** even with a fixture
  attestation response.
* Run 206 implements **no real cloud-KMS attestation verifier**, **no real
  PKCS#11 attestation verifier**, **no real HSM vendor attestation
  verifier**, **no real RemoteSigner backend**, and **no real KMS/HSM
  backend**. Fixture custody attestation remains DevNet/TestNet
  evidence-only and is refused on a MainNet trust domain.
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path
  (Runs 203–204)** remain separate, unchanged backend-boundary options.
* Run 206 adds **no new metric, no new exit code**, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken Runs 070, 130–205.
* Governance execution, real on-chain proof verification, and validator-set
  rotation all remain unimplemented/open. **Full C4 remains OPEN; C5
  remains OPEN.**
## Run 207 — source/test custody-attestation payload carrying and production preflight integration

Run 207 is a **source/test-only** pass that makes the Run 205 typed
custody-attestation evidence/input reachable from production call-site
contexts. It adds the module
`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs` and the
suite `crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`
(64 tests, all PASS).

* Run 207 adds an **additive, optional** `custody_attestation` sibling on
  the v2 ratification sidecar JSON
  (`CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD`, wire schema version `1`).
  A v2 sidecar without the sibling parses exactly as before and yields
  `CustodyAttestationLoadStatus::Absent`; **legacy/no-attestation payload
  compatibility is preserved**.
* Wire types (`CustodyAttestationClassWire`,
  `CustodyAttestationEvidenceWire`, `CustodyAttestationInputWire`,
  `CustodyAttestationPayloadWire`, `CustodyAttestationParts`) convert into
  the Run 205 internal `CustodyAttestationEvidence` /
  `CustodyAttestationInput`, **failing closed** via
  `CustodyAttestationWireParseError` on an unknown schema version or an
  empty required field. `CustodyAttestationLoadStatus` distinguishes
  `Absent` / `Available` / `Malformed`, and
  `CustodyAttestationPayloadParseError` separates JSON-shape from
  wire-structural failures.
* The combined loader
  `load_v2_ratification_sidecar_with_custody_attestation_from_path` /
  `_from_bytes` extracts the sibling **before** the strict v2 sidecar
  parse, so a malformed sibling cannot poison the ratification.
* The typed `CustodyAttestationCallsiteContext` bundles the in-process
  Run 188 custody attestation, the candidate / persisted v2 records, the
  trust domain, the lifecycle / governance / custody / suite bindings, the
  Run 188 custody policy, the Run 205 attestation policy, and `now_unix`.
* Seven per-surface routing helpers
  `route_loaded_custody_attestation_to_{reload_check, reload_apply,
  startup_p2p_trust_bundle, sighup, local_peer_candidate_check,
  live_inbound_0x05, peer_driven_drain}_callsite_decision` drive the
  carrier into the Run 205 `verify_custody_attestation` /
  `validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation` boundary. A **malformed
  carrier short-circuits** before the verifier and before any
  sequence/marker write, live trust swap, session eviction, or Run 070
  call; the peer-driven drain helper refuses MainNet unconditionally.
* The fixture attestation is **DevNet/TestNet source/test only**; the
  production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation paths
  remain **unavailable/fail-closed**; the default
  `CustodyAttestationPolicy::Disabled` is unchanged.
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path
  (Runs 203–204)** remain separate, unchanged backend-boundary options.
* Run 207 implements **no real cloud-KMS / PKCS#11 / HSM-vendor attestation
  verifier** and **no real RemoteSigner backend**, adds **no new metric, no
  new exit code**, and makes no authority-marker / sequence-file /
  trust-bundle core / schema change; it does not weaken Runs 070, 130–206.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** even with a carried fixture attestation. Release-binary
  custody-attestation payload/carrying evidence is deferred to **Run 208**.
  Governance execution, real on-chain proof verification, and validator-set
  rotation all remain unimplemented/open. **Full C4 remains OPEN; C5
  remains OPEN.**

## Run 208 — release-binary custody-attestation payload carrying and production-context routing evidence

Run 208 is the **release-binary evidence** run for the Run 207 source/test
custody-attestation payload carrying and production-context wiring
(`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`). It adds
the release helper
`crates/qbind-node/examples/run_208_custody_attestation_payload_release_binary_helper.rs`,
the harness `scripts/devnet/run_208_custody_attestation_payload_release_binary.sh`,
the evidence archive `docs/devnet/run_208_custody_attestation_payload_release_binary/`
(tracked: README.md, summary.txt, .gitignore), and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_208.md`. It makes **no production
source change** (helper + harness + docs only).

* The harness drives the **real `target/release/qbind-node`** and proves that
  `--help`, `--print-genesis-hash --env {devnet,testnet,mainnet}`, the Run 193
  custody policy selector, the Run 198 RemoteSigner policy selector, and the
  governance fixture flag stay **custody-attestation-payload-silent**: no
  custody-attestation / KMS / HSM / cloud-KMS / PKCS#11 / RemoteSigner-backend
  enablement banner, no `run-205`..`run-208` token, no governance-execution or
  validator-set-rotation claim, and no MainNet peer-driven apply enablement —
  even with the custody and RemoteSigner selectors armed on `--env mainnet`
  (S1–S8).
* The **release-built helper** exercises the Run 207 A1–A15 / R1–R43
  payload/carrying corpus in release mode through the production library
  symbols `pqc_custody_attestation_payload_carrying::*` over
  `pqc_custody_attestation_verifier::*` and `pqc_authority_custody::*` (five
  tables: `accepted`, `rejection`, `loader`, `determinism`,
  `refusal_reachability`; `verdict: PASS`).
* It confirms in release mode that legacy/no-attestation payloads remain
  compatible under the default `CustodyAttestationPolicy::Disabled`; that
  DevNet/TestNet fixture attestation carried through the additive optional
  `custody_attestation` sidecar sibling routes through the seven per-surface
  helpers into the Run 205 verifier and is accepted under the explicit fixture
  policy; that evidence / input / transcript / provider-identity digests stay
  deterministic and domain-bound through wire conversion; that the production /
  cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation material routes into the
  verifier and fails closed as the typed unavailable outcome; that a malformed
  carrier short-circuits before the verifier and before any sequence/marker
  write, live trust swap, session eviction, or Run 070 call; and that the
  combined loader returns `Absent` / `Available` / `Malformed` while the
  ratification still parses.
* The fixture attestation remains **DevNet/TestNet evidence-only** and is
  refused on MainNet; the production / cloud-KMS / PKCS#11 / HSM-vendor /
  RemoteSigner attestation paths remain **unavailable/fail-closed**; the
  **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path (Runs
  203–204)** remain separate, unchanged backend-boundary options.
* Run 208 implements **no real cloud-KMS / PKCS#11 / HSM-vendor attestation
  verifier**, **no real RemoteSigner backend**, **no real KMS/HSM backend**,
  **no governance execution**, **no real on-chain proof verifier**, and **no
  validator-set rotation**; it adds **no new metric, no new exit code**, and
  makes no authority-marker / sequence-file / trust-bundle core / wire / schema
  change beyond Run 207's additive optional sibling; it does not weaken Runs
  070, 130–207.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with a carried fixture attestation. **Full C4 remains OPEN; C5 remains
  OPEN.**
## Run 209 — source/test hidden custody-attestation policy selector and production preflight integration

Run 209 is a **source/test-only** pass that adds a hidden,
disabled-by-default custody-attestation policy selector and wires the
resolved Run 205 `CustodyAttestationPolicy` into all seven production v2
marker-decision preflight contexts through the Run 207 payload-carrying /
routing layer. It adds the module
`crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs`, the
hidden CLI flag in `crates/qbind-node/src/cli.rs`, the test target
`crates/qbind-node/tests/run_209_custody_attestation_policy_selector_tests.rs`,
and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_209.md`.

* **Selector (hidden, disabled by default).** One hidden clap flag
  `--p2p-trust-bundle-custody-attestation-policy` (`hide = true`) plus the
  env var `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`, sharing one
  case-insensitive value grammar
  (`disabled` | `fixture-attestation-allowed` |
  `remote-signer-attestation-required` | `kms-attestation-required` |
  `hsm-attestation-required` | `production-attestation-required` |
  `mainnet-production-attestation-required`). Operators reading `--help`
  see no new surface.
* **Default unchanged.** When both the CLI flag and the env var are
  absent the resolved policy is `CustodyAttestationPolicy::Disabled` —
  legacy no-attestation payloads remain bit-for-bit compatible (Run 207).
* **Deterministic precedence.** When both sources are supplied the **CLI
  flag wins** (mirroring the Run 192 custody and Run 198 RemoteSigner
  selectors). Invalid / unknown values fail closed with a typed
  `CustodyAttestationPolicySelectorParseError`; the resolver never
  silently downgrades an explicit-but-invalid value to `Disabled`.
* **Reachability.** The resolved policy reaches all seven production
  preflight contexts (reload-check, reload-apply, startup
  `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain) through the per-surface wrappers
  `preflight_v2_marker_custody_attestation_for_*`, which are **pure**: no
  marker write, no sequence write, no live trust swap, no session
  eviction, no Run 070 call.
* **Fail-closed behavior.** Fixture attestation is **DevNet/TestNet
  evidence-only** and cannot satisfy MainNet production attestation;
  production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation
  reaches the Run 205 verifier and fails closed as unavailable; missing
  attestation under a required policy fails closed; malformed material
  fails closed before the verifier.
* Run 209 implements **no real cloud-KMS / PKCS#11 / HSM-vendor
  attestation verifier**, **no real KMS/HSM backend**, **no real
  RemoteSigner backend**, **no governance execution**, **no real on-chain
  proof verifier**, and **no validator-set rotation**; it adds **no new
  metric, no new exit code**, and makes no authority-marker / sequence-file
  / trust-bundle core / wire / schema change; it does not weaken Runs 070,
  130–208.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** even with `MainnetProductionAttestationRequired` and a carried
  fixture attestation. Release-binary custody-attestation policy selector
  evidence is deferred to **Run 210**. **Full C4 remains OPEN; C5 remains
  OPEN.**
## Run 210 — release-binary custody-attestation policy selector evidence

Run 210 is a **release-binary evidence** pass that closes the Run
209-deferred release-binary boundary for the hidden custody-attestation
policy selector. It adds the release helper
`crates/qbind-node/examples/run_210_custody_attestation_policy_release_binary_helper.rs`,
the harness
`scripts/devnet/run_210_custody_attestation_policy_release_binary.sh`, the
evidence archive
`docs/devnet/run_210_custody_attestation_policy_release_binary/` (tracks
`README.md`, `summary.txt`, `.gitignore`; all per-run artifacts are
`.gitignore`d), and the canonical report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_210.md`. It makes **no production
source change** (helper + harness + docs only).

* **Real-binary surface.** On the real `target/release/qbind-node`, `--help`
  hides the Run 209 selector flag
  `--p2p-trust-bundle-custody-attestation-policy` (`hide = true`); the hidden
  CLI/env selector is accepted without enabling any production custody
  attestation, KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend, governance
  execution, validator-set rotation, or MainNet peer-driven apply; and every
  Run 070 / 130–209 surface stays custody-attestation-silent (S1–S10).
* **Release-mode selector corpus.** The release-built helper exercises the
  Run 209 selector resolver (`custody_attestation_policy_from_selector` /
  `custody_attestation_policy_env_selector` /
  `custody_attestation_policy_from_cli_or_env`) and the seven per-surface
  preflight wrappers through the production library symbols: unset resolves to
  `Disabled`; CLI/env tags resolve; CLI-over-env precedence is deterministic;
  invalid values fail closed with typed parse errors; the resolved policy
  reaches all seven preflight contexts; fixture attestation is accepted on
  DevNet/TestNet only where the policy allows; production / cloud-KMS /
  PKCS#11 / HSM / RemoteSigner attestation reaches the Run 205 verifier and
  fails closed as unavailable; rejected cases produce no mutation.
* **Honest limitation.** The Run 209 CLI flag is parsed by the release binary
  (hidden) but its resolved policy is not yet wired into a long-running node
  runtime, so the full env/CLI → resolved-policy → preflight-context chain is
  proven in release mode through the production library symbols by the helper
  rather than by deep binary runtime behavior.
* Run 210 implements **no real cloud-KMS / PKCS#11 / HSM-vendor attestation
  verifier**, **no real KMS/HSM backend**, **no real RemoteSigner backend**,
  **no governance execution**, **no real on-chain proof verifier**, and **no
  validator-set rotation**; it adds **no new metric, no new exit code**, and
  makes no authority-marker / sequence-file / trust-bundle core / wire /
  schema change; it does not weaken Runs 070, 130–209.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with `mainnet-production-attestation-required` and a carried fixture
  attestation. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 211 — source/test governance execution policy boundary

Run 211 is a **source/test** pass that adds a typed governance execution
policy boundary modeling how an approved governance decision authorizes an
authority lifecycle action. It adds the module
`crates/qbind-node/src/pqc_governance_execution_policy.rs` and the test
target `crates/qbind-node/tests/run_211_governance_execution_policy_tests.rs`.

* **No operator action required.** Run 211 changes no runtime behavior.
  The boundary defaults to `GovernanceExecutionPolicy::Disabled`, under
  which `evaluate_governance_execution_policy` returns
  `GovernanceExecutionDisabled` and existing GenesisBound /
  EmergencyCouncil / OnChainGovernance proof-carrier and custody /
  RemoteSigner / KMS-HSM / custody-attestation paths are unchanged.
* **Fixture governance is DevNet/TestNet source/test only.** A fixture or
  emergency-council fixture governance decision is accepted only under the
  matching explicit fixture policy on a DevNet/TestNet trust domain; it is
  refused on a MainNet trust domain (`FixtureRejectedForMainNet`).
* **Production / on-chain / MainNet governance execution fail closed.** The
  `ProductionGovernanceExecutionEvaluator`,
  `OnChainGovernanceExecutionEvaluator`, and
  `MainnetGovernanceExecutionEvaluator` are callable but return the
  matching typed unavailable outcome.
* **Action authorization.** Governance execution authorizes a lifecycle
  action only when the governance action, lifecycle action, candidate
  digest, and authority-domain sequence match the decision; emergency
  revoke is accepted only under the explicit emergency fixture policy;
  validator-set rotation and the policy-change requests are rejected as
  unsupported.
* **No mutation.** The evaluator and the
  `evaluate_governance_execution_with_peer_driven_guard` composition helper
  are pure: no marker write, no sequence write, no live trust swap, no
  session eviction, no Run 070 call.
* Run 211 implements **no real governance execution engine**, **no real
  on-chain governance proof verifier**, **no MainNet governance**, **no
  real KMS/HSM backend**, **no real RemoteSigner backend**, **no production
  signing-key custody**, and **no validator-set rotation**; it adds **no
  new metric, no new exit code, no CLI flag**, and makes no authority-marker
  / sequence-file / trust-bundle core / wire / schema change; it does not
  weaken Runs 070, 130–210.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** even with fixture governance approval. Release-binary
  governance execution policy-boundary evidence is deferred to **Run 212**.
  **Full C4 remains OPEN; C5 remains OPEN.**
## Run 212 — release-binary governance execution policy-boundary evidence

Run 212 is a **release-binary evidence** pass that closes the Run 211-deferred
boundary for the source/test governance execution policy boundary
(`crates/qbind-node/src/pqc_governance_execution_policy.rs`). It adds the
release example helper
`crates/qbind-node/examples/run_212_governance_execution_policy_release_binary_helper.rs`,
the release harness
`scripts/devnet/run_212_governance_execution_policy_release_binary.sh`, the
evidence archive `docs/devnet/run_212_governance_execution_policy_release_binary/`,
and the canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_212.md`.

* **No operator action required.** Run 212 changes no runtime behavior and no
  production source. It only links and exercises the already-additive Run 211
  boundary in release mode through the production library symbols.
* **Reproduce.** `bash scripts/devnet/run_212_governance_execution_policy_release_binary.sh`
  rebuilds the release node binary and the release helper, runs the real-binary
  surface checks (S1–S7), drives the Run 211 corpus through the release helper
  (accepted / rejection / reachability tables, verdict PASS over 73 checks),
  records the source-reachability and no-mutation/denylist proofs, and
  cross-checks the Run 134–211 regression target set. The harness is idempotent
  and rewrites everything under the evidence archive except `README.md`,
  `summary.txt`, and `.gitignore`.
* **Real binary stays governance-execution-silent.** The real
  `target/release/qbind-node` exposes no governance-execution surface,
  advertises no production / MainNet governance enablement and no on-chain
  governance proof verifier, and keeps every existing Run 070 / 130–211 surface
  governance-execution-silent with the MainNet peer-driven apply refusal
  preserved.
* Run 212 implements **no real governance execution engine**, **no real
  on-chain governance proof verifier**, **no MainNet governance**, **no real
  KMS/HSM backend**, **no real RemoteSigner backend**, and **no validator-set
  rotation**; fixture governance execution remains DevNet/TestNet evidence-only
  and is refused on MainNet; production / on-chain / MainNet governance
  execution remains unavailable/fail-closed; the existing custody / KMS-HSM /
  RemoteSigner / custody-attestation / governance proof paths remain
  compatible; and it does not weaken Runs 070, 130–211.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with a fixture governance approval. **Full C4 remains OPEN; C5 remains
  OPEN.**
## Run 213 — source/test governance-execution payload carrying and production-context wiring

Run 213 is a **source/test** pass that makes the Run 211 typed
governance-execution input/decision material reachable from production
call-site contexts. It adds the module
`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs` and the
test target
`crates/qbind-node/tests/run_213_governance_execution_payload_callsite_tests.rs`.

* **No operator action required.** Run 213 changes no runtime behavior. It
  only adds an additive, optional `governance_execution` sibling on the v2
  ratification sidecar and source/test routing helpers that carry the
  Run 211 governance-execution material into the seven production
  marker-decision call-site contexts (reload-check, reload-apply, startup
  `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain) where it reaches the Run 211 evaluator.
* **Default stays compatible.** Under the default
  `GovernanceExecutionPolicy::Disabled`, a legacy no-governance-execution
  payload is accepted unchanged; a present-but-malformed carrier or a
  required-but-absent carrier under a non-`Disabled` policy fails closed
  before the evaluator and before any sequence/marker write, live trust
  swap, session eviction, or Run 070 call.
* **Reproduce.**
  `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
  drives the A1–A16 / R1–R40 corpus representable at the payload-carrying
  layer (61 tests): legacy compatibility, fixture governance carried and
  accepted on DevNet/TestNet under the explicit fixture policy, the seven
  surfaces reaching the Run 211 evaluator, production / on-chain / MainNet
  governance carried and failing closed as unavailable, digest determinism
  through wire conversion, malformed/absent fail-closed, and the MainNet
  refusal invariant.
* Run 213 implements **no real governance execution engine**, **no real
  on-chain governance proof verifier**, **no MainNet governance**, **no real
  KMS/HSM backend**, **no real RemoteSigner backend**, and **no validator-set
  rotation**; fixture governance execution remains DevNet/TestNet
  evidence-only and is refused on MainNet; production / on-chain / MainNet
  governance execution remains unavailable/fail-closed; the existing custody
  / KMS-HSM / RemoteSigner / custody-attestation / governance proof paths
  remain compatible; and it does not weaken Runs 070, 130–212. Release-binary
  governance-execution payload/carrying evidence is deferred to **Run 214**.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with a fixture governance approval. **Full C4 remains OPEN; C5 remains
  OPEN.**
## Run 214 — release-binary governance-execution payload/carrying evidence

Run 214 is a **release-binary evidence** pass that closes the release-binary
boundary deferred by Run 213 for the governance-execution payload/carrying and
production-context wiring. It adds the release-built helper
`crates/qbind-node/examples/run_214_governance_execution_payload_release_binary_helper.rs`,
the harness `scripts/devnet/run_214_governance_execution_payload_release_binary.sh`,
the evidence archive `docs/devnet/run_214_governance_execution_payload_release_binary/`,
and the canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_214.md`.

* **No operator action required.** Run 214 makes no production source change and
  changes no runtime behavior. It only proves, on the real
  `target/release/qbind-node` plus a release-built helper linking the production
  library symbols, that the Run 213 payload/carrying boundary holds end-to-end in
  release mode.
* **Default stays compatible.** The real `target/release/qbind-node` exposes no
  governance-execution surface; the default DevNet/TestNet/MainNet
  `--print-genesis-hash` surfaces, including with the Run 193 custody / Run 198
  RemoteSigner / Run 209 custody-attestation selectors and the Run 180 governance
  on-chain fixture flag armed, emit no governance-execution enablement banner and
  no MainNet peer-driven apply enablement.
* **Reproduce.**
  `bash scripts/devnet/run_214_governance_execution_payload_release_binary.sh`
  builds the release node binary and the Run 214 helper, drives the A1–A16 /
  R1–R40 corpus through the production library symbols (release helper
  `verdict: PASS`, 73 checks, 0 fail), runs the S1–S7 real-binary surface
  scenarios, records the source-reachability and no-mutation/denylist proofs, and
  cross-checks the Run 134–213 regression target set.
* Run 214 implements **no real governance execution engine**, **no real on-chain
  governance proof verifier**, **no MainNet governance**, **no real KMS/HSM
  backend**, **no real RemoteSigner backend**, and **no validator-set rotation**;
  fixture governance execution remains DevNet/TestNet evidence-only and is refused
  on MainNet; production / on-chain / MainNet governance execution remains
  unavailable/fail-closed; the existing custody / KMS-HSM / RemoteSigner /
  custody-attestation / governance proof paths remain compatible; and it does not
  weaken Runs 070, 130–213.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with a fixture governance approval. **Full C4 remains OPEN; C5 remains
  OPEN.**
## Run 215 — hidden governance-execution policy selector (source/test)

Run 215 is a **source/test** pass that adds a hidden, disabled-by-default
governance-execution policy selector and wires the resolved
`GovernanceExecutionPolicy` into the seven production v2 marker-decision
preflight contexts through the Run 213 routing helpers. It adds the new module
`crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`, the hidden
CLI flag `--p2p-trust-bundle-governance-execution-policy` in
`crates/qbind-node/src/cli.rs`, the tests
`crates/qbind-node/tests/run_215_governance_execution_policy_selector_tests.rs`,
and the canonical report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_215.md`.

* **Hidden, disabled-by-default selector.** Choose the policy with the hidden
  CLI flag
  `--p2p-trust-bundle-governance-execution-policy <disabled | fixture-governance-allowed | emergency-council-fixture-allowed | production-governance-required | mainnet-governance-required>`
  or the `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var (same
  grammar; case-insensitive). When both are absent the resolved policy is
  `GovernanceExecutionPolicy::Disabled` and legacy no-governance-execution
  payloads remain accepted (Run 213 compatibility).
* **Deterministic precedence.** When both the CLI flag and the env var are
  supplied, the CLI flag wins (mirrors the Run 192 custody / Run 198
  RemoteSigner / Run 209 custody-attestation selectors). An empty / unknown
  value fails closed with a typed `GovernanceExecutionPolicySelectorParseError`
  — the resolver never silently downgrades an explicit-but-invalid value to
  `Disabled`.
* **Default stays compatible.** The selector is hidden via clap, so the real
  binary `--help` and the default `--print-genesis-hash` surfaces are
  unchanged; no governance-execution enablement banner is emitted by default.
* **Policy semantics.** `fixture-governance-allowed` and
  `emergency-council-fixture-allowed` are DevNet/TestNet evidence-only and
  cannot satisfy MainNet production governance execution;
  `production-governance-required` and `mainnet-governance-required` fail
  closed as unavailable because no real governance execution engine exists.
* **Reproduce.**
  `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
  (55 tests) and
  `cargo test -p qbind-node --lib pqc_governance_execution_policy_surface`
  (7 tests).
* **Live inbound `0x05` limitation.** The live `0x05` runtime config does not
  yet thread the per-connection governance-execution policy; the source/test
  wrapper exposes the injection and the limitation is documented. Release-binary
  governance-execution-policy selector evidence is deferred to **Run 216**.
* Run 215 implements **no real governance execution engine**, **no real
  on-chain governance proof verifier**, **no MainNet governance**, **no real
  KMS/HSM backend**, **no real RemoteSigner backend**, and **no validator-set
  rotation**; production / on-chain / MainNet governance execution remains
  unavailable/fail-closed; the existing custody / KMS-HSM / RemoteSigner /
  custody-attestation / governance proof paths remain compatible; and it does
  not weaken Runs 070, 130–214.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal**
  even with `MainnetGovernanceRequired` and a fixture governance approval.
  **Full C4 remains OPEN; C5 remains OPEN.**
## Run 216 — release-binary governance-execution policy selector evidence

Run 216 is the **release-binary** counterpart to Run 215. The real `target/release/qbind-node` hides but accepts `--p2p-trust-bundle-governance-execution-policy` and `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`; the release helper proves default `GovernanceExecutionPolicy::Disabled`, CLI/env selectors, deterministic CLI-over-env precedence, invalid selector fail-closed behavior, all seven preflight wrappers, A1–A16 accepted/compatible cases, and R1–R40 rejection/no-mutation cases. Fixture governance remains DevNet/TestNet evidence-only, emergency council fixture execution remains explicit and non-production, production/on-chain/MainNet governance execution remains unavailable/fail-closed, MainNet peer-driven apply remains refused, existing custody/KMS-HSM/RemoteSigner/custody-attestation/governance-proof paths remain compatible, and no real governance engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented. **Full C4 remains OPEN; C5 remains OPEN.**

## Run 217 — source/test governance-execution runtime policy arming wiring

Run 217 is **source/test only** and wires the Run 215 hidden governance-execution selector into the long-running runtime preflight contexts through the new runtime-config carrier `GovernanceExecutionRuntimeArmingConfig` (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`). Operationally there is **no behavior change by default**: with neither `--p2p-trust-bundle-governance-execution-policy` nor `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` set, `GovernanceExecutionRuntimeArmingConfig::from_cli_or_env` resolves `GovernanceExecutionPolicy::Disabled` and legacy no-governance-execution payloads remain accepted (Run 214 compatibility). When a policy is selected, the carrier routes the resolved policy into the seven runtime preflight wrappers (`preflight_reload_check`, `preflight_reload_apply`, `preflight_startup_p2p_trust_bundle`, `preflight_sighup`, `preflight_local_peer_candidate_check`, `preflight_live_inbound_0x05`, `preflight_peer_driven_drain`), through the Run 213 routing helpers to the Run 211 evaluator. CLI-over-env precedence is preserved and invalid selector values fail closed before any runtime mutation. Fixture and emergency-council fixture execution remain DevNet/TestNet source/test only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `MainnetGovernanceRequired` and fixture approval; validation-only and mutating rejection surfaces remain non-mutating. Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation sibling selectors remain independent and compatible. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented; release-binary governance-execution runtime-arming evidence is deferred to **Run 218**. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 218 — release-binary governance-execution runtime-arming evidence

Run 218 is the **release-binary** evidence run for the Run 217 governance-execution runtime-arming carrier `GovernanceExecutionRuntimeArmingConfig` (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`). Operationally there is still **no behavior change by default**: with neither `--p2p-trust-bundle-governance-execution-policy` nor `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` set, the carrier resolves `GovernanceExecutionPolicy::Disabled` and legacy no-governance-execution payloads remain accepted (Run 214 compatibility). Run 218 proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_218_governance_execution_runtime_arming_release_binary_helper.rs`, driven by `scripts/devnet/run_218_governance_execution_runtime_arming_release_binary.sh`) that the hidden selector is consumed through the carrier and routed into the production preflight contexts: the CLI flag and env var both reach runtime arming, CLI-over-env precedence is deterministic at the runtime config boundary, and an invalid selector value fails closed before any runtime mutation — the binary emits the Run 217 FATAL (`invalid governance-execution policy selector … No runtime config is armed …`) and exits non-zero before the unrelated `--print-genesis-hash` requirement is evaluated. Operators should treat an invalid selector as a hard startup failure: fix the value and re-run; nothing is armed, no preflight runs, and no marker/sequence/trust state changes. Fixture and emergency-council fixture execution remain DevNet/TestNet evidence-only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `mainnet-governance-required` and fixture approval; rejected runtime-armed scenarios remain non-mutating. The live inbound `0x05` runtime config does not yet thread a per-connection governance-execution policy; this remains the documented limitation. The Run 193 custody, Run 199 RemoteSigner, Run 210 custody-attestation selectors and the Run 204 KMS/HSM and Run 202 RemoteSigner transport boundaries remain independent and compatible. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 219 — governance-execution runtime-surface gap audit

Run 219 is an **audit / spec / docs-only** run; there is **no behavior change** and nothing for operators to enable or configure. It maps every governance-execution runtime surface from the Run 211–218 sequence and records that, by default (`--p2p-trust-bundle-governance-execution-policy` and `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` both unset), `GovernanceExecutionRuntimeArmingConfig::from_cli_or_env` resolves `GovernanceExecutionPolicy::Disabled` and the live reload/SIGHUP/startup/local-peer-candidate paths run bit-for-bit as before. Operationally relevant findings: the hidden selector is parsed and fail-closed on invalid values at startup (unchanged from Run 216/218); the runtime arming carrier is constructed on the long-running path but its resolved outcome is not yet consumed to gate behavior, and the live sidecars carry no `governance_execution` payload (load status `Absent`), so an armed non-Disabled policy fails closed without mutating; the live inbound `0x05` per-connection policy is still not threaded and the peer-driven drain governance-execution wrapper has no production call site (the real drain path refuses MainNet independently). Across every surface, rejection remains non-mutating (no marker write, no sequence write, no live trust swap, no session eviction, no Run 070 apply call) and **MainNet peer-driven apply remains refused**. The audit selects the next closure sequence — **Run 220** (source/test long-running consumption wiring) and **Run 221** (release-binary consumption evidence) — without enabling any production behavior. Fixture and emergency-council fixture execution remain DevNet/TestNet evidence-only and non-production; production/on-chain/MainNet governance execution remains unavailable/fail-closed; validator-set rotation remains unsupported; KMS/HSM, RemoteSigner, and custody-attestation remain boundary-only. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented. See `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md`. **Full C4 remains OPEN; C5 remains OPEN.**
## Run 220 — governance-execution runtime consumption wiring (source/test)

Run 220 is **source/test** long-running governance-execution runtime
consumption wiring; there is still **nothing for operators to enable or
configure**, and default behavior is unchanged. Acting on the Run 219
finding, the four binary runtime call sites (reload-check, reload-apply,
startup `--p2p-trust-bundle`, local peer-candidate-check) and the SIGHUP
runtime hook now **consume** the selected `GovernanceExecutionPolicy` and
the **real** governance-execution sidecar load status: the previous
discard of the `arm_surface` outcome and the forced
`GovernanceExecutionLoadStatus::Absent` are removed on those surfaces, and
a rejected verdict fails closed **before** any mutation. By default
(`--p2p-trust-bundle-governance-execution-policy` and
`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` both unset) the
resolved policy remains `GovernanceExecutionPolicy::Disabled` and the
Disabled + absent-carrier path proceeds bit-for-bit as before Run 217 (a
legacy bypass), so live reload/SIGHUP/startup/local-peer-candidate paths
run exactly as before. Because binary/SIGHUP candidate metadata still
carries no governance proposal/decision bindings, a present carrier at the
binary surface reaches the Run 211 evaluator and fails closed on the
expectation mismatch; the live inbound `0x05` per-connection policy is
still not threaded, and full positive binary acceptance is deferred to
**Run 221**. Across every surface, rejection remains non-mutating (no
marker write, no sequence write, no live trust swap, no session eviction,
no Run 070 apply call) and **MainNet peer-driven apply remains refused**.
Fixture and emergency-council fixture execution remain DevNet/TestNet
evidence-only and non-production; production/on-chain/MainNet governance
execution remains unavailable/fail-closed; validator-set rotation remains
unsupported; KMS/HSM, RemoteSigner, and custody-attestation remain
boundary-only. No real governance execution engine, on-chain verifier,
KMS/HSM backend, RemoteSigner backend, or validator-set rotation is
implemented. Release-binary runtime-consumption evidence is deferred to
**Run 221**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**
## Run 221 — release-binary governance-execution runtime-consumption evidence

Run 221 is the **release-binary** evidence run for the Run 220 long-running
governance-execution runtime-consumption wiring; there is still **nothing
for operators to enable or configure**, and default behavior is unchanged.
With neither `--p2p-trust-bundle-governance-execution-policy` nor
`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` set, the resolved
policy remains `GovernanceExecutionPolicy::Disabled` and the Disabled +
absent-carrier path proceeds bit-for-bit as a legacy bypass (Run 214
compatibility). Run 221 proves on real `target/release/qbind-node` plus a
release-built helper (`crates/qbind-node/examples/run_221_governance_execution_runtime_consumption_release_binary_helper.rs`,
driven by `scripts/devnet/run_221_governance_execution_runtime_consumption_release_binary.sh`)
that the Run 220 consumption layer (`GovernanceExecutionRuntimeConsumption`,
`consume_surface`, `consume_surface_from_optional_sidecar_value`,
`governance_execution_load_status_from_optional_sidecar_value`) gates the
long-running path: the consumed outcome proceeds on the legacy bypass, fails
closed before any mutation on a rejected verdict, and reads the **real**
governance-execution sidecar load status from the optional sidecar value
rather than a forced `Absent` where representable. An invalid CLI or env
selector value fails closed before any runtime mutation — the binary emits
the Run 217 FATAL (`invalid governance-execution policy selector … No
runtime config is armed …`) and exits non-zero before the unrelated
`--print-genesis-hash` requirement is evaluated; operators should treat an
invalid selector as a hard startup failure. The live inbound `0x05`
per-connection policy threading and full positive binary acceptance remain
the documented limitation (binary/SIGHUP candidate metadata carries no
governance proposal/decision bindings). Across every surface, rejection
remains non-mutating (no marker write, no sequence write, no live trust
swap, no session eviction, no Run 070 apply call) and **MainNet peer-driven
apply remains refused**. Fixture and emergency-council fixture execution
remain DevNet/TestNet evidence-only and non-production;
production/on-chain/MainNet governance execution remains
unavailable/fail-closed; validator-set rotation remains unsupported;
KMS/HSM, RemoteSigner, and custody-attestation remain boundary-only. No real
governance execution engine, on-chain verifier, KMS/HSM backend,
RemoteSigner backend, or validator-set rotation is implemented. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_221.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**
## Run 222 — production governance-execution evaluator interface boundary

Run 222 is a **source/test** run that adds the typed production governance
execution **evaluator interface**
(`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`). There is
still **nothing for operators to enable or configure**, and default
behavior is unchanged: the evaluator interface is fail-closed by default
(`EvaluatorPolicy::Disabled`), and because it does not touch the runtime
call sites, the Run 220 runtime-consumption behavior is unchanged. The
interface models how a *future* governance engine would supply decisions
from a decision source, validate decision provenance, track replay, check
proposal/decision state, and return fail-closed production outcomes — it is
**not** a real governance engine and **not** a real on-chain governance
proof verifier. The fixture evaluator is DevNet/TestNet source/test only;
the emergency fixture evaluator is explicit and non-production;
production/on-chain/MainNet evaluators are callable but fail closed as
unavailable. **MainNet peer-driven apply remains refused** even with a
fixture evaluator approval; validator-set rotation remains unsupported;
KMS/HSM, RemoteSigner, and custody-attestation remain boundary-only. No real
governance execution engine, on-chain verifier, KMS/HSM backend,
RemoteSigner backend, or validator-set rotation is implemented.
Release-binary evaluator-interface evidence is deferred to **Run 223**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_222.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**
## Run 223 — release-binary governance-execution evaluator-interface evidence

Run 223 is the **release-binary evidence** companion to the Run 222
source/test production governance execution evaluator interface. There is
still **nothing for operators to enable or configure**: the evaluator
interface has no runtime CLI/env selector and no production call-site
wiring, default behavior is unchanged, and the evaluator interface is
fail-closed by default (`EvaluatorPolicy::Disabled`). Run 223 proves on real
`target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_223_governance_execution_evaluator_release_binary_helper.rs`,
driven by `scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh`)
that the release-built library code exposes and exercises the Run 222
interface: the deterministic source-identity / request / response /
transcript digests are stable and field-binding in release mode; the fixture
evaluator accepts only DevNet/TestNet decision sources under the explicit
fixture policy; the emergency-council fixture evaluator accepts only an
explicit emergency decision under the explicit emergency policy; an evaluator
response authorizes a lifecycle action only when the authorized action,
candidate digest, and sequence all match; production/on-chain/MainNet
evaluators are callable but fail closed as unavailable; the `Disabled` policy
stays inert so the Run 221 runtime-consumption behavior is unchanged; and the
peer-driven guard preserves the MainNet peer-driven apply refusal even with a
fixture approval. The release helper records 111 typed checks across accepted
(49) / rejection (42) / reachability (20) covering A1–A18 / R1–R40, and the
harness proves the release binary `--help` exposes no evaluator-interface
surface and the default DevNet/TestNet/MainNet surfaces make no
evaluator / production-governance / MainNet-governance / on-chain-verifier /
validator-set-rotation / KMS-HSM / RemoteSigner / autonomous-apply /
apply-on-receipt / peer-majority / MainNet-peer-driven-apply enablement claim
(22 forbidden patterns proven empty). It is **not** a real governance engine
and **not** a real on-chain governance proof verifier. The fixture evaluator
remains DevNet/TestNet evidence-only; the emergency fixture evaluator is
explicit and non-production; production/on-chain/MainNet evaluators remain
unavailable/fail-closed; **MainNet peer-driven apply remains refused**;
validator-set rotation remains unsupported; KMS/HSM, RemoteSigner, and
custody-attestation remain boundary-only. No real governance execution
engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or
validator-set rotation is implemented. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_223.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 224 — source/test governance evaluator runtime integration

Run 224 is a **source/test** run that integrates the Run 222 governance
evaluator interface into the Run 220 governance-execution runtime-consumption
pipeline at the source/test level. **The evaluator interface is now composed
into runtime consumption at the source/test level** via the new pure
integration layer
(`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`):
the pipeline calls Run 220 runtime consumption, then constructs and evaluates
the Run 222 evaluator request/response, then reconciles against Run 211
governance execution decision validation over the Run 213 payload material,
preserving the required ordering (selector resolution → load-status
derivation → runtime consumption → evaluator request construction → evaluator
evaluation → governance execution decision validation → mutation only after
all required checks pass). Mutation authorization (`ProceedMutate`) is
produced only when both the runtime-consumption stage and the evaluator stage
agree on the same lifecycle action / candidate digest / authority-domain
sequence; every rejection path is non-mutating — **no Run 070 call, no live
trust swap, no session eviction, no sequence write, no marker write** — and
the integration module exposes no mutation API. It is **not** a real
governance engine and **not** a real on-chain governance proof verifier. The
fixture evaluator remains DevNet/TestNet source-test only; the emergency
fixture evaluator is explicit and non-production; production/on-chain/MainNet
evaluators remain unavailable/fail-closed; **MainNet peer-driven apply remains
refused** even where a fixture evaluator would otherwise approve;
validator-set rotation remains unsupported; KMS/HSM, RemoteSigner, and
custody-attestation remain boundary-only. Operators gain no new runtime
CLI/env surface and no new mutation path. Coverage:
`crates/qbind-node/tests/run_224_governance_evaluator_runtime_integration_tests.rs`
(48 tests, A1–A12 / R1–R30, PASS). Release-binary evidence is deferred to
**Run 225**. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_224.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 225 — release-binary governance evaluator runtime integration evidence

Run 225 is the **release-binary evidence** companion to the Run 224 source/test
governance evaluator runtime integration. Run 224 landed the pure integration
layer
(`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`)
that composes Run 220 runtime consumption with the Run 222 evaluator interface
and Run 211 governance execution decision validation, and deferred
release-binary evidence. Run 225 proves on real `target/release/qbind-node`
plus a release-built helper
(`crates/qbind-node/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper.rs`,
driven by `scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh`)
that the release-built code exposes and exercises the integration: runtime
consumption composes with the evaluator interface in release mode, the
request/response binding is deterministic and field-checked, mutation
authorization (`ProceedMutate`) is produced only when both the runtime-consumption
stage and the evaluator stage agree (after the required ordering), the default
Disabled-policy + absent-carrier `ProceedLegacyBypass` is preserved, the
production/on-chain/MainNet evaluator paths are reached and fail closed as
unavailable, and **MainNet peer-driven apply remains refused** even with a
fixture evaluator approval. The release helper records 112 typed checks across
accepted (59) / rejection (37) / reachability (16) covering the full
A1–A15 / R1–R30 matrix, and the harness drives the real release binary to prove
`--help` exposes no integration surface and the default DevNet/TestNet/MainNet
surfaces make no integration / governance-execution / MainNet-governance /
on-chain-verifier / validator-set-rotation / KMS-HSM / RemoteSigner /
autonomous-apply / apply-on-receipt / peer-majority / MainNet-peer-driven-apply
enablement claim (24 forbidden patterns proven empty). Operators gain **no new
runtime CLI/env surface and no new mutation path**. It is **not** a real
governance engine and **not** a real on-chain governance proof verifier; the
fixture evaluator remains DevNet/TestNet evidence-only; the emergency fixture
evaluator is explicit and non-production; production/on-chain/MainNet evaluators
remain unavailable/fail-closed; validator-set rotation remains unsupported;
KMS/HSM, RemoteSigner, and custody-attestation remain boundary-only; existing
Run 221 and Run 223 release behaviour remains compatible. Validation: the
harness builds the release binary and helper, runs the helper (112/112 PASS),
drives release-binary scenarios S1–S4, and runs the
run_224/222/220/217/215/213/211 regression corpus plus `--lib` (all rc=0). See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_225.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 226 — source/test governance evaluator runtime call-site wiring

Run 226 is a **source/test** run that wires the existing Run 220
governance-execution runtime call sites through the Run 224 governance
evaluator integration layer. Where Run 224 landed the pure integration layer
and Run 225 proved it in release mode, the runtime call sites (reload-check,
reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
peer-candidate-check, live inbound `0x05`, peer-driven drain) still called the
Run 220 `consume_surface` path directly. Run 226 adds the call-site wiring
entry points (`wire_governance_evaluator_runtime_callsite` and
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`) and
routes `consume_run_220_governance_execution_runtime_outcome` (in `main.rs`)
and `consume_run_220_sighup_governance_execution_marker_decision` (in
`pqc_live_trust_reload.rs`) through the integration layer.

**Operator impact: none.** Operators gain **no new runtime CLI/env surface
and no new mutation path**. The default Disabled + absent-carrier path is
preserved (`ProceedLegacyBypass`); any present carrier at the binary call
sites fails closed (production unavailable or runtime-consumption rejection),
strictly stricter than the Run 220 behaviour it replaces; every rejection is
non-mutating. The binary marker/candidate metadata cannot yet carry a
governance proposal/decision evaluator binding, so the live inbound `0x05` and
peer-driven drain surfaces are wired at the source/test level but their full
positive evaluator binding is not yet representable from the binary
(documented limitation). It is **not** a real governance engine and **not** a
real on-chain governance proof verifier; the fixture evaluator remains
DevNet/TestNet source-test only; the emergency fixture evaluator is explicit
and non-production; production/on-chain/MainNet evaluators remain
unavailable/fail-closed; MainNet peer-driven apply remains refused;
validator-set rotation remains unsupported. Tests:
`crates/qbind-node/tests/run_226_governance_evaluator_runtime_callsite_wiring_tests.rs`
(59, A1–A17 / R1–R31, PASS). Release-binary call-site wiring evidence is
deferred to **Run 227**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_226.md` and
`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 227 — release-binary governance evaluator runtime call-site wiring evidence

Run 227 is the **release-binary evidence** run for the Run 226 governance
evaluator runtime call-site wiring. Where Run 226 wired the representable
Run 220 runtime call sites through the Run 224 integration layer at the
source/test level, Run 227 proves on real `target/release/qbind-node` plus a
release-built helper
(`crates/qbind-node/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper.rs`,
driven by
`scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`)
that the release-built code exposes and exercises the Run 226 wiring entry
points (`wire_governance_evaluator_runtime_callsite` and
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`).

**Operator impact: none.** Run 227 introduces no production source behavior
change, no new runtime CLI/env surface, and no new mutation path. The release
helper PASSes an A1–A23 / R1–R31 / reachability corpus (144 checks): the
representable call sites consume the
`GovernanceEvaluatorRuntimeIntegrationOutcome` (consumed, not discarded), the
default Disabled + absent-carrier legacy bypass is preserved
(`ProceedLegacyBypass`), a present carrier without evaluator context fails
closed, and every rejection is non-mutating. The real binary scenarios
confirm the default surfaces make no call-site wiring claims and that an
invalid governance-execution selector fails closed before mutation (no marker
write, no sequence write, no live trust swap, no session eviction, no Run 070
call); a 26-pattern denylist is proven empty. The live inbound `0x05` and
peer-driven drain surfaces remain wired but not fully representable from the
binary (documented limitation). Production/on-chain/MainNet evaluators remain
unavailable/fail-closed; the fixture evaluator remains DevNet/TestNet
evidence-only; the emergency fixture evaluator is explicit and non-production;
MainNet peer-driven apply remains refused; validator-set rotation remains
unsupported; no real governance engine or on-chain proof verifier is
implemented; Run 221/223/225 release behaviour remains compatible. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_227.md` and
`docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary/`.

## Run 228 — source/test peer evaluator-context representation boundary

Run 228 adds a typed **evaluator-context representation boundary** for the
live inbound `0x05` peer-candidate validation and peer-driven drain surfaces
(`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`, registered
in `crates/qbind-node/src/lib.rs`, with
`crates/qbind-node/tests/run_228_peer_evaluator_context_representation_tests.rs`,
48 tests A1–A14 / R1–R27, PASS). It lets these surfaces carry or reference an
evaluator context in source/test plumbing where representable and routes that
context into the Run 226 call-site wiring → Run 224 integration layer →
Run 222 evaluator interface.

**Operator impact: none.** Run 228 is source/test only, introduces no
production source behavior change, no new runtime CLI/env surface, and no new
mutation path, and changes no wire/schema/marker/sequence/trust-bundle format.
The carrier taxonomy (`Absent`, `Present`, `Malformed`, `UnsupportedSurface`,
`WireSchemaUnavailable`, `PeerMajorityUnsupported`, `MainNetRefused`)
represents the live-wire path that cannot carry an evaluator binding as a
typed `WireSchemaUnavailable` fail-closed status — never an approval. The
default Disabled + absent-carrier path preserves legacy validation; a present
well-formed context routes through the integration layer; any
unsupported/malformed/no-carrier status under an explicit evaluator policy is
typed fail-closed; only the routed `ProceedMutate` outcome authorizes apply.
Invalid live inbound `0x05` candidates are not propagated, staged, or applied;
invalid peer-driven drain candidates are not applied; every rejection is
non-mutating (no marker write, no sequence write, no live trust swap, no
session eviction, no Run 070 call). Production/on-chain/MainNet evaluators
remain unavailable/fail-closed; the fixture evaluator remains DevNet/TestNet
evidence-only; the emergency fixture evaluator is explicit and non-production;
MainNet peer-driven apply remains refused; validator-set rotation remains
unsupported; no real governance engine or on-chain proof verifier is
implemented. Release-binary evidence is deferred to **Run 229**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_228.md`.

## Run 229 — release-binary peer evaluator-context representation evidence

Run 229 is the **release-binary evidence** run for the Run 228 peer
evaluator-context representation boundary
(`crates/qbind-node/examples/run_229_peer_evaluator_context_representation_release_binary_helper.rs`,
`scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`,
`docs/devnet/run_229_peer_evaluator_context_representation_release_binary/`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_229.md`). It proves on real
`target/release/qbind-node` plus a release-built helper using the production
library symbols (170 typed checks across accepted/rejection/reachability,
`verdict: PASS`) that the release-built code exposes and exercises the Run 228
representation boundary.

**Operator impact: none.** Run 229 is release-binary evidence only, introduces
no production source behavior change, no new runtime CLI/env surface, and no
new mutation path, and changes no wire/schema/marker/sequence/trust-bundle
format. The release evidence reconfirms the default Disabled + absent-carrier
path preserves legacy validation, a `Present` context routes through the
Run 226 wiring into the Run 224 integration where representable,
`WireSchemaUnavailable` is fail-closed and never an approval, invalid live
inbound `0x05` is not propagated/staged/applied, invalid peer-driven drain is
not applied, MainNet peer-driven apply remains refused, and production/on-chain/
MainNet evaluators remain unavailable/fail-closed. The real release binary
makes no peer evaluator-context claims and an invalid governance-execution
selector fails closed before mutation; a 26-pattern denylist is proven empty;
regression targets run_228/226/224/222/220/217/215/213/211/157/152/150/148/142,
`--lib pqc_authority`, and `--lib` all PASS. Validator-set rotation remains
unsupported; no real governance engine or on-chain proof verifier is
implemented. **Full C4 remains OPEN; C5 remains OPEN.** See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_229.md`.
**Full C4 remains OPEN; C5 remains OPEN.**

## Run 230 — source/test governance evaluator replay/freshness state boundary

Run 230 is source/test governance evaluator replay/freshness state boundary work. It defines a typed, pure, fail-closed replay/freshness state boundary (`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`, registered in `lib.rs`, with `crates/qbind-node/tests/run_230_governance_evaluator_replay_state_tests.rs`, 52 tests, PASS) that decides — before any lifecycle mutation — whether an evaluator decision is fresh, not-yet-effective, expired, stale, a replay, already consumed, superseded, bound to the wrong domain, or unavailable. Only `ProceedFresh` authorizes a mutation; `ProceedDeferred` is not an approval. A DevNet/TestNet in-memory `FixtureReplayStateStore` is the only store that records anything and records a consumed decision only on an explicit consume call (read-only validation never consumes); the production/MainNet readers/writers are callable but always unavailable/fail-closed.

## Run 231 — release-binary governance evaluator replay/freshness state evidence

Run 231 is the **release-binary evidence** run for the Run 230 governance evaluator replay/freshness state boundary (`crates/qbind-node/examples/run_231_governance_evaluator_replay_state_release_binary_helper.rs`, `scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`, `docs/devnet/run_231_governance_evaluator_replay_state_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_231.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (207 typed checks across accepted/rejection/reachability, `verdict: PASS`) that the release-built code exposes and exercises the Run 230 replay/freshness state boundary: only `ProceedFresh` authorizes a mutation; fresh, not-yet-effective (deferred), expired, stale, replayed, already-consumed, superseded, wrong-binding, and state/production/MainNet-unavailable outcomes are distinguished and every non-`ProceedFresh` outcome is non-mutating.

**Operator impact: none.** Run 231 is release-binary evidence only, introduces no production source behavior change, no new runtime CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format. The release evidence reconfirms the default Disabled / not-wired path preserves legacy validation, the DevNet/TestNet `FixtureReplayStateStore` records a consumed decision only on an explicit consume call while read-only validation never consumes, and the production/MainNet replay-state readers remain callable-but-unavailable/fail-closed. The real release binary makes no replay/freshness state claims and an invalid governance-execution selector fails closed before mutation (no marker write, no sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty; regression targets run_230/228/226/224/222/220/217/215/213/211/157/152/150/148/142, `--lib pqc_authority`, and `--lib` all PASS. MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_231.md`.

**Operator impact: none.** Run 230 is source/test only, introduces no production source behavior change, no new runtime CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format. Fixture replay state is DevNet/TestNet source-test only; production/MainNet replay state remains unavailable/fail-closed. The boundary is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) so every rejection is non-mutating. MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation remains unsupported; no real governance engine or on-chain proof verifier is implemented. Release-binary replay/freshness evidence is deferred to **Run 231**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_230.md`.

## Run 232 — source/test governance evaluator replay/freshness runtime integration

Run 232 is source/test governance evaluator replay/freshness runtime integration work. Where Run 230 defined the replay/freshness state boundary as a standalone module and Run 231 closed its release-binary evidence, the boundary was not yet integrated into the evaluator runtime integration path as a mandatory pre-mutation gate. Run 232 adds a pure integration layer (`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`, registered in `lib.rs`, with `crates/qbind-node/tests/run_232_governance_evaluator_replay_runtime_integration_tests.rs`, 47 tests, PASS) whose entry point `integrate_governance_evaluator_replay_runtime` composes the Run 224 evaluator-runtime integration, the Run 226 runtime call-site wiring, the Run 228 peer evaluator context (where relevant), and the Run 230 replay/freshness state boundary so the runtime integration path runs replay/freshness validation **before any mutation authorization**. The typed `GovernanceEvaluatorReplayRuntimeOutcome` distinguishes `ProceedLegacyBypass` / `ProceedDeferred` / `ProceedFresh` (the only mutation-authorizing outcome) / `ReplayFreshnessFailClosed` / `RuntimeIntegrationFailClosed` / `MainNetPeerDrivenApplyRefused`; `ProceedDeferred` is not an approval.

**Operator impact: none.** Run 232 is source/test only, introduces no production source behavior change, no new runtime CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format. The default Disabled / not-wired replay policy preserves the legacy validation path. The integration is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) so every non-`ProceedFresh` outcome is non-mutating; it never marks a decision consumed (read-only validation never consumes; explicit consume remains fixture-only, performed by the caller after a fresh authorization). Fixture replay state remains DevNet/TestNet source-test only; production/MainNet replay state remains unavailable/fail-closed. MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Validation: `cargo build -p qbind-node --lib` PASS; run_232 (47), run_230 (52), run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), `--lib pqc_authority` (164), and `--lib` (1355) all PASS. Release-binary replay/freshness runtime-integration evidence is deferred to **Run 233**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_232.md`.

## Run 233 — release-binary governance evaluator replay/freshness runtime integration evidence

Run 233 is the **release-binary evidence** run for the Run 232 governance evaluator replay/freshness runtime integration (`crates/qbind-node/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`, `docs/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_233.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (184 typed checks across accepted A1–A17 / rejection R1–R27 / reachability, `verdict: PASS`) that the release-built code exposes and exercises the Run 232 composed runtime integration: only `ProceedFresh` authorizes a mutation — and only after the Run 224 layer authorized a mutate and the Run 230 state classified the decision fresh; legacy-bypass, deferred (not-yet-effective), and replay/freshness or runtime-integration fail-closed outcomes are distinguished and every non-`ProceedFresh` outcome is non-mutating.

**Operator impact: none.** Run 233 is release-binary evidence only, introduces no production source behavior change, no new runtime CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format. The release evidence reconfirms the default Disabled / not-wired path preserves legacy validation, the integration never marks a decision consumed (read-only validation never consumes; explicit consume remains fixture-only, performed by the caller after a fresh authorization), and the production/MainNet replay-state readers remain callable-but-unavailable/fail-closed. The real release binary makes no replay-runtime claims and an invalid governance-execution selector fails closed before mutation (no marker write, no sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty; regression targets run_232/230/228/226/224/222/220/217/215/213/211/157/152/150/148/142, `--lib pqc_authority`, and `--lib` all PASS. MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Existing Run 231/229/227/225/223 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_233.md`.

## Run 234 — source/test governance evaluator post-mutation replay consume boundary

Run 234 is the **source/test** run that models the post-mutation replay-state consume step as a strict after-success-only boundary (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_boundary.rs`, registered in `crates/qbind-node/src/lib.rs`, plus `crates/qbind-node/tests/run_234_governance_evaluator_replay_consume_boundary_tests.rs`, 58 tests A1-A18 / R1-R33, PASS). It separates four phases — pre-mutation freshness validation, mutation authorization (`MutationAuthorizationOutcome`), successful mutation completion (`MutationCompletionStatus`), and an explicit replay-state consume after success only — resolving a typed `ConsumeBoundaryOutcome`. Consume is after-success-only: only `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) authorizes a fixture consume via the Run 230 DevNet/TestNet writer; deferred, validation-only, authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume. Production/MainNet consume writers are callable but always fail closed unavailable.

**Operator impact: none.** Run 234 is source/test only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format — it implements no persistent storage at all. Evaluation is pure (no Run 070 call, no live trust swap, no session eviction, no marker/sequence write), and the writer is never called on a non-consume path. Fixture consume remains DevNet/TestNet source-test only; production/MainNet consume remains unavailable/fail-closed. MainNet peer-driven apply remains refused and never consumes even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. The Run 232 runtime integration remains compatible when the consume boundary is not wired. Regression: run_234 (58), run_232 (47), run_230 (52), run_228 (48), run_226 (59), run_224 (48), run_222 (60), `--lib pqc_authority` (164), and `--lib` (1355) all PASS. Release-binary consume-boundary evidence is deferred to **Run 235**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_234.md`.
## Run 235 — release-binary governance evaluator post-mutation replay consume boundary evidence

Run 235 is the **release-binary** evidence run for the Run 234 post-mutation replay-state consume boundary (`crates/qbind-node/examples/run_235_governance_evaluator_replay_consume_boundary_release_binary_helper.rs`, `scripts/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary.sh`, `docs/devnet/run_235_governance_evaluator_replay_consume_boundary_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_235.md`). Where Run 234 landed the consume boundary at the source/test level, Run 235 proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`evaluate_post_mutation_consume`, `perform_post_mutation_consume`, `MutationAuthorizationOutcome`, `MutationCompletionStatus`, the `ConsumeBoundaryOutcome` taxonomy, and the consume authorization/transcript/record digest helpers) that the release-built code exposes and exercises the consume boundary. The release helper records 225 typed checks across accepted (A1–A21)/rejection (R1–R33)/reachability with `pass=225`, `fail=0`: consume is after-success-only — only `ConsumeFixtureAfterSuccess` (after `AppliedSuccessfully`) authorizes a fixture consume via the Run 230 DevNet/TestNet writer; deferred, validation-only, authorized-but-not-applied, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume; production/MainNet consume writers are callable but always fail closed unavailable.

**Operator impact: none.** Run 235 is release-binary evidence only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format — it implements no persistent storage at all. The harness drives the real release binary to prove the default DevNet/TestNet/MainNet surfaces make no consume-boundary claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty. Fixture consume remains DevNet/TestNet evidence-only; production/MainNet consume remains unavailable/fail-closed. MainNet peer-driven apply remains refused and never consumes even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine or on-chain proof verifier is implemented. Regression: run_234, run_232, run_230, run_228, run_226, run_224, run_222, run_220, run_217, run_215, run_213, run_211, run_157, run_152, run_150, run_148, run_142, `--lib pqc_authority`, and `--lib` all PASS; existing Run 233/231/229/227/225 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_235.md`.

## Run 236 — source/test governance evaluator replay consume runtime integration

Run 236 composes the Run 232 replay/freshness runtime integration with the Run 234 post-mutation consume boundary into a single lifecycle integration layer (`crates/qbind-node/src/pqc_governance_evaluator_replay_consume_runtime_integration.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_236_governance_evaluator_replay_consume_runtime_integration_tests.rs`, 56 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_236.md`). `integrate_replay_consume_runtime` runs the Run 232 runtime integration first and maps any non-`ProceedFresh` outcome directly to the matching non-consuming Run 236 outcome without calling the consume writer; only on `ProceedFresh` does it override the consume binding's mutation-authorization outcome with the Run 232-derived `AuthorizedFresh`, run `perform_post_mutation_consume`, and project the Run 234 `ConsumeBoundaryOutcome` into the composed `ReplayConsumeRuntimeOutcome` taxonomy. Consume is integrated as an after-success-only post-mutation step: only `ConsumeFixtureAfterMutationSuccess` authorizes a fixture consume, and only after a successful mutation completion; fresh is required before mutation authorization; deferred, validation-only, before-apply, failed-apply, rolled-back, unsupported-surface, and MainNet-refused outcomes never consume.

**Operator impact: none.** Run 236 is source/test only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format — it implements no persistent storage at all. The composition is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so a rejection is non-mutating and the writer is never called on a non-consume path. Fixture consume remains DevNet/TestNet source-test only; production/MainNet consume remains unavailable/fail-closed. MainNet peer-driven apply remains refused and never consumes even when the replay state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 234/232 behaviour remains compatible. Release-binary consume-runtime-integration evidence is deferred to **Run 237**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_236.md`.

## Run 237 — release-binary governance evaluator replay consume runtime integration evidence

Run 237 is the release-binary evidence run for the Run 236 source/test governance evaluator replay consume runtime integration (`crates/qbind-node/examples/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary_helper.rs`, driven by `scripts/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary.sh`, `docs/devnet/run_237_governance_evaluator_replay_consume_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_237.md`). The release-built helper exercises the Run 236 symbols (`integrate_replay_consume_runtime`, `wire_replay_consume_runtime_callsite`, the `ReplayConsumeRuntimeIntegrationInput` binding, the `ReplayConsumeRuntimeOutcome` taxonomy, and the invariant guard functions) through production library code on real `target/release/qbind-node`, recording 254 typed checks across accepted (A1-A23)/rejection (R1-R35)/reachability with `verdict: PASS`. The Run 232 replay/freshness runtime integration runs before consume; fresh is required before mutation authorization; consume is after-success-only — only `ConsumeFixtureAfterMutationSuccess` (after `AppliedSuccessfully`) authorizes a fixture consume.

**Operator impact: none.** Run 237 is release-binary evidence only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path, and changes no wire/schema/marker/sequence/trust-bundle format and no RocksDB/file/schema/migration/storage format — it implements no persistent storage at all. The harness drives the real release binary to prove the default DevNet/TestNet/MainNet surfaces make no consume-runtime-integration claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty. Fixture consume remains DevNet/TestNet evidence-only; production/MainNet consume remains unavailable/fail-closed. MainNet peer-driven apply remains refused and never consumes even when state is fresh; validator-set rotation and policy-change actions remain unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_236, run_234, run_232, run_230, run_228, run_226, run_224, run_222, run_220, run_217, run_215, run_213, run_211, run_157, run_152, run_150, run_148, run_142, `--lib pqc_authority`, and `--lib` all PASS; existing Run 235/233/231/229/227 release behaviour remains compatible. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_237.md`.
## Run 238 — source/test governance evaluator replay-state durable backend boundary

Run 238 defines a typed, pure durable backend contract for the governance evaluator replay/freshness state — the durability, atomicity, crash-window, and fail-closed semantics a real persistent replay-state store must honour — plus a DevNet/TestNet in-memory fixture that models those semantics (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_backend.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_238_governance_evaluator_replay_durable_backend_tests.rs`, 68 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_238.md`). It adds `DurableBackendDecisionInput`/`DurableBackendDecisionExpectations` (derived from a Run 230 `EvaluatorReplayFreshnessInput` via `from_freshness_input`, carrying the Run 230 `replay_state_key_digest`); the typed `DurableRecordState`/`DurableBackendOutcome`/`DurableConsumeOutcome`/`CrashWindow`/`DurableBackendKind`/`DurableMutationCompletion` enums; reader/writer/atomic traits and the pure operations `read_decision_state`/`observe_decision_if_absent`/`mark_consumed_after_success`/`compare_and_mark_consumed`; a fixture that models observed/consumed/replayed/superseded states with restart durability via `restart_snapshot`/`from_snapshot` over a `DurableBackendSnapshot` value clone; and `classify_crash_window`.

**Operator impact: none.** Run 238 is source/test only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path. It defines a typed durable backend contract but implements **no** production persistence: there is **no** RocksDB backend, **no** file format, **no** schema, **no** database migration, and **no** storage-format change. Restart durability is modeled only through a source/test fixture snapshot (an in-process value clone, not a file). The fixture durable backend is DevNet/TestNet source-test only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed. Compare-and-mark-consumed consumes only on an exactly-`ObservedFresh` record after a successful mutation and fails closed on any non-fresh/superseded/already-consumed state. The contract is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating. MainNet peer-driven apply remains refused and never observes or consumes even when the would-be state is fresh; validator-set rotation remains unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 236/234/232/230 behaviour remains compatible. Release-binary durable-backend evidence is deferred to **Run 239**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_238.md`.

## Run 239 — release-binary governance evaluator replay-state durable backend boundary evidence

Run 239 is the release-binary evidence run for the Run 238 source/test durable replay-state backend boundary (`crates/qbind-node/examples/run_239_governance_evaluator_replay_durable_backend_release_binary_helper.rs`, `scripts/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary.sh`, `docs/devnet/run_239_governance_evaluator_replay_durable_backend_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_239.md`). It proves on real `target/release/qbind-node` plus a release-built helper that the release-built code exposes and exercises the Run 238 durable backend contract through production library symbols (`read_decision_state`/`observe_decision_if_absent`/`mark_consumed_after_success`/`compare_and_mark_consumed`/`classify_crash_window`, the `DurableBackendDecisionInput`/`DurableBackendDecisionExpectations` binding, the `DurableRecordState`/`DurableBackendOutcome`/`DurableConsumeOutcome`/`CrashWindow`/`DurableBackendKind`/`DurableMutationCompletion` taxonomies, the reader/writer/atomic traits, the `FixtureDurableReplayBackend` `restart_snapshot`/`from_snapshot` durability model, and the production/MainNet unavailable backends), recording an A1-A25 / R1-R37 corpus of 202 typed checks (`pass=202`, `fail=0`, `verdict: PASS`).

**Operator impact: none.** Run 239 is release-binary evidence only: it adds one release-built example helper, one harness script, one evidence archive (tracking only README.md/summary.txt/.gitignore), the canonical report, and narrow doc updates, with no production runtime behavior change, no new CLI/env surface, and no new mutation path. A first-seen DevNet/TestNet decision records `ObservedFresh` and reads `ProceedKnownFresh`; not-yet-effective reads deferred (not a mutation approval); expired/stale read fail-closed; an explicit consume after a successful mutation marks consumed, after which the decision reads `FailClosedConsumed`; read-only validation, rollback, and failed-apply never consume; observe-only and consumed state both survive an in-process fixture restart snapshot (a value clone, never a file format); compare-and-mark-consumed atomicity is release-evidenced (it consumes only on an exactly-`ObservedFresh` record and rejects a wrong expected state); the crash-window classifier types every window and never silently approves an after-mutation-before-consume window; the durable digests are deterministic in release mode; production/MainNet durable backends remain callable-but-unavailable/fail-closed; MainNet peer-driven apply remains refused even when the fixture reads fresh; and validator-set rotation and policy-change actions remain unsupported. **No** real persistent replay backend, RocksDB schema, file format, database migration, or storage-format change is implemented; no real governance engine, mutation engine, or on-chain proof verifier. The harness drives the real release binary to prove the default surfaces make no durable-backend/persistent-replay claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty. Regression: run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, run_222, run_220, run_217, run_215, run_213, run_211, run_157, run_152, run_150, run_148, run_142, `--lib pqc_authority`, and `--lib` all PASS; existing Run 237/235/233/231/229 release behaviour remains compatible; no weakening of Runs 070, 130-238. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_239.md`.
## Run 240 — source/test governance evaluator durable replay backend runtime integration

Run 240 wires the Run 238 typed durable replay-state backend boundary into the Run 236 / 232 / 230 replay/freshness + after-success-only consume runtime path as the **durable state provider** (`crates/qbind-node/src/pqc_governance_evaluator_replay_durable_runtime_integration.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_240_governance_evaluator_replay_durable_runtime_integration_tests.rs`, 63 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_240.md`). The durable replay backend is integrated as a typed runtime state provider only: `integrate_durable_replay_runtime` performs the durable read/observe **before** mutation authorization, the Run 230 / 232 replay/freshness runtime still gates authorization, and `recover_durable_replay_runtime_crash_window` / `wire_durable_replay_runtime_callsite` keep crash-window and call-site handling fail-closed.

**Operator impact: none.** Run 240 is source/test only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path. No real persistent replay backend is implemented: there is **no** RocksDB backend, **no** file format, **no** schema, **no** database migration, and **no** storage-format change. The fixture durable backend remains DevNet/TestNet source-test only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; the fixture restart snapshot models durability only for source/test evidence (an in-process value clone, not a file). A durable compare-and-mark-consumed runs only after a modeled `AppliedSuccessfully` mutation on an exactly-`ObservedFresh` record; a read-only validation surface observes but never consumes; apply-failed and rolled-back never consume; every determinable crash window fails closed. The composition is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write), so every rejection is non-mutating. MainNet peer-driven apply remains refused even when the durable state reads fresh; validator-set rotation remains unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 238/236/234/232/230 behaviour remains compatible. Release-binary durable-runtime integration evidence is deferred to **Run 241**. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_240.md`.


## Run 241 — release-binary governance evaluator durable replay backend runtime integration evidence

Run 241 is the release-binary evidence run for the Run 240 source/test durable replay backend runtime integration (`crates/qbind-node/examples/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary.sh`, `docs/devnet/run_241_governance_evaluator_replay_durable_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_241.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`integrate_durable_replay_runtime`, `recover_durable_replay_runtime_crash_window`, `wire_durable_replay_runtime_callsite`, the `DurableReplayRuntimeIntegrationInput` binding, the `DurableReplayRuntimeOutcome` taxonomy, and the invariant/refusal helpers) that the release-built code exposes and exercises the Run 240 integration; the release helper A1–A27 / R1–R38 corpus passes 203/203.

**Operator impact: none.** Run 241 is release-binary evidence only and introduces no production source behavior change, no new CLI/env surface, and no new mutation path. The durable read/observe runs before mutation authorization, the Run 230 / 232 replay/freshness runtime still gates authorization, a durable compare-and-mark-consumed runs only after a modeled `AppliedSuccessfully` mutation on an exactly-`ObservedFresh` record, read-only validation/failed-apply/rollback never consume, and every determinable crash window fails closed. The fixture durable backend remains DevNet/TestNet evidence-only; the production/MainNet durable backends remain callable-but-unavailable/fail-closed; the fixture restart snapshot models durability only for release evidence (an in-process value clone, not a file). No real persistent replay backend is implemented: there is **no** RocksDB backend, **no** file format, **no** schema, **no** database migration, and **no** storage-format change. The harness drives the real release binary to prove the default surfaces make no durable-runtime-integration claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist of forbidden "active/enabled" claims is proven empty. MainNet peer-driven apply remains refused even when the durable state reads fresh; validator-set rotation remains unsupported; no real governance engine, mutation engine, or on-chain proof verifier is implemented. Regression: run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, the broader regression set, `--lib pqc_authority`, and `--lib` all PASS; existing Run 239/237/235/233/231 release behaviour remains compatible; no weakening of Runs 070, 130–240. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_241.md`.

## Run 242 — source/test governance execution mutation-engine boundary

Run 242 makes the hand-off of an already-authorized governance evaluator decision to a future mutation executor explicit and typed (`crates/qbind-node/src/pqc_governance_execution_mutation_engine.rs`, registered in `crates/qbind-node/src/lib.rs`, `crates/qbind-node/tests/run_242_governance_execution_mutation_engine_tests.rs`, 38 tests PASS, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_242.md`). It introduces a typed mutation-engine boundary, not a real production mutation engine.

**Operator impact: none.** Run 242 is source/test only, introduces no production runtime behavior change, no new CLI/env surface, and no new mutation path. No real mutation engine is implemented: the fixture executors model success/failure/rollback/ambiguous outcomes and perform no real trust mutation; the production/MainNet mutation engines remain callable-but-unavailable/fail-closed. The engine refuses MainNet peer-driven apply before any mutation attempt, honours the legacy no-mutation bypass, validates the binding before any apply (a wrong environment/chain/genesis/governance surface/mutation surface/candidate digest/decision digest/proposal id/decision id/authority-domain sequence/lifecycle action, or a malformed candidate, is rejected and never reaches the executor), never mutates on a read-only validation surface, and treats validator-set rotation and policy-change actions as unsupported. Only a modeled `MutationAppliedSuccessfully` projects to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`; failed apply, rollback, and ambiguous after-authorization windows never consume. The engine is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker/durable write of its own), so every rejection is non-mutating. No real governance execution engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented; there is **no** RocksDB/file/schema/migration/storage-format change and **no** wire/marker/sequence/trust-bundle change. Regression: run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 240/238/236/234/232/230 behaviour remains compatible; no weakening of Runs 070, 130–241. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_242.md`.
## Run 243 — release-binary governance execution mutation-engine boundary evidence

Run 243 is the release-binary evidence run for the Run 242 source/test governance execution mutation-engine boundary (`crates/qbind-node/examples/run_243_governance_execution_mutation_engine_release_binary_helper.rs`, `scripts/devnet/run_243_governance_execution_mutation_engine_release_binary.sh`, `docs/devnet/run_243_governance_execution_mutation_engine_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_243.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`evaluate_governance_mutation_engine`, `recover_governance_mutation_window`, `wire_governance_mutation_engine_callsite`, `project_mutation_outcome_to_durable_completion`, the typed bindings, the `GovernanceMutationEngineKind`/`GovernanceMutationOutcome` taxonomy, the `GovernanceMutationExecutor` trait with `FixtureMutationExecutor`/`ProductionMutationExecutor`/`MainNetMutationExecutor`, and the grep-verifiable invariant helpers) that the release-built code exposes and exercises the Run 242 boundary; the release helper corpus passes 206/206 (accepted/rejection/recovery/projection/reachability).

**Operator impact: none.** Run 243 is release-binary evidence only and introduces no production source behavior change, no new CLI/env surface, and no new mutation path. A Disabled policy/engine kind is a legacy no-mutation bypass with no executor invocation; binding validation runs before any apply and a mismatch is a non-mutating reject-before-apply that never reaches the executor; a read-only validation surface never mutates; only a modeled `MutationAppliedSuccessfully` projects to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`, while authorized-not-applied, failed apply, rollback, and ambiguous after-authorization windows never consume; production/MainNet engine kinds are reachable but always unavailable/fail-closed. The harness drives the real release binary to prove the default DevNet/TestNet/MainNet smoke surfaces and `--help` make no mutation-engine enablement claims, the hidden governance-execution selector still parses, and an invalid selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a 32-pattern denylist of forbidden "active/enabled" claims is proven empty. Run 243 also narrowly fixes a Run 242 docs typo (`` `Production`/`MainNetMutationUnavailable` `` → `` `ProductionMutationUnavailable` / `MainNetMutationUnavailable` ``). MainNet peer-driven apply remains refused before binding validation and before executor invocation; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine, mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented; there is **no** RocksDB/file/schema/migration/storage-format change and **no** wire/marker/sequence/trust-bundle change. Regression: run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 242/241 behaviour remains compatible; no weakening of Runs 070, 130–242. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_243.md`.
## Run 244 — source/test governance modeled trust-state mutation applier boundary

Run 244 is **source/test only**. It adds the smallest in-memory model of what a future governance mutation applier would do after every Run 242 mutation-engine gate has already passed (`crates/qbind-node/src/pqc_governance_modeled_trust_mutation_applier.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_244_modeled_governance_trust_mutation_applier_tests.rs`, 45 tests; evidence in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_244.md`). Where Run 242/243 modeled only mutation *outcomes*, Run 244 adds a modeled in-memory state transition: it snapshots a modeled trust state (`ModeledGovernanceTrustState`/`ModeledGovernanceTrustSnapshot`/`ModeledGovernanceTrustRoot`), applies a modeled trust-state update (`ModeledGovernanceTrustMutation` with `AddTrustRoot`/`RetireTrustRoot`/`RevokeTrustRoot`/`EmergencyRevokeTrustRoot`/`Noop` and unsupported `ValidatorSetRotationUnsupported`/`PolicyChangeUnsupported`), reports the typed `ModeledTrustMutationOutcome`, and projects the result through the Run 242 `GovernanceMutationOutcome` into the Run 240 `DurableMutationCompletion`. The pure/mockable `ModeledGovernanceTrustMutationApplier` trait has a DevNet/TestNet `FixtureModeledTrustMutationApplier` (invocation-counted) plus `ProductionModeledTrustMutationApplier`/`MainNetModeledTrustMutationApplier` (always unavailable/fail-closed); the entry point `evaluate_modeled_trust_mutation` enforces MainNet peer-driven refusal → legacy bypass → binding validation (reject before snapshot) → read-only validation gating → unsupported-action gating → applier-kind routing → applier hand-off, and `recover_modeled_trust_mutation` fails closed on every ambiguous/unknown window.

**Operationally Run 244 changes nothing.** The modeled applier mutates ONLY the in-memory `ModeledGovernanceTrustState` in DevNet/TestNet fixture tests; it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself. Only a modeled `ModeledMutationApplied` becomes consume-eligible; rejected/failed/rollback/rollback-failed/ambiguous/unavailable/unsupported outcomes never consume. No real production mutation engine, governance execution engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no weakening of Runs 070, 130–243. Validation: run_244 (45) plus the regression corpus run_242 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN; C5 remains OPEN.
## Run 245 — release-binary governance modeled trust-state mutation applier evidence

Run 245 is the release-binary evidence run for the Run 244 source/test governance modeled trust-state mutation applier boundary (`crates/qbind-node/examples/run_245_modeled_governance_trust_mutation_applier_release_binary_helper.rs`, `scripts/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary.sh`, `docs/devnet/run_245_modeled_governance_trust_mutation_applier_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_245.md`). It proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`evaluate_modeled_trust_mutation`, `recover_modeled_trust_mutation`, `map_modeled_outcome_to_mutation_engine_outcome`, `project_modeled_outcome_to_durable_completion`, `modeled_outcome_authorizes_durable_consume`, the `ModeledGovernanceTrustState`/`ModeledGovernanceTrustSnapshot`/`ModeledGovernanceTrustRoot` modeled state, the typed bindings, the `ModeledTrustMutationAction`/`ModeledTrustMutationOutcome` taxonomy, the `ModeledGovernanceTrustMutationApplier` trait with `FixtureModeledTrustMutationApplier`/`ProductionModeledTrustMutationApplier`/`MainNetModeledTrustMutationApplier`, and the grep-verifiable invariant helpers) that the release-built code exposes and exercises the Run 244 boundary; the release helper corpus passes 221/221 (accepted/rejection/recovery/projection/modeled-state/reachability).

**Operator impact: none.** Run 245 is release-binary evidence only and introduces no production source behavior change, no new CLI/env surface, and no new mutation path. A disabled policy/applier kind is a legacy no-mutation bypass with no applier invocation; binding validation runs before any snapshot and a mismatch is a non-mutating reject-before-snapshot that never reaches the applier; a read-only validation surface never mutates; retiring/revoking a missing root snapshots then rejects before apply with the modeled state unchanged; only a modeled `ModeledMutationApplied` projects through `MutationAppliedSuccessfully` to the consume-eligible `DurableMutationCompletion::AppliedSuccessfully`, while not-attempted, failed apply, rollback, rollback-failed, and ambiguous windows never consume; production/MainNet applier kinds are reachable but always unavailable/fail-closed. The harness drives the real release binary to prove the default DevNet/TestNet/MainNet smoke surfaces and `--help` make no modeled-applier enablement claims, the hidden governance-execution selector still parses, and an invalid selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a 36-pattern denylist of forbidden "active/enabled" claims is proven empty. Run 245 also narrowly fixes a Run 244 docs typo (`` `Production`/`MainNetModeledMutationUnavailable` `` → `` `ProductionModeledMutationUnavailable` / `MainNetModeledMutationUnavailable` ``). MainNet peer-driven apply remains refused before any snapshot and before applier invocation; validator-set rotation and policy-change actions remain unsupported; no real governance execution engine, mutation engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend is implemented; there is **no** RocksDB/file/schema/migration/storage-format change and **no** wire/marker/sequence/trust-bundle change. Regression: run_244, run_242, run_240, run_238, run_236, run_234, run_232, run_230, run_228, run_226, run_224, `--lib pqc_authority`, and `--lib` all PASS; existing Run 244/243 behaviour remains compatible; no weakening of Runs 070, 130–244. **Full C4 remains OPEN; C5 remains OPEN.** See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_245.md`.
## Run 246 — source/test governance modeled end-to-end pipeline boundary

Run 246 is **source/test only**. It composes the already-landed typed boundaries into one typed source/test end-to-end modeled governance pipeline (`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_246_governance_modeled_end_to_end_pipeline_tests.rs`, 47 tests; evidence in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_246.md`). The pipeline is an ordering/composition layer, **not** a replacement for any existing module: `run_modeled_end_to_end_pipeline` orders MainNet peer-driven apply refusal → legacy bypass → Run 226 evaluator/call-site authorization → Run 240 durable replay/freshness observation → Run 242 mutation-engine authorization → Run 244 modeled trust-state applier success → durable consume decision (`recover_modeled_end_to_end_pipeline_window` fails closed on every ambiguous/unknown window and refuses MainNet peer-driven apply first). It reuses the Run 244 `evaluate_modeled_trust_mutation` entry point and consumes the typed Run 226/Run 240 outcomes via `EvaluatorCallsiteAuthorization::from_runtime_outcome` / `DurableReplayObservation::from_runtime_outcome`.

**Operationally Run 246 changes nothing.** Durable consume is authorized only after evaluator/call-site authorization, durable replay freshness, mutation-engine authorization, and modeled applier success all agree (`ModeledApplierAppliedAndDurableConsumeAuthorized`); evaluator success alone, durable replay freshness alone, and mutation-engine authorization alone are each insufficient. Failed apply, rollback, rollback-failed, ambiguous windows, unavailable production/MainNet paths, rejected replay states (consumed/superseded/stale/expired/backend-unavailable), and unsupported actions (validator-set rotation, policy-change) never consume. The pipeline mutates ONLY the in-memory `ModeledGovernanceTrustState` through the composed Run 244 fixture applier in DevNet/TestNet tests; it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself. A rejection before the applier stage never invokes the applier; MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation. No real production mutation engine, governance execution engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_246 (47) plus the regression corpus run_244 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–245. Full C4 remains OPEN; C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_246.md`.
## Run 247 — release-binary governance modeled end-to-end pipeline evidence

Run 247 is the **release-binary evidence** run for the Run 246 source/test governance modeled end-to-end pipeline boundary (`crates/qbind-node/src/pqc_governance_modeled_end_to_end_pipeline.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_247_governance_modeled_end_to_end_pipeline_release_binary_helper.rs`, driven by `scripts/devnet/run_247_governance_modeled_end_to_end_pipeline_release_binary.sh`) that the release-built code exposes and exercises the Run 246 boundary symbols (`run_modeled_end_to_end_pipeline`, `GovernanceModeledEndToEndPipelineExecutor`, `recover_modeled_end_to_end_pipeline_window`, the typed bindings/stages/classifications, the `GovernanceModeledEndToEndPipelineOutcome` taxonomy, the `GovernanceModeledEndToEndPipelineDecision` result, and all grep-verifiable invariant helpers). MainNet peer-driven apply is refused before any replay consume, modeled snapshot, or applier invocation; a disabled pipeline / evaluator-call-site policy is a legacy no-mutation, no-consume bypass; durable consume is authorized only after evaluator/call-site authorization, durable replay freshness, mutation-engine authorization, and modeled applier success all agree (the only consume-authorizing outcome is `ModeledApplierAppliedAndDurableConsumeAuthorized`; each predecessor alone is insufficient); every rejection, rejected replay state, rollback, rollback-failed, ambiguous window, unavailable production/MainNet path, and unsupported action never consumes and remains non-mutating, with a rejection before the applier stage leaving the applier invocation count at zero. The release-helper corpus (262 checks: accepted=47, rejection=130, recovery=15, projection=12, stage_ordering=22, non_mutation=16, reachability=20) and the real-binary surface scenarios all PASS, with a 36-pattern denylist proven empty. Run 247 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates; the release helper remains dead code from the production runtime. **No real production mutation engine, governance execution engine, on-chain proof verifier, persistent replay backend, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–246.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_247.md`.
## Run 248 — source/test governance modeled durable-consume projection sink boundary

Run 248 is **source/test only**. It extends the Run 246 modeled end-to-end pipeline with a mockable, in-memory consume-receipt **sink** (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_248_modeled_durable_consume_projection_sink_tests.rs`, 68 tests) that models how a future production call site would **record** an after-success-only durable consume *receipt* once the Run 246 pipeline has authorized consume. `evaluate_modeled_durable_consume_projection_sink` orders MainNet peer-driven apply refusal → legacy bypass → pipeline-outcome projection → pre-sink environment/surface binding validation → sink record, and `recover_modeled_durable_consume_projection_sink_window` fails closed on every ambiguous/unknown window. Only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome creates a sink intent; only `ConsumeReceiptRecorded` authorizes a new modeled receipt-recorded state; a duplicate identical receipt is idempotent (no second receipt) and the same receipt id with a different digest fails closed as equivocation. Every non-success pipeline outcome produces no sink invocation and no receipt; a record failure, rollback, rollback-failed, ambiguous receipt window, unavailable production/MainNet sink path, and unsupported action never consume; rejected sink paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableConsumeProjectionSink` mutates ONLY the in-memory `ModeledDurableConsumeReceiptLedger` and exposes an invocation counter so tests prove non-success paths never invoke it; the production/MainNet sinks are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–247.** Validation: run_248 (68) plus the regression corpus run_246 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_248.md`.

## Run 249 — release-binary governance modeled durable-consume projection sink evidence

## Run 250 — source/test governance modeled durable-consume completion-reporter boundary

Run 250 is **source/test only**. It extends the Run 248 modeled durable-consume projection sink with a mockable, in-memory completion **reporter** (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_250_modeled_durable_consume_completion_reporter_tests.rs`, 88 tests) that models how a future production call site would **report** an after-record-only durable consume *acknowledgement* / completion report once the Run 248 sink has recorded a consume receipt. `evaluate_modeled_durable_consume_completion_reporter` orders MainNet peer-driven apply refusal → legacy bypass → sink-outcome projection → pre-reporter environment/surface binding validation → reporter record, and `recover_modeled_durable_consume_completion_reporter_window` fails closed on every ambiguous/unknown window. Only the Run 248 `ConsumeReceiptRecorded` outcome creates a completion-report intent; `ConsumeReceiptDuplicateIdempotent` may only match an already-recorded completion report and never creates a new one; only `CompletionReportRecorded` authorizes a new modeled completion-reported state; a duplicate identical completion report is idempotent (no second report) and the same report id with a different digest fails closed as equivocation. Every non-recording sink outcome produces no reporter invocation and no completion; a record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never complete; rejected reporter paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableConsumeCompletionReporter` mutates ONLY the in-memory `ModeledDurableConsumeCompletionReportLedger` and exposes an invocation counter so tests prove non-recording paths never invoke it; the production/MainNet reporters are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, completion-report backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–249.** Validation: run_250 (88) plus the regression corpus run_248 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_250.md`.

Run 249 is the **release-binary evidence** run for the Run 248 source/test governance modeled durable-consume projection sink boundary (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_projection_sink.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_249_modeled_durable_consume_projection_sink_release_binary_helper.rs`, driven by `scripts/devnet/run_249_modeled_durable_consume_projection_sink_release_binary.sh`) that the release-built code exposes and exercises the Run 248 boundary symbols (`evaluate_modeled_durable_consume_projection_sink`, the `GovernanceModeledDurableConsumeProjectionSink` trait and its fixture/production/MainNet sinks, `project_pipeline_outcome_to_consume_sink_intent`, `recover_modeled_durable_consume_projection_sink_window`, the typed bindings/receipt-ledger model, the `GovernanceModeledDurableConsumeSinkOutcome` taxonomy, and all grep-verifiable invariant helpers). MainNet peer-driven apply is refused before any pipeline projection or sink invocation; a disabled sink / pipeline / evaluator-call-site policy is a legacy no-mutation, no-consume, no-receipt bypass; only the Run 246 `ModeledApplierAppliedAndDurableConsumeAuthorized` outcome creates a sink intent and only `ConsumeReceiptRecorded` records a new modeled receipt, while a duplicate identical receipt is idempotent (no second record) and a same-id different-digest receipt fails closed as equivocation; every non-success pipeline outcome, record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet sink path, and unsupported action never consumes and remains non-mutating, with a rejection before the sink stage leaving the sink invocation count at zero. The release-helper corpus (280 checks: accepted=47, rejection=116, recovery=14, projection=25, stage_ordering=14, receipt_ledger=23, non_mutation=18, reachability=23) and the real-binary surface scenarios all PASS, with a 39-pattern denylist proven empty. Run 249 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates; the release helper remains dead code from the production runtime. **No real durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–248.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_249.md`.

## Run 251 — release-binary governance modeled durable-consume completion-reporter evidence

Run 251 is the **release-binary evidence** run for the Run 250 source/test governance modeled durable-consume completion-reporter boundary (`crates/qbind-node/src/pqc_governance_modeled_durable_consume_completion_reporter.rs`). It proves on real `target/release/qbind-node` plus a release-built helper (`crates/qbind-node/examples/run_251_modeled_durable_consume_completion_reporter_release_binary_helper.rs`, driven by `scripts/devnet/run_251_modeled_durable_consume_completion_reporter_release_binary.sh`) that the release-built code exposes and exercises the Run 250 boundary symbols (`evaluate_modeled_durable_consume_completion_reporter`, `GovernanceModeledDurableConsumeCompletionReporter` / `FixtureModeledDurableConsumeCompletionReporter` / `ProductionModeledDurableConsumeCompletionReporter` / `MainNetModeledDurableConsumeCompletionReporter`, `project_sink_outcome_to_completion_report_intent`, `CompletionReportIntent`, `recover_modeled_durable_consume_completion_reporter_window`, `ModeledDurableConsumeCompletionReportWindow`, the `GovernanceModeledDurableConsumeCompletionReporterInput` / `Expectations` / `Policy` bindings, the `ModeledDurableConsumeCompletionReportLedger` / `Record` / `Snapshot` / `Digest` / `Status` completion-report model, the `GovernanceModeledDurableConsumeCompletionReport` carrier, the `ModeledDurableConsumeCompletionReporterKind` / `ModeledCompletionReportFault` types, the `GovernanceModeledDurableConsumeCompletionReporterOutcome` taxonomy, the `completion_reporter_outcome_authorizes_modeled_completion` / `completion_reporter_outcome_projects_to_durable_completion` predicates, and all grep-verifiable invariant helpers): MainNet peer-driven apply is refused before any pipeline progression, sink invocation, or reporter invocation; a disabled reporter / sink / pipeline / evaluator-call-site policy is a legacy no-acknowledgement, no-completion bypass with no reporter invocation; only the Run 248 `ConsumeReceiptRecorded` outcome creates a completion-report intent and only `CompletionReportRecorded` records a new modeled completion report, while a duplicate identical completion report is idempotent (no second report) and a same-id different-digest completion report fails closed as equivocation; every non-recording sink outcome, record failure, rollback, rollback-failed, ambiguous acknowledgement window, unavailable production/MainNet reporter path, and unsupported action never completes and remains non-mutating, with a rejection before the reporter stage leaving the reporter invocation count at zero. The release-helper corpus (316 checks: accepted=67, rejection=114, recovery=16, projection=37, stage_ordering=14, completion_report_ledger=25, non_mutation=20, reachability=23) and the real-binary surface scenarios (`--help` and default DevNet/TestNet/MainNet smoke surfaces emit no completion-reporter enablement claim; the hidden governance-execution selector still parses; an invalid selector fails closed before mutation) all PASS, with a 43-pattern denylist proven empty. Run 251 adds **no** production source behaviour change: only an example helper, a harness script, evidence, and narrow doc updates. The release helper remains dead code from the production runtime. **No real completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no weakening of Runs 070, 130–250.** Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_251.md`.
## Run 252 — source/test governance modeled durable-completion finalization-projection boundary

Run 252 is **source/test only**. It extends the Run 250 modeled durable-consume completion reporter with a mockable, in-memory **finalization projection** (`crates/qbind-node/src/pqc_governance_modeled_durable_completion_finalization_projection.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_252_modeled_durable_completion_finalization_projection_tests.rs`, 98 tests) that models how a future production call site would **project** an after-completion-report-only acknowledgement into a terminal **modeled durable-completion-finalized** state once the Run 250 reporter has recorded a completion report. `evaluate_modeled_durable_completion_finalization` orders MainNet peer-driven apply refusal → legacy bypass → reporter-outcome projection → pre-finalizer environment/surface binding validation → finalizer record, and `recover_modeled_durable_completion_finalization_window` fails closed on every ambiguous/unknown window. Only the Run 250 `CompletionReportRecorded` outcome creates a finalization intent; `CompletionReportDuplicateIdempotent` may only match an already-finalized completion and never creates a new one; only `DurableCompletionFinalized` authorizes a new modeled durable-completion-finalized state; a duplicate identical finalization is idempotent (no second finalization) and the same finalization id with a different digest fails closed as equivocation. The finalization identity binds both the Run 248 sink decision digest and the Run 250 reporter decision digest. Every non-recording reporter outcome produces no finalizer invocation and no finalization; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet finalizer path, and unsupported action never finalize; rejected finalizer paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableCompletionFinalizer` mutates ONLY the in-memory `ModeledDurableCompletionFinalizationLedger` and exposes an invocation counter so tests prove non-recording paths never invoke it; the production/MainNet finalizers are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, completion-report backend, finalization backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–251.** Validation: run_252 (98) plus the regression corpus run_250 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_252.md`.

## Run 253 update — release-binary governance modeled durable-completion finalization-projection evidence

Run 253 is the **release-binary evidence** run for the Run 252 source/test governance modeled durable-completion finalization-projection boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_253_modeled_durable_completion_finalization_projection_release_binary_helper.rs` (driven by `scripts/devnet/run_253_modeled_durable_completion_finalization_projection_release_binary.sh`) that the release-built code exposes and exercises the Run 252 boundary symbols: `evaluate_modeled_durable_completion_finalization_projection`, `project_completion_reporter_outcome_to_finalization_intent`, `recover_modeled_durable_completion_finalization_window`, the typed input/expectation/policy/binding model, the in-memory `ModeledDurableCompletionFinalizationLedger`, the fixture/production/MainNet finalizers, the outcome taxonomy, and all grep-verifiable invariant helpers. The helper corpus PASSes (292 checks: accepted=52, rejection=132, recovery=18, projection=32, stage_ordering=4, finalization_ledger=10, non_mutation=20, reachability=24), release-binary S1-S6 surfaces PASS, and the 43-pattern denylist is empty. Run 253 adds **no** production source behavior change; the helper remains dead code from the production runtime. No real finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The finalizer does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, or write a marker. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_253.md`.

## Run 254 update — source/test governance modeled durable-completion finalization attestation-projection boundary

Run 254 is **source/test only**. It extends the Run 252 modeled durable-completion finalization projection with a mockable, in-memory **attestation projection** (`crates/qbind-node/src/pqc_governance_modeled_durable_completion_attestation_projection.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_254_modeled_durable_completion_attestation_projection_tests.rs`, 108 tests) that models how a future production call site would **project** an after-finalization-only acknowledgement into a terminal **modeled durable-completion-attested** state once the Run 252 finalization projection has recorded a `DurableCompletionFinalized` outcome. `evaluate_modeled_durable_completion_attestation_projection` orders MainNet peer-driven apply refusal → legacy bypass → finalization-outcome projection → pre-attestor environment/surface binding validation → attestor record, and `recover_modeled_durable_completion_attestation_window` fails closed on every ambiguous/unknown window. Only the Run 252 `DurableCompletionFinalized` outcome creates an attestation intent; `DurableCompletionDuplicateIdempotent` may only match an already-attested completion and never creates a new one; only `DurableCompletionAttested` authorizes a new modeled durable-completion-attested state; a duplicate identical attestation is idempotent (no second attestation) and the same attestation id with a different digest fails closed as equivocation. The attestation identity binds the Run 248 sink decision digest, the Run 250 reporter decision digest, and the Run 252 finalization decision digest. Every non-finalized finalization outcome produces no attestor invocation and no attestation; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet attestor path, and unsupported action never attest; rejected attestor paths are non-mutating. The DevNet/TestNet `FixtureModeledDurableCompletionAttestor` mutates ONLY the in-memory `ModeledDurableCompletionAttestationLedger` and exposes an invocation counter so tests prove non-finalizing paths never invoke it; the production/MainNet attestors are reachable-but-unavailable/fail-closed. **No real persistent replay backend, durable consume backend, completion-report backend, finalization backend, attestation backend, audit ledger backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB / file / schema / migration / storage-format change; no wire / marker / sequence / trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation; no Run 070 call, `LivePqcTrustState` mutation, real trust swap, session eviction, sequence write, or marker write; no weakening of Runs 070, 130–253.** Validation: run_254 (108) plus the regression corpus run_252 down to run_224, `--lib pqc_authority`, and `--lib` all PASS. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_254.md`.
## Run 255 update — release-binary governance modeled durable-completion attestation-projection evidence

Run 255 is the **release-binary evidence** run for the Run 254 source/test governance modeled durable-completion attestation-projection boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_255_modeled_durable_completion_attestation_projection_release_binary_helper.rs` (driven by `scripts/devnet/run_255_modeled_durable_completion_attestation_projection_release_binary.sh`) that the release-built code exposes and exercises the Run 254 boundary symbols: `evaluate_modeled_durable_completion_attestation_projection`, `project_finalization_outcome_to_attestation_intent`, `recover_modeled_durable_completion_attestation_window`, the typed input/expectation/policy/binding model, the in-memory `ModeledDurableCompletionAttestationLedger`, the fixture/production/MainNet attestors, the outcome taxonomy, and all grep-verifiable invariant helpers. No symbol substitutions were required. The helper corpus PASSes (315 checks: accepted=56, rejection=125, recovery=20, projection=47, stage_ordering=4, attestation_ledger=18, non_mutation=21, reachability=24), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 255 adds **no** production source behavior change; the helper remains dead code from the production runtime. No real attestation, audit ledger, finalization, completion-report, durable consume, persistent replay, production mutation, governance execution, on-chain verifier, KMS/HSM/RemoteSigner, RocksDB/file/schema/migration/storage-format, wire/marker/sequence/trust-bundle, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The attestor does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, or write a marker. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_255.md`.
## Run 256 update — source/test production durable-completion attestation backend interface boundary

Run 256 is **source/test only**. It extends the Run 254 modeled durable-completion attestation projection with a typed, mockable, in-memory **backend interface boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_attestation_backend.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_256_durable_completion_attestation_backend_tests.rs`, 46 tests) that models the first backend-facing interface a future production call site would use **after** the Run 254 `DurableCompletionAttested` outcome has been recorded. It is a backend-interface layer — not a replacement for any existing module. `evaluate_durable_completion_attestation_backend` orders MainNet peer-driven apply refusal → legacy bypass → attestation-outcome projection (`project_attestation_outcome_to_backend_request`) → pre-backend environment/surface binding validation → backend submit, and `recover_durable_completion_attestation_backend_window` fails closed on every ambiguous/unknown window. Only the Run 254 `DurableCompletionAttested` outcome creates a backend request; `DurableCompletionAttestationDuplicateIdempotent` may only match an already-submitted backend record and never creates a new one; only `BackendSubmissionRecorded` authorizes a new modeled backend-submitted state; a duplicate identical submission is idempotent (no second submission) and the same backend record id with a different digest fails closed as equivocation. Every non-attested attestation outcome produces no backend request, no backend invocation, and no submission; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet/external-publication backend path, and unsupported action never submit. The DevNet/TestNet `FixtureDurableCompletionAttestationBackend` mutates ONLY the in-memory `DurableCompletionAttestationBackendLedger` and exposes an invocation counter so tests prove non-attesting and pre-backend-rejected paths never invoke it; the `ProductionDurableCompletionAttestationBackend` / `MainNetDurableCompletionAttestationBackend` / `ExternalPublicationDurableCompletionAttestationBackend` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, or perform a durable consume by itself; no real persistent replay backend, durable consume backend, completion-report backend, finalization backend, production attestation backend, audit ledger backend, external publication backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_256 (46) plus the regression corpus run_254 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–255. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_256.md`.


## Run 257 update — release-binary governance durable-completion attestation backend interface evidence

Run 257 is the **release-binary evidence** run for the Run 256 source/test production durable-completion attestation backend interface boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_257_durable_completion_attestation_backend_release_binary_helper.rs` (driven by `scripts/devnet/run_257_durable_completion_attestation_backend_release_binary.sh`) that the release-built code exposes and exercises the Run 256 boundary symbols: `evaluate_durable_completion_attestation_backend`, `project_attestation_outcome_to_backend_request`, `recover_durable_completion_attestation_backend_window`, the predicate helpers `backend_outcome_authorizes_durable_attestation_submission` / `backend_outcome_projects_to_backend_submission_recorded`, the typed input/expectation/policy/kind/identity/request/response/receipt/record/digest model, the in-memory `DurableCompletionAttestationBackendLedger`, the fixture/production/MainNet/external-publication backends, the outcome/intent/fault taxonomy, and all grep-verifiable invariant helpers. No symbol substitutions were required. The helper corpus PASSes (407 checks: accepted=68, rejection=153, recovery=24, projection=74, stage_ordering=5, backend_ledger=24, non_mutation=24, reachability=35), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 257 adds **no** production source behavior change; the helper remains dead code from the production runtime. The fixture backend mutates only the in-memory `DurableCompletionAttestationBackendLedger`; production/MainNet/external-publication backends remain reachable but unavailable/fail-closed. No real attestation backend, audit ledger backend, external publication backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, MainNet peer-driven apply, or validator-set rotation behavior is enabled. The backend does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_257.md`.## Run 258 update — source/test durable-completion audit-ledger / external-publication receipt boundary

Run 258 is **source/test only**. It extends the Run 256 modeled durable-completion attestation backend interface boundary with a typed, mockable, in-memory **audit-ledger / external-publication receipt boundary** (`crates/qbind-node/src/pqc_governance_durable_completion_audit_publication_receipt.rs`, registered in `crates/qbind-node/src/lib.rs`; tests in `crates/qbind-node/tests/run_258_durable_completion_audit_publication_receipt_tests.rs`, 57 tests) that models the first post-Run-256 backend-submission receipt interface a future production audit ledger or external publication system would use **after** the Run 256 `BackendSubmissionRecorded` outcome has been recorded. It is a receipt-interface layer — not a replacement for any existing module. `evaluate_durable_completion_audit_publication_receipt` orders MainNet peer-driven apply refusal → legacy bypass → backend-outcome projection (`project_backend_submission_outcome_to_audit_receipt_request`) → pre-receipt environment/surface binding validation → receipt record, and `recover_durable_completion_audit_publication_receipt_window` fails closed on every ambiguous/unknown window. Only the Run 256 `BackendSubmissionRecorded` outcome creates a receipt request; `BackendSubmissionDuplicateIdempotent` may only match an already-recorded receipt and never creates a new one; only `AuditReceiptRecorded` authorizes a new modeled audit/publication receipt state; a duplicate identical receipt is idempotent (no second receipt) and the same receipt record id with a different digest fails closed as equivocation. Every non-submitted backend outcome produces no receipt request, no receipt sink invocation, and no receipt; a record failure, rollback, rollback-failed, ambiguous window, unavailable production/MainNet audit-ledger/external-publication receipt path, and unsupported action never record. The Run 258 tests attach every recording case to the **actual** Run 256 `BackendSubmissionRecorded` path and the real Run 256 backend identity/request/response/receipt/transcript digests — not a faked, unattached receipt. The DevNet/TestNet `FixtureDurableCompletionAuditPublicationReceiptSink` mutates ONLY the in-memory `DurableCompletionAuditPublicationReceiptLedger` and exposes an invocation counter so tests prove non-submitting and pre-receipt-rejected paths never invoke it; the `ProductionAuditLedgerDurableCompletionReceiptSink` / `MainNetAuditLedgerDurableCompletionReceiptSink` / `ExternalPublicationDurableCompletionReceiptSink` are reachable-but-unavailable/fail-closed. Source/test only: it does not mutate `LivePqcTrustState`, call Run 070, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger; no real audit ledger backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain proof verifier, or KMS/HSM/RemoteSigner backend; no RocksDB/file/schema/migration/storage-format change; no wire/marker/sequence/trust-bundle change; no MainNet governance or peer-driven apply enablement; no validator-set rotation. Validation: run_258 (57) plus the regression corpus run_256 down to run_224, `--lib pqc_authority`, and `--lib` all PASS; no weakening of Runs 070, 130–257. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_258.md`.## Run 259 update — release-binary governance durable-completion audit-publication receipt interface evidence

Run 259 is the **release-binary evidence** run for the Run 258 source/test durable-completion audit-ledger / external-publication receipt boundary. It proves on real `target/release/qbind-node` plus `crates/qbind-node/examples/run_259_durable_completion_audit_publication_receipt_release_binary_helper.rs` (driven by `scripts/devnet/run_259_durable_completion_audit_publication_receipt_release_binary.sh`) that the release-built code exposes and exercises the Run 258 boundary symbols: `evaluate_durable_completion_audit_publication_receipt`, `project_backend_submission_outcome_to_audit_receipt_request`, `recover_durable_completion_audit_publication_receipt_window`, the predicate helpers `audit_receipt_outcome_authorizes_receipt_record` / `audit_receipt_outcome_projects_to_audit_receipt_recorded`, the typed input/expectation/policy/kind/identity/request/response/receipt/record/digest model, the in-memory `DurableCompletionAuditPublicationReceiptLedger`, the fixture/production/MainNet/external-publication receipt sinks, the outcome/intent/fault taxonomy, and all grep-verifiable invariant helpers. Recording cases attach to the **actual** Run 256 `BackendSubmissionRecorded` path and real Run 256 digests. No symbol substitutions were required. The helper corpus PASSes (378 checks: accepted=65, rejection=120, recovery=27, projection=39, stage_ordering=7, receipt_ledger=56, non_mutation=27, reachability=37), release-binary S1-S6 surfaces PASS, and the denylist is empty. Run 259 adds **no** production source behavior change; the helper remains dead code from the production runtime. The fixture receipt sink mutates only the in-memory `DurableCompletionAuditPublicationReceiptLedger`; production/MainNet/external-publication receipt sinks remain reachable but unavailable/fail-closed. No real audit-publication receipt backend, audit ledger backend, external publication backend, production attestation backend, finalization backend, completion-report backend, durable consume backend, persistent replay backend, production mutation engine, governance execution engine, on-chain verifier, KMS/HSM/RemoteSigner backend, RocksDB/file/schema/migration/storage-format change, wire/marker/sequence/trust-bundle change, MainNet governance, MainNet peer-driven apply, validator-set rotation, or policy change behavior is enabled. The receipt boundary does not call Run 070, mutate `LivePqcTrustState`, perform a real trust swap, evict sessions, write a sequence, write a marker, perform external publication, or write a real audit ledger. Full C4 remains OPEN. C5 remains OPEN. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_259.md`.
