# QBIND DevNet Evidence — Run 070

**Title:** Disabled-by-default PQC trust-bundle local operator-triggered reload-apply boundary (partial-positive — apply contract landed, binary surfaces `UnsupportedRuntimeContext` honestly because no mutable runtime trust-state handle exists yet)
**Date:** 2026-05-14
**C-row narrowed:** C4 — "on-the-fly trust-bundle hot reload" (NARROW sub-piece; full C4 still OPEN)

---

## 1. Exact objective

Land the **smallest safe** local-operator-triggered live-apply primitive
defined by `task/RUN_070_TASK.txt`. Run 070 builds **on top of** the
Run 069 disabled-by-default validation/staging boundary; it must NEVER
weaken Run 069's non-mutation contract, must NEVER accept peer-supplied
or gossiped bundles, must NEVER add an automatic filesystem-watcher
hot-reload path, and must NEVER advertise hot-reload to operators who
have not opted in via two explicit flags. The exact ordering required
on a successful live apply is `validate → swap → evict_sessions →
commit_sequence`, with rollback if any post-swap step fails and a
distinct **fatal** outcome (`SequenceCommitFailedRollbackAlsoFailed`)
if rollback itself fails after a successful swap.

`task/RUN_070_TASK.txt` explicitly authorises the safer fallback when
the current code cannot expose a mutable live trust context safely:

> If current code does not support mutable live trust context safely:
> do not fake hot reload. Implement the smallest safe "reload apply
> unsupported because immutable trust context" boundary and document
> it.

The current `qbind-node` binary binds active PQC trust state
(`active_roots`, `revoked_leaf_fingerprints`, the
`LeafCertRevocationList` revocation closure, the configured root /
leaf certs) into the immutable `ClientHandshakeConfig` /
`ServerHandshakeConfig` constructed once inside
`crates/qbind-node/src/p2p_node_builder.rs::build_p2p_node`. There is
no process-wide mutable trust-context handle, no production
session-manager `evict_all` hook on the honest PQC path, and no way
for an in-process actor to swap roots / revocations under a live
handshake verifier without redesigning the builder + transport
contracts. Per the task instruction, Run 070 therefore lands the
boundary honestly: the apply *contract* is implemented and fully
proven by tests against a deterministic fake `LiveTrustApplyContext`,
and the running binary surfaces `ReloadApplyError::UnsupportedRuntimeContext`
to operators with an unambiguous log line.

---

## 2. Exact verdict

**PARTIAL POSITIVE.** The Run 070 apply contract (`ApplyMode`,
`ReloadApplyError`, `LiveTrustApplyContext`,
`apply_validated_candidate{,_with_previous}`, `AppliedCandidate`) lands
in the library and is fully exercised by 13 integration tests proving
the exact `snapshot → swap → evict → commit` callback ordering on the
happy path, the no-mutation behaviour on every validation-failure
class, the no-commit behaviour on state-swap failure, the rollback
behaviour on session-eviction failure, the rollback behaviour on
sequence-commit failure, and the explicit fatal-variant behaviour when
rollback also fails. Run 069's validation/staging boundary is
preserved bit-for-bit (12 Run 069 integration tests still pass; one
new Run 070 test re-proves `validate_candidate_bundle` is unchanged).
The binary surface adds two hidden flags
`--p2p-trust-bundle-reload-apply-enabled` and
`--p2p-trust-bundle-reload-apply-path <PATH>` with the same TestNet /
MainNet preconditions as the Run 069 reload-check hook (signed-only,
`--data-dir`-required), and reports `VERDICT=unsupported-runtime-context`
on the production-honest path with an unambiguous explanation. **No
fake hot reload is shipped.** A future run that lands a mutable
runtime trust handle + a session-eviction hook can implement
`LiveTrustApplyContext` and wire it into the existing
`apply_validated_candidate` call site without touching the validation
pipeline, the sequencing contract, the rollback semantics, the CLI
surface, or the operator-log lines.

All required regressions pass:

- `cargo test -p qbind-node --lib pqc_trust_` — 166/166 (`pqc_trust_reload` 5/5, `pqc_trust_bundle` 100/100, `pqc_trust_sequence` 27/27, `pqc_trust_activation` 34/34 — superset);
- `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` — 13/13;
- `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` — 12/12 (Run 069 unchanged);
- `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` — 14/14;
- `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` — 13/13;
- `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` — 12/12;
- `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` — 12/12;
- `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` — 12/12;
- `cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests` — 9/9;
- `cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests` — 11/11;
- `cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests` — 8/8;
- `cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests` — 9/9;
- `cargo test -p qbind-node --lib metrics` — 108/108 (no new metric family, no removed metric family);
- `cargo build -p qbind-node --bin qbind-node` — clean.

---

## 3. Exact files changed

| File | Kind | Purpose |
|---|---|---|
| `crates/qbind-node/src/pqc_trust_reload.rs` | extended | New Run 070 apply surface: `ApplyMode` (`ValidateOnly` / `ApplyLive`), `ReloadApplyError` (7 variants — `ValidationFailed`, `UnsupportedRuntimeContext`, `LiveReloadDisabled`, `StateSwapFailed`, `SessionEvictionFailed { rollback_ok }`, `SequenceCommitFailed`, `SequenceCommitFailedRollbackAlsoFailed`), `LiveTrustApplyContext` trait (`snapshot_active` + `swap_trust_state` + `evict_sessions` + `commit_sequence` + `rollback_trust_state`), `AppliedCandidate { validated, previous_fingerprint_prefix, previous_sequence, session_evictions }` with `applied_log_line()` operator-log helper, and `apply_validated_candidate{,_with_previous}` entry points. The Run 069 entry points (`validate_candidate_bundle{,_full}`, `ValidatedCandidate`, `ReloadCheckError`, `ReloadCheckInputs`) are **untouched**. New module-level documentation block explains the immutable-runtime-context boundary and the strict sequencing contract. |
| `crates/qbind-node/src/cli.rs` | extended | Two new hidden flags: `p2p_trust_bundle_reload_apply_enabled: bool` (operator opt-in) and `p2p_trust_bundle_reload_apply_path: Option<PathBuf>` (local candidate path). Doc-comments explicitly call out the scope boundary (no peer/gossip input; not KMS/HSM; not signing-key ratification; not `activation_epoch` runtime sourcing; not a filesystem watcher). |
| `crates/qbind-node/src/main.rs` | extended | Run 070 hook block positioned immediately after the Run 069 reload-check hook (still BEFORE the network-mode dispatch). Refuses partial-config shapes (path without `--enabled`, or `--enabled` without path) up front. Inherits the EXACT same signing-key / data-dir / local-leaf preconditions as the Run 069 hook (no silent fallback, no divergence from startup parity). Calls `apply_validated_candidate(..., ApplyMode::ApplyLive, None)` because the running binary has no mutable runtime trust-state handle yet, and the apply path surfaces `ReloadApplyError::UnsupportedRuntimeContext` honestly. Emits `VERDICT=unsupported-runtime-context` / `VERDICT=invalid` / `VERDICT=applied` operator-log lines and exits with code `0` only on applied success. |
| `crates/qbind-node/tests/run_070_pqc_trust_bundle_reload_apply_tests.rs` | new (integration tests) | 13 tests covering: ValidateOnly mode never invokes the context; ApplyLive + no context returns `UnsupportedRuntimeContext`; happy-path exact callback order `snapshot_active → swap_trust_state → evict_sessions → commit_sequence`; state-swap failure stops after the failed swap with no commit and no rollback; session-eviction failure rolls back with `rollback_ok=true` and never commits; sequence-commit failure with successful rollback surfaces `SequenceCommitFailed` and reverts active state; sequence-commit failure with failed rollback surfaces `SequenceCommitFailedRollbackAlsoFailed` (fatal variant); four validation-failure classes (rollback, tampered signature, local-leaf-revoked, local-issuer-root-revoked) each surface `ValidationFailed(...)` with **zero** apply-context callbacks invoked; Run 069's `validate_candidate_bundle` semantics unchanged; on-disk sequence file untouched on every Run 070 apply branch. Uses a deterministic in-memory `FakeLiveTrustApplyContext` so the apply ordering / rollback semantics are exercised without depending on production transport. |
| `docs/whitepaper/contradiction.md` | extended | C4 Run 070 narrowing entry (records the local-operator-triggered reload-apply contract + the `UnsupportedRuntimeContext` binary boundary; full C4 still OPEN on KMS/HSM, signing-key ratification, `activation_epoch` runtime sourcing, peer/gossip input, automatic FS-watcher hot reload, runtime mutable trust-context handle wiring, and selective session retention). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md` | new | this document. |

**Zero pre-existing source files touched outside the list above.** No `Cargo.toml`
modified. No new dependency. No new `/metrics` family (the Run 070
binary hook exits before `/metrics` would be served — same discipline
documented for Run 069 and the Run 061 / Run 063 startup self-checks).
No metric removed. No Run 069 entry point modified. No transport-root
reuse as a bundle-signing authority. No `--p2p-trusted-root` fallback
path added. No classical signatures introduced. No `DummySig` /
`DummyKem` / `DummyAead` fallback path introduced or strengthened.
No private-key material referenced by `AppliedCandidate`.

---

## 4. Exact security/scope boundary

### 4.1 What Run 070 IS

A library API that, given a validated trust-bundle candidate **and a
caller-supplied** `LiveTrustApplyContext`, performs the following
fail-closed pipeline in this exact order:

1. **Validate** via `validate_candidate_bundle_full` — reuses the
   exact Run 050/051/052/053/057/061/062/063/065 startup pipeline.
   Validation failure → `ReloadApplyError::ValidationFailed(_)`. **No**
   live state mutation; **no** sequence write; **no** context
   callback invoked.
2. **Snapshot active live trust state** via
   `LiveTrustApplyContext::snapshot_active`. Snapshot failure →
   `StateSwapFailed`. No mutation occurred yet.
3. **Atomically swap** the active trust state via
   `LiveTrustApplyContext::swap_trust_state`. Swap failure →
   `StateSwapFailed`. Old live state remains active; no eviction; no
   commit.
4. **Evict** existing P2P / KEMTLS sessions via
   `LiveTrustApplyContext::evict_sessions` (conservative v0 policy:
   evict ALL existing sessions because pre-existing sessions may
   have been authenticated under roots or leaves now revoked /
   removed). Eviction failure → invoke
   `LiveTrustApplyContext::rollback_trust_state`; surface
   `SessionEvictionFailed { rollback_ok }`. No commit.
5. **Commit sequence** via `LiveTrustApplyContext::commit_sequence`.
   Commit failure → invoke `rollback_trust_state`; if rollback
   succeeds surface `SequenceCommitFailed`; if rollback fails
   surface `SequenceCommitFailedRollbackAlsoFailed` (the operator
   MUST stop the node).

The binary surface exposes two hidden flags
`--p2p-trust-bundle-reload-apply-enabled` +
`--p2p-trust-bundle-reload-apply-path <PATH>` (operator opt-in,
local file only, evidence-only). The node does **not** start in this
mode (the process exits with `0` on `VERDICT=applied`, `1` on
`VERDICT=unsupported-runtime-context` / `VERDICT=invalid`). The
`--p2p-trust-bundle-reload-apply-path` flag requires the
`--enabled` flag and vice versa; either partial-config shape is
refused up-front so an operator cannot accidentally arm the apply
path by typing the path alone.

### 4.2 What Run 070 IS NOT (full C4 still OPEN)

- **NOT** peer-supplied / gossiped bundle acceptance. The only
  allowed source is a local file path the operator already controls
  (same trust assumption as the existing `--p2p-trust-bundle` flag
  and the Run 069 reload-check flag).
- **NOT** an automatic filesystem watcher. Apply must be
  operator-triggered.
- **NOT** activated by default. Both `--enabled` AND `--path` are
  required; either alone is refused.
- **NOT** a working production live apply on the current binary.
  The running `qbind-node` binary has no mutable runtime
  trust-state handle yet, and Run 070 honestly surfaces
  `UnsupportedRuntimeContext` instead of fabricating a swap. **A
  future run will land the mutable handle + session-manager
  eviction hook and wire them into `apply_validated_candidate`
  without changing this surface.**
- **NOT** KMS / HSM custody.
- **NOT** in-binary or on-chain bundle-signing-key ratification /
  rotation.
- **NOT** `activation_epoch` runtime sourcing. `ActivationContext`
  still carries `current_epoch = None` on the apply path (same
  boundary as Run 057 / Run 069).
- **NOT** selective session retention. Conservative v0 policy
  evicts all sessions on a successful swap; pre-existing sessions
  may have been authenticated under roots or leaves now revoked /
  removed.
- **NOT** a new `/metrics` family. The Run 070 binary hook exits
  before `/metrics` would be bound; a counter family would never
  be scrapeable and would mislead operators (same discipline as
  Run 069 / Run 061 / Run 063).

**Full C4 remains OPEN** on all of the above items.

---

## 5. Sequencing invariants proven by tests

For each line below the linked test asserts the precise callback
ordering of the deterministic `FakeLiveTrustApplyContext`:

- **Happy path** (`run070_apply_live_happy_path_runs_callbacks_in_exact_order`)
  `snapshot_active → swap_trust_state → evict_sessions → commit_sequence`
  (no `rollback_trust_state`).
- **State-swap failure**
  (`run070_state_swap_failure_does_not_commit_sequence_or_evict_or_rollback`)
  `snapshot_active → swap_trust_state` (NO evict, NO commit, NO
  rollback — no swap occurred).
- **Session-eviction failure**
  (`run070_session_eviction_failure_triggers_rollback_and_does_not_commit`)
  `snapshot_active → swap_trust_state → evict_sessions → rollback_trust_state`
  (NO commit; live trust fingerprint reverted to pre-swap value).
- **Sequence-commit failure with successful rollback**
  (`run070_sequence_commit_failure_rolls_back_live_state_and_surfaces_error`)
  `snapshot_active → swap_trust_state → evict_sessions → commit_sequence → rollback_trust_state`
  (live trust fingerprint reverted to pre-swap value).
- **Sequence-commit failure with failed rollback**
  (`run070_commit_failure_with_rollback_failure_surfaces_fatal_variant`)
  same call sequence as above but the `rollback_trust_state` callback
  returns `Err` and the apply surfaces
  `SequenceCommitFailedRollbackAlsoFailed`; `Display` output literally
  contains `"FATAL"`, `"ahead of persisted sequence"`, and `"stop the
  node"`.

For each validation-failure class
(`run070_validation_failure_rollback_does_not_call_apply_context`,
`run070_validation_failure_tampered_signature_does_not_call_apply_context`,
`run070_validation_failure_local_revoked_leaf_does_not_call_apply_context`,
`run070_validation_failure_local_issuer_root_revoked_does_not_call_apply_context`),
the test asserts:

- the returned `ReloadApplyError::ValidationFailed(inner)` matches the
  expected Run 069 subtype (`ReloadCheckError::Sequence`,
  `ReloadCheckError::Bundle`, `ReloadCheckError::LocalLeafRevoked`,
  `ReloadCheckError::LocalIssuerRootRevoked`);
- **zero** apply-context callbacks were invoked;
- the on-disk sequence-persistence file is byte-and-mtime equal to
  its pre-apply snapshot;
- the fake-context active fingerprint is unchanged.

---

## 6. Release-binary smokes (operator-visible boundary)

The following two smokes were verified against
`cargo run --release --bin qbind-node` from a clean checkout to prove
the binary surfaces the `UnsupportedRuntimeContext` boundary honestly
and refuses partial-config shapes.

### 6.1 Partial-config refusal (path without `--enabled`)

```
$ cargo run --release --bin qbind-node -- \
    --env devnet \
    --p2p-trust-bundle-reload-apply-path /tmp/qbind-070-cand.json

[binary] FATAL: --p2p-trust-bundle-reload-apply-path requires
 --p2p-trust-bundle-reload-apply-enabled. Live reload-apply is
 disabled by default. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md.
$ echo $?
1
```

### 6.2 `VERDICT=unsupported-runtime-context` on a valid DevNet candidate

Helper-minted DevNet signed bundle written to disk, signing key
supplied, both apply flags supplied. The binary validates the
candidate using the exact Run 069 pipeline and then surfaces the
boundary without mutating any live state:

```
$ cargo run --release --bin qbind-node -- \
    --env devnet \
    --network-mode p2p \
    --validator-id 0 \
    --p2p-trust-bundle-signing-key dev:<KEY_ID_HEX>:0x07:<PK_HEX> \
    --p2p-trust-bundle-reload-apply-enabled \
    --p2p-trust-bundle-reload-apply-path /tmp/qbind-070-cand.json

[binary] Run 070: VERDICT=unsupported-runtime-context (candidate
 validated against the same Run 050/051/052/053/057/061/062/063/065
 pipeline as startup; no live trust apply performed because the
 running qbind-node binary has no mutable runtime trust-context
 handle yet; no sequence persistence write; no peer/session
 mutation; no /metrics mutation). Candidate path=/tmp/qbind-070-cand.json.
 Reason: ApplyMode::ApplyLive requires a LiveTrustApplyContext handle;
 current qbind-node binary has no mutable runtime trust-state handle
 yet. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_070.md.
$ echo $?
1
```

The persistence file (under `--data-dir` when supplied) is byte-and-
mtime equal before and after the smoke — identical to the Run 069
"validation only, no sequence write" guarantee.

---

## 7. Why no new `/metrics` family

The Run 070 binary hook exits before `/metrics` is bound (the
`spawn_metrics_http` call site sits inside `run_p2p_node`, which is
only reached on the live startup path — see
`crates/qbind-node/src/main.rs` network-mode dispatch). A new
`qbind_p2p_pqc_trust_bundle_apply_*` counter family would therefore
never be scrapeable and would mislead operators into thinking live
hot-apply is implemented. The verdict + safe public metadata are
surfaced in operator logs only — same discipline documented for
Run 069 and the Run 061 / Run 063 startup self-checks. A future run
that lands a mutable runtime trust handle will run in a process that
also has `/metrics` bound, at which point introducing
`qbind_p2p_pqc_trust_bundle_apply_attempts_total`,
`qbind_p2p_pqc_trust_bundle_apply_success_total`,
`qbind_p2p_pqc_trust_bundle_apply_failed_total{stage=...}`, and a
`qbind_p2p_pqc_trust_bundle_session_evictions_total` family will be
genuinely countable.

---

## 8. No-fallback / no-mutation proofs

- **No `DummySig` / `DummyKem` / `DummyAead` fallback.** Run 070
  reuses the Run 050/051/053/057/062/065 loader exactly; tampered
  signatures are rejected by ML-DSA-44 verification before the apply
  pipeline ever reaches the context.
- **No transport-root reuse as bundle-signing authority.** Inherited
  from Run 050.
- **No `--p2p-trusted-root` fallback path.** Inherited from Run 050.
- **No silent regression of Run 069.** The Run 070 binary hook is
  positioned AFTER the Run 069 reload-check hook so neither flag
  surface affects the other; both Run 069 hook and library entry
  points are bit-for-bit unchanged and proven by 12/12 Run 069
  integration tests + 5/5 `pqc_trust_reload` lib tests (3 of which
  are new for Run 070 and verify the existing Run 069 log line
  invariants still hold).
- **No fabricated metric.** See §7.
- **No new dependency.** `cargo metadata` shows no `Cargo.toml`
  modification.
- **No private-key material referenced by `AppliedCandidate`.** The
  struct carries only the same public log-safe metadata `Run 069`
  surfaces (fingerprints, sequence, environment, chain id, root
  counts, revocation counts, session-eviction count) plus the
  caller-supplied previous-fingerprint-prefix and previous-sequence
  echoes for operator logs.

---

## 9. Remaining C4 items (full C4 still OPEN)

After Run 070 lands, the remaining C4-OPEN items under "on-the-fly
trust-bundle hot reload" are:

- **Runtime mutable trust-context handle.** A concrete
  `LiveTrustApplyContext` implementation backed by a process-wide
  `Arc<RwLock<LiveTrustState>>` (or equivalent), wired into the
  `ClientHandshakeConfig` / `ServerHandshakeConfig` constructors in
  `p2p_node_builder.rs` so handshake verifiers dynamically read
  active roots / revocations rather than holding the closure
  captured at startup.
- **Production session manager `evict_all` hook.** A real
  implementation of `LiveTrustApplyContext::evict_sessions` that
  closes every in-flight P2P / KEMTLS session.
- **`activation_epoch` runtime sourcing.** `ActivationContext.current_epoch`
  is still `None` on the apply path.
- **Peer-supplied / gossiped bundle acceptance** with the
  correspondingly larger trust-model analysis.
- **External KMS / HSM custody** of the bundle-signing key set.
- **Bundle-signing-key ratification** (in-binary, on-chain, or
  governance-driven).
- **Per-environment production trust-anchor operation.**
- **Selective session retention** (instead of evict-all v0).

Each of these is an independent future run.