# QBIND DevNet Evidence — Run 146

**Subject**: Source/test wiring of the Run 145 non-applying
[`PeerCandidateStagingQueue`] into the live inbound `0x05`
**validation-only** receive path, behind an explicit
**disabled-by-default** local policy gate.

## Scope notice (mandatory per `task/RUN_146_TASK.txt`)

* **Run 146 is source/test wiring only.** Release-binary staging
  evidence is **deferred to Run 147**.
* **No release-binary evidence harness is added in this run.** No
  CLI flag is added; the Run 145 module-level documentation already
  describes the future Run 147 production-binary wiring. The
  dispatcher exposes [`set_staging_queue`] and `staging_queue()`
  accessors so a future Run 147 main-binary entry point can install
  the queue once an operator-facing CLI flag (e.g. hidden
  `--p2p-trust-bundle-peer-candidate-staging-enabled` plus a
  matching environment policy) is resolved.
* **No peer-driven live apply.** No Run 070 apply invocation.
* **No `LivePqcTrustState` mutation.**
* **No sequence write** (`pqc_trust_bundle_sequence.json` is
  byte-identical pre/post on every Run 146 test).
* **No authority-marker write** (`pqc_authority_state.json` is
  byte-identical pre/post on every Run 146 test).
* **No P2P / KEMTLS session eviction.**
* **No SIGHUP / reload-apply invocation.**
* **No new wire format.** The live inbound `0x05` envelope and
  `LivePeerCandidateWireDispatcher` route remain unchanged.
* **No trust-bundle / ratification-sidecar / authority-marker
  schema change.**
* **No KMS / HSM.**
* **No governance implementation.**
* **No signing-key rotation / revocation lifecycle.**
* **No MainNet staging enablement.** MainNet refuses staging
  unconditionally even with `enabled = true` and `allow_mainnet =
  true` set on the policy.
* **Validation-only and propagation-only behaviour remain
  unchanged.** The Run 143 outcome of a frame on the live inbound
  `0x05` path is bit-for-bit identical when the staging queue is
  absent or its policy is disabled.
* **Full C4 remains OPEN. C5 remains OPEN.**

## Deliverables landed under Run 146

1. New dispatcher field
   [`LivePeerCandidateWireDispatcher::staging_queue`] (and matching
   `LivePeerCandidateWireDispatcherConfig::staging_queue`) typed as
   `Option<Arc<Mutex<PeerCandidateStagingQueue>>>`. Defaults to
   `None`; behaviour is bit-for-bit Run 143 when `None`.
2. New runtime accessor surface:
   * `set_staging_queue(&mut self, queue)` — late-install path for
     the Run 147 production binary.
   * `staging_queue() -> Option<&Arc<Mutex<…>>>` — read-only handle
     for tests and operator introspection.
   * `staging_hook_is_armed() -> bool` — `true` iff a queue is
     installed AND its `PeerDrivenStagingPolicy` is currently
     willing to accept candidates on the current environment
     (MainNet always returns `false`).
3. New non-mutating staging hook
   [`LivePeerCandidateWireDispatcher::maybe_stage_after_validation`]
   invoked inside `dispatch_frame_from_peer_for_test` **AFTER** the
   Run 142 v2-marker conflict check and the Run 123 v1-marker
   conflict check, and **BEFORE** `maybe_propagate_after_validation`.
   Forwards only `PeerCandidateOutcome::Validated(_)` outcomes to
   `PeerCandidateStagingQueue::try_stage_outcome`; every other
   outcome (Rejected / Oversize / RateLimited / DuplicateSuppressed /
   Disabled) is filtered out by the queue's
   [`StagingOutcome::RefusedNotValidated`] guard and never reaches
   `try_stage_validated`.
4. New focused integration test suite
   `crates/qbind-node/tests/run_146_live_inbound_0x05_staging_hook_tests.rs`
   covering the full Run 146 matrix:
   * **A1** accepted v2 candidate stages when policy enabled.
   * **A2** accepted idempotent v2 candidate dedupes in the runtime
     hook (Run 088 duplicate-suppression filters the second arrival
     before staging is consulted).
   * **A3** higher-sequence v2 candidate stages.
   * **A4** v2-after-v1 migration candidate stages; existing v1
     authority-marker bytes are preserved.
   * **R1** staging disabled (default policy) preserves Run 143
     behavior exactly.
   * **R2** MainNet refuses staging even with `enabled = true` and
     `allow_mainnet = true`.
   * **R3** lower-sequence v2 candidate does not stage (validation
     rejects upstream).
   * **R4** same-sequence different-digest candidate does not stage.
   * **R5** bad-signature candidate does not stage.
   * **R6** wrong-chain (wrong-domain) candidate does not stage.
   * **R7** ambiguous v1+v2 candidate does not stage.
   * **R8** propagation disabled + staging enabled: candidate stages,
     no rebroadcast.
   * **R9** propagation enabled + staging disabled: candidate
     propagates under existing Run 088 rules, queue stays empty.
   * **R10** propagation enabled + staging enabled: valid candidate
     both stages and propagates; invalid candidate neither stages
     nor propagates.
   * **R11** per-peer and global queue caps are enforced through the
     live hook.
   * **R12** TTL expiry sweeps the staged entry through the live
     hook.
   * **R13** v1 live inbound `0x05` regression remains unchanged.
   * **R14** legacy/no-sidecar regression remains unchanged.
   * Late-install regression: `set_staging_queue` after dispatcher
     construction arms the hook identically to constructor-time
     installation.
5. Every Run 146 test additionally asserts the Run 146 negative
   invariants:
   * `pqc_trust_bundle_sequence.json` byte-identical pre/post.
   * `pqc_authority_state.json` byte-identical pre/post.
   * No Run 070 apply call (the hook has no apply path; the
     dispatcher does not call apply).
   * No `LivePqcTrustState` swap (the dispatcher does not own one).
   * No session eviction (the dispatcher has no session evictor
     handle).
   * No SIGHUP / reload-apply outcome (the dispatcher does not
     trigger either).
   * No peer-driven apply metric/log line (the only Run 146 log
     lines are `[binary] Run 146: …STAGED / already staged /
     refused …` and these explicitly disclaim apply, sequence
     persistence, live trust mutation, marker write, and session
     touch).
   * No trusted-root fallback (the validator reused is the existing
     Run 069 / Run 076 / Run 130 pipeline, which is fail-closed on
     `DummySig` / `DummyKem` / `DummyAead`).
6. Documentation alignment:
   * `docs/whitepaper/contradiction.md` — Run 146 paragraph.
   * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 146
     entry.
   * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 146
     entry.
   * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
     — Run 146 progress entry recording that the Phase 2 staging
     queue is now reachable from the live inbound `0x05`
     validation path behind an explicit disabled-by-default local
     policy.

## Why no CLI flag was added in Run 146 (and how Run 147 stays honest)

The Run 146 task explicitly permits omitting the runtime flag and
deferring binary-facing arming to Run 147, provided Run 147 has an
honest path to trigger staging on the release binary. The Run 146
implementation makes this honest path concrete:

1. **Late-install API**: `LivePeerCandidateWireDispatcher::set_staging_queue`
   takes an owned `Arc<Mutex<PeerCandidateStagingQueue>>` after
   dispatcher construction. The Run 147 main-binary entry point can
   build the dispatcher exactly as it does today and then call
   `set_staging_queue` once it has parsed the (yet-to-be-added)
   hidden DevNet/TestNet flag, the resolved
   `qbind_types::NetworkEnvironment`, and a
   `PeerDrivenStagingPolicy`.
2. **Queue policy carries all the gating**: the queue's
   `PeerDrivenStagingPolicy::permitted` already refuses
   `enabled = false`, refuses MainNet unconditionally, and refuses
   environments whose `allow_*` switch is `false`. Run 147 only
   needs to add the flag parsing; no further safety logic is
   required at the dispatcher layer.
3. **Hook observability**: `staging_hook_is_armed()` lets the
   Run 147 release-binary evidence harness assert the hook is
   actually live before generating release-binary evidence, so the
   release-binary claim is not honesty-laundered through a default
   `None`.

The Run 147 expected flag surface (documented but **not** added in
Run 146) is:

* `--p2p-trust-bundle-peer-candidate-staging-enabled` — hidden,
  defaults `false`, refuses MainNet unconditionally, requires the
  existing live `0x05` validation flag, does not imply propagation,
  does not imply apply.
* (Optional) `--p2p-trust-bundle-peer-candidate-staging-max-global`,
  `…-max-per-peer`, `…-ttl-secs` for tuning the
  `PeerDrivenStagingPolicy` caps and TTL; safe defaults already
  exist on `PeerDrivenStagingPolicy::devnet_enabled` /
  `…::testnet_enabled`.

When Run 147 adds the flag, no dispatcher-level code needs to
change.

## Component identity (Run 146)

Run 146 promotes the Run 145 staging queue from a pure library
artefact to a **dispatcher-observable** primitive. The receive
pipeline becomes:

```
  live inbound 0x05 frame
      │
      ▼  (Run 079 decode + size checks)
  PeerCandidateWireReceiver
      │
      ▼  (Run 109 v1 ratification gate, when enabled)
      ▼  (Run 142 v2 ratification gate, when enabled)
  PeerCandidateOutcome::Validated(v)  │ or Rejected/Oversize/…
      │
      ▼  (Run 142 v2 authority-marker conflict check)
      ▼  (Run 123 v1 authority-marker conflict check)
      │
      ▼  ───────────────────  Run 146 staging hook  ───────
      │   if staging_queue.is_some()  &&  outcome is Validated
      │     queue.try_stage_outcome(outcome, fp+seq digest, now)
      │   else: no-op  (Run 143 behaviour preserved)
      │
      ▼  (Run 088 propagation-only rebroadcast, when enabled)
      │
      ▼
  outcome returned to caller (PeerCandidateWireFrameSink::handle_frame)
```

The staging hook is strictly downstream of validation and strictly
upstream of propagation, exactly as
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
prescribes for the Phase 2 layer. It is end-of-line for the data
it accepts: a staged record is never the source of an apply.

## Negative assertions exercised by the Run 146 test suite

Each Run 146 test, in addition to its primary positive/negative
expectation, asserts the following Run 146-mandated invariants:

| Invariant | How the test asserts it |
|---|---|
| No Run 070 apply call | The dispatcher has no apply path; the staging hook itself calls only `try_stage_outcome` which is a pure queue insert. |
| No `LivePqcTrustState` swap | The dispatcher does not own a `LivePqcTrustState`; the staging hook does not construct one. |
| No sequence write | `pqc_trust_bundle_sequence.json` byte-identical pre/post. |
| No authority-marker write | `pqc_authority_state.json` byte-identical pre/post. |
| No session eviction | The dispatcher has no `P2pSessionEvictor` handle; the staging hook does not construct one. |
| No SIGHUP / reload-apply outcome | The dispatcher does not call the Run 070 / Run 073 / Run 074 apply / reload paths. |
| No peer-driven apply metric/log | The only Run 146 log line is `[binary] Run 146: …STAGED / already staged / refused …` and explicitly disclaims apply / sequence persistence / live trust mutation / marker write / session touch. |
| No trusted-root fallback | The reused Run 069 / Run 076 / Run 130 validator pipeline rejects `DummySig` / `DummyKem` / `DummyAead` at startup; the staging hook does not relax this. |

## What Run 146 explicitly does NOT close

* Full **C4** ("peer-driven trust-bundle apply") remains **OPEN**:
  Run 146 stages observation only. No applied state changes hands.
* **C5** ("operator / governance approval surface") remains
  **OPEN**: the queue is a candidate list, not an approval decision.
* **Peer-driven live apply** remains unimplemented.
* **MainNet staging** remains refused unconditionally. A future
  governance / ratification / KMS-HSM proof type is required to
  even consider MainNet staging.
* **Release-binary staging evidence** is deferred to **Run 147**.

## Required validation commands (per `task/RUN_146_TASK.txt`)

```
cargo build -p qbind-node --lib
cargo test  -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests
cargo test  -p qbind-node --test run_145_peer_candidate_staging_tests
cargo test  -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test  -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test  -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test  -p qbind-node --lib pqc_authority
cargo test  -p qbind-node --lib
```

All commands pass with Run 146 changes in place.
