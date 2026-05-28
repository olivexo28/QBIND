# QBIND DevNet Evidence — Run 148

**Subject**: Source/test wiring of a peer-driven trust-bundle
**live apply controller** (`pqc_peer_candidate_apply`) that
consumes already-staged, validated peer candidates and applies
them through the existing Run 070 apply contract behind explicit
local DevNet/TestNet policy, with v2 marker post-commit
persistence per Run 134/138.

## Verdict (mandatory disclosure per `task/RUN_148_TASK.txt` §1, §3)

**Run 148 is source/test only.** No release-binary evidence is
captured in this run. The new controller is library-only; it is
not yet wired into the node binary's reload-apply path or its
SIGHUP path. Release-binary DevNet/TestNet peer-driven apply
evidence is deferred to **Run 149**.

The source delta is exactly:

1. One new library module
   `crates/qbind-node/src/pqc_peer_candidate_apply.rs` exposing:
   * `PeerDrivenApplyPolicy` (defaults disabled; constructors
     `devnet_enabled()`, `testnet_enabled()`,
     `mainnet_attempted()`),
   * `PeerDrivenApplyOutcome` enum with the 13 outcome variants
     enumerated in `task/RUN_148_TASK.txt` §6,
   * `V2MarkerCoordinator` trait + `NoV2MarkerCoordinator`
     default implementation,
   * `try_apply_staged_peer_candidate(...)` controller function
     that runs the gate order
     `enabled → MainNet refusal → environment policy →
     staged-candidate lookup → TTL → validation flag →
     domain (env + chain_id) → v2 marker pre-apply →
     Run 070 apply → v2 marker post-commit persist`.
2. One `pub mod pqc_peer_candidate_apply;` declaration in
   `crates/qbind-node/src/lib.rs`.
3. One new integration test file
   `crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`
   covering matrix A1–A4 and R1–R16.

The controller **does not** call into `pqc_trust_reload`'s
SIGHUP path, **does not** touch the node binary's main loop,
**does not** invoke the network/peer-manager directly, and
**does not** introduce new CLI flags. It is reachable only by
library callers and tests.

## Scope statement (mandatory per task §302)

* **Run 148 is source/test only.**
* **Peer-driven apply is now source/test wired only for
  DevNet/TestNet local policy.** A disabled-by-default
  `PeerDrivenApplyPolicy` refuses on every environment; the
  caller must construct
  `PeerDrivenApplyPolicy::devnet_enabled()` or
  `PeerDrivenApplyPolicy::testnet_enabled()` explicitly to
  enable apply.
* **MainNet remains refused unconditionally.** Both the
  policy-environment field and the runtime-domain environment
  are checked; either being MainNet returns
  `PeerDrivenApplyOutcome::RefusedMainNet` with no further
  pipeline work. The `allow_mainnet` field on
  `PeerDrivenApplyPolicy::mainnet_attempted()` is kept for
  future governance/KMS-HSM wiring but has **no effect** on the
  refusal in this run.
* **Release-binary DevNet/TestNet peer-driven apply evidence
  is deferred to Run 149.**
* **Governance/KMS-HSM/signing-key lifecycle remain open.** No
  changes to authority signing-key management are made in this
  run.
* **Full C4 remains open.** Run 148 closes only the source/test
  layer of the peer-driven apply pipeline. Release-binary
  wiring, operator runbook, governance approvals, and the
  broader C4 acceptance package remain outstanding.
* **C5 remains open.** No multi-node DevNet/TestNet evidence
  is produced.

## What changed vs. Run 147

| Aspect | Run 147 | Run 148 |
| --- | --- | --- |
| Live `0x05` staging | hidden opt-in arming flag | unchanged |
| Stage → apply path  | **absent** (queue is non-applying) | **added (library only)** behind `PeerDrivenApplyPolicy` |
| MainNet apply       | n/a                  | refused unconditionally |
| Apply contract      | n/a                  | **reuses** Run 070 `apply_validated_candidate_with_previous` |
| v2 marker           | n/a                  | persisted **only after** sequence commit, per Run 134/138 |
| Release binary      | armed staging only   | **unchanged** (Run 148 does not touch the binary) |

## Properties enforced by `try_apply_staged_peer_candidate`

* Disabled policy refuses without mutation
  (`PeerDrivenApplyOutcome::Disabled`).
* MainNet refuses unconditionally
  (`PeerDrivenApplyOutcome::RefusedMainNet`), regardless of
  `allow_mainnet`.
* DevNet-only policy refuses on TestNet/MainNet, TestNet-only
  policy refuses on DevNet/MainNet, with
  `PeerDrivenApplyOutcome::RefusedEnvironmentPolicy`.
* Only an already-staged candidate (by
  `StagedPeerCandidateId{ fingerprint_prefix, sequence }`) can
  reach apply. Unstaged → `CandidateNotFound`; TTL-expired →
  `CandidateExpired`; not validation-accepted →
  `CandidateNotValidated`; wrong env or wrong chain →
  `CandidateWrongDomain`.
* Pre-apply v2 marker check (lower sequence / same-sequence
  conflicting digest) returns
  `CandidateMarkerConflict` **before** any state swap.
* Apply itself is delegated to
  `apply_validated_candidate_with_previous` from
  `pqc_trust_reload`. Run 070's
  `validate → snapshot_active → swap_trust_state →
  evict_sessions → commit_sequence` ordering and rollback
  semantics are preserved unchanged.
* v2 marker is persisted only after the sequence commit
  succeeds, by delegating to a `V2MarkerCoordinator` whose
  production implementation wraps
  `persist_accepted_v2_marker_after_commit_boundary`. A
  post-commit persist failure surfaces as the fatal,
  operator-actionable outcome
  `MarkerPersistFailedAfterCommit`.

## Tests

`cargo test -p qbind-node --test
run_148_peer_driven_apply_devnet_tests` runs 20 tests covering
the full A1–A4 + R1–R16 matrix from `task/RUN_148_TASK.txt`
§7, plus a `NoV2MarkerCoordinator` smoke test, all passing.
The in-module unit tests
(`cargo test -p qbind-node --lib pqc_peer_candidate_apply`)
add 8 additional cases covering policy constructors,
outcome-classification helpers, staged-candidate id matching,
the saturating age helper, and the no-op coordinator.

## What Run 148 explicitly does NOT do

* Does not modify `crates/qbind-node/src/main.rs`.
* Does not modify `crates/qbind-node/src/cli.rs`.
* Does not modify the SIGHUP reload-apply path in
  `pqc_trust_reload.rs`.
* Does not modify the live `0x05` dispatcher in
  `pqc_live_inbound_dispatcher.rs` or its staging hook.
* Does not change MainNet refusal semantics anywhere.
* Does not produce a release binary or capture release-binary
  evidence.
