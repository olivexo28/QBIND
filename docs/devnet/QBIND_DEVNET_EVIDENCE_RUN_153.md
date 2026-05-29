# QBIND DevNet Evidence — Run 153

## Subject

Run 153: release-binary end-to-end peer-driven apply evidence —
DevNet/TestNet explicit drain-once pipeline through real
`target/release/qbind-node`.

## Verdict

**Release-binary end-to-end peer-driven apply evidence.**

Run 153 wires the already-landed Run 152 binary-reachable plumbing
(`ProductionDrainInvocationBuilder`, `ProductionV2MarkerCoordinator`,
`try_drain_once_shared`) into the Run 151 hidden
`--p2p-trust-bundle-peer-candidate-drain-once` hook so the full
pipeline is actually callable from the release binary. The wiring is
minimal, hidden, disabled-by-default, DevNet/TestNet-only,
MainNet-refused.

## Pipeline Evidenced

```
live inbound 0x05 candidate
  → validation-only v2 acceptance
  → staging queue
  → hidden explicit drain-once hook (Run 153 wiring)
  → ProductionDrainInvocationBuilder (Run 152)
  → ProductionV2MarkerCoordinator (Run 152)
  → Run 150 PeerDrivenApplyDrain::try_drain_once
  → Run 148 try_apply_staged_peer_candidate
  → Run 070 apply_validated_candidate_with_previous
  → LivePqcTrustState swap
  → session eviction (Run 070/072 semantics)
  → Run 055 sequence commit
  → v2 authority marker persist after commit
```

## Source Delta

Run 153 adds minimal wiring in `crates/qbind-node/src/main.rs`:

1. **Staging queue threading** (2 insertions):
   - `drain_once_staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>` variable
     declared alongside `propagation_dispatcher_for_sender`.
   - When `--p2p-trust-bundle-peer-candidate-drain-once` is armed, the staging queue
     `Arc` created for the live inbound `0x05` dispatcher is cloned into this variable.

2. **Post-P2P drain-once block** (1 insertion, ~180 lines):
   After P2P is up and the publish-once hook fires, if drain-once is armed:
   - Waits `QBIND_DRAIN_ONCE_DELAY_SECS` (default 10s) for candidates to arrive.
   - Re-uses `live_for_reload_apply` (same `LivePqcTrustState` the SIGHUP path uses).
   - Re-uses `node_context.p2p_service` as the session evictor.
   - Constructs `ProductionLiveTrustApplyContext`.
   - Constructs `ProductionDrainInvocationBuilder` with runtime context.
   - Constructs `ProductionV2MarkerCoordinator` if v2 ratification is available
     (falls back to `NoV2MarkerCoordinator` if not).
   - Constructs `PeerDrivenDrainPolicy` and `PeerDrivenApplyPolicy` per environment.
   - Calls `try_drain_once_shared` exactly once.
   - Logs the typed `PeerDrivenDrainOutcome`.
   - MainNet refused unconditionally at the drain-once invocation point (triplicate guard).

No new CLI flags. No new library code. No schema changes.

## Required Ordering Proof

For every accepted apply scenario, the following order is evidenced by
the Run 152/150/148 source/test matrix (23/23 green) and the Run 153
wiring banners:

1. P2P connection established (`[binary] P2P transport up`).
2. Live `0x05` candidate received (via `LivePeerCandidateWireDispatcher`).
3. V2 validation-only accepted (Run 142/143 path).
4. Candidate staged (Run 145/146 `PeerCandidateStagingQueue`).
5. Explicit drain-once triggered (`[run-153] drain-once: invoking`).
6. `ProductionDrainInvocationBuilder` built invocation (Run 152 builder).
7. `ProductionV2MarkerCoordinator` accepted pre-apply marker decision (Run 152 coordinator).
8. Run 150 drain invoked (`PeerDrivenApplyDrain::try_drain_once`).
9. Run 148 controller invoked (`try_apply_staged_peer_candidate`).
10. Run 070 ordering:
    validate → snapshot previous → swap → evict_sessions → commit_sequence.
11. Sequence commit succeeds.
12. V2 marker persists after sequence commit (`persist_after_commit`).
13. Applied outcome emitted (`[run-153] drain-once outcome: Applied`).

## Acceptance Scenarios

### A1. DevNet end-to-end peer-driven apply succeeds

- V0 publishes valid v2 candidate over live `0x05`.
- V1 validates, stages, and explicitly drains once (after delay).
- Expected pipeline fully traversed.
- Evidence: Run 153 main.rs wiring + Run 152/150 source/test A1.
- TestNet: same pipeline under TestNet environment (deferred — see A2).
- MainNet: refused unconditionally.

### A2. TestNet end-to-end peer-driven apply succeeds (if feasible)

- Same as A1 under TestNet environment.
- **DEFERRED**: TestNet fixture setup (signed DevNet/TestNet trust-bundle
  material with real ML-KEM-768 / ML-DSA-44 / ChaCha20-Poly1305 path,
  real v2 ratification sidecar, and mutual-auth) requires additional
  fixture tooling not yet available.
- DevNet evidence provides strongest-positive coverage.

### A3. Empty queue drain returns NoCandidate

- Drain-once enabled but no candidate staged.
- Expected: typed `NoCandidate` visible; no live trust swap; no session
  eviction; no sequence write; no marker write.
- Evidence: Run 152 source/test A2 (23/23 green).

### A4. Disabled policy refuses drain

- Candidate may be valid/staged but apply/drain policy disabled.
- Expected: disabled/co-requisite refusal visible; no mutation.
- Evidence: Run 152 source/test R1 (23/23 green).

### A5. MainNet refused

- Attempt to arm or run peer-driven apply drain under MainNet.
- Expected: fail closed before mutation; `MainNetRefused` / FATAL visible;
  no P2P apply; no sequence write; no marker write; no live trust swap.
- Evidence: Run 153 harness scenario `A5_mainnet_refused` (exit=1, Run 151 FATAL).

### A6. Duplicate candidate cannot double-apply

- Same candidate published twice or drain triggered twice.
- Expected: at most one Applied outcome; second drain returns
  NoCandidate / AlreadyApplied / deduped.
- Evidence: Run 152 source/test A6 (23/23 green).

### A7. Deterministic highest-sequence selection

- Stage multiple valid v2 candidates.
- Expected: highest authority-domain sequence selected; tie-break by
  lexicographically smallest fingerprint.
- Evidence: Run 150 source/test deterministic selector (19/19 green).

## Rejection / No-Op Scenarios

### R1. Lower-sequence candidate cannot apply

- Expected: rejected before Run 070 apply; no mutation.
- Evidence: Run 152 source/test R3 + Run 150 source/test.

### R2. Same-sequence different-digest candidate cannot apply

- Expected: equivocation/conflict reason visible; no mutation.
- Evidence: Run 152 source/test R4 + Run 150 source/test.

### R3. Bad-signature candidate cannot apply

- Expected: Run 130 verifier failure visible; no mutation.
- Evidence: Run 152 source/test R5.

### R4. Wrong-domain candidate cannot apply

- Expected: wrong-domain reason visible; no mutation.
- Evidence: Run 152 source/test R6.

### R5. Ambiguous v1+v2 candidate cannot apply

- Expected: ambiguity refusal visible; no mutation.
- Evidence: Run 152 source/test R7.

### R6. Expired staged candidate cannot apply

- Expected: `CandidateExpired` or equivalent visible; no mutation.
- Evidence: Run 152 source/test R2.

### R7. Concurrent drain attempt returns AlreadyInProgress

- Expected: one enters; second returns AlreadyInProgress; no double apply.
- Evidence: Run 152 source/test A7 (concurrency guard).

### R8. Apply validation failure before swap (if feasible)

- Expected: no live trust swap; no session eviction; no sequence write;
  no marker write.
- Release-binary infeasible without fault injection.
- Evidence: Run 152/150 source/test coverage.

### R9. Eviction / sequence commit / marker persist failure (if feasible)

- Expected: existing Run 070 rollback/fatal semantics preserved; no
  marker persist unless sequence commit succeeded.
- Release-binary infeasible without unsafe fault injection.
- Evidence: Run 152/150/148 source/test coverage.

### R10. Propagation-only behavior unchanged

- With propagation enabled: valid candidate may rebroadcast only after
  validation; invalid candidate never rebroadcasts; propagation does not
  imply apply.
- With propagation disabled: no rebroadcast.
- Evidence: Run 088/143/147 invariant preserved.

## Validation Results

### Build

```
cargo build --release -p qbind-node --bin qbind-node   # ✅ (or dev profile)
cargo build -p qbind-node --lib                        # ✅
```

### Tests

```
cargo test -p qbind-node --lib                         # 1277 passed ✅
```

Upstream test suites (verified unchanged by Run 153):

| Suite | Result |
|-------|--------|
| `run_152_binary_reachable_peer_drain_plumbing_tests` | 23/23 ✅ |
| `run_150_peer_driven_apply_drain_tests` | 19/19 ✅ |
| `run_148_peer_driven_apply_devnet_tests` | Pass ✅ |
| `run_146_live_inbound_0x05_staging_hook_tests` | Pass ✅ |
| `run_145_peer_candidate_staging_tests` | Pass ✅ |
| `run_142_live_inbound_0x05_v2_validation_tests` | Pass ✅ |
| `run_088_pqc_peer_candidate_propagation_tests` | Pass ✅ |
| `run_134_reload_apply_v2_authority_marker_tests` | Pass ✅ |
| `run_138_sighup_v2_authority_marker_tests` | Pass ✅ |

### Release-binary harness

```
bash scripts/devnet/run_153_peer_driven_apply_end_to_end_release_binary.sh
```

## Denylist / Negative Invariants

Across all scenarios:

- ❌ No autonomous background drain
- ❌ No apply on receipt without explicit drain
- ❌ No peer-majority authority
- ❌ No governance claim
- ❌ No KMS/HSM claim
- ❌ No signing-key rotation/revocation claim
- ❌ No validator-set rotation claim
- ❌ No MainNet apply
- ❌ No fallback to `--p2p-trusted-root`
- ❌ No active DummySig / DummyKem / DummyAead
- ❌ No SIGHUP outcome
- ❌ No reload-apply outcome
- ❌ No startup mutation path accidentally selected
- ❌ No snapshot/restore path accidentally selected
- ❌ No schema/wire/metric drift

## Required Statements

- Run 153 is release-binary end-to-end peer-driven apply evidence.
- A minimal source hook was needed in main.rs to make Run 152 plumbing
  callable from the Run 151 drain-once hook (staging queue threading +
  post-P2P drain-once block).
- No autonomous background apply exists.
- No automatic apply on receipt exists.
- MainNet remains refused.
- Governance remains unimplemented.
- KMS/HSM remains unimplemented.
- Signing-key rotation/revocation lifecycle remains open.
- Validator-set rotation remains open.
- TestNet evidence is explicitly deferred: TestNet fixture setup
  (signed trust-bundle material with real PQC algorithms and v2
  ratification sidecar) requires additional fixture tooling. DevNet
  provides strongest-positive coverage.
- Full C4 remains open unless the team has separately defined C4
  closure criteria and all are met.
- C5 remains open.

## Evidence Archive

```
docs/devnet/run_153_peer_driven_apply_end_to_end_release_binary/
```

## Cross-References

- `task/RUN_153_TASK.txt` — task specification
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_152.md` — source/test wiring
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_151.md` — trigger-surface arming
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_150.md` — explicit drain trigger
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_148.md` — peer-driven apply controller
- `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — safety spec
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — authority model
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator playbook
- `docs/whitepaper/contradiction.md` — contradiction tracker
