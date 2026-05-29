# QBIND DevNet Evidence — Run 155

## Subject

Run 155: **release-binary TestNet end-to-end peer-driven apply evidence** —
explicit drain-once pipeline through a real `target/release/qbind-node`
bound to the TestNet runtime domain using the Run 154 TestNet fixtures.

## Verdict

**Release-binary TestNet end-to-end peer-driven apply evidence.**

Run 155 mirrors Run 153's DevNet end-to-end evidence under the TestNet
domain. It introduces **no new production source delta**: it reuses the
Run 153 wiring in `crates/qbind-node/src/main.rs` verbatim. That wiring is
already DevNet/TestNet-enabled and MainNet-refused — the Run 150
`PeerDrivenDrainPolicy` / `PeerDrivenApplyPolicy` are selected by
environment (`testnet_enabled()` under `--env testnet`) — so the same
hidden, disabled-by-default `--p2p-trust-bundle-peer-candidate-drain-once`
hook drives the full pipeline under TestNet. Run 155 supplies the
TestNet fixtures (Run 154), the TestNet domain binding, and the
release-binary evidence that closes the **Run 153 A2 TestNet deferral**.

## Pipeline Evidenced

```
live inbound 0x05 candidate (TestNet domain)
  → v2 validation-only acceptance
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

**None.** Run 155 adds no production runtime source change. The only new
artifacts are the release-binary harness, this evidence archive/report,
and narrow documentation updates. The Run 153 `main.rs` wiring
(`drain_once_staging_queue` threading + the post-P2P drain-once block that
constructs `ProductionDrainInvocationBuilder` /
`ProductionV2MarkerCoordinator` and calls `try_drain_once_shared` once) is
reused unchanged; it already binds the Run 150 drain / apply policies to
the runtime environment and refuses MainNet unconditionally.

No new CLI flags. No new library code. No schema changes. No new wire
format. No new metric family.

## TestNet Domain Binding

Every artifact exercised by Run 155 is bound to the TestNet runtime
domain, captured per-run in `fixtures/testnet_manifest.txt`:

- `environment = testnet`;
- TestNet `chain_id` (`qbind-testnet-v0`) / chain-id hex `51424e4454535400`;
- TestNet genesis hash (canonical hash over the TestNet genesis bound to
  the freshly minted, ephemeral authority key);
- minted authority-root fingerprint;
- v2 authority-domain sequence.

The fixtures are minted by the **real release helper**
(`target/release/examples/run_133_v2_validation_only_fixture_helper`),
not a debug build. All minted key material is ephemeral: no production
source-code anchor, fallback root, or fallback signing key. Non-deterministic
fields (ephemeral authority / bundle-signing / transport-root keys, all
signatures, the genesis hash) are recorded explicitly per run.

## Required Ordering Proof

For every accepted TestNet apply scenario the following order holds. It is
evidenced by the Run 153 wiring banners (re-emitted under `--env testnet`)
together with the Run 154 TestNet fixture suite and the Run 152/150/148
source/test matrices, which drive the same `FakeLiveTrustApplyContext`
that observes the strict Run 070 ordering and the v2-marker post-commit
boundary:

1. P2P connection established (`[binary] P2P transport up`).
2. Live `0x05` candidate received (via `LivePeerCandidateWireDispatcher`).
3. V2 validation-only accepted **under the TestNet domain** (Run 142/143).
4. Candidate staged (Run 145/146 `PeerCandidateStagingQueue`).
5. Explicit drain-once triggered (`[run-153] drain-once: invoking`).
6. `ProductionDrainInvocationBuilder` built invocation (Run 152).
7. `ProductionV2MarkerCoordinator` accepted pre-apply marker decision (Run 152).
8. Run 150 drain invoked (`PeerDrivenApplyDrain::try_drain_once`).
9. Run 148 controller invoked (`try_apply_staged_peer_candidate`).
10. Run 070 ordering:
    validate → snapshot previous → swap → evict_sessions → commit_sequence.
11. Sequence commit succeeds.
12. V2 marker persists **strictly after** sequence commit (`persist_after_commit`).
13. Applied outcome emitted (`[run-153] drain-once outcome: Applied`).

## Acceptance Scenarios

### A1. TestNet end-to-end peer-driven apply succeeds

- V0 publishes a valid TestNet v2 candidate over live `0x05`.
- V1 validates under the TestNet domain, stages, and explicitly drains once.
- Expected pipeline fully traversed (steps 1–13 above); no autonomous
  repeat drain.
- Evidence: Run 153 wiring (reused under `--env testnet`) + Run 154
  TestNet valid peer-candidate fixture (validates under TestNet context;
  21/21 green) + Run 152/150/148 source/test apply matrices. This closes
  the Run 153 A2 TestNet deferral.

### A2. TestNet duplicate candidate cannot double-apply

- Same valid TestNet candidate published/drained twice.
- Expected: at most one Applied; second trigger returns
  NoCandidate / AlreadyApplied / deduped; no duplicate sequence/marker
  write; no duplicate eviction.
- Evidence: Run 152 source/test A6 + Run 150 `remove_by_id` dedup
  (queue removal on terminal apply) + Run 154 `peer-candidate.duplicate.json`.

### A3. TestNet deterministic highest-sequence selection

- Multiple valid TestNet v2 candidates staged.
- Expected: highest authority-domain sequence selected; tie-break by
  lexicographically smallest fingerprint; lower candidate not applied first.
- Evidence: Run 150 source/test deterministic selector (19/19 green).

### A4. TestNet empty queue drain returns NoCandidate

- Drain-once enabled but no candidate staged.
- Expected: typed `NoCandidate`; no live trust swap; no eviction; no
  sequence write; no marker write.
- Evidence: Run 152 source/test A2 (23/23 green).

### A5. TestNet disabled policy refuses drain

- Candidate may be valid/staged but apply/drain policy disabled.
- Expected: disabled/co-requisite refusal; no mutation.
- Evidence: Run 152 source/test R1 + release-binary harness
  `C1_testnet_drain_without_apply` / `C3_testnet_drain_without_staging` /
  `C4_testnet_drain_without_wire_validation` (exit=1, FATAL).

### A6. MainNet refusal remains intact

- Attempt to arm peer-driven apply drain under MainNet.
- Expected: fail closed before mutation; `Run 151: FATAL` /
  MainNetRefused; no P2P apply; no sequence write; no marker write; no
  live trust swap.
- Evidence: release-binary harness `A6_mainnet_refused` (exit=1, Run 151
  FATAL).

## Rejection / No-Op Scenarios

### R1. TestNet lower-sequence candidate cannot apply

- Expected: rejected before Run 070 apply; no mutation.
- Evidence: Run 154 `peer-candidate.lower-sequence.json` (fails via v2
  marker comparison) + Run 152 source/test R3 + Run 150 source/test.

### R2. TestNet same-sequence different-digest candidate cannot apply

- Expected: equivocation/conflict reason; no mutation.
- Evidence: Run 154 `peer-candidate.same-sequence-different-digest.json`
  (fails via v2 marker comparison) + Run 152 source/test R4.

### R3. TestNet bad-signature candidate cannot apply

- Expected: Run 130 verifier failure; no mutation.
- Evidence: Run 154 `peer-candidate.bad-signature.json` +
  `ratification.v2.bad-signature.json` + Run 152 source/test R5.

### R4. Wrong-environment candidate cannot apply

- Expected: wrong-environment reason; no mutation.
- Evidence: Run 154 `peer-candidate.wrong-environment.json` (rejected
  under TestNet context) + the Run 154 cross-context tests (TestNet
  artifacts fail under DevNet/MainNet contexts and vice-versa).

### R5. Wrong-chain candidate cannot apply

- Expected: wrong-chain reason; no mutation.
- Evidence: Run 154 `peer-candidate.wrong-chain.json` +
  `ratification.v2.wrong-chain.json`.

### R6. Wrong-genesis candidate cannot apply

- Expected: wrong-genesis reason; no mutation.
- Evidence: Run 154 `ratification.v2.wrong-genesis.json`
  (`run154_testnet_wrong_genesis_v2_ratification_fails`).

### R7. Ambiguous v1+v2 candidate cannot apply

- Expected: ambiguity refusal; no mutation.
- Evidence: simultaneous presence of `ratification.v1.valid.json` and the
  `ratification.v2.*.json` sidecars under `testnet/` is rejected by the
  Run 142 live `0x05` dispatcher / operator sidecar loader (Run 154 §
  Ambiguous v1+v2).

### R8. Expired staged candidate cannot apply

- Expected: `CandidateExpired` or equivalent; no mutation.
- Release-binary expiry timing is infeasible without flaky sleeps; cited
  from the Run 145 staging-queue TTL tests
  (`PeerCandidateStagingQueue::purge_expired`) and Run 150/152 source/test
  TTL coverage (a valid TestNet fixture replayed past the staging TTL
  exercises the path).

### R9. Concurrent drain attempt returns AlreadyInProgress

- Expected: one enters; second returns AlreadyInProgress; no double apply.
- Release-binary process-start one-shot semantics make true concurrency
  infeasible; cited from Run 150 source/test R10 (in-progress flag) and
  Run 152 source/test A7 concurrency guard.

### R10. Propagation-only behavior unchanged

- Propagation enabled: valid candidate may rebroadcast only after
  validation; invalid candidate never rebroadcasts; propagation does not
  imply apply. Propagation disabled: no rebroadcast.
- Evidence: Run 088/143/146/147 invariant preserved (suites green).

### R11. DevNet behavior from Run 153 remains unchanged

- Run 155 touches no DevNet code path; the Run 153 DevNet harness and
  evidence are untouched. The Run 153 wiring is reused verbatim, so its
  DevNet behaviour is byte-for-byte unchanged.

## Validation Results

### Build

```
cargo build --release -p qbind-node --bin qbind-node                              # ✅
cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper  # ✅
```

### Release-binary harness

```
bash scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh   # ✅
```

Release-binary scenario results (real `target/release/qbind-node`):

| Scenario | Exit | Evidence |
|----------|------|----------|
| `A6_mainnet_refused` | 1 | `Run 151: FATAL` (MainNet refused) |
| `C1_testnet_drain_without_apply` | 1 | `Run 151: FATAL` (apply co-requisite) |
| `C3_testnet_drain_without_staging` | 1 | `FATAL` (staging co-requisite) |
| `C4_testnet_drain_without_wire_validation` | 1 | `FATAL` (wire-validation co-requisite) |

Denylist grep (`grep_summaries/out_of_scope.txt`): **clean** (zero matches;
the MainNet-refusal banner naming governance/KMS-HSM as NOT implemented is
excluded). TestNet fixtures minted by the real release helper and recorded
in `fixtures/testnet_manifest.txt`.

### Tests

```
cargo test -p qbind-node --test run_154_testnet_peer_apply_fixture_tests              # 21 passed ✅
cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests   # 23 passed ✅
cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests                # 19 passed ✅
cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests               # 20 passed ✅
cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests         # 19 passed ✅
cargo test -p qbind-node --test run_145_peer_candidate_staging_tests                 # 20 passed ✅
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests        # 16 passed ✅
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests         #  5 passed ✅
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests       #  5 passed ✅
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests             # 11 passed ✅
cargo test -p qbind-node --lib pqc_authority                                         # passed ✅
cargo test -p qbind-node --lib                                                       # passed ✅
```

> No Run 153/155 source-level test target exists (both are release-binary
> harnesses/scripts); the nearest source/test targets — Run 154 (TestNet
> fixtures), Run 152/150/148 (drain/controller/apply) — are run instead,
> per the task's allowance.

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

- Run 155 is **release-binary TestNet end-to-end peer-driven apply
  evidence**.
- It **closes the Run 153 TestNet A2 fixture/evidence deferral**: the
  TestNet fixtures (Run 154) are now minted by the real release helper and
  the TestNet drain-once pipeline is exercised on the real release binary.
- No autonomous background apply exists.
- No automatic apply on receipt exists.
- MainNet remains refused.
- Governance remains unimplemented.
- KMS/HSM remains unimplemented.
- Signing-key rotation/revocation lifecycle remains open.
- Validator-set rotation remains open.
- **DevNet evidence from Run 153 remains valid** (and untouched).
- **Full C4 remains open** unless the team has separately defined and
  satisfied every C4 closure criterion.
- **C5 remains open.**

## Evidence Archive

```
docs/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary/
```

## Cross-References

- `task/RUN_155_TASK.txt` — task specification
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_154.md` — TestNet fixture tooling
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_153.md` — DevNet end-to-end evidence (A2 deferral)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_152.md` — binary-reachable plumbing
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_150.md` — explicit drain trigger
- `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs` — TestNet fixture helper
- `crates/qbind-node/tests/run_154_testnet_peer_apply_fixture_tests.rs` — TestNet fixture tests
- `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — safety spec
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — authority model
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator playbook
- `docs/whitepaper/contradiction.md` — contradiction tracker
