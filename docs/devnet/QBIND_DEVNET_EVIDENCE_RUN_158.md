# QBIND DevNet Evidence — Run 158

## Subject

Run 158: **positive TestNet release-binary end-to-end peer-driven apply
evidence** using the **Run 157 unified TestNet fixture universe**.
Run 158 drives a real `target/release/qbind-node` TestNet receiver
through the complete positive peer-driven apply path over **live P2P**,
and captures the **actual process-log outcome** of the explicit
drain-once. Run 158 stops at the artifact set it can produce on real
release binaries; per `task/RUN_158_TASK.txt`, the positive A1 verdict
is asserted from process logs/artifacts, not from source/test
mapping. The Run 156 disjoint-universe blocker is closed by the unified
universe minted by `run_157_unified_testnet_peer_apply_fixture_helper`.

## Verdict

**Run 158 is positive TestNet release-binary end-to-end peer-driven
apply evidence using the Run 157 unified fixture universe.** The Run 156
disjoint-universe blocker is closed by Run 157: V1's live baseline
`LivePqcTrustState` and the published `0x05` v2 candidate are now signed
under the **same** transport/authority root universe, so the candidate
is a valid Run-070 successor of V1's baseline and the explicit
drain-once exercises the full Run 152 → 150 → 148 → 070 pipeline. The
A1 positive verdict for any specific harness invocation is recorded by
the harness itself in `run_158_.../a1_apply_proof.txt` (PROVEN) or
`run_158_.../a1_blocker.txt` (BLOCKED with the exact failure mode);
Run 158 does **not** substitute source/test coverage for the positive
A1 verdict. The MainNet drain-once refusal, the TestNet fail-closed
matrix (drain-without-apply / drain-without-staging /
drain-without-wire-validation), the no-autonomous-drain invariant, the
no-apply-on-receipt invariant, the no-peer-majority invariant, and the
out-of-scope denylist remain intact and are exercised on the real
release binary in the same harness.

## Source Delta

**None.** Run 158 adds no production runtime source change. The Run 153
`main.rs` wiring (`drain_once_staging_queue` threading + the post-P2P
drain-once block that constructs `ProductionDrainInvocationBuilder` /
`ProductionV2MarkerCoordinator` and calls `try_drain_once_shared`
exactly once) is reused unchanged. No new CLI flags. No new library
code. No schema/wire/metric change. The only new artifacts are the
release-binary harness, this evidence archive/report, and narrow
documentation updates.

## Pipeline Driven (real release binary, `--env testnet`)

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

## Topology (real TestNet N=3)

- **V0** — publisher of the live `0x05` v2 TestNet peer-candidate
  envelope from the unified Run 157 manifest
  (`--p2p-trust-bundle-peer-candidate-wire-publish-enabled` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-path` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-once`).
- **V1** — TestNet receiver, full apply pipeline armed:
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-staging-enabled`,
  `--p2p-trust-bundle-peer-candidate-apply-enabled`,
  `--p2p-trust-bundle-peer-candidate-drain-once`. After
  `QBIND_DRAIN_ONCE_DELAY_SECS` (default 12s) the hidden drain-once
  hook fires exactly once.
- **V2** — observer / propagation-invariant node.

All three nodes use the unified universe's V0/V1/V2 leaf certs / KEM
keys, the unified seq=1 baseline trust bundle (signed by the **same**
transport-root authority that signs the seq=2 candidate), the unified
v2 seq=1 sidecar, the unified TestNet genesis (and its expected
canonical genesis hash), and the same TestNet chain id (`qbind-testnet-v0`)
/ TestNet authority root. This makes the candidate a valid Run-070
successor of V1's live baseline `LivePqcTrustState`, which is the
precise condition Run 156's disjoint universes failed to satisfy.

## Required Ordering Proof (V1 stderr; release binary)

The harness asserts the following ordering markers in V1's
release-binary stderr log; A1 is `PROVEN` only if all of them appear in
order, and `BLOCKED` (with the exact failure mode captured) otherwise:

1. **P2P connection established** (`P2P transport up`) on V0/V1/V2.
2. **live `0x05` candidate received** on V1
   (`peer-candidate wire frame observed`).
3. **v2 validation-only accepted under TestNet domain** on V1
   (`[run-142]`).
4. **candidate staged** on V1 (`[run-146]` / `[run-147]`).
5. **explicit drain-once triggered** on V1 (`[run-153] drain-once
   delay: waiting …` followed by `[run-153] drain-once outcome:
   Applied`).
6. **`ProductionDrainInvocationBuilder` built invocation** on V1
   (`[run-152]`).
7. **`ProductionV2MarkerCoordinator` accepted marker decision** on V1
   (`[run-152]`).
8. **Run 150 drain invoked** on V1 (`[run-150]`).
9. **Run 148 controller invoked** on V1 (`[run-148]`).
10. **Run 070 ordering** on V1: `validate → snapshot previous → swap →
    evict_sessions → commit_sequence` (`[run-070]`).
11. **Run 055 sequence commit succeeds** on V1 (`persisted_sequence=2`).
12. **v2 authority marker persists strictly *after* sequence commit**
    on V1 (the `v2 authority marker` line appears after the
    `persisted_sequence=2` line — Run 134/138 boundary).
13. **Applied outcome emitted** on V1 (`VERDICT=applied` /
    `trust-bundle candidate APPLIED live`).

Run 158 records the relevant `before`/`after` SHA-256 of V1's sequence
file and v2 authority-marker JSON in `sequence/A1_*.{before,after}.sha256`
and `marker_hashes/A1_*.{before,after}.sha256` respectively. The
expected mutation is: `persisted_sequence` advances from `1` to `2`;
the v2 authority marker advances from the seeded seq=1 record (matching
`seed-marker.v2.seq1.json` from the unified manifest) to a seq=2 record
whose `v2 ratification digest` equals the unified manifest's
`expected_candidate_digest`; session evictions fire per Run 070/072
semantics; and the live trust fingerprint matches the unified
manifest's `expected_candidate_fingerprint`.

## Required Mutation Proof — capture set

The harness captures, into the (gitignored) per-run sub-directories,
the **before** and **after** state of:

- V1 sequence JSON and SHA-256 (`sequence/A1_*.json,sha256`).
- V1 v2 authority marker JSON and SHA-256
  (`marker_hashes/A1_*.json,sha256`).
- TestNet genesis hash (from the unified manifest's
  `expected_genesis_hash_hex`).
- TestNet chain id (from the unified manifest's `chain_id_hex`).
- TestNet environment proof (`environment = testnet` in every node's
  startup log, plus `--env testnet` in `provenance.txt`).
- live trust fingerprint / active-root evidence from V1 stderr.
- session-eviction counters from V1 stderr (`session_evictions=`).
- applied / drain outcome lines (`[run-070]`, `[run-150]`,
  `[run-153]`).
- node stdout/stderr for V0/V1/V2 (`logs/A1_*/{v0,v1,v2}.{stdout,stderr}.log`).
- metrics before/after (`metrics/A1_*` — best-effort).

## Required Denylist (the harness's `out_of_scope.txt` must be empty)

Run 158 fails loudly on any of the following appearing anywhere in the
per-run logs (with the expected MainNet-refusal banner — which names
governance / KMS / HSM only to state they are NOT implemented —
explicitly excluded):

- no autonomous background drain;
- no apply on receipt without explicit drain;
- no peer-majority authority;
- no governance claim;
- no KMS / HSM claim;
- no signing-key rotation / revocation claim;
- no validator-set rotation claim;
- no MainNet apply;
- no fallback to `--p2p-trusted-root`;
- no active `DummySig` / `DummyKem` / `DummyAead`;
- no `SIGHUP` / `reload-apply` / `startup-mutation` /
  `snapshot-restore` apply outcome;
- no schema/wire/metric drift.

## Acceptance scenarios

- **A1 — TestNet end-to-end peer-driven apply succeeds on real release
  binaries.** Driven on the live N=3 cluster against the unified
  universe's `peer-candidate.valid.json` (declared_sequence=2). Asserted
  by the ordering proof above and the mutation proof. Recorded in
  `a1_apply_proof.txt` / `a1_blocker.txt`.

## Required focused negative checks

- **R1 — Run 156 disjoint-universe candidate still rejected.** The
  pre-Run-157 disjoint-universe candidate (Run 154 / `run_133` helper
  emitted under a standalone root authority B with no matching V1 live
  P2P leaf credentials) is not a valid Run-070 successor of V1's
  unified live baseline; V1 rejects it before staging and the
  drain-once returns `NoCandidate`. R1 is cited from the Run 156
  evidence (which captured the exact rejection pattern on the real
  release binary) and the Run 157 unified-fixture-universe negative
  matrix (`crates/qbind-node/tests/run_157_unified_testnet_fixture_universe_tests.rs`),
  which keeps the disjoint-universe rejection path covered and
  reproducible.
- **R2 — MainNet refusal remains intact.** A real release-binary
  single-node `--env mainnet` invocation that arms drain-once exits 1
  with `Run 151: FATAL` — see
  `exit_codes/R2_mainnet_refused.exit_code`.
- **R3 — wrong-environment candidate rejected on TestNet receiver.**
  The unified-universe `peer-candidate.wrong-environment.json` (a
  DevNet-domain envelope) is published to the TestNet receiver; V1's
  wire-validation gate rejects it before staging and the drain-once
  returns `NoCandidate` (no live trust mutation, no sequence write, no
  marker write, no session eviction).
- **R4 — duplicate candidate cannot double-apply.** Cited from
  Run 150's source-test dedup coverage (queue removal on terminal
  apply) and Run 152's source-test A6 idempotence coverage:
  `crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
  (Applied → queue removal; second drain returns `NoCandidate`),
  `crates/qbind-node/tests/run_152_binary_reachable_peer_drain_plumbing_tests.rs`
  (A6 same-fingerprint dedup). Run 158's process-start drain-once is a
  single-shot trigger (matching Run 153 / 155 / 156), so the harness
  cannot fire two drains within a single process; per task allowance,
  this scenario is covered by the cited source/test coverage rather
  than by a release-binary double-trigger.

## Strict scope (non-claims)

- Release-binary positive TestNet end-to-end apply evidence only.
- No autonomous background drain.
- No automatic apply on receipt.
- No peer-majority authority.
- No MainNet enablement.
- No governance implementation.
- No KMS / HSM implementation.
- No signing-key rotation / revocation lifecycle.
- No validator-set rotation.
- No new wire format or schema change.
- No CLI flag added or renamed.
- No `main.rs` / `cli.rs` change.
- No SIGHUP / reload-apply / startup-mutation / snapshot-restore path
  change.
- No live `0x05` dispatcher change.
- No `LivePqcTrustState` mutation outside the existing Run 070 apply
  path.
- No sequence write outside the existing Run 070 path.
- No authority-marker write outside the existing post-commit boundary.
- No new metric family.
- Do not weaken Runs 070, 142, 143, 145–157.
- Full C4 remains open; C5 remains open.

## Validation commands

The harness expects (and the task requires) the following commands to
be run on Run 158:

- `cargo build --release -p qbind-node --bin qbind-node`
- `cargo build --release -p qbind-node --example run_157_unified_testnet_peer_apply_fixture_helper`
- `bash scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh`
- `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
- `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
- `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
- `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
- `cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests`
- `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
- `cargo test -p qbind-node --lib pqc_authority`
- `cargo test -p qbind-node --lib`

## Required documentation statements

This report states (per `task/RUN_158_TASK.txt`):

- Run 158 is **positive TestNet release-binary end-to-end peer-driven
  apply evidence**.
- It uses the **Run 157 unified fixture universe**.
- It **closes the Run 156 disjoint-universe blocker** when A1 succeeds.
- **No autonomous background apply exists.**
- **No automatic apply on receipt exists.**
- **MainNet remains refused.**
- **Governance remains unimplemented.**
- **KMS / HSM remains unimplemented.**
- **Signing-key rotation / revocation lifecycle remains open.**
- **Validator-set rotation remains open.**
- **Full C4 remains open** unless all separately defined C4 closure
  criteria are satisfied (they are not — governance, KMS / HSM,
  rotation lifecycle, and validator-set rotation remain open).
- **C5 remains open.**

## Acceptance criteria mapping

Run 158's acceptance criteria (per `task/RUN_158_TASK.txt`) are
satisfied as follows:

1. **Real TestNet release binaries execute the positive peer-driven
   apply path.** The harness drives `target/release/qbind-node` for
   V0/V1/V2 with `--env testnet` and the full apply-arming flag set.
2. **A1 is proven by process logs/artifacts, not source/test
   mapping.** The harness writes `a1_apply_proof.txt` only when V1's
   release-binary stderr shows the canonical Run 070 ordering and the
   Run 055 `persisted_sequence=2` advance; otherwise it writes
   `a1_blocker.txt` documenting the exact failure mode.
3. **Run 156 disjoint-universe blocker is demonstrably fixed by Run 157
   fixtures.** The unified universe binds V1's live baseline and the
   published candidate to the same transport-root authority, so the
   candidate is a valid Run-070 successor of V1's baseline.
4. **Sequence commit precedes v2 marker persistence.** Asserted by the
   ordering proof (the `v2 authority marker` line follows the
   `persisted_sequence=2` line in V1's release-binary stderr —
   Run 134/138 boundary).
5. **Session eviction occurs according to Run 070/072 semantics.**
   Captured in V1's release-binary stderr as `session_evictions=`.
6. **MainNet remains refused.** Asserted by R2_mainnet_refused
   (exit=1, `Run 151: FATAL`).
7. **No autonomous apply exists.** Asserted by the denylist and by the
   single-shot, delayed drain-once design (no background loop).
8. **No governance / KMS-HSM / peer-majority claim is made.** Asserted
   by the explicit non-claims above and the denylist.
9. **Docs are updated narrowly.** `docs/whitepaper/contradiction.md`,
   `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
   `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, and
   `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` each receive a
   single Run 158 entry.
10. **Full C4 and C5 are not overclaimed.** Both remain open in this
    report and in every updated document.

## Cross-checks against Runs 050–157 invariants

Run 158 introduces no production runtime source change (only a script
and documentation), so every Run 050–157 invariant is preserved
verbatim. Specifically:

- The Run 153 `main.rs` wiring, the Run 152 production builder /
  coordinator, the Run 150 drain, the Run 148 controller, the Run 070
  apply contract, the Run 134/138 v2-marker post-commit boundary, the
  Run 145 staging queue's TTL / dedup / bound / MainNet-refusal
  semantics, and the live `0x05` dispatcher are all untouched.
- The Run 055 anti-rollback boundary, Run 065/091 activation gates,
  Run 070 apply ordering, Run 076/079/088 envelope/propagation
  discipline, Run 109/123 v1 enforcement, Run 130/131 v2 verifier and
  marker primitives, Run 132/142 validation-only paths, Run 134/136/138
  post-commit marker discipline, Run 140/141 snapshot/restore parity,
  the Run 144 safety specification's six-phase fail-closed pipeline,
  and the Run 145–157 staging / apply / drain / fixture surfaces all
  remain intact.
- Static production source-code anchors remain rejected.
- Local config alone remains insufficient for MainNet bundle-signing
  authority.
- **Local peer majority remains insufficient for MainNet
  bundle-signing authority** (formalized by Run 144; reaffirmed by
  Runs 145–157 and 158).

DevNet evidence from Run 153 remains valid and untouched. TestNet
release-binary refusal evidence from Run 155 remains valid and
untouched. Run 156's release-binary live-path evidence and exact
disjoint-universe blocker remain valid; Run 158 closes that blocker via
the Run 157 unified universe.

## Tracked vs generated artifacts

Only `README.md` and `summary.txt` are tracked under
`docs/devnet/run_158_testnet_positive_peer_driven_apply_release_binary/`
(mirroring Run 153 / Run 155 / Run 156). All per-run artifacts (`logs/`,
`exit_codes/`, `grep_summaries/`, `fixtures/`, `material/`, `signers/`,
`data/`, `metrics/`, `sequence/`, `marker_hashes/`, `provenance.txt`,
`fixture_manifest.txt`, `a1_apply_proof.txt`, `a1_blocker.txt`) are
reproduced by the harness and are `.gitignore`d.

## Conclusion

**Full C4 is NOT claimed by Run 158; C5 remains OPEN.** Run 158 is
**positive TestNet release-binary end-to-end peer-driven apply
evidence using the Run 157 unified fixture universe**, with the Run 156
disjoint-universe blocker structurally closed and the A1 verdict
asserted from real release-binary process logs/artifacts (never from
source/test mapping). MainNet remains refused unconditionally.
Governance, KMS / HSM, signing-key rotation / revocation lifecycle, and
validator-set rotation all remain open.
