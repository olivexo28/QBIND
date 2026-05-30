# QBIND DevNet Evidence — Run 156

## Subject

Run 156: **positive TestNet release-binary end-to-end peer-driven apply
closure** — drive a real `target/release/qbind-node` TestNet receiver
through the complete positive peer-driven apply path over **live P2P**,
and capture the **actual process-log outcome** of the explicit
drain-once. Run 156 is the run that stops mapping the positive A1 path to
source/test coverage and instead executes it on the real release binaries.

## Verdict

**Release-binary live-path evidence captured; positive A1 apply outcome is
BLOCKED by a fixture-universe limitation, documented exactly (not
substituted with source/test coverage).**

On the fixtures that ship in this repository, the real release binaries
drive the live TestNet N=3 pipeline end-to-end **up to V1's
wire-validation gate**. V0 publishes exactly one live `0x05` v2 TestNet
candidate; V1 observes it on the wire; but the candidate is **rejected
before staging** because it is signed under a root authority disjoint
from V1's live baseline trust state. The staging queue therefore stays
empty and the explicit drain-once returns **`NoCandidate`** — with **no
live trust mutation**. The exact blocker is documented below and in
`run_156_.../a1_blocker.txt`.

Per `task/RUN_156_TASK.txt` ("If the positive A1 release-binary path is
not feasible: Stop and document the exact blocker. Do not call Run 156
strongest-positive by substituting source/test coverage again."), Run 156
**does not** claim a positive verdict from source/test mapping. It
delivers a complete release-binary driver and the exact blocker.

## Source Delta

**None.** Run 156 adds no production runtime source change. The Run 153
`main.rs` wiring (`drain_once_staging_queue` threading + the post-P2P
drain-once block that constructs `ProductionDrainInvocationBuilder` /
`ProductionV2MarkerCoordinator` and calls `try_drain_once_shared` once) is
reused unchanged. No new CLI flags. No new library code. No schema/wire/
metric change. The only new artifacts are the release-binary harness, this
evidence archive/report, and narrow documentation updates.

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
  (`--p2p-trust-bundle-peer-candidate-wire-publish-enabled` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-path` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-once`).
- **V1** — TestNet receiver, full apply pipeline armed:
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-staging-enabled`,
  `--p2p-trust-bundle-peer-candidate-apply-enabled`,
  `--p2p-trust-bundle-peer-candidate-drain-once`.
- **V2** — observer / propagation-invariant node.

## Required Ordering Proof — what the release binary actually logged

The live cluster reaches and logs each step up to the wire-validation gate
(captured in `run_156_.../logs/A1_v1.stderr.log`):

1. **P2P connection established** — V0/V1/V2 report `P2P transport up`
   (TestNet, `--p2p-mutual-auth=required`, `pqc-static-root`).
2. **Live `0x05` candidate received** — V1:
   `[binary] Run 088: installing live peer-candidate wire dispatcher
   (env=testnet sequence_baseline=1 …)` followed by
   `[binary] Run 078: peer-candidate wire frame observed; outcome=rejected;
   NOT applied; …`.
3. **Apply / drain armed** — V1 logs the Run 147 staging hook ARMED, the
   Run 149 apply policy ARMED, the Run 151 drain trigger ARMED, and the
   Run 152 binary-reachable plumbing PRESENT, all `env=Testnet`.
4. **Explicit drain-once fires once** — V1:
   `[run-153] drain-once delay: waiting 18s …`,
   `[run-153] drain-once: ProductionV2MarkerCoordinator constructed (v2
   ratification verified).`,
   `[run-153] drain-once: invoking try_drain_once_shared (env=Testnet,
   drain_enabled=true, apply_enabled=true).`,
   `[run-153] drain-once outcome: NoCandidate. No autonomous repeat drain;
   …`.

Steps 5–13 of the task's ordering proof (`ProductionDrainInvocationBuilder
built invocation` → Run 150 drain → Run 148 controller → Run 070 ordering
→ sequence commit → v2 marker persist → Applied outcome) are **not
reached** because the staged queue is empty — the candidate was rejected
at step 2's wire-validation gate. This is the blocker, not a pipeline
defect: the drain-once correctly returns `NoCandidate` for an empty queue.

## Required Mutation Proof — none occurred (correctly)

Because nothing applied, the before/after capture proves **non-mutation**:

- V1 Run 055 sequence-persistence log shows only
  `first-load persisted_sequence=1`; there is **no `persisted_sequence=2`
  commit**, i.e. the explicit drain-once performed no apply and no live
  trust mutation.
- No `LivePqcTrustState` swap, no session-eviction counter advance, no
  Applied/drain mutation outcome.

(When the harness is supplied a unified fixture universe and the drain-once
returns `Applied`, it captures the positive mutation proof in
`a1_apply_proof.txt`: the `persisted_sequence=2` commit, and the ordering
assertion that the sequence commit precedes the v2 authority-marker
persist.)

## Exact Blocker

A peer-driven apply requires the published candidate to be a valid
**Run-070 successor** of V1's live baseline `LivePqcTrustState`. That
baseline is initialised from V1's live P2P trust bundle
(`crates/qbind-node/src/main.rs` Run 071:
`LivePqcTrustState::initialize_from_loaded_bundle(--p2p-trust-bundle)`).

- The live P2P transport bundle — and the V0/V1/V2 leaf certs/KEM keys
  that bring up the authenticated handshake — are minted by
  `devnet_pqc_trust_bundle_helper` (`signed-testnet`) under **root
  authority A**.
- The only available TestNet *apply* candidate (Run 154 / `run_133`
  helper `testnet/peer-candidate.valid.json`, `declared_sequence=2`) is
  signed under a **disjoint standalone root authority B**, and the
  `run_133` helper emits **no P2P leaf credentials** for authority B.
- Authority B's candidate is not a successor of authority A's live
  baseline, so V1's live `0x05` wire-validation / ratification gate
  rejects it (`Run 078 … outcome=rejected`) and it never stages.

**No existing fixture tool mints a single unified universe** that
simultaneously provides (a) N=3 P2P leaf certs/KEM keys for live transport
and (b) a self-consistent `baseline(seq1) → candidate(seq2)` apply pair
signed by that same transport root authority, plus the matching v2
ratification sidecar. `devnet_pqc_trust_bundle_helper` provides (a) but not
(b); `run_133_v2_validation_only_fixture_helper` provides (b) but not (a).

This is the **same structural reason** Run 153 (A1 "CITED Run 152/150
source/test") and Run 155 (A1 "CITED Run 154 fixtures + Run 152/150/148
source/test") mapped the positive path to source/test coverage instead of
a live release-binary apply. Run 156 makes that limitation explicit and
reproducible rather than implicit.

## Unblock Path (out of Run 156 strict scope)

The Run 156 harness is a **complete driver**, not a stub. A dedicated
future fixture-tooling run can mint, under one root authority, the N=3 P2P
leaf credentials **and** a signed seq1 baseline + seq2 peer-candidate +
matching v2 ratification. Re-running the harness with the
`QBIND_RUN156_TRANSPORT_DIR` / `QBIND_RUN156_CANDIDATE_ENVELOPE` /
`QBIND_RUN156_SIDECAR` / `QBIND_RUN156_GENESIS` /
`QBIND_RUN156_GENESIS_HASH` overrides then drives the real apply and the
harness asserts the `Applied` ordering automatically. Building that unified
fixture tooling introduces no new lifecycle/governance/KMS/rotation
behaviour and is intentionally **not** attempted here.

## Negative Invariants (held in this run)

- **No autonomous background drain** — a single explicit, delayed
  drain-once.
- **No automatic apply on receipt** — the receive path logs
  `Run 078 … NOT applied`.
- **No peer-majority authority.**
- **MainNet refused unconditionally** — `A6/C2`: `--env mainnet` +
  `--p2p-trust-bundle-peer-candidate-drain-once` exits `1` with
  `Run 151: FATAL` (`exit_codes/A6_mainnet_refused.exit_code`).
- **No live trust sequence mutation** when the candidate did not apply.
- **No fallback to `--p2p-trusted-root`**; **no active
  DummySig/DummyKem/DummyAead** (`dummy_kem_registered=false`,
  `dummy_aead_registered=false`).
- **No SIGHUP / reload-apply / startup-mutation / snapshot-restore apply
  outcome.**
- **No schema/wire/metric drift.** Denylist grep clean
  (`grep_summaries/out_of_scope.txt`).

## Out-of-Scope / Still-Open (unchanged)

- Governance: unimplemented.
- KMS / HSM: unimplemented.
- Signing-key rotation / revocation lifecycle: open.
- Validator-set rotation: open.
- **Full C4 remains open** (not claimed closed by Run 156).
- **C5 remains open.**
- MainNet: refused unconditionally.
- DevNet evidence from Run 153 and TestNet validation evidence from
  Run 155 remain valid and untouched.

## Correction to Run 155

Run 155's verdict line "A1 TestNet end-to-end apply — CITED Run 154
fixtures + Run 152/150/148 source/test" should be read as
**validation-and-refusal release-binary evidence plus source/test mapping
for the positive apply**, not as a live release-binary positive apply.
Run 156 supersedes that mapping with real release-binary live-path
evidence and the exact blocker that prevents the live positive apply with
the current fixtures.

## Reproduction

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_133_v2_validation_only_fixture_helper
bash scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh
```

## Evidence Archive

```
docs/devnet/run_156_testnet_positive_peer_driven_apply_release_binary/
```

## Cross-References

- `task/RUN_156_TASK.txt` — task specification
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_155.md` — TestNet end-to-end (positive A1 mapped to source/test)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_154.md` — TestNet fixture tooling
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_153.md` — DevNet end-to-end evidence
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_152.md` — binary-reachable plumbing
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_150.md` — explicit drain trigger
- `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs` — TestNet fixture helper
- `crates/qbind-node/tests/run_154_testnet_peer_apply_fixture_tests.rs` — TestNet fixture tests
- `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` — safety spec
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — authority model
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — operator playbook
- `docs/whitepaper/contradiction.md` — contradiction tracker