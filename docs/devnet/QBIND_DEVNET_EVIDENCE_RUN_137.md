# Run 137 — Release-binary evidence for the v2 startup `--p2p-trust-bundle` mutating surface (Run 136 wiring)

**Date:** 2026-05-25
**Verdict:** STRONGEST-POSITIVE (evidence-only; no production runtime source changed)
**Scope axis:** C4 — release-binary evidence for the Run 136 v2 mutating-surface wiring on the startup `--p2p-trust-bundle` path.

## 1. Statement and Boundaries

Run 137 is **release-binary evidence only**. It captures end-to-end
proof, on the real `target/release/qbind-node` binary, that the Run 136
v2 ratification wiring on the startup `--p2p-trust-bundle` mutating
surface behaves on a real Linux process exactly as the Run 134 / Run 135
wiring does on the process-start reload-apply surface:

- v2 sidecars are dispatched into the Run 130 v2 verifier instead of the
  v1-only `apply_run_105_ratification_gate_at_startup` gate;
- accepted v2 candidates persist a `PersistentAuthorityStateRecordV2`
  marker with `last_update_source = "startup-load"` strictly **after**
  the Run 055 `check_and_update_sequence` commit boundary;
- rejected v2 candidates fail closed **before** any sequence write,
  bundle-root merge, marker write, OR P2P listener bind;
- v1 ratifications fall through the unmodified Run 105/106 + Run 120
  startup gate;
- the per-startup mutual-exclusion invariant
  (`startup_marker_decision` vs `startup_marker_decision_v2`) is
  observed end-to-end.

Run 137 does **not**:

- change any production runtime source (`crates/**/src/**`);
- add or change any CLI flag, log line, metric name, trust-bundle
  format, ratification sidecar format, peer-candidate envelope, or P2P
  wire frame;
- wire v2 into any new mutating surface (SIGHUP live reload, snapshot/
  restore, peer-driven live apply all remain v1-only);
- implement signing-key rotation or revocation lifecycle plumbing,
  KMS/HSM custody, MainNet governance artifact verification, or
  validator-set rotation;
- claim full C4 or C5 closure.

The release `qbind-node` binary used is the unmodified output of
`cargo build --release -p qbind-node --bin qbind-node` at the
repository's current `HEAD`. The fixtures are minted by the existing
Run 133 release example
(`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`)
exactly as Run 135 reused them — no new helper crate, no new
production code, no production runtime patch.

## 2. Harness

```
scripts/devnet/run_137_v2_startup_trust_bundle_release_binary.sh
```

What it does:

1. Builds `target/release/qbind-node` (`cargo build --release -p
   qbind-node --bin qbind-node`).
2. Builds the Run 133 v2-fixture release example
   (`cargo build --release -p qbind-node --example
   run_133_v2_validation_only_fixture_helper`).
3. Records the binary SHA-256 and ELF Build ID, plus repository git
   commit and toolchain version, in `summary.txt`.
4. Mints ephemeral DevNet fixtures via the Run 133 helper.
5. For each scenario, runs the release binary with the **mutating**
   startup `--p2p-trust-bundle` block (`--network-mode p2p
   --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`) and the v2 or v1
   sidecar; captures stderr, stdout, exit code, marker SHA-256
   pre/post, and sequence-file SHA-256 post.
6. Bounds each accepted scenario with
   `timeout --signal=TERM --kill-after=5s` — long enough for the
   v2 marker persist line to appear, then the kernel SIGTERMs the
   still-running node. Rejected scenarios exit `rc=1` quickly and the
   timeout is purely a defensive upper bound.
7. Asserts every scenario's expected log lines, exit-code class,
   on-disk marker shape, byte-equality invariants, and the cross-
   scenario non-mutation / non-fall-back invariants.

The harness is purely an evidence harness: it does **not** depend on
any production change, and it does **not** invoke any non-existent
flag.

## 3. Scenarios (11 total)

### Acceptance (4)

| ID | Setup | Sidecar | Expected | Marker assertions |
|----|-------|---------|----------|--------|
| **A1** | no marker | `ratification.v2.ratify.seq1.json` | v2 first-write succeeds | `record_version=2`, `latest_authority_domain_sequence=1`, `latest_lifecycle_action=ratify`, `last_update_source=startup-load`; sequence file present |
| **A2** | v1 seed marker (`seed-marker.v1.json`) | `ratification.v2.ratify.seq2.json` | v2-after-v1 startup migration succeeds; seeded v1 record replaced | `record_version=2`, `latest_authority_domain_sequence=2`, `last_update_source=startup-load`; `cmp -s` proves bytes ≠ v1 seed |
| **A3** | v2 seed marker (`seed-marker.v2.seq1.json`) | `ratification.v2.same.seq1.json` (same digest) | idempotent — `[run-136] v2 authority-marker unchanged ... (idempotent; no rewrite)` | `cmp -s` proves marker bytes byte-identical before/after |
| **A4** | v2 seed marker (`seed-marker.v2.seq1.json`) | `ratification.v2.ratify.seq2.json` | higher-sequence v2 upgrade succeeds | `record_version=2`, `latest_authority_domain_sequence=2`, `last_update_source=startup-load`; `cmp -s` proves bytes ≠ seq=1 seed |

### Rejection (6) — every rejection must occur BEFORE any mutation AND BEFORE P2P listener bind

| ID | Setup | Sidecar | Verifier / preflight verdict | Refusal proofs |
|----|-------|---------|------------------------------|----|
| **R1** | v2 seed marker @ seq=2 | `ratification.v2.lower.seq1.json` | `MutatingSurfaceMarkerV2Error::LowerV2SequenceRefused { persisted=2, attempted=1 }` | rc=1; no sequence file; no `.tmp`; marker bytes == seeded seq=2 |
| **R2** | v2 seed marker @ seq=1 (active target) | `ratification.v2.equivocation.seq1.json` (rotated target, same seq) | `SameSequenceConflicting…` (digest or key/action equivocation) | rc=1; no sequence file; no `.tmp`; marker bytes == seeded seq=1 |
| **R3a** | no marker | `ratification.v2.bad-signature.json` | Run 130 v2 verifier failure: `signature failed ML-DSA-44 PQC verification`, wrapped into `Conflict(MalformedOrUnsupportedMarkerRejected)` | rc=1; no marker created; no sequence file |
| **R3b** | no marker | `ratification.v2.wrong-environment.json` | Run 130 v2 verifier failure: `WrongEnvironment`, wrapped into `Conflict(MalformedOrUnsupportedMarkerRejected)` | rc=1; no marker created; no sequence file |
| **R4**  | no marker | `ratification.v2.wrong-chain.json` | Run 130 v2 verifier failure: `ChainMismatch`, wrapped into `Conflict(MalformedOrUnsupportedMarkerRejected)` | rc=1; no marker created; no sequence file |
| **R5**  | no marker | `ratification.v2.wrong-genesis.json` | Run 130 v2 verifier failure: `GenesisHashMismatch`, wrapped into `Conflict(MalformedOrUnsupportedMarkerRejected)` | rc=1; no marker created; no sequence file |

The three wrong-domain refusals (R3b / R4 / R5) exercise the three
binding axes of the v2 verifier (environment, chain_id, genesis hash)
that together pin a v2 sidecar to a single
`(env, chain_id, genesis_hash, authority_root_fingerprint)` trust
domain. Together with R3a (signature) they cover the four cryptographic
binding axes the Run 130 verifier rejects.

### v1 regression (1)

| ID | Setup | Sidecar | Expected | Marker assertions |
|----|-------|---------|----------|---------|
| **V1** | no marker | `ratification.v1.valid.json` | Run 105/Run 106 startup gate INVOKED, Run 120 v1 marker persist | `record_version=1`; no `[run-136]` log line in stderr |

### R4-analogue (apply-failure-after-preflight) is documented not-feasible on the release binary

Identical treatment to Run 135 §R4 and Run 134 §C.3. A release binary
cannot deterministically trigger a post-preflight, pre-
`check_and_update_sequence` apply failure on the startup surface
using operator-supplied flag inputs alone — the live trust-state
apply step inside the binary has no fault-injection knob exposed via
CLI, and synthesising a failure between the v2 preflight and the
Run 055 commit would require modifying production source (out of
scope for an evidence run). The Run 118 §D crash-window discipline
that governs this case is unit-tested by the Run 136 in-module
`run136_v2_startup_tests::dropped_decision_never_persists` test
(§A.8) and remains the canonical proof for that corner case.

## 4. Key log-line proofs (per accepted v2 scenario)

For A1/A2/A4 the harness asserts the following lines appear in stderr in
this order, and that the `Run 055` line strictly precedes the
`[run-136] v2 authority-marker persisted` line:

```
[run-106] startup ratification gate INVOKED (policy=devnet-operator-opt-in, env=Devnet).
[run-136] startup --p2p-trust-bundle v2 ratification path SELECTED ...
[binary] Run 055: trust-bundle sequence persistence ... first-load persisted_sequence=<N> ...
[run-136] v2 authority-marker persisted at <data_dir>/pqc_authority_state.json (v2-first-write|v2-upgrade ...; candidate latest_authority_domain_sequence=<seq>).
[binary] P2P transport up. Listen address: 127.0.0.1:<port>, static peers: 0
```

For A3 (idempotent) the line is instead:

```
[run-136] v2 authority-marker unchanged at <data_dir>/pqc_authority_state.json (idempotent; no rewrite).
```

For V1 (regression) the lines are:

```
[run-106] startup ratification gate INVOKED (policy=devnet-operator-opt-in, env=Devnet).
... (Run 105 v1 enforcer succeeds; NO [run-136] line is emitted) ...
[binary] Run 055: trust-bundle sequence persistence ...
[run-120] authority-marker persisted at <data_dir>/pqc_authority_state.json (...; candidate authority_sequence=<seq>).
```

For every rejected scenario the line is:

```
[run-136] FATAL: startup --p2p-trust-bundle refused by v2 authority-marker preflight: <typed reason>. Path=<bundle path>. No Run 055 sequence write, no bundle-root merge, no live trust mutation, no P2P startup, no marker write. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_136.md, docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md §"Authority anti-rollback marker ...".
```

The full per-scenario logs are archived under
`docs/devnet/run_137_v2_startup_trust_bundle_release_binary/logs/`.

## 5. Invariants asserted across all scenarios

- **No SIGHUP v2 wiring** — no
  `SIGHUP-driven live trust-bundle reload-apply trigger is ACTIVE`
  line in any scenario stderr;
- **No live inbound `0x05` v2 wiring** — no `live inbound 0x05` line in
  any scenario stderr;
- **No peer-driven live apply v2** — no `peer-driven live apply` line
  in any scenario stderr;
- **No snapshot/restore v2 wiring** — no `snapshot/restore v2` /
  `snapshot-restore v2` line in any scenario stderr;
- **No KMS/HSM custody** — no `KMS` or `HSM` line in any scenario
  stderr;
- **No signing-key rotation/revocation lifecycle log line** — no
  `signing-key (rotation|revocation) lifecycle` line in any scenario
  stderr;
- **No trusted-root fall-back** — no
  `falling back to --p2p-trusted-root` or `trusted-root fallback` line
  in any scenario stderr;
- **Run 132 validation-only v2 paths do not fire on a mutating-surface
  run** — no `[run-132] reload-check v2 authority-marker check` or
  `[run-132] peer-candidate-check v2 authority-marker check` in any
  scenario stderr;
- **Run 134 reload-apply v2 path does not fire on a pure startup-
  surface run** — no
  `[run-134] reload-apply v2 ratification path SELECTED` in any
  scenario stderr.

## 6. Repository regression after this run

Run 137 changes are confined to:

- `scripts/devnet/run_137_v2_startup_trust_bundle_release_binary.sh`
  (new)
- `docs/devnet/run_137_v2_startup_trust_bundle_release_binary/` (new
  archive)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_137.md` (this file)
- short Run 137 narrowing prose updates in
  `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, and
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

No `crates/**/src/**` file is touched. Therefore:

- `qbind-ledger --lib` test count and behaviour is identical to Run 136
  (260 passed unchanged).
- `qbind-node --lib` test count and behaviour is identical to Run 136
  (1254 passed unchanged, including the 8 in-module
  `run136_v2_startup_tests` cases).
- `qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  remains 5 passed.
- `qbind-node --test run_119_authority_marker_acceptance_tests` remains
  4 passed.
- `qbind-node --test run_112_reload_apply_ratification_tests` remains
  10 passed.

These regressions are the same suites that gate Run 134 / Run 135 /
Run 136. They are unaffected by Run 137 because Run 137 does not
modify production runtime code.

## 7. C4 status after Run 137

**OPEN but further narrowed for the startup `--p2p-trust-bundle`
mutating surface — now release-binary-evidenced.**

After Run 137:

- Run 130 (v2 schema / verifier / tests) — present
- Run 131 (v2 marker primitives) — present
- Run 132 (v2 validation-only wiring on `reload-check` +
  `peer-candidate-check`) — present
- Run 133 (release-binary v2 validation-only evidence) — present
- Run 134 (v2 reload-apply mutating-surface wiring) — present
- Run 135 (release-binary v2 reload-apply mutating-surface evidence)
  — present
- Run 136 (v2 startup `--p2p-trust-bundle` mutating-surface wiring)
  — present
- **Run 137 (release-binary v2 startup `--p2p-trust-bundle` mutating-
  surface evidence) — present**

Remaining open pieces (unchanged by Run 137):

- v2 wiring for the remaining mutating surfaces (SIGHUP live reload,
  snapshot/restore);
- live inbound `0x05` v2 wiring;
- signing-key rotation/revocation lifecycle plumbing beyond the
  Run 130/131 primitives already enforced;
- peer-driven live apply (v1 and v2);
- KMS/HSM custody;
- MainNet governance artifact verification;
- validator-set rotation;
- full C4 closure;
- C5 closure.

Static production source-code anchors remain rejected. Local config
alone remains insufficient for MainNet bundle-signing authority. No
Run 050–136 invariant was changed.
