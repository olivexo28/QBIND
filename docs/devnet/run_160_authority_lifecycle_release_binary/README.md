# Run 160 — Release-Binary Evidence / Boundary for Run 159 v2 Signing-Key Lifecycle Validation

## Scope

Run 160 produces the strongest **honest** release-binary evidence
currently possible for the Run 159 v2 bundle-signing-key lifecycle
validator
(`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`).
Per `task/RUN_160_TASK.txt`, Run 160 is required to **first determine**
whether the Run 159 lifecycle validator can be exercised through any
existing release-binary surface and, if not, to capture that fact as a
**partial-positive boundary** without fabricating production-surface
lifecycle evidence.

The Run 160 source-level call graph (captured by the harness in
`call_graph/reachability.txt`) shows that
`validate_v2_lifecycle_transition` and `classify_local_lifecycle_action`
have **zero production callers**. The Run 159 module is referenced only
from:

* its own definition in `crates/qbind-node/src/pqc_authority_lifecycle.rs`;
* the `pub mod pqc_authority_lifecycle;` declaration in
  `crates/qbind-node/src/lib.rs`;
* the Run 159 test suite
  `crates/qbind-node/tests/run_159_authority_signing_key_lifecycle_tests.rs`.

None of the existing release-binary surfaces — startup
`--p2p-trust-bundle` v2 (Run 137), reload-check validation-only (Run
132/133), local peer-candidate-check validation-only (Run 132/133),
process-start reload-apply (Run 134/135), SIGHUP live-reload
(Run 138/139), live inbound `0x05` validation-only (Run 142/143), and
peer-driven staged queue / drain-once (Run 148/150/151/152/153/158) —
calls the Run 159 lifecycle validator. The Run 134 / 136 / 138 / 150 /
152 marker-comparison helpers continue to own the mutating-surface
accept-and-persist composition for the v2 marker; Run 159 explicitly
deferred their rewiring, and Run 160 does not introduce that wiring.

## Verdict

**partial-positive: release-binary fixture/evidence boundary captured;
lifecycle validator not yet production-surface reachable.**

Run 160 does **not** claim strongest-positive. Run 160 does not
fabricate a production lifecycle code-path. Run 160 captures the
release-binary evidence that is honestly available today:

1. A real release-built helper
   (`target/release/examples/run_160_authority_lifecycle_fixture_helper`)
   mints the lifecycle fixture corpus covering A1–A6 (ActivateInitial,
   Rotate, Retire, Revoke, EmergencyRevoke, Idempotent) and R1–R14
   (lower-sequence rollback, same-sequence equivocation,
   wrong-environment / wrong-chain / wrong-genesis / wrong-authority-root,
   wrong-previous-key, revoked-key reuse, retired-key reuse,
   emergency-revoke replay surfaces, malformed revoked metadata, non-PQC
   suite, unsupported lifecycle action, V1-persisted-V2-candidate
   refusal). Every record is built through the existing
   `PersistentAuthorityStateRecordV2::new` /
   `PersistentAuthorityStateRecord::new` primitives and the existing
   structural validators — no new wire format, no new sidecar schema,
   no marker schema change, no sequence-file schema change.

2. The real `target/release/qbind-node` is built and its identity
   recorded (sha256 + ELF Build ID) in `provenance.txt`. The harness
   verifies, by source grep, that this binary's production surfaces do
   not silently claim lifecycle enforcement.

3. The existing Run 159 lifecycle test suite plus the Run 134 / 138 /
   142 / 148 / 150 / 152 / 157 regression suites and `pqc_authority` /
   full library tests are run on the same checkout; per-suite
   stdout/stderr/exit_code are captured in `test_results/`.

4. The harness writes `partial_positive_proof.txt` documenting the
   verdict, the schema-gap analysis (Retire / EmergencyRevoke are
   representable on the existing wire/marker schemas via the Run 159
   metadata sub-class convention; what is missing is the production
   wiring of the validator into the marker-comparison pipeline), and
   the **exact next required integration run**: **Run 161 — compose
   `validate_v2_lifecycle_transition` into the existing Run 134 / 136
   / 138 / 150 / 152 marker-comparison and accept-and-persist
   boundary**.

## Source delta

* `crates/qbind-node/examples/run_160_authority_lifecycle_fixture_helper.rs`
  — new release-built helper (additive, no production-surface caller).
* `scripts/devnet/run_160_authority_lifecycle_release_binary.sh` —
  new harness.
* `docs/devnet/run_160_authority_lifecycle_release_binary/` — new
  evidence archive (this file + `summary.txt` are tracked; everything
  else is `.gitignore`d, mirroring the Run 153 / 155 / 156 / 158
  precedent).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_160.md` — canonical evidence
  report.
* Narrow doc updates to:
  * `docs/whitepaper/contradiction.md`,
  * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

**No production runtime source change.** No `main.rs` / `cli.rs` edit.
No CLI flag added or renamed. No SIGHUP / reload-apply / startup-mutation
/ snapshot-restore / live `0x05` dispatcher / drain-once code path
change. No `LivePqcTrustState` mutation. No sequence-file write. No
authority-marker write. No new wire format. No schema/wire/metric drift.

## Surfaces investigated

Per `task/RUN_160_TASK.txt` §Investigation requirement:

| # | Surface                                                  | Calls validator? | Carries `LocalLifecycleAction`? | Carries Activate/Rotate/Retire/Revoke/Emergency? | Wire/schema change required? | Used for release-binary evidence? |
|---|----------------------------------------------------------|------------------|---------------------------------|--------------------------------------------------|------------------------------|-----------------------------------|
| 1 | startup `--p2p-trust-bundle` v2 (Run 137)                | NO               | NO                              | Activate/Rotate/Revoke only via the existing Run 130 wire byte set | NO new wire byte is required for Retire / EmergencyRevoke (the Run 159 metadata sub-class convention rides on the existing `Revoke=2` byte); production wiring of the validator is missing | NO |
| 2 | reload-check validation-only (Run 132/133)               | NO               | NO                              | same                                              | same                         | NO |
| 3 | local peer-candidate-check validation-only (Run 132/133) | NO               | NO                              | same                                              | same                         | NO |
| 4 | process-start reload-apply (Run 134/135)                 | NO               | NO                              | same                                              | same                         | NO |
| 5 | SIGHUP live-reload (Run 138/139)                         | NO               | NO                              | same                                              | same                         | NO |
| 6 | live inbound `0x05` validation-only (Run 142/143)        | NO               | NO                              | same                                              | same                         | NO |
| 7 | peer-driven staged queue / drain-once (Run 148/150/151/152/153/158) | NO    | NO                              | same                                              | same                         | NO |
| 8 | release-built fixture helper / example (Run 160)         | INDIRECT         | YES (encoded in JSON)           | YES (corpus carries all five logical actions)     | NO                           | YES (corpus minted by real release helper; corpus + Run 159 source/test runs together form the partial-positive boundary) |

## Lifecycle action coverage at the release-binary surface

| Action            | Release-binary fixture | Release-binary surface call? |
|-------------------|------------------------|------------------------------|
| `ActivateInitial` | YES (A1)               | NO                           |
| `Rotate`          | YES (A2)               | NO                           |
| `Retire`          | YES (A3)               | NO                           |
| `Revoke`          | YES (A4)               | NO                           |
| `EmergencyRevoke` | YES (A5)               | NO                           |
| Idempotent        | YES (A6)               | NO                           |

Every accept-matrix entry is matched by a release-built fixture
record in `fixtures/lifecycle_corpus/candidates/`. Every reject-matrix
entry R1–R14 is matched by a release-built fixture record in the same
directory. None of the eight production runtime surfaces calls the
Run 159 validator on those records — the validator is invoked only by
the Run 159 source/test suite running on release-built test binaries
(`cargo test -p qbind-node --test
run_159_authority_signing_key_lifecycle_tests`).

## Schema gap analysis

* The on-wire `BundleSigningRatificationV2Action` byte set
  (`Ratify=0`, `Rotate=1`, `Revoke=2`) is **preserved unchanged** by
  Run 159 and Run 160. Retire and EmergencyRevoke ride the existing
  `Revoke=2` byte plus a Run 159 local sub-class prefix in
  `revoked_key_metadata` (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke).
* Run 160 introduces **no** wire byte additions, **no** trust-bundle
  schema change, **no** authority-marker schema change, **no**
  sequence-file schema change, and **no** peer-candidate envelope
  schema change.
* Retire / EmergencyRevoke release-binary evidence is therefore
  **representable** on the existing schemas via the metadata
  convention; what is missing is the production wiring of
  `validate_v2_lifecycle_transition` into the Run 134/136/138/150/152
  marker-comparison and accept-and-persist pipeline. That wiring is
  the precise scope of **Run 161**.

## Harness

`scripts/devnet/run_160_authority_lifecycle_release_binary.sh`

The harness:

1. Builds the real release `target/release/qbind-node`,
   `target/release/examples/run_160_authority_lifecycle_fixture_helper`,
   and (if missing) the Run 157 unified TestNet helper.
2. Captures provenance (git commit, rustc/cargo versions, binary +
   helper SHA-256 and ELF Build IDs) into `provenance.txt`.
3. Mints the lifecycle fixture corpus with the real release-built
   helper into `fixtures/lifecycle_corpus/` and writes per-file
   SHA-256s to `fixture_manifest.txt`.
4. Captures the source-level call graph of
   `validate_v2_lifecycle_transition` /
   `classify_local_lifecycle_action` /
   `pqc_authority_lifecycle` into `call_graph/{src_grep.txt,
   tests_grep.txt, main_rs_grep.txt, reachability.txt}`. The
   reachability summary names Run 161 as the exact next required
   integration run.
5. Runs the Run 159 lifecycle test suite plus the Run 134 / 138 /
   142 / 148 / 150 / 152 / 157 regression suites and the `lib
   pqc_authority` / full lib targets, capturing per-suite
   stdout/stderr/exit_code into `test_results/`.
6. Writes `grep_summaries/in_scope.txt` (expected-present markers)
   and `grep_summaries/out_of_scope.txt` (denylist; expected empty).
7. Writes `partial_positive_proof.txt` (verdict + schema gap analysis
   + exact next required integration run) and `summary.txt`.

## Required denylist (the harness's `out_of_scope.txt` must be empty)

* no autonomous drain;
* no apply on receipt;
* no peer-majority authority;
* no governance enforced;
* no KMS / HSM enforced;
* no validator-set rotated;
* no MainNet apply;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead`;
* no schema/wire/metric drift;
* no claim of production lifecycle enforcement.

The expected MainNet-refusal banner — which names `governance` /
`KMS` / `HSM` only to say they are NOT implemented — is excluded from
the denylist match (same precedent as Run 153 / 155 / 156 / 158).

## Invariants held in this run

* MainNet remains refused (no harness scenario enables MainNet
  drain-once or MainNet apply).
* No autonomous background drain.
* No automatic apply on receipt.
* No peer-majority authority.
* No fallback to `--p2p-trusted-root`.
* No active `DummySig` / `DummyKem` / `DummyAead`.
* No `SIGHUP` / `reload-apply` / startup-mutation / snapshot-restore
  apply outcome (Run 160 does not exercise mutating surfaces; the
  validator is pure).
* No marker write before sequence commit (no mutating surface is
  exercised at all).
* No sequence write on validation-only surfaces.
* No marker write on validation-only surfaces.
* DevNet evidence from Run 153 and TestNet evidence from Runs 154 /
  155 / 156 / 157 / 158 remain valid and untouched.

## Out-of-scope deferrals (unchanged)

* Governance / KMS / HSM: unimplemented.
* Validator-set rotation: open.
* Full **C4**: open. **C5**: open.
* MainNet: refused unconditionally.

## Tracked vs generated artifacts

Only `README.md` and `summary.txt` are tracked (mirroring Run 153 /
Run 155 / Run 156 / Run 158). All per-run artifacts (`logs/`,
`test_results/`, `exit_codes/`, `grep_summaries/`, `fixtures/`,
`call_graph/`, `provenance.txt`, `fixture_manifest.txt`,
`partial_positive_proof.txt`) are reproduced by the harness and are
`.gitignore`d (they contain absolute paths, ephemeral helper output,
and timestamps).

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_160.md` for the canonical
evidence report.