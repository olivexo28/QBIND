# Run 149 — release-binary evidence archive

This directory is the persistent archive for the **DevNet/TestNet
peer-driven trust-bundle apply** release-binary evidence produced
by:

```
scripts/devnet/run_149_peer_driven_apply_release_binary.sh
```

## Verdict scope (mandatory disclosure per `task/RUN_149_TASK.txt`)

Run 149 is **NOT pure evidence-only.** The feasibility gate
("Can the real `target/release/qbind-node` arm and invoke the
Run 148 peer-driven apply controller through an existing runtime
path?") returned **NO** against the Run 148 state — the Run 148
`qbind_node::pqc_peer_candidate_apply::try_apply_staged_peer_candidate`
controller was library-only with **no operator-visible surface in
`main.rs`**. Under the task's explicit "preferred path if a flag
is necessary" allowance, Run 149 added the smallest hidden,
disabled-by-default DevNet/TestNet-only arming flag:

```
--p2p-trust-bundle-peer-candidate-apply-enabled
```

and the matching `main.rs` co-requisites gate (MainNet refused
unconditionally; requires
`--p2p-trust-bundle-peer-candidate-wire-validation-enabled`;
requires `--p2p-trust-bundle-peer-candidate-staging-enabled`;
does NOT imply propagation; does NOT introduce a new apply
algorithm; does NOT bypass staging/validation/marker/Run 055/
activation gates) plus the controller-layer
`PeerDrivenApplyPolicy` arming banner at the dispatcher-install
site. Run 149 is therefore classified as **"minimal source wiring
+ release-binary evidence — partial-positive."** The exact source
delta and rationale are recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`.

## Partial-positive disclosure (mandatory)

Run 149 does **NOT** introduce a queue-to-controller drain task
in the node binary. Wiring such a drain would be a new
apply-triggering algorithm, which is **explicitly out of scope**
per `task/RUN_149_TASK.txt` §20 ("must not create a new apply
algorithm"). End-to-end release-binary apply of an already-staged
validated peer candidate through the Run 070 contract (matrix
rows A1–A4) therefore remains under **Run 148 source/test
coverage**
(`crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`
A1–A4 + R1–R16, 20/20 green). Run 149 captures release-binary
evidence for:

* the new arming-surface **refusal scenarios** (C1 missing
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`;
  C2 / R2 MainNet refused unconditionally; C3 missing
  `--p2p-trust-bundle-peer-candidate-staging-enabled`);
* the new arming-surface **acceptance log evidence** (C5 DevNet
  with co-requisites; C6 TestNet with co-requisites) via the
  optional N=3 cluster harness described below;
* the **Run 147 release-binary non-mutation invariants** under
  the new flag (denylist grep + pre/post sequence/marker SHAs
  remain identical, asserting that the Run 149 source delta
  introduces no mutation surface and no apply call site beyond
  the arming banner).

## Archive layout

When the harness runs on a build-capable environment it emits the
following layout under this directory:

* `summary.txt` — top-level provenance and per-scenario verdict.
  Includes:
  * `git_commit`, `rustc --version`, `cargo --version`;
  * release `qbind-node` `sha256` + ELF `BuildID`;
  * the **feasibility-gate result** explicitly recorded as `NO`
    against the Run 148 state, with the Run 149 source delta
    disclosed (the new hidden flag, the early MainNet refusal,
    the co-requisites gate, the
    `[binary] Run 149: peer-candidate apply arming flag accepted`
    acceptance line, the
    `[run-149] live peer-driven apply policy ARMED` banner);
  * pass/fail status for every C1–C6, R1–R12, D1 scenario, with
    A1–A4 / R3–R10 cited honestly as Run 148 source/test
    coverage;
  * the **out-of-scope deferral list** restated verbatim from
    the Run 147 / Run 148 archives (governance / ratification /
    KMS / HSM custody / signing-key rotation / revocation
    lifecycle / validator-set rotation / full C4 closure / C5
    closure — all remain OPEN).
* `logs/` — per-scenario, per-node `stdout` and `stderr` from
  every release `qbind-node` process started by the harness.
  The Run 149 positive log markers asserted by the harness are:
  * `[binary] Run 149: FATAL ...` — emitted on V1 (or on the
    single-node refusal scenarios) when the gate fires
    fail-closed;
  * `[binary] Run 149: peer-candidate apply arming flag accepted` —
    emitted exactly once on V1 when the flag is supplied with
    valid co-requisites on DevNet/TestNet;
  * `[run-149] live peer-driven apply policy ARMED` — emitted
    exactly once on V1 by the controller-layer arming banner;
  * `[binary] Run 147: peer-candidate staging hook arming flag
    accepted` and `[run-147] live peer-candidate staging hook
    ARMED` — the Run 147 banners continue to fire under the
    Run 149 flag (the Run 149 source delta does not relax any
    Run 147 invariant);
  * `[binary] Run 146: ...STAGED / already staged / refused ...`
    — the Run 146 hook log line, asserting that staging acted on
    a validated candidate or refused without mutation.
* `exit_codes/` — per-scenario exit code for every single-node
  refusal scenario:
  * `C1_apply_enabled_without_wire_validation_enabled.exit_code`
    — asserts the Run 149 top-level gate refuses arming without
    the upstream live `0x05` validation flag (exit code 1);
  * `C2_R2_mainnet_refused.exit_code` — asserts the Run 149
    early MainNet refusal fires unconditionally (exit code 1);
  * `C3_apply_enabled_without_staging_enabled.exit_code` —
    asserts the Run 149 top-level gate refuses arming without
    the upstream staging flag (exit code 1).
* `grep_summaries/in_scope.txt` — collected `Run 149: FATAL`
  lines from every captured stderr.
* `grep_summaries/out_of_scope.txt` — explicit empty file (the
  harness fails closed if it is ever non-empty). Asserts the
  **denylist** of forbidden outcomes: Run 070 apply invocation,
  live trust apply, sequence write, marker write, session
  eviction, SIGHUP, reload-apply, snapshot/restore audit marker,
  KMS / HSM, signing-key rotation/revocation lifecycle, MainNet
  governance, fallback to `--p2p-trusted-root`, and any active
  `DummySig` / `DummyKem` / `DummyAead`.

## N=3 DevNet cluster topology (optional path)

When run with the optional cluster fixtures the harness mirrors
the Run 143 / Run 147 N=3 DevNet topology bit-for-bit:

* **V0** — publisher (real release `qbind-node`).
* **V1** — receiver / would-be apply node (real release
  `qbind-node`, the Run 147 staging hook armed PLUS the Run 149
  apply arming flag armed). The controller-layer
  `[run-149] live peer-driven apply policy ARMED` banner is
  asserted on V1.
* **V2** — observer (real release `qbind-node`).

The cluster-level delta vs. Run 147 is limited to V1's extra-args
list (V1 receives `--p2p-trust-bundle-peer-candidate-apply-enabled`
in addition to the Run 147 extra args). The Run 143 fixture
helpers (`devnet_pqc_root_helper`, `devnet_pqc_trust_bundle_helper`,
`devnet_consensus_signer_keystore_helper`,
`run_133_v2_validation_only_fixture_helper`) are reused verbatim
with the same `sha256` / `BuildID` provenance — Run 149 introduces
**no new fixture helper, no new metric family, no new wire-format
change, no schema change, no propagation-protocol change**.

The cluster harness confirms that under the Run 149 flag:

* the Run 147 staging banners continue to fire;
* the Run 149 acceptance banner fires exactly once on V1;
* per-node `pqc_trust_bundle_sequence.json` and
  `pqc_authority_state.json` remain byte-identical pre/post
  (no mutation, because the controller is armed but no drain
  caller is wired);
* the Run 147 denylist plus the Run 149 governance / KMS / HSM
  / signing-key rotation/revocation additions see zero matches.

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md` for the
canonical verdict, the full scenario matrix, the source delta,
and the explicit deferral list (governance / KMS / HSM /
signing-key rotation / revocation lifecycle / validator-set
rotation / full C4 closure / C5 closure — all OPEN).
