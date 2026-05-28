# Run 147 — release-binary evidence archive

This directory is the persistent archive for the **live inbound
`0x05` peer-candidate staging hook release-binary** evidence
produced by:

```
scripts/devnet/run_147_live_0x05_peer_candidate_staging_release_binary.sh
```

## Verdict scope (mandatory disclosure per `task/RUN_147_TASK.txt`)

Run 147 is **NOT pure evidence-only.** The feasibility gate
("Can a real `target/release/qbind-node` binary arm
`LivePeerCandidateWireDispatcher::staging_queue` through an
existing runtime config path?") returned **NO** against the
Run 146 state. Under the task's explicit "preferred path if a
flag is necessary" allowance, Run 147 added the smallest hidden,
disabled-by-default DevNet/TestNet-only arming flag:

```
--p2p-trust-bundle-peer-candidate-staging-enabled
```

and the matching `main.rs` install branch that constructs a
bounded, non-applying `PeerCandidateStagingQueue` (the Run 145
`PeerDrivenStagingPolicy::{devnet,testnet}_enabled` policy with
conservative caps and TTL) and installs it on the live `0x05`
dispatcher. Run 147 is therefore classified as **"source/test +
release-binary evidence for hidden opt-in staging arming."** The
exact source delta and rationale are recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md`.

## Archive layout

The Run 147 harness mirrors the Run 143 N=3 DevNet cluster pattern
and archive layout, with the Run 147-specific cluster delta limited
to V1's extra-args list (V1 receives
`--p2p-trust-bundle-peer-candidate-staging-enabled`). When the
harness runs on a build-capable environment it emits the following
layout under this directory:

* `summary.txt` — top-level provenance and per-scenario verdict.
  Includes:
  * `git_commit`, `rustc --version`, `cargo --version`;
  * release `qbind-node` and helper binary `sha256` + ELF `BuildID`
    for `qbind-node`, `devnet_pqc_root_helper`,
    `devnet_pqc_trust_bundle_helper`,
    `devnet_consensus_signer_keystore_helper`, and
    `run_133_v2_validation_only_fixture_helper`;
  * the **feasibility-gate result** explicitly recorded as `NO`
    against the Run 146 state, with the Run 147 source delta
    disclosed;
  * pass/fail status for every C1, C2/R2, C3, A1–A4, R1, R3–R13
    scenario;
  * the **out-of-scope deferral list** restated verbatim from the
    Run 143 / Run 146 archives (peer-driven live apply, signing-key
    rotation/revocation lifecycle, KMS/HSM, MainNet governance,
    full C4 closure, C5 closure — all remain OPEN).
* `logs/` — per-scenario, per-node `stdout` and `stderr` from every
  release `qbind-node` process started by the harness. The Run 147
  positive log markers asserted by the harness are:
  * `[binary] Run 147: peer-candidate staging hook arming flag accepted` —
    emitted exactly once on V1 when the flag is supplied with
    valid co-requisites on DevNet/TestNet;
  * `[run-147] live peer-candidate staging hook ARMED` — emitted
    exactly once on V1 by the dispatcher constructor when the
    queue is actually installed;
  * `[binary] Run 146: ...STAGED / already staged / refused ...` —
    the Run 146 hook log line, asserting staging acted on a
    validated candidate (positive A-row scenarios) or refused
    without mutation (R-row scenarios).
* `metrics/` — per-scenario, per-node Prometheus scrapes captured
  at the moment each invariant was asserted. Run 147 introduces
  **no new metric family**; the harness re-uses the existing
  `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters.
* `sequence/` — pre/post `sha256` of every node's
  `pqc_trust_bundle_sequence.json`, proving the file is
  byte-identical across every scenario (the Run 088 / Run 142 /
  Run 146 non-mutation contract — staging never writes the
  sequence file).
* `marker_hashes/` — pre/post `sha256` of every node's
  `pqc_authority_state.json` when the scenario seeded one,
  proving the staging hook never rewrites, repairs, or deletes
  the authority marker on accept or reject.
* `grep_summaries/in_scope.txt` — the collated Run 109 / Run 123 /
  Run 130 / Run 132 / Run 142 / Run 146 / Run 147 in-scope marker
  lines from every node's stderr corpus.
* `grep_summaries/out_of_scope.txt` — explicit empty file (the
  harness fails closed if it is ever non-empty). Asserts the
  **denylist** of forbidden outcomes: Run 070 apply invocation,
  live trust apply, sequence write, marker write, session
  eviction, SIGHUP, reload-apply, snapshot/restore audit marker,
  KMS / HSM, signing-key rotation/revocation lifecycle, MainNet
  governance, fallback to `--p2p-trusted-root`, and any active
  `DummySig` / `DummyKem` / `DummyAead`.
* `exit_codes/` — per-scenario exit code for any single-node
  refusal scenario. In particular:
  * `C1_staging_enabled_without_wire_validation_enabled.exit_code`
    — asserts the Run 147 top-level gate refuses arming without
    the upstream live `0x05` validation flag (exit code 1);
  * `C2_R2_mainnet_refused.exit_code` — asserts the Run 147
    top-level gate refuses MainNet unconditionally (exit code 1).
* `inventories/` — per-scenario, per-node `find` inventory of the
  scenario `--data-dir`, proving that no
  `pqc_authority_state.json.tmp` sibling and no
  `RESTORED_FROM_SNAPSHOT.json` audit marker were ever created
  on the live inbound `0x05` path.

The harness reuses the **existing** Run 143 fixture pipeline
(`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
plus the cluster scaffolding in
`scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh`)
verbatim. The helpers' provenance is the same one Run 133 / Run 143
already pinned (same `sha256`, same `BuildID`). Run 147 introduces
**no new fixture helper, no new metric family, no new wire-format
change, no schema change, no propagation-protocol change.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_147.md` for the
canonical verdict, the full scenario matrix, and the explicit
deferral list (peer-driven live apply, signing-key rotation /
revocation lifecycle, KMS/HSM, MainNet governance, full C4
closure, C5 closure).