# Run 143 — release-binary evidence archive

This directory is the persistent archive for the
**live inbound `0x05` v2 validation-only release-binary** evidence
produced by:

```
scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh
```

The harness mirrors the Run 110 N=3 DevNet cluster pattern and the
Run 141 archive layout. When run on a build-capable environment it
emits the following layout under this directory:

* `summary.txt` — top-level provenance and per-scenario verdict.
  Includes:
  * `git_commit`, `rustc --version`, `cargo --version`;
  * release `qbind-node` and helper binary `sha256` + ELF `BuildID`
    for `qbind-node`, `devnet_pqc_root_helper`,
    `devnet_pqc_trust_bundle_helper`,
    `devnet_consensus_signer_keystore_helper`, and
    `run_133_v2_validation_only_fixture_helper`;
  * pass/fail status for every A1–A4, R1–R11 scenario.
* `logs/` — per-scenario, per-node `stdout` and `stderr` from every
  release `qbind-node` process started by the harness.
* `metrics/` — per-scenario, per-node Prometheus scrapes captured at
  the moment each invariant was asserted.
* `sequence/` — pre/post `sha256` of every node's
  `pqc_trust_bundle_sequence.json`, proving the file is byte-identical
  across the scenario (the Run 088 / Run 142 non-mutation contract).
* `marker_hashes/` — pre/post `sha256` of every node's
  `pqc_authority_state.json` when the scenario seeded one, proving the
  validation-only path does not rewrite, repair, or delete the marker
  on accept or reject.
* `grep_summaries/in_scope.txt` — the collated Run 109 / Run 123 /
  Run 130 / Run 132 / Run 142 in-scope marker lines from every node's
  stderr corpus.
* `grep_summaries/out_of_scope.txt` — explicit empty file (the harness
  fails closed if it is ever non-empty). Asserts the **denylist** of
  forbidden outcomes: live trust apply, sequence write, marker write,
  session eviction, SIGHUP, reload-apply, snapshot/restore audit
  marker, KMS / HSM, signing-key rotation/revocation lifecycle,
  MainNet governance, fallback to `--p2p-trusted-root`, and any active
  `DummySig` / `DummyKem` / `DummyAead`.
* `exit_codes/` — per-scenario exit code for any single-node refusal
  scenario (in particular `R7_ambiguous_v1_v2_fail_closed_v1.exit_code`,
  which asserts the versioned sidecar loader refuses ambiguous
  documents at preflight before the transport comes up).
* `inventories/` — per-scenario, per-node `find` inventory of the
  scenario `--data-dir`, proving that no `pqc_authority_state.json.tmp`
  sibling and no `RESTORED_FROM_SNAPSHOT.json` audit marker were ever
  created on the live inbound `0x05` path.

The harness reuses the **existing**
`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
fixture helper verbatim — no new helper is introduced. The helper's
provenance is the same one Run 133 already pinned (same `sha256`,
same `BuildID`). Run 143 makes **no production runtime source
changes** and **no fixture-helper source changes**.

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md` for the canonical
verdict, the full scenario matrix, and the explicit deferral list
(peer-driven live apply, signing-key rotation/revocation lifecycle,
KMS/HSM, MainNet governance, full C4 closure, C5 closure).
