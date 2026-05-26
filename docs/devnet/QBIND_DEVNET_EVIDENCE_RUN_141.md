# QBIND DevNet Evidence — Run 141

**Subject**: Release-binary evidence that snapshot/restore parity for v2
authority anti-rollback markers (wired in source/test in Run 140) actually
behaves as designed when exercised against the real release-mode
`qbind-node` binary via `--restore-from-snapshot`, using the existing
versioned authority marker primitives (Run 130/131/134) and the existing
snapshot-restore authority-check surface (Run 117/124/140).

## Scope notice (mandatory per `task/RUN_141_TASK.txt`)

* **Run 141 is release-binary evidence only.**
* **No production runtime source code is modified in Run 141.** The only
  new files are an ephemeral, opt-in `cargo --example` fixture helper
  (`crates/qbind-node/examples/run_141_v2_snapshot_restore_fixture_helper.rs`),
  a release-binary harness shell script
  (`scripts/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary.sh`),
  this evidence MD, the captured artifacts under
  `docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/`,
  and narrow append-only references in `docs/whitepaper/contradiction.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, and
  `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
* **No CLI flag is added, removed, or renamed.** The harness uses only
  pre-existing flags (`--env`, `--data-dir`, `--genesis-path`,
  `--expect-genesis-hash`, `--restore-from-snapshot`).
* **No wire format / on-disk format / metric is changed.**
* **No new test-only / `cfg(test)` snapshot or marker fabrication surface
  is exposed in production code.** All fixtures are minted exclusively
  by the new `cargo --example` binary, which is not part of the
  `qbind-node` release binary itself.
* **Snapshot/restore v2 authority-marker parity is release-binary
  evidenced** by the 11 captured scenarios under
  `docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/logs/`
  (A1–A4 accepts, R1–R9 rejects, R10–R11 v1/legacy regressions) and the
  4 + 2 source-test suites that remain green
  (`run_140_snapshot_restore_v2_authority_marker_tests` 13/13,
  `run_124_snapshot_restore_authority_marker_tests` 11/11,
  `run_134_reload_apply_v2_authority_marker_tests` 13/13,
  `run_138_sighup_v2_authority_marker_tests` 11/11,
  `qbind-node --lib pqc_authority` 148/148,
  `qbind-ledger t215_state_snapshot_tests` 10/10).
* Live inbound `0x05` v2 PQC trust-bundle frame validation **remains
  open**.
* Peer-driven live trust-bundle apply **remains open**.
* Signing-key rotation/revocation lifecycle **remains open**.
* KMS / HSM authority-key custody **remains open**.
* MainNet governance attestation track **remains open**.
* Full C4 acceptance **remains open**.
* C5 acceptance **remains open**.

## What landed in Run 141

`task/RUN_141_TASK.txt` §§1–6 — implemented entirely outside production
runtime source:

* `crates/qbind-node/examples/run_141_v2_snapshot_restore_fixture_helper.rs`
  (new, `cargo --example` only): mints DevNet genesis at the canonical
  Run 101 verification path (one `GenesisAuthorityRoot` with an ML-DSA-44
  keypair whose secret bytes are dropped immediately after the canonical
  hash is computed), writes `genesis.json` + `expected-genesis-hash.txt`,
  and produces 11 ephemeral snapshot directories and 3 local marker
  fixtures covering every scenario in §3 of the task:
  * `snap-v2-only`, `snap-v2-higher-seq`, `snap-v2-lower-seq`,
    `snap-v2-same-seq-diff-digest`, `snap-v2-wrong-genesis`,
    `snap-v2-wrong-environment`, `snap-v2-wrong-chain`,
    `snap-v2-wrong-authority-root`, `snap-v2-and-v1-ambiguous`,
    `snap-v1-only`, `snap-legacy-no-marker`;
  * `markers/matching-v2.json` (canonical v2 marker; `latest_sequence=5`,
    matches `snap-v2-only` bit-for-bit),
    `markers/matching-v1.json` (canonical v1 marker whose
    `authority_root_fingerprint` matches the v2 root so the Run 140
    `V2AfterV1ExplicitMigrationAllowed` path can accept under A4), and
    `markers/corrupt.bin` (arbitrary non-JSON bytes, exercises the
    `RejectLocalMarkerCorrupt` fail-closed path).
  * Emits a shell-sourceable `manifest.env` so the harness can address
    every fixture by stable variable name.
  * Each generated snapshot directory carries the matching state inventory
    (`state/.checkpoint_complete`) so Run 117's checkpoint copy step has
    something legal to materialize on accept paths, ensuring the
    `[restore] OK: restored from snapshot height=...` log line is the
    actual success line and not a coincidental early-exit.
* `scripts/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary.sh`
  (new, evidence-only): builds the release `qbind-node` binary
  (`cargo build --release -p qbind-node --bin qbind-node`) and the
  fixture helper (`cargo build --release -p qbind-node --example
  run_141_v2_snapshot_restore_fixture_helper`), records build provenance
  (`sha256`, `build-id`, `git_commit`, `rustc --version`, `cargo
  --version`), mints all fixtures via the helper, and for each of the 11
  scenarios:
  1. Stages a fresh empty data directory (and seeds
     `pqc_authority_state.json` from the appropriate marker fixture when
     applicable).
  2. Records the **pre-execution** sha256 of the local marker file (or
     `<none>`) and a full pre-execution inventory of the data directory.
  3. Invokes the real release binary with the pre-existing
     `--restore-from-snapshot` CLI path (`qbind-node --env devnet
     --data-dir <D> --genesis-path <G> --expect-genesis-hash <H>
     --restore-from-snapshot <S>`), captures stdout/stderr/exit-code, and
     for accept scenarios sends `SIGKILL` after a short timeout so the
     captured artifact is the restore log alone and not the subsequent
     long-running consensus loop.
  4. Records the **post-execution** sha256 of the local marker file and
     a full post-execution inventory of the data directory, and asserts
     `sha_before == sha_after` for every scenario where a local marker
     existed (verifying the restore surface really is pure with respect
     to the on-disk marker bytes on both accept and reject paths).
  5. For accept scenarios that should route through the v2 path
     (A1–A4), asserts that `[restore] Run 140 v2 authority-marker check`
     appears on a strictly lower line number than the
     `[restore] OK: restored from snapshot height=` line in the same
     stderr file (release-binary ordering proof).
  6. For reject scenarios, asserts the expected outcome substring
     (e.g. `LowerSequenceRejected`, `WrongAuthorityRootRejected`,
     `RejectSnapshotMarkerWrongDomain`, `RejectAmbiguousSnapshotMarkers`,
     `RejectLocalMarkerCorrupt`, `Run 140 v2 authority-marker check`,
     `Run 124 authority-marker check`) appears in the captured stderr
     and that exit code is `1`.
  7. Records the sha256 of every snapshot `meta.json` and an inventory
     of every snapshot's state files.
  8. Greps the full corpus of captured stderr logs for an explicit
     **out-of-scope** denylist (`falling back to --p2p-trusted-root`,
     `\bDummySig\b`, `\bDummyKem\b`, `\bDummyAead\b`, `live inbound
     0x05`, `peer-driven live apply`, `signing-key (rotation|revocation)
     lifecycle`, `\bKMS\b`, `\bHSM\b`) and asserts **zero matches**.
  9. Writes a `summary.txt` with all build provenance, fixture
     manifest, fixture sha256s, per-scenario verdict, and grep
     summaries.
* `docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/`
  (new evidence artifacts, committed): `summary.txt`,
  per-scenario stdout/stderr/exit-code logs under `logs/` and
  `exit_codes/`, pre/post local-marker hashes under `marker_hashes/`,
  pre/post data-directory inventories under `inventories/`, every
  snapshot `meta.json` under `snapshot_meta/`, every snapshot state
  inventory under `snapshot_state_inventory/`, and the in-scope /
  out-of-scope grep summaries under `grep_summaries/`.

## Build provenance (from `summary.txt`)

```
git_commit: 40ad9e4075d1ab492bb9db9b35d9ae36ca9f08bf
rustc_version: rustc 1.95.0 (59807616e 2026-04-14)
cargo_version: cargo 1.95.0 (f2d3ce0bd 2026-03-21)
qbind-node_path: target/release/qbind-node
qbind-node_sha256: 75129bd63d9a5c92949ec25dbdda04b3ed907c8ac0e905e092b9e5de299de748
qbind-node_build_id: 591bae399b17d84dbacc2df2ccf374c0051436d3
fixture-helper_sha256: 259015f7f002729736c8fb61dcb38988b51f392974a357b92b869b5539b8e836
fixture-helper_build_id: 2dc12da656f8ccd8f616a35f1c18bb7cd5b493f2
```

## Scenario verdicts

Every scenario log referenced below is committed under
`docs/devnet/run_141_snapshot_restore_v2_authority_marker_release_binary/logs/`.
For each scenario the harness also captured pre/post local-marker sha256
under `marker_hashes/`, pre/post data-directory inventories under
`inventories/`, and exit code under `exit_codes/`.

### Accepts (v2 dispatch path)

| Scenario | Fixture(s) | Observed `[restore] Run 140 v2 authority-marker check` outcome | `[restore] OK:` line | Local marker `sha_before == sha_after` |
| --- | --- | --- | --- | --- |
| **A1** v2 snapshot, empty data dir | `snap-v2-only`, no local marker | `no local v2 authority marker; snapshot v2 authority metadata matches the runtime trust domain (restore may proceed; local marker is NOT synthesised from snapshot bytes)` | `height=201 chain_id=0x51424e4444455600` | n/a (no local marker pre or post) |
| **A2** v2 snapshot, matching local v2 | `snap-v2-only`, `matching-v2.json` | `local v2 authority marker matches snapshot v2 authority metadata bit-for-bit (restore may proceed; local marker NOT rewritten)` | `height=201 chain_id=0x51424e4444455600` | ✅ `1345bb…a972a7` |
| **A3** v2 snapshot, higher sequence over local v2 | `snap-v2-higher-seq` (seq=10), `matching-v2.json` (seq=5) | `snapshot v2 authority metadata advertises a strictly higher latest_authority_domain_sequence (5 → 10) and matches the local v2 trust domain (restore may proceed; release-binary reload-apply will persist the new sequence atomically)` | `height=202 chain_id=0x51424e4444455600` | ✅ `1345bb…a972a7` — sequence is **NOT** persisted by the restore surface; persistence remains the Run 134 reload-apply path's responsibility |
| **A4** v2 snapshot, local v1 marker, matching authority root | `snap-v2-only`, `matching-v1.json` | `local v1 authority marker matches snapshot v2 authority metadata under the explicit v1→v2 migration semantics (restore may proceed; the v1 → v2 marker swap on disk is a separate release-binary step)` | `height=201 chain_id=0x51424e4444455600` | ✅ `42ed60…e7fd60` — the on-disk v1 → v2 marker swap is **explicitly NOT performed** on the restore surface |

Ordering proof for every accept: the `[restore] Run 140 v2
authority-marker check` line appears at line 3 of each scenario stderr,
strictly before the `[restore] OK: restored from snapshot height=` line
at line 6.

### Rejects (v2 dispatch path)

| Scenario | Fixture(s) | Observed `[restore] FATAL: refused by Run 140 v2 authority-marker check` outcome substring | Exit | Local marker `sha_before == sha_after` |
| --- | --- | --- | --- | --- |
| **R2** v2 lower sequence | `snap-v2-lower-seq` (seq=2), `matching-v2.json` (seq=5) | `LowerSequenceRejected { persisted_sequence: 5, candidate_sequence: 2 }` | 1 | ✅ `1345bb…a972a7` |
| **R3** v2 same sequence, different digest | `snap-v2-same-seq-diff-digest`, `matching-v2.json` | `SameSequenceDifferentDigestRejected { sequence: 5, persisted_digest: …d × 64, candidate_digest: …9 × 64 }` | 1 | ✅ `1345bb…a972a7` |
| **R4** v2 snapshot wrong `genesis_hash_hex` | `snap-v2-wrong-genesis`, no local marker | `snapshot v2 authority metadata advertises a different (environment, chain_id, genesis_hash) trust domain than the running runtime — snapshot.genesis_hash_hex=0…0` (RejectSnapshotMarkerWrongDomain) | 1 | n/a |
| **R5** v2 snapshot wrong `environment` | `snap-v2-wrong-environment`, no local marker | `snapshot.environment=mainnet runtime.environment=devnet` (RejectSnapshotMarkerWrongDomain) | 1 | n/a |
| **R6** v2 snapshot wrong `chain_id_hex` | `snap-v2-wrong-chain`, no local marker | `snapshot.chain_id_hex=ffffffffffffffff runtime.chain_id_hex=51424e4444455600` (RejectSnapshotMarkerWrongDomain) | 1 | n/a |
| **R7** corrupt local marker, v2 snapshot | `snap-v2-only`, `corrupt.bin` | `local authority marker is structurally invalid or its record_version is not supported by this binary (fail closed; marker bytes preserved verbatim)` (RejectLocalMarkerCorrupt) | 1 | ✅ `237a54…e463e7` (corrupt bytes preserved verbatim) |
| **R8** ambiguous snapshot carries both v1 and v2 blocks | `snap-v2-and-v1-ambiguous`, no local marker | `snapshot meta carries both a v1 (authority_state) and a v2 (authority_state_v2) authority block; a single snapshot must not advertise two simultaneously valid authority markers (fail closed)` (RejectAmbiguousSnapshotMarkers) | 1 | n/a |
| **R9** v2 snapshot with different `authority_root_fingerprint` | `snap-v2-wrong-authority-root`, `matching-v2.json` | `WrongAuthorityRootRejected { persisted_authority_root: …b × 40, candidate_authority_root: …1 × 40 }` | 1 | ✅ `1345bb…a972a7` |

### Rejects (v1 dispatch path — regression guard)

| Scenario | Fixture(s) | Observed log substring | Exit | Local marker `sha_before == sha_after` |
| --- | --- | --- | --- | --- |
| **R1** legacy snapshot with local v2 marker present | `snap-legacy-no-marker`, `matching-v2.json` | `[restore] FATAL: refused by Run 124 authority-marker check: snapshot restore rejected: local authority marker is corrupt or unsupported …` — the dispatch falls through to the Run 124 v1 entry point because the snapshot advertises no v2 block; the v1 path then fails closed because the local marker is the v2 schema which the Run 124 v1 verifier rejects as malformed (fail closed; bytes preserved verbatim) | 1 | ✅ `1345bb…a972a7` |

### Accepts (v1 / legacy regression guard)

| Scenario | Fixture(s) | Observed log substring | `[restore] OK:` line | Local marker `sha_before == sha_after` |
| --- | --- | --- | --- | --- |
| **R10** v1-only snapshot, matching v1 local marker | `snap-v1-only`, `matching-v1.json` | `[restore] Run 124 authority-marker check: local authority marker matches snapshot authority metadata bit-for-bit (restore may proceed; local marker NOT rewritten)` | `height=210 chain_id=0x51424e4444455600` | ✅ `42ed60…e7fd60` (Run 124 v1 path still passes — no v1 regression introduced by Run 140 dispatch) |
| **R11** legacy snapshot, empty data dir | `snap-legacy-no-marker`, no local marker | `[restore] Run 124 authority-marker check: no local authority marker and no snapshot authority metadata (legacy snapshot, fresh data dir; restore may proceed without authority enforcement on the restore surface)` | `height=211 chain_id=0x51424e4444455600` | n/a |

## Aggregate in-scope / out-of-scope grep summary

From `grep_summaries/`, across the full corpus of 11 scenario stderr
logs:

| Pattern | Total matches | Expectation |
| --- | --- | --- |
| `\[restore\] Run 140 v2 authority-marker check` | 4 (A1, A2, A3, A4) | ≥ 4 (one per v2-accept) ✅ |
| `\[restore\] Run 124 authority-marker check` | 2 (R10, R11) | ≥ 2 (v1/legacy regressions) ✅ |
| `\[restore\] OK: restored from snapshot` | 6 (A1–A4, R10, R11) | = 6 (every accept scenario) ✅ |
| `\[restore\] ERROR:` | 9 (R1–R9) | = 9 (every reject scenario) ✅ |
| `\[restore\] FATAL:` | 9 (R1–R9) | = 9 (every reject scenario) ✅ |
| `falling back to --p2p-trusted-root` | 0 | = 0 ✅ |
| `\bDummySig\b` | 0 | = 0 ✅ |
| `\bDummyKem\b` | 0 | = 0 ✅ |
| `\bDummyAead\b` | 0 | = 0 ✅ |
| `live inbound 0x05` | 0 | = 0 ✅ |
| `peer-driven live apply` | 0 | = 0 ✅ |
| `signing-key (rotation\|revocation) lifecycle` | 0 | = 0 ✅ |
| `\bKMS\b` | 0 | = 0 ✅ |
| `\bHSM\b` | 0 | = 0 ✅ |

## Source-level regression suites (re-run after Run 141 artifacts landed)

| Suite | Result |
| --- | --- |
| `cargo test --release -p qbind-node --test run_140_snapshot_restore_v2_authority_marker_tests` | **13 passed; 0 failed** |
| `cargo test --release -p qbind-node --test run_124_snapshot_restore_authority_marker_tests` | **11 passed; 0 failed** |
| `cargo test --release -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` | **13 passed; 0 failed** |
| `cargo test --release -p qbind-node --test run_138_sighup_v2_authority_marker_tests` | **11 passed; 0 failed** |
| `cargo test --release -p qbind-node --lib pqc_authority` | **148 passed; 0 failed** |
| `cargo test --release -p qbind-ledger --test t215_state_snapshot_tests` | **10 passed; 0 failed** |

Run 050–140 invariants are preserved.

## Closure claim and what remains open

Run 141 closes, **for the snapshot/restore surface only and for the v2
marker schema only**, the release-binary observation gap that Run 140
explicitly deferred:

1. The release-mode `qbind-node` binary built from this revision really
   does route v2-bearing snapshots through the Run 140 v2 dispatch and
   v1-bearing / legacy snapshots through the Run 124 v1 dispatch — both
   ordering proofs and dispatch labels are present in the captured
   stderr logs.
2. Every Run 140 acceptance and rejection variant
   (`AcceptSnapshotV2MarkerNoLocal`, `AcceptMatchingV2Marker`,
   `AcceptHigherV2Sequence`, `AcceptV2AfterV1Migration`,
   `RejectLocalMarkerCorrupt`, `RejectSnapshotMarkerWrongDomain` for
   each of `chain_id_hex` / `environment` / `genesis_hash_hex`,
   `RejectAmbiguousSnapshotMarkers`, and the
   `RejectV2Comparison(LowerSequenceRejected /
   SameSequenceDifferentDigestRejected / WrongAuthorityRootRejected)`
   sub-variants) is reachable from the real CLI surface with the
   expected exit code and the expected log substring.
3. The restore surface is pure with respect to the local marker file
   on **every** accept and reject path: sha256 of the local marker
   before invocation equals sha256 after invocation in every scenario
   where a local marker was seeded (A2, A3, A4, R1, R2, R3, R7, R9,
   R10). The on-disk v1 → v2 marker swap is **not** performed by the
   restore surface, and a strictly-higher v2 sequence is **not**
   persisted by the restore surface — both of those mutations remain
   the responsibility of the Run 134 reload-apply path on next process
   start (not exercised here).
4. No out-of-scope code path is reached: every entry in the explicit
   denylist (`falling back to --p2p-trusted-root`, `DummySig`,
   `DummyKem`, `DummyAead`, `live inbound 0x05`, `peer-driven live
   apply`, `signing-key (rotation|revocation) lifecycle`, `KMS`, `HSM`)
   has **zero matches** across the entire captured stderr corpus.
5. The v1 / legacy regression surface still works end-to-end: R10
   (matching v1-only snapshot under matching v1 local marker) and R11
   (legacy snapshot under empty data dir) both reach `[restore] OK:
   restored from snapshot height=…` via the Run 124 v1 path with the
   local marker bytes preserved verbatim.

Run 141 explicitly does **not** close, claim, or claim-by-implication
any of the following: live inbound `0x05` v2 PQC trust-bundle frame
validation; peer-driven live trust-bundle apply; signing-key rotation
or revocation lifecycle; KMS / HSM authority-key custody; MainNet
governance attestation track; validator-set rotation; the on-disk v1 →
v2 marker swap surface; the higher-sequence v2 persistence surface;
full C4 closure; or C5 closure. The C4 step that Run 141 narrows is
the snapshot/restore v2 authority-marker parity sub-step (B3 v2), and
**only** that sub-step.
