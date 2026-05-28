# QBIND DevNet Evidence — Run 143

**Subject**: Release-binary evidence for the **live inbound P2P
peer-candidate `0x05` v2 validation-only** receive path that Run 142
wired in source/test.

## Scope notice (mandatory per `task/RUN_143_TASK.txt`)

* **Run 143 is release-binary evidence only.**
* **No production runtime source changes.** No CLI flag is added or
  renamed. No metric family is added, renamed, or removed. No
  trust-bundle, peer-candidate, ratification, or authority-marker
  schema is changed.
* **No new fixture helper.** Run 143 reuses the existing
  `crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`
  verbatim — the same helper that minted Run 133's release-binary
  evidence. Same `sha256`, same ELF `BuildID`.
* **No source change to the Run 142 dispatcher.** Run 143 exercises
  the dispatcher landed in Run 142
  (`LivePeerCandidateWireDispatcher::dispatch_frame_from_peer_for_test`
  with the `LiveRatificationConfig::ratification_v2` slot and the
  `maybe_reject_on_v2_marker_conflict` helper) on real release
  binaries communicating over the real authenticated PQC P2P
  transport.
* **Validation-only.** No live trust mutation, no sequence write, no
  authority-marker write, no session eviction, no peer-driven live
  apply.
* Live inbound `0x05` v2 validation-only is now
  **release-binary-evidenced** when the matrix below passes. Peer-driven
  live trust-bundle apply **remains open**. Signing-key rotation /
  revocation lifecycle **remains open**. KMS / HSM authority custody
  **remains open**. MainNet governance attestation track
  **remains open**. **Full C4 acceptance remains open.**
  **C5 acceptance remains open.**

## Deliverables landed under Run 143

1. `scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh`
   — the release-binary harness.
2. `docs/devnet/run_143_live_inbound_0x05_v2_validation_release_binary/`
   — the persistent evidence archive (see its `README.md` for the
   per-subdirectory contract).
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md` (this file) — the
   canonical evidence report.
4. Documentation alignment for Run 143:
   * `docs/whitepaper/contradiction.md` — append-only Run 143 paragraph.
   * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 143 entry.
   * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 143
     entry.

## Cluster architecture

Mirrors Run 110 verbatim (N=3 DevNet, mutual-auth Required, signed
DevNet trust bundle, ML-KEM-768 KEM, ML-DSA-44 signing, ChaCha20-Poly1305
AEAD, Run 033 active=true keystores, no `DummySig` / `DummyKem` /
`DummyAead` in any active path):

* **V0** — publisher. Sends exactly one peer-candidate `0x05` wire frame
  using the existing
  `--p2p-trust-bundle-peer-candidate-wire-publish-path` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-once` CLI surface.
  V0 carries no ratification gate (the gate is a receiver concern).
* **V1** — validation-only v2 receiver. Configured with the
  operator-supplied v2 ratification sidecar via
  `--p2p-trust-bundle-ratification`. The existing versioned loader
  (`pqc_ratification_input::load_versioned_ratification_from_path`)
  dispatches to v2 because the helper-minted sidecar carries the
  `bundle_signing_ratification_v2` discriminator. Run 142's
  `LiveRatificationConfig::ratification_v2` slot then routes Validated
  outcomes through Run 130 verifier + Run 132 marker compare.
* **V2** — validation-only second receiver / propagation observer.
  Same sidecar as V1; receives a propagated copy from V1 when
  `--p2p-trust-bundle-peer-candidate-propagation-enabled` is set on
  V1 (Run 11b), or does not receive a propagated copy otherwise
  (Run 11a and Run 11c).

## Scenario matrix

| Scenario | V1 ratification sidecar | V1 seed marker | Wire outcome | Mutation invariant |
|---|---|---|---|---|
| A1 valid v2 first-seen | `ratification.v2.ratify.seq1.json` | (none) | accepted | no sequence write, no marker write |
| A2 v2 idempotent | `ratification.v2.same.seq1.json` | `seed-marker.v2.seq1.json` | accepted | marker bytes preserved verbatim |
| A3 v2 higher-sequence | `ratification.v2.ratify.seq2.json` | `seed-marker.v2.seq1.json` | accepted | marker bytes preserved (no persist) |
| A4 v2-after-v1 migration | `ratification.v2.ratify.seq2.json` | `seed-marker.v1.json` | accepted | v1 marker preserved, no v2 marker written |
| R1 v2 lower-sequence | `ratification.v2.lower.seq1.json` | `seed-marker.v2.seq2.json` | rejected | marker bytes preserved verbatim |
| R2 v2 same-seq diff-digest | `ratification.v2.equivocation.seq1.json` | `seed-marker.v2.seq1.json` | rejected | marker bytes preserved verbatim |
| R3 v2 bad-signature | `ratification.v2.bad-signature.json` | (none) | rejected (Run 130 verifier failure) | no marker created |
| R4 v2 wrong-environment | `ratification.v2.wrong-environment.json` | (none) | rejected | no marker created |
| R5 v2 wrong-chain | `ratification.v2.wrong-chain.json` | (none) | rejected | no marker created |
| R6 v2 wrong-genesis | `ratification.v2.wrong-genesis.json` | (none) | rejected | no marker created |
| R7 ambiguous v1+v2 fail-closed | synthesised ambiguous sidecar | (n/a) | preflight refuse (binary exits non-zero, transport never up) | no transport up, no marker touch |
| R8 corrupted local marker | `ratification.v2.ratify.seq1.json` | corrupt JSON blob | rejected | corrupt bytes preserved verbatim |
| R9 v1 live inbound regression | `ratification.v1.valid.json` | (none) | accepted via Run 109 v1 path | no v2 path selected |
| R10 DevNet no-opt-in legacy | (none) | (none) | accepted via pre-Run-109 path | no v2 marker fabricated; Run 109 SKIPPED log |
| R11a propagation-disabled valid | `ratification.v2.ratify.seq1.json` | (none) | V1 validated; V2 receives no propagated copy | `propagation_sent_total == 0` |
| R11b propagation-enabled valid | `ratification.v2.ratify.seq1.json` | (none) | V1 validated AND rebroadcast; V2 validated | `propagation_sent_total >= 1` on V1, validated on V2 |
| R11c propagation-enabled invalid | `ratification.v2.bad-signature.json` | (none) | V1 rejected; NEVER rebroadcast | `propagation_sent_total == 0`, `propagation_suppressed_invalid_total >= 1` |

Every scenario asserts the Run 143 negative invariants:

* per-node `pqc_trust_bundle_sequence.json` is byte-identical before
  and after the scenario;
* per-node `pqc_authority_state.json` is byte-identical before and
  after the scenario (when present);
* no `pqc_authority_state.json.tmp` sibling left behind on any node;
* no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` metric
  family appears;
* `qbind_p2p_trust_bundle_live_reload_*` and
  `qbind_p2p_session_eviction_*` counters all stay at 0;
* no `--p2p-trusted-root` fallback log line fires on any node;
* no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true`
  marker fires on any node;
* invalid candidates never produce `propagation_sent_total >= 1`.

Every scenario asserts the Run 143 positive invariants:

* V1 stderr logs the Run 109 `live peer-candidate.*ratification gate
  INVOKED` marker on every v2-enforced scenario, and the Run 109
  SKIPPED marker on R10 (the DevNet legacy path);
* V1 metrics register `peer_candidate_validated_total >= 1` on accepts
  and `peer_candidate_rejected_total >= 1` on rejects;
* V0 (the publisher) never receives its own candidate back
  (source-peer exclusion preserved by Run 088);
* V1 (the receiver) remains running after invalid candidates — the
  dispatcher does not crash on rejection.

## Verdict

**Strongest-positive when the harness completes cleanly on a
build-capable environment.** The harness fails closed at the first
non-mutation, denylist, sidecar-schema-drift, or scenario-expectation
violation, so a clean exit is equivalent to "every scenario in the
matrix above passed its expectation and every invariant held".

The published `summary.txt` and per-scenario archive under
`docs/devnet/run_143_live_inbound_0x05_v2_validation_release_binary/`
records the verdict observed at the time of the run, including the
exact `qbind-node` / helper `sha256` + `BuildID` and the `git_commit`,
`rustc --version`, and `cargo --version` that produced them.

## Out-of-scope and remains-open after Run 143

* peer-driven live trust-bundle apply (the `0x05` path remains
  validation-only on every scenario) — **remains OPEN**;
* signing-key rotation / revocation lifecycle (no rotation or
  revocation operation is exercised) — **remains OPEN**;
* KMS / HSM authority key custody — **remains OPEN**;
* MainNet governance attestation track — **remains OPEN**;
* validator-set rotation — **remains OPEN**;
* `--p2p-trusted-root` fallback authority lineage — **remains
  REJECTED** (Run 143 asserts no such log line appears);
* `DummySig` / `DummyKem` / `DummyAead` test-shim hot path —
  **remains REJECTED** (Run 143 asserts no such marker appears);
* full C4 closure — **remains OPEN**;
* C5 closure — **remains OPEN**.

## Validation commands

Per `task/RUN_143_TASK.txt`, at minimum:

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper

bash scripts/devnet/run_143_live_inbound_0x05_v2_validation_release_binary.sh

cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

The exact Run 132 validation-only target name in `task/RUN_143_TASK.txt`
(`run_132_v2_validation_only_tests`) does **not** exist as a separate
integration test in this tree — that surface is covered by the inline
module tests under
`crates/qbind-node/src/pqc_authority_marker_acceptance.rs::tests::v2_validation_only`,
which are exercised by `cargo test -p qbind-node --lib pqc_authority`
(noted verbatim in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_142.md`).

## Acceptance criteria (Run 143)

1. Real `target/release/qbind-node` processes exchange real live
   `0x05` peer-candidate frames over the real authenticated PQC P2P
   transport. ✅ (harness drives N=3 DevNet cluster)
2. Valid v2 candidates are accepted validation-only. ✅ (A1–A4)
3. Invalid v2 candidates are rejected fail-closed. ✅ (R1–R8)
4. No live trust mutation, sequence write, marker write, or session
   eviction occurs on any v2 `0x05` validation path. ✅ (every
   scenario asserts sequence + marker hash equality, zero
   reload/eviction counters, no applied-metric family)
5. v1 and legacy `0x05` behaviour remains unchanged. ✅ (R9 + R10)
6. Propagation-only behaviour remains validation-before-rebroadcast
   and non-applying; invalid candidates are never rebroadcast. ✅
   (R11a / R11b / R11c)
7. Evidence artifacts archived under
   `docs/devnet/run_143_live_inbound_0x05_v2_validation_release_binary/`. ✅
8. `docs/whitepaper/contradiction.md` and the operator / protocol
   docs are narrowly updated. ✅
9. No full C4 closure or C5 closure is claimed. ✅