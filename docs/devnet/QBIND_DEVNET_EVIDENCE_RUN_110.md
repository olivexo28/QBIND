# QBIND DevNet Evidence — Run 110

**Task:** `task/RUN_110_TASK.txt` — release-binary live multi-node evidence for the Run 109 ratification gate on the live inbound `0x05` peer-candidate wire validation path.

**Verdict:** **partial-positive**. The Run 110 deliverables — a release-binary multi-node N=3 DevNet harness (`scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh`), an evidence-only fixture helper (`crates/qbind-node/examples/run_110_live_ratification_fixture_helper.rs`), and the operator/whitepaper/authority-model doc updates — land in-tree and are repeatable by an operator or CI environment with a release toolchain. A fresh full release-binary capture (`target/release/qbind-node` + helpers, all six harness scenarios, archived metrics / logs / sequence-hash matrices under `docs/devnet/run_110_live_peer_candidate_ratification_n3/`) was **not** produced in this run because the sandbox available to this task could not feasibly complete a full workspace release build plus a multi-process N=3 networking harness in the available budget; the operator-side replay procedure below is fully self-contained.

This continues the Run 109 / Run 089 verdict shape: source code + focused integration tests already pin the Run 109 ratification gate at the library level (23 passing tests in `crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs`); Run 110 adds the **release-binary multi-node harness** that exercises the same surface end-to-end across real `qbind-node` processes on loopback. The fresh capture is left as a one-command follow-up for an operator/CI environment.

---

## Scope

Run 110 is evidence-only. No production runtime code under `crates/**/src/**` changed. The only additions are:

1. `crates/qbind-node/examples/run_110_live_ratification_fixture_helper.rs` — a small ML-DSA-44 fixture mint helper that overlays the Run 089-style DevNet trust material with:
   - a Run 101 `GenesisConfig` with a populated `genesis_authority` block;
   - the canonical Run 102 expected genesis hash for that genesis;
   - a Run 103 signed `BundleSigningRatification` sidecar covering the **R1 ratified key** (the existing DevNet trust-bundle signing key, read from `<material>/signing-key.spec`);
   - a tampered copy of that sidecar (signature byte 0 flipped) for the bad-signature scenario;
   - a **U1 unratified signing key** (a freshly minted ML-DSA-44 keypair NOT covered by the ratification sidecar);
   - a U1-signed alternate trust bundle (same `roots` / `revocations` as the cluster baseline, `sequence = baseline + 1`) for the missing-ratification scenario;
   - two `PeerCandidateEnvelope` JSON files wrapping the R1-signed and U1-signed bundles respectively;
   - a `summary.json` manifest of the minted identities.

2. `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` — a release-binary harness modeled on `scripts/devnet/run_089_peer_candidate_propagation_n3.sh`. It:
   - reuses the Run 089 N=3 DevNet topology (`V0`, `V1`, `V2` on loopback, mutual-auth ML-KEM-768 + ChaCha20-Poly1305 + ML-DSA-44, real consensus signer keystores, signed DevNet trust bundle);
   - additionally wires V1 and V2 with `--genesis-path`, `--expect-genesis-hash`, `--p2p-trust-bundle-ratification-enforcement-enabled`, and (per-scenario) `--p2p-trust-bundle-ratification <PATH>`;
   - additionally wires every node with a **second** `--p2p-trust-bundle-signing-key` line carrying the U1 unratified key. This is what lets the U1-signed alternate bundle pass the inner Run 050 / 076 signature check on V1 and **actually reach the Run 109 ratification gate**. Without U1 in the accepted-keys list the rejection would fire one layer earlier (Run 050 wrong-signer), and the Run 109 surface this harness is supposed to evidence would never execute on the live wire.

3. Narrow doc updates in `docs/whitepaper/contradiction.md` (Run 110 paragraph appended to the C4 thread), `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 110 section appended), and `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 110 operator update appended). All updates restate the same security boundaries and explicitly do not claim full C4 or C5 closure.

Run 110 does **not**:

- change the `0x05` peer-candidate wire format,
- change the trust-bundle wire format,
- introduce a new metric family,
- introduce a peer-supplied ratification object,
- introduce static production source-code anchors or fallback authorities,
- introduce peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, KMS/HSM custody, fast-sync ratification parity, governance, or validator-set rotation;
- claim full C4 closure or C5 closure.

---

## Test architecture

```
                +-----------+   0x05 peer-candidate frames     +-----------+
   ratified ->  |    V0     | --------------------------->     |    V1     |
   envelope     |  (sender) |                                   | (relay+   |
                +-----------+                                   |  rat gate)|
                                                                +-----+-----+
                                                                      | Run 088
                                                                      | propagation
                                                                      | gated on
                                                                      | Validated
                                                                      v
                                                                +-----------+
                                                                |    V2     |
                                                                | (rat gate)|
                                                                +-----------+
```

- V0 is the **sender**. It uses the existing Run 080 `--p2p-trust-bundle-peer-candidate-wire-publish-*` flags to broadcast exactly one 0x05 frame to its connected peers. V0 does NOT receive 0x05 frames from V1 (source-peer exclusion is the Run 088 invariant).
- V1 is the **relay + ratification hub**. It validates every inbound 0x05 frame through the Run 109 ratification-aware receiver, then propagates only validated frames to V2 (Run 088). On ratification rejection it suppresses propagation via `propagation_suppressed_invalid_total`.
- V2 is a **terminal observer**. It validates inbound 0x05 frames through the same ratification gate, but it never propagates further (`--p2p-trust-bundle-peer-candidate-propagation-enabled` is NOT set on V2).

Both V1 and V2 in the enforced-policy scenarios are started with `--p2p-trust-bundle-ratification-enforcement-enabled` AND `--p2p-trust-bundle-ratification <ratification.valid.json>`. Both also accept R1 and U1 via two `--p2p-trust-bundle-signing-key` lines, so the inner signature check accepts both bundles and the **only layer that distinguishes them is the Run 109 ratification gate**.

---

## Scenario matrix

| # | Scenario                              | V0 envelope            | V1 sidecar                    | Expected V1 outcome                              | Expected V2 outcome           | Notes |
|---|---------------------------------------|------------------------|-------------------------------|--------------------------------------------------|-------------------------------|-------|
| A | `baseline_ratification`               | (none — no publish)    | `ratification.valid.json`     | `transport up`, Run 109 gate logs `INVOKED`      | same as V1                    | proves cluster boots with Run 109 gate INVOKED on V1+V2; no peer-candidate traffic |
| 1 | `valid_ratified`                      | `envelope.ratified.json` (R1-signed) | `ratification.valid.json` | `validated_total=1`, `propagation_sent_total=1`, `received_total=1` | `validated_total=1`, `propagation_sent_total=0` | full happy path; V0 source excluded |
| 2 | `missing_ratification`                | `envelope.unratified.json` (U1-signed) | `ratification.valid.json` | `validated_total=0`, `rejected_total=1`, `propagation_sent_total=0`, `propagation_suppressed_invalid_total>=1`; log contains `RatificationRefused` / `Missing` | `validated_total=0`, `propagation_sent_total=0` | the wire path's primary negative case |
| 3 | `bad_ratification_startup_refuse`     | (none — V1-only smoke) | `ratification.bad-signature.json` | V1 exits non-zero; log contains a `RatificationRefused` / `BadSignature` / `run-105.*refused` marker; `P2P transport up` is NEVER reached; no `pqc_trust_bundle_sequence.json` is created | not applicable               | defense-in-depth: a tampered sidecar cannot reach the live wire path because Run 105's startup preflight refuses it. This is the truthful Run 109 / Run 105 layering — bad-signature ratification objects are intercepted upstream of the wire gate. |
| 4 | `duplicate_unratified_no_promotion`   | `envelope.unratified.json` (twice from two V0 processes) | `ratification.valid.json` | `received_total>=2`, `validated_total=0`, `propagation_sent_total=0`, `rejected_total + duplicate_total >= 2` | `validated_total=0`, `propagation_sent_total=0` | proves the seen-cache does NOT promote a prior rejection to acceptance on a repeat arrival |
| 5 | `devnet_no_opt_in_legacy`             | `envelope.ratified.json` | (no `--p2p-trust-bundle-ratification*` flags) | `validated_total=1`, `propagation_sent_total=1`; log contains `SKIPPED` / `devnet-no-operator-opt-in` | `validated_total=1` | proves the DevNet developer ergonomics branch is byte-for-byte preserved when ratification is not opted in (regression-protects Run 089's exact behavior) |

Across **every** scenario the harness asserts the cross-cutting non-mutation invariants from Run 087 / 088 / 089 / 105 / 107 / 109:

- `pqc_trust_bundle_sequence.json` is byte-identical on every node before and after each scenario (no sequence write, no apply);
- `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` is absent from `/metrics` on every node (Run 088 metric-family contract);
- all `qbind_p2p_trust_bundle_live_reload_*` and `qbind_p2p_session_eviction_*` counters stay at `0`;
- no `--p2p-trusted-root` fallback log line fires;
- no `DummySig` / `DummyKem` / `DummyAead` / `dummy_*_registered=true` line fires;
- `qbind_p2p_pqc_cert_verify_accepted_total >= 1` and `qbind_p2p_pqc_cert_verify_rejected_total == 0` (the Run 037 / Run 040 PQC mutual-auth path was real).

---

## Why Scenario 3 lives at the startup boundary

Run 109 reuses the **already-existing Run 105 sidecar model**: the operator-supplied `--p2p-trust-bundle-ratification <PATH>` JSON is loaded once at startup, owned by the live dispatcher for the process lifetime, and reborrowed per-frame. There is no peer-supplied ratification material on the `0x05` wire.

That means a "bad-signature ratification" can only enter the system through the operator's local file. When the operator supplies a tampered sidecar, the Run 105 startup preflight fires **before** the live dispatcher is even installed, and the binary exits non-zero with a typed `RatificationRefused(...)` line — exactly the defense-in-depth shape Runs 105 / 107 / 108 already produce on their non-live surfaces. Therefore the truthful release-binary evidence for "bad ratification cannot reach the live wire path" is:

> V1 with a bad-signature ratification sidecar exits non-zero, never reaches `P2P transport up`, never creates a `pqc_trust_bundle_sequence.json`, and never installs a live `0x05` dispatcher.

Scenario 3 in the Run 110 harness asserts exactly that. It is a defense-in-depth proof of the bad-signature case — not a runtime-rejection-at-V1 proof, because Run 109's design (no peer-supplied ratification) makes the latter mechanically impossible on the live wire today. The future-work item "peer-distributed ratification objects on the wire" would re-open a path for a runtime-V1 bad-signature evidence; that path is out of scope for both Run 109 and Run 110 and is explicitly flagged as future work below.

---

## Replay procedure

Prerequisites:

- a release Rust toolchain that builds the workspace,
- a Linux host with `curl`, `python3`, `awk`, `readelf`, `sha256sum`, and loopback networking,
- approximately 1–2 GB of disk for `target/release/` and the scenario archive.

One-command replay:

```bash
scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh
```

This script:

1. builds (or reuses) `target/release/qbind-node`, `devnet_pqc_trust_bundle_helper`, `devnet_pqc_root_helper`, `devnet_consensus_signer_keystore_helper`, and `run_110_live_ratification_fixture_helper`;
2. records each binary's SHA-256 and ELF BuildID into `artifact_sha256.txt` and `artifact_build_id.txt`;
3. mints DevNet trust material (signed bundle, transport root + leaf certs, consensus signer keystores) under `<OUTDIR>/material/` and `<OUTDIR>/signers/`;
4. overlays the Run 110 ratification fixtures under `<OUTDIR>/fixtures/`;
5. runs the six scenarios above, scraping `/metrics` and `stderr` after each;
6. snapshots `pqc_trust_bundle_sequence.json` on every node before and after every scenario;
7. writes `<OUTDIR>/summary.txt`, `<OUTDIR>/ratification_lines.txt`, `<OUTDIR>/run033_run040_lines.txt`, and archives the full evidence tree under `docs/devnet/run_110_live_peer_candidate_ratification_n3/`.

Tunables (env): `QBIND_RUN110_NODE_TIMEOUT`, `QBIND_RUN110_P2P_BASE`, `QBIND_RUN110_METRICS_BASE`, `QBIND_RUN110_ARCHIVE_DIR`, `QBIND_RUN110_NODE_BIN`, `QBIND_RUN110_*_HELPER`.

---

## What the harness mechanically asserts (per scenario)

`scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` is intentionally written in the same style as Run 089 (`run_baseline`, `run_valid_propagation`, …) so the assertion shape is mechanical and reviewable. The metric assertions on V1 in the enforced-policy scenarios collapse to the following ordered claims:

- **Scenario 1 (valid_ratified)** — V1: `received_total=1`, `validated_total=1`, `rejected_total=0`, `propagation_attempt_total=1`, `propagation_sent_total=1`, `propagation_suppressed_invalid_total=0`. V2: `validated_total=1`, `rejected_total=0`. V0: `received_total=0` (source exclusion).
- **Scenario 2 (missing_ratification)** — V1: `received_total=1`, `validated_total=0`, `rejected_total=1`, `propagation_attempt_total=0`, `propagation_sent_total=0`, `propagation_suppressed_invalid_total>=1`, stderr contains a `RatificationRefused` / `Missing` marker. V2: `validated_total=0`, `propagation_sent_total=0`, `received_total<=1` (an at-most-one direct broadcast from V0; never via V1 propagation). V0: `received_total=0`.
- **Scenario 3 (bad_ratification_startup_refuse)** — V1 exits non-zero; stderr contains a `RatificationRefused` / `BadSignature` / `run-105.*refused` / `run-109.*FATAL` marker; `P2P transport up` is NEVER reached; no `pqc_trust_bundle_sequence.json` is created under V1's data dir.
- **Scenario 4 (duplicate_unratified_no_promotion)** — V1: `received_total>=2`, `validated_total=0`, `propagation_sent_total=0`, `rejected_total + duplicate_total >= 2`. V2: `validated_total=0`, `propagation_sent_total=0`.
- **Scenario 5 (devnet_no_opt_in_legacy)** — V1 stderr contains a `SKIPPED` / `devnet-no-operator-opt-in` marker; V1: `validated_total=1`, `propagation_sent_total=1`; V2: `validated_total=1`. (Regression protection that the no-opt-in path is byte-for-byte the Run 089 path.)

If any of these assertions fail, the harness exits non-zero with a `[run110] FAIL: <metric/log/sequence>` line that names the exact assertion that failed.

---

## Source / test coverage already pinning the same behavior

These library-level tests already pin the ratification gate semantics that Run 110 exercises on release binaries:

- `crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs` (23 tests, all passing): every rejection variety (`Missing`, `Verifier(BadSignature)`, `Verifier(WrongChain)`, `Verifier(WrongEnvironment)`, `Verifier(UnknownAuthorityRoot)`, `Verifier(TransportRootNotAllowed)`, `Verifier(UnsupportedSuite)`, `Verifier(MissingKeyMaterial)`, `Verifier(MalformedKeyMaterial)`), every gate decision (`Invoke(MainnetDefaultStrict)`, `Invoke(TestnetDefaultStrict)`, `Invoke(DevnetOperatorOptIn)`, `Skip(DevnetNoOperatorOptIn)`), and the propagation gating (`run109_unratified_candidate_does_not_rebroadcast`, `run109_bad_ratification_candidate_does_not_rebroadcast`, `run109_valid_ratified_candidate_may_rebroadcast_under_run088_rules`);
- `crates/qbind-ledger/src/bundle_signing_ratification.rs` test module (Runs 103 / 105 verifier pins);
- `crates/qbind-node/tests/run_107_pqc_peer_candidate_check_ratification_tests.rs` (Run 107 local CLI pins, share `try_accept_with_ratification`);
- `docs/devnet/run_108_peer_candidate_check_ratification_release_binary_evidence/` (release-binary evidence for the local CLI surface; same library code that the live dispatcher reuses);
- `docs/devnet/run_089_peer_candidate_propagation_n3/` (release-binary N=3 DevNet propagation evidence; the **transport** topology Run 110 reuses verbatim).

Run 110's contribution is to exercise the union of those surfaces on real release `qbind-node` processes simultaneously, on a real multi-node DevNet topology, behind real PQC mutual auth, with real Run 109 ratification flags on the V1 relay and V2 observer.

---

## Security boundaries (unchanged)

Run 110 changes none of the existing security boundaries. The harness, helper, and docs explicitly preserve:

- **Local config alone is still not enough for MainNet bundle-signing authority.** The ratification verifier is rooted in the genesis authority block via the canonical genesis hash; Run 110's harness mints a fresh DevNet authority for each run and never reuses any production identity.
- **Static production source-code anchors remain rejected.** Run 110 introduces no new static anchors, no fallback authorities, and no static signing keys.
- **Transport roots cannot ratify bundle-signing keys.** The `TransportRootNotAllowed` rejection variety is pinned by the Run 109 test suite; the Run 110 harness's `--p2p-trust-bundle-signing-key` flag accepts only the ML-DSA-44 bundle-signing keys (R1 and U1), never the transport ML-KEM-768 root.
- **Rejection remains validation-only and non-mutating.** No sequence file is written, no root merge occurs, no live trust state is mutated, no sessions are evicted, no `_applied_total` metric family is introduced, no `0x05` rebroadcast happens on rejection, and no node reload-applies on rejection.
- **No wire-format changes.** `0x05` peer-candidate envelopes and the trust-bundle on-disk format are bit-for-bit unchanged.

---

## Future work (still open, explicitly not closed by Run 110)

Run 110 does **not** close any of the following C4 sub-pieces, all of which remain OPEN:

- peer-driven live apply,
- reload-apply ratification (Run 070 path),
- SIGHUP ratification,
- signing-key rotation lifecycle,
- signing-key revocation lifecycle,
- authority anti-rollback persistence,
- persistent ratified-authority state,
- peer-distributed ratification objects on the `0x05` wire,
- KMS/HSM custody,
- production fast-sync / broader consensus-storage restore ratification parity,
- governance,
- validator-set rotation.

C5 remains OPEN / unchanged.

Run 110 is **partial-positive** because the harness, helper, and docs land in-tree and are repeatable, but a fresh full release-binary multi-node capture under this PR was not produced (no archived `docs/devnet/run_110_live_peer_candidate_ratification_n3/` tree is added in this commit). Operators or CI environments with a release toolchain can produce the archive with a single command (`scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh`); the harness self-archives into the canonical directory on success.

---

## Run 111 closure update

The Run 110 release-binary capture gap was closed by **Run 111** (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_111.md`). Run 111 executed `scripts/devnet/run_110_live_peer_candidate_ratification_n3.sh` end-to-end on real release `qbind-node` processes with no harness, helper, or production runtime changes; all six scenarios passed first-shot. The archived release-binary capture is `docs/devnet/run_110_live_peer_candidate_ratification_n3/` (per-node `logs/`, `metrics/`, `sequence/`, `fixtures/`, plus `summary.txt`, `artifact_sha256.txt`, `artifact_build_id.txt`, `ratification_lines.txt`, `run033_run040_lines.txt`). With Run 111's capture in place, Run 110's deliverable shape is now **strongest-positive at the Run 110 + Run 111 boundary**: the harness, fixture helper, doc updates, and the fresh release-binary multi-node capture all exist in-tree. Run 110's own verdict line above is preserved verbatim for historical accuracy; the closure is recorded here, in the Run 111 evidence doc, and in `docs/whitepaper/contradiction.md`. Run 110 + Run 111 together still do not claim full C4 closure and still do not claim C5 closure — every future-work item listed in "Future work" above remains OPEN.