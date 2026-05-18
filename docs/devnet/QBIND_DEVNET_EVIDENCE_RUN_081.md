# QBIND DevNet Evidence — Run 081

## Exact objective

Complete Run 080 with **evidence-only** release-binary proof that a real `0x05` peer-candidate frame is exchanged over live N=2 P2P transport, the receiver validates/rejects through the Run 079 path, and validation-only invariants remain intact (no apply, no sequence burn, no live-trust mutation, no session eviction, no live-reload apply side effects, no propagation).

## Exact verdict

**Partial positive.**  
Run 081 provides release-binary N=2 live artifacts for real `0x05` exchange:

- valid candidate: sender `sent_total` increments and receiver `received_total`/`validated_total` increment;
- receiver-disabled case: sender sends while receiver cheap-ignores (`received/validated/rejected` stay zero);
- invalid candidate: receiver rejects (`rejected_total` increments);
- duplicate case: receiver `duplicate_total` increments;
- receiver sequence file hash remains unchanged across all candidate-wire scenarios;
- live-reload apply metrics and session-eviction metrics remain unchanged (all zero).

Boundary kept explicit: the run still surfaces the existing Run 033 timeout-verification probe line containing `TrustedClientRoots/DummySig`, so Run 081 does **not** claim full “no DummySig” closure and therefore does not claim strongest-positive closure of the broader C4/C5 scope.

## Exact files changed

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` (new)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_080.md` (appended Run 081 follow-up evidence note)
- `docs/whitepaper/contradiction.md` (appended C4 Run 081 evidence update)

## Binary/helper identities

Build host repo state at build time:

- branch: `copilot/update-readme-file-again`
- commit: `97817576ac350e2de962f1dd8ebfea9218926376`
- working tree: `clean`

Artifacts:

| Artifact | sha256 | ELF BuildID |
|---|---|---|
| `target/release/qbind-node` | `d28c5493d3782dea5a20b03449eb01ab582f69c32e36d0a657c5f356fdb2ca49` | `c7ae28418d107f7e467fd4346f85644e6fcd943a` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `39b4a9a5d61aa3c3c0117ceefe5849d087f13e0ee5024b90d95ebaeb08076efb` | `5050ded02408a3a27d1eccc382a5f48fa47b2501` |
| `target/release/examples/devnet_pqc_root_helper` | `58298104e52b687d28d6ca5a0606f54191cad28a84f2b8cda896a43dbbe005e4` | `7e514ca79e45bea41d743266f3224f631769902f` |

## Exact commands run

### Release builds and artifact identity

- `cargo build --release -p qbind-node --bin qbind-node`
- `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper`
- `cargo build --release -p qbind-node --example devnet_pqc_root_helper`
- `git rev-parse --abbrev-ref HEAD`
- `git rev-parse HEAD`
- `git status --porcelain`
- `sha256sum target/release/qbind-node`
- `sha256sum target/release/examples/devnet_pqc_trust_bundle_helper`
- `sha256sum target/release/examples/devnet_pqc_root_helper`
- `readelf -n ... | grep -A1 'Build ID'`

### Required regression commands (Run 081 task list)

- `cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests`
- `cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests`
- `cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests`
- `cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests`
- `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests`
- `cargo test -p qbind-node --lib pqc_peer_candidate_wire`
- `cargo test -p qbind-node --lib metrics::tests::peer_candidate_send_metrics`
- `cargo test -p qbind-node --lib`
- `cargo test -p qbind-net --lib`
- `cargo test -p qbind-crypto --lib`

### N=2 trust material + candidate envelope generation

- `./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run081/mat 2 signed-devnet`
- `cat /tmp/run081/mat/signing-key.spec`
- Python envelope generation writing:
  - `/tmp/run081/envelopes/candidate_valid.json`
  - `/tmp/run081/envelopes/candidate_invalid_wrong_chain.json`
- Optional local-check sanity probe:
  - `./target/release/qbind-node ... --p2p-trust-bundle-peer-candidate-validation-enabled --p2p-trust-bundle-peer-candidate-check /tmp/run081/envelopes/candidate_valid.json`

### N=2 live release-binary orchestration

Baseline startup:

- V1 (`:19811`, metrics `:9281`) + V0 (`:19810`, metrics `:9280`) with:
  - `--env devnet --network-mode p2p --enable-p2p`
  - `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root`
  - `--p2p-trust-bundle /tmp/run081/mat/trust-bundle.json`
  - `--p2p-trust-bundle-signing-key "$(cat /tmp/run081/mat/signing-key.spec)"`
  - per-node `--p2p-leaf-cert/--p2p-leaf-cert-key`
  - cross `--p2p-peer-leaf-cert`
  - per-node `--data-dir /tmp/run081/data_v{0,1}`
  - process lifetime bounded with `timeout`

Scenario 4 (valid candidate; sender publish enabled, receiver validation enabled):

- Receiver V1: add `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
- Sender V0: add
  - `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`
  - `--p2p-trust-bundle-peer-candidate-wire-publish-path /tmp/run081/envelopes/candidate_valid.json`
  - `--p2p-trust-bundle-peer-candidate-wire-publish-once`

Scenario 5 (receiver disabled):

- Receiver V1: **no** wire-validation flag
- Sender V0: same publish flags as Scenario 4 with valid envelope

Scenario 6 (invalid candidate):

- Receiver V1: wire-validation enabled
- Sender V0: publish flags with
  - `--p2p-trust-bundle-peer-candidate-wire-publish-path /tmp/run081/envelopes/candidate_invalid_wrong_chain.json`

Scenario 7 (duplicate case):

- Receiver V1 runs once with wire-validation enabled
- Sender V0 launched twice sequentially with publish-once valid envelope
- Receiver metrics scraped from `:9331` after second send

Metrics were scraped with `curl -s --max-time ... http://127.0.0.1:<port>/metrics`.

## Test/evidence pass/fail status

### Regression commands

All required regression commands: **pass**.

- `run_080_pqc_peer_candidate_wire_send_tests`: 3/3 pass
- `run_079_pqc_peer_candidate_wire_live_dispatch_tests`: 11/11 pass
- `run_078_pqc_peer_candidate_wire_tests`: 19/19 pass
- `run_077_binary_peer_candidate_check_tests`: 12/12 pass
- `run_076_pqc_peer_candidate_validation_tests`: 16/16 pass
- `--lib pqc_peer_candidate_wire`: 28/28 pass
- `--lib metrics::tests::peer_candidate_send_metrics`: 2/2 pass
- `-p qbind-node --lib`: 1063/1063 pass
- `-p qbind-net --lib`: 17/17 pass
- `-p qbind-crypto --lib`: 68/68 pass

### Live evidence scenarios

- Baseline N=2 signed-bundle startup: **pass**
- Scenario 4 valid `0x05` exchange with receiver validation: **pass**
- Scenario 5 receiver disabled cheap-ignore: **pass**
- Scenario 6 invalid candidate rejection: **pass**
- Scenario 7 duplicate suppression evidence: **pass**

## N=2 orchestration details and proofs

### 1) Baseline N=2 signed-bundle startup

Observed:

- both nodes reached `P2P transport up` on live binary path;
- cert verification accepted and no rejections:
  - `qbind_p2p_pqc_cert_verify_accepted_total 2` (both nodes)
  - `qbind_p2p_pqc_cert_verify_rejected_total 0` (both nodes)
  - all per-reason `qbind_p2p_pqc_cert_rejected_*_total 0`;
- trust bundle loaded with signature verified:
  - `qbind_p2p_pqc_trust_bundle_loaded 1`
  - `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`
  - `qbind_p2p_pqc_trust_bundle_sequence 1`;
- sequence file created:
  - `/tmp/run081/data_v0/pqc_trust_bundle_sequence.json`
  - `/tmp/run081/data_v1/pqc_trust_bundle_sequence.json`.

### 2) Scenario 4 — sender enabled + receiver wire-validation enabled (valid candidate)

Sender log (`sc4_v0.stderr.log`):

- `Run 080: peer-candidate wire publish attempt complete; ... sent=1 ... outcome=validation-only/not-applied/...`

Sender metrics (`sc4_v0.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1`
- send-failure/no-peer/oversize all `0`.

Receiver log (`sc4_v1.stderr.log`):

- `Run 079: installing live peer-candidate wire dispatcher ...`
- `Run 078: peer-candidate wire frame observed; outcome=validated; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched`

Receiver metrics (`sc4_v1.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 0`.

### 3) Scenario 5 — sender enabled + receiver disabled (cheap-ignore)

Sender metrics (`sc5_v0.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1`

Receiver metrics (`sc5_v1.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 0`
- `...validated_total 0`
- `...rejected_total 0`
- `...disabled_total 0`

This matches the Run 079 no-sink cheap-drop path (frame consumed without validation-side counters).

### 4) Scenario 6 — invalid candidate (wrong-chain envelope), receiver enabled

Sender metrics (`sc6_v0.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 1`

Receiver log (`sc6_v1.stderr.log`):

- `Run 078: peer-candidate wire frame observed; outcome=rejected; NOT applied; ...`

Receiver metrics (`sc6_v1.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 0`.

### 5) Scenario 7 — duplicate case (same candidate sent twice)

Receiver log (`sc7b_v1.stderr.log`):

- first frame: `outcome=validated`
- second frame: `outcome=duplicate-suppressed`

Receiver metrics (`sc7b_v1.metrics`):

- `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total 2`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_duplicate_total 1`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_rate_limited_total 0`.

## Sequence file before/after hashes (non-mutation proof)

Receiver (`/tmp/run081/data_v1/pqc_trust_bundle_sequence.json`) hash remained unchanged:

- before scenarios: `5a6ba1ffb859398bc469c9a49c946f11cd60b5966c53da101f25e8c8751a7023`
- after Scenario 4: same
- after Scenario 5: same
- after Scenario 6: same
- after Scenario 7: same

This proves candidate-wire validation/rejection/duplicate paths did not burn sequence.

## Proof no live reload apply metrics moved

Receiver metrics remained zero in all scenario scrapes:

- `qbind_p2p_trust_bundle_live_reload_trigger_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_success_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_failure_total 0`
- `qbind_p2p_trust_bundle_live_reload_already_in_progress_total 0`
- `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total 0`.

## Proof no session eviction metrics moved

Receiver metrics remained zero:

- `qbind_p2p_session_eviction_attempt_total 0`
- `qbind_p2p_session_eviction_success_total 0`
- `qbind_p2p_session_eviction_failure_total 0`
- `qbind_p2p_session_eviction_sessions_evicted_total 0`.

## Proof sessions remained healthy

Across baseline and all wire scenarios:

- live `P2P transport up` on both peers;
- `newly_connected_peers=1` re-emit line observed on sender in active scenarios;
- cert verification remained healthy (`qbind_p2p_pqc_cert_verify_accepted_total >= 2`, rejected totals all zero in scenario metrics);
- all processes ended by `timeout` (expected bounded-capture shutdown), not by panic/FATAL.

## Fallback / dummy-crypto statements

- No fallback-to-`--p2p-trusted-root` log line observed in scenario logs.
- `Run040` banner shows:
  - `dummy_kem_registered=false`
  - `dummy_aead_registered=false`.

But Run 033 probe line still contains `TrustedClientRoots/DummySig`; therefore this run cannot honestly claim complete “no DummySig” closure.

## Exact remaining C4 boundaries (unchanged by Run 081)

C4 remains open for:

- peer-driven live apply / propagation,
- `activation_epoch` runtime source,
- KMS/HSM custody,
- in-binary/on-chain signing-key ratification,
- production fast-sync / consensus-storage restore,
- per-environment production trust-anchor operation.

Run 081 only narrows the Run 080 sub-piece to live release-binary validation-only `0x05` exchange evidence.

## Immediate next action

Run a focused follow-up that removes/lands the remaining `DummySig`-related timeout-verification boundary on the same N=2 release-binary path (while preserving Run 081 validation-only invariants), then re-capture the same sender/receiver `0x05` evidence matrix to upgrade from partial to strongest positive.

---

## Run 082 follow-up note (2026-05-18) — boundary isolated as probe/log-only

DevNet Evidence Run 082 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_082.md`)
investigated the residual `TrustedClientRoots/DummySig` reference noted
above and classified it as **probe/log-only — stale narrative text inside
a fail-closed `Disabled` outcome**. Specifically, the reference is the
`detail: &'static str` carried by
`TimeoutVerificationDisabledReason::ProductionPiecesUnavailable` at
`crates/qbind-node/src/timeout_verification_bridge.rs:551-555`, reachable
only via `run_031_probe_production_pieces_for_run_p2p_node`. Under the
Run 081 command shape the signer keystore is loaded honestly, so the
binary's `run_032_probe_with_signer` branch is taken and the rendered
`[binary] Run 033: …` `reason=` substring is
`SignerPresentKeyProviderUnavailable { … }` — which does **not** contain
the `DummySig` substring. The Run 031 static text remains in source on
purpose (pinned by the existing
`run_031_probe_today_is_disabled_with_precise_detail` regression-guard
unit test) and is **not** a registration / selection path for any
`Dummy*` primitive. The Run 081 baseline cryptographic-honesty banners
(`[Run040] dummy_kem_registered=false dummy_aead_registered=false`,
`qbind_p2p_pqc_trust_bundle_signature_verified_total=1`,
`qbind_p2p_pqc_cert_verify_accepted_total=2` per node) are unchanged by
Run 082 because Run 082 makes no source changes; it is purely an evidence
isolation and classification artifact. Run 082's verdict is **partial
positive (boundary isolated; no production-active `DummySig` found; live
N=2 matrix rerun deferred)**.