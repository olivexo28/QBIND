# QBIND DevNet Evidence — Run 084

## Exact objective

Commit a repeatable release-binary N=2 orchestration harness for the peer-candidate `0x05` matrix, then use it to rerun the Run 081/083 matrix end-to-end inside the repository scope only.

## Exact verdict

**Strongest positive for the Run 081/082/083 evidence gap.**

Run 084 adds `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh` and executes it successfully from the committed harness revision `8170189975d21673eb0986c8d7f209f3befb0d92`. The harness builds release binaries, records sha256 + ELF BuildID, mints signed N=2 DevNet trust-bundle material, mints DevNet consensus signer keystores for the Run 033 proof, generates valid / wrong-chain / duplicate candidate envelopes, starts two release `qbind-node` processes over loopback, scrapes `/metrics`, captures stderr logs, captures `[Run040]` + `[binary] Run 033` lines, hashes the receiver sequence file before/after each scenario, and asserts the requested invariants.

All live release-binary N=2 scenarios pass:

- baseline N=2 signed-bundle startup;
- valid `0x05` send + receiver validation;
- receiver-disabled cheap-ignore;
- invalid/wrong-chain candidate reject;
- duplicate suppression.

Full C4 and C5 are **not** claimed closed.

## Exact files changed

- `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh` (new harness)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_084.md` (new evidence file)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md` (Run 084 follow-up note)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_083.md` (Run 084 follow-up note)
- `docs/whitepaper/contradiction.md` (C4 Run 084 evidence update)

No peer-candidate protocol feature, propagation path, peer-driven live apply path, activation-epoch source, KMS/HSM path, signing-key ratification, fast-sync restore, KEMTLS redesign, or consensus redesign was added.

## Binary/helper identities

Run 084 final harness run:

- command: `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh /tmp/qbind-run084-peer-candidate-0x05-matrix`
- repo: `/home/runner/work/QBIND/QBIND`
- harness commit at run time: `8170189975d21673eb0986c8d7f209f3befb0d92`
- artifact directory: `/tmp/qbind-run084-peer-candidate-0x05-matrix`

| Artifact | sha256 | ELF BuildID |
|---|---|---|
| `target/release/qbind-node` | `d28c5493d3782dea5a20b03449eb01ab582f69c32e36d0a657c5f356fdb2ca49` | `c7ae28418d107f7e467fd4346f85644e6fcd943a` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `39b4a9a5d61aa3c3c0117ceefe5849d087f13e0ee5024b90d95ebaeb08076efb` | `5050ded02408a3a27d1eccc382a5f48fa47b2501` |
| `target/release/examples/devnet_pqc_root_helper` | `58298104e52b687d28d6ca5a0606f54191cad28a84f2b8cda896a43dbbe005e4` | `7e514ca79e45bea41d743266f3224f631769902f` |
| `target/release/examples/devnet_consensus_signer_keystore_helper` | `18f455bd0e8891381ee00dd31472beade2409d843ddae25fcf327843620d8b4c` | `ebb61100054d043ad0e0d2dc4272968641233f38` |

The consensus signer helper is an existing DevNet evidence helper used by the Run 084 harness to make the Run 033 timeout-verification proof active and remove the previous log-only DummySig ambiguity. It does not add production custody or KMS/HSM functionality.

## Exact commands run

### Required baseline commands before editing

```text
cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
cargo test -p qbind-node --lib pqc_peer_candidate_wire
cargo test -p qbind-node --lib metrics::tests::peer_candidate_send_metrics
cargo test -p qbind-node --lib
cargo test -p qbind-net --lib
cargo test -p qbind-crypto --lib
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper
cargo build --release -p qbind-node --example devnet_pqc_root_helper
```

### Harness commands

```text
scripts/devnet/run_084_peer_candidate_0x05_matrix.sh /tmp/qbind-run084-peer-candidate-0x05-matrix
```

The first harness iteration intentionally failed its own no-Dummy assertion because the Run 033 line still took the no-signer/no-key-provider disabled probe path and rendered the stale `TrustedClientRoots/DummySig` detail. The harness was then tightened to mint DevNet consensus signer keystores and pass both `--signer-keystore-path` and all `--validator-consensus-key VID:100:HEXPK` entries. The final two harness executions passed; the binding final artifact set is from commit `8170189975d21673eb0986c8d7f209f3befb0d92`.

### Required post-change commands

Post-change required regression/build commands were rerun after the harness and documentation edits; all passed with the same pass counts as the baseline run (3/3, 11/11, 19/19, 12/12, 16/16, 28/28 selected, 2/2 selected, 1063/1063, 17/17, 68/68) and all required release builds completed successfully.

## Test / evidence pass/fail status

### Baseline regression commands before editing

All required baseline commands passed:

- `run_080_pqc_peer_candidate_wire_send_tests`: 3/3 pass
- `run_079_pqc_peer_candidate_wire_live_dispatch_tests`: 11/11 pass
- `run_078_pqc_peer_candidate_wire_tests`: 19/19 pass
- `run_077_binary_peer_candidate_check_tests`: 12/12 pass
- `run_076_pqc_peer_candidate_validation_tests`: 16/16 pass
- `qbind-node --lib pqc_peer_candidate_wire`: 28/28 pass
- `qbind-node --lib metrics::tests::peer_candidate_send_metrics`: 2/2 pass
- `qbind-node --lib`: 1063/1063 pass
- `qbind-net --lib`: 17/17 pass
- `qbind-crypto --lib`: 68/68 pass
- required release builds: pass


### Required regression/build commands after edits

All required post-change commands passed:

- `run_080_pqc_peer_candidate_wire_send_tests`: 3/3 pass
- `run_079_pqc_peer_candidate_wire_live_dispatch_tests`: 11/11 pass
- `run_078_pqc_peer_candidate_wire_tests`: 19/19 pass
- `run_077_binary_peer_candidate_check_tests`: 12/12 pass
- `run_076_pqc_peer_candidate_validation_tests`: 16/16 pass
- `qbind-node --lib pqc_peer_candidate_wire`: 28/28 pass
- `qbind-node --lib metrics::tests::peer_candidate_send_metrics`: 2/2 pass
- `qbind-node --lib`: 1063/1063 pass
- `qbind-net --lib`: 17/17 pass
- `qbind-crypto --lib`: 68/68 pass
- required release builds: pass

### Live release-binary N=2 matrix

| Scenario | Status | Key evidence |
|---|---|---|
| Baseline N=2 startup | **pass** | both nodes reached `P2P transport up`; cert accepted counters non-zero, rejected counters zero |
| Valid `0x05` send/validate | **pass** | sender `sent_total=1`; receiver `received_total=1`, `validated_total=1`, `rejected_total=0` |
| Receiver-disabled cheap-ignore | **pass** | sender `sent_total=1`; receiver `received_total=0`, `validated_total=0`, `rejected_total=0`, `duplicate_total=0` |
| Invalid/wrong-chain reject | **pass** | sender `sent_total=1`; receiver `received_total=1`, `rejected_total=1`, `validated_total=0` |
| Duplicate suppression | **pass** | receiver `received_total=2`, `validated_total=1`, `duplicate_total=1` |

Receiver sequence-file hash stayed unchanged across every candidate scenario:

- `f7782b7fe20b395722fddd114c1baa73c4efb889fc75e2d7ef488c3b44124cb4` before/after valid;
- same hash before/after receiver-disabled;
- same hash before/after invalid/wrong-chain;
- same hash before/after duplicate.

Live-reload apply metrics remained zero in every receiver scrape:

- `qbind_p2p_trust_bundle_live_reload_trigger_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_success_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_failure_total 0`
- `qbind_p2p_trust_bundle_live_reload_already_in_progress_total 0`
- `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total 0`

Session-eviction metrics remained zero in every receiver scrape:

- `qbind_p2p_session_eviction_attempt_total 0`
- `qbind_p2p_session_eviction_success_total 0`
- `qbind_p2p_session_eviction_failure_total 0`
- `qbind_p2p_session_eviction_sessions_evicted_total 0`

Sessions remained healthy: every scenario had `P2P transport up`, `qbind_p2p_pqc_cert_verify_accepted_total >= 1`, and `qbind_p2p_pqc_cert_verify_rejected_total 0` on the asserted nodes.

## Run033 / Run040 proof

The final harness run captures `[Run040]` lines with:

```text
pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

The final harness run captures `[binary] Run 033` lines with:

```text
SuiteAwareValidatorKeyProvider built honestly
Run 033: timeout-verification probe: active=true reason=n/a ... local_signer=loaded(...) peer_key_provider=loaded(...)
Run 033: timeout verification ACTIVE ... signer_loaded=1 key_provider_loaded=1 validator_count=2
```

No runtime log in the final harness artifact contains `DummySig`, `DummyKem`, `DummyAead`, `dummy_kem_registered=true`, `dummy_aead_registered=true`, or a `--p2p-trusted-root` fallback line. The previous Run 081/082/083 DummySig ambiguity is therefore closed for this N=2 release-binary matrix by using real DevNet consensus signer material and explicit per-validator consensus public-key distribution in the harness.

## What was proven

Run 084 proves, on release binaries driven by committed repo harness code:

1. the N=2 `pqc-static-root` live P2P path starts over loopback with signed trust-bundle material;
2. valid `0x05` peer-candidate frames validate and remain validation-only;
3. receiver-disabled runs cheap-ignore without validation counters;
4. invalid/wrong-chain candidate frames reject;
5. duplicate candidate frames suppress;
6. candidate validation/rejection/duplicate paths do not rewrite the receiver sequence file;
7. live-reload apply metrics remain zero;
8. session-eviction metrics remain zero;
9. sessions remain healthy;
10. no `--p2p-trusted-root` fallback occurs;
11. no active `DummySig`, `DummyKem`, or `DummyAead` is present;
12. no peer-driven apply or propagation occurs.

## What remains not solved

Run 084 does **not** solve or implement:

- peer-driven live apply;
- peer/gossip propagation;
- `activation_epoch` runtime sourcing;
- KMS/HSM custody;
- signing-key ratification;
- fast-sync restore;
- production per-environment trust-anchor operations;
- N-node MainNet peer-connection smoke;
- full C4 closure;
- C5 closure.

## contradiction.md update

`docs/whitepaper/contradiction.md` was updated because Run 084 changes the C4 evidence state: the previously deferred, uncommitted release-binary N=2 `0x05` matrix harness now exists in the repository and passes end-to-end. The update narrows the peer-candidate evidence gap but keeps full C4 and C5 open for the explicit remaining production features above.

## Immediate next action

Use `scripts/devnet/run_084_peer_candidate_0x05_matrix.sh` as the repeatable regression harness for future peer-candidate changes, and only proceed to a separate scoped task for peer-driven live apply / propagation if that feature is explicitly requested.