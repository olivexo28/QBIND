# QBIND DevNet Evidence — Run 085

## Exact objective

Produce N=4 MainNet-mode, release-binary, validation-only peer-candidate `0x05` evidence by extending the committed Run 084 harness pattern, without adding peer-driven live apply, propagation/rebroadcast, activation_epoch, KMS/HSM, signing-key ratification, fast-sync restore, KEMTLS redesign, consensus redesign, or any broad redesign.

## Exact verdict

**Strongest positive for the scoped Run 085 evidence objective.**

The committed harness `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh` ran successfully from commit `c28b70b0aa72cb34bd343dfa58fcdb2e476e3ea6`. It built/used release binaries, recorded sha256 + ELF BuildID, minted signed N=4 MainNet trust-bundle material, minted consensus signer keystores, launched four release `qbind-node` processes with `--env mainnet`, explicit trust-bundle signing key, per-node data dirs, peer leaf mappings, and no `--p2p-trusted-root` fallback, then exercised all required `0x05` scenarios.

All required N=4 MainNet scenarios passed:

- baseline N=4 MainNet startup;
- valid `0x05` send/validate;
- receiver-disabled cheap-ignore;
- invalid/wrong-chain candidate reject;
- duplicate suppression.

Full C4 and C5 are **not** claimed closed.

## Exact files changed

- `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh` (new evidence harness)
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_085.md` (new evidence file)
- `docs/devnet/run_085_mainnet_peer_candidate_0x05_matrix/` (archived Run 085 metrics, logs, envelopes, sequence hashes, summary)
- `docs/whitepaper/contradiction.md` (C4 Run 085 evidence update)

No production peer-candidate feature, propagation path, peer-driven live apply path, activation-epoch source, KMS/HSM path, signing-key ratification, fast-sync restore, KEMTLS redesign, or consensus redesign was added.

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
scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh /tmp/qbind-run085-mainnet-peer-candidate-0x05-matrix
```

The final passing harness run archived artifacts under `docs/devnet/run_085_mainnet_peer_candidate_0x05_matrix/`.

### Required post-change commands

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

## Tests / evidence pass/fail status

Baseline commands before editing all passed:

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

Run 085 final harness: **pass**.

Post-change regression/build commands all passed after the harness/documentation/archive updates:

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

## Binary/helper identities

Final Run 085 harness run:

- command: `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh /tmp/qbind-run085-mainnet-peer-candidate-0x05-matrix`
- repo: `/home/runner/work/QBIND/QBIND`
- harness commit at run time: `c28b70b0aa72cb34bd343dfa58fcdb2e476e3ea6`
- artifact directory: `/tmp/qbind-run085-mainnet-peer-candidate-0x05-matrix`
- committed archive: `docs/devnet/run_085_mainnet_peer_candidate_0x05_matrix/`

| Artifact | sha256 | ELF BuildID |
|---|---|---|
| `target/release/qbind-node` | `d28c5493d3782dea5a20b03449eb01ab582f69c32e36d0a657c5f356fdb2ca49` | `c7ae28418d107f7e467fd4346f85644e6fcd943a` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `39b4a9a5d61aa3c3c0117ceefe5849d087f13e0ee5024b90d95ebaeb08076efb` | `5050ded02408a3a27d1eccc382a5f48fa47b2501` |
| `target/release/examples/devnet_pqc_root_helper` | `58298104e52b687d28d6ca5a0606f54191cad28a84f2b8cda896a43dbbe005e4` | `7e514ca79e45bea41d743266f3224f631769902f` |
| `target/release/examples/devnet_consensus_signer_keystore_helper` | `18f455bd0e8891381ee00dd31472beade2409d843ddae25fcf327843620d8b4c` | `ebb61100054d043ad0e0d2dc4272968641233f38` |

## N=4 MainNet material procedure

The harness mints:

- signed MainNet trust bundle: `devnet_pqc_trust_bundle_helper <outdir>/material 4 signed-mainnet 1`;
- consensus signer keystores: `devnet_consensus_signer_keystore_helper <outdir>/signers 4`;
- per-node leaf cert/key material: `<outdir>/material/v{0..3}.cert.bin` and `v{0..3}.kem.sk.bin`;
- explicit per-node `--p2p-peer VID@127.0.0.1:PORT` entries and `--p2p-peer-leaf-cert VID:PATH` mappings;
- explicit `--p2p-trust-bundle-signing-key` from `material/signing-key.spec`;
- no `--p2p-trusted-root` argument.

`chain_id` used: `51424e444d41494e` (`QRNDMAIN` domain bytes as emitted by the MainNet fixture).

Trust-bundle signature proof appears in each baseline node log, for example:

```text
[binary] Run 050/051: trust bundle loaded ... env=mainnet ... sequence=1 ... signature=verified(signing_key_id=14480f43..) signing_keys_configured=1
```

Sequence persisted as `sequence=1` in all four data dirs during baseline startup.

## Run033 / Run040 lines

The archive contains `docs/devnet/run_085_mainnet_peer_candidate_0x05_matrix/run033_run040_lines.txt`.

Representative Run040 line:

```text
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

Representative Run033 lines:

```text
[binary] Run 033: SuiteAwareValidatorKeyProvider built honestly — loaded(validators=4,...suite_ids=[100]...)
[binary] Run 033: timeout-verification probe: active=true reason=n/a policy=OptionalActivate validators=4 chain_id=chain_51424e444d41494e ... local_signer=loaded(...) peer_key_provider=loaded(...)
[binary] Run 033: timeout verification ACTIVE ... signer_loaded=1 key_provider_loaded=1 validator_count=4
```

## Baseline N=4 MainNet startup evidence

All four nodes started with the signed MainNet trust bundle and reached `P2P transport up`.

| Node | cert accepted | cert rejected | committed height |
|---|---:|---:|---:|
| v0 | 6 | 0 | 1 |
| v1 | 6 | 0 | 3 |
| v2 | 6 | 0 | 3 |
| v3 | 6 | 0 | 4 |

All four logs show `env=mainnet`, `signature=verified(...)`, `sequence=1`, and Run033 `active=true reason=n/a` with four real consensus signer keys.

## Valid `0x05` send/validate evidence

Scenario files: `metrics/valid_v0.metrics`, `metrics/valid_v1.metrics`, `sequence/valid.*.sha256`, and `peer_candidate_lines.txt`.

- sender v0: `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total 3`
- receiver v1: `received_total 1`, `validated_total 1`, `rejected_total 0`, `sent_total 0`
- logs include `outcome=validation-only/not-applied/not-propagated/no-sequence-write/no-session-eviction`
- logs include `outcome=validated; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched`
- all sequence hashes unchanged before/after
- live reload apply metrics stayed zero
- session eviction metrics stayed zero
- sessions stayed healthy with cert accepted counters non-zero and rejected counters zero
- no propagation/rebroadcast from non-senders (`sent_total=0` on v1/v2/v3)

## Receiver-disabled evidence

Scenario files: `metrics/receiver_disabled_v0.metrics`, `metrics/receiver_disabled_v1.metrics`, `sequence/receiver_disabled.*.sha256`.

- sender v0: `sent_total 3`
- receiver v1: `received_total 0`, `validated_total 0`, `rejected_total 0`, `duplicate_total 0`, `sent_total 0`
- connection remained healthy with `qbind_p2p_pqc_cert_verify_accepted_total 6` and `qbind_p2p_pqc_cert_verify_rejected_total 0` on v1
- all sequence hashes unchanged before/after
- live reload apply metrics stayed zero
- session eviction metrics stayed zero

## Invalid/wrong-chain evidence

Scenario files: `metrics/invalid_wrong_chain_v0.metrics`, `metrics/invalid_wrong_chain_v1.metrics`, `sequence/invalid_wrong_chain.*.sha256`, and `peer_candidate_lines.txt`.

- sender v0: `sent_total 3`
- receiver v1: `received_total 1`, `validated_total 0`, `rejected_total 1`, `sent_total 0`
- logs include `outcome=rejected; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched`
- all sequence hashes unchanged before/after
- live reload apply metrics stayed zero
- session eviction metrics stayed zero
- sessions stayed healthy

## Duplicate evidence

Scenario files: `metrics/duplicate_v1.metrics`, `sequence/duplicate.*.sha256`, and `peer_candidate_lines.txt`.

- receiver v1: `received_total 2`, `validated_total 1`, `duplicate_total 1`, `rejected_total 0`, `sent_total 0`
- logs include `outcome=duplicate-suppressed; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched`
- all sequence hashes unchanged before/after
- live reload apply metrics stayed zero
- session eviction metrics stayed zero
- sessions stayed healthy

## Sequence file before/after hashes

For all candidate scenarios (`valid`, `receiver_disabled`, `invalid_wrong_chain`, `duplicate`), every `sequence/*.before.sha256` hash equals the matching `sequence/*.after.sha256` hash. Representative hashes:

- v0/v1: `153a1a946d6498256c0295f320809ab1c0702844f9917ba1ee1c6c64d92a48c1` before/after in all candidate scenarios
- v2/v3: `3d83e30c8ac3f81435d2372b3d7362e687632ad99e46e9f189cfd89ee1bceccf` before/after in all candidate scenarios

## Live reload apply metrics proof

The harness asserts these remain zero on every scraped node in every scenario:

- `qbind_p2p_trust_bundle_live_reload_trigger_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_success_total 0`
- `qbind_p2p_trust_bundle_live_reload_apply_failure_total 0`
- `qbind_p2p_trust_bundle_live_reload_already_in_progress_total 0`
- `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total 0`

## Session eviction metrics proof

The harness asserts these remain zero on every scraped node in every scenario:

- `qbind_p2p_session_eviction_attempt_total 0`
- `qbind_p2p_session_eviction_success_total 0`
- `qbind_p2p_session_eviction_failure_total 0`
- `qbind_p2p_session_eviction_sessions_evicted_total 0`

## Session / peer health evidence

Each asserted node in each scenario had `P2P transport up`, non-zero accepted cert counters, and `qbind_p2p_pqc_cert_verify_rejected_total 0`. Baseline N=4 committed-height gauges advanced to at least 1 on all four nodes.

## Proof no active DummySig / DummyKem / DummyAead

The final archive logs contain no `DummySig`, `DummyKem`, `DummyAead`, `dummy_kem_registered=true`, or `dummy_aead_registered=true` matches. Run040 lines show `dummy_kem_registered=false`, `dummy_aead_registered=false`, `transport_kem_suite_name=ml-kem-768`, and `transport_aead_suite_name=chacha20-poly1305`. Run033 lines show `active=true reason=n/a` with loaded signer and key provider for four validators.

## Proof no `--p2p-trusted-root` fallback

The harness never passes `--p2p-trusted-root`; it uses only `--p2p-trust-bundle` plus `--p2p-trust-bundle-signing-key`. The final archive logs contain no `--p2p-trusted-root` fallback matches.

## Exact remaining C4 boundaries

Run 085 narrows C4 to include N=4 MainNet release-binary peer-candidate validation evidence, but C4 remains open for:

- peer-driven live apply / propagation;
- `activation_epoch` runtime source;
- KMS/HSM custody;
- in-binary/on-chain signing-key ratification;
- production fast-sync / consensus-storage restore;
- per-environment production trust-anchor operation;
- broader production KEMTLS lifecycle/readiness boundaries still tracked by C4.

C5 remains open; Run 085 only reuses existing Run033 timeout-verification activation evidence to avoid DummySig ambiguity in this matrix.

## contradiction.md update

`docs/whitepaper/contradiction.md` was updated because Run 085 changes the C4 evidence state: N=4 MainNet release-binary peer-candidate `0x05` validation-only matrix now passes from a committed harness. The update narrows C4 but does not close full C4 or C5.

## Immediate next action

Use `scripts/devnet/run_085_mainnet_peer_candidate_0x05_matrix.sh` as the repeatable N=4 MainNet validation-only regression harness. The next scoped task should address peer-driven live apply / propagation only if explicitly requested.