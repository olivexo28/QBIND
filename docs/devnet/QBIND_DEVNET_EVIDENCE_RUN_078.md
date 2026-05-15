# QBIND DevNet Evidence — Run 078

**Date:** 2026-05-15
**Scope (positive narrow):** C4 — production-binary-facing, **disabled-by-default P2P wire receive path** for peer-supplied trust-bundle candidate **validation only**.
**Status:** ⚠️ **OPEN — partial (POSITIVE NARROW C4 sub-piece)** — Run 078 lands the smallest defensible **wire-receive surface** for peer-supplied trust-bundle candidates. Full C4 still OPEN for peer-driven live apply, peer/gossip propagation, admin-API / filesystem-watcher triggers, `activation_epoch` runtime sourcing, selective per-peer session retention, KMS / HSM custody, on-chain signing-key ratification, fast-sync / consensus-storage restore parity, per-environment trust-anchor operation, and the N-node MainNet release-binary peer-connection smoke.

---

## 1. What is narrowed in Run 078

Run 078 closes the smallest defensible **wire-receive surface** piece of the long-standing "peer-supplied / gossiped bundle acceptance remains C4-OPEN" residual previously narrowed by Runs 076 (library-level validator) and 077 (binary-facing local-file fixture check). Before Run 078, the production `qbind-node` binary had **no** decode surface for a peer-supplied trust-bundle candidate frame — there was no wire envelope type, no frame discriminator reservation, no codec, and no receiver. Run 078 lands the safest possible wire-receive foundation:

1. A new module `crates/qbind-node/src/pqc_peer_candidate_wire.rs` that defines:
   - **`PeerCandidateWireEnvelopeV1`** — a strict, log-safe, versioned (`envelope_version = 1`), domain-tagged (`"QBIND:PQC_TRUST_BUNDLE_PEER_CANDIDATE_WIRE:v1"`) wire envelope. **Distinct from the Run 076 / Run 077 local fixture envelope** (`"qbind-peer-trust-bundle-candidate-v0"`): different domain tag, different version namespace, separate type, so a fixture file can never be replayed as a wire frame and vice versa. The `bundle_bytes` field reuses the Run 076 lowercase-hex serde codec (now publicly re-exported as `peer_candidate_bundle_bytes_hex_pub`) so captured wire frames are operator-inspectable with the same tooling as Run 077 fixtures.
   - **`DISCRIMINATOR_PEER_CANDIDATE_WIRE = 0x05`** — a reserved P2P frame discriminator that **does not collide** with the existing `p2p_tcp.rs` consensus (`0x01`), DAG (`0x02`), or control (`0x03`) discriminators (`0x04` is left reserved for any future control-plane extension). The exact same `[discriminator: u8][payload_len: u32-be][payload: payload_len bytes]` length-prefixed framing is reused so any future production gossip dispatcher can route Run 078 frames over the existing KEMTLS-encrypted secure channel with no framing change.
   - **`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES`** — a hard wire-layer cap (`2 × MAX_PEER_CANDIDATE_BUNDLE_BYTES + 16 KiB`) enforced on the **declared** `payload_len` from the 5-byte frame header **before** any allocation, decode, or signature work. An adversary cannot force a large allocation or expensive JSON decode by sending an oversized header.
   - **`encode_peer_candidate_wire_frame` / `decode_peer_candidate_wire_frame`** — strict, fail-closed frame codec. `PeerCandidateWireFrameError` enumerates the seven frame-layer fail-closed boundaries (`FrameTooShort`, `UnknownDiscriminator`, `DeclaredPayloadOversize`, `FrameTruncated`, `PayloadParseError`, `UnsupportedEnvelopeVersion`, `UnknownDomainTag`) with log-safe `Display` impls that include the canonical disclaimer substrings (`live trust state unchanged`, `sequence not persisted`, `sessions untouched`).
   - **`PeerCandidateWireReceiverConfig`** — disabled-by-default wrapper config; `Default::default()` returns `enabled = false`. When `enabled` is `true` on the wrapper, the inner Run 076 `PeerCandidateConfig::enabled` is forced to `true` at construction time so a misconfigured caller cannot accidentally bypass the validator.
   - **`PeerCandidateWireReceiver`** — the disabled-by-default receive handler. Wraps a Run 076 `PeerCandidateValidator` one-to-one. Holds **no** live PQC trust state, **no** session evictor, **no** broadcast handle, **no** admin-API endpoint, **no** filesystem watcher, **no** sequence persistence handle. The receiver's only entry point is `try_handle_frame(frame_bytes, ctx, metrics) -> PeerCandidateWireOutcome`.
   - **`PeerCandidateWireOutcome`** — three-variant return shape (`Disabled`, `FrameRejected(PeerCandidateWireFrameError)`, `ValidatorRan(PeerCandidateOutcome)`). Every variant is non-mutating for live trust state, sequence persistence, and P2P sessions.
   - **`wire_observed_log_line`** — single source of truth for the operator log line; contains the stable substrings `Run 078`, `NOT applied`, `not propagated`, `sequence not persisted`, `live trust state unchanged`, `sessions untouched`.

2. A new hidden CLI flag `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` (disabled by default) in `crates/qbind-node/src/cli.rs` and a one-line banner hook in `crates/qbind-node/src/main.rs` positioned **AFTER** the Run 077 binary-facing local check hook and **BEFORE** the Run 073 process-start reload-apply hook — same staging discipline Run 069 → Run 073 → Run 077 already follow. When the flag is supplied, a single safe banner line is logged so the operator audit trail records the armed state. **The banner is the ONLY behaviour the flag adds to the production startup path in this run.** No new network listener is bound; no new gossip subscription is started; no new admin-API endpoint is exposed; no filesystem watcher is spawned. The wire-receive codec + receiver are library-level types available to a future production gossip dispatcher under a separate review.

3. A new integration test file `crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs` (19 tests, all pass) covering:
   - Disabled-by-default boundary: a default-constructed receiver never decodes the payload, never calls the validator, and bumps only `received_total` + `disabled_total`.
   - Encode/decode roundtrip preserves all envelope fields byte-for-byte.
   - Unknown-discriminator frame (`0x01` consensus discriminator stamped on the first byte) is rejected at the frame layer with `rejected_total` bumped (not `dropped_oversize_total`).
   - Oversize declared payload (`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1`) is dropped BEFORE any allocation / decode / crypto; `dropped_oversize_total` bumped without any scratch file write.
   - Truncated frame, malformed JSON payload, unknown envelope version (`9999`), and unknown domain tag (the Run 076 fixture domain tag stamped onto a wire envelope) each rejected at the frame layer with `rejected_total` (not `dropped_oversize_total`).
   - Enabled + valid higher-sequence candidate validates and is NOT applied — the on-disk sequence file is bit-for-bit unchanged after the success path; no scratch file is left behind; `received_total` AND `validated_total` are each bumped by exactly one; every other peer-candidate counter remains at zero; the operator log line contains the stable disclaimer substrings.
   - Enabled + tampered-signature candidate (first hex nibble of `sig_bytes` flipped post-signing) rejected at the Run 069 loader stage; sequence file bit-for-bit unchanged.
   - Enabled + wrong-environment envelope (claims `Mainnet`, runtime expects `Devnet`) rejected at the envelope pre-check BEFORE any crypto runs.
   - Enabled + wrong-chain-id envelope (`"deadbeefdeadbeef"`) rejected at the envelope pre-check BEFORE any crypto runs.
   - Enabled + duplicate-fingerprint frame: second call short-circuits via the Run 076 LRU without paying ML-DSA verification cost twice; `duplicate_total` bumped.
   - Enabled + rate-limit kicks in after `max_in_window = 1` admissions; `rate_limited_total` bumped.
   - Run 069 reload-check entry point still validates the SAME bundle bytes cleanly AFTER a successful Run 078 wire-receive has seen them.
   - Run 077 binary-facing local fixture check still validates the SAME bundle bytes cleanly AFTER a successful Run 078 wire-receive has seen them; both paths share the same `--data-dir` (and therefore the same sequence persistence path) but neither writes to it.
   - `P2pMetrics::format_metrics()` output rendered after a Run 078 `Validated` outcome contains the seven Run 076 counters but does NOT contain `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` and does NOT contain any `qbind_p2p_pqc_trust_bundle_peer_candidate_wire_*` family.
   - Wire envelope ↔ Run 076 fixture envelope bridge round trip preserves `bundle_bytes` byte-for-byte.
   - The wire-frame cap strictly exceeds the Run 076 inner bundle cap (`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES > MAX_PEER_CANDIDATE_BUNDLE_BYTES`) so a legitimate maximum-sized Run 076 bundle is never dropped at the wire layer.

4. New module unit tests in `crates/qbind-node/src/pqc_peer_candidate_wire.rs::tests` (16 tests, all pass) covering: the frame discriminator non-collision invariant, the encode/decode roundtrip, every frame-layer error variant (short, unknown discriminator, declared-oversize-before-allocation, truncated, unknown version, unknown domain tag, malformed payload), the disabled-by-default short-circuit, the receiver-armed oversize / unknown-version paths, the `PeerCandidateWireReceiverConfig` default, the `PeerCandidateWireReceiver::new` `inner.enabled = enabled` forcing, the disabled-outcome stable log-line shape, and the wire cap / inner cap relationship.

---

## 2. What is NOT narrowed and what remains C4-OPEN

Run 078 is **not** peer-driven live apply — the receiver has no apply function and `LivePqcTrustState` is untouched on every return path (the strict library-level non-mutation boundary inherited from Run 076 is the entire point of Run 078). Run 078 is **not** a peer/gossip propagation surface — the receiver never re-broadcasts; the candidate is end-of-line at the receiver. Run 078 is **not** an admin-API trigger or filesystem-watcher hot reload — Run 074's SIGHUP-only trigger surface is unchanged; Run 078 adds **no** new trigger surface. Run 078 is **not** a production gossip subscription — no Run 078 code path *publishes* a peer-candidate frame on the wire today; no `P2pMessage` variant is added; no `TcpKemTlsP2pService` read loop is modified; no `qbind-net` handshake is changed. The wire codec + receiver are library-level types only, and the binary banner hook is the only operator-visible production-binary surface added by Run 078. Run 078 is **not** a change to startup trust-bundle validation, Run 069 reload-check, Run 070 apply contract, Run 071 `LivePqcTrustState`, Run 072 session-evictor, Run 073 `ProductionLiveTrustApplyContext`, Run 074 `LiveReloadController`, Run 076 library-level peer-candidate validator, or Run 077 binary-facing local check — all eight are bit-for-bit unchanged (12/12 Run 069, 13/13 Run 070, 10/10 Run 073, 10/10 Run 074, 16/16 Run 076, and 12/12 Run 077 integration tests continue to pass after Run 078 lands). Run 078 is **not** `activation_epoch` runtime sourcing (unchanged from Run 057; bundles that declare `activation_epoch` continue to fail closed via the inherited loader). Run 078 is **not** KMS / HSM custody. Run 078 is **not** bundle-signing-key on-chain / in-binary ratification. Run 078 is **not** fast-sync / consensus-storage restore parity. Run 078 is **not** selective per-peer session retention. Run 078 is **not** the N-node MainNet release-binary peer-connection smoke. **Full C4 remains OPEN** on all of the above items.

---

## 3. Files changed

| File | Purpose |
|---|---|
| `crates/qbind-node/src/pqc_peer_candidate_wire.rs` (new) | Run 078 wire envelope v1, frame codec, receiver, `PeerCandidateWireOutcome`, `wire_observed_log_line`, 16 module unit tests. |
| `crates/qbind-node/src/pqc_trust_peer_candidate.rs` | Public re-export `peer_candidate_bundle_bytes_hex_pub` of the existing Run 076 lowercase-hex `bundle_bytes` serde codec so the Run 078 wire envelope can reuse it (NO change to Run 076 behaviour, NO change to existing fixture format, NO change to existing Run 076 tests — 16 module unit tests + 16 integration tests still pass). |
| `crates/qbind-node/src/lib.rs` | Register `pub mod pqc_peer_candidate_wire`. |
| `crates/qbind-node/src/cli.rs` | New hidden CLI flag `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` (disabled by default). |
| `crates/qbind-node/src/main.rs` | New Run 078 banner hook positioned AFTER the Run 077 hook and BEFORE the Run 073 hook. When the flag is unset, the hook is byte-for-byte silent. When the flag is set, a single safe banner line records the armed state. |
| `crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs` (new) | 19 Run 078 integration tests covering the full coverage matrix. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_078.md` (this file) | Evidence document for Run 078. |
| `docs/whitepaper/contradiction.md` | New C4 Run 078 evidence-update entry. |

No `Cargo.toml` was touched; no new dependency was introduced; no `Dummy*` primitive was added, strengthened, or referenced; no classical signature surface was introduced (suite 100 / ML-DSA-44 only on the bundle layer continues to be the only signing surface); no transport-root reuse as a bundle-signing authority; no protocol / wire-format / consensus / forged-traffic / KEMTLS change in production code paths (the new `0x05` discriminator is a *reservation*, not an active production publisher); no removal or modification of any existing test (only additions, plus a strictly mechanical public re-export of an existing private serde codec).

---

## 4. Test commands and results

```
$ cargo test -p qbind-node --lib pqc_peer_candidate_wire
running 16 tests
test pqc_peer_candidate_wire::tests::run078_decode_rejects_declared_oversize_before_allocation ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_short_frame ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_truncated_frame ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_malformed_payload ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_unknown_discriminator ... ok
test pqc_peer_candidate_wire::tests::run078_max_frame_cap_strictly_greater_than_inner_bundle_cap ... ok
test pqc_peer_candidate_wire::tests::run078_discriminator_does_not_collide_with_p2p_tcp_discriminators ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_unknown_domain_tag ... ok
test pqc_peer_candidate_wire::tests::run078_decode_rejects_unknown_version ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_config_default_is_disabled ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_disabled_by_default_short_circuits_without_decoding ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_enabled_oversize_frame_drops_before_validator ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_disabled_outcome_label ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_new_forces_inner_enabled_to_match ... ok
test pqc_peer_candidate_wire::tests::run078_receiver_enabled_unknown_version_frame_rejected_not_oversize ... ok
test pqc_peer_candidate_wire::tests::run078_wire_envelope_roundtrip ... ok
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 1033 filtered out

$ cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
running 19 tests
test run078_disabled_by_default_does_not_decode_or_call_validator ... ok
test run078_coexists_with_run077_binary_local_check_path ... ok
test run078_malformed_payload_rejected_at_frame_layer ... ok
test run078_does_not_affect_run069_reload_check_path ... ok
test run078_duplicate_fingerprint_frame_short_circuits_via_lru ... ok
test run078_oversize_declared_payload_dropped_before_allocation ... ok
test run078_truncated_frame_rejected_at_frame_layer ... ok
test run078_tampered_signature_candidate_rejected_at_loader ... ok
test run078_metrics_output_never_contains_applied_total_family ... ok
test run078_rate_limit_triggers_after_max_in_window ... ok
test run078_unknown_discriminator_rejected_at_frame_layer ... ok
test run078_wire_envelope_bridge_to_run076_fixture_preserves_fields ... ok
test run078_wire_envelope_roundtrip_preserves_all_fields ... ok
test run078_wire_frame_cap_strictly_exceeds_run076_bundle_cap ... ok
test run078_unknown_domain_tag_rejected_at_frame_layer ... ok
test run078_unknown_envelope_version_rejected_at_frame_layer ... ok
test run078_wrong_chain_id_envelope_rejected_pre_crypto ... ok
test run078_wrong_environment_envelope_rejected_pre_crypto ... ok
test run078_valid_candidate_validates_but_is_not_applied ... ok
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**Regression suites all green after Run 078 lands:**

```
$ cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests   → 12/12 pass
$ cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests   → 13/13 pass
$ cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests  → 10/10 pass
$ cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests    → 10/10 pass
$ cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests   → 16/16 pass
$ cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests     → 12/12 pass
$ cargo test -p qbind-node --lib pqc_trust_peer_candidate                       → 16/16 pass
$ cargo test -p qbind-node --lib pqc_peer_candidate_binary                      → 11/11 pass
$ cargo test -p qbind-node --lib metrics                                        → 114/114 pass
```

---

## 5. Anchoring

The wire receive surface is anchored in `crates/qbind-node/src/pqc_peer_candidate_wire.rs` (16 module unit tests in the same file, 19 integration tests in `crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs`). The reuse-not-fork discipline is anchored at `pqc_peer_candidate_wire::PeerCandidateWireReceiver::try_handle_frame` where the inner call is the SAME `pqc_trust_peer_candidate::PeerCandidateValidator::try_accept` (Run 076) whose inner call is in turn the SAME `pqc_trust_reload::validate_candidate_bundle_full` (Run 069) that startup, the local reload-check, Run 073 process-start apply, Run 074 SIGHUP live reload-apply, and Run 077 binary-facing local check all use. The non-mutation contract is anchored verbatim by `run078_valid_candidate_validates_but_is_not_applied` (calls `assert_seq_file_unchanged` AFTER the success path), `run078_oversize_declared_payload_dropped_before_allocation` (asserts `dropped_oversize_total` bumped and no scratch file written), `run078_unknown_discriminator_rejected_at_frame_layer`, `run078_unknown_domain_tag_rejected_at_frame_layer`, `run078_tampered_signature_candidate_rejected_at_loader`, `run078_does_not_affect_run069_reload_check_path`, and `run078_coexists_with_run077_binary_local_check_path` (proves the Run 069 reload-check and Run 077 binary-facing local check entry points still validate the same bundle cleanly after Run 078 has seen it, even when all three share the same `--data-dir` and the SAME sequence-persistence path). The intentional absence of an `_applied_total` family **and** the intentional absence of any new `peer_candidate_wire_*` metric family are anchored by `run078_metrics_output_never_contains_applied_total_family` (explicit `format_metrics()` substring assertion). The disabled-by-default boundary is anchored by `run078_disabled_by_default_does_not_decode_or_call_validator` (default-constructed receiver short-circuits on the cheap discriminator-check path and never decodes the payload) and by `PeerCandidateWireReceiverConfig::default()` returning `enabled = false`.

---

## 6. Banners

Run 040 banner `dummy_kem_registered=false dummy_aead_registered=false` continues to hold (no `Dummy*` primitive added, strengthened, or referenced in Run 078). Run 050 trust-separation invariant (`signing_key_id` ≠ any `roots[i].root_id`) continues to hold (Run 078 inherits via the unchanged `validate_candidate_bundle_full` path). Run 069/070/071/072/073/074/076/077 entry points are all bit-for-bit unchanged.

---

## 7. No-fallback / no-mutation proof (Run 078)

No new dependency is introduced (no `Cargo.toml` change). No new metric family is added — the seven existing Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters are the only `/metrics` surface bumped by the wire path, and `run078_metrics_output_never_contains_applied_total_family` asserts both that `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` does **not** appear and that no `qbind_p2p_pqc_trust_bundle_peer_candidate_wire_*` family appears. No `Dummy*` primitive is referenced or re-activated. No transport-root reuse as a bundle-signing authority (Run 078 inherits the Run 050 trust-separation invariant via the unchanged `validate_candidate_bundle_full` path). No `--p2p-trusted-root` fallback path is added — Run 078 introduces only one new hidden CLI flag (`--p2p-trust-bundle-peer-candidate-wire-validation-enabled`) which on its own only flips the operator banner. No Run 069 entry point is modified (12/12 integration tests continue to pass after Run 078 lands; `run078_does_not_affect_run069_reload_check_path` exercises both paths in the same test). No Run 070 entry point is modified (`ApplyMode`, `ReloadApplyError`, `LiveTrustApplyContext`, `apply_validated_candidate{,_with_previous}` are bit-for-bit unchanged; 13/13 Run 070 integration tests continue to pass). No Run 071 entry point is modified. No Run 072 entry point is modified (the four `qbind_p2p_session_eviction_*` counters are bit-for-bit unchanged). No Run 073 entry point is modified (`ProductionLiveTrustApplyContext`, `NoActiveSessionsEvictor`, and the at-startup-time `--p2p-trust-bundle-reload-apply-path` hook are bit-for-bit unchanged; 10/10 Run 073 integration tests continue to pass). No Run 074 entry point is modified (`LiveReloadController`, `LiveReloadOutcome`, `spawn_run074_live_reload_task`, and the six `qbind_p2p_trust_bundle_live_reload_*` counters/gauge are bit-for-bit unchanged; 10/10 Run 074 integration tests continue to pass). No Run 076 entry point is modified (`PeerCandidateValidator::try_accept` and the seven `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters are bit-for-bit unchanged; 16/16 integration tests + 16 module unit tests continue to pass; the public re-export of the existing `peer_candidate_bundle_bytes_hex` serde codec is a strictly mechanical visibility change with no behavioural impact). No Run 077 entry point is modified (`run_local_check`, `Run077Inputs`, `Run077Result`, `Run077RefusalReason`, the binary-facing local check hook, and the canonical Run 077 `VERDICT=...` log line are bit-for-bit unchanged; 12/12 integration tests + 11 module unit tests continue to pass; `run078_coexists_with_run077_binary_local_check_path` proves Run 077 still validates the same bundle cleanly after Run 078 has seen it). The Run 050–077 §10 boundaries are preserved bit-for-bit: rejected wire frames do NOT advance the persisted highest sequence (proven by every `assert_seq_file_unchanged` call in the Run 078 integration suite); the receiver does NOT mutate `LivePqcTrustState` (proven by construction — the type holds no live-state handle); idempotent re-acceptance of the same bytes does NOT pay ML-DSA verification cost twice (proven by `run078_duplicate_fingerprint_frame_short_circuits_via_lru`); rate-limited or oversized frames do NOT touch the disk-side scratch (proven by `count_scratch_files(...) == 0` assertions in those tests); the disabled-by-default short-circuit guarantees zero side effects when the receiver is constructed by `PeerCandidateWireReceiver::disabled()` (proven by `run078_disabled_by_default_does_not_decode_or_call_validator`). **No fabricated metric** (there is no `_applied_total` because the receiver never applies; there is no `peer_candidate_wire_*` because Run 078 reuses the Run 076 counters), **no silent regression**, **no protocol behaviour change** (the production binary does not publish or subscribe to `0x05` frames in this run; the discriminator is reserved, not actively wired into any existing P2P read loop), **no removed tests**, **no `DummySig` / `DummyKem` / `DummyAead` fallback path introduced or strengthened**, **no transport-root reuse as bundle-signing authority**, **no classical signatures introduced**, **no `--p2p-trusted-root` fallback when `--p2p-trust-bundle` is absent**, **no admin-API / network listener added**, **no peer/gossip subscription added**, and **no private-key material referenced by `PeerCandidateWireEnvelopeV1`, `PeerCandidateWireReceiverConfig`, `PeerCandidateWireReceiver`, `PeerCandidateWireOutcome`, or any Run 078 log line** are introduced by Run 078.