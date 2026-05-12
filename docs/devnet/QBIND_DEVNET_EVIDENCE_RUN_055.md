# QBIND DevNet Evidence — Run 055: Trust-Bundle Sequence-Number Monotonicity Persistence Across Restarts

## Exact objective

Run 055 closes the explicit "sequence-number monotonicity
persistence across restarts" C4 boundary that Runs 050, 051, 052,
and 054 each recorded as remaining-open. It adds a persistent,
atomically-written JSON record under
`<data_dir>/pqc_trust_bundle_sequence.json` that captures the
highest signed-bundle `sequence` accepted on this node for the
runtime `(environment, chain_id)` trust domain, together with the
corresponding canonical bundle fingerprint, and wires that record
into the live `--p2p-trust-bundle` startup path AFTER the existing
Run 051 ML-DSA-44 signature verification + Run 053 chain-id
crosscheck + Run 050 root status/window/revocation filtering, BUT
BEFORE any bundle root is merged into the live PQC trust set.

The scope is intentionally narrow:

- prove a strictly higher `sequence` is accepted and persisted;
- prove a strictly lower `sequence` is rejected as a rollback;
- prove an equal `sequence` with the same canonical fingerprint is
  accepted as a no-op restart (no record rewrite);
- prove an equal `sequence` with a different canonical fingerprint
  is rejected as equivocation;
- prove a malformed / unsupported-`record_version` / wrong-env /
  wrong-chain persistence file fails closed (no silent reset);
- prove a persistence write failure fails closed (the bundle is NOT
  accepted if its new highest sequence cannot be recorded);
- prove `--p2p-trust-bundle` on TestNet/MainNet without `--data-dir`
  fails closed (anti-rollback persistence is a hard requirement on
  production-honest environments);
- prove DevNet convenience: `--p2p-trust-bundle` on DevNet without
  `--data-dir` emits a clear WARNING and proceeds (no silent
  weakening);
- prove Run 050 / 051 / 052 / 053 / 054 behaviour is preserved
  bit-for-bit (wrong-chain, tampered-signature, revoked-root,
  revoked-leaf, signed-bundle envelope, chain-id crosscheck all
  still fail BEFORE the new sequence check ever runs);
- prove no fallback to `--p2p-trusted-root`, `DummySig`, `DummyKem`,
  or `DummyAead` on any path.

Explicitly out of scope for Run 055 (and listed in
`docs/whitepaper/contradiction.md`):

- activation epoch / height gating for revocation or root-status
  entries (only `effective_from` UNIX seconds is honored);
- operator-facing CA / certificate rotation / signing-key rotation
  playbook;
- production fast-sync / consensus-storage restore;
- live MainNet signed-bundle release-binary smoke with a
  production-grade signing key;
- the live release-binary smoke artefact set for the Run-055
  anti-rollback path itself (the unit + integration test coverage
  is complete; the release-binary smoke artefact set was not
  produced in this session and is recorded as a separate
  remaining-open evidence item rather than fabricated);
- any redesign of KEMTLS, trust bundles, transport, or consensus.

## Exact verdict

**Strongest positive for the scoped Run 055 trust-bundle sequence
anti-rollback persistence work.** The new module
`crates/qbind-node/src/pqc_trust_sequence.rs` provides:

- `PersistentTrustBundleSequenceRecord` (Serde JSON record:
  `record_version`, `environment`, `chain_id`, `highest_sequence`,
  `bundle_fingerprint`, `updated_at_unix_secs`);
- `load_record(path)` — strict JSON parse, structural validation,
  fail-closed on every malformed surface (missing field, wrong
  schema version, non-hex chain_id, non-hex fingerprint);
- `atomic_write_record(path, record)` — tmp file + `sync_all` +
  rename, creating the parent directory if needed, cleaning up the
  `.tmp` sibling on rename failure;
- `check_and_update_sequence(...)` — the entry point: first-load
  accepts and persists; strictly higher accepts and persists;
  strictly lower rejects (`SequenceRollback`); equal + same
  fingerprint accepts no-op (no rewrite); equal + different
  fingerprint rejects (`EqualSequenceFingerprintMismatch`); wrong
  env/chain on a pre-existing record rejects (`WrongEnvironment` /
  `WrongChainId`); persistence write failure rejects
  (`PersistFailure`).

Wiring lives in `crates/qbind-node/src/main.rs` immediately after
the existing Run 050/051/053 trust-bundle load + signature
verification block and the static-root-bundle conflict check, but
BEFORE the active-roots-into-`trusted_roots` merge. On every
fail-closed path the binary emits a precise FATAL message and calls
`std::process::exit(1)`; it never falls back to
`--p2p-trusted-root`, never installs `DummySig` / `DummyKem` /
`DummyAead`, and never silently deletes or rewrites a corrupted
persistence file.

Four new metrics are surfaced through the shared `P2pMetrics`
Arc — `qbind_p2p_pqc_trust_bundle_sequence_highest` (gauge),
`qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`
(counter), `qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total`
(counter), and
`qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total`
(counter) — and the existing Run 050/051/052/053/054 metric
families are preserved bit-for-bit.

All required regression suites stay green (numbers below). Full
C4 remains OPEN for: activation epoch/height gating, operator CA /
rotation playbook, production fast-sync / consensus-storage
restore, live MainNet signed-bundle release-binary smoke, live
release-binary smoke for Run 055 itself.

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/src/pqc_trust_sequence.rs` | New module. `PersistentTrustBundleSequenceRecord` + `TrustBundleSequenceError` + `SequenceCheckOutcome` + `load_record` + `validate_record_for_domain` + `atomic_write_record` + `check_and_update_sequence` + `sequence_file_path` + `fingerprint_hex` + `chain_id_hex` + 21 unit tests. |
| `crates/qbind-node/src/lib.rs` | One-line `pub mod pqc_trust_sequence;` module declaration with a four-line documentation comment. |
| `crates/qbind-node/src/main.rs` | Sequence check + persist call wired into the `--p2p-trust-bundle` `Ok(loaded)` branch, between the static-roots conflict check and the active-roots merge. Adds `[binary] Run 055: trust-bundle sequence persistence env=… chain_id=… path=… {first-load|upgraded|equal-sequence same-fingerprint (no write)} fp=…` log on success; emits precise FATAL log + `std::process::exit(1)` on every fail-closed surface; adds DevNet-only `Run 055 WARNING` when `--p2p-trust-bundle` is supplied without `--data-dir` on DevNet (TestNet/MainNet fail closed in the same situation). |
| `crates/qbind-node/src/metrics.rs` | Four new `AtomicU64` fields + accessors + `format_metrics` rendering for `qbind_p2p_pqc_trust_bundle_sequence_highest`, `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`, `qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total`, `qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total`, plus two new unit tests. |
| `crates/qbind-node/tests/run_055_pqc_trust_bundle_sequence_tests.rs` | New integration test suite. 12 tests, each driving a real Run 050/051/053-validated `LoadedTrustBundle` through `check_and_update_sequence` to pin operator-visible behaviour. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 055 evidence update" recording that sequence-number monotonicity persistence is now closed, and listing the still-open C4 pieces explicitly. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_055.md` | This evidence document (new). |

No `Cargo.toml` changes. No `--p2p-trusted-root` weakening. No
KEMTLS / transport / consensus / forged-traffic / leaf-revocation
library source changes. No tests removed or weakened.

## Exact commands run

```bash
# 0) Baseline identity.
git rev-parse HEAD                # baseline before Run 055 edits
git status --porcelain | wc -l    # 0 (clean before Run 055 edits)

# 1) Build the lib + binary cleanly.
cargo check -p qbind-node --lib
cargo check -p qbind-node --bin qbind-node

# 2) Run the new module's unit tests.
cargo test -p qbind-node --lib pqc_trust_sequence
# -> 21/21 pass.

# 3) Run the new integration test suite.
cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests
# -> 12/12 pass.

# 4) Run the metrics unit tests (Run 050/051 + new Run 055 families).
cargo test -p qbind-node --lib metrics
# -> 106/106 pass (was 104/104; +2 from Run 055).

# 5) Run all PQC trust-bundle / signing / leaf-revocation / static-root
#    regression suites. Behaviour is preserved bit-for-bit.
cargo test -p qbind-node --lib pqc_trust_bundle                                   # 70/70
cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests                    # 14/14
cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests            # 13/13
cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests                 # 12/12
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests         # 12/12
```

## Test results

| Suite | Result |
| --- | --- |
| `cargo test -p qbind-node --lib pqc_trust_sequence` | **21/21 pass** (new module) |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | **12/12 pass** (new suite) |
| `cargo test -p qbind-node --lib metrics` | **106/106 pass** (was 104/104; +2 for Run 055 metric families) |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | **70/70 pass** (preserves Run 050/051/052/053 assertions) |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | **14/14 pass** |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13/13 pass** |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12/12 pass** |
| `cargo check -p qbind-node --bin qbind-node` | clean (only pre-existing `bincode::config` deprecation warnings unrelated to Run 055) |

## Key invariants pinned by the new tests

### Unit tests (`pqc_trust_sequence::tests`, 21/21)

1. `fingerprint_hex_is_64_lowercase_hex_chars` — pin the canonical
   form persisted in the record.
2. `chain_id_hex_is_16_lowercase_hex_chars` — pin the canonical
   form persisted in the record.
3. `load_record_returns_none_when_file_missing` — first-load
   semantics; no implicit creation.
4. `load_record_rejects_malformed_json` — fail-closed on garbage.
5. `load_record_rejects_wrong_record_version` — fail-closed on
   schema bump without operator action.
6. `load_record_rejects_missing_field` — fail-closed on partial
   record.
7. `load_record_rejects_malformed_chain_id_hex` — fail-closed on
   bad chain id form.
8. `load_record_rejects_malformed_fingerprint_hex` — fail-closed
   on bad fingerprint form.
9. `first_load_writes_record_and_returns_first_load_outcome` —
   first acceptance persists the record exactly.
10. `higher_sequence_is_accepted_and_persists` — monotonic upgrade
    persists.
11. `lower_sequence_is_rejected_as_rollback` — rollback rejected;
    record untouched.
12. `equal_sequence_same_fingerprint_is_accepted_without_write` —
    restart-with-identical-bundle no-op; `updated_at_unix_secs`
    NOT bumped because no write happens.
13. `equal_sequence_different_fingerprint_is_rejected` —
    equivocation guard fires; record untouched.
14. `wrong_environment_in_record_fails_closed` — stray
    cross-environment file blocked.
15. `wrong_chain_id_in_record_fails_closed` — stray
    cross-chain file blocked.
16. `atomic_write_then_load_round_trips` — tmp sibling NOT left
    behind on success.
17. `atomic_write_creates_missing_parent_dir` — operator-friendly
    `mkdir -p` behaviour.
18. `rollback_after_two_step_upgrade_still_fails` — record retains
    the highest sequence across multiple upgrades.
19. `persist_failure_when_path_is_a_directory` — fail-closed on
    fundamentally unwritable paths (no silent ignore).
20. `equivocation_detail_carries_both_fingerprints` — operator
    sees BOTH the persisted and attempted fingerprint in the error
    message for forensics.
21. `display_messages_are_operator_actionable` — every error
    variant renders a non-trivial, self-describing log line.

### Integration tests (`run_055_pqc_trust_bundle_sequence_tests.rs`, 12/12)

1. `first_load_signed_devnet_seq1_accepts_and_writes_record` — a
   real ML-DSA-44-signed DevNet bundle at sequence=1 persists.
2. `signed_devnet_seq2_accepted_after_seq1_persists_2` — upgrade
   path on real signed bundles.
3. `signed_devnet_seq1_rejected_after_seq2` — rollback rejected;
   highest sequence stays at 2.
4. `restart_with_identical_bundle_is_accepted_no_write` —
   common steady-state restart case; record left intact.
5. `equal_sequence_different_fingerprint_rejected_as_equivocation`
   — two same-sequence bundles with different `generated_at`
   timestamps surface as distinct fingerprints; the second one is
   rejected fail-closed.
6. `wrong_chain_id_bundle_fails_before_sequence_update` —
   Run 053 chain-id check still fires BEFORE Run 055; sequence
   record stays untouched.
7. `tampered_signature_fails_before_sequence_update` —
   Run 051 signature check still fires BEFORE Run 055; sequence
   record stays untouched.
8. `revoked_root_only_bundle_still_loads_and_does_not_disturb_sequence`
   — Run 050 revoked-root-only bundles still load (the root is
   filtered out of active_roots, but the bundle envelope is valid),
   and the sequence layer honors the bundle's sequence verbatim.
9. `corrupt_persistence_file_fails_closed_no_silent_reset` — a
   corrupted record file is NOT silently overwritten or deleted.
10. `stray_mainnet_record_blocks_devnet_load_fail_closed` — a
    stray MainNet record under a DevNet `data_dir` cannot leak.
11. `null_chain_id_bundle_persists_under_runtime_chain_id` — the
    Run 053 legacy `chain_id: null` compatibility window still
    works end-to-end; the persisted record carries the RUNTIME
    chain id, not "none".
12. `trust_bundle_signature_type_still_re_exported` — the
    `TrustBundleSignature` public symbol stays re-exported so
    future helper-binary refactors do not silently break the
    crate boundary.

### Metrics unit tests (`metrics::tests`, +2 for Run 055)

- `pqc_trust_bundle_sequence_metrics_start_at_zero_and_increment_atomically`
  — every new metric starts at 0; counters move atomically; the
  gauge stores the supplied value.
- `pqc_trust_bundle_sequence_metrics_render_once_in_format_metrics`
  — each of the four new metric families renders exactly once in
  the rendered metrics body, the values reflect the in-memory
  state, and the existing Run 050/051 metric families are still
  present (no displacement).

## No-fallback proof (Run 055)

- The sequence persistence wiring in `main.rs` keys off the
  LOADED TRUST BUNDLE's `sequence` and canonical `fingerprint`,
  NOT off `--p2p-trusted-root`.
- On every error path (`SequenceRollback`,
  `EqualSequenceFingerprintMismatch`, `PersistFailure`,
  `WrongEnvironment`, `WrongChainId`, `Malformed`,
  `UnsupportedRecordVersion`, `Io`, plus `TestNet/MainNet without
  --data-dir`) the binary emits a precise FATAL message and calls
  `std::process::exit(1)`. It does NOT fall back to
  `--p2p-trusted-root`, does NOT install bundle roots, does NOT
  install `DummySig` / `DummyKem` / `DummyAead`, and does NOT
  silently delete or reset the persistence file.
- The persisted record is written via tmp + `sync_all` + rename;
  on a mid-write crash the destination file is left intact and
  the `.tmp` sibling is harmless.
- The persisted record carries no secret-key material, no
  validator-signer key bytes, and no signing-key public bytes —
  only `(record_version, environment, chain_id, highest_sequence,
  bundle_fingerprint, updated_at_unix_secs)`.

## Explicit remaining boundaries (NOT done in Run 055)

- Activation epoch / height gating for revocation entries and
  root-status windows (only `effective_from` UNIX seconds is
  honored today).
- Operator-facing CA + certificate rotation + signing-key rotation
  playbook.
- Production fast-sync / consensus-storage restore.
- Live MainNet signed-bundle release-binary smoke with a
  production-grade signing key.
- Live release-binary smoke artefact set for the Run 055
  anti-rollback path itself. The unit + integration test coverage
  is complete (`pqc_trust_sequence` 21/21,
  `run_055_pqc_trust_bundle_sequence_tests` 12/12, plus the
  metrics tests); the release-binary smoke artefact set
  (positive first-load, positive upgrade, negative rollback,
  negative equivocation, negative TestNet-without-data-dir,
  negative corrupt-persistence) was deliberately not produced in
  this session and is explicitly recorded as a future evidence
  run rather than fabricated.
- A startup self-check that fails the binary closed when
  `--p2p-leaf-cert` matches an active entry in the loaded bundle's
  `revoked_leaf_fingerprints` (Run 052/054 boundary; still open).

**C5 remains NOT closed** by Run 055; Run 055 does not touch
timeout/NewView wire formats, forged-traffic policy, KEMTLS wire
formats, consensus message wire formats, or any signature /
verification semantics outside the trust-bundle persistence
layer. **Full C4 remains OPEN.**