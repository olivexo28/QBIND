# QBIND DevNet Evidence — Run 057: PQC Trust-Bundle Activation Epoch/Height Gating

## Exact objective

Run 057 implements and proves PQC trust-bundle **activation gating** so a
structurally valid + signed + anti-rollback-checked trust bundle is **not
accepted** before its declared activation condition is satisfied at the
loading node. The Run 050/051/053 boundary recorded
`activation_epoch` / `activation_height` as "accepted by the schema but
NOT enforced by the runtime"; Run 057 closes the height-gating boundary
end-to-end on DevNet (unit + integration + cross-suite regression) and
records epoch-gating as `remaining-open` with a precise reason
(no safe pre-consensus epoch source exists today, so the loader fails
closed when a bundle declares `activation_epoch`).

The scope is intentionally narrow:

- Add `pqc_trust_activation` module with `ActivationContext`,
  `check_bundle_activation`, and `TrustBundleActivationError`.
- Extend `TrustBundle` with optional bundle-level `activation_epoch`
  and `activation_height` fields (the per-root fields already
  existed). Both are covered by `canonical_signing_bytes` and
  `canonical_fingerprint` (proved by Run 057 tests
  `tampering_activation_height_after_signing_invalidates_signature`
  and `canonical_fingerprint_covers_activation_height`).
- Add the activation-aware loader
  `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
  that runs the activation check AFTER signature/env/chain_id/window/
  revocation validation and returns
  `TrustBundleError::Activation(_)` on any future-dated gate or
  runtime-source-unavailable gate.
- Wire the activation gate into `crates/qbind-node/src/main.rs` at the
  binary `--p2p-trust-bundle` load path. Runtime source is
  `current_height = restore_baseline.snapshot_height` when the node
  was started with `--restore-from-snapshot`, else `0` (fresh-from-
  genesis local committed height). `current_epoch = None` (no safe
  pre-consensus epoch source). The gate runs BEFORE sequence
  persistence (Run 055) and BEFORE bundle-root merge (Run 050) — so
  a future-activation bundle does NOT advance the persisted highest
  sequence and does NOT inject trust anchors into the live set.
- Surface the activation observability on `P2pMetrics`:
  `qbind_p2p_pqc_trust_bundle_activation_height_required`,
  `_height_current`, `_epoch_required`, `_epoch_current`, and
  `_rejected_total`.
- Extend the DevNet helper `devnet_pqc_trust_bundle_helper` with an
  optional 5th positional `[activation_height_override]` u64
  argument (additive; identical to the Run 056 sequence_override
  pattern). This is the only edit to the helper.
- Documentation: this evidence file, and a narrowing entry in
  `docs/whitepaper/contradiction.md` recording the Run 057 boundary
  closure plus the explicit remaining items (epoch gating; live
  release-binary smoke).

Out of scope (explicitly NOT done in Run 057):

- Live release-binary smoke of the activation gate. The Run 057
  changes are exercised end-to-end by 14 unit tests and 12
  integration tests covering the same `validate_at_*` +
  `check_and_update_sequence` codepaths that the release binary
  runs in production, but a real-binary release-build smoke
  artefact set (matching Run 056's shape) is recorded as
  remaining-open below.
- Epoch gating runtime source. The bundle's `activation_epoch`
  field is honored at the schema and signature/fingerprint layer
  (a bundle declaring `activation_epoch` fails closed at load time
  in this build), but a real runtime epoch source pre-consensus
  does not exist; this is documented as remaining-open.
- No consensus, KEMTLS, timeout-verification, NewView wire format,
  or forged-traffic policy changes. Run 057 does not touch any
  signature/verification semantics outside the trust-bundle
  activation surface.

## Files touched

- `crates/qbind-node/src/lib.rs` — register `pub mod pqc_trust_activation`.
- `crates/qbind-node/src/pqc_trust_activation.rs` — new module
  (14 unit tests).
- `crates/qbind-node/src/pqc_trust_bundle.rs` — add optional
  bundle-level `activation_epoch` / `activation_height` fields
  (`#[serde(default)]`, covered by canonical signing bytes and
  canonical fingerprint), add `Activation(_)` variant on
  `TrustBundleError`, add new loader
  `load_from_path_with_signing_keys_chain_id_and_activation`.
- `crates/qbind-node/src/metrics.rs` — add five new
  `pqc_trust_bundle_activation_*` atomic gauges + counter, accessors,
  format_metrics render lines, and two new render-once tests.
- `crates/qbind-node/src/main.rs` — wire the activation context
  (current_height from `restore_baseline`, current_epoch = None)
  and use the activation-aware loader; on activation rejection
  bump the rejected counter and surface the height gauges.
- `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` —
  add optional 5th positional `[activation_height_override]` u64;
  echo `bundle_activation_height=` in the summary log.
- `crates/qbind-node/tests/run_055_pqc_trust_bundle_sequence_tests.rs`
  — add the two new optional struct fields to the helper that
  constructs literal `TrustBundle { ... }`.
- `crates/qbind-node/tests/run_057_pqc_trust_bundle_activation_tests.rs`
  — new integration tests (12 tests).
- `docs/whitepaper/contradiction.md` — narrow C4 activation
  height-gating boundary (this evidence file referenced).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_057.md` — this file.

## Test evidence

All commands run from the repository root.

### Run 057 unit tests (`pqc_trust_activation` module)

```
cargo test -p qbind-node --lib pqc_trust_activation
```

Result: **14 passed; 0 failed**. Tests cover:

- `missing_activation_fields_accepted_with_no_runtime_source`
- `missing_activation_fields_accepted_with_height_source`
- `bundle_activation_height_satisfied_accepted`
- `bundle_activation_height_equal_accepted_inclusive`
  (inclusive `current >= required` boundary)
- `bundle_activation_height_future_rejected`
- `bundle_activation_height_requires_runtime_source`
  (`CurrentHeightUnavailable` fail-closed)
- `bundle_activation_epoch_future_rejected_when_epoch_source_present`
- `bundle_activation_epoch_requires_runtime_source_today`
  (epoch-deferred fail-closed)
- `both_gates_satisfied_accepted`
- `both_gates_one_future_rejected`
- `root_level_activation_height_future_rejected`
- `root_level_activation_only_enforced_on_active_status`
  (Retired/Revoked roots: activation field is advisory-only,
  mirrors `not_before`/`not_after` semantics)
- `required_height_is_max_across_bundle_and_active_roots`
- `display_error_messages_carry_fail_closed_phrase`

### Run 057 integration tests

```
cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests
```

Result: **12 passed; 0 failed**. Tests cover:

1. `no_activation_fields_accepted_under_any_context` — back-compat
   for legacy bundles.
2. `activation_height_satisfied_accepts_bundle` — `current >= required`.
3. `activation_height_future_refuses_bundle` — precise
   `TrustBundleError::Activation(ActivationHeightNotYetReached{..})`.
4. `activation_height_inclusive_equal_accepts` — inclusive boundary.
5. `activation_height_present_without_current_height_refuses` —
   `CurrentHeightUnavailable` fail-closed.
6. `activation_epoch_present_without_current_epoch_refuses` —
   `CurrentEpochUnavailable` fail-closed, proving "epoch gating is
   deferred" at the boundary.
7. **`future_activation_does_not_advance_sequence_persistence`** —
   the central invariant. A signed DevNet bundle at `sequence=5`
   with `activation_height=1_000` at `current_height=0` is
   rejected with `Activation(_)`, no persistence file is written
   (verified by `load_record(&seq_path).expect("load").is_none()`),
   and a subsequent satisfied bundle at the same `sequence=5`
   then advances the record cleanly. This proves the
   future-activation rejection path does NOT burn a higher
   sequence.
8. `future_activation_bundle_is_structurally_valid_and_signed` —
   the same bundle passes the non-activation
   `load_from_bytes_with_signing_keys_and_chain_id` cleanly, so
   the activation gate is its own boundary, not a side-effect of
   structural or signature failure.
9. `tampering_activation_height_after_signing_invalidates_signature`
   — proves `activation_height` is in the canonical signing
   preimage.
10. `canonical_fingerprint_covers_activation_height` — proves the
    fingerprint is sensitive to `activation_height`, so Run 055's
    equivocation guard cannot be bypassed by re-publishing
    "same sequence, different activation_height".
11. `per_root_activation_height_future_refuses_bundle` — per-root
    activation enforced on Active roots.
12. `legacy_bundle_json_without_activation_fields_parses_clean` —
    `#[serde(default)]` back-compat verified on hand-crafted JSON
    that omits the new bundle-level fields entirely.

### Metrics tests

```
cargo test -p qbind-node --lib metrics
```

Result: **108 passed; 0 failed** (was 106 before Run 057; +2 new
tests for `pqc_trust_bundle_activation_metrics_start_at_zero_and_increment_atomically`
and `pqc_trust_bundle_activation_metrics_render_once_in_format_metrics`,
which assert each of the five new metric names appears exactly once
in `P2pMetrics::format_metrics()`).

### Cross-suite regression (no displacement)

All required prior suites green on the same workspace:

| Suite | Tests | Result |
|---|---|---|
| `cargo test -p qbind-node --lib pqc_trust_bundle` | 72 | passed |
| `cargo test -p qbind-node --lib pqc_trust_sequence` | 21 | passed |
| `cargo test -p qbind-node --lib metrics` | 108 | passed |
| `cargo test -p qbind-node --lib pqc_trust_activation` | 14 | passed |
| `cargo test -p qbind-node --lib` (full) | 898 | passed |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | 12 | passed |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | 14 | passed |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | 13 | passed |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 | passed |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | 12 | passed |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | 12 | passed |
| `cargo test -p qbind-net --lib` | 17 | passed |
| `cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests` | 9 | passed |
| `cargo check -p qbind-node --bin qbind-node` | — | clean (only pre-existing `bincode::config` deprecation warnings unrelated to Run 057) |
| `cargo build -p qbind-node --example devnet_pqc_trust_bundle_helper` | — | clean |

## No-fallback proof (Run 057)

On the activation-rejection path the binary surface in
`crates/qbind-node/src/main.rs`:

1. Returns `Err(TrustBundleError::Activation(_))` from
   `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
   BEFORE the trust-bundle's roots are merged into `trusted_roots`
   and BEFORE `check_and_update_sequence` is invoked. The integration
   test `future_activation_does_not_advance_sequence_persistence`
   pins this end-to-end on the public API.
2. Increments `qbind_p2p_pqc_trust_bundle_activation_rejected_total`
   by exactly one (covered by the metrics atomic-increment test).
3. Emits FATAL `... No fallback to --p2p-trusted-root on bundle
   failure (production-honest lifecycle must not silently
   downgrade). See docs/whitepaper/contradiction.md C4 (signed root
   distribution).` and exits `std::process::exit(1)`. The
   activation-error string (covered by
   `display_error_messages_carry_fail_closed_phrase`) explicitly
   ends with `No fallback to --p2p-trusted-root.`.

No `--p2p-trusted-root` rescue path is taken on activation failure.
No silent downgrade to DummySig/DummyKem/DummyAead is possible (the
binary exits before `P2pNodeBuilder` is constructed, exactly as in
Run 055/056).

## Explicit remaining boundaries (NOT done in Run 057)

- **Epoch gating runtime source.** Bundles that declare
  `activation_epoch` are rejected at load with
  `CurrentEpochUnavailable` today, because no safe pre-consensus
  epoch source exists in this binary (epoch transitions only happen
  AFTER consensus begins committing blocks, and the trust bundle is
  required BEFORE consensus can establish peer transport). Epoch
  gating is therefore deferred behind a future change that plumbs a
  persisted "last committed epoch" into the pre-consensus startup
  context, in the same way Run 057 plumbs `restore_baseline.snapshot_height`
  for height gating. The bundle layer's signature and fingerprint
  ALREADY cover `activation_epoch`, so when this future change
  lands, no schema or signing change is needed.
- **Live release-binary smoke artefact set for the Run 057
  activation gate.** Run 057 ships unit + integration tests covering
  the exact codepaths the release binary runs, but does NOT include
  the matched Run-056-style release-binary smoke artefacts
  (positive `activation_height` satisfied + negative `activation_height`
  future + identity). Recorded explicitly as remaining-open.
- **Activation gate on revocation entries.** `TrustBundleRevocation`
  carries `effective_from` (UNIX seconds) and is honoured at the
  validity-window layer. An equivalent activation-height /
  activation-epoch field on revocation entries is NOT introduced by
  Run 057 — only bundle-level + root-level gating.
- **Per-environment trust-anchor activation policy.** Run 057
  enforces the gate uniformly across DevNet / TestNet / MainNet
  (because activation is part of the bundle envelope, not the
  environment policy). Per-environment minimum-activation-height
  policy (e.g. "MainNet bundles MUST declare
  `activation_height >= last_finalized_height + N`") is not
  introduced and remains an open production-operability item under
  C4.
- **C5 remains NOT closed** by Run 057. Run 057 does not touch
  timeout/NewView wire formats, forged-traffic policy, KEMTLS wire
  formats, consensus message wire formats, or any signature/
  verification semantics outside the trust-bundle activation surface.

**No fabricated metrics**, **no silent regression**, **no protocol
behaviour change**, **no removed tests**, **no DummySig/DummyKem/
DummyAead fallback path introduced or strengthened**, **no
transport-root reuse as bundle-signing authority**, **no classical
signatures introduced** (suite 100 / ML-DSA-44 only on the bundle
layer), and **no leak of root_sk / signing_sk / kem_sk / validator
signer key bytes** were observed in the run.

**Full C4 remains OPEN.** Run 057 closes the activation
**height**-gating boundary on the DevNet binary path and at the
unit + integration test layer; activation **epoch**-gating, live
release-binary smoke artefacts, and broader C4 production-
operability items remain open.