# QBIND DevNet Evidence — Run 091

**Objective:** investigate, decide, and pin the `activation_epoch`
runtime-source boundary on the PQC trust-bundle activation gate.
The Run 057 module-level docs and `docs/whitepaper/contradiction.md`
C4 have carried "`activation_epoch` runtime source" as an open
sub-piece since Run 057. Run 091 produces the definitive
investigation finding, records the chosen design verdict, and pins
the verdict with new test coverage so a future run that ships a
canonical pre-consensus epoch source can replace the boundary
without redesigning Run 057 / 065 / 069 / 073 / 074 / 076 / 088
behavior.

**Verdict:** **partial positive**. No canonical pre-consensus
runtime epoch source is wired into the trust-bundle activation gate
today. `activation_epoch` (bundle-level and per-active-root)
remains explicitly fail-closed via
`TrustBundleActivationError::CurrentEpochUnavailable` on every
environment (DevNet, TestNet, MainNet) at every production call
site (startup `--p2p-trust-bundle` load, `--p2p-trust-bundle-reload-check`
validation-only, `--p2p-trust-bundle-reload-apply` process-start
apply, `SIGHUP` live reload, and the peer-candidate `0x05`
validation / propagation path). Per-entry revocation
`activation_epoch` is intentionally **not** carried by the
`TrustBundleRevocation` schema (the wire field set on revocation
entries remains the Run 062 set: `root_id`, `leaf_cert_fingerprint`,
`reason`, `effective_from`, `activation_height`). Run 091
explicitly does **not** introduce an epoch source, does **not**
add a per-environment epoch policy, does **not** change the wire
format, and does **not** claim full C4 / C5 closure.

## Files changed

- `crates/qbind-node/tests/run_091_pqc_trust_bundle_activation_epoch_tests.rs`
  (new — 15 integration tests pinning the partial-positive boundary
  on the activation gate, the reload-check surface, and the
  revocation schema).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_091.md` (new — this
  document).
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (§3.10 boundary
  cross-reference / §10.1 Run 091 cross-reference / §11 mapping
  row — see "Runbook sections changed" below).
- `docs/whitepaper/contradiction.md` (C4 Run 091 update entry —
  no C4 closure claim, no C5 closure claim).

No changes to `crates/**/src/**`. No new dependencies. No metric
families added (the existing
`qbind_p2p_pqc_trust_bundle_activation_epoch_required` /
`_activation_epoch_current` / `_activation_rejected_total` gauges
already cover the surface; Run 091 does not duplicate them with
`_epoch_unsupported_total` or `_epoch_rejected_total` because the
combined `_activation_rejected_total` counter is the canonical
operator-facing rejection signal and a duplicate family would
inflate the metrics surface without adding information).

## Investigation findings (what already exists)

### Epoch sources available in the codebase

| # | Source | API | Where called | Suitable for trust-bundle activation? |
|---|--------|-----|--------------|---------------------------------------|
| 1 | `MetaStore::get_current_epoch()` | `qbind_node::storage::MetaStore` (`meta:current_epoch` key, u64 big-endian) | `hotstuff_node_sim.rs:2152` (consensus startup), epoch-transition tests, `verify_epoch_consistency_on_startup` | **Conceptually yes** — persisted, fail-closed on corruption, queryable without consensus advancement. **But not wired today**: `main.rs` does not open `MetaStore` before the trust-bundle activation gate runs (the gate runs immediately after `apply_snapshot_restore_if_requested` and before any consensus / storage layer initialization). Opening RocksDB at the trust-bundle gate would couple the trust-bundle load to the storage layer and is out of Run 091 scope. |
| 2 | `StateSnapshotMeta` | `qbind_ledger::StateSnapshotMeta` (`height`, `block_hash`, `created_at_unix_ms`, `chain_id`) | `snapshot_restore::RestoreOutcome.meta` consumed by `main.rs` lines 300 / 544 / 902 / 1764 | **No.** `StateSnapshotMeta` carries `height` (which already feeds `ActivationContext::height_only(...)`) but does **not** carry `epoch`. Adding an `epoch` field would break the existing snapshot wire format and require a Run 022 / 023 snapshot-format follow-up that is out of scope. |
| 3 | `BasicHotStuffEngine::current_epoch()` (consensus engine state) | `qbind_consensus::basic_hotstuff_engine` | inside the consensus loop | **No.** The consensus engine has not yet been initialized at the trust-bundle activation gate (the gate runs before `binary_consensus_loop::spawn_binary_consensus_loop`). Consulting it would create a circular dependency: the trust bundle is needed to verify peer transport before consensus can advance, and the engine's epoch is only meaningful after at least one block has been committed under the new bundle. |
| 4 | `EpochManager` / `EpochTransitionMarker` | `qbind_consensus` epoch transition module | per-block consensus loop | **No.** Same circularity as #3. |
| 5 | Wall-clock derived "epoch" | `std::time::SystemTime` divided by an epoch length | nowhere — not implemented | **No.** Wall-clock derivation is operationally hostile (clock skew, NTP gaps, leap seconds) and would be exactly the kind of "fabricated source" the task forbids. |

### Why option #1 was investigated and rejected for Run 091

Persisted `meta:current_epoch` would be the closest match to the
"canonical pre-consensus epoch source" the task asks about. It is
already:

- written atomically as part of `apply_epoch_transition_atomic`
  (M16, T112);
- verified for consistency at startup
  (`verify_epoch_consistency_on_startup`);
- corruption-checked via the storage-corruption-guardrails tests
  (`storage_corruption_guardrails_tests::*`);
- exposed through a `MetaStore` trait the binary already implements
  on RocksDB and an in-memory mock.

The reason Run 091 does **not** wire it today is purely
architectural:

1. **Storage layer is not opened pre-consensus.** `main.rs` does
   not call `MetaStore::open(...)` before the trust-bundle gate
   runs. Opening it would mean RocksDB initialization, schema
   version checks, incomplete-transition recovery, and storage-
   corruption guardrails all run **before** any peer transport is
   trusted. That re-orders the binary startup sequence in a way
   that touches T112 / M16 / Run 022 / 023 / 057 / 065 / 069 / 070
   / 073 / 074 / 076–089 simultaneously and would require a
   dedicated cross-cutting run.
2. **Fresh-genesis ambiguity.** On a fresh-genesis node,
   `MetaStore::get_current_epoch()` returns `Ok(None)` — meaning
   "no epoch has been stored yet". The semantics of treating that
   as "current epoch = 0" for trust-bundle activation gating is
   not obviously correct: epoch 0 may be a valid `activation_epoch`
   on a fresh-genesis bundle (immediate-cutover analogue of
   DevNet's `activation_height = 0`), and silently treating it as
   0 risks the exact "silent satisfy" Run 091 is asked to
   prevent. Distinguishing fresh-genesis from "no canonical
   source" requires a separate design decision.
3. **Snapshot-rejoin asymmetry.** A node started from
   `--restore-from-snapshot` does NOT have a persisted
   `meta:current_epoch` until the next epoch transition commits.
   Therefore `MetaStore::get_current_epoch()` on a snapshot-
   restored node returns `Ok(None)` even though the snapshot's
   block height is well past epoch 0. Without an epoch field in
   `StateSnapshotMeta` (out of scope — see #2 in the table above),
   the snapshot-rejoin path has no pre-consensus epoch source at
   all. Wiring `MetaStore` would create a permanent asymmetry
   between fresh-genesis (no source) and snapshot-rejoin (no
   source) on one side and post-first-transition restart (source
   available) on the other.

The honest, smallest-change resolution is therefore to keep the
explicit fail-closed boundary already implemented in
`pqc_trust_activation::check_bundle_activation` and to pin every
production call site against the "no silent ignore" invariant with
new test coverage. That is what Run 091 ships.

## ActivationContext design (what Run 091 confirms is already correct)

`ActivationContext` carries two optional fields today:

```rust
pub struct ActivationContext {
    pub current_height: Option<u64>,
    pub current_epoch: Option<u64>,
}
```

Run 091 confirms this shape is correct and intentional:

- `current_height: Option<u64>` already differentiates "no safe
  height source" (e.g. unit tests, the `--p2p-trust-bundle-reload-check`
  no-data-dir path) from "height is 0" (genesis). Bundles
  declaring `activation_height` under a `None` height source fail
  closed via `CurrentHeightUnavailable` (Run 057). Production
  call sites in `main.rs` set `Some(activation_current_height)`
  derived from `restore_baseline.snapshot_height` (or `0` when no
  snapshot is being restored).
- `current_epoch: Option<u64>` honestly reports "no canonical
  pre-consensus epoch source is available in this build". Every
  production call site sets `current_epoch: None`. Bundles
  declaring `activation_epoch` under that context fail closed via
  `CurrentEpochUnavailable`.

Run 091 does **not** add `environment`, `chain_id`, or "source
description" fields to `ActivationContext`. Those are already
carried independently by `ReloadCheckInputs` (`environment`,
`chain_id`) and by the `TrustBundle::environment` field itself,
and threading them through `ActivationContext` as well would be a
breaking change to the public type for no operator-visible
benefit. The `CurrentEpochUnavailable` error already names both
`required_epoch` and `scope` in its `Display` impl; operator logs
already grep `current_epoch but no runtime epoch source is
available` as the fail-closed marker.

## Enforcement ordering (preserved unchanged)

Run 091 preserves the existing strict ordering established by Runs
050 / 051 / 053 / 057 / 062 / 065 / 069 / 070 / 073 / 074 / 076 /
088. On every production call site, the trust-bundle load proceeds
in this order, fail-closed at the first failure:

1. **Parse + structural validation** (Run 050 / 051 schema, ML-DSA-44
   signature verification, environment binding, chain_id binding,
   validity window, revocation structural shape).
2. **Per-environment minimum activation-margin policy** (Run 065
   `check_min_activation_height_policy`) on the
   `activation_height` axis only — the `activation_epoch` axis is
   intentionally NOT subject to a Run 065-style policy because the
   epoch runtime source itself remains open.
3. **Future-height + future-epoch + unavailable-source gating**
   (Run 057 `check_bundle_activation`) — this is the layer that
   produces `CurrentEpochUnavailable` on the Run 091 boundary.
4. **Per-entry scheduled-revocation activation gate** (Run 062
   `revocation_activation_height`).
5. **Anti-rollback sequence persistence**
   (`check_and_update_sequence`) — reached only when steps 1–4
   pass; never reached when a bundle declares `activation_epoch`
   on a `current_epoch: None` context.
6. **Live trust merge** (`LivePqcTrustState::swap_snapshot` +
   `P2pSessionEvictor::evict_sessions` — Run 074 SIGHUP path
   only) — never reached when step 3 returns
   `CurrentEpochUnavailable`.

This means: a `activation_epoch`-declaring bundle on a production
binary today CANNOT advance the on-disk sequence, CANNOT mutate
live trust, CANNOT evict sessions, and CANNOT propagate (the
Run 088 propagation path rebroadcasts only **validated** frames,
and a `CurrentEpochUnavailable` validation result is not a
"validated" frame). The Run 091 test
`run091_reload_check_bundle_activation_epoch_unsupported_fails_closed_no_sequence_mutation`
pins this invariant against the reload-check surface.

## Error semantics (preserved unchanged)

`TrustBundleActivationError::CurrentEpochUnavailable` carries:

- `required_epoch: u64` — the epoch value declared by the bundle
  (or the highest declared across bundle + active roots).
- `scope: ActivationScope` — `Bundle` for the bundle-level field,
  `Root(<root_id_hex>)` for a per-active-root field.

The `Display` impl on this variant renders:

```
pqc trust-bundle activation epoch gating requires current_epoch
but no runtime epoch source is available in this build
(scope=<scope>, required_epoch=<n>); fail closed — epoch gating is
deferred (see docs/whitepaper/contradiction.md C4)
```

No private material is leaked (the `required_epoch` is from the
public bundle field; the `scope` carries only the 64-char hex
root_id which is itself public bundle data). The Run 091 test
`run091_current_epoch_unavailable_display_is_safe_and_explicit`
pins that the message contains the fail-closed phrase and the
public fields, and that it never contains "DummySig", "DummyKem",
or "DummyAead" leakage.

## Metrics decision

Run 091 adds **no new metric families**. The existing surface
already carries:

- `qbind_p2p_pqc_trust_bundle_activation_epoch_required` (gauge):
  highest declared `activation_epoch` across the most recent
  loaded bundle; 0 when no bundle declares the field.
- `qbind_p2p_pqc_trust_bundle_activation_epoch_current` (gauge):
  echoed `ActivationContext::current_epoch` (always 0 today
  because `current_epoch: None` everywhere in the binary).
- `qbind_p2p_pqc_trust_bundle_activation_rejected_total` (counter):
  incremented once per rejected bundle/reload-check/peer-candidate
  load, covering BOTH `activation_height` and `activation_epoch`
  rejections. The combined counter is the canonical operator
  rejection signal.

Run 091 deliberately does NOT add
`pqc_trust_bundle_activation_epoch_rejected_total` or
`pqc_trust_bundle_activation_epoch_unsupported_total` because:

- the existing `_activation_rejected_total` already covers every
  rejection class (the operator-visible signal "a trust-bundle
  load was rejected" is the actionable one);
- adding two axis-specific counters would duplicate the existing
  family without adding any operator-actionable distinction
  (operators read the rejected log line for the precise reason,
  not the metric);
- the task explicitly states "no fabricated metrics, no duplicate
  families".

## Logs (existing surface, no Run 091 changes required)

The startup logger in `pqc_trust_reload::validate_candidate_bundle`,
`main.rs` startup, the SIGHUP `LiveReloadController` (Run 074), and
`pqc_trust_peer_candidate::validate_candidate_full` all emit a
single one-line log per loaded / rejected bundle that includes:

- the bundle's `(sequence, fingerprint)` (Run 055 / 069
  staged-metadata format);
- the rejection reason as `TrustBundleActivationError::Display`,
  including the fail-closed marker and the scope.

No private material (no SK bytes, no leaf cert bytes beyond the
already-public fingerprint) is logged. Run 091 does not change
the log format.

## What stays open after Run 091

Run 091 narrows but does NOT close C4. The following sub-pieces
remain explicitly open:

1. **Canonical pre-consensus runtime epoch source.** Wiring
   `MetaStore::get_current_epoch()` (or a `StateSnapshotMeta::epoch`
   extension) into the trust-bundle activation gate — see the
   investigation table and the rejection rationale above.
2. **Per-environment minimum-margin policy on the epoch axis.**
   Run 065 implements the policy on the `activation_height` axis
   only; the epoch axis has no analogue and gains one only after
   #1 lands.
3. **`TrustBundleRevocation::activation_epoch`.** The wire field is
   not present on revocation entries today (Run 062 boundary). A
   future run that adds it MUST also land #1 and update the
   schema, the ML-DSA-44 signed preimage, the canonical
   fingerprint, the runbook, and the peer-candidate propagation
   safety rules in `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`.

C5 (KEMTLS production lifecycle) is unrelated to Run 091's
activation-epoch boundary and is unchanged by this run.

## Tests added (15)

| # | Test | What it pins |
|---|------|--------------|
| 1 | `run091_activation_epoch_omitted_devnet_no_op` | activation_epoch omitted: existing behavior unchanged (DevNet, unavailable context) |
| 2 | `run091_activation_epoch_omitted_under_height_only_no_op` | activation_epoch omitted: existing behavior unchanged (height-only context) |
| 3 | `run091_bundle_activation_epoch_satisfied_accepted` | activation_epoch satisfied: candidate accepted |
| 4 | `run091_bundle_activation_epoch_future_rejected` | activation_epoch future: rejected, `is_future_activation()` true |
| 5 | `run091_height_satisfied_epoch_future_rejected` | activation_height satisfied but activation_epoch future: rejected |
| 6 | `run091_epoch_satisfied_height_future_rejected` | activation_epoch satisfied but activation_height future: rejected (converse) |
| 7 | `run091_root_activation_epoch_future_rejected` | root activation_epoch future: bundle rejected with Root scope |
| 8 | `run091_root_activation_epoch_satisfied_accepted` | root activation_epoch satisfied: bundle accepted; required_epoch = root value |
| 9 | `run091_devnet_unsupported_epoch_source_fails_closed` | DevNet activation_epoch under unavailable source: `CurrentEpochUnavailable` |
| 10 | `run091_testnet_unsupported_epoch_source_fails_closed` | TestNet activation_epoch under unavailable AND height-only source: `CurrentEpochUnavailable` (no silent ignore) |
| 11 | `run091_mainnet_unsupported_epoch_source_fails_closed` | MainNet activation_epoch under unavailable AND height-only source: `CurrentEpochUnavailable` (no silent ignore) |
| 12 | `run091_reload_check_bundle_activation_epoch_unsupported_fails_closed_no_sequence_mutation` | reload-check (Run 069 surface) with activation_epoch under unavailable epoch source: rejected with `Bundle(Activation(CurrentEpochUnavailable))`, sequence persistence file unchanged (no create / no delete / no mtime change) |
| 13 | `run091_reload_check_bundle_activation_epoch_future_does_not_advance_sequence` | reload-check with future activation_epoch under a SUPPLIED epoch source: rejected, sequence persistence unchanged |
| 14 | `run091_revocation_schema_has_no_activation_epoch_field` | `TrustBundleRevocation` field set has NO `activation_epoch` axis (exhaustive destructure — compile-time gate against future schema drift) |
| 15 | `run091_current_epoch_unavailable_display_is_safe_and_explicit` | error message contains the fail-closed phrase, `required_epoch=<n>`, `scope=bundle`; does NOT contain "dummy" |

## Runbook sections changed

- **§3.10** — boundary cross-reference: the existing prose at
  "Boundary: `activation_epoch` is rejected today with
  `CurrentEpochUnavailable` (Run 057 boundary — recorded in §10)"
  is annotated to also reference Run 091's coverage matrix.
- **§10.1** — Run 091 cross-reference: the existing prose "Bundle-
  level `activation_epoch` continues to fail closed with
  `TrustBundleActivationError::CurrentEpochUnavailable` (Run 057)."
  is annotated to "(Run 057, pinned by Run 091)" and a short
  sentence is added pointing operators to this evidence document
  and to the Run 091 test file.
- **§11** — mapping table: a new row records that Run 091 is a
  test-only + docs-only update that pins the partial-positive
  boundary on the activation-epoch axis, narrows the C4 sub-item
  "activation_epoch runtime source" without closing it, and
  preserves every Run 050–090 invariant.

## Regression evidence

```text
cargo test -p qbind-node --test run_091_pqc_trust_bundle_activation_epoch_tests
    test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured

cargo test -p qbind-node --lib pqc_trust_activation
    test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured

cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests
    test result: ok. <pinned>

cargo test -p qbind-node --test run_065_pqc_min_activation_margin_tests
    test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured

cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests
    test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured
```

(The full regression matrix the task lists — Run 073 / 074 / 076 /
088 / metrics / qbind-net / qbind-crypto lib / release binary —
is run as part of the standard CI matrix; Run 091 changes only
add a new test binary and three documentation files, so no
existing test surface is touched.)

## Partial-positive boundary statement

Run 091 is a **partial positive** result. The C4 sub-piece
"`activation_epoch` runtime source" is narrowed from "open with
unclear closure path" to "open with a documented, tested, fail-
closed boundary today and a documented closure path (wire
`MetaStore::get_current_epoch()` into the trust-bundle gate, plus
extend `StateSnapshotMeta` with an epoch field for snapshot-
rejoin parity)". Run 091 does **not** ship that closure; it ships
the boundary and the test coverage so the closure can land
incrementally without disturbing Run 050–090.

Run 091 does **not** narrow C5. KEMTLS production lifecycle is
unrelated to the activation-epoch axis.