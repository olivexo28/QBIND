# QBIND DevNet Evidence — Run 046

## §1. Exact objective

Replace the fixed binary B14 view-timeout cadence with a bounded
exponential-backoff pacer so repeated absent-leader / no-progress
views do not fire `TimeoutMsg`s at a constant aggressive cadence,
while preserving B14 safety, active timeout verification,
forged-traffic rejection guarantees, and recovery liveness.

This is a **timeout-pacing task**. It is NOT a consensus-safety
redesign, NOT a new view-change protocol, NOT a transport / certificate
task, and NOT a claim of full C4 closure. The smallest production-honest
change.

## §2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-node/src/binary_consensus_loop.rs` | Added `DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_MULTIPLIER = 2` and `DEFAULT_BINARY_CONSENSUS_VIEW_TIMEOUT_MAX_TICKS = 800`. Added `BinaryConsensusLoopConfig` fields `view_timeout_backoff_multiplier` and `view_timeout_max_ticks` with builder methods. Added the `ViewTimeoutBackoffState` struct (base/multiplier/max/level, integer arithmetic, fail-closed on invalid config via `ViewTimeoutBackoffConfigError`) and a `ViewTimeoutProgress` helper struct distinguishing view-only vs commit progress. Changed `ViewTimeoutState::observe(...)` return type from `bool` to `ViewTimeoutProgress` (single call site updated in-place). Changed `maybe_emit_view_timeout(...)` signature to take `&mut ViewTimeoutBackoffState` in place of `view_timeout_ticks: Option<u64>`; threshold is now read from `backoff.threshold()`; pacer level is reset on committed-height progress only; pacer level is increased exactly once on successful local emission (recorded on the success path, after `engine.mark_timeout_emitted()` and `stats.view_timeouts_emitted += 1`). Wired the two production call sites (inbound-rx and no-inbound-io branches) to construct and re-use a per-loop `view_timeout_backoff` and pushed its state to `/metrics` on each tick via the new `update_binary_view_timeout_backoff_metrics(...)` helper. All 14 in-file test call sites updated to construct a `ViewTimeoutBackoffState::no_growth(...)` (multiplier=1, max=u64::MAX) so existing fixed-cadence semantics are preserved bit-identically for the pre-Run-046 tests. Added 11 new `run046_*` unit tests (default-base-equals-old, doubles-then-saturates, reset-counts-real-only, multiplier-1-preserves-fixed-cadence, invalid-config-rejected-fail-closed, disabled-primitive-inert, second-view-emits-at-doubled-threshold-after-self-fire, committed-height-progress-resets-pacer, view-only-progress-does-not-reset-pacer, metrics-export-reflects-pacer-state-exactly, metrics-export-disabled-primitive-reads-zero). |
| `crates/qbind-node/src/metrics.rs` | Added five new fields on `BinaryViewTimeoutMetrics`: `view_timeout_current_threshold_ticks`, `view_timeout_backoff_level`, `view_timeout_backoff_resets_total`, `view_timeout_backoff_increases_total`, `view_timeout_max_cap_hits_total`. Added the `set_run046(...)` method to store them atomically. Extended `format_metrics()` to emit five new `# Binary view-timeout exponential-backoff pacing (Run 046)` lines: `qbind_consensus_view_timeout_current_threshold_ticks`, `qbind_consensus_view_timeout_backoff_level`, `qbind_consensus_view_timeout_backoff_resets_total`, `qbind_consensus_view_timeout_backoff_increases_total`, `qbind_consensus_view_timeout_max_cap_hits_total`. |
| `docs/whitepaper/contradiction.md` | Appended Run 046 paragraph narrowing the documented C4 "exponential-backoff timeout pacing" cell on the binary path. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_046.md` | **NEW** — this file. |

No other crate / module was touched. No protocol behavior beyond
the threshold the pacer uses to decide whether to emit a local
`TimeoutMsg` was changed. The wire-format of `TimeoutMsg`,
`TimeoutCertificate`, and `NewView` is untouched. Verification
semantics, signing semantics, restore-catchup gating,
single-validator suppression, and `--require-timeout-verification`
behaviour are all unchanged.

## §3. Pacing semantics — exact specification

The pacer is deterministic, tick-based, and uses only integer
arithmetic. No floating-point appears in the binary tick loop, so
the schedule is bit-deterministic for tests and replays.

### Configuration

| Parameter | Default | Validation |
|---|---|---|
| `view_timeout_ticks` (base) | `Some(50)` (unchanged from pre-Run-046) | `Some(0)` rejected |
| `view_timeout_backoff_multiplier` | `2` | `< 1` (i.e. `0`) rejected |
| `view_timeout_max_ticks` | `800` | `< base` rejected when `base` is `Some(_)` |

Invalid configuration **fails closed**: the pacer is constructed
disabled (`threshold() == None`) and a single warning line is
emitted. No silent fallback to the pre-Run-046 fixed cadence; no
secret default; no "ignore validation" bypass.

### Threshold schedule

At default settings: `50, 100, 200, 400, 800, 800, 800, …`. The
fourth increase lands exactly on the cap of 800 ticks (recorded as
one `max_cap_hits_total`), and every subsequent increase attempt
records an additional cap-hit without changing the threshold.

### Reset condition (truthful — no fabricated resets)

`reset_on_progress()` resets the pacer level to 0 and the
threshold to `base` if and only if **committed-height** strictly
increased since the previous `observe(...)` call. View-only
advances (including TC-driven view advances, which are themselves
timeout-driven and therefore NOT a recovery signal) do **not**
reset the pacer. This matches the standard HotStuff pacemaker
convention that only commits demonstrate liveness, and is the
strictest signal we can wire without introducing false positives
that would defeat the purpose of the backoff.

`backoff_resets_total` increments only when the reset genuinely
lowered the threshold (i.e. the level was non-zero); no-op resets
at base do not increment.

### Increase condition

`increase_after_timeout()` is called exactly once per successful
local `TimeoutMsg` emission, after `engine.mark_timeout_emitted()`
and after the canonical `view_timeouts_emitted` counter is
incremented. It is NOT called on the early-return / fail-closed
paths (signer missing, signing failed, broadcast failed, etc.):
those paths bail out before reaching the success-broadcast site.

`backoff_increases_total` increments only when the increase
genuinely raised the threshold (multiplier=1 calls do not
increment).

`max_cap_hits_total` increments when an increase lands at or
exceeds the cap (the transition into saturation) AND on every
subsequent already-saturated increase attempt. Both branches
record honestly what the pacer was asked to do.

### Tick-window boundary (inclusive)

The same inclusive boundary the pre-Run-046 path used:
`current_tick - last_progress_tick >= threshold` ⇒ window elapsed.
First timeout fires at exactly the same tick as pre-Run-046 (because
the pacer starts at level 0, threshold = base). Only subsequent
no-commit-progress views see the larger thresholds.

## §4. Safety / non-regression checklist

| Property | Status under Run 046 |
|---|---|
| At most one local `TimeoutMsg` per view per validator | Preserved — gate via `engine.timeout_emitted_in_view()` unchanged. |
| `--require-timeout-verification` semantics | Untouched — the verification context is threaded through unchanged. |
| Forged traffic cannot advance views | Untouched — verification still runs first; rejected traffic never reaches `engine.on_timeout_msg` / `engine.on_timeout_certificate`. |
| Restore-catchup suppression (`RestoreCatchupModeState.active = true` ⇒ no emission) | Preserved — gate ordering unchanged. |
| Single-validator / no-outbound-facade suppression | Preserved — the `outbound.is_none()` early-return is unchanged. |
| TC verification semantics | Untouched. |
| `TimeoutMsg` / `TimeoutCertificate` / `NewView` wire format | Untouched. |
| `view_timeouts_emitted`, `timeout_certificates_formed`, `outbound_new_views_sent`, `view_timeout_advances`, `view_advances_due_to_verified_tc_total` | Names and meaning preserved exactly. |
| Consensus uses wall-clock time | NO — pacer is purely tick-based. Wall-clock remains used only for transport cert freshness (Run 045). |
| Run 037–045 PQC transport behaviour | Preserved — `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` 12/12 pass. |
| Pre-existing B14 test suite | Preserved — 791/791 qbind-node lib tests pass. |

## §5. New `/metrics` lines (Prometheus text format)

Emitted unconditionally on every tick alongside existing B14
metrics. Values reflect the current in-process pacer state exactly
— no fabrication, no smoothing, no defaults.

```
# Binary view-timeout exponential-backoff pacing (Run 046)
qbind_consensus_view_timeout_current_threshold_ticks <u64>
qbind_consensus_view_timeout_backoff_level <u64>
qbind_consensus_view_timeout_backoff_resets_total <u64>
qbind_consensus_view_timeout_backoff_increases_total <u64>
qbind_consensus_view_timeout_max_cap_hits_total <u64>
```

When `view_timeout_ticks = None` (primitive disabled) all five
gauges/counters read `0` for the lifetime of the loop. There is no
sentinel "disabled" magic number; the disabled state is observable
externally as "current_threshold_ticks == 0 AND
backoff_increases_total stays at 0 across many ticks".

## §6. Test evidence

Command:

```
cargo test -p qbind-node --lib binary_consensus
```

Result: 63 passed; 0 failed; 0 ignored. This is the original 52 B14
/ Run 030 / restore-mode / snapshot-trigger tests plus the 11 new
`run046_*` tests:

- `run046_default_base_equals_old_fixed_threshold`
- `run046_threshold_doubles_then_saturates_at_max`
- `run046_reset_returns_to_base_and_counts_real_resets_only`
- `run046_multiplier_one_preserves_fixed_cadence`
- `run046_invalid_config_rejected_fail_closed`
- `run046_disabled_primitive_is_inert`
- `run046_second_view_emits_at_doubled_threshold_after_self_fire`
- `run046_committed_height_progress_resets_pacer`
- `run046_view_only_progress_does_not_reset_pacer`
- `run046_metrics_export_reflects_pacer_state_exactly`
- `run046_metrics_export_disabled_primitive_reads_zero`

Full library suite:

```
cargo test -p qbind-node --lib
# test result: ok. 791 passed; 0 failed; 0 ignored; 0 measured
```

Run 037 PQC transport regression check:

```
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
# test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured
```

## §7. Truthful framing — what Run 046 does NOT close

- **C4 is NOT closed.** The "exponential-backoff timeout pacing"
  remaining-item is now NARROWED on the binary B14 path
  (production-default base 50 ticks, multiplier 2, max 800 ticks,
  reset-on-committed-height-progress, fully observable on `/metrics`),
  but C4 still has open items: production CA / cert rotation / cert
  revocation / signed root distribution lifecycle; production
  fast-sync / consensus-storage restore; per-environment trust
  anchors.
- **C5 is NOT closed.** Run 046 does not touch transport-root
  dependency, transport KEM, transport AEAD, forged-traffic
  rejection, or timeout-verification activation. Those remain in
  the post-Run-045 state.
- **No new view-change protocol.** Run 046 does not redesign
  HotStuff or B14 timeout / new-view message semantics. The same
  `TimeoutMsg` / `TimeoutCertificate` / `NewView` payloads, the
  same `engine.on_timeout_msg` / `engine.on_timeout_certificate`
  ingestion path, the same 2/3 quorum rule.
- **No DummySig / DummyKem / DummyAead reintroduction or
  strengthening.** The crypto path is unchanged from Run 042 / 044
  / 045.
- **No claim of liveness guarantees beyond pre-Run-046.** The cap
  of 800 ticks is a "do not pace even slower than this" bound, not
  a liveness theorem. A cluster that has been partitioned for
  hours will, after re-convergence, still see view-timeout fires
  bounded by 800 ticks each, and a single committed-height advance
  will fully reset the pacer back to base.
- **No live-binary N=4 multi-validator backoff smoke run was
  performed in this Run.** The 11 unit tests prove the pacer state
  machine, the wiring into `maybe_emit_view_timeout`, and the
  metric exposition; the new metric lines are visible on `/metrics`
  immediately at loop start because they are unconditional. A
  live-binary N=4 absent-leader smoke proving multi-view backoff
  progression on a real binary at real /metrics is reasonable
  future work and is not claimed here.

## §8. Files NOT changed

For audit clarity:

- `crates/qbind-consensus/**` — untouched. The existing
  `TimeoutPacemakerConfig` / `TimeoutPacemaker` is Duration-based
  and was deliberately not threaded through the binary loop;
  the binary loop is tick-deterministic and Run 046's pacer is a
  small loop-local state machine that does not import from
  `qbind-consensus`. This was the smallest production-honest
  scope: zero changes to consensus crate, zero risk of touching
  any safety-critical engine path.
- `crates/qbind-crypto/**`, `crates/qbind-net/**`,
  `crates/qbind-wire/**`, `crates/qbind-ledger/**`,
  `crates/qbind-system/**`, `crates/qbind-runtime/**`,
  `crates/qbind-serde/**`, `crates/qbind-types/**` — untouched.
- `crates/qbind-node/tests/**`, `crates/qbind-node/examples/**` —
  untouched (no external test reference `view_timeout_ticks` /
  `view_timeout_backoff` / `ViewTimeoutBackoffState`, verified by
  grep).
- All CLI flags — unchanged. No new CLI flag was added. The
  defaults are production-reasonable (50/2/800) and the change is
  observable on `/metrics`. If operators need to override the
  defaults in a future Run, the builder methods
  (`with_view_timeout_backoff_multiplier`, `with_view_timeout_max_ticks`)
  are already in place; no further binary loop changes will be
  required.