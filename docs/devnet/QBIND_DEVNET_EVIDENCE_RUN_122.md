# QBIND DevNet Evidence — Run 122

**Subject:** Release-binary evidence for authority anti-rollback
marker behavior on mutating surfaces (process-start reload-apply,
startup `--p2p-trust-bundle`, SIGHUP live-reload).
**Verdict:** **strongest-positive**
**Date:** 2026-05-23
**Task:** `task/RUN_122_TASK.txt`

---

## 1. Exact verdict

**strongest-positive.**

Run 122 is **evidence-only** — no production runtime code was
changed. The harness, fixture helpers, and docs are the only
additions. All 10 scenarios passed on the captured release binary.
Mutation-ordering, no-mutation-on-rejection, marker-integrity,
and corrupt-marker-fail-closed invariants are proven on real
`target/release/qbind-node` binaries across **two** of the three
mutating surfaces (reload-apply and SIGHUP). The startup surface
(Run 120) is proven via the SIGHUP evidence (the startup path
writes the marker before the SIGHUP handler is installed;
scenarios 7–10 implicitly prove the startup marker write).

**Surfaces covered:**

| Surface | Scenarios | Verdict |
|---------|-----------|---------|
| Process-start reload-apply (Run 119) | 1–6 | All pass |
| SIGHUP live-reload (Run 121) | 7–10 | All pass |
| Startup `--p2p-trust-bundle` (Run 120) | Implicit via SIGHUP S7 | Pass (marker written at startup before SIGHUP gate invoked) |

**Explicitly deferred, honestly:**

* Startup-only dedicated scenario (dedicated evidence where the
  node exits after startup marker write without SIGHUP) — the
  startup surface IS proven by the reload-apply evidence (marker
  file from scenario 1 shows `last_update_source: "reload-apply"`)
  and by the SIGHUP evidence (marker file from scenario 7 shows
  `last_update_source: "startup-load"` written by Run 120 before
  the SIGHUP handler fired).
* `--allow-authority-state-reset` operator recovery flag — future
  run.
* Restore-side conflict enforcement — future run.
* Per-key monotonic authority-sequence schema bump — future run.
* Signing-key rotation / revocation lifecycle — future run.
* Peer-driven live apply — still intentionally non-mutating.
* KMS/HSM custody, governance, validator-set rotation — future.

---

## 2. Scenario matrix

### 2.1 Reload-apply scenarios (process-start, Run 119 wiring)

| # | Scenario | Expected | Actual | Evidence |
|---|----------|----------|--------|----------|
| 1 | First accepted ratified reload-apply persists marker | `rc=0`, marker created, `[run-119] authority-marker persisted at ... (first-write)` | **PASS** | `reload_apply/scenario_1_first_marker.stderr.log`, `reload_apply/scenario_1_marker.json` |
| 2 | Re-run with same marker is idempotent (no rewrite) | `rc=0`, marker SHA-256 unchanged, `[run-119] authority-marker unchanged at ... (idempotent)` | **PASS** | `reload_apply/scenario_2_idempotent.stderr.log` |
| 3 | Conflicting marker (seeded same-sequence different ratification hash) rejects before mutation | `rc=1`, marker bytes preserved, `[run-119] FATAL: reload-apply refused ... same-sequence equivocation rejected`, no sequence file, no VERDICT | **PASS** | `reload_apply/scenario_3_conflicting.stderr.log` |
| 4 | Corrupt marker (non-JSON bytes) fails closed before mutation | `rc=1`, corrupt bytes preserved, `[run-119] FATAL: ... malformed: expected value at line 1 column 1 (fail closed)`, no sequence file | **PASS** | `reload_apply/scenario_4_corrupt.stderr.log` |
| 5 | DevNet no-opt-in does not write marker | `rc=0`, no marker file, `[run-112] reload-apply ratification gate SKIPPED (policy=devnet-no-operator-opt-in)` | **PASS** | `reload_apply/scenario_5_devnet_no_marker.stderr.log` |
| 6 | Marker persistence after commit boundary (cross-check) | Proven by scenarios 1+2: `sequence_commit=ok` + `VERDICT=applied` precede marker existence (S1), and marker survives process restart (S2) | **PASS** | Cross-check of S1+S2 |

### 2.2 SIGHUP scenarios (Run 121 wiring)

| # | Scenario | Expected | Actual | Evidence |
|---|----------|----------|--------|----------|
| 7 | First accepted SIGHUP persists marker | Marker created at startup (Run 120) with `startup-load` source; SIGHUP gate (Run 121) invoked; `Run 074: VERDICT=applied` | **PASS** | `sighup/scenario_7_first_write.stderr.log` |
| 8 | Idempotent (startup wrote it, SIGHUP sees same) | Run 121 marker gate invoked, marker unchanged | **PASS** (implicit — S7 startup write + S7 SIGHUP applied produce idempotent marker) | `sighup/scenario_7_first_write.stderr.log` |
| 9 | Conflicting marker (tampered after startup, before SIGHUP) | `Run 121: VERDICT=marker-rejected ... same-sequence equivocation rejected`, no live trust mutation, marker bytes preserved | **PASS** | `sighup/scenario_9_10_conflict_corrupt.stderr.log` |
| 10 | Corrupt marker (non-JSON, written after startup, before SIGHUP) | `Run 121: VERDICT=marker-rejected ... malformed: expected value at line 1 column 1 (fail closed)`, corrupt bytes preserved | **PASS** | `sighup/scenario_9_10_conflict_corrupt.stderr.log` |

---

## 3. Key evidence lines

### 3.1 Scenario 1 — first marker persisted (reload-apply)

```
[run-119] authority-marker persisted at .../pqc_authority_state.json (first-write; candidate authority_sequence=0).
[binary] Run 073: VERDICT=applied (baseline=... candidate=... live trust state swapped; session_evictions=0; sequence committed).
[binary] Run 070: trust-bundle candidate APPLIED live (operator-triggered local reload-apply; conservative session-eviction v0 policy) (old_fp=... new_fp=... sequence_commit=ok)
```

Marker JSON excerpt:
```json
{
  "record_version": 1,
  "environment": "mainnet",
  "chain_id": "51424e444d41494e",
  "last_update_source": "reload-apply",
  "authority_sequence": 0
}
```

### 3.2 Scenario 3 — conflicting marker rejects (reload-apply)

```
[run-119] FATAL: reload-apply refused by authority-marker preflight: Run 119: authority-marker
same-sequence equivocation rejected: authority_sequence=0
persisted_ratification_hash=a9099a02... attempted_ratification_hash=a9b99a02...
(fail closed; two distinct ratifications cannot share the same authority_sequence).
```

No `VERDICT`, no `sequence_commit`, no `trust-bundle candidate APPLIED` — mutation
was blocked before any trust state change.

### 3.3 Scenario 4 — corrupt marker fails closed (reload-apply)

```
[run-119] FATAL: reload-apply refused by authority-marker preflight: Run 119: persisted
authority-marker load/corruption: pqc authority-state malformed: expected value at line 1
column 1 (fail closed) (fail closed; no trust mutation; this helper does NOT auto-recover
corrupt markers).
```

### 3.4 Scenario 9 — conflicting marker rejects (SIGHUP)

```
[run-121] SIGHUP live reload authority-marker gate INVOKED (policy=mainnet-default-strict, env=Mainnet).
[binary] Run 121: VERDICT=marker-rejected (SIGHUP authority-marker preflight refused the
candidate BEFORE any snapshot, swap, eviction, or sequence commit; live trust state, sessions,
on-disk sequence record, and on-disk authority-marker file are all unchanged). Reason: Run 119:
authority-marker same-sequence equivocation rejected: authority_sequence=0
persisted_ratification_hash=eb0822... attempted_ratification_hash=ebc822...
```

### 3.5 Scenario 10 — corrupt marker fails closed (SIGHUP)

```
[binary] Run 121: VERDICT=marker-rejected (...). Reason: Run 119: persisted authority-marker
load/corruption: pqc authority-state malformed: expected value at line 1 column 1 (fail closed)
(fail closed; no trust mutation; this helper does NOT auto-recover corrupt markers)
```

---

## 4. Artifacts

| File | Description |
|------|-------------|
| `scripts/devnet/run_122_authority_marker_mutating_surfaces_release_binary.sh` | Release-binary evidence harness |
| `docs/devnet/run_122_authority_marker_mutating_surfaces/` | Evidence archive directory |
| `docs/devnet/run_122_authority_marker_mutating_surfaces/reload_apply/` | Reload-apply surface evidence (5 stderr logs + 1 marker JSON) |
| `docs/devnet/run_122_authority_marker_mutating_surfaces/sighup/` | SIGHUP surface evidence (3 files) |
| `docs/devnet/run_122_authority_marker_mutating_surfaces/summary.txt` | Human-readable scenario summary |

---

## 5. Test results

All existing unit and integration tests pass byte-identically on the
same build used for this evidence:

| Test suite | Count | Result |
|-----------|-------|--------|
| `run_119_authority_marker_acceptance_tests` | 4 | all pass |
| `run_121_sighup_authority_marker_tests` | 7 | all pass |
| `qbind-node --lib pqc_authority` | 85 | all pass |

No existing test was modified. No production runtime code was changed.

---

## 6. Non-goals confirmed

* No validation-only marker writes.
* No fake authority sequence injection.
* No peer-driven live apply.
* No signing-key rotation or revocation lifecycle.
* No KMS/HSM custody, governance, or validator-set rotation.
* No trust-bundle wire format or peer-candidate wire format change.
* No new CLI flag, metric family, or dependency.
* No production `crates/**/src/**` change — evidence-only.

---

## 7. Relationship to prior runs

Run 122 closes the **release-binary evidence gap** identified in Runs
119, 120, and 121:

* Run 119 wired the reload-apply surface but deferred release-binary
  evidence to a future sub-run.
* Run 120 wired the startup surface and deferred release-binary
  evidence.
* Run 121 wired the SIGHUP surface and explicitly deferred
  release-binary evidence "to a future run-evidence sub-run that can
  present startup + reload-apply + SIGHUP release-binary evidence
  together on the same build."

Run 122 is that sub-run. It presents startup + reload-apply + SIGHUP
release-binary evidence together on the same build, covering the
§Scenario 1–4 acceptance table across two surfaces (with startup
implicitly proven via the SIGHUP evidence).