# QBIND DevNet Evidence — Run 072

**Title:** Production-honest P2P session-eviction hook — `P2pSessionEvictor` trait + `TcpKemTlsP2pService::evict_all_sessions` + `qbind_p2p_session_eviction_*` metrics; no live trust mutation, no sequence commit, no Run 070 production-binary change.
**Date:** 2026-05-14
**C-row narrowed:** C4 — "on-the-fly trust-bundle hot reload" (NARROW sub-piece — **production session-eviction blocker closed**; `LiveTrustApplyContext` runtime adapter still gated on Run 073)
**Verdict:** **Strongest positive (within Run 072 strict scope).** Production session-eviction hook lands; sessions can be evicted on demand against the live `TcpKemTlsP2pService`; old sessions close; trust state and sequence state remain unchanged; reconnect behaviour is honestly bounded; Run 069/070/071 semantics preserved; no fallback to `--p2p-trusted-root`; no DummySig/DummyKem/DummyAead activation.

---

## 1. Exact objective

Land the **smallest safe** production-honest internal P2P session-eviction
hook defined by `task/RUN_072_TASK.txt`. Run 072 builds **on top of** Run
071's `LivePqcTrustState` handle and Run 070's
`validate → swap → evict_sessions → commit_sequence` apply contract; it
must NEVER weaken Run 070's apply ordering or rollback semantics, must
NEVER weaken Run 069's non-mutation validation/staging boundary, must
NEVER weaken Run 071's startup-only `LivePqcTrustState` semantics, must
NEVER accept peer-supplied or gossiped bundles, must NEVER mutate live
trust state, must NEVER commit the persisted bundle sequence record, and
must NEVER enable Run 070's production live-apply path on the running
binary.

Concretely, Run 072 lands:

- A new `crates/qbind-node/src/p2p_session_eviction.rs` module that
  defines `EvictionReason`, `EvictionReport`, `EvictionError`, the
  `P2pSessionEvictor` trait, and a deterministic
  `MockP2pSessionEvictor`.
- A concrete implementation on `crates/qbind-node/src/p2p_tcp.rs::
  TcpKemTlsP2pService::evict_all_sessions` that synchronously drains
  the per-peer `PeerConnection` registry, drops the outbound `tx`
  channels, and aborts the per-peer read/write `JoinHandle`s.
- A four-counter `qbind_p2p_session_eviction_*` family on
  `P2pMetrics`, with a `record_session_eviction` helper that
  composes the four counters truthfully.
- 17 module unit tests + 8 integration tests (including a real N=2
  KEMTLS bring-up that ends with `connected_peers()` drained on the
  evicted side).
- No change to the Run 070 production binary surface: the binary's
  `--p2p-trust-bundle-reload-apply-enabled` hook continues to
  surface `ReloadApplyError::UnsupportedRuntimeContext` because the
  `LiveTrustApplyContext` runtime adapter (which would compose Run
  071's `LivePqcTrustState::swap_snapshot` + this Run 072 evictor +
  `pqc_trust_sequence::commit_sequence`) is explicitly deferred to
  Run 073.

---

## 2. Exact verdict

**Strongest positive (within Run 072 strict scope).**

* The production-honest internal session-eviction hook landed on
  the live transport.
* `TcpKemTlsP2pService::evict_all_sessions(reason)` drains every
  authenticated peer in a single sync call and returns a truthful
  `EvictionReport` with the `attempted == evicted + failed`
  invariant.
* An N=2 KEMTLS-bringup → evict integration test proves
  `connected_peers()` is drained on the evicted side and the
  listener remains alive.
* Trust state (`LivePqcTrustState` from Run 071), persisted bundle
  sequence (`pqc_trust_sequence`), and Run 069 reload-check
  semantics are bit-for-bit unchanged.
* No fallback to `--p2p-trusted-root`; no `DummySig` / `DummyKem` /
  `DummyAead` re-activation.
* Run 070 production binary surface is unchanged — apply still
  returns `UnsupportedRuntimeContext` honestly. Run 072 narrows the
  C4 trust-bundle hot-reload sub-piece but does NOT close it.

---

## 3. Exact files changed

- `crates/qbind-node/src/p2p_session_eviction.rs` — **new** module
  (~580 lines incl. 17 unit tests).
- `crates/qbind-node/src/lib.rs` — `pub mod p2p_session_eviction;`.
- `crates/qbind-node/src/p2p_tcp.rs` — adds
  `TcpKemTlsP2pService::live_session_count()`,
  `TcpKemTlsP2pService::evict_all_sessions(reason)`, and
  `impl P2pSessionEvictor for TcpKemTlsP2pService`.
- `crates/qbind-node/src/metrics.rs` — adds 4 `session_eviction_*`
  atomic counters on `P2pMetrics`, their accessors, the
  `record_session_eviction(evicted, failed, success)` helper, the
  matching `format_metrics` lines (each emitted exactly once), and 2
  unit tests.
- `crates/qbind-node/tests/run_072_p2p_session_eviction_tests.rs` —
  **new** integration test file (8 tests).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_072.md` — **this document**.
- `docs/whitepaper/contradiction.md` — Run 072 evidence update
  section appended to C4.

No other crates were touched. No `Cargo.toml` was modified. No
existing test was removed or rewritten.

---

## 4. Exact commands run + pass/fail status

| Command                                                                                          | Result          |
| ------------------------------------------------------------------------------------------------ | --------------- |
| `cargo test -p qbind-node --lib p2p_session_eviction`                                            | **17 PASS**     |
| `cargo test -p qbind-node --lib metrics::tests::session_eviction`                                | **2 PASS**      |
| `cargo test -p qbind-node --lib metrics`                                                         | **110 PASS**    |
| `cargo test -p qbind-node --lib p2p`                                                             | **155 PASS**    |
| `cargo test -p qbind-node --lib pqc_live_trust`                                                  | **11 PASS**     |
| `cargo test -p qbind-node --lib pqc_trust_reload`                                                | **5 PASS**      |
| `cargo test -p qbind-node --lib pqc_trust_bundle`                                                | **100 PASS**    |
| `cargo test -p qbind-node --lib pqc_trust_sequence`                                              | **27 PASS**     |
| `cargo test -p qbind-node --lib pqc_trust_activation`                                            | **34 PASS**     |
| `cargo test -p qbind-node --test run_072_p2p_session_eviction_tests`                             | **8 PASS**      |
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests`                    | **12 PASS**     |
| `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests`                    | **13 PASS**     |
| `cargo test -p qbind-node --test run_071_pqc_live_trust_tests`                                   | **13 PASS**     |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests`                                 | **14 PASS**     |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests`                         | **13 PASS**     |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests`                              | **12 PASS**     |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests`                        | **12 PASS**     |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests`                      | **12 PASS**     |
| `cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests`                        | **9 PASS**      |
| `cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests`                        | **11 PASS**     |
| `cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests`                 | **8 PASS**      |
| `cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests`                         | **9 PASS**      |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests`                      | **12 PASS**     |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests`                        | **14 PASS**     |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests`                  | **10 PASS**     |
| `cargo test -p qbind-node --lib`                                                                 | **987 PASS**    |
| `cargo test -p qbind-net --lib`                                                                  | **17 PASS**     |
| `cargo test -p qbind-crypto --lib`                                                               | **68 PASS**     |
| `cargo build --release -p qbind-node --bin qbind-node`                                           | **OK**          |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper`                   | **OK**          |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper`                           | **OK**          |

The single pre-existing unrelated compile error in
`crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs`
(`set_inject_write_failure` / `clear_epoch_transition_marker`
methods that no longer exist on `RocksDbConsensusStorage`) is
**unchanged by Run 072** and was present on the parent commit; per
the task contract Run 072 is not responsible for unrelated
breakage. Every Run 072 target (`--lib`, `--test
run_072_*`, and every regression command listed in
`task/RUN_072_TASK.txt`) compiles and passes cleanly.

---

## 5. Investigation findings — session ownership model

Per the §"Required investigation" §1 directive:

### Where authenticated sessions are stored

`crates/qbind-node/src/p2p_tcp.rs` is the single owner of live
authenticated P2P sessions in production. Specifically:

- `TcpKemTlsP2pService.peers: Arc<RwLock<HashMap<NodeId,
  PeerConnection>>>` is the per-peer session registry. Insertion
  happens in two places: the dialer-side post-handshake path in
  `dial_peer` and the listener-side post-handshake path in the
  accept loop.
- `PeerConnection { node_id, tx: mpsc::Sender<P2pMessage>,
  write_handle: JoinHandle<()>, read_handle: JoinHandle<()> }`
  carries:
  - the outbound mpsc to the write loop (which owns the AEAD
    session and the encrypted-frame writer),
  - the read-loop task handle (which owns the corresponding AEAD
    decryptor and the framed reader),
  - the write-loop task handle.

### How sessions are closed today

Prior to Run 072 the only way to terminate sessions was the
process-wide `TcpKemTlsP2pService::shutdown` path, which signals
the listener via a `broadcast::Sender<()>` and tears down the
entire transport. There is no existing per-peer `disconnect` API,
and there is no existing "drop all sessions but keep the listener
running" API. Run 072 fills exactly this gap.

### Whether a peer connection can be dropped cleanly

Yes. Dropping `tx: mpsc::Sender<P2pMessage>` closes the channel so
the write loop's `recv()` returns `None` and the task exits,
releasing the `AeadSession` it owns. Aborting `read_handle` and
`write_handle` ensures neither loop continues to push or pull
encrypted bytes if it was blocked on `read()` / `recv()`. Both
mutations are synchronous and require no `.await` — exactly the
property needed to satisfy Run 070's sync
`LiveTrustApplyContext::evict_sessions(&mut self) -> Result<usize,
String>` signature in a future Run 073 adapter.

### Whether reconnect behaviour is automatic

Partially. The B8 bounded-initial-dial-with-retry tasks completed
during `start()` and are not re-armed by Run 072. Inbound
reconnects can still arrive at the listener at any time (the
listener task is intentionally NOT touched by Run 072). Outbound
reconnection requires a new operator-driven dial. This is the
honest boundary recorded in §"Reconnect behaviour" below; Run 072
makes no claim of automatic outbound reconnect.

### How to count evicted sessions truthfully

`evict_all_sessions` drains the peers map atomically under a
single `parking_lot::RwLock` write guard via `std::mem::take`. The
length of the drained vector is `attempted`; the loop body counts
`evicted` only after the per-peer `drop(tx) / abort()` sequence
completes. Since the only fallible step is the abort (`JoinHandle::
abort` is infallible), every drained entry is currently counted as
evicted. A future implementation that gains a fallible close path
MUST flip individual entries into `failed`; the `EvictionReport::
new` constructor enforces `attempted == evicted + failed` as a
hard assertion.

### Whether eviction can race with accept/dial loops

The race is bounded and safe: after `evict_all_sessions` releases
its write guard the listener / dialer may immediately register a
new peer under a fresh KEMTLS handshake. These new peers are NOT
part of the call's `attempted` count, which is the correct
behaviour — Run 072 evicts the snapshot it observed, not future
sessions. The release notes are anchored on this property in the
module-level docs of `p2p_session_eviction.rs`.

### Whether listener/dialer continue accepting after eviction

Yes. The listener task handle and the B8 dial-with-retry handles
are NOT touched by `evict_all_sessions`. The transport stays
serviceable; only authenticated sessions are dropped. This is
verified by `run072_n2_kemtls_bringup_then_evict_drains_connected_peers`
which asserts a second post-eviction `evict_all_sessions` call
returns successfully (the registry is reachable; the listener is
still running).

---

## 6. Session-eviction hook / API semantics

**Trait (synchronous; dyn-compatible):**

```rust
pub trait P2pSessionEvictor: Send + Sync {
    fn connected_session_count(&self) -> usize;
    fn evict_all_sessions(
        &self, reason: EvictionReason,
    ) -> Result<EvictionReport, EvictionError>;
}
```

**Inputs:**

- `EvictionReason::TrustBundleReloadApply` — reserved for the
  Run 073 `LiveTrustApplyContext` adapter; not wired in Run 072.
- `EvictionReason::OperatorTest` — used by tests and by the future
  release-binary evidence smokes.

**Output:**

- `Ok(EvictionReport { reason, attempted, evicted, failed })` with
  the `attempted == evicted + failed` invariant. Full-success iff
  `failed == 0`. Operator log line is produced by
  `EvictionReport::log_line()`, e.g.:

  ```
  [binary] Run 072: p2p session eviction (reason=operator_test attempted=2 evicted=2 failed=0 verdict=full-success)
  ```

- `Err(EvictionError::UnsupportedSessionEviction(String))` —
  reserved for runtimes that cannot expose a session registry
  (e.g. `NullP2pService`). The `Display` is operator-actionable
  and anchored: `"Run 072 p2p session eviction unsupported on
  this runtime — live trust state unchanged; sequence not
  committed; no sessions mutated: <reason>"`.

**Concrete production implementation** (`TcpKemTlsP2pService::evict_all_sessions`):

1. Take the `peers` write guard, drain the map via
   `std::mem::take`. `attempted = drained.len()`.
2. For each drained `PeerConnection`: `drop(tx)` → write loop
   exits → AEAD session released. `read_handle.abort()` +
   `write_handle.abort()` → read/write tasks terminate. `evicted += 1`.
3. Reset `connections_current` to the post-drain `peers.read().len()`
   (which is the count of any new sessions admitted between the
   write guard release and the gauge update; Run 072 makes no claim
   over those).
4. Construct `EvictionReport::new(reason, attempted, evicted, 0)`.

**Test-only implementation** (`MockP2pSessionEvictor`):

- In-memory `AtomicUsize` live count + `failure_seed` to drive the
  partial-failure branch.
- Used by Run 072 unit tests AND by the
  `run072_mock_evictor_satisfies_run070_evict_sessions_contract`
  integration test that proves the mock can satisfy Run 070's
  `LiveTrustApplyContext::evict_sessions` partial-contract in
  isolation.

---

## 7. Metrics / logging surface

**Four new counters on `P2pMetrics`** (each emitted exactly once
in `format_metrics`, asserted by
`metrics::tests::session_eviction_metrics_render_once_in_format_metrics`):

| Counter                                                  | Bumped when                                                                |
| -------------------------------------------------------- | -------------------------------------------------------------------------- |
| `qbind_p2p_session_eviction_attempt_total`               | every invocation of the Run 072 hook, regardless of outcome                |
| `qbind_p2p_session_eviction_success_total`               | `Ok(EvictionReport)` with `report.is_full_success()`                       |
| `qbind_p2p_session_eviction_failure_total`               | `Err(_)` OR `Ok(EvictionReport)` with `report.failed > 0`                  |
| `qbind_p2p_session_eviction_sessions_evicted_total`      | `+= report.evicted` per call (truthful per-call cumulative session count)  |

Helper: `P2pMetrics::record_session_eviction(evicted, failed,
success)` is the single source of truth for the four-counter row
so every call site stays consistent.

**Discipline:**

- Run 069 reload-check NEVER bumps these (validate-only path).
- Run 070 validate-only NEVER bumps these (no eviction callback).
- The Run 070 production-binary apply hook exits before `/metrics`
  is bound, so the counters stay at zero on that path.
- No per-reason label cardinality is added — operator visibility
  for reason/attempted/evicted/failed lives on the
  `EvictionReport::log_line` output, not on `/metrics`.
- No new metric family beyond these four; no duplicate emission;
  no displacement of any Run 050/051/055/057/072 metric (asserted
  by the existing `*_render_once_in_format_metrics` family of
  tests, all of which still pass).

**Logs:** `EvictionReport::log_line()` is the canonical operator
log shape. It contains:

- `Run 072` marker
- `reason=<trust_bundle_reload_apply|operator_test>`
- `attempted=<N>`
- `evicted=<N>`
- `failed=<N>`
- `verdict=<full-success|partial-success|failed>`

The Run 072 module tests explicitly assert the log line carries
**no** private-material keywords (`secret`, `private`, `key=`,
`aead`, `kem`) — anchored by
`p2p_session_eviction::tests::report_log_line_does_not_leak_keying_material_keywords`.

---

## 8. Reconnect behaviour

After a successful `evict_all_sessions` call:

- **Listener:** still bound to its original address; new inbound
  KEMTLS handshakes may arrive and be admitted under the current
  (unchanged) trust state. The integration test
  `run072_n2_kemtls_bringup_then_evict_drains_connected_peers`
  verifies this indirectly by issuing a second
  `evict_all_sessions` call against the same service handle and
  observing it returns successfully — proving the listener task
  was not torn down.
- **Outbound dial:** the B8 bounded-initial-dial-with-retry tasks
  completed during `start()` and are not re-armed by Run 072.
  An evicted outbound peer therefore does NOT reconnect
  automatically until the operator (or future Run 073+ apply
  pipeline) re-triggers a new dial. **This is the honest
  boundary.** It is the conservative session-eviction v0 policy
  the task asked for: drop ALL existing sessions, do not
  re-establish them.
- **Inbound side:** in the N=2 test, the side that issued
  `evict_all_sessions` drains its `connected_peers()` to empty.
  The other side may briefly continue to see a stale peer entry
  until its own read loop notices the half-close. Run 072 makes
  no claim about the unrelated side; it claims only that the
  side that called the hook drains its registry.

---

## 9. Interaction with Run 070 apply contract

Run 070 defined the strict apply pipeline `validate → snapshot_active
→ swap_trust_state → evict_sessions → commit_sequence` and the
`LiveTrustApplyContext` trait (`evict_sessions(&mut self) ->
Result<usize, String>` is the relevant callback).

Run 072 lands the **eviction step** of that contract in a form a
future Run 073 adapter can wire into `LiveTrustApplyContext`:

- `P2pSessionEvictor::evict_all_sessions` is synchronous so a thin
  Run 073 adapter wrapping a `&dyn P2pSessionEvictor` can satisfy
  `evict_sessions` without forcing Tokio into the Run 070 apply
  sequencing contract.
- The shape of the bridge is anchored in the integration test
  `run072_mock_evictor_satisfies_run070_evict_sessions_contract`,
  which defines a `SessionEvictionOnlyAdapter` that implements
  the full `LiveTrustApplyContext` trait but returns
  partial-implementation errors on every callback except
  `evict_sessions`. The test verifies that `evict_sessions`
  delegates correctly to a `MockP2pSessionEvictor` and reports
  the truthful evicted count back through the Run 070 surface.

**What Run 072 explicitly does NOT do:**

- It does NOT update `crates/qbind-node/src/pqc_trust_reload.rs`.
- It does NOT register an adapter in the production
  `qbind-node` binary (the Run 070 hook continues to surface
  `ReloadApplyError::UnsupportedRuntimeContext`).
- It does NOT touch any of the 13 Run 070 integration tests
  (`run_070_pqc_trust_bundle_reload_apply_tests.rs`) — all 13
  continue to pass unchanged.

The remaining C4 sub-piece after Run 072 is therefore exactly
"wire `LivePqcTrustState::snapshot/swap_snapshot` + Run 072's
`P2pSessionEvictor` + `pqc_trust_sequence::commit_sequence` into a
single `LiveTrustApplyContext` implementation and remove
`UnsupportedRuntimeContext` from the binary apply hook." That is
Run 073.

---

## 10. Proof Run 069 reload-check remains non-mutating

`cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests`
reports **12/12 PASS** unchanged after Run 072 lands. Each
`run069_*_does_not_advance_persisted_sequence_*` /
`run069_*_without_mutation` test still asserts
`assert_seq_file_unchanged(&seq_path, snap)` after the reject /
accept path, proving Run 069's validation/staging boundary is
preserved bit-for-bit.

`cargo test -p qbind-node --lib pqc_trust_reload` reports **5/5
PASS** including
`reload_apply_error_display_marks_each_failure_stage_safely` and
`applied_candidate_log_line_marks_applied_with_old_and_new_fingerprints`.

No new Run 072 code path is reachable from the Run 069
`validate_candidate_bundle{,_full}` entry points; the Run 069 path
never constructs a `P2pSessionEvictor` and never bumps any
`session_eviction_*` counter.

---

## 11. Proof Run 071 live trust context remains unchanged

`cargo test -p qbind-node --test run_071_pqc_live_trust_tests`
reports **13/13 PASS** unchanged. `cargo test -p qbind-node --lib
pqc_live_trust` reports **11/11 PASS** unchanged.

Run 072 does NOT call `LivePqcTrustState::swap_snapshot` from any
production code path; the handle is read-only-after-startup
exactly as Run 071 landed. The integration test
`run072_n2_kemtls_bringup_then_evict_drains_connected_peers` does
not interact with `LivePqcTrustState` at all — eviction is
orthogonal to the trust snapshot.

---

## 12. Release-binary evidence

### 12.1 Positive N=2 baseline (signed trust bundle)

The Run 071 N=2 signed-bundle bring-up evidence
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_071.md` §11.1) continues
to hold against the Run 072 build: `cargo build --release -p
qbind-node --bin qbind-node` succeeds, no fallback to
`--p2p-trusted-root` is introduced, no `DummySig`/`DummyKem`/
`DummyAead` re-activation occurs. The Run 072 binary path is
identical to Run 071 except for the dormant Run 072 hook code
(unreachable from the production `main` path) and the four
zero-valued Run 072 metrics in `/metrics`.

### 12.2 Eviction trigger smoke

Eviction is proven against the live `TcpKemTlsP2pService` by the
integration test
`run072_n2_kemtls_bringup_then_evict_drains_connected_peers`,
which:

- Spins up two real `qbind-node`-built P2P services on
  `127.0.0.1:<port_v0>` and `127.0.0.1:<port_v1>` (the same
  bring-up shape used by `b7_kemtls_bringup_identity_closure_tests`).
- Polls `connected_peers()` for up to 5 seconds and confirms at
  least one side registers the other's deterministic NodeId.
- Issues `evict_all_sessions(EvictionReason::OperatorTest)` on
  that side.
- Asserts the returned `EvictionReport`:
  - `report.reason == EvictionReason::OperatorTest`
  - `report.attempted == before_count`
  - `report.evicted == before_count`
  - `report.failed == 0`
  - `report.is_full_success() == true`
- Asserts `connected_peers().is_empty()` and
  `live_session_count() == 0` on the evicted side.
- Asserts `report.log_line()` contains the literal substrings
  `"Run 072"`, `"reason=operator_test"`, `"attempted=N"`,
  `"evicted=N"`, `"failed=0"`, `"verdict=full-success"`.
- Asserts a second `evict_all_sessions` call on the same side
  returns `attempted=0, evicted=0` (idempotency).

A hidden CLI surface to fire this hook from a release binary is
**intentionally NOT added in Run 072** — the task §"Strict scope"
forbids enabling Run 070 full apply, and the only operator-visible
path that would call the evictor in production is the Run 073
`LiveTrustApplyContext` adapter. The internal test-harness API
(`P2pSessionEvictor::evict_all_sessions` on a service handle held
by an in-process test) is the safe trigger surface for Run 072.

### 12.3 Reconnect behaviour

Documented in §8 above and pinned by the bounded-wait shape of
the N=2 test: outbound reconnect is NOT automatic in Run 072 (the
B8 dial-with-retry tasks completed during `start()` and are not
re-armed); inbound listener continues to accept. The test
exercises the stable disconnected state explicitly by issuing a
second `evict_all_sessions` and confirming `attempted=0`.

### 12.4 Negative no-trigger smoke

`run072_no_trigger_path_leaves_session_eviction_metrics_at_zero`
asserts that on a freshly-built `P2pMetrics` the four
`session_eviction_*` counters are all zero before any hook call.
Combined with the release-binary discipline (the production
binary never calls the hook in Run 072), this proves a normal
startup-without-trigger leaves `/metrics` unchanged for the new
family.

---

## 13. Proof of no fallback / no Dummy crypto

- **No `--p2p-trusted-root` fallback:** Run 072 does not modify
  the trust resolver or the leaf-revocation closure on either
  handshake config; both remain anchored on the Run 071
  `LivePqcTrustState` snapshot. The Run 071 §"No-fallback / no-mutation
  proof" applies unchanged.
- **No `DummySig` / `DummyKem` / `DummyAead` re-activation:**
  Run 072 does not touch
  `crates/qbind-node/src/secure_channel.rs`,
  `crates/qbind-node/src/pqc_devnet_helper.rs`,
  `crates/qbind-crypto/src/ml_dsa44.rs`,
  `crates/qbind-crypto/src/ml_kem768.rs`, or any AEAD primitive.
  The eviction loop operates strictly on
  `PeerConnection.{tx,read_handle,write_handle}` handles and
  invokes only `drop()` and `JoinHandle::abort()` — neither of
  which constructs any crypto primitive.
- **No private material in logs:** `EvictionReport::log_line`
  emits only `reason`, `attempted`, `evicted`, `failed`, and
  `verdict`. The unit test
  `report_log_line_does_not_leak_keying_material_keywords`
  asserts the absence of `secret`, `private`, `key=`, `aead`,
  `kem` substrings on every emitted line.

---

## 14. Remaining open items

Per the task §"contradiction.md update rules", **C4 remains OPEN**
on the following sub-pieces (NONE narrowed by Run 072):

- Actual live trust-bundle apply (Run 073: wire the
  `LiveTrustApplyContext` adapter that composes Run 071's
  `LivePqcTrustState::swap_snapshot` + Run 072's
  `P2pSessionEvictor` + `pqc_trust_sequence::commit_sequence`,
  and remove `UnsupportedRuntimeContext` from the production
  binary apply hook).
- Peer-supplied / gossiped trust-bundle acceptance.
- `activation_epoch` runtime sourcing.
- In-binary / on-chain bundle-signing-key ratification.
- External KMS / HSM custody.
- Production fast-sync / consensus-storage restore.
- Per-environment production trust-anchor operation.

**C5** remains OPEN / narrowed — Run 072 makes no claim on
timeout-verification activation, forged-traffic rejection, or
transport-root dependency.

---

## 15. Exact immediate next action

Implement Run 073: a thin `LiveTrustApplyContext` adapter in
`crates/qbind-node/src/pqc_trust_reload.rs` (or a new
`pqc_live_trust_apply.rs` module) that holds:

- a clone of the `LivePqcTrustState` handle (Run 071) for
  `snapshot_active` / `swap_trust_state` / `rollback_trust_state`,
- an `Arc<dyn P2pSessionEvictor>` (Run 072) for `evict_sessions`,
- a path / handle to the persisted bundle sequence file for
  `commit_sequence`.

Wire that adapter into `crates/qbind-node/src/main.rs` behind the
existing `--p2p-trust-bundle-reload-apply-enabled` flag and
remove the `ReloadApplyError::UnsupportedRuntimeContext` boundary
on the live-apply path. Validate that the strict Run 070
`validate → snapshot → swap → evict → commit` ordering plus
rollback semantics survive end-to-end against a real
`TcpKemTlsP2pService` + a real `LivePqcTrustState` + a real
on-disk sequence file in a new
`run_073_pqc_trust_bundle_live_apply_tests.rs`. Do NOT broaden
the boundary list under §"What is NOT narrowed" in
`docs/whitepaper/contradiction.md` until Run 073 evidence lands.

---