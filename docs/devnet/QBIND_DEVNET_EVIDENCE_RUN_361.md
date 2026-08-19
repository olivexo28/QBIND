# QBIND DevNet Evidence — Run 361

Public DevNet abuse/DoS hardening: operator-configurable peer rate-limit posture + bounded inbound
connection-rate limiter boundary (**source/test only**).

Run 361 lands a small, focused **source + test + docs** boundary that makes the public DevNet
abuse/DoS posture operator-configurable **at the type/source level** and introduces a pure,
deterministic bounded inbound **connection-rate limiter** model. It changes **no** runtime default
behavior: the safe default profile preserves the current per-peer behavior (`1000` msg/s + `100`
burst) and leaves the connection limiter **disabled**. It adds **no** public CLI flag, wires **no**
behavior into the live `p2p_tcp` accept loop, registers **no** metric, changes **no** P2P wire format /
peer-admission / trust-bundle behavior, deploys **no** seed/bootnode/faucet/RPC/explorer/status page,
enables **no** MainNet/TestNet, and performs **no** validator-set mutation / epoch transition /
execution-sink write. Release-binary / runtime evidence is **deferred to Run 362**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

## 1. Exact verdict

**PASS / public-DevNet-abuse-DoS-hardening source-test positive.** The source boundary
(`crates/qbind-node/src/public_devnet_abuse_dos_config.rs`), the dedicated test target
(`crates/qbind-node/tests/run_361_public_devnet_abuse_dos_hardening_tests.rs`, 30 tests, all passing),
the narrow docs, this evidence file, the secret scan, and the CodeQL result all landed. **M12 moves
Yellow/Partial → Yellow (strengthened)**; **M12 Green is deferred to Run 362** because no runtime
wiring or release-binary evidence exists yet. M4 remains Yellow/launch-blocking, public DevNet remains
**NOT launch-ready**, and Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/src/public_devnet_abuse_dos_config.rs` — source boundary (config model +
  connection-rate limiter + adapter/metric plan).
- `crates/qbind-node/tests/run_361_public_devnet_abuse_dos_hardening_tests.rs` — dedicated test target
  (30 tests).
- `docs/release/public-devnet/p2p/VERIFY.md` — P2P posture + Run 361 boundary verification commands.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_361.md` — this file.

Modified (narrow):

- `crates/qbind-node/src/lib.rs` — declares `pub mod public_devnet_abuse_dos_config;` (module wiring
  only; no other change).
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M12 Yellow → Yellow (strengthened), Green
  deferred to Run 362; status header, checklist, status matrix, next-run table, blocker summary, and
  §17 summary updated. M4/M6–M9/M13–M15 unchanged.
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md` — new §7a documenting the Run 361 source/test
  boundary; §8 future-work updated. No change to the documented current runtime defaults.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status header (Run 361) + run-log Run 361 entry;
  C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 361 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 361 no-change-to-surface
  entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 361 trust-lifecycle-inert note.
- `docs/whitepaper/contradiction.md` — Run 361 "No contradiction found" entry.

## 3. Source boundary summary

`crates/qbind-node/src/public_devnet_abuse_dos_config.rs` is a self-contained, pure module. It depends
only on `qbind_types::primitives::NetworkEnvironment` and the existing
`crate::peer_rate_limiter` config/constants. It introduces no I/O, no global state, and no runtime
call sites. It is a source/test boundary only — Run 362 (or later) is required to wire it into runtime
and produce release-binary evidence.

## 4. Abuse/DoS config model

`AbuseDosConfig` fields:

- `environment: NetworkEnvironment` — environment binding.
- `genesis_hash: Option<[u8; 32]>` — optional genesis-hash binding.
- `per_peer_max_messages_per_second: u64`, `per_peer_burst_allowance: u64` — per-peer thresholds.
- `connection_limiter_enabled: bool` — default `false`.
- `connection_rate_window: Duration`, `max_connections_per_window: u64`,
  `connection_burst_allowance: u64` — global inbound connection-rate window + burst.
- `per_address_rate_window: Option<Duration>`, `max_connections_per_address_window: u64` — optional
  per-remote-address window.
- `fail_mode: FailMode` (`FailOpen` / `FailClosed`) — fail-open vs fail-closed marker.
- `profile: AbuseDosProfile` (`CompatibilityDefault` / `PublicDevnetRecommended` / `Custom`) — explicit
  profile marker.

Validation (`validate`, `validate_devnet`, `check_genesis_binding`) rejects: zero per-peer
messages/sec; per-peer rate/burst above documented maxima (`MAX_MESSAGES_PER_SECOND`,
`MAX_BURST_ALLOWANCE`); zero/too-large connection window; zero/too-large connections per window;
non-DevNet environment (for `validate_devnet`); genesis-binding mismatch; and MainNet outright
(`MainNetRefused`, no production policy). A stricter `public_devnet_recommended()` profile is provided
for source/test use only and is never applied to runtime defaults.

## 5. Connection-rate limiter boundary

`ConnectionRateLimiter` owns an immutable, pre-validated `AbuseDosConfig` and operates on
caller-supplied `ConnectionRateLimiterState` (global + per-remote-address token buckets). Its `check`
method returns a deterministic `ConnectionDecision`:

- `ConnectionAllowed`, `ConnectionRateLimited`, `ConnectionLimiterDisabled`, `InvalidConfig`,
  `MainNetRefused`, `StateUnavailable`.

It performs bounded token-bucket window refill, is non-mutating outside the caller-owned state, and
performs no I/O. An `inbound_connection_adapter_shape` helper documents the intended `p2p_tcp`
call site **without** wiring it into runtime.

## 6. Default compatibility

`AbuseDosConfig::default()` == `1000` msg/s + `100` burst per-peer (matching
`DEFAULT_MAX_MESSAGES_PER_SECOND` / `DEFAULT_BURST_ALLOWANCE`), connection limiter **disabled**,
`FailMode::FailOpen` (matching the current runtime limiter which fails open on lock poisoning),
`profile = CompatibilityDefault`. `preserves_runtime_defaults()` returns `true`. Importing this module
changes nothing at runtime. Existing `PeerRateLimiter::with_defaults()` remains compatible
(test `t33`).

## 7. Runtime / CLI wiring status

**None.** No runtime wiring into the `p2p_tcp` accept loop, no public CLI flag, no `NodeConfig`
plumbing, no metric registration. The future connection-rate-drop metric name
(`qbind_p2p_connection_rate_drop_total`) is **reserved but not registered**. This is a deliberate
source/test-only run; Run 362 must land runtime wiring + release-binary evidence before M12 → Green.

## 8. Accepted / construction tests

`t01`–`t05`: default profile preserves `1000` msg/s + `100` burst; valid custom per-peer thresholds
accepted; valid connection-rate thresholds accepted; DevNet source/test profile accepted;
TestNet/MainNet profiles are **not** accepted as DevNet.

## 9. Rejection / fail-closed tests

`t06`–`t13`: zero max messages/sec rejected; unbounded burst rejected (zero burst explicitly allowed as
safe); impossible connection window rejected; unbounded/too-large per-peer + connection values rejected;
malformed config (zero connections/window) rejected; wrong environment rejected; wrong genesis binding
rejected; MainNet refused absent a production policy (config and limiter construction both refuse).

## 10. Non-mutation evidence

`t24`–`t32`: rejected config constructs no limiter (no mutation); the limiter writes only caller-owned
fixture state (two independent states stay independent); the module has no trust-bundle /
`LivePqcTrustState` / sequence-file / validator-set / epoch-transition / Run 070 dependency (enforced by
its import set and asserted side-effect-free over 1000 calls); no launch claim — the metric plan only
reserves a future name.

## 11. Readiness matrix delta for M12

- **M12: Yellow/Partial → Yellow (strengthened).** Source/test operator-configurable abuse/DoS config
  model + bounded inbound connection-rate limiter boundary landed; safe default preserves current
  behavior. **Green deferred to Run 362** (runtime wiring + release-binary evidence). No other matrix
  cell changed.

## 12. Current public DevNet readiness status

**NOT launch-ready.** Green must-haves: M1, M2, M3 (same-host scope), M5, M10, M11, M16, M17, M18, M19,
M20. Still Yellow/Red: M4 (Yellow/launch-blocking), M6 (Yellow/Partial), M7–M9, M12 (Yellow,
strengthened), M13–M15.

## 13. Remaining public DevNet blockers

M4 (live seed/bootnode reachability evidence — the launch blocker), M6 (identity-generation command),
M7–M9, M12 (runtime wiring + release-binary evidence for Green), M13–M15.

## 14. Public TestNet blockers

Public TestNet readiness is **not** claimed. It requires, at minimum: live joinable infrastructure,
runtime-enforced operator-configurable abuse/DoS + connection-rate limiting validated under load,
identity generation/registration, monitoring/alerting, and the full must-have set Green — none claimed
here.

## 15. MainNet blockers

MainNet is **not** enabled and is refused by this module (`MainNetRefused`). MainNet authority
rotation/revocation remains **Red**; production custody/governance/settlement remain out of scope.

## 16. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 361 does not close, advance, or reinterpret C4/C5,
and the Run 353/354 boundary remains **Green-for-scope only**.

## 17. Tests run

- `cargo build -p qbind-node --lib` — **success** (module compiles; no default change).
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — **30 passed;
  0 failed; 0 ignored**.
- `cargo test -p qbind-node --lib` — **1380 passed; 0 failed; 0 ignored** (was 1377 before this run +
  3 new inline module tests). No pre-existing test weakened or removed.

The test target name matches the task-suggested name exactly; no substitution was required.

## 18. Security scans

- **Secret scan** over all changed files: no private key, mnemonic, seed phrase, credential, API key,
  token, private infrastructure, real production hostname, or live endpoint introduced. Sample remote
  addresses in tests use RFC 5737 documentation ranges (`203.0.113.0/24`).

## 19. CodeQL

- CodeQL (Rust) was run over the source changes. Result recorded in the run summary; it is **not**
  claimed clean if it was skipped, timed out, reported database-too-large, or reported an
  infrastructure failure — see the final task summary for the exact reported result.

## 20. Provenance

- **Repository:** `olivexo28/QBIND`.
- **Branch:** `copilot/run-361-integration-tests`.
- **Base commit:** `34a97c5b3a857b74c38659cc65cdafe18da28220` (this evidence lands with the Run 361
  commit on the branch; the working tree is committed clean — no unexplained `git_status: dirty`).
- **Source module path:** `crates/qbind-node/src/public_devnet_abuse_dos_config.rs`.
- **Test target path:** `crates/qbind-node/tests/run_361_public_devnet_abuse_dos_hardening_tests.rs`.
- **Commands run:** see §17.
- **Readiness matrix delta:** M12 Yellow/Partial → Yellow (strengthened), Green deferred to Run 362;
  no other cell changed.
- **Exact reason M12 is not Green:** no runtime wiring into the live accept loop, no public CLI/config
  runtime surface, and no release-binary/runtime evidence exist yet. Per the readiness rules, M12 → Green
  requires actual runtime/operator-configurable protection that is implemented, validated, documented,
  and release-binary evidenced — deferred to Run 362.

## 21. Honest limitations

- **Source/test only:** the boundary is pure and never consulted by runtime; nothing changes for a
  running node.
- **No metric registered:** the connection-rate-drop metric is a reserved name, not an emitted counter.
- **No live infrastructure:** M4 remains Yellow/launch-blocking; public DevNet is NOT launch-ready.
- **Connection limiter model is deterministic/single-threaded in tests:** the `StateUnavailable` outcome
  is defined for a future runtime that shares state under a lock; it is not exercised by a lock-poison
  path in Run 361 because the limiter takes caller-owned `&mut` state (documented, not modelled as a
  poison path).

## 22. Suggested Run 362 next step

Wire the Run 361 `AbuseDosConfig` / `ConnectionRateLimiter` boundary into the `qbind-node` runtime:
consult it in the `p2p_tcp` inbound accept loop behind runtime-owned state, add the
`qbind_p2p_connection_rate_drop_total` metric, optionally expose narrow validated CLI/config plumbing
(with tests + docs), validate under real inbound load, and capture release-binary evidence — then move
**M12 → Green**. (M4 live-seed reachability remains the separate launch blocker.)
