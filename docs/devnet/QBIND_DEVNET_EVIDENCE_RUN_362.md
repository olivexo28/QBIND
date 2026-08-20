# QBIND DevNet Evidence — Run 362

Public DevNet abuse/DoS **runtime wiring + release-binary evidence** for M12: the Run 361
`AbuseDosConfig` / `ConnectionRateLimiter` model is wired into the live `qbind-node` P2P accept path
behind runtime-owned, default-off state; a connection-rate-drop metric is added; and hidden/devnet-only
operator CLI flags are exposed. Release-binary evidence is captured.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

## 1. Exact verdict

**PARTIAL-POSITIVE / public-DevNet-abuse-DoS-runtime positive (M12 stays Yellow/Partial,
strengthened — NOT Green).**

The runtime wiring, the connection-rate-drop metric, the operator-configurable connection-rate CLI
surface, the release-binary evidence, the Run 362 tests (38 passing), and the docs all landed and are
release-binary evidenced. **M12 does not move Green** because the task's Green gate (§"M12 may move
Green only if …", item 2) requires public DevNet to run with operator-configurable **connection-rate
*and* per-peer message-rate** posture at runtime. Run 362 delivers runtime-wired, operator-configurable
**connection-rate** posture, but the live per-peer **message-rate** limiter (`PeerRateLimiter` in
`async_peer_manager`) is **not** overridable at runtime — the `--p2p-max-messages-per-second` /
`--p2p-burst-allowance` flags are parsed and validated into the runtime config but are not applied to
the live per-peer limiter. Per the readiness rules ("If operator configurability lands but … evidence
is incomplete, keep M12 Yellow/Partial"), **M12 stays Yellow/Partial (strengthened)**. M4 remains
Yellow/launch-blocking; M6 remains Yellow; public DevNet remains **NOT launch-ready**; Full **C4 / C5
remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs` — runtime-owned config + state holder
  composing the Run 361 model (`PublicDevnetAbuseDosRuntimeConfig`,
  `PublicDevnetAbuseDosRuntimeState`, runtime-owned `ConnectionRateLimiterState`). 5 inline tests.
- `crates/qbind-node/tests/run_362_public_devnet_abuse_dos_runtime_tests.rs` — dedicated test target
  (38 tests).
- `crates/qbind-node/examples/run_362_public_devnet_abuse_dos_runtime_release_binary_helper.rs` —
  release helper linking the real Run 361/362 runtime symbols (5 scenarios).
- `scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh` — release-binary harness.
- `docs/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary/{README.md,summary.txt,.gitignore}`
  — evidence archive (only these three files tracked; raw artifacts gitignored).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md` — this file.

Modified (narrow):

- `crates/qbind-node/src/lib.rs` — declares `pub mod public_devnet_abuse_dos_runtime;` (module wiring
  only).
- `crates/qbind-node/src/p2p_tcp.rs` — `TcpKemTlsP2pService` gains a runtime-owned
  `abuse_dos_runtime` handle (`Arc<RwLock<Option<...>>>`, default `None`) + setter; the accept loop
  consults the connection-rate limiter at the top of the accepted-socket arm and drops the stream +
  `continue`s on refusal, before any KEMTLS handshake / trust-bundle / genesis work.
- `crates/qbind-node/src/metrics.rs` — `P2pMetrics` gains the `connection_rate_drop_total`
  counter, its accessor/recorder, and a render line
  (`qbind_p2p_connection_rate_drop_total`). No existing family changed.
- `crates/qbind-node/src/p2p_node_builder.rs` — builder gains `with_abuse_dos_runtime_config()`; the
  `metrics` Arc is computed before `start()` so the runtime state (which references the metrics Arc)
  is installed before the accept loop begins.
- `crates/qbind-node/src/cli.rs` — 8 hidden/devnet-only abuse/DoS flags + `abuse_dos_runtime_config()`
  parse/validate method.
- `crates/qbind-node/src/main.rs` — wires the parsed abuse/DoS runtime config into the builder before
  `builder.build(...)`, prints a status line, and fails closed on validation error.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M12 Yellow (strengthened) →
  Yellow/Partial (strengthened, runtime-wired connection-rate limiter); Green still deferred. No other
  cell changed (M4/M6/M7–M9/M13–M15 untouched).
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md` — documents the runtime wiring, the metric,
  and the hidden CLI flags.
- `docs/release/public-devnet/p2p/VERIFY.md` — adds Run 362 verification commands.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — Run 362 run-log entry; C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 362 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 362 no-authority-surface
  entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 362 trust-lifecycle-inert note.
- `docs/whitepaper/contradiction.md` — Run 362 "No contradiction found" entry.

`docs/release/public-devnet/operator/QUICKSTART.md` is intentionally **not** modified: the operator
posture is exposed only through hidden/devnet-only flags, so the public quickstart operator command
surface is unchanged.

## 3. Runtime wiring summary

`PublicDevnetAbuseDosRuntimeState` owns a pre-validated `AbuseDosConfig`, a runtime-owned
`ConnectionRateLimiterState` (global + optional per-address token buckets, guarded by a lock), and an
`Arc<P2pMetrics>` handle. It is installed into `TcpKemTlsP2pService` through the builder before the
accept loop starts. In `spawn_accept_loop`, immediately after a socket is accepted and before any
KEMTLS handshake / trust-bundle / genesis work, the accept loop calls `should_admit(remote_addr)`:

- if no runtime state is installed (default), the check is skipped entirely — the accept loop is
  byte-for-byte the pre-Run-362 path;
- if installed but the limiter is disabled, `should_admit` always returns `true`;
- if enabled, an over-budget inbound connection returns `false`; the accept loop drops the `TcpStream`
  and `continue`s — no peer is admitted, no handshake is attempted, and the drop metric is incremented.

State is bounded (fixed token buckets, per-address map bounded by config), lock poisoning fails **open**
(matching the existing per-peer limiter posture), and a malformed/unknown remote address never panics.

## 4. Abuse/DoS config and operator configurability

`PublicDevnetAbuseDosRuntimeConfig` composes the Run 361 `AbuseDosConfig`. It exposes:

- `disabled_default()` — the compatibility profile: connection limiter disabled, per-peer `1000` msg/s
  + `100` burst, `FailMode::FailOpen`. `preserves_runtime_defaults()` is `true`.
- `from_config(...)` — build from an operator-supplied, validated `AbuseDosConfig`.
- `into_runtime_state(metrics)` — produce the installable `PublicDevnetAbuseDosRuntimeState`.

Operator configurability is exposed through **hidden/devnet-only** CLI flags (§8). Enabling requires an
explicit `--p2p-connection-rate-limit-enabled` plus a positive window and max; invalid/zero/unbounded/
inconsistent values fail closed at CLI validation; MainNet is refused (`MainNetRefused`).

**Honest limitation:** the per-peer message-rate flags are validated into the runtime config but the
live per-peer `PeerRateLimiter` (used by `AsyncPeerManagerImpl`, not by `TcpKemTlsP2pService`) still
uses its hardcoded defaults — per-peer message-rate runtime override is **not** delivered in Run 362.
This is the reason M12 stays Yellow/Partial (§1, §14).

## 5. Connection-rate limiter runtime behavior

The runtime state delegates to the Run 361 `ConnectionRateLimiter::check`, mapping its
`ConnectionDecision` to an admit/drop decision:

- `ConnectionAllowed` / `ConnectionLimiterDisabled` → admit (no metric change);
- `ConnectionRateLimited` → drop (increment `connection_rate_drop_total` + the P2pMetrics counter);
- `InvalidConfig` / `MainNetRefused` / `StateUnavailable` → fail open (admit) so a misconfiguration can
  never silently blackhole inbound traffic, and count as neither an allow nor a drop.

Window refill uses `Duration::as_secs_f64()`, so sub-second windows (e.g. 500 ms) refill correctly;
behavior is deterministic given a fixed clock/budget.

## 6. Metric behavior

`qbind_p2p_connection_rate_drop_total` is a single unlabeled `AtomicU64` counter on `P2pMetrics`. It
increments **only** when the connection-rate limiter refuses an inbound connection. It carries no
endpoint labels or secrets, does not duplicate an existing family, and is registered exactly once. The
release helper renders the metric text and asserts `registered_once: true` and
`endpoint_label_leak: false`.

## 7. Default compatibility

With no abuse/DoS flags, `TcpKemTlsP2pService` installs no runtime state and the accept loop is
unchanged. Per-peer defaults remain `1000` msg/s + `100` burst; the connection limiter is disabled;
`PeerRateLimiter::with_defaults()` is unchanged. Tests t01–t04 and helper scenario 01 prove default
compatibility; the metric stays at `0` on allowed connections (t26 / helper scenario 05).

## 8. CLI/config surface

Eight **hidden** (`hide = true`, devnet-only, absent from `--help`) flags on `CliArgs`:

- `--p2p-connection-rate-limit-enabled` (flag)
- `--p2p-connection-rate-window-ms <N>`
- `--p2p-connection-rate-max <N>`
- `--p2p-connection-burst <N>`
- `--p2p-max-messages-per-second <N>`
- `--p2p-burst-allowance <N>`
- `--p2p-per-address-connection-rate-window-ms <N>`
- `--p2p-per-address-connection-max <N>`

`CliArgs::abuse_dos_runtime_config()` parses/validates them: default (no flags) → `None` (behavior
unchanged); enabling requires a positive window-ms and max; per-address flags must be supplied as a
pair; connection sub-flags without the enable flag are rejected; MainNet `--env` → `MainNetRefused`.
Because the flags are hidden, the public operator command surface (QUICKSTART) is unchanged; the
release-binary `--help` evidence proves they are absent from help, an invented flag is rejected by
clap, and the real hidden flags parse.

## 9. Release artifacts and hashes

- toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`
- `target/release/qbind-node`
  SHA-256 `c1171fd1bc3f111ec2defe7d28d2e7dde9a985903e633caca4125a9b502b1733`
  Build ID `323a116f912f7d458e12d06bf0c9a809c39bf5c0`
- `target/release/examples/run_362_public_devnet_abuse_dos_runtime_release_binary_helper`
  SHA-256 `29b1ae238c3e8e52601cf70d4e98b64bc4bac7d245efa5774d4d2451bbf29a4c`
  Build ID `67569c6b0a3f460d31da66aa2528aca3926e9fda`

SHA-256 / Build ID are environment-specific reproducibility anchors for this build (they depend on the
exact toolchain, absolute build path, and dependency graph); a different environment will legitimately
produce different hashes.

## 10. Helper/harness corpus

Helper `run_362_public_devnet_abuse_dos_runtime_release_binary_helper` (5 scenarios, all PASS):

1. `01_default_preserves_behavior` — disabled limiter never refuses; drop_count=0.
2. `02_enabled_allows_then_refuses` — 30 admitted; 31st `ConnectionRateLimited`; metric=1.
3. `03_invalid_config_fails_closed` — zero-window enabled config rejected.
4. `04_mainnet_refused` — MainNet abuse/DoS config refused.
5. `05_metric_not_increment_on_allow` — allowed connection leaves metric at 0.

Harness `scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh` builds the release
binary + helper, captures SHA-256/Build ID/toolchain, runs the release-built helper, and exercises the
production binary CLI surface. **Harness verdict: PASS.**

## 11. Runtime/load evidence

The release-built helper links the real Run 361/362 library symbols and exercises the runtime state at
the token-bucket level: it drives the global bucket to its `20 + 10 = 30` t0 capacity, proves the 31st
attempt is refused, and reads back the incremented metric from the same `P2pMetrics` instance the
accept loop would use. This is deterministic single-process evidence; it does **not** open a P2P socket
or drive live network traffic (no public port is opened in Run 362).

## 12. Rejection/fail-closed evidence

Zero/invalid connection window rejected; connection sub-flags without the enable flag rejected;
per-address flags rejected unless supplied as a pair; unbounded/too-large values rejected by the Run
361 `validate()`; wrong environment rejected; MainNet refused (`MainNetRefused`). Helper scenarios 03
and 04 prove invalid-config and MainNet fail-closed on the release binary; production-binary scenarios
prove the invented flag is rejected by clap (rc=2).

## 13. Non-mutation evidence

A refusal drops the socket before any handshake and never: admits a peer (t22), mutates trust state /
`LivePqcTrustState` (t23/t32), writes sequence/marker files (t24), mutates the validator set (t33),
triggers an epoch transition (t34), or invokes a Run 070 apply path (t35). No P2P wire format changed
(t29), no peer-admission or trust-bundle behavior weakened (t30/t31), and no launch claim is made
(t36).

## 14. Readiness matrix delta for M12

- **M12: Yellow (strengthened) → Yellow/Partial (strengthened, runtime-wired connection-rate
  limiter).** Runtime wiring into the live accept loop + operator-configurable connection-rate posture
  + connection-rate-drop metric + release-binary evidence landed with default compatibility proven.
  **Green is NOT taken** because operator-configurable per-peer message-rate posture is not wired into
  the live per-peer limiter (Green gate item 2 unmet). No other matrix cell changed.

## 15. Current public DevNet readiness status

**NOT launch-ready.** Green must-haves: M1, M2, M3 (same-host scope), M5, M10, M11, M16, M17, M18, M19,
M20. Still Yellow/Red: M4 (Yellow/launch-blocking), M6 (Yellow/Partial), M7–M9, M12 (Yellow/Partial,
strengthened), M13–M15.

## 16. Remaining public DevNet blockers

M4 (live seed/bootnode reachability — the launch blocker), M6 (identity generation), M7–M9, M12
(per-peer message-rate runtime override + load evidence for Green), M13–M15.

## 17. Public TestNet blockers

Public TestNet readiness is **not** claimed. It requires, at minimum, live joinable infrastructure,
runtime-enforced operator-configurable abuse/DoS validated under load, identity generation, monitoring/
alerting, and the full must-have set Green — none claimed here.

## 18. MainNet blockers

MainNet is **not** enabled and is refused by this module (`MainNetRefused`). MainNet authority
rotation/revocation remains **Red**; production custody/governance/settlement remain out of scope.

## 19. C4/C5 status

Full **C4 remains OPEN**. **C5 remains OPEN.** Run 362 does not close, advance, or reinterpret C4/C5;
the Run 353/354 boundary remains Green-for-scope only and is not wired into runtime.

## 20. Tests run

- `cargo build -p qbind-node --release` — **success**.
- `cargo build -p qbind-node --example run_362_public_devnet_abuse_dos_runtime_release_binary_helper
  --release` — **success**.
- Run 362 harness `scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh` —
  **verdict: PASS** (5 helper scenarios + CLI-surface checks).
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` — **38 passed;
  0 failed; 0 ignored**.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — **30 passed;
  0 failed; 0 ignored** (Run 361 unbroken).
- `cargo test -p qbind-node --lib` — **1385 passed; 0 failed; 0 ignored** (includes the 5 new
  `public_devnet_abuse_dos_runtime` inline tests; no pre-existing test weakened or removed).

## 21. Security scans

- **Secret scan** over all changed files: no private key, mnemonic, seed phrase, credential, API key,
  token, private infrastructure, real production hostname, or live endpoint introduced. Test remote
  addresses use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) and RFC 3849 (`2001:db8::/32`)
  documentation ranges only.

## 22. CodeQL

- CodeQL (Rust) was invoked over the source changes and **did not run to completion**: the analysis was
  **skipped because the CodeQL database size is too large** ("Analysis was skipped because the database
  size is too large"; 0 alerts reported). Per the run rules this is **not** claimed clean — the result
  is an infrastructure/database-size skip, not a clean pass. No CodeQL coverage is asserted for this
  diff. This matches the Run 361 CodeQL outcome on the same repository.

## 23. Provenance

- **Repository:** `olivexo28/QBIND`.
- **Branch:** `copilot/run-362-task`.
- **Base commit (core wiring):** `a7d7c4bb48f256c7e8e18473b41e8484dfcc39f1`; this evidence + docs land
  with a follow-up commit on the same branch. The working tree is committed clean — no unexplained
  `git_status: dirty`.
- **Runtime module:** `crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs`.
- **Test target:** `crates/qbind-node/tests/run_362_public_devnet_abuse_dos_runtime_tests.rs`.
- **Helper:** `crates/qbind-node/examples/run_362_public_devnet_abuse_dos_runtime_release_binary_helper.rs`.
- **Harness:** `scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh`.
- **Release binary SHA-256:** `c1171fd1bc3f111ec2defe7d28d2e7dde9a985903e633caca4125a9b502b1733`.
- **Helper SHA-256:** `29b1ae238c3e8e52601cf70d4e98b64bc4bac7d245efa5774d4d2451bbf29a4c`.
- **Metric name:** `qbind_p2p_connection_rate_drop_total`.
- **CLI/config changes:** 8 hidden/devnet-only abuse/DoS flags (§8); defaults preserve behavior.
- **Commands run:** see §20.
- **Test results:** see §20.
- **Secret scan result:** see §21.
- **CodeQL result:** see §22.
- **Readiness matrix delta:** M12 Yellow (strengthened) → Yellow/Partial (strengthened); no other cell
  changed.
- **Exact reason M12 is not Green:** the Green gate requires operator-configurable connection-rate
  **and** per-peer message-rate posture at runtime; Run 362 wires and exposes the connection-rate
  limiter but does not wire per-peer message-rate override into the live per-peer limiter, so M12 stays
  Yellow/Partial per the readiness rules.

## 24. Honest limitations

- **Per-peer message-rate not runtime-overridable:** the live per-peer limiter still uses hardcoded
  defaults; the message-rate flags are validated but inert against it.
- **No live network load:** the release evidence is deterministic single-process token-bucket evidence;
  no P2P socket is opened and no live traffic is driven.
- **Hidden flags:** the operator surface is devnet-only/hidden, deliberately absent from `--help`.
- **No live infrastructure:** M4 remains Yellow/launch-blocking; public DevNet is NOT launch-ready.
- **Fail-open on lock poisoning / misconfig:** consistent with the existing limiter posture, a poisoned
  lock or an `InvalidConfig`/`MainNetRefused` runtime decision admits rather than blackholes traffic.