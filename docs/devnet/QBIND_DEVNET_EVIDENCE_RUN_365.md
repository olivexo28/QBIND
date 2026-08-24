# QBIND DevNet Evidence — Run 365

Source/test evidence for threading the public DevNet abuse/DoS **per-peer message-rate override**
through the **deployed** `qbind-node` builder path (`main.rs` → `p2p_node_builder`) into the live
`AsyncPeerManagerImpl` construction path. This closes the source/test gap Run 364 flagged.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · **source/test only** (no new CLI flag, no live
> deployment, no P2P wire-format change). Release-binary evidence is deferred to Run 366.

## 1. Exact verdict

**PASS / public-DevNet-per-peer deployed-node threading source-test positive (M12 stays
Yellow/Partial, strengthened — NOT Green).**

The deployed-node threading, tests, docs, secret scan, CodeQL provenance, and readiness-matrix updates
all landed. The deployed `P2pNodeBuilder` now derives the validated CLI per-peer
`peer_rate_limiter_config` and constructs the live `AsyncPeerManagerImpl` from it, with defaults and
the Run 362 connection-rate limiter preserved exactly. **M12 does not move Green** — release-binary
end-to-end evidence is deferred to Run 366. M4 remains Yellow/launch-blocking; M6 remains Yellow;
public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs` — 20 tests
  covering the deployed-builder threading, defaults, custom overrides, connection-limiter
  independence, fail-closed rejection, CLI surface, and non-mutation invariants.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md` — this file.

Modified (source, narrow):

- `crates/qbind-node/src/p2p_node_builder.rs` — added `P2pNodeContext.peer_rate_limiter_config`;
  added `P2pNodeBuilder::deployed_peer_rate_limiter_config`,
  `deployed_async_peer_manager_config`, and `build_deployed_peer_manager`; `build()` records the
  derived config on the context. Default `None` preserves prior behaviour bit-for-bit.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

No new public CLI flags. No P2P wire-format change. No default change.

## 3. Deployed-node threading summary

Run 363 wired the validated per-peer thresholds into an `AsyncPeerManagerImpl` built by a *test*
helper; the deployed `P2pNodeBuilder` did not itself thread the CLI-derived config. Run 365 adds that
threading to the deployed builder:

- `P2pNodeBuilder::with_abuse_dos_runtime_config(..)` installs the validated runtime config, exactly
  as `main.rs` already does from `CliArgs::abuse_dos_runtime_config()`.
- `P2pNodeBuilder::deployed_peer_rate_limiter_config()` derives the validated
  `Option<PeerRateLimiterConfig>` (None when no override → defaults; Some when a validated override
  is installed).
- `P2pNodeBuilder::deployed_async_peer_manager_config()` produces the `AsyncPeerManagerConfig` with
  that per-peer config threaded via `with_peer_rate_limiter_config`.
- `P2pNodeBuilder::build_deployed_peer_manager()` constructs the live `AsyncPeerManagerImpl` from that
  config.
- `P2pNodeContext.peer_rate_limiter_config` records the derived config on the built context so the
  deployed value is observable.

## 4. Per-peer message-rate config path

`CliArgs::abuse_dos_runtime_config()` → `PublicDevnetAbuseDosRuntimeConfig::peer_rate_limiter_config()`
→ `P2pNodeBuilder::deployed_peer_rate_limiter_config()` →
`AsyncPeerManagerConfig::with_peer_rate_limiter_config(..)` → `AsyncPeerManagerImpl::new` →
`build_peer_rate_limiter` → live `PeerRateLimiter`. The config is validated at
`PublicDevnetAbuseDosRuntimeConfig::from_config` before it can be installed, so only accepted
(non-zero, bounded) per-peer thresholds reach the deployed peer manager.

## 5. Peer manager construction behavior

- No override installed (`None`) → `PeerRateLimiter::with_defaults()` (`1000` msg/s + `100` burst).
- Valid override installed (`Some(cfg)`) → `PeerRateLimiter::new(cfg)` from the validated per-peer
  thresholds.

Verified by tests t01–t06 and t29_31.

## 6. Default compatibility

With no abuse/DoS flags, `deployed_peer_rate_limiter_config()` is `None`,
`deployed_async_peer_manager_config()` equals the default `AsyncPeerManagerConfig`, and the deployed
peer manager's limiter equals `PeerRateLimiter::with_defaults()` — identical to a directly-built
default peer manager (t07). The connection limiter stays disabled unless explicitly enabled. Bit-for-
bit unchanged.

## 7. CLI / config surface

No new public CLI flags. The hidden/devnet-only Run 362/363 flags remain absent from `--help` (t14),
parse when supplied (t15), and reject invented variants (t16). The connection-rate flag family is
unchanged.

## 8. Accepted tests

- t01 deployed default → `with_defaults()`.
- t02 default values `1000`/`100`.
- t03 `--p2p-max-messages-per-second 500` reaches deployed peer-manager config.
- t04 `--p2p-burst-allowance 42` reaches deployed peer-manager config.
- t05 custom limiter allows under-budget messages.
- t06 custom limiter drops over-budget messages (and refills deterministically).
- t07 deployed default matches direct default bit-for-bit.
- t15 real hidden flags parse.
- t29_31 deployed derived config equals the runtime config's per-peer config exactly.

## 9. Rejection / fail-closed tests

- t11 zero message-rate max rejected.
- t12 unbounded message-rate (and unbounded burst) rejected.
- t13 MainNet refused (`--env mainnet`).
- t16 invented flags rejected by clap.

## 10. Runtime / non-mutation evidence

- t08 connection-rate limiter config still reaches the accept-loop runtime state.
- t09 connection-rate and per-peer limiters remain independent (a per-peer override never enables the
  connection limiter).
- t10 the connection-rate drop metric never increments on a per-peer message drop.
- t17_25 additive threading: only per-peer thresholds change; the connection limiter stays disabled,
  inbound admission is unchanged, no P2P wire-format change, no peer-admission weakening, no
  trust-bundle weakening, no `LivePqcTrustState` / sequence-marker / validator-set / epoch mutation,
  no Run 070 path.
- t25 constructing the deployed peer manager is inert with respect to launch readiness (no
  seed/bootnode/faucet/RPC/explorer/status-page surface created).
- t26_28 deployed defaults preserve readiness-matrix neutrality.

## 11. Readiness matrix delta for M12

M12: `Yellow/Partial (stronger, Run 364 — release-binary evidence for both controls)` →
`Yellow/Partial (stronger, Run 365 — deployed-node per-peer threading landed at source/test level)`.
**Not Green.** The deployed builder now threads the CLI-derived `peer_rate_limiter_config` into the
live `AsyncPeerManagerImpl`, closing the source/test gap Run 364 flagged. M12 remains Yellow/Partial
pending Run 366 release-binary evidence that a running `qbind-node` honors both connection-rate and
per-peer message-rate runtime config end-to-end.

## 12. Current public DevNet readiness status

**NOT launch-ready.** Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16–M20. Yellow/Partial: M4,
M6, M7–M9, M12 (strengthened), M13–M15. M4 remains launch-blocking.

## 13. Remaining public DevNet blockers

M4 (live seed/bootnode reachability) launch-blocking; M6 (stable identity generation); M7–M9, M13–M15;
and M12 release-binary end-to-end evidence (deferred to Run 366) plus load evidence.

## 14. Public TestNet blockers

All public-DevNet blockers above, plus TestNet-scope reachability, identity, and abuse/DoS end-to-end
release evidence. **No TestNet readiness is claimed.**

## 15. MainNet blockers

MainNet authority rotation/revocation Red; no production abuse/DoS policy (MainNet refused by this
surface); Full C4/C5 OPEN. **No MainNet enablement.**

## 16. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 365.

## 17. Tests run

- `cargo build -p qbind-node --lib` — ok.
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests` —
  **20 passed; 0 failed**.
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` —
  **21 passed; 0 failed**.
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` —
  **38 passed; 0 failed**.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` —
  **30 passed; 0 failed**.
- `cargo test -p qbind-node --lib` — **1385 passed; 0 failed**.

> Run 361 reconciliation: the authoritative count for
> `run_361_public_devnet_abuse_dos_hardening_tests` in this tree is **30 passed** (preserved from
> Run 364).

## 18. Security scans

Secret scanning run over all changed files — no secrets, keys, mnemonics, credentials, tokens, private
infrastructure, or live endpoints. All addresses in the new test are RFC 5737 (`192.0.2.0/24`)
documentation ranges or localhost.

## 19. CodeQL

This run changes Rust production source (`p2p_node_builder.rs`) plus a new test file, so
`codeql_checker` was invoked (declared non-trivial). **Exact result: CodeQL analysis for `rust` was
SKIPPED — the database size is too large (0 alerts returned because the analysis did not run).** This
is recorded verbatim and is **not** asserted as a clean scan. The production change is additive and
default-preserving (a new context field plus three builder methods that thread an already-validated
`PeerRateLimiterConfig` into `AsyncPeerManagerImpl::new`), introducing no new unsafe code, no I/O, no
untrusted-input parsing, and no new external surface.

## 20. Provenance

- branch: `copilot/run-365-task`.
- base git commit: `f15b2956e167660203310c0b975e89dc0017b9fd`.
- toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)`.
- source change: `crates/qbind-node/src/p2p_node_builder.rs` (threading + context field + builder
  methods).
- tests: `crates/qbind-node/tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs`.
- test counts: §17. secret scan: §18. CodeQL: §19. readiness delta: §11.

## 21. Honest limitations

- **Source/test only.** No release-binary evidence in this run; deferred to Run 366.
- The deployed builder now *constructs* the live `AsyncPeerManagerImpl` from the CLI-derived per-peer
  config, but this run does not launch a full node or prove end-to-end operator effect on a running
  `qbind-node` over a real socket; that is the Run 366 release-binary scope.
- M12 stays Yellow; no Green, no launch-ready, no TestNet/MainNet readiness, no C4/C5 closure claim.
- M4 remains launch-blocking; M6 remains Yellow.

## 22. Suggested Run 366 next step

Produce release-binary evidence that a running `qbind-node` honors both the connection-rate limiter and
a custom per-peer message-rate override end-to-end (over a real inbound path), using the deployed
`build_deployed_peer_manager` threading landed here. If that evidence holds with defaults preserved,
it would justify evaluating the M12 Green gate.