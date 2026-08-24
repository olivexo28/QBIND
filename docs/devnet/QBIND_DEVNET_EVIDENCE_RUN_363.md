# QBIND DevNet Evidence — Run 363

Public DevNet abuse/DoS **per-peer message-rate runtime override** wiring for M12, at
**source/test level only**. Run 363 makes the already-validated Run 362 hidden/devnet-only flags
`--p2p-max-messages-per-second` and `--p2p-burst-allowance` actually affect the live per-peer inbound
message-rate limiter (`PeerRateLimiter`) used by `AsyncPeerManager`, instead of being parsed and
validated but inert.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · source/test only (no release-binary evidence).

## 1. Exact verdict

**PASS / public-DevNet-per-peer-message-rate runtime source-test positive (M12 stays Yellow/Partial,
strengthened — NOT Green).**

The per-peer message-rate runtime override wiring, tests (21 passing), docs, security scan, and matrix
updates all landed. **M12 does not move Green**: the task defers release-binary evidence — and any M12
Green decision — to Run 364. Per the readiness rules, M12 moves `Yellow/Partial → Yellow/stronger`
(source/test runtime override landed) but must not move Green until Run 364 release-binary evidence
proves **both** connection-rate and per-peer message-rate runtime configurability. M4 remains
Yellow/launch-blocking; M6 remains Yellow; public DevNet remains **NOT launch-ready**; Full **C4 / C5
remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/tests/run_363_public_devnet_per_peer_message_rate_runtime_tests.rs` — dedicated
  test target (21 tests) proving the previously inert per-peer flags now affect the live limiter
  construction path while preserving defaults.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_363.md` — this file.

Modified (narrow):

- `crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs` — `PublicDevnetAbuseDosRuntimeConfig`
  gains `peer_rate_limiter_config()` (derives the validated `PeerRateLimiterConfig` from the backing
  `AbuseDosConfig`) and `build_peer_rate_limiter()`. No behavior change to the connection-rate path.
- `crates/qbind-node/src/async_peer_manager.rs` — `AsyncPeerManagerConfig` gains an optional
  `peer_rate_limiter_config: Option<PeerRateLimiterConfig>` field (default `None`) and a
  `with_peer_rate_limiter_config()` builder; `AsyncPeerManagerImpl::new`/`with_metrics` build the
  per-peer limiter via a shared `build_peer_rate_limiter()` helper (`None` →
  `PeerRateLimiter::with_defaults()`); a `peer_rate_limiter()` accessor is added for inspection.
- Docs updated narrowly (see §Required docs below).

## 3. Per-peer message-rate runtime wiring summary

The seam is: `CliArgs::abuse_dos_runtime_config()` (Run 362, parses/validates
`--p2p-max-messages-per-second` / `--p2p-burst-allowance`) → `PublicDevnetAbuseDosRuntimeConfig` →
`peer_rate_limiter_config()` → `AsyncPeerManagerConfig::with_peer_rate_limiter_config(Some(cfg))` →
`AsyncPeerManagerImpl::new(..)` builds `PeerRateLimiter::new(cfg)`. When no override is present, the
config is `None` and the peer-manager builds `PeerRateLimiter::with_defaults()` exactly as before.

## 4. Abuse/DoS config integration

The per-peer thresholds are carried by the same Run 362 `AbuseDosConfig` object already validated by
`PublicDevnetAbuseDosRuntimeConfig::from_config` (non-zero, bounded max messages/sec and burst,
correct environment, MainNet refused). `peer_rate_limiter_config()` returns only accepted values via
the existing `AbuseDosConfig::peer_rate_limiter_config()`. The connection-rate limiter path from Run
362 is unchanged and composes with the same runtime config object.

## 5. PeerRateLimiter construction behavior

- No override → `PeerRateLimiter::with_defaults()`.
- Override present → `PeerRateLimiter::new(PeerRateLimiterConfig { max_messages_per_second,
  burst_allowance })` from validated thresholds.
- Token-bucket allow/refill/burst semantics are unchanged; only the construction inputs are now
  operator-configurable.

## 6. Default compatibility

Default max messages/sec remains `1000`; default burst remains `100`. With no flags, the peer-manager
limiter is bit-for-bit `PeerRateLimiter::with_defaults()`. Verified by t01, t02, t15, t30.

## 7. CLI/config surface

No new public CLI flags. The existing hidden/devnet-only Run 362 flags
`--p2p-max-messages-per-second` and `--p2p-burst-allowance` are reused. Both remain hidden from
`--help` (t16) and parse (t17); invented flags are rejected (t18).

## 8. Accepted tests

t03 (custom max accepted), t04 (custom burst accepted), t05 (custom values reach the live
peer-manager limiter), t06 (under-budget allowed), t08/t09 (refill/burst deterministic), t17 (real
hidden flags parse).

## 9. Rejection / fail-closed tests

t12 (zero max messages/sec rejected), t13 (unsafe/unbounded message-rate + burst rejected), t14
(MainNet refused), t18 (invented flags rejected).

## 10. Runtime / non-mutation evidence

t10/t11 (connection-rate limiter and its metric remain independent of message-rate drops),
t19_26 (per-peer override is additive: no peer-admission weakening, no trust-bundle change, no
`LivePqcTrustState`/sequence/validator/epoch mutation reachable from this path), t27_29 (readiness
posture unchanged; MainNet refused), t30 (Run 361/362 behavior preserved). Run 361 (38) and Run 362
(38) test targets remain green.

## 11. Readiness matrix delta for M12

M12: `Yellow/Partial` → `Yellow/stronger` (source/test per-peer message-rate runtime override landed).
**Not Green** — deferred to Run 364 release-binary evidence proving both connection-rate and per-peer
message-rate runtime configurability.

## 12. Current public DevNet readiness status

**NOT launch-ready.** Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16–M20.
Yellow/Partial: M4, M6, M7–M9, M12 (strengthened), M13–M15.

## 13. Remaining public DevNet blockers

M4 (live seed/bootnode reachability) remains launch-blocking; M6 (stable identity generation);
M7–M9, M13–M15; and M12 release-binary evidence (Run 364).

## 14. Public TestNet blockers

All public-DevNet blockers above, plus TestNet-scope reachability, identity, and abuse/DoS
release-binary evidence. No TestNet readiness is claimed.

## 15. MainNet blockers

MainNet authority rotation/revocation Red; no production abuse/DoS policy (MainNet refused by this
surface); Full C4/C5 OPEN. No MainNet enablement.

## 16. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 363.

## 17. Tests run

- `cargo build -p qbind-node --lib` — ok.
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` — 21
  passed.
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` — 38 passed.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — 38 passed.
- `cargo test -p qbind-node --lib` — 1385 passed.

## 18. Security scans

Secret scanning run over all changed files — no secrets. All test addresses are RFC 5737
documentation ranges or localhost.

## 19. CodeQL

CodeQL invoked over the Rust source changes; result recorded in the run log. If skipped/unavailable/
timed-out/database-too-large, that exact result is recorded and not called clean.

## 20. Provenance

Run 363 continues Run 362 (accepted PARTIAL-POSITIVE). Source/test-only; no release-binary evidence,
no live seed/bootnode/faucet/RPC/explorer/status-page deployment, no MainNet/TestNet enablement.

## 21. Honest limitations

- Source/test-only: the live `qbind-node` binary path does not yet construct `AsyncPeerManager` with
  this override in production wiring; the seam is exercised via the peer-manager construction path and
  tests. Release-binary evidence is deferred to Run 364.
- M12 stays Yellow; no Green claim.

## 22. Suggested Run 364 next step

Produce release-binary evidence that a running `qbind-node` honors **both** the connection-rate and the
per-peer message-rate runtime overrides end-to-end (helper + harness like Run 362), then evaluate the
M12 Green gate.