# QBIND Public DevNet — P2P Posture Verification (VERIFY)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document lists the exact commands a reviewer/operator can run to verify the published public
DevNet P2P posture package (`P2P_PORT_POSTURE.md`, `PEER_ADMISSION_POLICY.md`, `ABUSE_DOS_POSTURE.md`)
and the Run 361 source/test abuse/DoS hardening boundary. All commands are read-only or build/test
commands; none deploy infrastructure, none open a public port, and none claim launch readiness.

## 1. Scope

- Run 360 published the P2P port / peer-admission / abuse-DoS posture (docs-only, CLI-validated).
- Run 361 added a **source/test-only** operator-configurable abuse/DoS config model + a bounded inbound
  connection-rate limiter boundary. **No runtime wiring, no CLI flag, no default change.**
- Run 362 **wires the connection-rate limiter into the live `p2p_tcp` accept loop** behind
  runtime-owned, default-off state, adds the `qbind_p2p_connection_rate_drop_total` metric, and exposes
  hidden/devnet-only operator CLI flags. Defaults are preserved bit-for-bit. §4 below describes the
  Run 361 boundary state; §7 describes the Run 362 runtime wiring.

## 2. Verify the abuse/DoS posture doc matches source

```
# Existing per-peer rate limiter defaults referenced by ABUSE_DOS_POSTURE.md:
grep -n "DEFAULT_MAX_MESSAGES_PER_SECOND\|DEFAULT_BURST_ALLOWANCE\|NUM_SHARDS" \
  crates/qbind-node/src/peer_rate_limiter.rs
# Expect: 1000 msg/s, 100 burst, 16 shards (enabled by default; fails open on lock poisoning).
```

## 3. Verify the Run 361 source/test boundary

```
# Module and test target exist:
ls crates/qbind-node/src/public_devnet_abuse_dos_config.rs
ls crates/qbind-node/tests/run_361_public_devnet_abuse_dos_hardening_tests.rs

# Build the library (source boundary compiles, no default change):
cargo build -p qbind-node --lib

# Run the Run 361 tests (accepted/construction, validation failures, limiter behavior,
# non-mutation, compatibility):
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests

# Regression: existing library tests still pass:
cargo test -p qbind-node --lib
```

## 4. Verify the Run 361 boundary state (source/test only)

The following describes the **Run 361** boundary as it stood before Run 362 runtime wiring; §7
documents the Run 362 changes.

```
# As of Run 361, the connection-rate limiter was NOT referenced by the live accept loop.
# As of Run 362 it IS (behind runtime-owned, default-off state) — see §7.
```

## 5. Verify the safe default preserves current behavior

The default profile (`AbuseDosConfig::default()`) preserves `1000` msg/s + `100` burst per-peer and
leaves the connection limiter **disabled** (test `t01_default_profile_preserves_current_values`,
`t33_peer_rate_limiter_with_defaults_compatible`). No runtime default is changed by this run.

## 6. Verify no forbidden claim

Run 361/362 do not claim public DevNet launch-readiness, TestNet readiness, MainNet readiness, C4/C5
closure, or M4/M6 Green. **M12 stays Yellow/Partial (strengthened)**: Run 362 wires the connection-rate
limiter into runtime with release-binary evidence, but M12 Green remains deferred because the live
per-peer message-rate limiter is still not operator-configurable at runtime. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md` and
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 7. Verify the Run 362 runtime wiring

```
# Runtime module and Run 362 test target exist:
ls crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs
ls crates/qbind-node/tests/run_362_public_devnet_abuse_dos_runtime_tests.rs

# The connection-rate limiter IS now consulted by the live accept loop (behind runtime-owned state):
grep -n "abuse_dos_runtime\|should_admit" crates/qbind-node/src/p2p_tcp.rs

# The connection-rate-drop metric is registered on P2pMetrics:
grep -n "connection_rate_drop_total\|qbind_p2p_connection_rate_drop_total" \
  crates/qbind-node/src/metrics.rs

# The hidden/devnet-only abuse/DoS CLI flags exist (and are absent from --help):
grep -n "p2p-connection-rate-limit-enabled\|abuse_dos_runtime_config" crates/qbind-node/src/cli.rs

# Build the release binary + helper, then run the Run 362 harness (captures SHA-256s + verdict):
cargo build -p qbind-node --release
cargo build -p qbind-node --release \
  --example run_362_public_devnet_abuse_dos_runtime_release_binary_helper
scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh /tmp/run362_out

# Run the Run 362 tests + Run 361 regression + library tests:
cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests
cargo test -p qbind-node --lib

# The abuse/DoS flags are hidden (devnet-only) and MUST NOT appear in --help:
target/release/qbind-node --help | grep -c "p2p-connection-rate" || echo "OK: hidden from --help"
```