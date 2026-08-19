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

## 4. Verify no runtime wiring / CLI flag was added

```
# The connection-rate limiter is NOT referenced by the live accept loop:
grep -n "ConnectionRateLimiter\|public_devnet_abuse_dos_config" crates/qbind-node/src/p2p_tcp.rs || \
  echo "OK: no runtime wiring in p2p_tcp.rs"

# No new public CLI flag was added for the abuse/DoS config:
grep -n "abuse.dos\|connection-rate\|connection_rate" crates/qbind-node/src/cli.rs || \
  echo "OK: no new abuse/DoS CLI flag"
```

## 5. Verify the safe default preserves current behavior

The default profile (`AbuseDosConfig::default()`) preserves `1000` msg/s + `100` burst per-peer and
leaves the connection limiter **disabled** (test `t01_default_profile_preserves_current_values`,
`t33_peer_rate_limiter_with_defaults_compatible`). No runtime default is changed by this run.

## 6. Verify no forbidden claim

Run 361 does not claim public DevNet launch-readiness, TestNet readiness, MainNet readiness, C4/C5
closure, or M4/M6/M12 Green. M12 stays **Yellow (strengthened)**; Green is deferred to Run 362 pending
runtime wiring + release-binary evidence. See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_361.md` and
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.
