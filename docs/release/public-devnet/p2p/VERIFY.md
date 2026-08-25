# QBIND Public DevNet — P2P Posture Verification (VERIFY)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document lists the exact commands a reviewer/operator can run to verify the published public
DevNet P2P posture package (`P2P_PORT_POSTURE.md`, `PEER_ADMISSION_POLICY.md`, `ABUSE_DOS_POSTURE.md`)
and the Run 361 source/test abuse/DoS hardening boundary. All commands are read-only or build/test
commands; none deploy infrastructure, none open a public port, and none claim launch readiness.

> **Run 375 note.** The first-class `qbind-node identity` command (Run 375) adds no P2P wire-format
> change and no peer-admission change. To confirm the P2P posture is unchanged, verify the
> pre-existing strict mutual-auth flags still appear in `qbind-node --help` and that the `identity`
> subcommand is a local generation/verification utility only (`qbind-node identity --help`).

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

Run 361/362/363/364/365/366/367/368/369/370 do not claim public DevNet launch-readiness, TestNet readiness, MainNet readiness,
C4/C5 closure, or M4/M6 Green. **M12 stays Yellow/Partial (strengthened)**: Run 362 wires the
connection-rate limiter into runtime, Run 363 wires the per-peer message-rate override at source/test
level, Run 364 lands release-binary evidence for both, Run 365 threads the CLI-derived per-peer
override through the deployed `P2pNodeBuilder` into the live `AsyncPeerManagerImpl` construction path at
source/test level, Run 366 lands deployed-builder-path release-binary end-to-end evidence, Run 367
proves the **connection-rate** control **live-socket** on a running P2P-capable node, Run 368
proves the per-peer **message-rate** control over a **real admitted-peer socket at the
`AsyncPeerManagerImpl` layer**, Run 369 **wires the per-peer `PeerRateLimiter` onto the deployed
TcpKemTls receive path** (`read_loop` → `inbound_tx` → `subscribe()` → `P2pInboundDemuxer` → handlers)
at source/test level, and Run 370 **threads a live `NodeMetrics` handle into the deployed adapter (Route
B)** so the deployed per-peer drop exports `qbind_net_per_peer_drops_total{reason="rate_limit"}` and adds
release-binary **live-socket** connection-rate evidence — but M12 Green remains **deferred** because the
fully-live KEMTLS-admitted deployed per-peer socket flood is not yet driven. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_370.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_369.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md`, and
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 7v. Verify the Run 369 deployed TcpKemTls receive-path per-peer wiring (source/test)

Run 369 wires the per-peer `PeerRateLimiter` onto the deployed inbound receive path via the
`DeployedInboundPerPeerLimiter` adapter, installed by `P2pNodeBuilder::start()` and consulted by the
`TcpKemTlsP2pService` per-peer `read_loop` before demuxer dispatch. Source/test only; no wire-format,
admission, or connection-rate change.

```bash
# Run 369 adapter + test target exist:
test -f crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs
test -f crates/qbind-node/tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs

# Build the lib and run the Run 369 tests + regression targets:
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_369_public_devnet_deployed_per_peer_limiter_wiring_tests
cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests
```

Expected: Run 369 tests **24/24 PASS**; the deployed inbound limiter derives `1000` msg/s + `100` burst
by default; the hidden `--p2p-max-messages-per-second` / `--p2p-burst-allowance` overrides reach it;
over-budget inbound frames drop with the adapter's per-peer counter (and
`qbind_net_per_peer_drops_total{reason="rate_limit"}`) incrementing while `qbind_p2p_connection_rate_drop_total`
stays 0; `--help` still hides the abuse/DoS flags and no Run 369 flag exists. Defaults preserved; no new
public CLI flags. **M12 stays Yellow/Partial — deployed TcpKemTls receive-path source/test wiring landed;
Green deferred to Run 370 pending release-binary live-socket deployed-path evidence.**

## 7va. Verify the Run 370 deployed per-peer exported-metric threading + release-binary evidence (Route B)

Run 370 threads a live `NodeMetrics` handle into the deployed `DeployedInboundPerPeerLimiter` (via
`P2pNodeBuilder::with_node_metrics` + the shared `build_deployed_inbound_per_peer_limiter()` seam, wired in
`main.rs`) so a per-peer drop on the deployed `read_loop` exports
`qbind_net_per_peer_drops_total{reason="rate_limit"}`. Default-preserving; no new public CLI flags.

```bash
# Run 370 helper + harness + test target exist:
test -f crates/qbind-node/examples/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper.rs
test -f scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh
test -f crates/qbind-node/tests/run_370_public_devnet_deployed_live_socket_m12_tests.rs

# Build the lib and run the Run 370 source tests:
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_370_public_devnet_deployed_live_socket_m12_tests

# Run the release-binary live-socket harness (builds release + helper, drives real sockets):
bash scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh
```

Expected: Run 370 tests **20/20 PASS**; the release helper **PASS (10/10)**; the connection-rate control
proven live-socket (10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live
`qbind_p2p_connection_rate_drop_total = 7`); the deployed adapter exports
`qbind_net_per_peer_drops_total{reason="rate_limit"}` on over-budget drops; invalid/unbounded/MainNet fail
the binary closed; `--help` still hides the abuse/DoS flags. **M12 stays Yellow/Partial (strengthened) — the
fully-live KEMTLS-admitted deployed per-peer socket flood remains the residual blocker; Green deferred.**

## 7vb. Verify the Run 371 KEMTLS-admitted deployed per-peer live-socket flood (Route A) — M12 Green

Run 371 uses production public APIs (no source change) to stand up a **second KEMTLS-admitted peer** that
completes a real KEMTLS mutual-auth handshake over a real loopback socket against a running
`target/release/qbind-node`, floods over-budget `P2pMessage::Consensus` frames through the deployed
`TcpKemTlsP2pService::read_loop`, and observes live `/metrics`.

```bash
# Run 371 helper + harness exist (no source test file — Route A / no source change):
test -f crates/qbind-node/examples/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper.rs
test -f scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh

# Run the release-binary live-socket harness (builds release + helper, drives real KEMTLS sockets):
bash scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh /tmp/qbind-run371
cat /tmp/qbind-run371/summary.txt
```

Expected: the helper scenario suite **PASS (10/10)**; the KEMTLS handshake completes against
`target/release/qbind-node`; under-budget frames → `qbind_net_per_peer_drops_total{reason="rate_limit"}`
ABSENT; over-budget frames → that counter increments (~47 of 60) on live `/metrics` with the connection
kept up; the connection-rate live-socket proof preserved (metric = 7) and independent; invalid/unbounded/
MainNet fail the binary closed; `--help` still hides the abuse/DoS flags. **M12 moves Green for the two
abuse/DoS deployed live-socket controls; defaults preserved; does not move M4/M6 or close C4/C5.**

## 7vc. Verify the Run 372 strict-mutual-auth + multi-peer concurrent flood hardening (Route A) — M12 Green

Run 372 re-proves the Run 371 result under **strict admission** (`--p2p-mutual-auth required`) and
**multi-peer concurrent flood** conditions, still using production public APIs (no source change). Two peers
(honest under-budget + abusive over-budget) each complete a `MutualAuthMode::Required` KEMTLS handshake
against a running `target/release/qbind-node`; live `/metrics` isolates the abusive peer's drops to its own
per-peer bucket while the honest peer's bucket stays clean.

```bash
# Run 372 helper + harness exist (no source test file — Route A / no source change):
test -f crates/qbind-node/examples/run_372_public_devnet_m12_strict_auth_multi_peer_flood_helper.rs
test -f scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh

# Run the release-binary live-socket harness (builds release + helper, drives real strict-auth sockets):
bash scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh /tmp/qbind-run372
cat /tmp/qbind-run372/summary.txt
```

Expected: the helper scenario suite **PASS (13/13)**; the deployed node logs `mutual_auth=Required`; both
peers complete the Required KEMTLS handshake; the abusive peer's over-budget flood surfaces
`qbind_net_per_peer_drops_total{peer="<abusive key>",reason="rate_limit"}` > 0 while the honest peer's bucket
label is ABSENT; the connection-rate live-socket proof preserved (metric = 7) and independent; the release
helper proves a production-grade `PqcRootMode::PqcStaticRoot` (ML-DSA-44 + ML-KEM-768) Required handshake;
invalid/unbounded/MainNet fail the binary closed; `--help` still hides the abuse/DoS flags and keeps
`--p2p-mutual-auth` public. **M12 remains Green (hardening); no new public CLI flags; strict mutual-auth only
tightens admission; does not move M4/M6 or close C4/C5.**

## 7vd. Verify the Run 373 cross-process PqcStaticRoot strict-auth flood hardening (Route A) — M12 Green

Run 373 extends Run 372's in-process static-root proof to a **cross-process** standalone-binary proof: the
deployed `target/release/qbind-node` runs under `--p2p-mutual-auth required --p2p-pqc-root-mode
pqc-static-root` with operator-configured `--p2p-trusted-root`/`--p2p-leaf-cert`/`--p2p-leaf-cert-key`
material, and two KEMTLS-admitted peers built from the same material flood cross-process with abusive-bucket
isolation on live `/metrics`. Production public APIs + pre-existing public CLI only (no source change).

```bash
# Run 373 helper + harness exist (no source test file — Route A / no source change):
test -f crates/qbind-node/examples/run_373_public_devnet_m12_pqc_static_root_cross_process_helper.rs
test -f scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh

# Run the release-binary live-socket harness (builds release + helpers, mints temporary static-root
# material, drives real cross-process strict-auth static-root sockets):
bash scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh /tmp/qbind-run373
cat /tmp/qbind-run373/summary.txt
```

Expected: the helper scenario suite **PASS (13/13)**; temporary ML-DSA-44 root + ML-KEM-768 leaf material is
generated in a temp dir (root signing key in memory only); the deployed node logs
`pqc_root_mode=pqc-static-root` and `mutual_auth=Required` and exports `qbind_p2p_pqc_root_mode 1` /
`qbind_p2p_pqc_roots_configured 1`; both peers complete the Required + PqcStaticRoot KEMTLS handshake and are
registered under their verified cert-derived NodeIds; the abusive peer's over-budget flood surfaces
`qbind_net_per_peer_drops_total{peer="<cert-derived key>",reason="rate_limit"}` > 0 while the honest peer's
cert-derived bucket label is ABSENT; the connection-rate live-socket proof preserved (metric = 7) and
independent; invalid/unbounded/malformed-root/MainNet fail the binary closed; `--help` still hides the
abuse/DoS flags and keeps the static-root/strict-auth flags public. **M12 remains Green (hardening); no new
public CLI flags; static-root + strict mutual-auth only tighten admission; does not move M4/M6 or close
C4/C5.**

## 7w. Verify the Run 368 admitted-peer per-peer message-rate live-socket evidence

Run 368 drives a real admitted peer on a live `AsyncPeerManagerImpl` over a loopback socket and proves
per-peer message-rate drops, and re-runs the Run 367 connection-rate live-socket proof. No production
source change.

```bash
# Run 368 helper + harness exist:
test -f crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs
test -f scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh

# Build the release binary + helper and run the harness:
cargo build -p qbind-node --release
cargo build -p qbind-node --release --example run_368_public_devnet_abuse_dos_per_peer_live_socket_helper
scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh /tmp/run368_out
```

Expected: helper **9/9 scenarios PASS**; a `5/0` bucket accepts 5 framed messages over a real socket
(0 drops) and drops an 80-frame flood (≈75 per-peer drops) with
`qbind_net_per_peer_drops_total{...,reason="rate_limit"}` rendering; the connection-rate regression
passes (10 connections, max 3 → 3 accepted / 7 refused, metric = 7); `--help` hides all 8 hidden
abuse/DoS flags; real hidden flags parse; invented flag rejected (rc=2). Defaults preserved; no new
public CLI flags. **M12 stays Yellow/Partial (strengthened); Green deferred (Route C) pending
per-peer message-rate enforcement on the deployed TcpKemTls receive path.**

## 7x. Verify the Run 367 live-socket connection-rate evidence

Run 367 launches the real release binary in a P2P-capable loopback mode and proves the accept-loop
connection-rate control over a real inbound socket. No production source change.

```bash
# Run 367 helper + harness exist:
test -f crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs
test -f scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh

# Build the release binary + helper and run the live-socket harness:
cargo build -p qbind-node --release
cargo build -p qbind-node --release --example run_367_public_devnet_abuse_dos_live_socket_helper
scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh /tmp/run367_out
```

Expected: helper **8/8 scenarios PASS**; `p2p_mode_discovery` confirms `P2P transport up` (real socket
bound via `--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`); default (no-flag) node
keeps `qbind_p2p_connection_rate_drop_total = 0`; a configured limiter (window 60000 ms, max 3) admits 3
under-budget inbound TCP connections (metric 0) and refuses over-budget (10 total → 3 accepted / 7
refused, live metric = 7). `--help` hides all 8 hidden abuse/DoS flags; real hidden flags parse; invented
flag rejected (rc=2). Defaults preserved; no new public CLI flags. **M12 stays Yellow/Partial
(strengthened); Green deferred pending per-peer message-rate live-socket evidence over an admitted peer.**

## 7y. Verify the Run 366 deployed-builder-path release-binary evidence

Run 366 proves on real release artifacts that the deployed `P2pNodeBuilder` path honors both abuse/DoS
controls. Release-binary evidence; no production source change; deployed-builder-path, not live-socket.

```bash
# Run 366 helper + harness exist:
test -f crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs
test -f scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh

# Build the release binary + helper and run the harness:
cargo build -p qbind-node --release
cargo build -p qbind-node --release --example run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper
scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh /tmp/run366_out
```

Expected: helper **8/8 scenarios PASS**; `--help` hides all 8 hidden abuse/DoS flags; real hidden flags
parse; invented flag rejected (rc=2); the bounded node launch is reaped by timeout under LocalMesh
(`enable_p2p=true ignored because network_mode=local-mesh`). Defaults preserved (`1000` msg/s + `100`
burst; connection limiter disabled), no new public CLI flags. **M12 stays Yellow/Partial (strengthened);
Green deferred pending live-socket end-to-end evidence.**

## 7z. Verify the Run 365 deployed-node per-peer threading (source/test)

Run 365 threads the CLI-derived `peer_rate_limiter_config` through the deployed `P2pNodeBuilder` into
the live `AsyncPeerManagerImpl` construction path. Source/test only; release-binary evidence deferred
to Run 366.

```bash
# Run 365 test target exists:
test -f crates/qbind-node/tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs

# Build the library and run the Run 365 tests + prior-run regressions + library tests:
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests
cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests
cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests
cargo test -p qbind-node --lib
```

Expected: Run 365 **20 passed**, Run 363 **21 passed**, Run 362 **38 passed**, Run 361 **30 passed**,
library **1385 passed**. Defaults preserved (`1000` msg/s + `100` burst; connection limiter disabled),
no new public CLI flags. **M12 stays Yellow/Partial (strengthened); Green deferred to Run 366.**

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

## 7a. Verify the Run 363 per-peer message-rate runtime override (source/test)

Run 363 makes the hidden `--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags actually
affect the live per-peer `PeerRateLimiter` used by `AsyncPeerManager` (default preserved: `1000` msg/s
+ `100` burst). Source/test only; release-binary evidence is deferred to Run 364.

```
# Run 363 test target exists:
ls crates/qbind-node/tests/run_363_public_devnet_per_peer_message_rate_runtime_tests.rs

# The runtime config derives a validated per-peer PeerRateLimiterConfig:
grep -n "peer_rate_limiter_config\|build_peer_rate_limiter" \
  crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs

# The peer-manager builds its live per-peer limiter from the operator-configured thresholds:
grep -n "peer_rate_limiter_config\|with_peer_rate_limiter_config\|build_peer_rate_limiter" \
  crates/qbind-node/src/async_peer_manager.rs

# Run the Run 363 tests + Run 362/361 regressions + library tests:
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests
cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests
cargo test -p qbind-node --lib

# The per-peer message-rate flags remain hidden (devnet-only) and MUST NOT appear in --help:
target/release/qbind-node --help | grep -c "p2p-max-messages-per-second" || echo "OK: hidden from --help"
```

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_363.md`. **M12 stays Yellow/Partial (stronger); Green is
deferred to Run 364** pending release-binary evidence for both connection-rate and per-peer
message-rate runtime configurability.

## 7b. Verify the Run 364 release-binary evidence for both controls

Run 364 produces release-binary evidence for **both** abuse/DoS controls on the real
`target/release/qbind-node` binary plus a release-built helper. It adds no source behavior and no new
CLI flag.

```
# Run 364 helper + harness exist:
ls crates/qbind-node/examples/run_364_public_devnet_abuse_dos_m12_release_binary_helper.rs
ls scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh

# Build the release binary + helper, then run the Run 364 harness (captures SHA-256s + verdict):
cargo build -p qbind-node --release
cargo build -p qbind-node --release \
  --example run_364_public_devnet_abuse_dos_m12_release_binary_helper
scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh /tmp/run364out
grep -E '^(verdict|helper_verdict):' /tmp/run364out/summary.txt

# Re-run the Run 363/362/361 regressions + library tests:
cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests
cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests
cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests
cargo test -p qbind-node --lib

# All Run 362/363 abuse/DoS flags remain hidden (devnet-only) and MUST NOT appear in --help:
target/release/qbind-node --help | grep -c -- "--p2p-connection-rate\|--p2p-max-messages-per-second\|--p2p-burst-allowance" \
  || echo "OK: hidden from --help"
```

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md` and
`docs/devnet/run_364_public_devnet_abuse_dos_m12_release_binary/`. **M12 stays Yellow/Partial
(strengthened) — NOT Green**: the connection-rate limiter is production-wired and release-proven, but
the deployed node does not yet thread the CLI-derived per-peer `peer_rate_limiter_config` into its live
`AsyncPeerManagerImpl`, so per-peer operator effect on a running node is not yet delivered.
## Run 374 — operator identity material (cross-reference)

The peer identity material verified through these admission paths can be generated and independently
verified with the Run 374 operator identity package (`docs/release/public-devnet/identity/`,
`VERIFY.md` / `IDENTITY_VERIFY.md`). Run 374 is **generation/verification only** (Route B, no production
source change, no new CLI flag): it does not change admission, the P2P wire format, or trust-bundle
handling, and it does not move M12. A real loopback `qbind-node` boot on generated material reports
`qbind_p2p_pqc_root_mode 1` / `qbind_p2p_pqc_roots_configured 1`; mismatched material fails closed.