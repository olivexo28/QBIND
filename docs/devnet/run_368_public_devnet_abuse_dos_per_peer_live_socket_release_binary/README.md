# QBIND DevNet evidence — Run 368

**Title.** Release-binary **admitted-peer per-peer message-rate live-socket**
evidence for the public DevNet abuse/DoS M12 controls — standing up a real
loopback TCP socket pair, registering one side as an **admitted peer** on a live
`AsyncPeerManagerImpl` (the component that owns the per-peer `PeerRateLimiter`),
flooding length-prefixed `NetMessage` frames from the other side, and proving
over a real socket that under-budget messages are accepted and over-budget
messages are dropped by the live limiter while the per-peer drop counter
increments — plus a re-run of the Run 367 **connection-rate** live-socket proof
on the real `target/release/qbind-node` as a regression.

**Status.** PARTIAL-POSITIVE (strengthened). Run 368 strengthens the per-peer
evidence beyond Run 367's synchronous `PeerRateLimiter::allow()` construction-path
proof: the per-peer message-rate control is now proven **over a real admitted-peer
socket** through the actual async `AsyncPeerManagerImpl::peer_reader_task` receive
loop, with the live `NodeMetrics::peer_network().total_rate_limit_drops()` /
`peer_rate_limit_drop_count(peer)` counter reflecting the drops and the
`qbind_net_per_peer_drops_total{...,reason="rate_limit"}` metric family rendering.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** M12 Green
requires BOTH controls proven over the **deployed** live socket. The per-peer
message-rate limiter enforces inside `AsyncPeerManagerImpl::peer_reader_task`,
which the **deployed** `qbind-node` inbound path does NOT invoke: the deployed
path is `TcpKemTlsP2pService::subscribe()` → `P2pInboundDemuxer` → handlers (see
`crates/qbind-node/src/p2p_node_builder.rs` ~L1435-1459), and neither
`p2p_inbound.rs` nor `p2p_tcp.rs` call `PeerRateLimiter::allow()`.
`build_deployed_peer_manager()` / `AsyncPeerManagerImpl` is construction-path-only
and is never spawned by `main.rs`. So the Run 368 per-peer proof is at the
`AsyncPeerManagerImpl` layer with a plain-TCP admitted peer, NOT the deployed
TcpKemTls receive path, and NOT a full KEMTLS mutual-auth handshake.

## Decision gate (recorded) — Route C

Per `task/RUN_368_TASK.txt`, the required decision gate resolves to **Route C**:
current code cannot drive admitted-peer per-peer message-rate limiting over the
**deployed** live socket without broader P2P runtime work, because the deployed
inbound message path bypasses the `PeerRateLimiter` entirely. Route A (adapt
existing harnesses to flood over the deployed peer path) is not possible without
that wiring; Route B (a tiny hidden seam) cannot help either, because even a seam
that emitted admitted-peer messages would flow through the demuxer path that does
not consult the limiter. The correct action under Route C is: **do not mark M12
Green; record the exact blocker and recommend the next source run.** Run 368
additionally contributes a genuine real-socket per-peer drop proof at the
`AsyncPeerManagerImpl` layer, which is the strongest per-peer evidence to date
and de-risks the eventual wiring run.

## What Run 368 proves (on real release artifacts)

* `target/release/qbind-node` and the Run 368 release helper build; SHA-256s,
  Build IDs, and the toolchain are captured in `summary.txt`.
* The Run 368 release helper PASSes 9/9 scenarios, including three real-socket
  admitted-peer scenarios (`02`/`03`/`04`).
* **Real socket, per-peer under budget:** a bucket of `5/0` accepts exactly 5
  framed messages over the admitted peer's socket with 0 per-peer drops.
* **Real socket, per-peer over budget:** a flood of 80 framed messages over a
  `5/0` bucket is dropped by the live `PeerRateLimiter`; the per-peer drop
  counter increments (≈75 drops observed) and the
  `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` family renders.
* **Live socket connection-rate regression (Run 367 parity):** a P2P-capable
  loopback release node with a `window=60s,max=3,burst=0` connection-rate limiter
  admits the first 3 inbound TCP connections (metric 0) and refuses the next 7
  (metric == 7; log shows 3 accepted / 7 rate-limited).
* **Default preserved:** a no-flag P2P node keeps the connection limiter disabled
  and `qbind_p2p_connection_rate_drop_total` at 0; per-peer defaults remain
  `1000` msg/s + `100` burst.
* **Independence:** a connection-rate refusal increments only the connection
  metric (`P2pMetrics`); a per-peer flush increments only the per-peer counter
  (`NodeMetrics::peer_network`).
* **Fail-closed / MainNet refused / hidden CLI surface:** proven via the release
  helper linking the production validation fn `CliArgs::abuse_dos_runtime_config`.

## Honest scope limitation (the remaining M12 blocker)

The deployed `qbind-node` binary's live inbound message path does not enforce the
per-peer `PeerRateLimiter`. Marking M12 Green requires a source run that wires the
`PeerRateLimiter` onto the deployed TcpKemTls receive path (either by routing
inbound frames through `AsyncPeerManagerImpl`, or by adding a per-peer
message-rate check in `P2pInboundDemuxer` / `TcpKemTlsP2pService`), then re-proving
per-peer drops over the deployed live socket with two KEMTLS-admitted peers. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md` for the full provenance and the
readiness-matrix delta.

## Reproduce

```bash
cargo build -p qbind-node --release
cargo build -p qbind-node --release \
  --example run_368_public_devnet_abuse_dos_per_peer_live_socket_helper
scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh
```

All addresses are loopback (`127.0.0.1`); documentation addresses use RFC 5737.
Temporary data dirs are created and removed; no seed/bootnode/faucet/RPC/explorer
/status page is deployed; no wire format, peer admission, trust bundle, validator
set, epoch, or `LivePqcTrustState` is changed. No MainNet enablement; no public
DevNet launch claim.

## Tracked files

Only `README.md`, `summary.txt`, and `.gitignore` in this directory are tracked.
Everything else the harness writes (helper output, per-scenario files, node logs,
temporary data dirs) is ephemeral, contains absolute paths, and is gitignored.
