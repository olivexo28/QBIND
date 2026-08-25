# QBIND DevNet evidence — Run 367

**Title.** Release-binary **live-socket** evidence for the public DevNet
abuse/DoS M12 controls — driving a real `target/release/qbind-node` in a
P2P-capable loopback mode and exercising the accept-loop **connection-rate
limiter** (Run 362) over real inbound TCP sockets, plus a release-built helper
that backs the runtime-symbol invariants.

**Status.** Partial-positive (strengthened). Run 367 fixes the Run 366 blocker:
Run 366 launched `qbind-node` **without** `--network-mode p2p`, so it ran in
LocalMesh and never bound a live P2P socket. Run 367 launches the real release
binary with `--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`,
confirms it binds a real socket (`P2P transport up`), and proves the
**connection-rate control end-to-end over a live loopback socket**: under-budget
inbound TCP connections are admitted with the drop metric at 0, and over-budget
connections are refused with `qbind_p2p_connection_rate_drop_total` incrementing
by exactly the over-budget count.

**M12 stays Yellow/Partial (strengthened) — it does NOT move Green.** M12 Green
requires BOTH controls proven over a live socket. The per-peer **message-rate**
control enforces on the ADMITTED-peer receive path inside `AsyncPeerManagerImpl`
and needs a second KEMTLS peer that completes the handshake and floods messages
over the configured bucket. Run 367 does not stand up that second-peer flood
path, so the per-peer message-rate control remains proven only through the
DEPLOYED `P2pNodeBuilder` path in the release helper. See the "Honest scope
limitation" below and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`.

## Decision gate (recorded)

**Conclusion A — the existing release binary supports a bounded P2P-capable
loopback mode.** No source change was required to drive live sockets:
`main.rs`'s `NetworkMode::P2p` branch calls `run_p2p_node`, which builds the
deployed `P2pNodeBuilder` (installing the operator abuse/DoS runtime config at
`main.rs:6823` via `with_abuse_dos_runtime_config`) and binds a real listener in
`TcpKemTlsP2pService`. Run 366's "`--enable-p2p` is ignored" observation was a
consequence of not passing `--network-mode p2p` (the DevNet default is
LocalMesh), not a missing mode. Run 367 therefore proceeds under option A and
adds evidence/helper/harness/docs only — **no production/library source change,
no new CLI flag.**

## What Run 367 states

* The inbound **connection-rate limiter** is runtime-wired into the live
  `p2p_tcp` accept loop (Run 362), **disabled by default**, consulted per
  inbound socket in `spawn_accept_loop` via
  `PublicDevnetAbuseDosRuntimeState::should_admit` BEFORE any KEMTLS handshake.
  Run 367 proves over a live loopback socket that it admits under-budget and
  refuses over-budget inbound TCP connections, does not admit a peer on refusal,
  and increments `qbind_p2p_connection_rate_drop_total` on refusal only.
* **Default preservation, live socket.** A P2P node launched with NO abuse/DoS
  flags binds the socket, logs no "limiter ENABLED", and serves
  `qbind_p2p_connection_rate_drop_total 0`.
* The **per-peer message-rate override** reaches the live `AsyncPeerManagerImpl`
  `PeerRateLimiter` construction path through the DEPLOYED `P2pNodeBuilder`
  (Run 365: `deployed_peer_rate_limiter_config` /
  `deployed_async_peer_manager_config` / `build_deployed_peer_manager`). The
  release helper proves a custom `--p2p-max-messages-per-second` /
  `--p2p-burst-allowance` is installed by the deployed builder and the resulting
  live limiter allows under-budget / drops over-budget messages. This remains
  deployed-builder-path evidence, NOT live-admitted-peer-socket evidence.
* The two limiters are independent: a connection-rate refusal never admits a
  peer, and a per-peer message-rate drop increments no connection-rate counter.
* MainNet is refused; invalid/zero/unbounded/inconsistent configs fail closed —
  both proven through the exact production validation function
  `CliArgs::abuse_dos_runtime_config()`.
* The hidden/devnet-only abuse/DoS flags are absent from `--help`; the real
  hidden flags parse on the real binary; invented flags are rejected by clap.
* **Run 367 does NOT launch a public DevNet**, deploy a seed / bootnode /
  faucet / RPC / explorer / status page, open a default-open public port,
  change any P2P wire format, weaken peer admission or trust-bundle behavior,
  wire authority lifecycle, mutate validator set / epoch, or make any
  TestNet/MainNet readiness claim. All addresses are loopback (127.0.0.1);
  temporary data dirs are used.
* M4 remains Yellow/launch-blocking; M6 remains Yellow; C4 and C5 remain OPEN.

## Honest scope limitation

* The **connection-rate limiter** is now proven **live-socket** on the real
  release binary: the accept loop refuses over-budget inbound TCP connections
  and increments `qbind_p2p_connection_rate_drop_total`, observed on the live
  `/metrics` endpoint of a running P2P-capable node.
* The **per-peer message-rate override** is proven only through the DEPLOYED
  builder live-peer-manager construction path
  (`P2pNodeBuilder::build_deployed_peer_manager` → `AsyncPeerManagerImpl::new`
  → `PeerRateLimiter`) in the release helper. Driving it over a live socket
  requires a SECOND KEMTLS peer that completes the handshake and sends messages
  faster than the per-peer bucket (the limiter enforces on the admitted-peer
  receive path). Run 367 does not stand up that second-peer flood harness.
* Because M12 Green requires BOTH controls over a live socket, M12 stays
  **Yellow/Partial (strengthened)** and does not move Green.
* The two production-binary semantic-fail-closed scenarios (invalid config /
  MainNet enablement) are proven through the release helper, which calls the
  exact production validation function `CliArgs::abuse_dos_runtime_config()`.

## Reproduce

```
scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh <OUT_DIR>
```

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this archive.
All raw logs/artifacts are `.gitignore`d because they contain absolute paths and
ephemeral data.
