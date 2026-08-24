# QBIND DevNet evidence — Run 366

**Title.** Release-binary **end-to-end** evidence for the public DevNet abuse/DoS
M12 controls — the runtime-owned **connection-rate limiter** (Run 362) and the
**per-peer message-rate override threaded through the deployed `P2pNodeBuilder`**
(Run 365) — proven together on the real `target/release/qbind-node` plus a
release-built helper.

**Status.** Partial-positive (release-binary evidence). Run 366 produces the
release-binary end-to-end evidence deferred by Run 365. It proves, in release
mode, that the **deployed** `P2pNodeBuilder` path (`with_abuse_dos_runtime_config`
→ `deployed_peer_rate_limiter_config` → `deployed_async_peer_manager_config` →
`build_deployed_peer_manager`) honors both abuse/DoS controls on real release
artifacts. **M12 stays Yellow/Partial (strengthened) — it does NOT move Green.**
A running `qbind-node` cannot be driven over its live P2P inbound/message socket
path in this environment because DevNet runs in LocalMesh mode (`--enable-p2p`
is ignored), so the end-to-end evidence is deployed-builder-path (release-binary)
rather than live-socket. See the "Honest scope limitation" below and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md` for the exact M12 disposition.

Run 366 proves on real `target/release/qbind-node` plus the release-built helper
`crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`
that the Run 361/362/363/365 production library symbols are linked and exercised
in release mode via the deployed builder path.

## What Run 366 states

* Run 366 is **release-binary evidence only** for the Run 361/362/363/365
  abuse/DoS model + deployed-builder wiring. It adds no source behavior and
  exposes no new CLI flag.
* The inbound **connection-rate limiter** is runtime-wired into the live
  `p2p_tcp` accept loop (Run 362), **disabled by default**, and only installed
  when an operator explicitly enables it. The release helper proves it accepts
  under-budget and refuses over-budget inbound connections, does not admit a
  peer on refusal, and increments `qbind_p2p_connection_rate_drop_total` on
  refusal.
* The **per-peer message-rate override** now reaches the live
  `AsyncPeerManagerImpl` `PeerRateLimiter` construction path through the
  **deployed** `P2pNodeBuilder` methods landed in Run 365
  (`deployed_peer_rate_limiter_config` / `deployed_async_peer_manager_config` /
  `build_deployed_peer_manager`). The release helper proves a custom
  `--p2p-max-messages-per-second` / `--p2p-burst-allowance` is installed by the
  deployed builder and the resulting live limiter allows under-budget / drops
  over-budget messages. This is the deployed-builder path (Run 365), stronger
  than the direct `AsyncPeerManagerConfig` seam Run 364 exercised.
* Default behavior is preserved bit-for-bit: per-peer `1000` msg/s + `100`
  burst, connection limiter disabled, no accept-loop change, deployed builder
  derives `None` and equals the direct default config.
* The two limiters are independent: a connection-rate refusal never admits a
  peer, and a per-peer message-rate drop increments no connection-rate counter.
* MainNet is refused; invalid/zero/unbounded/inconsistent configs fail closed —
  both proven through the exact production validation function
  `CliArgs::abuse_dos_runtime_config()`.
* The hidden/devnet-only abuse/DoS flags are absent from `--help`; the real
  hidden flags parse on the real binary; invented flags are rejected by clap.
* A bounded, timeout-supervised real `target/release/qbind-node` launch on an
  explicit temporary `--data-dir` with the hidden abuse/DoS flags starts
  successfully (the real binary accepts the flags), but on DevNet it runs in
  LocalMesh mode and the live P2P accept/message path is **not** driven over a
  socket in this environment.
* **Run 366 does NOT launch a public DevNet**, deploy a seed / bootnode /
  faucet / RPC / explorer / status page, open a default-open public port,
  change any P2P wire format, weaken peer admission or trust-bundle behavior,
  wire authority lifecycle, mutate validator set / epoch, or make any
  TestNet/MainNet readiness claim.
* M4 remains Yellow/launch-blocking; M6 remains Yellow; C4 and C5 remain OPEN.

## Honest scope limitation

* The **connection-rate limiter** is wired end-to-end into the production
  accept path (`main.rs` → `p2p_node_builder` → `TcpKemTlsP2pService`) and is
  release-binary proven via the helper.
* The **per-peer message-rate override** now reaches the *deployed builder*
  live-peer-manager construction path (`P2pNodeBuilder::build_deployed_peer_manager`
  → `AsyncPeerManagerImpl::new` → `PeerRateLimiter`), which the release helper
  exercises with real release symbols. **However**, a running `qbind-node`
  cannot be driven over its live P2P inbound/message socket path in this
  environment: DevNet uses LocalMesh mode and logs
  `enable_p2p=true ignored because network_mode=local-mesh`, then blocks in the
  consensus loop. The end-to-end evidence is therefore **deployed-builder-path
  release-binary**, not live-socket. For this reason M12 stays
  **Yellow/Partial (strengthened)** and does not move Green.
* The two production-binary semantic-fail-closed scenarios (invalid config /
  MainNet enablement) are proven through the release helper, which calls the
  exact production validation function `CliArgs::abuse_dos_runtime_config()`.
  They are not re-run as a full node launch because every reachable
  `qbind-node` invocation enters its blocking LocalMesh consensus loop before
  the abuse/DoS validation branch executes; a full-node run would hang rather
  than exit.

## Reproduce

```
scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh <OUT_DIR>
```

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this archive.
All raw logs/artifacts are `.gitignore`d because they contain absolute paths and
ephemeral data.
