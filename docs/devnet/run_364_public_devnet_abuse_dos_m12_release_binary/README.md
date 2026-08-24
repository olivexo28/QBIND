# QBIND DevNet evidence — Run 364

**Title.** Release-binary evidence for the public DevNet abuse/DoS M12 controls —
the runtime-owned **connection-rate limiter** (Run 362) and the **per-peer
message-rate override** (Run 363) — proven together on the real
`target/release/qbind-node` plus a release-built helper.

**Status.** Partial-positive (release-binary evidence). Run 364 produces the
release-binary evidence deferred by Run 363. It proves, in release mode, that the
production library symbols for both abuse/DoS controls are present and behave as
documented. **M12 stays Yellow/Partial (strengthened) — it does NOT move Green.**
See the "Honest scope limitation" below and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md` for the exact M12 disposition.

Run 364 proves on real `target/release/qbind-node` plus the release-built helper
`crates/qbind-node/examples/run_364_public_devnet_abuse_dos_m12_release_binary_helper.rs`
that the Run 361/362/363 production library symbols are linked and exercised in
release mode.

## What Run 364 states

* Run 364 is **release-binary evidence only** for the Run 361/362/363 abuse/DoS
  model + wiring. It adds no source behavior and exposes no new CLI flag.
* The inbound **connection-rate limiter** is runtime-wired into the live
  `p2p_tcp` accept loop (Run 362), **disabled by default**, and only installed
  when an operator explicitly enables it. The release helper proves it accepts
  under-budget and refuses over-budget inbound connections and increments
  `qbind_p2p_connection_rate_drop_total` exactly once on refusal.
* The **per-peer message-rate override** (Run 363) reaches the live
  `AsyncPeerManagerImpl` `PeerRateLimiter` construction path via
  `CliArgs::abuse_dos_runtime_config` → `peer_rate_limiter_config` →
  `AsyncPeerManagerConfig::with_peer_rate_limiter_config` →
  `AsyncPeerManagerImpl::new`. The release helper proves a custom
  `--p2p-max-messages-per-second` / `--p2p-burst-allowance` reaches that
  construction path and the resulting limiter allows under-budget / drops
  over-budget messages.
* Default behavior is preserved bit-for-bit: per-peer `1000` msg/s + `100`
  burst, connection limiter disabled, no accept-loop change.
* The two limiters are independent: a connection-rate refusal never admits a
  peer, and a per-peer message-rate drop increments no connection-rate counter.
* MainNet is refused; invalid/zero/unbounded/inconsistent configs fail closed —
  both proven through the exact production validation function
  `CliArgs::abuse_dos_runtime_config()`.
* The hidden/devnet-only abuse/DoS flags are absent from `--help`; the real
  hidden flags parse; invented flags are rejected by clap.
* **Run 364 does NOT launch a public DevNet**, deploy a seed / bootnode /
  faucet / RPC / explorer / status page, open a default-open public port,
  change any P2P wire format, weaken peer admission or trust-bundle behavior,
  wire authority lifecycle, mutate validator set / epoch, or make any
  TestNet/MainNet readiness claim.
* M4 remains Yellow/launch-blocking; M6 remains Yellow; C4 and C5 remain OPEN.

## Honest scope limitation

* The **connection-rate limiter** is wired end-to-end into the production
  accept path (`main.rs` → `p2p_node_builder` → `TcpKemTlsP2pService`).
* The **per-peer message-rate override** reaches the *live peer-manager limiter
  construction path* (`AsyncPeerManagerConfig::with_peer_rate_limiter_config` →
  `AsyncPeerManagerImpl::new` → `PeerRateLimiter`), which the release helper
  exercises with real symbols. **However**, the production `main.rs` /
  `p2p_node_builder` do not yet thread the CLI-derived `peer_rate_limiter_config`
  into the deployed node's live `AsyncPeerManagerImpl`; end-to-end operator
  effect on a running node is therefore not yet delivered. For this reason M12
  stays **Yellow/Partial (strengthened)** and does not move Green.
* The two production-binary semantic-fail-closed scenarios (invalid config /
  MainNet enablement exit non-zero) are proven through the release helper, which
  calls the exact production validation function
  `CliArgs::abuse_dos_runtime_config()`. They are not re-run as a full node
  launch because every `qbind-node` invocation reachable in this environment
  enters its blocking LocalMesh consensus loop before the abuse/DoS validation
  branch executes; a full-node run would hang rather than exit.

## Reproduce

```
scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh <OUT_DIR>
```

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this archive.
All raw logs/artifacts are `.gitignore`d because they contain absolute paths and
ephemeral data.