# QBIND DevNet evidence — Run 362

**Title.** Release-binary evidence for the public DevNet abuse/DoS runtime wiring (M12).

**Status.** PASS (release-binary evidence). Run 362 wires the Run 361 source/test
`AbuseDosConfig` / `ConnectionRateLimiter` model into the live `p2p_tcp` accept
path behind a runtime-owned, default-off handle, adds the
`qbind_p2p_connection_rate_drop_total` metric, and exposes a hidden/devnet-only
`--p2p-connection-rate-limit-*` CLI flag family.

Run 362 proves on real `target/release/qbind-node` plus the release-built helper
`crates/qbind-node/examples/run_362_public_devnet_abuse_dos_runtime_release_binary_helper.rs`
that the Run 361/362 production library symbols are present and exercised in
release mode.

## What Run 362 states

* Run 362 is runtime wiring + release-binary evidence for the Run 361 abuse/DoS
  model.
* The inbound **connection-rate limiter** is now wired into the live `p2p_tcp`
  accept loop behind a runtime-owned handle; it is **disabled by default** and
  only installed when an operator explicitly enables it.
* Default behavior is preserved bit-for-bit: per-peer `1000` msg/s + `100`
  burst, connection limiter disabled, no accept-loop change.
* Over-budget inbound connections are refused deterministically and closed
  early, before any KEMTLS handshake / trust-bundle / genesis work; a refusal
  never admits a peer and never mutates trust/validator/epoch state or writes
  any sequence/marker file.
* The `qbind_p2p_connection_rate_drop_total` metric increments only on refusal,
  is registered exactly once, and carries no endpoint labels.
* MainNet is refused: an enabled MainNet abuse/DoS config never validates.
* Invalid/zero/unbounded/inconsistent configs fail closed at CLI validation.
* **Run 362 does NOT launch a public DevNet**, deploy a seed / bootnode /
  faucet / RPC / explorer / status page, open a default-open public port,
  change any P2P wire format, weaken peer admission or trust-bundle behavior,
  wire authority lifecycle, mutate validator set / epoch, or make any
  TestNet/MainNet readiness claim.
* M4 remains Yellow/launch-blocking; M6 remains Yellow; C4 and C5 remain OPEN.

## Honest scope limitation

* The runtime-wired protection is the **connection-rate limiter** in the
  `TcpKemTlsP2pService` accept path (the primary Run 362 objective). The
  per-peer **message-rate** override flags (`--p2p-max-messages-per-second`,
  `--p2p-burst-allowance`) are parsed and validated into the runtime config,
  but the live per-peer `PeerRateLimiter` (in `async_peer_manager`) continues
  to use its hardcoded defaults; per-peer message-rate runtime override wiring
  is **not** delivered in Run 362. See the canonical evidence doc
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md` for the exact M12 disposition.

## Reproduce

```
scripts/devnet/run_362_public_devnet_abuse_dos_runtime_release_binary.sh <OUT_DIR>
```

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this archive.
All raw logs/artifacts are `.gitignore`d because they contain absolute paths and
ephemeral data.