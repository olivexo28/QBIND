# QBIND Public DevNet — P2P Port Posture (Run 360)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

This document defines the **public P2P port posture** for QBIND public DevNet, described only against
the **pre-existing** `qbind-node` CLI and transport surfaces
(`crates/qbind-node/src/cli.rs`, `crates/qbind-node/src/p2p_tcp.rs`). Run 360 adds **no** CLI flag and
changes **no** default network behaviour. All flags below are pre-existing and validated to appear in
`qbind-node --help` (see `VERIFY.md`).

## 1. P2P is disabled by default

Public DevNet P2P networking is **disabled by default**. The transport service only starts when P2P
is explicitly enabled:

- `--enable-p2p` defaults to `false` (`cli.rs`: `default_value = "false"`, "DevNet freeze
  preserved"). When `false`, no P2P listener is bound and no peers are dialed.
- `--network-mode` defaults to `local-mesh`. P2P transport starts only when `--enable-p2p` is `true`
  **and** the node is configured for the P2P transport path.

A default DevNet node therefore exposes **no** public P2P port. Enabling public exposure is an
explicit, opt-in operator action.

## 2. Existing listen / advertise / peer flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--enable-p2p` | `false` | Enable the P2P transport service. Off by default (DevNet freeze). |
| `--p2p-listen-addr` | `127.0.0.1:0` | Local address the P2P listener binds to. `:0` = OS-assigned port; `127.0.0.1` = loopback-only (not publicly reachable). |
| `--p2p-advertised-addr` | *(unset → uses listen addr)* | Address advertised to peers. Set this when the reachable address differs from the bind address (NAT / load balancer). |
| `--p2p-peer` | *(empty; repeatable)* | Static peer `host:port` to dial at startup. Repeatable. This is the primary peer-supply surface. |
| `--expect-genesis-hash` | *(unset)* | Pin the expected canonical genesis hash; mismatch refuses startup. Must be set for public DevNet (see §5). |

Notes grounded in source:

- The default `--p2p-listen-addr` of `127.0.0.1:0` binds **loopback only** on an ephemeral port; it
  is **not** publicly reachable. A public listener requires an explicit routable bind address.
- `--p2p-advertised-addr` exists specifically for NAT / load-balancer situations where the address
  peers should dial differs from the local bind address; if unset, the listen address is advertised.
- Peers are supplied **statically** via repeatable `--p2p-peer`. There is **no** operator CLI flag in
  `qbind-node --help` that turns on any public peer-discovery service; static `--p2p-peer` dialing is
  the supported operator surface. (An internal `P2pDiscoveryConfig` type exists in
  `crates/qbind-node/src/node_config.rs`, but it is **not** an operator-facing CLI surface in this
  release and is **not** relied on here. No discovery capability is claimed for public DevNet.)

## 3. Safe local dry-run posture

For evaluation without any public exposure (the recommended default, and what the Run 358 quickstart
uses), run with P2P disabled:

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f \
  --data-dir ./devnet-data
```

DevNet defaults to `--enable-p2p false` (LocalMesh), so this is a **local** boot that binds **no**
public port. This exercises the real startup and genesis-verification path without exposing anything.

## 4. Future live seed-node posture

The following is the **intended** posture for a later M4 live-seed run. It is **not** deployed by
Run 360 and makes **no** claim that any live seed exists.

- **Bind / listen address:** a routable bind address and fixed port via `--p2p-listen-addr`
  (e.g. `0.0.0.0:<port>` to accept inbound on all interfaces). The default `127.0.0.1:0` is
  loopback-only and must be overridden for public exposure.
- **Advertised address:** the externally reachable `host:port` via `--p2p-advertised-addr` when the
  node is behind NAT or a load balancer, so peers dial the reachable address rather than the private
  bind address.
- **Public port:** a single, stable, documented TCP port per seed, matching the `p2p_port` field of
  the seed's future live seed-list entry. The Run 357 placeholder uses port `19000` as the
  documentation-example port shape.
- **NAT / firewall expectations:** the advertised `host:port` must be reachable from the public
  internet; inbound TCP to the chosen port must be permitted by the host firewall and any NAT/LB in
  front of it. Reachability must be **evidenced** (see §8) before M4 can move Green.
- **Static peer list behaviour:** peers are supplied via repeatable `--p2p-peer`; each seed dials the
  configured static peers at startup and accepts inbound peers on its listener. There is **no**
  automatic discovery — the operator supplies the peer set explicitly.
- **No discovery claim:** QBIND public DevNet does **not** claim an operator-usable peer-discovery /
  gossip-based bootstrapping mechanism. Do not assume peers are learned automatically.

## 5. Genesis-hash pinning is mandatory

Every public DevNet node must pin the canonical genesis hash so it refuses to start against the wrong
chain:

```bash
./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f
```

- `--print-genesis-hash` prints the canonical Run 101 genesis hash (computed over the parsed
  `GenesisConfig`, independent of JSON whitespace) so an operator can confirm the value before
  pinning it.
- `--expect-genesis-hash` refuses startup on mismatch **before** any network/consensus start.
- The pinned value must equal the Run 356 canonical hash
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`, which is also the
  `genesis_hash` / `expected_genesis_hash` in the Run 357 seed list.

## 6. Mapping Run 357 seed-list fields to existing CLI flags

When a future **live** seed list exists, its fields map onto the **pre-existing** flags as follows
(identical mapping to the Run 358 quickstart; **only** dial entries with `status: "live"`):

| Seed-list field (Run 357) | Pre-existing CLI flag |
|---------------------------|-----------------------|
| `p2p_multiaddr` / `p2p_host:p2p_port` of a `status: "live"` entry | `--p2p-peer` (repeatable) |
| *(enable networking)* | `--enable-p2p` (default `false`) |
| local bind address | `--p2p-listen-addr` (default `127.0.0.1:0`) |
| advertised address (NAT / LB) | `--p2p-advertised-addr` |
| `transport_security_mode` | `--p2p-mutual-auth` (`required`\|`optional`\|`disabled`) |
| `trust_bundle_required` | `--p2p-trust-bundle` (+ `--p2p-trust-bundle-signing-key`) |
| `pqc_suite` / root material | `--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert` |
| `expected_genesis_hash` | `--expect-genesis-hash` |

## 7. What an operator must NOT do

- **Do not dial placeholder entries.** The Run 357 placeholder host `192.0.2.1` is a non-routable
  RFC 5737 documentation address and is not reachable. Only dial entries with `status: "live"`.
- **Do not expose MainNet / TestNet by accident.** Every command here uses `--env devnet` only. Do
  not point a public P2P listener at a MainNet or TestNet configuration.
- **Do not run with an unpinned genesis hash on public DevNet.** Always pass `--expect-genesis-hash`
  with the Run 356 canonical hash so the node refuses to start against the wrong chain.
- **Do not publish private infrastructure or secrets.** Do not put private keys, KEM secret keys
  (`--p2p-leaf-cert-key` material), internal hostnames, or credentials into published seed lists,
  docs, or logs.

## 8. Evidence required in the later M4 live-seed run

Before M4 can move Green, a future run must record, at minimum:

1. The deployed seed's public advertised `host:port` and pinned genesis hash.
2. A successful **inbound** KEMTLS handshake and genesis-pinned admission from an **independent**
   external host (external reachability evidence).
3. A committed **live** seed list replacing the placeholder, with `status: "live"` entries carrying
   `last_reachability_evidence` and matching `genesis_hash` / `genesis_file_sha256`.
4. Confirmation that the abuse/DoS posture (`ABUSE_DOS_POSTURE.md`) held under real inbound traffic.

Run 360 prepares this posture; it does **not** provide any of the above evidence, so M4 stays Yellow.
