# QBIND Public DevNet — P2P Exposure, Peer-Admission & Abuse/DoS Posture (Run 360)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**
>
> This is a **DevNet-only**, **docs / artifact / verification-only** package. It deploys **no**
> seed node, bootnode, faucet, RPC gateway, explorer, or status page; adds **no** CLI flag; and
> changes **no** P2P wire format, peer-admission logic, or peer rate-limiter behaviour. Public
> DevNet is **NOT launch-ready** (see §3). Nothing here is a public DevNet launch claim, a public
> TestNet readiness claim, or a MainNet readiness claim.

This directory publishes the canonical **public DevNet P2P exposure, peer-admission, and
abuse/DoS posture** package, produced under Run 360. It documents — against the **existing**
`qbind-node` CLI, transport, and peer-rate-limiter surfaces — how the public P2P port would be
exposed, how peers are admitted, and what abuse/DoS protections exist, so that a later live
seed/bootnode run (M4) has a published posture to deploy against. It invents **no** CLI flag,
deploys **no** infrastructure, and makes **no** claim that the network is joinable yet.

## 1. What this package is

- A published, source-grounded description of the **public P2P port posture** (listen/advertise,
  `--enable-p2p` default, NAT/firewall expectations, static-peer behaviour) — `P2P_PORT_POSTURE.md`.
- A published **peer-admission policy** for an open DevNet port, expressed only in terms of the
  existing KEMTLS mutual-auth + PQC trust-bundle / trust-root surfaces — `PEER_ADMISSION_POLICY.md`.
- A published **abuse/DoS posture** describing the existing peer rate-limiter, connection/metric
  surfaces, and a recommended minimum public DevNet posture — `ABUSE_DOS_POSTURE.md`.
- Exact **verification commands** to reproduce every documentation-safety and CLI-surface check in
  this package — `VERIFY.md`.

## 2. What this package is NOT

- It does **not** launch a public DevNet, deploy seeds/bootnodes, or claim the network is joinable.
- It does **not** add, rename, or hide any CLI flag; every flag it references is pre-existing in
  `crates/qbind-node/src/cli.rs` and validated to appear in `qbind-node --help` (or is explicitly
  marked future/unsupported).
- It does **not** change P2P wire format, peer-admission logic, peer rate-limiter implementation, or
  default network behaviour.
- It does **not** publish live seed addresses, private keys, mnemonics, seed phrases, credentials,
  tokens, API keys, private infrastructure, or real production hostnames. The only sample host is a
  non-routable RFC 5737 documentation address.
- It does **not** enable MainNet, claim TestNet readiness, close C4 or C5, mark M4 or M6 Green, or
  wire any authority-lifecycle boundary into runtime.

## 3. Public DevNet is NOT launch-ready

Publishing P2P posture documentation does not make the network joinable. There are still **no**
externally reachable seeds (must-have **M4** remains **Yellow / launch-blocking**), and other
must-haves (M6–M15) remain unresolved. Because at least one must-have is not Green, public DevNet
is **not** launch-ready. See `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 4. No live seeds are deployed by this run

This run deploys **no** seed node and **no** bootnode. The only seed artifact that exists is the
Run 357 **placeholder** seed list (`docs/release/public-devnet/network/devnet-seeds.placeholder.json`),
whose single entry uses `status: "placeholder"` with a non-routable RFC 5737 host and must **not**
be dialed.

## 5. DevNet-only / experimental / resettable / no value

This posture applies to **DevNet only**. DevNet is experimental, resettable, and carries **no**
economic value. Nothing in this package implies MainNet readiness, and nothing here closes C4 or C5.

## 6. Relationship to prior public DevNet runs

This package sits alongside the earlier public DevNet packages under the shared
`docs/release/public-devnet/` tree and references — but does **not** modify — their artifacts:

- **Run 356 genesis package** — `docs/release/public-devnet/genesis/` (canonical
  `devnet-genesis.json`, file SHA-256 `d1db07fe…5c86c`, canonical genesis hash
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`). The genesis hash is what
  every P2P join must pin via `--expect-genesis-hash`.
- **Run 357 seed-list format + placeholder** — `docs/release/public-devnet/network/`
  (`devnet-seed-list.schema.json`, `devnet-seeds.placeholder.json`). The seed-list fields map onto
  the pre-existing P2P flags documented here (`P2P_PORT_POSTURE.md` §6).
- **Run 358 operator onboarding** — `docs/release/public-devnet/operator/`
  (`README.md`, `QUICKSTART.md`, `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`). This package extends the
  operator onboarding with the public-exposure / admission / abuse posture.
- **Run 359 binary provenance** — `docs/release/public-devnet/binary/`
  (`RELEASE_PROVENANCE.md`, `REPRODUCIBILITY.md`, `BUILDINFO.md`, `qbind-node.sha256`, `VERIFY.md`):
  how to verify the `qbind-node` release-binary SHA-256 (`f916af6d…b22990`), inspect build inputs,
  and read the same-host reproducibility / BuildID result before exposing a node.

## 7. Which must-haves this run targets

This package targets the public DevNet readiness must-haves **M10** (public P2P port posture),
**M11** (peer admission policy), and **M12** (abuse / DoS protections), tracked in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`. It does **not** alter M4 (seed/bootnodes —
remains Yellow / launch-blocking) or M6 (validator identity — remains Yellow/Partial).

## 8. What remains before M4 can move Green

M4 moves Green only when a future run:

1. Deploys **real, externally reachable** DevNet seed/bootnode nodes.
2. Captures **external reachability evidence** (successful inbound KEMTLS handshake + genesis-pinned
   admission from an independent host).
3. Replaces the Run 357 placeholder with a **committed live seed list** whose entries carry
   `status: "live"` and `last_reachability_evidence`, all genesis-pinned to the Run 356 hash.

Until then, M4 remains **Yellow / launch-blocking** and public DevNet is **not** launch-ready.

## 9. Reading order

1. `P2P_PORT_POSTURE.md` — public port / listen / advertise / NAT / `--enable-p2p` posture.
2. `PEER_ADMISSION_POLICY.md` — KEMTLS mutual-auth + trust-bundle admission policy and failure modes.
3. `ABUSE_DOS_POSTURE.md` — peer rate-limiter, metrics, and recommended minimum posture.
4. `VERIFY.md` — reproduce every documentation-safety and CLI-surface check.

## Provenance

Full provenance (git commit, branch, clean/dirty state, artifact paths + P2P doc file hashes,
Run 356 genesis hash + file SHA-256, Run 357 schema + placeholder hashes, Run 358 operator package
reference, Run 359 `qbind-node` SHA-256 + BuildID reference, commands, test results, security scan,
readiness deltas) is recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_360.md`.
