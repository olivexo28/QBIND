# QBIND Public DevNet — Operator Safety Disclaimer (Run 358)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

This document publishes the user-facing safety disclaimer for external operators in
operator-facing material (not only in the internal readiness matrix). Read it before building or
running anything in `QUICKSTART.md`.

## Safety label

QBIND Public DevNet is:

- **experimental** — the network, its parameters, and this documentation are subject to change
  without notice;
- **resettable** — the network and any local state may be wiped at any time without advance notice;
- **no value** — all balances, stakes, allocations, and tokens are fixtures with **no** economic
  value and must never be treated as valuable;
- **no MainNet readiness claim** — nothing here implies or claims MainNet readiness;
- **no C4/C5 closure claim** — this material does **not** close C4 or C5.

## Additional disclaimers

- **No guarantees of availability, state durability, or continuity.** There is no uptime guarantee,
  no durability guarantee, and no continuity guarantee for DevNet.
- **No expectation that DevNet balances or state survive resets.** Any DevNet balance or state may be
  destroyed by a reset; do not rely on persistence. The full DevNet reset policy (triggers, notice,
  operator actions, evidence-record shape) and incident-response process are published in
  `docs/release/public-devnet/ops/` (`RESET_POLICY.md`, `INCIDENT_RESPONSE.md`; M15/M16, Run 390).
- **Public DevNet is NOT launch-ready.** There are no externally reachable seeds (M4 is Yellow /
  launch-blocking) and no documented release-binary reproducibility / BuildID (M3 is Red). This
  package does **not** launch a public DevNet and deploys no seed node, bootnode, faucet, RPC
  gateway, explorer, or status page.
- **TestNet and MainNet are separate future stages.** DevNet → TestNet Alpha → TestNet Beta →
  MainNet v0. Nothing here claims TestNet readiness or MainNet readiness, and nothing here modifies
  TestNet or MainNet.
- **No secret material.** This package publishes no private keys, mnemonics, seed phrases,
  credentials, API keys, tokens, private infrastructure, real production hostnames, or unapproved
  live endpoints. Any sample host value (e.g. RFC 5737 `192.0.2.1`) is a documentation-safe,
  explicitly non-secret, non-routable example only.

## Scope boundaries

- Full **C4 remains OPEN**; **C5 remains OPEN**.
- MainNet authority rotation/revocation remains **Red**.
- The Run 353/354 boundary remains **Green-for-scope only** and is not wired into runtime.
- Public DevNet readiness is a **separate** release-readiness track; see
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.