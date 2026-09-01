# QBIND Public DevNet — Blocker Register (Run 402)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This is the operator-facing **blocker register** for the QBIND public DevNet
launch decision. It lists every item that still blocks launch, who owns it, the
action required, the evidence needed to clear it, and its current status. It is
the itemized companion to `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` and is
governed by the canonical readiness matrix
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

This document is **docs-only**: it deploys nothing, starts no node, opens no
port, adds no CLI flag, changes no runtime behavior, and moves **no** readiness
item Green.

## Launch rule

**No launch until every must-have (M1–M20) is Green and a public DevNet launch is
explicitly in scope.** While any blocker below is open, the decision is
**NO-GO** (see `LAUNCH_GO_NO_GO.md` §9).

## Blocker register

| ID | Blocker | Owner | Action required | Evidence needed | Status |
| -- | ------- | ----- | --------------- | --------------- | ------ |
| **M4** | No real external seed reachability yet — no live, externally reachable public DevNet seed/bootnode exists. | Seed operator | Deploy a durable DevNet seed on a routable public host under strict KEMTLS mutual-auth + PQC static-root with the Run 356 genesis pinned; verify from a genuinely independent off-host vantage; promote to a schema-valid `devnet-seeds.live.json`. See `network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`. | Timestamped external TCP dial **and** external KEMTLS mutual-auth + static-root handshake from an independent off-host vantage (not same-host / same-NAT / same-VPC / RFC 5737), matching the published `node_id`; a live seed-list entry with non-null `last_reachability_evidence`; live `register-check` accepts and fails closed without evidence. Per `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`. | **Yellow / launch-blocking** |
| **M6** | Live-registration half is **M4-gated**; operator-supplied durable-**root** reuse / rotation / revocation is **C4/C5-deferred**. Generation + verification and non-mutating `register-check` halves are Green-for-scope. | Validator/seed operator + protocol (C4/C5) | Once M4 is Green, register a continuous operator identity into the live network and prove durable `node_id`/`peer_id` reuse across restarts. Do **not** attempt durable-root reuse/rotation/revocation until C4/C5 work is scoped. See `identity/IDENTITY_CONTINUITY.md`, `identity/ROTATION_REVOCATION_DEFERRAL.md`. | Proof of an operator identity admitted into the **live** seed list with persistent published identity across DevNet restarts (requires M4 Green); C4/C5 closure for durable-root rotation/revocation. | **Yellow / Partial** |
| **S5** | Live status / aggregate health view deferred until M4 / a live network — a live status page today would misrepresent an unproven network. Publish-safe static decision + schema published. | Ops / status | After M4 is Green, deploy a live health view wired to the real network using the frozen schema. See `status/STATUS_PAGE_DECISION.md`. | A live, externally usable status page / health view reflecting a **real** reachable network (requires M4 Green). | **Yellow** |
| **S7** | Live seed operation deferred until M4 — runbook + M4 Route-A checklist + evidence template published, but operating a real live seed is M4-gated. | Seed operator | Execute the published runbook against real external infrastructure as part of the M4 Route-A run. See `network/SEED_NODE_OPERATIONS.md`. | A real live seed operated + verified externally (the same off-host reachability evidence that gates M4). | **Yellow** |

## C4 / C5 (tracked separately, not launch must-haves)

| ID | Item | Owner | Status | Note |
| -- | ---- | ----- | ------ | ---- |
| **C4** | Authority / trust-anchor closure. | Protocol | **OPEN** | MainNet authority rotation/revocation remains Red; not closed, advanced, or reinterpreted by this run. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. |
| **C5** | Governance / lifecycle closure. | Protocol | **OPEN** | Production key rotation/revocation documented as deferred, not delivered. |

## TestNet / MainNet

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
`identity generate` refuses `mainnet` / `testnet`. **No TestNet readiness and no
MainNet readiness is claimed.**

## Cross-references

- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — launch decision gate.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — canonical readiness matrix.
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — M4 Green checklist.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — reachability evidence format.
- `docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md` — seed-node operations runbook (S7).
- `docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md` — operator identity continuity (M6).
- `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md` — rotation/revocation deferral (M6).
- `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` — status-page decision (S5).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — contradiction ledger.
