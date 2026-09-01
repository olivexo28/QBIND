# QBIND Public DevNet — Launch Go / No-Go Gate (Run 402)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN** ·
> no C4/C5 closure claim.

This document is the single operator-facing **launch decision gate** for the QBIND
public DevNet. It exists so the current non-launch posture is **impossible to
misread**: it summarizes what is already Green, what still blocks launch, the
exact evidence required to clear each blocker, and why TestNet/MainNet and
C4/C5 are untouched. It is **docs-only**: publishing it deploys nothing, starts
no node, opens no port, adds no CLI flag, changes no runtime behavior, and moves
**no** readiness item Green.

Companion documents:

- `docs/release/public-devnet/BLOCKER_REGISTER.md` — the itemized blocker register
  (owner / action / evidence-needed / status).
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — the canonical
  readiness matrix and gap analysis (source of truth for item status).
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — the
  exact steps that must pass before **M4** can move Green.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` —
  the reachability evidence format a live seed must carry.
- `docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md` — the seed-node
  operations runbook (S7).
- `docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md` and
  `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md` — the
  operator identity continuity + rotation/revocation deferral guidance (M6).
- `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` — the status-page
  decision (S5).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — the C4/C5 closure criteria.
- `docs/whitepaper/contradiction.md` — the contradiction ledger.

## 1. Current decision

**NO-GO. Public DevNet is NOT launch-ready.**

At least one launch-blocking must-have (**M4**) is Yellow, and a second must-have
(**M6**) is Yellow / Partial. Per the go/no-go rule in §9, launch requires **every**
must-have Green **and** launch explicitly in scope. Neither condition holds today,
so the decision is **NO-GO**.

## 2. Green items summary

The following are Green or Green-for-scope as recorded in the readiness matrix
(canonical status after Run 401; see `QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`):

- **Must-haves Green:** **M1–M3, M5, M7–M20.** This covers genesis /
  network-parameter artifacts (M1/M19/M20), release-binary provenance +
  reproducibility (M2/M3), operator onboarding (M5/M17/M18), security /
  key-management / PQC trust-bootstrap (M7/M8/M9), P2P port posture + peer
  admission (M10/M11), abuse/DoS controls (M12, Green-for-scope), and
  observability / ops / reset-policy / incident-response (M13–M16).
- **Should-haves Green:** **S1–S4, S6.**

These items are **documented and verified for DevNet scope**. Green here does not
imply a live, externally reachable public network — that is exactly what the
blocking items below still gate.

## 3. Blocking items summary

- **M4 — seed/bootnode reachability — Yellow / launch-blocking.** No real,
  externally reachable public DevNet seed with independent off-host reachability
  evidence exists. This is the primary launch blocker.
- **M6 — validator identity — Yellow / Partial.** The generation + verification
  and non-mutating registration-check halves are Green-for-scope, but the
  **live-registration** half is M4-gated, and operator-supplied durable-root
  reuse / rotation / revocation is C4/C5-deferred.
- **S5 — status page — Yellow.** A publish-safe static decision + schema is
  published; a **live** status / health view is deferred until M4 / a live network.
- **S7 — seed-node runbook — Yellow.** The runbook + M4 Route-A checklist +
  evidence template are published; **operating a live seed** is M4-gated.

## 4. Exact M4 Green prerequisites

M4 moves Yellow → Green **only when every** item below passes **together in one
run**, with publish-safe evidence, per
`docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`:

1. A durable DevNet **seed identity** generated via `qbind-node identity generate
   devnet seed <out>` (leaf KEM secret `0600` and private; root signing material
   offline; only public `node_id` / `peer_id` / leaf cert published), passing a
   non-mutating `register-check --role seed`.
2. A **real routable public endpoint**: seed bound `--p2p-listen-addr 0.0.0.0:<port>`
   with `--p2p-advertised-addr <public-host>:<port>` on a routable host (not RFC
   1918 / RFC 5737 / loopback); only the P2P port exposed inbound.
3. **Strict KEMTLS / static-root** posture: `--p2p-mutual-auth required`,
   `--p2p-pqc-root-mode pqc-static-root`, `--p2p-trusted-root <published-root>`,
   `--p2p-leaf-cert` + `--p2p-leaf-cert-key`, and genesis pinned via
   `--expect-genesis-hash <run356-hash>`; node starts, binds, and logs its `NodeId`.
4. A **genuinely independent off-host vantage point** (outside the seed host and
   its NAT; not same-host / same-NAT / same-VPC / private-VPN; not RFC 5737).
5. **External TCP evidence**: a timestamped (UTC) successful external TCP dial to
   `<public-host>:<port>` from the independent vantage, with an independence
   statement.
6. **External KEMTLS evidence**: a timestamped external KEMTLS mutual-auth + PQC
   static-root handshake from the independent vantage; the observed remote `NodeId`
   matches the published seed entry.
7. **Seed-list promotion**: a **new** `devnet-seeds.live.json` with a `status:
   "live"` entry, a **non-null** `last_reachability_evidence` referencing the
   completed record, real `p2p_host` / `p2p_multiaddr` / `operator`, schema-valid
   against `devnet-seed-list.schema.json`, and genesis fields matching the Run 356
   package.
8. **Live register-check acceptance**: `register-check ... --status live
   --reachability-evidence <record>` **accepts**, and the same command **without**
   `--reachability-evidence` **fails closed**.
9. No private key / KEM secret / signing secret / token / raw log / raw metrics /
   data dir / private endpoint / absolute build path committed; no other readiness
   item silently flipped Green.

Until real off-host external reachability evidence lands, **M4 stays Yellow**.

## 5. Exact M6 Green prerequisites

M6 moves Yellow / Partial → Green **only when both** of the following hold:

1. **Live registration path exercised.** A continuous operator identity is
   registered into a **live, externally reachable** public DevNet — which requires
   **M4 Green first** (M6's live half is M4-gated). This is proven, not asserted:
   an operator identity is admitted into the live seed list and its published
   `node_id` / `peer_id` persist across DevNet restarts (durable reuse per
   `IDENTITY_CONTINUITY.md`).
2. **Durable-root reuse / rotation / revocation resolved under C4/C5.** Today
   `identity generate` mints a fresh in-memory-only root signing key per run;
   operator-supplied durable-**root** reuse, rotation, and revocation are **NOT
   implemented** and are **explicitly deferred** to C4/C5/MainNet (see
   `ROTATION_REVOCATION_DEFERRAL.md`). This half cannot move Green while C4/C5 are
   OPEN, and this run does **not** attempt it.

The generation + verification and non-mutating `register-check` halves are already
Green-for-scope; the remaining gap is the M4-gated live half plus the C4/C5-gated
durable-root lifecycle.

## 6. Why S5 / S7 remain M4-gated

- **S5 (status page).** A live status / aggregate health view that claimed to
  reflect network health today would be **misleading**, because no externally
  reachable seed / network is proven (M4 Yellow). Run 395 published a publish-safe
  **static** decision + schema and **explicitly deferred** the live view until M4
  is Green (`STATUS_PAGE_DECISION.md`). S5 stays Yellow.
- **S7 (seed-node runbook).** The seed-node operations runbook, the M4 Route-A
  deployment checklist, and the reachability evidence template are published and
  verified, but **operating a real live seed** — the thing that would make S7 Green
  — depends on the same real external reachability that gates M4. S7 stays Yellow.

Both are downstream of M4: they cannot honestly move Green before a live,
externally reachable network exists.

## 7. C4 / C5 statement

**C4 remains OPEN. C5 remains OPEN.** MainNet authority rotation / revocation
remains **Red**. Nothing in this run — or in the M6 continuity documentation it
references — closes, advances, or reinterprets C4 or C5. Production key rotation
and revocation are documented as **deferred**, not delivered
(`ROTATION_REVOCATION_DEFERRAL.md`, `QBIND_C4_C5_CLOSURE_CRITERIA.md`). No C4/C5
closure is claimed.

## 8. TestNet / MainNet non-claim statement

TestNet and MainNet remain **untouched**. TestNet/MainNet readiness items
(N1–N7) remain **Red**. `identity generate` refuses `mainnet` / `testnet`, and no
TestNet or MainNet identity, custody, genesis, or deployment artifact is created
or implied. **No TestNet readiness and no MainNet readiness is claimed** anywhere
in this gate.

## 9. Final go / no-go rule

> **GO only if** every must-have (**M1–M20**) is **Green** **and** a public DevNet
> launch is **explicitly in scope** for the run making the decision.
>
> **Otherwise: NO-GO.**

Because **M4** is Yellow and **M6** is Yellow / Partial, and because launch is
**not** in scope for Run 402 (docs + verification harness only), the current
decision is **NO-GO — public DevNet is NOT launch-ready.** This run adds clarity
only; it moves no item Green and it does not launch anything.