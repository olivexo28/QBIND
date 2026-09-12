# QBIND Public DevNet — Blocker Register (Run 402)

> **Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
> NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
> no S7 Green · **RS1 OPEN / launch-blocking** · no TestNet readiness · no MainNet readiness ·
> **C4/C5 OPEN** · no C4/C5 closure claim.

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

**No launch until every must-have (M1–M20) is Green, the foundational
runtime-security blocker RS1 is closed with executable evidence that the deployed
consensus path is fail-closed, and a public DevNet launch is explicitly in scope.**
Public DevNet **GO requires both** (1) every required M1–M20 item Green **and**
(2) RS1 closed. While any blocker below is open — **including RS1, even if every
M1–M20 item were Green** — the decision is **NO-GO** (see
`LAUNCH_GO_NO_GO.md` §9).

## Blocker register

| ID | Blocker | Owner | Action required | Evidence needed | Status |
| -- | ------- | ----- | --------------- | --------------- | ------ |
| **RS1** | **Foundational runtime authentication and authorization is fail-open on the deployed consensus path** (Run 417 audit, `AUDIT-COMPLETE / NEGATIVE-FOR-RUNTIME-SECURITY`). The deployed `qbind-node` consensus loop (`crates/qbind-node/src/binary_consensus_loop.rs`) emits **unsigned** proposals/votes with the toy suite id `0`, accepts inbound proposals/votes **without** signature, membership, or suite verification, derives the consensus sender from a **self-declared** `proposer_index`/`validator_index` rather than the authenticated KEMTLS peer, and imports quorum certificates with **empty signer evidence**. Tracks Run 417 findings **F1–F8**. | Protocol / consensus | Make the deployed `binary_consensus_loop` path fail-closed: bind the authenticated KEMTLS peer to an authorized consensus sender (**F6**); sign + verify proposals/votes over domain-separated preimages with a production suite and reject suite `0`/unknown/disabled suites (**F3/F4/F8**); cryptographically verify imported QCs and make timeout/new-view verification mandatory (**F7/F5**); resolve transaction-authentication gaps (**F1/F2**) before transaction ingress is enabled. Do not suppress, weaken, or reclassify F1–F8 without new evidence. | Executable evidence captured on the deployed path (not a test harness) showing that unsigned, mismatched-identity, wrong/unknown-suite, and forged-QC inputs are **rejected with counters**, per `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md`. F1/F2 must be resolved **before** transaction ingress is enabled; their current lack of ingress is a **reachability mitigation, not cryptographic closure**. | **OPEN / launch-blocking** |
| **M4** | External reachability is PROVEN (Run 416, Route A) but no durable, published live seed yet — no durably operated, externally reachable public DevNet seed/bootnode with a published `devnet-seeds.live.json` exists (the Run 416 seed used temporary, discarded PQC material). | Seed operator | Deploy a durable DevNet seed on a routable public host under strict KEMTLS mutual-auth + PQC static-root with the Run 356 genesis pinned; verify from a genuinely independent off-host vantage; promote to a schema-valid `devnet-seeds.live.json`. See `network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`. | Timestamped external TCP dial **and** external KEMTLS mutual-auth + static-root handshake from an independent off-host vantage (not same-host / same-NAT / same-VPC / RFC 5737), matching the published `node_id` (demonstrated once in Run 416 against a temporary seed); a **durable** live seed-list entry with non-null `last_reachability_evidence`; live `register-check` accepts and fails closed without evidence. Per `network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`. | **Yellow / launch-blocking** |
| **M6** | Live-registration half is **M4-gated**; operator-supplied durable-**root** reuse / rotation / revocation is **C4/C5-deferred**. Generation + verification and non-mutating `register-check` halves are Green-for-scope. | Validator/seed operator + protocol (C4/C5) | Once M4 is Green, register a continuous operator identity into the live network and prove durable `node_id`/`peer_id` reuse across restarts. Do **not** attempt durable-root reuse/rotation/revocation until C4/C5 work is scoped. See `identity/IDENTITY_CONTINUITY.md`, `identity/ROTATION_REVOCATION_DEFERRAL.md`. | Proof of an operator identity admitted into the **live** seed list with persistent published identity across DevNet restarts (requires M4 Green); C4/C5 closure for durable-root rotation/revocation. | **Yellow / Partial** |
| **S5** | Live status / aggregate health view deferred until M4 / a live network — a live status page today would misrepresent a network that is not durably operating. Publish-safe static decision + schema published. | Ops / status | After M4 is Green, deploy a live health view wired to the real network using the frozen schema. See `status/STATUS_PAGE_DECISION.md`. | A live, externally usable status page / health view reflecting a **real** durably operating network (requires M4 Green). | **Yellow** |
| **S7** | Live seed operation deferred until M4 — runbook + M4 Route-A checklist + evidence template published, but operating a real live seed is M4-gated. | Seed operator | Execute the published runbook against real external infrastructure as part of the M4 Route-A run. See `network/SEED_NODE_OPERATIONS.md`. | A real live seed operated + verified externally (the same off-host reachability evidence that gates M4). | **Yellow** |

## C4 / C5 (tracked separately, not launch must-haves)

| ID | Item | Owner | Status | Note |
| -- | ---- | ----- | ------ | ---- |
| **C4** | Authority / trust-anchor closure. | Protocol | **OPEN** | MainNet authority rotation/revocation remains Red; not closed, advanced, or reinterpreted by this run. See `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. |
| **C5** | Governance / lifecycle closure. | Protocol | **OPEN** | Production key rotation/revocation documented as deferred, not delivered. |

**RS1 vs C4/C5.** RS1 is an **independent, launch-blocking** must-have-class gate
on the **deployed runtime** consensus authentication path; it is listed in the
blocker register above (not in this separately-tracked C4/C5 table). Closing F6
alone does not close F3, F4, F5, F7, F8, RS1, C4, or C5. RS1 remaining OPEN forces
**NO-GO** even if every M1–M20 item is Green. See
`docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`.

**F6 remediation status.** F6 (one of RS1's eight findings) is remediated in code
and test (Run 418) and has **partial** standalone-release-binary evidence (Run
419: core Required/static-root loopback KEMTLS path proven via live
`qbind_consensus_binding_total` deltas; unauthenticated-ingress and
outbound-identity vectors partial). This narrows one finding only; **RS1 stays
OPEN / launch-blocking** because F1–F5 and F7–F8 remain unresolved. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_419.md`.

**F3/F4/F8 remediation status.** F3/F4/F8 (three of RS1's eight findings — the
fail-open Proposal/Vote verification-context bypass) are remediated in code and
test (Run 420: typed `ConsensusVerificationPolicy` with `Required` production
default, fail-closed inbound rejection and outbound suppression under unavailable
authority) and have **unavailable-authority** standalone-release-binary evidence
(Run 421: live loopback KEMTLS + `/metrics` proof that the deployed binary rejects
inbound Proposal/Vote fail-closed when `verification_ctx == None`, F6 mismatch
precedes the Run 420 gate, and malformed signatures / wrong suites cannot bypass
the boundary; outbound suppression S7/S8 UNREACHABLE on the standalone binary;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED`). This narrows the
**configured/unavailable-authority path** of three findings only; the standalone
binary still has **no** authoritative consensus signer, so configured-authority
release-binary evidence is absent and **RS1 stays OPEN / launch-blocking** because
F1/F2/F5/F7 remain unresolved and F6 remains partial. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_421.md`. Run 422 additionally activates
**genesis-bound** consensus authority in code and test (opt-in fail-closed flag
`--consensus-authority-from-genesis` + module
`crates/qbind-node/src/genesis_consensus_authority.rs`, deriving the validator
set + per-validator authorized ML-DSA-44 `(suite, public_key)` provider directly
from the boot-verified canonical genesis and feeding the same validated
constructor `main` uses), closing the Runs 031–033 uncommitted-CLI-override gap.
This is **source/test activation only**
(`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`; adversarial
release-binary evidence is Run 423) and **RS1 stays OPEN / launch-blocking**. See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422.md`.

## TestNet / MainNet

TestNet and MainNet remain **untouched**; readiness items N1–N7 remain **Red**.
`identity generate` refuses `mainnet` / `testnet`. **No TestNet readiness and no
MainNet readiness is claimed.**

## Cross-references

- `docs/release/public-devnet/ARTIFACT_INDEX.md` — release-package navigation index.
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` — read orders + verification map + stop rule.
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` — launch decision gate.
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — canonical readiness matrix.
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` — M4 Green checklist.
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — reachability evidence format.
- `docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md` — seed-node operations runbook (S7).
- `docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md` — operator identity continuity (M6).
- `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md` — rotation/revocation deferral (M6).
- `docs/release/public-devnet/status/STATUS_PAGE_DECISION.md` — status-page decision (S5).
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria.
- `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` — RS1 foundational runtime-security reconciliation.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_417.md` — Run 417 audit evidence (RS1 findings F1–F8).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_419.md` — Run 419 partial release-binary evidence for finding F6.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_420.md` — Run 420 code/test fail-closed Proposal/Vote verification boundary (findings F3/F4/F8).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_421.md` — Run 421 unavailable-authority fail-closed release-binary evidence for findings F3/F4/F8.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422.md` — Run 422 genesis-bound consensus authority activation (code/test) for findings F3/F4/F8.
- `docs/whitepaper/contradiction.md` — contradiction ledger.