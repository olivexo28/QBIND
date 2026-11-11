# Consolidated Long-Term Authorization Charter

**Status: DOCUMENTATION-ONLY SYNTHESIS.** This charter indexes owner decisions and review qualifications; it makes no new decision, selects no mechanism, and does not claim that a target is implemented, feasible, or proven.

## Record and reviewed inputs

The authoritative carry-forward record used is the attached `QBIND_Audit_Carry_Forward_Operation_Identity_Review.md`, SHA-256 `8f166fbcbfc476b8a687d1b12a8d18dc4bbddfa6a5280f81ff7fc478aa1e49f5`. Owner decisions below refer to its entries 35, 38, 40, 44, 50, 54, 57, 58, 59, and 60; independent-review qualifications refer to entries 55, 56, and 61. The record was read as an input only and is not modified by this charter.

The source pin is `main` commit `ae6464120b15dabe6e994ee983b3d80046d89722` (tree `cd394644a3998d2e23c2e2d95b1767657b34f17d`). The following reviewed candidate documents are branch artifacts, not merged into main:

| Branch | Exact reviewed commit | Candidate document |
|---|---|---|
| `docs/route-b-independent-first-use-trust-contract` | `23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918` | `docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md` |
| `docs/long-term-independent-auth-succession-spec` | `f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a` | `docs/security/evidence/long-term-independent-authorization-recovery-succession-candidate-20261110.md` |
| `docs/shared-control-non-override-succession` | `974c74e43cf957282cd612caa75c4c7f29d9f0b7` | `docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md` |
| `docs/continuity-without-lowering-auth-bar` | `5b7418a5436930584f1609b8c7a563e040ef5704` | `docs/security/evidence/continuity-without-lowering-authorization-bar-candidate-20261110.md` |
| `docs/option-a-policy-semantics` | `4152038774523e8679fcc255f451ed61e71ea068` | `docs/security/evidence/option-a-policy-semantics-five-protected-actions-candidate-20261110.md` |
| `docs/step-0-initial-provisioning-trust-contract` | `2cf36c293a0e734cc6307da29d7dd2ef6d2cb169` | `docs/security/evidence/step-0-initial-provisioning-trust-contract-20261110.md` |
| `docs/currentness-anti-rollback-evidence-contract` | `1489390492a9857a34a1e0fceaed93ea8c432fab` | `docs/security/evidence/currentness-anti-rollback-evidence-contract-20261110.md` |

**HISTORICAL CANDIDATE:** Each candidate commit is a direct child of the pinned main. These documents predate some decisions in entries 57–60: their five-action scope and statements that collusion tolerance is open are historically accurate at their own pins, not updates to the later seven-action and up-to-two-collusion targets. This charter does not amend those documents. In particular, Step-0's "owner-authorized" wording does not imply that one actor may establish protected initial trust; action 6 requires binding independent authorization and a separately authenticated, non-circular provisioning basis.

## OWNER DECISION — seven protected actions and authorization direction

Entries 35 and 58 set binding independently operated authorization as the long-term direction for these seven actions:

1. Establishing or replacing accepted-genesis provenance.
2. Delegating or replacing mapping-policy issuer authority.
3. Approving or replacing an authorized mapping policy.
4. Establishing first-use enrollment or current authorization.
5. Resolving disputed currentness or permitting recovery after lost, conflicting, or uncertain state.
6. Accepting, replacing, or authoritatively revoking the initial provisioning trust relationship used to establish accepted-genesis provenance and mapping-purpose delegation.
7. Accepting, replacing, or authoritatively revoking, or permitting recovery of, an out-of-domain currentness reference, including its relevant authentication authority.

Advisory review is not binding authorization. A single participant or a single compromised shared control must not suffice for one actor alone to authorize a protected action. Entry 60 adds the target that collusion by up to two independently operated authorization participants is not, by itself, sufficient to authorize any of the seven. These are design targets to specify, assess, and prove, not established properties; the shared-control rule is not discharged merely by separate keys.

Entries 44 and 59 select conditional Option-A continuation as a design target for all seven actions: a qualifying combination of remaining participants may act only if the unchanged, already-authorized policy permits it and trustworthy current evidence remains available. Preauthorizing an eligible process does not preapprove a future policy change, recovery outcome, or disputed decision. Succession must be separately authorized and must not automatically transfer authority or override authorization, consensus safety, signing-history, or recovery safeguards. If sufficient authorization or trustworthy evidence cannot be established, the action remains unavailable, potentially indefinitely. No quantitative availability target is set.

Initial trust must not authenticate itself. Action 6 does not create its own provisioning basis. Action 7 replacement or recovery cannot rely solely on an unsupported assertion by the failed, compromised, or disputed reference. The long-term currentness feasibility direction (entry 50) combines independently authenticated currentness evidence outside the relevant local rollback/substitution domain with binding independent authorization in one Decision B / CurrentAuthorizationOwner lifecycle—not a second authoritative freshness lifecycle. The starting threat model (entry 54) includes whole-copy rollback of local durable state and network delay, loss, replay, and substitution; a signed or remote response alone does not establish independence or currentness.

The revocation-ordering direction (entry 57) is: if authoritative supersession `S` precedes an action's irrevocable security-relevant commit point `L`, the action must not commit under superseded authority; unknown ordering or currentness refuses. A check, response, ticket, or in-process confirm is not automatically `L`. Physical completion after `L` is permitted only under an action-specific contract independently reviewed to establish that it grants no new unauthorized effect. Existing signatures cannot be undone and require explicit validity, acceptance, and historical-use rules.

## SOURCE FACT — source limits and authority-sequence qualification

At main pin `ae6464120b15dabe6e994ee983b3d80046d89722`, `CurrentAuthorizationOwner` issues tickets bound to an owner identity and in-process generation; confirmation rejects a foreign owner, exhaustion, or a generation changed since admission. The source explicitly limits this to in-memory ordering, not durable anti-rollback (`crates/qbind-node/src/genesis_consensus_authority.rs:917-943,1179-1238`). Its only production-reachable constructor yields unavailable state; concrete establishment is test-only (`:1045-1058,1222-1238`). `AuthorizedProposalVoteSnapshot` checks local owner/verifier coherence, but its source says provenance is a separate guarantee and production constructs neither the verifier nor a current-authorization owner (`crates/qbind-node/src/binary_consensus_loop.rs:1133-1188`). Production genesis-authority activation is refused and `proposal_vote_authority` is `None` (`crates/qbind-node/src/main.rs:5428-5438,6164-6172`). Therefore these interfaces do not establish a production authorization lifecycle or resolve the D7 missing-owner gap.

The genesis `authority_sequence` field is encoded into the canonical genesis authority block (`crates/qbind-ledger/src/genesis.rs:760-764,1654-1662`). Separately, Run-117 persists a local `<data_dir>/pqc_authority_state.json` marker for ratified **bundle-signing authority** and rejects a lower sequence against that local marker (`crates/qbind-node/src/pqc_authority_state.rs:1-22,52-73,189-196,704-717`). These are distinct facts and domains. Under the owner's whole-copy-rollback model, the persisted local marker and its comparison baseline can be restored with the rest of local state; neither hash coverage nor local monotonic comparison is an independent currentness anchor. Bundle-signing authority is not authorized for Route B mapping-purpose delegation. The owner prohibition on relying on rollback-domain-local state for independent provenance or currentness remains unchanged.

## OPEN — evidence and implementation gates

| Gate | Status | Evidence not established |
|---|---|---|
| Action 6: initial provisioning, custody, and non-circular accepted-genesis provenance | OPEN | Independently authenticated provisioning basis, custody, and its assumptions; action 6 being protected does not supply them. |
| Action 7: out-of-domain currentness and authentication authority | OPEN | Purpose-bound, independently authenticated, current and non-equivocating evidence; safe replacement/recovery when the reference is lost or disputed. |
| Binding authorization; single-actor/shared-control rule; up-to-two collusion target | OPEN | Operational independence, common-control boundaries, and proof the targets hold. Collusion resistance does not establish conflict safety. |
| Conflicting views and `S`/`L` ordering | OPEN | Enforceable authoritative ordering, conflict handling, and refusal for concurrent or unknown outcomes. Entry 61 clarifies that a final recheck is not itself a required mechanism, and no proposed mechanism is selected. |
| One Decision B lifecycle and D7 missing-owner refusal | OPEN | Production evidence path feeding the one lifecycle and a proven refusal whenever required current-authorization ownership is missing while P/V authority is present. The D7 gap is not fixed. |
| Signer exclusivity and effect enforcement | OPEN | Evidence that a process/credential compromise cannot bypass the required decision at the protected effect. |
| Signing-history continuity | OPEN | Complete, rollback-safe signing history and recovery behavior. |
| Cross-process fencing | OPEN | Enforced single effective signer across concurrent processes/hosts and recovery. |
| Consensus safety, lock recovery, and finality | OPEN | Separate proof and recovery/finality handoff; authorization/currentness does not supply them. |
| Recovery authority | OPEN | Separately authorized, current and non-override recovery path, including lost or disputed evidence. |
| Native post-quantum continuity | OPEN | Native-PQ authentication and continuity evidence; any classical infrastructure or attestation dependency requires explicit isolation and separate review. |
| Execution-cursor non-entanglement | OPEN | Evidence that execution cursor, VM state position, and snapshot height do not supply signer position or freshness. |

Entry 61 qualifies earlier analysis: the up-to-two-collusion target does not itself prevent conflicting decisions; a proposed honest-intersection condition is one model-specific approach, not a requirement. A final recheck is likewise not mandated, and candidate ordering approaches are non-exhaustive. No consensus fallback is owner-approved; fail-closed unavailability remains the default while alternatives are assessed. At-most-one decision must be scoped to the same subject, position, and decision context while allowing a later, separately authorized supersession.

## Boundaries and status

This charter selects no participants, counts, thresholds, keys, roots, references, constructions, storage, or recovery mechanisms. It does not decide the initial-DevNet model, authorize a consensus fallback, or authorize implementation or activation. A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN; required-persistence remains NOT ACCEPTED / NOT INTEGRATION-READY; activation remains DISABLED; public DevNet remains NO-GO.

The six standing guardrails remain binding: (1) independently authenticate non-circular initial provenance; (2) do not repurpose bundle-signing, transport, bootstrap, or A33-F1 authority for mapping; (3) feed one Decision B lifecycle; (4) do not create a PR from inherited Route B or engine-handoff lineage—any later authorized change starts from verified current main and includes only approved paths; (5) cite main and unmerged sources at their exact commits; and (6) do not put identity, policy, issuer, or mapping metadata in `GenesisConfig.extra` under A50-F1. Any separately authorized Rust PR requires retained local `cargo test` and `cargo check --lib --bin qbind-node` evidence from a clean worktree based on applicable main; do not add intentionally red targets to default test discovery. None of that work is authorized here.
