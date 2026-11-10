# Currentness and Anti-Rollback Evidence Contract

## Status, scope, and labels

**SPECIFICATION-ONLY CANDIDATE.** This document specifies a feasibility
direction for currentness evidence that is independently authenticated and held
outside the node's local rollback/substitution domain, combined with binding
independently operated authorization for protected actions. It selects no
witness, service, participant, key, root, threshold, storage mechanism, or
cryptographic construction. It claims no currentness capability is approved,
implemented, or demonstrated.

- **SOURCE FACT** — established by the cited pinned repository source.
- **OWNER DECISION** — an explicit direction or guardrail, not proof of a
  capability.
- **CANDIDATE** — a proposed requirement or property, not an available path.
- **THREAT ASSUMPTION** — an explicit attacker or trust premise for analysis.
- **HYPOTHETICAL** — an explanatory case, not an observed production event.
- **OPEN** — undecided, unavailable, or unproved.

## Reviewed inputs and pins

Remote `main`, candidate branch tips, and commit identities were checked. The
new document is based directly on verified `origin/main`; none of the
unmerged documents below is represented as part of main.

| Input | Exact revision | Status |
|---|---|---|
| Main source and signing-state continuity contract | `ae6464120b15dabe6e994ee983b3d80046d89722`, tree `cd394644a3998d2e23c2e2d95b1767657b34f17d` | Verified remote `main` and `HEAD`; continuity contract is in this pinned tree. |
| Route B first-use trust contract | `23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, tree `1abd3237cfde990e347a00efacf822fab100b918` | Unmerged; parent is main. |
| Shared-control / non-override succession candidate | `974c74e43cf957282cd612caa75c4c7f29d9f0b7`, tree `3e44110f8ac71730ee60efbaddeff60b6801ad8d` | Unmerged; parent is main. |
| Option-A policy-semantics candidate | `4152038774523e8679fcc255f451ed61e71ea068`, tree `dd685eda479068be2fc858977522e556df4fd7d4` | Unmerged; parent is main. |
| Step-0 initial provisioning trust contract | `2cf36c293a0e734cc6307da29d7dd2ef6d2cb169`, tree `5d67fe46db92123092d44ae0bf1a867dcec4e3ed` | Unmerged; parent is main. |

The main-pinned signing-state continuity contract already distinguishes
ordinary crash consistency from complete-copy rollback, and leaves domain-
external anti-rollback evidence unresolved. This candidate narrows that
evidence gap into proof obligations; it does not select among the anchor
families described in that contract
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:602-612,758-851`).

## 1. Threat model and meaning of “current”

### 1.1 Bounded threat model

**THREAT ASSUMPTION — local whole-copy rollback/substitution:** At process
boundaries, an attacker may read, copy, replay, replace, delete, or restore the
node's complete local durable state, including authorization/configuration
records, databases, signing journals and sequences, epoch/consensus records,
local logs, and local VM or snapshot state. The attacker may restore a
mutually consistent older copy. For the indistinguishability argument below,
cryptographic primitives and honest code are assumed not to be broken or
modified.

This model does not assume that any state or evidence exists outside that
domain. A candidate external currentness reference is trustworthy only after a
separate review establishes that it is actually outside the specified
rollback/substitution domain, has independent custody, is authenticated for
its purpose, and cannot be rolled back or made to equivocate by the same
attacker. A remote location alone proves none of these properties. A protected
local anchor or hybrid may have a different boundary and must be analyzed
separately.

**OPEN:** The actual attacker capabilities, state inventory, trust-root
custody, external-source compromise/collusion, cross-host copying, source
equivocation, partition behavior, and acceptable availability remain
unselected. No numeric availability target is set; additional collusion
tolerance remains **OPEN**.

### 1.2 Currentness claim

**CANDIDATE:** For a protected action and deployment, “current” means that
the evidence identifies the unique latest applicable authorization state for
the exact deployment/genesis context, purpose, authorized policy/state, and
action scope, including its predecessor or lifecycle-generation relationship
and whether it has been superseded, revoked, or disputed. It is not merely
“a valid signature exists,” “a record is internally consistent,” or “this
response arrived most recently.”

The protected actions are establishing/replacing accepted-genesis provenance,
delegating/replacing mapping-policy issuer authority, approving/replacing an
authorized mapping policy, establishing first-use/current authorization, and
resolving disputed currentness or authorizing recovery. A currentness claim
may establish evidence about the state applicable to one of these actions; it
does **not** bind authorization to carry out that action or approve its
proposed result.

**SOURCE FACT:** In the local-only whole-copy model, “never signed before”
and “signed before but the record was lost/rolled back” are indistinguishable
from local state alone. The continuity contract likewise says that restoring
older signing records and all local references yields a whole-copy rollback
that a local reader cannot distinguish from a valid older state
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:602-612,643-646`).

**CANDIDATE consequence:** If no independently trusted datum outside the
attacker's rollback domain is authorized and available, latestness cannot be
established under this model. The claimed rollback-resistant currentness
property is **INFEASIBLE under the local-only assumption**; the required safe
behavior is refusal/unavailability, potentially indefinitely.

### 1.3 Insufficient signals

None of the following alone establishes latestness:

- a signed or otherwise authentic old record;
- local consistency among mutually restored records;
- a checksum or corruption-detection result;
- a timestamp or source label;
- a valid historical QC;
- a local or unpersisted monotonic value; or
- an empty store, missing state, or successful prior startup.

**SOURCE FACT:** The pinned continuity contract says a checksum is not rollback
protection, a valid historical QC does not prove latestness, and a monotonic
number alone neither binds signing history nor prevents cloned signers from
authorizing conflicting decisions. It also distinguishes a whole-copy
rollback from ordinary crash recovery
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:760-809,822-835`).
The local signing-reservation journal explicitly provides no durable
anti-rollback anchor (`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/signing_reservation_journal.rs:17-28`).
The Route B contract also rejects an unpersisted sequence or signed timestamp
as independent currentness (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:84-90`).

## 2. Evidence binding and authority boundaries

### 2.1 Distinct propositions

**CANDIDATE:** For an evidence item `E` and a proposed protected action `A`,
the review must establish each of these separately:

1. **Evidence authenticity:** the evidence content and its origin are
   authenticated; a label or self-asserted source identity is not proof.
2. **Authority to make the claim:** the source is authorized for the exact
   currentness or authorization claim and purpose. Authentication of a source
   does not itself grant that source authority.
3. **Applicability:** the claim covers this deployment, environment, accepted
   genesis, purpose, policy/state, and action. Valid evidence for another scope
   does not apply.
4. **Currentness and anti-rollback:** the claim is latest, non-replayed,
   non-superseded, and non-conflicting against an independently trusted
   reference outside the defined rollback/substitution domain.
5. **Binding authorization of `A`:** the required independently operated
   authorization approves the exact requested action and proposed effect.
   Currentness evidence alone is not that authorization.

**OWNER DECISION:** Long-term trust-creating and recovery actions require
binding independently operated authorization. One participant alone or one
shared control that enables one actor to authorize a protected action alone
fails the owner’s goal. Authorization after participant loss is possible only
when the unchanged prior policy already permits the remaining participants
and trustworthy evidence remains available; loss does not change policy or
transfer authority
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:41-62,88-122,141-175`;
`4152038774523e8679fcc255f451ed61e71ea068`,
`docs/security/evidence/option-a-policy-semantics-five-protected-actions-candidate-20261110.md:60-97,120-134`).

### 2.2 Data and relationship binding

**CANDIDATE:** Without choosing a schema or construction, future
currentness/authorization evidence must authenticate a relationship among:

- deployment and environment identity;
- independently accepted genesis identity/provenance;
- the relevant purpose and scope;
- the authorized policy or complete authorization-state identity/version;
- the protected action, exact subject/context, and proposed effect;
- the predecessor state or lifecycle-generation relationship, including
  replacement/revocation status; and
- the currentness/conflict statement and evidence reference that establishes
  latestness for that state.

Each field's meaning, binding, and source must be reviewed as a relation, not
as an isolated value. No value is selected here. Accepted-genesis provenance
and mapping-purpose delegation originate outside the policy bytes; a local
matching hash, policy-named signer, or unpersisted `authority_sequence` does
not establish independent provenance or currentness. `GenesisConfig.extra`
must not carry identity, policy, issuer, or mapping metadata under A50-F1
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-ledger/src/genesis.rs:1335-1340,1569-1621`;
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-111,233-266`).
The exact-pinned Step-0 candidate likewise treats initial trust acceptance,
provenance, purpose delegation, and currentness as distinct claims and leaves
their authority/evidence mechanisms open
(`2cf36c293a0e734cc6307da29d7dd2ef6d2cb169`,
`docs/security/evidence/step-0-initial-provisioning-trust-contract-20261110.md:42-88,100-109,202-223`).

**OPEN:** The external evidence's own authentication root, authority to attest
latestness, state continuity, anti-equivocation behavior, and compromise
boundary must themselves be independently established. Calling a source
“witness,” “anchor,” “quorum,” or “currentness service” does not establish
these properties.

## 3. One Decision B lifecycle and check-to-effect ordering

### 3.1 Evidence consumption

**CANDIDATE:** Independently authenticated out-of-domain evidence is an input
to the single Decision B enrollment/current-authorization lifecycle. It is
not a second permission path or parallel application freshness generation.
For each action, that lifecycle must bind together:

- the applicable provisioning, accepted-genesis, delegation, policy, and
  P/V-domain state;
- currentness evidence for that complete state and the relevant predecessor;
- binding independent authorization for the exact action and result; and
- the lifecycle generation/state admitted by the same
  `CurrentAuthorizationOwner`.

The outside source may provide evidence needed to prove currentness; it does
not independently authorize a P/V effect or let callers bypass the owner. Its
claim must be consumed and reconciled as part of the one owner lifecycle.
There must be no detached mapping-only currentness record whose state can
disagree with the authorization that P/V admission consumes.

The Route B contract proposes one complete Decision B state and explicitly
leaves durable currentness, first-use enrollment, and production source
unavailable (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:165-213,219-231`).

### 3.2 Ordering and uncertainty

**CANDIDATE:** Before a protected effect, the future implementation must prove
the following ordering and consistency properties without assuming a
particular atomic primitive:

1. Authenticate the evidence source, its purpose authority, deployment/action
   applicability, currentness, and conflict status.
2. Independently validate the binding authorization for the exact action,
   predecessor, and proposed result. A currentness response is not a
   substitute.
3. Admit the combined state through the one Decision B owner; ensure the
   verifier/action uses the exact state that was admitted.
4. Prevent a superseding authority/currentness state from slipping between
   admission and effect. Reconfirm at the effect boundary or otherwise prove
   an equivalent ordering; if the proof cannot be made, refuse before effect.
5. Reconcile any uncertain persistence or response outcome before retrying,
   replacing state, or claiming success. Never infer that a transition did
   not occur merely because its response was lost.

These are proof obligations, not a claim that a transaction, lock, network
protocol, or durable generation already exists. The Route B candidate's
ordering likewise does not assert an available atomic/durable primitive
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:177-213`).

**SOURCE FACT:** `CurrentAuthorizationOwner` has only an unavailable production
constructor; concrete establishment is test-only. Its admission ticket and
generation protect in-process ordering, not a durable currentness lifecycle
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1045-1058,1179-1238`).

**OPEN — D7 missing-owner refusal:** When P/V authority exists but the required
current-authorization owner/snapshot is absent or uncertain, refusal before
verification, signing, mutation, or forwarding remains an integration
requirement. This candidate does not claim that gap is fixed
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

Current authorization alone does not establish signer exclusivity,
signing-history continuity, cross-process fencing, consensus-lock recovery,
finality, or recovery authority. Native post-quantum authentication and
continuity are also separate **OPEN** obligations. Execution cursor, VM state
position, and snapshot height must not supply signer position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:225-266`).

## 4. Conflicts, failures, and succession

Each row is a **HYPOTHETICAL** scenario with a **CANDIDATE** refusal or
continuation outcome under the stated assumptions; none is an implemented flow.

| Scenario and assumptions | Required behavior |
|---|---|
| Evidence is unavailable, stale, replayed, substituted, or locally rolled back. | Refuse the affected action and dependent P/V authority. Do not fall back to a historical policy, local sequence, cached response, matching hash, or empty state. |
| Different hosts/copies receive conflicting currentness claims, or a source may equivocate. | Treat the state as disputed; do not choose by arrival order, local preference, or “newest-looking” timestamp. Refuse until independently authorized conflict resolution establishes one applicable current state. |
| One participant is compromised but no independently valid authorization can be formed without another authorized participant. | The compromised participant alone cannot authorize or alter the action. Refuse if compromise undermines authorization evidence, currentness, or binding; otherwise continue only if unchanged policy and all evidence/safety gates remain satisfied. |
| One shared control can operate multiple nominally independent participants or alter their evidence. | The arrangement fails the single-actor goal if one actor can thereby authorize a protected action alone. Do not claim independence from separate keys; refuse the affected action until the boundary is independently shown not to permit unilateral authority. |
| One participant becomes unavailable under an unchanged, already authorized policy. | Continue only if the remaining participants still satisfy that exact policy for the requested action, trustworthy current evidence remains available, and separate safety gates pass. Otherwise refuse. Loss, silence, timeout, or death report does not transfer authority. |
| Update request or response is lost; it is unknown whether evidence/state advanced. | Treat outcome as uncertain. Do not report success, use a presumed prior state, or issue a conflicting update. Reconcile using the same bound request and trusted evidence; if outcome cannot be established, remain unavailable. |
| Replacement, revocation, or separately authorized recovery is proposed. | Treat it as its own protected action with binding authorization, authenticated predecessor and successor/context, currentness and conflict checks, and same-lifecycle application. Do not let a currentness claim itself authorize it. |
| No independently trusted out-of-domain datum is available under the local-only whole-copy-rollback model. | Mark currentness/anti-rollback **INFEASIBLE under that model**. Local observations cannot identify the old copy as stale; refuse current authorization and effects, potentially indefinitely. |

**SOURCE FACT:** The main continuity contract describes full-copy rollback as
locally indistinguishable, requires trusted out-of-domain evidence to confirm
latestness, and leaves the domain-external anchor explicitly unresolved
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:645-646,837-851`).

## 5. Alternatives and proof obligations

**OWNER DECISION:** Investigate independently authenticated evidence outside
the node's local rollback/substitution domain together with binding,
independently operated authorization for the five protected actions.

**CANDIDATE:** A future comparison may consider an external source, a
protected-local anchor, or a hybrid. No option is selected. Each must be
evaluated against the same obligations; none alone is presumed to solve
authorization, currentness, non-equivocation, shared-control independence,
check-to-effect ordering, signer exclusivity, history continuity, and native-PQ
continuity. The main continuity contract lists protected-local and remote
evidence as unselected families and leaves anchor selection unresolved
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:770-851`).

| Proof obligation | What independent review must establish |
|---|---|
| Outside-domain placement | Define the whole rollback/substitution domain and prove the currentness reference, its custody, and its recovery path are outside it. A remote address or local hardware label is not evidence. |
| Authentication, purpose, deployment | Authenticate who made the claim, their authority for that purpose, and exact deployment/genesis/action applicability; prohibit circular reliance on policy bytes, source labels, or locally matching hashes. |
| Binding authorization | Show the exact protected action/result is independently authorized under the applicable policy; prove one participant or shared control cannot alone authorize or change it. |
| Conflict and equivocation | Specify how concurrent or divergent claims are detected and resolved without arrival-order selection, split views, or a source equivocating across hosts. Keep unavailable/disputed cases fail-closed. |
| One lifecycle and ordering | Bind external evidence, authorization, predecessor, and P/V domain into one Decision B state; prove no stale evidence or authority change can race from check through effect. Demonstrate missing-owner refusal. |
| Restart, replacement, recovery | Establish first use, latestness, revocation/succession, unknown outcomes, lost responses, and state recovery without interpreting absence as unused or resetting unresolved obligations. |
| Native-PQ authentication and continuity | Independently assess authentication and succession/recovery continuity under the native post-quantum objective. Do not silently rely on classical signatures, infrastructure, attestation roots, or transport trust. |
| Separate safety properties | Prove signer exclusivity, signing-history continuity, cross-process fencing, consensus-lock recovery, finality where applicable, and recovery authority separately from current authorization. |

## 6. Claim / assumption / counterexample / evidence / refusal matrix

| Claim | Assumption | Counterexample if assumption fails | Evidence required | Refusal |
|---|---|---|---|---|
| An external currentness reference can distinguish rollback. | It is authenticated, purpose-bound, available, non-equivocating, and outside the full local rollback/substitution domain. | The attacker restores every local record and reference to an older mutually consistent copy; with no outside datum, the observations match a valid older state. | Threat-boundary inventory; independent source/custody authentication; rollback and clone analysis; non-equivocation and outage evidence. | If no trustworthy out-of-domain reference is available, mark latestness infeasible under the local-only model and refuse. |
| Evidence applies to this action/deployment. | Genesis, purpose, policy/state, action, scope, and predecessor are all bound and authenticated. | A valid claim for another deployment, purpose, predecessor, or action is replayed as applicable. | Exact context-binding review, issuer/authority proof, applicability and supersession evidence. | Reject mismatch, omission, ambiguity, or stale evidence. |
| Currentness permits the requested transition. | Binding authorization separately approves the exact action/result. | A valid currentness statement is mistaken for authorization to replace/revoke policy or recover disputed state. | Independently operated action authorization and proof that currentness alone cannot invoke effects. | Currentness may inform state only; without action authorization, refuse. |
| One current state feeds P/V authorization. | All claims are admitted through one Decision B lifecycle and effect-boundary checks. | A policy-side freshness record and P/V owner advance independently and disagree, or owner changes after evidence check. | Unified state/use-path audit; check-to-effect ordering proof; stale-evidence and missing-owner refusal evidence. | Keep P/V and affected action unavailable on divergence or race uncertainty. |
| Participants are independent enough for the owner goal. | Credential, administration, provisioning, recovery, infrastructure, provider, and backup controls do not let one actor authorize alone. | A shared administrator can act for multiple nominal participants despite distinct keys. | Common-control and recovery-path audit; evidence for independence; explicit collusion analysis. | Fail the owner’s goal and refuse to claim the arrangement satisfies it. |
| Restart/recovery preserves latestness. | The latest currentness reference and any update outcome survive or can be re-established independently of local rollback. | A lost response leaves it unknown whether revocation/replacement committed; retry or old-state use creates conflicting decisions. | Lost-response/reconciliation rules, predecessor binding, recovery authority, restart and conflict evidence. | Treat outcome as uncertain; do not proceed until reconciled, otherwise unavailable. |
| Native-PQ continuity holds. | Authentication, evidence updates, succession, and recovery remain within the owner’s native-PQ requirement. | A remote source or hardware root silently depends on a non-approved classical or infrastructure trust chain. | Independent cryptographic and lifecycle review through replacement/recovery, including all trust dependencies. | Do not claim PQ satisfaction or enable dependent authority while unmet. |

## 7. OPEN decisions and future gates

**OPEN — owner decisions:**

- What rollback/substitution attacker domain is in scope, including copied
  hosts, backups, restore operators, and shared administrators?
- Which functional authority may authenticate currentness evidence for each
  purpose, deployment, and protected action, and how is that authority itself
  independently accepted?
- What evidence must bind policy/state identity, predecessor, action, and
  lifecycle generation? No schema or construction is selected.
- What conflict/equivocation behavior and outage/refusal consequences are
  acceptable? No quantitative availability target has been set.
- What additional collusion tolerance is required? **OPEN.**
- What criteria distinguish a trustworthy out-of-domain reference from an
  independently authoritative second freshness lifecycle?
- Which separately reviewed currentness alternatives, if any, are feasible
  without violating the one-Decision-B requirement?

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** Before implementation entry,
independent review must verify the threat boundary; source authority,
authentication, purpose and deployment binding; anti-equivocation and conflict
handling; shared-control independence; first-use/restart/replacement and
lost-response behavior; one-lifecycle ordering; the D7 missing-owner refusal;
and separate signer/history/fencing/consensus/recovery/PQ obligations. Any
later authorized Rust PR must start from verified applicable main, contain
only approved paths, and retain clean-worktree local `cargo test` and
`cargo check --lib --bin qbind-node` evidence before merge. No tests or
implementation are authorized by this document.

No trust anchor, external service, protected-local mechanism, hybrid, key,
root, threshold, storage, construction, or recovery process is selected,
approved, or executed. This document does not update the authoritative
carry-forward record.

## 8. Preserved status

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**.
