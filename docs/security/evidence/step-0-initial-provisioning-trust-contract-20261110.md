# Step-0 Initial Provisioning Trust Contract

## Status, scope, and evidence labels

**SPECIFICATION-ONLY CANDIDATE.** This document develops only the initial trust
relationship at Step 0 of Route B: who may establish and authenticate the
provisioning relationship, what claims that relationship must support, and
where its custody, substitution, and rollback boundaries must be proven. It
does not select an issuer, participant, key, trust root, cryptographic
construction, format, procedure, storage, currentness mechanism, or recovery
mechanism. It asserts no production capability.

- **SOURCE FACT** — established by the cited pinned source.
- **OWNER DECISION** — an explicit direction or guardrail, not evidence that a
  capability exists.
- **CANDIDATE** — a requirement or sequence proposed for independent review.
- **ASSUMPTION** — a trust premise that must be made explicit and evidenced.
- **HYPOTHETICAL** — an adversarial illustration, not an observed exploit.
- **OPEN** — undecided, unavailable, or unproved.

## Reviewed inputs

The reviewed commits and trees were verified against remote refs. The new
document is based directly on reviewed `origin/main`, not on any candidate
branch.

| Input | Exact revision | Status |
|---|---|---|
| Main source | `ae6464120b15dabe6e994ee983b3d80046d89722`, tree `cd394644a3998d2e23c2e2d95b1767657b34f17d` | Verified; remote `main` and `HEAD`. |
| Route B first-use trust contract | `23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, tree `1abd3237cfde990e347a00efacf822fab100b918` | Unmerged; parent is reviewed main. |
| Shared-control / non-override succession candidate | `974c74e43cf957282cd612caa75c4c7f29d9f0b7`, tree `3e44110f8ac71730ee60efbaddeff60b6801ad8d` | Unmerged; parent is reviewed main. |
| Option-A policy-semantics candidate | `4152038774523e8679fcc255f451ed61e71ea068`, tree `dd685eda479068be2fc858977522e556df4fd7d4` | Unmerged; parent is reviewed main. |
| Continuity candidate | `5b7418a5436930584f1609b8c7a563e040ef5704`, tree `5329feab2b518f332e349bd990162fb607ca234c` | Unmerged; parent is reviewed main. |
| Independent feasibility assessment | “QBIND — Independent Feasibility Assessment: First-Use Trust, Restart Currentness, and Rollback,” supplied with this task | Review input, not a repository revision. Its source assertions are cited below to their exact repository pins. |

The assessment's recommended bounded next unit is this Step-0 contract. Its
key constraint is that no local-only state can distinguish a complete older
rollback from a mutually consistent current state; the review does not select
an out-of-domain currentness mechanism. This document treats that assessment
as analysis, not as implementation evidence.

## 1. Step-0 trust-chain termination

### 1.1 What Step 0 must establish

**CANDIDATE:** Before any Route B policy is accepted, the initial provisioning
relationship must authenticate the claims below in the stated dependency
order. A valid signature, matching local hash, or policy encoding is not a
substitute for the authority that establishes these claims.

1. **Trust relationship and purpose.** An independently accepted authority
   establishes that the provisioning evidence is entitled to make the named
   claims, for the named deployment and purpose.
2. **Accepted deployment/genesis identity.** The evidence binds an accepted
   genesis identity to the intended deployment, environment, and context.
   Computing an identifier from local configuration may check correspondence;
   it does not establish who accepted that configuration.
3. **Mapping-purpose delegation.** An authority already trusted for this
   purpose delegates the mapping-policy purpose. The delegation identifies its
   scope and the deployment/genesis context to which it applies.
4. **Policy issuer and exact policy.** The delegated issuer authenticates the
   exact policy candidate. Policy authenticity is distinct from issuer
   authority, purpose, scope, applicability, and currentness.
5. **First-use and restart currentness.** Independently trustworthy evidence
   establishes unique first use and, on restart or replacement, which
   provisioning/delegation/policy state is current and whether any supersession
   or conflict exists.

**OWNER GUARDRAIL:** Genesis provenance and mapping-purpose delegation
originate outside the policy bytes being verified. Do not repurpose
bundle-signing, transport, bootstrap, or A33-F1 authority for the
mapping-policy purpose.

**CANDIDATE:** The trust chain terminates in an independently accepted trust
relationship, not in another assertion derived from the policy. That
termination means an owner-authorized external decision accepts the initial
authority, purpose, scope, and evidence source before they are used. The
decision is a trust assumption to be specified and independently evidenced;
cryptographic verification can authenticate evidence under an accepted trust
relationship, but cannot prove who was entitled to accept the first one.

**OPEN:** Which functional authority class is allowed to accept that initial
relationship, how its authority and independence are evidenced, and what
rollback/substitution boundary applies to its acceptance. If no such
independent trust input is available, Step 0 is not established and all
dependent Route B authority remains unavailable. A policy cannot authenticate
its own issuer; a local hash cannot authenticate its own provenance; an
already-enrolled `CurrentAuthorizationOwner` cannot be assumed at first use.
The Route B contract states these initial-trust limits explicitly
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-111`).

### 1.2 Functional authority classes — candidate, not selected

The following are functions that a future design must assign, not identities
or approved authorities. A single entity could hold multiple functions only
if an independently reviewed authority-boundary analysis proves that doing so
does not violate the owner’s single-participant/single-actor goal.

| Claim | Candidate functional authority class and scope | Evidence category | Refusal / unavailable outcome |
|---|---|---|---|
| Initial trust relationship | An owner-authorized **initial trust acceptance authority**, scoped to accepting the provisioning trust basis, its purpose, and deployment. The authority must be accepted independently of the Route B policy. | Authenticated owner decision or equivalent independent acceptance, plus evidence identifying the authorized scope and the evidence source it accepts. The representation and mechanism remain **OPEN**. | Without a non-circular acceptance of the initial authority and scope, do not accept provisioning claims or establish first use. |
| Accepted deployment/genesis identity | A **deployment/genesis provenance authority**, authorized under the accepted initial relationship to attest the intended deployment and genesis context. | Authenticated provenance binding deployment/environment to the accepted genesis identity; separately checked correspondence to local genesis configuration. | Missing, mismatched, substituted, disputed, or out-of-scope provenance means no accepted genesis and no dependent policy or enrollment. |
| Mapping-purpose delegation authority | A **mapping-purpose delegator**, whose authority to delegate this purpose is established outside the policy it enables. | Authenticated delegation tying an issuer to the mapping-policy purpose, accepted deployment/genesis context, and applicable scope, including status/supersession evidence. | No delegation if the delegator is not independently authorized, the purpose/scope is absent, or delegation evidence is stale, conflicting, or unauthenticated. |
| Policy issuer and exact policy | A **delegated mapping-policy issuer**, limited to the independently authorized purpose and scope. | Authentication of exact policy bytes and issuer identity, plus evidence of delegation and policy applicability. Policy signature alone does not establish delegation or currentness. | Do not accept policy when issuer, bytes, purpose, context, applicability, or currentness is missing, ambiguous, conflicting, or invalid. |
| First-use and restart currentness | A **currentness authority/source** authorized independently to establish unique first use, latest state, replacement/revocation status, and conflict status. It need not be the same class as the issuer or provenance authority. | Evidence that covers the complete relevant trust/authorization state and is trustworthy outside the rollback/substitution domain being addressed. Specific currentness evidence and its source remain **OPEN**. | Empty, missing, stale, replayed, rolled-back, or disputed state does not mean “never enrolled” or “still current.” Refuse until currentness is established. |

Every class and evidence category above is **CANDIDATE / OPEN**. No actual
authority or capability is claimed.

## 2. Root authority, custody, and trust boundaries

### 2.1 Decisions and evidence required

**OWNER DECISION:** Long-term trust-creating and recovery actions require
binding independently operated authorization. One participant alone, or a
shared control that gives one actor effective sole authority, must not authorize
a protected action. Continuation after participant loss is conditional on the
unchanged authorized policy and trustworthy evidence; it does not lower the
bar, transfer authority automatically, or override safeguards. These are
requirements to prove, not properties supplied by this contract
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:41-62,88-122,141-175`;
`4152038774523e8679fcc255f451ed61e71ea068`,
`docs/security/evidence/option-a-policy-semantics-five-protected-actions-candidate-20261110.md:60-97,181-208`;
`5b7418a5436930584f1609b8c7a563e040ef5704`,
`docs/security/evidence/continuity-without-lowering-authorization-bar-candidate-20261110.md:80-117,141-170`).

Those protected actions are accepted-genesis provenance, mapping-purpose
delegation, mapping-policy approval/replacement, first-use enrollment/current
authorization, and disputed-currentness resolution/recovery. Step 0 supplies
none of their outcomes in advance; any particular future action remains
separately bound to its request and current evidence
(`4152038774523e8679fcc255f451ed61e71ea068`,
`docs/security/evidence/option-a-policy-semantics-five-protected-actions-candidate-20261110.md:99-117,136-176`).

**CANDIDATE:** Before Step 0 is usable, the owner must decide and independently
review the following boundaries. Listing a boundary is not evidence that it
has been secured:

| Boundary | Required decision and evidence |
|---|---|
| Authority to establish purpose/scope | Identify the functional authority that may accept the initial trust relationship and the independent basis for that authority. Bind it to deployment, environment, and the mapping-purpose delegation boundary. The first policy or its named signer cannot establish this authority. |
| Custody and use | Identify the complete custody/use paths for accepted trust evidence and any credentials or records that could create, alter, replace, revoke, or recover it. Establish who can exercise each operation and whether one actor can combine them. |
| Replacement, revocation, recovery | Specify which authority can replace/revoke the initial relationship, how successor authority is independently authenticated, what happens to prior claims, and how recovery is separately authorized. Loss, death report, timeout, or silence is not consent or authority transfer. |
| Shared-control domains | Trace shared personnel, administrators, provisioning services, credential recovery, infrastructure, provider accounts, CI/release paths, backups, restore operators, and dispute/recovery procedures. Different keys alone do not prove independent operation. |
| Substitution boundary | Identify every path by which an attacker could replace the trust input, evidence, policy, identity binding, or apparent current state while preserving internal consistency. Authenticate evidence independently of that substitution path. |
| Whole-copy rollback boundary | State which complete local and replicated state an attacker may copy/restore. Currentness requires an independently trusted reference outside that defined rollback domain; local consistency and local counters cannot establish latestness if they roll back together. |
| Unavailability and irretrievable loss | Define the refusal response when root authority or required evidence is missing, stale, disputed, compromised, or irretrievably lost. Do not invent a fallback trust anchor or guarantee recovery. Indefinite unavailability remains possible. |

If one shared administrative or recovery control lets one actor cause multiple
nominally independent participants to authorize a protected action alone, the
design fails the owner’s stated goal regardless of key count. Additional
collusion tolerance remains **OPEN**. No numeric availability target is
selected.

### 2.2 Authorization is not currentness

**CANDIDATE:** Keep these questions separate:

- **Authority:** Who is entitled to make a claim or decision for this purpose?
- **Authentication:** Is the evidence bound to that authority and exact content?
- **Applicability:** Does it cover this deployment, genesis, purpose, and scope?
- **Currentness:** Is it the unique currently applicable state, not superseded,
  replayed, or rolled back?
- **Effect:** Has the independently authorized state been admitted into the
  same Decision B lifecycle before any dependent P/V authority is used?

A validly authenticated historical policy or delegation may still be stale.
A freshness indicator or sequence may still be unauthenticated, rollbackable,
or unbound to the full Decision B state. Neither authorization nor a monotonic
value alone proves the other properties.

**SOURCE FACT:** Main’s `CurrentAuthorizationOwner` has no production
constructor that establishes concrete current state; only the unavailable
production constructor exists, while fixture establishment is `cfg(test)`
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1045-1058,1222-1238`).
Its admission/confirmation generation provides in-process invalidation, not
durable restart currentness
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1179-1205`).
The local signing-reservation journal states that it has no durable
anti-rollback anchor and cannot detect whole-copy rollback or deletion from
local state alone
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/signing_reservation_journal.rs:17-28`). The main
continuity contract characterizes an internally consistent whole-copy rollback
as locally indistinguishable from an older valid state and leaves the
domain-external anchor unresolved
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md:643-646,770-845`).

**OPEN:** A separately reviewed currentness/anti-rollback mechanism must
establish at least: unique first use; continuity of trust-root, delegation,
policy, and revocation state across restart; detection or fail-closed handling
of rollback beyond the local rollback domain; and non-equivocating conflict
resolution across copies/hosts. Different mechanisms could address different
properties; naming a witness, protected-local anchor, multi-party process, or
combination does not prove sufficiency. No class or mechanism is selected.

## 3. One Decision B lifecycle

**CANDIDATE:** Step-0 evidence is a prerequisite input to the same proposed
Decision B enrollment / `CurrentAuthorizationOwner` lifecycle, not a second
freshness system:

1. Independently accept and authenticate the provisioning relationship.
2. Verify accepted-genesis provenance, mapping-purpose delegation, issuer and
   exact policy, applicability, and currentness as distinct propositions.
3. Bind the complete evidence and the P/V authorization domain into one
   candidate Decision B state.
4. Only after independent currentness and rollback checks may a future
   production owner/snapshot become current; all later P/V admissions and
   effects use that same owner and confirm at the effect boundary.
5. Restart, replacement, revocation, and recovery re-establish or replace that
   same current state. No parallel policy-only freshness generation or stale
   policy fallback is allowed.

The Route B contract specifies this candidate sequence and states that its
provisioning source, durable currentness, and production enrollment are not
established (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:165-213,225-231`).

**OPEN — D7 missing-owner refusal:** If P/V authority is present but its required
current-authorization owner/snapshot is missing or uncertain, refusal before
verification, signing, mutation, or forwarding remains an integration
requirement. This contract does not claim the D7 gap is fixed
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

Current authorization does not establish signer exclusivity,
signing-history continuity, cross-process fencing, consensus-lock recovery,
finality, recovery authority, or native-PQ authentication/continuity. Each
remains an independent proof obligation. Execution cursor, VM state position,
and snapshot height must not supply signer position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:225-266`).

## 4. Adversarial checks

The following cases are **HYPOTHETICAL** threat checks, not observed production
exploits.

| Case and threat assumption | Required result |
|---|---|
| **Policy names its own signer as delegator.** Assume an otherwise valid policy says its signer is also authorized to delegate mapping-policy purpose, but no independently authenticated authority established that delegation. | Reject the delegation and policy authority as circular. A policy signer cannot bootstrap the authority used to authenticate itself. |
| **Matching local genesis hash, no provenance.** Assume the local configuration hashes to a value named by a local policy/config, but no independent authority attests that this deployment/genesis was accepted. | Treat the hash only as local correspondence. Do not assert accepted provenance, accept a dependent policy, or enroll first use. Main’s canonical hash is computed from selected local fields; its function does not encode `extra` despite a contradictory comment (`ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-ledger/src/genesis.rs:1569-1621`). Under A50-F1, identity, policy, issuer, or mapping metadata must not be put in `GenesisConfig.extra`. |
| **Internally valid older whole-copy rollback.** Assume an attacker can restore every local state item and local reference to an older mutually consistent copy, while cryptography and code remain honest and no trustworthy reference exists outside that rollback domain. | The local state cannot prove latestness. Refuse currentness and dependent authority until evidence outside the rollback domain resolves it. Never reinterpret the old/empty copy as first use. |
| **Shared administrator/recovery system.** Assume separate participants have different credentials, but one administrator or credential-recovery system can control enough of them to authorize a protected action alone. | Fail the owner’s single-actor-compromise goal. Do not claim independence from different keys. Keep the affected authority unavailable unless an independently evidenced boundary disproves that unilateral control. |
| **Missing/disputed evidence at first use, restart, or succession.** Assume provenance, delegation, currentness, revocation, or successor evidence is missing, stale, conflicting, or cannot be authenticated. | Refuse first enrollment or restart/replacement. Do not choose by arrival order, local preference, silence, or a component’s self-declaration. A dispute/recovery outcome requires its own valid authorization and trustworthy current evidence; otherwise remain unavailable. |

## 5. First-use propositions and proof obligations

| Proposition | Required authority class and scope | Evidence category | Non-circular trust termination | Rollback / substitution boundary | Refusal on missing or conflicting evidence | Single-participant / shared-control proof | Status |
|---|---|---|---|---|---|---|---|
| Initial provisioning trust and purpose | Owner-authorized initial trust acceptance authority; scoped to the provisioning relationship, deployment, environment, and claims it may establish. | Independent acceptance of the trust basis, the authority’s scope, and the source of accepted evidence. | Acceptance originates outside the policy, local hash, and not-yet-enrolled owner; the initial owner decision is an explicit trust assumption, not a self-proving cryptographic fact. | Identify all custodians, provisioning and recovery paths, replacement/revocation controls, and complete-copy rollback domain. | No accepted trust relationship means no accepted genesis, delegation, policy, or enrollment. | Prove no one participant or shared control can create/replace the initial authority alone; analyze shared personnel, administration, recovery, infrastructure, providers, and backups. | **OPEN (Route B contract):** no initial provisioning input is established in current source (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, §1, lines 97-111). **OPEN:** authority, scope, custody, evidence, rollback model. |
| Accepted deployment/genesis identity and context | Deployment/genesis provenance authority, limited to the intended deployment/environment and genesis claim. | Authenticated provenance binding the deployment context to an accepted genesis identity; local canonical comparison is a separate check. | Provenance is authenticated under Step-0 authority, not derived from the genesis bytes or local hash. | Determine whether genesis/config/evidence can be substituted or restored together; prohibit `GenesisConfig.extra` metadata under A50-F1. | Missing, wrong-context, mismatched, stale, or disputed provenance prevents policy acceptance and enrollment. | Prove one actor cannot assert and independently approve/replace accepted provenance through a shared control. | **SOURCE FACT:** local hash is computed from local fields (`genesis.rs:1576-1621`). **OPEN:** accepted provenance and its authority. |
| Mapping-purpose delegation authority | Independently trusted mapping-purpose delegator; scoped to the exact purpose, deployment/genesis, issuer, and applicable period/status. | Authenticated purpose-specific delegation plus current revocation/succession state. | Delegator’s authority comes from Step 0, not from the policy or issuer it authorizes; disallowed bundle/transport/bootstrap/A33-F1 authorities are not substitutes. | Cover delegation replacement, revocation, backup/restore, replay, and whole-copy rollback; currentness source remains unselected. | No mapping-purpose delegation if authority, purpose, scope, currentness, or conflict status is missing or ambiguous. | Prove one participant/shared control cannot both grant and exercise issuer authority alone. | **OPEN (Route B contract):** no production mapping-purpose delegation path is established (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, §1, lines 84-90). **OPEN:** authority, scope, status, PQ continuity. |
| Delegation scope and applicability | The independently authorized delegator, with authority explicitly covering the mapping-policy purpose and the intended deployment/genesis context; exact grammar and bounds remain open. | Evidence binding issuer, purpose, deployment/environment, accepted genesis, and applicability/succession conditions. | Scope is authenticated under the prior trust relationship and delegation, not inferred from policy contents or a matching local identifier. | Detect scope substitution, stale delegation, and rollback of successor/revocation status across the complete trust-state rollback domain. | Missing, ambiguous, conflicting, stale, or out-of-scope delegation means no policy issuer authority. | Prove one actor cannot alter scope and supply its purported independent acceptance through shared administration or recovery. | **OPEN:** purpose grammar, scope representation, applicability, and current status (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, §1, lines 86-90). |
| Policy issuer, exact policy, and applicability | Delegated mapping-policy issuer, constrained by the exact prior purpose/scope; independent approver where owner policy requires it. | Issuer authentication, exact policy content/version, deployment/genesis applicability, and separate currentness evidence. | Issuer authority is independently delegated before policy verification; policy bytes do not name or authorize their own issuer. | Detect policy rollback/substitution and issuer succession/revocation; do not treat a valid old signature as current. | Reject invalid, unsupported, ambiguous, out-of-scope, stale, conflicting, or unauthenticated policy. | Prove one participant/shared control cannot make an effective policy by controlling both issuer and purported independent approval. | **OPEN (Route B contract):** no production policy authentication/applicability path is established (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, §1, lines 87-95). **OPEN:** issuer, format, authorization, PQ construction. |
| Unique first use and restart currentness | Independently authorized currentness authority/source for enrollment, latestness, supersession, and conflict status; scope covers the complete Decision B state. | Evidence of unique enrollment and the latest non-conflicting state across restart/replacement; anti-rollback reference outside the defined attacker domain. | Currentness authority is independently established from Step 0; no local sequence, empty store, owner generation, or prior policy authenticates its own freshness. | Threat-model the entire set of local databases, journals, config, VM/snapshot state, replicas, backups, and restore paths; show where the trusted reference lies outside it. | Missing, stale, replayed, rolled-back, or disputed state means no current owner/snapshot and no P/V authority. | Prove neither one participant nor common administration/recovery can establish conflicting “current” views or bypass the binding bar. | **SOURCE FACT:** local owner is unavailable in production and local journal lacks anti-rollback (`genesis_consensus_authority.rs:1045-1058`; `signing_reservation_journal.rs:17-28`). **OPEN:** currentness source, uniqueness, rollback resistance, conflicts. |

## 6. Decisions and evidence required before implementation entry

**OPEN — owner decisions:**

- Which independently accepted functional authority may establish the initial
  provisioning relationship, and what independent decision makes that
  authority trustworthy?
- What purpose and deployment/genesis scope may this relationship establish?
- What trust evidence, custodian, succession, replacement, revocation, and
  recovery boundaries are required?
- Which single-actor and common-control compromises are disqualifying? What
  additional collusion tolerance is required? **OPEN; no participant count or
  threshold selected.**
- What happens if initial trust or required evidence is irretrievably lost?
  Conditional continuation is not an availability guarantee; indefinite
  unavailability is permitted.
- Which separately reviewed currentness/anti-rollback properties are needed
  before a first-use or restart decision can feed Decision B? No numeric
  availability target is required or selected.

**FUTURE / NOT AUTHORIZED / NOT EXECUTED — independent review gates:**

1. Audit every production and administrative source/use path for provisioning,
   genesis provenance, mapping delegation, policy verification, enrollment,
   replacement, revocation, restart, recovery, and P/V effects. Include
   provisioning identities, personnel/admin paths, credential recovery,
   infrastructure/providers, backups/restores, copied state, and alternate
   processes.
2. Independently substantiate the initial authority’s purpose and scope,
   custody, common-control boundaries, and successor/revocation authority.
   Different keys or signatures alone are insufficient.
3. Define the attacker’s substitution and whole-copy rollback domain; provide
   evidence that any claimed currentness reference is outside that domain and
   cannot equivocate across relevant copies. No currentness mechanism is
   selected here.
4. Review the complete proposition chain for non-circular trust termination,
   request/subject/context binding, policy applicability, supersession,
   conflict resolution, and refusal behavior on missing or uncertain evidence.
5. Show how complete Step-0 evidence enters one Decision B lifecycle and
   independently verify the required missing-owner refusal. Do not claim the
   D7 gap is already closed.
6. Separately prove signer exclusivity, signing-history continuity,
   cross-process fencing, consensus-lock recovery, finality where applicable,
   recovery authority, and native-PQ authentication/continuity. Current
   authorization does not establish these properties.
7. Preserve A50-F1: no identity, policy, issuer, or mapping metadata in
   `GenesisConfig.extra`; no execution cursor, VM-state position, or snapshot
   height as signer position or freshness.
8. For any separately authorized real Rust PR, retain local `cargo test` and
   `cargo check --lib --bin qbind-node` evidence from a clean worktree based
   on applicable main before merge. Do not add intentionally red baseline
   targets to default test discovery.

No authority class, trust root, mechanism, implementation, enrollment,
currentness service, storage, or recovery procedure is approved or executed.
This document does not update the authoritative carry-forward record.

## 7. Preserved status

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**.
