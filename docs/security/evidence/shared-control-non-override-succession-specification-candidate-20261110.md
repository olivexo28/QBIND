# Shared-Control and Non-Override Succession Specification Candidate

## Status, labels, and scope

**SPECIFICATION-ONLY CANDIDATE.** This addendum refines the shared-control and
succession requirements for the long-term authorization model. It selects no
participants, participant count, threshold, key, root, construction, storage,
or recovery procedure. It authorizes no implementation, integration,
enrollment, migration, startup, recovery, or activation.

- **OWNER DECISION** records an explicitly selected requirement.
- **SOURCE FACT** states only behavior established by the cited pinned source.
- **CANDIDATE** is a required future property, not an available mechanism.
- **ASSUMPTION** identifies a condition that must be established.
- **OPEN** identifies an unresolved choice or proof obligation.

## 1. Reviewed inputs and decisions

**SOURCE FACT:** This candidate is grounded in main
`ae6464120b15dabe6e994ee983b3d80046d89722` (tree
`cd394644a3998d2e23c2e2d95b1767657b34f17d`), the reviewed unmerged succession
candidate `f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a` (tree
`781f001acb6b5fc9f14c70f490417388855f0b03`, parent the main pin), and the
reviewed unmerged Route B contract
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918` (tree
`1abd3237cfde990e347a00efacf822fab100b918`, parent the main pin).
The succession candidate is cited at its own commit and is not represented as
part of main.

The five protected actions are the ones enumerated by the reviewed succession
candidate (`f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a`,
`docs/security/evidence/long-term-independent-authorization-recovery-succession-candidate-20261110.md:57-81`):

1. Establish or replace accepted-genesis provenance.
2. Delegate or replace mapping-policy issuer authority.
3. Approve or replace an authorized mapping policy.
4. Establish first-use enrollment or current authorization.
5. Resolve disputed currentness or permit recovery after lost, conflicting,
   or uncertain state.

**OWNER DECISION:** Each action requires binding independently operated
authorization; advisory review alone is insufficient. Compromise of one
participant alone must not be sufficient to authorize any protected action.
The owner further requires independence claims to account for shared
administrators, credential recovery, provisioning, infrastructure, providers,
and backups. If compromise of a shared control could let one actor alone
authorize a protected action, the arrangement fails the single-participant
compromise goal. A separate key is not evidence of independence. Shared
infrastructure is assessed against its actual failure and control boundaries;
its presence alone is neither a pass nor a fail.

**OWNER DECISION:** Design a separately authorized succession path for death,
incapacity, prolonged absence, lost credentials, and participant replacement.
Succession must preserve binding independent authorization and must not
automatically override authorization, consensus safety, signing history, or
recovery safeguards. If necessary authorization or trustworthy evidence cannot
be established, the affected action remains unavailable. If authority or
evidence is irretrievably lost, recovery may remain unavailable indefinitely.

**OPEN:** Additional collusion tolerance and quantitative availability targets
are undecided. No participant, count, threshold, credential, trust root,
construction, storage, recovery procedure, or activation policy is selected.
This addendum neither decides the initial-DevNet authority model nor changes
the founder-authorized bootstrap decision
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:18-67`).

## 2. Shared-control boundary analysis

### 2.1 Review method

**CANDIDATE:** Before claiming that an action has independently operated
authorization, reviewers should trace the whole authorization path for that
action, from event and evidence creation through validation, authorization,
state transition, recovery, and enforcement. The review should:

1. Identify each functional authority boundary: who may attest, delegate,
   approve, establish currentness, revoke, replace, adjudicate, recover, and
   cause the protected effect. These are functions to analyze, not assigned
   roles.
2. Identify which participants can exercise or alter each function, including
   through shared administrators, credential recovery, provisioning,
   infrastructure, providers, backups, restore access, or rollback/
   substitution of evidence.
3. Ask whether compromise of one participant **or one shared control** could
   make one actor alone able to authorize or enact the action. If yes, the
   claimed arrangement fails the owner’s single-actor goal for that action.
4. Separately identify collusion among participants. The one-participant
   requirement does not specify which collusions must be tolerated.
5. Require evidence for the claimed control boundaries and their actual
   failure domains. Different keys, accounts, hosts, organizations, or labels
   are not sufficient evidence by themselves.
6. Refuse or leave the action unavailable if required authorization,
   independence evidence, currentness, or conflict status cannot be
   established.

**ASSUMPTION:** Independence must be evaluated against a stated threat and
rollback/substitution boundary. Shared infrastructure is not automatically
disqualifying; its operators, privileges, failure modes, state control, and
ability to exercise multiple authority functions determine whether it defeats
the claim. Conversely, nominally separate infrastructure does not prove that
those controls are independent.

### 2.2 Three different compromise cases

- **One compromised participant:** Tests the owner’s explicit requirement.
  No participant alone may supply binding authorization for a protected action.
- **One compromised shared control:** A single administrator, credential
  recovery system, provisioning authority, provider, or backup/restore control
  may affect several participants at once. The owner has explicitly decided
  that if this enables one actor to authorize alone, the arrangement fails the
  same goal. This case is not discharged merely by proving that individual
  participant credentials differ.
- **Collusion among participants:** Several otherwise independently operated
  participants may coordinate. No collusion tolerance beyond the
  single-participant requirement has been decided. It must not be implied by
  the word “independent.”

**OPEN:** Reviewers need evidence about actual control and failure boundaries.
No actual deployment, participant separation, provider independence, credential
custody, backup isolation, or rollback protection is established by this
specification.

### 2.3 Action-specific review and proof matrix

| Protected action | Functional authority boundaries to trace | Shared-control compromise questions | Evidence needed for an independence claim | Refusal / unavailable outcome |
|---|---|---|---|---|
| **1. Establish or replace accepted-genesis provenance** | Who accepts the genesis identity and deployment context; who can attest it; who can replace or supersede that attestation; who makes it effective for enrollment. | Could one provisioning administrator, credential-recovery authority, infrastructure/provider operator, backup controller, or restore actor substitute or replace provenance for all nominal participants? Could a shared personnel or administrative domain let one actor provide both the evidence and its apparent independent approval? | Evidence of who controls attestation and replacement; independent provenance outside the policy bytes and relevant substitution/rollback domain; trace of shared administration, credential recovery, provisioning, infrastructure, provider, backup, and restore privileges. Prove one participant or shared control cannot authorize alone. | No accepted provenance or dependent enrollment if provenance, scope, currentness, or independence is missing, stale, conflicting, substituted, or unverifiable. A matching local hash is insufficient. |
| **2. Delegate or replace mapping-policy issuer authority** | Who may delegate the mapping-policy purpose; who may issue, replace, revoke, or succeed that delegator; who verifies purpose, scope, deployment, and genesis binding before policy use. | Could one shared recovery/admin path exercise both delegator and issuer credentials? Can a provisioning authority silently replace the delegation input? Can backups or provider control restore an older delegation and make it appear current? | Evidence that delegation originates outside the policy bytes; scope- and purpose-specific authority lineage; tested trace of common control and rollback boundaries; proof that neither issuer nor one shared control can delegate or replace itself alone. | No policy issuer authority on missing, stale, wrong-purpose, out-of-scope, conflicting, rolled-back, or unauthenticated delegation. No substitution from bundle-signing, transport, bootstrap, or A33-F1 authority. |
| **3. Approve or replace an authorized mapping policy** | Who authenticates the exact policy; who establishes issuer authority; who authorizes policy applicability and replacement; who binds its mapping to the same deployment/genesis and P/V domain. | Could a shared administrator alter policy bytes and control the purported approval evidence? Could a provider or backup restore a stale policy or issuer record? Could shared credential recovery allow one actor to act as issuer and independent approver? | Evidence of exact policy identity and applicability, prior purpose delegation, independent approval path, and control boundaries over policy distribution, signing credentials, backups, and restoration. Show that one compromised participant or shared control cannot make a policy effective alone. | No policy selection, no stale-policy fallback, and no policy-enabled P/V authority where authenticity, authority, applicability, currentness, or independence is uncertain. |
| **4. Establish first-use enrollment or current authorization** | Who authorizes unique first use; who decides currentness; who commits the complete Decision B state; who can make an owner/snapshot current or replace it. | Could one host administrator, provisioning service, shared backup, provider, or recovery operator make empty or rolled-back state appear to be first use? Can one controller write both “approved” evidence and the effective enrollment state? | Evidence that first use/currentness is authenticated outside the relevant rollback/substitution domain; complete Decision B binding; review of all state writers, readers, recovery paths, and shared administrators. Prove no one participant/shared control can establish enrollment alone. | Do not establish an owner, snapshot, or signing permission if unique first use, currentness, state integrity, or independent authorization is unavailable or disputed. Missing state is not “never enrolled.” |
| **5. Resolve disputed currentness or permit recovery after lost, conflicting, or uncertain state** | Who may adjudicate evidence conflicts; who may authorize recovery, revoke or replace disputed state; who ensures recovery cannot erase signing or consensus obligations; who enforces the decision. | Could one shared recovery system, administrator, provider, or backup controller decide which history is accepted and enact that choice alone? Could a claimant control both the disputed evidence and its recovery path? | Evidence for the authority to adjudicate and recover, authenticated current state and history, common-control analysis of recovery/admin/provider/backup paths, and proof that no single participant or shared control can resolve and enact the result alone. | Keep disputed authority and dependent effects unavailable if authorization, currentness, evidence integrity, or recovery permission is missing or uncertain. Local refusal is not global revocation or a recovery decision. |

These are proposed review checks, not claims that the relevant evidence exists.
The Route B contract requires provenance and delegation to precede policy
authentication, distinguishes currentness and first use from policy validity,
and requires refusal for stale, conflicting, rolled-back, or unavailable
evidence (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-111,217-228`).

## 3. Separately authorized succession

### 3.1 Non-override rule

**OWNER DECISION:** Succession must be separately authorized; event recognition
is not authority transfer. A death report, incapacity assertion, elapsed
timeout, lost contact, credential-loss claim, or absence does not itself
appoint a successor, delegate policy authority, establish currentness, resolve
a dispute, authorize recovery, or permit a signing-history reset.

**CANDIDATE:** For any succession transition, verify the event evidence,
authority to recognize that event, independently authorized successor and
scope, currentness and conflict state, and consistency with the same Decision B
lifecycle. The succession authorization must satisfy the binding independent
authorization requirement. No automatic reduction in authorization,
emergency bypass, or silent rollover is allowed.

### 3.2 Event-to-authorization and refusal matrix

| Event or transition | Evidence and authorization categories required (mechanism not selected) | Currentness and conflict checks | Refusal / unavailability if unresolved |
|---|---|---|---|
| **Death** | Evidence supporting the event; authority to recognize its effect; independently authorized succession of the affected authority function; proof of successor scope and preserved obligations. | Confirm no conflicting succession, revocation, or current-authority evidence; ensure the prior authority is retired only under the authorized transition. | The affected role/action remains unavailable if event evidence, succession authority, currentness, or conflict status is missing or disputed. Death does not automatically transfer authority. |
| **Incapacity** | Evidence supporting incapacity and the scope/duration of the claim; independent authorization to suspend or reassign the affected function; successor authorization under the same binding rule. | Check for conflicting claims, restoration of capacity, prior authority status, and stale successor evidence. | No automatic reassignment, override, or recovery. Keep affected authority unavailable pending sufficient evidence and authorization. |
| **Prolonged absence or lost contact** | Evidence and owner-approved criteria for treating absence as relevant; independent authorization for any resulting suspension or succession. | Check whether the prior participant may still act, whether evidence is current, and whether a conflicting return or successor claim exists. | A timeout or lost contact alone cannot enable succession. Refuse if required authorization or evidence is unavailable. |
| **Credential loss or suspected compromise** | Evidence of loss/compromise; independent authorization for suspension/revocation and separately authorized replacement or recovery of the affected authority. Replacement credentials cannot authenticate their own authority. | Check whether old credentials remain usable, whether the revocation state is current, and whether backups or recovery channels restore compromised authority. | Treat authority as unavailable or suspect; do not infer global revocation from one component’s refusal. No replacement authority until separately authorized and current. |
| **Participant replacement / authority succession** | Evidence and authority to initiate the transition; binding independent authorization of the successor and exact function/scope; evidence of predecessor retirement and retained history. | Reconcile predecessor/successor claims, current policy/delegation, pending or uncertain signing obligations, and rollback state. | No automatic successor, no overlap assumption, and no stale predecessor fallback. Remain unavailable if authorization or continuity evidence cannot be established. |
| **Disagreement or conflicting event/currentness evidence** | Independent authorization from the authority class permitted to resolve that dispute; evidence supporting the decision and its scope. Advisory review may inform but cannot resolve or authorize. | Determine whether evidence is stale, substituted, rolled back, incomplete, or sourced from a common control. Do not select by arrival order or local preference. | The disputed action and dependent authorization remain unavailable. No default adjudicator is established by this candidate. |
| **Lost, rolled-back, or uncertain authorization state** | Authenticated evidence of the current Decision B state, authority to recover, and separate proof of signing-history and consensus-state obligations. | Establish non-rollback currentness and reconcile local/remote histories and any uncertain effects. Do not use a local empty state, old approval, or VM/snapshot position as freshness. | If sufficient authority/evidence is irretrievably lost, recovery may remain unavailable indefinitely. No recovery guarantee or automatic override. |

**SOURCE FACT:** A component can refuse its own operation when evidence is
unavailable, but such refusal does not establish a global revocation or confer
authority elsewhere. The Route B contract explicitly leaves revocation,
recovery authority/evidence, cross-process fencing, and continuity open
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:221-231`).

**OPEN:** What evidence is sufficient to recognize death, incapacity, or
prolonged absence; who may authorize event recognition and succession; how
conflicting claims are resolved; what role overlap is acceptable; what
participant unavailability can be tolerated; and which cases may remain
permanently unavailable are not decided here.

## 4. Decision B and separate safety properties

**CANDIDATE:** Accepted-genesis provenance, mapping-purpose delegation,
policy identity/applicability, first-use enrollment, currentness, replacement,
revocation, and succession must feed the same Decision B enrollment /
`CurrentAuthorizationOwner` lifecycle. No mapping-only or succession-only
freshness lifecycle may become independently authoritative. Any replacement
must preserve one coherent current state and invalidate stale admissions
through that lifecycle. The exact mapping must be bound to the applicable v2
domain and used unchanged downstream.

The Route B contract states that policy and P/V authority must not be committed,
replaced, or recovered under separate freshness generations, and that the
current owner/snapshot remains unavailable when the required evidence is not
established (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:171-213`).

**OPEN:** When P/V authority is present but its required
current-authorization owner/snapshot is missing, the system must refuse before
verification, signing, engine mutation, or forwarding. This is an OPEN
integration requirement, not a claim that the D7 production gap is fixed
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

Neither current authorization nor succession authorization proves:

- **Signer exclusivity:** that copied keys, old instances, or other signing
  routes cannot act.
- **Signing-history continuity:** that reservations, results, and uncertain
  outcomes survive restart and rollback.
- **Consensus safety or lock recovery:** that committed state, locks, and
  supporting evidence are recovered consistently.
- **Finality or recovery permission:** an authorization decision does not
  establish finality or grant permission to recover disputed state.

Execution cursor, VM state position, and snapshot height must not provide
signer position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:249-257`).

## 5. Review gates and remaining choices

### 5.1 Action-by-action boundary and proof-obligation summary

| Action | Required boundary | Minimum proof obligation before any future authorization |
|---|---|---|
| Accepted-genesis provenance establish/replace | Provenance attestation, replacement authority, and deployment/genesis scope | No single participant or shared control can authorize alone; provenance is independent of policy and current within the stated rollback domain. |
| Mapping-purpose delegation/replace | Delegator, issuer, succession/revocation authority, purpose and scope | No single participant/shared control can self-delegate or replace authority; the delegation is independently authenticated before policy use. |
| Policy approve/replace | Issuer authority, exact policy, applicability, replacement and currentness | No single participant/shared control can make an effective policy alone; exact content, authority, binding, and currentness are independently established. |
| First use/current authorization | Unique enrollment, currentness evidence, complete Decision B state and owner/snapshot activation | No single participant/shared control can establish first use alone; the full policy/PV state enters one lifecycle before becoming current. |
| Disputed currentness/recovery | Dispute adjudication, recovery authority, evidence integrity and preserved safety obligations | No single participant/shared control can resolve and enact recovery alone; uncertainty remains refused and history/consensus obligations are not bypassed. |

### 5.2 Open common-control, collusion, and availability choices

**OPEN:**

- Which administrative, personnel, provider, infrastructure, credential
  recovery, provisioning, backup, or restore relationships would invalidate
  independence, and what evidence will demonstrate the actual boundaries?
- What shared-control compromises must the design resist, beyond the stated
  rule that no shared control may let one actor authorize a protected action
  alone?
- What collusion tolerance is required? The single-participant goal does not
  specify it.
- Which actions may remain unavailable indefinitely when a participant,
  credential, or currentness/recovery evidence is lost?
- What quantitative availability or recovery targets, if any, are required?
  No target is selected.
- How are all five binding-authorization requirements preserved through
  succession, without automatic bypass or weakening?
- What independently reviewable evidence can justify any claimed separation
  when infrastructure is shared?

### 5.3 Prerequisite audits and independent evidence

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** Before any later implementation-entry
request, require:

1. Owner decisions for role boundaries, shared-control assumptions, collusion
   tolerance, unavailability, succession, conflict handling, and any
   availability targets.
2. A complete action-by-action source/use-path audit covering evidence
   creation, provisioning, credential issuance/recovery, authorization,
   policy/delegation changes, currentness, state persistence, restart,
   replacement, revocation, conflict adjudication, signing effects, stale
   handles, other processes, backups, restores, and recovery.
3. Independently reviewed evidence establishing accepted-genesis provenance
   and mapping-purpose delegation outside the policy bytes, exact policy
   authority/applicability, unique first-use/currentness, and the actual
   rollback/substitution boundary.
4. A threat-model review demonstrating that neither one participant nor one
   shared control can authorize any of the five actions alone, with explicit
   evidence for administrators, personnel, credential recovery, provisioning,
   infrastructure, providers, backups, and restoration domains.
5. A separately reviewed succession and dispute contract showing event
   recognition is not authority transfer; every replacement/recovery remains
   bindingly authorized; missing, stale, disputed, rolled-back, or uncertain
   evidence refuses; and no automatic override exists.
6. A reviewed consistency/restart/replacement contract proving that all
   decisions feed one Decision B / `CurrentAuthorizationOwner` lifecycle.
   Missing-owner refusal must be verified as an integration requirement; do not
   claim the D7 gap is fixed.
7. Separate proof for signer exclusivity, signing-history continuity,
   cross-process fencing, consensus-lock recovery, finality where applicable,
   and native-PQ authentication/continuity. These do not follow from current
   authorization.
8. Preservation of A50-F1: no identity, policy, issuer, or mapping metadata in
   `GenesisConfig.extra`. Execution cursor, VM state position, and snapshot
   height remain excluded from signer position and freshness.
9. For any separately authorized real Rust PR, retained local `cargo test` and
   `cargo check --lib --bin qbind-node` evidence from a clean worktree based on
   applicable main before merge; do not add intentionally red baseline targets
   to default cargo test discovery.

No evidence above is asserted to exist. No actual deployment is claimed to
meet the owner’s independence goal. Future controls remain **FUTURE / NOT
AUTHORIZED / NOT EXECUTED**. Any later authorized integration must start from
verified current main, contain only approved paths, and must not originate from
an inherited Route B or engine-handoff lineage.

## 6. Preserved boundaries and status

Do not treat a locally matching hash, unpersisted `authority_sequence`, or a
signer named in its own policy as independent provenance or currentness. Do
not repurpose bundle-signing, transport, bootstrap, or A33-F1 authority for
mapping-purpose authorization. Do not put identity, policy, issuer, or mapping
metadata in `GenesisConfig.extra`. These boundaries preserve the Route B
contract’s stated requirements
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:84-111,238-266`).

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**. No
authoritative carry-forward record is updated.

These operational statuses are recorded in the Route B contract at its own
commit `23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:357-366`.
