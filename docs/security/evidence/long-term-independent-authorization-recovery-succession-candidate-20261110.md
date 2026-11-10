# Long-Term Independent Authorization, Recovery, and Succession Candidate

## Status and scope

**SPECIFICATION-ONLY CANDIDATE.** This document records an owner-selected
long-term direction and requirements for further specification. It selects no
participants, participant count, threshold, credentials, trust roots,
cryptographic construction, storage, recovery procedure, or activation policy.
It authorizes no implementation, integration, enrollment, recovery, or
activation.

Labels are normative to this document:

- **SOURCE FACT** describes only behavior evidenced by the cited pinned source.
- **OWNER DECISION** records an explicitly selected requirement or direction.
- **CANDIDATE** describes a required future property, not an available mechanism.
- **ASSUMPTION** identifies a condition that would have to be established.
- **OPEN** identifies an unresolved decision, proof obligation, or source gap.

## 1. Pins and decision boundary

**SOURCE FACT:** This candidate is grounded in current main
`ae6464120b15dabe6e994ee983b3d80046d89722` (tree
`cd394644a3998d2e23c2e2d95b1767657b34f17d`) and the unmerged Route B contract
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918` (tree
`1abd3237cfde990e347a00efacf822fab100b918`, parent exactly the main pin).
Main source is cited only at the main pin; the Route B contract is cited only at
its own commit.

**OWNER DECISION:** The owner requires the long-term network to “design toward
independently operated authorization and recovery.” Binding independently
operated authorization is required for the five actions in §2. Advisory review
alone cannot authorize, withhold, or resolve any of them. Compromise of one
participant alone must not be sufficient to authorize one of these actions.
This is a requirement to specify and prove, not a claim about an existing
property.

This direction does not decide whether a single-controller model is acceptable
for initial DevNet and does not repurpose or overturn the existing
founder-authorized initial-DevNet bootstrap decision. That decision is limited
to its initial configuration scope and does not establish currentness,
continuity, recovery, or cross-host exclusive use
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:18-67`).

**SOURCE FACT:** The production `CurrentAuthorizationOwner` constructor remains
unavailable-only; concrete established state is test-only
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1045-1058`). The D10
signing-reservation journal is non-authorizing, has no whole-copy anti-rollback
anchor, and is not initialized by production startup
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/signing_reservation_journal.rs:7-28`). The D7 missing
owner refusal remains an **OPEN integration requirement**, not a closed
production gap
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

## 2. Action-by-action independence requirements

The authority classes below are functional descriptions, not selected roles,
people, or organizations. “Binding independent authorization” means that
authorization evidence from independently operated participants is required
for the action to proceed; advisory review may inform a decision but cannot
grant or veto it. No participant count or rule for combining authorizations is
selected here.

| Action | Proposed authorization subject and effect | Authority classes requiring independent operation | Single-participant compromise attempt | Required refusal | Proof obligation |
|---|---|---|---|---|---|
| **1. Establish or replace accepted-genesis provenance** | Bind an accepted genesis identity and deployment/environment context to independently established provenance. A replacement changes what deployment identity later authorization may rely on. A local hash comparison is not itself this decision. | The authority class permitted to attest accepted-genesis provenance must be distinct in control from the policy bytes and from the policy issuer. Any class authorizing replacement must be bound by the same independently operated authorization requirement. | A compromised participant could attest an attacker-selected genesis, misstate deployment context, or try to replace an accepted identity. | No enrollment or dependent authorization on missing, conflicting, stale, substituted, or unauthenticated provenance. | Show that no one participant can create, replace, or make effective accepted provenance without the required independently operated binding authorization; show evidence is not sourced solely from the policy or its rollback/substitution domain. |
| **2. Delegate or replace mapping-policy issuer authority** | Authorize a specified issuer for the runtime-to-wire mapping-policy purpose and applicable deployment/genesis scope; replacement changes who may issue policy authority. | The mapping-purpose delegation authority must be independently operated from the delegated policy issuer. Any successor-delegation authority must itself be independently authorized, not self-appointed by the successor. | A compromised participant could delegate to itself or an attacker, widen purpose/scope, or claim succession/revocation authority it does not hold. | Missing, wrong-purpose, out-of-scope, stale, conflicting, or unverified delegation means no policy authority. | Demonstrate that a single participant cannot grant or replace issuer authority alone; verify purpose/scope constraints, succession lineage, and that policy-named signers cannot self-authorize. |
| **3. Approve or replace an authorized mapping policy** | Approve exact policy identity/content and deployment/genesis applicability, or authorize a successor policy; the accepted mapping later flows unchanged to the relevant v2 signing domain. | The issuer must already have independently authorized mapping-purpose delegation. Where owner authorization is required for policy approval/replacement, those participants must be independently operated from the policy issuer and from the policy bytes. | A compromised issuer or approver could introduce a substituted mapping, mis-scope an otherwise valid policy, or present a historical policy as current. | Invalid, ambiguous, unsupported, altered, stale, conflicting, or unauthenticated policy means no policy selection, no fallback to an old value, and no P/V authority from that policy. | Prove that one participant alone cannot authorize an effective policy or successor; prove exact bytes, identity, scope, applicability, and currentness are all bound, not inferred from signature validity. |
| **4. Establish first-use enrollment or current authorization** | Establish that one applicable Decision B authorization is uniquely enrolled and currently authorizes the deployment, policy mapping, and P/V authority/domain. This is the point at which a future production owner/snapshot could become current. | Enrollment/currentness authority must be independently operated and rely on authenticated provenance, delegation, policy, and first-use/currentness evidence. It must not be merely the policy issuer or a local process declaring its own state current. | A compromised participant could claim an empty store means unused, replay old enrollment, or activate mismatched policy and P/V authority. | Do not create an established owner, verifier snapshot, or signing permission if enrollment/currentness is missing, uncertain, conflicting, stale, or rolled back. | Prove single-participant insufficiency and unique first-use under the relevant rollback threat; prove complete policy and P/V state enter one lifecycle before activation, without treating a local sequence as its own trust anchor. |
| **5. Resolve disputed currentness or permit recovery after lost, conflicting, or uncertain state** | Determine whether existing authorization remains current, whether replacement/revocation is effective, or whether recovery is permitted to re-establish availability. Recovery must not erase unresolved signing or consensus obligations. | Currentness adjudication and recovery authorization require independently operated binding authorization with authority separate from the claimant seeking recovery and from any policy whose status is disputed. Advisory reviewers do not resolve the dispute. | A compromised participant could declare its own preferred state current, suppress revocation, select a favorable conflict outcome, or seek a reset that erases history. | If authority, evidence, currentness, or recovery prerequisites cannot be established, remain unavailable. No automatic override, winner by arrival order, or “missing means never enrolled/signed” inference. | Prove that one participant cannot decide or enact the disputed outcome alone; demonstrate evidence completeness/currentness across the stated rollback domain and preservation of signing-history and consensus-safety obligations. |

The actions are intentionally distinct. Authenticating policy bytes does not
grant mapping-purpose authority; a valid delegation does not prove that the
policy is current; accepted-genesis provenance does not prove unique first use;
and current authorization does not itself permit recovery
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-95,217-228`).

## 3. Independence, common control, and collusion

**OWNER DECISION:** The required goal is that compromise of one participant
alone cannot provide sufficient binding authorization for any action in §2.

**CANDIDATE:** This goal requires independent operation to be demonstrated over
the whole authority path, including who can authorize, provision, recover,
replace, suppress, or roll back the evidence. A separate key is not proof of
independence. Multiple named operators do not establish independence if they
share effective control or consume a commonly substituted state.

Two independence questions must not be conflated:

1. **Evidence independence from policy:** Accepted-genesis provenance and
   mapping-purpose delegation must originate outside the policy bytes being
   verified. The policy cannot establish its own issuer, provenance, or
   currentness. A local matching hash, unpersisted `authority_sequence`, or
   policy-named signer is insufficient. The initial provisioning trust
   relationship and its rollback/substitution boundary remain open
   (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
   `docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:84-111`).
2. **Operational independence among participants:** Participants must not be
   treated as independent solely because they have different keys or labels.
   The owner must decide which common-control relationships defeat the
   single-participant-compromise goal and what evidence demonstrates separation.

For **each of the five actions**, review the following failure domains; the
candidate does not assert that any are independent today:

| Failure domain | Ways apparent independence can fail |
|---|---|
| Personnel and organization | Shared personnel, supervisors, ownership, appointment/removal powers, coercion, or coordinated decision-making can make nominally distinct participants one effective controller. |
| Credential custody and recovery | One administrator or recovery authority able to replace, reset, export, or exercise multiple credentials may authorize alone in practice. A separate key does not resolve common recovery control. |
| Provisioning and initial trust | A shared provisioning actor, enrollment path, or initial trust input can substitute every participant’s evidence before their separate review. |
| Administration and infrastructure | Shared privileged administrators, hosts, identity services, providers, networks, or operational tooling may permit one compromise to control multiple roles or alter evidence. |
| Backups and state management | Common backups, restore operators, replicated stale state, or common maintenance access may enable correlated loss or replacement. |
| Rollback and substitution | Participants may independently verify identical but rolled-back or substituted evidence. Operational separation does not establish currentness outside the relevant rollback domain. |
| Collusion and common failures | The number and combinations of colluding participants the model must tolerate, and the impact of provider-wide or organizational compromise, are **OPEN**. The single-participant goal does not imply any stronger collusion guarantee. |

**OPEN:** The owner has not chosen which role overlaps, shared administrators,
credential-recovery powers, common providers, or common rollback domains are
acceptable. Nor has the owner chosen a collusion tolerance beyond the explicit
single-participant-compromise goal. These assumptions require evidence and
independent review, not labels or key separation. The current bootstrap/recovery
trust model likewise warns that shared administrators/providers can collapse
separation and that no participant or infrastructure is established
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/devnet/QBIND_RUN_422_BOOTSTRAP_CREDENTIAL_RECOVERY_TRUST_MODEL.md:387-400`).

## 4. Succession and continuity

**CANDIDATE:** A succession path must itself be authorized under the applicable
binding independent-authorization requirement. No death, incapacity, timeout,
absence, lost credential, silence, or quorum unavailability automatically
appoints a successor, relaxes authorization, resolves a conflict, or permits
recovery.

| Event | Required future behavior | OPEN decisions and availability limit |
|---|---|---|
| Founder or participant death, incapacity, or prolonged absence | Preserve existing authority only while independently verifiable currentness and all other prerequisites remain valid. Any successor or role reassignment requires separately authorized succession. | What evidence can establish the event, who may recognize it, and how succession can be authorized if required participants are unavailable? No automatic successor is established. |
| Lost, compromised, or unavailable credentials | Treat authority as unavailable or suspect until separately authorized replacement/revocation and currentness are established. A replacement credential cannot self-authorize. | Who can authorize credential replacement without allowing one compromised participant to replace the authority unilaterally? What if the credential or its recovery evidence is irretrievably lost? |
| Participant replacement or authority succession | Authenticate the replacement under an independently authorized succession path; bind the change to the same deployment, purpose, and unified Decision B state; invalidate stale authority only through that lifecycle. | Who may initiate, authorize, and verify succession; how old authority is retired; and what evidence prevents a stale predecessor from acting? No procedure is selected. |
| Disagreement or conflicting evidence | Do not choose by arrival order, majority assertion without an approved rule, or local preference. Keep affected authority unavailable pending an authorized resolution. | Who can adjudicate, what evidence is authoritative, and whether resolution requires the same or separately scoped binding authorization are open. |
| Unavailable participants | Do not silently reduce participation requirements or convert advisory review into authorization. | Owner must decide acceptable delay and refusal cost. If required authority cannot be reached, authorization remains unavailable. |
| Lost, stale, rolled-back, or uncertain authorization state | Do not interpret absence as first use, accept a historical approval as current, or reset obligations. Re-establish currentness and continuity before restoring authority. | The trust source, rollback domain, recovery authority, and surviving evidence are unselected. If they are irretrievably lost, availability may be permanently unavailable; no recovery guarantee is made. |

A component may refuse or suspend its own action when evidence is absent or
suspect. That local refusal does **not** establish global revocation, grant
authority to another participant, permit recovery, or resolve a dispute.
Likewise, safe refusal and demonstrated recoverability are separate
properties. The Route B contract leaves currentness, recovery authority,
cross-process fencing, and continuity open
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:219-231,290-309`).

## 5. One Decision B lifecycle and separate safety properties

**CANDIDATE:** The action sequence must feed the same Decision B enrollment /
`CurrentAuthorizationOwner` lifecycle, not create a mapping-only freshness
owner:

1. Independently authenticated provisioning establishes accepted-genesis
   provenance and mapping-purpose delegation before policy authentication.
2. The delegated issuer’s exact policy is authenticated and checked for purpose,
   deployment/genesis binding, applicability, and policy identity.
3. Independently authorized first-use/currentness evidence binds provenance,
   delegation, policy/mapping, and the P/V authority plus complete v2 domain in
   one proposed Decision B state.
4. Only after that state and its non-rollback first-use/currentness status are
   established may a future production owner/snapshot become current.
5. Admission, replacement, revocation, restart, and recovery use that same
   lifecycle and invalidate stale admissions there. The resolved wire value
   flows unchanged into the applicable v2 domain; it is not re-derived
   downstream.

This is a sequencing requirement, not evidence that an atomic or durable
mechanism exists. The Route B contract explicitly says the production source,
persistence, and activation boundary do not exist; policy and P/V authority
must not use separate freshness generations
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:171-213`).

**OPEN:** When P/V authority is present but its required current-authorization
owner/snapshot is missing, the system must refuse before verification, signing,
engine mutation, or forwarding. The existing source gap is not claimed fixed;
the pinned contract marks this an open integration requirement
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

Current authorization is not proof of:

- **Signer exclusivity:** only one effective instance can use a key, including
  copied/exported keys and stale instances.
- **Signing-history continuity:** reservations, signed results, and uncertain
  outcomes survive restart and rollback.
- **Consensus safety / lock recovery:** the node’s committed state, lock, and
  required QC/TC/evidence are recovered consistently.
- **Finality or recovery authority:** an authorization decision does not itself
  establish finality or grant permission to recover disputed state.

These are separate proof obligations. Execution cursor, VM state position, and
snapshot height must not provide signer position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:249-257`).

## 6. Action requirements, assumptions, and proof obligations

| Action | Owner requirement | Candidate assumptions | Unresolved decisions | Required proof |
|---|---|---|---|---|
| Accepted-genesis provenance establish/replace | Binding independently operated authorization; one participant alone insufficient. | Evidence authority is trusted outside policy and relevant rollback/substitution domain. | Who may attest/replace; scope; common control; evidence source and succession. | Single-participant compromise cannot authorize; provenance is independently authenticated and current. |
| Mapping-purpose issuer delegation/replace | Binding independently operated authorization; purpose delegation precedes policy. | Delegator is distinct in effective control from issuer and cannot be self-appointed by issuer. | Scope/purpose boundaries; succession/revocation; credential recovery and shared administrators. | One participant cannot delegate or replace alone; delegation is purpose-bound and policy-independent. |
| Mapping policy approve/replace | Binding authorization, not advisory review; exact policy and applicable deployment bound. | Delegated issuer and any required approvers are independent in the threat domains claimed. | Which policy changes require authorization; allowed role overlap; stale-policy disposition. | One participant cannot make policy effective alone; authenticity, authority, applicability, and currentness each proved. |
| First use/current authorization | Binding independently operated enrollment/currentness authorization. | First-use evidence and currentness survive relevant rollback; state feeds one Decision B owner. | Who decides unique enrollment; persistent consistency and rollback boundary; no-owner behavior. | One participant cannot enroll alone; no circular provenance; policy/PV authority cannot split into freshness lifecycles. |
| Disputed currentness/recovery | Binding independent adjudication/recovery authorization; no automatic override. | Recovery evidence survives the failure domain and preserves signing/safety obligations. | Who resolves dispute; effect of unavailable/lost participants; whether recovery can ever be permanently unavailable. | One participant cannot resolve/enact alone; uncertain state remains refused; continuity and lock obligations survive. |

## 7. Owner choices still open

**OPEN — availability and common-control choices:**

- Which actors or organizations, if any, may hold more than one authority class;
  which shared personnel, administrators, providers, provisioning channels,
  credential-recovery controls, or backups defeat independence?
- Which single-participant compromise scenarios must be resisted, and what
  evidence will demonstrate that no participant has unilateral practical
  control?
- Beyond the required single-participant goal, which collusion and common
  infrastructure/provider failures must be tolerated? No stronger tolerance is
  implied.
- What happens to availability when independently operated participants
  disagree, are compromised, become unavailable, die, become incapacitated, or
  lose credentials or state? Can some cases remain unavailable indefinitely?
- What independently authorized succession path may replace authority, and
  what protections prevent that path from becoming an automatic bypass?
- Which actions require binding authorization versus independent review only?
  Review alone cannot authorize or resolve an action.
- How are these requirements separately evidenced for initial DevNet without
  deciding its single-controller acceptability or changing the existing
  founder-authorized bootstrap decision?

## 8. Evidence and review gates before any implementation entry

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** Any later implementation-entry
request requires, at minimum:

1. Owner decisions for every open authority boundary, action-specific binding
   participation requirement, role overlap, compromise/collusion assumptions,
   unavailability behavior, and succession/recovery limits.
2. Independently reviewed evidence for accepted-genesis provenance, purpose
   delegation, policy authentication/applicability, unique first use,
   currentness, revocation/succession, and rollback/substitution boundaries.
3. A complete source/use-path and threat-model review proving that compromise
   of one participant cannot authorize any listed action, including common
   provisioning, personnel, administrators, credential recovery,
   infrastructure, providers, backups, and state restoration.
4. A reviewed consistency/restart/replacement contract showing the same
   Decision B lifecycle governs policy and P/V currentness; explicit refusal
   coverage for missing, stale, conflicting, lost, substituted, rolled-back,
   and uncertain state.
5. Separate reviewed evidence for signer exclusivity, signing-history
   continuity, cross-process fencing, consensus-lock recovery, finality where
   applicable, and native-PQ authentication/continuity. None may be inferred
   from authorization or from a successful mapping.
6. Compliance with A50-F1: no identity, policy, issuer, or mapping metadata in
   `GenesisConfig.extra`. Execution cursor, VM position, and snapshot height
   remain excluded from signer position and freshness.
7. If a later separately authorized real Rust PR is considered, retained local
   `cargo test` and `cargo check --lib --bin qbind-node` transcripts from a
   clean worktree based on applicable main before merge; do not add
   intentionally red baseline targets to default cargo test discovery.

No evidence listed above is asserted to exist by this candidate. No implementation
or experiment is authorized. Any future repository change must start from
verified current main, contain only approved paths, and must not originate from
an inherited Route B or engine-handoff lineage. No PR is opened by this document.

## 9. Preserved status

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**. No
authoritative carry-forward record is updated.

These statuses match the reviewed Route B contract at
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:357-366`.
