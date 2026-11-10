# Option-A Policy Semantics for the Five Protected Actions

## Status and labels

**SPECIFICATION-ONLY CANDIDATE.** This document describes the Option-A design
target: before a participant is lost, an independently authorized policy could
already permit qualifying remaining participants to decide a future protected
action, without lowering the authorization bar. It does not claim that a
satisfactory policy exists, that the target is feasible for every action, or
that any policy or mechanism is implemented. No participant, count, threshold,
credential, key, root, construction, storage, recovery procedure, or activation
policy is selected.

- **OWNER DECISION** is an explicit owner direction or standing requirement.
- **SOURCE FACT** is behavior established only by the cited pinned source.
- **CANDIDATE** is proposed semantics or sequencing, not an available
  capability.
- **HYPOTHETICAL** is an explanatory example, not a QBIND configuration.
- **ASSUMPTION** is a condition that would have to be established.
- **OPEN** identifies an unresolved policy choice, evidence gap, or proof
  obligation.

## 1. Reviewed inputs and boundaries

**SOURCE FACT:** Reviewed main is
`ae6464120b15dabe6e994ee983b3d80046d89722` (tree
`cd394644a3998d2e23c2e2d95b1767657b34f17d`). The reviewed unmerged inputs are:

| Input | Exact commit and tree | Relationship |
|---|---|---|
| Route B trust contract | `23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`, tree `1abd3237cfde990e347a00efacf822fab100b918` | Unmerged; parent is the reviewed main pin. |
| Shared-control / non-override succession candidate | `974c74e43cf957282cd612caa75c4c7f29d9f0b7`, tree `3e44110f8ac71730ee60efbaddeff60b6801ad8d` | Unmerged; parent is the reviewed main pin. |
| Continuity candidate | `5b7418a5436930584f1609b8c7a563e040ef5704`, tree `5329feab2b518f332e349bd990162fb607ca234c` | Unmerged; parent is the reviewed main pin. |
| Long-term succession candidate | `f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a`, tree `781f001acb6b5fc9f14c70f490417388855f0b03` | Unmerged; parent is the reviewed main pin. |

These unmerged documents are cited at their own revisions below; none is
represented as part of main.

**OWNER DECISION:** The five protected actions are: establishing/replacing
accepted-genesis provenance; delegating/replacing mapping-policy issuer
authority; approving/replacing an authorized mapping policy; establishing
first-use enrollment/current authorization; and resolving disputed currentness
or permitting recovery after lost, conflicting, or uncertain state. Each
requires binding independently operated authorization. One participant alone,
or one shared control that gives one actor effective sole authority, must not
be sufficient. Succession and continuity cannot lower that bar or override
consensus, signing-history, or recovery safeguards
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:35-62`;
`f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a`,
`docs/security/evidence/long-term-independent-authorization-recovery-succession-candidate-20261110.md:57-81`).

**OWNER DIRECTION:** For each action, investigate an already authorized policy
that allows a qualifying combination of remaining participants to decide after
a participant loss. This does **not** preapprove a particular future
provenance claim, delegation, policy, enrollment, conflict resolution, or
recovery outcome. Each remains a separate protected action requiring binding
authorization and trustworthy current evidence.

## 2. Candidate semantics shared by all five actions

For each action `a`, let `P_a` be a policy independently authorized before the
loss; `R` the participants available after the specified loss; `X_a` the exact
future decision request and its deployment, purpose, scope, and evidence; and
`E_a` the independently established evidence of authority, applicability,
currentness, and conflict state.

**CANDIDATE — Option A:** A future action may be decided after loss only if:

1. `P_a` was validly established before loss, and already authorizes the
   decision process and eligible participant combinations for `a`.
2. At least one combination in `R` satisfies the unchanged authorization
   conditions in `P_a`. Loss, silence, timeout, or an event report does not
   change `P_a` or count as a participant's authorization.
3. Binding authorization applies to the exact `X_a`; eligibility to decide is
   not approval of any particular result.
4. `E_a` remains authenticated, current, applicable, non-conflicting, and
   trustworthy across the relevant rollback/substitution domain.
5. No one participant or one compromised shared control can alone satisfy,
   bypass, alter, or make effective the authorization condition.
6. Separate signer, consensus, history, fencing, and recovery prerequisites
   for the contemplated effect are independently satisfied.

If any condition fails, the action is **unavailable**. Option A is not a
reduced threshold, emergency path, automatic successor, presumed consent, or
permission to use a historical policy.

**CANDIDATE — Option B:** If `P_a` does not permit any combination in `R` to
decide `a`, keep `a` unavailable. A policy change, participant replacement,
revocation, or recovery requires its own validly authorized action under an
applicable prior authority path. It cannot be smuggled in as continuation under
`P_a`.

**ASSUMPTION:** A policy may be able to specify safe, redundant decision
eligibility before loss. The actual contents, conflict semantics, evidence
source, independence of controls, and compatibility with each action have not
been demonstrated.

## 3. Per-action semantics and refusal contract

| Action | Exact subject/context the future decision must bind | What must have been authorized before loss; what `R` must still satisfy | Current, non-conflicting evidence | Separate protected change and refusal boundary |
|---|---|---|---|---|
| **1. Establish or replace accepted-genesis provenance** | The accepted genesis identity and version, deployment/environment, claimed provenance, scope, and whether this is an initial claim or a supersession. Exact encoding remains **OPEN**. | An independently authorized source must establish `P_1` and its eligible decision process before loss. After loss, `R` must satisfy the same `P_1` for the exact provenance decision. Eligibility does not attest a particular genesis. | Provenance authenticated independently of the genesis file and policy; evidence of applicable deployment scope, currentness, and no competing provenance/supersession. A local matching hash is not provenance. | Changing `P_1`, replacing an authorized participant, or adjudicating competing genesis claims is separately protected. Missing, stale, disputed, substituted, or rolled-back evidence means no provenance decision or dependent enrollment. |
| **2. Delegate or replace mapping-policy issuer authority** | The issuer authority, mapping-policy purpose, deployment/genesis scope, delegation interval/status, and whether the action delegates, succeeds, or revokes an issuer. | An independent prior authority must establish `P_2` and its loss-tolerant decision eligibility. `R` must satisfy that unchanged policy for the exact issuer/purpose/scope. A policy-named signer cannot supply its own delegation. | Authenticated delegation and succession/revocation state current for the applicable scope; evidence must originate outside the policy bytes being verified. | Changing `P_2`, changing the delegated purpose, replacing participants, or resolving competing issuer claims is separately protected. Missing, stale, wrong-purpose, conflicting, or rolled-back delegation means no issuer authority. |
| **3. Approve or replace an authorized mapping policy** | Exact policy identity/bytes and version; issuer and purpose authority; deployment/environment/genesis binding; applicability; and the proposed mapping value/domain. | An independently authorized policy must establish `P_3` before loss. `R` must satisfy it for the particular policy approval/replacement. Preauthorization of the process does not approve the future policy contents. | Independently authorized issuer delegation; exact policy authenticity; applicable genesis/deployment; currentness/succession and conflict evidence. A valid policy signature alone is not purpose authority or currentness. | Changing `P_3`, replacing the issuer, or changing the policy is separately protected. On absent, ambiguous, stale, conflicting, altered, or out-of-scope evidence, do not select a policy or fall back to stale mapping. |
| **4. Establish first-use enrollment or current authorization** | Unique deployment enrollment; accepted genesis; issuer delegation; exact policy/mapping; P/V authority and complete signing domain; first-use/currentness and conflict state. | A prior independent trust relationship—not the uninitialized policy or owner—must authorize `P_4` and its decision eligibility. If that prior authority does not exist, there is no Option-A policy to rely on. `R` must satisfy the already established policy for the exact enrollment. | Independently authenticated initial provisioning and first-use state; current, non-rollback evidence covering the same complete Decision B state. No empty local state, unpersisted sequence, or matching hash proves first use/currentness. | Changing `P_4`, replacing a participant, or recovering enrollment is separately protected. Without prior trust, unique first-use evidence, currentness, or no-conflict evidence, do not establish an owner, snapshot, or signing permission. |
| **5. Resolve disputed currentness or permit recovery** | The specific disputed state and evidence, currentness/succession claim, recovery subject/scope, proposed disposition, and safety/history obligations affected. | A valid prior authority must establish `P_5` and its independently operated decision process. `R` must satisfy unchanged `P_5` for this exact dispute; process eligibility does not predetermine its outcome. | Complete and trustworthy state/history; authenticated currentness and conflict evidence; authority to adjudicate and recover. Local refusal, old approval, VM/snapshot position, or an event report is insufficient. | Changing `P_5`, replacing participants, global revocation, conflict adjudication, and recovery outcomes are each protected as applicable. If authority, state, currentness, or safety prerequisites are missing or disputed, keep the affected action unavailable. |

The five actions and their authority distinctions are specified in the reviewed
succession candidate (`f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a`,
`docs/security/evidence/long-term-independent-authorization-recovery-succession-candidate-20261110.md:57-81`).
Route B requires provenance and mapping-purpose delegation before policy
authentication, and distinguishes policy authenticity, purpose authority,
applicability, currentness, first use, and signing permission
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-95`).

### Hypothetical examples — not a QBIND policy

**HYPOTHETICAL — eligibility survives loss:** A prior independently authorized
policy allows alternative participant combinations to decide action `a`. A
participant becomes unavailable, but `R` still contains a combination
preauthorized by that exact policy. Honest participants verify the exact
request and current evidence; no participant or shared control can alone meet
the binding authorization condition; no conflict or separate safety gate is
unresolved. That combination may decide `a` under the existing policy. No
future result is approved in advance. This example selects no participant
count, threshold, or mechanism.

**HYPOTHETICAL — insufficient authority:** Every combination authorized by
`P_a` requires unavailable participant `x`. The remaining participants cannot
decide `a` under `P_a`. They refuse; they cannot interpret `x`'s silence as
consent or amend the policy. Only a separate, validly authorized policy change
or succession could alter the rule, if one is possible.

## 4. First-use dependency chain

**CANDIDATE:** First use cannot bootstrap the authority needed to authenticate
itself. The required dependency chain is:

1. **Independent initial trust:** an owner-authorized trust relationship
   authenticates the provisioning input independently of the genesis file,
   policy bytes, or future `CurrentAuthorizationOwner`.
2. **Accepted-genesis provenance:** the input establishes the accepted genesis
   identity and deployment/environment context; local computation checks
   correspondence but does not create provenance.
3. **Mapping-purpose delegation:** prior authenticated authority explicitly
   delegates the mapping-policy purpose and applicable scope before a policy
   issuer is trusted. Bundle-signing, transport, bootstrap, and A33-F1
   authority are not substitutes.
4. **Policy and eligibility:** authenticate exact policy bytes, issuer,
   purpose, applicability, and the loss-tolerant decision rules. This establishes
   eligibility to make future decisions, not any future decision itself.
5. **Specific decision authorization:** independently bind authorization to
   each exact provenance, delegation, policy, enrollment, dispute, or recovery
   request under the relevant policy.
6. **Currentness and conflict check:** establish that this decision is current,
   unique, applicable, and not superseded, replayed, rolled back, or in conflict.
7. **One Decision B enrollment:** only the complete accepted state and evidence
   may feed the same proposed Decision B / `CurrentAuthorizationOwner`
   lifecycle; no detached mapping-only freshness state.

**ASSUMPTION / OPEN:** The initial trust relationship, its authority and
purpose, provisioning channel, custody, compromise boundary, and rollback/
substitution protection are not established by current source. A local matching
hash, unpersisted `authority_sequence`, or policy-named signer cannot fill this
gap. The Route B contract says no such provisioning input or process is
established (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:97-111`).

Preauthorizing a decision process does not establish that a later outcome is
valid or current. Recognition of death, incapacity, timeout, loss, or silence
does not transfer authority, change eligibility, establish freshness, or
authorize recovery (`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:141-175`).

## 5. Conflicts, shared control, and independent safety gates

### Overlapping eligible combinations

**HYPOTHETICAL:** Suppose an abstract prior policy allows two eligible
combinations that overlap in participant `q`. If two participants outside the
intersection see different currentness evidence, they may bind to different
requests; if `q` can authorize both, both requests may appear to satisfy their
respective combination. The overlap alone does not ensure a unique decision.
This assumes inconsistent or compromised currentness views and does not
describe actual QBIND behavior or select a policy.

Separate proof is required for:

- **Request binding:** every authorization is bound to the exact action,
  subject, scope, policy and proposed effect.
- **Conflict handling:** competing requests cannot both become current; no
  winner is chosen by arrival order or local preference.
- **Anti-equivocation:** no participant or shared control can authorize
  incompatible requests across views, processes, or restores.
- **Currentness and rollback:** evidence distinguishes the unique current state
  from replay, substitution or rollback.
- **Shared-control independence:** one administrator, credential-recovery
  authority, provisioning path, provider, backup or restore domain cannot let
  one actor alone meet the authorization condition.

A quorum argument, separate keys, or an in-process lock does not alone prove
these properties. The owner’s rule that shared-control compromise enabling
one actor to authorize alone fails the single-actor goal is recorded in the
shared-control candidate (`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:41-50,88-122`).
Additional collusion tolerance remains **OPEN**.

### One Decision B lifecycle

**CANDIDATE:** All five protected-action decisions, their currentness evidence,
and any separately authorized successor/policy change must be consumed by the
same Decision B enrollment / `CurrentAuthorizationOwner` lifecycle. State
replacement must not create parallel policy and P/V freshness generations.
The exact mapping is bound to the relevant v2 domain and used unchanged.
Execution cursor, VM state position, and snapshot height do not supply signer
position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:171-213,249-257`).

**SOURCE FACT:** At reviewed main, `CurrentAuthorizationOwner` has only an
unavailable production constructor; establishment from concrete observed state
is test-only (`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1045-1058`). Its local
admit/confirm ticket protects in-process replacement ordering, not durable
currentness or anti-rollback (`crates/qbind-node/src/genesis_consensus_authority.rs:1030-1043,1179-1205`).
The P/V `AuthorizedProposalVoteSnapshot` binds that owner to the exact verifier,
but the pinned source says an established production owner/snapshot is not
constructible (`crates/qbind-node/src/binary_consensus_loop.rs:1133-1190,1255-1313`).
The separate local signing-reservation journal explicitly supplies no durable
anti-rollback anchor and is not wired into production startup
(`crates/qbind-node/src/signing_reservation_journal.rs:17-28`).

**OPEN:** When P/V authority exists but the required current-authorization
owner/snapshot is missing, refusal before verification, signing, engine
mutation, or forwarding remains an integration requirement; this candidate
does not claim the D7 gap is fixed
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

Current authorization or succession authorization alone does not establish:

- signer exclusivity across copied keys, old instances, hosts, and alternate
  routes;
- signing-history continuity for reservations, results, and uncertain
  outcomes;
- cross-process fencing or stale-owner prevention;
- consensus-lock recovery or its supporting evidence;
- finality;
- permission to resolve disputes or recover state; or
- native-PQ authentication and continuity through delegation, replacement,
  and recovery.

Each remains a separate **OPEN** obligation
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:183-221`;
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:225-266`).

## 6. Five-action semantics, refusal, and proof matrix

| Action | Option-A proof obligation | Option-B/refusal condition | Feasibility gap |
|---|---|---|---|
| Accepted-genesis provenance | Prove prior policy authorization covers remaining participants, exact genesis/deployment context, current evidence, and no unilateral or shared-control path. | Refuse if `R` is not authorized or provenance/currentness conflicts. | Independent initial trust and current provenance source are **OPEN**. |
| Mapping-purpose delegation | Prove prior purpose/scope-specific delegation policy remains satisfied by `R`, independently of the issuer/policy. | Refuse without current authenticated delegation or if issuer/scope is disputed. | Delegating authority, succession lineage, purpose rules and PQ authentication are **OPEN**. |
| Policy approval/replacement | Prove the existing rule authorizes `R` for the exact policy request; signatures establish neither applicability nor currentness by themselves. | Refuse selection/fallback when exact policy, applicability, or currentness is uncertain. | Policy representation, issuer authority, currentness and conflict controls are **OPEN**. |
| First-use/current authorization | Prove a prior, independent trust relationship established policy eligibility and current evidence supports this exact enrollment under `P_4`. | Do not create an established owner/snapshot without independent initial authority and unique current enrollment evidence. | No existing production enrollment/currentness path; first-use authority and anti-rollback are **OPEN**. |
| Disputed currentness/recovery | Prove `R` remains authorized under a prior rule for this exact dispute/outcome and that history/safety obligations remain satisfied. | Refuse if authority, evidence, currentness, conflict resolution, or recovery permission is missing. | Conflict adjudication, recovery authority, rollback resistance, and safety evidence are **OPEN**. |

An action may be impossible under Option A if its prior policy has no valid
remaining combination after the relevant loss, if trustworthy current evidence
cannot survive that loss, or if shared control defeats the binding
authorization condition. In those cases the only safe outcome under this
candidate is unavailability until a separately authorized path exists; no
availability guarantee is implied.

## 7. Owner decisions and evidence gates

**OPEN — required owner decisions:**

- For each of the five actions, whether a future policy must preauthorize a
  loss-tolerant decision process or may leave the action unavailable until
  separately authorized succession/policy change.
- What request, subject, deployment, scope, and evidence each action’s
  authorization must bind.
- Which common-control domains would defeat independence and what additional
  collusion tolerance, if any, is required.
- What evidence establishes currentness, uniqueness, conflict resolution,
  succession, and recovery authority.
- How Option A can apply to first use without an existing policy or
  `CurrentAuthorizationOwner` serving as its own authority.
- What availability consequences are acceptable if the required independent
  authority or evidence is lost. No quantitative target is selected.

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** Before any implementation-entry
request, require independent review of:

1. The initial trust/provisioning relationship and its authority, purpose,
   scope, and rollback/substitution boundary.
2. The exact action semantics and pre-loss policy eligibility for each
   Option-A case; proof that a participant loss does not lower the bar.
3. A complete source/use-path and common-control audit across participant
   credentials, administrators, recovery, provisioning, infrastructure,
   providers, backups, restore, rollback, other processes, and all protected
   effects.
4. Request binding, conflicting-request handling, anti-equivocation, currentness,
   uniqueness, revocation/succession, and fail-closed behavior.
5. A unified Decision B lifecycle proof covering first use, replacement,
   restart, revocation, disputed evidence, and recovery; verify missing-owner
   refusal rather than claiming the D7 gap is fixed.
6. Separate evidence for signer exclusivity, signing-history continuity,
   cross-process fencing, consensus-lock recovery, finality where applicable,
   recovery authority, and native-PQ continuity.
7. A50-F1 preservation: no identity, policy, issuer, or mapping metadata in
   `GenesisConfig.extra`; execution cursor, VM state, and snapshot height stay
   outside signer position and freshness.
8. For any separately authorized real Rust PR, retained local `cargo test` and
   `cargo check --lib --bin qbind-node` evidence from a clean worktree based on
   applicable main before merge; no intentionally red baseline targets in
   default test discovery.

No evidence above is asserted to exist. No participant, count, threshold, key,
root, construction, storage, recovery mechanism, quantitative availability
target, or initial-DevNet authority model is selected. The founder-authorized
bootstrap decision is unchanged. Future controls remain **FUTURE / NOT
AUTHORIZED / NOT EXECUTED**.

## 8. Preserved status

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**. No
authoritative carry-forward record is updated.
