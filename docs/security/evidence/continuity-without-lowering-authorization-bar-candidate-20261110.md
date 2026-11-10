# Continuity Without Lowering the Authorization Bar

## Status, scope, and evidence labels

**SPECIFICATION-ONLY CANDIDATE.** This document analyzes the owner’s continuity
goal after participant loss. It does not choose participants, counts,
thresholds, credentials, trust roots, cryptographic constructions, storage,
recovery mechanisms, or an activation policy. It is not evidence that
continuity is feasible in production and authorizes no implementation,
integration, enrollment, recovery, startup, migration, or activation.

- **OWNER DECISION** states an explicitly selected requirement.
- **SOURCE FACT** states a fact established by the exact cited source.
- **HYPOTHETICAL EXAMPLE** illustrates a logical case only.
- **CANDIDATE** describes a future property or sequencing requirement, not an
  existing mechanism.
- **ASSUMPTION** identifies a condition that must hold.
- **OPEN** identifies an unresolved policy choice, evidence gap, or proof
  obligation.

## 1. Reviewed inputs and unchanged requirements

**SOURCE FACT:** This candidate is grounded in main
`ae6464120b15dabe6e994ee983b3d80046d89722` (tree
`cd394644a3998d2e23c2e2d95b1767657b34f17d`), the reviewed shared-control and
non-override succession candidate
`974c74e43cf957282cd612caa75c4c7f29d9f0b7` (tree
`3e44110f8ac71730ee60efbaddeff60b6801ad8d`), the earlier long-term succession
candidate `f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a` (tree
`781f001acb6b5fc9f14c70f490417388855f0b03`), and the Route B contract
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918` (tree
`1abd3237cfde990e347a00efacf822fab100b918`). Each unmerged document is cited
at its own commit; none is represented as main.

**OWNER DECISION:** The owner’s continuity goal is to investigate continued
operation after one participant dies, becomes incapacitated, or is otherwise
unavailable, **provided** the remaining participants satisfy the independently
authorized policy and the necessary trustworthy evidence remains available.
This goal does not lower authorization requirements, automatically transfer
authority, or override consensus-safety, signing-history, or recovery
safeguards. It is a goal to specify and prove, not an established guarantee.

The following remain unchanged after participant loss:

1. The already authorized policy and its binding-authorization bar remain in
   force. An unavailable participant is not silently removed from that policy.
2. The required provenance, delegation, policy applicability, currentness, and
   authority boundaries remain required.
3. The single-participant/single-actor compromise goal remains required.
   Participant loss does not permit a shared control or remaining participant
   to authorize alone where the policy requires otherwise.
4. There is no automatic authority transfer or safety override. Policy change,
   participant replacement, and recovery are distinct protected actions and
   each requires its own applicable binding authorization and evidence.

These are consistent with the owner decisions in the reviewed shared-control
candidate
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:41-62`)
and the earlier succession candidate
(`f0858dbfaeb8ff11f94fcbeacb3a4b027b17e69a`,
`docs/security/evidence/long-term-independent-authorization-recovery-succession-candidate-20261110.md:57-81,141-168`).

**OWNER DECISION:** No recovery deadline or quantitative availability target
has been set. If sufficient authority or trustworthy evidence cannot be
established, the affected action stays unavailable. If necessary authority or
evidence is irretrievably lost, recovery may remain unavailable indefinitely.
Additional collusion tolerance beyond the single-participant/single-actor goal
remains **OPEN**.

**SOURCE FACT:** The existing founder-authorized bootstrap decision concerns
the initial DevNet configuration and does not establish freshness, signing
continuity, recovery, or cross-host exclusive use
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:18-67`).
This document neither decides the initial-DevNet authority model nor changes
that bootstrap decision.

## 2. Logical conditions for continuation

Let **P** denote the already authorized policy for the action at issue, and
**R** the participants still available. These symbols describe a logical
condition, not a selected policy, group, count, quorum, or mechanism.

**CANDIDATE:** Continuing under P after a participant becomes unavailable is
logically possible only if all of the following hold:

- P remains current, applicable, and independently authorized; the event does
  not itself amend P.
- Under P as already authorized, R satisfies the binding authorization
  condition for the particular action. No requirement is silently removed,
  reduced, or replaced.
- The evidence needed to establish the action, its authorization, currentness,
  and relevant conflict status is still trustworthy and available.
- The loss event is not used as a substitute for authorization to change P,
  replace a participant, revoke authority, or recover state.
- All separate signing-history, consensus-safety, exclusivity, and recovery
  prerequisites for the resulting effect are independently satisfied.

**HYPOTHETICAL EXAMPLE — continuation under unchanged policy:** Suppose P
already defines an authorization condition under which the available set R can
authorize a particular ordinary action without the unavailable participant.
If P is still current, all evidence remains trustworthy, no conflict exists,
and separate safety prerequisites hold, the action could be authorized under
P without changing P. This illustrates logical possibility only; it does not
assert that QBIND has such a policy or that any action is production-ready.

**HYPOTHETICAL EXAMPLE — insufficient remaining authority:** Suppose P
requires an authorization contribution that the unavailable participant can
no longer provide, and R therefore does not satisfy P. The action must remain
unavailable. The participants cannot count the loss as consent, lower P’s
requirements, or use ordinary continuation as a replacement-policy path.

Changing P, replacing the participant, revoking an authority, or permitting
recovery is not “continuing under P.” Each is a separate protected action and
must meet its own binding authorization requirement. Whether P already defines
a valid path for any such event is **OPEN**; no such path is assumed here.

## 3. Safety and availability scenarios

| Scenario | Continuation condition | Required outcome if condition is not established | Status of further assumptions |
|---|---|---|---|
| One participant unavailable; R satisfies unchanged P and trustworthy current evidence remains | May continue only for the action and scope that P already authorizes, with currentness and all separate safety gates satisfied. | Refuse if P’s condition, evidence, currentness, or a required safety prerequisite is uncertain. | **OWNER DECISION:** investigate this case. **OPEN:** whether any eventual policy permits it and what evidence proves satisfaction. |
| One participant unavailable; R does not satisfy P | No continuation under P. A policy change or participant replacement would be a separate protected action. | Keep the action unavailable; do not lower or reinterpret P. | **OWNER DECISION:** authorization bar is unchanged. **OPEN:** future succession/policy rules and their evidence. |
| One participant unavailable while another is compromised | Continue only if the existing authorization condition is still valid and the compromise has not enabled that actor to satisfy or alter it alone; trustworthy evidence and separate safety gates must remain. | Refuse where the compromised actor, alone or through a shared control, could authorize, alter, or make current the action. | **OWNER DECISION:** single-participant/single-actor protection remains. **OPEN:** which additional collusion cases are tolerated. |
| Conflicting authorizations or disputed currentness | No continuation based on selecting the more recent arrival, local preference, or a component’s unilateral statement. | Keep affected authorization unavailable pending the applicable independently authorized resolution and trustworthy evidence. | **OPEN:** dispute authority, evidence rules, and whether resolution is possible after loss. |
| Shared-control compromise affecting multiple participants | Continue only if evidence shows the control cannot make one actor alone authorize or alter the action and the affected evidence remains trustworthy. Shared infrastructure alone is not a pass/fail. | Refuse if compromise can defeat the binding authorization bar or invalidate evidence integrity/currentness. | **OWNER DECISION:** a shared control that enables one actor to authorize alone fails the goal. **OPEN:** additional common-failure and collusion tolerance. |
| Lost, stale, rolled-back, substituted, or unavailable evidence | Continue only if the required authoritative evidence can still be established independently and is current. | Refuse; do not infer first use, latestness, or authority from missing local state, matching hash, or an old approval. | **SOURCE FACT:** Route B rejects these inferences and requires refusal for uncertain evidence (`23c3c2c…:84-111,217-228`). Exact future evidence remains **OPEN**. |
| Sufficient authority or evidence irretrievably lost, with no authorized succession path | No demonstrated basis for continuation or recovery. | The affected action may remain unavailable indefinitely. Do not promise recovery or install an automatic successor. | **OWNER DECISION:** indefinite unavailability is permitted. **OPEN:** any future separately authorized succession path. |

No participant count or quorum-intersection argument by itself proves
authorization correctness, unique currentness, non-rollback evidence,
non-equivocation, safe signing, or valid recovery. Such claims require
independent review of the policy semantics, evidence provenance and currentness,
state transition and rollback boundaries, enforcement path, and safety
properties. The Route B contract explicitly distinguishes a valid policy,
purpose authority, applicability, currentness, first use, and signing
permission (`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:82-95`).

## 4. Decision B transitions and refusal boundaries

**CANDIDATE:** Every transition affecting provenance, issuer delegation,
policy, first use, current authorization, participant replacement, revocation,
or recovery must feed the same Decision B enrollment /
`CurrentAuthorizationOwner` lifecycle. No separate participant-loss,
succession, or mapping-policy freshness state may independently authorize P/V
effects.

| Transition | Required future sequence | Refusal boundary |
|---|---|---|
| Continue under existing policy after participant loss | Re-evaluate the unchanged, current policy for the specific action; establish that available participants satisfy its binding authorization condition; revalidate necessary evidence and separate safety gates; then use the same current Decision B owner. | Refuse if the remaining participants do not satisfy the existing policy, if evidence/currentness is uncertain, or if any separate safety prerequisite is missing. |
| Change policy to account for future participant availability | Treat policy approval/replacement as a protected action; require binding independent authorization under an already valid authority path; establish applicability, succession, currentness, and conflict status; commit it into the same Decision B lifecycle before use. | Refuse if the current authority cannot authorize the change, no currentness evidence exists, or the change would rely on its own policy or a disconnected freshness generation. |
| Replace an unavailable participant | Recognize the event separately from authority transfer; obtain independently authorized replacement and scope; reconcile predecessor authority, currentness, and outstanding obligations; update the same Decision B state. | Refuse on missing/disputed event evidence, missing binding authorization, stale predecessor/successor evidence, or unresolved safety/history obligations. No automatic transfer. |
| Revoke or suspend authority | Establish the authority and scope to revoke/suspend, current evidence, and effect through the same lifecycle. A local component may fail closed for itself but does not establish global revocation. | Refuse to treat local refusal as global status or permission to replace/recover. Conflicting or unverifiable revocation state leaves affected actions unavailable. |
| Recover after lost/conflicting state | Require separately authorized recovery, current trustworthy evidence, and independent satisfaction of signing-history and consensus-safety prerequisites; re-establish one coherent Decision B state. | Refuse if authority, evidence, currentness, or separate safety obligations cannot be proved. No automatic reset, stale-state fallback, or history erasure. |

The Route B contract requires policy and P/V authority to enter the same
Decision B lifecycle, prohibits a detached freshness generation, and says
missing or uncertain state must not become an established owner
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:171-213,219-228`).

**SOURCE FACT:** At pinned main, `CurrentAuthorizationOwner` has only a
production-reachable unavailable constructor; establishment is test-only
(`ae6464120b15dabe6e994ee983b3d80046d89722`,
`crates/qbind-node/src/genesis_consensus_authority.rs:1045-1058`). The missing
required owner/snapshot when P/V authority is present remains an **OPEN**
integration requirement, not a fixed production behavior
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:193-200`).

### Separate safety properties

Current authorization, a valid succession decision, or permission to continue
under P does **not** by itself establish:

- **Signer exclusivity:** one effective signing instance across copied keys,
  hosts, old instances, administrators, and alternate signing routes.
- **Signing-history continuity:** preservation and correct handling of
  reservations, signatures, and uncertain outcomes across restart or rollback.
- **Consensus-lock recovery:** correct committed history, lock, and supporting
  evidence after restart or restore.
- **Fencing:** prevention of stale or concurrent processes from acting.
- **Finality:** validity of the relevant consensus/finality result.
- **Native-PQ continuity:** authenticated authority and trust continuity across
  provisioning, policy succession, participant replacement, and recovery.
- **Recovery authority:** permission to resolve disputed state or recover a
  participant’s operation.

Each remains a separate **OPEN** proof obligation. The reviewed succession
candidate likewise separates current authorization from signer exclusivity,
signing history, consensus safety, finality, and recovery permission
(`974c74e43cf957282cd612caa75c4c7f29d9f0b7`,
`docs/security/evidence/shared-control-non-override-succession-specification-candidate-20261110.md:183-221`).

Execution cursor, VM state position, and snapshot height must not supply signer
position or freshness
(`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:249-257`).

## 5. Conditions and outcomes

| Condition | Authorization status | Evidence/safety status | Outcome |
|---|---|---|---|
| Remaining participants satisfy unchanged P | Existing policy remains applicable and current | Required evidence and separate safety gates remain trustworthy and satisfied | Continuation is logically possible under P for its authorized scope; not a production guarantee. |
| Remaining participants do not satisfy P | Binding authorization condition is unmet | Any available evidence does not cure the missing authorization | Refuse; do not lower P. |
| Participant unavailable and another compromised | Must still satisfy unchanged P without unilateral compromised authority | Must establish compromise has not enabled shared-control bypass and evidence remains trustworthy | Continue only if both are proved; otherwise refuse. |
| Conflicting authorization/currentness claims | No unambiguous applicable authorization | Conflict is unresolved or evidence is suspect | Refuse affected action; no arrival-order winner. |
| Shared-control compromise could authorize alone | Independence requirement fails | Claimed evidence/control separation is insufficient | Refuse affected action; arrangement does not satisfy the owner’s goal. |
| Evidence lost, stale, rolled back, substituted, or unavailable | Cannot establish the required current authorization | Required trustworthy evidence absent | Refuse; missing state is not first use or permission. |
| No sufficient authority/evidence and no authorized succession path | No valid authorization path can be established | State or evidence may be irretrievably lost | Remain unavailable indefinitely if necessary; no recovery promise. |

## 6. Unresolved policy, evidence, and review choices

**OPEN — policy design:** Whether an already authorized policy permits any
remaining participants to authorize ordinary actions after a participant is
unavailable; what scope that permission covers; how currentness and conflicts
are established; and which changes require a separate policy replacement.

**OPEN — succession:** What event evidence can establish death, incapacity,
prolonged absence, credential loss, or compromise; who may recognize it; what
authority can authorize participant replacement; how stale predecessors are
prevented from acting; and which authority/evidence losses may make recovery
permanently unavailable.

**OPEN — common control and collusion:** Which shared administrator,
credential-recovery, provisioning, infrastructure, provider, backup, or
rollback failures defeat the single-actor goal; what evidence demonstrates
actual boundaries; and what collusion tolerance beyond one participant/actor
is required. No quorum intersection alone settles these questions.

**OPEN — availability:** No recovery deadline or quantitative availability
target exists. The owner has not chosen how long actions may remain unavailable,
what loss scenarios may be unrecoverable, or whether any future policy may
permit continued operation in specific participant-loss cases.

**OPEN — initial DevNet:** This candidate does not decide the initial-DevNet
authority model or change the founder-authorized bootstrap decision.

### Proof obligations before implementation entry

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** Any later implementation-entry
request requires, at minimum:

1. An owner-approved policy meaning for continuation after participant loss,
   including explicit distinction among continuing under an unchanged policy,
   changing that policy, replacing a participant, revoking authority, and
   recovering state.
2. Independent review proving the binding-authorization condition remains
   satisfied after any permitted participant loss and that no participant or
   shared control can authorize alone.
3. Evidence that accepted-genesis provenance and mapping-purpose delegation
   originate outside policy bytes; policy identity, applicability, currentness,
   unique first use, revocation, and succession are bound to one coherent
   Decision B lifecycle. A matching local hash, unpersisted
   `authority_sequence`, or policy-named signer is insufficient.
4. A complete source/use-path audit for policy evaluation, enrollment, owner
   construction, every P/V read/write/effect path, replacement, revocation,
   restart, recovery, stale handles, other processes, shared administrators,
   credential recovery, provisioning, infrastructure, providers, backups, and
   rollback/substitution.
5. Separate threat-model and evidence review for signer exclusivity,
   signing-history continuity, fencing, consensus-lock recovery, finality
   where applicable, and native-PQ continuity.
6. Explicit refusal evidence for unmet policy authorization, unavailable
   participants, compromised participants/shared controls, conflicting
   currentness, lost/stale/rolled-back evidence, and irreversible loss of
   authority or evidence.
7. Preservation of A50-F1: no identity, policy, issuer, or mapping metadata in
   `GenesisConfig.extra`; execution cursor, VM state position, and snapshot
   height excluded from signer position and freshness.
8. For any separately authorized real Rust PR, retained local `cargo test` and
   `cargo check --lib --bin qbind-node` evidence from a clean worktree based on
   applicable main before merge. Do not add intentionally red baseline targets
   to default cargo test discovery.

No such proof or implementation is asserted here. No code, tests, experiments,
enrollment, startup, migration, integration, or activation is authorized. Any
future authorized integration must start from verified current main, contain
only approved paths, and must not originate from an inherited Route B or
engine-handoff lineage.

## 7. Preserved status

**A50-F1, A23-F1, A33-F1/E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**. No
authoritative carry-forward record is updated.

These statuses are recorded in the Route B contract at its own commit
`23c3c2c75d7ca7cd56ed93699cdebb1cfbd29918`,
`docs/security/evidence/genesis-bound-route-b-independent-first-use-trust-currentness-contract-20261110.md:357-366`.
