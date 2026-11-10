# Genesis-Bound Route B Independent First-Use Trust and Currentness Contract

## Status, scope, and evidence labels

**SPECIFICATION-ONLY CANDIDATE — INDEPENDENT REVIEW REQUIRED.** This document
does not authorize an implementation, capability, trust root, key, issuer,
construction, format, provisioning procedure, storage mechanism, recovery
authority, resolver, experiment, wiring, startup, migration, integration,
signing, deployment, or activation.

**OWNER DIRECTION:** Independently authenticated deployment provisioning is the
primary Route B specification candidate. The selected direction is a
deployment policy bound to an independently authenticated accepted genesis.
This direction authorizes investigation and specification only; it does not
approve any trust input or mechanism. Route B's policy remains the mapping
source. The separately authenticated mapping-association alternative remains
**UNSELECTED**.

**CURRENT FEASIBILITY: BLOCKED as a source-supported first-use path.** Current
QBIND source does not establish an independent provisioning input,
mapping-purpose issuer delegation, or a production currentness/enrollment
lifecycle for Route B. The sequence below is conditional and does not claim
that any prerequisite exists.

The terms below distinguish evidence from proposals:

- **SOURCE FACT** — directly established by the cited pinned source.
- **OWNER DECISION** — the scope or direction explicitly authorized by the
  owner; it is not evidence that a mechanism exists.
- **CANDIDATE** — a proposed contract requirement or sequence for review.
- **ASSUMPTION** — an external dependency that a future design would have to
  authenticate or justify; it is not established by this document.
- **OPEN** — unresolved, unavailable, or not demonstrated.

### Pins

| Evidence | Exact commit, tree, and parent |
|---|---|
| Current reviewed `main` source and documents | `ae6464120b15dabe6e994ee983b3d80046d89722`; tree `cd394644a3998d2e23c2e2d95b1767657b34f17d`; parents `677d5ef3aae4b944ea26fbd0824476b4f766fa89`, `6529f8ed80b569fbe8a70e2d28dede8329954773` |
| Reviewed first-use model (read-only reference; not this branch's base) | `b4736b6882b33fd91f0fdfa849ca1acb1718a2e3`; tree `7952c20747c6a645583ae38977a5bba09408699a`; parent `f67b944ce25bb67b547d01533319ac2bff0f6ad6` |
| Prior Route B deployment-policy specification (read-only reference) | `f67b944ce25bb67b547d01533319ac2bff0f6ad6`; tree `95aa28a7f520d0f4f29208b592df1ad99a5014f1`; parent `050008f19dce64795a7b52c3e0c6cc1c73f27187` |

The first-use model already separates accepted-genesis provenance,
mapping-purpose issuer delegation, policy authentication, binding and
applicability, currentness, and signing permission. It leaves the independent
provisioning input, evidence of issuer delegation, first-use enrollment,
currentness/anti-rollback source, and restart/recovery lifecycle open
(`b4736b6882b33fd91f0fdfa849ca1acb1718a2e3`,
`docs/security/evidence/genesis-bound-route-b-first-use-trust-model-20261110.md:37-130,175-205`).
This contract develops one coherent candidate lifecycle for those unresolved
dependencies. It does not claim that they are source-supported today.

## 1. Trust model and dependency sequence

**CANDIDATE:** No policy can be its own trust anchor. The sequence must begin
with deployment-provisioning evidence authenticated through an independent,
owner-authorized trust relationship. That evidence must establish the accepted
genesis provenance and a delegation for the mapping-policy purpose before the
policy is examined as authority. An independent root, an external
authorization assumption, or an equivalent already trusted provisioning
relationship is unavoidable: cryptographic verification cannot establish who
was entitled to provision the initial trust input.

The candidate flow is:

```text
independently authenticated provisioning input
    ├── accepted-genesis identity + provenance
    └── mapping-purpose issuer delegation
            ↓
authenticated policy bytes
            ↓
genesis / deployment binding + applicability
            ↓
independent currentness and first-use decision
            ↓
one Decision B current-authorization lifecycle
            ↓
exact policy mapping value in the v2 signing domain
```

| Step | Input and supplier | Independent check and binding | Undischarged assumption | Refusal / unavailable outcome |
|---|---|---|---|---|
| 0. Provisioning trust | A deployment-provisioning input supplied through a future owner-authorized channel. The channel, root, credentials, custody, and procedure are not selected. | Authenticate the exact input independently of the genesis file and policy it will authorize. Bind its purpose and scope to the intended deployment and environment. | **ASSUMPTION / OPEN:** the initial trust relationship is authentic, uncompromised, current, and outside the relevant substitution/rollback domain. A trust chain must terminate at an independently accepted root or external decision. | Missing, ambiguous, conflicting, stale, substituted, or unverifiable provisioning evidence means no first-use enrollment and no authorization. |
| 1. Accepted-genesis provenance | Authenticated provisioning evidence names the accepted genesis identity and its deployment/environment context. The genesis configuration is supplied separately. | Parse the configured genesis and compare its reviewed canonical identity to the independently authenticated accepted identity. Keep provenance separate from the local hash calculation and from the policy. | **OPEN:** who accepts the genesis, how evidence is delivered, and how the identity remains current. A computed/matching hash alone proves neither provenance nor currentness. | Missing or conflicting provenance, wrong environment, unsupported identity version, or mismatch refuses. Do not substitute a genesis identity named only by the policy. |
| 2. Issuer delegation | Authenticated provisioning evidence or a separately authenticated delegation supplied by an authority already trusted for this purpose. | Verify that it explicitly authorizes a particular issuer for the **runtime-to-wire mapping-policy purpose**, in the applicable deployment/genesis scope. Verify this before trusting the policy. | **OPEN:** delegation authority, exact purpose grammar, scope, succession, revocation, and PQ authentication. A signer named by its own policy is circular and insufficient. | Missing, wrong-purpose, out-of-scope, expired/stale, conflicting, or unauthenticated delegation refuses. No bundle-signing, transport, bootstrap, or A33-F1 authority substitution. |
| 3. Policy-byte authentication | One policy candidate supplied by an untrusted source or local storage. | Parse one unambiguous supported representation; authenticate its exact canonical bytes under the approved native post-quantum construction; verify the signing issuer against step 2. | **OPEN:** construction, parameters, key identity, canonical format, issuer lifecycle, and demonstrated security. | Invalid, ambiguous, duplicate, malformed, unsupported, altered, or unavailable policy refuses. A valid signature alone does not establish purpose authority or currentness. |
| 4. Binding and applicability | Authenticated policy plus independently established deployment and genesis context. | Check purpose, deployment/environment, accepted genesis identity, full runtime `u64`, expected wire `u32`, version, scope, and applicability as separate propositions. Authenticate the binding to the same deployment and genesis; do not infer context from incoming messages. | **OPEN:** exact policy schema, identity encoding, canonicalization, and applicability rules. | Any missing, inconsistent, conflicting, substituted, ambiguous, or out-of-range required value refuses. Do not guess, cast, truncate, default, or select by arrival order. |
| 5. Currentness and first use | Independently authenticated currentness/succession evidence and trusted first-use state, supplied by a future source. | Establish exactly one current applicable policy and authorized issuer; verify replacement/revocation and anti-rollback state. Establish whether this is a unique permitted enrollment, not merely a valid historical policy. | **OPEN:** freshness anchor, state owner, durability, rollback domain, conflict adjudication, recovery authority, and first-use enrollment. An unpersisted sequence or signed timestamp is not independent currentness. | Stale, replayed, rolled-back, superseded, conflicting, or unavailable state yields refusal/unavailability. Never interpret missing state as “never enrolled.” |
| 6. Decision B enrollment | The complete verified evidence set from steps 0–5, including the accepted genesis, issuer delegation, policy identity, mapping, and currentness decision. | Feed it into the same proposed current-authorization lifecycle that governs Proposal/Vote authority. Bind the mapping and the authority it enables to one deployment/currentness decision and one lifecycle generation. | **OPEN:** the source, persistence and activation boundary do not exist as a production lifecycle. The existing owner is in-process bookkeeping, not durable enrollment or anti-rollback. | If enrollment cannot be durably/currently established, do not create an established owner, signing snapshot, or signing permission. |
| 7. Exact mapping handoff | The single policy mapping accepted in step 6. | Pass the resolved wire `u32` unchanged into the applicable v2 signing domain. Bind it to the same accepted genesis, deployment, and Decision B authority; downstream use must not re-derive it. | **OPEN:** production resolver and authenticated source path do not exist. | Missing or changed value, mismatch, or unavailable provenance refuses. A mapping result alone confers no authority. |

Policy-byte authenticity, issuer authorization, accepted-genesis provenance,
binding, applicability, currentness, first-use authorization, and signing
permission are distinct propositions. None can be inferred from another.

### Non-circularity and the unavoidable initial assumption

**CANDIDATE:** The trust input at step 0 must be authenticated without relying
on the policy, a hash supplied by the same untrusted source, or a signer named
inside that policy. It may authenticate both the accepted-genesis provenance
and mapping-purpose delegation only if its own authenticated purpose and scope
explicitly authorize those claims. The policy cannot bootstrap the authority
used to authenticate itself.

**ASSUMPTION:** The first provisioned trust relationship is accepted by an
owner-controlled process outside the candidate policy's authority. That
process's trust basis and rollback boundary must be specified. No design can
remove the need for an initial independent trust assumption; it can only state
and constrain it. No such input, process, or evidence is established by current
QBIND source.

## 2. Decision B integration — one coherent lifecycle

### Source-established interfaces and gaps

- **SOURCE FACT:** `GenesisConsensusAuthority::authorize_current_state`
  rejects missing storage and storage without a committed epoch; it compares
  established state against the authority's founding configuration
  (`ae6464120b15dabe6e994ee983b3d80046d89722`,
  `crates/qbind-node/src/genesis_consensus_authority.rs:868-890`).
- **SOURCE FACT:** `CurrentAuthorizationOwner` privately holds a candidate
  authority and current state. Its production-reachable constructor is
  `unavailable`; `admit` checks current state and returns an owner/generation-
  bound ticket; `confirm` rejects foreign, stale, or exhausted tickets.
  `Established` construction is `cfg(test)` only. Its owner identity and
  generation are process-local, not durable anti-rollback
  (`crates/qbind-node/src/genesis_consensus_authority.rs:942-956,1066-1146,1179-1238`).
- **SOURCE FACT:** `AuthorizedProposalVoteSnapshot::try_bind` checks that the
  verifier corresponds to the owner's membership, key provider, genesis,
  commitment, runtime-chain label, and expected wire chain ID. It does not
  authenticate the provenance of those values. Production genesis authority
  sets `authorized_wire_chain_id` to `None`, and the snapshot cannot bind a
  verifier without an authorized wire value
  (`crates/qbind-node/src/genesis_consensus_authority.rs:188,439,769-770`;
  `crates/qbind-node/src/binary_consensus_loop.rs:1133-1190,1258-1313`).
- **SOURCE FACT:** the inbound Required path rejects a present P/V verifier
  with no current-authorization snapshot; outbound Required admission also
  rejects an absent snapshot before signing. These local refusal branches do
  not supply current authorization. Production config has
  `proposal_vote_authority: None`, and genesis-authority activation is refused
  (`crates/qbind-node/src/binary_consensus_loop.rs:6247-6335,5531-5630`;
  `crates/qbind-node/src/binary_consensus_loop.rs:3140-3150`;
  `crates/qbind-node/src/main.rs:5428-5435,6165-6172`).
- **SOURCE FACT:** the current owner/ticket is not a durable lifecycle; the
  current authority-lifecycle contract explicitly separates activation
  authorization, currentness, and signing-history continuity
  (`ae6464120b15dabe6e994ee983b3d80046d89722`,
  `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md:112-149,210-234,417-426,494-519,524-557`).

**OPEN:** no source-supported production interface currently consumes Route B
provisioning, independently authenticates a mapping-purpose delegation,
establishes Route B currentness, or enrolls it into an established
`CurrentAuthorizationOwner`. The present model's `LocalAuthorizationState`
does not constitute independently authenticated Route B evidence. No
production resolver, authorized wire mapping, Decision B persistence, or
activation route is established.

### Candidate lifecycle (proposed interfaces, not existing types)

The proposal is to integrate the Route B evidence into the existing
Decision B/current-authorization lifecycle—not to build an independent
mapping-policy freshness store.

1. **Verify before enrollment.** A proposed verifier consumes the
   independently authenticated provisioning input, accepted-genesis
   provenance, mapping-purpose delegation, exact policy bytes, binding, and
   currentness evidence. It returns either a complete candidate Decision B
   authorization or refusal. No Route B type or function with this contract
   is claimed to exist.
2. **Form one authorization state.** A proposed current-authorization source
   owns the complete Decision B state needed by P/V admission: deployment and
   accepted-genesis identity; delegation and issuer identity/purpose; exact
   policy identity/version and mapping; P/V authority identity and complete
   v2 domain; currentness/replacement status; and the evidence needed to prove
   the binding. Exact encoding and storage are **OPEN**.
3. **Enroll once, in the same lifecycle.** A future first-use enrollment
   operation must atomically/currently establish the complete state and its
   non-rollback first-use status before any production owner or verifier can
   become current. Policy state and P/V authority must not be committed,
   replaced, or recovered under separate freshness generations that can
   disagree. This requirement does not assert an available atomic primitive.
4. **Bind the verifier to that state.** A future production equivalent of
   `AuthorizedProposalVoteSnapshot::try_bind` must consume the exact mapping
   result from the enrolled state and establish local coherence to the verifier
   and v2 domain. The expected wire ID must flow unchanged; this binding is
   not itself provenance or currentness evidence.
5. **Use one owner for admission and effects.** P/V inbound, outbound,
   cached re-emission, and any other entitled P/V effect must use the same
   current-authorization owner and snapshot. Each admission is re-confirmed at
   the relevant effect boundary. Mapping-policy validity cannot bypass the
   owner.
6. **Keep the missing-owner condition fail-closed.** When P/V authority is
   present but the required current-authorization owner/snapshot is absent,
   refuse before verification, signing, engine mutation, or forwarding. An
   unavailable or uncertain owner also refuses. **This remains an OPEN
   integration requirement**, not a claim that the existing source gap is
   fixed. The inspected inbound/outbound code has local refusal branches for
   absence, but production currently has no P/V authority/current owner and
   has no established currentness lifecycle.
7. **Restart and replace through that same owner.** Restart re-authenticates
   the same independent evidence and re-establishes currentness and
   signing-history prerequisites before current authorization. Replacement
   advances the same durable/current Decision B state and invalidates prior
   admissions; there is no parallel mapping-only freshness state or stale
   policy fallback.

**CANDIDATE ordering:** establish independently authenticated evidence and
current state first; persist/commit that state under an independently reviewed
consistency and rollback model; only then permit a current owner/snapshot;
then admit, check the exact domain and operation, perform the effect, and
confirm at its boundary. No diagram, pseudocode, interface proposal, or local
generation counter establishes an atomic or durable primitive.

## 3. First use, restart, replacement, and uncertain state

| Situation | Required future evidence and behavior | What is not enough |
|---|---|---|
| New deployment / first use | Authenticate provisioning independently; prove accepted-genesis provenance; authenticate mapping-purpose delegation; verify the policy and binding; establish unique first-use/currentness and commit the complete Decision B state before activation. | Local canonical hash; same-source matching hash; policy naming its signer; a valid policy signature; empty local state; unpersisted sequence; mapping match. |
| Normal restart | Re-authenticate or independently re-validate the provisioning relationship, accepted genesis, issuer delegation, exact policy, applicability, currentness/anti-rollback state, and the same Decision B enrollment. Separately establish signing-history and recovery continuity. | Cached policy bytes, old signature, process-local owner generation, VM/snapshot height, or successful prior mapping. |
| Missing, stale, substituted, rolled-back, or conflicting evidence | Refuse/unavailable. Do not create an established owner, choose a winner by arrival order, fall back to a prior mapping, or reinterpret absent state as first use. | Matching balances, matching local hashes, a later flush, or equal-looking epochs. |
| Policy or issuer replacement/upgrade | Authenticate the successor under an independently authorized succession rule; bind it to the same deployment/genesis and purpose; establish freshness and commit the new unified Decision B state before the new authority is used. Retire/revoke old authority under the same lifecycle. | Higher policy sequence by itself; a signature from a newly named issuer; a separate policy-store update; continued use of a known superseded policy. |
| Uncertain enrollment, currentness, recovery, or signing history | Return unavailable and keep P/V effects refused until independent evidence resolves the uncertainty under an owner-approved procedure. | Inferring success from a policy parse, previous process state, restored VM state, or absence of a local journal. |

**OPEN:** trusted provisioning and first-use enrollment; durable currentness
and anti-rollback; state consistency and storage guarantees; replacement and
revocation authority; cross-process fencing and stale-owner handling; recovery
authority/evidence; signer exclusivity; and signing-history continuity.
Current-authorization validity does not establish signer exclusivity or
signing-history continuity. VM-state recovery does not authorize signing or
participation.

## 4. Authority and data boundaries

1. **Policy is the mapping source.** Dormant aliases are candidate values, not
   authority. No alias, helper, local default, or matching number authorizes
   a mapping.
2. **Purpose separation is mandatory.** Do not reuse bundle-signing,
   transport, bootstrap, or A33-F1 authority for mapping-purpose issuer
   authorization. No policy can authorize its own issuer.
3. **Fail closed for custom deployments.** Missing, inconsistent,
   unsupported, ambiguous, or out-of-range mappings refuse. Runtime chain ID
   remains a full `u64`; the expected wire ID is a `u32`. Never guess, cast,
   truncate, default, or derive the expected wire ID from inbound bytes.
4. **Exact v2 handoff.** The policy-resolved `u32` must be the value bound into
   the applicable v2 signing domain and used downstream unchanged. No
   downstream re-derivation or substitution is permitted. A domain binding
   does not authenticate the mapping's provenance.
5. **Mapping is not authority to act.** A successful mapping does not establish
   current authorization, signing permission, finality, restart safety,
   recovery, signer exclusivity, or execution/finality handoff.
6. **Keep position sources separate.** The execution cursor, VM-state
   position, and snapshot height must not supply signer position or freshness
   to this trust lifecycle. Finality, exact executed inputs, position
   continuity, deployment/backend association, authorized ruleset, commit
   identity, the six identity bindings, and cursor non-entanglement remain
   separate **OPEN** obligations.
7. **Preserve A50-F1.** `GenesisConfig.extra` is outside the inspected
   canonical genesis preimage and must not carry identity, policy, issuer, or
   mapping metadata under the current hash contract. **A50-F1 remains OPEN.**
   Do not treat a matching canonical hash as authenticating fields omitted
   from its preimage.
8. **Native post-quantum objective is fixed.** Construction, parameters, keys,
   trust roots, continuity, provisioning, and demonstrated security remain
   **OPEN**. No classical/infrastructure dependency may be silently presented
   as satisfying the native-PQ objective.

## 5. Alternatives and their boundary

| Option | Role in this contract | Distinguishing boundary | Unresolved consequences |
|---|---|---|---|
| Independently authenticated deployment provisioning (Route B primary candidate) | **OWNER-DIRECTED primary specification candidate.** Provisioning independently establishes accepted-genesis provenance and mapping-purpose issuer delegation; the issuer authenticates a deployment policy bound to that genesis. | The policy governs a scoped deployment mapping and its applicability/succession; it does not bootstrap its own issuer, genesis provenance, or currentness. | Independent initial trust assumption, purpose-specific delegation, policy authentication, anti-substitution, unique first use, currentness, restart, replacement, PQ, and integration into one Decision B lifecycle. None is established. |
| Genesis-anchored delegation | **PARKED** pending a separate compatibility and migration decision. | Genesis-contained delegation cannot solve first use unless the accepted genesis provenance is already independently established. Adding mapping/delegation fields to the canonical genesis identity may change compatibility and identity; `GenesisConfig.extra` is not an authenticated workaround. | Genesis migration/versioning, accepted-hash transition, historical configuration compatibility, purpose and issuer authorization, currentness, and owner decision. Not selected here. |
| Separately authenticated mapping association | **UNSELECTED.** | A separately authenticated tuple associating environment/genesis/runtime ID/wire ID is not equivalent to a deployment policy with policy purpose, scope, and succession. Its authority may be limited to that association; it does not implicitly grant policy-issuer authority. | Its independent trust source, purpose, lifecycle, replacement, currentness, and relationship to Route B require a separate owner decision and specification. Do not merge the models by terminology. |

## 6. Decision and evidence matrix

| Category | Evidence or decision | Status |
|---|---|---|
| Source-established behavior | Current boot/genesis identity operations and current P/V source interfaces exist, but no production Route B provisioning, issuer delegation, resolver, or currentness owner consumes them. | **SOURCE FACT:** current main; exact locations in §8. |
| Source-established behavior | `CurrentAuthorizationOwner` is an in-process admission/invalidation model; its only production-reachable constructor yields unavailable state, while current production wires no P/V authority and passes no current-authorization owner to the inbound handler. Activation is refused. | **SOURCE FACT:** fail-closed/local behavior only; not a current Route B solution. |
| Owner-approved requirement | Investigate independently authenticated deployment provisioning as the primary Route B specification candidate, separately establishing accepted-genesis provenance, mapping-purpose issuer delegation, policy authentication, anti-substitution, and first-use/restart currentness. | **OWNER DECISION:** specification direction only; no capability or mechanism approved. |
| Earlier scoped mapping decision | Current-main BR-03 acceptance is **MAPPING POLICY ONLY**; it does not establish independent provisioning or currentness. Its operational genesis label/pin remain unsupplied, provisioning is not done, and implementation authorization is pending. The BR-04 freshness/unique-first-use text remains a proposal. | `ae6464120b15dabe6e994ee983b3d80046d89722`, `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:2078-2159,2161-2255`; neither decision establishes a Route B production trust path. |
| Candidate design | Route B evidence and P/V authority feed one Decision B current-authorization lifecycle, with one enrollment/currentness generation and no detached mapping-only persistence/freshness lifecycle. | **CANDIDATE:** requires review and an implementable, independently justified consistency model. |
| Candidate assumption | An independent initial trust relationship exists and can authenticate provisioning evidence outside the candidate policy and its rollback/substitution domain. | **ASSUMPTION / OPEN:** no root, key, provisioning channel, custody, or anti-rollback guarantee is established. |
| Unselected alternatives | Genesis-anchored delegation remains parked; separately authenticated mapping association remains unselected. | No alternative is approved or equivalent by assertion. |
| Feasibility blockers | Current P/V owner is unavailable-only in production; Route B source, persistent currentness, anti-rollback, restart/recovery, cross-process fencing, signing history, and native-PQ continuity are not established. | **OPEN:** prevents implementation entry and activation. |
| Independent evidence before entry | Provenance and purpose-authority chain; currentness/anti-rollback threat model; owner-approved first-use/replacement/recovery rules; complete read/write/use-path audit; storage/fencing proof; exact mapping-to-v2 trace; PQ construction and continuity review; independent security review. | Required before any separately authorized implementation entry; no evidence is asserted here. |

## 7. Owner decisions and review gates

Before any implementation-entry request, the owner and independent reviewers
must resolve or explicitly bound:

- What independent provisioning authority is permitted to establish accepted
  genesis provenance, and what evidence authenticates that authority?
- What separate authority delegates the exact mapping-policy purpose, scope,
  issuer, and succession/revocation rights?
- What evidence distinguishes the unique first use and current authorization
  from replay, substitution, rollback, conflict, or unavailable state?
- How do policy validity and currentness enter the **same** Decision B owner
  lifecycle as P/V authority, and what persistent consistency boundary and
  restart/recovery contract must be proved?
- What precisely happens on issuer/policy replacement, uncertain recovery,
  multi-process access, stale handles, revoked authority, or lost state?
- What are the canonical policy representation, exact identity bindings, and
  non-circular genesis identity contract, while preserving A50-F1?
- What native post-quantum construction, parameter set, key/root provisioning,
  and continuity evidence meets the fixed objective?
- How are the separately open finality handoff, exact executed inputs,
  position continuity, backend association, authorized ruleset, commit
  identity, six identity bindings, and cursor non-entanglement kept out of
  this mapping-only result?

Required source/use-path work includes a complete audit of provisioning,
genesis acceptance, policy and issuer verification, first-use enrollment,
current authorization, P/V snapshot construction, every P/V read/write/effect
path, replacement/revocation, recovery, worker claims, retained handles,
other processes, stale owners, and restart. A source interface, unit-level
guard, local mutex, advisory lock, matching hash, or successful mapping alone
is not independent evidence that the full lifecycle is correct.

All proposed validation is **FUTURE / NOT AUTHORIZED / NOT EXECUTED**. If
separately authorized later, it must cover positive provenance/delegation/
policy/currentness evidence and fail-closed behavior for missing, malformed,
ambiguous, conflicting, stale, substituted, rolled-back, revoked, unavailable,
and uncertain inputs; restart and replacement; missing-owner refusal; exact
mapping propagation; and independent PQ/security review. This document does
not authorize those tests or any experiment.

## 8. Pinned source and document references

All current-main paths below are pinned to
`ae6464120b15dabe6e994ee983b3d80046d89722` (tree
`cd394644a3998d2e23c2e2d95b1767657b34f17d`). The two unmerged Route B
documents are cited only at their exact commits, not as though they are on
`main`.

| Claim | Exact pinned reference |
|---|---|
| Current-main BR-03 mapping-only acceptance and pending BR-04 freshness/unique-first-use proposal | `ae6464120b15dabe6e994ee983b3d80046d89722`, `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:2078-2159,2161-2255` |
| First-use model's trust propositions, sequence, restart and open items | `b4736b6882b33fd91f0fdfa849ca1acb1718a2e3`, `docs/security/evidence/genesis-bound-route-b-first-use-trust-model-20261110.md:37-130,152-205` |
| Earlier Route B policy and mapping/association distinction | `f67b944ce25bb67b547d01533319ac2bff0f6ad6`, `docs/security/evidence/genesis-bound-route-b-deployment-policy-specification-20261110.md:27-75,127-228` |
| Current authority/freshness lifecycle and separate A/B/C obligations | `ae6464120b15dabe6e994ee983b3d80046d89722`, `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md:112-149,210-234,417-426,494-519,524-557` |
| Current authorization checks and production-only unavailable owner | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-node/src/genesis_consensus_authority.rs:868-890,1066-1146,1179-1238` |
| Local owner-to-verifier coherence and wire-ID binding | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-node/src/binary_consensus_loop.rs:1133-1190,1258-1313`; `crates/qbind-node/src/genesis_consensus_authority.rs:188,439,769-770` |
| Inbound/outbound missing-snapshot refusal behavior | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-node/src/binary_consensus_loop.rs:5531-5630,6247-6335` |
| P/V production authority and current owner absent; genesis-authority activation refused | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-node/src/main.rs:5428-5435,6165-6172`; `crates/qbind-node/src/binary_consensus_loop.rs:3140-3150` |
| Canonical genesis preimage and `extra` exclusion; A50-F1 status | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-ledger/src/genesis.rs:1569-1678`; `Audit/QBIND_SECURITY_FINDINGS_REGISTER.md:21-42` |
| Current v2 signing-domain binding of caller-provided expected wire ID | `ae6464120b15dabe6e994ee983b3d80046d89722`, `crates/qbind-wire/src/pv_signing_domain.rs:185-234,280-290` |

The source references establish only the behaviors stated above. They do not
establish a complete deployment inventory, external trust configuration,
production activation path, independently authenticated currentness, durable
anti-rollback, or an applicable Route B use path.

## 9. Preserved operational status

**A50-F1, A23-F1, A33-F1 / E27, and recipient overflow remain OPEN.**
Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
activation remains **DISABLED**; public DevNet remains **NO-GO**.

No source or register entry is changed or closed by this candidate. No
implementation, resolver, test, experiment, wiring, migration, startup,
integration, signing, recovery, deployment, activation, or update to the
authoritative carry-forward record is authorized.
