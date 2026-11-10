# Genesis-Bound Mapping Policy: Coverage and Provenance

## Status and scope

**DOCUMENTATION ONLY — INDEPENDENT REVIEW REQUIRED.** This assessment does
not implement a resolver, select an operational authority, change production
behavior, or authorize startup, integration, signing, recovery, activation, or
DevNet.

**OWNER DECISION (already approved for specification only):** an independently
authenticated, genesis-bound deployment policy is the primary candidate
source for the runtime-to-wire mapping. The policy must bind
`{environment, accepted genesis identity, runtime chain ID, wire chain ID}`
with explicit authorization for the mapping purpose. Dormant standard aliases
are candidate values only; custom deployments require an explicit
authenticated mapping and fail closed. Bundle-signing, transport, bootstrap,
A33-F1, and the previously discussed bootstrap association are not approved
for this purpose. A separately authenticated mapping association remains an
**UNSELECTED** alternative, to be reconsidered only if the mapping genuinely
cannot be bound through the genesis/deployment policy. No key, root, format,
or provisioning procedure is selected.

**Pins:** `main` at
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`; reviewed
`docs/genesis-bound-runtime-wire-mapping` at
`511326ba7989379ebf5f11cc6ca9ff19397e98a7`, tree
`0a73dfccf74fba21d5e4294e059aa2e4f1758e2f`, parent
`f90e9d11997c20216b53fe38b21534c78fd8b94b`. The new proposal is a
candidate refinement of that mapping specification, not an operational
decision.

The labels **SOURCE FACT**, **OWNER DECISION**, **CANDIDATE REQUIREMENT**,
**ASSUMPTION**, and **OPEN** distinguish evidence from requirements and
unknowns. Every proposed control in §6 is **FUTURE / NOT AUTHORIZED / NOT
EXECUTED**.

## 1. Existing genesis identity and provenance

### Source-established forms

| Identity form | Source fact | What the source does not establish |
|---|---|---|
| Genesis chain name | `GenesisConfig.chain_id` is a `String` (`crates/qbind-ledger/src/genesis.rs:1300-1306`). Canonical hashing frames the environment scope and this string; the boot verifier applies a substring environment-name check for MainNet/TestNet (`genesis.rs:1576-1584,1792-1820`). | It is not the runtime `ChainId`, is not the wire ID, and the substring check does not establish numeric equivalence or authenticated provenance. DevNet does not receive that MainNet/TestNet substring check. |
| Runtime chain ID | `qbind_types::ChainId` is a `u64`; the three standard `NetworkEnvironment::chain_id()` values are code-defined constants (`crates/qbind-types/src/primitives.rs:34-40,64-87,105-118`). | These constants do not prove that a particular genesis file or deployment is accepted for them. The inspected boot-genesis verifier does not compare the genesis string to this `u64` by numeric conversion. |
| Wire chain ID | The consensus wire/domain uses `u32`; `ProposalVoteSigningDomainV2` stores the caller-supplied `expected_wire_chain_id` and includes that exact field in the v2 preimage (`crates/qbind-wire/src/pv_signing_domain.rs:46-52,185-222,232-234,280-290`). | The constructor does not authenticate the mapping source. There is no source-established runtime-to-wire mapping in the inspected production route. |
| Canonical genesis identity | `compute_canonical_genesis_hash` computes a domain-separated SHA3-256 digest over the environment scope and structured genesis fields (`crates/qbind-ledger/src/genesis.rs:1523-1586`). The boot verifier computes it from the parsed configuration and compares it with `expected_canonical_hash` only when one is supplied (`genesis.rs:1764-1855`). | Computing or retaining a digest of local input is not independent authentication of that input's origin, approval, or current applicability. |

The externally configured genesis path is loaded and parsed as a `GenesisConfig`
by `load_external_genesis`; the boot route then calls
`verify_boot_time_genesis` (`crates/qbind-node/src/pqc_boot_genesis.rs:181-196,
215-248`). On the DevNet/TestNet embedded-genesis path, verification returns
`SkippedNoExternalGenesis`; MainNet refuses that path
(`pqc_boot_genesis.rs:215-235`). With external genesis, the supplied expected
hash is optional for DevNet and TestNet and required for MainNet; if supplied,
the verifier compares it with the computed canonical hash
(`genesis.rs:1764-1855`). **Therefore an external expected genesis hash is
not always supplied or compared on DevNet/TestNet.** Even when comparison
occurs, the inspected code establishes equality to a configured local expected
value, not the independent authentication or provenance of that value.

The genesis-authority loader has a useful same-input consistency property:
it reads one owned genesis snapshot, verifies it, derives authority from that
snapshot, and optionally compares its hash to the boot-accepted hash
(`crates/qbind-node/src/genesis_consensus_authority.rs:1386-1443`). This
prevents mixing a hash and keys from different reads; it does not independently
authenticate the boot-accepted hash or establish that a local file is the
latest authorized genesis.

### Canonical-hash coverage discrepancy

**SOURCE FACT:** `compute_canonical_genesis_hash` encodes environment, chain
string, time, allocations, validators, council, monetary configuration, and
the authority block (`genesis.rs:1576-1641`). The adjacent documentation says
`GenesisConfig.extra` is hashed using canonical JSON at `genesis.rs:1569-1575`,
but the inspected function body does not encode `config.extra`.

**OPEN:** this source/documentation discrepancy means the reviewed source does
not establish that `extra` is covered by the canonical identity. Do not place
mapping fields in `extra` or claim they are genesis-hash-bound on the basis of
the comment. Resolving the discrepancy, if relevant to a future design,
requires separate review and an explicitly authorized change; this task makes
none. The current schema also has no explicit runtime-to-wire mapping field.

The genesis authority block has a policy version and sequence, transport roots,
and bundle-signing roots; its comments say those fields are hash-bound but do
not constitute live mapping-purpose authorization
(`crates/qbind-ledger/src/genesis.rs:754-785,1347-1359`). They must not be
repurposed for this mapping purpose.

## 2. Candidate policy-binding alternatives

Both alternatives remain within the owner-approved **genesis-bound
deployment-policy** direction. Alternative B is not the separately
authenticated mapping-association alternative.

| Candidate | Bytes/fields that would need authentication and purpose authorization | Provenance and issuer authority | Risks and deployment implications | Current source |
|---|---|---|---|---|
| **A. Mapping in a canonical genesis/deployment object** | The canonical object must unambiguously encode an explicit mapping-purpose tag; environment; runtime ID as full `u64`; wire ID as `u32`; and the genesis/deployment subject to which the mapping applies. All those fields must be within the exact canonical bytes authenticated as the accepted genesis/deployment object. The object identity should be the digest of the complete object; avoid a self-referential field that tries to contain its own final digest. | Independently establish that this exact canonical object is the accepted genesis/deployment and that its approval/signing authority is authorized to approve mapping-purpose assignments. A computed hash alone is insufficient. | Substitution or omission of fields from canonical encoding can disconnect the displayed mapping from accepted identity. An update to mapping changes the accepted object identity; upgrades need an authorized replacement and explicit handling of old/new objects, rollback, and conflicts. Standard aliases remain candidates; custom deployments need explicit entries. | No mapping field or mapping-purpose verifier exists. The `extra` coverage comment/code mismatch blocks reliance on `extra`. A purpose field added to an object would need demonstrated coverage, canonicalization, versioning, and authenticated genesis provenance. |
| **B. Separate authenticated policy bound to accepted genesis** | Policy bytes must canonically bind mapping purpose, environment, accepted canonical genesis identity, runtime `u64`, wire `u32`, policy version, and any sequence/validity/replacement fields required by the future currentness model. Authentication must cover exactly these fields and reject duplicate/ambiguous encodings. | Independently establish both (1) provenance and acceptance of the genesis identity and (2) provenance of the policy plus issuer authorization for this exact mapping purpose. A signature proves only what its verified key and policy authorize; it does not itself prove issuer authority or currentness. | Policy/genesis substitution, environment or purpose confusion, replay of an old policy, conflicting issuers, downgrade, and rollback must refuse. Updates need an authorized succession rule. Standard and custom deployments both require explicit authenticated mappings; no alias-only fallback. | No such policy format, trust source, purpose authorization, or currentness mechanism is established. The current hash/authority fields do not provide this policy. |

For either candidate, **authentication of bytes**, **authority to approve this
mapping purpose**, **genesis provenance**, **applicability/currentness**, and
**authority to sign or verify Proposal/Vote** are separate claims. A policy
signature, accepted-looking genesis string, local digest, matching runtime
value, or valid consensus signature cannot substitute for the others.

## 3. Version, replacement, and currentness

**CANDIDATE REQUIREMENTS — no mechanism selected:**

- A policy version must identify its canonical schema and interpretation.
  Unknown versions, unsupported fields, malformed or duplicate mapping
  subjects, and ambiguous issuer/authority results refuse.
- Environment, accepted genesis identity, full runtime `u64`, wire `u32`, and
  mapping-purpose authorization must be covered by the authenticated subject.
  No omitted-field defaults may create authority.
- A replacement must have an independently authorized succession rule. The
  system must reject rollback, stale policy, incompatible genesis, conflicting
  policies, and unsupported transitions rather than choose by arrival order or
  local preference.
- Restart inspection must reacquire or re-verify the applicable evidence.
  A local cache, a historical valid policy, or a valid signature alone does
  not establish that the policy is the latest applicable authorization.
  Missing, stale, unavailable, conflicting, or unverifiable evidence refuses.
- Any sequence, expiry, revocation, transparency, or other currentness
  mechanism is **OPEN**; none is selected here. First-use enrollment and
  current authorization remain the separate **Decision B**, OPEN. The mapping
  result must not bootstrap its own trust or currentness.

**ASSUMPTION:** a future system can obtain an independently trusted expected
context and independently authenticated evidence. The inspected source does
not demonstrate either an operational policy owner or such a lifecycle.

## 4. Future resolver and v2 signing-domain flow

This is a candidate interface contract, not implementation authorization:

1. A future policy verifier authenticates canonical policy bytes and checks
   the issuer's separately established authority for the mapping purpose.
2. The resolver receives explicit trusted expected environment, accepted
   genesis identity, runtime `ChainId`, and policy applicability evidence.
   None is inferred from a proposal, vote, incoming wire chain ID, or local
   mapping guess.
3. It requires exact policy/context agreement and exactly one supported,
   purpose-authorized mapping. It validates each representation independently:
   runtime is a full `u64`; wire is a `u32`. It must not truncate or cast the
   runtime value into the wire value. If parsing from a wider representation,
   use checked range validation. An authorized mapping is not necessarily
   numeric equality.
4. It returns the policy's exact `expected_wire_chain_id` or a typed refusal.
   Missing, inconsistent, unauthenticated, stale, unsupported, ambiguous, or
   out-of-range required input refuses.
5. Only after separate authorization of later authority construction, pass
   that exact resolver output to `ProposalVoteSigningDomainV2::try_new`.
   The immutable domain's exact value is then the sole expected wire ID used
   downstream and encoded in the v2 signing preimage. No downstream
   re-derivation, fallback, substitution, or copying from the message is
   allowed.

The current v2 domain already accepts and encodes an exact `u32`, but this
does not validate the argument's authority
(`crates/qbind-wire/src/pv_signing_domain.rs:185-222,232-234,280-290`).
`GenesisConsensusAuthority` currently has production
`authorized_wire_chain_id: None`, with a test-only fixture path that can
populate it
(`crates/qbind-node/src/genesis_consensus_authority.rs:169-188,431-439,1349-1374`). The production
Proposal/Vote route leaves `proposal_vote_authority` absent and uses
`ConsensusVerificationPolicy::Required`; under that policy inbound
Proposal/Vote is rejected and outbound emission suppressed
(`crates/qbind-node/src/main.rs:6162-6172,8680-8705`;
`crates/qbind-node/src/binary_consensus_loop.rs:736-786`). The inspected
genesis-authority activation flag is explicitly refused by the startup guard
(`main.rs:5428-5435`); no production mapping or fallback is active.

A successful mapping result is only a mapping result. It does not establish
current authorization, signing permission, finality, restart safety, signer
exclusivity, or execution-handoff acceptance.

## 5. Boundaries that remain open

- The D7 missing-owner freshness **requirement remains OPEN** for future
  authority/currentness design: present Proposal/Vote authority with an absent
  required current owner must refuse. The D7 record includes a scoped A1
  inbound missing-owner correction and tests, but D7 findings #2–#4,
  production current-authorization lifecycle, durable freshness, and broader
  lifecycle obligations remain open
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md:440-464,1140-1218,1284`). That scoped
  correction does not authorize or prove this policy path.
- Authority currentness, signer exclusivity, cross-process fencing,
  signing-history continuity, and recovery are separate open obligations.
- The execution cursor is not a signer position or freshness source. The
  snapshot-to-consensus-baseline and snapshot-to-activation non-entanglement
  channels remain open.
- The engine-produced finality handoff and all six identity bindings remain
  open. Mapping success is not finality.
- Native post-quantum trust is fixed; construction and demonstrated
  continuity remain open.
- Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**;
  recipient overflow, A23-F1, and A33-F1 / E27 remain **OPEN**; activation
  remains **DISABLED**; public DevNet remains **NO-GO**. Production remains
  on the `Required` / `None` refusal path with no fallback.

## 6. Future validation and entry gates

All controls below are **FUTURE / NOT AUTHORIZED / NOT EXECUTED**. No
experiment or implementation is authorized by this assessment.

| Control family | Positive evidence sought | Negative and bypass-sensitivity controls |
|---|---|---|
| Canonical coverage and genesis provenance | Demonstrate that the exact approved mapping-purpose fields are in the canonical object bytes and that accepted genesis provenance is independently authenticated. | Change each binding field independently; reject unapproved/unknown genesis, local hash without trusted expected provenance, the DevNet/TestNet path without expected hash, mismatched expected hash, omitted/extra mapping fields, and any unsupported schema. Resolve and test the `extra` documentation/implementation discrepancy before relying on it. |
| Separate policy and purpose | Verify exact canonical policy bytes, exact genesis binding, and independently authorized mapping-purpose issuer. | Reject transport, bundle-signing, bootstrap, A33-F1, wrong-purpose, wrong-environment, wrong-genesis, wrong issuer, malformed, or altered signed policy as mapping authority. |
| Standard aliases | A supported authenticated policy binds a dormant alias candidate to the exact environment, accepted genesis, runtime ID, and purpose; resolver returns exactly the authorized value. | Alias constant or publicly constructed wrapper alone, unknown alias, wrong genesis/runtime/environment, duplicate entry, or unapproved alias assignment refuses. |
| Custom deployment | An explicit authenticated policy provides an independently assigned wire `u32` for a supported custom deployment; no cast is assumed. | Missing entry, unsupported deployment, numeric overflow, negative or malformed representation, ambiguous/conflicting entries, or inferred/default ID refuses. |
| Version and currentness | An independently authorized policy is accepted only for its intended version and current deployment context, including after restart. | Reject replay, stale policy, rollback, unauthorized replacement, conflicting authorities, missing current evidence, and unknown version. |
| Resolver and v2 propagation | Trace exact resolver output into immutable v2 domain and preimage, preserving the full runtime `u64` and exact wire `u32`. | Reject truncated runtime, wrong/out-of-range wire value, incoming-message-derived expectation, downstream re-derivation, mismatched constructor/domain, and any signing attempt through resolver success alone. |
| Refusal and authorization separation | Mapping result contains no signer, freshness owner, finality evidence, or activation capability. | Present P/V authority plus absent required current owner refuses; resolver success cannot bypass `Required`/`None`, establish first-use currentness, authorize signing, or create finality. |

Before any isolated resolver implementation could be separately authorized,
independent review must settle the authenticated-genesis provenance input and
the A-versus-B policy encoding choice; mapping-purpose issuer authority;
canonical field coverage and the `extra` discrepancy; version/replacement and
currentness semantics; standard candidate/custom deployment treatment; the
trusted expected-context source; and a bounded implementation/test boundary
that does not wire startup or signing. This list selects no key, root,
credential, storage mechanism, provisioning, or recovery authority.

## 7. Source limits and unverified claims

Inspected the pinned genesis schema/hash/verifier and boot wrapper;
runtime/environment ID definitions; dormant alias helper; v2 signing-domain
constructor/preimage; genesis consensus-authority fields and loader; the
production startup guard and `Required`/`None` route; and the scoped Run 422
D7 evidence. Search was limited to the directly relevant workspace source and
evidence documents. No complete configuration-source, deployment,
feature/build, downstream consumer, cryptographic trust-root, filesystem, or
runtime trace was performed. No tests, builds, node, or experiment were run.

No required source file was unavailable. The following claims remain
unverified or unsupported by the inspected source: independently authenticated
genesis provenance in every route; an operational mapping-policy issuer or
format; mapping-purpose authorization; current policy selection and
replacement; a production runtime-to-wire resolver; production Proposal/Vote
authority; finality authority; and production enforcement of this candidate
policy. The comment/implementation discrepancy about hashing `GenesisConfig.extra`
is specifically unresolved.
