# Genesis-bound runtime-to-wire mapping specification

## Status and provenance

**DOCUMENTATION ONLY — INDEPENDENT REVIEW REQUIRED.** This specification
authorizes no resolver implementation, production wiring, startup,
integration, signing, or activation. The mapping policy and verification
described here are candidates, not existing capabilities.

**OWNER DECISION (specification only):** the PRIMARY candidate source for the
runtime-to-wire chain-ID mapping is an independently authenticated,
genesis-bound deployment policy. A separately authenticated mapping
association remains an **UNSELECTED** alternative, to be reconsidered only if
the mapping genuinely cannot be bound through the deployment/genesis policy.
No key, trust root, format, provisioning procedure, or implementation is
selected or authorized.

Pinned source: `main` at
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`; reviewed endpoint
`docs/engine-produced-finalized-input-handoff` at
`f90e9d11997c20216b53fe38b21534c78fd8b94b`, tree
`9610b4421a46bfc7b90bc00a2e0db50bc1d3d77c`, parent
`cdbe8b0fbe0b558e8040f1c07999880cfeb3741c`.

The statuses below separate **SOURCE FACT**, **OWNER DECISION**,
**CANDIDATE REQUIREMENT**, and **OPEN**. All controls in §7 are **FUTURE / NOT
AUTHORIZED / NOT EXECUTED**.

## 1. Existing identity and authority interfaces

| Interface | Source-established shape and behavior | Limitation for mapping authority |
|---|---|---|
| Runtime chain ID | `qbind_types::ChainId(pub u64)` (`crates/qbind-types/src/primitives.rs:34-40`); standard environments expose runtime IDs (`:64-87` and `NetworkEnvironment::chain_id`). | A full 64-bit runtime identifier is not the 32-bit wire identifier and must not be truncated or assumed numerically equal. |
| Wire chain ID | Consensus proposal/vote headers and v2 domain use `u32`; `ProposalVoteSigningDomainV2` stores `expected_wire_chain_id: u32` (`crates/qbind-wire/src/pv_signing_domain.rs:47-52,180-252`). The v2 preimage includes that exact field (`:270-290`). | The domain constructor requires a caller-supplied value. It does not authenticate the mapping source. |
| Genesis identity | `GenesisConfig.chain_id` is a string (`crates/qbind-ledger/src/genesis.rs:1296-1310`). The genesis-bound authority helper receives a boot-verified canonical genesis hash and includes the chain string/hash in its authority commitment (`crates/qbind-node/src/genesis_consensus_authority.rs:143-188,405-440`). | The inspected genesis schema has no runtime-to-wire mapping field. An accepted-looking hash or local genesis file is not independent proof of genesis provenance. |
| Consensus authority commitment | `GenesisConsensusAuthority.commitment` binds chain string, canonical genesis hash, validator indices, suites and public keys (`genesis_consensus_authority.rs:143-146,415-440`). | It identifies an intended validator-authority snapshot; it does not itself establish mapping-purpose authorization, currentness, or consensus signing permission. |
| Dormant network aliases | `NetworkWireAlias` and `resolve_network_wire_alias` define standard-environment candidates (`crates/qbind-types/src/network_wire_alias.rs:1-21,31-120`). The helper checks the supplied runtime ID against the selected environment before returning an alias. | The source marks values dormant, not deployed protocol values, not integrated, and not authorization. The wrapper is publicly constructible; possession of its raw `u32` proves no policy verification. |
| Production P/V authority and domain | `main.rs:6162-6172,8683-8705` leaves `proposal_vote_authority: None` and selects `ConsensusVerificationPolicy::Required`; absent P/V authority fails closed (`binary_consensus_loop.rs:736-786,1046-1090`). Genesis authority has `authorized_wire_chain_id: None` in production (`genesis_consensus_authority.rs:181-188,436-440`). | No mapping or production signing/verifying authority is active in the inspected route; no fallback is approved. These findings are route-specific, not claims about every configuration. |

### Distinct authorization questions

Authenticating policy bytes establishes, at most, that bytes satisfy a
particular cryptographic verifier under supplied keys and context. It does not
by itself establish:

1. that the verifier's root is independently authorized to approve this
   **mapping purpose**;
2. that this policy is applicable and current for the accepted deployment,
   including its environment, genesis, and authority state; or
3. that a validator may sign or verify Proposal/Vote under the resulting
   domain.

Those are separate trust decisions and evidence obligations. An accepted
genesis value or policy signature alone cannot collapse them.

## 2. Candidate deployment-policy contract

The owner-approved source direction is an independently authenticated,
genesis-bound deployment policy. A candidate policy subject must bind, as one
unambiguous purpose-authorized mapping:

```text
mapping purpose
environment
accepted canonical genesis identity
runtime ChainId (u64)
wire chain ID (u32)
```

The policy's authorization must explicitly cover assigning this runtime ID to
this wire ID for that environment and genesis. Reuse of bundle-signing,
transport, or bootstrap authority is not approved. The A33-F1 association and
previously discussed bootstrap association are not approved mapping paths.

No policy object, encoding, signer, root, provisioning route, or verification
implementation currently establishes this contract. A future design must
decide whether the policy is part of an extended genesis representation whose
fields are covered by the accepted canonical genesis hash, or a separately
authenticated policy that names and is bound to the exact accepted genesis
identity. This specification selects neither. Either route depends on
independently establishing the genesis identity and the policy issuer's
authority for this purpose.

### Dormant standard aliases

The values in `network_wire_alias.rs` may be candidate expected values only.
For a future resolver to use one, the accepted deployment policy must
explicitly bind and authorize that exact candidate together with its
environment, accepted genesis identity, and runtime `ChainId`. A hard-coded
constant, `NetworkWireAlias` value, or successful pure environment/runtime
lookup alone is insufficient authority.

The existing table covers standard environments only. It does not supply a
mapping for custom deployments, prove the aliases are deployed protocol
values, or bind them to a particular genesis or validator authority.
Whether the candidate assignments are appropriate is **OPEN**.

### Custom deployments and input semantics

Each custom deployment requires an explicit mapping in an appropriately
authenticated, purpose-authorized deployment policy. Do not infer a custom
wire ID from its name, runtime ID, another deployment, or a default.

The runtime `ChainId` and wire `u32` have separate semantics. An authorized
mapping need not be a numeric cast or equality. If a future policy parser
accepts a wider numeric representation for the wire value, it must perform a
checked range conversion to `u32`; overflow, sign ambiguity, malformed
encoding, conflicting entries, duplicate/ambiguous scope, missing environment
or genesis binding, unsupported deployment, and inconsistent identity all
refuse. No truncation, wrapping, fallback, or incoming-message-derived
expected value is permitted.

## 3. Future resolver contract and v2 data flow

This is a proposed interface contract only; no resolver is implemented.

1. A separately approved verifier authenticates policy bytes and proves the
   issuer is authorized for the mapping purpose.
2. The caller supplies an explicit trusted expected context: environment,
   accepted canonical genesis identity, runtime `ChainId`, and applicable
   policy/currentness evidence. None is sourced from the peer's message.
3. A pure resolver checks the policy subject exactly matches that context,
   confirms a single unambiguous supported mapping, validates the wire value's
   representation/range, and returns a typed mapping result or a typed
   refusal. Missing, stale, conflicting, unsupported, or unverifiable evidence
   refuses.
4. If later separately approved authority construction is permitted, that
   construction passes the resolver's exact `expected_wire_chain_id` into
   `ProposalVoteSigningDomainV2::try_new` along with the same accepted runtime
   ID, genesis identity, and authority commitment.
5. The resulting immutable domain is the sole source of expected wire ID for
   Proposal/Vote message signing and verification. Downstream must not
   independently re-derive, substitute, truncate, default, or copy that value
   from the message.

The current `ProposalVoteSigningDomainV2::try_new` accepts the expected wire
ID as an argument and binds it into the preimage; that does not prove the
argument was policy-authorized. `AuthorizedProposalVoteSnapshot::try_bind`
compares the verifier's domain to the authority's separately held wire ID
(`binary_consensus_loop.rs:1135-1190,1255-1318`), but a production genesis
authority currently has no authorized wire ID. This specification does not
modify the domain or wire any resolver.

A matching resolver result is only a mapping result. It does not establish
current authorization, signing permission, finality, restart safety, signer
exclusivity, or execution-handoff acceptance.

## 4. Current authorization and non-entanglement boundaries

First-use enrollment and current authorization remain **OPEN**. A future
owner would need independently authenticated evidence that the deployment
policy and mapping are the accepted ones, that the validator authority is
approved for the current epoch, and that this enrollment is permitted—not
merely the policy's own self-description.

After restart, the owner must establish currentness and continuity from an
independently trusted source. A valid historical policy/signature or local
record does not prove that it is the latest applicable authority, detect a
whole-store rollback, or prove signer exclusivity. Missing owner, missing or
stale evidence, conflicting authority, rollback, and unauthorized replacement
must refuse; stale authority must not be used as fallback.

The D7 missing-owner freshness gap remains **OPEN**: a future P/V design must
refuse when P/V authority is present but its required current-authorization
owner is absent. The present production `Required/None` route remains
fail-closed; that does not fix a future present-authority/absent-owner path.
This specification does not claim that the D7 gap is fixed.

Authority currentness is separate from signer exclusivity. Cross-process
fencing, signing-history continuity, recovery/currentness, and native-PQ
construction and continuity remain **OPEN**. The execution cursor must not be
used as a signer position or freshness source. Preserve the existing
snapshot-to-consensus-baseline and snapshot-to-activation channels documented
in the reviewed cursor audit; the resolver must not feed either channel.

The engine-produced finalized-input record remains only the primary
**specification** candidate. A mapping match does not establish consensus
finality or any of the six identity bindings. Native post-quantum trust remains
a fixed project requirement; actual keys, roots, constructions, provisioning,
and demonstrated security remain **OPEN**.

## 5. Future control plan

All controls below are **FUTURE / NOT AUTHORIZED / NOT EXECUTED**. They are
proposed evidence requirements, not present validation or runtime-enforcement
claims.

| Control family | Positive control | Negative / bypass-sensitivity controls |
|---|---|---|
| Standard deployment | Authenticated policy explicitly binds one supported environment, accepted genesis, runtime ID, and an alias candidate; resolver returns exactly the policy's wire `u32`. | Alias constant alone, publicly constructed alias, wrong environment, wrong genesis, wrong runtime ID, duplicate mapping, absent purpose authorization, stale policy, and unauthenticated policy all refuse. |
| Custom deployment | Explicit authenticated policy binds the custom deployment context and an independently chosen wire ID; resolver preserves it exactly without assuming a cast. | Missing custom entry, unsupported environment, ambiguous/conflicting entries, wrong deployment/genesis, malformed or out-of-range wire representation, negative/oversized integer, lossy conversion, or default mapping refuses. |
| Policy authentication and purpose | Verifier accepts bytes only under an independently authorized mapping-purpose policy and exact expected context. | A valid signature under a transport, bundle-signing, or bootstrap purpose is rejected for mapping; correct-looking signed bytes with wrong purpose, root, environment, genesis, or authority commitment refuse. |
| V2 domain propagation | The exact resolver output is the `expected_wire_chain_id` passed to domain construction and is observable unchanged in the immutable v2 domain and signature preimage. | No downstream re-derivation; mismatched constructor input, altered domain, incoming-message substitution, wire-ID truncation, and a mismatch between resolver output and bound domain refuse before signing/verification. |
| Narrow bypass sensitivity | Mapping resolution alone returns no signer, no `ProposalVoteAuthority`, no freshness ticket, and no finality evidence. | Present P/V authority with missing current owner refuses; timeout context, `None` owner, default environment, direct alias construction, or a resolver success cannot bypass the Required/None startup refusal or grant signing. This control is prospective; the documented D7 missing-owner gap remains open. |

Even successful future controls would establish only their scoped mapping
properties. They would not prove first-use currentness, signing permission,
finality, production runtime enforcement, signer exclusivity, restart safety,
or handoff atomicity.

## 6. Decision and evidence still needed

The owner-approved specification direction is the genesis-bound deployment
policy as primary mapping source; the separately authenticated association
remains unselected. Before any resolver implementation is separately
authorized, independent review must establish the policy's purpose-authorized
issuer and genesis provenance, whether mapping fields are covered by canonical
genesis identity or by a separately authenticated policy, exact custom
deployment semantics, version/upgrade and replacement behavior, and
currentness/first-use evidence. No root, key, format, or provisioning method
is selected here.

Separate open work remains for production current authorization and the D7
missing-owner gap, signer exclusivity/fencing/signing-history continuity and
recovery; native-PQ construction and continuity; cursor non-entanglement; the
engine-produced finality handoff; and all six identity bindings. Proposed
C05/C15/C12 register entries remain unassigned and unapplied.

## 7. Source limits and preserved dispositions

Inspected the pinned mapping/domain/authority interfaces in
`crates/qbind-types/src/primitives.rs`,
`crates/qbind-types/src/network_wire_alias.rs`,
`crates/qbind-ledger/src/genesis.rs`,
`crates/qbind-wire/src/pv_signing_domain.rs`,
`crates/qbind-node/src/genesis_consensus_authority.rs`,
`crates/qbind-node/src/binary_consensus_loop.rs`, and
`crates/qbind-node/src/main.rs`; and the scoped D7 evidence plus reviewed
engine-handoff and cursor-audit documents. Search was limited to the relevant
workspace source/docs; no complete feature/build matrix, macro expansion,
downstream consumer audit, or runtime trace was performed. No source object
required by this specification was unavailable. There is no source evidence
that the proposed policy, purpose authorization, mapping verifier, currentness
lifecycle, or resolver exists or has been independently reviewed.

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1, and A33-F1 / E27 remain **OPEN**. Activation
remains **DISABLED**; public DevNet remains **NO-GO**. Production remains on
the `Required` / `None` refusal path with no fallback.
