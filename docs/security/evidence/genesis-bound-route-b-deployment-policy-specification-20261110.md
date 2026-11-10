# Genesis-Bound Route B Deployment-Policy Specification

## Status, decision, and provenance

**DOCUMENTATION ONLY — INDEPENDENT REVIEW REQUIRED.** This specification
authorizes no resolver implementation, policy provisioning, production wiring,
startup, integration, signing, recovery, activation, or DevNet.

**OWNER DECISION (specification only):** Route B is the primary candidate: an
independently authenticated **deployment policy** bound to the independently
authenticated accepted genesis identity. This remains within the selected
genesis-bound deployment-policy direction. A separately authenticated
**mapping-association** artifact remains **UNSELECTED**. No issuer, key, trust
root, format, provisioning method, implementation, or activation is selected.

**Source pins:** `main` at
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`; reviewed
`docs/genesis-mapping-policy-coverage-provenance` at
`050008f19dce64795a7b52c3e0c6cc1c73f27187`, tree
`394617d02961a3d71bee55512611c0c244b04b3c`, parent
`511326ba7989379ebf5f11cc6ca9ff19397e98a7`.

The assessment distinguishes **SOURCE FACT**, **OWNER DECISION**,
**CANDIDATE REQUIREMENT**, **ASSUMPTION**, and **OPEN**. All validation in §7
is **FUTURE / NOT AUTHORIZED / NOT EXECUTED**.

## 1. Route B policy and authority

### Candidate policy subject

**CANDIDATE REQUIREMENT:** one canonical, independently authenticated
deployment-policy subject must explicitly bind:

```text
mapping authorization purpose
environment
independently authenticated accepted genesis identity
runtime chain ID (full u64)
wire chain ID (u32)
policy version and applicability/succession context
```

The authentication must cover the exact canonical policy bytes and all
security-relevant fields, with unambiguous parsing and no duplicate or
conflicting mapping entries. A policy's authenticated bytes must explicitly
authorize the issuer for this **mapping purpose**. A key that verifies a
signature is not, by that fact alone, authorized to set this mapping.
Authorization to issue deployment policy must be independently established,
not asserted by the signed policy itself.

No signing algorithm, credential, trust anchor, issuer, policy schema, or
provisioning channel is selected. Native post-quantum trust remains a fixed
requirement; an adequate construction and demonstrated continuity remain
**OPEN**.

### Distinct propositions

These are separate and must not be collapsed:

1. **Policy-byte authentication:** the exact bytes verify under an accepted
   cryptographic construction.
2. **Mapping-purpose authority:** the verifier's issuer is independently
   authorized to approve this exact deployment-mapping purpose.
3. **Applicability/currentness:** this policy is the unique, current,
   non-revoked, non-superseded policy for the accepted environment/genesis.
4. **Signing permission:** a separately authorized Proposal/Vote authority
   permits signing under a domain built with the mapping.

Route B establishes none of these today. Even a future successful mapping
verification grants **no** signing permission, finality authority, or
execution-handoff authority.

## 2. Genesis provenance and anti-substitution

### Independent relationship

**CANDIDATE REQUIREMENT:** establish the accepted genesis identity from an
independent trust source before accepting Route B. Independently authenticate
the deployment policy, then require its genesis identity to equal that
accepted identity exactly, along with exact environment and runtime-ID
agreement. The policy's own statement of a genesis hash, a recomputed local
hash, or equality with a locally configured value is not independent
provenance or freshness.

The genesis identity and the policy have distinct provenance questions:

- The genesis bytes/configuration must be tied to the independently accepted
  identity through an owner-approved trust input and a reviewed canonical
  identity contract.
- The policy bytes must be authenticated and tied to an issuer independently
  authorized for deployment-policy mapping.
- Their relation is the policy's authenticated, purpose-specific binding to
  that accepted genesis identity. Neither object supplies the other's
  provenance merely by naming it.

No accepted genesis trust channel, policy issuer, trusted root, signature
construction, first-use procedure, or currentness authority is established in
the inspected route.

### Refusal semantics

The future verifier/resolver must fail closed on missing, malformed,
unsupported, ambiguous, conflicting, stale, revoked, substituted, or
unavailable required evidence. It must not choose an input by arrival order,
fall back to a local alias or default, derive an expected value from inbound
bytes, or treat a locally matching value as authority. If it cannot prove the
accepted genesis and policy relationship and current applicability, it returns
refusal/unavailable; it must not return a success-shaped mapping.

**SOURCE FACT:** external genesis is parsed locally; boot computes its
canonical hash and compares it with a configured expected hash when supplied.
The expected hash is optional on DevNet and TestNet and mandatory on MainNet;
DevNet/TestNet may also take an embedded-genesis path that skips external
verification (`crates/qbind-node/src/pqc_boot_genesis.rs:215-248`;
`crates/qbind-ledger/src/genesis.rs:1797-1855`). This is equality checking,
not proof that the file or expected hash was independently authenticated.

The canonical-hash function's documentation says `GenesisConfig.extra` is
hashed, but its inspected body omits `config.extra`
(`crates/qbind-ledger/src/genesis.rs:1569-1641`). The standard/default DevNet
example initializes it to `Null` (`GenesisConfig::new`, `genesis.rs:1360-1380;
`docs/release/public-devnet/genesis/devnet-genesis.json:50`), which is inert
for that example only and not proof that all deployments use `Null`. Route B
must bind its policy bytes separately; it must not claim that `extra` is
authenticated by the current canonical hash.

## 3. Boundary from the unselected mapping-association alternative

Route B is proposed as a **deployment policy**, not a stand-alone signed
mapping tuple. Its candidate authority would govern a scoped deployment
context, explicitly connect the mapping to the accepted genesis, and have a
purpose authorization delegated for that policy role. Its mapping is one
policy decision within that deployment context.

The separately authenticated mapping-association alternative remains
unselected. A concrete design must be reviewed against at least these
questions before anyone can claim it is Route B rather than that alternative:

- Does the issuer have independently delegated authority to approve a
  deployment policy, or only to sign this one mapping association?
- Does the authenticated object represent a deployment's authorized policy
  state and succession, or merely attest `{environment, genesis, runtime ID,
  wire ID}`?
- Which authority grants the purpose, who may replace/revoke it, and how is
  that delegation authenticated independently of the object?
- How are exact policy identity, currentness, conflicts, and genesis binding
  established across first use and restart?

No answer or policy format is selected here. Do not presume the unselected
association is safe, unnecessary, or authorized. Do not reuse bundle-signing,
transport, or bootstrap authority for mapping purpose. The previously
discussed bootstrap association and A33-F1 association remain unapproved for
this purpose.

## 4. Standard and custom mappings; v2 domain flow

### Mapping rules

`NetworkWireAlias` values are dormant candidates, not authority. The wrapper
is publicly constructible, and the helper documents that it does not authorize
the value (`crates/qbind-types/src/network_wire_alias.rs:1-21,31-120`). A
future authenticated Route B policy must explicitly authorize the exact alias
for its environment, accepted genesis, and runtime ID before a resolver may
return it. The constant or helper result alone is insufficient.

Custom deployments require an explicit policy mapping; there is no guessed,
name-derived, default, cast, or alias fallback. Missing, inconsistent,
unsupported, ambiguous, or out-of-range required input refuses.

Runtime `ChainId` is a `u64`; the wire ID is a `u32`
(`crates/qbind-types/src/primitives.rs:34-40`;
`crates/qbind-wire/src/pv_signing_domain.rs:46-52`). They have separate
semantics. Validate each representation and its range independently. Never
truncate the runtime value; never infer or copy the expected wire ID from
inbound bytes. Do not require numeric equality or assume a cast absent an
approved mapping rule.

### Resolver-to-domain data flow

This is a future contract, not implementation:

1. A separately approved verifier authenticates the exact Route B policy and
   verifies mapping-purpose issuer authority and current applicability.
2. A pure resolver receives explicit trusted expected environment, accepted
   genesis identity, and full runtime `ChainId`; it checks exact policy
   agreement and a single unambiguous authorized `u32` result.
3. It returns that exact `expected_wire_chain_id` or a typed refusal.
4. If later separately authorized, that exact result is passed into
   `ProposalVoteSigningDomainV2::try_new`; downstream signing and verification
   use only the immutable domain's value. No independent re-derivation,
   substitution, default, truncation, or incoming-message copy is permitted.

The current v2 domain accepts the caller's `expected_wire_chain_id` and binds
it in the preimage, but does not authenticate its source
(`crates/qbind-wire/src/pv_signing_domain.rs:185-222,232-234,280-290`). In the
inspected production route, Proposal/Vote authority is `None` and
`ConsensusVerificationPolicy::Required`; inbound Proposal/Vote is rejected
and outbound emission is suppressed, with no fallback
(`crates/qbind-node/src/main.rs:6171,8680-8705`;
`crates/qbind-node/src/binary_consensus_loop.rs:736-786`). Production genesis
authority has `authorized_wire_chain_id: None`, and the genesis-authority
activation flag is refused at startup
(`crates/qbind-node/src/genesis_consensus_authority.rs:169-188,431-439`;
`crates/qbind-node/src/main.rs:5428-5435`).

A successful mapping result establishes only a mapping. It does not permit
signing, prove finality, establish restart safety or signer exclusivity, or
authorize the finalized-input handoff.

## 5. Version, currentness, first use, and restart

**CANDIDATE REQUIREMENTS:**

- Policy version must unambiguously define canonical encoding and semantics.
  Unknown versions and unsupported fields refuse.
- Applicability must bind the policy to the exact environment, accepted
  genesis identity, runtime ID, mapping purpose, and deployment scope.
- Replacement must follow an independently authorized succession rule.
  Rollback, stale policy, conflict, unauthorized replacement, and ambiguous
  first-use candidates refuse; arrival order does not select an authority.
- After restart, reacquire or re-verify the independently trusted accepted
  genesis and current deployment policy. A valid historical signature or
  stored policy is not proof of latest applicable state.
- If required evidence, current owner, or independent currentness source is
  absent or unavailable, refuse. No stale mapping or local cache is a
  success-shaped fallback.

**OPEN:** Decision B (first-use/current authorization); the D7 missing-owner
freshness requirement (present P/V authority plus absent required current
owner must refuse); signer exclusivity; cross-process fencing;
signing-history continuity; recovery; native-PQ construction/continuity;
finality handoff; and all six identity bindings. The execution cursor is not a
signer position or freshness source. A resolver result cannot seed signing
history, consensus locks/votes/finality, recovery, or activation.

## 6. Route A remains parked

Route A—mapping fields inside a canonical genesis/deployment object—remains
possible, not rejected. It must not place mapping data in `GenesisConfig.extra`
or another field outside the current canonical preimage and rely on that hash
for authentication. An explicitly added field that is included in a future
canonical preimage requires separate compatibility and migration analysis:
canonical genesis identity/versioning, existing expected-hash attestations,
accepted deployment changes, and cutover behavior. No such change or
implementation is authorized.

## 7. Future validation and implementation-entry gates

All controls below are **FUTURE / NOT AUTHORIZED / NOT EXECUTED**.

| Control family | Positive evidence sought | Negative and sensitivity controls |
|---|---|---|
| Genesis provenance and binding | Independently accepted genesis identity and authenticated policy bind exactly to the same environment/genesis/runtime context. | Reject locally computed/matching hash without independent provenance; wrong or substituted genesis; missing external expected hash; embedded-path skip; stale identity; mismatched policy binding. |
| Policy bytes and purpose | Exact canonical policy verifies under a separately established issuer authorized for this deployment-mapping purpose. | Reject altered/malformed bytes, wrong issuer, wrong purpose, bundle-signing/transport/bootstrap authority, unsupported fields, duplicate or ambiguous entries. |
| Standard mapping | Policy ratifies one dormant alias for exact environment/genesis/runtime scope; resolver returns exactly that `u32`. | Alias constant/helper alone, wrong scope, conflicting values, absent policy, or incoming-wire-derived value refuses. |
| Custom mapping | Explicit policy supplies an independently chosen wire `u32` for a supported custom deployment without a cast assumption. | Missing/unsupported entry, malformed numeric encoding, negative/oversized/out-of-range value, truncation, mismatch, or default mapping refuses. |
| Version/currentness/restart | Current applicable policy and authorized replacement are independently verified on first use and after restart. | Reject replay, stale/historical policy, rollback, conflicting policy, unauthorized replacement, missing owner/currentness evidence, and unavailable evidence. |
| Exact v2 propagation | Trace the resolver output unchanged through the immutable v2 domain into the signing preimage. | Reject a different downstream value, re-derivation, incoming-message substitution, runtime truncation, domain mismatch, or signing attempt through mapping success alone. |
| Narrow bypass sensitivity | Mapping result conveys no signer, freshness authority, finality evidence, or activation capability. | Present P/V authority with missing required current owner refuses; timeout context, cursor, local hash, alias, or resolver result cannot bypass `Required`/`None` or grant signing. |

Before any isolated resolver implementation is separately authorized,
independent review must settle the authenticated genesis input/provenance
source, policy issuer's explicit purpose authority, canonical policy
representation, Route B versus the unselected association boundary,
version/succession/currentness contract, trusted expected-context inputs,
standard/custom mapping semantics, and a bounded non-wiring implementation
and validation scope. No key, root, issuer, format, provisioning procedure,
cryptographic construction, or activation is selected here.

## 8. Source limits and unverified claims

Inspected the genesis schema/hash/boot-verification interfaces, dormant alias
helper, runtime and wire ID types, v2 signing domain, genesis consensus
authority fields, Required/None production route, prior mapping specification,
and D7 authority evidence. Search was limited to those source interfaces and
directly related evidence. No complete deployment inventory, external trust
configuration, cryptographic trust-root, feature/build matrix, runtime trace,
or downstream out-of-tree consumer audit was performed. No tests, builds,
node, or experiment were run.

No required source file was unavailable. Route B's policy format, issuer
authority, independent genesis provenance, first-use/currentness, replacement
and restart source, production resolver, signing permission, finality
authority, and runtime enforcement remain unestablished. Production remains
on the `Required` / `None` refusal path with no fallback. Required-persistence
remains **NOT ACCEPTED / NOT INTEGRATION-READY**; recipient overflow, A23-F1,
and A33-F1 / E27 remain **OPEN**; activation remains **DISABLED**; public
DevNet remains **NO-GO**.
