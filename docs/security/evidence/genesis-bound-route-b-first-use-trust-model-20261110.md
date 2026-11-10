# Genesis-Bound Route B First-Use Trust Model

## Status, decision, and source pins

**DOCUMENTATION-ONLY CANDIDATE — INDEPENDENT REVIEW REQUIRED.** This
document authorizes no implementation, new trust root, resolver, provisioning,
experiment, production wiring, startup, signing, recovery, deployment, or
activation.

**OWNER-SELECTED DIRECTION:** Route B is the primary specification candidate:
an independently authenticated deployment policy bound to the independently
authenticated accepted genesis identity. The separate mapping-association
alternative remains **UNSELECTED**. No issuer, key, trust root, cryptographic
construction, format, provisioning method, recovery authority, or lag policy
is selected.

**Source pins:** `main` commit
`677d5ef3aae4b944ea26fbd0824476b4f766fa89`, tree
`f54730c2ade70c648d8fb737ca2f81eed9cc7ba6`; prior Route B specification
branch `docs/route-b-deployment-policy-spec` at `f67b944ce25bb67b547d01533319ac2bff0f6ad6`,
tree `95aa28a7f520d0f4f29208b592df1ad99a5014f1`.

**BLOCKED as a current source-supported trust path:** inspected QBIND source
does not establish independent first-use genesis provenance, a mapping-purpose
issuer delegation, or a currentness/anti-rollback source for this policy. The
sequence below is a conditional design contract, not evidence that any
prerequisite exists or that the design is feasible with current provisioning.
The missing owner decision is whether to authorize specification of a
non-circular independent provenance and purpose-delegation model, plus evidence
for first-use/current authorization and restart. Until that is resolved, no
policy can be accepted as authoritative for this mapping.

All statements below distinguish source-established behavior from candidate
requirements and unresolved assumptions. Proposed controls in §7 are
**FUTURE / NOT AUTHORIZED / NOT EXECUTED**.

## 1. Trust dependencies

The proposed dependency direction is:

```text
independently trusted genesis-provenance evidence ──► accepted genesis identity
independently trusted mapping-purpose delegation ──► authorized policy issuer
authorized issuer ──► authenticated deployment-policy bytes
accepted genesis + issuer + policy ──► applicability and currentness decision
verified policy mapping ──► exact expected wire ID ──► future v2 signing domain
```

The two first inputs must be established independently of the policy being
checked. A policy cannot authenticate its own issuer, authorize itself by
naming its signer, or turn a locally calculated/matching genesis hash into
independent provenance or proof of currentness.

| Proposition | Candidate evidence and check | Current status and failure outcome |
|---|---|---|
| Accepted genesis identity and provenance | Before policy evaluation, obtain owner-authorized evidence from an independent trust relationship that identifies the accepted genesis identity and its environment. Parse the configured genesis, compute the reviewed canonical identity under that environment, and compare it to the independently accepted identity. Evidence must authenticate both the value and why it is accepted for this deployment. | **OPEN / not established by source.** Local computation, a matching local pin, or a policy-supplied hash alone is not independent provenance. Missing, ambiguous, conflicting, or unavailable provenance refuses/unavailable. |
| Issuer authority for this purpose | Independently authenticate a delegation or authorization that identifies an issuer and explicitly grants the purpose of approving runtime→wire mappings, with its deployment scope and applicability. Verify this authorization before trusting a policy signed by that issuer. | **OPEN / no such source-supported delegation.** A signing key or valid signature alone does not grant mapping authority. A policy cannot grant its own issuer authority. |
| Policy-byte authenticity | Authenticate the exact canonical policy bytes under an approved native post-quantum construction; verify the signing issuer is the independently authorized issuer. Reject ambiguous encodings, duplicate entries, unsupported versions, or altered bytes. | **OPEN / no construction or verifier selected.** Invalid or unavailable authentication refuses. Native-PQ trust is fixed; a construction and continuity are unproven. |
| Genesis binding and applicability | Require authenticated policy fields for mapping purpose, environment, exact accepted genesis identity, full runtime chain ID (`u64`), expected wire chain ID (`u32`), policy version, scope, and applicability. Check each against independently trusted runtime context; do not let the policy define its own expected context. | **OPEN / no policy source or resolver.** Any missing, mismatched, conflicting, ambiguous, or unsupported required field refuses. |
| Currentness | Verify the policy is the unique currently applicable policy, including any independently authorized replacement, revocation, and anti-rollback evidence. A valid signature or high-looking sequence in the policy is not itself proof that it is latest. | **OPEN / first-use and current authorization unresolved.** Stale, rolled-back, conflicting, or unavailable currentness evidence refuses/unavailable. |
| Mapping result and v2 handoff | Resolve only the explicitly authorized mapping for the exact trusted context. Preserve the resulting `u32` unchanged as `expected_wire_chain_id` in the future v2 signing domain. | **Candidate requirement only.** No truncation, cast, guessing, local alias authority, re-derivation, or value copied from inbound bytes. Mapping success conveys no signing permission or finality. |

Authentication of policy bytes, issuer authorization for this purpose,
genesis binding, applicability/currentness, and permission to sign are distinct
checks. Passing one does not imply any other.

## 2. Candidate first-use sequence

Each step depends only on evidence established before it; the policy itself
must not be used to manufacture an earlier trust premise.

1. **Establish deployment context independently.** An owner-authorized source
   must authenticate which environment and deployment are being initialized.
   The exact trust source, root, and provisioning process are **OPEN** and are
   not supplied by this candidate.
2. **Establish accepted genesis provenance.** Independently authenticate the
   accepted genesis identity and its environment. Parse the intended genesis
   input and compute its canonical hash; compare it to that independently
   accepted value. A local calculation or equality check without authenticated
   provenance is insufficient.
3. **Establish mapping-purpose issuer authorization.** Independently verify
   evidence that the policy issuer is authorized specifically to approve
   runtime→wire mapping policy for the relevant scope. Do not infer this
   purpose from bundle-signing, transport, bootstrap, or generic signing
   authority.
4. **Authenticate policy bytes.** Parse one supported canonical policy
   representation and authenticate its exact bytes under the approved
   construction. Verify its issuer against step 3. Reject duplicate,
   ambiguous, malformed, or unsupported policy content.
5. **Check binding and applicability.** Check purpose, environment, accepted
   genesis identity, full runtime `u64`, expected wire `u32`, version, scope,
   and applicability against the independently established context. Do not
   derive the expected wire ID from a message or the runtime ID.
6. **Check currentness.** Use independently authenticated currentness and
   succession evidence to establish that this is the unique applicable policy
   and that it is not revoked, stale, or rolled back. The evidence source,
   replacement rules, and first-use enrollment are **OPEN**.
7. **Resolve and hand off.** Resolve one explicit mapping or refuse. Pass that
   exact `u32` unchanged as the future v2 domain's `expected_wire_chain_id`;
   downstream code must not re-derive, substitute, truncate, default, or copy
   it from inbound data. This establishes only a mapping, not permission to
   sign.

No step is currently implemented as a Route B acceptance path. The sequence
does not establish provisioning, freshness, anti-rollback, signer authority,
or feasibility.

## 3. Restart and recovery sequence

After restart, repeat independent verification rather than treating a cached
policy or valid historical signature as proof of currentness:

1. Re-establish the deployment context and accepted genesis provenance from
   the independently authorized sources. Recompute and compare the canonical
   identity; do not let the policy establish the identity used to authenticate
   itself.
2. Re-establish the mapping-purpose delegation and verify that the issuer
   remains authorized under the approved currentness rules.
3. Re-authenticate the exact policy bytes, verify all bindings and applicability,
   and independently establish current policy status and anti-rollback state.
4. If any authority, provenance, currentness, recovery, or signing-history
   evidence is missing, conflicting, stale, rolled back, or unavailable,
   refuse/unavailable. Do not silently use cached state, infer success from a
   matching mapping, or permit VM-state recovery to authorize signing or
   participation.

The recovery authority, independently authenticated recovery evidence,
first-use enrollment, currentness source, anti-rollback mechanism, and
signing-history continuity are all **OPEN**. This sequence does not assert
they exist.

## 4. Refusal conditions

The future path must return refusal/unavailable—not a guessed or
success-shaped mapping—if any required evidence is:

- missing, malformed, unsupported, or unauthenticated;
- ambiguous or duplicated, including multiple candidate policies or mappings;
- signed by an issuer without independently established mapping-purpose
  authority;
- bound to another environment, accepted genesis, runtime ID, scope, or
  version;
- conflicting with independently accepted genesis or policy evidence;
- stale, revoked, superseded, or rolled back;
- unavailable at first use or restart; or
- insufficient to establish currentness, anti-rollback, or recovery authority.

There is no fallback to dormant aliases, an inferred numeric cast, incoming
bytes, a prior cached policy, bundle/transport/bootstrap authority, or local
hash equality.

## 5. Mapping and identity boundaries

- The authenticated deployment policy is the mapping source. Dormant standard
  aliases are candidate expected values only; an alias alone is never
  authority.
- A custom deployment requires an explicit authorized mapping. Missing,
  inconsistent, unsupported, ambiguous, or out-of-range required input
  refuses. Runtime `u64` and wire `u32` semantics remain separate; no numeric
  cast or equality rule is assumed.
- Never guess, truncate, default, or derive expected wire ID from inbound
  bytes. Carry the exact policy-resolved `u32` unchanged into the future v2
  signing domain.
- A successful mapping match establishes only the mapping. It grants no
  signing permission, finality, currentness, restart safety, or signer
  exclusivity.
- Do not reuse bundle-signing, transport, or bootstrap authority for mapping
  purpose. The separately authenticated mapping-association alternative is
  **UNSELECTED**.
- Preserve **A50-F1 OPEN**: the inspected canonical genesis preimage omits
  `GenesisConfig.extra` despite its documentation. `extra`, or any other
  field outside that preimage, cannot carry issuer or mapping authority while
  relying on the current canonical hash to authenticate it.

## 6. Source-established limits and open obligations

**Source-established:** the external-genesis path parses the file and computes
a canonical hash; an expected hash is optional on inspected DevNet/TestNet
paths, and embedded-genesis paths can skip external verification
(`crates/qbind-node/src/pqc_boot_genesis.rs:215-248`;
`crates/qbind-ledger/src/genesis.rs:1797-1855`). This is equality checking,
not independent proof of provenance or freshness. The current genesis
authority fields do not provide mapping-purpose delegation. The v2 signing
domain binds the caller-supplied expected wire ID but does not authenticate
where it came from (`crates/qbind-wire/src/pv_signing_domain.rs:185-234,280-290`).

**OPEN:** Decision B / first-use and current authorization; D7 missing-owner
freshness gap; signer exclusivity; cross-process fencing; signing-history
continuity; recovery authority and evidence; finality handoff; all six identity
bindings; cursor non-entanglement; native post-quantum construction and
continuity. The execution cursor is not a signer position or freshness
source. No applicable QBIND route or production caller is established here.

## 7. Future review controls

All controls below are **FUTURE / NOT AUTHORIZED / NOT EXECUTED**. They are
not authorization to run an experiment or implement any component.

| Control | Positive evidence sought | Negative controls |
|---|---|---|
| Independent genesis provenance | Accepted identity is independently authenticated before policy inspection and agrees with the parsed canonical identity. | Reject a locally calculated or matching hash without independent provenance; wrong environment/genesis; missing, ambiguous, or substituted evidence. |
| Mapping-purpose delegation | Independently authenticated authorization grants the named issuer this exact mapping purpose and scope. | Reject self-naming policy, wrong-purpose issuer, and bundle-signing/transport/bootstrap authority. |
| Policy authentication and binding | Exact policy bytes authenticate and bind purpose, environment, genesis, runtime `u64`, wire `u32`, version, scope, and applicability. | Reject altered/malformed bytes, wrong issuer/genesis/IDs, duplicate entries, unsupported version, ambiguous or out-of-range values. |
| Currentness and restart | Independently authenticated succession/currentness and anti-rollback evidence survive restart under an owner-approved rule. | Reject stale/revoked/rolled-back/conflicting policy; missing first-use/current owner; unavailable recovery evidence; historical signature alone. |
| Exact domain propagation | The exact policy-resolved `u32` reaches the v2 domain unchanged. | Reject truncation, cast, re-derivation, defaulting, inbound-byte substitution, or treating mapping success as signing permission. |
| Sensitivity and refusal | Every required-evidence failure returns refusal/unavailable with no success-shaped fallback. | Exercise missing, malformed, ambiguous, conflicting, stale, substituted, rolled-back, and unavailable evidence only after separately authorized future validation. |

No tests, experiments, resolver implementation, node, or activation are
authorized by this document.
