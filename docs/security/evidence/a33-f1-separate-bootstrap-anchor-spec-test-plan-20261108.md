# A33-F1 — separate bootstrap anchor: specification and isolated test plan

**DOCUMENTATION-ONLY SPECIFICATION AND TEST PLAN — NOT AN IMPLEMENTATION OR
PRODUCTION AUTHORIZATION.**

The owner-approved direction is to use a separate bootstrap anchor for
validating the initial-DevNet public identity association. The bootstrap
private credential and validator signer are separate roles, and the anchor's
purpose is association verification, distinct from bundle-signing authority.
Initial anchor delivery and anti-substitution protection still require
specification and review. A valid association does not establish freshness,
complete signing history, or exclusive signer control.

This direction approves no actual key, signature suite, file or wire format,
provisioning procedure, deployment, production wiring, or startup, signing,
restart, or recovery authority. Activation remains **DISABLED**; public
DevNet remains **NO-GO**. A23-F1 and A33-F1 / E27 remain **OPEN**.

## Scope and trust-chain specification

The proposed trust chain has distinct stages and roles:

1. **Founder approval.** An owner-designated founder authority approves the
   exact public identity association and its permitted deployment scope.
   Whether approval is by one founder, a threshold, or another governance
   arrangement is unresolved.
2. **Association signing.** The separately held bootstrap private credential
   signs a canonical, domain-separated representation of the association.
   This credential is not the validator's consensus-signing credential. The
   purpose and version are explicit and distinct from bundle-signing
   ratification. The exact encoding, signature suite, and credential custody
   are not selected.
3. **Independent anchor provisioning.** The verifier obtains the expected
   association-verification public anchor through a separately approved,
   deployment-bound channel. The association, destination record, and
   anchor must not be able to authenticate one another merely by co-location.
4. **Verification.** The verifier establishes the anchor's provenance and
   deployment binding, parses the association, checks its purpose/version
   and signing suite against independently authenticated policy, verifies
   its signature with that anchor, and validates all required fields. A
   failure at any of these steps produces refusal, not an authenticated
   expected association.
5. **Comparison.** Only after successful verification may a future
   refusal-only comparison compare observations with the authenticated
   association. Equality is a result separate from signature authenticity.
6. **Currentness/eligibility.** A separate decision would need independently
   trusted currentness evidence and policy. Without it, currentness is
   `Unresolved`; no inference of current, stale, or eligible status is
   available to the verifier.

These are separate, non-authorizing results:

| Result | What it establishes | What it does not establish |
|---|---|---|
| **Authenticity** | The association's signed representation verifies under the independently authenticated anchor and permitted verifier policy. | Equality to current observations, currentness, or permission to act. |
| **Equality** | Each required observed field equals the corresponding field in the authenticated signed tuple. | That the tuple is the latest association, is eligible, or grants permission to act. |
| **Currentness/eligibility** | Only what a separately approved, independently authenticated currentness policy and evidence can establish. | In the absence of that policy/evidence, the result is `Unresolved`, not current or eligible. |

Even when authenticity and equality both hold, a valid old association may
have been superseded. If trusted currentness evidence is unavailable, the
verifier cannot tell whether it was superseded. None of these results grants
startup, signer-loading, participation, signing, recovery, or restart
authority.

The association must authenticate every required field as one indivisible
tuple:

```text
environment
numeric_chain_id
full_genesis_identity
destination_identity
validator_id
validator_consensus_signature_suite
complete_validator_consensus_public_key
```

The association's own signing suite, purpose, and version are separate
metadata and must also be authenticated. A suite must be permitted by
independently authenticated verifier policy; an attacker-controlled header
cannot choose which suite is trusted. The representation must prevent
ambiguity, field omission, reinterpretation, or cross-purpose use. The
destination identity, environment-to-numeric-chain relationship, genesis
identity semantics, and validator-ID/key mapping remain owner decisions.
For external genesis, any acquired fields and canonical hash must derive from
the same owned parse and the hash must be checked against the retained boot
hash when present; `None` and embedded genesis remain unresolved
([boot-genesis verification][boot-genesis], [candidate genesis boundary][candidate-genesis]).

A local association record is untrusted input until this chain succeeds. A
self-signed association can prove only that its signer controls the key it
names; it cannot establish that the key is founder-authorized. A matching
record, a short fingerprint, a public key without authenticated provenance,
or unprotected configuration cannot establish its own authority. Likewise,
the identity of the validator signer is not the bootstrap anchor and must not
be substituted for it.

## Required anchor-delivery and anti-substitution properties

Any future provisioning design must demonstrate all of the following before
an anchor can be treated as expected authority:

| Required property | Acceptance condition |
|---|---|
| Independent anchor authentication | The expected anchor is authenticated by an owner-approved trust mechanism that is not the association or destination record being classified. If the bootstrap mechanism cannot authenticate the anchor's origin, classification refuses. |
| Deployment binding | The authenticated anchor is bound to the intended initial-DevNet deployment and cannot be silently reused for a different environment, numeric chain, genesis, destination, or validator association. The binding's exact fields and authority are owner decisions. |
| Anti-substitution | An attacker able to replace the association cannot also replace the expected anchor without detection under the accepted threat model. The same mutable local namespace must not be the sole trust source for both. |
| Controlled replacement | A named owner-authorized process controls anchor replacement, rotation, or revocation. An unrecognized or partial replacement, missing prior state, or unverifiable transition refuses; no automatic “first record wins,” clear, or recovery behavior is implied. |
| Integrity and availability | Missing, unreadable, malformed, ambiguous, unsupported, or unavailable provenance cannot default to a local value or a successful match. Denial of access may cause refusal but cannot create authority. |
| Honest scope | The accepted threat model states whether the initial provisioning channel, host, operator account, deployment tooling, storage namespace, or hardware root may be compromised. If the anchor and its independent authentication channel are both compromised, the verifier cannot prove the intended founder authority. |

Plausible mechanisms for owner review—not selections—include an independently
authenticated deployment package containing a public anchor; a separately
delivered, owner-authenticated anchor digest checked against a public key
obtained from the deployment channel; or a platform-protected trust store
whose enrollment and deployment binding are independently controlled.
Each requires an explicitly trusted initial channel and protection against
substitution and replay. A separately delivered digest is not independent
if it is fetched from the same compromised source as the key. A platform
store is not an authority unless its enrollment, update permissions, and
binding to this deployment are established. Operator configuration or a
canonical path alone does not establish that provenance. This document
selects none of these mechanisms, credentials, roots, or storage backends.

The approver, anchor custodian, initial delivery channel, deployment binding,
replacement/revocation authority, and response to host or namespace
compromise all require explicit owner decisions. A valid signature under a
substituted anchor is not evidence that the founder approved the association.

## Refusal outcomes and unresolved currentness

Verification failures produce no verified association. Comparison failures
produce no equality result. When trusted currentness evidence is unavailable,
currentness is unresolved and no eligibility or authority follows; any
previously established authenticity and equality remain non-authorizing.

| Input or result | Required outcome |
|---|---|
| Missing or unavailable anchor or association | Refuse; do not infer a default or fall back to another local record. |
| Unreadable anchor, association, or provisioning evidence | Refuse; surface the failure without converting it to absence or success. |
| Malformed, ambiguous, truncated, or structurally incomplete data | Refuse before pure comparison; do not guess field meanings or choose one of multiple candidates. |
| Unsupported purpose, version, encoding, or association-signing suite under independently authenticated policy | Refuse; no compatibility downgrade, attacker-selected suite, or cross-purpose interpretation. |
| Wrong, untrusted, or substituted anchor; unestablished provenance or deployment binding | Refuse; parsing a public key or matching a stored fingerprint is not authentication. |
| Invalid signature or a signature not covering every required field | Refuse; no unsigned or partially signed fallback. |
| Wrong environment/chain or any mismatch in the seven association fields | Refuse equality; missing required observations are not matches. |
| No independently trusted currentness evidence or policy | Return `Currentness::Unresolved`; do not call the association current, stale, or eligible. Authenticity and equality, if established, remain separate results. |

The unresolved-currentness case requires a separately approved mechanism and
authority, such as a rollback-resistant version state or an independently
authenticated revocation/current-association source. No such mechanism,
sequence semantics, durable state, refresh policy, or recovery authority is
selected here. A replayed authentic association may be stale, but without
trusted currentness evidence the verifier cannot know that it is stale.

## Startup boundary and separated safety claims

The candidate applies only to the previously reviewed normal initial-DevNet
route with a data directory: a future public comparison would be considered
after normal destination ownership and before reviewed protected effects.
This is a proposal boundary, not a production hook. `SignerLoaded` remains a
protected effect; this specification does not move private-key loading
earlier. A pre-load public association check does not verify or fence the
actual subsequently loaded signer. Any later actual-signer comparison would
be a separate, unapproved step
([normal ownership route][ownership], [protected-effect model][route-model]).

Restore, reset, no-data-directory startup, LocalMesh, and embedded-genesis
handling remain unresolved and are not covered by this direction. Their
ownership, available observations, and ordering differ; a normal-route
comparison cannot be generalized to them
([reviewed route proposal][route-proposal]). External-genesis acquisition
must preserve the same-parse and retained-boot-hash checks described above.
Neither a verified association nor a synthetic test match is permission for
startup, signing, recovery, restart, or participation.

The following are distinct claims and must not be inferred from association
authenticity:

- **Currentness / anti-rollback:** proof that an association is not stale,
  revoked, or replaced by an older valid record.
- **Signing-history completeness:** proof that all prior signing decisions
  and durable anti-equivocation state are represented and rollback-resistant.
- **Signer exclusivity:** proof that no other process, host, operator, or
  copied key can sign as the validator.
- **Durable intent and fencing:** proof that signing intent, external effects,
  barriers, and publication are correctly ordered and protected from
  concurrent or restarted actors.
- **Recovery authority:** proof of who may restore or replace missing,
  conflicting, or corrupt state, and what authenticated evidence governs it.

These require separate authority, lifecycle, persistence, and operational
decisions. A destination path or advisory lock does not prove a stable
filesystem incarnation, prevent all namespace substitution, or establish
signer exclusivity. No backend, restart policy, durable format, fencing
mechanism, or recovery procedure is chosen.

## Existing source capabilities and limits

Pinned main contains related components, but none is the proposed separate
bootstrap-anchor implementation:

| Existing source | Bounded observation |
|---|---|
| Genesis authority schema and canonical hash | `GenesisConfig.authority` is optional and included in canonical genesis hashing; its existing authority roots are for bundle-signing/transport purposes, not automatically for validator-association verification. The local presence of a hash-bound block does not authenticate genesis provenance ([genesis schema][genesis-schema], [authority hash][authority-hash]). |
| Bundle-signing ratification | The v1 verifier is a signed bundle-key authorization mechanism, not the validator identity association ([v1 verifier][ratification-v1-verifier]). The v2 type comment says Run 130 did not wire v2 into production enforcement, while pinned main has a conditional startup dispatch and preflight; this bounded wiring does not close A23-F1 or authorize validator associations ([v2 type comment][ratification-v2], [startup dispatch][v2-startup], [startup preflight][v2-preflight], [DevNet gate][devnet-gate], [A23-F1][a23-f1]). |
| Existing sidecar loader | It loads a local sidecar and distinguishes I/O/parse failures, but explicitly does not authenticate the provenance of the file or its trust anchor. It is not a bootstrap provisioning channel ([ratification input][ratification-input]). |
| Signer loader and reviewed route model | Complete validator public-key bytes are available after signer loading, which remains protected; the reviewed route model marks `SignerLoaded` protected. This does not provide an early public anchor or verify its provenance ([signer result][signer-result], [protected-effect model][route-model]). |
| Public-first comparison slice | The reviewed test demonstrates only synthetic comparison behavior, not authenticated provisioning or production enforcement ([comparison evidence][comparison-evidence]). |

The separate bootstrap anchor's purpose must remain distinct from the existing
bundle-signing authority. The documented A23-F1 K≠T ratified-target/bundle-
signer gap remains open; no v1/v2 bundle-signing result is treated as
association authority. All prior accepted findings remain limited to their
reviewed scopes.

## Isolated test plan — FUTURE / NOT EXECUTED

This section defines an unwired test plan only. No tests are implemented or
run by this document. The test must use disposable synthetic keys and
association data, no operational keys, no live signer, no production startup
hook, and no authority-bearing callback. Naming an existing QBIND suite or
format as a fixture would not select it for production.

### Fixture and decision interfaces

Use separately generated synthetic roles:

- `K_bootstrap_private` / `K_bootstrap_public`: synthetic bootstrap
  credential and corresponding public anchor. The private key signs the
  association; the test harness treats the public key's expected value and
  deployment binding as independently authenticated fixture inputs;
- `K_validator_public`: synthetic complete validator public key contained in
  the seven-field tuple, with no live or usable private signer.

The test harness supplies a fixed expected anchor with an explicit
`provenance_authenticated = true` fixture condition. This models, but does
not implement or prove, real independent provisioning. Define a test-only
canonical encoding with a purpose and version and signed bytes that cover
every tuple field plus the association-signing suite, purpose, and version.
Test permitted-suite policy is a separately fixed, authenticated fixture
input; never select a verifier based only on an untrusted association header.
Sign with `K_bootstrap_private`, not a validator key. The chosen test
encoding and crypto primitive are fixture details only; they do not select a
production signature suite or wire/file format.

Keep acquisition/parsing distinct from pure verification:

```text
acquire_anchor_and_association(input) -> ParsedEvidence | AcquisitionError
verify_association(parsed, independently_expected_anchor,
                   authenticated_verifier_policy)
    -> Authenticity::Verified | VerificationRefusal
compare_observation(verified_association, observed_tuple)
    -> Equality::Equal | Equality::Mismatch(field) | Equality::Unavailable(field)
evaluate_currentness(verified_association, trusted_currentness_evidence?)
    -> Currentness::Current | Currentness::NotCurrent | Currentness::Unresolved
```

No acquisition error may be converted into a successful verification or
comparison. Authenticity, equality, and currentness are reported separately
and are non-authorizing; `Currentness::Unresolved` is not a success or a
`NotCurrent` finding. `Currentness::NotCurrent` could be reported only if
separately approved trusted evidence supports that result. Do not build the
expected tuple by copying the observation under test. Keep temporary fixture
setup and cleanup outside the decision functions.

### Test matrix and expected results

| Case | Input variation from the valid fixture | Expected result |
|---|---|---|
| Positive synthetic control | Correct independently expected anchor and authenticated test verifier policy; association signed by `K_bootstrap_private`; supported authenticated purpose/version/suite; all seven fields fixed and matching. | Report `Authenticity::Verified`, `Equality::Equal`, and `Currentness::Unresolved` separately when no currentness evidence is supplied. Assert none grants startup, signer-loading, participation, signing, recovery, or restart authority. |
| Missing/unavailable evidence | Independently remove the anchor, association, signature, or any required observation, one at a time. | Acquisition or comparison refusal as appropriate; never a match. |
| Read/parse failures | Simulate unreadable input, malformed encoding, truncation, duplicate/ambiguous association, and unsupported schema before invoking pure verification. | Typed harness acquisition refusal; assert the pure verifier was not called for acquisition failures. These are simulated inputs unless an independently approved read-only helper is later used. |
| Anchor substitution | Keep association bytes fixed but provide a different anchor, or mark anchor provenance absent/untrusted. | Refuse before authenticated-fixture result. A test-only bypass that accepts the substituted/untrusted anchor must cause the negative assertion to fail. |
| Signature failure | Flip a signature byte, sign with a non-authorized synthetic key, or alter one signed field without re-signing. | Verification refusal. A test-only signature-bypass mutation must cause the corresponding negative assertion to fail. |
| Wrong purpose/version | Change purpose or version to an unsupported or bundle-signing value, then sign the otherwise well-formed changed payload with `K_bootstrap_private` so the signature itself is valid. | Verification refusal specifically for purpose/version. A test-only purpose/version bypass must make this negative assertion fail. |
| Wrong/unsupported association-signing suite | Supply an unsupported suite in authenticated test policy, or alter the suite metadata and re-sign using the synthetic key while keeping the trusted policy fixed. Also exercise a wrong-suite key that cannot verify under the permitted suite. | Refuse for policy/suite mismatch or signature verification. Test-only mutants that trust the header instead of policy or skip suite/key compatibility must make the corresponding negative assertions fail. |
| Validator consensus suite | Independently change the validator consensus-suite field inside the seven-field tuple, holding association-signing suite and key constant. | The signed-field mutation fails verification; a separately re-signed tuple compared against the fixed expected tuple mismatches the validator consensus suite. Its binding sensitivity is tested separately from association-signing suite controls. |
| Individual field binding | With the valid signed association and expected anchor held fixed, independently change, omit, or mark unavailable each of: environment, numeric chain ID, full genesis identity, destination identity, validator ID, validator consensus suite, and complete validator public key. For signature-binding controls, change one encoded association field while retaining its signature; for comparison controls, change only the observation. For each field, create a sensitivity mutant in the shared fixture signing/verification encoding path that omits that field. | Normally, changing a signed field while retaining its signature fails verification, and changing only the observation returns that field's mismatch/unavailable result. Under the per-field omission mutant, sign the original fixture tuple with the mutated shared helper, then alter just that field while retaining the signature; the negative assertion that the changed tuple must fail verification must now fail because the omitted field leaves the signed input unchanged. Independently, a comparator mutant that ignores that field must make its comparison negative fail. Do not use a whole-signature bypass as a substitute for these per-field controls. |
| Wrong deployment/domain | Change the fixed expected deployment binding or present an association for another environment/chain/genesis/destination. | Refuse; do not treat a valid signature for another scope as a match. |
| Old association with unavailable currentness evidence | Use a validly signed association whose fixture bytes are also equal to the observed tuple, but provide no independently trusted currentness evidence. The test harness may know separately that it constructed this as an old version; do not pass that label to the verifier or currentness evaluator. | Report `Authenticity::Verified`, `Equality::Equal`, and `Currentness::Unresolved`. The verifier cannot determine whether this authentic, equal association was superseded. Do not call it stale, current, eligible, or authorized based on harness-only knowledge. |
| Expected-anchor integrity | Mutate the fixture's anchor provenance status or deployment binding without changing association bytes. | Refuse. A test-only provenance/deployment-binding bypass must make its negative control fail. |

Run positive controls alongside every negative/sensitivity family so a
checker that rejects all inputs cannot pass. Record which guard each
negative assertion exercises and show that bypassing the signature check,
purpose/version check, authenticated suite policy/key compatibility, anchor
provenance/deployment binding, or any one of the seven field bindings breaks
that assertion. For each tuple field, include the shared fixture
signing/verification-encoding omission mutant described above. These are
test-harness sensitivity controls, not evidence that a production control
exists.

### Evidence and limitations for a future execution

If separately authorized, retain the exact test source revision/tree,
commands, complete outputs, exit codes, test counts, fixture-generation
details, and cleanup result. Attribute those records to the source commit
and tree; if evidence is committed later, verify that test inputs did not
change. Report simulated acquisition failures separately from any real
helper behavior used.

The planned test does not prove real founder authorization, independent
anchor delivery, trusted provisioning, anchor custody or replacement,
filesystem race resistance, production CLI ordering, protected-effect
enforcement, currentness, anti-rollback, durable intent, complete signing
history, signer exclusivity, fencing, recovery authority, or restart safety.
If a later test claims orchestration or that refusal blocks protected
effects, it must add observable protected-effect callbacks—including
`SignerLoaded` where relevant—and sensitive bypass controls. Such callbacks
would prove only test-harness behavior, not real production ordering.

## Open owner decisions before production use

1. Who can approve an association, and what approval threshold or delegation
   rules apply?
2. What separately controlled channel authenticates and provisions the
   initial bootstrap anchor, and how is it bound to the intended deployment?
3. Who controls anchor replacement, rotation, revocation, and recovery after
   lost, compromised, or conflicting provisioning state?
4. Which canonical association encoding, distinct purpose/version, and
   association-signing suite are approved, without reusing bundle-signing
   authority implicitly?
5. How are environment, numeric chain ID, genesis identity, destination,
   validator ID, validator suite, and complete key represented and bound?
6. What independently protected mechanism establishes currentness and
   anti-rollback, and what does the system do when it is unavailable?
7. Which startup routes are in scope, and what separately reviewed
   pre-protected-effect ordering applies to normal startup, restore, reset,
   no-data-directory, LocalMesh, and embedded genesis?
8. What separate mechanisms and authorities establish signing-history
   completeness, signer exclusivity, durable intent, fencing, and recovery?
9. Which namespace, process-cooperation, host-compromise, and operational
   trust assumptions are accepted, and what evidence validates them?

Until these decisions and their evidence are independently reviewed, this
specification remains a proposal. It does not change A23-F1 or A33-F1 / E27;
both remain **OPEN**. Activation remains **DISABLED**; public DevNet remains
**NO-GO**.

## Pinned source references

QBIND source references below pin to main commit
`810a6759ef1e3ddb42c9a0f09f78502dc4655276`. The reviewed route proposal is
pinned separately to commit
`5ca41d62395b20560fe2f12087142e811200fbf9`.

[genesis-schema]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1299-L1358
[authority-hash]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1555-L1672
[boot-genesis]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_boot_genesis.rs#L215-L245
[candidate-genesis]: https://github.com/olivexo28/QBIND/blob/ddfcf588175cafb73b145ca65af4cd3c17f21cbc/docs/security/evidence/a33-f1-devnet-public-association-authentication-candidate-20261108.md#L102-L114
[ownership]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2515-L2552
[route-model]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs#L124-L143
[route-proposal]: https://github.com/olivexo28/QBIND/blob/5ca41d62395b20560fe2f12087142e811200fbf9/docs/security/evidence/a33-f1-public-first-startup-identity-contract-proposal-20261108.md#L145-L173
[ratification-v2]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/bundle_signing_ratification.rs#L1309-L1370
[ratification-v1-verifier]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/bundle_signing_ratification.rs#L575-L705
[v2-startup]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L6692-L6813
[v2-preflight]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L1176-L1258
[devnet-gate]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_ratification_policy.rs#L140-L171
[a23-f1]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md#L220
[ratification-input]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_ratification_input.rs#L1-L99
[signer-result]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signer_loader.rs#L92-L115
[comparison-evidence]: https://github.com/olivexo28/QBIND/blob/9c0f14c14cfe7eb662e7c3e871934f0cddaf5694/docs/security/evidence/a33-f1-public-identity-comparison-test-evidence-20261108.md#L67-L71
