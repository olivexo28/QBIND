# A33-F1 — initial DevNet public-association authentication candidate

**CANDIDATE FOR INDEPENDENT REVIEW AND OWNER DECISIONS — NOT APPROVED.**
The founder-authorized initial-DevNet direction and public-first comparison
direction are approved as directions only. This document selects no
credential format, trust root, provisioning backend, restart policy, or
production startup behavior. It does not authorize startup, signer loading,
signing, recovery, or restart. Activation remains **DISABLED**; public DevNet
remains **NO-GO**. A33-F1 / E27 and other recorded obligations remain
**OPEN**.

## Revision and scope

The documentation branch starts from reviewed test endpoint
`9c0f14c14cfe7eb662e7c3e871934f0cddaf5694`, tree
`0e11bd861f38870f58047f6c2158c0680ef3de3a`, parent
`8df5c5be68ef14fc690d08b4d315b6146ad2d4e2`. The pinned expected main is
`810a6759ef1e3ddb42c9a0f09f78502dc4655276`, tree
`52fb056deb02677260319519fad10ed588bb10de`.

The passed public-first comparison slice remains **PASSED WITH LIMITATIONS**
within its reviewed synthetic scope. It demonstrates comparison controls,
not real founder provisioning, authenticated authority, production startup
enforcement, currentness, or signer control
([test evidence](a33-f1-public-identity-comparison-test-evidence-20261108.md)).
This candidate adds no code and does not rerun tests.

## Candidate authority and provenance

### Candidate trust chain

The narrow candidate is a founder-authorized, digitally signed association
whose expected values are authenticated by a verifier key provisioned
independently of the association and of the destination record being
classified:

1. A founder-approved authority approves the association tuple below and
   signs an unambiguous, domain-separated representation of every field.
   The signed representation must bind its format/version and distinguish
   the association-signature suite from the validator consensus signature
   suite contained in the tuple.
2. One candidate anchor source already represented in QBIND is
   `GenesisConfig.authority.bundle_signing_authority_roots`: root entries can
   carry a suite, full public key and fingerprint, and the authority block is
   included in the canonical genesis hash
   ([authority schema][genesis-authority-block],
   [hash encoding][genesis-authority-hash]). This can authenticate the
   association only if the expected genesis hash itself was authenticated
   independently before classification. The existing Trust-Anchor Authority
   Model describes out-of-band genesis delivery as an assumption, not a
   proven runtime channel ([authority model assumption][genesis-anchor-spec]).
   The boot verifier compares against `config.expected_genesis_hash`, but
   that comparison does not authenticate how the configured expected hash
   was provisioned ([boot verifier][boot-verifier]).
   Alternatively, an owner could approve a separate bootstrap anchor
   provisioned through an independently authenticated initial deployment
   channel.
   The association may be stored locally as untrusted bytes; it becomes an
   authenticated expected association only after verification against that
   independently trusted anchor and validation of all required fields.
3. Before any future comparison, the verifier must establish that its trust
   anchor itself came from the approved channel and is not being read from
   the same mutable destination record or namespace as the untrusted
   association. A public key, its fingerprint, a self-signed artifact, or a
   matching local record cannot authenticate its own provenance.

This is a candidate trust-chain shape, not an installed root or provisioning
procedure. For the genesis-root variant, the founder authority is authenticated
only if the expected genesis hash is independently provisioned and protected;
the presence of `authority` in a local genesis file is not itself proof.
DevNet validation permits an empty authority-root set, and the association
verifier cannot use an absent root. The owner must designate who may
approve/sign, whether that is one founder or a threshold, how the initial
genesis hash or separate verifier key is authenticated, where the anchor is
kept, how it is bound to this deployment, and who can replace or revoke it.
An anchor read from operator configuration can be independent only if that
configuration is itself protected and authenticated outside the
attacker-controlled source being classified; no such channel is established
by configuration alone.

If an attacker can replace both the association and its verifier anchor, the
signature check cannot detect that substitution. If the attacker controls the
founder signing key or its authorization process, they can create apparently
valid associations. A compromised namespace can substitute/delete local
artifacts, deny access, or replay a previously valid association. A canonical
path and advisory lock do not establish filesystem-incarnation identity,
exclude non-cooperating writers, or protect an anchor stored in the same
compromised domain.

### Candidate association

The signed expected association would bind all seven identity fields:

```text
environment
numeric_chain_id
full canonical genesis identity
destination identity
validator_id
validator consensus signature suite
complete validator consensus public key
```

The proposed external-genesis identity is the full canonical genesis hash
([canonical hash helper][canonical-genesis-hash]): any reread must derive
fields and hash from the same owned parse and compare the hash with the
retained boot hash when present ([boot identity][boot-identity]). The
embedded-genesis and missing-retained-hash cases remain unresolved. The
destination identity representation, its relationship to textual genesis
`chain_id`, environment-to-numeric-chain mapping, validator-ID mapping, and
supported consensus suite still require explicit owner decisions. The values
in a local invocation are observations; the signed tuple is expected authority
only if its signer and verifier anchor have independently authenticated
provenance. A comparison match means only that these observed public values
match that authenticated tuple.

The association-signing suite is separate from the tuple's validator
consensus suite. This candidate does not choose either algorithm or define a
wire/file format. If the representation is signed, every tuple field and any
domain/version information must be covered by the signature; a short
fingerprint or an unsigned header is insufficient.

### Authenticity is not currentness or complete signing history

A valid signature can show that a signer authorized these bytes under the
selected trust anchor. It does not show that the association is the latest
authorized one, that it was not superseded or revoked, or that a replayed
valid association is current. Freshness needs an independently protected
monotonic/currentness authority or another explicitly approved mechanism.
No association-specific sequence rule, anti-rollback store, time policy,
online witness, recovery source, or restart policy is selected here. QBIND has
separate v2 bundle-signing-key rotation/revocation and authority-marker
surfaces, but those govern another key purpose and do not establish freshness
for this validator identity tuple
([v2 ratification][ratification-v2]; [authority state][authority-state]).

Likewise, an authentic public key does not prove that signing history is
complete, that prior signed decisions are represented, that the signer
has not signed elsewhere, or that the signer is exclusively controlled by
this node. The signing-state contract identifies the durable anti-rollback
anchor as unresolved and records that restart/recovery does not supply an
authenticated, rollback-resistant history commitment
([continuity contract §1, §6.6][continuity]). Authentication of the
association and completeness/currentness of signing history remain separate
claims.

## Lifecycle and refusal

Candidate refusal-only verification would refuse to return an authenticated
association when the trust anchor or association is missing, unreadable,
malformed, ambiguous, unsupported, unauthenticated, foreign to the selected
environment/chain, or has an invalid signature. The later comparison would
also refuse missing or unavailable required observations and any mismatch in
any of the seven fields. There is no default tuple, fallback to a local
record, path, fingerprint, signer, or unsigned DevNet value. Diagnostic
detail does not turn refusal into permission.

Initial provisioning, an authorized later association change, trust-anchor
rotation/revocation, validator-key replacement, and recovery from missing or
corrupt state are distinct decisions. This candidate defines no automatic
replacement, clearing, repair, recovery, or “first record wins” behavior.
Until an owner-approved lifecycle can authenticate both the authority and
its currentness, a record's apparent match is not permission to proceed.

## Startup boundary and route limits

For the candidate **normal initial-DevNet route with `data_dir`**, the
proposed verifier/comparison position remains after normal destination
ownership and before the reviewed protected startup effects. The normal route
acquires and holds the advisory destination lock at
`main.rs:2515-2552`; this is the previously reviewed candidate boundary, not a
production hook
([ownership and lock sources][ownership]).
`SignerLoaded` remains a protected effect in the reviewed route model
([route model][route-model]). This proposal does not move private-key loading
earlier. A public association check before that boundary would not fence or
verify the actual later signer. Any later comparison with the actual signer's
full public key is a separate, unapproved check after `SignerLoaded`; it
cannot establish exclusive custody or history completeness.

The route also has effects before that candidate point: configuration/genesis
processing precedes destination-lock acquisition, and the normal setup may
create the destination and lock file before classification. Requested restore
has an early consensus-storage open before later restore processing; reset
branches separately and acquires its own lock; no-data-directory startup has
no destination lock; LocalMesh has a separate execution route. The previous
public-first contract records these route differences and their specific
source boundaries ([route proposal][route-proposal]). This candidate covers
none of restore, reset, no-data-directory, or LocalMesh. Those routes need
separate owner decisions and protected-effect ordering reviews.

For external genesis, any reread used to acquire identity fields must derive
those fields and the full canonical hash from the same owned parse and compare
that hash to the retained boot hash when present. The existing normal boot
flow records `None` for embedded genesis; this candidate does not treat `None`
as a wildcard or choose a production policy for it. Embedded genesis and
missing retained hash remain unresolved.

The normal lock is `flock(LOCK_EX | LOCK_NB)` on an open descriptor of
`<data_dir>/restore.lock`, and the source describes it as advisory
([lock implementation][lock]). It excludes only cooperating participants.
The source's canonicalized destination is an absolute path, not a
filesystem-incarnation proof ([destination helper][destination]). A stable
namespace and cooperating-process assumption would therefore need explicit
owner acceptance. Neither assumption proves that there is only one signer or
that no other process/host can use a copy of the key.

## Existing mechanisms and fit

| Existing QBIND mechanism | What is reusable or informative | What it does not establish for this candidate |
|---|---|---|
| Signed PQC trust bundle | `TrustBundle` includes environment and optional chain ID; its signature envelope names a signing-key ID and suite. `BundleSigningKeySet` parses full public-key specifications with duplicate and length checks. The verifier checks a canonical, domain-separated preimage with ML-DSA-44 and fails on missing keys or bad signatures ([bundle schema/key set][bundle-schema], [bundle verifier][bundle-verifier]). | This is a transport trust bundle, not the seven-field validator association. It lacks destination identity, validator ID, consensus suite/key and full canonical genesis identity as required fields; its signature domain is transport-specific. Its verification keys are passed in by the caller, so they are not independently authenticated merely because the bundle verifies. The code explicitly permits an unsigned DevNet bundle on the empty-key compatibility path ([DevNet unsigned behavior][bundle-devnet]). Reusing its format or DevNet policy without a separate bootstrap anchor would be circular or incomplete. |
| Genesis `authority` block | `GenesisConfig` now has an optional, canonical-hash-bound `authority` block. `GenesisAuthorityRoot` has a suite, fingerprint and optional full public key; the block includes bundle-signing-authority roots and a sequence field ([genesis schema][genesis-schema], [root fields][genesis-root], [authority block][genesis-authority-block]). This is a plausible bootstrap root source if the expected genesis hash is itself independently authenticated. | The block is optional and DevNet permits empty root sets. The expected hash/provisioning channel is still an owner trust decision. Its defined root set is purpose-specific to bundle signing or transport; owners must decide whether to add a distinct validator-association authority or explicitly approve a separate purpose. The code documents that authority metadata is hash-bound but does not by itself establish the genesis bytes' external provenance. A prior design document's “None today” table is stale against this pinned schema ([authority-model current-state][authority-model-current-state]). |
| Bundle-signing ratification verifier | `BundleSigningRatification` signs and binds environment, chain ID, canonical genesis hash, authority-root fingerprint, suite and complete target public key. `verify_bundle_signing_key_ratification` checks those fields and verifies against a root in the genesis authority block ([ratification type][ratification-type], [ratification verifier][ratification-verifier]). The existing signed sidecar loader refuses missing/unreadable/malformed input ([ratification input][ratification-input]). This is the closest implemented cryptographic precedent for founder-authorized public-key association. | It authorizes exactly a **bundle-signing** key, not the local validator identity. It has a chain-id string, not a separately authenticated numeric-chain field, and does not bind destination or validator ID. Its v1 contract excludes rotation, revocation, anti-rollback sequence and validity windows. The Run 130 v2 type comment records that v2 is not wired into production enforcement surfaces ([v2 type comment][ratification-v2]); however, pinned main later added a startup v2 sidecar dispatch, conditional on the enclosing `ratification_gate_decision.should_invoke()` gate, followed by a Run 136 preflight ([v2 startup dispatch][ratification-v2-startup], [v2 startup preflight][ratification-v2-preflight]). The preflight returns early when there is no v2 sidecar or no data directory; when both are available it calls the v2 verifier. DevNet's outer ratification gate remains operator-opt-in ([DevNet ratification gate][ratification-policy]). This is bounded wiring, not complete v2 enforcement: A23-F1 remains OPEN for the K≠T ratified-target/bundle-signer gap, and the recorded invocation, data-directory and independent-genesis-provenance limitations remain ([A23-F1 obligation][a23-f1]). Neither v1 nor v2 authenticates this validator tuple. The startup caller still consumes locally supplied genesis and sidecar inputs ([startup ratification caller][ratification-startup]); none of this is an already approved identity classifier. Reuse the trust-chain pattern only after owner decisions, with a distinct association purpose and full tuple binding. |
| Existing genesis-bound consensus authority helper | It performs a single owned external-genesis load, validates it and compares the resulting hash to the retained boot hash when present before building validator authority ([genesis authority helper][genesis-helper]). The source demonstrates a useful same-parse/retained-hash boundary for external genesis. | This is not a founder-signature/provisioning path, does not bind destination identity, and only supports external genesis. The `--consensus-authority-from-genesis` route is explicitly refused in production pending D4-D7 ([disabled activation guard][genesis-disabled]); it must not be treated as approved startup authority or reused as an admission decision. Its local-signer comparison occurs only after loading the signer, which remains a protected effect. |
| Local signer loader | After loading, `LoadedValidatorSigner` has validator ID, suite, complete derived public-key bytes and a short display fingerprint ([signer result][signer-result]). This could support a distinct post-load comparison if separately approved. | It does not provide the public key before signer loading. The four-byte-prefix fingerprint is not a full identity. Calling this loader earlier would cross `SignerLoaded`, and local signer output does not authenticate the expected association. |
| Signing reservation journal and continuity contracts | Journal positions bind validator, network/genesis, proposal/vote kind and originating view ([journal position][journal]). | A per-position record is not an independently provisioned founder association, a freshness witness, or proof that complete signing history is present. The documented durable anti-rollback anchor remains unresolved ([continuity contract][continuity]). |
| Genesis configuration / boot hash | The schema includes textual `chain_id`, validator entries and the optional authority block ([genesis schema][genesis-schema]); boot verification can retain a canonical hash for external genesis ([boot identity][boot-identity]). | The schema does not define the complete seven-field validator association. A configured expected hash or matching local genesis record is only independent if its provisioning is independently authenticated. The embedded-genesis path has no retained external hash. |

### Candidate choice and owner decisions

The smallest plausible next shape is a **new signed validator-association
artifact** authenticated by an owner-approved genesis-bound root, provided an
independently authenticated expected genesis hash is available. QBIND already
has the relevant cryptographic trust-chain pattern in
`BundleSigningRatification`; an association verifier would still need a
distinct purpose/domain and must bind destination identity and validator ID
in addition to the existing public-key, chain, environment and genesis
dimensions. Owners must decide whether the association authority is a
separate root set in the hash-bound genesis block or an independently
provisioned root; the existing bundle-signing roots are not automatically
authorized for this purpose. Neither option selects a file format, backend,
algorithm, or deployment procedure.

Before any implementation, owners must explicitly decide:

| Owner decision | Required choice; unresolved risk if not decided |
|---|---|
| Founder authority | Named approving authority; single or threshold approval; how revocation and delegation work. |
| Verifier trust anchor | Exact source and independent authentication of initial delivery; how it is protected from replacement with the association; whether it is bound to a specific DevNet deployment. |
| Credential semantics | Canonical signed representation, domain/version, association-signing suite, required tuple fields, and whether expiry/sequence/revocation data are included. |
| Identity semantics | Canonical genesis identity; environment/numeric-chain binding; destination identity beyond path; validator-ID and consensus-key/suite mapping. |
| Currentness/recovery | Independent rollback-resistant freshness source, replacement/revocation handling, and refusal behavior when currentness or recovery evidence is unavailable. No automatic clear or recovery is assumed. |
| Runtime scope/order | Whether only normal DevNet is in scope and the exact boundary relative to every protected effect; separate choices for restore, reset, stateless, LocalMesh, and embedded genesis. |
| Operational assumptions | Stable namespace, cooperating lock participants, trust-anchor secrecy/integrity where applicable, and whether signer exclusivity is required and how it could be established. |

No trust anchor, profile, backend or lifecycle policy is approved by this
candidate. A signed association can be authentic while stale; a current
association can still fail to prove exclusive signing control or complete
history. PR #11's final-tree transfer investigation remains **CLOSED** and is
not reopened here.

The repository's Trust-Anchor Authority Model is a design document, not a
runtime guarantee. Its older “None today” statement about genesis authority
roots conflicts with the current optional hash-bound `GenesisConfig.authority`
schema. The schema and verifier implementation at the pinned source revision
are controlling evidence here ([authority-model current-state
statement][authority-model-current-state]; [current genesis schema][genesis-schema]).

## Next isolated slice — FUTURE / NOT EXECUTED

After owners approve the trust profile and tuple semantics, the smallest
follow-on should be a test-only verifier slice with synthetic founder and
verifier keys, synthetic association bytes, and no live signer or production
startup integration. If source implementation is later authorized, keep it
unwired and isolated until ordering and lifecycle review separately approves
integration.

Required acceptance controls, all **FUTURE / NOT EXECUTED**:

1. A signature made by the synthetic authorized key over all seven fields
   returns only an authenticated-test-fixture result; it grants no startup,
   signer, signing, recovery, or restart authority.
2. Each tuple field is independently mutated, omitted, malformed, or foreign
   to the expected DevNet/chain profile and is refused. Include full-key
   same-short-prefix mismatch.
3. Mutating a signed field, changing the signature, using an unknown or
   wrong-suite signer key, or substituting an unauthenticated verifier anchor
   refuses. A same-checker bypass makes the matching negative control pass,
   and a positive control prevents reject-all implementations from passing.
4. A matching local record cannot replace missing/untrusted verifier
   authority; a test-only fallback mutation must invalidate that negative
   assertion.
5. Replay/currentness controls are separate: the test must not claim
   authenticity implies freshness. If an owner later selects a currentness
   mechanism, add its stale/revoked/rollback controls as a separate approved
   slice.
6. If any future slice claims startup ordering or refusal blocks protected
   effects, use observable protected-effect callbacks and a sensitive bypass
   control, including `SignerLoaded`. Test-harness behavior does not prove
   production CLI ordering.

Such a test would still not prove trusted real-world founder-key delivery,
namespace-race resistance, filesystem-incarnation identity, signer
exclusivity, complete signing history, production startup enforcement,
durability, recovery authority, or restart safety. Existing public-first
comparison results remain synthetic and unchanged in scope.

## Pinned source references

The QBIND source links below pin to main commit
`810a6759ef1e3ddb42c9a0f09f78502dc4655276`. The reviewed public-first
route-proposal link is separately pinned to the reviewed proposal commit
`5ca41d62395b20560fe2f12087142e811200fbf9`.

[ownership]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2515-L2552
[route-model]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs#L124-L138
[route-proposal]: https://github.com/olivexo28/QBIND/blob/5ca41d62395b20560fe2f12087142e811200fbf9/docs/security/evidence/a33-f1-public-first-startup-identity-contract-proposal-20261108.md#L145-L173
[lock]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/restore_completion.rs#L800-L911
[destination]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/restore_completion.rs#L148-L179
[bundle-schema]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_trust_bundle.rs#L276-L476
[bundle-verifier]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_trust_bundle.rs#L1488-L1544
[bundle-devnet]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_trust_bundle.rs#L973-L1007
[genesis-helper]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/genesis_consensus_authority.rs#L1404-L1450
[genesis-disabled]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L5403-L5435
[signer-result]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signer_loader.rs#L92-L115
[journal]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signing_reservation_journal.rs#L159-L184
[continuity]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md#L20-L36
[genesis-schema]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1299-L1358
[genesis-root]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L369-L400
[genesis-authority-block]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L749-L840
[genesis-authority-hash]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1555-L1672
[genesis-anchor-spec]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md#L140-L154
[boot-verifier]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_boot_genesis.rs#L215-L245
[canonical-genesis-hash]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1576-L1621
[authority-model-current-state]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md#L190-L205
[ratification-type]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/bundle_signing_ratification.rs#L160-L220
[ratification-verifier]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/bundle_signing_ratification.rs#L575-L705
[ratification-v2]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/bundle_signing_ratification.rs#L1309-L1370
[authority-state]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_authority_state.rs#L1-L40
[ratification-input]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_ratification_input.rs#L1-L95
[ratification-startup]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L123-L255
[ratification-policy]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_ratification_policy.rs#L140-L171
[ratification-v2-startup]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L6692-L6813
[ratification-v2-preflight]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L1176-L1258
[a23-f1]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md#L220
[boot-identity]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2404-L2449
