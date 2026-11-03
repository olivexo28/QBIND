# RUN 422 — DevNet founding-authority decision and bootstrap requirements

**Selected design direction — founder-authorized bootstrap for the initial
DevNet.** This is a decision about the initial authority model, not an
authorization ceremony, approved protocol, deployment, operating profile, or
resource limit. It does not create credentials or establish that any operator,
storage, rollback protection, or activation mechanism exists.
No approver signature, credential fingerprint, operator, hosting provider,
device, threshold, or completed ceremony is supplied or implied.

This decision supersedes only the prior open question of *which role is to
authorize the initial DevNet configuration*. It does not supersede the
unresolved requirements or historical evidence below, and does not approve the
whole Profile A contract.

## 1. Decision and trust boundary

The founder may approve one exact initial DevNet network/genesis configuration
and its founding validator set: validator identities, consensus public keys,
suite identifiers, and voting weights. That founding membership is fixed within
the selected founding scope. Each designated validator operator controls its
own consensus key. A dedicated post-quantum (PQ) bootstrap authorization
credential is separate from all validator consensus keys and authorizes the
exact initial configuration, not consensus messages.

The founder role is a concentrated authority. Founder-credential compromise or
equivocation could approve conflicting initial configurations; neither
cryptographic integrity nor the label “founder” prevents that risk. A conflict
or uncertain first-use state must therefore stop activation; this decision
selects no adjudicator or recovery authority.

The founder decision does **not** authorize changing membership or weights,
later-epoch signing, protocol restriction bypass, use of stale authority,
resetting or erasing signing history, treating missing state as “never signed,”
or resuming a signer whose prior outcome may conflict. It does not establish
credential custody, a trust root, freshness, continuity, recovery, cross-host
exclusive use, or a unique first activation.

These are separate obligations; a successful result in one does not satisfy
another:

| Obligation | Required independently | Not established by selecting the founder role |
|---|---|---|
| A — activation authorization | A verifiable approval for the exact initial configuration, accepted under an independently trusted bootstrap root | Root distribution, credential, signature format, approval verification, activation marker, or ceremony |
| B — current-authority freshness | Evidence that the approved authority is current and not superseded or rolled back | A matching genesis hash, valid historical approval, equal epoch, or founder statement alone |
| C — signing-history continuity | Preserve reservations, uncertain outcomes, and exact retained results for each validator key | An empty/missing journal, fresh process, or new founder approval |
| Consensus-lock recovery | Recover and validate node-owned lock, committed history, QC/TC and candidate/ancestry evidence under the applicable contract | Signer history or founder approval |
| Cross-host exclusive use | Establish one effective signer per validator key, including fencing copied keys and concurrent instances | Separate process, host, cloud account, HSM label, or transport alone |
| Authorized bootstrap / absent-QC behavior | Define and verify explicit permitted first-use state and operation-specific absent-QC rules | File/QC absence, new database, or an initial approval detached from currentness |

The fixed founding membership does **not** extend the existing founding-epoch
lifetime restriction. The current genesis-static guard permits only its
founding epoch (epoch 0); an unchanged validator list does not authorize later
epochs. Any future epoch or authority transition needs its own accepted
authorization and transition policy.

DevNet, TestNet, and MainNet require separate network identities, credentials,
and authorization records. Joint authorization by named independent
participants is the planned direction before MainNet. This task selects no
participants, approval threshold, cryptographic construction, or transition
mechanism.

For the planned separate-signer architecture, each signer is intended to own
the authoritative per-key signing history, while its node owns consensus-lock
and recovery state. Their exact cross-process correspondence, ordering,
acknowledgements, and recovery remain unimplemented and require a separate
specification and validation.

## 2. Logical bootstrap authorization record

The following is a logical requirements inventory, not an approved wire
encoding, parser, signature domain, hash construction, or resource profile.
Existing QBIND types are source-grounding opportunities only; they do not
implement or verify this record.

| Field | Meaning required | Existing source/type, if applicable | Intended consumer | Open question / missing mechanism |
|---|---|---|---|---|
| Record version | Identifies a supported logical schema and rejects unknown versions | No bootstrap-record type | Node and signer bootstrap verifiers | Version negotiation, canonical encoding, parser bounds, and unsupported-version refusal |
| Authorization purpose/domain | States this is initial DevNet bootstrap authority, not validator Proposal/Vote signing or another QBIND authority | `GenesisConfig.chain_id`; Proposal/Vote wire domains are separate | Node and each designated signer | Dedicated approval-signature domain and its PQ verification rule are not specified |
| Environment and network identity | Binds specifically to DevNet, the runtime/network identity, and exact chain identity | `NetworkEnvironment`, `GenesisConfig.chain_id`, `map_environment`, `resolve_network_wire_alias` | Node, signer, and every relying verifier | Binding and correspondence across environment, runtime `ChainId`, wire alias, and chain label |
| Independently pinned genesis | Identifies the exact canonical genesis accepted independently of the untrusted record/configuration | `GenesisHash`; `run_boot_time_genesis_verification`; `verify_boot_time_genesis` | Node, signer, bootstrap verifier | Who provisions the expected hash/root, how peers independently agree, and how currentness survives rollback |
| Exact founding membership | Binds the ordered validator identities and validator IDs | `GenesisConfig.validators` / `GenesisValidator`; `build_genesis_consensus_authority` maps genesis order to `ValidatorId` | Node consensus configuration and each signer | Identity semantics, canonical ordering, and whether stake/address metadata has any authority meaning |
| Consensus key and suite per member | Binds the full public key and explicit suite identifier for each validator | `GenesisValidator.pqc_public_key`; builder currently assigns `SUPPORTED_TIMEOUT_SUITE_ID` | Each validator operator/signer and node verifier | Approved key encoding, suite allowlist, key ownership proof, rotation/retirement rules |
| Voting weight per member | Binds the exact consensus voting weight; not inferred from a UI label or silently from token stake | `ConsensusValidatorSet` / `ValidatorSetEntry`; current genesis authority builder hardcodes weight `1` and suite rather than reading a consensus-weight/suite field from `GenesisValidator` | Consensus engine, QC verifier, each node | Authoritative source and canonical mapping for selected weights; no numeric weights are approved here |
| Authority commitment and founding scope | Binds the exact authority and names the applicable founding epoch/profile | `GenesisConsensusAuthority.commitment`, `GENESIS_STATIC_AUTHORITY_EPOCH`, `authorize_configuration` | Node and signer admission | Existing commitment does not itself encode every logical record field, including explicit weights, credential identity, or approval; record binding is unspecified |
| Permitted operation families and scope | Limits approval to the initial DevNet bootstrap operation and exact identity; excludes ordinary per-transaction approvals and unrelated authority families | `ConsensusVerificationPolicy`, `ProposalVoteAuthority`, signer operation types | Node and signer before effects | Exact operation allowlist, scope grammar, and separation from timeout, transaction, governance, and other keys |
| Bootstrap authority identity / credential reference | Identifies the founder role and the separate PQ credential used to approve | No consensus bootstrap credential/owner type; `GenesisAuthorityConfig` is a distinct governance/transport surface | Bootstrap verifier, node, signer | Credential creation, public-key identity, PQ suite, custody, recovery, revocation, and independent root distribution |
| Approval-to-configuration binding | Makes approval verifiably cover exactly the environment, genesis, membership, keys, suites, weights, epoch/profile, scope, and record version | `compute_canonical_genesis_hash`; `compute_authority_commitment` | All verifiers before accepting activation | Exact canonicalization and approved signature input are not specified; neither a founder statement nor a carried key authenticates itself |
| First-use, replay, conflict, and supersession state | Distinguishes one unique, current first activation from replay, equivocation, conflicting approvals, retired authority, or rollback | `CurrentAuthorizationOwner` has only an in-process model; its production constructor is `unavailable` | Node and signer durable state owners | Durable first-use marker, independent freshness/anti-rollback, conflict resolution, supersession, retirement, and recovery protocol |
| Per-validator signer identity / ownership | Binds the designated operator-controlled consensus key to one signer authority | `ValidatorSigner`, `LocalKeySigner`; `signing_reservation_journal` is local isolated code | Signer and node | Authenticated service identity, key custody, one-instance fencing, and proof that copied keys cannot sign concurrently |

Existing source does not consume this record. `GenesisConfig` includes a
chain ID and validator key strings, but the current consensus-authority builder
hardcodes equal voting power and a supported suite; it does not establish the
selected exact weighted profile. The existing domain-separated authority
commitment is useful source material, not an approved bootstrap-record digest
or a substitute for approving and binding the full required configuration.

## 3. Independent trust-root distribution and exact genesis agreement

A future node and signer must authenticate the bootstrap authority from a root
provisioned independently of the record and configuration they are asked to
accept. A record cannot authenticate itself by carrying its own public key.
Before activation, each verifier must independently establish the expected
DevNet identity and exact genesis, validate that the approval covers that
configuration, and obtain whatever independently current state is required to
prove this is the unique permitted first activation.

The current boot verifier can canonicalize and compare an external genesis
against an expected hash; DevNet may also take an embedded-genesis path without
that external verification. The `--expect-genesis-hash` input and downloaded
file do not, by themselves, identify who authorized them or prove they are
current. Even a matching hash, valid historical signature, or founder statement
does not prove freshness or unique first activation. A future design must state
how independent nodes obtain the same approved genesis and trust root without
trusting unverified network input.

Credential custody, initial trust-root distribution ceremony, backup and key
recovery, compromise response, revocation, freshness witnesses, durable
activation state, and independent rollback boundaries remain unresolved.
Any future proposal that adds classical signatures, certificate authorities,
cloud/IAM identity, host attestation, hardware roots, or another infrastructure
trust dependency must identify it explicitly and describe its trust and rollback
limits. “Offline,” “HSM,” “cloud account,” and “separate server” are not proof
of PQ completeness, independent control, freshness, or rollback resistance.

## 4. Recovery and future authority transition

Founder approval is not a recovery override. A node and signer must preserve
all existing signing reservations, uncertain outcomes, exact retained results,
and consensus safety restrictions. An uncertain invocation remains
potentially signed; missing or empty state is not evidence that it never signed.
The node must independently recover its consensus lock and safety state.
The signer must retain authoritative per-key history. Until a separately
specified and validated cross-process correspondence allows safe use of both,
the affected signing operation refuses.

A future transition to joint authority must, at minimum:

* be authorized under the applicable prior authority policy and bind the exact
  replacement authority and its permitted scope;
* specify one explicit activation boundary, continuity evidence, and handling
  for partial writes, lost acknowledgements, conflicting transitions, replay,
  retired-authority rejection, and rollback-safe recovery;
* preserve all node lock/recovery restrictions and signer reservations,
  uncertainty, and retained results; and
* refuse when prior/current authority or transition order cannot be
  independently established.

No participant count, approval threshold, or transition mechanism is selected.
No novel threshold cryptography is proposed. If a future policy uses several
independently verified PQ signatures, it must still specify distinct authorized
identities, bounds, exact configuration binding, and acceptance/replay/conflict
rules. Initial founder approval and future authority transitions are
configuration-level events, not ordinary per-transaction approval steps. No
throughput or latency is measured or claimed.

## 5. FUTURE / NOT EXECUTED acceptance matrix

Every row is a future acceptance requirement; **no scenario below was
executed in this task**. “Accept” means only that the exact authorized
bootstrap record may pass its specified bootstrap gate after every independent
requirement is satisfied; it does not mean signing, deployment, or public
DevNet is approved.

| Scenario | Required future outcome |
|---|---|
| Genuine exact bootstrap authorization | Accept only with independently authenticated root, exact environment/genesis/membership/weights/keys/suites, valid scope, currentness, continuity, recovery, and unique first-use evidence |
| Wrong root, environment, genesis, membership, weight, key, or suite | Refuse before activation or signing; no partial match or fallback |
| Malformed or unsupported authorization record | Refuse with bounded handling before state mutation, key use, or activation |
| Conflicting founder-approved configurations / founder equivocation | Refuse both as ambiguous until a separately authorized conflict/recovery rule applies; do not choose by arrival order |
| Replayed or retired approval | Refuse using independently current supersession/first-use state; a valid old signature alone is insufficient |
| Missing or empty state presented as first use | Refuse unless an independent trusted bootstrap root and current unique-first-use procedure explicitly establish first use; absence alone never authorizes |
| Node-only rollback | Signer history and current authority must reject stale/conflicting requests; node lock/recovery must be independently re-established |
| Signer-only rollback | Refuse when independent freshness or history proves stale; if it cannot be distinguished from current state, do not claim rollback protection and do not sign |
| Combined node-and-signer rollback | Refuse unless a third independent current source resolves the rollback; two mutually stale copies cannot establish currentness |
| Copied keys or concurrent signer instances | Reject or fence all but one authorized instance before signing; a copied unrestricted key remains an unresolved compromise, not a successful acceptance |
| Founder credential loss or compromise | Stop activation/transition as applicable; use only a separately specified recovery/retirement policy, never infer replacement authority |
| Future transition to joint authority | Accept only under the prior policy with exact replacement binding, explicit boundary, continuity, conflict/replay/retirement rules, and rollback-safe recovery |
| Attempt to override signing-history or lock restrictions | Refuse; founder approval cannot erase history, reclassify uncertainty, waive QC/lock restrictions, or resume a potentially conflicting signer |

Evidence must remain separated by layer. **Source tests** can cover record
parsing, binding, refusal ordering, and state-machine rules. **Process tests**
must exercise independent node/signer state, crash/lost-ack, concurrency,
rollback, fencing, and recovery boundaries. **Release-binary tests** must prove
the actual startup/activation path rejects invalid and unavailable authority
and only reaches permitted behavior with complete prerequisites.
**Operational evidence** must establish actual credential custody, independent
root distribution, currentness, rollback domains, key exclusivity, recovery,
and approved deployment configuration. A test at one layer does not substitute
for another. No tests, builds, services, keys, activation, or operational
evidence were run or created for this decision.

## 6. Source grounding and preserved status

The source references below identify existing code, not an implemented
bootstrap authorization:

* Boot-time genesis loading and optional expected-hash comparison:
  `crates/qbind-node/src/pqc_boot_genesis.rs:215-254`;
  canonical verification is delegated to
  `crates/qbind-ledger/src/genesis.rs`.
* Genesis validator fields and key type:
  `crates/qbind-ledger/src/genesis.rs:129-168,1300-1347`.
* Genesis-derived authority build, commitment, and equal-weight assignment:
  `crates/qbind-node/src/genesis_consensus_authority.rs:78-80,106,132-180,334-438,1462-1479`.
* Founding-epoch restriction and in-process configuration guard:
  `crates/qbind-node/src/genesis_consensus_authority.rs:758-835`.
* Current-authorization owner is unavailable in production; established
  fixtures are test-only:
  `crates/qbind-node/src/genesis_consensus_authority.rs:1069-1228`.
* Genesis/network correspondence is static correspondence, not activation:
  `crates/qbind-node/src/genesis_authority_record_correspondence.rs:254-290,886-980`.
* Release startup refuses `--consensus-authority-from-genesis` before P2P or
  consensus startup; the Proposal/Vote authority remains `None`:
  `crates/qbind-node/src/main.rs:5383-5410,6140-6149`.
* Production signing without the required D10 journal refuses before invoking
  the signer:
  `crates/qbind-node/src/binary_consensus_loop.rs:4348-4430`; this does not
  establish a production journal or signer-side continuity.
* The separate-signer feasibility assessment documents the isolated D7D14
  store, local D10 boundary, and missing process correspondence:
  `docs/devnet/QBIND_RUN_422_SEPARATE_SIGNER_FEASIBILITY.md`.

The whole native-admission and authority contracts remain
`DRAFT / NOT APPROVED / NOT IMPLEMENTED`. Preserved:
`D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`;
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`;
`D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`;
§13.6 whole-lifecycle `INCOMPLETE`; activation `DISABLED`; public DevNet
`NO-GO`; durable anti-rollback `NOT-ESTABLISHED`; C4/C5 `OPEN`; RS1 `OPEN`;
all candidate limits `UNAPPROVED`. No F1/F2 closure,
production-consistency guarantee, configured-authority acceptance, or release
approval follows.

## RUN 422 - proposed bootstrap custody and recovery trust model

`docs/devnet/QBIND_RUN_422_BOOTSTRAP_CREDENTIAL_RECOVERY_TRUST_MODEL.md`
is **DRAFT / NOT APPROVED / NOT IMPLEMENTED**. It advances the settled
founder-authorized initial DevNet direction with recommended offline founder
credential custody, independently authenticated manual root provisioning,
operator-controlled stateful validator signers, separate history/lock owners,
and explicit loss, uncertainty, migration, copied-key and rollback refusals.
No credential, suite, device, custodian, ceremony, currentness/unique-first-use
source, recovery authority or exclusivity mechanism is established. It preserves
all verdicts above, leaves activation DISABLED and public DevNet NO-GO, and
grants no history/lock override, implementation, deployment or release approval.

## Bootstrap approval record and verifier contract — candidate v1

**DRAFT / NOT APPROVED / NOT IMPLEMENTED**

This section turns the logical inventory above into one byte-level candidate
record and a non-authorizing verifier contract. The format and identifiers
below are proposals local to this document, not registered QBIND identifiers
or an approved cryptographic profile. No founder suite, credential, root,
person, or operational limit is assigned. This section does not implement a
verifier, establish custody, approve activation, or reopen the accepted D10 or
D7D14 scopes.

### 1. Guarantee and non-authorizing result

The isolated verifier receives (1) untrusted record bytes, (2) the candidate
`GenesisConfig` and environment/runtime/wire identity supplied by its caller,
(3) an independently provisioned full founder public root and immutable
verification profile including the root's accepted purpose, and (4) fixed
local parser limits. The caller-supplied configuration is not trusted merely
because it accompanies the record. The verifier may return a typed
`VerifiedBootstrapApprovalContent` only when the exact canonical payload
verifies under that external root/profile and agrees with the independently
supplied configuration and identity policy.

The result contains the complete immutable canonical payload bytes, parsed
fields, the exact selected trusted-root/profile context, and the matched
configuration identity. It is not a detachable Boolean, does not confer
authority, and cannot be reused with substituted bytes, configuration, root,
profile, or identity context. Its only claim is: **these exact candidate
content bytes verified under this independently supplied root/profile**.
Every later node or designated signer must independently compare its own
configuration to these exact bytes and perform its own required
currentness/decision-time checks.

This result establishes none of activation permission, B currentness,
unused identity, C continuity, L safe lock recovery, X exclusive key use,
consensus-signing permission, key custody/ownership, or recovery/replacement
authority. Verification has no side effects: it does not install a root,
initialize/advance lifecycle state, clear or create signing history, create a
first-use marker, activate a network, or enable a signer.

### 2. Candidate encoding and exact approval bytes

The following is one concrete candidate encoding to make review and future
decisions falsifiable. Its byte layout is fully specified here; the
cryptographic profile and operational values are not approved. The candidate
ASCII identifiers and numeric values are private to this proposal until
separately accepted; they do not allocate or alter existing consensus,
governance, transport, or signature-domain identifiers.

The complete record is:

```text
u32_be(payload_length) || payload || signature_envelope
```

`payload` is the concatenation of the positional fields in the table below,
with no padding, tags, optional omitted fields, or extension bytes. All
integers are unsigned and big-endian. Fixed byte arrays are emitted exactly
as shown. The one variable string has a `u16_be` byte length immediately
before its bytes. Members are repeated exactly `member_count` times in
genesis order. `payload_length` is the exact number of payload bytes, not
including the four-byte prefix or signature envelope.

The one candidate signature message is exactly:

```text
ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00
    || u32_be(payload_length) || payload
```

The four-byte payload-length prefix is included in the authenticated message.
The signature envelope and signature bytes are not. No JSON, pretty-printing,
transport framing, request ID, signature randomness, or trailing byte is
signed. The NUL is the literal single `0x00` byte. The proposed domain string
is a candidate only and is not a registry allocation.

The signature envelope is exactly:

```text
ASCII("SIG1") || u16_be(envelope_profile_id)
    || u32_be(signature_length) || signature_bytes
```

The payload's `founder_verification_profile_id` must equal
`envelope_profile_id` and the independently trusted root profile's profile
ID. The envelope is framing/selection metadata, not authenticated payload.
The profile ID inside the payload is authenticated. The signature itself is
the envelope's final `signature_length` bytes and is not included in its own
input.

| Order | Field | Type, width and canonical encoding | Meaning / source representation | Authenticated? / validation and refusal |
|---:|---|---|---|---|
| 1 | Record magic | 4 bytes, literal ASCII `QBAP` | Candidate record family; no existing QBIND type | Yes. Any other bytes refuse. |
| 2 | Record version | `u16_be`, exactly `1` | Logical record schema version | Yes. Other versions refuse; no negotiation or fallback. |
| 3 | Authorization purpose | `u16_be`, candidate value `1` = initial DevNet bootstrap only | Dedicated approval purpose, distinct from Proposal/Vote, Timeout, governance, transport, and transaction signing | Yes. Any other value or root-purpose mismatch refuses. Candidate value is not registered. |
| 4 | Environment | `u8`, candidate value `1` = DevNet | `NetworkEnvironment` classification, not a chain alias | Yes. This candidate accepts DevNet only; TestNet/MainNet/future transitions require separate records and policy. |
| 5 | Runtime chain identity | `u64_be` | Full `ChainId` from the independently supplied runtime/network context | Yes. Must equal the external expected runtime ID; never inferred from environment or text label. |
| 6 | Wire chain identity | `u32_be` | Exact wire `chain_id` expected for this identity | Yes. Must equal a separately trusted environment/runtime-to-wire mapping; the genesis-authority production route has no established mapping. |
| 7 | Genesis chain label | `u16_be(length) || 1..255 ASCII bytes`; permitted bytes are `[A-Za-z0-9._-]`, no NUL | Exact `GenesisConfig.chain_id` bytes | Yes. Must byte-equal the parsed genesis label and trusted expected label; no case-folding, Unicode normalization, aliasing, or substring match. |
| 8 | Canonical genesis identity | 32 raw bytes | `GenesisHash` from the current `compute_canonical_genesis_hash(config, environment)` | Yes. Recompute from the supplied structured genesis and selected environment; mismatch refuses. Because the implementation body omits `GenesisConfig.extra` despite its adjacent comment claiming it is hashed, this candidate additionally requires `config.extra == Null`; any non-null value refuses until the hash contract is reconciled. |
| 9 | Member count | `u16_be`, 1 through 4096 | Ordered `GenesisConfig.validators` count; candidate cap equals the current builder's `MAX_GENESIS_CONSENSUS_VALIDATORS` | Yes. Reject zero, over-limit, arithmetic overflow, and count/length disagreement before member allocation or key work. This is a format cap, not an approved operational capacity. |
| 10, repeated | Validator ID | `u64_be`; exactly the zero-based member index | Existing builder's `ValidatorId(i)` from genesis order | Yes. Must equal the index. No sorting, reassignment, gaps, or alternate ID rule. |
| 11, repeated | Validator address | 32 raw bytes; decode only the canonical 64-character lowercase hex address in `GenesisValidator.address` | Existing genesis validator identity representation | Yes. Must decode and match the corresponding genesis member; duplicate addresses refuse. It is not a validator ID or a signer credential. |
| 12, repeated | Designated signer reference | 32 opaque bytes; all-zero is invalid | External reference to the intended signer/ownership record for this member; no current source type exists | Yes, as an intended association only. Compare against independently provisioned signer identity; it proves neither key possession, operator identity, custody, nor X. No value is supplied by this task. |
| 13, repeated | Consensus suite ID | `u16_be`, exactly the source-supported `SUPPORTED_TIMEOUT_SUITE_ID` value `100` in this compatibility candidate | Existing genesis authority builder suite assignment | Yes. Other suites refuse in this candidate; it does not select or approve a founder signature suite. |
| 14, repeated | Consensus public key | Exactly 1312 raw bytes; no length prefix | Strictly decoded bytes of `GenesisValidator.pqc_public_key` | Yes. Must match the corresponding ordered genesis key and be valid/canonical for the supported key encoding; duplicate keys refuse. Existing source uses ML-DSA-44-sized keys. |
| 15, repeated | Consensus voting weight | `u64_be`, exactly `1` | Explicit consensus weight in `ValidatorSetEntry` | Yes. Must equal one for every member in this compatibility candidate. Never derive from token stake or metadata; arbitrary/heterogeneous weights refuse. |
| 16 | Authority commitment | 32 raw bytes | Recomputed current `GenesisConsensusAuthority.commitment` | Yes. Must exactly equal the builder result. It is only a redundant consistency check: the existing commitment does not include all approval fields, including explicit weights, signer/root references, profile, purpose, or operation scope. |
| 17 | Founding epoch | `u64_be`, exactly `0` | `GENESIS_STATIC_AUTHORITY_EPOCH` | Yes. Any other epoch refuses. This candidate cannot authorize later epochs or transitions. |
| 18 | Consensus configuration profile | `u16_be`, candidate value `1` = genesis-static, ordered, supported-suite, equal-weight, epoch-0 profile described above | Candidate description of the source-compatible consensus authority shape | Yes. It is not a profile registry allocation; unknown or unsupported profile refuses. |
| 19 | Permitted operation/scope | `u16_be`, candidate value `1` = one initial network instantiation of this exact DevNet identity and no other operation | Narrow scope, jointly determined by purpose plus all identity/configuration fields | Yes. No standing validator-signing, later activation, transition, or absent-QC exception is encoded. |
| 20 | Founder credential reference | 32 opaque bytes; all-zero is invalid | Reference compared byte-for-byte to a reference bound to the independently provisioned full public root | Yes, but not a key, fingerprint, or trust anchor. It cannot select a root or policy; absent, ambiguous, or mismatched external root refuses. |
| 21 | Founder verification profile ID | `u16_be`, candidate value `1`, unallocated | Profile identifier for the root-key encoding, suite and signature encoding; this candidate fixes direct raw-message verification, empty context, and no prehash | Yes. Must equal the envelope ID and independently provisioned trusted profile. The profile's value and cryptographic suite/key/signature encodings remain a blocker; no suite is selected here. |

**Classification.** Fields 1–7, 9–15, 17–19 are authenticated record
content. Fields 8 and 16 are derived values carried as authenticated,
recomputed consistency claims. Fields 12 and 20 are authenticated opaque
references, but resolving them to a designated signer or trusted root is an
independent verifier input; the references are not proof of identity,
ownership, freshness, or custody. Field 21 is authenticated content whose
meaning is accepted only from the independently trusted profile. The full
root key/profile, expected environment/runtime/wire mapping, candidate
genesis, and parser caps are independently trusted verifier inputs and are
not selected by the record. B/C/L/X/U are external lifecycle evidence and
must not be encoded as mutable signed claims. Signature-envelope fields are
framing/selection metadata, not authenticated content.

`approval-to-configuration binding` is not a separate caller-supplied digest:
the approval authenticates the complete canonical payload containing every
listed field, and a verifier independently recomputes/checks the derived
fields and compares the payload against the exact candidate configuration.
The `canonical_genesis_identity` authenticates all fields actually encoded
by the existing canonical genesis hash, including allocations, validator
addresses/keys/stakes/names/metadata, council, monetary configuration, and
genesis authority block. `GenesisConfig.extra` is the explicit exception:
although the hash-function comment says it is included, the function body
does not read it. Candidate v1 therefore requires `extra == Null`; the repeated
member fields separately state the consensus interpretation and require exact
order/key/suite/weight agreement. Neither hash substitutes for the founder
approval.

The existing canonical genesis function is **SHA3-256**, over
`QBIND:GENESIS:v1`, environment scope, chain label, genesis time, ordered
allocations, ordered validators, council, canonical serialized monetary
configuration, and authority block. It is stable across JSON whitespace and
map-order differences, not a hash of the raw JSON file. Its inputs and output
must be recomputed under the existing ledger definition; raw-file
`--expect-genesis-hash` is a distinct value and cannot be substituted.
The current authority commitment is the builder's SHA3-256 tagged commitment
with tag `qbind.run422.genesis-consensus-authority.v1` over chain label,
canonical genesis hash, ordered IDs, suite IDs, and keys. The record still
authenticates its explicit weights and all other fields directly.

Its recomputed body is exactly
`u64_be(chain_label_byte_length) || chain_label_bytes || canonical_genesis_hash
|| u64_be(member_count) ||` for each ordered member
`u64_be(validator_id) || u16_be(suite_id) || u64_be(public_key_length) ||
public_key_bytes`. The existing helper computes
`SHA3-256(UTF8("qbind.run422.genesis-consensus-authority.v1") || body)`.
Neither member weight nor signer/root/profile/scope fields are in that
commitment; those values are bound only by the approval payload and explicit
comparisons.

**Cryptographic profile and exact blocker.** This candidate fixes the
signature operation: verify the exact message bytes above directly, with an
empty algorithm context and no application-level prehash or substitute
digest. Approval-content identity is the exact canonical payload byte string,
not a digest. The only digest dependencies in this proposal are the existing
canonical genesis SHA3-256 and existing authority commitment helper. No
approval digest, fingerprint digest, or new hash algorithm is assigned. A
signature scheme that cannot implement this exact message/context mode is
not compatible with candidate v1; there is no mode fallback.

The founder suite, root-key encoding/size, signature byte encoding, and
profile registry/purpose policy are unassigned. The approved profile must
state exact canonical key/signature encodings and any suite parameters;
randomized output does not change content identity. The mode/context above is
fixed for this candidate and cannot be changed through record or envelope
metadata.
Existing `MlDsa44Backend::{sign,verify}` is one evidenced reusable primitive:
it accepts message bytes directly, uses pure ML-DSA with empty context, and
the signing path is randomized. That implementation has 1312-byte
public-key and 2420-byte signature encodings. Its existing
`MlDsa44SignatureSuite::canonical_key_descriptor` can validate the fixed
public-key encoding, but the genesis authority builder itself performs strict
hex decoding and length checks rather than that descriptor check.
`MlDsa44SignatureSuite::verify` instead
accepts a `Hash32` and verifies those 32 digest bytes as the message; it is
not interchangeable with direct verification of the framed message. These
source observations select no founder algorithm, suite, credential, digest,
or security acceptance. Until an accountable decision selects a complete
profile and binds it to the external root, the cryptographic interpretation
of profile ID `1` is unresolved and no verifier implementation is
implementation-ready.

### 3. Trust-root and algorithm-selection boundary

The trusted root and its accepted purpose/profile come from independent
provisioning. The verifier receives a unique selected root containing the
complete public key bytes, key-encoding identifier, accepted suite/profile,
and purpose; the record can only carry the opaque reference for comparison.
The root/profile selection is fixed before untrusted bytes are examined and
is not controlled by the payload or envelope.

Refuse on missing root, ambiguous root selection, root/reference mismatch,
wrong root purpose, unsupported profile, key/suite/profile inconsistency,
unsupported key/signature encoding, or attempted downgrade/fallback. There is
no trust-on-first-use, optional pin, short-fingerprint trust, carried-key
self-authentication, first-arrival selection, fallback suite, or automatic
root replacement. A carried key cannot authenticate itself. An untrusted
field cannot widen parser/resource limits or select environment/runtime-wire
mapping. Root distribution, root succession, and conflict adjudication are
external decisions, not verifier defaults.

### 4. Compatibility with current genesis authority

The candidate is deliberately narrower than a general authority format. At
the pinned source, `build_genesis_consensus_authority` assigns validator IDs
from genesis order, accepts its supported ML-DSA-44-sized public keys, assigns
the supported suite ID 100, and sets every voting power to one. The candidate
therefore authenticates those exact values and refuses another suite,
weight, ordering, or ID assignment. Stake, address metadata, and names do not
create consensus weight.

The candidate recomputes canonical genesis and the builder commitment rather
than trusting either carried value. Any redundant field disagreement refuses.
The genesis authority builder's `authorized_wire_chain_id` is `None` for
production construction: no production runtime-to-wire mapping has been
established. `resolve_network_wire_alias` defines a dormant standard-network
mapping but is not wired into that production authority route. A record's
wire ID therefore cannot cure this gap; absent an independently accepted
mapping, verification refuses. Environment, runtime `ChainId`, genesis text
label, and wire `chain_id` remain distinct values and must each match their
own trusted source.

The builder's lifetime is founding epoch 0 only. This candidate does not
extend it, authorize absent-QC behavior, change quorum/consensus rules, or
approve a TestNet, MainNet, or later authority transition. Those scopes need
separate authorization.

Baseline source grounding for this candidate:

| Source location at the required starting commit | Behavior used here |
|---|---|
| `crates/qbind-ledger/src/genesis.rs:129-168,1300-1347,1340,1569-1630,1654-1676` | Genesis validator/config representation; structured, domain-separated SHA3-256 canonical genesis hash and authority-block encoding. The comment at 1569-1574 claims `extra` is hashed; the body at 1576-1628 omits it, so candidate v1 rejects non-null `extra`. |
| `crates/qbind-node/src/genesis_consensus_authority.rs:78-80,334-438,1462-1479`; `crates/qbind-hash/src/hash.rs:1-24` | Genesis-order IDs, strict key decoding/length, suite 100, explicit unit weights, exact authority-commitment body/tag and SHA3-256 helper |
| `crates/qbind-node/src/genesis_consensus_authority.rs:758-835,1069-1168` | Founding-epoch configuration guard; in-process current-authorization model and production-unavailable current state |
| `crates/qbind-node/src/genesis_consensus_authority.rs:181-190,435-439,766-770` | Production authority has no authorized wire chain ID |
| `crates/qbind-node/src/timeout_verification_bridge.rs:97` | Existing supported consensus suite ID is 100; this is not founder-suite selection |
| `crates/qbind-types/src/network_wire_alias.rs:1-18,110-128`; `crates/qbind-node/src/genesis_authority_record_correspondence.rs:53` | Standard runtime/wire helper is explicitly dormant/not production-wired; correspondence route's stated production limitation |
| `crates/qbind-crypto/src/ml_dsa44.rs:37-43,412-440,531-574`; `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs:90-99,101-142` | Existing ML-DSA key/signature sizes, raw-message verification with empty context, digest-taking adapter, and canonical public-key descriptor |
| `crates/qbind-node/src/main.rs:5405-5418` | Explicit genesis-authority activation request refuses before network-mode dispatch |

### 5. Deterministic parsing and verification procedure

1. **Trusted inputs/policy.** Before parsing candidate data, require one
   independently supplied root and accepted purpose/profile, the local
   supported record version and parser caps, an independently supplied
   environment/runtime/wire expectation, and the candidate genesis input
   together with trusted limits for its canonicalization. If any trusted
   input or resource policy is unavailable or ambiguous, refuse as
   unavailable; do not infer it from the record. The present production wire
   mapping, founder profile, and accepted genesis-canonicalization resource
   policy are unavailable, so current production acceptance is impossible.
2. **Framing/resource admission.** Require the complete record byte slice and
   reject if shorter than the minimum envelope or larger than the fixed
   local cap. Read `payload_length` only after a four-byte availability check; use checked
   addition for prefix, payload, envelope header, and signature length,
   compare against input length before slicing, and do not allocate in
   proportion to an untrusted length until it has passed the fixed cap. Parse
   borrowed slices; any owned result copy is allowed only after successful
   verification and within that admitted bound. Candidate caps are label
   ≤255 bytes, members ≤4096, public key exactly 1312 bytes, signature
   ≤65535 bytes, fixed nesting depth 0, and fixed envelope sizes. The
   non-member field widths sum to
   `4+2+2+1+8+4+2+32+2+32+8+2+2+32+2 = 135` bytes. Each member is
   `8+32+32+2+1312+8 = 1394` bytes. Thus
   `payload_length = 135 + label_len + 1394*member_count` and
   `record_length = 4 + payload_length + 10 + signature_length`.
   At the caps, `payload_length = 135+255+4096*1394 = 5,710,214` bytes;
   `record_length = 4+5,710,214+10+65,535 = 5,775,763` bytes.
   Arithmetic cross-checks: `(member_count,label_len)=(1,1)` gives
   `payload_length=1530`; `(1,255)` gives `1784`; and `(4096,255)` gives
   `5,710,214`.
   These are proposed format bounds, not approved operational memory,
   throughput, latency, or capacity guarantees. Any deployed cap may be
   stricter from trusted local policy, never looser because the record asks.
   Before canonicalizing the separately supplied typed `GenesisConfig`, a
   no-allocation checked walk must check every source-encoded string/count,
   aggregate encoded-size arithmetic, and total canonicalization work against
   an independently configured `genesis_input_max`; only then may the
   canonical hash be computed. The ledger encoder uses `u32` length/count
   encodings and materializes a `Vec`; those conversions and allocations are
   not a bounded parser contract. `genesis_input_max` has no approved value,
   so absent that trusted policy refuse as
   `ConfigurationResourcePolicyUnavailable`; do not call the current
   materializing hash path on unadmitted input.
3. **Canonical parse.** Parse fixed-width fields in order without recursive
   structures. Require magic/version/purpose exact; require the string length
   within its fixed cap and its bytes to be the permitted ASCII grammar;
   require count within 1..=4096 before iterating; checked-compute
   `135 + label_len + count*1394` and require exact payload length. Reject
   unsupported versions/suites/fields, noncanonical integers or key/address
   representation, malformed lengths, duplicates, truncation, and any
   trailing byte. There are no duplicate named fields in this positional
   format; duplicate validator addresses, IDs, public keys, or signer
   references refuse. IDs and members must be in genesis order.
4. **Semantic/configuration consistency.** Require candidate DevNet purpose,
   environment, runtime ID, wire mapping, chain label, `GenesisConfig.extra`
   equal to `Null`, canonical genesis hash, ordered validator
   identities/keys/suites/explicit unit weights,
   authority commitment, epoch 0, consensus profile, operation scope,
   founder reference, and founder profile all to agree with the independent
   inputs and the supported candidate. Recompute canonical genesis and
   authority commitment from the actual typed genesis and exact member list.
   Reject all disagreement; do not repair, sort, default, alias, or infer a
   field.
5. **Signature verification.** Require the envelope magic and exact profile
   equality with both signed payload and independent root policy. Require the
   exact profile-defined key/signature lengths and canonical encodings, then
   verify only the reconstructed bytes
   `D || u32_be(payload_length) || payload` under the one external root,
   using direct raw-message verification, empty algorithm context, and no
   application-level prehash. Never attempt another key, suite, context,
   prehash, or legacy domain after refusal. The compatible signature profile
   decision is unresolved, so this step cannot currently produce an approved
   success.
6. **Restricted result.** Only after every prior step succeeds, construct an
   immutable result binding the complete payload bytes to the exact trusted
   root/profile and matched configuration. Do not expose a detached success
   Boolean or any activation/signing capability. On every refusal, return no
   partial result and perform no state mutation.

For member count `n`, label bytes `l`, and signature bytes `s`, the candidate
payload length is exactly `135 + l + 1394n`; the full record length is
`4 + payload_length + 10 + s`. With the candidate caps, framing and a
complete sequential scan of fixed/variable fields are linear in the admitted
record byte count. Direct equality comparisons against already supplied
fixed-size field values have total work no greater than the scanned field
bytes.

No duplicate-detection algorithm or scratch bound is selected. Although
addresses, IDs, keys, and signer references must be unique, their
duplicate-detection work and memory are unresolved; no linear-time or
constant-scratch claim is made. Genesis input preflight and canonical
serialization/hash work are separate from record parsing. They require a
checked walk and independently bounded input, but their total work and
scratch/materialization costs are not established here. An immutable result
may copy admitted payload bytes only after verification; its materialization
allocation/copy cost is separate and no scratch bound is claimed. Exactly
one signature verification is attempted after prior checks; the profile's
cryptographic work and scratch are profile-specific and unquantified.
Consequently, no overall worst-case `O(payload_length + G)` bound or
production resource/latency guarantee is claimed. The unresolved algorithmic
work and scratch policy remain part of BR-08.

Conceptual refusals distinguish `TrustedInputUnavailable` (root, mapping,
configuration, or policy evidence unavailable), `TrustedInputAmbiguous`,
`ConfigurationResourcePolicyUnavailable`, `MalformedOrNonCanonical`,
`UnsupportedVersionOrProfile`, `ConfigurationMismatch`,
`RootOrPurposeMismatch`, `SignatureInvalid`, and
`InternalVerificationFailure`. Unavailable evidence is not a demonstrated
mismatch; neither category yields a result. Precedence is: missing/ambiguous
trusted policy first; byte and arithmetic/resource admission second;
structural parsing third; semantic mismatch fourth; cryptographic
verification fifth. This avoids untrusted resource use before trusted policy
and avoids signature work on malformed/mismatched content.

### 6. Content identity, replay, and external lifecycle gates

Approval-content identity is the complete canonical `payload` byte string.
The signature bytes, randomized-signature output, envelope bytes, and
transport/request identifiers are not part of that identity. Distinct valid
signatures over the same payload are the same approval content and do not
create independent bootstrap permissions.

Repeated isolated verification of identical content is permitted and
non-authorizing. Multiple intended participants may independently verify one
coordinated bootstrap; their verification is not another activation.
A second activation requires external U evidence and is refused absent an
explicitly authorized separate lifecycle policy. Replay of a retired or
superseded approval requires B evidence and refuses when B is unavailable,
stale, or conflicting. Restored local activation state is not currentness.
Conflicting approvals or root installations are not resolved by arrival
order, timestamp, majority of downloads, or this stateless verifier. A
stateless verifier cannot detect an undisclosed conflicting approval.

Every later activation/signing consumer must enforce the following gates
independently. The role names below are proposed responsibilities, not
assigned people or operational evidence.

| Gate | Evidence owner / enforcing consumer | Exact identity/content binding | Authentication and currentness required | Relevant rollback/failure domain | Decision-time and missing/stale/conflicting/unverifiable behavior |
|---|---|---|---|---|---|
| B — current authority and supersession/conflict | Unassigned current-authority state owner / every activation and signing consumer | Exact approval payload identity, root/profile, network/runtime/wire identity, genesis, authority and supersession chain | Authenticated, independently current state outside the rollback domain being defended; valid historical A is not B | Must survive rollback of node, signer, local database, backup, image, and any claimed state source in its stated threat model; no source is selected | Recheck immediately before the dependent effect. Missing/unavailable is `unavailable`; stale or conflicting is a mismatch/refusal. No local epoch, matching hash, timestamp, empty database, operator statement, or repeated download proves freshness. |
| C — per-key signing history | Designated validator signer/state owner / signer; node must honor its result and must not keep a second independently authoritative history | Stable validator conflict identity plus exact network/genesis, operation, position, canonical request/evidence binding and retained result | Authenticated complete history including reservations, pending/uncertain outcomes, and exact retained results; D10's local result is not production/cross-process proof | Signer history and its actual storage/backup/restore/admin rollback domain; anchor remains unresolved | Revalidate at signing and exact-result reuse. Missing, stale, uncertain, or unverifiable history blocks; conflicting identity/content refuses and preserves the obligation. Pending/possibly-signed state is not cleared or re-signed by founder approval. Reuse only the exact retained result under the existing contract. |
| L — node lock and safety recovery | Node safety-state owner / consensus node; signer checks required correspondence evidence | Node's recovered committed state, effective lock/QC/TC and candidate/ancestry evidence for the exact decision, with decision-time L0 binding | Authenticated recovered state and required verified evidence under the recovery contract; signer history does not replace lock | Node's own database/snapshot/backup/restore and rollback domain, distinct from signer history | Recheck at the actual safety decision. Missing, stale, conflicting, insufficient, or unverifiable evidence refuses; a later L1 lock cannot retroactively justify L0. Do not broaden absent-QC permission or override a lock. |
| X — exclusive permitted key use | Validator operator's unassigned custody/exclusivity owner / all permitted signer instances and signing routes | Exact validator key, signer reference, network/operation and the instance authorized to use it | Evidence that no exported/copy key or concurrent instance can sign; local process shutdown/deletion is not evidence | All key copies, export paths, hosts, administrators, providers, backup/restore and incident domains | Enforce at each signing effect. Missing, stale, unverifiable, or conflicting/overlapping exclusivity refuses; never claim an unrestricted exported key was disabled by local fencing/deletion. |
| U — unique authorized first use | Unassigned bootstrap activation-state owner / every node and signer activation consumer | Exact payload identity, founder root/profile, network/runtime/wire identity, genesis, and one authorized network instantiation | Independently authenticated, current first-use/activation and conflict state outside the relevant rollback domain | Must remain current through restoration of relevant local state and be independent of that restored domain; mechanism/person not selected | Check atomically at activation time. Missing/uncertain/stale/conflicting evidence refuses. Empty DB, local marker, timestamp, equal epoch, old signature, operator statement, or repeated download does not prove unused identity. Unique first use means one network instantiation, not one verifier. |

These are separate from A. No founder/operator approval may erase missing
history, override a node lock, turn an unknown signing outcome into “not
signed,” or authorize automatic same-key restart. Preserve the existing
continuity and correspondence contracts, including their pending/uncertain
outcomes, stable-validator conflict identity, decision-time node-lock
restrictions, and exact-result reuse rules. Local shutdown, deletion, or
fencing does not disable an exported unrestricted private key.

### 7. Decision register

No role below is an assigned person/operator; no evidence or consent is
asserted to exist.

| ID | Exact unresolved question | Source-supported candidate or continued-refusal disposition | Decision-maker/accountable role required | Missing operational fact | Evidence needed | Affected operation | Blocks |
|---|---|---|---|---|---|---|---|
| BR-01 | Which founder public-key encoding, cryptographic suite, signature encoding, and profile ID are accepted for profile `1` under the candidate's fixed raw-message/empty-context/no-prehash mode? | Keep exact framed message bytes and mode as candidate; continue refusing verification until one complete compatible profile is approved. Existing ML-DSA raw-message/empty-context API is an option, not a selection. | Founder-root policy approver, role unassigned | No approved suite, key, credential, root, profile registry entry, or ceremony | Reviewed complete profile definition and independent-root policy, followed later by source/unit and independent-process evidence | Isolated signature verification and all downstream use | Candidate cryptographic profile / isolated implementation / activation |
| BR-02 | Are candidate magic, purpose/domain, format/version, field widths/order, and candidate IDs accepted without collision with any existing identifier? | Candidate values above; no registration or existing domain modification. Refuse on any unsupported value. | Protocol/record contract owner, unassigned | No registry decision or collision review | Explicit recorded identifier allocation and review of existing domain registry | Candidate encoding and implementation | Candidate encoding / isolated implementation |
| BR-03 | What trusted production mapping binds DevNet `NetworkEnvironment`, full runtime `ChainId`, genesis label, and wire `chain_id`? | Require exact independently supplied mapping; production genesis-authority path currently has none. Dormant alias helper is not production binding. | Network identity authority, unassigned | No accepted production mapping or operational identity | Source-backed mapping and independently provisioned expected values; release-binary correspondence evidence later | Configuration verification, activation, signing | Integration / activation |
| BR-04 | Who owns authenticated current authority, supersession/conflict, and unique-first-use evidence, and what source survives which rollback domains? | Continue refusing B/U when unavailable; do not invent a witness, counter, schema, or activation protocol. | B and U state owners, both unassigned | No owner, source, rollback domain, currentness/readback or conflict procedure | Threat-modelled independent state and process/release/actual rollback-domain evidence | Activation, replay/supersession, restart | Integration / activation |
| BR-05 | What exact designated signer references are bound for each validator, may one reference cover multiple validator keys, and what demonstrates X across every key copy/instance? | Candidate requires per-key unique references but authenticates only the association; continue refusing any exclusivity claim absent concrete evidence. | Each validator operator and X/custody owner, unassigned | No signer identities, key ownership, deployment, copies, access, or fencing evidence | Actual custody/export/backup/admin/provider/restore inventory and independent-process/device evidence | Signer admission and signing | Integration / activation |
| BR-06 | What authenticated per-key C history and cross-process contract is consumed by the signer, with which operation families and exact-result rule? | Preserve D10's accepted local scope; no second node history; retain unresolved/possibly-signed refusal. | Validator signer owner and node safety owner, unassigned | No production journal attachment, signer service, authenticated request protocol, or correspondence acknowledgement | Existing continuity contract implementation-entry requirements plus process and release evidence | Proposal/Vote signing, retries/recovery; Timeout/NewView remain separate | Integration / activation |
| BR-07 | What node-owned L evidence is sufficient at decision time, and how is exact L0 decision bound to the required retained generation/result? | Preserve recovery contract; no signer-history substitute, lock override, or L1 retroactive justification. | Node safety-state owner, unassigned | No production recovery wiring/cross-process binding | Contract-required authenticated recovery evidence, decision-time binding, process and release evidence | Consensus signing/activation after restart | Integration / activation |
| BR-08 | What approved parser/resource policy bounds record plus typed-genesis canonicalization and verification work? | Candidate record caps above are format bounds only; keep stricter trusted local caps and refuse beyond them. Existing genesis hash code has its own conversions/allocations, not a production resource profile. | Parser/profile owner, unassigned | No approved operational cap, safe typed-genesis admission policy, or measured resource budget | Reviewed checked-size implementation and source/unit evidence; release behavior later | Isolated parser/verifier | Isolated implementation |
| BR-09 | Who may resolve founder equivocation, retire/replace a root, or authorize a later authority transition? | No first-arrival policy, automatic replacement, or same-key restart; continue refusal absent an already authenticated policy. | Pre-existing authority/recovery decision-maker, unassigned | No named authority, policy, transition procedure, or currentness mechanism | Separately approved policy and authenticated current conflict/supersession evidence | Conflicting approval, root install, transition/recovery | Integration / activation |
| BR-10 | Which actual founder-root ceremony roles, credential custody, backups, and operator/device evidence are approved? | Retain the existing custody/recovery implementation-entry checklist; this record supplies none of it. | Founder and each operator's assigned custody roles, unassigned | No root, key, operator, device, backup, ceremony or consent | Future actual custody/device/rollback-domain evidence and explicit approval | Root trust, activation and operations | Activation |
| BR-11 | Is non-null `GenesisConfig.extra` permitted in the initial DevNet configuration despite the current canonical-hash implementation omitting it? | Candidate refuses every non-null `extra` until the hash implementation/contract demonstrably binds it; the adjacent source comment and function body disagree. | Genesis/hash contract owner, unassigned | No exact initial configuration or decision on non-null extension data | Independently inspected exact genesis plus a source-backed hash contract that covers every accepted field | Genesis identity and approval matching | Integration / activation if non-null |

### 8. Future acceptance matrix — NOT EXECUTED

No keys, signatures, test vectors, tests, or measured results were created.
The table distinguishes a future isolated source/unit result from lifecycle
and actual-world evidence; acceptance at one layer does not prove another.

| Input/scenario | Expected isolated verifier result | Additional lifecycle result / enforcing layer | Future evidence level |
|---|---|---|---|
| Exact matched approval/root/configuration | Typed exact-content result only; no permission | B/C/L/X/U still required; consumer compares same bytes | Source/unit; independent-process; release-binary; actual root/custody evidence separately |
| Mutation of each security-relevant bound field (version, purpose, environment, both IDs, genesis label/hash, `extra`, every member field, commitment, epoch/profile/scope, root/signer references) | Reject malformed/unsupported, configuration mismatch, or invalid signature; no partial result | Activation/signing consumer independently rechecks corresponding gates | Source/unit per field; release-binary later |
| Changed member order, ID, key, suite, or explicit weight | Refuse ordering/identity/suite/key/weight or signature mismatch | No altered authority accepted by node/signer | Source/unit; release-binary later |
| Wrong environment, runtime/wire identity, epoch, consensus profile, or purpose | Refuse semantic/policy mismatch | B/U/current epoch and operation checks still required | Source/unit; independent mapping and release-binary evidence |
| Substituted carried founder-root reference | Refuse root-reference mismatch; carried value never selects root | Root installation conflicts require external gate | Source/unit; independent-process root readback; actual ceremony |
| Correct signature under the wrong root | Refuse cryptographically or on root binding | No consumer may use alternate root fallback | Source/unit and independent-process; actual root provisioning evidence |
| Malformed key/signature or unsupported profile/version | Refuse with no fallback and no partial result | Consumer remains disabled/unavailable | Source/unit; release-binary later |
| Cross-purpose signature reuse | Refuse purpose/root-policy/domain mismatch | No consensus/governance/transport purpose may reuse it | Source/unit, including independent-purpose negative control |
| Duplicate record fields, members, IDs, addresses, keys, or signer references | Refuse duplicates; positional format has no repeatable named fields | No “first wins” or sorting repair | Source/unit |
| Noncanonical integer, text, key, address, or signature representation | Refuse canonical parsing/profile validation | None can normalize or substitute data after verification | Source/unit; independent-process |
| Truncation, arithmetic overflow, excessive length/count, or trailing bytes | Refuse before proportional allocation/crypto; require exact end-of-input | No state or key effect | Source/unit boundary coverage; release-binary later |
| Conflicting valid approvals or root installations | Stateless verifier may verify each presented exact content but cannot discover undisclosed conflict | B/U owner must detect/report conflict and activation refuses; no arrival-order choice | Independent-process, release-binary, actual currentness/rollback-domain evidence |
| Valid historical approval with unavailable or stale B | May return exact-content result only; no freshness claim | B consumer refuses unavailable/stale/conflicting state | Independent-process and release-binary; actual currentness source/rollback evidence |
| Missing or uncertain U | Verifier cannot infer first use | Activation consumer refuses | Independent-process, release-binary, actual external-state evidence |
| Restored local activation state | Verifier result unchanged and non-authorizing | B/U consumer rejects stale/unknown restore or remains unavailable | Independent-process restore; release-binary; actual rollback-domain evidence |
| Repeated verification versus attempted second activation | Repeated same-content verification may return same typed content result | U allows multiple verifier participants for one coordinated instance, but refuses a second activation absent separate authorization | Source/unit for identity; independent-process and release-binary for activation boundary |
| Valid A with missing C/L/X | Verifier may return exact-content result only | Signer/node refuse signing: missing C, L, or X is not supplied by A | Independent-process, release-binary; actual key/device/custody evidence |
| Pending or uncertain signing outcome | Verifier does not inspect or clear it | C preserves potentially-signed/pending state; no re-sign or founder override | Existing D10 source/storage scope remains distinct; future process/release recovery evidence |
| Configuration substituted after successful content verification | Previously returned object remains bound to original bytes/config/root context and cannot be retargeted | Node and signer each compare their current exact configuration and rerun required currentness/decision checks | Source/unit mutation controls; independent-process; release-binary later |

Future source/unit tests establish parser and local contract behavior only.
Independent-process tests must establish separate node/signer state and
cross-process refusal/reuse. Release-binary evidence must show actual startup
and activation wiring, with no bypass. Actual custody/device evidence must
establish root provenance, key exclusivity, and the named rollback domains.
None of these evidence levels is supplied by this documentation section.

### 9. Smallest next action and preserved posture

The smallest next action is for an assigned founder-root policy approver to
record acceptance or rejection of one complete verification profile
compatible with candidate v1's specified direct raw-message verification,
empty algorithm context, and no application-level prehash, including suite,
public-key/signature encodings, profile ID, and independent root/purpose
binding. No record or envelope metadata can change that mode. An incompatible
profile requires a separately reviewed candidate revision; it is not an
alternative interpretation of candidate v1. Without a compatible profile
decision, no signature can be interpreted as an approved bootstrap approval.
This one decision does not satisfy the remaining mapping, B/U, C/L/X, custody,
or implementation-entry prerequisites.

Preserved without promotion:

```text
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
Whole native-admission and authority contracts: DRAFT / NOT APPROVED / NOT IMPLEMENTED
Section 13.6 whole-lifecycle: INCOMPLETE
Activation: DISABLED
Public DevNet: NO-GO
Durable anti-rollback: NOT-ESTABLISHED
C4/C5: OPEN
RS1: OPEN
Candidate resource limits: UNAPPROVED
```

No F1/F2 closure, production authority, operational-security acceptance,
deployment permission, or release approval follows. The existing
implementation-entry checklist in
`QBIND_RUN_422_BOOTSTRAP_CREDENTIAL_RECOVERY_TRUST_MODEL.md` remains
applicable. Isolated implementation prerequisites are **NOT SATISFIED**.
This is a candidate documentation contract, not security acceptance or
operational approval.

## BR-01 founder verification profile — decision proposal

**PROPOSED / OWNER DECISION PENDING / NOT IMPLEMENTED**

This is one complete, concrete candidate for an explicit decision by the
unassigned founder-root policy approver. Preparing it is not acceptance,
identifier allocation, root provisioning, implementation authorization, or
activation. It keeps the settled scope: founder-authorized bootstrap of one
exact initial DevNet configuration, fixed initial membership, explicit unit
voting weights in this compatibility candidate, a dedicated bootstrap
credential separate from validator consensus keys, operator-controlled
validator keys, signer-owned authoritative per-key signing history, and
node-owned consensus-lock/recovery state. The founder cannot override
consensus safety, reset signing history, assume an uncertain signing outcome,
or establish freshness. Before MainNet, the planned transition is to genuinely
independent joint authority under a separately reviewed authorization and
transition policy. Environment identities, credentials, and authorization
records remain separate. No committee, threshold construction, recovery
authority, operational credential, or infrastructure is introduced.

### Proposed profile

| Property | Single candidate submitted for decision |
|---|---|
| Algorithm / parameter set | Pure ML-DSA-44, as specified by FIPS 204 |
| Standard and errata | NIST FIPS 204 final, published 2024-08-13. The NIST CSRC page's 2026-07-31 planning note points to an errata spreadsheet and says several minor issues are expected to be corrected in a future revision. The spreadsheet itself was not retrievable in this environment; its entries and applicability are **not verified**. Review that official errata before approval or implementation. No concrete incompatibility was found in the repository source inspected, but this is not a claim that the errata were cleared. |
| Public key | Exact raw FIPS 204 ML-DSA-44 encoding `rho || t1`, 1312 bytes; no wrapper, textual form, fingerprint, or alternate encoding on the wire |
| Signature | Exact raw FIPS 204 ML-DSA-44 encoding `c_tilde || z || h`, exactly 2420 bytes; no wrapper or alternate encoding |
| External verification | Pure ML-DSA verification of the **complete application message** below; algorithm context is empty; application-level prehash is none |
| Application message / domain | Exactly `ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00 || u32_be(payload_length) || payload` |
| Proposed profile ID | `1`, in the bootstrap proposal's local profile namespace only; unallocated pending BR-02. It is not consensus suite ID `100`, a standards identifier, or registry approval. |
| Purpose and scope | Dedicated founder authorization for one exact initial DevNet configuration and one initial network instantiation only; not consensus signing, other environments, later activation, or a standing authority |
| Refusal and compatibility | Accept only the exact algorithm, parameter set, key/signature encodings and lengths, pure mode, empty context, and message above. No alternate key, suite, context, digest, encoding, wrapper, domain, fallback, normalization, or legacy interpretation. A change requires a separately reviewed profile/version and authorized transition. |

This is a technical proposal, not an operational suite selection or approval.
Future algorithm agility does not permit changing the meaning of this profile
identifier in place.
A textual import representation, if separately specified in the future, is
outside this raw wire profile and must not become a second accepted wire
encoding.

### Standard and pinned-source correspondence

The primary normative reference is [NIST FIPS 204, final
(2024-08-13)](https://csrc.nist.gov/pubs/fips/204/final), also published at
[DOI 10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204). The CSRC
page was available through its indexed result, which identifies the final
publication and reports a 2026-07-31 planning note linking an “Errata
(potential updates)” spreadsheet. Direct retrieval of the CSRC page, official
PDF, and linked spreadsheet failed because the hostnames could not be
resolved. Therefore the exact errata entries, corrections, and their effect
on this candidate were **not inspected**; approval and implementation must
not treat errata review as complete.

At this baseline, `crates/qbind-crypto/Cargo.toml` requests
`fips204 = "0.4"`; this is a semver range, not an exact pin. `Cargo.lock`
resolves `fips204` **0.4.6** with package checksum
`c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15`.
The 0.4.6 crates.io archive was obtained from its versioned static archive
URL and its SHA-256 was checked against that exact lockfile checksum before
reading the extracted source. Only source and package metadata were read; no
package code, build script, examples, helper, or test was executed.

The source trace supports this one candidate:

* `MlDsa44Backend::verify(pk, message, signature)` in
  `crates/qbind-crypto/src/ml_dsa44.rs` checks `pk.len() == 1312` and
  `signature.len() == 2420`, converts each to the corresponding fixed array,
  and decodes the public key. Wrong key/signature lengths, failed fixed-array
  conversions, and public-key decoding errors map to
  `ConsensusSigError::MalformedSignature`. Once the full-length signature
  reaches the dependency's Boolean verifier with `message` and `&[]`, every
  `false` result maps to `ConsensusSigError::InvalidSignature`, including
  invalid signature encodings and failed mathematical verification. This
  wrapper does not expose those two failure causes separately; both remain
  rejected.
* `MlDsa44SignatureSuite::verify` in
  `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs` instead accepts a
  `Hash32` and passes those 32 digest bytes as its message. It is **not**
  evidence that the complete bootstrap message is verified and must not be
  used for this profile.
* The suite adapter's `canonical_key_descriptor` checks the same exact
  1312-byte length, decodes and re-encodes through the pinned `SerDes`
  implementation, and compares the bytes. Its source records that ML-DSA-44
  `rho` is arbitrary 32-byte data and each `t1` coefficient has a 10-bit
  encoding covering 0..=1023. Thus there is no distinct noncanonical
  full-length key pattern to invent for this parameter set; wrong length is
  malformed, and full-length encoding/canonicality is distinct from key
  validity, honest generation, private-key possession, identity, and custody.
* In the checksum-verified `fips204` 0.4.6 archive,
  `src/encodings.rs::pk_encode`/`pk_decode` (Algorithms 22/23) encode/decode
  `rho` followed by packed `t1`; `sig_encode`/`sig_decode` (Algorithms 26/27)
  encode/decode `c_tilde`, packed `z`, and packed hints `h`. Those source
  comments identify their FIPS 204 algorithm/page correspondence; the official
  PDF itself was not directly retrieved here. `z` is unpacked from its
  fixed-width coefficient encoding; the verifier then rejects values outside
  the strict norm bound. `HintBitUnpack` rejects invalid hint encodings,
  including out-of-order/duplicate hint positions and nonzero unused hint
  bytes.
  Verification requires `||z||_infinity < gamma1 - beta`, computes
  `w'_approx = A z - c t1*2^d`, reconstructs `w'_1` with the decoded hint,
  and checks that the challenge recomputed from the message representative
  and `w1Encode(w'_1)` equals encoded `c_tilde`. Failure returns false; there
  is no normalization or alternate parse. The wrapper rejects all
  wrong-length inputs before fixed-array conversion. The outer record parser
  must separately reject truncation, wrappers, extra/trailing bytes, and any
  signature length other than 2420; it must not normalize or retry another
  representation.
* `fips204`'s `try_sign(message, ctx)` and verification API implement the
  standard's pure ML-DSA message path. The pinned source forms the algorithm's
  internal message representative using its own mode byte, context-length
  byte, context, and message before internal hashing. For this proposal the
  external context is empty. The application's one NUL byte is only the
  separator in the application-domain bytes; it is not the algorithm context.
  “No application-level prehash” means pass the entire framed application
  message unchanged to raw-message verification. It does **not** disable
  ML-DSA's standard internal message formatting or hashing. Do not manually
  reproduce that internal framing, call an internal-only primitive, or
  substitute a digest.

The repository package is named `fips204` and implements a standardized
algorithm; neither fact establishes FIPS module validation, independent audit,
operational security acceptance, or production assurance. The source
inspection is not algorithm/module validation and no new test execution or
test evidence is claimed.

### Exact record, trust-root, and policy requirements

The existing signature envelope remains exactly:

```text
ASCII("SIG1") || u16_be(envelope_profile_id)
    || u32_be(signature_length) || signature_bytes
```

For this candidate, `signature_length` is exactly 2420 and the independently
trusted founder public key uses exactly the profile-defined 1312-byte raw
encoding. The payload's founder verification profile ID, the envelope profile
ID, and the independently selected trusted-root profile ID must all equal
candidate ID `1`. The record is untrusted input and cannot select or widen
root, profile, purpose, environment, or policy. Root/profile lookup is
independent of the record and refuses missing, ambiguous, mismatched, or
unsupported inputs.

The existing payload layout and application message above are unchanged:

```text
payload_length = 135 + label_length + 1394*member_count
record_length  = 4 + payload_length + 10 + signature_length
```

With the existing generic caps (`label_length <= 255`,
`member_count <= 4096`, generic `signature_length <= 65,535`), the generic
candidate maximum payload is **5,710,214 bytes** and generic maximum record
is **5,775,763 bytes**. With this profile's exact 2420-byte signature,
`record_length = payload_length + 2434` and its profile-specific maximum
record is **5,712,648 bytes**. The latter is a narrower profile acceptance
bound, not a change to the generic envelope cap and not an approved
operational resource limit. No parser allocation, latency, or other resource
policy is approved here.

Before any verification, each verifier independently provisions and selects
all of the following:

1. The **complete founder public-key byte string** in the exact profile
   encoding, not an untrusted carried key or a shortened fingerprint.
2. The exact accepted verification profile and **initial-DevNet-bootstrap**
   purpose.
3. The exact, nonzero 32-byte founder credential reference, associated
   independently and compared byte-for-byte; this is an opaque association,
   not a self-authenticating key, short fingerprint, or freshness proof.
4. The independently established environment/network identity and scope,
   including the external identity/configuration expectations required by
   the existing integrated approval contract (runtime and wire identities,
   exact genesis/configuration, fixed ordered membership, validator
   consensus-key associations, explicit unit weights, epoch/profile, and
   single-instantiation scope).
5. Any additional independently trusted purpose, conflict, and currentness
   policy inputs required by that contract. A valid signature alone does not
   establish B/U or the other lifecycle evidence.

No value for the root, private key, credential reference, network, operator,
device, certificate, or ceremony is created here. Root provisioning must
remain independent of first-arrival order and the approval record. No
trust-on-first-use, carried-key self-authentication, optional pins,
shortened-fingerprint trust, automatic root replacement, or first-arrival
conflict resolution is allowed. Repository access, HTTPS, SSH, email, and
administrative accounts do not themselves establish the founder root. The
existing ceremony recommendation assumes a manual direct founder-to-operator
encounter: each operator's verifier authenticates the founder through a
prearranged physical identity procedure independent of the repository,
download distributor, and installer; the founder personally presents the
full public key and exact intended DevNet manifest; and operators reconcile
full public references and conflicts before separately checking each
node/signer installation. This human identity check is itself a trust
assumption and can fail through impersonation, collusion, coercion, or
substitution; a paper copy or manual comparison is neither PQ identity
authentication nor freshness proof. These proposed steps and risks come
from the existing custody/recovery model; no personnel, procedure, evidence,
or ceremony is supplied here.

The founder credential must be dedicated to this bootstrap purpose and
separate from validator consensus keys and credentials for other environments
or purposes. Public-key bytes cannot prove exclusive custody or universal
absence of key reuse. Verification proves neither key ownership/possession nor
honest key generation, offline custody, non-copyability, side-channel
resistance, zeroization, or uncompromised execution.

### Signing procedure and limits of verification

The production-facing repository backend's current `generate_keypair()` calls
the pinned `try_keygen()`; its `sign()` and `sign_into()` paths call
`try_sign(message, &[])`. In `fips204` 0.4.6 those default APIs use the OS
default RNG (`OsRng`): key generation obtains its 32-byte random seed through
fallible RNG filling, and randomized signing obtains a 32-byte per-message
random value.
The backend returns an error on key-generation or signing failure; there is
no automatic deterministic fallback in these calls. Any separately
authorized future key-generation/signing procedure must use a cryptographic
random generator seeded with adequate entropy for the standard and its
approved environment, require the needed random bytes, and refuse on any
required randomness failure. It must not switch automatically to
`try_sign_with_seed`, a fixed seed, or another deterministic path.

The verifier cannot establish the entropy quality or custody of the signing
process, nor infer which permitted generation procedure produced a valid
signature. A signing error or uncertain result is not proof that no signature
was produced; preserve the potentially-signed/uncertain state and do not retry
or resolve it by assumption. Generating an operational key, signing an
approval, and conducting a root ceremony are separately authorized future
actions.

### Future acceptance cases — NOT EXECUTED

| Case | Expected isolated content-verifier result | Evidence level needed; not supplied here |
|---|---|---|
| Correct independent profile/root and exact framed message | Verify the complete message once and return only the existing exact-content result; no activation/signing permission | Source/unit, independent-process, release-binary, and actual root/custody evidence are separate |
| Wrong key, purpose, profile ID, or envelope/payload/root profile mismatch | Refuse before any alternate root/profile/purpose attempt | Source/unit; independent root provisioning and release-binary checks separately |
| Modified message, domain, NUL separator, payload, or length prefix | Signature verification fails; no alternate framing | Source/unit negative controls |
| Non-empty algorithm context | Unsupported by this profile; refuse, do not retry with another context | Source/unit |
| Digest-taking `MlDsa44SignatureSuite` adapter substituted for complete-message verification | Profile mismatch / no acceptance; adapter is not the specified input path | Source-level call-path check and source/unit control |
| Wrong key/signature lengths, wrappers, truncation, or trailing bytes | Refuse as malformed/noncanonical; no trimming, normalization, or fallback | Source/unit boundary controls; release-binary behavior separately |
| Decoder-invalid or mathematically invalid signature | Refuse; no partial content result | Source/unit controls; independent implementation testing separately |
| Correctly encoded public key without proof of ownership/custody | Encoding may parse; no ownership, possession, identity, or custody conclusion follows | Actual root ceremony, operator/device/custody evidence; not a source/unit fact |
| Different valid signatures over identical payload content | Same approval-content identity; no additional bootstrap permission | Source/unit identity control; activation remains separately gated |
| Valid signature with missing B/U or other lifecycle evidence | Content verification alone supplies no activation, freshness, or signing permission; consumer refuses the dependent effect | Independent-process, release-binary, and actual currentness/recovery evidence |

These are future cases, not vectors, keys, signatures, or tests created or run
by this task. Source/unit behavior, independent-process behavior,
release-binary behavior, and actual custody/device evidence remain distinct.
Historical tests retain their original revision and scope and are not new
evidence from this proposal.

### Owner decision card

**Decision requested:** accept or reject the exact proposed ML-DSA-44 profile
above for founder authorization of one exact initial DevNet configuration.
The decision is only about this proposed content-verification profile.

| Field | Status |
|---|---|
| Proposal prepared | YES — documentation only |
| Authorized technical-profile decision | **PENDING** — acceptance/rejection not supplied |
| BR-02 identifier allocation | **PENDING** — candidate ID `1` remains unallocated |
| Independent operational root/profile provisioning | **NOT DONE** |
| Implementation acceptance/authorization | **PENDING** — not authorized by preparing or accepting this proposal |
| Activation/release approval | **PENDING / DISABLED** |
| Accountable approver role | Founder-root policy approver; unassigned. No person is designated here. |
| Disposition, approval date, signature, evidence | **PENDING** — no value supplied or inferred |

Owner acceptance must cover this exact profile, its precise mode and root
policy, and the disclosed standard/errata limitation. An incompatible change
requires a separately reviewed profile/version. Even later acceptance cannot
supply B/C/L/X/U, waive BR-02–BR-11, authorize implementation automatically,
or enable activation.

Preserved without promotion:

```text
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
Whole native-admission and authority contracts: DRAFT / NOT APPROVED / NOT IMPLEMENTED
Section 13.6 whole-lifecycle: INCOMPLETE
Activation: DISABLED
Public DevNet: NO-GO
Durable anti-rollback: NOT-ESTABLISHED
C4/C5: OPEN
RS1: OPEN
Candidate resource limits: UNAPPROVED
Isolated implementation prerequisites: NOT SATISFIED
```

The existing non-null `GenesisConfig.extra` refusal and all other integrated
contract restrictions remain unchanged. No F1/F2 closure, deployment
permission, production authority, security acceptance, or release approval
follows.
