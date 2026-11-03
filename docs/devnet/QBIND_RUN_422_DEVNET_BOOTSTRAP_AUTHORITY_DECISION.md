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

## BR-01 FIPS 204 potential-updates applicability review - later evidence

**DOCUMENTATION ONLY / SOURCE INSPECTION / OWNER DECISION PENDING**

Inspection date: **2026-11-03 UTC**. This appended review follows the earlier
retrieval failure; it does not rewrite that historical account or imply that
the earlier task inspected the PDF or workbook. The resumed task inspected
user-supplied copies, not files downloaded directly from NIST by this agent.
The earlier attempt stopped without edits or commits after NIST hostname
resolution failed. The baseline proposal's "not verified" statements describe
that earlier evidence state; the entry coverage below is new, later evidence,
not retroactive access or acceptance of BR-01.

### Review baseline, sources, provenance and inspection method

The clean starting checkout was `olivexo28/QBIND`, origin
`https://github.com/olivexo28/QBIND`, commit
`b53d5bf783d7314e05ac2ec1a18fc92471029984`, tree
`8bfe69c4b810b73d6d9d798d3907c9c9da12d23d`. The raw commit has parent
`eed99ffc3af60c1817b2fde653ddb7a65e739b52`; this is raw object parentage,
not an inference from shallow traversal. Remote main matched that baseline.
The existing task branch `copilot/run-422-br01-fips204-errata-review` was
reused. No applicable `AGENTS.md` was found in the repository or ancestor
directories. Main was not modified.

The user reports that the official publication page was independently
retrieved in the reviewing conversation and linked both files below:
`https://csrc.nist.gov/pubs/fips/204/final`.
That is **reported publication-page link evidence**, not a successful
publication-page retrieval or independent origin authentication performed in
this task. The supplied originals were uploaded after the request to download
the official files. Their original download timestamps were not supplied.
This task checked their exact byte counts and SHA-256 values against the
user's supplied values, then independently read their contents on the
inspection date. No repeated NIST network retrieval was needed.

| Inspected input | Source URL associated with supplied copy | Byte count | SHA-256 | Acquisition/date evidence |
|---|---|---|---|---|
| `NIST.FIPS.204.pdf` | `https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf` | 3291746 | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` | User-supplied copy; inspected 2026-11-03 UTC; original download time unknown |
| `fips-204-potential-updates.xlsx` | `https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx` | 23071 | `5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793` | User-supplied copy; inspected 2026-11-03 UTC; original download time unknown |
| `fips204-0.4.6.crate` | `https://static.crates.io/crates/fips204/fips204-0.4.6.crate` | 1540138 | `c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15` | Retrieved by this task 2026-11-03 UTC; checksum verified before source extraction/inspection |

These hashes identify the inspected bytes; they do not independently
authenticate NIST origin. Likewise, the archive checksum establishes equality
with the locked package, not independent security assurance. Research inputs,
extracted dependency source and inspection artifacts were kept outside the
repository.

The PDF was opened with a PDF reader and text extracted from all 65 physical
pages; the affected prose, algorithms and appendices were read, not inferred
from search excerpts. Its title page states "Published August 13, 2024".
Printed standard pages 1-55 are physical PDF pages 11-65; standard locations
below use printed pages when a page number is supplied.

The workbook was inspected as ZIP/XML, without executing macros, formulas,
external content, or package code. Inspection covered the package manifest,
workbook/sheet XML, all populated cells and shared strings, relationships,
core/custom properties and custom XML. There is exactly one worksheet,
`Sheet1` (default visible state), with no hidden worksheets, hidden rows or
hidden columns. All shared strings are referenced. There are no formula
cells, comment/note parts, VBA parts or external-link parts; the worksheet's
only relationship is printer settings, which were not executed. The custom
XML contains document-library/content-type metadata, not additional errata.
Blank formatted cells outside the table contain no further entries.

`Sheet1!C1` states **"Last updated 7/31/2026"**. `B3` states "August 2024";
`B4` is the release date 2024-08-13 (Excel serial 45517). The workbook's core
modified timestamp is `2026-07-31T17:14:24Z`; its core created timestamp
`2020-11-03T17:29:38Z` is metadata, not a FIPS 204 publication/retrieval date.
The twelve entries occupy `A16:D27`: A is date identified, B standard
location, C issue, D potential correction. Rows 8-13 expressly say these
**potential corrections DO NOT introduce new technical requirements and ARE
NOT official changes**; they may be corrected in a future update/revision.
This review preserves that status instead of treating proposed wording as
an adopted amendment. An editorial label does not by itself establish lack
of security relevance.

`Cargo.lock:1323-1333` resolves `fips204` 0.4.6 with exactly the archive
checksum above. `crates/qbind-crypto/Cargo.toml:9` still requests `"0.4"`;
the lockfile resolves the inspected release, while the manifest is not an
exact version pin. No newer release was substituted. Only source and
metadata were read; no dependency code, build scripts, examples or tests
were executed.

### Unchanged candidate and source-locator key

The candidate remains **pure ML-DSA-44**, exact raw 1312-byte public key and
raw 2420-byte signature, verifying the complete application message:

```text
ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00 ||
u32_be(payload_length) || payload
```

Algorithm context remains empty and application prehash remains absent.
The standard's internal pure-mode framing and hashing are not an application
prehash: for empty context, `M' = 0x00 || 0x00 || application_message`, and
`mu = H(tr || M', 64)`. The application's domain separator and length field
are unchanged. No manually preframed internal API input or digest adapter is
an alternative. Profile ID `1` remains proposal-local and **unallocated
pending BR-02**, not consensus suite ID 100. Independent full-root and purpose
provisioning remain unresolved; no record-carried selector can replace them.
The fixed initial-DevNet, exact-configuration, single-instantiation scope,
custody requirements and all lifecycle restrictions are preserved.

In the applicability table, dependency paths are relative to the extracted,
checksum-verified `fips204-0.4.6/` archive, **not repository-owned source**.
QBIND source locations refer to the baseline above. These abbreviations give
each table entry an explicit repository call-path locator:

* **QV**: `crates/qbind-crypto/src/ml_dsa44.rs:531-572`,
  `MlDsa44Backend::verify`/`verify_internal`, raw complete-message API, exact
  key/signature lengths, `public_key.verify(message, &sig_array, &[])`;
  dependency false becomes `InvalidSignature`.
* **QS**: `crates/qbind-crypto/src/ml_dsa44.rs:386-394,412-432,484-514`,
  key generation, signing and `sign_into`; default random generation,
  `try_sign(message, &[])` and returned-error propagation.
* **QD**: `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs:90-98`,
  the `Hash32` adapter. It verifies those digest bytes as its message and is
  **not** the candidate's complete-message verifier.

The shared `functionality!` macro (`src/lib.rs:116-133,254-410`) and shared
`ml_dsa`, NTT, encoding and arithmetic helpers were checked, including the
ML-DSA-65/87 branches in `src/high_low.rs:82-86,182-187`. Entries were not
dismissed merely because they also concern other parameter sets or the
non-candidate HashML-DSA APIs.

### Exhaustive entry-by-entry applicability

| Workbook locator | Affected standard location and potential correction | Applicability / class | Pinned dependency locator | QBIND locator | Source observation, discrepancy and remaining uncertainty | BR-01 consequence / smallest future action |
|---|---|---|---|---|---|---|
| `Sheet1!A16:D16` (2024-09-20) | Sections 2.5 and 7.5, immediately after equations (2.1)/(7.1), pp. 8/42: evaluation point is `zeta^(2*BitRev8(i)+1) mod q`, not that expression evaluated through `w` a second time. | Applicable shared NTT semantics; explanatory mathematical correction, not a wire-format change. | `src/ntt.rs:11-75,85-157`; `src/helpers.rs:176-190`, `gen_zeta_table_mont`/`ZETA_TABLE_MONT`; `src/ml_dsa.rs:81-92,215-223,406-419`. | QV and QS use these shared transforms. | Butterflies use powers from the bit-reversed zeta table in Montgomery form; table generation depends on `ZETA`, not on the input polynomial. No nested `w(w(...))` evaluation is observed. Full numerical transform conformance was not executed or proved here. | No candidate change indicated. Future independent conformance evidence must cover the actual transform; do not implement the erroneous explanatory composition. |
| `Sheet1!A17:D17` (2024-10-17) | Sections 6.2/6.3, pp. 23/25: internal signing/verifying prose should refer to formatted `M'`, not unformatted `M`. | Directly applicable message framing; prose correction with security-relevant interpretation. | `src/ml_dsa.rs:143-194,335-399`; `src/lib.rs:268-295,364-379`; `src/hashing.rs:13-17`. | QV/QS pass message and empty context; QD is excluded. | Ordinary pure APIs select `nist=false` with empty OID and hash `tr`, mode byte 0, context-length byte, context, complete message in that order. Empty context produces the concatenation of `tr`, `00`, `00`, then `message`. Direct internal-vector paths are different and are not the candidate API. No framing discrepancy observed; execution not established. | Preserve full application message, not a digest or manually formatted `M'`. Future isolated verifier must wire QV with the exact framing and independent root; this review does not implement that consumer. |
| `Sheet1!A18:D18` (2025-12-02) | Various internal PDF links: Algorithms 4, 5, 9-14, 49 and footnotes 1, 5, 6, 13; links will be repaired. | Editorial navigation, not a cryptographic algorithm or rejection change. | `src/lib.rs:297-410` (Algorithms 4/5); `src/helpers.rs:154-170` (Algorithm 49). Source paths/algorithm numbers are used rather than depending on PDF hyperlinks. | QV/QS; QD boundary unchanged. | No runtime dependency on intra-PDF links is involved in these calls. A PDF link repair does not alter source behavior. The repair itself has not been supplied as an adopted replacement PDF or validated here. | No implementation correction indicated; use stable section/algorithm locators for future evidence. No approval follows from navigation repair. |
| `Sheet1!A19:D19` (2025-12-02) | Section 2: remove unused AES acronym; bold vector `w` in the infinity-norm definition and vectors `v[0], v[1], ...` in Section 2.4.2. | Editorial acronym/typography; vector interpretation still matters to implementation. | `src/helpers.rs:142-151`, `infinity_norm`, flattens vector rows and takes the maximum centered coefficient magnitude; `src/ml_dsa.rs:274-279,434-436`. | QV/QS norm checks. | The source norm operates across the polynomial vector, not only one selected polynomial. The acronym deletion adds no AES operation or alternate suite. No computational change indicated by this entry; numerical norm behavior not executed. | Keep current candidate and future vector/norm conformance checks; no new algorithm dependency or code change justified by typography alone. |
| `Sheet1!A20:D20` (2025-12-02) | Section 3: bold vector `b` in footnote 2; Section 3.3 challenge-hash explanation must concatenate `mu` then `w1`, not `w1` then `mu`, consistent with Algorithm 7 line 15. | Typography is editorial; challenge-input order is directly security/interoperability relevant to signing and verification. | `src/ml_dsa.rs:230-234,426-431`; `src/hashing.rs:13-17`. | QV/QS share these paths; QD still does not satisfy application framing. | Signing hashes `&[&mu, &w1_tilde]`, verification hashes `&[&mu, &tmp]`; the hash helper absorbs slices sequentially. Both agree with Algorithms 7/8 and the potential correction, not the reversed prose order. No observed source discrepancy; hash/conformance execution absent. | No source-order fix indicated. Future cross-implementation evidence must retain the exact order; do not interpret "minor" as permission to reverse it. |
| `Sheet1!A21:D21` (2025-12-02) | Section 5, Algorithms 1, 2, 4: replace undefined randomness-failure notation `NULL` with bottom/failure. | Failure-notation correction; applicable to key generation and randomized signing. HashML-DSA is excluded as a candidate mode, but its shared RNG/error path was inspected. | `src/ml_dsa.rs:26-45`; `src/lib.rs:268-295,311-340`; `src/traits.rs:44-46,156-158`. | QS keygen/sign/sign_into; QV performs no randomness acquisition. | Fallible `try_fill_bytes` obtains 32-byte seed/randomness; failure propagates as `Err` before the internal call. Default APIs use `OsRng`. Some pseudocode comments retain `NULL`, but no automatic deterministic fallback is observed. Source cannot establish entropy quality, RBG approval or actual failure handling in a deployed environment. | No computational discrepancy established from notation. Future authorized ceremony/signing work must preserve randomness refusal and independently evidence entropy/custody; comment cleanup is separate and not performed here. |
| `Sheet1!A22:D22` (2025-12-02) | Section 6: call `t` (two occurrences) and hint `h` polynomial vectors, not polynomials; Algorithm 6 must say `Power2Round`, not `PowerTwoRound`; Algorithm 8 line 7 has redundant outer hash parentheses. | Editorial terminology/naming/parentheses, with shared keygen and verification interpretation checked. | `src/ml_dsa.rs:81-92,209,303-309,369-376,385-399`; `src/high_low.rs:10-47`. | QS keygen/sign; QV verification. | `t`/`h` are arrays of polynomials; keygen calls `power2round`, which maps coefficients across K polynomials. Hash-parenthesis removal does not change `mu`. No computational discrepancy observed; algebraic equivalence is not independently proved here. | No algorithm/profile change indicated. Keep vector-level and named-operation correspondence in future evidence; no code correction required solely by the editorial entry. |
| `Sheet1!A23:D23` (2025-12-02) | Section 7, prose above Algorithm 28, p. 35: `w1Encode` is used by `Sign_internal` and `Verify_internal`, rather than merely `Sign`. | Editorial call-site description; encoding is directly shared by both candidate paths. | `src/encodings.rs:331-359`; `src/ml_dsa.rs:230-234,426-431`. | QV/QS. | Both internal routines call `w1_encode`; its bound and packing depend on gamma2. Its source comment still names old `sign_finish`/`verify_finish` functions, while actual calls establish correspondence. No missing verifier encoding call observed; runtime encoding compatibility untested. | No encoding change indicated. Smallest future documentation cleanup is correcting stale helper call-site names; preserve real signing and verifying calls and add conformance evidence later. |
| `Sheet1!A24:D24` (2025-12-02) | Appendix A / Algorithm 49, p. 50: exclusive positive input bound; signed low-32-bit representative and sign extension of `t`; result magnitude less than q, not merely less than 2q. | Applicable shared Montgomery arithmetic, not just editorial or other-parameter-set material. | `src/helpers.rs:154-170`; uses in `src/ntt.rs:42-48,116-132`, `src/ml_dsa.rs:406-419`. | QV/QS through shared NTT/multiplication. | **Comment:** retains inclusive `-2^31*q <= a <= 2^31*q`. **Debug checks:** lower `-17996808479301632`, upper `17996808470921215`, a stricter positive bound than `2^31*q` (=17996808479301632). **Arithmetic:** signed `i32` truncation, `wrapping_mul(QINV)`, signed widening to `i64`, subtraction and arithmetic shift; debug output checks assert `-q < res < q`. Arithmetic matches the signed-representation correction in source; the stale inclusive comment does not describe the actual debug interval. Call-site range sufficiency and all outputs have not been exhaustively proved/executed. | Concrete documentation discrepancy, not an observed verification-result defect. Smallest future correction is documenting the intended helper range consistently with its checks and reviewing callers before any range/assertion change. No arithmetic patch or dependency upgrade is authorized by this review. |
| `Sheet1!A25:D25` (2026-02-23) | Section 5.3, Algorithm 3 step 2, p. 18: return `false`, rather than bottom, when context length exceeds 255. | Verification rejection behavior; candidate always uses empty context, but shared public API was checked. | `src/lib.rs:364-379`; also `391-410` for non-candidate hash verification. | QV fixes context to `&[]` and maps false to `InvalidSignature`. | Both public verifier implementations return `false` for `ctx.len() > 255`; adjacent pseudocode comments still say bottom. Runtime source corresponds to the potential correction. No overlong context is admitted by the proposed profile; no boundary execution performed. | No behavior fix indicated. Smallest future cleanup is the stale comment; preserve mandatory empty-context policy and future boundary refusal evidence, with no alternate-context retry. |
| `Sheet1!A26:D26` (2026-02-27) | Section 7.4, Algorithm 40, p. 41: tighten documented UseHint upper bound to `(q-1)/(2*gamma2)-1`; verification feeds this to `w1Encode`, which already requires that bound. | Applicable shared verification value range/encoding interface. Original loose inequality is technically true, not the tight bound. | `src/high_low.rs:66-95,147-190`; `src/encodings.rs:336-345`; `src/ml_dsa.rs:419-429`; ML-DSA-44 constants `src/lib.rs:640-653`. | QV. | `use_hint` doc comment retains the loose inclusive bound. For ML-DSA-44, gamma2=(q-1)/88, so m=44: `decompose` selects 0..43, h=0 returns that value, and hint adjustment explicitly wraps 43 to 0 or 0 to 43. The 65/87 branches mask to 0..15. `w1_encode` documents/checks the tight bound. No source path returning 44 for the selected branch is indicated; no exhaustive executed range check is claimed. | Documentation discrepancy only observed. Smallest future correction is tightening the helper output comment; independently validate the decompose/hint/encoding interface before implementation acceptance. Do not change the encoding or parameter set. |
| `Sheet1!A27:D27` (2026-07-31) | Section 4 Table 1, p. 15, and Appendix C/Table 3, p. 52: expected signing repetitions 4.36/5.14/3.91 replace 4.25/5.1/3.85 after accounting for Algorithm 7 line 28; minimum permissible signing-loop limit, **if imposed**, changes 814 to 821. | Applicable signing probability/resource analysis across shared parameter sets, not a verification-encoding change or mandate to add a cap. | `src/ml_dsa.rs:204-212,274-318`; `src/hashing.rs:281-301`; `src/lib.rs:640-647` (L=4); public result wrapper `src/lib.rs:268-295`. | QS, including `sign_into`; QV does not execute this signing loop. | Both rejection checks, including line 28's norm/hint-weight check, are present. Signing uses `loop` and ordinary `u16` `kappa_ctr += L` on rejection; `expand_mask` also uses ordinary `u16` `mu + r`. There is no explicit iteration cap or checked exhaustion error return. Finite counters are not evidence of a safe resource bound or uniform exhaustion refusal: overflow behavior depends on build overflow checks (panic versus wrapping). Neither signing time nor exhaustion behavior was executed; no exploit is demonstrated. | Do not introduce 821 as a cap or claim bounded signing time. Future signing-implementation work must resolve counter representability/exhaustion, conditional-limit semantics, intermediate-result destruction and uniform failure handling if a limit is selected, with separate evidence. This does not change BR-08 or other existing gate definitions, authorize signing or require a profile change. |

### Bounded findings, unresolved work and owner disposition

**Coverage:** all twelve entries in the supplied, 2026-07-31-updated workbook
are covered individually above, including the initial notes and nonvisible
package-content inspection. This is coverage of these exact supplied bytes,
not proof that no later official workbook exists. Reported official links
and byte-identity checks are distinct from independent origin authentication.
The earlier inability to retrieve NIST sources remains part of the history.

**Source-level compatibility:** no applicable computational discrepancy was
observed in the inspected candidate verification paths for pure-mode message
formatting, challenge-input order, context-length rejection, internal
`w1Encode` use or the selected UseHint branch. Signed Montgomery arithmetic
also corresponds at source level, but this is not a proof of all caller
ranges or complete arithmetic conformance. The review does not establish
whole-package conformance or declare every erratum security-irrelevant.
Editorial corrections in rows 18/19/22 do not change the candidate wire bytes.
Rows 16/17/20/21/23-27 merit the specific mathematical, framing, randomness,
encoding, rejection or resource considerations recorded above.

**Concrete documentation discrepancies and smallest future corrections:**
the dependency retains the inclusive Montgomery input comment (row 24),
the loose UseHint bound comment (row 26), the old `w1_encode` caller names
(row 23), and old pseudocode failure notation (rows 21/25). These do not by
themselves show incorrect executed verification. A separately authorized
future dependency-maintenance task could align those comments with the
intended algorithms and actual code; the Montgomery contract requires caller
range review, not merely replacing a bound mechanically. No source fix or
dependency upgrade was made here.

**Remaining implementation questions:** the ordinary signing-counter
increments are not a checked, uniform exhaustion-refusal mechanism. A future
signing implementation review must decide how to preserve distinct mask
inputs and safely handle counter exhaustion, including build-dependent
overflow behavior, cleanup and uncertain outcomes. If it elects a loop limit,
the workbook's revised minimum is 821, not a directive to cap at 821;
Appendix C's conditional cleanup/uniform-outcome requirements must be
addressed. Expected repetitions, finite counter width and a caller-owned
output buffer establish neither a running-time bound nor acceptable
operational resources. This source observation does not demonstrate an
exploit, mean a signature was produced, or permit retry after uncertainty.
It is a future implementation concern within the existing decisions, not a
new gate, an automatic BR-01 rejection, or an approval exception.

Future executed conformance/interoperability and malformed-input evidence,
complete arithmetic/call-site range assurance, release-binary correspondence,
and any actual randomness, custody or offline-environment assurance remain
absent from this task. The future bootstrap parser/consumer must still
verify the complete framed message under an independently provisioned root
and purpose; the digest-taking QD adapter remains unsuitable. Previously
closed documentation findings are not reopened by this review. The custody
model's section 10 implementation-entry checklist remains in force.

**Owner acceptance/rejection: PENDING.** This review supplies later errata
evidence for the existing decision card only; it does not allocate profile
ID 1, select/provision a root, assign an approver, accept the cryptographic
profile, authorize implementation, or waive any prerequisites. BR-02-BR-11
and B/C/L/X/U remain unchanged. No keys, signatures, test vectors, tests,
builds, scans, activation or deployment were produced/run. Source inspection
does not establish executed conformance, FIPS algorithm/module validation,
security acceptance or production readiness.

Both authorized documents retain their complete baseline-byte prefixes and
mode 100644. This authority document retains LF and its terminal newline;
the evidence cross-reference uses a leading CRLF delimiter, CRLF throughout
the append, and no final newline. The delivery checks are documentation-only:
entry/locator correspondence, supported conclusions and explicit gaps,
restricted changed paths, prefix/mode/EOL preservation and whitespace.

All existing status blocks and gates are preserved without promotion:
`D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`;
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`;
`D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`;
whole native-admission and authority contracts **DRAFT / NOT APPROVED / NOT
IMPLEMENTED**; section 13.6 whole-lifecycle **INCOMPLETE**; durable
anti-rollback **NOT-ESTABLISHED**; C4/C5 and RS1 **OPEN**; candidate resource
limits **UNAPPROVED**; isolated implementation prerequisites **NOT
SATISFIED**; activation **DISABLED**; public DevNet **NO-GO**.

## BR-01 founder verification profile owner decision — 2026-11-03

**ACCEPTED — DESIGN ONLY.**

| Decision field | Recorded decision |
|---|---|
| Disposition | **ACCEPTED — DESIGN ONLY** |
| Public approver label | `olive` |
| Accountable role for this decision | Founder-root policy approver |
| Decision date | 2026-11-03 (Asia/Calcutta; calendar date only) |
| Accepted definition | The BR-01 verification-profile design and independent-root/purpose policy recorded at commit `bc97cd5cb50341c208c4265942b05ceefb0c5c58`, tree `cdc6a432f88516bb40cb7ef567c51ea8310abdc5`, including its appended FIPS 204 potential-updates applicability review and expressly disclosed limitations |
| Decision evidence | Explicit user confirmation conveyed through this task instruction: “yes” to “ACCEPT — olive” as founder-root policy approver, accepting the reviewed BR-01 verification-profile design only while retaining open implementation prerequisites and disabled activation |
| Cryptographic signature | **NOT SUPPLIED OR GENERATED** |

This decision supersedes earlier **PENDING** and unassigned-approver statements
only as to the BR-01 owner's technical-profile decision and the accountable
approver role for that decision. Those statements remain preserved above as
historical evidence of the proposal's prior state; no other PENDING, DRAFT,
NOT APPROVED, NOT IMPLEMENTED or disabled status is globally replaced.

The accepted design is unchanged: pure ML-DSA-44; exact raw 1312-byte public
key and 2420-byte signature; verification of the complete message
`ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00 ||
u32_be(payload_length) || payload`; empty algorithm context; no application
prehash; and an independently trusted root/purpose policy for one exact
initial DevNet configuration, with fixed membership and all existing
lifecycle restrictions. Acceptance includes the source-only errata review
and its provenance, conformance, source-level and signing-exhaustion
limitations without converting those limitations into findings of executed
conformance or operational assurance.

The public label and conversational decision do not provision or authenticate
an operational founder credential. They establish no legal identity,
GitHub-account binding, public key, credential reference, root distribution,
ceremony, custody, or independent root/purpose provisioning.

The scope of this acceptance is limited to the owner design decision:

| Status or gate | Preserved status |
|---|---|
| Candidate profile ID `1` | **UNALLOCATED — PENDING BR-02** |
| Operational root/profile provisioning | **NOT DONE** |
| Implementation acceptance/authorization | **PENDING** |
| BR-02–BR-11 and B/C/L/X/U | **UNCHANGED** |
| Whole native-admission and authority contracts | **DRAFT / NOT APPROVED / NOT IMPLEMENTED** |
| Isolated implementation prerequisites | **NOT SATISFIED** |
| Activation | **DISABLED** |
| Public DevNet | **NO-GO** |
| D7D14/D7D10, recovery, anti-rollback, resource and other status blocks | **UNCHANGED** |

This acceptance does not authorize implementation, operational signing, key
generation, deployment, release, or activation. It does not assign an
operational approver or waive any prerequisite. Existing source-only errata
evidence, source provenance limitations, and signing-counter/exhaustion
follow-up concerns remain intact. No technical review is reopened or
repeated by this decision record.

## RUN 422 BR-02 identifier-allocation and compatibility proposal

**PROPOSAL PREPARED / BR-02 OWNER DISPOSITION PENDING / NO IDENTIFIERS
ALLOCATED / NOT IMPLEMENTED**

This is a source-grounded proposal for the separate protocol/record contract
owner's explicit BR-02 accept-or-reject decision. It does not accept BR-02,
allocate values in a registry, authorize implementation, or alter the
accepted BR-01 design. The accountable BR-02 owner remains unassigned; BR-01's
founder-root policy approver role does not assign this separate contract-owner
role.

### Layout and allocation scope

The authoritative candidate layout remains this document's “Bootstrap
approval record and verifier contract — candidate v1,” subsection
“2. Candidate encoding and exact approval bytes,” specifically its payload
and message framing at lines 301–340 and the ordered 21-field table at lines 342–362,
followed by its classification at lines 364–376. Those existing bytes,
order, constraints, arithmetic bounds, profile-specific sizes, and the
`GenesisConfig.extra == Null` refusal are unchanged. This proposal points to
that table rather than defining a competing layout. Its 21 entries remain in
order: fields 1–9 once, fields 10–15 repeated `member_count` times in genesis
order, then fields 16–21 once. All integers remain unsigned big-endian;
field 7 retains its `u16_be` byte-length framing and permitted ASCII
constraints; fields 8, 11, 12, 14, 16, and 20 retain their specified fixed
byte widths. The outer payload length, member count, validator-ID/index rule,
per-field bounds, checked arithmetic, and candidate size rules are unchanged.
These are encoding/format constraints, not approval of operational resource
limits.

Within this BR-02 append, “candidate §2” means that exact encoding subsection,
not the earlier “2. Logical bootstrap authorization record.” “Candidate §3”
means the same candidate contract's “3. Trust-root and algorithm-selection
boundary” at lines 445–462.

The following is the complete proposed identifier/domain set for BR-02.
“Proposed only” is the status of every row: none is registered or allocated
by this task. Hex is shown to make the literal bytes unambiguous.

| Candidate item / layout slot | Exact candidate bytes or value and width | Namespace and meaning | Authentication status | Source / proposal locator | Bounded collision comparison | Proposed status |
|---|---|---|---|---|---|---|
| Record magic / field 1 | ASCII `QBAP` = `51 42 41 50`, 4 bytes | Bootstrap approval-record family | Authenticated field; the complete payload is signed | Candidate §2 fields 1–2; no executable bootstrap record type located | No exact `QBAP` record magic observed in the inspected source; unrelated persisted-record magics have their own formats | Proposed only; unallocated |
| Record format version / field 2 | `u16_be(1)` = `00 01` | Bootstrap approval-record schema version | Authenticated field | Candidate §2 field 2; compare persistence versions at `crates/qbind-node/src/signing_reservation_journal.rs:56-59` | Numeric value 1 also occurs in other format namespaces, including a distinct journal `u16`; value equality alone is not a collision | Proposed only; unallocated |
| Authorization purpose / field 3 | `u16_be(1)` = `00 01` | Bootstrap approval-purpose namespace; initial DevNet bootstrap only | Authenticated field | Candidate §2 field 3; no executable bootstrap-purpose registry located | No same-purpose registry allocation observed in inspected source; unrelated enums/versions do not allocate this purpose | Proposed only; unallocated |
| Environment / field 4 | `u8(1)` = `01` | Candidate bootstrap-record environment namespace; DevNet only | Authenticated field | Candidate §2 field 4; `NetworkEnvironment` at `crates/qbind-types/src/primitives.rs:105-146`; `TrustBundleEnvironment` at `crates/qbind-node/src/pqc_trust_bundle.rs:105-127` and its request-digest consumer at `crates/qbind-node/src/pqc_remote_signer_transport.rs:293-308` | `NetworkEnvironment` itself has no explicit integer wire representation in its enum definition. Separately, `TrustBundleEnvironment::metric_code()` uses `u64` 1 for TestNet, encoded little-endian in the transport digest; candidate `u8` 1 means DevNet only. Numeric equality is not correspondence or a demonstrated collision | Proposed only; unallocated |
| Application signing domain | ASCII `QBIND:BOOTSTRAP-APPROVAL:v1` (27 bytes: `51 42 49 4e 44 3a 42 4f 4f 54 53 54 52 41 50 2d 41 50 50 52 4f 56 41 4c 3a 76 31`) followed by literal `00` | Dedicated bootstrap-approval message domain; the NUL is a separator, not part of the text | Not a payload field; fixed bytes prefix the authenticated message | Candidate §2 exact message at lines 313–324; compare `crates/qbind-wire/src/pv_signing_domain.rs:91,273-291`, `crates/qbind-types/src/domain.rs:175-181`, and trust-bundle domain at `crates/qbind-node/src/pqc_trust_bundle.rs:102,1607-1642` | No exact executable-source match observed. Distinct from existing chain-scope, Proposal/Vote, trust-bundle, remote-signer, timeout, and persisted-authority domains | Proposed only; no domain registration |
| Envelope magic | ASCII `SIG1` = `53 49 47 31`, 4 bytes | Bootstrap signature-envelope framing | Unauthenticated selection/framing metadata; it is outside the signed input | Candidate §2 envelope at lines 326–339 | No exact `SIG1` envelope magic observed in inspected source; not interchangeable with record magic or another format's prefix | Proposed only; unallocated |
| Consensus configuration profile / field 18 | `u16_be(1)` = `00 01` | Bootstrap consensus-configuration-profile namespace; ordered genesis members, the existing supported suite, unit weights, founding epoch 0 | Authenticated field | Candidate §2 field 18; source shape at `crates/qbind-node/src/genesis_consensus_authority.rs:86,106,336-435` | Distinct field/namespace from suite identifiers; no existing bootstrap configuration-profile registry entry observed | Proposed only; unallocated |
| Permitted operation/scope / field 19 | `u16_be(1)` = `00 01` | Bootstrap permitted-operation/scope namespace; one initial instantiation of the exact approved DevNet configuration | Authenticated field | Candidate §2 field 19; candidate §3 independent root-selection rule | No same-namespace scope registry entry observed; other operation codes are not adopted by this candidate | Proposed only; unallocated |
| Founder verification profile / field 21 | `u16_be(1)` = `00 01` | Bootstrap founder-verification-profile namespace; exactly the unchanged BR-01 design accepted **DESIGN ONLY** | Authenticated field; meaning is accepted only through the independently trusted profile | Candidate §2 field 21; BR-01 decision above, lines 1270–1324 | Distinct from consensus suite ID 100 and from every other profile namespace reviewed; does not itself select a root | Proposed only; **UNALLOCATED — PENDING BR-02** |
| Envelope profile ID | `u16_be(1)` = `00 01`; same namespace/value as field 21 | Same founder-verification-profile namespace, not a second profile allocation | Envelope metadata is unauthenticated; verifier must require equality with authenticated field 21 and its independently selected trusted-root profile | Candidate §2 envelope and field 21, lines 326–362 | Reuse is intentional only for this exact profile-selection equality; the envelope cannot choose the trusted root | Proposed only; unallocated |

This identifier set does **not** allocate the existing consensus suite ID
`100`, any `SuiteRegistry` ID, runtime `ChainId`, wire `chain_id`, genesis
label/hash, validator ID, root or credential reference, or any environment
mapping. In the unchanged 21-field layout, field 13 remains the existing
`u16_be` consensus suite value `100`; field 18 is a different field and
namespace. `ConsensusSigSuiteId(pub u16)` and `SUPPORTED_TIMEOUT_SUITE_ID`
are defined at `crates/qbind-crypto/src/consensus_sig.rs:34` and
`crates/qbind-node/src/timeout_verification_bridge.rs:97`; the genesis
authority builder assigns that suite and `ValidatorId(i)` in genesis order
and constructs unit voting power at
`crates/qbind-node/src/genesis_consensus_authority.rs:336-416`. The separate
genesis `SuiteRegistry` stores `suite_id: u8` with values `0x01`, `0x02`,
`0x03`, and `0x10`, at `crates/qbind-types/src/state_suite.rs:7-43,52-104`.
Those integers are not automatically collisions, but neither Rust wrapper
types nor names alone establish safe separation: a future decoder must first
select this record format and exact positional field, then enforce that
field's namespace and supported value.

Likewise, candidate environment byte `01` is not an encoding of
`NetworkEnvironment`, the `ChainId(u64)` constants, the `NetworkWireAlias(u32)`
values, or `GenesisConfig.chain_id`. `NetworkEnvironment` has no explicit
integer representation in `crates/qbind-types/src/primitives.rs:105-146`;
runtime IDs are defined separately at lines 34–87. Separately,
`TrustBundleEnvironment` serializes as lowercase labels and its
`metric_code()` returns `u64` values 0=DevNet, 1=TestNet, 2=MainNet
(`crates/qbind-node/src/pqc_trust_bundle.rs:105-127`). The request-envelope
digest actually consumes that numeric encoding:
`field(b"environment", &self.environment.metric_code().to_le_bytes())`
at `crates/qbind-node/src/pqc_remote_signer_transport.rs:308`, inside the
existing domain-prefixed, labelled, length-framed digest input at lines
293–308. Its field builder prefixes each label and value with a `u64`
little-endian byte length. Thus existing value 1 means TestNet and occupies
eight little-endian bytes there, whereas the candidate's one-byte `u8` 1
means DevNet only in the bootstrap-record namespace. Neither direct copying
or casting nor numeric equality establishes environment correspondence.
Distinct domain/framing and explicit field interpretation are required;
this is not a demonstrated cross-protocol collision.

A dormant standard runtime-to-wire alias helper exists at
`crates/qbind-types/src/network_wire_alias.rs:21-29,66-79,110-128`.
`ExpectedGenesisIdentity::check_network_correspondence` checks a selected
environment against its retained validation policy and a supplied full-width
runtime ID against that helper, returning only a borrowed, explicitly
non-authorizing correspondence
(`crates/qbind-node/src/genesis_authority_record_correspondence.rs:229-277,
308-379`). This is static source correspondence, not a serialization for the
candidate environment byte or production activation. No mapping between these
record fields is proposed; BR-03 remains open. The separate
`GenesisAuthorityConfig` and `GenesisAuthorityRoot` are governance/transport
authority surfaces in `crates/qbind-ledger/src/genesis.rs:402-426,703-789`,
not this bootstrap record or its founder root. No mapping between these
values is proposed.

Other numeric values in the existing layout retain their current meanings
and are not allocations by this decision: field 5 runtime chain identity;
field 6 wire chain identity; field 7 genesis chain label; field 8 genesis
hash; field 9 member count; repeated field 10's existing index-derived
validator ID; field 11 address; field 12 signer reference; field 13 suite
ID 100; field 14 key bytes; field 15 weight 1; field 16 derived authority
commitment; field 17 epoch 0; and field 20 founder credential reference.
Lengths, counts, weights, opaque references, hashes, indices, and operational
identities are not added to the BR-02 allocation set.

### Bounded collision and compatibility review

The review compared executable source definitions and constructors, not
comments or historical test fixtures as if they were runtime registrations.
Relevant test and historical documentation matches were used only to locate
source or understand prior claims. “No collision observed” below is limited
to the inspected baseline and search scope; it is not proof of global
uniqueness, runtime isolation, deployed parser behavior, or cryptographic
conformance.

| Baseline source locator(s) | Inspected namespace / constructed preimage | Comparison result | Unresolved limitation |
|---|---|---|---|
| `crates/qbind-node/src/signing_reservation_journal.rs:51-60,93-100`; `crates/qbind-node/src/restore_completion.rs:58,244-282`; `crates/qbind-node/src/safety_record_store/owner/model.rs:923-941`; `crates/qbind-types/src/state_suite.rs:20-43` | Executable persistence magics and format versions, including `QSJ1`, `QSJM`, and model-only `R4B2`; RTR's exact definition is `const RTR_MAGIC: &[u8; 8] = b"QBNDRTR\x01";` at `restore_completion.rs:58`, eight bytes `51 42 4e 44 52 54 52 01`. Its final `0x01` belongs to the magic, distinct from the separately encoded `u32_be` RTR version field at lines 245,279; separate `SuiteRegistry` u8 identifiers | No exact candidate record magic `QBAP` or envelope magic `SIG1` observed. Existing magic/version pairs identify other formats; numeric version `1` is reused across those independent formats. Correcting the RTR transcription changes no identifier or collision verdict | The repositories contain many additional serializers and schemas. A source text search cannot prove every downstream, generated, private, or future parser has distinct dispatch |
| `crates/qbind-crypto/src/consensus_sig.rs:34-60`; `crates/qbind-crypto/src/suite_catalog.rs:39-58,103-155`; `crates/qbind-node/src/timeout_verification_bridge.rs:97`; `crates/qbind-types/src/state_suite.rs:7-43` | Consensus suite ID 100 is a `u16`; state SuiteRegistry IDs are `u8`; candidate configuration and founder profile IDs are `u16` at different fixed bootstrap fields | Candidate profile/scope value 1 does not replace suite 100 or any SuiteRegistry value. The intended distinct-field/namespace interpretation is explicit; raw equal integers alone do not prove safety | This candidate proposes no parser or typed runtime registry. Future implementation must reject a value found in the wrong field/namespace |
| `crates/qbind-types/src/domain.rs:49-72,175-181,187-211`; `crates/qbind-wire/src/consensus.rs:126,168-185,807,867-886`; `crates/qbind-wire/src/pv_signing_domain.rs:91-94,273-291`; `crates/qbind-consensus/src/timeout.rs:50`; `crates/qbind-ledger/src/execution.rs:163-190`; `crates/qbind-ledger/src/bundle_signing_ratification.rs:92-107,1238-1246,1450-1493` | Chain-specific transaction/batch/legacy Proposal/Vote/timeout tags; transaction preimage fields; v2 Proposal/Vote domain tag, version, family, runtime and wire IDs, genesis/authority hashes, `u64_be` body length, canonical body; governance ratification v1/v2 domains and canonical v2 preimage | No exact candidate application-domain literal observed. The complete candidate message starts with a distinct 27-byte ASCII domain and NUL, followed by a fixed-width `u32_be` payload length and exactly that payload; it is not the legacy helper's raw `domain_prefix || body` | Domain separation is a byte-level contract, not inferred from the text tag alone. No cryptographic cross-protocol proof or implementation conformance is claimed |
| `crates/qbind-node/src/pqc_trust_bundle.rs:102,1607-1642,1736-1765`; `crates/qbind-node/src/pqc_authority_state.rs:177-185,929-958`; `crates/qbind-node/src/remote_signer.rs:73,842`; `crates/qbind-node/src/pqc_remote_signer_transport.rs:88-105,297-398,950-967` | Trust-bundle signature prefix plus serialized JSON; separate fingerprint digest; persisted authority-state digest prefix; remote-signer and transport request/response/transcript domains | Inspected exact prefixes differ from the candidate literal and operate over different preimages/framing. None is substituted for the proposed bootstrap message | Repository-wide search does not cover external consumers or unindexed generated/dependency code; transport/version strings are not bootstrap registrations |
| `crates/qbind-types/src/primitives.rs:34-146`; `crates/qbind-types/src/network_wire_alias.rs:21-29,49,66-79,110-128`; `crates/qbind-node/src/pqc_boot_genesis.rs:69-80`; `crates/qbind-node/src/genesis_authority_record_correspondence.rs:229-277,308-379`; `crates/qbind-ledger/src/genesis.rs:402-426,703-789,1300-1357`; `crates/qbind-node/src/pqc_trust_bundle.rs:105-127`; `crates/qbind-node/src/pqc_remote_signer_transport.rs:293-308` | Runtime enum with no explicit integer wire representation; runtime `u64` ChainId; dormant wire `u32` aliases; non-authorizing static correspondence; lowercase trust-bundle environment labels and `metric_code()` values `u64` 0=DevNet, 1=TestNet, 2=MainNet, consumed as eight little-endian bytes in the request-envelope digest's existing domain-prefixed, labelled, length-framed input; genesis chain string and distinct authority config/root | Candidate `u8` 1 means DevNet only; existing numeric `u64` 1 means TestNet. Different meanings and widths prohibit inferring correspondence from direct copying/casting or numeric equality; distinct domain/framing and explicit field interpretation are required. This is not a demonstrated cross-protocol collision; no new mapping is proposed | BR-03's environment/runtime/wire/genesis binding remains unresolved; correspondence and alias code do not serialize the candidate byte or establish production activation/authority |
| `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:301-376`; `crates/qbind-node/src/genesis_consensus_authority.rs:86,106,336-435` | Exact payload/envelope framing, positional field boundaries, member repetition/order, existing suite/weight/epoch builder behavior | No domain-prefix/concatenation ambiguity was observed for the required message: the NUL is literal, the payload length is fixed `u32_be`, the payload is consumed at that exact length, and the signature envelope is outside the signed input | This is a proposed format, not a parser audit. Existing framing/bounds remain unchanged and do not approve operational resource limits |

The required signature message remains exactly:

```text
ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00 ||
u32_be(payload_length) || payload
```

BR-01 remains pure ML-DSA-44, exact raw 1312-byte public key, exact raw
2420-byte signature, empty algorithm context, and no application prehash.
The complete message above—not a digest—is the verification input. This
proposal does not substitute a digest-taking adapter, the existing chain-scope
domain helper, another domain, or another framing. The existing profile's
source-only errata, provenance, conformance, and signing-exhaustion limitations
remain as recorded under BR-01; this BR-02 proposal does not repeat or close
those reviews.

Search coverage was read-only across the repository Rust source tree and
relevant contract/status documents for candidate literals and source terms
including `MAGIC`, `FORMAT_VERSION`, `RECORD_VERSION`, `DOMAIN`,
`domain_prefix`, suite IDs/registries, genesis authority, environment, runtime
chain IDs, and wire chain IDs. Relevant transaction/consensus,
governance/trust-bundle, transport, genesis, and persisted-authority source
families were inspected, and constructed consensus identifiers were followed
to the genesis authority builder. Documentation, comments, and tests were
separated from executable definitions. The bounded review excludes proving
uniqueness in unavailable shallow-history objects, external or generated
consumers, runtime state not represented in source, and cryptographic
isolation/conformance. No material collision or incompatibility was observed
within this baseline and scope that prevents recommending the unchanged
candidate set for owner decision. If later evidence establishes one, BR-02
must remain blocked pending an explicit owner decision; this proposal does not
authorize silent renumbering, domain changes, layout redesign, or BR-01
amendment.

### Proposed compatibility and evolution rules

These are proposed rules, not implemented behavior:

* Interpret every value only within its explicitly named record, purpose,
  environment, operation/scope, consensus-configuration, or founder-profile
  namespace. Select the format first and parse only its exact field layout.
* Require the exact supported record magic, record version, purpose,
  environment, operation/scope, and profile values. Refuse unknown values and
  inconsistent combinations. No fallback, auto-detection retry, downgrade,
  normalization, or legacy reinterpretation is allowed.
* Values not listed in this candidate remain unsupported. Do not allocate
  TestNet/MainNet values or reserve broad ranges by implication.
* Preserve each allocated value's meaning. An incompatible change requires
  separate review, explicit version/profile decisions, and the applicable
  authority-transition policy; never reuse an identifier with changed
  semantics.
* The record or envelope cannot select its own trusted root or widen policy.
  Independently select the expected root/profile/purpose before examining
  untrusted record bytes. The envelope profile ID must match both the
  authenticated payload ID and independently selected trusted-root profile.
* Matching payload, envelope, and root profile IDs is necessary but does not
  establish authorization, freshness, unique first use, or custody.
* Identifier allocation alone causes no registry fetching, root replacement,
  authority transition, implementation, operational approval, or activation.

### Future owner acceptance matrix — NOT EXECUTED

| Future case | Proposed expected disposition | Status |
|---|---|---|
| Wrong or unknown record magic, version, purpose, environment, operation/scope, or profile value | Refuse; do not retry another format or value | NOT EXECUTED |
| Interpret candidate `1` in another namespace, including suite ID / SuiteRegistry confusion | Refuse inconsistent or unsupported field/namespace use | NOT EXECUTED |
| Envelope profile, authenticated field 21, or independently selected root profile differs | Refuse profile mismatch; envelope cannot select or replace the root | NOT EXECUTED |
| Altered NUL separator, payload length, field order/width, member repetition, or trailing/omitted bytes | Refuse non-exact framing; preserve the existing bounds | NOT EXECUTED |
| Substitute legacy chain-scope, Proposal/Vote, trust-bundle, or other domain framing | Refuse; only the exact BR-01 message is proposed | NOT EXECUTED |
| Reinterpret an unallocated value under a future profile/version without explicit review | Refuse unsupported value; require separate version/profile and authority-transition decision | NOT EXECUTED |

These are future cases only: no vectors, parser, test, refusal class, or
runtime behavior is introduced here. The terminology “refuse” preserves the
existing candidate contract; it does not claim implementation evidence.

### BR-02 owner decision card

**Required decision-maker role:** protocol/record contract owner.
**Accountable person:** unassigned; no explicit BR-02 assignment is evidenced.

The complete proposed set for decision is the allocation table above:
`QBAP`; record `u16_be` version 1; purpose `u16_be` 1; environment `u8` 1;
the exact `QBIND:BOOTSTRAP-APPROVAL:v1 || 00` domain; `SIG1`; consensus
configuration profile `u16_be` 1; permitted operation/scope `u16_be` 1;
founder profile `u16_be` 1; and envelope profile ID `u16_be` 1 in the same
founder-profile namespace, required to match the payload and independent
trusted root. The exact existing 21-field layout and compatibility rules
above are part of the same decision. Collision review found no material
collision in its inspected baseline/scope, with the bounded search and
runtime/external/cryptographic limitations stated above.

The owner may **ACCEPT** this exact set and rules, or **REJECT** them with the
candidate remaining unallocated. Acceptance must be recorded later as an
explicit BR-02 owner decision; it does not itself implement a registry or
authorize implementation, provisioning, signing, recovery, release, or
activation. Rejection leaves the candidate blocked and unallocated; no
automatic renumbering or redesign follows. Any replacement proposal requires
its own source-grounded collision review and explicit owner decision.

| Decision field | Status |
|---|---|
| Proposal preparation | **COMPLETE** — documentation-only source review supports submitting the unchanged candidate for decision |
| BR-02 owner disposition | **PENDING** |
| Identifier allocation | **NOT PERFORMED** |
| Decision date / signature / evidence | **NOT SUPPLIED** |
| Accountable BR-02 protocol/record contract owner | **UNASSIGNED** |
| Founder profile ID 1 | **UNALLOCATED — PENDING BR-02** |
| BR-01 owner design acceptance | **UNCHANGED — ACCEPTED, DESIGN ONLY** |
| Independent operational root/profile provisioning | **NOT DONE** |
| Implementation acceptance/authorization | **PENDING** |
| Whole native-admission and authority contracts | **DRAFT / NOT APPROVED / NOT IMPLEMENTED** |
| Isolated implementation prerequisites | **NOT SATISFIED** |
| Activation / public DevNet | **DISABLED / NO-GO** |
| D7D14, D7D10, recovery, anti-rollback, resource and whole-lifecycle statuses | **UNCHANGED** |
| Non-null `GenesisConfig.extra` | **REFUSED by the unchanged candidate; no hash-contract change proposed** |
| BR-03–BR-11 and B/C/L/X/U | **UNCHANGED** |

Preparing, reviewing, committing, or merging this proposal is not BR-02
acceptance. No founder override, history reset, operational credential,
runtime-to-wire mapping, recovery mechanism, new authority, source registry
entry, operational resource approval, or lifecycle authorization is created.
The existing isolated implementation-entry checklist remains unsatisfied and
in force.

## RUN 422 BR-02 owner acceptance and identifier allocations — 2026-11-03

**ACCEPTED — IDENTIFIER ALLOCATION AND COMPATIBILITY CONTRACT ONLY.**

### Explicit owner decision and evidence

| Decision field | Recorded decision |
|---|---|
| Public approver label | olive |
| Accountable role for this BR-02 decision | Protocol/record contract owner |
| Decision date | 2026-11-03, Asia/Calcutta; calendar date only, no timestamp supplied |
| Accepted definition | The complete corrected BR-02 proposal, its allocation table, exact 21-field layout, and complete compatibility/evolution rules at commit `81f016a0fbc4917235080662a2bd25541e606754`, tree `9f56f4af81f34798399b1a7511a2fcc02ec31c94` |
| Decision evidence | The explicit user statement quoted below, conveyed through this task instruction |
| Cryptographic signature | **NOT SUPPLIED OR GENERATED** |

> ACCEPT BR-02 — olive, protocol/record contract owner. I accept the exact reviewed identifier-allocation proposal and compatibility rules at commit 81f016a0fbc4917235080662a2bd25541e606754.

This records the supplied decision, not a new design choice. Acceptance
includes the proposal's recorded collision-review scope and limitations.
Bounded source observations do not become global uniqueness, executed
conformance, runtime isolation, deployed-parser evidence, cryptographic
assurance, or operational assurance. The closed collision and cryptographic
reviews are not repeated or promoted by this decision.

The public label and conversational statement establish no legal identity,
GitHub-account binding, operational credentials, custody, root provisioning,
or cryptographically authenticated decision.

### Accepted allocation record

These are the complete accepted allocations in the approved contract
namespaces, not executable registry entries.

| Item / layout slot | Exact allocation | Approved contract namespace / unchanged meaning |
|---|---|---|
| Record magic / field 1 | ASCII `QBAP` (`51 42 41 50`) | Bootstrap approval-record family |
| Record version / field 2 | `u16_be(1)` (`00 01`) | Bootstrap approval-record schema version |
| Authorization purpose / field 3 | `u16_be(1)` (`00 01`) | Bootstrap approval-purpose namespace; initial DevNet bootstrap only |
| Bootstrap environment / field 4 | `u8(1)` (`01`) | Bootstrap-record environment namespace; DevNet only |
| Application domain | `ASCII("QBIND:BOOTSTRAP-APPROVAL:v1")` followed by literal `0x00` | Dedicated bootstrap-approval message domain; unchanged 27 ASCII bytes plus the one-byte NUL separator |
| Envelope magic | ASCII `SIG1` (`53 49 47 31`) | Bootstrap signature-envelope framing |
| Consensus configuration profile / field 18 | `u16_be(1)` (`00 01`) | Bootstrap consensus-configuration-profile namespace; genesis-static, genesis-ordered members, existing supported suite, unit weights, founding epoch 0 |
| Permitted operation/scope / field 19 | `u16_be(1)` (`00 01`) | Bootstrap permitted-operation/scope namespace; one initial instantiation of the exact approved DevNet configuration |
| Founder verification profile / field 21 | `u16_be(1)` (`00 01`) | Bootstrap founder-verification-profile namespace; bound to the unchanged accepted BR-01 design |
| Envelope profile ID | `u16_be(1)` (`00 01`) | The same founder-profile namespace/value, not a second allocation; must match authenticated field 21 and the independently selected trusted-root profile |

Founder profile ID 1 is now **ALLOCATED** within that bootstrap
founder-verification-profile namespace. This is not an allocation in the
existing consensus suite catalog or the `u8` `SuiteRegistry`. Existing
consensus suite ID `100` in field 13 is unchanged; field 18 and field 21 are
separate namespaces. No executable registry entry, parser, or verifier is
implemented by recording this decision.

No additional values, future environment profiles, ranges, runtime or wire
identities, genesis labels/hashes, validator IDs, keys, credential references,
weights, counts, or epoch values are allocated by this acceptance.

### Exact layout, framing, and compatibility retained

The accepted layout is the existing candidate encoding at baseline lines
301–376, including the exact 21-field table at lines 342–362, as incorporated
by the corrected BR-02 proposal. That table is not rewritten: fields 1–9
occur once, fields 10–15 repeat exactly `member_count` times in genesis order,
and fields 16–21 occur once. All widths, unsigned big-endian integers,
field-7 byte-length/ASCII constraints, fixed byte arrays, member/index rules,
arithmetic and size bounds, validation/refusal rules, and the non-null
`GenesisConfig.extra` refusal remain unchanged. No operational resource
capacity is approved.

Complete record framing remains:

```text
u32_be(payload_length) || payload || signature_envelope
```

The complete signed message remains exactly:

```text
ASCII("QBIND:BOOTSTRAP-APPROVAL:v1") || 0x00 ||
u32_be(payload_length) || payload
```

The signature envelope remains exactly:

```text
ASCII("SIG1") || u16_be(envelope_profile_id) ||
u32_be(signature_length) || signature_bytes
```

The length prefix and complete canonical payload are authenticated; envelope
metadata and signature bytes are outside the signed input. No padding,
omitted fields, extensions, trailing bytes, alternative domain framing, or
digest substitution is accepted. BR-01 remains pure ML-DSA-44, exact raw
1312-byte public key, exact raw 2420-byte signature, complete raw-message
verification, empty algorithm context, and no application prehash.

The complete baseline compatibility/evolution rules are accepted unchanged:
select the exact format and positional field before interpreting its
namespace; require the supported values and combinations; refuse unknown or
unsupported values. No fallback, auto-detection retry, downgrade,
normalization, legacy reinterpretation, or automatic transition is allowed.
Allocated values must never be reinterpreted with changed semantics.
Incompatible changes require separate review, explicit version/profile
decisions, and applicable authority-transition policy. The record/envelope
cannot choose or replace its own root or widen policy; independently select
the expected root/profile/purpose, then require payload/envelope/root-profile
equality. Equality alone establishes no authorization, freshness, unique
first use, or custody. Allocation causes no registry fetching, root
replacement, authority transition, implementation, operational approval,
or activation. Future conformance cases remain **NOT EXECUTED**.

Environment encodings remain separate: this candidate's one-byte `u8`
DevNet value is `1`; `TrustBundleEnvironment::metric_code()` uses `u64`
0=DevNet, 1=TestNet, 2=MainNet, encoded little-endian in the transport digest's
existing domain-prefixed, labelled, length-framed input. Numeric equality,
copying, or casting proves no correspondence. No runtime/environment/wire
mapping is inferred or allocated, and BR-03 remains open.

### Narrow supersession and unchanged gates

Earlier BR-02 **PENDING**, **UNASSIGNED**, **NOT PERFORMED**, and
**UNALLOCATED** statements are superseded only for this accepted BR-02
decision, its accountable owner, and the exact allocation set above.
Earlier absent-decision-date/evidence statements are historical; no
cryptographic signature is supplied. All historical text remains evidence
of the earlier state, including in the D7 cross-references. This does not
globally replace statuses or alter BR-01's decision.

| Gate / obligation | Status after this decision |
|---|---|
| BR-01 | **ACCEPTED — DESIGN ONLY; UNCHANGED** |
| BR-02 | **ACCEPTED — IDENTIFIER ALLOCATION AND COMPATIBILITY CONTRACT ONLY**, including the exact layout |
| BR-03–BR-11 and B/C/L/X/U | **UNCHANGED** |
| Operational root/profile provisioning | **NOT DONE** |
| Implementation acceptance/authorization | **PENDING** |
| Whole native-admission and authority contracts | **DRAFT / NOT APPROVED / NOT IMPLEMENTED** |
| Isolated implementation prerequisites | **NOT SATISFIED** |
| Activation | **DISABLED** |
| Public DevNet | **NO-GO** |
| Non-null `GenesisConfig.extra` | **REFUSED** under the unchanged candidate |

All existing D7D14/D7D10, recovery, anti-rollback, resource, and whole-lifecycle
statuses remain unchanged, including
`D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`,
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`,
`D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`,
section 13.6 whole-lifecycle INCOMPLETE, durable anti-rollback
NOT-ESTABLISHED, C4/C5 OPEN, RS1 OPEN, and candidate resource limits
UNAPPROVED. Errata provenance, source-only limitations, and signing-exhaustion
follow-up concerns remain unchanged.

This acceptance supplies no implementation, signing, key-generation,
deployment, release, activation, history-reset, recovery, or
authority-transition authorization. It establishes neither operational root
trust nor currentness.

### Baseline and history provenance

Repository: `olivexo28/QBIND`. The clean starting worktree, local `main`,
remote-tracking `origin/main`, and advertised remote `main` matched commit
`81f016a0fbc4917235080662a2bd25541e606754` and tree
`9f56f4af81f34798399b1a7511a2fcc02ec31c94`. No applicable `AGENTS.md`
was present. The task branch created from that exact baseline is
`copilot/run-422-br02-owner-allocation-acceptance`; `main` is not modified.

The baseline commit's raw parent header names
`0c9982a86f1707d4f7bda2fb80bc1339ed3d8a9c`. That parent object is unavailable
in this shallow checkout: the header is recorded parentage, not locally
proven earlier ancestry. This decision commit is to be a direct child of the
verified baseline; no earlier ancestry is inferred from unavailable objects.

## RUN 422 BR-03 network-identity binding proposal — documentation only

**Mapping-policy proposal: PREPARED; BR-03 owner disposition: PENDING.**
This source-grounded proposal does not accept a mapping, provision an
operational identity, implement a verifier, authorize implementation, or
enable activation. It preserves BR-01 **ACCEPTED — DESIGN ONLY** and BR-02
**ACCEPTED — IDENTIFIER ALLOCATION AND COMPATIBILITY CONTRACT ONLY** without
changing either decision or any BR-02 allocation/layout.

Source baseline: commit `2ab43791edca4e6b1c98464950918b417e52c21c`, tree
`181736cbd66d376432e7f704b563b99ed8bf2250`; actual task branch:
`copilot/run-422-br03-network-identity-binding-proposal`. The raw commit
object names parent `81f016a0fbc4917235080662a2bd25541e606754`; this checkout
is shallow and that parent object is unavailable. The matching branch/main
and `origin/main` starting tips prove only the required baseline equality,
not older ancestry.

### 1. Proposed standard-DevNet tuple

Use the existing standard-network definitions as a proposed policy, not as
evidence of a production binding or operational approval. The proposal is
for this one standard environment only. Custom runtime IDs, alternate aliases,
and other environments are unsupported and must refuse; future support needs
a separate decision. The wire value is selected from its existing definition,
never derived from the runtime ID.

| Component | Representation | Candidate value / status | Authoritative source | Independent provisioning required | Proposed comparison | Refusal condition |
|---|---|---|---|---|---|---|
| Bootstrap environment, BR-02 field 4 | `u8` in the accepted bootstrap-record namespace | `1` = DevNet; allocation is already recorded by BR-02 | Accepted BR-02 field-4 allocation; this is not a Rust enum encoding | The trusted bootstrap policy must select DevNet before reading the untrusted record | Exact equality to independently selected `u8(1)` | Any other value or unsupported combination |
| Runtime environment | `NetworkEnvironment` enum | `NetworkEnvironment::Devnet` | `NodeConfig.environment`; standard enum definition | Trusted local/runtime selection, not the record | Exact enum equality; do not infer it from a string or the bootstrap byte | Any other environment for this policy |
| Genesis validation policy | Separate `NetworkEnvironmentPolicy` enum | `NetworkEnvironmentPolicy::Devnet` | `pqc_boot_genesis::map_environment(NetworkEnvironment::Devnet)` | Selected by trusted runtime environment | Exact equality to the policy used to validate and hash the same genesis | Policy differs from the selected environment or relabels a validated identity |
| Full runtime chain ID | `ChainId(u64)` | `QBIND_DEVNET_CHAIN_ID = 0x51424E4444455600` | `NetworkEnvironment::chain_id()` / existing DevNet constant | Approved mapping policy, established independently of the untrusted record and verifier domain | Full-width `ChainId` equality against `NetworkEnvironment::Devnet.chain_id()` | Any differing 64-bit value, including one with matching low 32 bits |
| Wire `chain_id` alias | `NetworkWireAlias(u32)` / wire-domain `u32` | `QBIND_DEVNET_WIRE_ALIAS = 0x44455600` | `resolve_network_wire_alias` standard mapping | Approved mapping policy independently bound to the identity and verifier domain | Exact equality to the resolver result after full runtime-ID equality | Wrong or unsupported wire value; never truncate, cast, parse text, take a substring, or copy a record/verifier value |
| Exact genesis chain label | Exact `GenesisConfig.chain_id` string bytes | **REQUIRED — NOT SUPPLIED** | Independently approved exact initial genesis/configuration; the label is not selected by this proposal | Yes: trusted expected label from the network-identity authority's approved provisioning | Byte-for-byte equality, with no case folding, normalization, alias, or substring substitute | Missing/untrusted expectation, mismatch, or any substitute comparison |
| Canonical genesis identity pin | `GenesisHash` (32 bytes), formatted externally as 64 hex digits when text is needed | **REQUIRED — NOT SUPPLIED** | Independently approved initial genesis identity, computed under the accepted canonical hash contract and DevNet policy | Yes: a trusted expected pin established independently of the record and candidate file | Validate/canonicalize the admitted structured genesis under DevNet, then compare the computed canonical identity to the independent pin | Missing/untrusted pin, canonical mismatch, wrong policy, unsupported input, or non-null `extra` under unchanged BR-11 |
| Raw genesis-file-byte digest | Digest over the exact serialized file bytes | Not a canonical identity component; not the pin in this proposal | `compute_genesis_hash_bytes` is a distinct raw-byte helper; no production `--expect-genesis-hash` or print path uses it | No: it must not be provisioned or substituted as the canonical pin | Never compare it in place of `GenesisHash` | Any substitution for the canonical identity refuses |
| Trust-bundle environment code | `TrustBundleEnvironment` plus `metric_code(): u64` | DevNet code `0`; TestNet `1`; MainNet `2` | `TrustBundleEnvironment::metric_code`; remote-signer digest encodes this as eight little-endian bytes | Not a bootstrap/network identity source | Keep its type, width, semantics, and transport framing separate | Numeric copying/casting or equality with bootstrap `u8(1)` is not correspondence and must not select DevNet |

`NetworkEnvironment` has no explicit integer wire representation in its enum
definition. Its `ChainId` is a separate `u64`; the wire alias is a separate
`u32`; `GenesisConfig.chain_id` is a string. The bootstrap byte `1` means
DevNet only in the accepted BR-02 namespace, whereas `TrustBundleEnvironment`
uses `u64` metric values with `1` meaning TestNet. These are separate
representations and domains, not interchangeable numbers.

The policy's runtime comparison must use the existing full-width mapping
semantics: `resolve_network_wire_alias(environment, supplied_runtime)` first
compares the supplied `ChainId` to `environment.chain_id()` and only then
returns the environment's fixed alias. There is no low-word equivalence,
truncation, cast, parsing, label inference, or inbound-field fallback.
BR-03's actual official label and pin remain required inputs, not values this
table chooses.

### 2. Executable source behavior and hash distinction

The following observations describe maintained code at the source baseline,
not comments, historical claims, test-only fixtures, or future requirements:

* `NodeConfig.environment` is a `NetworkEnvironment`; `NodeConfig::chain_id()`
  returns `environment.chain_id()`. `pqc_boot_genesis::map_environment`
  separately maps that enum to the ledger validation-policy enum.
  `verify_boot_time_genesis` applies substring-based chain-label checks only
  for TestNet and MainNet; it does not impose an environment-label check for
  DevNet. The Run 127 reset path compares the canonical hash and deliberately
  does not equate the human-readable genesis string to the numeric runtime
  `ChainId`. Neither path supplies the proposed independent, exact DevNet
  label comparator.
* `resolve_network_wire_alias` defines the standard DevNet/TestNet/MainNet
  runtime-to-wire assignments and checks full runtime equality. Its module
  calls the assignments dormant and states they are not integrated into
  production message construction, genesis authority, signing, verification,
  or activation. `NetworkWireAlias` itself is publicly constructible and is
  not proof that the resolver ran.
* `--expect-genesis-hash` is parsed into a `GenesisHash` and stored in
  `NodeConfig.expected_genesis_hash`. The normal external-genesis boot path
  loads structured `GenesisConfig`, calls `verify_boot_time_genesis` under
  the mapped environment policy, and compares the supplied expectation with
  `compute_canonical_genesis_hash(config, policy)`. For DevNet, that function
  currently allows a missing expected hash. If no external genesis is
  configured, the DevNet boot-verification path returns
  `SkippedNoExternalGenesis`; an embedded path is not a pinned external
  identity.
* The CLI also passes `--expect-genesis-hash` to the Run 127 authority-state
  reset path. That path requires a value, loads the external structured
  genesis, computes `compute_canonical_genesis_hash` under the mapped
  environment policy, and compares the result with the parsed expectation
  before continuing its separate reset checks. The genesis-authority loader
  likewise passes `NodeConfig.expected_genesis_hash` into
  `verify_boot_time_genesis` and compares its single reread snapshot's
  canonical identity against the boot-accepted canonical hash. These paths
  also do not consume a raw file-byte digest.
* `--print-genesis-hash` requires an external path, parses a structured
  `GenesisConfig`, computes and prints the canonical structured-genesis hash
  under the selected environment policy, and exits. This print helper does
  not run full boot-time authority validation and does not establish that the
  printed candidate is an official or trusted identity.
* `compute_genesis_hash_bytes` hashes raw file bytes. A source search at this
  baseline finds its callers in tests and the helper's own documentation,
  not in the production `--expect-genesis-hash`, normal boot, reset, or
  `--print-genesis-hash` path. It is not interchangeable with the canonical
  structured hash.
* **Source-comment discrepancy relevant to BR-03:** the comment immediately
  above `compute_canonical_genesis_hash` says the file-byte hash continues to
  back `--expect-genesis-hash`, while the executable CLI and boot path use the
  structured canonical hash. This proposal follows those executable paths;
  no source contract or behavior is changed here. The bounded consequence is
  that the stale comment must not be used to select or compare the BR-03 pin.
* **BR-11 source discrepancy:** the `GenesisConfig.extra` field comment above
  the canonical-hash function says `extra` is hashed, but the function body
  does not read `config.extra`, and no `extra` refusal was found in the
  inspected validation path. The unchanged bootstrap candidate requires
  `extra == Null` and refuses non-null values until the canonical hash
  contract covers them. This is a future contract requirement, not a claim
  that current generic DevNet boot code enforces it; no hash implementation
  change or relaxation is proposed.

The canonical hash function is SHA3-256 over its structured/domain-separated
encoding, including the selected environment scope and exact chain-label
bytes; it is not a raw JSON-file digest. Its current omission of `extra` and
the DevNet validator's permissive/no-pin behavior are not acceptable substitutes
for the proposed independent pin and BR-11 refusal. The actual genesis label
and canonical pin remain **REQUIRED — NOT SUPPLIED**. No fixture, embedded
genesis, repository example, zero, or conveniently computed value is selected
as the official identity.

### 3. Independent expected-identity boundary

The conceptual future expected identity is:

```text
ExpectedDevNetIdentity {
    bootstrap_environment: u8(1),
    runtime_environment: NetworkEnvironment::Devnet,
    validation_policy: NetworkEnvironmentPolicy::Devnet,
    runtime_chain_id: ChainId(QBIND_DEVNET_CHAIN_ID),
    wire_chain_id: QBIND_DEVNET_WIRE_ALIAS,
    exact_genesis_label: independently approved exact bytes,
    canonical_genesis_pin: independently approved GenesisHash,
}
```

This is a documentation model only: no wire format, registry, signed
manifest, runtime API, or implementation is introduced. Every mandatory
expected value, especially label and pin, must be established independently
of the untrusted approval being checked. A record cannot authenticate its own
network identity by supplying both a claimed value and its comparator.
Repository access, transport security, a filename, an operator-entered value,
or successful hash computation alone does not establish that a configuration
is the intended official genesis. Preserve the existing founder-root/purpose
provisioning model: trusted root and purpose selection remain independent of
the approval and of any key/reference carried inside it.

Future verification must, in order, require all mandatory independently
trusted inputs and the approved resource policy; check the selected
environment and full runtime ID against the accepted mapping; admit one
genesis snapshot under that environment's validation policy; validate and
canonicalize that snapshot; compare its canonical identity with the
independent pin; compare its exact label with the trusted expected label;
derive membership, keys, weights, and authority commitment from that same
validated snapshot; then compare the bootstrap record's corresponding fields
against those independently established expectations. Missing/untrusted
inputs, unsupported combinations, mismatch, or unavailable resource policy
must refuse without authorizing effects.

One owned, admitted snapshot is necessary to avoid combining a label/hash
from one read with membership, keys, weights, or authority commitment from
another read. Existing `ExpectedGenesisIdentity::load_pinned` reads once and
derives its current expected genesis-authority fields from that snapshot, but
its input loader is not thereby an approved bounded parser. The existing
`load_external_genesis` uses `std::fs::read` followed by JSON parsing; the
canonical hashing and broader validation paths have not been accepted as a
bounded record-plus-genesis parser/resource contract. BR-08's independent
resource-admission requirements and unapproved limits remain in force. Do
not infer safe allocation or work bounds from the available API.

The non-null `GenesisConfig.extra` refusal and BR-11 remain unchanged.
Historical/current matching identity is also insufficient for B/C/L/X/U:
mapping and genesis identity do not prove freshness, signing-history
continuity, lock recovery, cross-host exclusivity, or unique authorized first
use. No actual genesis, key, credential reference, operator, device, ceremony,
or provisioning package is created here.

### 4. Existing helpers versus missing production binding

What exists:

* `resolve_network_wire_alias` defines a dormant standard mapping and checks
  full runtime-ID equality. It is not production integrated.
* `ExpectedGenesisIdentity::load_pinned` requires a caller-supplied canonical
  pin, validates one loaded snapshot against it, and derives an immutable
  genesis-authority identity from that same snapshot. The caller's trust
  provenance for the pin is not authenticated by this helper.
* `ExpectedGenesisIdentity::check_network_correspondence` compares the
  retained validation policy against the selected environment's mapped policy
  and invokes the full-width runtime-to-alias resolver. It returns a borrowed,
  **non-authorizing** correspondence attached to the same identity. It does
  not compare the label against a separately provisioned expected label, prove
  the official pin was correctly provisioned, establish current authority,
  or grant activation.
* `GenesisConsensusAuthority` production construction sets
  `authorized_wire_chain_id: None`. The `Some` setter path is in a
  `#[cfg(test)]` verification-snapshot fixture constructor; test fixtures
  are not production support. Production `AuthorizedProposalVoteSnapshot`
  binding compares the owner's independently retained wire ID to the verifier
  domain and refuses when it has none (`WireChainIdMismatch`).
* `main` retains a startup guard: an explicit
  `--consensus-authority-from-genesis` request exits nonzero before P2P
  service construction or consensus tasks. The later per-mode genesis
  authority route is unreachable in ordinary production startup. This
  containment and activation refusal remain in force.

Therefore static correspondence does not create current authority, an
authorization ticket, an activated verifier, or a signing capability. No
helper is wired into production and no constructor is exposed or reinterpreted
here. Any separately authorized future integration must keep the independently
established mapping attached to the same pinned identity and exact verifier
domain. An inbound verifier must never supply its own expected wire ID.
Different genesis identities may share the same standard environment/runtime/
wire constants; those constants alone identify neither one unique network
instance nor a one-time activation. Preserve the full genesis/configuration
binding and U's separate obligations.

### 5. Future acceptance matrix — NOT EXECUTED

These are proposed contract cases only. They are not tests or vectors, and no
new refusal class is implied. Where an existing typed outcome applies, it is
named; otherwise the future contract must refuse without inventing an
implemented class here.

| Case | Expected result |
|---|---|
| Independently provisioned complete DevNet tuple, exact label/pin, and one admitted matching genesis | Correspondence may be established only; bootstrap record comparisons still require their independent checks. No activation follows from this case alone. |
| Expected label or canonical pin missing or untrusted | Refuse future verification. Current generic DevNet boot may accept a missing hash; it is not this proposed path. |
| Expected values copied from the record being checked | Refuse: no independent comparator exists; record self-assertion is not trust. |
| Wrong environment, or identity validated under one policy relabelled under another | Refuse; the existing correspondence helper reports `ValidationPolicyMismatch` for policy relabelling. |
| Wrong full runtime ID with the same low 32 bits | Refuse full-width mapping; existing resolver returns `NetworkWireAliasMismatch` (wrapped as `RuntimeMismatch` in correspondence). |
| Wrong wire ID while runtime/genesis/authority otherwise match | Refuse exact domain binding; existing production authority remains `None`, and `try_bind` refuses with `WireChainIdMismatch`. |
| Same environment/runtime/wire values but a different canonical genesis identity | Refuse against the independent pin; matching network constants do not identify a unique genesis instance. |
| Exact-label mismatch, including case-only or substring-only agreement | Refuse byte-exact label comparison; no normalization or substring rule. No existing label-specific refusal class is claimed. |
| Raw-file-byte digest substituted for canonical identity | Refuse as the wrong representation; compare only the canonical structured-genesis identity. |
| Mixed or changed genesis snapshots across label/hash/membership/key/weight derivation | Refuse; identity and derived authority must use the same admitted snapshot. Existing activation loader has `IdentityChangedSinceBoot` for its boot/reread canonical-identity mismatch, but does not implement this complete future pipeline. |
| Generic DevNet validation succeeds without a pin | Future identity verification still refuses missing required pin; current `verify_boot_time_genesis(Devnet, ..., None)` permits this generic case. |
| Non-null `extra` or unavailable resource policy | Refuse under unchanged BR-11; refuse if mandatory trusted BR-08 policy is unavailable. These are not claimed as current generic boot refusals. |
| Historical matching identity, but B or U unavailable | No activation or signing authorization; preserve unavailable currentness/unique-first-use refusal. |
| Attempt to turn static correspondence into production authorization | No conversion exists; outcome remains non-authorizing. Production `None` cannot bind an activated verifier. |

### 6. BR-03 owner decision card and explicit gaps

| Decision field | Proposed record |
|---|---|
| Required decision-maker role | Network identity authority |
| Accountable person | **UNASSIGNED**; no BR-03 assignment is evidenced. Do not infer this role from olive's BR-01 or BR-02 decisions. |
| Mapping-policy proposal | **PREPARED**: standard DevNet `u8(1)`, `NetworkEnvironment::Devnet`, `NetworkEnvironmentPolicy::Devnet`, full `QBIND_DEVNET_CHAIN_ID`, and `QBIND_DEVNET_WIRE_ALIAS`, with exact independent label/pin still mandatory |
| Owner disposition | **PENDING**; this proposal is neither acceptance nor rejection |
| Exact operational genesis label, canonical pin, and approved configuration | **NOT SUPPLIED** |
| Independent provisioning | **NOT DONE** |
| Production mapping implementation/integration | **NOT IMPLEMENTED** |
| Executed and release-binary correspondence evidence | **NOT PRODUCED by this task** |
| Overall BR-03 closure | **NOT ESTABLISHED** |

| Missing fact / accountable role | Required later evidence | Affected operation |
|---|---|---|
| Named BR-03 network identity authority and explicit accept/reject disposition; person remains unassigned | Explicit decision against this exact proposed standard tuple, or a separately reviewed replacement/refusal policy; role assignment must be evidenced | Approval of mapping policy; no value may be treated as approved before this decision |
| Official exact genesis label, canonical pin, and exact approved initial configuration; network identity authority with founder-root provisioning roles | Independently authenticated provisioning/readback evidence tying exact label and canonical pin to the approved structured genesis; no value inferred from the record or example | Genesis/configuration verification and any later bootstrap approval |
| Independent provenance/currentness and consistent distribution of expected identity; founder-root/purpose and B/U owners remain unassigned | Evidence under the existing custody/recovery model, including conflict handling and B/U; identity pin alone is historical identity, not currentness | Trust-root verification, first activation, recovery and all dependent signing |
| Production binding of expected mapping to the same identity and verifier domain; implementation owner unassigned | Separately authorized implementation; source/unit and independent-process evidence, followed by release-binary correspondence evidence; production value must not come from inbound verifier | Configuration verification, activation and signing |
| Approved resource-admission and bounded parsing/canonicalization policy (BR-08); parser/resource policy owner unassigned | Explicit trusted limits and checked admission evidence for record bytes, genesis input, allocation/work/scratch, and the actual parser/hash path | Safe admission and verification; absent policy must refuse |
| Complete lifecycle proof B/C/L/X/U and existing recovery/anti-rollback contracts; relevant state owners remain unassigned as recorded | Independent, operation-specific evidence and enforcement; historical identity or mapping agreement is insufficient | First use, activation, signing, recovery and continued operation |
| Executed correspondence and release-binary evidence | Later authorized acceptance cases and release-binary evidence against the approved exact configuration; not produced or run here | Any claim that production correspondence is implemented or operational |

Policy acceptance alone would not satisfy the missing operational identity,
independent provisioning, production integration, release evidence, or
lifecycle requirements, and would not close BR-03.

### 7. Preserved decisions and gates

BR-01 remains **ACCEPTED — DESIGN ONLY**. BR-02 remains **ACCEPTED —
IDENTIFIER ALLOCATION AND COMPATIBILITY CONTRACT ONLY**, including its exact
layout and allocations. BR-03 remains **PENDING**; BR-04–BR-11 and B/C/L/X/U
are unchanged. Whole native-admission and authority contracts remain
**DRAFT / NOT APPROVED / NOT IMPLEMENTED**; implementation authorization is
**PENDING**; prerequisites are **NOT SATISFIED**; activation is **DISABLED**;
public DevNet is **NO-GO**.

All D7D14/D7D10, recovery, anti-rollback, resource, whole-lifecycle,
cryptographic-review limitation, and non-null `GenesisConfig.extra`/BR-11
statuses remain unchanged. No closed review is repeated or promoted. No tests,
builds, scanners, key generation, signing, operational commands, activation,
deployment, actual identity provisioning, or source/dependency/configuration
changes are performed by this documentation-only proposal.

### 8. Source baseline and exact locators

All source references below are from commit
`2ab43791edca4e6b1c98464950918b417e52c21c`; executable behavior controls where
a comment differs. The existing source supports the standard-DevNet proposal
but does not establish its production integration or official operational
identity.

| Source locator | Relevant behavior / boundary |
|---|---|
| `crates/qbind-types/src/primitives.rs:34-64,105-146` | `ChainId(u64)`, `QBIND_DEVNET_CHAIN_ID`, `NetworkEnvironment`, and `chain_id()`; no explicit environment integer encoding |
| `crates/qbind-types/src/network_wire_alias.rs:1-18,38-44,49-71,108-131` | Dormant standard aliases, publicly constructible raw `u32` alias, full runtime equality in `resolve_network_wire_alias`, and explicit non-production scope |
| `crates/qbind-node/src/node_config.rs:3985,5301-5303,6829-6841` | Expected hash type, runtime environment-to-chain selection, and environment parser/default |
| `crates/qbind-node/src/pqc_boot_genesis.rs:69-80,188-248,256-278` | Runtime-to-policy mapping; external genesis read and boot verification; optional DevNet expectation; canonical print computation without full authority validation |
| `crates/qbind-node/src/cli.rs:1530-1577,2366-2384` | Canonical hash CLI documentation and actual parsing of `--expect-genesis-hash` to `GenesisHash` |
| `crates/qbind-node/src/main.rs:2216-2234,2262-2328,2380-2417,5405-5422,5799-5859` | Reset input consumer, actual print path, normal boot path, DevNet skip/pin retention, production activation guard, and later disabled authority loader call |
| `crates/qbind-ledger/src/genesis.rs:726-746,1300-1357,1532-1541,1569-1630,1797-1854,1984-2005,2053` | Separate validation policy, exact label/`extra` fields, canonical structured hash body, DevNet no-pin behavior, distinct raw-byte hash function, and pin parser |
| `crates/qbind-node/src/pqc_authority_state_reset.rs:562-620` | Run 127 requires an expected hash and compares it with the canonical structured-genesis hash under the mapped policy |
| `crates/qbind-node/src/pqc_trust_bundle.rs:105-150`; `crates/qbind-node/src/pqc_remote_signer_transport.rs:293-308` | Separate `TrustBundleEnvironment` encoding and little-endian `u64` transport-digest framing |
| `crates/qbind-node/src/genesis_authority_record_correspondence.rs:88-181,218-282,292-399,408-426` | Independent-pin helper, same-snapshot derivation, retained validation-policy comparison, full runtime resolver, borrowed non-authorizing correspondence |
| `crates/qbind-node/src/genesis_consensus_authority.rs:132-190,338-439,769-770,1349-1375,1404-1437` | Production authority's `None`, builder provenance, accessor, test-only `Some` fixture constructor, and shared loader behavior |
| `crates/qbind-node/src/binary_consensus_loop.rs:1270-1314` | `try_bind` checks the independently retained owner's wire ID against the verifier domain and rejects `None`/mismatch |
| `docs/devnet/QBIND_RUN_422_BOOTSTRAP_CREDENTIAL_RECOVERY_TRUST_MODEL.md:1-3,57-68,410-468` | Existing founder-root/purpose and B/C/L/X/U trust model and unchanged implementation-entry checklist |
| `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md:301-376,510-615,664-674,1601-1729` | Accepted BR-02 layout/allocations, existing resource and BR-11 refusal requirements, decision register, and narrowly scoped accepted BR-01/BR-02 decisions |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md:26615-26651` | BR-02 acceptance record and preserved D7D14/D7D10, recovery, anti-rollback, resource, lifecycle, activation, and NO-GO status |

This append changes no executable contract. BR-03 owner disposition remains
**PENDING**, and no operational network identity or implementation
authorization is established.
