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
