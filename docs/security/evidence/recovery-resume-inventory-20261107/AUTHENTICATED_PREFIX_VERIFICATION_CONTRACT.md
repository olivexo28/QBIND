# Authenticated-prefix verification contract

**AUTHENTICATED-PREFIX CONTRACT — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
SOURCE_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
DESIGN=PROPOSED; NO FORMAT OR CRYPTOGRAPHIC CONSTRUCTION SELECTED
PREFIX_VERIFICATION=NOT IMPLEMENTED
SIGNING_OR_RESUME_AUTHORITY=NOT GRANTED
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

This documentation-only contract proposes the evidence and ordering a future
reviewed verifier would have to establish before an authenticated prefix could
be considered for application. It does not specify a wire or persistence
encoding, approve a cryptographic construction, create a recovery procedure,
or grant authority to clear quarantine or resume participation. Production
source references are pinned to the protected main commit above; historical
test evidence remains tied to its own recorded producer revisions.

The user supplied **PASS WITH LIMITATIONS** for the three preceding inventory
corrections (restore-open ordering, effect-aware refusal language, and the plan
cross-reference). Those corrections are **PASSED / CLOSED within their
documented scope**. This does not close A17-F1 / RS1-F7, RS1, or A33-F1 / E27,
and does not approve authenticated recovery. No reviewer identity or raw
review artifact is asserted.

## 1. Evidence contract: anchor through finality

Every item below is a prerequisite, not a claim that production currently
supplies it. The verifier must use trusted context selected independently of
the responder and the recovered/copyable state. Missing, stale, ambiguous, or
unsupported evidence refuses the candidate before protected prefix
application.

| Fact | What current code can do | Missing / trust assumption | Required refusal |
|---|---|---|---|
| **Trusted starting anchor** | Snapshot restore supplies `height` and `block_hash` to a fresh engine as an opaque baseline; it does not supply or reconstruct a signed finality witness. [`baseline handoff`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L2880-L2904), [`engine initialization`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L2835-L2860) | A checkpoint/genesis anchor must be accepted by an independent trust procedure outside the restored directory and bind block ID, height, epoch, validator authority and a finalized-prefix commitment. A snapshot hash, local marker, peer claim, or matching height is not that trust root. | Refuse if no independently accepted anchor or if the first recovered parent does not match it exactly. |
| **Chain and genesis identity** | `ProposalVoteSigningDomainV2` can bind trusted runtime chain ID, expected wire chain ID, genesis identity and authority commitment. QC verification checks the wire chain ID against the supplied domain. [`domain fields and validation`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L185-L255), [`QC chain gate`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L959-L1000) | The actual verifier's domain and runtime-to-wire mapping must come from the intended network's trusted configuration. The domain type itself cannot establish that its constructor inputs are authentic/current; production has no activated runtime-to-wire mapping for genesis authority. [`genesis authority boundary`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L86-L106), [`no authorized wire ID`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L425-L439) | Refuse wrong or absent runtime/wire chain, genesis identity, authority commitment, or conflicting proof domain. Do not retry under another domain. |
| **Epoch and validator authority** | The QC verifier checks the QC epoch against a caller-supplied authorized epoch and uses a caller-supplied validator set, key provider and backend. Genesis authority construction has a fixed epoch-0 guard and rejects unsupported epoch changes. [`QC epoch gate`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L959-L1000), [`genesis authority epoch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L86-L106), [`configuration refusal`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L800-L838) | Those inputs must be derived from an independently trusted, epoch-specific authority. Genesis construction is a candidate source, not a production-enabled Proposal/Vote authority; it currently exposes no authorized wire-chain ID and its static set does not authorize later epochs. | Refuse unknown epoch, missing authority/key/suite/weight, inconsistent authority commitment, or any transition for which verified old-to-new authority evidence is absent. Never carry a set forward by assumption. |
| **Block identity and prefix continuity** | The library importer checks selected structural relations (anchor, heights, parents, view/leader and derived ID) but consumes logical signer indices, lacks block payload, and mutates sequentially. Its derived block ID is not a full payload commitment. [`catch-up importer`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3954-L4048), [`response schema`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p.rs#L181-L220), [`block ID derivation`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L1922-L1937) | A future verifier must authenticate each required block/content commitment and check a strictly ordered, gap-free, non-duplicated parent chain from the trusted anchor to the claimed tip. Canonicalization and execution/application semantics must be reviewed separately. | Refuse duplicate, gap, reordered, wrong-parent, wrong-ID, missing-content, overflow, or conflicting-prefix input before application. |
| **Consensus finality** | The consensus state engine has a Classic HotStuff three-chain commit rule requiring QCs on B, P and G plus strictly increasing views; the domain-aware QC verifier can authenticate one QC under supplied trusted context. These are separate capabilities: a verified individual QC is not by itself a finalized prefix, and the catch-up importer does not invoke the verifier. [`three-chain commit rule`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1825-L1900), [`QC verification API`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L916) | The proof must establish the exact reviewed protocol finality relation, including each certified block's placement in the ordered chain and the required consecutive-QC/view relation. The fault threshold and applicable authority must match the intended deployment. No responder height or isolated quorum-shaped index list proves finality. | Refuse absent, incomplete, misordered, wrong-block, or wrong-epoch finality evidence; do not promote a peer-selected tip. |

The trust anchor and verifier inputs are external design obligations, not
outputs inferred from the bytes being checked. No current source establishes
that a signed checkpoint is latest or that a copied local state has not rolled
back.

## 2. Endorsement and signing-domain contract

### Proposal versus Vote/QC evidence

A Proposal signature authenticates a proposal message under its proposer; it
is not a quorum certificate or a finality proof. The message-bound Proposal
verifier checks the trusted expected wire chain, authenticated claimed sender
against `header.proposer_index`, validator membership, governed key and suite,
and a signature over the recomputed v2 domain preimage. [`Proposal verifier`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L405-L443)

A QC contains a signer bitmap and a correspondingly ordered list of Vote
signature bytes. The domain-aware verifier reconstructs each Vote from the
QC's chain, epoch, height, round, step, block ID and suite, derives signer
identity from bitmap bits, maps signatures to set bits in ascending order,
and verifies every declared signature. It then accumulates the authority
set's voting power once per authenticated signer and requires at least
`ceil(2W/3)`. A later invalid extra signature still rejects even if an earlier
subset reached threshold. [`QC structure and verifier contract`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L912), [`preflight, signature checks and quorum`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L959-L1123)

The verifier is useful prior art, not an already-wired recovery verifier. It
only authenticates a QC against the *supplied* context; it does not prove that
the supplied context is currently authoritative, prove prefix continuity,
validate a chain of finality, or authorize application/resume. A returned
`VerifiedQuorumCertificate` retains the certificate, verified signer
identities, voting power/threshold and the chain/epoch/domain context, but
inherits those caller trust assumptions. [`verified evidence type`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L521-L568)

### Required authentication for every endorsement

Before any endorsement can count toward a recovered prefix, a future verifier
must establish all of the following from the message bytes and independently
trusted context:

1. **Identity and uniqueness:** bind each endorsement's claimed signer to its
   message signer/index and exactly one member in the authorized epoch set.
   Reject duplicate/ambiguous validator identities, duplicate bitmap
   membership, unknown members and key aliases. A transport-authenticated
   sender identifies only the transmitting peer; it is not evidence that
   other validators signed.
2. **Key and suite authority:** retrieve the public key and allowed signature
   suite from the selected authority snapshot; require the message/QC suite to
   match exactly and the backend to be explicitly allowed. No suite/key retry.
3. **Message and domain binding:** recompute the signature preimage from the
   actual Proposal/Vote and the trusted `ProposalVoteSigningDomainV2`.
   The v2 domain separates Proposal from Vote and binds runtime chain ID,
   expected wire chain ID, genesis identity and authority commitment; the
   canonical body binds the message-specific consensus fields. [`v2 preimage`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L185-L294), [`Vote fields`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L47-L105)
4. **Cryptographic validity:** verify each signature with the governed member key and allowed suite. Do not accept a signer-index vector, bitmap, claimed quorum count, responder signature, or unverified aggregate assertion as a substitute for individual endorsements or a separately reviewed equivalent proof.
5. **Voting weight and QC semantics:** compute total weight from the authenticated epoch set, count each verified member once with checked arithmetic, and apply the reviewed QC threshold and certificate-to-block/epoch relation. Do not infer quorum from member count if weights differ.
6. **Consensus proof:** after individual QCs verify, establish the required chain/finality relation across them. Proposal authentication, Vote authentication, QC quorum, prefix continuity and finality are distinct checks.

The existing per-message verification core follows sender binding, membership,
signature presence, key lookup, suite match, allowed-backend dispatch, then
cryptographic verification; this is a message verifier, not an authority
discovery or prefix verifier. [`verification core`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L230-L357)

## 3. Epoch scope and transition boundary

**Recommended first review slice: a single fixed epoch only.** A candidate
test/library verifier should accept one independently selected chain/genesis
domain, one authority commitment, one epoch-specific validator/key/weight
snapshot, and one trusted start anchor. Every recovered block and QC in that
candidate must use that exact epoch and authority. The genesis-static authority
candidate is limited to epoch 0 and deliberately supplies no production
wire-chain mapping; it is not a ready production verification context.
[`static epoch and no transition`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L86-L106), [`unmapped wire chain`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L425-L439)

This scope is intentionally bounded; it does not silently assume that a
genesis set remains valid indefinitely. If an input crosses an epoch boundary,
names another set/domain, or leaves the active authority ambiguous, the first
slice refuses the *whole candidate prefix* before application. No truncation
to a convenient pre-transition prefix may be described as verification of
the requested tip.

A separately reviewed cross-epoch verifier would need, for every transition:

* an old-epoch-finalized transition statement with the exact effective
  boundary and identity of the next authority;
* an independently validated new validator/key/suite/weight snapshot and
  authority commitment, bound to the transition and subsequent evidence;
* explicit rules for old/new-set overlap, transition finality, activation
  timing, key rotation/revocation, and which epoch authenticates boundary
  blocks; and
* continuity proving that no block, epoch or authority transition was skipped.

Those rules and authorities are not currently selected or established.
Unrecognized, conflicting, missing or unsupported transition evidence is a
hard refusal; do not verify a later QC using whichever set the responder
supplies.

## 4. Verification, resource admission, and effects

The future caller must finish bounded admission and verification before the
first protected recovered-prefix effect. “Before effect” does not mean before
all startup/setup effects: the corrected inventory records that requested
restore currently opens consensus storage before checking the RTR, and that
`create_if_missing(true)` can permit storage creation. This contract does not
claim that a particular open created or wrote anything. [`restore-order correction`](README.md#7-review-corrections-and-superseding-clarifications)

Required order, without selecting a wire format:

1. **Before frame allocation/read:** enforce a configured hard cap on encoded
   frame bytes and concurrent in-flight restore inputs at the transport
   boundary. The current generic decoder accepts a `u32` frame length and
   constructs a full message before the handler; the exporter’s 128-block
   cap is outbound only. [`decoder and handler boundary`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L172-L201), [`outbound-only cap`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L248-L250)
2. **During bounded deserialization:** cap block count, per-block and total
   payload bytes, nesting depth, per-certificate bitmap/signature count,
   per-signature bytes, aggregate signature/proof bytes, and decoded working
   set. Reject lengths/counts before nested `Vec` allocation; checked arithmetic
   must precede reserve/allocate. A post-handler check cannot undo pre-handler
   allocation.
3. **Before cryptography:** validate chain/epoch/domain/anchor and the entire
   structural prefix; enforce aggregate signature/proof and per-request crypto
   work budgets; reserve bounded scratch/retained-evidence capacity before
   cloning or retaining. The existing QC verifier's bitmap, signature-count,
   individual-signature and aggregate-signature checks are preflight *inside
   that verifier*, but do not cap the generic frame's earlier decode or replace
   an overall restore budget. [`QC bounds and preflight`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L158-L193), [`QC preflight before crypto`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L996-L1066)
4. **Before application:** authenticate all endorsements, continuity and
   finality for the complete requested prefix in bounded staged state. Refuse
   on any error without invoking protected prefix publication/application,
   changing the engine, or invoking a signer. The actual current response
   dispatch already refuses bound non-empty responses and ignores bound empty
   responses before peer-height/mode effects; the proposed verifier is not
   wired there. [`current dispatch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7390-L7442)
5. **Application and acknowledgement:** only after independent verification
   may a separately reviewed application protocol begin. Its durable intent,
   publication and cross-store atomicity/reconciliation rules remain open.
   Record acknowledged effects as known; a later refusal does not undo them.
   Distinguish a known pre-effect failure from a partial effect and an
   ambiguous write/rename/barrier outcome. After any application attempt,
   remain closed pending authoritative reconciliation; do not claim rollback
   or unchanged state. [`effect-aware correction`](README.md#7-review-corrections-and-superseding-clarifications)

Resource values remain an open review decision. Existing verifier constants
are not automatically acceptable whole-message limits, and the `u32` framing
or outbound 128-block setting must not be presented as complete inbound
budgets. Oversize, overflow, reserve failure, crypto-budget exhaustion or
missing limits refuse before the relevant effect boundary.

## 5. Verification is not freshness, ownership, or resume authority

Successful verification of an authenticated prefix establishes, at most, that
the supplied evidence is internally valid under the selected trust inputs and
protocol rules. It does **not** establish:

* that the checkpoint/authority is globally current, latest, or not superseded;
* rollback resistance for a copied or restored directory, local revision,
  checksum, database or journal;
* durable destination ownership, cross-host lease or fencing;
* signing-history continuity, including uncertain or reserved signer outcomes;
* exclusive ownership of the signing key or invalidation of late/stale workers;
* permission to clear quarantine, resume signing, vote, propose, or otherwise
  participate.

Each remains a separate obligation requiring an independently authorized
source and decision. A valid certificate, completed prefix application, mode
flip, local ownership lock, successful database write, transport identity, or
matching height alone grants none of them. Until separately established, remain
closed to signing and participation.

## 6. Bounded options and acceptance cases

| Option | Safety posture and availability cost | Limitation |
|---|---|---|
| **Current fail-closed behavior** | Actual dispatch refuses every bound non-empty response and ignores admitted empty responses before peer-height/mode effects. This prevents unauthenticated catch-up through that path. | No recovery liveness: restore mode may persist indefinitely; selected proposal deferral and local timeout suppression remain, and it is not a complete engine/worker/signer fence. |
| **Proposed single-epoch verification slice** | Could permit a candidate prefix to be considered only after one fixed trusted domain/set, individual Vote authentication, continuity and finality verify; pre-effect refusal stays closed. It deliberately refuses any epoch/set transition. | It does not supply currentness, transactional/durable application, signing continuity/fencing, or separate resume authority. Production cannot use it until trusted authority and wire mapping exist. It improves only within-slice availability; cross-epoch inputs remain unavailable. |

The following are acceptance work, not completed tests. Every row is
**FUTURE / NOT EXECUTED**. Test-only controls must call the same verifier and,
once wired, the actual inbound caller. Negative/sensitivity controls must
demonstrate that intentionally omitted pre-effect checks are detected, without
shipping defective behavior in production.

| Case | Required assertion | Status |
|---|---|---|
| Valid single-epoch prefix | Correct anchor, chain/domain, epoch authority, unique signed endorsements, quorum, continuous blocks and complete finality are accepted into a non-mutating verified result; no resume authority is produced. | **FUTURE / NOT EXECUTED** |
| Evidence tampering | Alter one signature byte, signed message field, block/content commitment, parent, or certificate/QC field; reject the whole candidate before protected effects. | **FUTURE / NOT EXECUTED** |
| Wrong chain/genesis/domain | Independently vary runtime chain, wire chain, genesis identity, authority commitment, signing family, or signing domain; refuse with no fallback/retry. | **FUTURE / NOT EXECUTED** |
| Wrong epoch / authority | Change QC epoch, validator set, key, suite, weight, or authority commitment; refuse before protected application. | **FUTURE / NOT EXECUTED** |
| Duplicate / unauthorized signer | Duplicate signer identity/bitmap membership, ambiguous key, unknown validator, or nonmember key; reject even if claimed indices or transport peer suggest quorum. | **FUTURE / NOT EXECUTED** |
| Insufficient or malformed quorum | Below-threshold weight, invalid signature, missing/extra signature, bitmap-popcount mismatch, or invalid extra signer after nominal quorum; reject. | **FUTURE / NOT EXECUTED** |
| Discontinuous prefix | Gap, reordering, duplicate block, wrong parent/height/view/ID, anchor mismatch, absent content commitment, or non-final tip; reject all of it before effects. | **FUTURE / NOT EXECUTED** |
| Unsupported transition | Epoch change with no old-set-finalized transition/new-set binding, conflicting effective boundary, or unsupported overlap; refuse rather than reusing the prior set. | **FUTURE / NOT EXECUTED** |
| Oversized input | Over-limit frame rejected before full allocation; nested vector count/length, aggregate evidence, staged bytes, retained bytes, crypto work, and concurrency rejected at their respective pre-allocation/pre-work boundaries. | **FUTURE / NOT EXECUTED** |
| Actual caller | Exercise real authenticated transport binding, decoder bounds, actual response handler, configured authority and verifier; prove a valid in-scope proof reaches only the verified staging result and invalid/unsupported proof cannot reach application. | **FUTURE / NOT EXECUTED** |
| Negative/sensitivity controls | Test-only omitted chain/epoch/signature/quorum/continuity/pre-effect gate variants are caught by a protected-state and call-recording oracle; production builds contain none of those variants. | **FUTURE / NOT EXECUTED** |
| Partial/uncertain application failure | Inject failure before first effect, after durable intent, during partial application, after rename before directory sync, and after signer invocation with lost result; distinguish acknowledged, failed-before-effect, partial and unknown outcomes, remain closed, and require reconciliation without asserting rollback. | **FUTURE / NOT EXECUTED** |
| Restart/release/multi-node | Reopen after every crash boundary; verify actual release config/caller, authority source, independent nodes, transitions and operational currentness/fencing separately from prefix verification. | **FUTURE / NOT EXECUTED** |

The prior 44 selected test executions and compile checks remain historical
author evidence from their own pinned implementation-task source manifest.
They are not reruns, authenticated-prefix acceptance, release-binary evidence,
or deployed recovery. No unchanged Rust tests or builds were rerun for this
documentation task.

## 7. Open decisions and disposition

Review must still determine the independently trusted anchor/currentness
source, trusted domain and runtime-to-wire chain mapping, epoch authority
source, block/content commitment, exact finality witness, bounded resource
values and decoder integration, safe application/reconciliation protocol, and
later signing-history/fencing/clear-resume authorities. No option here fills
those gaps by assumption.

This contract is **PROPOSED — INDEPENDENT REVIEW PENDING**. It changes no
source, tests, recovery behavior, audit-register finding, signer path or
activation state. A17-F1 / RS1-F7, RS1, and A33-F1 / E27 remain **OPEN**;
activation remains **DISABLED**; public DevNet remains **NO-GO**.

## 8. AP1 — block identity and committed-prefix citation correction

The user supplied **PASS WITH LIMITATIONS** for the proposed design direction
and identified AP1 as an open documentation citation. This correction
supersedes the block-ID source citation in section 1; it does not reopen the
three inventory corrections, their bounded acceptances, or any other prior
accepted evidence. No reviewer identity or raw review artifact is asserted.

The correct protected-main source for `derive_block_id_from_header` is
[`basic_hotstuff_engine.rs:3875-3890`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3875-L3890).
The function takes `proposer`, `view`, and `parent_block_id`; it writes the
little-endian proposer and view into the first 16 result bytes, then copies
only `parent_block_id[..16]` into the remaining result bytes. It has no
payload input. This describes the implementation and does not demonstrate a
collision, exploit, or new production failure. The earlier section-1
`1922-1937` citation was incorrect and is superseded by this citation.

The pinned three-chain implementation
[`try_commit_with_qc`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1819-L1938)
identifies B as the block certified by the incoming QC, P as B's parent, and
G as P's parent. When all three nodes have `own_qc`, their views strictly
increase G < P < B, and the monotonic commit conditions hold, the engine
sets `committed_block` and `committed_height` to G. P and B are supporting
descendants in that rule; the newest certified block B is not thereby the
committed block. A future witness must identify the committed prefix through
G separately from the supporting P/B descendants and their certificates.
This source clarification is not itself a complete finality proof, does not
establish that arbitrary supplied QCs are authenticated, and selects no
witness format.

The plan addendum and current AP1 hashes are recorded in
[`AP1-CORRECTION-SHA256SUMS`](AP1-CORRECTION-SHA256SUMS). The pre-correction
`CONTRACT-SHA256SUMS` and earlier inventory manifests remain historical
evidence verified against their producing revisions, not against these
appended bytes.
