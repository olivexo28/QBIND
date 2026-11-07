# Quorum-to-content binding analysis

**QUORUM-CONTENT BINDING ANALYSIS — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
SOURCE_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
DESIGN=PROPOSED; NO NEW FORMAT, ALGORITHM OR ACTIVATION SELECTED
RECOVERY_OR_RESUME_AUTHORITY=NOT GRANTED
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the finality-witness direction
and **PASSED / CLOSED** for AP1 and its document-source navigation follow-up.
The earlier inventory corrections and all bounded acceptances remain
preserved. No reviewer identity or raw review artifact is asserted. This is
an analysis for independent review, not a proof of safety, implementation,
wire format, commitment construction, migration procedure or permission to
recover or participate.

## 1. Existing signed facts and available artifacts

| Artifact | Exactly what is authenticated | Context and limitation |
|---|---|---|
| Proposal | The proposer's canonical body contains version, wire chain, epoch, height, round, **full parent ID**, payload hash, proposer and suite, transaction count, timestamp, payload kind, next epoch, batch commitment, encoded embedded QC and each length-framed transaction. Signature bytes themselves are excluded. [`proposal body`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L915-L958). | Under the v2 verifier the claimed proposer, membership, allowed key/suite, wire chain and actual recomputed preimage are checked [`proposal verification`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L385-L433). This authenticates a proposer message, not quorum agreement that its payload/hash or full parent is the one voted for. Content availability and consistency require separate validation. |
| Vote | Canonical signed body contains version, wire chain, epoch, height, round, step, block ID, validator index and suite; the signature itself is excluded. It carries no complete parent or payload field. [`vote body`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L180-L219). | The body authenticates the **block ID bytes** and listed vote fields, not external bytes merely stored alongside the signature. A signer index alone is not a signature. |
| Domain-verified wire QC | The wire QC carries common Vote fields, bitmap and signature list. The verifier derives signer indices from set bits, associates signatures in bit order, reconstructs each Vote and verifies **every** declared signature; it checks chain, authorized epoch, membership, suite and accumulated weight against `ceil(2W/3)`. [`QC layout`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L250-L302), [`verification`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L877), [`reconstruction`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L1059-L1119). | It verifies constituent Votes, not a separate signature over the entire QC container or arbitrary adjacent proposal/content. Bitmap and signatures are structurally associated by the verifier; the selected set, keys, weights, epoch and domain are trusted caller inputs, not made current by verification. |

The [`v2 domain`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L185-L225)
binds its explicit signing-format version and Proposal/Vote family, full
runtime chain, expected wire chain, genesis identity and authority
commitment as well as the respective canonical body
([`preimage construction`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L252-L294)).
Epoch and wire version are in those bodies. The legacy v1 chain-aware
preimage uses its own domain prefix plus the same canonical body
([`Vote v1`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L160-L177),
[`Proposal v1`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L885-L902));
do not infer v2 authority/genesis binding for a legacy signature or retry a
failed signature under another version. The binary path's bound verification
context delegates preimages to v2
([`context`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L1104-L1121)).
The v2 domain inputs themselves must be independently authorized; current
genesis-static authority is epoch 0 only and has no production authorized
wire-chain ID
([`epoch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L88-L106),
[`mapping`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L425-L439)).

**Retention is conditional, not a historical completeness claim.** The
[`VerifiedQuorumCertificate`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L520-L567)
owns the wire certificate and verified signer/weight/domain summary. A
[`BlockNode`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/block_state.rs#L31-L74)
can retain an admission-time verified *parent justification*, but it is
non-serialized, is not that node's `own_qc`, and is absent on logical
restart reconstruction. The engine's
[`logical QC`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc.rs#L20-L38)
contains only block ID, view and signer IDs, not signatures. A separate
[`in-memory BlockStore`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/block_store.rs#L103-L135)
can hold a proposal; an ordinary insert can replace one for the same ID
([`store_proposal`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/block_store.rs#L203-L227)).
The [`ConsensusStorage`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/storage.rs#L142-L162)
interface can persist wire proposals and QCs when its callers supply them;
this is not evidence that every historical block, signature and G/P/B
certificate is present or independently authenticated.

The current [`catch-up export`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3897-L3943)
exports logical signer IDs and block metadata, not signatures or payload;
[`response schema`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p.rs#L190-L219)
has the same limit. The current snapshot baseline carries only opaque block
ID and height, not reconstructed vote/QC history
([`baseline`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L2883-L2892)).
Availability, authenticity, completeness and provenance of historical
proposal, constituent signatures, content and descendants remain unknown for
any particular chain. Local checksums or a stored proposal do not create
missing quorum signatures.

## 2. Binding gap and existing commitment APIs

[`derive_block_id_from_header`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3875-L3890)
uses proposer and view and copies only the first 16 bytes of the parent ID;
it has no payload input. Thus, for this derivation, a valid proposer signature
over full proposal fields plus valid Votes over that ID does **not** by
itself establish that the quorum signed the same complete parent and content.
An authenticated correspondence binding the exact proposal/content to what
each validator attested is needed. This source comparison asserts no
demonstrated collision, exploit or new production failure.

[`BlockProposal::canonical_body`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L915-L954)
is a proposer-signing body, not by itself a quorum content commitment.
[`compute_batch_commitment`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L496-L540)
computes an existing ordered certified-batch-ref commitment; it is not shown
to cover the full parent and all application-relevant content or to be
quorum-bound by the current derived ID. Comments in the wire header about
votes binding a block hash are not a substitute for tracing the actual ID
derivation and signed Vote. The generic
[`vote_digest`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-hash/src/consensus.rs#L6-L19)
is a separate helper; it is not the v2 message-bound verification proof and
its input fields must not be conflated with the v2 canonical body.

Historical artifacts consisting only of these existing signatures and
derived IDs cannot, *by themselves*, establish the required full
quorum-to-content binding. This is not a claim that no other evidence could
exist: a separately reviewed, independently authenticated historical
attestation/checkpoint or equivalent proof, with trusted provenance and a
precise binding to those blocks and contents, would be required. No such
authority or artifact is assumed here.

## 3. Conceptual options and protocol boundary

| Option | What is attested / checked | Safety and availability boundary |
|---|---|---|
| **Continue refusal** | No new attestation is accepted. Current bound non-empty catch-up responses are refused and admitted empty ones ignored before peer-height/mode effects ([`dispatch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7438)). | Avoids granting recovery on insufficient evidence; restore mode may persist indefinitely and is not a complete engine/worker/signer fence. It provides no automatic recovery or resume. |
| **Future content-bound consensus votes** | Under a separately reviewed version and authority, each validator attests a canonical commitment identifying the exact full parent and all application-relevant block/content plus consensus position. For G, P and B separately, verify the corresponding quorum attestations and exact commitment-to-block association, full parent links and content, domain and reviewed three-chain relation. | Requires protocol/signing and voting-rule changes, evidence retention and versioned verification; existing votes do not retroactively attest the new commitment. Cross-epoch transitions, historical bridging and resume remain separate. |
| **Future separate quorum content attestations** | Under a distinct reviewed message purpose, validators independently attest the same canonical commitment and its chain/epoch/position association; recovery checks each G/P/B attestation quorum *and* the separate relevant consensus QCs and their reviewed association to the same objects. | More evidence and a second agreement/association rule are needed; a later signature must not be represented as an original consensus vote or automatically imply historical finality/currentness. No such service, evidence or authority is assumed. |

For either future route the logical attestation must bind: intended chain and
genesis; exact epoch and authority snapshot; message purpose and protocol,
signing and commitment versions; consensus height/view/step and block role
association; a commitment to the **full** parent identity and all
application-relevant header, payload, transaction and batch/reconfiguration
content; and unambiguous algorithm/commitment identifiers. A validator must
validate the relevant content and its parent/commitment relationship before
attesting under an independently reviewed rule. G/P/B are witness roles:
do not make an attestation replayable for another object, view, purpose or
authority merely because a peer labels it with that role.

The future verifier must reconstruct one reviewed, unambiguous canonical
representation, reject unsupported versions/algorithms, duplicate or
ambiguous encodings, mismatched counts/lengths and missing data, and verify
that supplied content corresponds to the commitment. It must include all
semantically relevant fields and ordering, distinguish absent/empty values,
frame variable-length data, use checked lengths and reject unknown extensions
unless a reviewed version defines them. No serialization or cryptographic
construction is selected here. The existing
[`len_to_u16` / `len_to_u32`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/io.rs#L81-L100)
panic on overflow; a future untrusted-input path needs bounded, fallible
admission rather than relying on these helpers as refusal mechanisms.

For each G/P/B role, independently authenticate all required signatures or a
separately reviewed equivalent, enforce unique authorized membership and
checked voting weights, compare the attested statement to the exact supplied
object and its parent/content, and validate QC position, parent relationships
and increasing views. The current
[`three-chain rule`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1819-L1938)
commits G subject to its conditions; P and B support it, not automatically
committed tips. Require evidence for each claimed committed block or an
independently reviewed coverage rule; no ancestor is made recoverable merely
by labeling it so. The existing `ceil(2W/3)` verifier threshold is a code
fact, not a standalone safety theorem: reviewers must establish the exact
fault-weight bound, strictness at threshold equality, quorum intersection,
honest-validator signing/locking behavior and cryptographic assumptions for
the chosen protocol and all transitions.

The first review slice is one independently trusted epoch and authority;
unsupported transitions refuse. A future protocol activation would require
review of consensus and signer/anti-equivocation rules, version/domain
negotiation, old/new-node behavior and downgrade refusal, durable retention
and retrieval of signed content commitments and constituent evidence,
bounded parsing and canonicalization, execution semantics, crash consistency,
and release/multi-node evidence. Upgrade or historical bridging procedures
are **not** selected. A new commitment's signatures can cover blocks only
where actual compatible attestations exist; they cannot be inferred from old
Vote signatures, local storage, or successful rollout.

## 4. Future verifier and effect boundary

**Trusted inputs:** independently accepted starting anchor and full content
association, chain/genesis and runtime-to-wire mapping, epoch, authorized
validator keys/suites/weights and allowed verification policy, accepted
protocol/commitment versions and algorithms, fault/finality/coverage rules
and enforceable resource limits. **Untrusted inputs:** claimed committed
endpoint, ordered blocks and content, their purported G/P/B descendants,
certificates/attestations and claimed associations. Peer authentication is
transport identity, not endorsement authority.

Admission must bound the frame **before allocation**, nested lengths/counts,
decoded capacities, content and evidence, cryptographic work and concurrent
requests before their respective allocations or work; check arithmetic and
reject malformed, missing, ambiguous or unsupported material. Verify every
required quorum and authenticated content binding, full parent continuity,
G/P/B relations and per-block coverage through the exact requested endpoint
before any protected application or publication. A claim beyond the proven
committed endpoint is refused, not silently truncated. The earlier witness's
numeric ceilings and deadline are **unvalidated proposals**, not runtime,
memory, scheduling or cancellation guarantees. Backend allocation and late
outcomes remain separate review obligations.

The only proposed successful output is a bounded **non-mutating** verification
result with the trusted context identity, exact proven committed endpoint and
evidence/role associations; supporting descendants are not output as
committed solely by their role. It grants no application, currentness,
rollback resistance, durable ownership, signing-history continuity, exclusive
signer/fencing, quarantine-clearance or participation authority. Missing or
uncertain evidence refuses before protected effects.

A separate future application protocol would require independent admission,
durable intent, cross-store reconciliation and explicitly authorized resume.
Before an effect is attempted, refusal must not invoke protected recovery
publication/application or signing. After an attempted effect, record
acknowledged, known-failed-before-effect, known partial and **Unknown**
outcomes separately; remain closed and reconcile, never assume rollback or
unchanged state merely because a later operation refused.

## 5. Review controls and open decisions

All cases below are **FUTURE / NOT EXECUTED**; they are proposed controls,
not source evidence or an executed acceptance claim.

| Case | Required result | Status |
|---|---|---|
| Valid G/P/B per claimed committed block | Trusted single-epoch authority, content-bound quorum statements, exact full parents and reviewed coverage yield only the requested committed endpoint; no application/signing/resume calls. | FUTURE / NOT EXECUTED |
| Payload / full-parent substitution | Vary payload, content ordering, parent suffix or commitment identifier while retaining a claimed ID/signature; refuse before protected effects. | FUTURE / NOT EXECUTED |
| Domain and version | Wrong chain/genesis, epoch/authority, purpose, signing version, commitment version or algorithm refuses, with no fallback. | FUTURE / NOT EXECUTED |
| Signers and quorum | Duplicate/unknown signer, wrong key/suite, invalid extra signature or insufficient weight refuses; threshold-equality scenarios exercise the reviewed fault model. | FUTURE / NOT EXECUTED |
| Conflicting proposals | Different full content or parent sharing an apparent logical identity is not treated as the same quorum-attested object; reject ambiguity or inconsistent bindings. | FUTURE / NOT EXECUTED |
| Finality coverage | Missing P/B, missing QC or attestation, wrong link/view or unproven claimed newer tip refuses the whole requested result. | FUTURE / NOT EXECUTED |
| Historical evidence | Existing pre-binding votes, logical signer indices or copied checkpoint alone cannot verify a new content commitment; only separately reviewed actual historical proof can qualify. | FUTURE / NOT EXECUTED |
| Malformed / oversize | Overflow, nested length/count/depth, cumulative evidence, decoded capacities, crypto-work and concurrency limits refuse at their actual pre-allocation/pre-work boundaries. | FUTURE / NOT EXECUTED |
| Sensitivity and caller | Test-only missing-domain, missing-parent/content binding, omitted-signature and omitted-effect-gate controls are detected by the real caller and protected-effect oracle; defect variants never ship. | FUTURE / NOT EXECUTED |
| Later attempted effects | Separate application tests distinguish acknowledged, partial, pre-effect failure and Unknown writes/late results, remain closed and require reconciliation rather than claiming rollback. | FUTURE / NOT EXECUTED |

**Next review decision:** decide whether to pursue a future content-bound
consensus-vote protocol or a separately purposed quorum attestation, or
retain refusal. Before choosing, review the exact attested semantics,
canonical field inventory and identifier/version policy, quorum/fault
intersection and signing rules, relationship to G/P/B and per-block
coverage, history/bridge authority, authority-transition policy, durable
evidence storage and compatibility/activation boundary. Resource values,
deadlines, cancellation guarantees, currentness, operational ownership and
resume authority remain unresolved. No unchanged Rust tests or builds were
run for this documentation task.
