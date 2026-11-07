# Candidate finality-witness contract

**FINALITY-WITNESS DESIGN — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
SOURCE_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
WITNESS=PROPOSED; NOT IMPLEMENTED OR APPROVED
APPLICATION_OR_RESUME_AUTHORITY=NOT GRANTED
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the authenticated-prefix
direction and **PASSED / CLOSED** for AP1 within its documentation scope.
The three earlier inventory corrections and all bounded acceptances remain
preserved. No reviewer identity or raw review artifact is asserted. This
candidate is for independent review, not a selected wire format,
cryptographic construction, finality proof, recovery implementation or
authority to apply or participate.

## 1. Independent inputs and candidate evidence

The following are distinct logical inputs, not an encoding:

* **Trusted independently of the peer and copied local state:** an accepted
  finalized starting anchor A with its exact block identity, height, epoch and
  reviewed content/chain commitment; the intended runtime and wire chain
  mapping, genesis identity, authorized epoch, validator identities, unique
  keys, suites and weights, authority commitment and approved verification
  backend; the applicable consensus/finality and fault assumptions; a
  reviewed relationship between commitments and block contents; and the
  finite admission profile. The mechanism selecting these inputs remains
  open. The snapshot baseline in current startup is only height plus opaque
  block ID, not a reconstructed signed history:
  [`main.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L2883-L2892).
* **Untrusted peer-supplied candidate:** a claimed endpoint E and ordered
  blocks above A through E, their full parent links and content or reviewed
  content commitments, plus for each claimed committed block X the distinct
  logical evidence roles G=X, P=child(G), B=child(P), and authenticated QCs
  for G, P and B. Supporting descendants may lie beyond E. Records and QCs
  may be shared across triples, but every role and association must be
  explicit and independently checked. The peer may supply signed proposals,
  evidence of full content and link binding, and any claimed proof material;
  none becomes trusted merely because transport authenticates the responder.
* **Output proposed for a future verifier:** a bounded, non-mutating
  description of A, E and the verified prefix and evidence associations,
  conditional on all independent assumptions and checks. It is not a
  permission to apply, publish, clear quarantine, sign or participate.

If A, authority or a sufficient reviewed content-binding rule is unavailable,
refuse before a protected recovery effect. A valid local snapshot or responder
claim is not an independent authority.

## 2. Source rule versus witness obligations

[`try_commit_with_qc`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1819-L1938)
starts at B identified by the incoming logical QC's block ID, follows B's
parent to P and P's parent to G, requires each node's `own_qc` to be present
and requires `G.view < P.view < B.view`. It then advances the recorded
committed block and height to G only when its `should_commit` and
`height_ok` checks permit it: G is not the existing committed ID, G's
height is greater than the stored committed height if present, and its view
is greater than the stored committed node's view if that node is present.
The implementation permits the view check when the previous committed node
is absent. It logs G's ID/view/height, subject to duplicate suppression and
log eviction. These are local state transitions, not a proof that a remote
prefix or every ancestor is recoverable.

[`on_qc`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1778-L1805)
attaches a logical QC to the matching block as `own_qc`. A node's separate
[`verified_justification`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/block_state.rs#L31-L74)
is non-serialized, refers to its *parent*-certifying justification, is not
its own QC, and is not durable current authority. `own_qc` presence alone is
not proof that separately supplied constituent signatures verify. The
proposed verifier must authenticate and associate each actual certificate
with its intended G, P or B and independently check the full links, heights,
views, authority and content. It must not infer B is finalized simply
because B has a QC.

For each supplied QC, use the reviewed domain-aware verification semantics:
authenticate every declared Vote signature under the selected authority,
require unique authorized signers, matching chain/epoch/domain and suite,
checked voting weight and quorum, and bind the actual signed vote fields to
that role. The existing
[`QC verifier`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L877)
checks each declared signature and `ceil(2W/3)` under **caller-supplied**
context; it is not itself a recovery verifier or a source of current
authority. The witness must establish the correspondence between the
wire-QC fields and logical block/view/height roles under a reviewed rule;
do not assume that a same-named field or signer-index list supplies it.

## 3. Coverage and endpoint

The conservative candidate does **not** rely on an unreviewed rule that a
single finality witness for E automatically proves all earlier blocks
recoverable. It requires, for every block X claimed committed above A through
E, its own valid G=X/P/B triple, authenticated per-role certificates, and
authenticated full block/content and parent evidence. Verify exact full
parent equality, contiguous checked heights, no gaps/duplicates/reordering,
and consistent chain, epoch and role identities from A through E and each
supporting descendant. A reviewed protocol rule must explain the relationship
between those per-block triples, the starting committed state and monotonic
advancement; merely reproducing the current local monotonic check with
peer-supplied prior state is insufficient. Verify the whole candidate before
returning a result, and refuse if the rule or evidence is unavailable.

An alternative compact prefix-coverage rule could replace per-block triples
only after separate review establishes precisely which ancestors are covered,
how full links and content are authenticated, and what proof and assumptions
are required. None is selected here. The empty extension E=A requires a
separately reviewed result rule, not fabricated descendants.

P and B support the proof for G; their presence does not include them in the
committed output. If a peer claims a tip newer than E or presents only P/B
without independently sufficient proof for those blocks, refuse the claimed
whole endpoint. Do not silently truncate or relabel it as finalized. A
separately requested E, with its own complete evidence, could be evaluated
independently; no newer claimed block is accepted by implication.

## 4. Block identity and content binding

The pinned [`derive_block_id_from_header`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3875-L3890)
takes proposer, view and a 32-byte parent ID, copies little-endian proposer
and view and only the first 16 parent bytes into its 32-byte result, and has
no payload input. This describes the source, not a demonstrated collision,
exploit or new production failure.

The signed [`Vote` canonical body](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L180-L219)
binds version, wire chain, epoch, height, round, step, block ID, validator
index and suite; the
[`v2 domain`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L252-L294)
also binds message family, runtime/wire chain, genesis and authority. The
[`QC verifier`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L1059-L1119)
reconstructs those votes from QC fields and signer indices. With the current
derived ID, these votes/QCs do not by themselves establish the entire parent
ID or bind payload bytes, nor prove that an independently supplied header
and content correspond to the voted block.

The signed [`Proposal` body](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/consensus.rs#L915-L954)
includes the full parent ID, payload hash, other header fields, QC bytes and
transactions; this can authenticate the proposer's message under a trusted
key, but a proposer signature alone does not establish that a quorum endorsed
that exact complete parent/content. A future candidate therefore needs an
additional independently authenticated and reviewed binding from the
quorum/finality evidence to the exact full parent and all application-relevant
content, including how any supplied content matches its commitment. Neither
the current ID nor a peer's matching ID supplies that binding. The construction,
compatibility with historical votes, and whether such evidence can exist for
past blocks are open. Refuse when it cannot be established.

## 5. Scope, budgets, and pre-effect ordering

The initial candidate is **single trusted epoch and one fixed authority**;
refuse cross-epoch blocks, authority changes, ambiguous activation boundaries
or unsupported transitions throughout both prefix and descendants. Static
genesis authority is epoch 0 only and currently provides no authorized
production wire-chain ID:
[`genesis authority`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L88-L106),
[`wire mapping`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L425-L439).
This is a conditional test/design slice, not an available production context.
Currentness, rollback resistance, durable application, signer history,
exclusive ownership/fencing and an independently authorized clear/resume
decision remain separate and unprovided.

For a **candidate test-only review profile**, all limits below are hard
upper bounds, not production settings or a selected encoding. A profile
exceeding any bound or lacking a needed lower deployment-specific cap must
refuse, not default to unlimited:

| Resource | Candidate maximum and enforcement |
|---|---|
| Framed input | 4 MiB total per candidate, checked before frame allocation/read; one in-flight candidate per receiver and 4 MiB aggregate in-flight frame bytes. |
| Prefix and descendants | 32 claimed blocks above A, at most 64 total distinct block records including support, at most 96 triple roles and 96 distinct QC records; all counts checked before allocation. |
| Authority / signatures | 64 members, 64 signatures per QC, 32 KiB per signature, 2 MiB aggregate signature bytes and 6,144 signature verifications per candidate; count actual work even for shared objects and invalid extras. |
| Content / retained state | 2 MiB aggregate supplied block/content bytes, 2 MiB aggregate other proof bytes, 16 MiB peak decoded + scratch + staged/retained candidate bytes including capacities and simultaneous copies; check checked sums and reserve before materialization. |
| Parsing and time | Maximum nesting depth 8, 4 MiB total encoded length, checked integer/height/count conversions and multiplication; 30-second maximum verification deadline, cancellation and no late effect. |

These are intersecting ceilings, not reservations or a promise all maxima
can coexist. Each count, byte length, depth, cumulative crypto operation and
concurrency charge must be admitted before its allocation/work; enforce
transport length before allocation, then nested deserialization budgets,
structural checks, complete cryptographic checks, and bounded non-mutating
result. Exhaustion, overflow, cancellation or missing binding refuses.
[`p2p_tcp.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L178-L195)
currently deserializes before the handler; the
[`128` setting](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L247-L248)
is not an inbound or complete-evidence budget. Numeric ceilings and accounting
must be reviewed and measured before any implementation; cryptographic
backend scratch and cancellation behavior must also fit the budget.

Before any protected recovery application/publication or signer call,
failure must leave those protected effects unattempted. A future separate
application protocol would need its own crash/partial/unknown reconciliation;
an error after an effect was attempted cannot establish rollback. Current
[`dispatch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7438)
refuses admitted non-empty responses and ignores admitted empty responses;
it does not run this candidate.

## 6. Future acceptance cases

All cases below are **FUTURE / NOT EXECUTED**. No fixture or successful
verification may invoke application, signing, quarantine clearance or
participation; an actual-caller test must record all those effects.

| Case | Required check | Status |
|---|---|---|
| Valid multi-block single-epoch prefix | Independently trusted A/domain/set, each X's G/P/B roles, verified role QCs, reviewed authenticated full content and monotonic coverage yield exactly E, never P/B. | FUTURE / NOT EXECUTED |
| G/P/B structure | Wrong parent, swapped role, duplicate ID, missing P/B, missing height or non-increasing view rejects whole candidate. | FUTURE / NOT EXECUTED |
| QC integrity | Missing own-role QC, wrong certified block, tampered or absent signature, malformed bitmap/signature association, invalid extra after quorum, or insufficient weight refuses. | FUTURE / NOT EXECUTED |
| Authority/domain | Wrong chain, genesis, epoch, message family or authority; unknown/duplicate signer, wrong key/suite or weight refuses without fallback. | FUTURE / NOT EXECUTED |
| Coverage | Missing one claimed block's triple, broken A-to-E continuity, unsupported compact ancestry assumption, or unreviewed monotonic-state rule refuses. | FUTURE / NOT EXECUTED |
| Content and full parent | Substitute payload or full parent including its last 16 bytes while preserving a claimed ID; absent or invalid quorum-to-content binding must refuse. No collision or exploit is asserted. | FUTURE / NOT EXECUTED |
| Unfinalized endpoint | Claim P, B or newer tip without independent finality evidence; refuse the requested candidate, no silent truncation. | FUTURE / NOT EXECUTED |
| Limits | Smallest over-limit frame before allocation, each nested length/count, depth, per-signature and aggregate bytes, decoded capacity, concurrent candidates, crypto work, checked arithmetic/height overflow and deadline cancellation refuse. | FUTURE / NOT EXECUTED |
| Real caller and sensitivity | Once a caller is proposed, exercise the actual decoder and handler and use test-only omitted-link, omitted-signature, omitted-binding and omitted-effect-gate controls that the oracle detects; no production defect variant. | FUTURE / NOT EXECUTED |
| After-attempt outcomes | In a separately reviewed application protocol, inject known failure and uncertain/partial publication after attempted effects; retain known/unknown outcomes and remain closed, never assume rollback. | FUTURE / NOT EXECUTED |

No new Rust tests or builds were run. This contract does not establish
currentness, signing continuity or permission to resume.
