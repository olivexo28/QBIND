# A33-F1 / E27 quarantine-record capacity inputs

**CAPACITY INVENTORY — INDEPENDENT REVIEW PENDING.**
**65,536-byte production sufficiency: UNESTABLISHED.**
A33-F1 / E27 and all remaining obligations **OPEN**; activation **DISABLED**;
public DevNet **NO-GO**. This is source analysis, not a format or limit change.

## 1. Pin, inputs and review attribution

Repository `olivexo28/QBIND`, branch `copilot/a33-f1-bounded-eviction`.
Inspected entry/producer parent `bf2e2020e981697e1fb44cf65fe44b6b57303767`,
tree `46d6968f81c6d6175c4322f6043f561abd3b819c`.
Repository/branch/tip/tree, clean worktree/staging, remote task and protected
local/remote main were verified before editing. All matched; no fast-forward.
Main remains `c9aaef40b045e896ddfa8b01bad230f6b680715e`.
Source anchors refer to that entry commit, not a claim that branch changes
are merged to main. [Check record](capacity-inventory-checks.txt) identifies
source hashes and executed documentation checks.

Controlling proposals remain unchanged:
[stay-closed contract](stay-closed-contract.md),
[storage candidate](storage-candidate-design.md) and
[initialization/binding/continuity amendment](initialization-binding-continuity.md).
The filesystem-prototype review checkpoint and its
[author evidence](filesystem-prototype-evidence.txt) are unchanged.
The owner supplied **PASS WITH LIMITATIONS** review of that prototype:
source/evidence were reviewed, but the reviewer **did not independently rerun
the author's 11 Rust tests**. This is user-supplied attribution, not an
independent review performed here. No reviewer identity or standalone raw
review artifact was provided or invented. No earlier passing tests or checks
were rerun; historical checksum/preservation checks are not reruns of the
filesystem experiment.

The owner additionally supplied the conditional successive-prefix observation
in section 6. It is attributed as user-supplied, not an implemented encoding,
new receiver bound or separately authenticated review artifact.

Classification used below:
**E** = enforced at the exact cited point;
**P** = producer/path/transport/validated-input scope only;
**F** = test fixture only;
**A** = proposed/assumed, not enforced;
**U** = unresolved count, size, encoding or history rule.
An E check can still have only P scope; it is not automatically a record cap.

## 2. Catch-up pipeline and signer inventory

| Input/stage | Source anchor at entry | Enforcement and capacity consequence |
|---|---|---|
| Producer response count | `crates/qbind-node/src/binary_consensus_loop.rs:248-248,8392-8428`; `crates/qbind-consensus/src/basic_hotstuff_engine.rs:3904-3943` | **E/P:** handler passes 128 into exporter; exporter loops while `out.len() < max_blocks`, may return fewer. Export API accepts an arbitrary caller `usize`. 128 bounds this producer call, NOT all callers or inbound responses. |
| Producer certificate material | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:3914-3938` | **P:** chooses a retained child with `own_qc`, clones all logical signers. No separate export signer-count check here. |
| Structured message | `crates/qbind-node/src/p2p.rs:155-219` | **U before admission:** serde-derived `Vec<RestoreCatchupBlock>` and each `Vec<u16>` have no field-level count validator. A comment saying “bounded” is not enforcement. Fields are height/view `u64`, parent/ID `[u8;32]`, proposer/index `u16`, optional responder height and request anchor. |
| Sender conversion | `crates/qbind-node/src/binary_consensus_loop.rs:8413-8428` | **P:** proposer/signers cast from `u64` IDs to `u16` using `as`; no checked range enforcement here. A faithful export bound needs validator IDs representable in `u16`; the cast is not that proof. |
| Inner P2P framing | `crates/qbind-node/src/p2p_tcp.rs:145-205` | **E/P:** discriminator byte + u32-BE declared payload length + bincode-serialized `P2pMessage`. Decoder checks header/truncation/discriminator and calls `bincode::deserialize` on the declared slice. No catch-up 128 check, signer count check or quarantine-record encoding. Encoder's `payload.len() as u32` is not a checked maximum enforcement. |
| Secure-channel frame | `crates/qbind-net/src/framed_io.rs:21-21,113-140`; `crates/qbind-node/src/secure_channel.rs:218-225,547-575,830-842,1257-1274` | **E/P:** transport reader rejects ciphertext length above 16,777,216 BEFORE allocating its full frame. Secure receive goes through that reader and decrypts; async worker delivers plaintext. This is a per-ciphertext-frame bound on this transport, not a record size, lifetime or decoded-count policy. Exact plaintext/codec/allocator bounds need their own derivation. |
| Decode and routing order | `crates/qbind-node/src/p2p_tcp.rs:2213-2285` | **P:** `channel.recv` then structured decode; optional rate limiting is AFTER decode. It does not impose a semantic vector cap or bound malformed pre-validation observations across messages. Other in-process typed callers do not acquire a TCP bound by using the same Rust type. |
| Inbound queues | `crates/qbind-node/src/p2p_inbound.rs:475-519`; `crates/qbind-node/src/p2p_tcp.rs:852-852` | **E/P:** handler channel has caller-specified finite capacity and `try_send`; TCP service creates an inbound channel of 256. Occupancy bound only, not lifetime response/evidence count, bytes per typed element, or active operation history. |
| Receiver admission | `crates/qbind-node/src/binary_consensus_loop.rs:7393-7412,8437-8506` | **E/P:** transport-sender binding, self-response/empty handling and exact local request-anchor check. Then maps ALL supplied blocks/signers to engine types. No receiver-side `len <= 128` enforcement at these points. Empty/stale responses also drive restore-mode observations; a future quarantine gate must not let these silently clear. |
| Engine input | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:3954-4017` | **E/P:** iterates provided slice without a response-count cap. Per-item contiguous height, parent, height/view, proposer, derived ID and logical QC validation; preceding valid items can already have effects before later rejection. Signer vector is cloned into logical QC before validation. |
| Insertion/replay/current item | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:4018-4050` | **E/P:** `register_block`, then fallible `on_vote` per signer, then prefix counter; final view advance only after loop. Current item may insert/replay some votes before error; voting may affect QC/lock/commit. Result is `Result<usize, ...>`, not a full prefix/current-domain report on error. No response rollback or marker journal is implemented. |
| Node continuation effects | `crates/qbind-node/src/binary_consensus_loop.rs:8506-8538,3125-3210` | **P/U:** handler logs/counts success/error; loop updates state metrics, triggers snapshot and checks/persists epoch after inbound handling. Error comment claiming no mutation is not a capacity/effect guarantee. Exact future effect-report inventory is not yet a production interface. |

Source links:
[message types](../../../../crates/qbind-node/src/p2p.rs),
[producer/receiver](../../../../crates/qbind-node/src/binary_consensus_loop.rs),
[engine](../../../../crates/qbind-consensus/src/basic_hotstuff_engine.rs),
[transport framing](../../../../crates/qbind-node/src/p2p_tcp.rs),
[outer frame limit](../../../../crates/qbind-net/src/framed_io.rs).
Logical QC checks are not signature authentication (A17-F1 remains separate).
Sender binding is not validation of the embedded logical signer claims.

### Signer cardinality and width before versus after validation

`crates/qbind-consensus/src/qc.rs:29-39,60-113` constructs a QC with a
`Vec<ValidatorId>` and validates each signer for membership, then duplicates,
then voting-power quorum. It does NOT bound an unvalidated vector by committee
size before the loop. Rejected/duplicate inputs can have a much longer supplied
vector than any accepted QC. Preserving rejected raw input is a distinct term
from retaining a validated signer set. The TCP frame bounds that path's
available encoded bytes, not a general typed-vector length or aggregate history.

For an accepted engine QC, distinct membership implies `S_i <= N_i`, where
`N_i` is the actual validator set used for that validation. On the node
catch-up path, indices originated as `u16`, so successful distinct indices
also imply `S_i <= 65,536` and therefore `S_i <= min(N_i, 65,536)`.
This is a **validated, path-only combinatorial bound**, not the supplied
pre-validation length and not a 65,536-byte size limit. Direct engine callers
carry `ValidatorId(u64)` (`crates/qbind-consensus/src/ids.rs:29-29`) and instead
have the `N_i` bound; do not apply the node index restriction there.

`crates/qbind-consensus/src/validator_set.rs:380-432` constructs a finite,
nonempty, unique set but specifies no cardinality maximum. The binary uniform
builder enumerates `0..num_validators`
(`crates/qbind-node/src/binary_consensus_loop.rs:564-567,711-721,2813-2813`);
the constructor's `.max(1)` is a minimum, not a maximum. No universal approved
`N_max` or representable-ID rule was established at these boundaries.
Quorum is a voting-power threshold, not a fixed “three signers” count.
For multi-epoch histories, bind each observation to its validator set/epoch;
one assumed current `N` cannot silently cover earlier committees.

Widths: index scalar `u16` is 2 value bytes, logical ID `u64` is 8 value bytes,
block/parent IDs are 32 value bytes. These are type-level widths, not a chosen
quarantine encoding or `Vec` allocation size. Catch-up carries **logical
indices, no per-signer signature bytes**; importing crypto-suite signature
sizes into this message formula would be wrong. If a proposed record retains
real signer results or verified evidence from other domains, add those sizes
separately. Bincode enum/vector/option framing and outer transport tags must
be counted for wire bytes; do not copy them into an unselected marker schema.
No exact bincode worst-case allocation proof was performed here. In particular,
the ciphertext cap is not proof that adversarial encoded sequence lengths
cannot cause excessive decode work/allocation before rejection.

## 3. Pre-barrier domains and cumulative observations

There is **no production quarantine all-producer registry/barrier** with a
configured global worker/history cap in the inspected paths. Existing local
limits below do not establish that missing contract.

| Domain | Source evidence | What could be retained; count/size classification |
|---|---|---|
| Proposal/Vote signer | `crates/qbind-node/src/binary_consensus_loop.rs:4371-4378,4738-4820,4951-4958,5180-5188` | Bound operation/admission, reservation, consumed continuation, key invocation, signature/completion, retained retry, journal publication and failure/conflict. **P:** guarded routes have their own journal rules; source loop passes journal `None` at `3125-3148`. Do not infer either live signer admission or a zero-size global signing domain from those route refusals. |
| Timeout signer | `crates/qbind-node/src/binary_consensus_loop.rs:7696-7725` | Separate signing surface: admitted request, preimage/binding and key/result/late completion. Proposal/Vote journal limits do not automatically cover it. **U:** quarantine worker/event inventory, backend continuation and retained payload maximum. |
| Journal storage/results | `crates/qbind-node/src/signing_reservation_journal.rs:66-118,358-380,393-439,2356-2363,2683-2689,3310-3316` | **E/P:** retained signature <= 8,192 checked in journal codec; record decode bound is that plus 128. Initialization checks supported position limit 1,048,576; reservation paths check exhaustion. Recovered-ack cache default 128 is process-local journal bookkeeping (`1936-1941`), not quarantine history. These are not a per-quarantine-operation count or guarantee all signer outputs were admitted to that codec. Retaining full signatures, hashes, or references in the marker is **U**. |
| Engine/callback/view/reconfiguration | `crates/qbind-node/src/binary_consensus_loop.rs:3125-3210`; engine application anchors above | Blocks, votes, QC/lock/commit, view/anchor/retry position and callback completion/error. Sequential mutable loop ownership is not ownership of all asynchronous producers. **U:** exact event set, record widths, number of effect observations, typed prefix/current error report. |
| Epoch/storage | `crates/qbind-node/src/binary_consensus_loop.rs:8734-8778`; `crates/qbind-node/src/storage.rs:1042-1080` | Previous/target epoch, block binding, write and sync status independently; failure may follow engine change. **P:** synchronous calls/monotonic cursor in that loop do not bound all writes or cumulative callbacks. Distinguish intentional marker writes from application storage effects. |
| Alternate storage consumer | `crates/qbind-node/src/hotstuff_node_sim.rs:3204-3219` | Per commit, optional block and QC writes then last-committed write, individually fallible. **P:** separate node/simulation path, not assumed executed by binary catch-up; illustrates why generic storage handle users need an inventory rather than copying one path's count. |
| Periodic snapshot | `crates/qbind-node/src/binary_consensus_loop.rs:9135-9245` | Duplicate height suppression; asynchronous spawned task and blocking snapshot, completion/error/abandonment. **P:** one height cursor does not cap distinct heights, queued tasks or retained history across time. |
| Signal snapshot | `crates/qbind-node/src/main.rs:9263-9358`; `crates/qbind-node/src/vm_v0_runtime.rs:175-214` | Signal loop waits for its task; runtime compare-exchange refuses concurrent snapshot on that runtime. **E/P:** one snapshot execution per runtime, not one process-wide worker, not a bound on pending requests or lifetime completion/error observations. |
| Outbound facade | `crates/qbind-node/src/consensus_net_p2p.rs:298-365`; `crates/qbind-node/src/p2p_tcp.rs:2992-3010` | Serialization, enqueue/drop, per-peer worker/send completion and Unknown delivery. Facade `Ok`/`try_send` is not delivery; broadcast clones per peer. **U:** operation's fan-out, peers, messages, bytes and observations over time. |
| Transport workers/queues | `crates/qbind-node/src/secure_channel.rs:830-842`; `crates/qbind-node/src/p2p_tcp.rs:646-646,1827-1834` | **E/P:** per-channel reader/writer queues 32; per-peer ordinary queue 64; raw-frame queue 8 (different traffic). Plus in-service work. None bounds total peers, produced events, retry history or late completion after quarantine. |
| Record fixtures | `crates/qbind-consensus/tests/a33_f1_quarantine_store_interface_tests.rs:4-6,85-139`; `crates/qbind-consensus/tests/a33_f1_marker_filesystem_tests.rs:27-28` | **F:** interface limits 4 prefix entries and 16 evidence bytes/distinct evidence/prefix observations; filesystem LIMIT 65,536 synthetic bytes. No production bound or whole-record encoder is implemented. |

For each retained worker, observation must keep identity/operation/revision,
domain, admitted/cancel-requested/reserved/key-invoked/signature/enqueued
facts as applicable, completion and delivery separately, known effects,
Unknown/conflict and provenance/ordering needed by the reviewed contract.
Which flags, raw results, errors, evidence references or repeated observations
are retained is not yet specified. Error/debug strings and paths are not
bounded marker fields merely because source logs them; an encoding must define
their treatment without silently dropping required evidence.

Finite queue occupancy, one runtime snapshot lock, per-message rate limits
and a finite real deployment do not establish finite **enforced maxima for
the entire unresolved operation**. No production rule currently caps number
of responses, retries, distinct workers, late results, conflicts or observation
revisions retained by this proposed marker. A fixed revision integer would
require checked exhaustion refusal; it is not a chosen observation budget.
Quarantine can last indefinitely. The proposed no-clear slice must refuse new
effects, but work already admitted can still finish; source does not supply
the complete finite producer inventory needed to reserve that evidence.

## 4. Complete record terms and conditional checked formula

No whole-record serialization exists for this proposal. The following is a
capacity-accounting vocabulary, **not an encoding selection**.

Let `LP(x) = L(x) + x` for the specified length framing of a byte/string/list
payload, `OPT(x) = T_option + x`, and `SUM`/`ADD`/`MUL` be checked operations.
Tags, counters and lengths are widths in the eventual encoding, not Rust
`size_of` or an implicit bincode representation.

| Symbol | Complete accounting obligation | Current status |
|---|---|---|
| `H` | Magic/domain tag, total length, format/version, state/discriminant, flags, reserved/padding and fixed top-level framing; excludes lengths already counted by `LP` | **U** exact layout/widths, no codec |
| `I` | Chain/genesis, store/incarnation, operation, writer/session/ownership and binding references | **A/U** identities proposed, allocation/widths/encoding unresolved |
| `R` | Current/predecessor/intent-ack/outcome revision, sequence and optional status fields; operation identity is in `I`, per-response IDs in `B` | **A/U** number/widths and reuse/history rules |
| `A` | Global starting and observed committed anchor, view, lock/QC identity, epoch/validator-set binding and retry position; per-response bindings are in `B` | **A/U** exact count/representation; 32-byte IDs alone insufficient |
| `B` | Retained response/block/QC payload or reference inventory, including rejected/unvalidated material if required | **P/U** per-path inputs above; no universal admitted response cap or retention representation |
| `P` | Completed-prefix IDs/indices, counts, source response, conflicting prefix observations and framing | **U** histories/dedup/representation, see section 6 |
| `C` | Current-item index/identity, refusal/partial insertion/vote/QC/lock/commit status, known/Unknown/conflict evidence | **U** not captured by current engine Result on error |
| `D` | Distinct worker/domain inventories and their cumulative observations/effects | **U** global workers, event counts, payload maxima and conflict representation |
| `UQ` | Rejected/unrecorded input references/diagnostics and unresolved publication observations | **U** owner registry/representation/bound; cannot mark caller bytes durable |
| `Z` | Integrity field and any integrity framing/algorithm identifier | **U** checksum choice/length; corruption detection, not authenticity |

Conditional whole-record formula, with no overlapping terms:

```text
Q = ADD(H, I, R, A,
        LP(SUM[r=1..n_response](ResponseBinding_r + BlockEvidence_r)),
        LP(PrefixEvidence), LP(CurrentItemEvidence),
        LP(SUM[d in domains](
            DomainHeader_d +
            LP(SUM[w=1..W_d](
                WorkerIdentity_dw + WorkerKnownFacts_dw +
                LP(SUM[j=1..J_dw] Observation_dwj))))),
        LP(UnrecordedAndPublicationDiagnostics), Z)

BlockEvidence_r =
    SUM[i=1..B_r](BlockFields_ri + LP(SignerEvidence_ri)
                 + LP(OtherRetainedEvidence_ri))
SignerEvidence_ri =
    SUM[k=1..S_ri](SignerIdentity_rik + RetainedSignerPayload_rik)
```

`BlockFields` includes per-block tags, anchors, view/height/proposer and
other fields actually retained, not merely 32-byte IDs; lengths already
counted by the displayed `LP` terms are excluded. `RetainedSignerPayload=0`
for a record choosing to retain only logical catch-up indices; that choice
has not been approved for the full evidence obligation. Wire certificates
or signer results are different terms. Avoid counting the same complete
response bytes twice if a reviewed record references them rather than
duplicates their contents; references need stable ownership and durable
availability, not just a volatile pointer or checksum.

Compute each length/count conversion with `try_from`, every addition/
multiplication with `checked_add`/`checked_mul` (e.g. checked `u128` sizing),
and reject overflow, unsupported representations or a violated approved cap
before encoding/admission. For the triangular example, check `n+1` and
`n*(n+1)`, divide exactly by 2, then multiply by ID width. Check whole
encoded result against any approved record bound; checking a payload alone
is insufficient. There is no numeric Q maximum here: even `H/I/R/A/Z` widths,
domain count/contents, `B_r` receiver bound, `W_d`, `J_dw`, `n_response`,
conflict histories, evidence ownership and cumulative rules remain unspecified.
**65,536-byte sufficiency is UNESTABLISHED**, not “probably sufficient”.

## 5. Cumulative histories: requirements before a number is valid

| History | Existing enforceable maximum relevant to the marker? | Needed before a numeric record bound |
|---|---|---|
| Blocks from this exporter call | 128 (**P**); received response not capped at 128 | Independent receiver/admission count and rejected-input policy; no new limit imposed here |
| Accepted logical QC signers | `N_i`, or `min(N_i,65536)` on node index path (**P**) | Actual pinned membership/epoch, representable IDs, allowed rejected input and representation |
| Responses per unresolved operation | **U**, one handler invocation is not an operation-history cap | Definition of operation lifetime, response binding, accepted/rejected/empty/stale observations |
| Successive prefixes/conflicts | **U** in production; 16 distinct observations only in fixture | Append-only semantics or complete conflict representation, count/byte admission and late-report behavior |
| Signer/storage/callback/snapshot/epoch workers | **U** globally | All-producer registry, enforced worker fan-out and maximum late output sizes |
| Outbound messages/delivery results | Local queue counts only (**P**) | Max peers/fan-out, admitted/in-service messages, late worker/delivery result inventory |
| Retries/duplicate/late observations | **U** globally | Identity/non-reuse, idempotency equivalence, conflict handling and bounded cumulative rule |
| Revision/error/diagnostic history | **U** | Checked revision exhaustion, maximum events/raw errors or reviewed lossless evidence reference policy |

A capacity reservation would have to cover the full supported maximum before
guarded effects, including outstanding work. Source alone does not establish
such a reservation. No limits are introduced by this inventory.

## 6. User-supplied successive-prefix example and compact alternatives

**User-supplied review observation:** if one record retains every successive
prefix of lengths 1 through 128 as separate lists of **32-byte IDs**, IDs alone:

```text
32 * SUM[k=1..128](k)
= 32 * (128 * 129 / 2)
= 32 * 8,256
= 264,192 bytes
```

This exceeds 65,536 before any list lengths, provenance, bindings, conflicts
or integrity bytes. It is a **conditional example**, not current marker
encoding, an inbound 128-block guarantee or a test of the filesystem prototype.
The interface fixture actually stores distinct `Vec<u64>` prefix observations
and enforces tiny fixture bounds; substituting those widths/caps into a
production example would be unjustified. The arithmetic is checked separately
in documentation validation, not reported as a Rust test.

A **proposed compact alternative**, not selected or implemented, could keep
one immutable canonical prefix of `n` IDs and represent each compatible
observation as `(response/operation binding, revision, prefix length, outcome/
provenance)`. For n=128 and 32-byte IDs, canonical ID bytes alone are 4,096.
That is NOT the whole compact record or evidence equivalence proof:

* All compatible observations must be prefixes of the exact bound sequence,
  not assumed equivalent from equal IDs. If parent, QC, payload, signer/effect
  evidence differ, retain their differences or report a conflict separately.
* Maximum completed length alone preserves a monotone completed prefix, but
  loses which intermediate prefixes were observed, their order, revision,
  provenance and failed/retried recording claims. It is sufficient only if
  a separately reviewed contract explicitly requires that summary rather
  than the complete observation history.
* If every observation must remain reconstructible, bound and retain the
  observation table. A conflicting sequence needs its distinct IDs/content,
  length and provenance; a conflict bit cannot reconstruct conflicting
  payloads. A shared dictionary/trie/delta representation can deduplicate
  common material, but arbitrary conflicts may share nothing.
* Duplicate retries may be coalesced only under reviewed exact equivalence,
  with required multiplicity/order retained if relevant. Receipt identity,
  publication uncertainty, late effects and conflicts must not disappear as
  “same prefix”. The earlier existing-ID-refusal default is unchanged.
* Per-worker sticky known-effect and Unknown/conflict lattice may summarize
  existence/completion safely for stay-closed decisions, but does not preserve
  arbitrary raw signatures, error payloads, ordering or every late observation.
  Complete history versus decision summary is an unresolved retention choice.
* Hash-only references prove neither equality of omitted contents without
  an approved scheme nor durable availability. An external evidence object
  would introduce another bounded ownership/publication/recovery contract;
  none is selected here.

Conditional compact prefix accounting:
`P_compact = LP(n * ID_width) + LP(SUM[o=1..O] CompatibleObservation_o)
+ LP(SUM[c=1..K] ConflictPayloadAndProvenance_c) + PrefixFraming`.
A numeric result needs enforced `n`, `O`, `K`, per-observation/conflict byte
maxima, exact fields/encoding, dedup and lifetime rules, plus all other Q terms.
This can avoid quadratic duplicate-ID storage for compatible histories, but
**cannot be claimed lossless or bounded for unrestricted conflicts/retries/
late effects**. There is no silent-loss compact encoding approved by this task.

## 7. Oversized, unknown or unrecorded outcomes and remaining work

First identify the legitimate active operation from its acknowledged
store/incarnation/operation/writer scope; a foreign token cannot own its latch.
For that operation, latch further mutation **before** fallible current
ownership/revision/payload/encoding checks, per the corrected prototype.
Return rejected payload to its owner or leave the immutable borrowed payload
with that owner, explicitly `RejectedUnrecorded`; do not truncate it to fit,
replace its known effect with NoEffect, or describe it as a durable Unknown
record. Owner retains failure, original prefix/effects and uncertainty
separately from any later smaller retry. Foreign attempts must not mutate
another operation's evidence/latch; their caller owns its own failure.

An unobserved domain remains Unknown; a known effect plus unresolved worker
must preserve both; contradictory observations retain conflict. If recording
fails after visibility, no acknowledgement and no assertion that old bytes
remain. Caller-held rejected evidence is **not crash durable**. Earlier
acknowledged Applying is intended to keep restart closed, not reconstruct
lost evidence. No automatic clear, restart permission or finite-memory
guarantee follows from keeping a process quarantined indefinitely.

Unresolved: complete encoding and integrity field; producer-to-receiver
capacity contract; committee/cardinality/range assumptions; all-producer
barrier/worker fan-out and payload inventory; required raw versus summarized
evidence; bounded conflict/retry/response histories; late-output reservation;
durable external-evidence references if any. None was established from current
source or chosen here. No universal source bound over alternate entrypoints,
backend/hardware worker concurrency or arbitrary signer error payloads was
established. Guessed files `quorum_certificate.rs`, `node.rs`, `commit.rs`
did not exist; relevant QC and storage surfaces were instead located at
`qc.rs`, the binary loop and `hotstuff_node_sim.rs`. No substantive cited
source file was inaccessible. Bincode internals and every alternate node/
signer/backend path were not exhaustively audited.

Only documentation is changed. No production backend/gate/signing/network/
catch-up change, format, protocol limit or clear/resume authority is implemented.
No Rust tests, filesystem checks, crash/power-loss, binary or live operations
were rerun. Required future checks include full encoded size extrema,
arithmetic overflow and count enforcement; rejected/pre-validation input;
cumulative conflict/retry and multiple-worker histories; owner retention and
failed publication; real node caller and later separately authorized storage/
process evidence. They are **not executed** by this inventory.
