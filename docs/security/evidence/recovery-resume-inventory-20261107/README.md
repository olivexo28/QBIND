# Authenticated recovery and resume design inventory

**RECOVERY AND RESUME INVENTORY — INDEPENDENT REVIEW PENDING.**

```text
SOURCE_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
SOURCE_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

This append-only source inventory proposes a direction for independent review.
It does not implement a format, verification gate, recovery procedure, durable
quarantine, or clear/resume authority. All `main` links below pin source to the
verified protected commit above. Historical task-branch evidence has its own
revision labels and is not presented as production-main behavior.

## 1. Current boundary inventory

### Restore initialization and stores

Requested snapshot restore is entered only on the configured restore path in
[`main.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L2500-L2578).
Startup takes the local advisory destination lock, rejects an occupied or
invalid restore-transaction record, opens the canonical consensus DB, and
checks the live epoch before materializing account state. The guarded restore
publishes `INTENT`, copies validated snapshot state, appends the local restore
audit line, synchronizes the installed state, persists/barriers the snapshot
epoch, and then publishes `COMPLETE`:
[`snapshot_restore.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/snapshot_restore.rs#L458-L535),
[`snapshot materialization`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/snapshot_restore.rs#L837-L958),
and [`main.rs durability/finalization`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L5210-L5340).
The RTR has bounded reads and staged atomic publication; its checksum and
destination/attempt bindings are local integrity/bookkeeping, not
authentication, currentness, or anti-rollback:
[`restore_completion.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/restore_completion.rs#L1-L40),
[`bounded read/publication`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/restore_completion.rs#L540-L700).
The local `restore.lock` serializes participating processes on that destination;
it is not a cross-host lease or fencing token.

The resulting `RestoreBaseline` uses snapshot metadata `height` and `block_hash`
as an opaque engine anchor; it does not reconstruct historical block data, lock,
QC, vote/anti-equivocation history, or signer journal. Production starts a fresh
engine, then seeds the baseline:
[`main.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L2880-L2904),
[`engine initialization`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L2835-L2860).
Storage APIs exist for blocks, QCs, epoch state and signing records, but the
restore baseline is not a read/verification of consensus history. The signer
journal library is not opened by production startup.

### Inbound dispatch and catch-up application

At actual inbound response dispatch, authenticated transport-origin binding and
response receipt accounting precede the non-empty guard. **Every bound
non-empty catch-up response is refused**, because the response carries no
verifiable constituent QC endorsements. A bound empty response increments its
ignored counter and returns. Neither response reaches peer-height tracking,
restore-mode transition, or state application:
[`binary_consensus_loop.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7390-L7442).
The responder identity is bound to the authenticated session by the peer
binding gate, but this authenticates only which mapped transport peer sent the
frame; it does not authenticate the reported height, a QC, or individual
validator endorsements:
[`peer_consensus_binding.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/peer_consensus_binding.rs#L388-L447).

The response schema has block height/view/parent/id/proposer and a vector of
logical QC signer indices, but no chain/epoch fields, block payload, or QC
signature bytes:
[`p2p.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p.rs#L181-L220).
The engine's public `apply_restore_catchup_blocks` library method checks the
current anchor, contiguous heights/parents, `height == view`, expected leader,
derived block ID and logical quorum membership. It then registers each block
and replays claimed signer indices as votes. It does not cryptographically
verify constituent signatures, and a later error can follow earlier mutations;
it is not transactional:
[`basic_hotstuff_engine.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3954-L4048).
The helper that converts a response and calls this method remains compiled for
direct characterization but is not the current inbound dispatch path:
[`binary_consensus_loop.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L8469-L8567).

The outbound exporter limits responses to 128 blocks. That is an export-only
limit, not an inbound block/endorsement/byte bound:
[`binary_consensus_loop.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L248-L250),
[`exporter`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L8418-L8458).
The generic P2P decoder accepts a `u32` frame length and deserializes a full
message before this handler; no restore-response-specific bound is present at
that boundary:
[`p2p_tcp.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L172-L201),
[`received decoded frame`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L2230-L2260).
This inventory makes no claim about a tighter limit in a lower transport
dependency; the restore-specific allocation bound is not established.

### Restore mode, engine, worker, and signer

Restore mode starts active when a snapshot baseline is configured. The current
dispatch cannot exit it. Its remaining gates are limited: catch-up request
emission, deferral of selected far-future/wrong-parent proposals, and local
view-timeout emission. **Mode can therefore remain active indefinitely and is
not a complete engine, worker, or signer fence.** Leader ticks still run and
mutate the engine before action authorization; single-validator local
self-votes can progress the engine, and configured periodic snapshots may
publish from committed progress. The mode only defers selected proposals:
near-anchor proposals are not blanket-blocked (although the current production
Required policy with no PV authority refuses them before engine delivery).
Eligible inbound Timeout/NewView paths are separately processed. The production
`Required` policy and absent
Proposal/Vote authority suppress the corresponding production signing and
verification routes; they do not undo local engine effects:
[`mode definition`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L2308-L2398),
[`leader/tick dispatch`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L3220-L3300),
[`periodic snapshots`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L3160-L3175),
[`timeout gate`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7550-L7610),
[`production authority policy`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L8680-L8710).

Guarded Proposal/Vote signers require current authorization and a journal before
signer invocation. Those guards fail closed when inputs are missing, but
production supplies no Proposal/Vote authority/current snapshot and no journal;
that is a refusal boundary, not a recovery/resume mechanism:
[`guarded signing`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L4376-L4455),
[`vote signing`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L4956-L5035).
The reservation journal and per-backend `SigningOwnershipDomain` are
library/storage capabilities with local ownership; separate database copies or
hosts obtain separate domains. They do not prove an external exclusive signer
lease or rollback resistance:
[`journal boundary`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/signing_reservation_journal.rs#L1-L35),
[`storage ownership`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/storage.rs#L1698-L1730).

Historical quarantine analysis is retained at
[`empty-response investigation`](../empty-restore-response/README.md) and its
accepted-containment implementation evidence at
[`implementation record`](../empty-restore-response/implementation-20261107/README.md).
These are pinned in their own records to frozen main `541d9a6c9a43fe10410260d9c2494a5fc4416c7a`
and implementation-task source hashes. The implementation evidence records
task base `30a79a21996c11f97f1c496082551dba4cbd3a45` and binds its final
`binary_consensus_loop.rs` test/compile executions to SHA-256
`c3144dcaf5e2afb785062be8828df66ed8e680bd199b7f9ad4e2f01db15496c1` in its
[`manifest`](../empty-restore-response/implementation-20261107/SHA256SUMS).
The 44 selected tests and compilation checks documented there are prior author
executions, **not reruns here**, not release/deployed recovery evidence, and
not proof that mode fences all engine or signer activity.

The accepted safety-record owner design is also historical design evidence:
[`safety_record_store module`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/safety_record_store/mod.rs#L1-L31)
explicitly describes a disabled, isolated component with ownership and
expected-revision fencing, no production caller, and no engine integration,
recovery-time signature verification, or anti-rollback. Its process-local
ownership/revision mechanism is not a distributed signer lease.

For A33-F1 / E27, the historical voting-ancestry package identifies corrected
source producer `e57a337fd5afc5f1bd2f49ea43a50c0a866c86aa` (tree
`09a196c6b85a396c4d8d6b762ed0cbb5a38dad89`) and its separate test-only
observations:
[`voting-ancestry record`](../voting_ancestry/README.md).
That package's cycle fixtures and executed test models are not treated as
production-main ingress evidence or current recovery acceptance. The historical
producer SHA is cited from its retained package and is not asserted to be an
ancestor of this checkout; no A33 test execution is repeated or upgraded to
production/runtime evidence. Current-main
source has a bounded voting ancestry walk with refusal on missing/exhausted
ancestry:
[`hotstuff_state_engine.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/hotstuff_state_engine.rs#L2128-L2180).
The residual A33-F1 / E27 obligations remain open; this inventory does not
repeat or expand their accepted review.

## 2. Evidence required before applying a recovered prefix

The following is a finite design inventory, not an approved wire/persistence
format. Every row must be supplied by an independently trusted source, checked
before state application, and produce refusal if absent, stale, ambiguous, or
unverifiable.

| Required fact | Proposed source and verification point | Trust assumption | Failure behavior |
|---|---|---|---|
| Chain identity and genesis identity | Independently configured/certified network identity plus exact canonical chain/genesis binding in each recovered proof; compare before accepting the checkpoint or any segment. Existing genesis authority construction is a dormant/library candidate, not an activated production source: [`genesis_consensus_authority.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L334-L445). | Trust root is obtained outside the restored/copyable data directory and matches the intended deployment. | Refuse before parse-to-mutation if domain identity is missing or differs. |
| Trusted starting anchor | Independently approved checkpoint/genesis plus block ID, height, epoch, validator-set context, and authenticated finalized-prefix commitment. Validate it against the local expected start before accepting descendants. Snapshot `block_hash` is currently only an opaque parent ID, not this proof. | At least one starting anchor remains authentic and its approval policy is current. | Refuse; do not infer trust from snapshot metadata, a peer response, or matching local height. |
| Validator set and authority | Authenticated epoch-specific membership, public keys, suite policy and voting weights, derived from trusted genesis or an already verified transition. Bind the exact set/context to every endorsement. | Validator configuration is authentic, current, and not self-asserted by responder. | Refuse unknown/ambiguous members, unsupported suites, missing keys, or inconsistent set identity. |
| Individually authenticated endorsements or reviewed equivalent proof | A reviewed verifier over each constituent signature (or an independently reviewed proof system) before a QC/finality certificate can affect state. The existing domain-aware QC verifier checks chain ID, epoch, signer bitmap/signature correspondence, signatures and weighted quorum, but catch-up does not call it: [`qc_verify_domain.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L848-L912), [`core checks`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L959-L1128). | Verification context comes from the independently trusted authority row, not certificate fields. | Refuse the entire candidate batch before any commit/lock/store mutation. |
| Ordering, continuity, and contents | Verify every expected height, parent, view/consensus rule, block identity and required payload/application commitment from anchor to tip. The current derived block ID commits only to proposer, view, and 16 bytes of parent ID; do not treat it as a payload/content commitment. | Deterministic canonical encoding and execution rules are fixed by the reviewed protocol. | Refuse any gap, duplicate, mismatch, overflow or unbound payload; no valid-looking prefix may leak from a failed batch. |
| Consensus finality | Verify the protocol's reviewed HotStuff finality relation (including required QC/lock/three-chain or equivalent semantics) under the exact epoch's authority, rather than equating a responder height or isolated quorum-shaped signer list with finality. | Finality rule and fault threshold are reviewed and match the actual deployment. | Refuse without a complete finality witness; never promote an arbitrary peer-selected tip. |
| Epoch / validator-set transitions | Verify each transition in order under the previously authorized set, validate the transition's exact new set and effective boundary, then verify subsequent certificates under that new set. Old/new overlap and transition finality require an explicit protocol decision. | Transition policy and source authority are independently pinned; no latest-set retroactive verification. | Refuse transition gaps, conflicting sets, missing old-set authorization, or unsupported overlap rules. |

Transport authentication and validator endorsement authentication are distinct.
The peer-binding gate identifies a mapped transport peer. It does not prove that
the peer's reported committed height is true, that other validators endorsed
the data, or that a quorum certificate is valid. A signed checkpoint likewise
proves only the state it authenticates under its signing authority; without an
independent freshness/currentness source it does not prove that no newer
authorized state exists.

## 3. Currentness, durability, and ownership

**Currentness is separate from authenticity.** A design would need an
independently authorized source that can establish the currently valid
authority/epoch and reject superseded checkpoints (for example, an externally
protected monotone authority record or an authorized online/operational lease).
No such production authority/currentness service is established here. An RTR,
database revision, local generation, checksum, wall-clock timestamp, transport
identity, or copied directory all remain in a rollback/copy domain controlled
by whoever can restore that state. Matching them locally cannot prove freshness.

The affected local stores and boundaries are distinct:

| Store/effect | Existing role and boundary |
|---|---|
| RTR (`RESTORE_TRANSACTION.rtr`) and destination lock | Local restore attempt `INTENT`/`COMPLETE`, bounded read, atomic file publication and process-lifetime advisory lock. No external authority, global lease, or rollback proof. After rename but failed directory sync, the final record may already have changed; next startup classifies observed bytes and refuses uncertainty. |
| Account state and `RESTORED_FROM_SNAPSHOT.json` | Snapshot directory copy and appended audit line are separate effects. Copy/marker failure can leave partial files; the guarded path retains/refuses through `INTENT`. The audit line is not a signed recovery certificate. |
| Consensus DB (RocksDB) | Epoch values have synced write/barrier support for restore completion; epoch alone is not consensus/signer history. Block/QC/last-committed storage APIs do not imply that the fresh production engine restored and authenticated those records. |
| Signing namespace | Synced reservation and accounting APIs exist in the library. Production recovery does not open or reconcile this namespace before enabling signing; even a successful local journal write is not external currentness or global signer fencing. |
| In-memory engine and inbound evidence | The current network catch-up importer is unreachable from actual response dispatch. The callable engine importer registers and processes blocks sequentially; an error on a later block does not undo earlier effects. No multi-store transaction joins engine, account state, RTR, epoch and signer records. |

Restore publication has explicit crash windows: intent before copy; account
copy and marker append; tree sync; epoch synced write/barrier; atomic COMPLETE
replacement and parent-directory sync. A process termination can leave an
interrupted attempt, and a failure after replacement has an uncertain observed
outcome; no stage should be interpreted as success without its acknowledgement
and subsequent authoritative classification. The current restore flow is
synchronous, but a future cancellable recovery worker must treat cancellation,
late completion, ambiguous I/O outcomes, process restart, and loss of its
destination/signer ownership as refusal conditions until reconciled. A timed-out
or cancelled signer call may have completed; it must never be treated as
"definitely unsigned." Any proposal must specify a durable intent/evidence
boundary and all affected stores before mutation.

Unknown or missing evidence must remain an explicit refusal. In particular,
neither an empty journal nor an absent/corrupt record can be success-shaped
"no prior signing" or "no effect."

## 4. Preconditions for signing or participation resume

Successful verification/application of bytes and completion of catch-up are
not authority to participate. Before any signing or consensus participation
resumes, an independent decision must establish all of:

1. Recovered chain/genesis, trusted anchor, complete consensus finality and each
   epoch/set transition have been verified and durably published without
   partial application.
2. The recovered safety state (including lock and any anti-equivocation
   obligations) corresponds to the full retained signing history. Conflicting,
   reserved, uncertain or partially acknowledged signing positions remain
   blocked unless a separately reviewed recovery rule proves a safe disposition.
3. The currently authorized chain/epoch/set/key/suite is independently current,
   not merely self-consistent with copied local data.
4. Exactly one authorized signer owner holds a current, fenced capability.
   Ownership loss invalidates all stale workers and late signer results; copied
   databases/hosts cannot each obtain an apparently independent local lease.
5. A separately authorized, independently verifiable clear/resume decision
   binds the exact recovered-state identity, authority epoch, signer owner/fence
   and intended participation scope. The decision is distinct from checkpoint
   verification and data application.

A mode flip, matching height, local checksum, transport identity, successful DB
write, completed download, or valid signed checkpoint alone grants none of this
authority. If any fact cannot be established, remain quarantined/refuse signing
and participation.

## 5. Bounded options and acceptance plan

| Option | Safety assumptions and liveness cost | Missing prerequisites and failure handling |
|---|---|---|
| **A. Continued refusal; no automatic resume** | Preserves current non-empty response refusal and ignored-empty containment. No unverified peer height changes the mode. Simple fail-closed posture; restored nodes may remain in mode indefinitely, continue eligible request attempts, defer selected proposals and suppress local timeout emission. | No authenticated recovery path or resume authority. Refuse ambiguous evidence and leave state unchanged where the actual path can guarantee that; do not offer timeout/height fallback. Operator availability remains intentionally unavailable. |
| **B. Proposed verified recovery, then separate resume decision** | Could restore liveness only if the independent chain/authority/currentness, finality, signing continuity, durability, resource and ownership assumptions are all met. Recovery validation is not the resume decision. | No selected proof format, trusted-currentness source, epoch transition policy, inbound complete-evidence budget, atomic application/reconciliation protocol, cross-copy fencing mechanism, or independently authorized clear/resume authority exists. Any missing, stale, cancelled, late, partially applied, or uncertain result refuses and preserves quarantine. No implementation authorized by this inventory. |

**Resource bounds are prerequisites, not selected values.** An eventual protocol
must impose checked limits on total wire bytes, block count, per-block and total
endorsement count/bytes, payload bytes, certificate/proof bytes, nesting,
verification CPU, concurrent requests, retained evidence, and durable staging.
Apply the byte/frame bound before reading or allocating a complete frame; apply
bounded deserialization before nested `Vec` allocation; recheck count/aggregate
bounds before constructing engine objects or invoking crypto; and reserve
retained/durable capacity before publication. Failure to reserve at any stage
must refuse before effects and release provisional resources. The current 128
block outbound export limit is not an inbound/evidence cap. The existing QC
verifier's own count/byte limits are useful library constraints only when the
actual ingress invokes that verifier; they do not bound the current catch-up
wire decoder or make the legacy logical-signer importer authenticated.

| Acceptance stage | Required evidence | Status in this inventory |
|---|---|---|
| Design/input contract and exact-source review | Independent review of trust assumptions, encoding/domain, proof, limits, epoch transitions, refusal semantics and effects | **FUTURE / NOT EXECUTED** |
| Test-only verifier | Real signature/proof controls, chain/epoch/set mismatch, duplicate/missing endorsements, bad finality, transition boundaries, overflow/oversize and no-effect refusal | **FUTURE / NOT EXECUTED** |
| Actual inbound caller | Authenticated transport plus actual recovery verifier; prove no pre-handler allocation bypass and no mutation/publication on every refusal | **FUTURE / NOT EXECUTED** |
| Apply/restart/crash | Staged atomic application, each crash/write/rename/barrier/cancel/late-result boundary, fresh-process reopen, rollback/copy and ambiguous-outcome refusal | **FUTURE / NOT EXECUTED** |
| Signing history and fencing | Reconcile lock and all signing positions; uncertain signer results; competing process, copied data, stale owner, lease expiry and fence rejection | **FUTURE / NOT EXECUTED** |
| Separately authorized resume | Verify explicit independent resume decision after data verification, under the exact current authority and fenced signer owner | **FUTURE / NOT EXECUTED** |
| Release binary/configuration | Exact release artifact/config with required authority; prove actual dispatch, storage, signer and resume paths fail closed | **FUTURE / NOT EXECUTED** |
| Multi-node evidence | Multiple independently managed nodes, real authenticated transport, epoch/validator transitions, quorum/finality and operational currentness/fencing evidence | **FUTURE / NOT EXECUTED** |

Retained author executions are not new acceptance rows: the cited empty-response
package records 44 selected tests and production compilation at its own source
hashes. These are historical author evidence only; no unchanged Rust test or
compile was rerun for this docs-only task. They are not recovery acceptance,
release-binary execution, deployed recovery, external currentness, or activation.

## 6. Open decisions and disposition

Independent reviewers must still decide the trusted anchor/currentness source,
validator-authority and transition rules, exact finality evidence, bounded wire
and staged-state limits, failure atomicity/reconciliation, external owner/fence
semantics, signer-history recovery rule, and which independently authorized
principal may issue a scoped resume decision. None is selected or implemented
here.

This inventory updates no audit-register finding. The audit register and all
prior evidence remain byte-identical. No Rust tests, compilation, live node,
network experiment, operational signing, activation, merge, or PR was run or
authorized in this task.
