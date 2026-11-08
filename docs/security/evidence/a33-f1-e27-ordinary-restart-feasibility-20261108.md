# Initial DevNet: bounded ordinary-restart feasibility

**BOUNDED ORDINARY-RESTART FEASIBILITY — INDEPENDENT REVIEW PENDING.**
No restart policy, production implementation, recovery or participation
authority is approved. Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27
remain **OPEN**; activation **DISABLED**; public DevNet **NO-GO**.

Preflight: repository `olivexo28/QBIND`; local and direct remote `main`
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`; checked-out and direct remote
`docs/a33-f1-e27-stay-closed-next-slice` parent
`22c5ebc551b8ed6568f667f1a7980a0fc115838c`, tree
`185aa85a6b54941ff229d726e64be18f7dfdcecf`. Index, worktree and untracked
status were clean. No applicable `AGENTS.md` was found. This continuation
adds only this file. Final commit/tree are reported after commit.

The [accepted A/B/C and permit/revocation clarification](a33-f1-e27-production-stay-closed-20261108.md#local-owner-and-worker-contract--fencing-clarification)
and [reviewed restart-policy comparison](a33-f1-e27-restart-policy-comparison-20261108.md)
remain unchanged. Nothing here clears unresolved catch-up, Unknown effects
or the proposed one-shot marker. All controls below are **FUTURE / NOT
EXECUTED**.

## Result and proposed local operating assumptions

**Conclusion:** a bounded ordinary restart is *conditionally design-feasible*
under the assumptions below and further implementation, not supported as a
safe validator restart by current production wiring. In particular, existing
component APIs cannot currently establish a complete, durable, corresponding
engine/signing/worker closure. It is not necessary to posit a running remote
signer or invent a new cryptographic construction; neither is established.
If these local assumptions cannot be justified for an actual deployment,
this conclusion does not apply and restart must remain refused.

**PROPOSED profile**, to be decided and evidenced by the owner, not a
present configuration or global guarantee:

1. One operator-controlled host and one validator identity; an existing
   persistent local data volume and local keystore, with directory permissions
   and process isolation restricting write and key use to the intended node.
   The production loader's `LocalKeySigner` is the proposed signing backend;
   no external signer, HSM or second host can invoke or copy the key during
   the run or any restart. No other local CLI, test process or signer-capable
   service uses it.
2. One participating binary and its workers honor one stable destination
   lock object for the whole run and shutdown; no older binary bypasses the
   protocol. The operator does not replace lock/directory objects while held.
   OS/process death releases that local lock, but release itself is not a
   proof of closure.
3. A supported local filesystem/DB profile actually provides the reviewed
   atomicity and durable file/DB barriers, including cross-store ordering,
   with failure surfaced. Power loss and write-cache behavior are separately
   validated or expressly outside the claim. Backups are read-only archives:
   no restore, snapshot rollback, cloned destination, cloned key or live
   second instance is admitted; loss or uncertainty means refusal, not
   recreation. Local checksums cannot enforce this restriction.
4. An independently reviewed local provisioning process establishes the
   exact chain/genesis, validator/key, destination identity and complete
   pre-run signing/safety history. An empty namespace or an operator assertion
   is insufficient. Legacy, copied, foreign or unclassifiable state refuses;
   the exact provisioning evidence and decision authority remain unselected.
5. A complete inventory of protected work covers engine mutations, retained
   safety evidence, all signer families, snapshot/epoch storage, queued
   transport and children; all use the same local owner/ledger and accepted
   final-effect permits. An orderly run has no admitted catch-up attempt and
   no Unknown or unresolved result. Durable signing/safety state corresponds
   to an independently validated consensus history and the current permitted
   configuration. These properties are requirements, not assumptions that
   the current code satisfies.

Under this strictly local, non-adversarial profile, the trusted operating
assumptions and a separately reviewed local lifecycle authorization could
stand in for a distributed lease **only for that profile**. Which principal
may establish history and authorize closure/restart remains an independent
decision; a marker, journal or successful decode is not that authority.
If copied state, hostile rollback, another host or external signer is in
scope, a separately established cross-owner/currentness/fencing mechanism is
necessary; none is selected here.

### Why each assumption matters

| Assumption | Concrete crash or competing-owner counterexample |
|---|---|
| 1: key use isolated | A second process holding the same key signs a conflicting vote while the intended node's local journal remains clean; alternatively an external signer completes after the node times out. A local close cannot establish its outcome. |
| 2: one stable owner | Two processes open different copied directories or an unlinked/replaced lock file and each holds a valid local `flock`; both can invoke the same key. On a crash, automatic lock release can let the second start before the first run's effects are classified. |
| 3: durable non-rollback volume | A completed reservation or closure acknowledgement is lost on power failure or an old backup is restored; a fresh process sees older valid bytes and may sign at a previously used position. CRC and path equality do not expose rollback. |
| 4: known initial history | A copied or previously used validator key is paired with an empty newly initialized journal; after restart it signs an already used position. Empty storage cannot distinguish that from a virgin key. |
| 5: complete covered state and authority | A crash after an uncommitted vote or late timeout signature but before the corresponding safety/ledger record leaves a clean-looking committed height; reinitialization can lose the per-view latch or misrepresent the actual lock. An untracked snapshot worker can publish after a purported barrier. |

These are failure constructions, not claims of a deployed incident. No
single local lock or no-error shutdown rules them out without the relevant
assumption and coverage evidence.

## Current source and evidence inventory

All source links are pinned to main `0d1b56515c52abe2862064027d1a9f103fef5a0c`.

| Boundary | Status and source-supported limit |
|---|---|
| Startup/ownership | **Implemented and wired, locally scoped:** normal data-dir startup holds `restore.lock`, and reset uses its own lock; stateless starts lack one ([`main.rs:2503-2552`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2503-L2552), [`:2222-2267`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2222-L2267)). P2P preflight loads a local signer before network build ([`main.rs:5711-5785`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5711-L5785), [`signer_loader.rs:13-22`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signer_loader.rs#L13-L22)). Locking the data directory does not exclusively lock the key or other copies. |
| Proposal/Vote journal | **Implemented component, unwired in production startup:** reserve-before-sign, exact-result retention/retry, and recovered `Reserved` treated as potentially signed; no authorization, anti-rollback or empty-history proof ([`signing_reservation_journal.rs:1-34`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signing_reservation_journal.rs#L1-L34)). `open` refuses absent or inconsistent metadata and does not initialize on fallback ([`:2340-2445`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signing_reservation_journal.rs#L2340-L2445)). Its ownership domain is per backend instance, not cross-copy/host ([`:1329-1345`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signing_reservation_journal.rs#L1329-L1345)). Production passes no current owner or journal and selects Required/no PV authority ([`binary_consensus_loop.rs:3124-3153`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3124-L3153), [`main.rs:8680-8707`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8680-L8707)). These refusals do not make a restart safe or roll back engine effects. |
| Safety state | **Implemented isolated component, disabled and unwired:** bounded records, local revision-fenced owner and structural/semantic validation; evidence remains unverified, with no production engine, startup, signer or recovery-time crypto integration ([`safety_record_store/mod.rs:1-31`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/safety_record_store/mod.rs#L1-L31)). It cannot alone certify correspondence to journal, chain or current authority. |
| Timeout / NewView | **Separate production path:** P2P requires a timeout verification context and local signer; when enabled and not in restore mode, local timeout calls `sign_timeout_with_chain_id` before engine ingestion and broadcast ([`binary_consensus_loop.rs:7601-7620`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L7601-L7620), [`:7718-7854`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L7718-L7854)). The PV journal is not a Timeout journal. NewView/TC handling and publication are distinct engine/network effects, not automatically a separate signer call; enumerate actual paths before closure. Other key-capable CLI/library entrypoints remain unassessed. |
| Engine restart | **APIs exist; binary integration insufficient:** binary loop constructs a fresh engine and only optionally seeds a snapshot baseline ([`binary_consensus_loop.rs:2820-2854`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L2820-L2854)). `initialize_from_restart` and snapshot initializer reset `voted_in_view` and timeout latch ([`basic_hotstuff_engine.rs:2597-2621`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L2597-L2621), [`:2661-2698`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L2661-L2698)). Committed height is not an uncommitted signing/lock record; source comments asserting safety are not a continuity proof. |
| Durability and closure | **Local precedents, no composed closure:** RTR uses bounded reads and staged sync/rename, with post-rename sync uncertainty ([`restore_completion.rs:455-571`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L455-L571), [`:586-718`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L586-L718)); it is not a catch-up or signing closure. Shutdown waits on some handles, but periodic snapshot is fire-and-forget with an inner blocking worker ([`main.rs:8722-8738`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8722-L8738), [`binary_consensus_loop.rs:9239-9254`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L9239-L9254)). A shutdown return is not a complete join, durable seal or local quiescence proof. |
| Prior test evidence | **Test-only, not production restart:** D7-D2 characterizes lost uncommitted vote/latch and a conflicting engine decision in fixtures ([`run_422_d7d2_signing_state_recovery_tests.rs:1-39`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs#L1-L39), [`:274-365`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs#L274-L365)). D10 real-storage fixture tests include close/reopen and abort after reservation, before signer invocation; opaque signatures and process death are not power-loss or production-wiring evidence ([`run_422_d7d10_signing_reservation_journal_tests.rs:1-30`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs#L1-L30)). Existing accepted test-only models remain scoped to their records, not global fencing or closure. |

## Minimum ordinary-run closure

A possible **future** local contract, applicable only to a run with no
catch-up attempt and no unresolved or ambiguous effects:

Startup classification would occur after acquiring the relevant destination
ownership and before opening protected storage, restore materialization,
reset effects or participation; the reset early-exit path needs its own
post-lock classification. Creating the destination and lock object needed
to acquire ownership is not evidence that the destination is clean.
Stateless/no-data-directory, early CLI and alternate signer-capable paths
remain unassessed and must not be asserted covered. Before a covered
protected effect, the appropriate reviewed durable run intent must already
be acknowledged; its exact representation is not selected here.

1. Under continuously held destination/key ownership, close new admission A.
   Already admitted work remains owned and may finish after A; obtain C by
   positively observing termination of all covered local workers,
   descendants, queued publications and effect permits. Dropped handles,
   a signal, counters or an `Unknown` classification do not prove C.
2. Complete and durably acknowledge every Proposal/Vote reservation and
   result under the exact domain and signer position; unresolved `Reserved`,
   failed/uncertain result writes or untracked invocations block closure.
   Proven no-effect ordinary work may close only through the reviewed
   lifecycle decision; it does not automatically clear an unresolved intent.
   Establish an equivalent reviewed accounting rule for **Timeout** signing,
   plus NewView, local engine mutations, snapshot/epoch writes and transport
   effects. A completed signature may exist without a broadcast. A local
   quiescent worker does not prove an external signer did not act; if an
   external outcome is uncertain, it remains Unknown and closure refuses.
3. Durably retain and validate the actual committed state, lock/QC and
   safety-decision state, per-view anti-equivocation obligations and
   signing-history correspondence; bind them to chain/genesis, validator/key
   and exact run/destination. Establish ordering or an atomic correspondence
   across the stores, not just individual successful sync calls. Missing
   provenance, unsupported verification, corrupt or inconsistent state,
   uncertain barrier or capacity exhaustion refuses. The isolated unverified
   safety record and current fresh-engine startup do not supply this today.
4. Only after these checks may a **separately reviewed lifecycle authority**
   attest that this exact ordinary run is closed and permit subsequent
   independent startup checks. The local profile could rely on an
   independently verified local decision under the stated single-owner,
   non-rollback assumptions; who provides it, its evidence, representation
   and durability are unresolved. If those assumptions are not defensible,
   an independently fenced current authority is required. Neither option is
   selected. Decoding a closure record, an operator assertion, clean exit or
   a local Boolean is insufficient.

Any crash before all closure prerequisites and acknowledged publication
leaves the run unresolved. Even a previously acknowledged marker may be
rolled back under an unsupported volume/backup model, which cannot be
detected from that marker alone. This is **not** a procedure for clearing
the prior one-shot marker; it would require a distinct reviewed lifecycle
and migration decision. No ordinary rejected peer response creates a
persistent latch; the actual catch-up importer remains disabled at dispatch.

## Recommendation and next bounded implementation task

Keep initial public DevNet **disabled**. Existing local components are
promising pieces, but safe bounded ordinary restart is blocked by unwired
PV journal/safety recovery, absent cross-component durable correspondence,
unaccounted Timeout and worker lifetime, unknown provisioning/closure
authority, and unproven filesystem and exclusive-key assumptions. No
production restart should be authorized by this analysis.

**Smallest targeted next task:** implement a non-authorizing,
default-unwired local lifecycle observation seam around the **actual
`maybe_emit_view_timeout_with_auth` signer invocation** and its
owner-controlled execution, exercised with a recording/pauseable test signer.
Track admission, invocation, result (`success`, explicit pre-invocation
refusal, or unknown) and actual worker termination as separate states under
the accepted permit/revocation ordering. The owner must retain an invoked
operation until its executor and descendants can no longer publish; late
results are accounted for and cannot publish under a revoked generation.
Exhaustion or a missing handoff refuses the observation's closure claim.
Wire this seam only into the explicit test/opt-in harness, not a new
production authority or a startup gate. Include a sensitivity mutant for
check-then-revoke and an omitted live child, and assert no actual
operational key use.

This removes a **bounded evidence gap**: the actual local Timeout signer
call can be observed through invocation, revocation and worker completion,
including the unknown/late-result case. It does not by itself establish
durable Timeout anti-equivocation, inventory all other workers, prove power
loss behavior or authorize restart. Follow-on integration must connect
production ownership and durable history only after their separate contracts
and authority are reviewed. The previously recommended all-refusal
classification primitive remains a valid policy-neutral predecessor; this
task identifies the Timeout-lifetime seam as the smallest **restart-specific**
blocker reduction, not a replacement for startup classification.

## Comparison and acceptance evidence

The reviewed [one-shot candidate](a33-f1-e27-durable-intent-contract-20261108.md)
acknowledges `ACTIVE_UNRESOLVED` before a protected run and refuses **every**
later startup even after a clean shutdown. It has a smaller local refusal
surface but deliberately prevents honest validator restarts; losing enough
validators can halt quorum. The conditional ordinary-run direction could
allow restart after proven closure, but requires all above evidence and
dependencies and still refuses crash/Unknown/catch-up. Neither is approved,
and no local-marker scheme alone protects against copies or rollback.

| Control | FUTURE / NOT EXECUTED — required observation and limit |
|---|---|
| Orderly shutdown/restart | Exercise actual admission closure, all tracked workers, signer outcomes, safety/journal sync and independent closure decision; a fresh process must refuse if any item is absent or mismatched. A positive ordinary run requires a fully specified approved authority; a test fixture is not that authority. |
| Process crash | Terminate before/during/after reservation, signer invocation, result sync, safety capture and closure acknowledgement; reopen a fresh domain and refuse unresolved/uncertain records. Process death is not power-loss durability. |
| Uncertain or late signing | Pause an actual test signer through revocation; prove A does not imply C, retain Unknown independently and reject stale publication. A terminated local worker cannot prove an external signer produced no signature. |
| Stale/copy/rollback | Restore an older data directory and copy the key/destination. Demonstrate local bytes can be indistinguishable and refuse unless the selected independent authority can establish current history; no existing local checksum detects arbitrary rollback. |
| Competing ownership | Compete on the same lock, then exercise a copied directory/replaced lock and a second key user. The first must refuse contention; the latter cases demonstrate why the profile's key/host assumptions or a separately fenced authority matter. |
| Capacity/children | Exhaust tracked work and force a late child/handoff; no new effect may start untracked and no C while it can act. Omitted-permit and omitted-child controls must fail the same oracle. |

New execution in this task consists only of source/ref inspection,
documentation/scope checks and branch publication. No Rust tests, node,
deployment or operational signing are run; source, tests, audit register
and prior evidence remain unchanged. No PR or merge is created. Transport,
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**; activation remains
**DISABLED**; public DevNet remains **NO-GO**.
