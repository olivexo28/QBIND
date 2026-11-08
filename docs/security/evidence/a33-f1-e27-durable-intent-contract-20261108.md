# A33-F1 / E27: bounded durable intent and startup classification

**DURABLE INTENT AND STARTUP CLASSIFICATION CONTRACT —
INDEPENDENT REVIEW PENDING.** This is a candidate for review, not
implemented behavior or approval to participate. The accepted stay-closed,
no-automatic-clear direction and the A/B/C fencing clarification and
permit/revocation ordering at `405297a0e791d1f9db9898323495902e26e46d82`
are **PASSED/CLOSED within documentation scope**; neither is reopened.
Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**.

## Identity, scope and evidence

Preflight identified repository `olivexo28/QBIND`, local and direct remote
`main` at `0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`, and local, checked-out and
direct remote branch `docs/a33-f1-e27-stay-closed-next-slice` at parent
`405297a0e791d1f9db9898323495902e26e46d82`, tree
`e846c9b2766203e42fe2bb4052b629aee4e44555`. Index, worktree and untracked
status were clean. No applicable `AGENTS.md` was found. This continuation
adds only this file; parent and final commit/tree are reported separately
after commit, not embedded as a self-referential identity.

All source references below are pinned to main `0d1b56515c52abe2862064027d1a9f103fef5a0c`.
The [accepted local owner contract](a33-f1-e27-production-stay-closed-20261108.md#local-owner-and-worker-contract--fencing-clarification)
remains unchanged. The one-shot startup marker below is a **new candidate
policy choice** with a larger availability cost than merely marking a
catch-up attempt; it is not asserted to be previously accepted or currently
implemented.

## Source boundary and assumptions

* Normal startup creates the configured data directory and acquires the
  process-held, nonblocking local destination lock at
  [`main.rs:2503-2552`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2503-L2552).
  Requested restore can open consensus storage at
  [`main.rs:2617-2630`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2617-L2630)
  before materialization; the RocksDB opener uses `create_if_missing(true)`
  ([`storage.rs:744-758`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/storage.rs#L744-L758)).
  The ordinary RTR guard is much later, after metrics setup, and admits
  absent RTR ([`main.rs:5005-5065`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5005-L5065)).
  It is not a catch-up-state guard.
* The separate authority-reset path acquires its own lock at
  [`main.rs:2222-2267`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2222-L2267);
  it exits before the normal path. First-class `identity` dispatch is earlier
  still ([`main.rs:2010-2025`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2010-L2025)).
  Reload-check, peer-candidate and reload-apply CLI exit modes can open
  storage themselves ([`main.rs:2554-2582`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2554-L2582)).
  Stateless/no-data-dir startup has no destination lock. The identity
  command's effects, other early exits, direct library callers and alternate
  binaries are not exhaustively assessed: they must be inventoried and
  classified as harmless or gated/refused before coverage is claimed.
* Existing RTR uses a canonical UTF-8 destination path, a bounded record
  reader and a file-sync, rename, directory-sync publication sequence:
  [`restore_completion.rs:148-175`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L148-L175),
  [`:455-571`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L455-L571),
  [`:586-718`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L586-L718).
  Its no-follow final-component open and regular-file check, bounded read
  and differentiated post-rename failure are useful precedents, not a new
  catch-up record. Guarded snapshot restore publishes its own intent before
  copy ([`snapshot_restore.rs:438-535`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/snapshot_restore.rs#L438-L535)).
  RTR `COMPLETE` says nothing about catch-up, external effects or signing
  history. Its POSIX sync guarantees are assumptions, not demonstrated
  power-loss guarantees ([`restore_completion.rs:13-33`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L13-L33)).
* The local `flock` only coordinates participants holding the same lock
  object ([`restore_completion.rs:800-905`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L800-L905)).
  This candidate assumes a stable, non-adversarial destination and that all
  relevant local participants honor that lock and the new protocol. A copied
  store, another host, a replaced lock object, hostile rollback or a signer
  accessible outside this owner violates or escapes those assumptions.
  Nothing here supplies global exclusivity, authentication or currentness.

## Candidate profile: provision once, mark before protected work

**Proposed, not owner-approved:** a separate fixed-schema file named
`CATCHUP_STAY_CLOSED.v1`, under the destination directory and its held
ownership, with one final record and a separate staging file. It is not the
snapshot RTR. The lifecycle owner is its only writer; the accepted local
coordinator owns the live admissions, permits and outstanding ledger.

The conservative reason for marking **every protected run**, not only a
later catch-up attempt, is the crash window: an older `CLEAN` record after a
failed or unacknowledged intent publication cannot reveal pre-existing
in-flight work. The candidate therefore permits no covered participation,
signing, protected storage/restore/reset effect or worker admission on a
fresh process until an `ACTIVE_UNRESOLVED` record has been acknowledged
durable. This marker is written because a protected run is starting, **not**
because a peer sent a rejected response. It is sticky, including after a
clean shutdown and even when no work occurred. A later catch-up attempt may
replace it with `ATTEMPT_UNRESOLVED` only under the accepted A/B/C ordering;
no importer is enabled. Both unresolved states refuse the next startup. This
is a deliberate one-shot availability cost, not a claim that a normal
startup without this marker was previously unsafe or a recovery policy.

### Wire record and bounds

Use the following exact candidate encoding: fixed-width unsigned integers are
big-endian; no counts or nested lists; exactly one record and no trailing
bytes. Fixed overhead is **126 bytes**; the sole variable field is at most
**4096 bytes**, so maximum record size is **4222 bytes**.

| Field, in order | Bytes and validation |
|---|---|
| Magic | 8 ASCII bytes `QBCUSI01`. |
| Version | 2; only `1` accepted. Unknown version refuses, never migrates. |
| State | 1: `0` = `PROVISIONED_CLEAN`, `1` = `ACTIVE_UNRESOLVED`, `2` = `ATTEMPT_UNRESOLVED`; other values refuse. |
| Flags | 1; bit 0 is anchor-present, all other bits zero. |
| Destination length | 2; 1..4096, checked before offset arithmetic or slicing. |
| Provision identity | 16 bytes, nonzero CSPRNG-generated opaque identifier; failure to generate refuses. |
| Run/attempt identity | 16 bytes; all zero for `PROVISIONED_CLEAN`, nonzero freshly CSPRNG-generated for each `ACTIVE_UNRESOLVED` or `ATTEMPT_UNRESOLVED` publication. Generation failure or equality with any locally retained ID refuses; no global uniqueness is claimed. Identity is bookkeeping, not a lease. |
| Chain label | 8-byte configured local numeric chain ID; compare to the configured value before classification. It is a domain label, not a trusted chain commitment. |
| Anchor height and block ID | 8 + 32 bytes. When anchor-present is zero both fields must be all zero; when one, retain the exact locally supplied anchor. `PROVISIONED_CLEAN` and `ACTIVE_UNRESOLVED` require absent anchor; `ATTEMPT_UNRESOLVED` requires present anchor or refuses before publication. This preserves even a zero-valued present anchor distinctly. |
| Destination | Exactly `destination length` UTF-8 bytes of the absolute, canonical `data_dir` path; no NUL. Compare byte-for-byte to the canonical path obtained under the held lock. Failure to resolve, non-UTF-8, length above 4096 or mismatch refuses. |
| Checksum | 32-byte SHA3-256 over all preceding bytes, checked after exact-length validation. Detects accidental corruption only; not a MAC or authority. |

The 4096-byte path and 4222-byte total are explicit small local bookkeeping
caps, consistent in scale with the existing RTR's 4096/8192 caps, not
measured deployment needs. Owner review may choose a different cap before
implementation; no truncation or hash-only path fallback is allowed.
Comparing a canonical path binds the local name, **not** a filesystem
identity or protection against copied state at the same path. The candidate
requires the opened destination directory and lock to remain the same
objects through classification/publication; use directory-relative
operations and verify identity/ownership without a path-check-then-follow
race. If the required platform semantics or stable binding cannot be
established, refuse. Resolve an initially configured alias to the canonical
path; moving the destination changes the binding and refuses. Neither path
nor checksum proves authenticity, freshness, signer ownership or anti-rollback.

The reader opens the authoritative final component once using no-follow and
nonblocking semantics, verifies the opened object is a regular file, and
reads at most **4223 bytes** into a bounded buffer; it never allocates from
metadata or any encoded length. The extra byte detects excess input even if
the file grows. Open/stat/read failure, including partial I/O, refuses;
symlink (including dangling), FIFO, device, directory or unsupported
platform refuses. A genuine missing final file is **absent**, not clean.
After read: reject >4222 before decode; require the 126-byte minimum; check
magic/version/state/flags; bound length, use checked endpoint arithmetic
and exact total length; check state-dependent canonical zero fields and
checksum; then compare destination and chain label. Reject truncation,
trailing bytes, invalid UTF-8, bad checksum and unknown tags. No parser
fallback or partial success. These are candidate requirements, not claims
that RTR's private helpers already meet all new requirements.

### Provisioning and deterministic classification

`PROVISIONED_CLEAN` is a one-use **bootstrap classification**, not proof of
safe participation. It may be installed only by a separately reviewed,
offline provisioning procedure under the same ownership, on a demonstrably
new destination before any protected run, with an independently established
history that the associated signer/identity has no prior unresolved work.
Creation must refuse existing state, existing records or ambiguous history;
do not infer virgin history from an empty directory or a new key file.
Provisioning authority, evidence and procedure are not selected here; until
they are approved and implemented, even a plausible clean record is not
eligible. Legacy/copy/migration is **refused** unless a separate future
review establishes history and an authorized migration procedure; this
contract selects no such recovery. Existing snapshot RTR `COMPLETE`, a
checksum, matching heights or an operator assertion alone are not sufficient.

| Observed state under ownership | Candidate classification and outcome |
|---|---|
| Strictly valid `PROVISIONED_CLEAN`, same destination/chain, no staging ambiguity, eligible under approved virgin provisioning | `ProvisionedClean`: eligible for the one-shot transition only; write and acknowledge `ACTIVE_UNRESOLVED` before any protected effect. It grants no signer or consensus authority. |
| Final absent, including a new, legacy or unprovisioned directory | `UnprovisionedOrUnknown`: refuse startup/reset/protected work; no auto-create, no clean inference. |
| Strictly valid matching `ACTIVE_UNRESOLVED` or `ATTEMPT_UNRESOLVED` | `Unresolved`: refuse startup/reset/participation; preserve bytes and diagnostics. Do not clear even after a known no-effect attempt. |
| Wrong canonical destination or configured chain label | `Foreign`: refuse regardless of state. |
| Truncated, oversized, malformed, unsupported version/tag, invalid checksum, trailing data, invalid fields or non-regular/symlink final object | `Invalid`: refuse, preserve evidence; report a bounded reason without secret data. |
| Unreadable/partial-read/lock failure or unsupported semantics | `Unavailable`: refuse, never map to absence. |
| Any staging artifact, inconsistent objects, missing ownership or otherwise unclassifiable state | `Ambiguous`: refuse without promotion, deletion or cleanup. |

The classifier does not equate any record with trusted currentness, a complete
signing history, an exclusive signer or a verified recovered prefix. Safe
startup still needs all separately applicable security gates. The exact
authorization of provisioning and the policy for its evidence are
implementation blockers, not an implicit operational ceremony.

### Publication, failure and local work accounting

Under held destination ownership, open the destination directory and
exclusive staging file without following links; refuse a pre-existing staging
entry. Encode the bounded record only after its fields and destination
binding are checked. Write the entire staging file, sync it, atomically
rename within the same directory over the final entry, then sync the directory;
acknowledge only after all steps succeed. Retain the lock throughout. The
supported profile requires a reviewed local filesystem with reliable file and
directory sync and atomic same-directory rename; it fails closed elsewhere.
An error before rename leaves the observed prior final unchanged under this
profile, but a staging artifact may exist; after rename or an ambiguous
rename result, final bytes may already have changed. A directory-sync error
means the durable outcome is unknown. Refuse and retain any artifacts; do not
claim the previous record survived, promote a temporary file, or resume.

On startup, after the lock and classification, publish and acknowledge
`ACTIVE_UNRESOLVED` **before** opening protected consensus storage, invoking
restore/reset effects, starting participating services or admitting protected
workers. Before classification, this assessed path permits only configuration
and identity inputs needed to locate and classify the destination, bounded
record reads, diagnostics, and the directory/lock-file creation and lock
acquisition already needed for ownership. No consensus database open,
restore/reset mutation, network participation, signing or snapshot
publication is permitted. Classification itself never writes the record.
On an allowed local catch-up attempt, close admission A using the
accepted coordinator; publish and acknowledge `ATTEMPT_UNRESOLVED` before
any catch-up mutation and before relying on C; no call to the existing
importer or replacement is permitted in this slice. Pre-existing workers
remain tracked through permits until the barrier is proven; they may finish
after A, and the already-acknowledged `ACTIVE_UNRESOLVED` makes restart
refuse if the attempt publication fails. `Unknown` is not C. Both actual
empty and non-empty response dispatch returns remain unchanged and neither
creates or updates this file.

If a process dies before the startup marker acknowledgement, the ordering
prohibits any protected work by that process. Under the stated sync and
non-rollback assumptions, startup may observe a valid clean final without a
stage, an unresolved final, or an ambiguous stage; only the first is
eligible to repeat the transition and only if the independent provisioning
assumptions still hold. A crash or error after acknowledged
`ACTIVE_UNRESOLVED` must lead to refusal, not clean. This is a **required
durability invariant under the specified filesystem assumptions**, not
evidence that power loss actually satisfies them. A missing/rolled-back
marker after an acknowledged write violates those assumptions; a local
reader cannot detect it from clean bytes alone. Competing old binaries,
copied directories and out-of-process signers are outside that invariant.

Candidate live ledger: a preallocated fixed table of **256 operation slots**,
each holding one fixed-size operation identity (16 bytes), parent identity
(16 bytes; zero means root), owner incarnation and generation (8 bytes
each), effect class, worker/permit state and separate effect outcome tags.
There are no variable-length strings or child lists in entries; children
occupy their own slots. Reserve the parent/child slot and all needed
accounting before queueing or invoking an effect, with atomic handoff under
the coordinator. IDs and counters never wrap or get reused in an
incarnation; invalid tags, exhausted IDs, capacity or failed reservation
close admission and refuse the new work before its effect. Existing
in-flight entries remain owned and drain normally; do not drop one to make
space. Retain unknown outcomes as occupied entries even after local
quiescence, so C and B remain distinct: a terminated entry with no capable
descendants or permits is not in the live-operation set tested for C, but
its slot remains occupied as an unknown-outcome tombstone. A full table may
block indefinitely.
The cap is a conservative proposed control-plane bound, **not** a measured
safe concurrency setting or a whole-node byte/queue/payload budget; exact
entry layout, allocation overhead, queue sizes and supported workload still
need review. If unavoidable downstream work cannot be accounted for within
the cap, refuse to start it rather than silently exceed the bound.

The live table is **not** persisted in this candidate. An acknowledged
unresolved record survives as a coarse refusal on restart; individual
operation IDs/outcomes may be unavailable after a crash. Treat that loss as
unknown, not as an empty ledger or proof that a signer did not act. A future
reconciliation mechanism would need separately reviewed durable evidence;
it is not selected here. The owner must report capacity/accounting failure
and effect uncertainty distinctly from metrics; bounded diagnostic counters
do not prove C or reconstruct lost work.

## Review decisions, alternatives and liveness

Reviewers must decide whether the one-shot cost is acceptable. Every
protected start consumes the provisioned clean state; a restart, normal
shutdown, no-effect local attempt or reset leaves the destination refused.
An honest restored node may also remain in restore mode indefinitely.
Availability and quorum can be lost; no deployment liveness is measured.
Unlike an alternative that writes intent only at catch-up entry, this
candidate covers a crash with already-admitted local work by ensuring a
sticky marker was acknowledged before that run's protected work began.
That alternative has lower restart cost but requires an independently
reviewed durable accounting/signing-history mechanism to avoid interpreting
an old clean record as evidence that prior work had no effect. A durable
per-operation journal or external monotonic service are other possible
designs, not selected or presumed available.

Before implementation the owner/reviewer must decide: provisioning
identity and independent history evidence; exact startup/CLI coverage;
platform and directory/lock object semantics; record and ledger limits
against real workloads; how every worker and queue is inventoried and joined;
handling of local signer results and external signer authority; and
whether/how to validate filesystem durability. The fixed profile above is a
concrete review candidate, not an owner-approved policy or a claim that the
missing dependencies are solved. Clear/resume authority, authenticated
recovery/currentness, cross-host signer fencing, copy/rollback resistance,
resource bounds beyond this record/ledger, and operational activation remain
separate OPEN obligations.

## Acceptance matrix — FUTURE / NOT EXECUTED

Assert actual effects and persistent bytes independently from diagnostics and
counters, using the real startup/owner boundary and bounded fake I/O:

| Control | Required outcome and limitation |
|---|---|
| Record read and decode | At 4222 and 4223 actual bytes, growing source, lying metadata, short/partial I/O, every truncation and trailing byte, bad magic/version/state/flags/checksum/path, special files and symlinks: bounded 4223-byte read before length-directed allocation; exact refusal. Proves tested local reader bounds, not whole-node memory. |
| Provisioning and absence | Approved virgin clean fixture takes only the clean-to-active transition; absent, unprovisioned, legacy, non-virgin or unverifiable histories refuse before protected effects. Clean is not participation authority. |
| Ownership and binding | Two contenders for one supported destination: one owns, the other refuses; wrong path/chain and path-object replacement/alias cases refuse as specified. Does not prove cross-host or copied-store exclusivity. |
| Publication failures | Inject each open/write/file-sync/rename/directory-sync failure, plus unknown rename and staging residue. Verify retained bytes, stage-specific error, no new protected work and refusal where state is ambiguous; never assert post-rename rollback. |
| Process death | Kill before and after staging, file sync, rename, directory sync, acknowledgement, admission and attempt write; restart fresh without restore flags. Assert clean only when transition had not been acknowledged and protected work never began, otherwise unresolved/ambiguous refusal. Process-kill is not host power-loss evidence. |
| Peer rejection | Real empty and non-empty dispatch, including binding rejection, preserves prior accounting and produces no record write or change; compare against an already active marker as well as a no-marker fixture. Proves only those dispatch paths. |
| Restart/reset | Matching unresolved, invalid, foreign, unavailable, absent and staging-ambiguous cases refuse before assessed storage open, restore, reset, network and signer-capable effects; test each assessed mode and explicitly mark unassessed modes. |
| Ledger and late work | Exhaust slots/IDs, fail handoff, hold a worker across A, return late/unknown signer result, and lose owner. Require refusal without untracked effect, preserve B independently from C, never publish stale result; detect omitted permit/child tracking via sensitivity mutants. This cannot prove an external signer stopped or global exclusivity. |

New execution in this task is limited to Git/ref checks, source inspection,
documentation/scope checks and branch publication. No unchanged Rust tests,
node, deployment or operational signing are run; all controls above remain
**FUTURE / NOT EXECUTED**. No production source, tests, manifests, lockfile,
audit register or historical evidence is changed. No PR or merge is created.
Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**.
