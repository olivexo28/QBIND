# QBIND — Storage path-encoding refusal proposal and future test matrix

**DOCUMENTATION-ONLY PROPOSAL FOR OWNER REVIEW — NOT APPROVED OR
IMPLEMENTED.** This document considers refusing storage paths that cannot
be represented without loss when passed to the current RocksDB wrapper. It
selects no production error contract, migration, recovery procedure, or
Candidate B authority.

Path representability is only an encoding property. It does not authenticate
or bind a filesystem object, prevent symlink or namespace changes, establish
ownership or fencing, or guarantee that a representable path exists or opens.
The existing no-replacement-database finding, CB-1, CB-FIXTURE-1, and
author-run characterization remain within their accepted scopes. A23-F1 and
A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet remains
NO-GO.

## 1. Pinned basis and scope

| Reference | Revision |
|---|---|
| Main source baseline | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed guard-to-storage characterization | `4ca2839796e27b8384ff6b4b12e21ab9d3b2fccf`, tree `50a406a986cf830cdc2d166e4a30ba29440a2aa6` |
| Characterization test-source commit | `7af0d66578ea3e538f24dde3e67b0895ee2766cd`, tree `9d714c32e82bde478485b3a5d9ed712b7e41092f` |
| Reviewed path-encoding source qualification | `docs/security/evidence/a33-f1-candidate-b-existing-destination-authorization-contract-20261109.md` at the reviewed characterization endpoint |
| Owner-approved scoped pre-ownership boundary | `docs/security/evidence/a33-f1-candidate-b-pre-ownership-gate-spec-20261109.md` at reviewed characterization endpoint `4ca2839796e27b8384ff6b4b12e21ab9d3b2fccf` |
| Upstream wrapper source inspected by the prior review | rust-rocksdb v0.22.0 commit `e523ca4a13a7bf364abd0743149d0b3cd40856c0` (`src/db.rs`, `src/ffi_util.rs`) |

Source line references below are pinned to main. The characterization
document retains the complete author-run outputs, source-at-run identity,
environment and dependency evidence, including the initial compile failure
records and the qualification that their shell exit codes were not captured.
Those observations are not an ordinary node invocation or an attack.

The retained characterization reports that the actual
`evaluate_ordinary_startup(raw_alias)` guard returned `ProceedComplete` for
a non-UTF-8 symlink spelling whose canonical target was the in-root UTF-8
destination. The separately called account `open_existing` API returned
the marker at the alias's lossy spelling, not the intended destination's
distinct marker. This is author-run Unix/ext4 synthetic evidence
(`docs/security/evidence/a33-f1-nonutf8-complete-guard-storage-characterization-20261109.md`,
with raw output in the neighboring `*-focused-output.txt` file); it does not
show that an ordinary node invocation reaches the sequence.

## 2. Proposed direct storage API contract

### Contract invariant

For each covered account and consensus storage entry point, the path checked
for lossless representability must be the exact captured path value later
passed to `rocksdb::DB::open`. The check and use must share one captured
value; a wrapper must not check one generic `AsRef<Path>` evaluation and
then independently evaluate that input again for the open.

Conceptually, a future implementation could capture the borrow once, reject
if it is not representable as UTF-8 without replacement, and pass that same
borrow to `DB::open`. This is a contract sketch, not an implementation
decision. A successful check only means the conversion used by the inspected
wrapper should not replace invalid Unicode; it is not an open-success or
object-identity guarantee.

The covered direct APIs are:

| API | Current behavior at pinned main | Proposed refusal point |
|---|---|---|
| `RocksDbAccountState::open` | Enables `create_if_missing(true)` and calls `rocksdb::DB::open` (`crates/qbind-ledger/src/execution.rs:1393-1419`). | Reject a non-representable captured database path before entering the RocksDB wrapper, directory creation, or database initialization. |
| `RocksDbAccountState::open_existing` | Sets `create_if_missing(false)` and calls `rocksdb::DB::open` (`execution.rs:1421-1445`). The accepted no-replacement-database finding remains in force; it does not mean the wrapper has no earlier filesystem effects. | Apply the same path check before wrapper entry, without weakening existing-only behavior or broadening its accepted finding. |
| `RocksDbConsensusStorage::open` | Enables `create_if_missing(true)` and calls `rocksdb::DB::open` (`crates/qbind-node/src/storage.rs:719-758`). | Reject a non-representable captured database path before wrapper entry or database initialization. |

For each API the wrapper's input itself is the check subject: the complete
`Path` value at that boundary, including ancestors, not just the final
database leaf. In particular, a fixed UTF-8 leaf such as `state_vm_v0` does
not make a path representable if one of its ancestors is not. Any caller
that performs filesystem work before the direct API needs a separate earlier
check as described below.

The reviewed rust-rocksdb v0.22.0 source qualification reports that the
wrapper calls `create_dir_all` using the Rust path and derives the C path
through `to_string_lossy()` before calling RocksDB. If that source behavior
applies to the dependency artifact in use, a refusal before wrapper entry
would precede those wrapper effects as well as a lossy backend open. This
remains a source observation requiring platform and artifact review: the
reviewer did not verify the published crate archive byte-for-byte against
the upstream tag or inspect the author's local registry. It is not proof
that every QBIND route reaches the wrapper or that every platform behaves
identically.

### Error contract remains an owner decision

Two reasonable API approaches need explicit review; neither is selected:

1. **Typed path-encoding refusal.** Add a distinguishable variant in the
   account and consensus storage error APIs (for example
   `qbind_ledger::StorageError::PathEncoding`, propagated inside
   `VmV0RuntimeError::OpenState`, and
   `qbind_node::storage::StorageError::PathEncoding`, propagated through
   `ProductionConsensusStorageError::OpenFailed`), or a shared lower-level
   representation error propagated without erasure. These are candidate
   names only. This allows callers to distinguish an unsupported path from
   RocksDB I/O, missing database, corruption, and schema errors. It may
   change public enums and require updates to exhaustive matches and
   downstream consumers.
2. **Existing I/O error with a stable diagnostic.** Return the current
   account or consensus `StorageError::Io` variant with an unmistakable
   message such as `storage path is not representable without loss as UTF-8`.
   This reduces enum/API surface changes but makes programmatic distinction
   weaker and risks callers treating the refusal as an ordinary open failure.

The account enum is currently `Io(String)` / `Corrupt(String)`
(`execution.rs:1209-1229`); the consensus enum has `Io(String)` plus codec,
schema, corruption, and transition variants (`storage.rs:59-110`). The
owner must decide whether to add typed variants, how they propagate through
`VmV0RuntimeError` and `ProductionConsensusStorageError`, and what
diagnostic data may be exposed. A lossy path display must not be presented
as the exact rejected input or as filesystem identity.

An existing data directory with a raw path that is not representable without
loss would be refused under this proposal, including on a COMPLETE route.
This is a compatibility change for users of such paths. No automatic
renaming, migration, adoption, or recovery process is proposed.

### Other invalid path cases are distinct

Embedded NUL is representable as UTF-8, so a UTF-8 representability check
does not reject it. It may fail in a later C-string conversion or backend
step; its error and first-effect behavior require separate source and test
evidence. Other representable-but-invalid paths, permissions failures,
missing or malformed databases, and RocksDB errors also remain separate.
The proposal must not relabel all such errors as path-encoding refusal or
imply a refusal always occurs before every possible filesystem effect unless
the relevant layer is verified.

## 3. Separate earlier-startup check and effect ordering

The reviewed Candidate B specification scopes a proposed gate to ordinary
P2P startup with configured `data_dir`; its owner-approved protected set is
data-directory and lock-file creation, metrics task creation, consensus and
account database opening, `SignerLoaded`, and P2P construction or
participation. The target gate precedes that set. It explicitly excludes
reset, restore, LocalMesh, stateless, and other routes; it is not current
enforcement (`a33-f1-candidate-b-pre-ownership-gate-spec-20261109.md` §§1,
2, 4).

A path-representability check is a separate, narrow precondition, not that
gate. For the scoped normal P2P route, the proposal is to check the captured
`config.data_dir` value, and the exact derived data-directory/lock/storage
paths required by the approved sequence, before crossing the first
protected effect. Do not treat successful representability as authorization
to perform an effect. If a separate owner-approved gate is required, all
its independent authority, input, and object-binding conditions must still
be satisfied; they are unresolved and not supplied by this proposal.

At pinned main the current normal startup creates `data_dir` and then opens
or creates `<data_dir>/restore.lock` for the advisory lock before the
ordinary RTR guard (`crates/qbind-node/src/main.rs:2517-2526`;
`restore_completion.rs:858-890, 988-1017`). The normal route later creates
metrics state and may create a metrics task, inspects the ordinary RTR,
opens production consensus storage, opens/validates account state, performs
the P2P security preflight that loads the validator signer, then continues
to P2P construction (`main.rs:4995-5070, 5146-5190, 5370-5400,
5665-5738, 8119-8135`). These are source-order observations, not a claim
that a future check is wired in.

The consensus opener itself derives `<data_dir>/consensus`, creates its
parent if missing, then calls `RocksDbConsensusStorage::open`
(`crates/qbind-node/src/node_config.rs:5279-5290`;
`production_consensus_storage.rs:391-437`). Thus a check only inside
`RocksDbConsensusStorage::open` is too late to prevent the caller's parent
creation. The account paths derive `<data_dir>/state_vm_v0`; direct
account API checks cover callers that reach those APIs without this
startup check, but cannot undo earlier caller-side effects
(`node_config.rs:5279-5286`; `vm_v0_runtime.rs:68-84, 292-306`).

The scoped startup check would need to occur before `create_dir_all(data_dir)`
and lock-file creation, not merely before the first database open. It must
also precede metrics task creation, consensus-parent creation, account open,
`SignerLoaded`, and P2P construction/participation as required by the
reviewed protected set. It does not claim that all earlier non-protected
startup operations are side-effect-free, and it does not generalize to
reset, restore, LocalMesh, or other routes.

Inputs available at a candidate pre-effect point include the parsed
`NodeConfig` data-directory `PathBuf`, execution profile, network mode, and
CLI-derived route flags. Whether the exact ordinary-P2P-with-data-dir route
can be selected there, before the existing lock and before restore-route
handling is rearranged, is an implementation-entry decision. The current
code derives `restore_requested` after lock acquisition
(`main.rs:2548+`); a future proposal must not accidentally apply the normal
route check to excluded restore or reset behavior. The configured path is
only an observed input, not an authenticated destination.

The separate Candidate B blockers remain: no independent trust root or
pre-load public association source exists in the reviewed route, the actual
signer public key is obtained only after `SignerLoaded`, and a configured
path does not establish a filesystem-object binding. An encoding check
cannot resolve any of these blockers. If required pre-effect inputs or
route classification cannot be established at the proposed point, that
step remains infeasible or unestablished and the protected route must not be
claimed to proceed under Candidate B.

## 4. Optional in-memory execution-adapter fallback

`execution_adapter.rs:856-900` contains a generic VM-v0 worker path. When
given `Some(state_dir)`, it calls `RocksDbAccountState::open`; on an open
error it logs the failure and continues with `InMemoryAccountState`.
The same adapter API also has an explicitly absent `state_dir` mode for
in-memory execution (`execution_adapter.rs:465-572`). This source fact does
not establish that the reviewed normal P2P startup reaches this worker:
the main startup route instead uses `VmV0RuntimeState::open_from_config` or
`open_existing_from_config` (`main.rs:5380-5386`), and no normal-route
caller of this optional worker fallback is established by this review.

The following are alternatives for an owner decision:

| Policy option | Consequence |
|---|---|
| **Refuse if persistence is required.** A non-representable path or persistent-open failure for a configured required store is returned to the caller and startup/operation refuses; no silent switch to memory. | Preserves an explicit expectation of durable state, but changes current generic adapter behavior for `Some(state_dir)` and may affect callers relying on fallback. |
| **Explicitly selected in-memory mode.** In-memory execution is selected by an explicit mode with no persistent path, rather than as an error fallback from a configured persistent store. | Makes durability intent clearer but requires owner review of configuration, callers, and any compatibility impact. |
| **Retain fallback on open failure.** Continue the existing `Some(path)` to memory fallback, including path refusal. | Preserves current generic behavior but can hide that a configured persistent path was not used; it is unsuitable where persistence is required. |

**RECOMMENDED FOR OWNER DECISION, NOT APPROVED:** where a caller declares
persistent storage required, propagate path-validation/open failures and
refuse rather than fall back. Permit in-memory execution only when an
explicitly selected in-memory mode requests it. This recommendation does
not claim the normal P2P route reaches the adapter, nor does it change
current behavior.

## 5. FUTURE / NOT EXECUTED test matrix

Every control below is **FUTURE / NOT EXECUTED**. The matrix is a proposal
for separately authorized evidence, not a request to rerun previously
accepted tests. In particular, do not rerun accepted missing/existing-only
controls merely to reopen their disposition; the new justification for
future work is to test the proposed path-refusal ordering and its callers.

| Future control | Setup and expected observation if the proposal is adopted | Evidence class and limit |
|---|---|---|
| **Account create / valid path — FUTURE / NOT EXECUTED** | Under a unique test root, `RocksDbAccountState::open` with a representable path succeeds; confirm the database is created and readable. This is the valid-path compatibility control. | Actual account API/backend observation for one pinned build and platform; not cross-platform proof. |
| **Account existing-only / valid path — FUTURE / NOT EXECUTED** | Create a synthetic existing database, release setup handles, and open it through `open_existing`; confirm its marker is read and no replacement behavior is introduced. | Actual API/backend control. Preserve the accepted no-replacement-database scope; do not broaden conclusions. |
| **Account APIs / invalid encoding — FUTURE / NOT EXECUTED** | On a platform that supports non-UTF-8 paths, call both account entry points with a captured non-representable full path. Assert the proposed refusal type/message and that the wrapper is not invoked. Observe raw and lossy-spelling trees for absence of directory creation, `LOCK`/`LOG`, or database changes at the claimed boundary. | API-level test plus an explicit test-only invocation seam or equivalent evidence for pre-wrapper refusal. Filesystem listings alone do not identify private descriptors. |
| **Consensus open / valid path — FUTURE / NOT EXECUTED** | Open a synthetic consensus database at a representable path and verify a known value after reopen. | Actual consensus API/backend control; not proof of node startup reachability. |
| **Consensus open / invalid encoding — FUTURE / NOT EXECUTED** | At the direct consensus API boundary, pass a non-representable captured full path and assert refusal before wrapper invocation, with no raw/lossy-path database effects. | Actual API observation for tested platform/build. Separately test `open_production_consensus_storage`, whose parent creation occurs before its direct backend call. |
| **Reviewed alias/marker — FUTURE / NOT EXECUTED** | Recreate the prior synthetic COMPLETE record, UTF-8 destination and distinct lossy-spelling marker fixtures under a unique root. Call the actual guard with the raw non-UTF-8 alias, then call the account API only as allowed by the test flow. Under this proposal the expected guard decision remains a separate observation; a subsequent direct API refusal must precede wrapper effects, leave both markers unchanged, and must not be described as a production startup sequence. | Extends the retained author-run alias result with the proposed refusal behavior. Does not prove node route, exploitability, authority, or race resistance. |
| **Caller-side consensus parent and startup ordering — FUTURE / NOT EXECUTED** | Use a narrowly scoped test-only harness for ordinary P2P plus `data_dir`. Instrument effect boundaries and assert invalid encoding refuses before data-dir creation, lock-file open/create, metrics task creation, consensus parent/database effects, account database effects, `SignerLoaded`, and P2P builder/listener/dial calls. Add valid UTF-8 ordering control. | A synthetic harness proves only its modeled sequence. A reviewed real-node orchestration test would be needed to establish executable call-site ordering; do not start a node in this assessment. |
| **COMPLETE path and profile — FUTURE / NOT EXECUTED** | Include VM-v0 and non-VM-v0 COMPLETE admission to show the profile-independent existing-only validation path rejects an invalid account path before wrapper effects; retain separate guard decision and storage refusal assertions. | Test actual guarded APIs/caller wiring only under separately authorized test scope. Do not reinterpret the existing guard harness controls as production orchestration. |
| **Adapter persistent error — FUTURE / NOT EXECUTED** | Exercise `Some(state_dir)` with invalid encoding and with an ordinary open failure. For a selected refusal policy, verify that a required-persistent caller observes the failure and does not silently execute in memory. | Adapter-level behavior only; first establish whether any normal P2P route uses this adapter. |
| **Adapter explicit memory mode — FUTURE / NOT EXECUTED** | Exercise the explicit no-path/in-memory mode and demonstrate it is selected by configuration, not by a failed persistent open. | Adapter-level control; does not establish production policy or startup route use. |
| **Embedded NUL and other failures — FUTURE / NOT EXECUTED** | Separately test a UTF-8 path containing NUL where the platform permits construction, plus representable paths with permission, missing-database, or backend errors. Record the precise error and each observed effect; do not classify these as non-UTF-8 refusal. | Platform/backend-specific error behavior; no assumed no-effect guarantee. |

Test reports must identify the exact source commit/tree, test source, locked
and resolved backend artifact, OS/filesystem, and commands. The reviewed
alias result is retained author-run evidence from its recorded environment;
it is not independently reproduced here. A synthetic harness can check
control flow and markers but cannot stand in for the actual wrapper, actual
startup ordering, backend artifact provenance, or every supported platform.
Platform/backend claims and any actual-node orchestration claim require
their own separately authorized, independently reviewed evidence.

## 6. Limits and smallest next reviewable step

This refusal could prevent one known lossy-path selection only if the
validated path is the same captured path passed to the wrapper. It does not
bind a pathname to a filesystem object between check and use; a symlink,
parent, mount, or namespace can change. It does not establish destination
authority, ownership, fencing, backend confinement, or that a valid path
will open. It also does not determine whether RocksDB or its wrapper performs
later filesystem operations through retained handles or new path resolutions.

**Smallest next reviewable step:** have the owner decide the direct API error
contract and the scoped normal-P2P check point, including whether persistent
adapter failures must refuse and how explicit in-memory mode is selected.
Then review and authorize only the FUTURE test matrix needed to verify
pre-wrapper and pre-effect refusal. No production correction is proposed
until those decisions and test scope are accepted. No claim beyond the
retained characterization and the pinned source observations is made.
