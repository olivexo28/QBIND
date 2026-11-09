# QBIND — Existing-destination authorization-to-use proposed contract

**DOCUMENTATION-ONLY PROPOSAL. NO AUTHORITY, FILESYSTEM PRIMITIVE,
PROVISIONING, RECOVERY PROCEDURE, OR PRODUCTION MECHANISM IS SELECTED.**

## 1. Scope and pinned references

This proposed contract considers only an already-existing destination on
the previously scoped ordinary P2P startup route with a data directory. It
does not cover creating a new destination, prove that the route is feasible,
or claim that Candidate B currently protects any startup effect.

| Reference | Pinned revision |
|---|---|
| QBIND main source | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed pre-existing destination threat model | `docs/candidate-b-preexisting-destination-threat-model`, commit `b125f24bf3ad467cbfadc0f29ee80c42bf50efca`, tree `da8de91fcf630aaab095c5b283cbeab4eb0df6fc` |
| Reviewed pre-ownership specification | `docs/candidate-b-pre-ownership-gate-spec`, commit `b13762c790e25ef9d29071d4a12de5369f3ef02f`, tree `a160d82321cf8a9479a023309f4baca863d17ae8` |
| Upstream rust-rocksdb source examined for wrapper behavior | `v0.22.0` source at commit `e523ca4a13a7bf364abd0743149d0b3cd40856c0` (`src/db.rs`, `src/ffi_util.rs`) |

The approved proposed protected-effect boundary includes data-directory
and lock-file creation, metrics task creation, consensus/account database
opening, `SignerLoaded`, and P2P construction or participation. The gate
must precede these effects. This is a specification boundary, not current
enforcement. The reviewed threat model explicitly leaves the object
authority, ownership bootstrap, namespace and backend semantics unresolved
(`a33-f1-candidate-b-preexisting-destination-threat-model-20261109.md`,
§§3, 5–9).

## 2. First-use authority and evidence

Before the gate authorizes any protected effect on an existing destination,
the proposed design must receive independently authenticated evidence
binding:

1. the intended deployment scope;
2. the exact identity of the already-existing destination object, not just
   the configured path or its canonicalized spelling;
3. the association of that object with the intended deployment;
4. an authorization by an identified authority to use that object for this
   startup and scope; and
5. the authority and evidence status needed to establish that this
   authorization is acceptable and has not been superseded, withdrawn, or
   rendered inapplicable.

The evidence must be authenticated through a first-use basis that is not
derived solely from the destination, its local contents, the path or
configuration under assessment, or a flag from that same host. It must
identify who may authorize use, how that authority is itself established,
and how conflicting, stale, unavailable, or superseded evidence is
recognized. The exact evidence form, trust source, authority arrangement,
currentness mechanism, and enrollment process remain owner decisions; this
contract selects none.

A pathname, an existing directory, or a local record cannot establish its
own authority. A record stored in the destination may be evidence to compare
only after an independent trust basis authenticates its issuer and scope; its
presence does not bootstrap that basis.

The gate cannot retroactively authorize the directory's historical creation.
Whether an independently authenticated, already-existing object may be
enrolled and reused under a newly approved authorization is an explicit
owner-policy decision. If policy does not allow enrollment of this existing
object, or if its origin and history are required but cannot be independently
established, refuse. The current source establishes neither historical
authorization nor destination identity authority.

## 3. Proposed authorization and ownership sequence

The intended logical order is:

1. **Acquire bounded inputs.** Read the proposed destination evidence,
   expected deployment scope, and pre-load public observations under
   separately reviewed bounds and provenance rules. Inputs are not trusted
   merely because they are local, readable, or already present.
2. **Evaluate the gate.** Authenticate the authority, object identity,
   deployment association, current authorization-to-use, and all independent
   Candidate B inputs. Keep the exact authenticated evidence and object
   identity bound in an immutable checked context. Missing, conflicting,
   stale, ambiguous, or inapplicable evidence refuses before protected
   effects.
3. **Authorize ownership acquisition.** The successful gate must authorize
   a specifically defined ownership acquisition over the same object and
   scope. It must not infer ownership merely from a path, from the fact that
   the object exists, or from the gate's successful evaluation.
4. **Acquire ownership without an unauthorized effect.** The chosen
   ownership operation must serialize competing invocations and establish
   that its ownership object or authority applies to the already
   authenticated destination. It must not create or modify a lock or other
   protected object before authorization.
5. **Revalidate while ownership is effective.** Revalidate that the
   authenticated destination identity, deployment binding, authorization
   currentness, and immutable checked context still correspond to the
   object that ownership covers. Revalidation must be serialized with
   subsequent protected operations; it cannot be a detached check followed
   by path-based use.
6. **Use only the bound destination.** Open consensus and account storage,
   then continue the protected route only if each operation is demonstrably
   rooted in the authenticated destination and ownership remains effective.
   Keep and reuse the database handles returned from those opens where
   intended, but do not mistake handle reuse for proof of the identity of
   the original open.

This sequence is a required logical contract, not an available or selected
mechanism. The ownership acquisition and subsequent revalidation must be
serialized against namespace mutation and any actor capable of changing the
object or access to it. If that cannot be established before the first
protected effect, the route must refuse.

### 3.1 Ownership without creating a lock object

An ownership mechanism that does not create a lock object could avoid that
particular pre-ownership create, but it does not become safe by omission of a
lock file. Before reliance, it would need an independently authenticated
ownership authority, a binding of its grant to the exact destination object
and deployment, exclusive/concurrent-acquisition semantics, and evidence
that the grant is enforced at all protected effects. It would also need
stale-owner fencing, loss and revocation behavior, and crash/recovery rules.
The relevant authority, enforcement boundary, availability and platform
assumptions remain unresolved. No such mechanism is selected.

### 3.2 First lock-object creation after the gate

A design could propose that creation of a lock object is the first
ownership-establishing protected effect, but it must explicitly authorize
that create after successful gate evaluation. It must show that the
operation acts within the exact authenticated destination object and that
concurrent or hostile namespace actors cannot redirect or race the creation
to another object. The created lock object must then be related to the
destination and to ownership of subsequent storage use.

The existence of a lock file is not ownership. A successful lock on an
opened descriptor does not, by itself, prove that the descriptor was opened
under the authenticated directory or that later database path opens refer
to that same directory. The operation must establish both object binding
and serialization; neither may be assumed from create or lock success
alone. If a namespace substitution can occur between checking and this
first create, the proposed sequence fails the boundary. Post-create
revalidation cannot undo an unauthorized create.

The exact acquisition semantics, namespace assumptions, failure handling,
and evidence required for either ownership category are unsettled. Do not
combine them into an implicit assumption that a lock-free step is harmless
or that a newly created lock solves ownership bootstrap.

## 4. Storage binding contract

The authenticated destination object, the ownership object or grant, and
every storage open must have one reviewed, explicit binding:

> The consensus-storage open and account-storage open used by the protected
> route must be proven to address storage within the exact destination
> object authenticated by the gate and covered by current ownership. Any
> change in path resolution, parent namespace, mount, ownership, or backend
> object identity that breaks that relationship must prevent or stop the
> affected protected operation before it is performed.

This requires more than rechecking the path. It must address the interval
between gate evaluation, ownership acquisition, revalidation, each backend
open, and later backend operations. It must account for whether each database
backend follows pathnames again, holds directory or file handles, performs
internal opens, creates auxiliary files, uses locks, or accesses storage
through other paths. It must establish that ownership remains effective for
all such operations and that relevant writers cannot bypass it—or expressly
limit the threat claim and refuse to claim protection against those writers.

At pinned `main`, `NodeConfig::consensus_storage_dir` derives
`<data_dir>/consensus` as a `PathBuf` (`crates/qbind-node/src/node_config.rs:5279-5290`).
`open_production_consensus_storage` ensures the path parent exists, then
opens `RocksDbConsensusStorage` by path and returns both that path and a
retained database handle (`crates/qbind-node/src/production_consensus_storage.rs:302-309,391-437`).
For normal non-restore startup, the returned handle is reused later; restore
has an earlier pre-restore open and reuses that handle
(`crates/qbind-node/src/main.rs:2626-2643,5173-5184`). These handles support
continued use of the opened database instance. They do not prove that the
initial path-based open reached the gate-authenticated destination, and
source inspection does not establish that every later backend filesystem
operation is confined to an authenticated directory object.

Account storage is derived as `<data_dir>/state_vm_v0`; its opener accepts a
path and returns a database/runtime handle (`crates/qbind-node/src/vm_v0_runtime.rs:277-305`).
Startup selects the existing-only or create-if-missing path based on restore
admission and opens it after the consensus lifecycle
(`crates/qbind-node/src/main.rs:5380-5386`). That open and later handle reuse
likewise do not prove that the original open was rooted in the
gate-authenticated object.

### Source qualifications: existing-only open and path encoding

The account `RocksDbAccountState::open_existing` sets
`create_if_missing(false)` before calling `rocksdb::DB::open`
(`crates/qbind-ledger/src/execution.rs:1423-1445`). This prevents
initialization of a replacement RocksDB database when the database is
missing, within the accepted no-replacement-database finding and its
previously reviewed scope. It does not imply that the wrapper performs no
filesystem effects before RocksDB decides whether the database can be opened.

In the examined rust-rocksdb v0.22.0 source, the shared open implementation
forms a C path and then calls `fs::create_dir_all(&path)` before invoking
the RocksDB open (`src/db.rs:599-615`); `to_cpath` constructs the C path using
`path.as_ref().to_string_lossy()` (`src/ffi_util.rs:53-59`). Therefore, if
this wrapper is reached with a missing account-database path and permissions
allow, it can create directory components even though
`create_if_missing(false)` refuses to initialize the missing database.
`create_dir_all` may also leave partial directory effects if a later
component fails. This is a source-derived possibility, not evidence that a
specific QBIND startup route reaches `open_existing` with a missing path;
earlier route guards may refuse first. It does not reopen or broaden the
accepted no-replacement-database findings.

The wrapper uses the original Rust `Path` for `create_dir_all`, while the
RocksDB C call receives the `to_string_lossy()`-derived path. A future
contract must define whether non-UTF-8 paths are supported or refused and
must establish that all relevant operations—including directory creation
and the backend open—address the intended object. This is a source
observation requiring platform-specific review, not an observed attack or
an established reachable route. The reviewer did not independently verify
the published crate archive byte-for-byte against the cited upstream commit
or inspect the author's local Cargo registry; the cited evidence is the
upstream source at the pinned commit, not archive-provenance evidence.

Current interfaces therefore do not accept or propagate a gate-authenticated
destination-object binding into lock acquisition or consensus/account
openers. They remain path-based at these boundaries. Current interface
compliance with this contract is **NO**.

### Evidence missing before relying on storage binding

At minimum, a later implementation review would require:

- authoritative documentation for each supported OS and filesystem
  describing the object/handle, rename, unlink, symlink, parent, mount and
  namespace semantics relied upon;
- a reviewed path-encoding contract, including explicit non-UTF-8 handling,
  and evidence that path-based directory creation and backend opens resolve
  to the same intended object under each supported platform configuration;
- separately reviewed tests for the exact supported configurations and
  backend versions, including whether every database operation and auxiliary
  filesystem operation remains rooted in the bound object;
- runtime evidence that the actual lock and both storage opens receive and
  preserve the same authenticated object binding, with no re-resolution
  through an untrusted path;
- evidence that competing participating invocations serialize before
  protected use and that uncooperative writers or namespace administrators
  are either excluded by an evidenced trust/permission boundary or explicitly
  outside the supported claim; and
- failure/crash evidence showing loss of ownership, revocation, ambiguous
  identity, backend error, or unavailable currentness evidence stops
  protected use and does not permit path-only recovery.

No platform-specific or backend-specific guarantee is asserted here. Until
the exact platform, filesystem and backend semantics are selected and
independently reviewed, they are assumptions, not established properties.

## 5. Failure and race behavior

The proposed contract requires refusal before the first affected protected
effect for:

| Failure or race | Required proposed response |
|---|---|
| Missing, malformed, conflicting, stale, revoked, or unavailable authority, object, deployment, or authorization evidence | Refuse; do not infer authority from the path, local record, existing directory, or prior successful startup. |
| Authorization is valid but currentness or applicability cannot be established | Refuse; authenticated old evidence may have been superseded. |
| Name, parent, mount, namespace, configuration, or object identity changes after gate evaluation | Do not use a different object as the authorized destination. Refuse before the next protected effect; do not claim a later check repairs earlier unauthorized activity. |
| A competing invocation seeks ownership | One invocation may proceed only if the approved mechanism serializes it against the same authenticated object; otherwise refuse both/ambiguous ownership. |
| An uncooperative writer can alter the destination or backend state | Do not claim it is fenced by an advisory lock. Exclude it using an independently evidenced boundary or refuse any protection claim that requires its exclusion. |
| Ownership is lost, expires, is revoked, or its target becomes uncertain | Stop before subsequent protected use. Do not continue on a stale grant or reacquire by path without reauthentication. |
| Partial lock/open/effect or crash leaves artifacts or uncertain ownership | Treat state as ambiguous. Refuse path-only adoption; require separately authorized recovery evidence and exact object binding, or remain stopped. |
| Revalidation detects mismatch after an unauthorized create/open | Stop further effects and report the incident; the earlier effect remains unauthorized and cannot be undone by this check. |

Guarantees about atomicity, exclusive ownership, namespace stability,
backend path resolution, stale-owner rejection, and crash persistence depend
on specific trust, platform, filesystem, storage, and runtime assumptions
that have not been established. A retained handle, advisory lock, or
coordinator alone is not a complete solution. The coordinator remains an
unselected alternative and would itself require authenticated authority,
binding at each effect, fencing, availability and recovery evidence.

## 6. Contract requirements versus current interfaces

| Proposed requirement | Current source behavior | Meets contract? |
|---|---|---|
| Independently authenticate the destination object, deployment scope, prior-use authority, and currentness before effects | No destination trust authority or authorization-to-use input is provided by these interfaces. `DestinationId` is a canonical path string. | **No** |
| Obtain ownership before protected effects without an unauthorized protected create | Startup creates the data directory, then `acquire_destination_lock` opens/creates `<data_dir>/restore.lock` and applies advisory `flock`. | **No** |
| Serialize uncooperative namespace/backend writers and bind the lock to the authenticated destination | Lock is on an open descriptor for a path-resolved lock file; source/contract protects participating entrypoints only and explicitly excludes malicious directory manipulation and arbitrary nonparticipants. | **No** |
| Revalidate and use the exact same authenticated object | No authenticated object binding is carried from a gate into ownership or storage openers; the current source has no such gate. | **No** |
| Open consensus and account storage under that binding | Openers construct paths from `NodeConfig` and return/reuse backend handles; they do not receive a gate-authenticated destination binding. | **No** |
| Fail closed for all listed races, currentness loss, partial effects, and recovery ambiguity | Some current lock and database errors refuse, but this is not equivalent to the proposed destination-authorization and binding contract. | **No** |

Source references: `restore_completion.rs:148-173,800-905`;
`main.rs:2515-2546,2626-2643,5173-5184,5380-5386`;
`node_config.rs:5279-5290`; `production_consensus_storage.rs:302-309,391-437`;
`vm_v0_runtime.rs:277-305`; and
`docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md:514-556`.

**FEASIBILITY BLOCKER remains OPEN:** current QBIND interfaces cannot satisfy
this contract as-is. They provide no independently authenticated
destination-use authority, no pre-effect ownership contract bound to the
authenticated object, and no way to pass that object binding into lock and
database opening/use. If these contracts cannot be established and evidenced
before the first protected effect, the route must refuse. Later
revalidation cannot authorize or undo a prior protected effect.

## 7. Boundaries and separate unresolved work

This contract does not cover a nonexistent destination. That case still
requires independently authenticated parent identity, authorized child
name, deployment binding, and creation policy **before the first create**,
as well as binding the created object into ownership and later use.

The following remain separate unresolved blockers and must not be inferred
from destination authorization:

- first-use authority for the expected commitment and deployment binding;
- authority and current applicability of the channel-independence review;
- external-genesis and expected-hash provenance and currentness;
- independently authenticated pre-load public identity observations;
- later full-key, suite, and validator-ID binding to the loaded signer;
- signer exclusivity, complete signing history, durable intent, fencing,
  replacement/revocation and recovery.

Restore, reset, LocalMesh, embedded genesis, and no-data-directory remain
outside the scoped ordinary P2P proposal and need separate route-specific,
fail-closed treatment. This contract does not claim that current QBIND
enforces those exclusions or that the ordinary route is protected.

CB-1 and CB-FIXTURE-1 remain accepted only within their existing scopes. The
fixture conflict outcome propagates a supplied classification; it does not
detect conflicting review contents. Synthetic fixture results do not prove
destination authority, currentness, namespace safety, storage binding, or
runtime enforcement.

## 8. Future verification matrix

All controls in this matrix are **FUTURE / NOT EXECUTED**. No tests, builds,
filesystem attacks, runtime checks, provisioning, or operational evidence
were performed for this proposal.

| Evidence class | Proposed controls | What the evidence could establish | What it cannot establish alone |
|---|---|---|---|
| **Synthetic model controls** | Positive authorized-object case; missing/conflicting/stale/revoked evidence; wrong deployment/object association; local-path self-authorization; unauthorized prior-use claim; same-checker bypass controls; currentness unavailable; refusal result and protected-effect counter remain zero on refusal. | Modeled decision logic, refusal behavior, and sensitivity to required checks. | Real authority, first enrollment, actual currentness, filesystem identity, namespace race resistance, backend confinement, or runtime ordering. |
| **Platform/filesystem** | On every explicitly supported OS/filesystem/mount profile, review authoritative documentation and separately controlled tests for object identity, handles, rename/unlink, symlink/parent substitution, mount/namespace changes, open/create semantics, permissions, and behavior under crash. | The specific tested platform semantics and assumptions relevant to the selected design. | Authority over destination identity, independence of administrators, backend behavior not covered by the tests, or other platforms/configurations. |
| **Storage backend** | Review exact consensus/account backend APIs and versions; determine all internal path opens, auxiliary files, lock behavior, directory-handle use, create/reopen behavior, and whether later operations can escape or re-resolve outside the bound object. | Whether the selected backend operations preserve the proposed object binding under the tested environment. | Hostile platform semantics, untested backend versions, or operational authority and currentness. |
| **Runtime integration** | Instrument the approved protected-effect sequence; show gate precedes every protected effect, ownership binds to the same object, both database opens use that binding, and ownership remains valid through later use; inject missing/conflicting inputs, namespace changes, concurrency, ownership loss, and errors; verify refusal before effects. | Ordering and integration behavior for the tested binary, backend, and configuration. | Real provisioning authority, all possible platform/storage behaviors, or untested hostile actors. |
| **Operational authority** | Independently review first-use enrollment, authority scope, actual administrative/credential/recovery control, authorization-to-use, replacement/revocation/currentness, shared failure domains, and refusal if approvers or evidence are unavailable. | Evidence for the documented operational arrangement and its stated limits. | Cryptographic or platform correctness not otherwise verified, absolute future currentness, or exclusivity beyond the evidenced scope. |
| **Crash and recovery** | Interrupt at gate, ownership acquisition, lock/open, each database open, and protected-use boundaries; inspect partial artifacts, stale ownership, restart behavior, and every recovery decision. | Observed failure/recovery behavior under the exact tested setup. | Unmodeled crashes, untested filesystems/backends, or authority to adopt uncertain state. |

Before implementation review, the owner must decide whether reuse of an
already-existing destination is permitted despite its unproven historical
creation; which authority may authorize its use; the first-use and currentness
basis; the object-identity semantics; whether ownership is obtained without
creating an object or through a first authorized lock create; the
serialization and writer threat model; the required storage-binding
capability; and the recovery/refusal policy. No option is selected here.

## 9. Status

This document defines proposed requirements and records current interface
gaps; it does not implement, select, or prove a solution. **FEASIBILITY
BLOCKER remains OPEN.** CB-1 and CB-FIXTURE-1 retain their accepted scopes.
A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO.
