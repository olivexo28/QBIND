# QBIND — Candidate B pre-existing destination or parent threat model

**DOCUMENTATION-ONLY INVESTIGATION. NO PRODUCTION MECHANISM, AUTHORITY,
PROVISIONING, OR RECOVERY PROCEDURE IS SELECTED OR PROVEN.**

## 1. Scope and pinned references

This threat model investigates only the category of a pre-existing,
independently authenticated destination or parent as a possible way to
address the destination-binding feasibility blocker. It does not approve an
implementation, establish that the normal P2P route is feasible, or claim
that Candidate B is enforced. The separately controlled coordinator remains
an unselected alternative and is not designed here.

| Reference | Pinned revision |
|---|---|
| QBIND main source | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed pre-ownership specification branch | `docs/candidate-b-pre-ownership-gate-spec` |
| Reviewed pre-ownership specification | `b13762c790e25ef9d29071d4a12de5369f3ef02f`, tree `a160d82321cf8a9479a023309f4baca863d17ae8` |

The reviewed specification approves a proposed gate before data-directory
and lock-file creation, metrics task creation, consensus/account database
opening, `SignerLoaded`, and P2P construction or participation. These are
proposed protected effects, not current Candidate B enforcement. It records
the ownership-bootstrap and namespace-race feasibility blocker and requires
refusal if the first protected effect cannot be authorized without relying
on the local destination path under examination
(`a33-f1-candidate-b-pre-ownership-gate-spec-20261109.md`, §§1, 4–5).

## 2. Actors, assets, boundaries, and threat assumptions

### Actors and assets

The threat model distinguishes:

- **Deployment authority:** whoever is authorized to identify the intended
  deployment and destination. The source, enrollment basis, and scope of this
  authority are unresolved.
- **Anchor and review authorities:** authorities for the expected commitment
  and deployment binding, and for independently trusted channel-separation
  review applicability. Their first-use trust and independence remain
  unresolved and separate from destination authority.
- **Destination administrator:** an actor able to provision, permission,
  rename, replace, or recover the destination or its ancestors.
- **Node operator/process:** supplies local configuration, evaluates the
  proposed gate, acquires ownership, and later opens storage and loads a
  signer.
- **Namespace/storage actors:** privileged or uncooperative processes able
  to mutate directory entries, parent namespaces, mounts, storage, or
  permissions, whether or not they participate in QBIND locking.
- **Concurrent node invocations:** processes that may evaluate the same
  inputs before either has acquired ownership.

Assets include the authenticated destination or parent object; the
deployment-to-destination association; the authorized child name and
creation policy when the destination does not yet exist; the ownership
claim; and the identity of the exact object used for each later protected
effect. Also in scope are the integrity of the Candidate B gate result,
storage state, and recovery decisions after interruption.

### Trust boundaries and attacker capabilities

The local path and configuration are attacker-controlled inputs unless
independently authenticated. A path string, successful canonicalization,
directory existence, exclusive create, or lock acquisition alone does not
prove that the object is the intended destination. A retained handle can
identify the object opened through that handle, but does not establish that
the configured name, parent namespace, or mount still designates it.

The adversary may control or race local configuration; change names,
symlinks, parent entries or mounts where permissions permit; create, rename,
remove, or replace entries; run uncooperative writers that ignore the QBIND
lock; start concurrent invocations; interrupt a process after some effects;
or leave the destination unavailable. Privileged storage or host control may
permit namespace and mount changes that an unprivileged process cannot make.
Capabilities depend on the actual OS, filesystem, mount namespace, privilege
model, and storage and must not be generalized without evidence.

This investigation does not assume an attacker can defeat a correctly
implemented independent trust source. It does not establish what that source
is, whether a destination administrator is independent of the anchor/review
authorities, or whether any local or remote record is authentic or current.
No cryptographic suite, filesystem API, trust root, account arrangement, or
operational procedure is selected.

### Shared versus separate authority arrangements

Owners must decide whether destination identification and provisioning are
controlled by the same founder or organization as the commitment/review
authorities, or by separately controlled parties. A common founder does not
make every delivery or storage channel operationally identical; conversely,
different channel names, accounts, or services do not establish independent
control. Shared arrangements may share administrator access, credentials,
recovery channels, devices, approval paths, host access, or compromise and
availability domains. Separate arrangements still may share those same
dependencies or be jointly controlled in practice.

Before relying on either arrangement, evidence would need to identify the
actual administrators and approval rights; credential issuance, custody,
recovery and revocation; shared accounts, devices, infrastructure and
support access; who can change destination names, parent permissions and
mounts; and how disputes, compromise, loss and absence of an authorized
approver cause refusal. This is evidence of the modeled operational
separation, not proof inferred from labels or nominal ownership.

## 3. Case A — destination already exists

### Required authentication and intended binding

Before a protected effect, the design would need independently authenticated
evidence that identifies all of:

1. the intended deployment scope;
2. the exact destination object identity, not only a local pathname;
3. the intended association between that deployment and object; and
4. the authority allowed to enroll, approve, replace, or revoke that
   identification.

The authority for this evidence and its first-use trust cannot derive solely
from the destination path, a file in that destination, local configuration,
or a flag supplied by the same host being assessed. Owners have not selected
an independent authority, enrollment method, object-identity representation,
or currentness mechanism. An authenticated identification could still be
old or superseded; authentication alone does not establish that it remains
current.

### Binding from check to ownership and later use

A possible investigation target is to authenticate the identity of an
already-existing destination or approved parent, obtain a retained reference
to the relevant object, and require ownership and later operations to remain
bound to that same object. This is a requirement, not a chosen filesystem
design. If later operations resolve the original pathname again, the design
must establish why they reach the authenticated object despite changes to
the name, parent namespace, mount, or configuration. If operations instead
use a retained object reference, the design must establish that all protected
effects—including lock creation, database opening, and subsequent state
use—are safely and completely rooted in that object and its intended
deployment scope.

A retained reference may continue to refer to an object after that object
has been renamed or unlinked, while the configured pathname resolves
elsewhere. Rechecking a path can detect some mismatches but is not itself an
atomic binding between the earlier check and later use. A mount or namespace
change may alter path resolution; whether an already-open reference is
affected, and whether operations through it retain the intended semantics,
depends on platform and filesystem behavior that is not established by
QBIND source.

### First protected effect

For an existing destination, the first protected effect may be opening or
creating the destination lock object, or another owner-designated protected
operation. The exact first effect and the operation that authorizes it must
be explicit. Authorization must bind to the same authenticated object that
will be owned and used. Acquiring the current pathname-based advisory lock
after a gate does not solve this bootstrap requirement: the lock file is
opened with create semantics under a path, and a later identity check cannot
undo a create on a substituted object.

If authentication, object identity, deployment binding, ownership
serialization, or safe use cannot be established before that first effect,
the proposed route must refuse before the effect. Do not recover from
ambiguity by accepting whichever object the pathname currently resolves to.

## 4. Case B — destination does not exist

### Authenticate an existing parent and authorize a child

There is no destination object to authenticate before its creation. A
candidate design would therefore need to authenticate an already-existing
parent object and independently bind all of the following before creation:

- the intended deployment and parent object;
- the exact child-name representation and permitted namespace;
- the authority to create that child for this deployment;
- the creation policy, including whether the child must be absent and what
  conditions constitute a conflict; and
- how the identity of the newly created child will be captured and carried
  into ownership and every later protected use.

No such parent authority, name encoding, creation policy, atomicity
guarantee, or identity handoff is selected or present in current QBIND
source. The local configuration path alone is insufficient. A successful
exclusive create or a returned handle, without independently authenticated
authorization and verified semantics for the exact parent/name operation,
would not establish the deployment binding.

### First create, ancestors, and partial effects

The first protected creation must occur only after prior authorization of
the exact parent object, child name, and creation policy. The operation must
ensure that the created object is the one subsequently owned and used, and
that a competing actor cannot substitute a different parent or child between
authorization and creation. No specific primitive is recommended here.

If one or more ancestors are missing, each ancestor creation is itself a
protected effect that requires prior authorization and object binding. A
recursive directory-creation call cannot be presumed safe merely because
its final path matches the configuration. The design must either refuse
when required ancestors are absent or specify how every ancestor creation
is independently authorized and how each newly created object is carried
forward. That is an unresolved owner decision.

Creation can be partial: a process may create some ancestor or the child,
then fail before recording or acquiring ownership. A crash can leave an
empty or partially initialized directory, lock file, or other artifacts.
The design must not silently adopt such state on restart solely because it
exists at the configured name. It needs independently authorized recovery
and an identity check that distinguishes the originally created object
from a replacement. Until a recovery rule and evidence source are approved,
ambiguous or partial state must refuse.

### Creation-to-use binding

After creation, the design must transfer the actual created-object identity
into ownership and all later protected operations without reopening an
unbound pathname. It must define the response if the entry is renamed,
removed, replaced, or moved under a different parent before ownership is
established or while later operations are in progress. Detection after an
unauthorized create is not a remedy: the create itself crossed the protected
boundary. If the design cannot establish authorization and binding before
the first create, it is infeasible under the approved boundary and must
refuse.

## 5. Races, concurrency, stale ownership, and recovery

Both cases must address these adversarial situations:

| Situation | Required proposed behavior |
|---|---|
| Parent entry, destination name, symlink, or mount changes after checking | Do not use a different object as if it were the authenticated one. Refuse before any not-yet-authorized protected effect; establish how the design prevents or accounts for an earlier create/open. |
| Configuration changes between evaluation and use | Keep the authenticated expected scope and object identity immutable and bind later operations to them; reject changed or ambiguous input. |
| Concurrent invocations both pass first-use evaluation | Serialize authorization and first protected effect against the same object. One invocation may proceed only if the other cannot create/use a competing object; otherwise refuse. |
| Uncooperative writer ignores the advisory lock | Do not claim it is fenced. Either account for that writer within the threat model and enforce exclusion by evidenced means, or state the threat is not covered and refuse claims requiring it. |
| Lock/object is replaced or ownership becomes stale | Prove later operations remain bound to the held/authorized object and that stale ownership cannot write after reassignment. A lock file's presence is not ownership. |
| Crash during or after create, before ownership or durable state | Treat leftover or partial state as ambiguous; do not adopt it by path alone. Require separately authorized recovery evidence or refuse. |
| Authority, parent/object, or recovery evidence is missing, conflicting, or unavailable | Refuse before the first protected effect; do not substitute local configuration, the observed object, or a stale record as the authority. |

An advisory lock can serialize only actors that cooperate on the same lock
object. Its kernel-managed lifetime and release on process death do not
establish that the locked pathname is the intended object, fence an
uncooperative writer, or resolve partial creation and recovery. An external
coordinator could be considered in a separate investigation but is not
selected here; it too would require independently established authority,
object binding, enforcement at the effect, stale-owner fencing, and
availability and recovery rules.

## 6. Pinned source facts and limits

At pinned `main`, `DestinationId::canonicalize` requires an existing
directory and stores its canonical absolute path as a UTF-8 string. It is
path identity, not an independently authenticated filesystem-object identity
(`crates/qbind-node/src/restore_completion.rs:148-173`).

The normal startup path calls `create_dir_all(data_dir)` and then acquires
the destination lock (`crates/qbind-node/src/main.rs:2503-2548`, especially
`:2517-2546`). The lock implementation opens or creates
`<data_dir>/restore.lock`, then takes `flock(LOCK_EX | LOCK_NB)` on the open
descriptor; contention refuses, and the descriptor's closure or process
death releases the kernel lock (`crates/qbind-node/src/restore_completion.rs:800-905`).
These current operations do not implement the proposed Candidate B gate
before directory/lock creation.

The snapshot/restore contract limits the advisory lock to participating
entrypoints and explicitly does not claim protection against arbitrary
non-participating tools, external processes, or malicious directory
manipulation (`docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md:514-556`).
Its lock contract does not prove a pre-ownership binding to an independently
authenticated destination. The reviewed Candidate B specification identifies
the same namespace race and says post-lock revalidation cannot undo a
protected create on a substituted destination
(`a33-f1-candidate-b-pre-ownership-gate-spec-20261109.md:186-227`).

These are source and specification observations, not evidence about the
semantics of every supported OS, filesystem, mount type, container, or
storage backend. The source does not establish hostile-namespace safety,
atomic check/use behavior, fencing of nonparticipants, or operational
destination authority.

## 7. Separate unresolved blockers

Destination binding must not be used to resolve:

- first-use trust for the expected commitment and deployment authority;
- first-use trust and current applicability of the channel-independence
  review;
- provenance and currentness of external genesis or expected-hash inputs;
- independently authenticated pre-load public identity observations;
- the later full-key, suite, and validator-ID binding to the loaded signer;
- signer exclusivity, complete signing history, durable intent, fencing, or
  recovery authority.

Each remains a separate owner decision and evidence requirement. A destination
handle, local record, successful create, lock, genesis hash, or synthetic
fixture grants no signing, startup, currentness, or recovery authority.

## 8. Proposed adversarial controls and evidence

All controls below are **FUTURE / NOT EXECUTED**. They are proposals for a
later review, not implemented behavior.

### Synthetic tests

Synthetic tests could model refusal for missing, conflicting, substituted,
stale, or cross-deployment destination evidence; changed parent/name
between modeled check and use; unauthorized child name or creation policy;
missing ancestors; concurrent ownership attempts; stale owner after
reassignment; partial creation and interrupted recovery; and attempts to
derive authority solely from local path/configuration. Same-checker bypass
controls could show each modeled check is material, while positive controls
guard against refusing every case.

Such tests can establish only the modeled decision logic and mutation
sensitivity. They do not prove filesystem object identity, namespace race
resistance, OS enforcement, real authority separation, actual crash
durability, or runtime ordering.

### Platform, filesystem, runtime, and operational evidence

Before implementation review could rely on a candidate design, separate
evidence would be needed for:

- **Platform/filesystem:** object-identity and handle semantics; name,
  parent, rename, symlink, mount and namespace behavior; create and open
  atomicity; permissions and privilege boundaries; behavior on every
  supported filesystem/storage configuration.
- **Runtime:** evidence that the first protected effect follows successful
  independent authorization; ownership remains bound to the same object
  across all database, signer and P2P effects; concurrent invocations and
  uncooperative writers are either excluded or handled; missing or
  conflicting inputs refuse before effects.
- **Crash/recovery:** interruption at each creation/ownership boundary,
  resulting durable artifacts, stale-owner exclusion, and refusal or
  authorized recovery without path-only adoption.
- **Operational authority:** independently reviewed first enrollment,
  administrators, shared-control/failure domains, credential custody and
  recovery, approval and revocation authority, and evidence that destination
  identification is current when relied upon.

No such evidence is produced here. Tests, builds, operational keys, node
execution, provisioning, and production implementation were not performed.

## 9. Unresolved decisions and feasibility outcome

Owners must decide whether an already-existing destination or only an
existing parent is acceptable; who independently authenticates its identity
and deployment binding; whether that authority shares control with the
anchor/review authorities; how exact object identity and authorized names
are represented; what first effect is protected; how creation and ownership
are serialized; whether and how missing ancestors may be created; how
nonparticipants and privileged namespace actors are treated; and how crash,
partial state, stale ownership, revocation, and unavailable evidence are
handled.

**FEASIBILITY BLOCKER remains OPEN:** current source provides neither
independently authenticated destination authority nor a reviewed atomic
relationship between pre-effect authorization, the destination object, and
later ownership/use. If owners and reviewers cannot establish that
relationship before the first protected create/open, the proposed route must
refuse; later revalidation cannot cure the unauthorized effect. This
document selects no filesystem mechanism, authority arrangement, key,
algorithm, trust root, provisioning, or recovery procedure.

CB-1 and CB-FIXTURE-1 remain within their accepted scopes. The fixture's
conflict result propagates a supplied classification and does not detect
conflicting review contents; its synthetic results do not prove operational
authority or destination binding. A23-F1 and A33-F1 / E27 remain OPEN;
activation remains DISABLED; public DevNet remains NO-GO.
