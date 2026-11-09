# QBIND — Candidate B pre-ownership gate specification

**DOCUMENTATION-ONLY SPECIFICATION. NO OPERATIONAL TRUST SOURCE,
PROVISIONING, PRODUCTION CODE, STARTUP, SIGNING, OR AUTHORITY IS APPROVED.**

## 1. Scope and pinned revisions

This proposal covers only an ordinary P2P startup with a configured data
directory. It proposes a Candidate B gate before data-directory and lock-file
creation, metrics task creation, consensus/account database opening,
`SignerLoaded`, and all P2P construction or participation. The scope does
not claim current behavior enforces any Candidate B gate or refuses any
excluded route.

| Reference | Revision |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed normal-P2P route specification | `3520c2d3ad0adfa61ec8f20f78c18c8046d8cf3e`, tree `30c0ef244f6c797beaca91dd06296109aab582c9` |
| Reviewed Candidate B endpoint | `c19fe2ab2c268b658f1aecb3f4c4808d5e8254a7`, tree `990571f7d0fd260d738ed1518aae79ddb2bf8e01` |
| Candidate B documentation specification | `af55d73be9b3eb043a1997f7b0e6061121494fa7` |

All source citations below are pinned to expected `main`; the Candidate B
assumptions and synthetic-test limitations refer to the reviewed endpoint.
This document adds no input API, filesystem mechanism, authority, trust root,
or implementation decision. Items labeled **FEASIBILITY BLOCKER** prevent
an implementation claim until owners resolve them.

## 2. Current startup order (observed, not Candidate B)

For comparison, pinned source presently proceeds as follows:

1. `main` intercepts the `identity` subcommand, parses CLI arguments and
   constructs `NodeConfig`; then it resolves several policies and applies
   early refusals (`crates/qbind-node/src/main.rs`,
   `aa382fa…:2009-2143`). Config construction can consume arguments and
   environment. This source does not establish that all input acquisition is
   bounded, side-effect-free, or trustworthy.
2. The early reset route (`--authority-state-reset`) can create a directory,
   acquire a lock and execute reset effects before ordinary startup continues.
   The print-genesis operator route also exits before normal startup
   (`main.rs:2211-2365`). Neither is covered by this proposal.
3. Ordinary startup reads and validates configured external genesis before
   destination ownership. DevNet/TestNet may compute and retain a canonical
   hash without an expected-hash comparison; if an expected hash is supplied,
   it is compared. Neither hash computation nor equality authenticates the
   genesis or expected-hash provenance (`main.rs:2374-2449`;
   `pqc_boot_genesis.rs:17-34, 215-245`;
   `qbind-ledger/src/genesis.rs:1797-1855`).
4. With `data_dir` set, source creates it if needed and acquires the advisory
   `restore.lock` (`main.rs:2503-2548`). This happens after genesis
   acquisition.
5. If restore is requested, source can open production consensus storage
   for a pre-restore epoch check before publishing restore INTENT
   (`main.rs:2552-2652, 2700-2855`). Restore is excluded from this design.
6. Later startup creates metrics state and starts the optional metrics HTTP
   task, checks ordinary restore-completion state, opens production consensus
   storage, and opens/validates account state
   (`main.rs:4990-5070, 5146-5190, 5370-5400`).
7. LocalMesh and P2P dispatch separately. The P2P consensus security preflight
   runs before `builder.build`, but the preflight itself loads the local
   validator signer (`main.rs:5402-5465, 5665-5738, 8119-8135`;
   `signer_loader.rs:306-373`). Therefore it is not before `SignerLoaded`.

No Candidate B gate currently occurs before these operations. The
genesis-authority production path remains disabled and is refused separately;
it is not a Candidate B implementation (`main.rs:5402-5438`).

## 3. Proposed inputs before the first protected effect

The proposed gate must not evaluate successfully unless it has all required
inputs in a stable, bounded representation. Input collection may involve
reads, parsing, allocation, path resolution, environment access or external
services. Calling an operation a “read” does not establish that it is
side-effect-free, bounded, safe against malicious inputs, or independent of
the host being evaluated.

| Required input | Required content and provenance | Availability / unresolved trust |
|---|---|---|
| **Authenticated expected commitment** | Authenticated issuer and role; complete public association anchor value and suite; association-only purpose; approved interpretation/policy version; recipient and deployment binding; complete statement semantics, with no attacker-selected downgrade or ambiguous representation. | No production input or trust root exists. First-use authentication, delegation and source are unresolved. A digest or local copy is not authority. |
| **Independently expected deployment context** | Authenticated expected environment, numeric chain, full genesis identity, destination identity, and any owner-selected validator/association scope. Values must not be copied solely from the anchor-delivery object or the local path under examination. | `NodeConfig` provides environment and chain ID; external genesis can provide a computed identity as described in §2. These values do not authenticate their provenance. Destination identity semantics and independent binding are absent. |
| **Trusted independence-review applicability evidence** | Separately authenticated review authority and delegation; identified commitment and anchor channels/authorities, recipient and deployment; evaluated authority/account/credential/administrator/provider/recovery/failure-domain separation; evidence that the scoped review remains applicable. | No production review input, trust policy, or currentness source exists. Common founder/account/credential/recovery control may invalidate independence; channel names alone cannot prove separation. |
| **Pre-load public association observations** | Environment, numeric chain ID, full genesis identity, destination identity, validator ID, validator suite and complete validator public key, all scoped to the same intended deployment and association. | No single authenticated pre-load tuple is currently provided. The actual signer public key and suite are derived by the P2P signer loader after `SignerLoaded`. Any pre-load source and its provenance remain undecided. |
| **Bounded acquisition policy** | Maximum input sizes, record counts, parse/work limits, timeouts, supported interpretation rules, ambiguity handling and explicit refusal behavior for each evidence source. | No Candidate B bounds or acquisition contract exists. Resource exhaustion, partial reads, ambiguous sources or unavailable evidence must not produce an accepted result. |

**FEASIBILITY BLOCKER — first-use authority:** No independently trusted
source or enrollment for the commitment authority or review authority is
approved or present in source. A local file, flag, path, environment value,
synthetic fixture, founder assertion or digest cannot bootstrap its own
authority. If that first-use trust cannot be independently established before
the gate, the proposed gate must refuse; do not resolve circularity by
trusting the data directory that the gate is intended to authenticate.

**FEASIBILITY BLOCKER — pre-load public identity:** The actual validator
public key is obtained only by loading the signer on the current P2P route.
Using that load to populate a supposedly pre-gate observation violates the
approved protected-effect boundary. A separately authenticated
pre-load public observation and a reviewed binding to the later signer are
not available in current production source. Until owners identify an
independently trusted source for the complete pre-load tuple, the proposed
gate must refuse.

**FEASIBILITY BLOCKER — genesis and destination provenance:** External
genesis and configured expected-hash comparison can produce a matching
identity without authenticating who chose either value. The local
destination path also does not by itself establish an independently expected
destination identity. If the gate cannot obtain independently authenticated
expected deployment scope before directory creation/ownership, it must
refuse.

No blocker is resolved by the synthetic Candidate B fixture. Its `Trusted`
review evidence and values exercise checker logic only; the retained 11/11
test result and compile-only output are author-run evidence, not hosted CI or
an independent rerun.

## 4. Proposed order and protected-effect boundary

The following is a target ordering, not current enforcement:

1. **Entry and bounded configuration acquisition.** Parse only the normal
   P2P-with-data-directory route. Reject reset, restore, LocalMesh,
   embedded-genesis and missing-data-directory modes before protected
   effects. Configuration needed to locate candidate evidence is untrusted;
   it may not choose or replace the trust root used to authenticate itself.
2. **Bounded pre-gate acquisition.** Acquire the commitment, its
   authentication/provenance evidence, independently expected deployment
   context, scoped review-applicability evidence, genesis-derived material
   if used, and pre-load public association observation. Enforce approved
   byte/work/time limits. Any missing, unavailable, malformed, ambiguous,
   conflicting, wrong-scope, unauthenticated or over-limit result refuses.
   The sources and handling must not create data directories or lock files,
   start metrics, open consensus/account stores, load a signer, construct
   P2P, or participate.
3. **Candidate B gate.** Authenticate the commitment issuer and
   deployment/recipient binding under separately established policy;
   authenticate the scoped review evidence and its applicable status;
   compare the full anchor and required scope against independently expected
   context; authenticate/verify the public association and compare its full
   tuple to pre-load observations. Keep raw match, expected-anchor
   authentication, association authenticity, tuple equality and currentness
   as distinct results. If any prerequisite fails, expected-anchor and
   dependent association results are refused/unavailable. No startup,
   signer-loading, signing, recovery or restart authority follows.
4. **Destination ownership and mandatory revalidation.** Only after a
   successful gate may the route attempt the protected data-directory and
   lock-file operations. Acquire destination ownership under a separately
   approved mechanism, then revalidate the destination identity, route,
   deployment scope, and every mutable input used in the gate against the
   retained authenticated values. Do not silently reread and replace the
   accepted context. Any changed or unavailable value refuses before later
   protected effects.
5. **Protected runtime preparation.** Under retained ownership and the
   accepted context, perform only the owner-approved sequence for metrics,
   ordinary restore-completion inspection, consensus/account database
   opening and other designated effects. Hold the ownership mechanism
   continuously through the protected route. A future design must state
   whether and how each effect is serialized with revalidation.
6. **Signer load and later binding.** Immediately before `SignerLoaded`,
   ensure all gate preconditions and required revalidation still hold.
   Preserve signer loading as protected. After loading, compare the actual
   signer's validator ID, suite and complete derived public-key bytes with
   the authenticated public association. Refuse on mismatch or missing
   data, retain the exact loaded signer object for later uses, and do not
   reload a mutable path. Equality is a binding result only; it is not
   signing or startup authority.
7. **P2P construction and participation.** Only after the above results
   and any required signer binding succeed may P2P construction, listeners,
   dials, consensus tasks or participation proceed. That ordering would
   require separate implementation and operational evidence; no such
   enforcement exists today.

### Effects the proposed gate must precede

The owner-approved protected set is explicit: data-directory and lock-file
creation; metrics task creation; consensus- and account-database opening;
`SignerLoaded`; all P2P construction and participation. The proposal places
the gate before each of these. In current source, configuration parsing,
early policy/argument handling and external-genesis acquisition precede
destination ownership; reset can take a separate earlier effectful path.
This proposal does not claim that those steps are trusted or inherently
safe. Their acquisition costs, resource limits, file namespace behavior and
possible side effects must be reviewed. If any required trust input cannot
be established before the first protected effect, refuse.

## 5. Check-to-ownership race and feasibility

The gate is proposed before destination and lock-file creation, but the
current destination lock is obtained through the configured filesystem
namespace (`main.rs:2503-2548`). A path checked before ownership can resolve
to a different directory or filesystem object by the time creation or lock
acquisition occurs. Namespace changes can include symlink or mount
replacement, parent-directory substitution, rename/replacement, path
normalization ambiguity, and changes by another process. A check of a
string path does not bind the later opened object.

The current advisory lock only serializes cooperating processes that use
the same lock object. It does not prove that the path resolved to the
authenticated destination, prevent a hostile namespace writer from
substituting objects, or make prior reads and later effects atomic. Two
concurrent invocations can both evaluate first-use evidence before either
has acquired ownership. A later under-lock revalidation may detect a
mismatch, but it cannot undo data-directory or lock-file creation that
already occurred in an unauthorized or substituted destination.

Any future design must preserve an immutable checked context containing the
exact authenticated commitment and provenance, review-attestation bytes and
applicability result, expected deployment scope, pre-load observations,
association bytes/result and source identities. It must define the
filesystem object identity to which the gate result applies, not only a
pathname. It must then specify how ownership acquisition is bound to that
object and how revalidation is serialized with every subsequent protected
effect. No effect may occur in a window in which the binding is unknown or
stale.

**FEASIBILITY BLOCKER — ownership bootstrap and namespace race:** the
approved set makes directory and lock-file creation protected, yet those
operations are also how the current implementation establishes destination
ownership. Gate-before-creation followed by revalidation-after-lock leaves
a window in which the namespace can change and a protected create can occur
on the wrong object; detecting that after acquisition cannot reverse it.
Current source provides no reviewed atomic relationship between the
pre-gate authenticated destination and the later lock/directory object.
Owners must decide and independently review a race-safe ownership/bootstrap
model before implementation. Possible categories to evaluate include an
already independently established stable filesystem-object handle or an
external owner that serializes namespace ownership, but neither is selected
or proven here. If no approved model can bind gate evaluation to ownership
without an unauthorized protected effect, this route is not presently
feasible and must refuse rather than claim protection.

Revalidation is still required even if a future ownership model is approved:
it must be performed while ownership is held, before later protected
effects, against exact object identity and immutable retained inputs.
Revalidation is not a cure for an earlier forbidden effect. The necessary
ordering, atomicity, crash behavior, lock recovery, hostile-host limits and
non-cooperating-writer behavior remain unresolved.

## 6. Later signer binding and authority boundary

The pre-gate public association tuple must include validator ID, suite and
full public key from an independently trusted pre-load source. After the
gate and protected signer load, compare those fields against the actual
loaded signer and require exact equality. Do not infer the pre-load value
from the later signer and call it independently authenticated. Retain the
loaded signer object and the exact authenticated association/context; a
path change or signer reload requires a new reviewed check.

`SignerLoaded` remains protected even if loading is followed by refusal. A
matching public key, suite and validator ID does not authorize a signature,
consensus participation, startup, recovery or restart. Signer exclusivity,
which process may use the key, signing-history completeness and continuity
are separate and unresolved.

## 7. Excluded routes

The following remain outside this first design and need separate
route-specific fail-closed treatment. Current node source is **not** claimed
to enforce these Candidate B exclusions:

| Route | Required separate treatment |
|---|---|
| Snapshot restore | Restore can open production consensus storage for the pre-restore epoch check before restore INTENT (`main.rs:2552-2652`). If a future restore gate protects that open, it must precede it. Restore state effects and completion handling are not covered here. |
| Authority-state reset | The reset ceremony has a separate early path and effects before ordinary genesis handling (`main.rs:2211-2250`). Require a separately reviewed gate before its effects or an explicit independent refusal. |
| LocalMesh | It bypasses the P2P security preflight and enters a separate consensus route (`main.rs:5402-5465`). Add separately reviewed coverage or refuse. |
| Embedded genesis | DevNet/TestNet may skip external-genesis verification and have no boot-accepted canonical hash (`pqc_boot_genesis.rs:215-245`). Require another authenticated deployment-identity source or refuse. |
| No data directory | No configured destination identity or current destination lock exists (`node_config.rs:3992-3997`; `main.rs:2503-2548`). Define separately authenticated identity/ownership semantics or refuse. |

These are proposed scope exclusions only. They are not existing Candidate B
guards.

## 8. Unresolved decisions and future evidence

Before implementation review, owners must resolve:

1. Commitment authority, association approver, review authority, delegation,
   first-use enrollment and separation of founders, accounts, credentials,
   administrators, providers and recovery paths.
2. Complete authenticated commitment semantics and deployment/recipient
   identity; trust and provenance for genesis and any expected hash.
3. A separately trusted review-applicability input and its own authority,
   enrollment, currentness, withdrawal and changed-control semantics.
4. The pre-load source and provenance of every public association field,
   particularly complete validator key bytes, plus destination identity.
5. Bounded and side-effect-reviewed acquisition: size, work, time, parsing,
   path and external-source limits, and fail-closed handling.
6. The earliest protected operation and a race-safe relationship among gate,
   filesystem object identity, destination ownership, revalidation and
   protected effects. Resolve the ownership-bootstrap feasibility blocker.
7. The immutable handoff and later full-key/suite/validator-ID binding to
   the exact loaded signer.
8. Whether the selected route is viable without restore, reset, LocalMesh,
   embedded genesis or no-data-directory behavior, and how each excluded
   invocation is independently refused before its own effects.

Future adversarial controls are **FUTURE / NOT EXECUTED**. They should include
missing/ambiguous/conflicting commitment and review inputs; wrong recipient
and cross-deployment replay; common founder/account/credential/recovery
control; stale or inapplicable review evidence; genesis or expected-hash
substitution; over-limit, malformed and partial inputs; pre-gate path
replacement, symlink/parent/mount changes, concurrent invocations,
non-cooperating namespace writers, changed objects between gate and
ownership, and check/use mutation; refusal before each protected-effect
counter; and correct signer mismatch by validator ID, suite and full key.
Same-checker bypass controls should demonstrate that each required check is
material to the expected refusal, while a positive control prevents
reject-everything behavior.

Synthetic fixtures can demonstrate modeled decisions, bounded parser
behavior and mutation sensitivity only. They cannot establish real authority
or channel separation, first enrollment, credential custody, review
applicability/currentness, hostile filesystem behavior, atomic namespace
binding, concurrency serialization, actual protected-effect ordering, or
runtime signer enforcement. Those claims require independently reviewed
provisioning, storage/filesystem, binary/runtime and operational evidence.
No tests or operational evidence are produced by this document.

CB-1 remains CLOSED within its documentation scope. CB-FIXTURE-1 remains
within its accepted synthetic scope: the conflict fixture propagates a
supplied classification and does not detect conflicting review contents.
The 11/11 focused and compile-only results remain retained author evidence,
not hosted CI or an independent rerun.

Commitment/review currentness, association currentness, replacement and
revocation, signer exclusivity, signing-history completeness, durable
intent, fencing and recovery remain separate and unresolved. An authentic
old commitment or association may have been superseded. No rollback or
currentness protection follows from this proposal.

A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO. This document selects no actual key, algorithm,
channel, format, trust root, provisioning procedure, recovery procedure,
or production implementation.
