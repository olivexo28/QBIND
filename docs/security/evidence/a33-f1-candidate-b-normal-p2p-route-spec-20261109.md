# QBIND — Candidate B normal P2P route specification

**PROPOSED ROUTE SPECIFICATION ONLY. NO PRODUCTION WIRING, OPERATIONAL
PROVISIONING, STARTUP, SIGNING, OR AUTHORITY IS APPROVED.**

## 1. Scope and pinned inputs

This specification considers only a future ordinary P2P startup with a
configured data directory. It excludes restore, reset, LocalMesh,
embedded-genesis and no-data-directory routes. Exclusion is a design
boundary, not evidence that those invocations currently refuse or are
protected by Candidate B. No Candidate B verifier is present in production
source.

| Reference | Pinned revision |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed Candidate B endpoint | `c19fe2ab2c268b658f1aecb3f4c4808d5e8254a7`, tree `990571f7d0fd260d738ed1518aae79ddb2bf8e01` |
| Candidate B specification | `af55d73be9b3eb043a1997f7b0e6061121494fa7` |
| Trusted-input feasibility and route decision brief | The assessment is read-only and was not committed to the reviewed endpoint; its relevant findings are restated and source-pinned below. |

This document is based on the `main` and Candidate B endpoint above. Source
citations below refer to `main` at its pinned commit, not to an unpinned
working-tree state. Candidate B definitions, assumptions and accepted test
limitations refer to the reviewed endpoint. This is not a request to add a
verifier API, select an authority, or implement an effect barrier.

## 2. Existing normal-startup sequence (observed, not Candidate B)

The following describes the current binary control flow. It does not assert
that any step authenticates a Candidate B input or that normal P2P startup
currently refuses when one is absent.

1. **Entry and configuration:** `main` first intercepts the `identity`
   subcommand, parses CLI arguments, constructs `NodeConfig`, and resolves
   the hidden governance-execution policy. Errors exit. Several policy and
   MainNet-only argument refusals follow. These steps precede any
   Candidate B code because none exists (`crates/qbind-node/src/main.rs`,
   `aa382fa…:2009-2143`; `crates/qbind-node/src/node_config.rs`,
   `aa382fa…:3614-3633`).
2. **Genesis operator mode and reset mode:** `--authority-state-reset`
   takes an early, separate ceremony path and exits; `--print-genesis-hash`
   is another operator path that prints and exits. Both are excluded from
   this ordinary-startup route. Their effects and trust boundaries are not
   covered by this proposal (`main.rs:2211-2365`).
3. **External genesis:** on normal startup, `run_boot_time_genesis_verification`
   reads, parses and validates an external genesis when configured, computes
   its canonical hash, and retains that hash. For DevNet and TestNet the
   expected hash is optional; when supplied it is compared. A successful
   computation or comparison does not authenticate the genesis file or the
   source of the expected hash. Without external genesis, DevNet/TestNet
   follow the embedded-genesis path and return no boot-accepted canonical
   hash; that path is excluded here
   (`main.rs:2374-2449`; `pqc_boot_genesis.rs:17-34, 215-245`;
   `qbind-ledger/src/genesis.rs:1797-1855`).
4. **Destination ownership:** after genesis handling, when `data_dir` is
   configured, startup creates the directory if needed and acquires the
   advisory exclusive `restore.lock`, retained through startup. With no
   configured directory, this lock is absent; that route is excluded
   (`main.rs:2503-2548`).
5. **Restore routing and possible pre-restore storage open:** startup
   determines whether restore was requested and refuses certain restore
   combinations with CLI exit modes. If restore is requested on the normal
   path, it opens production consensus storage for the pre-materialization
   epoch check before restore INTENT publication. The same handle is reused
   later. Ordinary non-restore startup does not take this early restore
   open (`main.rs:2552-2652`). Restore is excluded from this first design,
   but an owner decision is still needed on whether storage opening itself
   is protected. If it is, a future design claiming restore coverage must
   gate before this early open; that is not solved here.
6. **Restore processing:** restore preconditions are checked and the guarded
   restore publishes INTENT before its state materialization hook; later
   startup persists the restored epoch and publishes COMPLETE. These are
   restore-only effects, not Candidate B-protected behavior. Restore is
   excluded pending a separate route review (`main.rs:2700-2855` and
   `main.rs:5180-5360`).
7. **Metrics and ordinary destination checks:** startup creates metrics
   state and starts the optional metrics HTTP task before the ordinary
   restore-completion-record check and before canonical consensus-storage
   opening. The ordinary check is performed only with a configured
   directory. Storage is opened and schema/recovery-probed fail-closed when
   the directory is configured (`main.rs:4990-5070, 5146-5190`).
8. **Account state:** the VM-v0 runtime is opened after the ordinary
   restore-completion check and after restore completion when applicable,
   before route dispatch (`main.rs:5370-5400`).
9. **Route split:** `main` dispatches LocalMesh directly to
   `run_local_mesh_node`, while P2P goes to `run_p2p_node` only when P2P is
   enabled; otherwise it exits (`main.rs:5402-5465`). LocalMesh is excluded.
10. **P2P preflight, signer, and transport:** inside `run_p2p_node`,
    `run_p2p_consensus_security_preflight` is called before
    `builder.build`. Within that preflight the local validator signer is
    loaded and its public key bytes are obtained. The builder then creates
    the P2P node/transport and startup proceeds toward the consensus loop
    (`main.rs:5665-5738, 8119-8135`; `signer_loader.rs:306-373`).
    Thus the existing preflight is before P2P service construction, but it
    is **not** before `SignerLoaded`. Candidate B currently protects neither.

### Effects before destination ownership

Destination ownership does not begin until after CLI/config processing,
early policy and argument refusals, reset/print-mode dispatch checks, and
external-genesis handling. In particular, the external-genesis file is read
and its identity computed before the directory lock is acquired. The
proposed specification does not assume these earlier steps are harmless or
Candidate B-authenticated. Owners must decide whether any of them count as
protected effects for the new gate, whether genesis/config inputs are
trusted enough to supply the gate's deployment context, and whether the
gate must run before directory creation or lock-file creation.

## 3. Proposed inputs and trust boundaries

A future gate for this route would return only a refusal-capable
**association-verification result**. It would not authorize startup,
signer loading, signing, participation, recovery, or restart.

### 3.1 Expected anchor commitment and deployment binding

The verifier would need an independently authenticated commitment to the
complete expected public association anchor and its intended scope. Its
authenticated meaning must bind the anchor value and suite, association
purpose, verification policy/version, recipient and deployment domain under
owner-approved identity semantics. The exact statement, encoding,
cryptographic mechanism, channel, trust root and provisioning procedure are
not selected. A raw digest match is diagnostic only; it authenticates no
sender or deployment (`Candidate B specification @ af55d73…:290-359`).

First-use authority remains unresolved: owners must identify how the
commitment authority and its delegation are independently authenticated at
enrollment, outside the anchor-delivery channel. If this trust cannot be
established independently, the gate refuses/unavailable. No local
configuration value, URL, path, digest or account label is self-authenticating.

### 3.2 Scoped channel-independence review applicability

The gate would additionally require separately trusted evidence that a
review applies to the actual commitment authority/channel, anchor/deployment
channel, recipient and deployment, and remains applicable. It must not be a
boolean flag, self-assertion, channel-name comparison, synthetic fixture, or
an unauthenticated local record. The review must address common authority,
account, credential, administrator, provider, recovery and failure-domain
control. Shared founder control, or shared accounts/credentials or recovery,
cannot be relabeled independent merely by using two channels.

The review authority's own first-use trust, delegation, evidence provenance
and applicability/currentness source are unresolved. An authentic statement
that a review once passed does not show that channel administration or
custody has not since changed. Missing, conflicting, insufficient or
inapplicable review evidence refuses/unavailable the authenticated-anchor
result; dependent association authenticity and equality are also
refused/unavailable. This review's current applicability is distinct from
whether an association or commitment is current
(`Candidate B specification @ af55d73…:149-194, 255-288`).

### 3.3 Deployment identity and observed public association tuple

Before comparison, a future verifier needs independently expected deployment
scope and observed public identity fields: environment, numeric chain ID,
full genesis identity, destination identity, validator ID, validator suite,
and full validator public key. Candidate B’s reviewed specification
identifies these as association tuple values and leaves their exact
relationship to the anchor commitment as an owner decision
(`Candidate B specification @ af55d73…:297-337`).

Current code exposes environment and chain ID through `NodeConfig`; for
external genesis it computes and retains a canonical hash, even if DevNet or
TestNet has no configured expected hash. If a DevNet/TestNet expected hash is
configured, it is compared. Neither the retained hash nor equality to a
configured expected value authenticates its source
(`node_config.rs:3614-3633, 5301-5312`;
`pqc_boot_genesis.rs:215-245`; `qbind-ledger/src/genesis.rs:1797-1855`).
The configured directory path exists as input, but its canonical identity
semantics and authentication as a deployment binding are not established by
Candidate B. Validator ID is available from configuration. The actual
validator public key is currently derived by loading the signer inside the
P2P preflight (`signer_loader.rs:306-373`), which is after `SignerLoaded`.

Therefore this specification does not claim the whole tuple is presently
available before signer loading. Owners must choose an allowed pre-load
source for the public association tuple, define destination identity
semantics, and approve a later same-key binding to the loaded signer. If
those inputs cannot be authenticated and checked before a protected effect,
the claimed route must refuse; do not move the gate earlier by assuming
unreviewed inputs are trustworthy.

## 4. Proposed protected-effect inventory and placement

The inventory below is proposed for owner review; it does not assert
existing Candidate B enforcement.

| Operation | Proposed classification | Placement requirement if designated protected |
|---|---|---|
| CLI parsing, `NodeConfig` resolution, policy validation | Configuration acquisition; no Candidate B guarantee. May read attacker-controlled inputs. | Decide whether policy/config construction itself is in scope. Invalid/missing trust inputs must not default to acceptance. |
| External-genesis read, parse, canonical-hash computation and optional expected-hash comparison | Input acquisition and computation; the hash is not provenance authentication. | Gate may depend on the computed value only if its source and meaning are separately authenticated. If reading or validating genesis is itself protected, gate must precede it, which may require a different trusted deployment identity input. |
| Data-directory creation and advisory destination-lock acquisition | Filesystem mutation/ownership setup before the current storage opens. | Owner must decide whether these are protected effects. If so, gate must precede them and cannot depend on an unauthenticated directory created by this invocation. |
| Metrics task creation/listening | Observable external service effect before ordinary restore check and storage opening. | If protected, gate must precede task spawn/bind. The route design must not assume current metrics ordering is already safe. |
| Restore-completion record inspection | Reads local lifecycle state. | Owner must decide whether protected; for this first route restore is excluded and invocations requesting restore must be rejected before restore effects by a separately reviewed boundary. |
| Production consensus-storage open/schema/recovery probe | Opens persistent state and acquires storage resources. Restore can open it earlier for pre-restore epoch checking, before INTENT. | If protected, normal non-restore gate precedes the ordinary open; any future restore design must gate before the pre-restore open. No restore protection is claimed here. |
| VM-v0 account database opening | Opens or validates account state before route dispatch. | If protected, gate must precede it. |
| `SignerLoaded` | Explicitly protected: loading local signing authority into process memory. | Gate must precede `load_validator_signer_from_config`; P2P preflight currently does not. |
| P2P node/transport construction, listeners/dials, consensus task and participation | External communication and protocol participation. | Gate and later signer binding must succeed before builder construction or any such activity. Missing/conflicting evidence refuses startup for the claimed route. |

**Earliest protected effect is an owner decision.** If the protected set is
limited to signing authority and P2P/network participation, `SignerLoaded`
is the earliest currently identified effect in this route. If owners include
data-directory creation/lock, metrics binding, storage opens, or account
state, that earlier operation becomes the ordering boundary. The source
provides no approved Candidate B first-use inputs or public association tuple
before these points, so this specification does not claim that moving the
gate ahead of them is feasible. A gate after one of those effects cannot
retroactively protect it.

The route also requires check/use consistency: the authenticated commitment,
scope, review evidence and compared tuple must be immutable retained values
or otherwise revalidated at use. Reopening mutable configuration or
re-resolving a path after checking is not sufficient. Threats from a host
that can replace both evidence and verifier state remain outside any
software-only claim (`Candidate B specification @ af55d73…:361-440`).

## 5. Proposed later binding to the loaded signer

After the gate has authenticated and compared the public association, the
P2P preflight would load the configured signer. Before any P2P builder,
listener, dial, consensus task or signing path, a separate check would
compare the loaded signer's validator ID, suite and complete derived public
key bytes against the already authenticated and equal association tuple.
Mismatch, absent key, unsupported suite, unreadable signer, or changed
identity refuses; no fallback to another key or unsigned participation.
The same loaded signer object/key must be retained for later use rather than
reloading a mutable path after the comparison.

This is a proposed binding, not existing protection. The public association
match alone grants no authority; loading a signer alone grants no authority;
even successful equality grants no signing, startup, recovery or restart
authority. Signer exclusivity and who may authorize its use remain separate
decisions. `SignerLoaded` remains a protected effect, so the first gate must
precede loading even though the actual-key equality check can only follow
loading.

## 6. Explicit route exclusions and required refusals

The first design must explicitly reject or otherwise fail closed before
protected effects when an invocation enters a route outside its scope. It
must not claim existing code already provides that Candidate B refusal.

| Excluded route | Why separate review is required |
|---|---|
| Snapshot restore | Restore has earlier transaction and state effects; consensus storage may open before INTENT for the pre-restore epoch check. Any later restore-capable gate must precede whichever of these effects owners classify as protected. |
| Authority-state reset | Early reset ceremony precedes normal genesis verification and has audit/marker effects. Needs its own gate before effects or explicit exclusion. |
| LocalMesh | Bypasses the P2P security preflight and starts the local consensus loop. Needs an equivalent separately reviewed gate or refusal. |
| Embedded genesis | DevNet/TestNet skip external-genesis verification and have no retained external canonical hash. Needs another independently authenticated deployment identity input or refusal. |
| No data directory | No destination lock or data-dir identity is available; persistent currentness/recovery semantics are not established. Needs independently authenticated destination identity and separately approved state handling or refusal. |

These are scope limitations, not route-specific implementation claims.

## 7. Unresolved decisions and evidence before implementation review

Owners must decide, at minimum:

1. Association-approval authority and its separation from the reviewer;
   whether any founder, account, credential, administrator, provider,
   recovery or break-glass control may be shared.
2. First-use trust and delegation for both the commitment authority and
   review authority, with a non-circular enrollment story and defined
   recipient/deployment binding.
3. What complete anchor and deployment identity are committed, how the
   expected and observed identity fields are sourced before protected
   effects, and how destination identity is defined.
4. Which operations in §4 count as protected, especially directory/lock
   creation, genesis reads, metrics effects, storage opens and account-state
   opening; identify the earliest effect the gate must precede.
5. The route's expected-hash policy and which independent trust source
   authenticates genesis and any expected hash. A computed hash or matching
   expected hash is not provenance evidence.
6. The post-load public-key comparison boundary and immutable-use handoff.
7. Exact fail-closed behavior for missing, unavailable, malformed,
   conflicting, insufficient, inapplicable or wrong-scope evidence.

Before implementation review, provide source-backed route-order analysis,
an owner-approved trust and threat model, independently reviewable evidence
for authority/delegation and channel control (including common recovery
domains), a field-by-field scope contract, and a proposed adversarial
verification plan. Any future tests for refusal, substitution, route
coverage, ordering, check/use mutation and signer mismatch are **FUTURE /
NOT EXECUTED**. Synthetic fixtures can exercise checker logic and mutations
only; real channel independence, initial custody/enrollment, review
applicability, deployment binding and runtime effect ordering require
independent provisioning, storage, binary and operational evidence.

Currentness of the commitment, currentness of the association, replacement
and revocation, signer exclusivity, signing-history completeness, durable
intent, fencing and recovery remain separate and unresolved. An authentic
old commitment, valid signature or matching tuple can be superseded. No
rollback or currentness claim follows from this route specification.

## 8. Prior accepted scope and status

CB-1 remains closed only within its documentation scope. CB-FIXTURE-1
remains limited to synthetic checker controls: the conflict variant
propagates a supplied classification and does not detect conflicting review
contents. The 11/11 focused tests and compile-only output are retained
author-run evidence, not hosted CI or an independent rerun.

A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO. This document selects no operational key, algorithm,
channel, format, trust root, provisioning procedure, recovery process, or
production implementation.
