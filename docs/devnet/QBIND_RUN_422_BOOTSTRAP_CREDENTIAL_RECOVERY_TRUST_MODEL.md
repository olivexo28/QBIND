# RUN 422 - Bootstrap credential custody and recovery trust model

**DRAFT / NOT APPROVED / NOT IMPLEMENTED**

**Selected recommendations, not operational approval.** Founder-authorized
bootstrap for one exact initial DevNet configuration is already settled by
`docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md`; this proposal
does not reopen that decision. It proposes custody, independent public-root
provisioning, and recovery/refusal requirements for that scope. No actual
device, operator, credential, trust anchor, recovery authority, rollback
protection, completed ceremony, activation, or deployment is established.
Approver, approval evidence, credential suite, key identity, and operating
profile remain unassigned. No key or fingerprint is generated or invented.

## 1. Baseline, scope, and contract ownership

Inspected starting commit: `9cf46e641c2889cc48c04ea84228f5117fc13877`.
Independently resolved root tree: `1d134e347187012546f4e110b0a9ec1594ec184b`.
Both objects are locally available and the commit's raw tree header matches.
The raw commit has one parent header:
`bca50c2ea896ac3041dea22659ea023fe0d45abe`. That parent object is unavailable
in this shallow checkout. Available-object traversal stops at the baseline;
the shallow log's empty parent display is not the raw parentage and does not
make the baseline a historical root. No older ancestry is established.

Repository origin is `https://github.com/olivexo28/QBIND`; starting branch was
`main`, at the required baseline with a clean working tree. Only
`copilot/run-422-bootstrap-credential-recovery-trust-model` is used for changes.
No `AGENTS.md` was found in the repository. This task creates this document
and appends notes only to the authority decision, separate-signer feasibility,
D7 evidence, and contradiction documents. Existing bytes, modes, EOL
conventions, and terminal-newline states are preserved. The new document is
mode `100644`, LF-only, with a terminal LF.

The current versions of these contracts govern; historical proposed or
partial findings must be read with their later scoped updates:

| Document | Authority retained by that document |
|---|---|
| `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md` | Settled founder role, exact founding scope, logical approval-record requirements; not credential provisioning or activation |
| `docs/devnet/QBIND_RUN_422_SEPARATE_SIGNER_FEASIBILITY.md` | Source-backed local/isolated/unsupported signer attribution; not a deployed service |
| `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` | Activation authorization and current-authority freshness, including founding-epoch and absent-QC restrictions |
| `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` | D10 journal semantics, reservations, canonical conflict identity, uncertainty and exact-result reuse; accepted local D10 result preserved |
| `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` | Node lock/safety-state recovery, decision-time restriction and recovered-state correspondence; accepted isolated D7D14 subset preserved |

This is a custody/recovery proposal, not a replacement wire protocol,
signature domain, parser, state schema, quorum rule, or second journal.
Source locators in section 8 refer to this baseline, not to the older
line numbers or producing revisions recorded in historical contracts.

## 2. Separate authorities and state owners

The following labels are requirements, not claims that their owners or
mechanisms are installed. Proposed accountable roles must be assigned before
implementation/operation; no person or organization is designated here.

| Obligation | Proposed owner and enforcing consumer | Trusted evidence needed independently |
|---|---|---|
| A - bootstrap approval | Founder approves; each operator's founder-root verifier authenticates; node and signer verify the same exact approval | Independently authenticated founder public root and valid purpose-bound approval covering the exact DevNet environment, network, canonical genesis, ordered membership, validator keys/suites, weights, founding epoch/profile and permitted scope |
| B - current-authority freshness | Current-authority state owner, still unassigned; node and signer enforce | Authenticated current approval/supersession/conflict state, retained outside the relevant rollback domain; historical A alone is insufficient |
| C - per-key signing-history continuity | Validator operator's designated stateful signer is the intended sole history authority; node must respect its decisions | Complete current reservations, exact bindings/results and uncertain outcomes for the key, preserving the existing stable-validator conflict namespace |
| L - node consensus-lock recovery | Node safety-state owner, under the validator operator; node enforces and signer checks the specified correspondence evidence | Recoverable effective lock identity and view, supporting QC/TC and authority context, committed-state association, and checked per-candidate evidence/ancestry under the recovery contract |
| X - cross-host exclusive signing | Validator operator's custody/exclusivity owner; all permitted signing routes must enforce | Evidence that only the designated authority can use the key, including exported/copied keys and old instances; no enforcing mechanism is established |
| U - unique authorized first use | Bootstrap activation-state owner, still unassigned; every node and signer enforce | Independently current, exact-identity first-use/activation state with replay and conflict refusal; missing files are not evidence of unused identity |

Founder approval supplies only the proposed A authorization. It cannot supply
B/C/L/X/U by assertion, reset history, override consensus locks, broaden
absent-QC permission, or extend the founding-epoch guard to later epochs.
The signer owns history for its key; it does not own or replace the node's
consensus lock. The node may not maintain a second independently authoritative
signing history. Cross-process ordering, durable acknowledgements, exact
candidate binding, and recovery correspondence remain to be specified.

## 3. Proposed credential custody

### 3.1 Dedicated founder bootstrap credential

Recommend a dedicated **post-quantum authorization credential under founder
custody**, normally offline, brought into controlled use only for the exact
authorized initial DevNet bootstrap purpose. It must be distinct from
validator consensus, transaction, transport, administration, governance
credentials for other purposes, and every future TestNet/MainNet credential.
**No remote signing service for this bootstrap credential** is proposed.
The separately protected validator signer is a different credential boundary.

| Custody requirement | Concrete proposed procedure and retained evidence | Unresolved operational fact |
|---|---|---|
| Inventory | Maintain a restricted custody inventory linking the full public key, role, environment, permitted purpose, lifecycle status, authorized access and every known usable original/backup/export; retain public identity and purpose separately from private custody locations | No key, suite, device, custodian, backup count, access principal, or inventory exists from this task |
| Controlled use | Before access, compare the complete intended approval input against the independently agreed manifest; verify purpose and unresolved/conflicting approval state; use a reviewed offline approval procedure; verify the resulting approval against the independently pinned root before distribution; record the use and return the credential to offline custody | Canonical approval format/domain, PQ suite/implementation, trusted offline execution environment, access controls and observation procedure require approval and evidence |
| Backup access | Authorize and record backup creation/access explicitly; protect confidentiality and integrity, keep access separate from ordinary node administration, track every copy and any exposure during retrieval; test retrieval later without authorizing another activation | Protection format, storage locations, access/recovery roles, copy count and integrity procedure are undecided; no home-grown splitting or threshold construction is proposed |
| Loss or suspected compromise | Suspend credential use and activation/transition dependent on it; retain public records and incident evidence; do not silently restore, generate or accept a replacement root; follow section 6 only if trusted recovery evidence exists | Replacement/retirement authority, authenticated distribution and currentness mechanism are not established |
| Retirement | After the unique initial use has been independently established, recommend retiring this credential from further authorization use; preserve public approval and conflict history, classify and control remaining copies, and require relying verifiers to enforce the retired scope | Activation boundary and verifier-side replay/retirement enforcement are missing; deletion or an inventory entry alone cannot retire authority |

Offline storage reduces routine network exposure. It does **not** establish
integrity of a key or signing environment, exclusive possession, currentness
of an approval, unique use, non-copyability, or rollback resistance. Malware
introduced during controlled use, tampered media, unauthorized copies,
coercion, founder equivocation and stale approvals remain in the failure model.
An offline use log itself can be lost, forged or rolled back; it is not U or B.

### 3.2 Validator signing credentials

Recommend that **each validator operator controls its own consensus key**,
with **one designated stateful signer** as the intended signing authority.
Place its key custody and authoritative history outside ordinary node
VM/database snapshot restoration and ordinary node administrative access.
The operator must demonstrate that separation against actual storage, backup,
administrator, provider, image, update and incident-control domains; another
VM or account alone does not demonstrate it.

The signing service must enforce the approved canonical request, identity,
operation/domain and evidence rules, reserve before key use, retain unknown
outcomes as potentially signed, and durably record exact results before any
permitted delivery. Request IDs are correlation, not signing positions.
Proposal/Vote continuity does not automatically cover Timeout/NewView or
shared-key interactions; their operation, state and dispatch policy is a
specific remaining decision. A signer is not assumed to run a second engine.
It must independently verify the evidence specified by the correspondence
contract or explicitly refuse what it cannot establish.

**No automatic hot-standby, same-key failover, local-key fallback, or
empty-history restart** is recommended. A process lock, dedicated host,
encrypted backup, operator promise, local shutdown or purported deletion
does not prove that another copy cannot sign. Signing-history ownership is
not proof of cross-host key exclusivity, and key control does not give an
operator permission to override consensus safety restrictions.

### 3.3 Backups: availability is not continuity

For the rarely used bootstrap credential, backup access addresses credential
availability; safe reuse still needs authenticated approval-use, conflict,
retirement and currentness evidence. A restored key and matching fingerprint
cannot establish that activation never happened or that an old approval is
still current.

For continuously used validator signing keys, **a private-key backup is never
sufficient validator recovery**. A proposed recovery package must associate
the exact network/validator/key identity with the full authoritative
reservation/result history, pending and uncertain outcomes, history-head
commitment, required node safety evidence and the independently current
reference needed to validate it. A snapshot of that package remains a dated
recovery input, not a freshness source. Restoring a key does not restore
history; possessing history does not establish the latest lock.

Backup policy must address confidentiality of key and access secrets;
integrity/authentication of restored records; authorized read/write access;
export and intermediate copies; stale history; unavailable signature bytes;
and uncertain writes/signing acknowledgements. Record copies created by
restore and migration in the custody inventory, never enable a restored
copy merely because decryption worked, and preserve obligations rather than
prune to make recovery succeed. Retained results may be resent only under
the existing D10 exact-binding, durability-acknowledgement, verification and
current-authority/recovery checks, with zero new signer calls.
Encryption is not authenticity, freshness or non-copyability by itself.
No key-splitting, threshold scheme, backup count or cryptographic suite is
selected here.

## 4. Independent public-root provisioning ceremony - PROPOSED / NOT RUN

Recommend a **manual, direct founder-to-operator root-authentication ceremony**
with an accountable founder-root verification role for each relying operator,
distinct in responsibility from bundle distribution and installation. Its
actual personnel, independence and identity-verification method must be
approved and evidenced; the procedure has not occurred.

1. **Authenticate the founder before trusting bytes.** Each operator's
   founder-root verifier directly establishes the founder's identity through
   a prearranged physical identity-verification procedure independent of the
   repository/download distributor and installer. The founder personally
   presents the full public credential and exact intended DevNet manifest
   in that controlled encounter. A claimed founder identity on an admin,
   email or messaging account is insufficient. If the verifier cannot
   authenticate the person independently, stop; no public key is yet trusted.
2. **Establish the reference independently.** From that encounter, retain the
   full expected public key and approved encoding/suite, explicit credential
   purpose, environment, exact runtime chain ID and wire correspondence,
   canonical genesis and hash, and complete ordered founding membership,
   validator identities/keys/suites/weights, founding epoch/profile and scope.
   Compare complete public material, not a short log fingerprint. Obtain the
   distributable bundle separately as untrusted input and compare it against
   the directly authenticated reference. Two downloads through the same
   compromised channel, even with identical hashes, are not independent.
3. **Verify exact approval and genesis.** Independently parse/canonicalize
   under the future approved format and existing genesis rules; verify that
   the founder approval covers every agreed field and the dedicated purpose,
   using the externally authenticated root rather than a key carried in the
   record. A config file, canonical hash or authority commitment alone is
   not approval of the whole configuration. Require a separate B/U decision;
   a valid signature and matching fingerprint are not fresh-authority evidence.
4. **Reconcile all public observations before installation/activation.**
   Operators exchange and compare the authenticated public references and
   approval observations under the approved ceremony procedure. Retain
   discrepancies, alternate approvals and refusals. Any wrong root,
   environment, configuration, genesis, unsupported format or conflicting
   founder approval stops activation for the affected founding configuration;
   do not select the first arrival, majority of downloads or convenient copy.
   Conflicts remain blocked without a separately authorized and independently
   current resolution rule, which is not selected here.
5. **Check each installed node and signer separately.** The installation
   verifier reads back the actual installed root, complete manifest, genesis,
   signing domains and validator-to-signer binding from each component, not
   only the source bundle or installer success output. Compare against the
   retained independent reference and cross-check node/signer consistency.
   Require evidence that the actual verifier uses those pins, rejects
   substitutions and has no alternate root, optional-pin or local-signer
   fallback. Today there is no implemented bootstrap-record consumer or
   working remote consensus signer to perform this procedure.
6. **Retain a public evidence package.** Preserve full public root and its
   algorithm/encoding identifier, exact canonical approval input and approval,
   genesis/configuration and their defined canonical commitments, public
   validator mapping, ceremony procedure/version, authenticated-reference
   provenance, verification/readback observations per node/signer, comparison
   outcomes, conflict/refusal records and approved B/U evidence when available.
   Keep private keys, passwords, private backup locations and personal identity
   documents out of the public package. Procedural sign-offs and timestamps
   record observations; they are not themselves PQ authorization, latestness
   or rollback proof. Public retention supplies auditability, not U.

### Infrastructure and human trust dependencies

The proposed direct identity encounter is a **human authentication assumption
inside the initial root-provisioning trust boundary**. It maps the already
selected founder role to the public credential; subsequent native approval
verification must use that independently pinned PQ key. Impersonation,
collusion, coercion or substitution during that encounter can install an
attacker root. A paper/reference copy and manual comparison do not provide
cryptographic PQ identity authentication or durable freshness. The exact
identity procedure, integrity of reference custody, and independent review
need evidence; this proposal asserts none of them operationally.

| Potential dependency | Proposed role and boundary | Assumption and compromise consequence |
|---|---|---|
| Repository access, HTTPS and DNS | Untrusted distribution/convenience outside the native root-authentication path | They may substitute, omit or replay bytes; independent full-root/configuration comparison must refuse substitution, while omission can deny availability; classical TLS is not the native PQ approval root |
| Email or messaging accounts | Logistics only, outside the native trust path | Account compromise can impersonate communications or hide conflicts; do not authenticate the founder, freshness or approval using that account |
| Cloud IAM and administrator identity | Access control/install management only, not native authorization | Compromise may replace binaries/pins or export keys; separation and actual installed-verifier integrity need independent evidence, not the administrator's identity or promise |
| Hardware attestation, HSM, firmware roots or hardware counters | Not selected as an authentication, custody or freshness mechanism | If proposed later, state whether in the native trust path, exact roots/algorithms and PQ dependencies, update/rollback/export assumptions, compromise consequences, availability and required device evidence; a product label is insufficient |
| Public evidence hosting | Audit/distribution outside the native authorization path | Host compromise can erase or serve stale observations; independent retention and a separately established B/U mechanism are still needed |

Moving any dependency inside native authentication or currentness requires
an explicit reviewed trust-boundary change; none silently becomes the native
post-quantum root. Even correct root provisioning does not protect against
a later compromised verifier binary or establish first activation.

## 5. Currentness and rollback boundaries

Ordinary crash durability, authentication of a historical record, latestness,
lock recovery and key exclusivity are separate properties. A signed old
record, counter in a restorable database, restored clock, matching epoch,
valid old QC, or pair of mutually stale replicas cannot establish currentness
after combined rollback. A fresh challenge authenticates latestness only
if its responder and retained latest state are independently trustworthy.
No currentness service, hardware counter, HSM or online witness is added
merely to fill that gap.

| Rollback/compromise domain | What must remain trustworthy outside it | Present conclusion |
|---|---|---|
| Node database/VM, including its local lock records and installed configuration | Signer-owned latest C history and X control; independently retained B/U state and root/configuration reference; recoverable L evidence not rewound with the node | Separate custody is recommended, not demonstrated; current signer history alone cannot reconstruct the required lock or prove B |
| Signer database/whole host, including local counters, key and binary | Authenticated latest per-key history commitment and sufficient full recovery material outside that restore/control domain; X evidence and independently current B/U; node L independently recovered | Node chain state, maximum view or an epoch-only observation does not cover all uncommitted/uncertain signing; no concrete outside mechanism established |
| Combined node and signer restore, including their backups and local references | Authenticated B/U and full C commitment/material plus required L recovery evidence and X control that cannot be rewound with either or their shared administrator/provider | Two stale copies cannot certify each other; safe same-key recovery is unavailable without a concrete mechanism and evidence |
| Bootstrap credential/reference or activation-state rollback | Independently retained authenticated root/approval/conflict evidence and current B/U/retirement state outside the affected custody/restore domain | Restoring an offline key or use log cannot prove unique first use or no compromise |
| Exported unrestricted validator key | Verifier-side authorized retirement/identity transition rejecting old-key effects at an explicit boundary, with current membership and replay rules | Local shutdown, deletion or host fencing cannot disable an already exfiltrated key; no such transition is established |

The outside state must authenticate exact identity, bind the relevant ordered
history and pending outcomes, resist replay/rollback under a named failure
model, and have durable update/readback and exclusivity semantics. It need
not be an off-box service, but its independence must be real against the
specified domain. A merely distinct host controlled/restored by the same
principal is not sufficient. Candidate mechanisms need explicit trust
boundaries, fault/partition/cold-start/all-restart models, PQ dependency
analysis and evidence at each layer in section 7 before selection.

**Without that evidence, retain refusal. Safe same-key recovery is unavailable,
not a procedure made safe by manual approval.** Refusal on missing mandatory
evidence does not claim that local code detects an otherwise indistinguishable
rollback. Founder statements cannot manufacture the missing evidence.

## 6. Intended recovery and refusal rules

**Every permission below is conditional future behavior, not an available
production operation.** A/B/C/L/X/U refer to section 2 and remain independent
gates. Owners below are proposed roles, not assigned operators. Refusal
retains records and incident evidence; it never initializes missing history,
silently resets counters, releases reservations or falls back to another key.
Common availability cost: loss of a signer removes its validator's votes;
multiple losses or shared control-plane failure can prevent quorum. No quorum
availability or recovery-time guarantee is made.

| Scenario | Required trusted evidence | State owner | Permitted action or refusal | Missing mechanism | Availability cost |
|---|---|---|---|---|---|
| 1. Clean restart with independently established current state | A/B/U exact current identity; complete acknowledged C history/results and uncertainty; validated effective L record/context and per-candidate evidence; X; reconcile any surviving writes through the required fresh durability barriers | Signer owns C; node owns L; separate B/U and X owners | Only after all gates: fresh eligible positions may reserve/sign; existing Signed positions may resend exact retained results with zero new signing; recovered Reserved stays potentially signed and refuses re-signing | Production recovery/authority/journal wiring and cross-process correspondence; actual durability, currentness and exclusivity evidence | Restart blocks signing until gates complete; uncertain positions may remain unavailable |
| 2. Node-only snapshot rollback | Independently current signer C and B/U/X; sufficient current L evidence outside node restore; exact restored-state/history and candidate correspondence | Node recovery owner, signer history owner | Block new signing and reuse until L and correspondence are re-established; refuse conflicting requests at covered positions; epoch equality or signer response success does not license resumption | Node lock persistence/recovery and authenticated correspondence, plus demonstrated separate rollback domains | Validator unavailable during reconciliation; stale snapshot may be unusable |
| 3. Signer-only rollback | Authenticated latest C head and complete obligations/results outside signer restore, B/U/X and independent node L; positive current-state reconciliation | Signer history/recovery owner; node retains L | Refuse the restored signer; resume same key only if complete current history and exclusivity can be established, never by restoring a key alone | Domain-external history/currentness and safe recovery/import protocol; newer node state alone is insufficient | Same-key recovery unavailable without evidence; potentially indefinite signer outage |
| 4. Combined node-and-signer rollback | Independently authenticated latest B/U, full C history commitment/material, recoverable L and X outside both restore domains | Each state owner plus unassigned external-evidence responsibility | Refuse all dependent effects while currentness/recovery is unestablished; do not compare two stale stores and call that freshness | Concrete outside mechanism and recovery proof; local valid records/counters cannot detect this case | Safe same-key recovery unavailable; entire network may remain stopped |
| 5. Lost, incomplete or stale signing history | Independently authenticated complete current reservations, uncertainty and exact results for the key, current B/U, L and X | Signer history owner | Refuse new signing and unvalidated reuse; never infer first use from missing state or reconstruct full history from committed blocks/max view; restore only under a separately accepted complete reconciliation protocol | Full-history recovery source, binding and currentness; no accepted lossy reconstruction/pruning rule | May permanently lose same-key signing availability |
| 6. Crash or lost acknowledgement after possible signing | Observable durable reservation/result identity and current acknowledgements; exact retained bytes if available; current A/B/U/L/X | Signer owns reservation/result; node owns publication and L | Unknown outcome remains potentially signed; no new invocation or release for recovered Reserved; exact retained reuse only after D10 barriers, signature/binding verification and current recovery checks; absent result stays refused | Cross-process effect/ack protocol and independent history reconciliation; local D10 does not establish RPC or device power-loss behavior | Position and possibly signer blocked; lost result may be unrecoverable |
| 7. Planned signer migration | Complete current C including uncertainty; authenticated same-identity handover binding old/new instances and history; B/U/L; proven X before replacement use and rejection of stale-instance effects | Validator operator's custody/migration owner, signer C and node L owners | Stop affected signing; transfer only under a separately accepted protocol; no overlapping use, automatic standby or history namespace reset; without enforceable exclusion refuse same-key migration | Migration protocol, current handover state, cross-host exclusivity and copied-key handling; no mechanism selected | Planned outage with no promised recovery time; migration may be unavailable |
| 8. Concurrent instances or unrestricted copied validator key | Evidence of all known copies and compromise; enforceable X for permitted instances; for exfiltration, authorized verifier-side retirement/transition with current boundary and old-history preservation | Operator incident/custody owner; membership/lifecycle retirement owner unassigned | Stop permitted local signing, preserve evidence and refuse ambiguous same-key continuation; do not claim shutdown/deletion/fencing disables the exported key; no automatic replacement | Verifier-side old-key rejection, authorized membership/key transition, replay and partial-cutover handling; initial fixed founding scope does not authorize it | Validator or network may have to stop; attacker signatures remain possible; original-network recovery not guaranteed |
| 9. Bootstrap credential loss before activation | Independent public-root/approval evidence; current U proving whether any activation or possibly conflicting approval occurred, B and compromise assessment | Founder custody owner and B/U owners | Stop activation; intact existing approval is usable only if all gates independently hold, not because the private key is lost; backup access/replacement requires the approved custody/recovery rule; uncertain first use refuses | Loss assessment, backup-access policy and independently authenticated replacement/retirement and B/U mechanisms | Bootstrap delayed or unavailable; no root inferred from a replacement key |
| 10. Bootstrap credential loss or compromise after activation | Independently established activation boundary, current B/U and authenticated incident/retirement evidence; unaffected validator C/L/X; for compromise, complete conflict scope where establishable | Founder custody/incident owner, B/U owners; validators retain C/L | Loss alone does not reset validators or require restoring this key to sign consensus; any continued operation would require independently established unaffected current authority and all safety gates. Compromise/conflicting or uncertain authority blocks affected operation; do not approve another bootstrap or history reset | Enforceable one-purpose retirement, conflict detection/currentness and authorized root/authority transition; no post-compromise recovery authority established | Bootstrap/transition use stops; authority uncertainty can stop network; unaffected-state continuation is not operationally available today |
| 11. Conflicting bootstrap approvals or root installations | Independently authenticated full roots, exact approval inputs and conflicting observations; current B/U; any resolution authorized under an already accepted policy | Operator founder-root verifiers and unassigned conflict/B/U owner | Stop activation of the disputed configuration at all relying components; isolate mismatched installs, retain both observations; no arrival-order choice, download vote, repinning or manual safety override | Conflict-resolution authority/policy, authenticated consistent distribution and rollback-safe supersession/unique-use enforcement | Network start/cutover blocked indefinitely absent valid resolution |
| 12. Recovery evidence unavailable or unverifiable | All mandatory A/B/C/L/X/U evidence with independent provenance, currentness, complete bindings and durability acknowledgements | Owner of missing evidence; each node/signer must enforce refusal | Refuse dependent signing, reuse, activation or transition; distinguish unavailable comparison from proven mismatch; preserve obligations; no timeout-based unsafe resume or new empty history | Each missing verifier/source/recovery capability, identified explicitly in the incident; no success-shaped default | Loss of availability for as long as evidence remains missing, potentially permanent |

Manual incident approval can authorize investigation, evidence access and
permitted recovery steps; it cannot turn missing history into never-used
history or permit a lock-conflicting signature. Unknown signing outcomes
remain potentially signed even if no peer reports receiving a signature.
The local D10 surviving-result/re-acknowledgement rules remain useful but do
not supply independent currentness after rollback.

If an unrestricted key escaped, prevention requires relying verifiers to
reject old-key effects under a separately authorized, current membership/key
retirement or transition policy, with explicit cutover, domain/identity
binding, replay, partial installation, stale verifier and recovery rules.
Neither local fencing nor a founder approval of new keys implements that.
The fixed founding membership and epoch are not silently amended.

**A newly authorized network with new identities is a separate bootstrap,
not recovery of the original network.** It does not preserve original
signing history, assets, membership authority, consensus history or safety
by implication. Any such continuity would need its own authorized protocol
and evidence, neither supplied here.

## 7. Future acceptance matrix - FUTURE / NOT EXECUTED

Every cell names evidence still required, not a PASS or new execution. A
matched case tests only permission under complete prerequisites; it is not
deployment approval. Historical source/storage/process results retain their
original producing revisions and scopes and are not rerun or reattributed.

| Scenario / intended outcome | Source/test evidence required | Independent-process evidence required | Release-binary evidence required | Actual operator/device/deployment evidence required |
|---|---|---|---|---|
| Matched independent provisioning: conditional admission only | Exact approval/domain/root/manifest binding and all A/B/C/L/X/U gates | Separate node/signer installation readback and identical reference enforcement | Actual startup uses mandatory independent pins and no bypass; complete path admits only matched scope | Founder identity procedure, public reference provenance, custody/access inventory, ceremony records, actual install and currentness/exclusivity proof |
| Substituted root/configuration/environment/genesis: refuse | Every bound field mutation rejects before activation, reservation or key use | Different delivered/install copies cannot evade comparison | No embedded/optional-pin or alternate-root/local-key fallback | Independently obtained full reference survives compromised distribution and installer controls |
| Conflicting approvals/root installs: stop | Conflict state, no first-arrival/manual override and no unsafe supersession | Withheld/reordered/conflicting approvals and partial installs remain blocked | Actual entrypoints refuse ambiguous authority with public diagnostic evidence | Independent observation exchange, conflict retention and authorized resolution/current B/U outside rollback domains |
| Stale backups or lost history: refuse | Missing/corrupt/stale records never initialize/reset; full bindings and uncertainty retained | Restore key without history and stale package; prove independent source or refusal | Startup/reuse cannot silently adopt old/missing history | Backup confidentiality/integrity/access/copy inventory and independently current full recovery evidence |
| Crash uncertainty/lost acknowledgement: potentially signed | Fault points at reservation, invocation, result, durability ack and delivery; exact reuse has zero signer calls | Real distinct owners, possible sign then crash, lost ack and reconnect reconcile only exact operation | Actual guarded path and refusal/delivery counts; no retry fallback | Actual storage/device durability and acknowledgement semantics; process death is not power-loss proof |
| Copied keys/concurrent instances: no unsafe same-key continuation | Local ownership scope explicit; no namespace reset; old-key transition policy if later approved | Concurrent old/new hosts and exported unrestricted-key attempts, not only one-process locks | All permitted routes enforce X and any later verifier-side retirement | Real key export/access assumptions, cross-host controls and compromised-copy consequences; local deletion cannot be credited |
| Planned migration: no overlap or erased obligation | Exact history/handover binding, preserved pending results/uncertainty | Interrupted handover, stale old instance, partial transfer and ack loss | Migration/restart cannot activate replacement before accepted gates | Actual old/new custody, outside-current-state and exclusion evidence; absent proof migration refuses |
| Node-only, signer-only and combined rollback: refuse without independent recovery | Separate C/L/B/U obligations and locally indistinguishable whole-copy case | Each restore domain exercised, including same-epoch and both replicas stale | Actual restore/startup paths block signing/reuse with missing gates | Named outside state survives each real restore/admin/provider domain, cold start, partition and all-validator restart |
| Bootstrap loss/compromise before and after activation: no inferred replacement | Stage-specific loss, retirement, conflict and currentness rules; validator history remains unchanged | Missing credential, replayed approvals and compromised-root observations | No automatic root replacement, second activation or history reset | Custody/incident evidence, independently established activation/retirement boundary and authorized recovery policy |
| Founder/operator attempted history or lock override: refuse | Changed key/suite/label cannot erase stable conflict identity; unknown outcomes and L restriction preserved | Manual approval/reset/migration cannot bypass history owner or node lock | All real entrypoints reject override and unsafe local fallback | Operator procedure/access enforcement and retained refusal evidence; policy approval alone proves no safety mechanism |
| Unavailable/unverifiable recovery evidence: refuse | Typed unavailable versus mismatch; no silent defaults or timeout permission | Missing/partitioned/conflicting evidence source and unrecoverable result | Actual release preserves disabled/unavailable behavior and explicit failure | Actual outage and incident handling preserve safety despite availability pressure |

Source tests cannot establish human identity, custody, storage/device
durability, administrative independence, key non-copyability or a real
rollback-resistant source. Independent processes cannot prove the actual
release wiring; release results cannot prove actual operator/device facts.
Future evidence must name the revision, binary, procedure and failure domain
actually exercised. This documentation task performs only documentation
checks; no tests, builds, scans, service startup, keys, activation or deployment.

## 8. Source-grounded implemented behavior and limits

These baseline source observations bound the proposal. They are not newly
executed test, process, release-binary or operational results.

| Baseline source locator | Inspected behavior | Attribution limit |
|---|---|---|
| `crates/qbind-node/src/pqc_boot_genesis.rs:215-247` | External genesis is loaded and passed with optional expected hash to canonical verification; DevNet/TestNet can take the skipped embedded path | Existing comparison is not independent root provisioning, mandatory proposed pinning, founder approval, B or U |
| `crates/qbind-node/src/genesis_consensus_authority.rs:334-438,758-849,1462-1479` | Genesis authority derives ordered validator keys, fixes supported suite/equal weight in the builder, restricts founding epoch; commitment covers chain/genesis/ordered IDs, suite and keys | Not an exact bootstrap approval-record verifier; commitment does not separately encode every proposed field, including explicit weights or founder credential/approval |
| `crates/qbind-node/src/genesis_consensus_authority.rs:1069-1168` | CurrentAuthorizationOwner generation is in-process; production constructor makes current state unavailable | Neither durable latestness nor an established production activation source |
| `crates/qbind-node/src/main.rs:5405-5418,6139-6149` | Explicit genesis-authority activation request exits nonzero before mode dispatch; preflight Proposal/Vote authority is None, separate from Timeout/NewView context | Production refusal, not positive configured authority or bootstrap approval |
| `crates/qbind-node/src/binary_consensus_loop.rs:2807-2851,3133-3147,4348-4430` | Fresh engine with optional snapshot baseline; production inbound handoff supplies no current owner/journal; otherwise signer-eligible Proposal guard refuses missing journal before signer | Actual unwired production boundary; local guarded code is not separate-signer recovery |
| `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2598-2618,2665-2688` | Restart accepts committed id/height and logical lock input and resets volatile latches; snapshot baseline carries no QC/history input and resets latches | Does not restore uncommitted reservations or establish sufficient current lock recovery; no recovery override inferred |
| `crates/qbind-node/src/signing_reservation_journal.rs:1-39` | Local non-authorizing durable reservation, conflict/refusal, retained reuse and potentially-signed recovery contract | Local D10 code/storage and historical process evidence only; no independent rollback source or production initialization |
| `crates/qbind-node/src/safety_record_store/mod.rs:1-31`; `crates/qbind-node/src/safety_record_store/backend.rs:358-365` | Maintained isolated O1-O5 component, default Disabled; recovery evidence Unverified absent separate verification; no production wiring | Preserve implemented isolated subset, not whole-lifecycle integration, recovery authentication or anti-rollback |
| `crates/qbind-node/src/signer_loader.rs:306-330`; `crates/qbind-remote-signer/src/main.rs:467-597,627-687` | Production loader refuses remote/HSM modes; daemon accepts sockets without handshake/handler dispatch; validate_and_sign is an unreachable helper | No live stateful remote consensus signer, actual custody or deployable HSM inferred |
| `crates/qbind-node/src/remote_signer.rs:346-382,411-428,904-921`; `crates/qbind-node/src/validator_signer.rs:370-400` | TCP decode_response checks echoed request ID; sign_common does not; client constructs Timeout preimage; LocalKeySigner sign_vote signs supplied bytes unchanged | Dispatch named sign_vote alone proves no wrong Timeout domain/signature. Canonical server operation/domain validation and backend dispatch/policy remain unresolved; transport correlation is not C |

The feasibility assessment separately identifies the `pqc_remote_*`
governance/trust-authority source/test family; it is not the consensus signer
(`crates/qbind-node/src/pqc_remote_authority_signer.rs:1-40`;
`crates/qbind-node/src/pqc_production_remote_signer_backend.rs:1-55`).
No older resolved attribution error is reinstated, and isolated maintained
helpers or their tests are not called missing source or production wiring.

## 9. Evolution, trade-offs, and unchanged posture

DevNet, TestNet and MainNet require distinct network identities, authorization
records and credentials. Preserve planned movement toward joint independent
authority before MainNet, with a separately approved prior-authority transition,
exact new scope, continuity, supersession/retirement and rollback-safe cutover.
No participants, approval thresholds or novel cryptography are selected.
Initial founder approval is a configuration-level bootstrap event, not a
per-transaction approval step or ongoing validator signing credential.

Founder trust is concentrated: compromise or equivocation can authorize
conflicting starts, so provisioning/conflict/currentness gates cannot be
replaced by faith in the role. Separate signer custody adds operational cost:
privileged service management, independent state/backup control, ordered
durable effects, authenticated cross-process messages, recovery evidence and
planned outages instead of hot failover. Shared administrators/providers may
collapse that separation. Refusal favors safety over availability and can
leave same-key recovery permanently unavailable; it does not cure an exported
key or promise quorum liveness.

This proposal establishes **no TPS, latency, resource, hardware capacity,
availability or recovery-time guarantee**. No candidate resource limit is
approved. A future witness, HSM, cloud service or protected counter is not a
default solution: its actual trust boundary, failure/rollback/copy model,
authenticated history binding, PQ dependencies and evidence must be reviewed
before proposing it as a selected mechanism.

Preserved without promotion:

```text
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
Whole native-admission and authority contracts: DRAFT / NOT APPROVED / NOT IMPLEMENTED
Section 13.6 whole-lifecycle: INCOMPLETE
Activation: DISABLED
Public DevNet: NO-GO
Durable anti-rollback: NOT-ESTABLISHED
C4/C5: OPEN
RS1: OPEN
Candidate resource limits: UNAPPROVED
```

No F1/F2 closure, positive production authority, production-consistency
guarantee, deployment permission, operational security property or release
approval follows. No custody ceremony or recovery mechanism was established
operationally by this task.

## 10. Implementation-entry checklist

Before a separately authorized implementation task, resolve and document:

1. **Credential and approval contract:** reviewed PQ suite/key encoding,
   canonical purpose-bound record and complete configuration binding, parser
   bounds/refusals, offline use/inventory/backup-access and retirement policy;
   do not generate operational credentials as part of design approval.
2. **Root ceremony responsibilities:** accountable founder-root verifier and
   installer roles, independently authenticated physical identity/reference
   procedure, public evidence package, conflict handling and actual
   node/signer readback/mandatory-pin verification plan.
3. **B/U and loss/compromise policy:** exact current-authority and unique-first-use
   state owner, outside-rollback mechanism or explicit continued refusal,
   update/readback/retirement/supersession semantics, and who may authorize
   replacement or conflict resolution under which pre-existing policy.
4. **C/L process correspondence:** sole signer history ownership, complete
   canonical request/position/evidence and exact-result bindings, node lock
   recovery/decision-time frontier, effect/ack/retry ordering, surviving-write
   reconciliation, and explicit Timeout/NewView/shared-key scope.
5. **X and recovery boundary:** actual custody/admin/backup/restore domains and
   trustworthy state outside each; complete-history recovery proof, no-overlap
   migration and verifier-side retirement/identity-transition requirements
   for copied keys. If no concrete safe mechanism is supportable, retain
   unavailable same-key recovery rather than invent one.
6. **Evidence and approval gates:** map every section 7 row to source/test,
   independent-process, release-binary and actual operator/device evidence;
   name revisions and failure models, including power-loss, partition and
   all-restart limits. Implementation acceptance, resource-policy approval,
   operational custody/provisioning evidence and explicit activation/release
   approval are separate later gates; none is satisfied by this draft.
