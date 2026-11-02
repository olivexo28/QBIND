# QBIND Public DevNet Critical Path — Run 422 current reconciliation

> **Public DevNet: NO-GO. RS1: OPEN / launch-blocking. Activation: DISABLED.
> Durable anti-rollback: NOT-ESTABLISHED. C4/C5: OPEN.** M4 remains Yellow and
> launch-blocking; M6 remains Yellow / Partial. The intended operating profile
> is **UNRESOLVED**: Profile A is a proposal, not approved policy. This is not a
> TestNet or MainNet readiness assessment.

## 1. Scope, baseline, and provenance

This documentation-only reconciliation was prepared from required starting
commit `a47688b178397e2189282078f756ce5b51f0be66`, root tree
`efa87d68d74d1a60492032f6baf8e1cbeee98b5e`, on
`copilot/run-422-public-devnet-readiness-reconciliation`. The starting worktree
was clean; origin fetch/push is `https://github.com/olivexo28/QBIND`. The raw
starting commit header names parent
`081c95e9ba65ef5925183a16974b85e189602acb`, whose object is unavailable at the
shallow boundary. That is not evidence of a parentless commit; ancestry through
that unavailable object is indeterminate. No applicable `AGENTS.md` was found.
This assessment changes no runtime, policy, activation, readiness verdict,
resource limit, seed, or deployment.

The replaced critical-path assessment was blob
`6354dce1c04836103f66e4940fa224aa4599b5f3` (mode `100644`). Its provenance
identifies inspection at `de05c009a130d7d044a0c896b8a8559b00b411e4`, root tree
`4fcb30ffd7b387aefdf647dc7725f78fa61fb287`. That is document-reported
provenance, not fresh execution or a newly established ancestry claim here.
This version preserves its historical conclusions where still applicable and
explicitly supersedes its now-stale statements that native auth was entirely
empty-auth fail-open and that isolated TC/O4 pre-effect composition was the
next unimplemented task. The D7 and contradiction records remain append-only;
their complete starting bytes are retained as exact prefixes.

## 2. Governing sources and current caller boundaries

The launch rule remains the canonical rule in
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`,
`docs/release/public-devnet/BLOCKER_REGISTER.md`, and
`docs/release/public-devnet/LAUNCH_GO_NO_GO.md`: all must-have M1–M20 Green,
RS1 closed with deployed-path executable evidence, and launch explicitly in
scope. Otherwise NO-GO. The F1–F8 definitions and deployed-binary versus
harness boundary are in
`docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`.
Activation, freshness, and signing/consensus continuity are separate under
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`; recovery
and decision correspondence are governed by
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` and
`docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`.
Native admission, key identity, and authority remain governed by
`docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_RESOURCE_ASSESSMENT.md`,
`docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_STATE_CONTRACT.md`,
`docs/devnet/QBIND_RUN_422_NATIVE_AUTH_KEY_IDENTITY_CONTRACT.md`,
`docs/devnet/QBIND_RUN_422_NATIVE_GOVERNANCE_AUTHORITY_CONTRACT.md`,
`docs/devnet/QBIND_RUN_422_NATIVE_VALIDATOR_AUTHORITY_CONTRACT.md`, and
`docs/devnet/QBIND_RUN_422_NATIVE_KEYSET_CREATE_AUTHORITY_CONTRACT.md`; these
remain DRAFT / NOT APPROVED / NOT IMPLEMENTED. Findings in
`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md` are correlated with current code
below; Run 422 evidence and corrections are in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and
`docs/whitepaper/contradiction.md`. Neither audit conclusions nor test
artifacts are a policy decision or current release validation.

**Current production startup and consensus.** In `crates/qbind-node/src/main.rs`,
consensus-security preflight runs before P2P construction. The production binary
selects `ConsensusVerificationPolicy::Required`; `LocalFixtureUnsigned` is
test-only. Timeout/NewView verification context and Proposal/Vote authority
are separate. The timeout context does not grant Proposal/Vote authority.
Current production wiring supplies no Proposal/Vote authority, no current
authorization owner, and no signing journal; genesis-derived activation
remains disabled. Required policy therefore refuses inbound Proposal/Vote and
suppresses outbound Proposal/Vote. This is fail-closed unavailability, not
configured consensus readiness. Mandatory timeout preflight and inbound QC
checks do have runtime call paths, subject to their own configuration and
proof inputs; their existence does not establish a configured-authority
lifecycle or release-binary acceptance.

**Transaction paths are distinct.**

* Native `qbind_wire::tx::Transaction` flows through
  `qbind_runtime::TxExecutor` / `BlockExecutor` to native system programs, with
  authentication in `qbind-ledger::auth`. Public `QbindNode::apply_block`
  (`crates/qbind-node/src/lib.rs`) decodes proposal transactions and invokes
  `BlockExecutor`, but no caller from production `main.rs` is established.
  Harnesses and tests invoking that API are not deployed reachability. The
  current standalone binary consensus proposal construction uses empty
  transaction lists. The absence of a production caller is not cryptographic
  closure of F1/F2.
* Ledger `QbindTransaction` uses the nonce/VM execution and node
  `ExecutionAdapter` route. `hotstuff_node_sim` and integration/cluster
  harnesses attach this adapter; no such adapter is constructed by the
  standalone production consensus path reviewed here.
* Runtime `QbindTx` uses the separate `qbind-runtime` block/EVM/Revm route.
  `EvmExecutionBridge` documents the `NodeHotstuffHarness` composition;
  its integration tests do not establish standalone `qbind-node` production
  execution.

The DAG mempool and peer batch facilities are not evidence that any of those
three transaction-execution routes is wired into the standalone binary.
Likewise, public APIs and passing harness tests alone do not prove deployed
reachability.

## 3. Completed scoped work retained (not reopened)

These are component or test-scope results, not full RS1 closure, production
integration, or release approval.

| Obligation | Completed scope and producing evidence | Still not established |
|---|---|---|
| Native structural/format admission | Current `crates/qbind-ledger/src/auth.rs` rejects empty auth, enforces exact signer-index coverage, transaction version/reserved-byte rules, checked streaming digest, complete borrowed stored-keyset framing, returned account ID/owner/non-executable status, provider-returned suite-ID consistency, stored version/reserved fields, nonzero threshold and individually sufficient first-selected key weight. The current source blob is `47b8309be4b42ab284b184f9ccf6ea12eecb1382`; the earlier threshold source blob was `895763fd47267a008fe10e2729b5db73606ca8cc`. Threshold controls were tested at test commit `31af27f46aef427299fc83bffdfaaee7c0077753` against production source commit `0a163bb733f7dd160a588b5aa11cd37ad13fd143`; format controls at test commit `15b53f496c8164d5bab4bff2713c44de5413e81b` against `da9bb1ffac15a5d2746014dcb89f8c1d36a5ea92`. | Not full weighted authorization: no aggregate weight across identities/proofs, canonical alias/duplicate consistency, common-state semantics, replay/freshness, approved limits, independent program authority, or production caller. The historical 990-selected package result belongs to `1112d4b9f93a281085c10a0b4fd016f9194f0f0e`, not the later corrected identity-test revision. |
| Canonical key identity characterization | Corrected alias-order, repeated-proof, exact-snapshot retry controls: focused 6/6 at source `52a9bcd1280c002755311c2a5d290b67691b11b1`. | Focused test only; does not change first-match production semantics, approve resource bounds or establish production authorization. Do not transfer the earlier 990-package result to this revision. |
| Native privileged-program authority | Governance, validator registration, and keyset creation refuse when authority is unavailable. Refusal evidence is distinct from earlier successful-write characterization. Refusal-producing source/test revisions: governance `99023fcb30ec2c6c042dea0f0196b88c072049ac` (runtime focused 6/6); validator `02198fac5ba638a1fbcbc2c5361fce7116a33e51` (runtime focused 15/15); keyset `92ba29ee13b2470e4b21b681aefcd8cf1ecf3264` (runtime focused 9/9). Historical successful-write characterizations only: governance `c279c7be1cc415032975f162109e5e2c3f9c6ed0`, validator `8769118ef4b5b27631a4177862b1dc91cd66c7ca`, keyset `ce25c42e3a389608832294c29bf5d2cdc7a59a6d`. These historical results were not rerun here. All are source/library tests, not production integration. | No usable authority, configured production caller, or conclusion that refusal makes governance/registration live. |
| D7 D14 storage | `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`. Preserve the independently reviewed 23-row accepted subset: candidate `aad0a4aaca8f66580d257c3468f1c27059145dbd`, reviewed evidence `ecf4cfdcc36e9438293173d89e44cd819d709ca5`. | Later isolated extensions do not enlarge that accepted subset or establish production ownership/publication/recovery. |
| Signing and safety-record components | D10 local signing-reservation journal and guarded signing refusal; O1–O5/owner/publication/recovery compositions; QC verification, retention, and staged-effect work exist at their cited D7 revisions. D10 is positive only in its demonstrated local code/storage-test scope. | No production journal/owner construction or exact engine-decision-to-generation binding. Whole §13.6 lifecycle remains INCOMPLETE. |
| TC/O4 and explicit O5 | Isolated TC/O4 publication composition and corrections were tested, including final finishing source `37709512d03c547d32d3494d4270bf04c2ad28d1`; explicit O5 and exact-TC resumption were tested at `0553e374edf6a9221870b9c5e4f8a6689af3901f`. The latter retained in-process evidence and did not model process-death reconstruction. | No production TC/O4 caller, no full TC lifecycle acceptance, no activation or recovery guarantee. The previous section 5 TC/O4 recommendation is completed in isolation and is superseded; do not repeat it. |
| Native context and staged effects | Context slice tested at `34ee33fd5c96c6d78d9979293411823fa622a170`; staged-effects model and keyset-create model tested at `beec901e974715932f0d3faf6470189d0c562fec`. | Unused in-memory/test slices; no approved state contract or operational cap. `DRAFT / NOT APPROVED / NOT IMPLEMENTED` and candidate limits `UNAPPROVED` remain. |
| F5/F7, domain, and exhaustion checks | Mandatory timeout gates, bounded retained-QC revalidation, domain-v2 signing, and timeout/QC exhaustion controls remain implemented with their producing revisions in D7 E7–E9 and D6. | Conditional caller prerequisites and historical tests do not establish configured-authority release-binary evidence, full recovery, or RS1 closure. |

The corrected native key-identity test source received focused validation only;
the historical 990-selected package run remains attributed solely to
`1112d4b9f93a281085c10a0b4fd016f9194f0f0e`. No result is reassigned to the
current source or later test revision. The D7 storage accepted subset is not
reopened merely because production integration remains incomplete.

## 4. Current dependency and acceptance matrix

“Launch gate” means the canonical RS1/M1–M20 launch decision. “Operating
profile prerequisite” means required before enabling signing under a selected
DevNet profile; the resettable/no-value label does not waive it. “Deferred”
means not imported wholesale from MainNet/C4/C5 requirements into DevNet.

| Requirement and governing source | Current implementation / actual caller | Existing evidence and limits | Exact remaining decision or work; dependency and concrete acceptance | Classification |
|---|---|---|---|---|
| **RS1 overall; Foundational reconciliation; Blocker Register** | Required production Proposal/Vote policy refuses absent authority. F1–F8 and native transaction concerns remain separate. | Current source inspection at required baseline; Runs 418–422 and D7 evidence retain per-item producers. No current configured-authority release run. | Close every applicable F1–F8 obligation on real deployed paths, then capture adversarial release-binary evidence and obtain explicit launch-in-scope authorization; all M1–M20 must be Green. | Launch gate |
| **F1 — empty/absent native transaction authentication; Foundational §5** | Native verifier now rejects empty auth and structurally covers each required signer. `TxExecutor` has no standalone production caller. | Threshold/format evidence and revisions above; the 990-package result is limited to its own earlier source. Run 417’s old empty-auth finding describes the historical source, not current `auth.rs`. | Preserve verifier checks; before any transaction ingress is enabled, demonstrate rejection and positive authorization on the actual deployed ingress/execution path. Disabled/unwired ingress is not crypto closure. | Pre-ingress prerequisite within RS1; RS1 stays open |
| **F2 — threshold/weight/key identity; Foundational §5 and native-auth contracts** | Nonzero threshold and selected first key’s individual weight are enforced. Isolated analyzer detects duplicate/alias conflicts but production verifier does not use it. | Production threshold controls: source `0a163bb733f7dd160a588b5aa11cd37ad13fd143`, tests `31af27f46aef427299fc83bffdfaaee7c0077753`. Corrected identity focused tests: `52a9bcd1280c002755311c2a5d290b67691b11b1`, 6/6 only. | Decide approved canonical identity/alias semantics and resource profile; then integrate and test full deployed authorization before ingress. Current selected-key rule is not aggregate weighted authorization. | Pre-ingress prerequisite within RS1; RS1 stays open |
| **F3 — Proposal authentication, outbound and inbound; Findings Matrix F3; Foundational §5** | `Required` and guarded Proposal signer are present; production authority/journal are absent, so outbound emission is suppressed and inbound proposals are refused without authority. | Run 420 code/test and Run 421 unavailable-authority release-binary evidence do not establish configured-authority operation. Proposal authentication is distinct from F4 Vote authentication, F6 transport peer/sender binding, and F7 QC verification. | After A/B/C policy and authority/journal integration, demonstrate configured outbound proposal signing plus inbound signature, leader/membership, and domain verification before proposal delivery or engine effects. Acceptance must include genuine matched proposal acceptance and relevant adversarial refusals (unsigned/bad signature, wrong leader or membership, wrong domain/suite), with deployed-path evidence. | Launch gate |
| **F4 — Vote verification/signing; Foundational §5** | `Required` rejects inbound without `proposal_vote_authority`; production authority is `None`. Timeout context is not a Proposal/Vote credential. | Run 420 code/test; same Run 421 unavailable-authority binary, not configured positive-authority evidence. | Same authority/lifecycle prerequisites as F3; prove genuine configured Vote verification/signing plus forged, wrong-key, wrong-domain and missing-context rejection on deployed path. | Launch gate |
| **F5 — Timeout/NewView authentication; Foundational §5; D7 E7** | Mandatory timeout policy/preflight runs before P2P construction; actual message gate is conditional on valid configured verification inputs. It does not grant Proposal/Vote authority. | D7 E7 cites source tree `be1860d270c6c3278ca8a24f0a169bedab82e789` and separate marker correction; preflight acceptance is not transport readiness. | Retain mandatory policy and prove configured release-binary acceptance/rejection, including unavailable, malformed and wrong-domain evidence, without bypassing the preflight. | Launch gate |
| **F6 — authenticated peer to consensus sender; Foundational §5; Runs 418–419** | Origin-binding gate is in consensus ingress. | Run 418 code/test (`82c4b6d`, abbreviated as reported); Run 419 is partial standalone release-binary F6 peer/sender-binding evidence, runtime commit `1ec128379f3ce215706959d50901bbd6e56abd6b`. It does not establish usable configured-authority consensus or close F3/F4/F5/F7/F8 or RS1. | Complete missing F6 inbound/outbound adversarial vectors and combine with actual configured-authority evidence; preserve authenticated session identity to engine sender. | Launch gate |
| **F7 — imported QC verification/retention; Foundational §5; D7 E8** | Conditional Proposal-QC admission and retained-proof revalidation exist; they require the appropriate authority/evidence inputs. | D7 E8 cites implementation `d17a4db2a24c682f988594e6c3347f24adeffcae` and reconciliation `efa76f08134792d754a0a25fae7898df6579592e`; bounded isolated/handler controls only. | Prove complete configured QC admission/propagation, forged/evicted/ambiguous refusal, and recovery on the deployed binary; never treat Timeout credentials as QC authority. | Launch gate |
| **F8 — suite enforcement; Foundational §5** | Production Required policy prevents absent-authority bypass; supported-suite checks apply only once authority/context is available. | Run 420 code/test; Run 421 unavailable-authority binary at `85bb3a73e6fe2686c074cee5c0f15ff3cf1d2103` does not prove configured suite acceptance. | Prove configured suite allowlist, unknown/zero/wrong-suite rejection and no fallback on actual release binary. | Launch gate |
| **A — activation authorization; Lifecycle §§2.3, 3.3.1(1), 4** | Genesis activation remains disabled; unavailable constructor/preflight refuses. Identity correspondence is not permission. | No configured positive-activation evidence. Harness fixtures and genesis validation do not authorize production signing. | Owner must select and approve authenticated evidence authorizing this exact network, genesis, authority, validator/key and domain. Reject bare flag/scalar/fixture. This decision precedes production integration, independently of B/C. | Operating-profile prerequisite |
| **B — current-authority freshness; Lifecycle §§2.3, 3.3.1(6), 5.2** | Read-only epoch observation and in-process generation checks are not independent latestness or rollback resistance. | No deployed/history-bound freshness evidence; `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`. | Select the freshness trust/rollback domain and define cold-start, all-restart, partition, stale/conflicting witness, and unavailable behavior. Accept only independent authenticated freshness bound to network, validator, and history; epoch equality is insufficient. | Operating-profile prerequisite |
| **C — signing-history continuity; Lifecycle §3.3.1(7); Continuity §§3–6** | D10 journal and guarded signers exist; production passes no journal. Local backend single-writer protection does not defeat whole-copy rollback. | D10 `CODE-AND-STORAGE-TEST-POSITIVE` is limited to demonstrated local scope; Continuity remains defined, not implemented as a production lifecycle. | Choose and implement durable anti-rollback/history anchoring before any dependent reservation or sign. Demonstrate process restart, lost-ack, power-loss/rollback domain and retained-result behavior. “Resettable/no-value” is not a waiver. | Operating-profile prerequisite |
| **Consensus-lock recovery; Continuity §5.3; Recovery §§12, 13.3A–13.6** | Production snapshot recovery does not restore the full current lock/signing restriction; harness committed-QC reconstruction is not equivalent. O1–O5 and TC/O4/O5 compositions are isolated. | D7 D2 and D7 §13.6 evidence distinguish recovery characterization from implemented components; explicit O5 is in-process resumption only. | Bind the durable safety record and journal to the actual engine decision, load before signing, and prove restart/lost-ack/TC restrictions preserve allowed actions. Requires selected A/B/C policy and actual production storage ownership. | Operating-profile prerequisite |
| **Copied-key/host assumptions; Lifecycle and Continuity §6** | Local writer ownership does not fence another host holding copied key/database state. | No cross-host exclusivity or whole-copy freshness evidence. | Explicitly decide custody, cloning, concurrent-host, backup/restore, identity replacement and compromise assumptions; either enforce a selected boundary or refuse activation. A local mutex/checksum is insufficient. | Operating-profile prerequisite |
| **Canonical key identity and aliases; `docs/devnet/QBIND_RUN_422_NATIVE_AUTH_KEY_IDENTITY_CONTRACT.md`** | Production auth uses first matching suite entry and does not apply the isolated canonical descriptor/duplicate analyzer. | Corrected focused 6/6 at `52a9bcd1280c002755311c2a5d290b67691b11b1`; no package-wide claim for this revision. | Decide alias equivalence, duplicate-key/weight, ordering and rotation semantics; integrate only after approval and prove order-independent acceptance/refusal. | Operating-profile prerequisite before native ingress |
| **Resource limits; `docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_RESOURCE_ASSESSMENT.md` and `docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_STATE_CONTRACT.md`** | Framing and helper resource evidence exists; limits are candidate/test values, not production ceilings. | Resource, context, staged-effect and D7 storage models are isolated; all candidate limits remain `UNAPPROVED`. | Approve workload/profile-specific limits and account for complete end-to-end allocations, provider work, concurrent operations and failure carriers; demonstrate cap refusals without arbitrary limits or a silently trusted service. | Operating-profile prerequisite before native ingress |
| **Configured-authority production integration; Lifecycle §§3–7; Recovery §13.6** | `main.rs` constructs neither Proposal/Vote authority nor current-authorization owner/journal; safety backend defaults Disabled. Required mode consequently refuses. No production caller invokes isolated D7 owner/context/TC models. | D7 integrations are test/private models; fail-closed refusal is not usable configured consensus. | Only after A/B/C and lock-recovery decisions: wire exact validated identity, current authority, journal, owner and all ingress/leader/re-emission/QC/TC paths; prove actual effects are gated by durable state and missing prerequisites refuse. | Operating-profile prerequisite and launch gate |
| **Release-binary adversarial evidence; launch gate 7a/9** | Run 419 provides partial standalone release-binary F6 peer/sender-binding evidence. Run 421 provides unavailable-authority fail-closed release-binary evidence. Neither establishes usable configured-authority consensus. | Run 419 runtime commit `1ec128379f3ce215706959d50901bbd6e56abd6b`; Run 421 runtime commit `85bb3a73e6fe2686c074cee5c0f15ff3cf1d2103`. No configured-authority release evidence. | After safe integration, capture exact source/build/binary and actual callers; demonstrate configured outbound Proposal signing, genuine matched inbound Proposal acceptance only after signature/leader/membership/domain checks, and counter-backed rejection of relevant adversarial Proposal, Vote, transport-identity, QC, and Timeout/NewView cases. Separate release review and launch authorization still required. | Launch gate |
| **M4 — durable published seed; Blocker Register M4** | Run 416 proved external TCP/KEMTLS reachability to a temporary/discarded seed, not a durable public identity/listing. | Historical Run 416 runtime commit `1c2ba28d1532474a9e1124bc9873cd54193f29b6`; no durable live seed entry or current independent reachability evidence. | Prepare durable host/identity and independent off-host TCP plus strict KEMTLS/static-root evidence. Preparation may proceed alongside RS1; publish only after the authorized operational decision and evidence are complete. | Launch gate; preparation can proceed in parallel |
| **M6 — live identity admission/restart; Blocker Register M6** | Generation/verification and non-mutating register-check are complete for their documented scope; live registration is M4-gated. | Runs 375/376/401 are historical identity/CLI evidence; those reports do not identify a tested source commit. No live admission/restart proof. | After M4, admit a durable operator identity into the live seed list and prove node/peer identity reuse across permitted DevNet restarts. This is distinct from consensus signing-history continuity. | Launch gate; M4 dependency |

F1/F2 are not closed by the current absence of a native executor caller. F1/F2
must be cryptographically resolved before that ingress is enabled; RS1 itself
remains open until the complete applicable runtime-security gate is satisfied.
F3/F4/F8 fail-closed unavailability does not count as configured usable
consensus. Full C4/C5 closure and every MainNet obligation are not silently
imported as DevNet gates, but no applicable Profile A freshness or signing
history requirement is waived. M4 preparation is parallel to security work;
M6 live registration waits for M4.

## 5. Exactly one recommended next bounded task

**Recommended: obtain and record an owner decision on the public-DevNet
Proposal/Vote trust and signing-continuity profile before proposing production
integration.** The previous isolated TC/O4 task is implemented and tested; this
is a policy decision, not a repeat of that component work.

* **Problem / launch relevance:** A, B, C, consensus-lock recovery, and copied-key
  assumptions govern whether production Proposal/Vote signing may safely begin.
  They are unresolved operating-profile prerequisites and block configured
  authority integration needed for RS1 evidence.
* **Prerequisites already satisfied:** lifecycle, signing-continuity, and
  recovery correspondence contracts exist; local D10, O1–O5, QC/TC, state
  context, and staged-effect components have their documented scoped evidence.
  The existing fail-closed production posture can remain unchanged while owners
  decide.
* **Unresolved decision:** approve a specified Profile A trust model or decline
  it and keep activation disabled. Decide the authenticated activation root;
  freshness/history anchor and rollback domain; bootstrap/lost-state behavior;
  lock recovery; copied-key/host, backup/restore, and same-identity reset
  assumptions. Alternatives include protected non-rewindable local hardware,
  an authenticated live-quorum witness, a decentralized external anchor, or
  explicit continued refusal. These are alternatives, not selected policy.
  A local D10 journal alone is not anti-rollback; resettable/no-value is not an
  exemption.
* **Proposed path allowlist:** `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`,
  `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`,
  `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
  plus an append-only decision/evidence entry in
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and
  `docs/whitepaper/contradiction.md`.
* **Required deliverable / discriminating acceptance:** an authorized, reviewable
  decision record selects or rejects Profile A and names exact trust roots,
  evidence, identity/domain binding, rollback boundary, restart/partition and
  lost-ack behavior, key-copy/reset assumptions, and fail-closed cases. Every
  A/B/C/lock requirement has an owner and testable acceptance criterion. If
  any policy choice is unresolved, record it as unresolved and keep production
  activation/signing disabled; no implementation may bypass the missing choice.
* **Exclusions:** no code or resource caps; no policy silently chosen by an
  implementer; no trusted service introduced without approval; no activation,
  release approval, seed publication, deployment, tests/builds, launch date,
  readiness percentage, or change to NO-GO.

## 6. Preserved posture

```text
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET
§13.6 whole-lifecycle INCOMPLETE
activation DISABLED
public DevNet NO-GO
durable anti-rollback NOT-ESTABLISHED
C4/C5 OPEN
RS1 OPEN
candidate limits UNAPPROVED
whole native-admission and authority contracts DRAFT / NOT APPROVED / NOT IMPLEMENTED
```

No F1/F2 closure, production activation, configured-authority release approval,
launch approval, launch-date estimate, or readiness percentage follows from
this documentation reconciliation.