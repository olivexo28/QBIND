# QBIND Public DevNet - Critical Path (Run 422 reconciliation)

> DevNet only: experimental, resettable, no value. **RS1 OPEN / launch-blocking;
> public DevNet NO-GO; activation DISABLED; durable anti-rollback NOT-ESTABLISHED;
> C4/C5 OPEN.** M4 Yellow / launch-blocking; M6 Yellow / Partial; S5/S7 Yellow.
> No TestNet or MainNet readiness claim.

This source-backed planning reconciliation is inspected at
`de05c009a130d7d044a0c896b8a8559b00b411e4`, root tree
`4fcb30ffd7b387aefdf647dc7725f78fa61fb287`. It changes no security contract,
readiness status, reset procedure, runtime, activation guard, or resource ceiling.
No node startup, deployment, seed publication, D15, Run 423, Cargo execution, or
fresh security-tool result is part of this task. Source inspection at this revision
is **not** fresh execution of the inherited evidence below.

## 1. Governing requirements and baseline

The governing sources read for this reconciliation are:

| Source | Governs |
| --- | --- |
| `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (must-have/should-have matrices and current status) | Canonical M1-M20 / S1-S7 statuses |
| `docs/release/public-devnet/BLOCKER_REGISTER.md` (launch rule, RS1, M4, M6) and `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` sections 7a and 9 | Every must-have Green **and** RS1 closed with deployed-path executable evidence **and** explicit launch-in-scope authorization; otherwise NO-GO |
| `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md` sections 2 and 5 | F1-F8 obligations and distinction between deployed binary and harness |
| `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` sections 2.3, 3.3.1, 4, 5 and 7 (below: **Lifecycle**) | Proposed Profile A; independent activation authorization (A), current-authority freshness (B), signing/consensus continuity (C) |
| `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` sections 3-6 and 9.7 (below: **Continuity**) | Reservation/conflict/recovery semantics; accepted local D10 scope versus production lifecycle |
| `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` sections 12 and 13, especially 13.3A, 13.5-13.9 (below: **Recovery**) | Durable safety restriction before dependent signing; exact decision binding, O1-O5, unverified TC-derived carry |
| `docs/release/public-devnet/ops/RESET_POLICY.md` sections 2, 5, 6 and 8 | Existing operational resets; no implicit new signing authorization |

**Starting state:** branch `main`, clean worktree, HEAD/tree exactly as above;
origin fetch/push URL `https://github.com/olivexo28/QBIND`; remote main matched HEAD;
the task branch did not exist remotely. Work uses only
`copilot/run-422-devnet-critical-path-reconciliation`.

**Availability, content, ancestry are separate checks.** The required commit and
tree objects were available and all three planning/evidence files matched their
baseline blobs byte-for-byte. The clone was shallow with HEAD in `.git/shallow`.
Its raw commit header names parent `b17bb2beb8baa106eadfcd163fe6c5c1387a8f51`,
initially unavailable locally: this was **not a parentless commit**. A depth
extension (`git fetch --deepen=2 origin main`) made that parent available;
`git merge-base --is-ancestor` then verified it is an ancestor. No broader historical
ancestry or whole-tree identity with a historical tested revision is inferred.
The current engine blob `ba95124764cc3c88ee9bdd71da540acf0392aad4` (mode
`100755`) matches the engine blob explicitly recorded for E9 below; this is
file-content correspondence only.

## 2. Current implementation, callers and inherited evidence

### 2.1 Source map (line numbers at the inspected baseline)

| ID | Exact source / caller boundary | Current meaning |
| --- | --- | --- |
| S1 | `crates/qbind-node/src/main.rs:5405-5417`, `:5695`, `:6148`; `crates/qbind-node/src/genesis_consensus_authority.rs:1125-1144`, `:1227-1244` | Genesis activation still exits 1 before P2P/consensus. P2P timeout policy is RequireOrFail; Proposal/Vote authority remains None. Only unavailable owner construction is production-available; Established construction is test-only. |
| S2 | `crates/qbind-node/src/pqc_boot_genesis.rs:215`; `crates/qbind-node/src/genesis_consensus_authority.rs:334`, `:814`; `crates/qbind-node/src/genesis_authority_record_correspondence.rs:156`, `:254`, `:886`; `crates/qbind-types/src/network_wire_alias.rs:110` | Reuse boot verification, independent pin, founding-epoch guard, pinned correspondence and standard alias registry. These are identity/correspondence, not activation or latestness. |
| S3 | `crates/qbind-node/src/binary_consensus_loop.rs:3129-3146`, `:3265`, `:3414`, `:4371`, `:4951`, `:5818` | Real inbound/leader/re-emission forwarding exists, but runtime passes no current snapshot or signing journal. Guarded Proposal/Vote signers require a journal; missing authority/journal fails closed. This is not a wired signing lifecycle. |
| S4 | `crates/qbind-node/src/signing_reservation_journal.rs:2350`, `:2411`, `:2611`, `:2992`, `:4122`, `:4180`; `crates/qbind-node/src/storage.rs:1456`, `:1531`, `:1764`, `:1833` | D10 initialize/open, reserve/consume/publish/checked retrieval and acknowledged atomic-plus-sync storage operations exist. Do not prescribe their implementation again. Backend-local ownership does not exclude copied keys on another host. |
| S5 | `crates/qbind-node/src/safety_record_store/owner.rs:1033`, `:1121`, `:2170`, `:2499`, `:2578`, `:2839`, `:2849`, `:3110`, `:3297`, `:3360-3361`; `crates/qbind-node/src/safety_record_store/backend.rs:358-364` | Owner, prepared generation, logical/verified inbound and leader owning routes, O4 and O5 exist. The backend defaults Disabled. Signing and received-QC composition models are test-only; there is no production owner construction here. |
| S6 | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2938-2956`, `:3376`, `:3398`, `:3587`, `:4483`; `crates/qbind-consensus/src/hotstuff_state_engine.rs:598`, `:700`; `crates/qbind-node/src/safety_record_store/owner/received_qc_publication_model.rs:2398`, `:3451` | Opt-in owning capture, original received-Vote retention, complete signed-QC staging and pre-QC-effect gating exist. The node composition uses the actual O4/O5 operations, not acknowledgement Booleans. This is isolated, not the deployed Vote route. |
| S7 | `crates/qbind-node/src/binary_consensus_loop.rs:1404`, `:1514-1665`, `:6477`, `:6615`, `:7033`, `:7256`, `:7734`, `:7886-7965`; `crates/qbind-consensus/src/hotstuff_state_engine.rs:2324`; `crates/qbind-consensus/src/qc_verify_domain.rs:878`, `:916` | F5 mandatory outer Timeout/TC checks and F7 retained high-QC revalidation are runtime caller paths. Present high-QC needs a Proposal/Vote snapshot; timeout credentials alone cannot supply it. Lookup is bounded, borrowed and fail-closed. |
| S8 | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2598`, `:2665`, `:5106-5230`; `crates/qbind-node/src/binary_consensus_loop.rs:2840`; `crates/qbind-node/src/hotstuff_node_sim.rs:2035` | Production snapshot-baseline recovery does not restore the latest lock/history; harness committed-QC reconstruction is not sufficient lock preservation. TC application validates then directly raises an in-memory lock and advances view; there is no O4 barrier on this path. |
| S9 | `crates/qbind-consensus/src/timeout.rs:291-320`, `:640`, `:697`; `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2461`, `:5129` | Checked TC target/successor, clipped inclusive timeout search and truthful checked QC advancement are implemented. They do not prove every arithmetic/terminal/restart path safe. |
| S10 | `crates/qbind-node/src/safety_record_store/record.rs:20-29`, `:41-47`; `crates/qbind-node/src/safety_record_store/validate.rs:205-310`, `:378-478` | Storage validation remains Unverified, including TC-derived logical high-QC plus full TC. Structural/semantic association, timeout authentication, constituent-QC verification, durability and freshness remain different checks. |

### 2.2 Evidence ledger (historical execution, not rerun)

The producing revision is reported by the cited committed evidence, not inferred
from current content. Unless expressly stated in section 1, historical objects,
ancestry and full source identity were not re-established in this shallow checkout.
All D7 entries below are in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`;
headings disambiguate their append-only chronology. Counts are not added across
overlapping selectors. Later implementation deliveries do not extend the earlier
independently accepted storage subset.

| ID | Existing evidence and producing attribution | Scope / limitation |
| --- | --- | --- |
| E1 | Continuity section 9.7 / D7 D10 aggregate A-F consolidation: reviewed/tested `2cf125ccd2ee9b4af29280095b48461ec0eae975`; `crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs` and inline journal/handler tests | Local durable reservation, one-use continuation, exact retained reuse, frozen authorization checks, capacity and real-process abort/reopen. `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`; not production initialization, power-loss, whole-copy rollback or copied-key exclusion. |
| E2 | D7 "pre-reservation acceptance reconciliation": earlier integration/build results explicitly attributed to `b40c322d92948317524617b4e97fbe63cf9b7789`; its subsequent finishing reruns have no explicit final source SHA in that entry | Isolated process-death boundaries exist before reservation, after consumption, after write/before acknowledgement, after sign/before publication and after publication, plus retry exhaustion. Exact boundary-specific results stay with their original entries, not a fabricated common producing revision. Current code: `crates/qbind-node/src/safety_record_store/owner/model.rs:16007`, `:18169`, `:20027`. |
| E3 | D7 "verified-owner acceptance completion": earlier broad results attributed to implementation HEAD `33f8d9677287f1f6b8d127b10b69b60a0c5a95f0`; finishing selections not given a distinct full producing SHA. Owning leader finishing results likewise not given a distinct full SHA | `crates/qbind-node/tests/run_422_owning_capture_binding_tests.rs` and `crates/qbind-node/tests/run_422_leader_proposal_owning_handoff_tests.rs` prove exact L0 capture/pairing, proof preservation, domain contention and independent-ledger cleanup in isolation. Do not convert an attribution gap into current-revision execution. |
| E4 | D7 "received-Vote retention return-path acceptance correction": starts at `e71d02936539e51b60d9765d67162b0f866ef3c3`; no distinct final producing SHA is assigned there. Signed-QC staging starts at `0525f772d11c0c67ce509fa43b8283f87bb39eb4`; its execution is labelled pinned-working-tree evidence, not a final SHA | Current S6 and inline tests retain original signatures, reconcile actual history/accumulator membership, stage complete real signatures and preserve returned owners. The baseline SHA is not mislabelled as the final tested source. The stronger pinned composition evidence is E5. |
| E5 | D7 O4 composition `12c39541bd00f93f5e9cf7e8940ec7c5c13ec7ff`, accounting correction `1853e695755e71047a412bcfc77b875d8dd4d4fe`; uncertain-O4/O5 exact-QC resumption `09f884b6643688b1ed39094309cd48813947cace` | Private `received_qc_publication_model` uses actual received-QC gate, held-domain ordinary O4, genuine O3/explicit O5, exact complete-certificate resumption, no automatic recovery or production caller. |
| E6 | D7 exact-layout correction `8abb2ff2bfa87c55059d8c0995e955ad71d320b3`; captured-Vote acceptance gap closure `57948f56db346ca9f9d56af1e6ce16d3347335ae` | `received_qc_captured_vote_lifecycle`, `_pressure`, `_alternative_membership` in `crates/qbind-node/src/safety_record_store/owner/model.rs:9376-9390`: original capture survives acknowledged advancement; genuine signing once, retained reuse after O4/O5/resumption, negative membership/authorization controls. Three lifecycle tests passed at the latter revision; exact-copy Miri belongs to the former. Immutable fixture authority is not authenticated production activation. |
| E7 | D7 "F5 acceptance-evidence follow-up": Rust-source tree `be1860d270c6c3278ca8a24f0a169bedab82e789`, based on `04f6b69bde0f717fbe33aa93aa2180e29f1ea08f`; marker exit-race correction separately based on `f338cdc89ef11c686e3f835f8d0e5afaf8b34ebc` | Mandatory F5, local refusal/retry and `crates/qbind-node/tests/run_422_mandatory_timeout_policy_tests.rs`; ACTIVE marker proves preflight acceptance, not transport readiness. TC target-view correction at `f5aeb09e9761eeca4ee3b37275d7776731b6b028` has genuine substitution rejection tests (`run422_tc_target_view`). |
| E8 | D7 F7 implementation `d17a4db2a24c682f988594e6c3347f24adeffcae`; accounting/handler reconciliation `efa76f08134792d754a0a25fae7898df6579592e` | `run422_f7_retained_qc` tests in S7 files: original-ticket checks; distinct triggering/selected QCs; evicted/missing/ambiguous proof refusal; exact capacity-boundary helper tests and real-handler recovery controls. One MiB is a named admission/revalidation envelope, not whole-handler/RSS/signing coverage. Full F7 propagation/restart assurance remains open. |
| E9 | D7 timeout/TC exhaustion final source `fdfdd37619a18109e7d08ae0bce3efa9d176466c`; QC-driven exhaustion final source `8d82989e41e7f841e0c601e868aded37a451deb7` | `run422_timeout_view_exhaustion` and `run422_qc_view_exhaustion` inline tests; ordinary and release profiles. MAX-1 to MAX works; MAX refusal does not wrap/reset. QC effects may already be applied while `view_advanced=false`. The clarification attributes MAX-2 onward to the focused test and ordinary advancement to `basic_engine_advance_view`. These are not deployed release-binary executions. |
| E10 | `docs/devnet/run_422_d7d14_fixed_candidate_assurance/independent_review/00_review_report.md` section 2: candidate `aad0a4aaca8f66580d257c3468f1c27059145dbd`, reviewed evidence `ecf4cfdcc36e9438293173d89e44cd819d709ca5` | Accepted 23-row storage subset only. `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`. Neither frozen-candidate review nor its tooling covers all later extensions. |
| E11 | D7 C1 correction tested `3b573bd945c44f8f615298076b73966d8fcea339`; C2 correction `708d2c30cb0845843cb99d99f5e29175a4355004`; C3A checkpoint `fcdc7ca20f78ec9aa9389bcc354c5c8e9292e260` | `crates/qbind-node/tests/run_422_d7c1_storage_observation_tests.rs`, inline correspondence and alias tests. Non-authorizing identity/storage observations; current source inspected as S2, not freshly executed. |

Historical Runs 418/419 (F6 code/test and partial release-binary), 420/421
(F3/F4/F8 fail-closed policy and unavailable-authority release-binary), D6
(domain-v2 signing), and D7 C3D/E/F (QC verification/retention) remain inputs at
their documented revisions. Their evidence documents are, respectively,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_418.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_419.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_420.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_421.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D6.md` and the D7 record.
No earlier partial release-binary result validates a configured authority at
`de05c009...`. In particular C3D is **conditionally reachable**, not wholly
dormant: the compiled present-Proposal-QC gate calls it when a bound snapshot
and QC exist; F7 also uses its shared borrowed revalidation core (S7).
Current production supplies no Proposal/Vote authority or current snapshot.

## 3. Current prerequisite matrix

These are Profile A/integration prerequisites, **not additional canonical
launch-status rows**. Evidence IDs identify both producing revision and scope;
"none" means no positive implementation/evidence is established. Closed local
checks are reused, not reopened. Owners are proposed responsibilities, not
newly delegated authority.

| Prerequisite: exact requirement / governing source | Current implementation and actual caller | Existing evidence / revision | Remaining work or decision | Dependencies / concrete completion criteria / owner |
| --- | --- | --- | --- | --- |
| **P1 Activation authorization (A)** - Lifecycle 2.3, 3.3.1(1), 4.0: authenticated permission for this exact authority | S1 refuses activation; production constructor is unavailable only. Identity validation/Established fixtures do not authorize signing. | S1 inspected at baseline; no configured-authority positive evidence or producing revision exists. Runs 420/421 are historical refusals, not activation proof. | Owner must approve a trusted activation root/policy and evidence binding exact network/genesis, authority, validator/key/domain and lifecycle conditions. A CLI flag or caller Boolean is not that evidence. | Independent decision from P4. Completion: reviewed authenticated authorization mechanism exercised through the real constructor, negative replay/wrong-authority tests; public use still requires all applicable profile gates. Owner + protocol. |
| **P2 Bootstrap / absent QC** - Lifecycle 3.3.1(2), 4.1-4.2; Continuity 5.1 | Present QC verification exists; absent Proposal QC is unchanged, neither verified nor an authorized bootstrap exception. S5 storage BootstrapNoLock is a representation, not permission to found/re-found a signing identity. | S1/S5/S7 inspected; E10 covers storage representation, not authorized bootstrap. No approved positive bootstrap evidence/revision. | Decide authentic first use versus lost/rolled-back state, permitted epoch/fields, replay/restart rule and irreversible termination. Empty DB, None QC, zero QC or peer claim is insufficient. | P1, P4/P5 continuity evidence and P7 compatibility. Completion: approved bounded policy, fail-closed lost-state/replay tests, no fabricated QC. Protocol + owner. |
| **P3 Trusted identity / runtime-wire correspondence** - Lifecycle 3.3.1(3), S1/S11/S12 and 6.1 | S2 supplies independent pin validation, standard alias and membership/key/suite derivation. Dormant authority builder does not activate; non-MainNet boot pin can be absent, so a genesis path alone is not independently pinned identity. | E11 at named checkpoints; domain-v2 and C3B evidence remain historical. Current S2 inspected at baseline. | Consume independently pinned identity and exact runtime/wire/domain correspondence in the authorized constructor; do not parse labels or truncate arbitrary ChainId. | P1 supplies permission, not identity. Completion: same validated identity supplies engine, verifier, signer and storage context with mismatch refusal, no duplicate registry. Protocol. |
| **P4 Current-authority freshness (B)** - Lifecycle 3.3.1(6), 5.2.1; Continuity 6 | S1 unavailable owner; `observe_consensus_storage` is read-only epoch evidence. In-process generations invalidate tickets, not rollbackable history. | E11 observations; none for independent latestness, no producing positive revision. | Unresolved rollback-domain/anchor model. Must authenticate origin, network/validator/history binding, freshness/replay resistance, unavailable/conflicting behavior, cold start/all-restart/partition assumptions. | Independent of P1 authorization. Completion: reviewed domain-external mechanism, rollback/partition/partial-update tests, durable ordering; epoch equality or a historical QC cannot pass. Owner + protocol. |
| **P5 Journal / owner / signer integration (C local frontier)** - Lifecycle 3.3.1(4),(7); Continuity 3-5, 9.7; Recovery 13.5-13.6 | S3 guarded signers already require D10; S4 journal and S5 owning captures exist. E5/E6 compose exact capture, one sign, retained use and actual O4/O5 in private models. Production S3 still passes None; no owner construction/startup recovery. | E1-E6 at their stated revisions; not wholly missing. | Production context ownership, explicit initialize/open, real recovery inputs, all inbound/leader/received-QC/TC routes and cached sends must meet one serialized safety-before-reservation-before-sign frontier. No reimplementation of accepted journal. | P1/P3/P4/P6/P7 before production use. Completion: real caller wiring with exact original ticket/candidate/L0 binding; refusal on uncertain state; no signer before acknowledged safety and D10 barriers; retained reuse invokes zero signers. Protocol. |
| **P6 Consensus-lock recovery / correspondence (C)** - Continuity 5.3; Recovery 12, 13.3A-13.6 | O1-O5 and process-death models exist (S5, E2/E5/E6/E10). S8 production snapshot restores no latest lock/history; harness committed-QC reconstruction is not proof of preserving the pre-crash restriction. Storage stage-2 remains Unverified (S10). | E2/E5/E6 local recovery; D7-D2/D12 characterization is inherited, not rerun. No current production lock-recovery acceptance/revision. | Load acknowledged effective safety record and journal before engine/signing; provide independent committed history when anchored; verify applicable evidence separately. TC unverified restriction carry is not full authenticated TC replay. | P3/P5/P7; P4 separately handles whole-copy rollback. Completion: real startup/restore refuses unavailable/mismatched safety/history; recovered restriction demonstrably preserves allowed-action constraints, including surviving-write/lost-ack cases, no resurrected volatile prepared pin. Protocol/storage. |
| **P7 QC propagation / Timeout-NewView compatibility** - Lifecycle 3.3.1(5), 6.1; Recovery 13.3A/13.6; RS1 F5/F7 | S6 signed received-QC staging and O4/O5 exist in isolation. S7 **mandatory F5 is implemented**, TC target binding and bounded F7 admission are implemented runtime gates. Present high-QC without admitted authority/retained complete proof refuses; None remains distinct. S8 TC lock raise is still memory-only. | E4-E9; code/test and release-profile tests, not configured-authority release-binary assurance. | Wire complete QC formation/propagation into real authority-owned path; handle unknown/evicted remote proof and cold start under decided policy, not fallback. Add TC durable restriction frontier; selected QC needs its own admission, not reuse of triggering Timeout proof. | P2/P3/P5/P6; bounded isolated next task in section 5 needs no P1/P4 trust selection. Completion: each effective QC/TC raise crosses required durable barrier; genuine end-to-end proofs with negative forgery/substitution/refusal tests; unchanged bounded refusal, no weakened F5/F7. Protocol. |
| **P8 Configured-authority release-binary evidence** - Lifecycle 3.3.1(8), 7; launch gate 7a/9 | Refusal in S1 remains. Earlier standalone unavailable-authority evidence cannot exercise configured signing/verification. | Runs 419/421 partial historical runtime evidence; `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`. No producing configured-positive revision. | After safe implementation/review, isolated executable configured-path validation must produce deployed-path rejection counters for unsigned, mismatched sender, wrong/unknown suite and forged QC, plus applicable F5/F7 cases. Evidence production is not public-operation authorization. | P1-P7 design/implementation sufficient to exercise safely; **not Run 423 now**. Completion: attributed release binary/source/build and actual caller evidence satisfying RS1, then separate owner release/launch decision. Release + protocol. |
| **RS1 F1/F2 transaction authentication (separate)** - Foundational reconciliation 2.1/5; launch gate 7a | `crates/qbind-ledger/src/auth.rs:22-39` still allows empty auth and omits thresholds/weights/dedup. No enabled deployed transaction ingress is cryptographic closure. | Run 417 historical characterization; current auth source inspected at baseline; no new execution. | Require at least one auth, account threshold/weight/key dedup and explicit genesis exemption **before transaction ingress is enabled**. | Independent RS1 obligation, not solved by P1-P8. Completion: executable transaction-auth rejection/positive evidence on applicable ingress path. Ledger/protocol. |
| **M4 durable published seed** - Blocker Register M4; readiness M4 | Run 416 demonstrated temporary external reachability; durable identity/operation and `devnet-seeds.live.json` remain absent per canonical register. | Run 416 historical runtime evidence at reported `1c2ba28d...` (abbreviated attribution retained, not newly resolved). No fresh reachability. | Owner-provisioned routable host/durable PQC identity, independent off-host TCP and strict KEMTLS/static-root evidence, matching published node_id. | Eligible preparation can proceed alongside RS1; no publication/activation in this task. Completion: durable schema-valid live entry with non-null reachability evidence and canonical owner disposition. Seed operator. |
| **M6 live identity continuity** - Blocker Register M6; readiness M6 | Identity generate/verify/non-mutating register-check is Green-for-scope; live half remains M4-gated. | Runs 375/376/401 historical identity guidance/CLI evidence; canonical readiness references retain producing-pass attribution, not baseline execution. | Register persistent operator identity in live network and prove reuse across permitted DevNet restarts. Deferred durable-root rotation/revocation remains separately C4/C5-scoped. | M4 Green. Completion: actual admitted durable live identity and restart continuity evidence; does not waive signing-history obligations for consensus keys. Operator. |

M4 preparation and RS1 implementation are parallel inputs, **not** an invented
RS1 -> M4 code dependency. M6 live registration waits for M4. All M1-M20 must be
Green at the launch decision; S5 (live health) and S7 (seed operation) remain
M4-gated **should-haves**, not new mandatory gates. Canonical statuses remain
M1-M3/M5/M7-M20 Green, M4 Yellow, M6 Yellow/Partial; S1-S4/S6 Green, S5/S7 Yellow.
Full C4/C5 closure is not imported into the DevNet launch gate.

## 4. Resolve the planning conflict, not the security contract

**Exact superseded statements** in this document's baseline blob
`3fcac2a6b34448431314ec96eb879fb688e8a2d8`:

| Location | Previous claim | Reconciliation / attribution |
| --- | --- | --- |
| Section 3, "Explicitly NOT public-DevNet launch blockers" | "Durable anti-rollback anchor ... and signing-state-continuity-across-restart are production-hardening obligations; they are not listed as public-DevNet must-haves (DevNet is resettable / no-value)." Also: "open, not launch-gating for DevNet." | The canonical matrix does not enumerate a separate anchor item. **That absence and the safety label do not waive an applicable profile's pre-signing requirements.** The blanket deferral is withdrawn. |
| Section 4.1 row 7 / section 4.3 / section 5 | "continuity contract ... DEFINED-NOT-IMPLEMENTED"; next task "Implement the durable, single-writer, local signing journal" | Superseded by Continuity 9.7 and E1-E6. Local journal, process recovery and substantial owning composition exist. Production lifecycle remains incomplete; the next unit is section 5, not repeating D10. |
| Section 2 / section 4.1 rows 4-5 | QC/verifier modules "no non-test callers"; "Timeout/NewView crypto verification is the unresolved F5 boundary" | Overbroad even for C3E's conditional compiled call, and obsolete after E7/E8. F5 mandatory gates and bounded F7 exist. Their configured-authority runtime/propagation/recovery acceptance remains separate. |

The conflicting requirement is explicit in **Lifecycle 3.3**: "Profile A is not
'no restart safety': a fixed founding authority still needs the durable
anti-rollback proof of §5 before it can sign in production." Its
**3.3.1(6)-(7)** require current-authority freshness and signing-state recovery/
rollback safety, and **7(3)** permits production activation only after the
complete checklist. **Continuity 5.1/5.2 rows 10-13 and 6** independently prohibit
assuming unused/current history from local emptiness, equal epochs or old QCs.

The accurate planning distinction is:

* **Canonical public-DevNet launch:** M1-M20 Green + RS1 deployed fail-closed
  evidence + explicit launch in scope, unchanged. Documentation cannot close RS1.
* **Proposed operating profile:** Profile A is a recommended founding-only
  profile, **not approved policy**. If adopted for actual public-DevNet signing,
  its A/B/C prerequisites apply **before that signing**; no DevNet exemption has
  been approved. A permission decision cannot substitute for freshness or C.
* **Unresolved owner/design decisions:** adoption of that profile; exact
  authenticated activation root/evidence; bounded first-use/bootstrap policy;
  rollback domain and independent history-bound freshness mechanism; production
  recovery integration. Existing generation/exhaustion and serialized-handler
  checks are accepted scoped inputs, not reopened as missing.
* **Later TestNet/MainNet:** full C4/C5 governance/root lifecycle, broader
  production hardening and their own readiness criteria remain later obligations.
  Their full closure is not a DevNet prerequisite; conversely a future requirement
  is not deferred when the chosen DevNet signing profile already requires it.

**Keep five questions separate:** permission to activate (A), current-authority
latestness (B), preservation of signing history (C), recovery of the consensus
lock restriction, and copied-key/host exclusivity. An epoch-only witness answers
neither latestness nor history. A valid historical QC proves past quorum signing,
not latestness or survival of an uncommitted reservation. A per-backend local
single-writer domain does not make copied private keys exclusive.

**Reset-policy compatibility:** RESET_POLICY sections 2 and 5 allow data-dir
discard, same or successor pinned genesis, and backup/reuse of still-trusted
identity material. Those operational instructions are unchanged. They do **not**
establish that a previously used consensus signing identity/domain may forget
history and sign again. An operating-profile decision must reconcile any same-
genesis/same-domain reset with preserved authenticated signing/lock history or
independently authorized safe domain/identity retirement and replacement. No new
reset procedure, key-reuse permission or automatic domain migration is approved.
Offline `--authority-state-reset` remains a marker ceremony, not this permission.

**Trust-model decisions remain open, not collapsed to "select an anchor".**
For A, an explicitly pinned PQ-authenticated activation policy/evidence can bind
the exact authority; a bare CLI flag/fixture/scalar cannot. For B/C, protected local
hardware avoids a remote service but needs non-rewindable, history-bound state,
custody/exclusive-use assumptions and local-record ordering; a live-quorum witness
reuses quorum trust but needs authenticated freshness, trusted membership, cold-
start/all-restart and partition rules, and still must preserve individual
uncommitted history. A decentralized external anchor adds trust/availability/PQ
integration; a cloud/operator service would introduce a new trusted authority
and is not silently admissible. None is selected here. The concrete recommendation
for owner review is **retain the founding-only Profile A proposal with all A/B/C
requirements intact, and keep production signing unavailable until a fully
history-bound mechanism and authenticated activation policy are approved**,
rather than approve a resettable/no-value continuity waiver. This does not block
the non-authorizing implementation unit below.

## 5. Exactly one next bounded implementation task

**Selected task: isolated TC-derived lock/O4 pre-effect composition.** Add an
opt-in engine TC effect gate and a private node composition proving that an
advancing TC-derived restriction is acknowledged by the existing O4 owner
**before** that route installs the lock or advances view. This is one vertical
slice of Recovery 13.6's TC row, not production activation or complete TC recovery.
It is **specified here, not implemented in this documentation task**.

**Why ready:** the durable profile-(a) restriction, TC unverified-carry rule,
semantic predicates, O4 uncertainty semantics, one-domain ownership and resource
model are already selected in Recovery 13.3A/13.5-13.7. S8 shows the precise
missing pre-effect boundary. S5/S6 provide the held-guard O4/QC-gate pattern;
E7-E9 already establish mandatory runtime verification and successor checks.
No activation/freshness model is needed to test an explicitly non-authorizing
restriction-publication composition. Fixture membership is used only to construct
genuine test evidence, never as production permission.

**Entry points:** `BasicHotStuffEngine::on_timeout_certificate` (S8), after
logical target/quorum validation and stale-TC determination but before the
first lock/view/recorder/accumulator effect; `SafetyRecordOwner::publish_locked_held`
and its authoritative charged loader (S5); `SupportingEvidence::TcDerived`,
`validate_tc` (S10). Reuse the received-QC composition's single-domain pattern.
The ordinary runtime F5/F7 admission paths in S7 are preserved, not rewired.

**Narrow proposed implementation allowlist (future task only):**

| Path | Permitted purpose |
| --- | --- |
| `crates/qbind-consensus/src/basic_hotstuff_engine.rs` | Shared TC body with opt-in fallible pre-effect gate and truthful outcome; unchanged legacy wrapper; inline acceptance tests/test-utils-only adapter if needed |
| `crates/qbind-node/src/safety_record_store/owner.rs` | Private test-module registration and minimal reuse of existing held-domain operations; no new public activation constructor |
| `crates/qbind-node/src/safety_record_store/owner/tc_publication_model.rs` (new) | Private `cfg(all(test, feature = "test-utils"))` composition and tests |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and `docs/whitepaper/contradiction.md` | Append attributed implementation/evidence limits only |

**Required behavior and ownership:**

1. Borrow the exact TC and selected logical high-QC; classify stale/no-raise/
   strictly-raising cases without normalizing signed fields. Invalid target
   (including MAX successor overflow) refuses before gate/effects. Stale TCs
   preserve existing no-op semantics; no QC/evidence is fabricated for None.
   The bounded task requires O4 only for an effective strict lock raise;
   no-raise view advancement retains existing semantics without inventing a
   lock publication or making this a durable pacemaker.
2. Admit route controls and any complete TC/candidate copy before their
   construction. Hold the **same existing owner serialization domain once**
   from authoritative predecessor/context/revision comparison through O4,
   gate return, TC engine application, synchronous callbacks and route return.
   Check exact engine/durable predecessor correspondence, including absence,
   and preserve any committed anchor using independently supplied history.
   No re-entrant locking, equal/stored shortcut or manual engine-first publish.
3. Use the actual complete `TcDerived` candidate and ordinary held-guard O4.
   Only `DurableAcknowledged` allows the pending strict raise; refusal,
   ambiguous write and uncertain acknowledgement prevent its lock/view/latch/
   accumulator/recorder effects. Already completed Timeout ingestion is not
   rolled back. A surviving uncertain successor is reported honestly, recovery
   remains required, and this slice supplies **no automatic O5 or replay**.
   Evidence remains `Unverified`; no manufactured VerifiedQuorumCertificate,
   authorization token, acknowledgement Boolean or caller-supplied "current" scalar.
4. Inventory control-result/move overlap and TC nested capacities, candidate,
   authoritative loader, O4 buffers and failure carriers against the **existing**
   operational/context/shared aggregate caps before allocation. Reserve source
   copies separately from ordinary O4 working set; retain coverage through
   destruction. Consensus evidence stays on its separate ledger. Valid
   over-cap evidence refuses for capacity, not invalid cryptography; never
   truncate signers/evidence or enlarge ceilings. No physical-memory claim.

**Discriminating acceptance tests (new execution required by that future task):**

| Case | Required observation |
| --- | --- |
| Genuine strict raise | Real ML-DSA-44 signed timeout quorum; existing F5 verification and independently retained/domain-verified selected high-QC used as test inputs. Acknowledged O4 readback contains the exact full TC and selected lock, still Unverified. Existing post-ack hook sees old engine lock/view; only afterward one ordinary TC application changes them. |
| Publication outcomes | Existing pre-write, ambiguous-write and uncertain-after-write injections each report their actual O4 result and zero dependent engine/success effects. Inspect surviving bytes/revision rather than assuming ambiguous writes changed nothing. Recovery latch blocks retry; no acknowledgement shortcut. |
| Independent fences | Stale expected revision, wrong pinned domain/membership, mismatched engine/durable predecessor (both absence directions), missing anchored history and attempted strict-raise publications with equal/lower restriction candidates refuse before O4 submission. Genuine stale TC and non-raising/None controls keep legacy behavior without a publication attempt. No epoch/count-only correspondence. |
| Target/boundaries | Genuine signed evidence with only `tc.view` substituted refuses before publication; terminal timeout cannot form a valid successor; valid MAX-1 -> MAX target remains accepted when eligible. Preserve accepted E9 semantics, not an open-ended arithmetic audit. |
| Ownership/pressure | Same-domain competitor observes WouldBlock at post-ack/pre-effect and callback/return boundaries, then Acquired after release, using bounded supervised cleanup. Independently sample ledger occupancy/ceilings across real admission pressure, refusal, relief/retry, successful return, abandonment and full teardown; prove backing destruction before coverage release. |
| Compatibility/scope | Legacy TC wrapper behavior and existing target/F5/F7/exhaustion selectors stay passing with nonzero selection. Explicitly label helper controls versus actual composed route; record exact producing source and no-run versus execution separately. |

**Explicit exclusions:** `main.rs` and `binary_consensus_loop.rs` wiring;
activation/freshness policy or anchor implementation; authorized bootstrap;
new wire proofs, preimages, timeout signing journal, stage-2 recovery verifier,
TC crash/reopen/replay/resumption, production lock recovery, copied-key exclusion,
prepared signing/reuse enablement, new resource ceilings, node startup,
deployment, seeds, D15, Run 423, RS1/C4/C5 closure. A successful isolated slice
would remove **one TC durable-transition integration prerequisite**, not satisfy
P1-P8 or authorize any release/public operation.

## 6. Reconciliation disposition

The obsolete local-journal successor and blanket DevNet continuity deferral are
withdrawn with attribution above. Completed isolated work stays completed in its
accepted scope; later evidence extensions are not promoted to full acceptance.
The exact remaining production decisions and dependencies are the matrix, not a
new launch policy or a generic roadmap. Launch dates/effort remain UNKNOWN until
the actual policy and integration scope are approved.

```text
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET
§13.6 whole-lifecycle INCOMPLETE
activation DISABLED
public DevNet NO-GO
durable anti-rollback NOT-ESTABLISHED
C4/C5 OPEN
```

Only documentation reconciliation is delivered. It does not close RS1 or authorize launch.