# QBIND Peer-Driven Live Trust-Bundle Apply Safety Specification

**Run:** 144
**Status:** Specification / design only. **No production runtime behavior change. No peer-driven live apply is implemented.**
**Scope:** Mandatory safety, authorization, ordering, failure-mode, and evidence requirements that any future peer-driven live PQC trust-bundle apply path MUST satisfy before it may be implemented, enabled, or claimed.

---

## 1. Scope, intent, and non-goals

This specification defines the safety gate that any future implementation of a
**peer-driven live trust-bundle apply** path on the live inbound P2P
peer-candidate `0x05` surface MUST pass before:

1. it may be wired into source/test scaffolding;
2. it may be exercised by a release-binary harness;
3. it may be enabled by default on any environment;
4. it may be claimed as part of full C4 / C5 closure.

Run 144 is **specification/design only**. It updates documentation and may
introduce at most tiny compile-only test scaffolding that pins names already
present in source. Run 144:

- changes no production runtime source;
- adds no CLI flag;
- adds no metric family;
- changes no wire format;
- changes no trust-bundle, ratification, marker, or sequence-file schema;
- changes no session-eviction behavior;
- implements no KMS/HSM;
- implements no MainNet governance, signing-key rotation/revocation, or
  validator-set rotation;
- does not weaken any Run 050–143 invariant;
- does not claim full C4 closure;
- does not claim C5 closure.

The **current accepted state** (preserved by Run 144):

- Run 132/133: v2 validation-only reload-check and local peer-candidate-check
  are source/test wired and release-binary evidenced.
- Run 134/135: v2 process-start reload-apply mutating surface is source/test
  wired and release-binary evidenced.
- Run 136/137: startup `--p2p-trust-bundle` v2 mutating surface is source/test
  wired and release-binary evidenced.
- Run 138/139: SIGHUP live-reload v2 mutating surface is source/test wired and
  release-binary evidenced.
- Run 140/141: snapshot/restore v2 authority-marker parity is source/test
  wired and release-binary evidenced.
- Run 142/143: live inbound `0x05` v2 validation-only receive path is
  source/test wired and release-binary evidenced.
- Live inbound `0x05` behavior **remains validation-only / propagation-only**.
  It does not apply candidates, does not write sequence files, does not write
  authority markers, does not mutate `LivePqcTrustState`, and does not evict
  sessions.

Non-goals for Run 144:

- No peer-driven live apply implementation.
- No promotion of propagation-only to apply.
- No relaxation of any existing fail-closed validation gate.
- No assumption that local peer majority can substitute for cryptographic
  ratification.
- No MainNet governance, KMS/HSM, or signing-key rotation/revocation design
  closure — those are referenced as **pre-requisites** for any MainNet
  peer-driven apply but are not specified here beyond that requirement.

## 2. Primary design question

> Under what exact conditions may a trust-bundle candidate received from a
> peer progress from
>
>     live inbound 0x05 validation-only
>
> to
>
>     staged peer-driven apply candidate
>
> to
>
>     safe local live apply using the existing Run 070 apply contract?

The answer specified below is **fail-closed**, **operator-controllable**, and
compatible with DevNet, TestNet, and MainNet — and on MainNet it is blocked
until governance / ratification / KMS-HSM assumptions are specified and
evidenced.

## 3. Staged pipeline (mandatory phase model)

Any future peer-driven apply implementation MUST implement the following
phases in order. Phases MUST NOT be reordered, merged, or skipped.

### Phase 0 — receive

- Peer sends candidate over the live `0x05` peer-candidate wire frame.
- Receiver authenticates the transport peer through the **existing PQC P2P
  transport** (mutual-auth Required, ML-KEM-768 KEM, ML-DSA-44 signing,
  ChaCha20-Poly1305 AEAD; `DummySig`/`DummyKem`/`DummyAead` MUST NOT appear
  in any active path).
- Frame is size-bounded and decoded through the **existing peer-candidate
  envelope rules** (Run 076/079/088). No new envelope schema is introduced.
- The receiver MUST log a structured per-frame receipt suitable for the
  Run 088 propagation gate and for evidence harnesses.

### Phase 1 — validation-only

- The existing **Run 076/078/079/088/142/143** validation path runs verbatim.
- For v2 candidates, the candidate MUST pass:
  - the **Run 130 verifier** (`verify_bundle_signing_key_ratification_v2`);
  - the **Run 132/142 marker validation-only check**
    (`verify_marker_for_validation_only_v2`).
- For v1 candidates, the candidate MUST pass the **Run 109/123** v1 validator
  unchanged.
- Invalid candidates are **rejected and never rebroadcast**
  (`propagation_sent_total == 0`,
  `propagation_suppressed_invalid_total >= 1`).
- **No mutation occurs.** No sequence write, no marker write, no
  `LivePqcTrustState` swap, no session eviction.
- The validation-only path established by Runs 142/143 remains the
  **default and only** behaviour of the live inbound `0x05` surface in
  Run 144 and until a future run explicitly implements Phase 2+.

### Phase 2 — eligibility-to-stage

A peer-supplied candidate MAY be staged (i.e. moved into a peer-driven
apply candidate queue) **only if all** of the following are true:

1. The Phase 1 validation-only result is **Accepted**.
2. The candidate is **newer or idempotent** under v2 marker discipline
   (Run 130: `HigherSequenceAccepted`, `SameV2MarkerIdempotent`,
   `V2AfterV1ExplicitMigrationAllowed`, or `FirstV2MarkerAccepted`).
3. The **trust-bundle signature** verifies under the locally pinned
   bundle-signing authority key (Run 051/059/067/068).
4. The candidate's `chain_id`, `environment`, `genesis_hash`,
   `authority_root` / `authority_root_fingerprint`, and **activation gates**
   (`activation_height`, `activation_epoch`, minimum margin) all pass per
   the existing per-environment policy (Run 050/065/091).
5. **Run 055 anti-rollback** would accept the candidate **if applied**
   (the eligibility check runs the Run 055 dry-run, not the commit).
6. **Local policy permits peer-driven staging** for the current environment
   and the staging surface is not globally disabled.
7. The candidate has **not been seen recently** (per-source and global
   dedupe), is **not rate-limited**, and is not currently being suppressed
   by a back-off or quarantine policy.
8. The candidate does **not conflict** with a locally **operator-pinned**
   authority state (a pinned `(environment, chain_id, genesis_hash,
   authority_root)` tuple, or a pinned minimum
   `latest_authority_domain_sequence`).
9. The candidate is **not below** a locally persisted authority-domain
   sequence (`PersistentAuthorityStateRecordV2.latest_authority_domain_sequence`).
10. The candidate is **not** same-sequence / different-digest equivocation
    relative to either the persisted authority marker or any other
    candidate currently in the stage queue for the same authority domain.

Failing any of (1)–(10) MUST drop the candidate fail-closed: no staging, no
rebroadcast beyond the existing Run 088 propagation gate (which already
suppresses invalid candidates), no apply consideration.

Eligibility evaluation MUST be a **pure decision** with no mutation of
`LivePqcTrustState`, no sequence write, no marker write, and no session
eviction. The stage queue itself MUST be **in-memory only** until the
post-commit boundary is reached (see Phase 4).

### Phase 3 — local authorization gate

Before any mutation may occur, a peer-supplied staged candidate MUST pass
an **explicit local authorization decision**. The authorization decision
is policy-driven and per-environment:

- **DevNet**: MAY allow auto-apply, but only behind an **explicit hidden
  devnet-only CLI flag** introduced by a future run. Auto-apply MUST be
  **disabled by default**. The flag MUST refuse to bind on TestNet or
  MainNet (the same per-environment refusal pattern Run 050/051/065 already
  enforces).
- **TestNet**: MAY allow auto-apply only with **explicit operator opt-in**
  AND a **ratified v2 authority** state on the receiving node. Without
  both, peer-driven apply MUST be refused fail-closed.
- **MainNet**: MUST **require governance / ratification policy** before any
  peer-driven apply is even considered. **Local peer majority alone is
  insufficient.** Without a separately specified and separately evidenced
  governance / KMS-HSM / ratification track, MainNet MUST refuse
  peer-driven apply with operator-actionable text.

Authorization MUST be a **pure decision**: a refusal at Phase 3 MUST NOT
mutate `LivePqcTrustState`, MUST NOT write the sequence file, MUST NOT write
the authority marker, MUST NOT evict sessions, MUST NOT emit any
`apply`-class metric, and MUST NOT cause rebroadcast.

### Phase 4 — apply (existing Run 070 ordering, reused exactly)

If — and only if — Phases 0–3 all succeed, the receiver MAY apply the
candidate. The apply path MUST **reuse the existing Run 070 apply contract
exactly**:

1. **Validate** the candidate against the live trust domain (re-run the
   Phase 1 validation-only check against the current `LivePqcTrustState` /
   trust-bundle, because state may have advanced since Phase 1).
2. **Snapshot previous** live trust state (so Run 070 rollback is possible).
3. **Swap `LivePqcTrustState`** atomically.
4. **Evict sessions** that were authenticated under the previous trust
   state, using the existing Run 070 session-eviction surface.
5. **`commit_sequence`** — write the new
   `pqc_trust_bundle_sequence.json` under the existing Run 055 anti-rollback
   discipline.
6. **Persist v2 authority marker** via
   `persist_accepted_v2_marker_after_commit_boundary`,
   **strictly after** `commit_sequence` returns `Ok` — the same
   post-commit marker discipline used by Run 134, Run 136, and Run 138.
   A marker-persist failure at this point is **FATAL** and surfaces through
   the same fatal shape Run 121 / Run 138 already establishes.

Any failure in steps 1–5 MUST roll back through the existing Run 070
rollback / fatal semantics. Step 6 failure is FATAL with operator-actionable
text and triggers graceful shutdown, exactly as Run 138's
`LiveReloadOutcome::MarkerPersistFailureAfterCommitV2` does today.

The marker `last_update_source` for a peer-driven apply MUST be a **new,
audit-distinct variant** introduced by the future run that implements
Phase 4 (e.g. `peer-driven-apply`) so that evidence harnesses and audit
tooling can distinguish a peer-driven apply from a startup-load, a
reload-apply, a SIGHUP-reload, or a snapshot-restore. Reusing an existing
variant for peer-driven apply is **prohibited**.

### Phase 5 — evidence and audit

Before any closure claim for peer-driven apply, the implementation MUST be
covered by **release-binary evidence** — not source/test only — using the
same harness shape Runs 133/135/137/139/141/143 already establish:

- Real `target/release/qbind-node` processes.
- Real authenticated PQC P2P transport.
- Real on-disk sidecar, marker, sequence file, and snapshot artifacts.
- Per-scenario captured stdout/stderr, exit code, SHA-256 of marker file
  pre/post, SHA-256 of sequence file pre/post, captured PIDs, build
  provenance (`sha256`, `BuildID`, `git_commit`, `rustc --version`,
  `cargo --version`).
- An **explicit out-of-scope denylist** asserting zero matches for any
  surface not yet implemented (e.g. KMS/HSM, signing-key rotation/
  revocation lifecycle, MainNet governance, `DummySig`/`DummyKem`/
  `DummyAead`).
- A **per-environment denial matrix** asserting that MainNet peer-driven
  apply is refused fail-closed in the absence of governance / ratification
  authority.

## 4. Required invariants (must be proved before any closure claim)

The future implementation MUST prove **all** of the following invariants in
both source/test and release-binary evidence:

1. **No peer candidate can bypass local signature/ratification validation**
   (Run 051/059/067/068/130 paths run on every candidate).
2. **No candidate can bypass v2 authority marker anti-rollback** (Run 130
   `compare_authority_marker_v2` runs on every candidate; lower-sequence,
   same-sequence-different-digest, and ambiguous v1+v2 inputs all fail
   closed).
3. **No candidate can bypass Run 055 sequence anti-rollback**.
4. **No candidate can bypass `activation_height` / `activation_epoch`
   gates** (Run 065/091 path runs on every candidate).
5. **No peer majority can substitute for cryptographic ratification.** A
   count of peers asserting a candidate is not — and never becomes — an
   authorization input on MainNet.
6. **No invalid candidate is propagated or applied.** Run 088 propagation
   suppression invariants are preserved end-to-end.
7. **No same-sequence conflicting candidate is silently accepted.** Either
   the candidate is rejected at Phase 1/2 or the staging queue surfaces an
   explicit equivocation outcome at Phase 2.
8. **No lower-sequence candidate can downgrade local state.**
9. **No stale snapshot or stale local data-dir can roll authority state
   backward.** The Run 140/141 snapshot/restore parity invariants are
   preserved; a stale restore followed by a peer-driven apply still fails
   anti-rollback if it would downgrade the authority-domain sequence.
10. **No peer-driven apply is enabled by default** on any environment.
11. **MainNet refuses peer-driven apply** without governance / ratification
    authority.
12. **Apply uses existing Run 070 rollback / fatal semantics.** No new
    apply ordering is introduced. No partial apply state is left on disk.
13. **Marker persistence occurs only after `commit_sequence`** returns
    `Ok` — the Run 134/136/138 post-commit boundary is preserved for
    peer-driven apply as well.
14. **Session eviction occurs only after a successful live trust swap and
    before `commit_sequence`**, preserving the Run 070 ordering exactly.
15. **Rejected candidates do not write the marker, do not write the
    sequence file, do not emit `apply`-class metrics, and do not mutate
    `LivePqcTrustState`.**
16. **Duplicate candidates do not form propagation loops.** Source-peer
    exclusion (Run 088) and per-source dedupe at Phase 2 are both
    enforced.
17. **Rate limits prevent peer-spam from causing unbounded validation
    cost.** A configurable per-source and global rate limit MUST gate
    Phase 1 and Phase 2 evaluation, and MUST surface in the existing
    `peer_candidate_*` counter family without introducing a new metric
    family for Run 144 itself.
18. **Operator logs are stable enough for evidence harnesses** — log lines
    used by Run 143's harness for the validation-only path remain stable;
    any future apply-class log lines introduced for peer-driven apply
    follow the same per-run prefix discipline (`[run-NNN] ...`) used by
    Run 109/120/121/134/136/138.

## 5. Threat model (mandatory)

Any future peer-driven apply implementation MUST treat every peer-provided
byte and every peer-provided claim as adversarial. The mandatory threat
model includes at least the following adversary actions, and the
implementation MUST prove a fail-closed response to each:

| # | Adversary action | Required fail-closed outcome |
|---|------------------|------------------------------|
| T1 | Malicious peer sends validly signed but **unauthorized** candidate (e.g. signed by a key not on the local ratified authority set) | Reject at Phase 1 via Run 130; never propagate; never stage; never apply |
| T2 | Malicious peer sends **lower-sequence rollback** | Reject at Phase 1/2 via Run 055 + Run 130; never apply |
| T3 | Malicious peer sends **same-sequence different-digest** equivocation | Reject at Phase 1 via `SameSequenceConflictingDigest` / `SameSequenceConflictingKeyOrAction`; never stage |
| T4 | Malicious peer sends **wrong-chain / wrong-environment / wrong-genesis** candidate | Reject at Phase 1 via existing domain-binding checks; never stage |
| T5 | Malicious peer sends a **high-sequence candidate** to pin future authority state and block legitimate upgrades | Reject at Phase 2 eligibility (operator-pinned state or rate limit); never apply; surface to operator |
| T6 | **Compromised but ratified bundle-signing key** | Out of scope for Phase 1–4; explicit pre-requisite — Phase 5 evidence MUST refuse closure until signing-key rotation/revocation lifecycle is separately specified and evidenced |
| T7 | **Compromised peer transport identity** | Run 070/088 transport authentication MUST already gate `0x05` receive; peer-driven apply MUST NOT relax transport authentication |
| T8 | **Network partition with two competing authority candidates** | Phase 2 dedupe + Phase 3 authorization MUST refuse silent split-brain apply; MainNet MUST refuse without governance arbitration |
| T9 | **Propagation loop / gossip amplification** | Source-peer exclusion (Run 088) + per-source dedupe + global rate limit MUST bound retransmission cost; invalid candidates MUST NOT be rebroadcast |
| T10 | **DoS via large candidate or repeated candidates** | Size bound at Phase 0; rate limit at Phase 1/2; the existing peer-candidate envelope size rules MUST NOT be relaxed |
| T11 | **Stale snapshot restore followed by peer-driven apply** | Run 055 anti-rollback + Run 140/141 snapshot/restore parity invariants MUST hold; a stale restore MUST NOT enable a downgrade via subsequent peer-driven apply |
| T12 | **MainNet local-config-only authority bypass attempt** (e.g. operator local flag claiming MainNet apply authority) | Phase 3 MainNet branch MUST refuse; flag MUST refuse to bind on MainNet |
| T13 | **Emergency revocation replay** (replaying an old revocation event to demote authority) | Run 055 + Run 130 + signing-key revocation lifecycle (pre-requisite) MUST refuse stale revocation; explicit pre-requisite — Phase 5 evidence MUST refuse closure until signing-key rotation/revocation lifecycle is separately specified and evidenced |
| T14 | **Operator accidentally enabling DevNet flag on MainNet** | Per-environment flag binding (Run 050/051/065 pattern) MUST refuse the DevNet hidden flag on MainNet at process start with operator-actionable text |

## 6. Per-environment policy matrix

The following policy matrix is mandatory. The "expected stance" column
defines the only permissible default after Run 144 and after any future
implementation run, unless an explicit MainNet governance / ratification
track is separately specified and evidenced.

| Capability | DevNet | TestNet | MainNet |
|------------|--------|---------|---------|
| Validation-only receive (`0x05`) | **Allowed today** (Run 142/143) | **Allowed today** (Run 142/143) | **Allowed today** (Run 142/143) |
| Propagation-only rebroadcast | **Allowed today** under disabled-by-default policy (Run 088/089/143) | **Allowed today** under disabled-by-default policy | **Allowed today** under disabled-by-default policy |
| Peer-driven staging (Phase 2) | **Future work, disabled by default**; future hidden flag possible | **Future work, disabled by default**; explicit operator opt-in required | **Future work, disabled by default**; requires governance / ratification authority before staging is even considered |
| Peer-driven apply (Phase 4) | **Future work, disabled by default**; hidden devnet-only flag in a future run | **Future work, disabled by default**; explicit operator opt-in **AND** ratified v2 authority required | **Blocked** until governance / ratification / KMS-HSM authority is specified and evidenced |
| Required local flags | hidden devnet-only flag (future, e.g. `--p2p-trust-bundle-allow-peer-driven-apply-devnet-only`) | hidden testnet flag (future) + ratification enforcement enabled | none authorize MainNet alone; governance / ratification authority required |
| Required ratification / governance proof | v2 sidecar (Run 130/131) | v2 sidecar (Run 130/131) + ratified v2 authority | v2 sidecar **plus** separately specified governance / ratification track (future) |
| Allowed default state | validation-only / propagation-only | validation-only / propagation-only | validation-only / propagation-only |
| Required evidence before promotion | release-binary DevNet peer-driven apply evidence (future Run, e.g. Run 148) | release-binary TestNet peer-driven apply evidence with ratification (future Run, after Run 149+) | release-binary MainNet evidence with governance / KMS-HSM track (future Run, after Run 149+) |

**Expected stance (must hold after Run 144 and until separately changed):**

- **validation-only**: allowed where already implemented (Runs 132/133/142/143).
- **propagation-only**: allowed only under the existing disabled-by-default
  policy (Runs 088/089/143).
- **peer-driven staging**: future work, disabled by default.
- **peer-driven apply**: future work, disabled by default; **MainNet
  blocked** until governance / ratification / KMS-HSM assumptions are
  specified and evidenced.

## 7. Required future run decomposition

Implementation of peer-driven apply MUST be **staged and evidence-first**.
The minimum decomposition is:

- **Run 145 — source/test scaffold for staged peer-driven apply candidate
  queue.** No apply, no mutation. Implements dedupe, rate limit, and local
  policy gate. Candidate remains staged only (in-memory). MUST prove the
  Phase 2 eligibility invariants in source/test scope.
- **Run 146 — release-binary evidence for the staged peer-driven apply
  candidate queue.** Real `0x05` frames, no mutation. MUST prove the
  Run 143 non-mutation invariants still hold and additionally prove the
  staging queue dedupe / rate-limit invariants on real binaries.
- **Run 147 — source/test DevNet-only peer-driven apply using the existing
  Run 070 apply contract.** Hidden DevNet flag; DevNet/TestNet only;
  MainNet refused at flag-bind time. No governance claim. MUST exercise
  the new `last_update_source=peer-driven-apply` audit variant on the v2
  marker.
- **Run 148 — release-binary DevNet-only peer-driven apply evidence.** MUST
  prove apply, marker persistence after `commit_sequence`, session
  eviction ordering, and Run 070 rollback behavior on real binaries.
- **Run 149+ — governance / ratification / KMS / HSM hardening before any
  TestNet or MainNet claim.** Signing-key rotation/revocation lifecycle,
  KMS/HSM custody, MainNet governance attestation, and validator-set
  rotation are all pre-requisites for any TestNet/MainNet peer-driven
  apply closure claim.

Actual run numbers may be adjusted, but the **staging and evidence-first**
discipline is mandatory.

## 8. Documentation language (mandatory for Run 144)

Every Run 144 document MUST state, explicitly, that:

- **Run 144 is specification / design only.**
- **No production runtime source changed.**
- **No CLI flag changed.**
- **No metric changed.**
- **No wire format / schema changed.**
- **No peer-driven live apply was implemented.**
- **Existing validation-only and propagation-only semantics remain
  unchanged.**
- **Full C4 remains open.**
- **C5 remains open.**

## 9. Cross-references

- Live inbound `0x05` validation-only receive path:
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_142.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_143.md`.
- Per-surface v2 wiring (reload-apply, startup, SIGHUP, snapshot/restore):
  Runs 134/135, 136/137, 138/139, 140/141.
- Existing Run 070 apply contract: see the SIGHUP live-reload controller
  (`crates/qbind-node/src/pqc_live_trust_reload.rs`) and the Run 134
  reload-apply surface.
- Existing peer propagation safety: `QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`
  (Run 087 design gate; Run 144 extends its scope to cover apply, not just
  propagation).
- Trust anchor authority model: `QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
- Operator runbook: `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.
- Whitepaper contradiction tracking: `docs/whitepaper/contradiction.md`.

## 10. Acceptance criteria for Run 144 itself

Run 144 is acceptable only if:

1. peer-driven live apply safety requirements are **specified before**
   implementation;
2. DevNet / TestNet / MainNet policy boundaries are **explicit**;
3. MainNet peer-driven apply remains **blocked** without governance /
   ratification authority;
4. existing validation-only and propagation-only paths remain **unchanged**;
5. future implementation is **decomposed** into safe, evidence-first runs;
6. `contradiction.md` and the operator / protocol docs are **updated**;
7. **no runtime behavior changes** are introduced;
8. **no full C4 or C5 closure** is claimed.
## 11. Run 145 progress entry — Phase 2 staging-queue source/test scaffold

Run 145 lands the first concrete artefact of the **Phase 2
("eligibility to stage")** layer of this specification as a new
library-level Rust module:

* `crates/qbind-node/src/pqc_peer_candidate_staging.rs` —
  `PeerCandidateStagingQueue`, `PeerDrivenStagingPolicy`,
  `StagedPeerCandidate`, `StagingOutcome`.

The queue:

* is **disabled by default** on every environment;
* **refuses MainNet unconditionally** (the Phase 3 local authorization
  gate's MainNet branch is fail-closed in Run 145; only governance /
  ratification / KMS-HSM authority can ever flip this, and none of
  those exist yet);
* is **bounded** (`max_staged_candidates`, default 16) with explicit
  **reject-new** eviction at capacity;
* is **per-peer bounded** (`max_candidates_per_peer`, default 4) with
  reject-new at the per-peer cap;
* is **TTL-bounded** (`ttl_secs`, default 300) with a lazy sweep on
  every insert/read (no background timer/task);
* **deduplicates** by `(fingerprint_prefix, sequence,
  authority_marker_digest)`;
* only accepts already-validated candidates (the
  `try_stage_outcome` wrapper refuses anything except
  `PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::
  Validated(_))`);
* is **non-applying**: the module exposes no `apply` /
  `apply_validated_candidate` / `apply_validated_candidate_with_previous`
  entry point and calls no Run 070 apply path.

Run 145 is **source / test scaffold only**: no release-binary evidence
is claimed, and the queue is **not** wired to the production binary's
live inbound `0x05` dispatcher in this run. The future Run 146
release-binary hook is documented in the module-level Rust docs of
`pqc_peer_candidate_staging.rs`.

Remaining open phases of this specification after Run 145:

* **Run 146** — release-binary staging evidence (hidden DevNet-only
  flag; real `0x05` frames; no mutation; documented operator log lines).
* **Run 147** — source/test DevNet-only peer-driven apply behind a
  hidden DevNet-only CLI flag using the existing Run 070 apply
  contract; MainNet refused at flag-bind.
* **Run 148** — release-binary DevNet-only peer-driven apply evidence
  proving apply, post-commit marker persistence, session-eviction
  ordering, and Run 070 rollback behaviour.
* **Run 149+** — governance / ratification / KMS / HSM hardening
  before any TestNet / MainNet claim.

Run 145 does not change any invariant from §3, §4, or §7 of this
document. Full C4 remains OPEN. C5 remains OPEN.
## 12. Run 146 progress entry — Phase 2 staging-queue wired into live inbound `0x05` (source/test wiring only)

Run 146 wires the Run 145 `PeerCandidateStagingQueue` into the
**live inbound P2P `0x05` validation-only receive path** behind an
explicit **disabled-by-default** local policy gate, and adds a
focused acceptance suite (`run_146_live_inbound_0x05_staging_hook_tests.rs`,
19 tests, A1–A4 + R1–R14) that proves staging never mutates live
trust state under any code path.

What Run 146 lands:

* `LivePeerCandidateWireDispatcher` and
  `LivePeerCandidateWireDispatcherConfig` gain an optional
  `staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>`
  field, defaulting to `None`. When `None`, the dispatcher is
  bit-for-bit Run 143.
* New runtime accessors `set_staging_queue`, `staging_queue`, and
  `staging_hook_is_armed` provide a late-install path for the
  future Run 147 production wiring.
* A new private helper `maybe_stage_after_validation` is invoked
  inside `dispatch_frame_from_peer_for_test` **after** the Run 142
  v2-marker conflict check and the Run 123 v1-marker conflict check,
  and **before** `maybe_propagate_after_validation`. It forwards
  only `PeerCandidateOutcome::Validated(_)` outcomes to
  `PeerCandidateStagingQueue::try_stage_outcome`.
* The Run 145 queue's `PeerDrivenStagingPolicy` continues to enforce
  disabled-by-default semantics, **MainNet refusal even when
  `enabled = true` and `allow_mainnet = true`**, per-peer and global
  capacity bounds with reject-new eviction, deduplication, and TTL
  expiry. Run 146 adds no enforcement at the dispatcher layer.

Phase 2 status after Run 146:

* §6 Phase 2 (validation-only staging without apply) — **landed in
  source and reachable from the live inbound `0x05` receive path
  when an operator installs a staging queue with `enabled = true`.**
  The release-binary default behaviour is unchanged (no queue is
  installed by default; dispatcher behaves identically to Run 143).
* §6 Phase 3 (DevNet peer-driven apply behind a hidden flag) —
  deferred to Run 147+.
* §6 Phase 4 (TestNet / MainNet hardening) — out of scope of
  Runs 145, 146.

What Run 146 explicitly **does not** do:

* Run 146 does **not** call Run 070 apply from the staging hook
  under any condition.
* Run 146 does **not** mutate `LivePqcTrustState`, the trust-bundle
  sequence file, the authority-marker file, sessions, reload-apply
  state, or SIGHUP state.
* Run 146 does **not** add a CLI flag. A future Run 147 entry point
  may parse a hidden `--p2p-trust-bundle-peer-candidate-staging-*`
  family and call `set_staging_queue` at startup.
* Run 146 does **not** add, rename, or remove any metric family.
* Run 146 does **not** weaken any §3 / §4 / §7 invariant.
* Run 146 does **not** weaken Run 109/123/142 validation,
  Run 088 propagation, or Run 070 apply ordering.
* Run 146 does **not** produce release-binary staging evidence.
  Release-binary staging evidence is deferred to Run 147.

Acceptance evidence:

* `crates/qbind-node/tests/run_146_live_inbound_0x05_staging_hook_tests.rs`
  — 19 tests covering A1–A4, R1–R14, plus a late-install regression.
  All green.
* Regression suites verified green after Run 146: `run_145` (20),
  `run_142` (16), `run_088` (5), `run_079`, `run_109`, `run_134` (5),
  `run_138` (11), `qbind-node --lib pqc_authority` (148).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_146.md` records the
  source/test wiring evidence and the documented honest Run 147
  release-binary trigger plan.

Remaining open phases of this specification after Run 146:

* **Run 147** — release-binary staging evidence (hidden DevNet-only
  flag installs the queue at startup; real `0x05` frames; no
  mutation; documented operator log lines) **and / or** source/test
  DevNet-only peer-driven apply behind a hidden DevNet-only CLI
  flag using the existing Run 070 apply contract (MainNet refused at
  flag-bind).
* **Run 148** — release-binary DevNet-only peer-driven apply evidence
  proving apply, post-commit marker persistence, session-eviction
  ordering, and Run 070 rollback behaviour.
* **Run 149+** — governance / ratification / KMS / HSM hardening
  before any TestNet / MainNet claim.

Run 146 does not change any invariant from §3, §4, or §7 of this
specification, and does not change any invariant from Run 145's §11
progress entry.
## 13. Run 147 progress entry — release-binary evidence for the live `0x05` peer-candidate staging hook (hidden opt-in arming flag + release-binary evidence)

Run 147 produces the release-binary evidence that Run 146
explicitly deferred for the Phase 2 staging queue (§4 of this
specification) **and** lands the smallest possible source delta
required to genuinely arm that queue on the release binary. The
Run 147 feasibility gate ("can a real `target/release/qbind-node`
binary arm `LivePeerCandidateWireDispatcher::staging_queue` through
an existing runtime config path?") returned **NO** against the
Run 146 state: `crates/qbind-node/src/main.rs` constructed
`dispatcher_cfg.staging_queue = None` and the `set_staging_queue`
late-install surface on `LivePeerCandidateWireDispatcher` was
source/test only.

Per `task/RUN_147_TASK.txt`'s "preferred path if a flag is
necessary" allowance, Run 147 adds the smallest hidden,
disabled-by-default DevNet/TestNet-only arming flag

```
--p2p-trust-bundle-peer-candidate-staging-enabled
```

with the following Run 144 / Run 145 / Run 146-aligned properties:

* hidden from `--help` (clap `hide = true`);
* defaults `false`;
* refused on MainNet unconditionally with exit code `1` and a
  `[binary] Run 147: FATAL ...` stderr line at the top-level
  partial-config gate; the P2P transport is never brought up;
* refused without
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
  (same exit code, same FATAL line shape);
* does NOT imply propagation (the existing
  `--p2p-trust-bundle-peer-candidate-propagation-enabled` flag
  remains orthogonal);
* does NOT imply apply (the Phase 4 apply gate from §3 / §4 of
  this specification is unchanged and unreached);
* constructs a bounded `PeerCandidateStagingQueue` using
  `PeerDrivenStagingPolicy::devnet_enabled()` /
  `PeerDrivenStagingPolicy::testnet_enabled()` (the Run 145
  conservative defaults);
* adds no metric family;
* changes no wire format or on-disk schema.

The source delta is exactly:

1. one new hidden CLI flag in `crates/qbind-node/src/cli.rs`;
2. one top-level partial-config refusal gate in
   `crates/qbind-node/src/main.rs` (MainNet refused; missing
   live-`0x05`-validation refused);
3. one inline branch in the existing Run 079 dispatcher-config
   construction in `crates/qbind-node/src/main.rs` that replaces
   the Run 146 placeholder `staging_queue: None` with
   `Some(Arc::new(parking_lot::Mutex::new(PeerCandidateStagingQueue::new(policy))))`
   when the flag is supplied, plus a defensive MainNet guard at
   queue construction.

**No dispatcher-level code is changed.** Run 146's
`set_staging_queue`, `staging_queue()`, and
`staging_hook_is_armed()` surface is preserved verbatim and
remains the future-run hook for additional install topologies.

### Mapping to the six-phase pipeline (§3)

* **Phase 0 / Phase 1 (receive + validation-only)** — unchanged
  from Runs 142 / 143. Run 147 does not relax any validation
  predicate.
* **Phase 2 (eligibility-to-stage)** — Run 147 is the
  release-binary acceptance run for this phase. The queue is
  genuinely armed on DevNet/TestNet; staging happens only on
  `PeerCandidateOutcome::Validated(_)`; rejected/oversize/rate-
  limited/duplicate-suppressed/disabled outcomes never reach
  `try_stage_validated` (the queue's
  `StagingOutcome::RefusedNotValidated` guard filters them).
* **Phase 3 (local authorization gate)** — unchanged. The DevNet
  flag is hidden, defaults off, requires the existing live
  `0x05` validation flag, and is refused on TestNet without
  explicit operator opt-in via the policy's `allow_testnet`
  selector (the Run 147 flag selects
  `PeerDrivenStagingPolicy::testnet_enabled()` only when
  `config.environment == NetworkEnvironment::Testnet`; MainNet is
  refused at the CLI gate and again defensively at queue
  construction).
* **Phase 4 (apply)** — **NOT reached.** Run 147 does not
  implement peer-driven apply. The Phase 4 specification still
  governs the future Run 148+ apply runs.
* **Phase 5 (evidence and audit)** — Run 147 lands the canonical
  release-binary evidence report and harness for Phase 2.

### Run 147 release-binary evidence

`scripts/devnet/run_147_live_0x05_peer_candidate_staging_release_binary.sh`
captures, for every Run 147 scenario:

* binary identities (`sha256` and ELF `BuildID` for `qbind-node`
  plus the four reused Run 143 helper binaries);
* `git_commit`, `rustc --version`, `cargo --version`;
* per-node stdout / stderr;
* per-node Prometheus metrics scrapes;
* per-node `pqc_trust_bundle_sequence.json` and
  `pqc_authority_state.json` `sha256` pre/post (byte-identical
  asserted);
* per-node data-dir inventories (absent of
  `pqc_authority_state.json.tmp`, `RESTORED_FROM_SNAPSHOT.json`);
* per-scenario refusal exit codes for C1 / C2 / R2;
* denylist grep (asserted empty).

Acceptance evidence (source-level regression):

* `crates/qbind-node/tests/run_146_live_inbound_0x05_staging_hook_tests.rs`
  — 19 tests covering A1–A4, R1–R14, plus a late-install
  regression. All green under the Run 147 binary (Run 147 does
  not change dispatcher-level code; the source-level proof of the
  hook is unchanged).
* `crates/qbind-node/tests/run_145_peer_candidate_staging_tests.rs`
  — 20 tests covering the underlying queue invariants. All green.
* Regression suites verified green after Run 147: `run_146` (19),
  `run_145` (20), `run_142` (16), `run_088`, `run_079`, `run_109`,
  `run_134`, `run_138`, `qbind-node --lib pqc_authority`,
  `qbind-node --lib`.

### Verdict (mandatory disclosure per `task/RUN_147_TASK.txt`)

Run 147 is **NOT pure evidence-only.** It is

> **"source/test + release-binary evidence for hidden opt-in
> staging arming."**

The source delta is the single new hidden CLI flag, the top-level
partial-config refusal gate, and the dispatcher-construction
install branch documented above. Default release-binary behaviour
(no flag supplied) is bit-for-bit Run 143 / Run 146.

### Remaining open phases of this specification after Run 147

* **Run 148** — release-binary DevNet-only peer-driven apply
  evidence proving apply, post-commit marker persistence,
  session-eviction ordering, and Run 070 rollback behaviour. (The
  Run 144 specification still governs that surface.)
* **Run 149+** — governance / ratification / KMS / HSM hardening
  before any TestNet / MainNet claim.

### Invariants preserved by Run 147

Run 147 does not change any invariant from §3, §4, §7, §11, or §12
of this specification, and does not change any invariant from
Runs 145 / 146 progress entries. Specifically:

* Phase 4 (apply) is not entered.
* The Run 070 apply ordering is not changed.
* The Run 144 invariants 1–18 continue to hold.
* The Run 145 staging-queue non-application property continues to
  hold.
* The Run 146 dispatcher-hook ordering continues to hold:
  staging is downstream of validation and Run 142 / Run 123
  marker conflict checks, and strictly upstream of Run 088
  propagation.
* MainNet is refused both at the CLI gate and at queue
  construction; local peer majority remains insufficient for
  MainNet bundle-signing authority.
* No new wire format, no new on-disk schema, no new metric
  family, no new fixture helper.
## Run 148 progress entry — source/test peer-driven apply controller

Run 148 adds the first source-and-test wiring of a peer-driven
**apply** controller, behind an explicit local DevNet/TestNet
policy. It is library-only; the node binary's reload-apply and
SIGHUP paths are unchanged in Run 148.

Source delta:

* New module `crates/qbind-node/src/pqc_peer_candidate_apply.rs`
  exposing `PeerDrivenApplyPolicy` (default disabled;
  `devnet_enabled()`, `testnet_enabled()`, `mainnet_attempted()`
  constructors), the 13-variant `PeerDrivenApplyOutcome` enum,
  a `V2MarkerCoordinator` trait + `NoV2MarkerCoordinator`, and
  `try_apply_staged_peer_candidate(...)`.
* One `pub mod` line in `crates/qbind-node/src/lib.rs`.
* New integration test
  `crates/qbind-node/tests/run_148_peer_driven_apply_devnet_tests.rs`
  covering the A1–A4 + R1–R16 matrix from
  `task/RUN_148_TASK.txt` §7.

Scope statement:

* **Run 148 is source/test only.**
* **Peer-driven apply is now source/test wired only for
  DevNet/TestNet local policy.**
* **MainNet remains refused unconditionally.** Both the
  policy environment and the runtime-domain environment are
  checked; `allow_mainnet` is reserved for future governance
  wiring and has no effect on the refusal in Run 148.
* **Release-binary DevNet/TestNet peer-driven apply evidence is
  deferred to Run 149.**
* **Governance / KMS / HSM / signing-key lifecycle remain open.**
* **Full C4 remains open.**
* **C5 remains open.**

Invariants preserved by Run 148:

* The Run 070 apply contract is reused unchanged. The controller
  calls `apply_validated_candidate_with_previous(...)`; it does
  not duplicate validation, snapshot, swap, eviction, commit, or
  rollback logic.
* The v2 authority marker is **never** persisted before the
  Run 070 sequence commit succeeds. Persistence is delegated to
  a `V2MarkerCoordinator` after the apply returns `Ok`; a
  persist failure is surfaced as
  `PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`, an
  operator-actionable fatal outcome.
* Pre-apply marker conflicts (lower sequence, same-sequence
  different digest) refuse **before** any state mutation, per
  Run 123 / Run 134 / Run 138.
* The Run 144 invariants 1–18 continue to hold; the Run 145
  staging-queue non-application property continues to hold; the
  Run 146 dispatcher-hook ordering continues to hold; the
  Run 147 hidden-arming-flag semantics are unchanged.
* MainNet remains refused at every layer.
* No new wire format, no new on-disk schema, no new metric
  family, no new operator CLI flag.
## Run 149 progress entry — release-binary evidence for DevNet/TestNet peer-driven apply arming surface (minimal source wiring + release-binary evidence; partial-positive)

Run 149 produces the release-binary evidence that Run 148
explicitly deferred for the DevNet/TestNet peer-driven apply
controller. The Run 149 feasibility gate ("can a real
`target/release/qbind-node` arm and invoke the Run 148 peer-driven
apply controller through an existing runtime path?") returned
**NO** against the Run 148 state (the Run 148 controller was
library-only with no operator surface in `main.rs`); per
`task/RUN_149_TASK.txt`'s "preferred path if a flag is necessary"
allowance the smallest hidden, disabled-by-default DevNet/TestNet-only
arming flag was added:

```
--p2p-trust-bundle-peer-candidate-apply-enabled
```

with `clap hide = true`, `default = false`, refused on MainNet
unconditionally (early gate + defensive duplicate inside the
co-requisites block + the controller-layer banner's match arm),
refused without `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
refused without `--p2p-trust-bundle-peer-candidate-staging-enabled`,
does NOT imply propagation, does NOT introduce a new apply
algorithm, does NOT bypass staging / validation / v2 marker /
Run 055 anti-rollback / activation gates. When the gates pass,
two operator-visible log lines fire on DevNet/TestNet:

* `[binary] Run 149: peer-candidate apply arming flag accepted (env=...)` — operator acceptance line, mirroring the Run 147 acceptance line shape;
* `[run-149] live peer-driven apply policy ARMED (env=..., enabled=true, allow_devnet=..., allow_testnet=..., allow_mainnet=...)` — controller-layer banner that exercises the Run 148 `PeerDrivenApplyPolicy::devnet_enabled()` / `PeerDrivenApplyPolicy::testnet_enabled()` constructor at startup and surfaces the policy matrix to the operator.

**Partial-positive disclosure (mandatory).** Run 149 does not
wire a queue-to-controller drain task in the node binary. Wiring
such a drain would be a **new apply-triggering algorithm**, which
is explicitly out of scope per `task/RUN_149_TASK.txt` §20 and
§70. End-to-end release-binary apply of an already-staged
validated peer candidate through the Run 070 contract (matrix
rows A1–A4 in the Run 149 task) therefore remains under Run 148
source/test coverage; Run 149 captures release-binary evidence
for the new arming-surface refusal scenarios (C1 missing
wire-validation, C2/R2 MainNet refused, C3 missing staging) and
the new arming-surface acceptance log evidence on DevNet/TestNet,
plus the Run 147 release-binary non-mutation invariants under
the new flag.

A new release-binary harness
`scripts/devnet/run_149_peer_driven_apply_release_binary.sh`
builds the real release `qbind-node`, records build provenance
(`sha256`, `build-id`, `git_commit`, `rustc --version`,
`cargo --version`), exercises the Run 149 refusal surface (C1
apply-enabled without `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
— refused with exit code 1 and the Run 149 FATAL line; C2/R2
apply-enabled on `--env mainnet` — refused with exit code 1 and
the Run 149 FATAL line; C3 apply-enabled without
`--p2p-trust-bundle-peer-candidate-staging-enabled` — refused
with exit code 1 and the Run 149 FATAL line; C4 flag recognised
by parser — confirmed by C1/C2/C3 firing the Run 149 FATAL line
rather than the clap "unrecognized argument" error), reuses the
Run 143 / Run 147 N=3 DevNet topology bit-for-bit for the C5/C6
acceptance scenarios (cluster delta vs. Run 147: V1's extra-args
list receives `--p2p-trust-bundle-peer-candidate-apply-enabled`),
captures per-node stdout / stderr / exit codes, computes pre/post
`sha256` of every node's `pqc_trust_bundle_sequence.json` and
`pqc_authority_state.json` (asserted byte-identical pre/post on
every scenario), asserts (i) the `[binary] Run 149: peer-candidate
apply arming flag accepted` log line appears exactly once on V1
when the flag is supplied with valid co-requisites on
DevNet/TestNet and never on V0/V2, (ii) the `[run-149] live
peer-driven apply policy ARMED` controller-layer banner appears
exactly once on V1 and never on V0/V2, (iii) the Run 147 banners
continue to fire on V1, (iv) the Run 149 denylist (Run 147 denylist
+ `\bKMS\b`/`\bHSM\b`/`signing-key (rotation|revocation)`/`MainNet governance`)
sees **zero matches** across the entire captured corpus, and
(v) the V1 receiver remains running across reject scenarios (the
Run 146 / Run 147 hooks do not crash on rejection).

The captured artifacts (`summary.txt`, per-scenario stdout/stderr
logs, pre/post sequence hashes, pre/post marker hashes, in-scope /
out-of-scope grep summaries, C1/C2/C3 refusal exit codes) are
committed under `docs/devnet/run_149_peer_driven_apply_release_binary/`;
the verdict is recorded in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_149.md`.

Invariants preserved by Run 149:

* When the new flag is absent the binary is bit-for-bit identical
  to Run 147 (the entire Run 149 source delta is gated by the new
  flag).
* The Run 070 apply contract is reused unchanged. The Run 148
  controller is the only path to apply; the controller calls
  `apply_validated_candidate_with_previous(...)`; it does not
  duplicate validation, snapshot, swap, eviction, commit, or
  rollback logic.
* The v2 authority marker continues to be persisted only after
  the Run 070 sequence commit succeeds via the Run 148
  `V2MarkerCoordinator` post-commit boundary.
* Pre-apply marker conflicts (lower sequence,
  same-sequence-different-digest, v1-after-v2 downgrade,
  wrong-domain) refuse before any state mutation per the Run 148
  controller's existing gate order.
* The Run 144 invariants 1–18, the Run 145 staging-queue
  non-application property, the Run 146 dispatcher-hook ordering,
  the Run 147 hidden-arming-flag semantics, and the Run 148
  controller's 13-variant `PeerDrivenApplyOutcome` fail-closed
  taxonomy are all unchanged.
* MainNet remains refused at every layer (CLI early gate,
  defensive duplicate inside the co-requisites block, controller-
  layer banner's match arm, controller's runtime
  `RefusedMainNet` outcome).
* No new metric family, no new wire format, no new on-disk
  schema, no new fixture helper. The only new operator-visible
  surface is the single hidden disabled-by-default
  `--p2p-trust-bundle-peer-candidate-apply-enabled` flag and its
  two new log lines.

Run 149 is **not pure evidence-only**; it is **minimal source
wiring + release-binary evidence** under the §6 "Local
authorization gate" allowance. The §7 future-run decomposition
remains in force: governance / ratification / KMS / HSM hardening
(future Run 150+), signing-key rotation/revocation lifecycle, and
validator-set rotation remain pre-requisites for any TestNet /
MainNet peer-driven apply closure claim.

## Run 150 progress entry — explicit DevNet/TestNet drain trigger (source/test only)

Run 150 lands the smallest **source/test-only** wiring that connects
the Run 145/146 staged peer-candidate queue to the Run 148
peer-driven apply controller — and through it the existing Run 070
apply contract — behind an explicit local DevNet/TestNet-only
policy. Release-binary operator trigger evidence is **deferred to
Run 151**.

The new module
`crates/qbind-node/src/pqc_peer_candidate_drain.rs` adds:

* `PeerDrivenDrainPolicy` (disabled-by-default; explicit
  `devnet_enabled()` / `testnet_enabled()` /
  `mainnet_attempted()` constructors mirroring Run 145 / Run 148);
* `PeerDrivenDrainOutcome` (typed enum: `Disabled`,
  `MainNetRefused`, `RefusedEnvironmentPolicy`,
  `AlreadyInProgress`, `NoCandidate`, `CandidateExpired`,
  `CandidateNotValidated`, `CandidateWrongDomain`,
  `CandidateRejectedBeforeApply`, `CandidateMarkerConflict`,
  `Applied`, `ApplyRejected`, `ApplyFatal`);
* `PeerDrivenDrainInvocationBuilder` (the only seam through
  which a caller threads the candidate path / signing keys /
  live apply context / previous-fingerprint metadata into the
  Run 148 `PeerDrivenApplyInvocation`);
* `PeerDrivenApplyDrain` controller holding an `Arc<AtomicBool>`
  RAII-released concurrency guard with `try_drain_once(...)` as
  the single entry point;
* a deterministic selection rule: highest sequence wins; ties
  broken by lexicographically smallest `fingerprint_hex`; only
  signature-verified, domain-matching, non-expired entries are
  eligible.

Plus one additive helper on the Run 145 staging queue:

* `PeerCandidateStagingQueue::remove_by_id(fingerprint_prefix,
  sequence) -> Option<StagedPeerCandidate>` — strictly in-memory
  removal used by the drain after a successful terminal apply
  (or after a permanently-invalid pre-apply refusal classified as
  drop-from-queue). Touches no live trust state, no sequence
  file, no marker file, no P2P sessions, and no propagation.

The Run 150 safety contract that this document reaffirms:

* **Disabled by default.** The drain policy's
  `enabled / allow_devnet / allow_testnet` flags all default to
  `false`. The first decision in `try_drain_once` is the policy
  gate; the staging queue is never consulted and the concurrency
  guard is never touched when disabled.
* **DevNet / TestNet only.** MainNet is refused at the policy
  gate, again at the runtime-domain check, again defensively
  inside the environment-permission match, and the Run 148
  controller enforces its own MainNet refusal on the delegated
  call.
* **Operator/local only.** No peer-driven trigger surface. The
  trigger is an internal method exercised by tests and
  explicitly documented as the future Run 151 binary hook.
* **Concurrency-guarded.** Atomic compare-exchange on an
  `AtomicBool` ensures at most one drain enters the pipeline per
  controller instance; concurrent triggers observe
  `AlreadyInProgress`. The guard is RAII-released so a panic in
  the drain never leaves the controller permanently locked.
* **At most one candidate per trigger.** Each `try_drain_once`
  call drains a single eligible candidate; bulk / autonomous /
  background drains are explicitly out of scope.
* **No new apply algorithm.** Apply is delegated to the Run 148
  controller, which delegates to the Run 070
  `apply_validated_candidate_with_previous(...)` contract.
  `validate → snapshot_active → swap_trust_state →
  evict_sessions → commit_sequence` ordering is preserved
  verbatim; rollback / fatal semantics mirror Run 070; the v2
  authority marker is persisted only after `commit_sequence`
  succeeds via the existing Run 148 `V2MarkerCoordinator`
  post-commit boundary; a post-commit persist failure surfaces
  as the fatal / operator-actionable
  `PeerDrivenDrainOutcome::ApplyFatal{inner=MarkerPersistFailedAfterCommit}`.
* **No staging-queue / validation-only / propagation-only
  weakening.** The drain consumes the existing
  `StagedPeerCandidate` type, never re-validates the candidate
  (defence-in-depth filters re-check `signature_verified`,
  domain, and TTL), and never invokes any propagation surface.
* **No new metric family, no new wire format, no new on-disk
  schema, no new CLI flag.**

Out of scope for Run 150 (unchanged from Run 148 / Run 149):

* Release-binary operator-visible trigger (deferred to Run 151).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.

Run 150 is **strongest-positive within source/test scope**: the
A1–A8 + R1–R12 matrix from `task/RUN_150_TASK.txt` is implemented
in `crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
(19/19 green) and every refusal/no-op scenario asserts no live trust
swap, no sequence write, no marker write, no session eviction, no
Run 070 apply call, no SIGHUP outcome, no reload-apply outcome, no
peer-majority authority claim, and no MainNet apply.
## Run 151 — release-binary evidence for the explicit DevNet/TestNet drain trigger

Run 151 lands release-binary evidence for the smallest hidden,
disabled-by-default DevNet/TestNet-only **explicit local one-shot
drain trigger** that surfaces the Run 150 source/test
`PeerDrivenApplyDrain::try_drain_once` controller on the real
`target/release/qbind-node`. The trigger is the hidden CLI flag
`--p2p-trust-bundle-peer-candidate-drain-once` (defined in
`crates/qbind-node/src/cli.rs`); the matching `main.rs` blocks
add an early-startup MainNet refusal, a co-requisites gate
requiring `--p2p-trust-bundle-peer-candidate-apply-enabled`
(which itself transitively requires staging-enabled +
wire-validation-enabled), an acceptance banner
(`[binary] Run 151: peer-candidate drain-once trigger flag
accepted ...`), and a Run 150 controller-layer arming banner
(`[run-151] live peer-driven apply drain trigger ARMED ...`)
that materializes `PeerDrivenDrainPolicy::{devnet,testnet}_enabled()`
plus a fresh `PeerDrivenApplyDrain` controller with an
observably initialized `in_progress=false` concurrency flag.

The Run 151 source delta honours the Run 150 contract bit-for-bit:

* **Disabled by default.** The CLI flag is `hide=true` and
  defaults to `false`.
* **DevNet / TestNet only; MainNet refused.** The early-startup
  gate, the controller-layer gate, and the Run 150
  `PeerDrivenDrainPolicy` itself each enforce MainNet refusal
  independently (defensive triplicate).
* **Smallest possible hook.** Run 151 adds a single CLI bool
  plus two `main.rs` blocks (early refusal + co-requisites /
  arming). No new module, no new metric family, no new wire
  format, no new on-disk schema, no production
  `PeerDrivenDrainInvocationBuilder` impl, no production
  `V2MarkerCoordinator` impl, no plumbing of the live
  staging-queue handle across the `LivePeerCandidateWireDispatcher`
  builder scope.
* **Never calls Run 070 directly from `main.rs`.** The arming
  banner declares the chain `Run 150 try_drain_once → Run 148
  try_apply_staged_peer_candidate → Run 070
  apply_validated_candidate_with_previous`; Run 151 does not
  shortcut the chain.
* **At most one candidate per trigger.** The Run 150
  `try_drain_once` contract is unchanged; Run 151 does not
  introduce a bulk drain.
* **Concurrency-guarded.** The arming banner observably loads
  and prints the `Arc<AtomicBool>` in-progress flag's value as
  `in_progress=false`, confirming the guard is freshly
  constructed.
* **Operator/local only.** The trigger is operator-supplied at
  process start. No autonomous background task / timer / signal
  handler / peer-supplied trigger is added.

Verdict for Run 151:
**"minimal source wiring + release-binary evidence —
partial-positive (trigger-surface arming)."**

The release-binary harness (C1 missing apply-enabled co-requisite;
C2 / R2 MainNet refused unconditionally; C3 missing staging-enabled
via transitive Run 149 gate; C4 missing wire-validation-enabled
via upstream Run 147 gate; C5 / C6 DevNet / TestNet acceptance via
optional N=3 cluster harness; C7 clap-parser recognition; R1 flag
absent → Run 149 behaviour preserved; R12 propagation-only
unchanged; D1 denylist see-zero) is captured in
`scripts/devnet/run_151_peer_driven_apply_drain_release_binary.sh`
and archived under
`docs/devnet/run_151_peer_driven_apply_drain_release_binary/`.

End-to-end release-binary apply through the drain (matrix rows
A1, A2, A6, A7) remains under **Run 150 source/test coverage**
(`crates/qbind-node/tests/run_150_peer_driven_apply_drain_tests.rs`
19 / 19 green) which already exercises the strict Run 070
ordering `validate → snapshot_active → swap_trust_state →
evict_sessions → commit_sequence`, the v2 marker
`decide_pre_apply → persist_after_commit` post-commit-only
boundary, the `Applied` outcome, the queue-removal-on-success
contract, and the rollback / fatal semantics for R7 / R8 / R9
forced failures. Wiring the production
`PeerDrivenDrainInvocationBuilder` + `V2MarkerCoordinator`
implementations and plumbing the live staging-queue handle
across `main.rs` scopes so a real release-binary candidate
flows through the drain into Run 070 → `commit_sequence` →
post-commit v2 marker persist is a multi-piece production
source change that exceeds the "smallest possible hook"
allowance of `task/RUN_151_TASK.txt` and is the next future-run
piece on the C4 closure decomposition.

Out of scope for Run 151 (unchanged from Run 148 / Run 149 /
Run 150):

* Production `PeerDrivenDrainInvocationBuilder` /
  `V2MarkerCoordinator` impls wired into the binary (next
  future-run piece on the C4 closure decomposition).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.

Run 151 is **partial-positive trigger-surface arming**: the
trigger surface is now release-binary-armed and refusable, and
every refusal / no-op scenario asserts no live trust swap, no
sequence write, no marker write, no session eviction, no
Run 070 apply call from `main.rs`, no SIGHUP outcome, no
reload-apply outcome, no peer-majority authority claim, and no
MainNet apply.

## Run 152 — source/test wiring for binary-reachable peer-driven drain invocation plumbing

Run 152 lands the source/test wiring that Run 151 explicitly
deferred under its "smallest possible operator-local hook"
allowance: a production `PeerDrivenDrainInvocationBuilder`
implementation, a production `V2MarkerCoordinator`
implementation, and a shared in-memory staging-queue handle so
that the Run 151 hidden `--p2p-trust-bundle-peer-candidate-drain-once`
hook is now capable of constructing a real drain invocation
from the live staged peer-candidate queue and routing it
through:

```
live inbound 0x05 candidate
  → validation-only v2 acceptance
  → staging queue
  → hidden explicit drain-once hook
  → ProductionDrainInvocationBuilder
  → ProductionV2MarkerCoordinator
  → Run 150 PeerDrivenApplyDrain::try_drain_once
  → Run 148 try_apply_staged_peer_candidate
  → Run 070 apply_validated_candidate_with_previous
```

The Run 152 source delta honours the Run 150 / Run 151
contracts bit-for-bit:

* **`ProductionV2MarkerCoordinator`** (in
  `crates/qbind-node/src/pqc_peer_candidate_apply.rs`) reuses
  the existing Run 130/134/136/138 marker-acceptance helpers
  (`pqc_authority_marker_acceptance`); the pre-apply decision
  is captured by `decide_pre_apply` and persisted by
  `persist_after_commit` strictly **after** the Run 070
  `commit_sequence` boundary has succeeded. The coordinator
  fails closed on lower sequence, same-sequence different
  digest, wrong domain, and corrupted local marker. A
  post-commit persist failure is surfaced as the
  fatal/operator-actionable
  `PeerDrivenApplyOutcome::MarkerPersistFailedAfterCommit`
  per Run 134 §PersistFailure. The coordinator never mutates
  `LivePqcTrustState`, never evicts sessions, and never calls
  Run 070 directly.

* **`ProductionDrainInvocationBuilder<C: LiveTrustApplyContext>`**
  (in `crates/qbind-node/src/pqc_peer_candidate_drain.rs`)
  consumes only candidates already accepted by
  validation-only/staging, re-checks freshness/expiry,
  environment / chain_id / genesis_hash / authority-root
  binding, and v2 marker relation before any apply; fails
  closed on missing candidate material, malformed staged
  metadata, and ambiguous v1+v2 material. The builder never
  writes marker or sequence files itself, never mutates
  `LivePqcTrustState`, never evicts sessions, and never calls
  Run 070 directly.

* **Shared in-memory staging queue handle.** The drain
  consumes the same
  `Arc<parking_lot::Mutex<PeerCandidateStagingQueue>>` that the
  `LivePeerCandidateWireDispatcher` stages into via
  `pqc_peer_candidate_drain::try_drain_once_shared`. The queue
  remains in-memory only (no on-disk staging), bounded,
  deduped, and disabled unless the existing staging/apply
  flags enable it. Existing validation-only and
  propagation-only behaviour is unchanged.

* **`main.rs` arming-only reachability block** (gated entirely
  by the Run 151 `--p2p-trust-bundle-peer-candidate-drain-once`
  co-requisites scope) names the production types and the
  shared-queue drain function so the release binary observably
  links them in, and emits a `[run-152] binary-reachable
  peer-driven drain invocation plumbing PRESENT ...` banner
  declaring the full pipeline and the post-commit-only marker
  persist discipline. The release binary does **not**
  autonomously invoke the drain here: the live apply context,
  the verified v2 ratification, and the operator-supplied
  previous-fingerprint metadata are threaded by the Run 153
  end-to-end release-binary harness, which is explicitly
  deferred.

* **Hidden, disabled-by-default, DevNet/TestNet-only,
  MainNet refused.** The Run 151 CLI flag, gating, and arming
  banners are unchanged; Run 152 enforces MainNet refusal
  defensively at three layers (early-startup gate, Run 150
  `PeerDrivenDrainPolicy`, Run 148 controller).

* **Concurrency-guarded; one-shot.** Run 150's
  `Arc<AtomicBool>` RAII concurrency guard is unchanged; a
  second drain after a successful apply returns
  `NoCandidate` / `AlreadyApplied` / deduped per Run 150
  policy; a concurrent drain returns `AlreadyInProgress`.

* **Strict Run 070 ordering preserved.** The accepted
  source/test apply path preserves exactly
  `validate → snapshot previous → swap LivePqcTrustState →
  evict_sessions → commit_sequence → persist v2 authority
  marker`. The marker persist is strictly after sequence
  commit.

Verdict for Run 152: **"source/test wiring only"** for the
binary-reachable peer-driven drain invocation plumbing. The
production builder, the production v2 marker coordinator, the
shared staging-queue handle, and the shared-queue drain entry
point are now compiled into and reachable from the release
binary; end-to-end release-binary peer-driven apply evidence
is **DEFERRED to Run 153**.

Out of scope for Run 152 (unchanged from Run 148 / Run 149 /
Run 150 / Run 151):

* Release-binary end-to-end peer-driven apply harness
  (deferred to Run 153).
* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.

Run 152 is **source/test wiring only**: validation-only and
propagation-only behaviour remain unchanged, every refusal /
no-op scenario asserts no live trust swap, no sequence write,
no marker write, no session eviction, no Run 070 apply call,
no SIGHUP outcome, no reload-apply outcome, no peer-majority
authority claim, and no MainNet apply. **Full C4 is NOT
claimed by Run 152; C5 remains OPEN.**

## Run 153 — release-binary end-to-end peer-driven apply evidence

Run 153 wires the Run 152 binary-reachable plumbing into the Run 151
hidden `--p2p-trust-bundle-peer-candidate-drain-once` hook so the full
peer-driven apply pipeline is callable from a real release binary.

The source delta in `crates/qbind-node/src/main.rs` is minimal (~180
LOC, gated by the existing drain-once flag): a staging queue
`Arc<Mutex<PeerCandidateStagingQueue>>` is cloned from the live `0x05`
dispatcher's queue into the drain-once block, and after P2P startup +
configurable delay the drain block constructs the production builder,
coordinator, and context from the live trust state and invokes
`try_drain_once_shared` exactly once through the full pipeline:

    staging queue → ProductionDrainInvocationBuilder
    → ProductionV2MarkerCoordinator → Run 150 drain
    → Run 148 controller → Run 070 apply → LivePqcTrustState swap
    → session eviction → sequence commit → v2 marker persist

The Run 153 source delta honours the Run 150 / Run 151 / Run 152
safety contract bit-for-bit:

* **MainNet refused at four layers.** Early-startup gate (Run 151),
  co-requisites gate (Run 151), `PeerDrivenDrainPolicy` MainNet
  refusal (Run 150), and a new defensive guard at the drain-once
  invocation point.
* **One-shot, operator-triggered.** The drain fires exactly once
  after a configurable delay (`QBIND_DRAIN_ONCE_DELAY_SECS`); no
  autonomous background loop.
* **Ordering unchanged.** The drain routes through Run 150 / Run 148
  / Run 070 verbatim; the Run 070 ordering invariant is preserved.
* **Concurrency-guarded.** Run 150's `Arc<AtomicBool>` in-progress
  flag prevents concurrent drains.
* **No new wire format, no schema change, no new CLI flag.**

Verdict for Run 153: **"release-binary end-to-end peer-driven apply
evidence"** — the full pipeline is now callable from the release
binary via the hidden drain-once hook. Accepted apply evidence (A1,
A3, A4, A6, A7) and rejection evidence (R1–R10) are cited from
Run 152 (23 / 23 green) and Run 150 (19 / 19 green) source/test
coverage. Refusal scenarios (C1–C4, A5 MainNet) are evidenced by the
Run 153 release-binary harness. A2 TestNet evidence is deferred.

Out of scope for Run 153 (unchanged from Run 152):

* Autonomous background drain task.
* Automatic apply on receipt.
* Peer-majority authority.
* MainNet enablement.
* Governance / KMS / HSM implementation.
* Signing-key rotation / revocation lifecycle.

Run 153 is **release-binary end-to-end evidence**: validation-only
and propagation-only behaviour remain unchanged, MainNet remains
refused unconditionally, the drain is operator-triggered and
one-shot, no autonomous background apply exists, no governance /
KMS / HSM is implemented, no signing-key rotation / revocation
lifecycle is added. **Full C4 is NOT claimed by Run 153; C5
remains OPEN.**
## Run 154 — source/test TestNet fixture tooling (fixture tooling only)

Run 154 adds the smallest TestNet fixture tooling required to mint signed
TestNet trust-bundle material, v2 ratification sidecars bound to the
TestNet environment, transport credentials, a valid v2 peer-candidate
`0x05` fixture, and the invalid peer-candidate negative matrix
(lower-sequence, same-sequence different-digest, bad-signature,
wrong-environment, wrong-chain, duplicate). It is **source/test fixture
tooling only** and **does not modify the peer-driven apply safety
contract** in any way.

The fixture tooling extends the existing Run 133 v2 fixture helper
(`crates/qbind-node/examples/run_133_v2_validation_only_fixture_helper.rs`)
to also emit a `testnet/` directory; DevNet and MainNet output remain
byte-for-byte unchanged and the MainNet directory stays clearly
fixture-only (it is never production-authoritative). Every TestNet
artifact is domain-bound to `environment = TestNet`, the TestNet
`chain_id`, the TestNet genesis hash, the minted authority-root
fingerprint, and the v2 authority-domain sequence. All minted key
material is ephemeral: no production source-code anchor, fallback root,
or fallback signing key is introduced.

The Run 154 verify/reject matrix (21 tests in
`crates/qbind-node/tests/run_154_testnet_peer_apply_fixture_tests.rs`)
proves TestNet bundles / v2 ratifications / peer-candidates verify under
a TestNet context and fail under DevNet and MainNet contexts, that
wrong-chain / wrong-genesis / bad-signature variants fail, and that
lower-sequence and same-sequence different-digest variants fail through
the validation-only v2 authority-marker comparison (the on-disk marker is
byte-identical pre/post). The Run 070 / Run 142 / Run 143 / Run 145–153
surfaces are untouched and their suites remain green.

Run 154 closes the fixture-tooling blocker that caused the **Run 153 A2
TestNet evidence to be deferred**. Release-binary TestNet end-to-end
peer-driven apply evidence remains **deferred to Run 155**. MainNet
remains refused. Governance, KMS/HSM, signing-key rotation/revocation
lifecycle, and validator-set rotation all remain open. **Full C4 is NOT
claimed by Run 154; C5 remains OPEN.**
## Run 155 — release-binary TestNet end-to-end peer-driven apply evidence (evidence only)

Run 155 produces **release-binary TestNet end-to-end peer-driven apply
evidence** under the safety specification. It mirrors the Run 153 DevNet
end-to-end exercise on a real `target/release/qbind-node`, but binds the
whole exercise to the **TestNet runtime domain** using the Run 154 TestNet
fixtures. It **adds no source delta** and **does not modify the
peer-driven apply safety contract** in any way: the Run 153 wiring in
`main.rs` (the hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook driving
`ProductionDrainInvocationBuilder` → `ProductionV2MarkerCoordinator` →
Run 150 drain → Run 148 controller → Run 070 apply contract) is reused
verbatim, with the Run 150 `PeerDrivenDrainPolicy` / `PeerDrivenApplyPolicy`
selected by environment (`testnet_enabled()`) and MainNet refused
unconditionally.

The six-phase fail-closed pipeline is unchanged. For every accepted
TestNet apply the strict Run 070 ordering
(validate → snapshot previous → swap → evict_sessions → commit_sequence)
holds, the v2 authority marker persists strictly **after** sequence commit,
and there is no autonomous repeat drain. The TestNet domain binding
(`environment = testnet`, TestNet `chain_id` / chain-id hex
`51424e4454535400`, TestNet genesis hash, minted authority-root
fingerprint, v2 authority-domain sequence) is captured per run; all key
material is ephemeral (no production anchor, fallback root, or fallback
signing key).

The release-binary harness
(`scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh`)
proves on the real binary that drain-once is refused fail-closed when
co-requisites are missing (C1 without apply, C3 without staging, C4 without
wire-validation) and that MainNet is refused unconditionally (A6/C2), each
with exit=1 and a `FATAL` banner. The positive TestNet apply path (A1) and
the deterministic-selection / duplicate / reject matrix (A2–A5, R1–R11) are
evidenced by the Run 154 TestNet fixture suite (21 tests) and the
Run 152/150/148 source/test matrices, all green.

Run 155 closes the **Run 153 A2 TestNet evidence deferral**. DevNet
evidence from Run 153 remains valid. MainNet remains refused. Governance,
KMS/HSM, signing-key rotation/revocation lifecycle, and validator-set
rotation all remain open. **Full C4 is NOT claimed by Run 155; C5 remains
OPEN.**

## Run 156 — positive TestNet release-binary apply driven live; positive A1 BLOCKED by disjoint fixture universes, exact blocker documented (evidence only)

Run 156 drives the **positive** TestNet end-to-end peer-driven apply path
on a real `target/release/qbind-node` over a **live N=3 TestNet P2P
cluster**, instead of mapping the positive path to source/test coverage as
Run 153/155 did. It **adds no source delta** and **does not modify the
peer-driven apply safety contract**: the Run 153 `main.rs` wiring (the
hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook →
`ProductionDrainInvocationBuilder` → `ProductionV2MarkerCoordinator` →
Run 150 drain → Run 148 controller → Run 070 apply contract) is reused
verbatim, with the Run 150 policies selected by environment and MainNet
refused unconditionally.

The six-phase fail-closed pipeline is unchanged. On the fixtures shipped
in this repository, the live binaries drive the pipeline end-to-end **up
to V1's wire-validation gate**: V0 publishes one live `0x05` candidate and
V1 observes it (`Run 078 … outcome=rejected; NOT applied`), but the
candidate is rejected before staging — so the explicit drain-once returns
`NoCandidate` with **no live trust mutation** (the fail-closed contract
held correctly: an empty staged queue does not apply). The
wire-validation gate behaved exactly as the safety contract requires; the
limitation is in the fixtures, not the contract.

**Exact blocker:** peer-driven apply requires the candidate to be a valid
Run-070 successor of V1's live baseline `LivePqcTrustState`, initialised
from V1's live `--p2p-trust-bundle`. The live transport bundle and the
N=3 leaf credentials are minted by `devnet_pqc_trust_bundle_helper`
(`signed-testnet`) under one root authority; the only TestNet apply
candidate (`run_133` helper `testnet/peer-candidate.valid.json`,
`declared_sequence=2`) is signed under a **disjoint** root with no
matching P2P leaf credentials, so it is not a successor of V1's live
baseline and is rejected at the live `0x05` wire-validation / ratification
gate. No existing fixture tool mints a single unified universe providing
both (a) N=3 P2P leaf credentials and (b) a self-consistent seq1→seq2
apply pair signed by that same transport root plus the matching v2
ratification sidecar.

The release-binary harness
(`scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh`)
is a **complete driver**: it accepts `QBIND_RUN156_TRANSPORT_DIR` /
`QBIND_RUN156_CANDIDATE_ENVELOPE` / `QBIND_RUN156_SIDECAR` /
`QBIND_RUN156_GENESIS` / `QBIND_RUN156_GENESIS_HASH` overrides so that,
once a future fixture-tooling run mints a unified universe, re-running it
drives the real apply and asserts the strict Run 070 ordering
(validate → snapshot previous → swap → evict_sessions → commit_sequence,
with the v2 authority marker persisted strictly after sequence commit)
automatically. It also re-confirms MainNet drain-once refusal (A6/C2,
exit=1, `Run 151: FATAL`).

Run 156 explicitly **does not** claim the positive A1 path closed and
**does not** substitute source/test coverage for the live positive
verdict. DevNet evidence from Run 153 and TestNet evidence from Run 155
remain valid. MainNet remains refused. Governance, KMS/HSM, signing-key
rotation/revocation lifecycle, and validator-set rotation all remain open.
**Full C4 is NOT claimed by Run 156; C5 remains OPEN; the positive TestNet
release-binary A1 apply remains BLOCKED pending unified fixture tooling.**
## Run 157 fixture-universe requirement

Run 157 adds source/test fixture tooling only for a unified TestNet peer-driven apply universe. The helper-generated TestNet manifest is intended for validation and future Run 158 harness consumption; it does not change the peer-candidate wire format, does not add automatic apply on receipt, and does not make a release-binary positive apply claim.

A valid TestNet positive-apply fixture universe must bind all of the following to the same domain: environment `testnet`, TestNet chain id, canonical TestNet genesis hash, genesis-bound authority root, active bundle-signing key, live transport root, baseline bundle sequence 1, candidate bundle sequence 2, v2 ratification sidecar, seeded marker if present, and peer-candidate envelope. A disjoint-universe shape like Run 156 must fail before staging.

Run 157 leaves MainNet refused and fixture-only. Governance, KMS/HSM, signing-key rotation/revocation lifecycle, validator-set rotation, full C4, and C5 remain open. Release-binary positive TestNet apply evidence remains deferred to Run 158.
## Run 158 — positive TestNet release-binary peer-driven apply evidence using the Run 157 unified fixture universe (evidence/harness/docs only)

Run 158 closes the **Run 156 disjoint-universe blocker** for the positive TestNet release-binary end-to-end peer-driven apply path. It uses the **Run 157 unified TestNet fixture universe** (one self-consistent universe binding live transport material, baseline seq=1 trust bundle, candidate seq=2 trust bundle, v2 ratification sidecar, seeded v2 marker, V0/V1/V2 leaf certs/KEM keys, and the valid `0x05` peer-candidate envelope to one TestNet domain, chain id, genesis hash, authority root, transport root, and bundle-signing authority) so that the published candidate is a **valid Run-070 successor** of V1's live baseline `LivePqcTrustState`. This is the precise condition Run 156's disjoint universes failed to satisfy.

Run 158 introduces **no production runtime source change** and **no change to the Run 144 safety specification**. The Run 153 wiring (`drain_once_staging_queue` + the post-P2P drain-once block constructing `ProductionDrainInvocationBuilder` / `ProductionV2MarkerCoordinator` and calling `try_drain_once_shared` exactly once) is reused unchanged; the Run 144 six-phase fail-closed pipeline (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) is exercised verbatim by the unified universe.

The harness asserts the canonical ordering on V1's release-binary stderr (P2P up → live `0x05` received → v2 validation-only accepted under TestNet domain → staged → drain-once triggered → `ProductionDrainInvocationBuilder` invoked → `ProductionV2MarkerCoordinator` accepted → Run 150 drain → Run 148 controller → Run 070 `validate → snapshot → swap → evict_sessions → commit_sequence` → `persisted_sequence=2` → v2 authority marker persisted strictly **after** the sequence commit → `VERDICT=applied`) and writes `a1_apply_proof.txt` (PROVEN) or `a1_blocker.txt` (BLOCKED with the exact failure mode). Run 158 does **not** substitute source/test coverage for the positive A1 verdict.

Run 158 also re-confirms the safety contract on the real binary: MainNet drain-once is **refused unconditionally** (`Run 151: FATAL`, exit code 1); the TestNet fail-closed gates (drain-without-apply, drain-without-staging, drain-without-wire-validation) each exit 1 with `FATAL`; the unified-universe wrong-environment / wrong-chain / bad-signature / lower-sequence / same-sequence-different-digest / ambiguous-v1+v2 / disjoint-universe negative envelopes are rejected before staging (cited from Run 156 + the Run 157 source/test negative matrix); and the out-of-scope denylist (`autonomous drain`, `apply on receipt`, `peer-majority`, `governance`, `KMS`, `HSM`, `signing-key rotation/revocation`, `validator-set rotation`, `--p2p-trusted-root`, `DummySig` / `DummyKem` / `DummyAead`, `SIGHUP / reload-apply / startup-mutation / snapshot-restore applied`, `mainnet applied`, `schema/wire/metric drift`) is required to be empty.

Run 158 is **evidence/harness/docs only**: no production runtime source change, no CLI flag added or renamed, no `main.rs` / `cli.rs` change, no SIGHUP / reload-apply / startup-mutation / snapshot-restore path change, no live `0x05` dispatcher change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 070 path, no authority-marker write outside the existing post-commit boundary, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance implementation, no signing-key rotation / revocation lifecycle, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour.

DevNet evidence from Run 153, TestNet release-binary refusal evidence from Run 155, and Run 156's release-binary live-path evidence + exact disjoint-universe blocker remain valid and untouched. **Full C4 is NOT claimed by Run 158; C5 remains OPEN.** When A1 is PROVEN by a given harness invocation, the Run 156 disjoint-universe blocker is closed for that invocation; the open C4 closure pieces (governance / ratification authority, KMS / HSM custody, signing-key rotation / revocation lifecycle, MainNet governance attestation, validator-set rotation) remain open.
## Run 159 — source/test signing-key lifecycle validation; safety contract unchanged

Run 159 lands typed pure transition validation for the v2 bundle-signing-key lifecycle (`ActivateInitial`, `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke`) as a new `qbind_node::pqc_authority_lifecycle` module. The new validator is **pure** and **typed**: it performs no I/O, never mutates the persisted authority marker, never writes the sequence file, and never touches a live trust bundle. The Run 144 safety contract and the **six-phase fail-closed pipeline** are **unchanged**.

The Run 159 validator is intentionally **not yet wired** into any mutating surface; it is offered as a *typed pre-flight surface* that future runs may compose into the existing Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist pipeline once a wire-level encoding for `Retire` / `EmergencyRevoke` lands. Until then, the existing marker-comparison helpers remain the authoritative mutating-surface decision points and are unchanged. No autonomous peer-driven apply, no automatic apply on receipt, no peer-majority authority, no MainNet drain-once enablement, no governance, no KMS / HSM, no validator-set rotation, no fallback authority root, and no static production source-code anchor are introduced or weakened. DevNet evidence from Run 153, TestNet evidence from Runs 154/155/157/158, the Run 156 disjoint-universe documentation, and the six-phase fail-closed pipeline remain valid and untouched.

Run 159 is **source/test only**: no production runtime source change beyond the additive new module and the `pub mod` declaration, no CLI flag added or renamed, no `main.rs` / `cli.rs` change, no SIGHUP / reload-apply / startup-mutation / snapshot-restore path change, no live `0x05` dispatcher change, no `LivePqcTrustState` mutation, no sequence write, no authority-marker write, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. **Release-binary lifecycle evidence is deferred to Run 160. Full C4 is NOT claimed by Run 159; C5 remains OPEN.**
## Run 160 — release-binary evidence / boundary for the v2 signing-key lifecycle validator; safety contract unchanged

Run 160 produces release-binary evidence for the Run 159 v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`). The Run 144 safety contract and the **six-phase fail-closed pipeline** (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) are **unchanged**. Run 160 does **not** wire the Run 159 lifecycle validator into any mutating surface. The Run 134 / 138 / 150 / 152 / 153 / 158 marker-comparison and accept-and-persist composition continues to own the mutating-surface decision and is unchanged.

The Run 160 source-level call graph (captured by the harness in `docs/devnet/run_160_authority_lifecycle_release_binary/call_graph/reachability.txt`) shows that `validate_v2_lifecycle_transition` and `classify_local_lifecycle_action` have **zero** production callers — none of the eight release-binary surfaces enumerated by `task/RUN_160_TASK.txt` (startup `--p2p-trust-bundle` v2, reload-check validation-only, local peer-candidate-check validation-only, process-start reload-apply, SIGHUP live-reload, live inbound `0x05` validation-only, peer-driven staged drain-once, fixture helper / example) calls the validator. The Run 160 verdict is `partial-positive: release-binary fixture/evidence boundary captured; lifecycle validator not yet production-surface reachable`; **strongest-positive is intentionally NOT claimed**.

Run 160 adds a release-built lifecycle fixture helper (`target/release/examples/run_160_authority_lifecycle_fixture_helper`) that mints the A1–A6 + R1–R14 fixture corpus using the existing `PersistentAuthorityStateRecordV2::new` / `PersistentAuthorityStateRecord::new` / `PersistentAuthorityStateRecordV2::validate_structure` primitives. No new wire format, no trust-bundle schema change, no authority-marker schema change, no sequence-file schema change, and no peer-candidate envelope schema change is introduced. The on-wire `BundleSigningRatificationV2Action` byte set (`Ratify=0`, `Rotate=1`, `Revoke=2`) is preserved unchanged; Retire and EmergencyRevoke ride the existing `Revoke=2` byte plus the Run 159 local sub-class prefix in `revoked_key_metadata` (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke). The Run 160 harness re-confirms the existing safety contract on the real release binary by running the Run 134 / 138 / 142 / 148 / 150 / 152 / 157 regression suites and the Run 159 lifecycle test suite, and by recording the binary's identity (sha256 + ELF Build ID) in `provenance.txt`.

Run 160 is **release-binary evidence/boundary only**: no production runtime source change, no CLI flag added or renamed, no `main.rs` / `cli.rs` change, no SIGHUP / reload-apply / startup-mutation / snapshot-restore / live `0x05` dispatcher / drain-once code path change, no `LivePqcTrustState` mutation, no sequence write, no authority-marker write, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. **Release-binary lifecycle apply is not enabled. The exact next required integration run is Run 161 — wire `validate_v2_lifecycle_transition` into the existing Run 134 / 136 / 138 / 150 / 152 marker-comparison and accept-and-persist boundary. Full C4 is NOT claimed by Run 160; C5 remains OPEN.**
## Run 161 — wire the v2 signing-key lifecycle validator into the shared marker-decision helper; six-phase pipeline unchanged

Run 161 is **source/test integration only**. The Run 144 safety contract and the **six-phase fail-closed pipeline** (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) are **unchanged**. Run 161 composes the Run 159 typed v2 bundle-signing-key lifecycle validator (`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`) inside the shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2` that is already used at the post-commit-marker decision step by Run 134 (process-start reload-apply), Run 136 (startup `--p2p-trust-bundle`), Run 138 (SIGHUP live-reload), Run 150 (peer-driven drain), Run 152 (`ProductionV2MarkerCoordinator`), Run 132 (reload-check), and Run 142 (live inbound `0x05` validation-only). The six phases themselves are untouched — preflight / wire-validation / staging admission / drain selection / apply ordering remain bit-for-bit identical to Run 144. The single typed pre-mutation lifecycle gate is added inside the existing helper at the marker-decision step that already precedes Run 070 apply on every mutating surface, surfacing every Run 159 fail-closed reject (wrong previous-key fingerprint on rotate, revoked-key reuse, retired-key reuse, malformed revoked metadata, non-PQC suite, unsupported lifecycle action under the current persisted state, emergency-revoke replay, structurally malformed v2 candidate) as the new typed reject `MutatingSurfaceMarkerV2Error::LifecycleRejected(AuthorityLifecycleTransitionOutcome)`. `decide_marker_acceptance_v2` itself never touches disk; the persist primitive `persist_accepted_v2_marker_after_commit_boundary` continues to be the only disk-touching helper, persistence remains strictly after Run 055 sequence commit, and the post-commit marker boundary is unchanged.

Run 161 introduces **no wire-format change**: the on-wire `BundleSigningRatificationV2Action` byte set (`Ratify=0`, `Rotate=1`, `Revoke=2`) is unchanged; the trust-bundle / ratification-sidecar / authority-marker / sequence-file / peer-candidate-envelope schemas are unchanged; the Run 159 local sub-class metadata convention (`01`=Revoke, `02`=Retire, `03`=EmergencyRevoke) is reused verbatim. Two Run 159 reject variants are passed through to the existing comparison decision rather than escalated, by design (R20 back-compat): `InitialActivationAfterPersistedRejected` (the wire-byte `Ratify` advancement that pre-Run-161 fixtures continue to issue, where anti-rollback is already enforced by the existing v2 marker-schema compare) and `V1PersistedV2CandidateNotSupportedHere` (the Run 131 explicit v1→v2 migration boundary, which Run 159 deliberately does not validate). All other Run 159 reject variants are fail-closed.

Run 161 is **source/test only**: no release-binary evidence, no CLI flag added or renamed, no `main.rs` / `cli.rs` change, no SIGHUP / reload-apply / startup-mutation / snapshot-restore / live `0x05` dispatcher / drain-once code-path *signature* change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 055 path, no authority-marker write outside the existing post-commit boundary, no new wire format, no schema change, no new metric family, no KMS / HSM, no governance implementation, no MainNet enablement, no autonomous background drain, no automatic apply on receipt, no peer-majority authority, and no weakening of validation-only or propagation-only behaviour. **Release-binary lifecycle apply evidence is deferred to Run 162. Full C4 is NOT claimed by Run 161; C5 remains OPEN.**
## Run 162 — release-binary lifecycle ENFORCEMENT evidence on real `target/release/qbind-node`; safety contract unchanged

Run 162 is **release-binary evidence only**. The Run 144 safety contract and the **six-phase fail-closed pipeline** (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) are **unchanged**. Run 162 produces release-binary evidence that the Run 161 wiring of the Run 159 lifecycle validator into `decide_marker_acceptance_v2` is exercised on real `target/release/qbind-node`: lifecycle accepts (`ActivateInitial`, `Rotate`, `Idempotent`) and lifecycle rejects (`lower-sequence`, `same-sequence different-digest` equivocation, `wrong environment`, `wrong chain`, `wrong genesis`, the PQC-verifier surrogate for `non-PQC suite`, and `corrupted local marker`) are observable on the release binary through the `--p2p-trust-bundle-reload-check` (validation-only) and `--p2p-trust-bundle-reload-apply-path` (mutating) v2 marker-decision surfaces. The new artifacts are exclusively the harness `scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`, the curated evidence archive `docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/` (only README.md + summary.txt tracked; per-run logs / data / fixtures / exit_codes / marker_hashes / sequence_hashes / data_inventories / grep_summaries / reachability / provenance.txt / fixture_manifest.txt are .gitignored mirroring Run 153 / 155 / 156 / 158 / 160), the canonical evidence report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md`, and four narrow doc alignment updates.

For every mutating accept (`B.A1`, `B.A2`, `B.A6`), Run 162 verifies bit-for-bit that the existing six-phase pipeline still owns the apply: lifecycle validation runs **before** any live trust mutation; Run 070 apply succeeds (`trust-bundle candidate APPLIED live`); Run 055 sequence commit succeeds (`sequence_commit=ok`); the v2 marker persists strictly **after** the sequence commit (`[run-134] v2 authority-marker persisted ... candidate latest_authority_domain_sequence=N`); marker SHA-256 before+after and sequence SHA-256 after are captured. For every reject (validation-only or mutating), Run 162 verifies no live trust swap, no session eviction, no Run 055 sequence write, no v2 marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead`.

Run 162 **explicitly supersedes Run 160's "zero production caller" partial-positive boundary**: a `grep -nE 'validate_v2_lifecycle_transition|LifecycleRejected'` over `crates/qbind-node/src/**.rs` now returns hits in `pqc_authority_marker_acceptance.rs` (where Run 161 added the production call site and the matching typed-reject constructor), and that helper is the one the release binary's reload-check / reload-apply / SIGHUP / startup / peer-driven drain paths invoke; Run 161's source/test results A1–A9 / R1–R20 are therefore now claims about the **same production code path** the release binary actually executes.

Run 162 introduces **no wire-format change, no schema change, no metric drift, no new CLI flag, no production runtime source change**, and does not touch SIGHUP / startup-trust-bundle / live `0x05` / drain-once code paths. MainNet remains refused unconditionally (this harness does not enable MainNet on any surface; MainNet peer-driven apply refusal is cited from Run 151 / Run 158 release-binary evidence). Governance / KMS / HSM / validator-set rotation remain unimplemented. Sub-class-metadata-driven Retire / EmergencyRevoke release-binary acceptance and the sub-class-only rejection cases (R6–R11) remain source/test-only on the release binary today and are cited from Run 159 + Run 161 source/test coverage. **Full C4 is NOT claimed by Run 162; C5 remains OPEN.**
## Run 163 — source/test governance ratification authority verifier; safety contract unchanged

Run 163 is **source/test only**. The Run 144 safety contract and the **six-phase fail-closed pipeline** (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) are **unchanged**. Run 163 lands a typed pure non-mutating governance ratification authority verifier (`crates/qbind-node/src/pqc_governance_authority.rs`, `verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, `GovernanceAuthorityProof`, `GovernanceAuthorityClass {GenesisBound, EmergencyCouncil, OnChainGovernance}`, `GovernanceAuthorityVerificationOutcome`, `CombinedLifecycleGovernanceOutcome`, `GovernanceIssuerSignatureVerifier`, `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`) that defines and validates the local proof object that — in a future run — can authorize MainNet/TestNet governance-controlled bundle-signing-key lifecycle transitions. The verifier is **NOT wired into mutating apply surfaces**: it is a pure typed decision aid only, paired with a pure non-mutating helper `validate_lifecycle_with_governance_authority` that composes Run 159's typed v2 lifecycle validator with the new governance authority verifier into a single `CombinedLifecycleGovernanceOutcome` performing no I/O, writing no marker, writing no sequence, and mutating no live trust state.

The verifier is **fail-closed** for `OnChainGovernance` (no on-chain proof format exists yet — the verifier rejects with `UnsupportedOnChainGovernance`); the typed reject surface explicitly carries `LocalOperatorConfigOnlyRejected` and `PeerMajorityProofRejected` variants so peer-majority / gossip-count and local-operator-config-only inputs are rejected as authority proofs at the type level — preserving the existing safety invariants that local config alone is insufficient for MainNet bundle-signing authority and local peer majority is insufficient for MainNet bundle-signing authority. Run 163 introduces **no wire-format change, no marker schema change, no sequence-file schema change, no trust-bundle schema change, no metric drift, no new CLI flag, and no production runtime change in any peer-driven apply surface** (no SIGHUP / reload-apply / startup-trust-bundle / live `0x05` / drain-once code path change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 055 path, and no authority-marker write outside the existing post-commit boundary).

MainNet remains refused unconditionally; governance execution / KMS / HSM / validator-set rotation remain unimplemented. **Release-binary governance verifier evidence is deferred to Run 164.** DevNet evidence from Run 153 and TestNet evidence from Runs 154/155/157/158 remain valid and untouched; Run 159 source/test lifecycle coverage, Run 161 source/test integration coverage, and Run 162's release-binary lifecycle enforcement evidence all remain valid. **Full C4 is NOT claimed by Run 163; C5 remains OPEN.**
## Run 164 — release-binary EVIDENCE / BOUNDARY for the Run 163 governance authority verifier; safety contract unchanged

Run 164 is **release-binary evidence/boundary only**. The Run 144 safety contract and the **six-phase fail-closed pipeline** (preflight → wire validation → staging admission → drain selection → apply ordering → post-commit marker boundary) are **unchanged**. Run 164 produces the strongest honest release-binary evidence currently possible for the Run 163 typed pure governance ratification authority verifier (`qbind_node::pqc_governance_authority::verify_governance_authority_proof`, `validate_lifecycle_with_governance_authority`, `GovernanceAuthorityProof`, `GovernanceAuthorityClass {GenesisBound, EmergencyCouncil, OnChainGovernance}`, `GovernanceAuthorityVerificationOutcome`, `CombinedLifecycleGovernanceOutcome`) and clearly determines that the verifier is **not** release-binary reachable from any production v2 surface today. None of the existing peer-driven apply surfaces (peer-candidate validation-only check, live `0x05` validation-only frame, staged queue admission, drain-once selection, Run 070 apply, Run 055 sequence commit, post-commit v2 marker persistence) calls the Run 163 governance verifier; the verifier is observed-not-claimed across the entire pipeline. The Run 161 wiring of the Run 159 lifecycle validator into the shared v2 marker-decision helper `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2` and Run 162's release-binary lifecycle ENFORCEMENT evidence both remain valid and untouched.

Run 164 captures the release-binary evidence that is honestly available through the release-built helper / example binary path: the new release-built helper `crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs` mints the governance proof corpus (A1 GenesisBound Rotate; A2 GenesisBound Revoke; A3 GenesisBound EmergencyRevoke; A4 EmergencyCouncil EmergencyRevoke; A5 idempotent same proof / same candidate; R1 wrong environment; R2 wrong chain; R3 wrong genesis; R4 wrong authority root; R5 wrong lifecycle action; R6 wrong candidate digest; R7 wrong authority-domain sequence; R8 invalid issuer signature; R9 unsupported issuer suite; R10 non-PQC issuer suite; R11 threshold not met; R12 malformed proof; R13 stale lower-sequence replay; R14 OnChainGovernance unsupported / fail-closed; R15 local operator config alone rejected; R16 peer-majority rejected) and invokes `verify_governance_authority_proof` and `validate_lifecycle_with_governance_authority` on every scenario; the release-binary harness `scripts/devnet/run_164_governance_authority_release_binary.sh` asserts the expected typed-outcome class per scenario.

Run 164 introduces **no wire-format change, no marker schema change, no sequence-file schema change, no trust-bundle schema change, no peer-candidate envelope schema change, no metric drift, no new CLI flag, and no production runtime change in any peer-driven apply surface**. No SIGHUP / reload-apply / startup-trust-bundle / live `0x05` / drain-once code path change, no `LivePqcTrustState` mutation outside the existing Run 070 apply path, no sequence write outside the existing Run 055 path, and no authority-marker write outside the existing post-commit boundary. The verifier is **NOT** wired into mutating apply surfaces; release-binary governance verifier production-reachability remains deferred to Run 165 (with Run 166 as the partner release-binary ENFORCEMENT evidence run for Run 165).

The verifier is **fail-closed** for `OnChainGovernance` (no on-chain proof format exists yet — the verifier rejects with `UnsupportedOnChainGovernance`); the typed reject surface explicitly carries `LocalOperatorConfigOnlyRejected` and `PeerMajorityProofRejected` variants so peer-majority / gossip-count and local-operator-config-only inputs are rejected as authority proofs at the type level — preserving the existing safety invariants that local config alone is insufficient for MainNet bundle-signing authority and local peer majority is insufficient for MainNet bundle-signing authority. MainNet remains refused unconditionally (Run 151 / Run 158); governance execution / KMS / HSM / validator-set rotation remain unimplemented. DevNet evidence from Run 153 and TestNet evidence from Runs 154/155/157/158 remain valid and untouched; Run 159 source/test lifecycle coverage, Run 161 source/test integration coverage, Run 162's release-binary lifecycle ENFORCEMENT evidence, and Run 163's source/test governance verifier coverage all remain valid. **Full C4 is NOT claimed by Run 164; C5 remains OPEN.**
## Run 165 — governance authority verification composed into the peer-driven marker decision (SOURCE/TEST)

Run 165 is **source/test integration only** and introduces **no wire-format change, no marker schema change, no sequence-file schema change, and no trust-bundle schema change**. The Run 144 peer-driven apply safety contract is unchanged.

The peer-driven drain `ProductionV2MarkerCoordinator::decide_pre_apply` now routes through the governance-aware shared helper `decide_v2_marker_acceptance_with_lifecycle_and_governance`, which composes the existing v2 anti-rollback compare + Run 159 lifecycle validity + Run 163 governance authority validity (where policy requires it). This makes `verify_governance_authority_proof` production-source reachable from the peer-driven path without changing its mutation contract: a governance rejection (`GovernanceAuthorityRejected`) or a required-but-missing proof (`GovernanceAuthorityRequiredButMissing`) fails closed — **no apply, no live trust swap, no session eviction, no sequence write, and no marker write** — exactly like the existing lifecycle/anti-rollback rejections.

The peer-driven wire material does **not** carry a governance proof (documented schema-carrying gap; no schema invented), so the peer-driven surface supplies `GovernanceProofContext::Unavailable` under the `NotRequired` policy — behaviour-preserving for Run 165. Accepting a governance proof would **not** enable MainNet peer-driven apply: **MainNet apply remains refused unconditionally even with a valid governance proof**, enforced by the existing environment gate, which Run 165 does not touch. Release-binary governance **enforcement** evidence is deferred to **Run 166**. Tests: `crates/qbind-node/tests/run_165_governance_marker_integration_tests.rs`. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_165.md`.
## Run 166 — release-binary EVIDENCE / ENFORCEMENT of the Run 165 governance gate on the peer-driven marker decision; safety contract unchanged

Run 166 is the release-binary partner of Run 165 and does **not** modify the Run 144 safety contract or the six-phase fail-closed pipeline. The peer-driven drain `ProductionV2MarkerCoordinator` continues to invoke `decide_v2_marker_acceptance_with_lifecycle_and_governance` at `policy=GovernanceProofPolicy::NotRequired` + `context=GovernanceProofContext::Unavailable`, exactly as wired in Run 165 — Run 166 captures the source-level grep proof that the four production callers (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`, and the two `main.rs` pre-flights) reach the governance-aware helper, and exercises the gate live on real `target/release/qbind-node` for `NotRequired`+`Unavailable` accept on the validation-only and mutating reload surfaces. Release-binary `RequiredButMissing` / `Rejected` fail-closed semantics are captured on a release-built helper that links the same production helper symbol; the peer-driven drain `RequiredButMissing` scenario is documented as not directly representable through `target/release/qbind-node` today because doing so would require either changing the peer-candidate-envelope schema to carry a `GovernanceAuthorityProof` or adding a CLI / environment knob to flip the production policy — both forbidden by Run 166's strict scope and deferred to Run 167.

Run 166 introduces no production runtime source change, no CLI flag, no environment variable, no marker / sequence / trust-bundle / peer-candidate-envelope schema change, no new metric family, and no MainNet enablement. MainNet peer-driven apply remains refused unconditionally even with a valid governance proof. Tests: the Run 165 marker-integration suite (`crates/qbind-node/tests/run_165_governance_marker_integration_tests.rs`) and the existing Run 161 / 159 / 152 / 150 / 148 / 142 / 138 / 134 regressions all remain green on the same checkout. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_166.md`, `docs/devnet/run_166_governance_gate_release_binary_enforcement/`.
## Run 167 — source/test governance-proof carrying schema for v2 authority sidecars; safety contract unchanged

Run 167 is **source/test schema/carrying work only** and does **not** modify the Run 144 safety contract, the six-phase fail-closed pipeline, or the peer-driven drain `ProductionV2MarkerCoordinator` runtime behaviour. The four production callers (`pqc_live_trust_reload.rs`, `pqc_peer_candidate_apply.rs`, `main.rs` reload-apply preflight, `main.rs` startup `--p2p-trust-bundle` preflight) continue to invoke `decide_v2_marker_acceptance_with_lifecycle_and_governance` at `policy=GovernanceProofPolicy::NotRequired` + `context=GovernanceProofContext::Unavailable`, exactly as Run 166 evidenced.

Run 167 adds the smallest additive carrier (`qbind_node::pqc_governance_proof_wire::GovernanceAuthorityProofWire` with `GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION = 1`) so a v2 ratification sidecar can transport a typed `GovernanceAuthorityProof` through the existing Run 167 sidecar loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`) into the Run 165 governance gate. The carrier is attached to the v2 ratification sidecar JSON **only** as an additive optional sibling field `governance_authority_proof`; `qbind_ledger::BundleSigningRatificationV2`, the trust-bundle schema, the authority-marker schema, the sequence-file schema, and the peer-candidate envelope schema are all unchanged — strictly preserving the Run 144 safety contract, the six-phase fail-closed pipeline, the Run 070 apply ordering (`validate → snapshot → swap → evict_sessions → commit_sequence`), and the post-Run-055 marker-write boundary on every mutating surface. Parsing the wire carrier performs **no marker write, no sequence write, no live trust swap, no session eviction**. Sidecars with malformed carriers fail closed at the gate under any policy that requires a proof; sidecars without the carrier remain valid under `NotRequired` (the production policy today) and fail closed under `RequiredForLifecycleSensitive` for lifecycle-sensitive actions, exactly as Run 165 specified.

MainNet peer-driven apply remains refused unconditionally even with a valid governance proof — gate acceptance is independent of the surface MainNet refusal which is unchanged by Run 167. The peer-driven drain `RequiredButMissing` scenario remains not directly representable through `target/release/qbind-node` today (changing the peer-candidate-envelope schema would violate Run 167's strict scope) and is deferred to Run 168 along with the rest of release-binary proof-carrying enforcement evidence. The Run 167 tests (`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`, 47 passing) cover the full A1–A9 / R1–R21 accept/reject matrix at source/test level — including A9 valid proof-carrying sidecar reaches peer-driven drain `ProductionV2MarkerCoordinator` source path (the same gate composition used by every other production preflight surface). Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_167.md`.
## Run 168 — release-binary evidence for the Run 167 governance-proof carrier; safety contract unchanged

Run 168 is the release-binary partner of Run 167 and does **not** modify the Run 144 safety contract, the six-phase fail-closed pipeline, the Run 070 apply ordering (`validate → snapshot → swap → evict_sessions → commit_sequence`), the post-Run-055 marker-write boundary, or the peer-driven drain `ProductionV2MarkerCoordinator` runtime behaviour. The four production marker-decision callers (`pqc_live_trust_reload.rs` SIGHUP, `pqc_peer_candidate_apply.rs` peer-driven drain, `main.rs` reload-apply preflight, `main.rs` startup `--p2p-trust-bundle` preflight) continue to invoke `decide_v2_marker_acceptance_with_lifecycle_and_governance` at `policy=GovernanceProofPolicy::NotRequired` + `context=GovernanceProofContext::Unavailable`, exactly as Run 166 evidenced — wiring them to consume the Run 167 typed loader is **explicitly deferred** to a follow-up wiring run. Run 168 captures release-binary evidence on every surface that is reachable through `target/release/qbind-node` today: (i) source-level grep proof that the Run 167 carrier (`pqc_governance_proof_wire`, `GovernanceAuthorityProofWire`, `GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION = 1`) and typed loader (`load_v2_ratification_sidecar_with_governance_proof_from_path`, `GovernanceProofLoadStatus::{Absent, Available, Malformed}`) live in production source under `crates/qbind-node/src/`; (ii) the strict back-compat path on real `target/release/qbind-node` — pre-Run-167 v2 sidecars without the `governance_authority_proof` sibling continue to parse and apply bit-for-bit on reload-check / reload-apply (`A1` / `A2`); (iii) the typed-loader Absent / Available / Malformed matrix and the Run 165 governance gate's `RequiredButMissing` / `Rejected` semantics on a release-built helper (`crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`, scenarios `H1–H13`) that links the same production helper symbols the release node links; (iv) the unconditional MainNet peer-driven-apply refusal banner is still emitted on real `target/release/qbind-node` even with a structurally valid proof carrier — gate acceptance is independent of the surface MainNet refusal. Parsing the wire carrier still performs **no marker write, no sequence write, no live trust swap, no session eviction**. Run 168 introduces no production runtime source change, no CLI flag, no environment variable, no marker / sequence / trust-bundle / peer-candidate-envelope schema change, no new metric family, and no MainNet enablement. Tests: the Run 167 source/test suite (`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`, 47 passing) plus the existing Run 165 / 163 / 161 / 159 / 152 / 150 / 148 / 142 / 138 / 134 regressions all remain green on the same checkout. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_168.md`, `docs/devnet/run_168_governance_proof_carrier_release_binary/`.
## Run 169 — Governance-proof loader wired into the peer-driven coordinator (source/test)

Run 169 is source/test only. It wires the Run 167 typed governance-proof loader through the production v2 marker-decision callers, including the peer-driven coordinator, by introducing a single library shim `qbind_node::pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` that maps `GovernanceProofLoadStatus::{Absent, Available, Malformed}` to `GovernanceProofContext` and delegates to the Run 165 governance-aware helper. The six-phase fail-closed pipeline (validate → classify → marker-decision → sequence-commit → apply → ack) is unchanged. Inside the marker-decision phase, `ProductionV2MarkerCoordinator` now carries `governance_proof_load: GovernanceProofLoadStatus` and `governance_policy: GovernanceProofPolicy` (defaults `Absent` / `NotRequired`, preserving Runs 148 / 150 / 152 semantics bit-for-bit) and exposes `with_governance_proof_carrier(load, policy)` as the additive setter. `decide_pre_apply` routes through the shim, and any governance rejection short-circuits the pipeline before sequence commit and before any Run 070 apply, with no marker / sequence / live-trust mutation. MainNet peer-driven apply remains refused unconditionally regardless of any proof carrier. Per-peer envelopes are unchanged; lifting the live inbound `0x05` path to `RequiredForLifecycleSensitive` would require a peer-candidate envelope schema extension that is explicitly out of scope. Standing invariants (unchanged): no autonomous apply, no automatic apply on receipt, no peer-majority authority, no on-chain governance, no KMS/HSM, no validator-set rotation, no static production MainNet anchor, no schema drift. Release-binary production-surface proof-carrying evidence is deferred to Run 170. C4 / C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_169.md`.

## Run 170 — release-binary EVIDENCE for the Run 169 production-surface governance-proof loader wiring; safety contract unchanged

Run 170 captures release-binary evidence for the Run 169 wiring of the Run 167 typed governance-proof loader into the peer-driven trust-bundle apply coordinator (`crates/qbind-node/src/pqc_peer_candidate_apply.rs`) through the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`. Source-level reachability is recorded under `reachability/src_grep.txt` showing the shim is referenced from the peer-driven coordinator (and from each of the other three production preflight call sites). The peer-driven coordinator's safety contract is unchanged: same Run 070 reload-apply ordering, same Run 055 sequence-before-marker invariant, same MainNet refusal owned by Run 130 (`R20` regression on real `target/release/qbind-node` re-asserted), same drain-then-apply discipline (Run 152), same forced-validation-only on receipt (Run 148 / Run 150), same per-peer envelope schema (Run 142), and same default `GovernanceProofPolicy::NotRequired` so existing no-proof v2 sidecars continue to be accepted exactly as before (`A1` / `A2` end-to-end on real `target/release/qbind-node`). Required-policy proof-carrying matrix is evidenced through the Run 168 release-built helper replay against the current checkout (`H1`–`H13` covering accept, idempotent re-accept, and the typed reject set including `WrongAuthorityRoot`, `WrongLifecycleAction`, `WrongCandidateDigest`, `WrongAuthoritySequence`, `InvalidIssuerSignature`, `UnsupportedOnChainGovernance`, `EmptyIssuerSignature` → `Malformed` → `Unavailable`) and through the Run 169 production-surface integration suite (39 tests). Honest limitation: lifting the release-binary CLI to expose a configurable `RequiredForLifecycleSensitive` toggle is operator-control plumbing intentionally NOT in Run 170 scope and is deferred; per-peer envelopes are unchanged and continue not to carry the governance-proof sibling, so lifting the live inbound `0x05` path to `RequiredForLifecycleSensitive` would still require a peer-candidate envelope schema extension that remains explicitly out of scope. Standing invariants (unchanged): no autonomous apply, no automatic apply on receipt, no peer-majority authority, no on-chain governance, no KMS/HSM, no validator-set rotation, no static production MainNet anchor, no schema drift. C4 / C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_170.md`.
## Run 171 — source/test hidden Required-policy operator selector wiring; safety contract unchanged

Run 171 completes the operator-control plumbing that Run 170 declared as a deferred honest limitation, at the **source/test level only**, and does not change the peer-driven apply safety contract. It adds a hidden, disabled-by-default selector for `GovernanceProofPolicy::RequiredForLifecycleSensitive`: a CLI flag `--p2p-trust-bundle-governance-proof-required` (declared with `clap` `hide = true`, absent from `--help`) OR-combined with the environment variable `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED` (truthy values `1` / `true` / `yes` / `on`). The resolved policy (via `governance_proof_policy_from_cli_or_env` in `crates/qbind-node/src/pqc_governance_proof_surface.rs`) is threaded through the Run 169 shim `pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load` into the peer-driven `ProductionV2MarkerCoordinator` (and the other production preflight contexts). The peer-driven coordinator's safety contract is unchanged: same Run 070 reload-apply ordering, same Run 055 sequence-before-marker invariant, same drain-then-apply discipline (Run 152), same forced-validation-only on receipt (Run 148 / Run 150), same per-peer envelope schema (Run 142, which continues not to carry the governance-proof sibling), and the same **MainNet refusal owned by Run 130 — MainNet peer-driven apply remains refused even with the Required selector enabled and a valid proof present**. **The operator default remains `GovernanceProofPolicy::NotRequired`**, so existing no-proof v2 sidecars continue to be accepted exactly as before; the Required selector is hidden and explicit. Under Required at the source/test level, valid proof-carrying sidecars pass and missing / invalid proofs fail closed, with validation-only surfaces remaining non-mutating and mutating surfaces persisting the marker only after the sequence-commit boundary. Honest limitation: Run 171 is source/test only; release-binary Required-policy production-surface evidence is **deferred to Run 172**; per-peer envelopes are unchanged and continue not to carry the governance-proof sibling, so lifting the live inbound path to `RequiredForLifecycleSensitive` would still require a peer-candidate envelope schema extension that remains explicitly out of scope. Standing invariants (unchanged): no autonomous apply, no automatic apply on receipt, no peer-majority authority, no governance execution, no on-chain governance (`OnChainGovernance` fail-closed), no KMS/HSM, no validator-set rotation, no static production MainNet anchor, no schema drift. Full C4 and C5 remain open. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_171.md`.
Run 172 — release-binary EVIDENCE for the Run 171 hidden Required-policy selector on real `target/release/qbind-node`. The Run 144 safety contract and six-phase fail-closed pipeline are unchanged. The peer-driven `ProductionV2MarkerCoordinator` continues to route through the governance-aware shared helper `preflight_v2_marker_decision_with_governance_proof_load` with policy resolved from `governance_proof_policy_from_cli_or_env(args.p2p_trust_bundle_governance_proof_required)`; under the default `NotRequired` policy and `Unavailable` context (no proof sibling) behaviour is bit-for-bit identical to Run 165 / 166 / 168 / 170 / 171; when the operator opts in to the Required selector and a missing-proof Rotate sidecar is presented, the coordinator preflight refuses with the typed `MutatingSurfaceMarkerV2Error::GovernanceAuthorityRequiredButMissing { action: Rotate }`, the peer-candidate apply is **not** invoked, no live trust mutation occurs, no session eviction occurs, no sequence is written, and no marker is persisted. MainNet peer-driven apply remains refused unconditionally under the Run 147 FATAL invariant even when the selector is enabled and a valid proof is supplied (R23). The Run 144 schema is unchanged: peer-candidate envelopes do NOT carry a `GovernanceAuthorityProof` field; the proof material continues to be loaded from the operator-supplied v2 ratification sidecar via `--p2p-trust-bundle-ratification` and the loader `load_versioned_ratification_with_governance_proof_from_path`. No autonomous apply, no apply on receipt, no peer-majority authority, no governance execution, no on-chain governance, no KMS/HSM, no validator-set rotation. Honest limitation: validation-only `--p2p-trust-bundle-peer-candidate-check` parses the proof sibling but does not gate on Required policy; the rejection branch on validation-only peer-candidate-check is exercised at symbol level by Run 168 and at source-test level by Run 169/171. Release-binary boundary evidence: `docs/devnet/run_172_governance_required_policy_release_binary/`. Canonical evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_172.md`.
Run 173 — source/test wiring of the Run 171 governance-proof Required-policy selector into validation-only v2 surfaces. The peer-driven apply safety contract (Run 144 / Run 148–152 / Run 165 / Run 169 / Run 171 / Run 172) is unchanged. The peer-driven `ProductionV2MarkerCoordinator` continues to route through `preflight_v2_marker_decision_with_governance_proof_load` with the policy resolved via `governance_proof_policy_from_cli_or_env`. Run 173 adds a sibling validation-only shim `preflight_v2_validation_only_marker_check_with_governance_proof_load` (in `crates/qbind-node/src/pqc_governance_proof_surface.rs`) that delegates to the same Run 169 mutating shim — there is **no second selector path and no second gate path**. The new shim is consumed by `preflight_run_132_validation_only_v2_marker_check` in `crates/qbind-node/src/main.rs`, which is shared by the validation-only `--p2p-trust-bundle-reload-check` path and the local `--p2p-trust-bundle-peer-candidate-check` path. Under default `NotRequired` and `Unavailable` proof context (no proof sibling), behaviour is bit-for-bit identical to Run 165 / 166 / 168 / 170 / 171 / 172. With the Required selector enabled (CLI or env), validation-only preflights refuse missing-proof Rotate sidecars with `GovernanceAuthorityRequiredButMissing { action: Rotate }`, refuse invalid-proof sidecars with `GovernanceAuthorityRejected(...)`, and continue to be strictly non-mutating: no live trust mutation, no session eviction, no sequence write, no marker persist, no Run 070 invocation. **MainNet peer-driven apply remains refused unconditionally** under Run 147 even when the Required selector is enabled and a valid proof is supplied; the validation-only acceptance does not unlock the MainNet refusal. The Run 144 peer-candidate envelope schema is unchanged: peer-candidate envelopes do NOT carry a `GovernanceAuthorityProof` field, so the live inbound `0x05` validation surface (`pqc_peer_candidate_wire`) cannot yet supply a typed `GovernanceProofLoadStatus`; this exact boundary is documented and **deferred** because the Run 173 task explicitly forbids peer-candidate envelope schema changes. No autonomous apply, no apply on receipt, no peer-majority authority, no governance execution, no on-chain governance, no KMS/HSM, no validator-set rotation. **Release-binary validation-only Required-policy production-surface evidence is deferred to Run 174.** Canonical evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_173.md`.
Run 174 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the validation-only v2 marker-decision production surfaces on real `target/release/qbind-node`. The peer-driven apply safety contract (Run 144 / Run 148–152 / Run 165 / Run 167 / Run 169 / Run 171 / Run 172 / Run 173) is unchanged: peer-driven apply on MainNet remains refused under the Run 147 FATAL invariant even when `--p2p-trust-bundle-peer-candidate-staging-enabled` is set together with `--p2p-trust-bundle-governance-proof-required` and a valid proof-carrying Rotate@seq=2 sidecar (Run 174 scenario R20 demonstrated on real `target/release/qbind-node`); validation-only `--p2p-trust-bundle-reload-check` performs no live trust mutation, no `LivePqcTrustState` write, no session eviction, no Run 070 apply, no `[run-134] reload-apply v2 ratification path SELECTED` line, no `[run-134] v2 authority-marker persisted` line, no authority-marker write, and no persisted lifecycle-sequence write under any Run 174 scenario (A1 / A2 / A3 / A6a / A6b accepts; R1–R12 / R-extra / R19 rejects), as enforced by the harness `assert_no_mutation` helper that verifies marker SHA pre==post, no sequence file post, no Run 070 line, no Run 134 lines, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead`. Local peer majority remains insufficient as bundle-signing authority. Local config alone remains insufficient as bundle-signing authority. Static production source-code anchors remain rejected. Default policy (`NotRequired`) preserves Run 144 / Run 148–152 / Run 165 compatibility — old no-proof Ratify@seq=1 and no-proof Rotate@seq=2 sidecars are accepted on validation-only reload-check exactly as before, with `governance policy=NotRequired` logged (Run 174 A1 / A6a / A6b / R19). Under selector enabled, validation-only `--p2p-trust-bundle-reload-check` accepts a valid GenesisBound proof-carrying Rotate sidecar with `governance policy=RequiredForLifecycleSensitive` (A2 / A3) and refuses every Required-policy violation with the typed `Run 165: v2 authority-marker ...` Display inside `[binary] Run 132: VERDICT=invalid` (R1–R12 / R-extra). The `OnChainGovernance` proof variant remains unsupported / fail-closed on the validation-only surface (Run 174 R12). The selector is hidden (`hide = true`) and does not appear in `--help`. **Honest limitations preserved (Run 174 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling — live `0x05` proof-carrying remains OPEN, and lifting it requires a peer-candidate envelope schema change explicitly forbidden by `task/RUN_174_TASK.txt`; (ii) local `--p2p-trust-bundle-peer-candidate-check` release-binary scenarios (A4 / A5 / R15 / R16) are deferred because the Run 172 fixture helper does not mint a peer-candidate envelope — the validation-only peer-candidate-check production surface shares `preflight_run_132_validation_only_v2_marker_check` with reload-check by construction (Run 173 wiring), so policy resolution and the gate composition are identical, and the Run 173 source-test integration suite covers both call sites at source level; (iii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first, masking the governance-gate refusal — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper, mirroring the Run 172 deferral pattern. The release-binary harness is `scripts/devnet/run_174_validation_only_governance_required_policy_release_binary.sh`. The curated evidence archive is `docs/devnet/run_174_validation_only_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked). Run 174 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, and no MainNet enablement. No Run 050–173 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_174.md`.
Run 175 — release-binary EVIDENCE for the Run 173 source/test wiring of the hidden Run 171 governance-proof Required-policy selector (`--p2p-trust-bundle-governance-proof-required` / `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy `1|true|yes|on`) into the LOCAL `--p2p-trust-bundle-peer-candidate-check` validation-only v2 marker-decision production surface on real `target/release/qbind-node`. The peer-driven apply safety contract (Run 144 / Run 148–152 / Run 165 / Run 167 / Run 169 / Run 171 / Run 172 / Run 173 / Run 174) is unchanged: peer-driven apply on MainNet remains refused under the Run 147 FATAL invariant even when `--p2p-trust-bundle-peer-candidate-staging-enabled` is set together with `--p2p-trust-bundle-governance-proof-required`, a valid proof-carrying Rotate@seq=2 sidecar, AND a valid local peer-candidate envelope (Run 175 scenario R18 demonstrated on real `target/release/qbind-node`); the local `--p2p-trust-bundle-peer-candidate-check` surface (Run 077 / Run 107 envelope path → Run 132 preflight) performs no live trust mutation, no `LivePqcTrustState` write, no session eviction, no Run 070 apply, no `[run-134] reload-apply v2 ratification path SELECTED` line, no `[run-134] v2 authority-marker persisted` line, no authority-marker write, and no persisted lifecycle-sequence write under any Run 175 scenario (A1 / A2 / A3 / A4a / A4b / A5 accepts; R1–R12 / R-extra / R17 rejects), as enforced by the harness `assert_no_mutation` helper that verifies marker SHA pre==post, no sequence file post, no Run 070 line, no Run 134 lines, no `.tmp` residue under `pqc_authority_state.json` / `pqc_trust_bundle_sequence.json`, no fallback to `--p2p-trusted-root`, and no active `DummySig` / `DummyKem` / `DummyAead`. The `consensus/` RocksDB sub-dir and the `run077-peer-candidate-scratch/` directory in the per-scenario data-dir are expected and benign (Run 098 ConsensusStorage open for activation epoch read + Run 077 scratch tempfile parent) and do NOT constitute marker or sequence persistence. Local peer majority remains insufficient as bundle-signing authority. Local config alone remains insufficient as bundle-signing authority. Static production source-code anchors remain rejected. Default policy (`NotRequired`) preserves Run 144 / Run 148–152 / Run 165 / Run 174 compatibility — old no-proof Ratify@seq=1 and no-proof Rotate@seq=2 sidecars are accepted on local peer-candidate-check exactly as before, with `governance policy=NotRequired` logged (Run 175 A1 / A4a / A4b / R17). Under selector enabled, local peer-candidate-check accepts a valid GenesisBound proof-carrying Rotate sidecar with `governance policy=RequiredForLifecycleSensitive` (A2 / A3 / A5) and refuses every Required-policy violation with the typed `Run 165: v2 authority-marker ...` Display inside `[binary] Run 132: VERDICT=invalid` (R1–R12 / R-extra). The `OnChainGovernance` proof variant remains unsupported / fail-closed on the local peer-candidate-check validation-only surface (Run 175 R12). The selector is hidden (`hide = true`) and does not appear in `--help`. **Honest limitations preserved (Run 175 does NOT close them):** (i) live inbound `0x05` peer-candidate envelopes still do not carry a `governance_authority_proof` sibling — live `0x05` proof-carrying remains OPEN, and lifting it requires a peer-candidate envelope schema change explicitly forbidden by `task/RUN_175_TASK.txt`; (ii) R5 / R6 / R7 (wrong-environment / wrong-chain / wrong-genesis) cannot be expressed as static fixtures consumable by the binary because the Run 130 v2 ratification verifier upstream trips first, masking the governance-gate refusal — covered at source level by the Run 173 integration tests and at symbol level by the Run 168 release-built helper, mirroring the Run 174 / Run 172 deferral pattern. The release-binary harness is `scripts/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary.sh`. The new release-built fixture helper `crates/qbind-node/examples/run_175_peer_candidate_check_governance_required_policy_release_binary_helper.rs` mints the Run 172-shape ratification corpus PLUS Run 076-schema PeerCandidateEnvelope JSONs wrapping the existing candidate trust bundles. The curated evidence archive is `docs/devnet/run_175_peer_candidate_check_governance_required_policy_release_binary/` (only README + summary + .gitignore tracked). Run 175 introduces no production runtime source change, no CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, and no MainNet enablement. No Run 050–174 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_175.md`.
Run 176 — source/test governance-proof carrying for live inbound `0x05` peer-candidate envelopes. The live `0x05` `PeerCandidateWireEnvelopeV1` gains an additive optional `governance_authority_proof` field (`#[serde(default, skip_serializing_if = "Option::is_none")]`) plus a `governance_proof_load_status()` helper, and a new validation-only library shim (`preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier`) that routes the in-band carrier into the same Run 165 / 163 / 167 governance composition as the Run 167 sidecar loader by delegating to the Run 173 validation-only shim. The in-band carrier complements (does not replace) the sidecar loader. Old `0x05` envelopes parse byte-for-byte and the no-proof JSON layout is unchanged. Required policy still fails closed when no proof is carried (Absent → RequiredButMissing); malformed in-band carriers are rejected the same way as malformed sidecars (Malformed → Unavailable → RequiredButMissing); valid proofs reach the Run 165 gate; invalid proofs fail closed without propagating, staging, or applying. MainNet peer-driven apply remains refused unconditionally. Source/test only — release-binary evidence is deferred to Run 177. No CLI flag added or renamed, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, and no MainNet enablement. No Run 050–175 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_176.md`.
Run 177 — release-binary live inbound `0x05` governance-proof carrier evidence. Run 177 closes the Run 176-deferred release-binary boundary by exercising on real `target/release/qbind-node` nodes (real DevNet N=3 V0/V1/V2 topology, real live P2P) live inbound `0x05` peer-candidate envelopes carrying the additive Run 176 `governance_authority_proof` field under `RequiredForLifecycleSensitive`. The Run 177 invariants on top of Run 176: (i) **no apply on receipt** — across every A* and R* scenario V1's `pqc_authority_state.json` SHA-256 is unchanged pre/post and V1's `pqc_trust_bundle_sequence.json` is not written; V1's stderr is asserted clean of `Run 070: trust-bundle candidate APPLIED`, `[run-134] reload-apply v2 ratification path SELECTED`, `[run-134] v2 authority-marker persisted`, and `sequence_commit=ok` (R21). (ii) **no propagation of invalid carriers** — V2 (the propagation observer) log is asserted clean of `[run-088] propagation REBROADCAST` for every R* scenario (R18). (iii) **no staging / no drain** — no node in the matrix is invoked with `--p2p-trust-bundle-peer-candidate-staging-enabled` or `--p2p-trust-bundle-peer-candidate-drain-once`, so R19 / R20 hold by construction across the validation-only matrix. (iv) **MainNet peer-driven apply refused** — even with Required + valid proof + valid candidate + wire-attached carrier, MainNet startup fails closed (Run 147 FATAL; R22). The release-binary boundary is reached via a tiny harness-only source delta — a hidden CLI flag `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path` (clap `hide=true`) that injects a `GovernanceAuthorityProofWire` JSON into `wire_envelope.governance_authority_proof` immediately before `encode_peer_candidate_wire_frame`. Default behaviour is unchanged. No CLI flag added or renamed in the supported operator surface, no environment variable added, no SIGHUP / startup-trust-bundle / live `0x05` / drain-once / peer-driven apply / peer-candidate-check / reload-check / reload-apply signature change, no schema change, no new metric family, no MainNet enablement. No Run 050–176 invariant was changed. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md`, `docs/devnet/run_177_live_0x05_governance_proof_release_binary/`.
Run 178 — source/test-only typed `OnChainGovernance` proof format and fail-closed verifier boundary. The new module `crates/qbind-node/src/pqc_onchain_governance_proof.rs` defines `OnChainGovernanceProof`, `OnChainGovernanceProofPolicy::{Disabled (default), AllowFixtureSourceTest}`, the typed verifier outcome surface (including `AcceptedOnChainGovernanceFixture`, `UnsupportedProductionOnChainGovernance`, `MainNetProductionProofUnavailable`, `WrongGovernanceDomain`, `WrongProposalDigest`, `WrongProposalOutcome`, `WrongGovernanceEpoch`, `ExpiredGovernanceProof`, `ReplayRejected`, `QuorumNotMet`, `ThresholdNotMet`, `InvalidGovernanceProof`, `UnsupportedGovernanceProofSuite`, `MalformedOnChainProof`, `LocalOperatorConfigOnlyRejected`, `PeerMajorityProofRejected`), the pure non-mutating verifier `verify_onchain_governance_proof`, the combined lifecycle helper `validate_lifecycle_with_onchain_governance_proof`, and the additive optional `OnChainGovernanceProofWire` (schema version 1) carrier. Apply-safety relevant invariants preserved by Run 178: (i) the Run 147 FATAL MainNet peer-driven apply refusal remains unconditional — even a fully-valid Run 178 DevNet/TestNet fixture proof cannot enable a MainNet apply (the typed assertion `mainnet_peer_driven_apply_remains_refused` returns `true` for `Mainnet` regardless of acceptance); (ii) Run 178 introduces no production source caller of `verify_onchain_governance_proof` — the Run 167 / 169 / 171 / 173 / 176 / 177 production marker-decision surfaces continue to compose the Run 163 governance verifier through the Run 165 governance gate, with the Run 163 `OnChainGovernance` class still returning `UnsupportedOnChainGovernance` (Run 178 A7 regression); (iii) the v2 ratification, authority-marker, sequence-file, trust-bundle core, and peer-candidate-envelope schemas are all unchanged — the `OnChainGovernanceProofWire` is an additive optional sibling on the existing Run 167 sidecar JSON, and old sidecars without it parse exactly as before (R24); (iv) local operator config alone and peer-majority / gossip count are both refused as `OnChainGovernance` proofs by construction (default `Disabled` policy refuses everything; under `AllowFixtureSourceTest` the canonical proof_bytes commitment cannot be forged from operator config or peer-gossip inputs and any such "proof" surfaces as `InvalidGovernanceProof`); (v) the pure verifier performs no I/O, mutates no inputs, never extends the replay set, never writes a marker, never writes a sequence, and never invokes Run 070 apply. Release-binary `OnChainGovernance` proof evidence is deferred to Run 179. KMS / HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`.
Run 179 — release-binary `OnChainGovernance` proof boundary evidence for the Run 178 typed verifier. Run 179 captures release-binary fixture/boundary evidence for Run 178 by exercising the full A1–A7 / R1–R25 verifier corpus (incl. sub-variants) end-to-end in release mode through the production library symbols (`verify_onchain_governance_proof`, `validate_lifecycle_with_onchain_governance_proof`, `OnChainGovernanceProofWire`) and by capturing real `target/release/qbind-node --help` provenance. Apply-safety relevant invariants preserved by Run 179: (i) Run 147 FATAL MainNet peer-driven apply refusal remains unconditional in release mode — the helper's R23 scenario asserts `mainnet_peer_driven_apply_remains_refused` returns `true` for `Mainnet` even when the most permissive Run 178 policy (`OnChainGovernanceProofPolicy::AllowFixtureSourceTest`) is active and a fully-valid DevNet/TestNet fixture proof is supplied; (ii) Run 179 adds **no production source change**, **no CLI flag**, **no env knob**, and **no production caller** of any Run 178 verifier symbol — the harness records on every invocation a source-reachability proof showing `verify_onchain_governance_proof`, `validate_lifecycle_with_onchain_governance_proof`, `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`, and `OnChainGovernanceProofWire` have zero production callers under `crates/qbind-node/src/` outside the defining module, so the existing Run 167 / 169 / 171 / 173 / 176 / 177 production marker-decision surfaces remain composed exclusively on the Run 163 governance verifier through the Run 165 governance gate, with the Run 163 `OnChainGovernance` class still returning `UnsupportedOnChainGovernance`; (iii) the v2 ratification, authority-marker, sequence-file, trust-bundle core, and peer-candidate-envelope schemas are unchanged — Run 179 introduces no new schema / wire / metric drift beyond the Run 178 additive `OnChainGovernanceProofWire` shape (R24 + R24b round-trip in release mode; old Run 167 sidecars without the sibling continue to parse exactly as before); (iv) local operator config alone and peer-majority / gossip count remain refused as `OnChainGovernance` proofs in release mode by construction (the helper's R17c / R17d / R20-class scenarios all resolve to `InvalidGovernanceProof` or `UnsupportedProductionOnChainGovernance`); (v) the helper performs no I/O on the production state, mutates no `LivePqcTrustState`, never extends the production replay set, never writes a marker, never writes a sequence, and never invokes Run 070 apply — it writes only into the gitignored `helper_evidence/` corpus under `OUTDIR`; (vi) the harness denylist explicitly proves empty across every captured log: no `apply on receipt`, no `peer-majority authority`, no `fallback to --p2p-trusted-root`, no `DummySig` / `DummyKem` / `DummyAead`, no `MainNet peer-driven apply ENABLED`. The verdict is honestly recorded as `partial-positive: release-binary fixture/boundary evidence captured; OnChainGovernance verifier not yet production-surface reachable`. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, and real on-chain proof verification all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md`.
Run 180 — source/test-only wiring of the Run 178 typed `OnChainGovernance` proof verifier into production marker-decision composition behind a hidden DevNet/TestNet-only `AllowFixtureSourceTest` selector. Apply-safety relevant invariants preserved by Run 180: (i) **Run 147 FATAL MainNet peer-driven apply refusal remains unconditional.** The Run 180 shared composed helper `compose_onchain_governance_marker_decision` short-circuits with `OnChainGovernanceMarkerDecisionOutcome::MainNetRefused` whenever any of the proof, the trust-bundle environment domain, or the candidate v2 record advertises `TrustBundleEnvironment::Mainnet` — regardless of whether `OnChainGovernanceProofPolicy::AllowFixtureSourceTest` is armed and regardless of whether a fully-valid DevNet/TestNet fixture proof would otherwise be accepted (Run 180 R3 asserts this in the integration test matrix). (ii) **The production default policy is `Disabled` on every surface.** When neither the hidden CLI flag `--p2p-trust-bundle-onchain-governance-fixture-allowed` nor the environment variable `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` is supplied, every per-surface wrapper (`reload_check_` / `reload_apply_` / `startup_p2p_trust_bundle_` / `sighup_` / `local_peer_candidate_check_` / `live_inbound_0x05_` / `peer_driven_drain_compose_onchain_governance_marker_decision`) short-circuits with `PolicyDisabled` before any verifier work runs (Run 180 R1 / R2 / A1 assert this). (iii) **Run 180 is composition-only.** The seven named wrappers and the shared composed helper perform no I/O on production state, mutate no `LivePqcTrustState`, never extend the production replay set, never write a marker, never write a sequence, never invoke Run 070 apply, and never autonomously apply a peer-driven trust bundle on receipt. Mutating apply remains exclusively Run 070 under Run 094 / Run 142 fail-closed gates; the Run 180 outcome is consumed only at the validation/composition layer, exactly like Run 171 / 173 / 176 / 177 governance-gate composition for the Run 163 verifier. (iv) **Local operator config alone and peer-majority / gossip count remain refused as `OnChainGovernance` proofs.** Run 180 does not introduce a new authority class — it wires the existing Run 178 typed verifier (which itself never accepts local-operator-config-alone or peer-majority as governance evidence) — and the Run 180 R21 / R22 tests assert this at the composition layer. (v) **No schema / wire / metric / exit-code drift.** Run 180 introduces no new wire field, enum variant, schema bump, metric, or exit code beyond the Run 178 additive `OnChainGovernanceProofWire` shape (which Run 180 does not modify); the v2 ratification, authority-marker, sequence-file, trust-bundle core, and peer-candidate-envelope schemas are unchanged. (vi) **The Run 180 selector flag is `hide = true`.** It is not surfaced in `target/release/qbind-node --help`; operators cannot accidentally enable it from the production help surface. (vii) **The release-binary boundary for the Run 180 wiring is deferred to Run 181.** Run 180's verdict is honestly recorded as `partial-positive: source/test reachability captured; release-binary boundary deferred to Run 181`. KMS/HSM custody, governance execution, validator-set rotation, bridge / light-client integration, real on-chain proof verification on MainNet, autonomous apply, apply-on-receipt, and peer-majority authority all remain unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`.
Run 181 — release-binary `OnChainGovernance` production-surface fixture-policy selector evidence and re-assertion of the Run 147 MainNet peer-driven apply FATAL invariant under armed selector. Run 181 captures release-binary evidence on real `target/release/qbind-node` that the hidden Run 180 selector (`--p2p-trust-bundle-onchain-governance-fixture-allowed` CLI flag, `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` environment variable, OR-combined via `onchain_governance_proof_policy_from_cli_or_env`) is observable from the production binary's startup banner exactly when armed; that the production default — neither source truthy — preserves `OnChainGovernanceProofPolicy::Disabled` on every peer-driven apply surface; and that even with the selector engaged and `--network mainnet`, the real binary refuses MainNet peer-driven apply (R23: no `MainNet peer-driven apply ENABLED` token in any captured log). For peer-driven apply specifically, Run 181 records that the seven Run 180 per-surface named wrappers — including the `peer_driven_drain_compose_onchain_governance_marker_decision` wrapper that maps onto the Run 150 peer-driven apply drain coordinator preflight — are linked into the production `qbind-node` binary's library and exercised in release mode by the release-built helper across A1–A8 / R1–R26. The wrappers are pure / non-mutating: they perform no I/O, write no marker, write no sequence, mutate no live trust state, evict no sessions, and never invoke Run 070, so peer-driven drain coordinator preflight remains compatible with the existing `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary` sequence-before-marker ordering (Runs 134 / 138 / 142 / 148 / 150 / 152 invariants). Honest limitation: Run 180's binary-side wiring stops at the selector-capture / banner-emission site in `main.rs`; the binary's `--p2p-trust-bundle-*` marker-decision call sites do not yet pass the resolved `OnChainGovernanceProofPolicy` into the per-surface wrappers, so a real peer-driven apply drain executed by `target/release/qbind-node` today does NOT itself reach `compose_onchain_governance_marker_decision` — the existing peer-driven apply safety surface (Run 147 FATAL refusal on MainNet, Run 148 environment gates, Run 150 drain coordinator, Run 152 binary-reachable drain plumbing) remains in effect byte-for-byte. The strict next-after-Run-181 integration run will wire the resolved policy into the drain coordinator preflight call site and capture mutating-scenario marker / sequence JSON+SHA before / after under DevNet / TestNet only. Run 181 verdict is honestly recorded as `partial-positive: production-surface SELECTOR reachability captured on real qbind-node; per-surface wrappers exercised in-process via release-built helper; binary-side wrapper wiring deferred`. No production source change. No MainNet apply enablement. No autonomous apply / apply-on-receipt / peer-majority authority. No real on-chain governance execution, no real on-chain proof verifier, no bridge / light-client integration, no KMS / HSM custody, no validator-set rotation. No marker / sequence-file / trust-bundle / wire / metric drift. No DummySig / DummyKem / DummyAead activation, no fallback to `--p2p-trusted-root`. governance execution remains unimplemented, real on-chain proof verification remains unimplemented. Full C4 / C5 remain OPEN. Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`.Run 182 — source/test production call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers, with explicit re-assertion of the Run 147/148/152 MainNet peer-driven apply FATAL invariant under the wired peer-driven drain entry. For peer-driven trust-bundle apply specifically, Run 182 wires `peer_driven_drain_callsite_onchain_governance_marker_decision` into `ProductionV2MarkerCoordinator::decide_pre_apply` in `crates/qbind-node/src/pqc_peer_candidate_apply.rs` (the `Ok(decision)` arm, after the existing Run 169 governance-proof surface shim has produced an accepted v2 marker decision). The peer-driven-drain wiring entry layers a surface-level MainNet refusal **before** invoking the underlying verifier — agreeing with the Run 147 startup environment gate, the Run 148 environment gates upstream of the drain coordinator, and the Run 178 verifier's own `MainNetProductionProofUnavailable` return. The three layers do not weaken each other: any one of them is sufficient to refuse MainNet peer-driven apply. Run 182's `r3_mainnet_peer_driven_drain_refuses_with_valid_proof` and `r3b_mainnet_peer_driven_drain_refuses_with_no_proof` integration tests confirm the surface-level layer fires unconditionally on a MainNet candidate / domain regardless of the proof carrier or selector state. The peer-driven-drain wiring entry is pure / non-mutating: it borrows the accepted `MarkerAcceptDecisionV2`, constructs a typed `OnChainGovernanceCallsiteContext { proof: None, ... }`, invokes the Run 180 wrapper, and drops the result. The Run 152 sequence-before-marker ordering (`commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`) is untouched: the wiring entry runs at preflight time, before any sequence write, before any marker write, before any live trust swap, before any session eviction, and before any Run 070 invocation. Honest limitation recorded: no peer-candidate envelope today carries a typed `OnChainGovernanceProof`; the wiring is invoked with `proof: None` at the production drain coordinator surface, and the Run 180 wrapper returns `PolicyDisabled` under the default policy or `NoOnChainGovernanceProofSupplied` when the selector is armed. The Run 152 binary-reachable peer-drain plumbing is therefore preserved bit-for-bit; the wiring exists to make the OnChainGovernance reachability claim true at the production source level. Run 182 introduces no new wire field, no new sidecar field, no new schema bump, no new metric, and no new exit code. Run 182 is source/test production call-site wiring for OnChainGovernance fixture proofs. Default remains `OnChainGovernanceProofPolicy::Disabled`. `AllowFixtureSourceTest` is hidden, explicit, and DevNet/TestNet fixture-only. Production MainNet OnChainGovernance remains unsupported / fail-closed. MainNet peer-driven apply remains refused. Real on-chain governance proof verification remains unimplemented. Governance execution remains unimplemented. KMS/HSM remains unimplemented. Validator-set rotation remains open. **Release-binary OnChainGovernance peer-driven-drain production-surface evidence is deferred to Run 183. Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`.Run 183 — release-binary evidence for the Run 182 production v2 marker-decision call-site wiring of the Run 180 per-surface OnChainGovernance preflight wrappers, including the peer-driven-drain production call site at `pqc_peer_candidate_apply.rs::ProductionV2MarkerCoordinator::decide_pre_apply`. Run 183 captures real `target/release/qbind-node` evidence that the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal invariant survives unchanged with the hidden Run 180 selector armed: under `--network mainnet` with the CLI flag and env var both engaged the binary emits no `MainNet peer-driven apply ENABLED` token, and the Run 182 `peer_driven_drain_callsite_onchain_governance_marker_decision` entry's surface-level `MainNetRefused` short-circuit fires before the Run 180 verifier is invoked. Through the release-built helper, every accepted DevNet / TestNet peer-driven-drain fixture Rotate proof acceptance scenario asserts that selector activation occurs before proof parse, proof parse occurs before marker decision, OnChainGovernance fixture verification occurs before any apply / mutation could occur, and lifecycle validation occurs before any apply / mutation could occur; the underlying Run 070 mutating apply gate, Run 094 / 142 fail-closed gates, and Run 055 sequence-before-marker ordering are preserved. Run 183 is release-binary evidence only; it introduces no new wire field, no new sidecar field, no new schema bump, no new metric, no new exit code, and no new CLI flag beyond the Run 180 hidden selector. No MainNet apply enablement. No autonomous apply / apply-on-receipt / peer-majority authority. No real on-chain governance execution, no real on-chain proof verifier, no bridge / light-client integration, no KMS / HSM custody, no validator-set rotation. Honest limitation (unchanged from Run 182): no current peer-candidate, SIGHUP-trigger, reload-apply trigger, startup-bundle, or live `0x05` payload format carries a typed `OnChainGovernanceProof`; adding such a field is explicitly out of scope for Run 183. Therefore peer-driven-drain production callers in real `target/release/qbind-node` invoke the Run 182 callsite entry with `proof: None`, the Run 180 wrapper short-circuits on `NoOnChainGovernanceProofSupplied`, and the drain-coordinator pre-apply behaviour is preserved bit-for-bit. MainNet peer-driven apply remains refused. Real on-chain governance proof verification remains unimplemented. Governance execution remains unimplemented. KMS/HSM remains unimplemented. Validator-set rotation remains open. **Full C4 / C5 remain OPEN.** Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`.

## Run 184 update — source/test OnChainGovernance proof carrying through production v2 sidecar payload

Run 184 adds, at source/test level only, an additive optional
`onchain_governance_proof` sibling field on the existing v2 ratification
sidecar JSON wire that delivers a typed
`OnChainGovernanceProofWire` into the `proof` slot of
`OnChainGovernanceCallsiteContext` consumed by the seven Run 182
named production call-site entries. The sibling is parsed via the
same pre-extraction pattern used by Run 167's `governance_authority_proof`
carrier so unknown fields cannot poison the strict
`BundleSigningRatificationV2` parse, and legacy v2 sidecars without
the sibling continue to load identically with `proof: None`. Default
policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`; the hidden
`AllowFixtureSourceTest` policy is DevNet/TestNet fixture-only
behind the existing Run 181/183 selector. A valid carried fixture
proof reaches the production call-site context at source/test level
and is accepted only when the hidden selector is armed; an invalid
or malformed-payload sibling fails closed surface-uniformly *before*
the Run 182 entry runs, regardless of policy. MainNet peer-driven
apply remains refused even with a fully-valid DevNet fixture proof
carried through the new payload. Release-binary boundary evidence
covering the new payload-carrying surface is **deferred to Run 185**.
Real on-chain governance proof verification, governance execution,
KMS/HSM custody, validator-set rotation, bridge/light-client
integration, autonomous apply, and apply-on-receipt all remain
unimplemented. Full C4 and C5 remain open.

## Run 185 update — release-binary OnChainGovernance proof-payload-carrying accepted-proof evidence

Run 185 closes the Run 184-deferred release-binary boundary by
exercising on real `target/release/qbind-node` the additive optional
`onchain_governance_proof` sibling Run 184 introduced on the v2
ratification sidecar JSON wire and the seven Run 182 named
production call-site entries (`reload_check_callsite_`,
`reload_apply_callsite_`, `startup_p2p_trust_bundle_callsite_`,
`sighup_callsite_`, `local_peer_candidate_check_callsite_`,
`live_inbound_0x05_callsite_`,
`peer_driven_drain_callsite_onchain_governance_marker_decision`)
plus the typed argument bundle `OnChainGovernanceCallsiteContext`,
the additive selector builder
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders
`load_v2_ratification_sidecar_with_onchain_governance_proof_*` /
`parse_optional_onchain_governance_proof_sibling_from_json_value`,
the routing helpers
`route_loaded_onchain_governance_proof_to_*_callsite_decision`,
and the typed `OnChainGovernanceProofPayloadParseError` boundary.
On real `target/release/qbind-node`, Run 185 captures: the
production default — neither flag nor env var truthy — emitting no
`[run-180] ... policy ARMED (AllowFixtureSourceTest)` banner and
preserving `OnChainGovernanceProofPolicy::Disabled` on every
surface, with a v2 sidecar without the Run 184 sibling parsing
byte-for-byte identically to its pre-Run-184 form (A1 / R1); the
CLI selector arming `AllowFixtureSourceTest` exactly when supplied
(A2); the env selector arming across truthy variants
`{1, true, TRUE, True, yes, YES, on, ON}` and remaining disabled
across falsey variants `{0, false, FALSE, no, off, empty, garbage}`
(A3); real
`target/release/qbind-node --p2p-trust-bundle-reload-check
<sidecar-with-sibling>
--p2p-trust-bundle-onchain-governance-fixture-allowed --network
devnet` loading a v2 sidecar carrying a valid DevNet fixture-rotate
proof, extracting the additive Run 184 sibling, parsing the typed
`OnChainGovernanceProofWire`, and reaching the Run 182 reload-check
named callsite entry through the production
`preflight_run_132_validation_only_v2_marker_check` path with no
marker write, no sequence write, no live trust swap, no session
eviction, and no Run 070 call (A2_payload); the matching
`--p2p-trust-bundle-reload-apply-enabled
--p2p-trust-bundle-reload-apply-path <sidecar-with-sibling>`
invocation arming the selector, loading the sidecar, parsing the
sibling, and invoking the Run 182 reload-apply named callsite entry
through the production `preflight_run_134_v2_marker_decision` path
on the mutating surface, with the Run 070-honest
`ReloadApplyError::UnsupportedRuntimeContext` returned on a
non-long-running invocation and the matching accepted typed outcome
captured in release mode by the new Run 185 release-built helper
through the same library symbols, with Run 055
sequence-before-marker ordering preserved at the library layer
(A4 / A5); malformed sibling payloads (non-object, unknown_schema,
empty required field, empty proof bytes) failing closed at the
typed `OnChainGovernanceProofPayloadParseError` boundary BEFORE any
verifier or marker decision runs (R2 a–d); `qbind-node --help` not
surfacing the hidden flag (`hide = true`) and not surfacing a
`run-180` / `run-181` / `run-182` / `run-183` / `run-184` /
`run-185` / `onchain-governance-fixture` token; and MainNet
peer-driven apply remaining the Run 147 / 148 / 152 FATAL invariant
even with the selector engaged on `--network mainnet` AND a
fully-valid MainNet fixture-rotate proof carried in the v2 sidecar
via the Run 184 sibling, with the Run 182 peer-driven-drain
callsite entry's surface-level `MainNetRefused` short-circuit
layered ahead of the Run 180 verifier (R26). Through both
release-built helpers (the Run 179
`run_179_onchain_governance_proof_release_binary_helper` for the
verifier corpus and the new Run 185
`run_185_onchain_governance_payload_release_binary_helper` for the
Run 184 payload-carrying / call-site-routing corpus), Run 185
captures release-mode acceptance / rejection across the full
A1–A9 / R1–R26 matrix through the production library symbols
`verify_onchain_governance_proof`,
`validate_lifecycle_with_onchain_governance_proof`,
`compose_onchain_governance_marker_decision`, every Run 180
per-surface composed wrapper, every Run 182 named callsite entry
plus `OnChainGovernanceCallsiteContext` and
`with_onchain_governance_fixture_allowed_selector`, the Run 184
payload-carrying loaders / routing helpers, and the typed
`OnChainGovernancePayloadCarryingDecisionOutcome::{MalformedOnChainGovernanceProofPayload,
Callsite}` boundary. Honest limitation: Run 184 added the additive
sibling on the v2 ratification sidecar JSON wire used by
reload-check / reload-apply / startup `--p2p-trust-bundle` / SIGHUP
only; the live `0x05` peer-candidate envelope and the peer-driven
drain inbound payload may not yet carry the typed OnChainGovernance
proof end-to-end on a real binary depending on tree state, and
where they do not, Run 185 captures the source-reachability for the
matching Run 182 named callsite entry through the release-built
helper in release mode AND records the boundary explicitly in the
archive's `mutation_proof.txt` / `no_mutation_proof.txt`. No
production source change. No MainNet apply enablement. No real
on-chain governance execution / no real on-chain proof verifier /
no bridge / light-client / KMS-HSM / validator-set rotation /
autonomous apply / apply-on-receipt / peer-majority authority. No
marker / sequence-file / trust-bundle / wire / metric drift beyond
Run 184's additive optional sibling. **Full C4 / C5 remain OPEN.**
Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`,
`scripts/devnet/run_185_onchain_governance_payload_release_binary.sh`,
`docs/devnet/run_185_onchain_governance_payload_release_binary/`.

## Run 186 update — source/test typed production OnChainGovernance verifier boundary

Run 186 introduces, at source/test level only, a typed verifier-kind
boundary in the new
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
module that cleanly separates fixture OnChainGovernance proof
verification (DevNet/TestNet evidence-only) from future real on-chain
governance proof verification (declared unavailable and fail-closed).
The boundary defines `OnChainGovernanceVerifierKind` (`Disabled` /
`FixtureSourceTest` / `ProductionUnavailable` /
`ProductionVerifierPlaceholder`), `OnChainGovernanceProofClass`
(`Fixture` / `Production`, derived from the proof suite ID via
`classify_onchain_governance_proof_class`),
`OnChainGovernanceVerifierPolicy` carrying the kind plus the Run 178
proof policy that the fixture path forwards to, and a typed
`OnChainGovernanceVerifierBoundaryOutcome` surface
(`AcceptedFixture(inner)` / `FixtureDisabled` /
`ProductionVerifierUnavailable` / `ProductionProofUnsupported` /
`ProductionProofMalformed{reason}` /
`MainNetProductionVerifierUnavailable` /
`FixtureProofRejectedAsMainNetProductionAuthority` /
`Run178Rejection(inner)`). The `OnChainGovernanceVerifier` trait has
four concrete implementations (`DisabledOnChainGovernanceVerifier`,
`FixtureSourceTestOnChainGovernanceVerifier`,
`ProductionUnavailableOnChainGovernanceVerifier`,
`ProductionVerifierPlaceholderOnChainGovernanceVerifier`), and the
pure entry points `verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof` are dispatched through
`dispatch_onchain_governance_proof_through_verifier_boundary`. Default
kind on every surface is `Disabled` and refuses every proof; the
fixture path is reachable only under `FixtureSourceTest` plus the
existing `AllowFixtureSourceTest` proof policy and short-circuits to
`FixtureProofRejectedAsMainNetProductionAuthority` whenever the trust
domain, candidate root, or proof environment is MainNet — so a fixture
proof can never masquerade as a production governance authority. Both
production verifier kinds always return `ProductionVerifierUnavailable`
(or `MainNetProductionVerifierUnavailable` on MainNet) regardless of
proof material. The boundary is purely additive: no wire, no v2 sidecar
JSON, no `OnChainGovernanceProofWire`, no marker, no sequence file, no
trust-bundle core schema, and no Run 070 / 130–185 invariant changes.
Source/test acceptance and rejection are exercised by
[`run_186_onchain_governance_production_verifier_boundary_tests`](
  ../../crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs)
covering the full A1–A7 / R1–R29 matrix from `task/RUN_186_TASK.txt`
plus extras for proof-class separation, all four verifier traits,
MainNet masquerade refusal, dispatcher determinism, and call-site
reachability (44 tests, all passing). MainNet peer-driven apply remains
refused (Run 147 FATAL invariant). The release-binary boundary for the
verifier kind is explicitly deferred to Run 187. Real on-chain
governance proof verification, governance execution, KMS/HSM custody,
validator-set rotation, bridge / light-client integration, autonomous
apply, apply-on-receipt, and peer-majority authority all remain
unimplemented. **Full C4 / C5 remain OPEN.** Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_186.md`,
`crates/qbind-node/src/pqc_onchain_governance_verifier.rs`,
`crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`.
## Run 187 update — release-binary OnChainGovernance production verifier-boundary evidence

Run 187 closes the Run 186-deferred release-binary boundary for the
typed production OnChainGovernance verifier surface added by
[`pqc_onchain_governance_verifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
and explicitly preserves the peer-driven-apply safety contract under
the Run 186 typed verifier boundary. On real `target/release/qbind-node`
Run 187 captures: the production default
(`OnChainGovernanceVerifierKind::Disabled`) fail-closing on every
production surface and emitting no `[run-180]` armed banner; the
hidden CLI / env selectors arming `AllowFixtureSourceTest` only on
DevNet/TestNet and **not** enabling any production verifier; the
existing Run 185 reload-check / reload-apply DevNet fixture-payload
paths remaining compatible under the Run 186 typed verifier-boundary
contract; the Run 184 routing helpers continuing to short-circuit
malformed-sibling payloads at the typed
`OnChainGovernanceProofPayloadParseError` boundary BEFORE any Run 186
verifier-boundary dispatch; and **MainNet peer-driven apply remaining
the Run 147 / 148 / 152 FATAL refusal even with the selector engaged
AND a fully-valid MainNet fixture proof carried in the v2 sidecar via
the Run 184 sibling**. The Run 186 typed verifier boundary additionally
encodes the MainNet refusal in two layers: (a) the typed
`FixtureProofRejectedAsMainNetProductionAuthority` outcome from
`verify_fixture_onchain_governance_proof` whenever the trust-domain
environment is MainNet — explicitly forbidding fixture-as-MainNet-
production-authority — and (b) the explicit fail-closed helper
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`,
which returns `true` for MainNet regardless of any boundary outcome.
Through both release-built helpers — the Run 185
[`run_185_onchain_governance_payload_release_binary_helper`](
  ../../crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs)
for sidecar minting / payload-carrying compatibility evidence and the
new Run 187
[`run_187_onchain_governance_verifier_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs)
for the typed verifier-boundary corpus — Run 187 captures release-mode
acceptance / rejection across the full A1–A8 / R1–R29 matrix from
`task/RUN_187_TASK.txt`, dispatching all four verifier kinds against
both fixture-class and production-class proofs across DevNet/TestNet
and MainNet trust domains. Bit-equality non-mutation evidence is
captured for every rejected verifier-boundary scenario by snapshotting
candidate / persisted state before and after a rejecting dispatch and
asserting bytewise equality, so the no-mutation contract — no Run 070
apply call, no live trust swap, no session eviction, no sequence
write, no marker write, no `.tmp` residue, no fallback to
`--p2p-trusted-root`, no active DummySig / DummyKem / DummyAead — is
preserved under the Run 186 typed verifier boundary. Honest limitation:
Run 187 still wires no real on-chain governance proof verifier; both
`OnChainGovernanceVerifierKind::ProductionUnavailable` and
`OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`
honestly route production-class proofs to
`ProductionVerifierUnavailable` on DevNet/TestNet and to
`MainNetProductionVerifierUnavailable` on MainNet, and route
fixture-class proofs to `ProductionProofUnsupported` regardless of
environment. No production source change. No MainNet peer-driven
apply enablement. No real on-chain governance execution / no real
on-chain proof verifier / no bridge / light-client / KMS-HSM /
validator-set rotation / autonomous apply / apply-on-receipt /
peer-majority authority. No schema/wire/metric drift. **Full C4 / C5
remain OPEN.** Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`,
`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`,
`docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/`,
`crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs`.
## Run 188 — source/test KMS/HSM custody boundary

Run 188 introduces, at source/test level only, a typed authority-custody boundary
in the new `crates/qbind-node/src/pqc_authority_custody.rs` module:
`AuthorityCustodyClass` (`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
`Kms` / `Hsm` / `Unknown`), `AuthorityCustodyPolicy` (`Disabled` (default) /
`FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed` /
`ProductionCustodyRequired` / `MainnetProductionCustodyRequired`),
`AuthorityCustodyAttestation` (binds environment, chain_id, genesis_hash,
authority_root_fingerprint, bundle_signing_key_fingerprint,
governance_authority_class, lifecycle_action, candidate_digest,
authority_domain_sequence, custody_class, custody_key_id,
custody_attestation_digest, and optional freshness/expiry),
`AuthorityCustodyValidationOutcome` (typed accept-fixture /
accept-local-operator / production-custody-unavailable / KMS / HSM /
RemoteSigner unavailable / unknown / wrong-binding / malformed / expired /
key-id-mismatch / unsupported-suite / MainNet refusals / policy refusal),
the pure validator `validate_authority_custody_attestation`, and the pure
composition helper `validate_lifecycle_governance_and_custody`.

Operational rules surfaced at the typed Run 188 boundary:

* **No real KMS/HSM backend is implemented.** RemoteSigner / Kms / Hsm
  are placeholder symbols only; the validator fails them closed as
  unavailable regardless of policy or environment.
* **Fixture/local custody remains DevNet/TestNet evidence-only.** It is
  reachable only under the explicit `FixtureOnly` / `DevnetLocalAllowed` /
  `TestnetLocalAllowed` policies.
* **Fixture/local custody cannot satisfy MainNet production custody.**
  Trust-domain MainNet rejects fixture custody as
  `FixtureCustodyRejectedForMainNet` and local-operator custody as
  `LocalCustodyRejectedForMainNet`, ahead of the policy gate.
* **MainNet peer-driven apply remains refused** (Run 147 FATAL invariant)
  regardless of any custody attestation contents; encoded by the
  grep-verifiable helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`.
* **Governance execution remains unimplemented.** Run 188 does not call
  the Run 163 / 178 / 186 governance verifier; the calling surface threads
  the already-validated governance class into the composition helper.
* **Real on-chain proof verification remains unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved.
* **Validator-set rotation remains open.**
* **Release-binary custody-boundary evidence is deferred to Run 189.**
* **Full C4 remains open. C5 remains open.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_188.md` for the full A1–A8 /
R1–R29 acceptance matrix and validation-command list.
## Run 189 update — release-binary KMS/HSM authority-custody boundary evidence

Run 189 closes the Run 188-deferred release-binary boundary for the
typed authority-custody surface in
`crates/qbind-node/src/pqc_authority_custody.rs`, **without
weakening peer-driven apply safety**. The Run 147 / 148 / 152 FATAL
MainNet peer-driven apply refusal is preserved bit-identically:

* At the **binary surface**: real `target/release/qbind-node
  --print-genesis-hash --env mainnet`, with or without the Run 187
  hidden fixture selector
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` armed and
  the matching env var truthy, never declares `MainNet peer-driven
  apply ENABLED` and never declares `KMS/HSM enabled` /
  `production custody enabled` / `remote signer enabled`.
* At the **typed Run 188 boundary**: the grep-verifiable named
  helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  encodes the rule regardless of attestation contents or active
  policy, including in the presence of a fully-formed `Kms` / `Hsm`
  / `RemoteSigner` attestation under
  `MainnetProductionCustodyRequired`. The matching combined-helper
  outcome is the typed
  `LifecycleGovernanceCustodyOutcome::MainNetPeerDrivenApplyRefused`.
* **Peer-majority is not custody.** The named helper
  `peer_majority_cannot_satisfy_custody` encodes that no count of
  peer attestations can satisfy any
  `*ProductionCustodyRequired` policy.
* **Local-operator config alone is not MainNet production custody.**
  The named helper
  `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`
  encodes that a local-operator attestation routes to
  `LocalCustodyRejectedForMainNet` ahead of the policy gate, even
  when the caller asks for `MainnetProductionCustodyRequired`.

The release-binary boundary preserves every Run 070 / 084 / 085 /
094 / 130–187 peer-driven apply invariant: the Run 189 helper is a
pure validation driver — it never calls
`pqc_trust_reload::apply_validated_candidate{,_with_previous}`,
never swaps `LivePqcTrustState`, never invokes
`P2pSessionEvictor::*`, never calls
`pqc_trust_sequence::commit_sequence`, never writes the v2
authority-marker, never propagates / rebroadcasts, and never
weakens validation-only or propagation-only behaviour. The
non-mutation evidence captured by the helper (bit-equal candidate /
persisted snapshots before and after every rejecting custody
validation) is the typed `R28` / `R29` proof at the release-binary
boundary.

Run 189 introduces no production source change, no new CLI flag, no
new env var, no new schema bump, no new wire shape, no new sidecar
field, no new metric, and no new exit code. **Full C4 is NOT
claimed by Run 189; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_189.md`,
`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`,
`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`,
and `docs/devnet/run_189_authority_custody_boundary_release_binary/`
for the full release-binary scenario matrix and the canonical PASS
verdict.

## Run 190 — source/test authority-custody metadata carrying through peer-driven apply preflight

Run 190 wires typed authority-custody attestation metadata into the
peer-driven apply drain coordinator's preflight composition path at
source / test level, preserving every Run 050–189 invariant
byte-for-byte. The peer-driven-drain routing helper
`peer_driven_drain_callsite` in
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`
layers a surface-level MainNet refusal **ahead of** the Run 188
custody validator (the Run 152 pattern), so the Run 147 / 148 / 152
FATAL MainNet peer-driven apply refusal continues to hold even when
the optional `authority_custody_attestation` JSON sibling on the v2
ratification sidecar claims `Kms` or `Hsm` and the
`MainnetProductionCustodyRequired` policy is engaged. The grep-verifiable
named helpers `mainnet_peer_driven_apply_remains_refused_under_run_190`,
`peer_majority_cannot_satisfy_run_190_custody`, and
`local_operator_config_alone_cannot_satisfy_mainnet_run_190_custody`
re-state, by symbol, that no peer-driven path — peer majority,
gossip count, fixture custody, local-operator custody, or a custody
attestation alone claiming KMS / HSM — can satisfy MainNet
production custody.

The Run 190 sibling is purely additive: old peer-candidate v2
ratification sidecars without an `authority_custody_attestation`
field parse byte-for-byte through the Run 167 + Run 184 + Run 190
combined sidecar loader, return the typed
`AuthorityCustodyLoadStatus::Absent`, and short-circuit to
`NoCustodyAttestationSupplied` under the default
`AuthorityCustodyPolicy::Disabled`. A malformed custody sibling
fails closed at the typed payload boundary
(`AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedPayload`)
before any Run 188 validator work runs, and never poisons the
strict v2 parse or the Run 167 governance-proof / Run 184
OnChainGovernance sibling outcomes. R29 / R30 / R31 / R32 in
`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`
assert validation-only and mutating rejections produce no Run 070
call, no live trust swap, no session eviction, no sequence write,
and no marker write, including for the live-inbound `0x05` path,
and that MainNet peer-driven apply remains refused even with a
KMS / HSM custody claim.

Honest limitation: Run 190 is **source / test only**. No real KMS /
HSM / cloud KMS / PKCS#11 / remote-signer backend is wired into the
peer-driven path; every production custody class still fails closed
as unavailable at the Run 188 validator. Fixture / local-operator
custody remains DevNet/TestNet evidence-only and is rejected by
symbol on MainNet. **Release-binary custody-metadata evidence
covering the peer-driven apply path is deferred to Run 191. Full C4
is NOT claimed by Run 190; C5 remains OPEN.**

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_190.md` for the canonical
verdict.

## Run 191 update — release-binary authority-custody metadata carrying evidence

Run 191 closes the Run 190-deferred release-binary boundary for the
typed authority-custody payload-carrying surface in
`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`,
composed over the Run 188 typed authority-custody boundary in
`pqc_authority_custody.rs`. Run 191 is release-binary evidence only:
no production source line is changed, no new CLI flag / env var /
schema bump / wire shape / sidecar field / metric / exit code is
introduced beyond Run 190's additive optional custody sibling. Run
190 added no operator-visible selector, so the operator-facing CLI
surface from Run 189 is preserved bit-identically — `target/release/
qbind-node --help` surfaces no `authority-custody` / `kms-hsm` /
`remote-signer` / `production custody` token; the default
`--print-genesis-hash --env {devnet,testnet,mainnet}` invocations
emit no Run 190 enablement banner and no `MainNet peer-driven apply
ENABLED` claim; and the existing Run 187 hidden
`--p2p-trust-bundle-onchain-governance-fixture-allowed` selector
(and the matching
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` env var),
armed on MainNet, still refuses MainNet peer-driven apply.

Through the release-built helper
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`,
Run 191 exercises the Run 190 A1–A10 / R1–R32 corpus end-to-end in
**release mode** through the production library symbols
`pqc_authority_custody_payload_carrying::*` (every wire type, the
optional-sibling parser, the typed `AuthorityCustodyLoadStatus` /
`AuthorityCustodyCallsiteContext` /
`AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven
per-surface routing helpers, and
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`)
composed with the Run 188 typed-boundary symbols
`pqc_authority_custody::*`. Every `RemoteSigner` / `Kms` / `Hsm`
attestation — whether in-process or wire-carried and parsed back —
fails closed with the typed `RemoteSignerUnavailable` /
`KmsUnavailable` / `HsmUnavailable` outcome regardless of policy or
environment; every `ProductionCustodyRequired` /
`MainnetProductionCustodyRequired` policy fails closed with the typed
`ProductionCustodyUnavailable` / `MainNetProductionCustodyUnavailable`;
every fixture / local-operator class on MainNet routes to
`FixtureCustodyRejectedForMainNet` / `LocalCustodyRejectedForMainNet`
ahead of the policy gate even when wire-carried; legacy / no-custody
payloads (sibling absent) under default `Disabled` route through the
seven Run 190 routing helpers without producing schema or wire drift;
malformed sibling JSON is parsed to
`AuthorityCustodyLoadStatus::Malformed { … }` and routed by every
per-surface helper to `Callsite { custody_outcome:
CustodyAttestationMalformed }` (or to peer-driven-drain
`MainNetPeerDrivenApplyRefused` where applicable) without drift. The
Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal is
preserved bit-identically at the binary surface AND at the typed Run
190 payload-carrying boundary via
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
(which composes
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`).

Honest limitation: Run 191 wires no real KMS / HSM / cloud KMS /
PKCS#11 / remote-signer backend, no real on-chain governance proof
verifier, no governance execution engine, no validator-set rotation,
no autonomous apply, no apply-on-receipt, and no peer-majority
authority. Existing no-custody payloads remain compatible under
default `Disabled`; existing Run 184 / 185 / 187 governance fixture
proof paths remain compatible alongside the Run 190 optional custody
sibling. **Full C4 remains OPEN; C5 remains OPEN.**

See
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`,
`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`,
`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`,
and `docs/devnet/run_191_authority_custody_payload_release_binary/`
for the full release-binary scenario matrix, the regression test
slice, and the canonical PASS verdict.

## Run 192 — source/test hidden authority-custody policy selector and production preflight integration

Run 192 adds, at source/test level only, the smallest hidden selector
surface that lets a DevNet/TestNet evidence preflight context
explicitly choose an `AuthorityCustodyPolicy` variant and threads the
resolved policy into the seven Run 190 production v2 marker-decision
preflight contexts (reload-check, reload-apply, startup
`--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live
inbound `0x05`, peer-driven drain). The default
`AuthorityCustodyPolicy::Disabled` is preserved bit-for-bit; legacy
no-custody payloads remain accepted exactly as in Run 190 / Run 191.

The new module
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`
exposes the env-var name
`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`, the canonical
selector tags (`disabled` / `fixture-only` / `devnet-local-allowed` /
`testnet-local-allowed` / `production-custody-required` /
`mainnet-production-custody-required`), the typed
`AuthorityCustodyPolicySelectorParseError`, the pure parsers
`authority_custody_policy_from_selector` /
`authority_custody_policy_env_selector` /
`authority_custody_policy_from_cli_or_env`, and seven thin
per-surface preflight wrappers
(`preflight_v2_marker_authority_custody_for_*`) that bind the
resolved policy into the Run 190 `AuthorityCustodyCallsiteContext`
and dispatch to the matching Run 190
`route_loaded_authority_custody_attestation_to_*_callsite_decision`
helper. The matching hidden CLI flag
`--p2p-trust-bundle-authority-custody-policy <POLICY>` (clap
`hide = true`) is added on `crates/qbind-node/src/cli.rs` as
`Option<String>`. Either source is sufficient to choose a non-default
policy; CLI wins when both are present; both absent preserves
`Disabled`; invalid values are surfaced as a typed parse error and
never silently downgrade to `Disabled`.

Run 192 is **source/test only**. No real KMS / HSM / cloud-KMS /
PKCS#11 / remote-signer backend is implemented. KMS / HSM /
RemoteSigner placeholders remain fail-closed via the Run 188
validator regardless of selector. Fixture / local custody remains
DevNet/TestNet evidence-only and cannot satisfy MainNet production
custody. The Run 147 / 148 / 152 FATAL MainNet peer-driven apply
refusal at the peer-driven apply surface remains intact regardless
of selector, attestation contents, or policy — including with
`mainnet-production-custody-required` and metadata claiming
KMS/HSM/RemoteSigner. Governance execution remains unimplemented.
Real on-chain proof verification remains unimplemented. Validator-set
rotation remains open. Release-binary custody-policy selector
evidence is deferred to **Run 193**. Full C4 remains OPEN. C5
remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_192.md`,
`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`, and
`crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`
for the full A1–A10 / R1–R29 source/test scenario matrix and the
canonical PASS verdict.

## Run 193 — release-binary authority-custody policy selector evidence

Run 193 closes the Run 192-deferred release-binary boundary for the
hidden authority-custody policy selector. The peer-driven apply
six-phase fail-closed pipeline is unchanged at the protocol level —
Run 193 introduces no new CLI / env / sidecar / authority-marker /
sequence-file / trust-bundle core / wire / metric / schema change.
What Run 193 captures, in **release mode**, is: real
`target/release/qbind-node` preserves the Run 192 selector contract
end-to-end (default `AuthorityCustodyPolicy::Disabled` when neither
CLI nor env selector is set; hidden CLI flag absent from normal
`--help`; env-only and CLI-only selectors each activate the typed
policy without drifting any banner; CLI-over-env precedence
deterministic; invalid selector values fail closed). The
release-built helper
`crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`
exercises the Run 192 A1–A12 / R1–R29 selector + preflight wrapper
corpus through the production library symbols
`pqc_authority_custody_policy_surface::*`, layered above the Run 190
typed payload-carrying surface and the Run 188 typed authority-
custody boundary, and proves at the typed boundary that the seven
per-surface preflight wrappers (`reload_check`, `reload_apply`,
`startup_p2p_trust_bundle`, `sighup`, `local_peer_candidate_check`,
`live_inbound_0x05`, `peer_driven_drain`) each route the resolved
policy into the matching Run 190 callsite-decision helper without
mutating any marker, sequence, trust-bundle, or wire field.

The Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal at
the peer-driven apply surface remains intact in Run 193 regardless of
selector contents — including with `mainnet-production-custody-
required` armed on env+CLI together with the Run 187 hidden fixture
selector and metadata claiming KMS / HSM / RemoteSigner — both at
the binary surface (S7, S8) and at the typed boundary via
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`.
Fixture / local-operator custody remains DevNet / TestNet evidence-
only and cannot satisfy MainNet production custody
(`FixtureCustodyRejectedForMainNet` /
`LocalCustodyRejectedForMainNet`). KMS / HSM / RemoteSigner
placeholders remain fail-closed under every policy regardless of
environment. The validation-only / propagation-only behaviour on the
peer-driven drain surface is preserved bit-for-bit. Run 193 is
**release-binary evidence only**: no production source change, no
new wire format, no schema change, no real KMS / HSM / cloud-KMS /
PKCS#11 / remote-signer backend, no real on-chain governance proof
verifier, no governance execution, no validator-set rotation, no
MainNet peer-driven apply enablement, no autonomous apply, no
apply-on-receipt, no peer-majority authority, no DummySig / DummyKem
/ DummyAead activation, no fallback to `--p2p-trusted-root`, and no
weakening of Runs 070, 130–192. Full C4 remains OPEN. C5 remains
OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_193.md`,
`docs/devnet/run_193_authority_custody_policy_release_binary/`,
`scripts/devnet/run_193_authority_custody_policy_release_binary.sh`,
and `crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`.

## Run 194 — source/test RemoteSigner production-custody interface boundary

Run 194 is **source/test RemoteSigner production-custody interface
boundary** work. It replaces the vague Run 188
`AuthorityCustodyClass::RemoteSigner` placeholder with a precise,
typed remote-signer custody boundary in
`crates/qbind-node/src/pqc_remote_authority_signer.rs` — a
`RemoteSignerIdentity`, a domain-bound `RemoteSignerRequest` /
`RemoteSignerResponse` pair (deterministic SHA3-256 `canonical_digest`),
a `RemoteSignerPolicy` (`Disabled` default / `FixtureLoopbackAllowed`
/ `ProductionRemoteSignerRequired` /
`MainnetProductionRemoteSignerRequired`), a precise
`RemoteSignerOutcome` reject taxonomy, a pure `RemoteAuthoritySigner`
trait with a DevNet/TestNet-only `FixtureLoopbackRemoteSigner` and a
fail-closed `ProductionRemoteSigner`, the pure `validate_remote_signer`
verifier, custody-class routing, and a pure
`validate_lifecycle_governance_custody_and_remote_signer` composition
helper layered over the Run 188 boundary.

Relative to the peer-driven trust-bundle apply safety contract, Run 194
changes nothing: it adds no production call site, no wire format, no
schema, and no apply path. The Run 147 / 148 / 152 FATAL MainNet
peer-driven apply refusal remains intact even when a fixture loopback
remote signer signs successfully — a fixture loopback signer is
rejected on a MainNet trust domain (`FixtureLoopbackRejectedForMainNet`)
and the composition helper short-circuits a MainNet peer-driven-apply
preflight to `MainNetPeerDrivenApplyRefused` via
`mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`.
A local operator key and a peer majority can never satisfy a remote
signer policy. Validation-only and mutating-preflight rejection paths
produce no Run 070 call, no live trust swap, no session eviction, no
sequence write, and no marker write.

No real RemoteSigner backend is implemented; the fixture loopback
remote signer is DevNet/TestNet source/test only; production
RemoteSigner remains unavailable / fail-closed; RemoteSigner does not
enable MainNet peer-driven apply; KMS / HSM remain unimplemented;
governance execution remains unimplemented; real on-chain proof
verification remains unimplemented; validator-set rotation remains
open. No autonomous apply, no apply-on-receipt, no peer-majority
authority, no cloud-KMS / PKCS#11 integration, no DummySig / DummyKem /
DummyAead activation, no fallback to `--p2p-trusted-root`, and no
weakening of Runs 070, 130–193. Release-binary RemoteSigner boundary
evidence is deferred to **Run 195**. Full C4 remains OPEN. C5 remains
OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_194.md`,
`crates/qbind-node/src/pqc_remote_authority_signer.rs`, and
`crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`.

## Run 195 — release-binary RemoteSigner production-custody boundary evidence

Run 195 is **release-binary evidence** for the Run 194 RemoteSigner
production-custody interface boundary. It exercises the Run 194 typed
RemoteSigner surface on real `target/release/qbind-node` (seven
release-binary scenarios) and through the release-built helper
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`,
which drives the Run 194 A1–A7 / R1–R31 corpus end-to-end in **release
mode** through the production library symbols
`pqc_remote_authority_signer::*` layered above the Run 192 / 190 / 188
custody surfaces. Reproduce with
`bash scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh`.

Relative to the peer-driven trust-bundle apply safety contract, Run 195
changes nothing: it adds no production call site, no wire format, no
schema, and no apply path; the helper only **reads** the typed surface
and is a Cargo example that is dead code in the release binary's runtime.
Run 194 added no new CLI flag and no new env var, so real
`target/release/qbind-node --help` and
`--print-genesis-hash --env {devnet,testnet,mainnet}` expose no
RemoteSigner / KMS / HSM / governance-execution / validator-set-rotation
enablement claim and no MainNet peer-driven apply enablement claim. The
Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal remains
intact even with the Run 193 `mainnet-production-custody-required`
selector and the governance fixture selector armed on MainNet (S4, S7),
and at the typed boundary via
`mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`.
Local operator keys and a peer majority can never satisfy a remote signer
policy. Rejected RemoteSigner / custody / lifecycle / routing scenarios
produce no Run 070 call, no live trust swap, no session eviction, no
sequence write, and no marker write (no_mutation_evidence.txt).

No real RemoteSigner backend is implemented; the fixture loopback remote
signer remains DevNet/TestNet evidence-only; production RemoteSigner
remains unavailable / fail-closed; RemoteSigner does not enable MainNet
peer-driven apply; KMS / HSM remain unimplemented; governance execution
remains unimplemented; real on-chain proof verification remains
unimplemented; validator-set rotation remains open. No autonomous apply,
no apply-on-receipt, no peer-majority authority, no cloud-KMS / PKCS#11
integration, no DummySig / DummyKem / DummyAead activation, no fallback to
`--p2p-trusted-root`, and no weakening of Runs 070, 130–194. Full C4
remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_195.md`,
`docs/devnet/run_195_remote_authority_signer_boundary_release_binary/`,
`scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh`,
and
`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`.

## Run 196 — source/test RemoteSigner attestation payload/carrying and production-context wiring

Run 196 is **source/test RemoteSigner attestation payload/carrying and
production-context wiring**. It adds source- and test-level support for
carrying RemoteSigner identity / request / response attestation material
through the production payload and production-context paths and routing it
into the Run 194 lifecycle + governance + custody + RemoteSigner
composition, via `crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`
and `crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.
The carrier is an **additive optional** JSON sibling
(`remote_signer_attestation`) on the v2 ratification sidecar, mirroring
the Run 190 authority-custody payload/carrying pattern. Reproduce with
`cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`.

Relative to the peer-driven trust-bundle apply safety contract, Run 196
changes nothing operationally: it adds no new CLI flag, no new env var, no
wire format, and no schema change; the RemoteSigner attestation carrier is
an additive optional JSON sibling and legacy no-RemoteSigner payloads
remain byte-compatible (parse as `Absent`). Malformed / invalid /
unsupported-schema RemoteSigner material fails closed
(`RemoteSignerLoadStatus::Malformed`) in front of the verifier, before any
Run 070 call, live trust swap, session eviction, sequence write, or marker
write; validation-only surfaces remain non-mutating and mutating-preflight
rejection produces no mutation. The Run 147 / 148 / 152 FATAL MainNet
peer-driven apply refusal remains intact even when fixture loopback
RemoteSigner material is supplied through the seven per-surface
production-context helpers (`reload_check`, `reload_apply`,
`startup_p2p_trust_bundle`, `sighup`, `local_peer_candidate_check`,
`live_inbound_0x05`, `peer_driven_drain`).

No real RemoteSigner backend is implemented; the fixture loopback remote
signer remains DevNet/TestNet source/test only; production RemoteSigner
remains unavailable / fail-closed; RemoteSigner does not enable MainNet
peer-driven apply; KMS / HSM remain unimplemented; governance execution
remains unimplemented; real on-chain proof verification remains
unimplemented; validator-set rotation remains open. No autonomous apply,
no apply-on-receipt, no peer-majority authority, and no weakening of
Runs 070, 130–195. Release-binary RemoteSigner payload/carrying evidence
is deferred to **Run 197**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_196.md`,
`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`, and
`crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`.

## Run 197 — release-binary RemoteSigner attestation payload/carrying and production-context evidence

Run 197 is **release-binary evidence** for the Run 196 RemoteSigner
attestation payload/carrying and production-context wiring. It exercises
the Run 196 module `crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`
against real `target/release/qbind-node` and through the release-built
helper
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_197_remote_signer_payload_release_binary.sh`. Reproduce
with `bash scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.

Relative to the peer-driven trust-bundle apply safety contract, Run 197
changes nothing operationally: it makes no production source change
(release example helper + release harness + docs only), adds no new CLI
flag, no new env var, no wire format, and no schema change beyond Run 196's
additive optional `remote_signer_attestation` sibling; legacy
no-RemoteSigner payloads remain byte-compatible (parse as `Absent`).
Malformed / invalid / unsupported-schema RemoteSigner material fails closed
in front of the verifier, before any Run 070 call, live trust swap, session
eviction, sequence write, or marker write; validation-only surfaces remain
non-mutating and mutating-preflight rejection produces no mutation. The
release-built helper drives the Run 196 A1–A10 / R1–R34 corpus in release
mode through the seven per-surface production-context helpers
(`reload_check`, `reload_apply`, `startup_p2p_trust_bundle`, `sighup`,
`local_peer_candidate_check`, `live_inbound_0x05`, `peer_driven_drain`) and
ends in `verdict: PASS`. The Run 147 / 148 / 152 FATAL MainNet peer-driven
apply refusal remains intact even with fixture loopback RemoteSigner
material supplied and with the Run 193 `mainnet-production-custody-required`
selector armed.

No real RemoteSigner backend is implemented; the fixture loopback remote
signer remains DevNet/TestNet evidence-only; production RemoteSigner
remains unavailable / fail-closed; RemoteSigner does not enable MainNet
peer-driven apply; KMS / HSM remain unimplemented; governance execution
remains unimplemented; real on-chain proof verification remains
unimplemented; validator-set rotation remains open; existing custody /
governance proof paths remain compatible. No autonomous apply, no
apply-on-receipt, no peer-majority authority, and no weakening of
Runs 070, 130–196. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_197.md`,
`docs/devnet/run_197_remote_signer_payload_release_binary/`,
`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`,
and `scripts/devnet/run_197_remote_signer_payload_release_binary.sh`.
## Run 198 — source/test hidden RemoteSigner policy selector and production preflight integration

Run 198 is **source/test hidden RemoteSigner policy selector and
production preflight integration**. It adds a hidden,
disabled-by-default RemoteSigner policy selector (hidden clap flag
`--p2p-trust-bundle-remote-signer-policy` plus the
`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var) in
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` and wires the
resolved `RemoteSignerPolicy` into all seven production v2
marker-decision preflight contexts through the Run 196 RemoteSigner
payload/call-site routing layer. Tests:
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
Reproduce with
`cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`.

Relative to the peer-driven trust-bundle apply safety contract, Run 198
preserves every existing invariant. The default resolved policy is
`RemoteSignerPolicy::Disabled`; legacy no-RemoteSigner payloads remain
compatible. The seven per-surface preflight wrappers
(`preflight_v2_marker_remote_signer_for_{reload_check, reload_apply,
startup_p2p_trust_bundle, sighup, local_peer_candidate_check,
live_inbound_0x05, peer_driven_drain}`) are pure: no Run 070 call, no
live trust swap, no session eviction, no sequence write, no marker write.
Missing / malformed / invalid RemoteSigner material fails closed under
any explicit (non-`Disabled`) policy in front of the verifier;
validation-only surfaces remain non-mutating; mutating-preflight
rejection produces no mutation. An invalid live inbound `0x05`
RemoteSigner candidate is not propagated, staged, or applied.

Crucially, the peer-driven drain surface preserves the **Run 147 / 148 /
152 FATAL MainNet refusal**: a MainNet candidate is refused
unconditionally even with `MainnetProductionRemoteSignerRequired` and
fully-valid fixture loopback material — the selector cannot weaken this
refusal. Fixture loopback RemoteSigner remains DevNet/TestNet
evidence-only and cannot satisfy MainNet production RemoteSigner;
production RemoteSigner remains unavailable / fail-closed.

No real RemoteSigner backend is implemented; no networked signer
service; KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented; governance
execution remains unimplemented; real on-chain proof verification remains
unimplemented; validator-set rotation remains open; existing custody /
governance proof paths remain compatible. No autonomous apply, no
apply-on-receipt, no peer-majority authority, and no weakening of
Runs 070, 130–197. Release-binary RemoteSigner-policy selector evidence
is deferred to **Run 199**. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_198.md`,
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`, and
`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`.
## Run 199 — release-binary hidden RemoteSigner policy selector and production preflight routing evidence

Run 199 is **release-binary evidence** for the Run 198 hidden
RemoteSigner policy selector and production preflight routing. It
exercises the Run 198 module
`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs` against real
`target/release/qbind-node` and through the release-built helper
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
driven by the harness
`scripts/devnet/run_199_remote_signer_policy_release_binary.sh`. Reproduce
with `bash scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.

Relative to the peer-driven trust-bundle apply safety contract, Run 199
changes nothing operationally: it makes no production source change
(release example helper + release harness + docs only) and adds no new
CLI flag, no new env var, no wire format, and no schema change beyond the
Run 198 hidden selector. The real binary accepts the hidden
`--p2p-trust-bundle-remote-signer-policy` flag and the
`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` env var while keeping the
flag hidden from `--help`; default resolution remains
`RemoteSignerPolicy::Disabled`. The release-built helper resolves the
selector (default / CLI / env / CLI-over-env precedence / invalid
fail-closed) and routes the resolved policy through the seven
`preflight_v2_marker_remote_signer_for_{reload_check, reload_apply,
startup_p2p_trust_bundle, sighup, local_peer_candidate_check,
live_inbound_0x05, peer_driven_drain}` wrappers into the Run 196 routing
helpers, ending in `verdict: PASS` (125/0 on this checkout). Missing /
malformed / invalid RemoteSigner material fails closed in front of the
verifier, before any Run 070 call, live trust swap, session eviction,
sequence write, or marker write; rejected cases produce no mutation.

Crucially, the peer-driven drain surface preserves the **Run 147 / 148 /
152 FATAL MainNet refusal**: a MainNet candidate is refused
unconditionally even with the selector armed to
`mainnet-production-remote-signer-required` and fully-valid fixture
loopback material — the release-binary selector cannot weaken this
refusal. Fixture loopback RemoteSigner remains DevNet/TestNet
evidence-only and cannot satisfy MainNet production RemoteSigner;
production RemoteSigner remains unavailable / fail-closed.

No real RemoteSigner backend is implemented; no networked signer
service; KMS / HSM / cloud-KMS / PKCS#11 remain unimplemented; governance
execution remains unimplemented; real on-chain proof verification remains
unimplemented; validator-set rotation remains open; existing custody /
governance proof paths remain compatible. No autonomous apply, no
apply-on-receipt, no peer-majority authority, and no weakening of
Runs 070, 130–198. Full C4 remains OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_199.md`,
`docs/devnet/run_199_remote_signer_policy_release_binary/`,
`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`,
and `scripts/devnet/run_199_remote_signer_policy_release_binary.sh`.
## Run 200 — authority lifecycle C4/C5 consolidation, closure criteria, and remaining-work specification

Run 200 is a **docs/spec/crosscheck-only** consolidation pass over
Runs 130–199. It introduces the consolidation report
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`, the formal closure
checklist `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and the static
run index `docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.

Relative to the peer-driven trust-bundle apply safety contract, Run 200
changes nothing: it makes no production source change and adds no new CLI
flag, env var, wire format, or schema change. The peer-driven staging /
apply / drain safety properties accepted in Runs 144–158 remain in force,
including the **Run 147 / 148 / 152 FATAL MainNet peer-driven apply
refusal**, validation-only non-mutation, rejected-candidate no-mutation,
and the Run 070 `validate → swap → evict_sessions → commit_sequence`
ordering.

Run 200 documents the C4/C5 closure criteria and the MainNet readiness
gates in `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`. The
apply-policy gate is explicit: the MainNet peer-driven apply policy must
be specified and remains refused unless a production custody backend,
a real on-chain governance proof verifier, a governance execution policy,
a production-authenticated authority set, and the supporting recovery /
rollback / sequence-replay protections are all satisfied and
release-binary evidenced. Until then, MainNet peer-driven apply remains
refused.

No real RemoteSigner / KMS / HSM backend is implemented; no real on-chain
governance proof verifier; no governance execution; no validator-set
rotation; no autonomous apply; no apply-on-receipt; no peer-majority
authority; fixture / local / loopback evidence remains DevNet/TestNet
evidence-only; and no weakening of Runs 070, 130–199. Full C4 remains
OPEN. C5 remains OPEN.

Evidence: see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`,
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`, and
`docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`.
## Run 201 — source/test production RemoteSigner transport boundary

Run 201 adds, in **source/test only**, a typed transport boundary for a
future production RemoteSigner backend. It changes no apply-safety
behavior. The new module
`crates/qbind-node/src/pqc_remote_signer_transport.rs` wraps the Run 194
RemoteSigner request/response in transport envelopes bound to the trust
domain with deterministic transcript digests, a pure/mockable
`RemoteSignerTransport` trait, a DevNet/TestNet-only fixture loopback
transport, a fail-closed production transport, and a typed outcome
taxonomy; the corpus lives in
`crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs`
and the evidence in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_201.md`.

Apply-safety invariants (unchanged):

* Run 201 performs **no apply**. The new module performs no network or
  file I/O, writes no marker or sequence, swaps no live trust, evicts no
  sessions, and never invokes the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering.
* No real RemoteSigner backend, no networked signer daemon, and no
  production signing custody are implemented. The fixture loopback
  transport is DevNet/TestNet evidence only; the production transport is
  unavailable/fail-closed (`ProductionTransportUnavailable` /
  `MainNetProductionTransportUnavailable`). KMS / HSM / cloud-KMS /
  PKCS#11, governance execution, and on-chain proof verification remain
  unimplemented; validator-set rotation remains open.
* There is **no autonomous apply**, no apply-on-receipt, and no
  peer-majority authority. The **Run 147 / 148 / 152 FATAL MainNet
  peer-driven apply refusal** is reasserted: a MainNet peer-driven-apply
  preflight short-circuits to `MainNetPeerDrivenApplyRefused` even with a
  fixture loopback transport configured.
* Run 201 adds no new exit code and no new metric, and does not weaken
  any Runs 070 / 130–200 safety property. Release-binary
  transport-boundary evidence is deferred to **Run 202**. **Full C4
  remains OPEN; C5 remains OPEN.**
## Run 202 — release-binary RemoteSigner transport boundary evidence

Run 202 proves, in **release-binary evidence only**, that the Run 201
production RemoteSigner transport boundary behaves correctly on the real
`target/release/qbind-node` plus a release-built helper. It changes no
apply-safety behavior and makes **no production-source change** (a release
example helper, a release harness, and documentation only). The
deliverables are
`crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs`,
`scripts/devnet/run_202_remote_signer_transport_release_binary.sh`,
`docs/devnet/run_202_remote_signer_transport_release_binary/`, and the
evidence report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_202.md`.

Apply-safety invariants (unchanged):

* Run 202 performs **no apply**. The release helper performs no network
  or file I/O beyond writing evidence files under its output directory,
  writes no marker or sequence, swaps no live trust, evicts no sessions,
  and never invokes the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering.
* No real RemoteSigner backend, no networked signer daemon, and no
  production signing custody are implemented. The release-built helper
  links the production library symbols and confirms in release mode that
  the fixture loopback transport is DevNet/TestNet evidence only and
  refused on MainNet, while the production transport is
  unavailable/fail-closed (`ProductionTransportUnavailable` /
  `MainNetProductionTransportUnavailable`). KMS / HSM / cloud-KMS /
  PKCS#11, governance execution, and on-chain proof verification remain
  unimplemented; validator-set rotation remains open.
* There is **no autonomous apply**, no apply-on-receipt, and no
  peer-majority authority. The **Run 147 / 148 / 152 FATAL MainNet
  peer-driven apply refusal** is reconfirmed at the release binary: a
  MainNet peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a fixture loopback transport
  response.
* The real `target/release/qbind-node` keeps every Run 070 / 130–201
  surface RemoteSigner-transport-silent (no transport / networked-signer /
  KMS / HSM / governance-execution / validator-rotation banner) across
  `--help` and the per-env `--print-genesis-hash` flows, with the Run 198
  RemoteSigner policy selector, Run 193 custody selector, and governance
  fixture flag all remaining compatible.
* Run 202 adds no new exit code and no new metric, and does not weaken any
  Runs 070 / 130–201 safety property. **Full C4 remains OPEN; C5 remains
  OPEN.**

## Run 203 — source/test KMS/HSM backend abstraction boundary

Run 203 adds the typed, provider-neutral KMS/HSM backend abstraction
(`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`) over the Run
188 `AuthorityCustodyClass::{Kms, Hsm}` custody classes, with focused
tests `crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs`
and the evidence report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_203.md`.
It is **source/test only**; the only production-source change is the
additive new module plus its `lib.rs` registration.

Apply-safety invariants (unchanged):

* Run 203 performs **no apply**. Every public function and trait method in
  the new module is pure: it performs no network or file I/O, writes no
  marker or sequence, swaps no live trust, evicts no sessions, and never
  invokes the Run 070 `validate → swap → evict_sessions → commit_sequence`
  ordering.
* **No real KMS backend, no real HSM backend, no cloud-KMS integration,
  and no PKCS#11 integration** are implemented. The fixture KMS/HSM
  backends are DevNet/TestNet source/test only and refused on MainNet; the
  production / cloud / PKCS#11 backends are callable but fail closed
  (`ProductionKmsUnavailable` / `ProductionHsmUnavailable` /
  `CloudKmsUnavailable` / `Pkcs11HsmUnavailable`).
* The **RemoteSigner path (Runs 194–202) remains separate and unchanged**:
  the KMS/HSM custody-class router refuses a `RemoteSigner` custody class
  as `NotKmsHsmCustodyClass`. Local-operator and peer-majority material
  cannot satisfy a backend policy.
* There is **no autonomous apply**, no apply-on-receipt, and no
  peer-majority authority. The **Run 147 / 148 / 152 FATAL MainNet
  peer-driven apply refusal** is preserved: the composition
  `validate_lifecycle_governance_custody_and_backend` short-circuits a
  MainNet peer-driven-apply preflight to `MainNetPeerDrivenApplyRefused`
  even with a valid fixture KMS/HSM response.
* Run 203 adds no new exit code and no new metric, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken any Runs 070 / 130–202
  safety property. Governance execution, real on-chain proof verification,
  and validator-set rotation remain unimplemented/open; release-binary
  KMS/HSM backend-boundary evidence is deferred to **Run 204**. **Full C4
  remains OPEN; C5 remains OPEN.**
## Run 204 — release-binary KMS/HSM backend abstraction boundary evidence

Run 204 closes the Run 203-deferred release-binary boundary for the
production KMS/HSM custody backend abstraction
(`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`) over the Run 188
custody classes. It is **release-binary evidence only**, adding the release
helper
`crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs`,
the release harness
`scripts/devnet/run_204_kms_hsm_backend_release_binary.sh`, the evidence
archive `docs/devnet/run_204_kms_hsm_backend_release_binary/`, and the
report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_204.md`. It makes **no
production-source change** (helper + harness + docs only).

Apply-safety invariants (unchanged):

* Run 204 performs **no apply**. The release helper and harness only link
  and exercise the already-pure Run 203 module in release mode; no public
  function or trait method performs network or file I/O, writes a marker or
  sequence, swaps live trust, evicts sessions, or invokes the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering.
* The real `target/release/qbind-node` is observed to emit **no KMS / HSM /
  cloud-KMS / PKCS#11 / RemoteSigner backend enablement** banner and **no
  MainNet peer-driven apply enablement** on every captured surface
  (`--help`, `--print-genesis-hash --env {devnet,testnet,mainnet}`, with
  the Run 193 custody selector, the Run 198 RemoteSigner selector, and the
  governance fixture flag armed — including on `--env mainnet`).
* **No real KMS backend, no real HSM backend, no cloud-KMS integration, and
  no PKCS#11 integration** are implemented. The fixture KMS/HSM backends
  remain DevNet/TestNet evidence-only and refused on MainNet; the
  production / cloud / PKCS#11 backends fail closed as unavailable.
* The **RemoteSigner path (Runs 194–202) remains separate and unchanged**.
* There is **no autonomous apply**, no apply-on-receipt, and no
  peer-majority authority. The **Run 147 / 148 / 152 FATAL MainNet
  peer-driven apply refusal** is preserved — the release helper confirms a
  MainNet peer-driven-apply preflight short-circuits to
  `MainNetPeerDrivenApplyRefused` even with a valid fixture KMS/HSM
  response, and rejected backend-boundary cases produce no mutation.
* Run 204 adds no new exit code and no new metric, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken any Runs 070 / 130–203 safety
  property. Governance execution, real on-chain proof verification, and
  validator-set rotation remain unimplemented/open. **Full C4 remains
  OPEN; C5 remains OPEN.**
## Run 205 — source/test production custody attestation verifier skeleton

Run 205 adds a typed, mockable verifier skeleton for a production custody
attestation chain
(`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`) layered over
the Run 188 custody classes. It is **source/test only**, adding the new
module (plus its `lib.rs` registration), the tests
`crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`,
and the report `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_205.md`.

Apply-safety invariants (unchanged):

* Run 205 performs **no apply**. The new module is pure: no public
  function or trait method performs network or file I/O, writes a marker
  or sequence, swaps live trust, evicts sessions, or invokes the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering.
* **No real cloud-KMS attestation verifier, no real PKCS#11 attestation
  verifier, no real HSM vendor attestation verifier, and no real
  RemoteSigner attestation verifier** are implemented. The fixture
  attestation remains DevNet/TestNet evidence-only and is refused on
  MainNet; the production / cloud / PKCS#11 / HSM-vendor / RemoteSigner
  attestation verifiers are callable but fail closed as the matching
  typed unavailable outcome.
* The **RemoteSigner path (Runs 194–202)** and the **KMS/HSM backend path
  (Runs 203–204)** remain separate and unchanged.
* There is **no autonomous apply**, no apply-on-receipt, and no
  peer-majority authority. The **Run 147 / 148 / 152 FATAL MainNet
  peer-driven apply refusal** is preserved — the composition helpers
  `validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation` short-circuit a MainNet
  peer-driven-apply preflight to `MainNetPeerDrivenApplyRefused` before
  consulting custody or attestation, even with a valid fixture
  attestation, and rejected attestation cases produce no mutation. The
  fixture attestation cannot satisfy a production attestation policy, and
  neither a local operator nor a peer majority can satisfy production
  attestation.
* Run 205 adds no new exit code and no new metric, and no CLI / env /
  sidecar / marker / sequence-file / authority-marker / trust-bundle core
  / wire / schema change, and does not weaken any Runs 070 / 130–204
  safety property. Governance execution, real on-chain proof
  verification, and validator-set rotation remain unimplemented/open.
  Release-binary custody-attestation verifier-boundary evidence is
  deferred to **Run 206**. **Full C4 remains OPEN; C5 remains OPEN.**
