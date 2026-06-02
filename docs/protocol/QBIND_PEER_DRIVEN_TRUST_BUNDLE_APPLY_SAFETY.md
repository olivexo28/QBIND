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