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