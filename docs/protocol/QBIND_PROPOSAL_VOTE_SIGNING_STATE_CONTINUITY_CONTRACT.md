# QBIND Proposal / Vote Signing-State Continuity Contract

**Run:** 422 D7-D9
**Status:** Source inspection and protocol definition only. No Rust, test,
dependency, storage key/schema, CLI flag, configuration, workflow, wire-format,
signing-preimage, or activation change is made or proposed for implementation in
this phase. This document *defines* a durable signing-state continuity protocol;
it does **not** implement one, does not enable signing, and does not move any
readiness item to Green.

```
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved, not reopened)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This is the single authoritative contract for **preserving a validator's
safety-relevant Proposal / Vote signing decisions across restart** and for
**identifying the additional protection required against restoration of older
storage**. It is the peer of, and defers to, the authority
lifecycle contract (`QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`) for
the three distinct security requirements it names — **(A) activation
authorization**, **(B) current-authority freshness**, **(C) signing /
consensus-state continuity**. This contract elaborates requirement **(C)** only;
it never establishes (A) or (B), and a signing record alone establishes neither.

**Unresolved dependencies (stated prominently, up front):**

* **Durable anti-rollback anchor: UNRESOLVED.** No repository mechanism today
  supplies an authenticated, rollback-resistant, freshness-bearing external
  commitment for signing history. Selection is left explicitly open (§6.6).
* **Consensus-lock recovery: DEPENDENCY, NOT SOLVED HERE.** Preventing
  conflicting signatures at one position does not by itself restore the HotStuff
  locking rule across later views (§6.7). Timeout / NewView compatibility is an
  explicit, unmigrated dependency.
* Design completion of this contract does **not** establish operational
  signing-state continuity, power-loss durability, or production authority
  readiness. C4/C5 remain OPEN. No activation, readiness promotion, or Run 423
  work is authorized or implied.

---

## 1. Inspected revision and source limitations

Inspected against the **actual supplied worktree**, not the SHAs the task
recites.

* **Working branch (actual):** `copilot/run-422-d7-d9`
  (`git branch --show-current`). Used unchanged; no rename, rebase, force-push,
  or history rewrite.
* **Starting worktree HEAD (actual, full SHA):**
  `c9025f2f3db06c2a0f1ec5e69514c29bb1fce035` (`update`). Worktree clean before
  this documentation pass.
* **Reviewed D7-D8 objects named by the task:**
  * Accepted final `9979c1ef43ce14346b47411d228edcab4afe8e61`: **object absent**
    from this shallow clone (`git cat-file -t` → *could not get object info*);
    not in local ancestry; not referenced by any tracked file.
  * Test checkpoint `1942c7a89c8871757d26bb2bc59a90573cc006e1`: **object absent**
    from this clone.
  * Release-build source `2aadc012693d3282146b49f16f19cd0a7aca5821`: **present**
    (it is the immediate parent of `c9025f2`).
* **Ancestry to an absent object is not manufactured.** For the two absent
  objects, correspondence is asserted only against the *content* of the current
  worktree (D7-D8 restore-completion implementation and its release-binary
  evidence, recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and
  `docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md`), not against a
  claimed commit chain.
* **Absence findings are scoped to the paths actually inspected** (below). No
  claim is made about paths outside this checkout.

### 1.1 Source references anchoring this contract (worktree HEAD)

All line numbers are against the inspected `c9025f2` worktree.

* Outbound signing path, `crates/qbind-node/src/binary_consensus_loop.rs`:
  * `forward_actions_to_facade` (L4101) — orchestrates `BroadcastProposal`,
    `BroadcastVote`, `SendVoteTo`.
  * `admit_outbound_action` (L3852) — pre-sign current-authorization + epoch
    gate; returns `(signer_ctx, ticket)`.
  * `sign_proposal_for_broadcast` (L3646), `sign_vote_for_broadcast` (L3733) —
    wire-chain-id check then `signer.sign_proposal` / `sign_vote` over the
    domain preimage.
  * `confirm_outbound_before_effect` (L3913) — re-confirms the ticket **after**
    signing, before the facade call; returns `false` to suppress the *effect*
    only.
  * `maybe_reemit_on_late_peer_connect` (L3379), `CachedReemissionProvenance`
    (L3122), `admit_cached_reemission` (referenced from L3247/L3282 capture
    sites) — cached late-peer re-emission with provenance binding.
  * `AuthorizedProposalVoteSnapshot` (L1182: `try_bind`, `owner`, `verifier`,
    `authorized_epoch`), `ProposalVoteAuthority` (L1053: `proposal_preimage`,
    `vote_preimage`, `wire_chain_id_ok`).
* Authority ownership, `crates/qbind-node/src/genesis_consensus_authority.rs`:
  `CurrentAuthorizationOwner` (`admit` / `confirm` / `generation` /
  `is_exhausted`), `AuthorizationTicket` (`generation`, `issued_by`).
* Signer, `crates/qbind-node/src/validator_signer.rs`: `trait ValidatorSigner`
  (L98: `validator_id`, `suite_id`, `sign_proposal`, `sign_vote`, `sign_timeout*`),
  `LocalKeySigner`, `make_local_validator_signer`.
* D6 verification, `crates/qbind-consensus/src/proposal_vote_verify.rs`:
  `verify_proposal_msg_with_domain`, `verify_vote_msg_with_domain` over
  `ProposalVoteSigningDomainV2` (documented in
  `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md`).
* Engine, `crates/qbind-consensus/src/basic_hotstuff_engine.rs`:
  `voted_in_view` (L317), `proposed_in_view`, `timeout_emitted_in_view`,
  `locked_qc` (L968), `initialize_from_restart` (L1134),
  `initialize_from_snapshot_baseline` (L1201).
* Recovery, `crates/qbind-node/src/hotstuff_node_sim.rs`
  `load_persisted_state` (~L2035, harness) vs `crates/qbind-node/src/main.rs`
  restore path + `initialize_from_snapshot_baseline` call
  (`binary_consensus_loop.rs` ~L2390, production).
* Storage, `crates/qbind-node/src/storage.rs`: `trait ConsensusStorage` (L142)
  with `get_current_epoch` (L200), `put_current_epoch_synced` (L224),
  `flush_epoch_durable` (L242), schema/atomic-transition methods; RocksDB impls
  (L1012 / L1041). **No signing-decision persistence method exists on this
  trait.**
* Test-only durable backend,
  `crates/qbind-node/src/pqc_governance_production_durable_replay_rocksdb.rs`
  (Run 291): atomic-write + anti-equivocation + partial-residue recovery,
  disabled-by-default, **no** DB-wide monotonic/anti-rollback counter.
* Prior characterization: `crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs`
  (D7-D2) — reused as evidence, not re-derived here.

---

## 2. Scope, preserved verdicts, and reuse boundaries

### 2.1 What is preserved unchanged (not reopened)

D7-D8's restore-admission and startup-containment result stands at its actual
revision and evidence: `D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`.
That result does **not** establish signing-state continuity, power-loss
durability, durable anti-rollback, or production authority readiness. This
contract does not repeat D7-D8 tests, re-run its release build, or re-derive the
D7-D2 characterization (repeated engine decisions across restart; fixture-level
conflicting-signature capability). Those are cited as inputs.

### 2.2 Reuse table

Format: existing mechanism → actual callers → property established → reuse limit
→ missing requirement.

| Existing mechanism | Actual callers | Property established | Reuse limit | Missing requirement |
|---|---|---|---|---|
| `admit_outbound_action` / `confirm_outbound_before_effect` (`binary_consensus_loop.rs` L3852/L3913) | `forward_actions_to_facade` (L4101) | Current-authority + epoch gate around each outbound action; ticket generation binding | Confirm runs **after** signing (L4148); it can suppress the *effect*, never un-sign | A durable reservation **before** `signer.sign_*` is invoked |
| `ValidatorSigner::sign_proposal` / `sign_vote` (`validator_signer.rs` L114/L125) | `sign_proposal_for_broadcast` (L3708) / `sign_vote_for_broadcast` (L3787) | Produces the signature over the D6 preimage | No persistence, no conflict check, no retry identity | Fail-closed persisted reservation guarding every call to this method |
| `ProposalVoteAuthority` + `ProposalVoteSigningDomainV2` (L1053; domain v2) | signing + `verify_*_with_domain` | Canonical, versioned preimage bound to network/genesis/epoch/suite | Preimage is computed, never stored as a decision record | A stored *authorized-decision* identity derived from the same domain |
| `verify_proposal/vote_msg_with_domain` (`proposal_vote_verify.rs`) | inbound handlers, QC verify | Signature/membership/suite verification | Verifies a message; does not record that *we* signed | Local durable record that a position was reserved/signed |
| `voted_in_view` / `proposed_in_view` latches (`basic_hotstuff_engine.rs` L317) | engine tick / view advance | In-memory single-vote / single-proposal per view | Reset on view advance; **lost on restart** | Durable per-position anti-equivocation record surviving restart |
| `initialize_from_restart` (L1134) / `initialize_from_snapshot_baseline` (L1201) | harness `load_persisted_state`; production restore path | Committed prefix + (harness) QC-reconstructed lock | No channel for an *uncommitted* vote / per-view record; snapshot path recovers **no** lock | Recovery input that re-establishes lock **and** signing reservation before signing resumes |
| `get_current_epoch` / `put_current_epoch_synced` / `flush_epoch_durable` (`storage.rs` L200/L224/L242) | epoch commit + D8 restore completion | Synced epoch write + durability barrier exist today | Epoch value is a coarse authority marker, not a signing decision | These operations do **not** persist signing decisions (see §2.4) |
| `apply_epoch_transition_atomic` + schema guards (`storage.rs`) | epoch transitions | Atomic multi-key write within one DB | Atomicity within a single RocksDB; no external freshness | Cross-store ordering + anti-rollback anchor |
| Run 291 durable replay backend (`pqc_...durable_replay_rocksdb.rs`) | tests only (Run 291) | Atomic-write, idempotency, anti-equivocation, partial-residue recovery | Disabled-by-default, MainNet-refused, **no** DB-wide monotonic/anti-rollback counter | A production, signing-scoped journal + independent anchor |
| D7-D8 restore-completion (RTR + advisory `flock`) | startup / restore admission | Restore-transaction containment; single destination-lock writer | Lock guards a **destination directory**, not copied keys / another host / a bypassing caller | Exclusivity bound to the guarded *signing* path and key |

### 2.3 Duplication guardrails

* This contract is **not** a second authority over requirements (A) or (B); it
  extends only requirement (C) of
  `QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`. Where the two overlap,
  the lifecycle contract governs activation/freshness and this contract governs
  signing-state continuity records and their recovery.
* No equivalent signing-state continuity contract, signing journal,
  anti-equivocation record, signer-fencing document, or durable-signing recovery
  contract exists under `docs/` (searched: `docs/protocol`, `docs/devnet`,
  `docs/whitepaper`). The only durable-record backend in the tree is Run 291's
  test-only replay store, which is not a signing journal and is reused only as
  the "atomic-write without anti-rollback" reference.

### 2.4 Correction of the obsolete "no synced operation" claim

The storage interface **does** expose `put_current_epoch_synced` (L224) and
`flush_epoch_durable` (L242). Any prior statement that consensus storage exposes
no synced/durable operation is obsolete and is not repeated here. However, those
epoch operations persist a coarse **epoch** value only; they do **not** persist
any Proposal/Vote signing decision, per-view reservation, or anti-equivocation
record. Requirement (C) is therefore still unmet by existing storage.

### 2.5 Traced signing routes and reachability classes

Every relevant Proposal/Vote signing route passes through
`forward_actions_to_facade` and the `admit → sign → confirm → facade` sequence:

| Route | Path | Reachability |
|---|---|---|
| Leader proposal broadcast | `BroadcastProposal` arm (L4116) → admit/sign/confirm | Production-reachable (Required policy, `None` snapshot → fail-closed today) |
| Broadcast vote (incl. leader self-vote) | `BroadcastVote` arm (L4170) | Production-reachable |
| Directed vote | `SendVoteTo` arm (L4224) | Production-reachable |
| Cached late-peer re-emission | `maybe_reemit_on_late_peer_connect` (L3379) + `admit_cached_reemission` | Conditionally reachable (in-process cache; per-view single-shot) |
| `LocalFixtureUnsigned` passthrough authority | `pv_authority` arg consulted only when no snapshot wired | Fixture-only (test policy) |

Immediate forwarding, leader/self-vote handling, directed votes, and cached
re-emission all reach `signer.sign_*`. Under production `Required` policy the
snapshot is `None`, so all routes fail closed **today**; this contract specifies
the reservation that must guard each route **when signing is later enabled**.

---

## 3. Safety invariant, conflict rule, and record semantics

### 3.1 The durable-before-sign safety invariant

> **INV-1 (durable-before-sign).** For every Proposal/Vote signing route, a
> durable, fail-closed **reservation** of the exact authorized signing decision
> MUST be committed to stable storage and its durability barrier acknowledged
> **before** `ValidatorSigner::sign_proposal` / `sign_vote` is invoked. If the
> reservation cannot be established (failure or uncertainty), **zero** signer
> invocations occur.

Confirmation (`confirm_outbound_before_effect`, L3920) already runs after
signing and can only suppress the network effect; it cannot un-sign. INV-1
inserts the missing exclusive reservation *before* the signer call, at the
linearization point defined in §5.

### 3.2 The conflict rule (derived from consensus rules, not invented)

The conflict rule is **derived from the existing HotStuff decision rules**, not
a generic "one signature per height." Two signing decisions **conflict** when
they occupy the same **consensus voting position** for the same stable validator
identity in the same network/authority context, yet bind different signed
content.

**Stable validator identity and context.** Identity is the validator's genesis-
membership identity as expressed by `ValidatorId` + the `ProposalVoteSigningDomainV2`
binding (network / genesis identity / authority commitment / authorized epoch /
membership / key / suite / message version). A **new OS process, a new in-process
`CurrentAuthorizationOwner` generation, a new PID, or a new caller label is NOT a
fresh validator identity** and MUST NOT open a new conflict namespace.

**Conflict-identifying fields (the position key).** Two decisions are compared on:

* validator identity (as above);
* consensus **step / kind**: Proposal vs Vote (distinct sub-namespaces);
* the consensus **view/round** and the **height** the message commits to (for a
  Vote, the voted block's height/round as the engine assigns them; for a
  Proposal, the proposed height/round);
* the network/genesis/authority-epoch context.

**Binding (exact-message) fields.** The stored record additionally binds the
fields that identify the *exact* authorized message: the block identifier being
voted for / proposed, the attached justification (QC) identity, and the domain-
canonical preimage bytes after permitted suite preparation **before** signing
(the same input `signer.sign_*` receives). A change to a **binding** field at the
same **position key** is a conflict, not a new namespace.

**Proposal vs Vote and legitimate combinations.** A leader legitimately produces
one Proposal and one self-Vote at the same view; these are distinct kinds and do
**not** conflict with each other. Two Votes at the same position for different
blocks conflict. A directed vote and a broadcast vote for the **same** position
and block are the **same** decision (exact retry, §3.5), not a conflict.

**Non-bypass rule.** A changed block identifier, height, step, suite, key, owner
generation, process identifier, or caller label MUST NOT create a namespace that
evades the position key. Only a change that legitimately creates a **new
authorization context** — a different network/genesis, a different authorized
epoch under a validated authority transition, or a different membership/key under
a validated rotation — creates a new conflict namespace, and only when the
lifecycle contract's requirement (A)/(B) has independently authorized it.

### 3.3 The signing-decision record (proposed representation)

The record is **proposed, not implemented**. It MUST be:

* **Bounded and versioned:** fixed maximum size, an explicit format-version
  field; unknown/incompatible versions are refused fail-closed.
* **Checked arithmetic:** all counters/lengths use checked/saturating
  operations; overflow is a fail-closed terminal state, never wraparound.
* **Integrity-checked:** a checksum over the record detects truncation/corruption.
  The checksum is a **corruption detector only** — it is explicitly **not**
  authentication and **not** rollback protection.
* **Fail-closed on malformed input:** any undecodable, truncated, or unsupported
  record makes the covered position **potentially-signed** (refuse to sign),
  never "assume unused."

Record fields (conceptual): format version; validator identity + domain binding
digest; position key (kind, view/round, height, epoch, network/genesis/authority
context); binding digest (block id + justification id + preimage digest);
lifecycle stage (§3.4); optional retained signature/result for exact retry;
checksum.

### 3.4 The signing-state machine (per position)

Small state machine, per position key:

1. **NONE** — no prior reservation for this position.
2. **RESERVED** — a durable reservation for exactly one decision at this
   position is committed and its durability barrier acknowledged.
3. **SIGNING** — signer invocation has been attempted; whether a signature was
   produced is not yet durably known.
4. **SIGNED (result retained, optional)** — a signature/result exists; the
   canonical authorized decision is retained for exact-retry resend.
5. **REFUSED** — a conflicting decision, or an unverifiable/malformed request,
   is fail-closed refused; the reservation is not released.

Permitted transitions: `NONE → RESERVED → SIGNING → SIGNED`; any state → `REFUSED`
on conflict/malformed. There is **no** transition back to `NONE` by erasing a
reservation because signing failed, authority changed, confirmation failed,
transmission failed, or an acknowledgement was lost. Once state may have reached
`SIGNING`, recovery treats the position as **potentially SIGNED** (§6).

### 3.5 Retry policy (chosen and justified)

* **Exact retry** is compared using the **canonical authorized decision** (the
  position key + binding digest), **never** signature-byte equality —
  signatures are not assumed deterministic. An exact retry at `SIGNED` **resends
  the retained signature**; it does **not** re-invoke the signer.
* **Conflicting retry** (same position key, different binding digest) is
  **REFUSED**.
* **Initial policy:** *resend-only after signing may have occurred.* If the
  record is `RESERVED` but no signer result is retained and it cannot be
  established that the signer was never invoked, the request is **refused**
  rather than re-signing or releasing the reservation. Re-invoking the signer is
  permitted only from `RESERVED` with positive evidence that no prior invocation
  occurred (§6 matrix). "Resending an existing signature" and "invoking the
  signer again" are distinct operations and are never conflated.

---

## 4. Ordering, serialization, and failure behavior

### 4.1 One explicit proposed sequence (per outbound signing action)

1. **Authorization + context checks (existing):** `admit_outbound_action`
   (L3852) — current-authority `admit()` + epoch equality against
   `authorized_epoch()`; obtain `(signer_ctx, ticket)`.
2. **Final signed-field preparation (existing):** compute the domain-canonical
   preimage via `ProposalVoteAuthority::proposal_preimage` / `vote_preimage`
   after wire-chain-id validation.
3. **Conflict lookup + exclusive reservation (new):** derive the position key
   and binding digest; look up existing record; if a conflicting record exists →
   **REFUSE**; otherwise reserve exclusively (`NONE → RESERVED`).
4. **Durable reservation acknowledgement (new):** commit the reservation with a
   synced write and an acknowledged durability barrier (the semantic already
   available via `put_current_epoch_synced` / `flush_epoch_durable` for epochs
   is the model; a signing-scoped store is required). No barrier ack ⇒ treat as
   uncertain ⇒ **no signer call**.
5. **Authorization revalidation after storage waits (new):** because the storage
   commit may block, re-check current authorization (re-`admit` / generation
   unchanged) before signing; a superseded authority ⇒ refuse to sign (the
   reservation is retained).
6. **Signer invocation (existing):** `signer.sign_*` over the prepared preimage
   (`SIGNING`; on success, `SIGNED` + retained result).
7. **Result handling (new + existing):** persist the signed/`SIGNED` marker;
   retain the canonical decision for exact-retry resend.
8. **Confirmation before facade handoff (existing):** `confirm_outbound_before_effect`
   (L3913) — suppress the effect if authority changed; does not un-sign.
9. **Transmission / re-emission (existing):** facade `broadcast_*` / directed
   send; cached re-emission stays bound to the recorded decision and re-passes
   current-authorization checks.

**Serialization boundary and linearization point.** Today the outbound handler
runs on a single serialized consumer of engine actions
(`forward_actions_to_facade` iterates actions sequentially, no concurrent
mutation in the current handler). The **linearization point** for a decision is
the acknowledged durable reservation at step 4: exactly one decision per position
can pass step 3→4, and the signer at step 6 is reached only after that point.

### 4.2 Concurrency and single-writer

* **Preserve current handler assumptions:** do not invent concurrent mutation
  that today's serialized handler does not have.
* **Future crossings:** if future storage I/O, async work, or another signing
  caller is introduced, the reservation/signing boundary MUST be protected so
  that no two callers cross step 3→6 for the same position; the single durable
  writer + exclusive reservation is the enforcement point. A second signing
  caller that bypasses the guarded path is outside the guarantee and MUST be
  prevented structurally (single guarded signing entrypoint), not assumed away.
* **Single-writer scope and its limit:** D8's advisory destination `flock`
  serializes writers to one destination directory; it does **not** establish
  exclusivity for a **copied key**, **another directory**, **another host**, or a
  caller that bypasses the guarded signing path. Signer exclusivity must be bound
  to the key + guarded signing entrypoint, and this is an explicit unmet
  requirement for multi-host / cloned-key cases (§6).

### 4.3 Required failure rules

* Failure or uncertainty establishing a durable reservation ⇒ **zero** signer
  invocations.
* Concurrent conflicting requests cannot both obtain permission (exclusive
  reservation at the linearization point).
* A reservation is **not** erased because signing fails, authority changes,
  confirmation fails, transmission fails, or an acknowledgement is lost.
* After signer invocation may have occurred, recovery conservatively treats the
  decision as **potentially signed**.
* **No fallback** to an unprotected signer or a legacy digest.
* Cached re-emission stays bound to the recorded decision and must pass current
  authorization checks.
* **Signing permission does not arise from the persistence record alone** — the
  record is a *guard*, not an *authorization*; requirements (A)/(B) must hold
  independently.

### 4.4 Latency / throughput

Adding a synced durable reservation before each signature adds one storage-sync
latency per decision. No benchmarks are invented. Any future batching MUST
preserve durable-before-sign ordering for **every** member of the batch (no
signature may precede its own reservation's durability ack). Optimization is
deferred unless required for correctness.

---

## 5. Crash recovery, rollback resistance, and consensus recovery (kept distinct)

The three lifecycle requirements are kept separate: **(A) activation
authorization**, **(B) current-authority freshness**, **(C) signing /
consensus-state continuity**. A signing record establishes neither (A) nor (B).

### 5.1 First-use vs lost-state problem

An **empty** signing store MUST NOT automatically mean a previously used
validator key is unused. "Never signed before" (legitimate first use) and "signed
before but the record was lost/rolled back" are indistinguishable from local
state alone. Distinguishing them requires **trusted external evidence** (an
anchor, §6) that binds the validator/network to a signing-history commitment.
Absent that evidence, first initialization over a non-empty key is **ambiguous**
and MUST be treated fail-closed (refuse to sign) until an activation gate
resolves it.

### 5.2 Failure / recovery matrix

For each row: observable state → permitted action → refused action → supporting
assumption.

| # | Scenario | Observable state | Permitted | Refused | Assumption |
|---|---|---|---|---|---|
| 1 | Failure **before** reservation persistence | No durable record | Retry reservation | Any signer call | Sync not acknowledged ⇒ never signed |
| 2 | Reservation write / barrier failure or **uncertain** completion | Record may or may not exist | Treat as RESERVED-or-worse; may retry reservation idempotently | Signer call until a clean RESERVED is confirmed | Uncertainty ⇒ potentially reserved, not signed |
| 3 | Crash **after** durable reservation, **before** signing | RESERVED, no result | Resume: re-validate auth, then sign once | Signing a *different* decision at this position | RESERVED binds exactly one decision |
| 4 | Crash **during** signing / after signature, before result persistence | SIGNING (result unknown) | Resend only if a retained result exists; else refuse | Re-invoking signer; releasing reservation | Potentially-signed ⇒ conservative |
| 5 | Confirmation / handoff failure after signing | SIGNED, effect suppressed | Exact-retry resend of retained signature | Signing a new decision | Confirm suppresses effect, not signature |
| 6 | Exact retry | Matching position key + binding digest | Resend retained signature | Re-signing | Canonical-decision equality, not byte equality |
| 7 | Conflicting retry | Same position key, different binding | Refuse | Any signature | Conflict rule §3.2 |
| 8 | Missing / malformed / truncated / incompatible record | Undecodable | Refuse (fail-closed) | Assuming unused | §3.3 |
| 9 | Ordinary restart, valid records | Consistent RESERVED/SIGNED set | Resume per state machine | Ignoring records | Local synced journal covers ordinary crash |
| 10 | Restoration of an **older account snapshot** while newer signing records remain | Snapshot epoch < journal records | Refuse to sign at superseded positions; require anchor to resolve | Signing from stale snapshot | Same-epoch/older snapshot must not un-record newer decisions |
| 11 | Restoration of the **entire** signing-state directory (older copy) | All local references older, internally consistent | Refuse until anchor confirms latestness | Trusting the restored journal as current | Local journal cannot self-detect a whole-copy rollback (§6.5) |
| 12 | Two instances using the **same** validator key | Two guarded signers, same key | At most one may hold exclusivity; other must refuse | Both signing | D8 lock does not cover copied keys/hosts (§4.2) |

### 5.3 Consensus-lock recovery is a separate requirement

Preventing conflicting signatures at one position does **not** preserve the
HotStuff locking rule across later views. On restart:

* The harness path (`load_persisted_state`) reconstructs a lock conservatively
  from the committed block's embedded QC; the production snapshot-baseline path
  (`initialize_from_snapshot_baseline`, L1201) recovers **no** lock and resumes
  unlocked above the snapshot anchor.
* Per D7-D2, neither recovery entrypoint carries a channel for an *uncommitted*
  vote or per-view anti-equivocation record.

Therefore, before signing may resume after restart, the safety state that MUST
be recovered (or signing MUST be refused until it is) includes: the current
`locked_qc` sufficient to enforce the lock rule for future votes, **and** the
signing reservations for any in-flight position. **A high-water mark alone does
not recover a lock.** Timeout / NewView compatibility is an explicit dependency;
no migration or redesign is performed here.

---

## 6. Rollback resistance and the anchor requirement

### 6.1 Crash-consistency vs rollback-resistance (do not conflate)

A **local synced journal** (RESERVED/SIGNED records written with an acknowledged
durability barrier) can address **ordinary crash recovery** under stated
filesystem/storage assumptions (fsync honored; no silent device rollback). It
**cannot** detect restoration of a complete older copy when every reference it
trusts (including the journal itself) was restored too. Crash-consistency is
therefore an independently useful, **non-authorizing** component; it is **not**
full rollback protection and must never be labeled as such.

### 6.2 The independent continuity (anti-rollback) requirement

To resist rollback, an **independent** commitment is required. Concretely it must
answer:

* **Outside the attacker's rollback domain:** what state is *not* restorable by
  the specified attacker (e.g., an external, append-only or monotonic authority
  the local host cannot rewind)?
* **Authentication:** how is that state authenticated (a real cryptographic
  verification against a pinned trust root — **not** a source label, which is not
  authenticated provenance)?
* **Binding:** what validator/network identity and **signing-history commitment**
  does it bind (must bind this validator + network + a monotonic signing-history
  value, not merely an epoch)?
* **Freshness / monotonicity / exclusive use:** how are latestness, monotonic
  advance, and single-writer/exclusive use established?
* **Ordering of local-record vs anchor updates:** which is written first, and
  what is the recovery rule if one succeeds and the other fails?
* **Availability:** behavior during anchor unavailability, partition, cold start,
  or all-validator restart.

### 6.3 What is insufficient (explicit)

* An **epoch-only witness** is insufficient (epoch is coarse and does not commit
  signing history).
* A **valid historical QC** does not prove latestness and does not preserve an
  uncommitted signing decision.
* A **source label / provenance string** is not authenticated provenance.
* A **checksum** is corruption detection, not rollback protection.

### 6.4 Existing options evaluated first

* Run 291 durable replay backend: atomic-write + anti-equivocation, but
  **no DB-wide monotonic/anti-rollback counter and no external anchor** — an
  older-but-valid DB is accepted on open. Insufficient as an anchor.
* D8 restore-completion + advisory `flock`: contains interrupted restores and
  serializes one destination writer; does **not** authenticate latestness or
  cover copied keys / other hosts. Insufficient as an anchor.
* `put_current_epoch_synced` / `flush_epoch_durable`: durability barrier for a
  coarse epoch; not a signing-history commitment. Insufficient as an anchor.

### 6.5 Ordering and partial-failure (when an anchor is later chosen)

Local record and anchor updates MUST be ordered so that neither a lost local
record nor a lost anchor update can license a conflicting future decision:
reserve locally (durable) → advance the anchor monotonically → then sign. If the
anchor advance succeeds but the local record is lost, recovery treats the
position as potentially-signed (refuse). If the local record persists but the
anchor advance is uncertain, refuse until the anchor is reconciled. During anchor
unavailability / partition / cold start / all-validator restart, **refuse to
sign** rather than proceed on stale local state.

### 6.6 Anchor recommendation — EXPLICITLY UNRESOLVED

The repository and current evidence do **not** justify selecting a concrete
rollback-resistant mechanism. Classical signatures, hardware-attestation roots,
external chains, cloud services, and a centralized signer each introduce distinct
cryptographic, operational, availability, and decentralization assumptions and
are **not** silently introduced here. Selection is left **explicitly unresolved**.
The unsatisfied activation gate is: *an authenticated, rollback-resistant,
freshness-bearing external anchor binding this validator/network to a monotonic
signing-history commitment.* No "authenticated witness" is invented that no
implementation can supply.

### 6.7 Consensus-recovery dependency (restated)

Signing may resume only after the HotStuff lock state required for safe future
voting is recovered (or signing is refused until it is), independently of the
anchor question. This is a dependency on the engine recovery entrypoints
(§5.3), not solved by the signing journal.

---

## 7. Future acceptance evidence and one bounded successor

### 7.1 Future acceptance matrix (not executed here)

These are **future** controls, not newly executed claims:

* Proposal positive control; Vote positive control.
* Exact retry (resend, no re-sign) and conflicting retry (refuse).
* Repeated view with changed message/binding fields that must **not** evade
  conflict detection.
* Signing-persistence failure with **direct zero-backend-call** assertions on
  the signer.
* Durable reservation followed by process death **before** signing (resume-sign
  once).
* Signature completion followed by failure **before** handoff (exact-retry
  resend only).
* Conflicting callers and cloned-validator-instance limits.
* Wrong network / domain / epoch / key association (refuse).
* Missing / corrupt records and ambiguous first initialization (fail-closed).
* Same-epoch older-snapshot rollback and whole-directory rollback (refuse
  pending anchor).
* Consensus-lock recovery prerequisites (refuse to sign until lock recovered).
* Authority revocation / supersession during the proposed I/O boundary (refuse
  to sign; reservation retained).
* Cached re-emission bound to the recorded decision.
* Bounded storage, overflow (checked arithmetic → fail-closed), and any pruning
  rule.

**Retention / pruning.** A record may be discarded only if it can be shown it can
**never** permit a conflicting future decision (e.g., the position is provably
below a committed, lock-protected watermark that future votes cannot revisit). If
that cannot yet be established, pruning is **deferred**; a bounded fail-closed
**exhaustion** policy applies (refuse to sign on store exhaustion) rather than
promising unlimited growth.

### 7.2 Evidence levels (kept separate)

`source contract → unit / injected-failure tests → real-storage restart →
release executable → multi-process / network → power-loss / rollback testing.`
Process termination is **not** power-loss evidence. An isolated test signer is
**not** configured production authority. A CodeQL scope skip is not a security
pass; a reviewer backend/model error is not a completed independent review.

### 7.3 Exactly one bounded successor task

**Successor (D7-D10 candidate): a non-authorizing, crash-consistent local
signing-reservation journal — source + tests only.**

* **Extends:** `crates/qbind-node/src/storage.rs` (a new *disabled-by-default*,
  signing-scoped record store modeled on the Run 291 atomic-write backend, using
  the existing synced-write / durability-barrier semantics), consulted from a
  single guarded signing entrypoint refactor around
  `binary_consensus_loop.rs::forward_actions_to_facade` (L4101) so the reservation
  sits **before** `sign_proposal_for_broadcast` / `sign_vote_for_broadcast`.
* **Prerequisites:** the conflict rule (§3.2), record/state machine (§3.3–3.4),
  and durable-before-sign ordering (§4.1) in this contract; no change to
  authority activation (A) or freshness (B).
* **Proposed tests:** the §7.1 rows reachable **without** an anchor — positive
  controls, exact/conflicting retry, zero-backend-call on persistence failure,
  reserve-then-process-death, malformed/missing records, bounded/overflow
  exhaustion, and single-guarded-entrypoint coverage.
* **Explicit exclusions:** the anchor (§6.6), whole-copy/cross-host rollback
  detection, consensus-lock recovery redesign, Timeout/NewView migration,
  enabling signing, and any activation/readiness change. This component is
  independently testable and **non-authorizing**; it is crash-consistency only
  and MUST NOT be called full rollback protection.

The successor **implementation is not begun** in this task.

---

## 8. Validation performed and retained posture

### 8.1 Checks actually performed (documentation-only)

* Verified cited paths, symbols, and caller relationships against the inspected
  `c9025f2` checkout (function line numbers in §1.1; ordering in
  `forward_actions_to_facade` L4114–4160 confirms admit→sign→confirm→facade).
* Confirmed the storage trait exposes `put_current_epoch_synced` (L224) /
  `flush_epoch_durable` (L242) and **no** signing-decision method (§2.4).
* Reviewed each state transition (§3.4) and failure-matrix row (§5.2) for
  contradictory instructions; each provenance/freshness comparison in §6 names an
  actual independent input or is marked unresolved.
* Checked authorized diff scope (documentation only), links, whitespace, and
  file-specific line endings (CRLF preserved for edited `docs/protocol` and
  `docs/devnet` files; `task/warning.txt` and unrelated files untouched).
* No Cargo tests, Clippy, or release rebuild are required for these Markdown
  changes, and none are claimed as new execution evidence. D7-D8 accepted
  evidence and historical results are preserved at their actual revisions and not
  re-run.
* Secret scan run over the changed files; outcome reported literally in the
  evidence section.

### 8.2 Scoped verdict and retained posture

```
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

**Unresolved dependencies (prominent):** the durable anti-rollback **anchor** is
unresolved (§6.6) and **consensus-lock recovery** is an unmet prerequisite
(§5.3 / §6.7). Design completion of this contract does **not** establish
operational signing-state continuity. C4/C5 remain OPEN. No activation, readiness
promotion, or Run 423 work is authorized. The bounded successor (§7.3)
implementation is **not** begun.
