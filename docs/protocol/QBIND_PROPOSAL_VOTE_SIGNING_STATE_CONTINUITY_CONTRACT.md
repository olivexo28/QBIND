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
  supplies an authenticated, rollback-resistant, freshness-bearing commitment for
  signing history **outside the attacker's rollback domain** (a protected local
  hardware mechanism or a remote witness — neither selected, implemented, or
  proven). Selection is left explicitly open (§6.6).
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

**Not every signing route passes through `forward_actions_to_facade`.** Two caller
families reach the shared signing helpers `sign_proposal_for_broadcast` (L3646) /
`sign_vote_for_broadcast` (L3733): the immediate-forwarding family (inside
`forward_actions_to_facade`, L4101) and the **cached re-emission** family
(`maybe_reemit_on_late_peer_connect`, L3379), which performs its **own**
`admit_cached_reemission` (L3989) → `sign_*_for_broadcast` →
`confirm_outbound_before_effect` cycle and does **not** call
`forward_actions_to_facade`. A guard wrapped around `forward_actions_to_facade`
alone would therefore miss the cached-re-emission callers.

| Caller | Entry | Shared helper | Through `forward_actions_to_facade`? | Reachability |
|---|---|---|---|---|
| Immediate Proposal forwarding | `BroadcastProposal` arm (L4116) | `sign_proposal_for_broadcast` (L3646) | Yes | Production-reachable (`Required`, `None` snapshot → fail-closed today) |
| Broadcast Vote | `BroadcastVote` arm (L4170) | `sign_vote_for_broadcast` (L3733) | Yes | Production-reachable |
| Directed Vote | `SendVoteTo` arm (L4224) | `sign_vote_for_broadcast` (L3733) | Yes | Production-reachable |
| Leader / self-vote handling | leader tick → `BroadcastProposal` + `BroadcastVote` arms | both helpers | Yes | Production-reachable |
| Cached Proposal re-emission | `maybe_reemit_on_late_peer_connect` (L3379) → `admit_cached_reemission` (L3989) | `sign_proposal_for_broadcast` (L3646) | **No — own admit/confirm cycle** | Conditionally reachable (in-process cache; per-view single-shot) |
| Cached Vote re-emission | `maybe_reemit_on_late_peer_connect` (L3379) → `admit_cached_reemission` (L3989) | `sign_vote_for_broadcast` (L3733) | **No — own admit/confirm cycle** | Conditionally reachable |
| `LocalFixtureUnsigned` passthrough | `pv_authority` consulted only when no snapshot wired | — | n/a | Fixture-only (test policy) |

Both caller families reach `signer.sign_*` through the two shared helpers, and
each helper **assigns the local signer's suite into the message**
(`proposal.header.suite_id = signer.suite_id()` L3706; `vote.suite_id =
signer.suite_id()` L3785) **before the D6 preimage is constructed**. A reservation
taken over an earlier, unprepared message would not bind the bytes actually
signed; the reservation MUST be taken over the prepared preimage (§4.1). Under
production `Required` policy the snapshot is `None`, so all routes fail closed
**today**; this contract specifies the reservation that must guard each route —
**both** caller families — when signing is later enabled (§4.2, §7.3).

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
they occupy the same **canonical consensus voting position** for the same stable
validator identity, yet bind different signed content. The position is defined so
that no independently-supplied numeric field and no mutable key/suite/version/
context label can split one engine voting position into two records.

**Stable validator identity (distinct from its current attributes).** Identity is
the validator's genesis-membership identity as expressed by `ValidatorId` within a
fixed network/genesis. This stable identity is **not** the validator's *current*
key, signature suite, message version, authority commitment, or in-process
`CurrentAuthorizationOwner` generation. A **new OS process, a new owner
generation, a new PID, or a new caller label is NOT a fresh validator identity**,
and neither is a validated change of the validator's current key or suite: none of
these may open a new conflict namespace or silently erase an existing conflict
obligation. Those current attributes bind the *exact authorized message*
(exact-message fields, below); they never relax the position key.

**Canonical consensus position for the supported founding-authority profile.**
The supported profile is single, static founding authority. Each signed decision
is bound to the **originating consensus view of the action itself** — the view that
was current when the engine *constructed* that action — **not** whatever value
`engine.current_view()` happens to hold later when the action reaches signing. This
distinction is load-bearing. In `on_leader_step` the engine captures
`view = self.current_view` (`basic_hotstuff_engine.rs:1443`), builds the
`BlockProposal` and self-`Vote` for that captured `view`, and — when the self-vote
immediately forms a QC — calls `advance_view()` (L1577) **before returning the
already-constructed actions** (L1581–1584). The returned `BroadcastProposal` /
`BroadcastVote` therefore already carry view `V` while the engine may already sit at
`V+1`. The reservation position MUST be that originating `V`, read from the action,
and MUST NOT be recomputed from the newer `engine.current_view()`, nor may the
message be rewritten to match the engine's later view.

The originating view is recoverable from the **existing** action and its provenance
without any new production field: a locally-emitted `BlockProposal` carries it in
`header.height` (`= view`, L1503) and a `Vote` carries it in `height` (`= view`,
L1557 / the proposal-triggered vote at L1833); for cached re-emission the captured
decision (its provenance ticket plus the cached `BlockProposal` / `Vote`) already
fixes the same originating view, so re-emission reserves that historical position
rather than the engine's current one. On ingest the engine likewise derives a peer
proposal's view from `proposal.header.height` (`ingest_proposal`,
`basic_hotstuff_engine.rs:1732`); that ingest view is the originating view of an
inbound decision, distinct from the local engine's mutable `current_view`. There is
exactly **one** engine voting position per originating view. The canonical position
key is:

* the stable validator identity (above), within its fixed network/genesis;
* the consensus **kind**: Proposal vs Vote (two distinct sub-namespaces of one
  view — see below);
* the **originating consensus view** carried by the action (never a later
  `current_view`).

The redundant numeric fields differ by message kind and MUST be classified
accordingly. A locally-emitted `BlockProposal` carries a `BlockHeader` with
`height = round = view` and **no step field at all** (`BlockHeader` has none —
L1503–1504); a `Vote` carries `height = round = view` **and** `step = 0`
(L1557–1559 / L1833–1835). An embedded `QuorumCertificate` carries **its own**
`height` / `round` / `step` certifying **its own** position (L1522–1524); it is
verified and associated separately (§4.1) and its fields are **never** borrowed to
fill the Proposal's originating position. Height and round are **not** independent
position coordinates; they are redundant encodings of the originating view, and for
a Vote `step` is an additional canonical field. The record MUST enforce, as a
**proposed pre-lookup requirement**, `height == round == view` for both kinds, plus
`step == 0` for the locally-emitted **Vote** profile; a Proposal has no step to
check. A message whose height/round (or a Vote's step) do **not** satisfy that
correspondence is an unsupported or inconsistent combination and MUST be
**refused** — it MUST NOT be admitted under a second namespace derived from its
divergent numeric fields.

**Identity of the decision vs eligibility to send it (kept separate).** Two
questions are distinct and MUST NOT be merged: (1) *which* decision is being
reserved — fixed by the originating view above and never redefined by later engine
progress; and (2) *whether* that decision may be sent **now** — governed by the
existing authorization / freshness / re-emission eligibility checks
(`admit_outbound_action`, `confirm_outbound_before_effect`, and the cached
re-emission provenance rules in `admit_cached_reemission`). Current-view equality is
**not** introduced here as a new universal signing prerequisite: an action whose
originating view differs from the engine's current view is not thereby ineligible,
and its reservation identity remains its originating view. The existing cached
re-emission eligibility checks and their provenance rules are preserved unchanged
and do **not** redefine the historical position of the cached decision.

**Field classification.** Each field has one trusted source and one role — it
either participates in the position key or it binds the exact authorized message —
with a required consistency check and a fail-closed rejection behavior:

| Field | Trusted source | Role | Required consistency check | Rejection behavior |
|---|---|---|---|---|
| validator identity (`ValidatorId`) | admitted snapshot's bound signer/domain, not the wire | position key | equals the admitted local validator identity | refuse (foreign/mismatched identity) |
| network / genesis | pinned domain (`ProposalVoteSigningDomainV2`) | position key | equals the pinned network/genesis | refuse (wrong network/genesis) |
| kind (Proposal vs Vote) | engine action type | position key (sub-namespace) | Proposal and Vote are distinct; broadcast vs directed of one Vote are the same kind | n/a (both legitimately exist per view) |
| originating consensus view | the action itself (locally-emitted `header.height` / `Vote.height` captured at construction; inbound `ingest_proposal` view) — **not** a later `engine.current_view()` | position key | single value per position, taken from the action and never recomputed from newer engine state | refuse on divergence |
| height / round | wire header (`header.height` / `header.round`) for a Proposal; `Vote.height` / `Vote.round` for a Vote | redundant encoding of the originating view | equals the originating view | refuse if `height != view` or `round != view` |
| step | wire `Vote.step` only (a `BlockProposal` / `BlockHeader` has **no** step field; an embedded QC's `step` certifies the QC's own position and is never substituted for the Proposal) | redundant, canonical, Vote-only | equals `0` for the locally-emitted Vote profile | refuse if a Vote's `step != 0`; not applicable to a Proposal |
| authorized epoch | admitted snapshot (`authorized_epoch()`) | exact-message binding | equals the admitted epoch | refuse (epoch-unauthorized) |
| current key / suite | admitted snapshot's bound signer (suite assigned at `sign_*_for_broadcast`, L3706 / L3785) | exact-message binding | equals the admitted signer's bound key/suite | refuse; a *validated change* does not open a new position namespace |
| wire-message version | wire field `BlockHeader.version` / `Vote.version` (the engine emits `1`, L1500 / L1554), validated against the supported wire-format source — **distinct from** the D6 signing-format version | exact-message binding | equals the supported wire version (`1`) | refuse (unsupported wire version) |
| D6 signing-format version | the `ProposalVoteSigningDomainV2` envelope (`signing_format_version` byte `2`) wrapping the message's existing canonical body — does **not** imply wire-message version 2 | exact-message binding (domain isolation) | is the pinned v2 domain | refuse (wrong / absent domain) |
| authority commitment | pinned domain / admitted snapshot | exact-message binding | equals the admitted commitment | refuse |
| block id + justification (QC) id | prepared engine action | exact-message binding | matches the reserved decision | conflict if changed at the same position |
| canonical preimage digest | the prepared D6 preimage `signer.sign_*` receives | exact-message binding | is the exact input reserved (§4.1) | conflict if changed at the same position |

A change to any **exact-message binding** field at the same **position key** is a
**conflict**, not a new namespace.

**Proposal vs Vote and delivery equivalence (preserved).** A leader legitimately
produces one Proposal and one self-Vote at the same view; these are distinct kinds
and do **not** conflict with each other. Two Votes at the same position for
different blocks conflict. A directed vote and a broadcast vote for the **same**
position and block are the **same** decision (exact retry, §3.5), not a conflict —
broadcast-vs-directed delivery is not a consensus-step distinction and no new step
policy is invented here.

**Non-bypass rule.** A changed block identifier, height, round, a Vote's step,
suite, key, wire-message version, authority-commitment label, owner generation,
process identifier, or caller label MUST NOT create a namespace that evades the
position key: the height/round correspondence check (plus a Vote's `step == 0`
check) runs **before** lookup, and key/suite/version/commitment are exact-message
bindings, not namespace selectors.
Authorization to rotate a key or membership does **not** by itself prove that
earlier signing obligations may be discarded. For this founding-authority design,
**rotation / epoch-transition continuity is explicitly gated**: a new conflict
namespace for a different authorized epoch or a different membership/key is **not**
designed here and remains deferred until its fencing and reservation-preservation
rules are defined (§5.3 / §6). No automatic rule makes a validated key/membership
rotation create a fresh namespace.

### 3.3 The signing-decision record (proposed representation)

The record is **proposed, not implemented**. It MUST be:

* **Bounded and versioned:** fixed maximum size, an explicit **journal-record
  format-version** field (a persistence-format identifier, distinct from the
  wire-message version and the D6 signing-format version); unknown/incompatible
  record versions are refused fail-closed.
* **Checked arithmetic:** all counters/lengths use checked/saturating
  operations; overflow is a fail-closed terminal state, never wraparound.
* **Integrity-checked:** a checksum over the record detects truncation/corruption.
  The checksum is a **corruption detector only** — it is explicitly **not**
  authentication and **not** rollback protection.
* **Fail-closed on malformed input:** any undecodable, truncated, or unsupported
  record makes the covered position **potentially-signed** (refuse to sign),
  never "assume unused."

Record fields (conceptual): **journal-record format version** (a persistence-format
identifier for the signing record, independent of both the wire-message version and
the D6 signing-format version — changing it alters neither the consensus position
nor the signed wire bytes); stable validator identity + network/genesis; position
key (kind + **originating consensus view** — with height/round, and a Vote's step,
stored only as that view's checked redundant encoding, never as independent
coordinates, and never taken from a later `engine.current_view()`); exact-message
binding digest (authorized epoch + current key/suite + **wire-message version** +
**D6 signing-format (v2) domain** + authority commitment + block id + justification
id + canonical preimage digest); lifecycle stage (§3.4); optional retained
signature/result for exact retry; checksum.

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
2. **Final signed-field preparation (existing):** using the **admitted
   snapshot's bound signer/domain**, perform the wire-chain-id / epoch checks,
   apply the permitted local suite preparation (`suite_id = signer.suite_id()`,
   L3706 / L3785), then compute the domain-canonical preimage via
   `ProposalVoteAuthority::proposal_preimage` / `vote_preimage`. This is the exact
   input `signer.sign_*` will receive; no parallel parser or new signing encoding
   is introduced (existing canonicalization is reused).
3. **Conflict lookup + exclusive reservation (new):** derive the position key
   (§3.2, after the height/round/step correspondence check) and the binding digest
   over the **prepared** preimage; look up existing record; if a conflicting
   record exists → **REFUSE**; otherwise reserve exactly that decision
   (`NONE → RESERVED`). The reserved signed fields and signing context MUST NOT
   change between this reservation and the signer invocation at step 6.
4. **Durable reservation acknowledgement (new):** commit the reservation with a
   synced write and an acknowledged durability barrier (the semantic already
   available via `put_current_epoch_synced` / `flush_epoch_durable` for epochs
   is the model; a signing-scoped store is required). No barrier ack ⇒ treat as
   uncertain ⇒ **no signer call**.
5. **Authorization revalidation after storage waits (new):** because the storage
   commit may block, before signing re-validate authorization against the
   **original ticket issuer/owner identity and its bound snapshot** (epoch,
   domain, membership, signer association) — a matching generation number **alone
   is insufficient** and MUST NOT be treated as revalidation. The admitted context
   is never silently replaced by a newly-supplied owner or signer after the
   reservation. A superseded, exhausted, or foreign-issuer authority ⇒ refuse to
   sign (the reservation is retained). This reuses the existing `admit` / `confirm`
   semantics (`admit_outbound_action` / `confirm_outbound_before_effect`) on the
   single serialized handler; the serialized boundary is what closes the
   check-to-sign gap, and no concurrent mutation is assumed in today's
   implementation.
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
* **Common signing boundary (covers both caller families):** the reservation
  MUST wrap the shared `sign_proposal_for_broadcast` / `sign_vote_for_broadcast`
  helpers so that it covers **both** the immediate-forwarding callers inside
  `forward_actions_to_facade` **and** the cached-re-emission callers in
  `maybe_reemit_on_late_peer_connect` (§2.5). A wrapper around
  `forward_actions_to_facade` alone is **insufficient** because it does not sit on
  the cached-re-emission path. This boundary is specified here and **not
  implemented** in this phase.
* **Future crossings:** if future storage I/O, async work, or another signing
  caller is introduced, the reservation/signing boundary MUST be protected so
  that no two callers cross step 3→6 for the same position; the single durable
  writer + exclusive reservation is the enforcement point. A second signing
  caller that bypasses the guarded helpers is outside the guarantee and MUST be
  prevented structurally (single guarded signing entrypoint over the shared
  helpers), not assumed away.
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
  authorization checks. **Today** `maybe_reemit_on_late_peer_connect` re-enters the
  signing helpers (it re-signs on re-emission); a future **resend-only** path
  (§3.5) that resends the retained signature instead of re-invoking the signer is a
  **proposed behavior change**, not existing behavior, and is not implemented here.
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
state alone. Distinguishing them requires **appropriately trusted state or
evidence outside the specified attacker's rollback domain** (§6) — a protected
local hardware mechanism or a remote witness, neither selected here — that binds
the validator/network to a signing-history commitment. Absent that evidence, first
initialization over a non-empty key is **ambiguous** and MUST be treated
fail-closed (refuse to sign) until an activation gate resolves it.

### 5.2 Failure / recovery matrix

Every row is keyed to **observable durable evidence**; no row relies on knowing an
unrecorded crash location. For each row: observable durable state → permitted
action → refused action → supporting assumption.

**Live continuation vs recovery (never conflated).** Four operations are kept
distinct: (1) a **live** operation continuing, *in the same process*, after its
own acknowledged reservation under exclusive in-process ownership — it may proceed
to sign under the required authorization checks; (2) **recovery after process
death**, which sees only the durable record and cannot know whether the signer was
invoked; (3) **resending a retained signature**; and (4) **invoking the signer
again**. From the durable record alone a `RESERVED` position with no usable
retained result is indistinguishable whether the crash preceded or followed the
signer call, so after restart it is treated as **potentially signed**: it cannot
authorize automatic re-signing and cannot be released. A retained result may back
an exact resend only after its association with the canonical decision and current
authorization is validated.

| # | Scenario | Observable durable state | Permitted | Refused | Assumption |
|---|---|---|---|---|---|
| 1 | Failure **before** reservation persistence | No durable record | Retry reservation | Any signer call | Sync not acknowledged ⇒ never signed |
| 2 | Reservation write / barrier failure or **uncertain** completion | Record may or may not exist | Treat as RESERVED-or-worse; may retry reservation idempotently | Signer call until a clean RESERVED is confirmed | Uncertainty ⇒ potentially reserved, not signed |
| 3 | **Live** in-process continuation after own acknowledged reservation | RESERVED held under exclusive in-process ownership (same run) | Proceed to sign once, under re-validated authorization (§4.1 step 5) | Signing a *different* decision at this position | In-process ownership proves the signer was not yet invoked |
| 4 | **Recovery after process death** at a reserved position | RESERVED, **no** usable retained result | Refuse; retain the reservation | Re-invoking the signer; releasing the reservation | Record cannot distinguish pre- from post-invocation ⇒ potentially signed |
| 5 | Confirmation / handoff failure after signing | SIGNED, retained result present, effect suppressed | Exact-retry resend of the retained signature after validating its association + current authorization | Signing a new decision | Confirm suppresses effect, not signature |
| 6 | Exact retry | Matching position key + binding digest, retained result present | Resend retained signature | Re-signing | Canonical-decision equality, not byte equality |
| 7 | Conflicting retry | Same position key, different binding | Refuse | Any signature | Conflict rule §3.2 |
| 8 | Missing / malformed / truncated / incompatible record | Undecodable | Refuse (fail-closed) | Assuming unused | §3.3 |
| 9 | Ordinary restart, required state intact | Consistent RESERVED/SIGNED set + lock inputs present | Resume per state machine (§3.4) and §5.3 | Ignoring records | Local synced journal covers ordinary crash; lock recovery per §5.3 |
| 10 | Older account/consensus state restored, **newer signing records retained** (incl. **same-epoch**: signed at epoch E, then an earlier epoch-E snapshot restored) | Retained signing records / recovery state do **not** correspond to the restored account/consensus state | Refuse to sign at positions the retained records already cover; require trusted out-of-domain state to resolve | Signing from the stale restored state | **Epoch equality does not prove freshness**; correspondence, not epoch inequality, is the test (§6) |
| 11 | Complete restoration of **older signing records and all local references** (internally consistent older copy) | All local references older and mutually consistent | Refuse until trusted out-of-domain state confirms latestness | Trusting the restored journal as current | A whole-copy rollback is **locally indistinguishable** from a valid older state (§6.1 / §6.5); the local reader cannot recognize it |
| 12 | Missing or unverifiable recovery / signing state | State absent or fails its integrity check | Refuse (fail-closed) | Assuming unused / assuming current | Neither latestness nor the consensus lock can be established |
| 13 | Two instances using the **same** validator key | Two guarded signers, same key | At most one may hold exclusivity; other must refuse | Both signing | D8 lock does not cover copied keys/hosts (§4.2) |

The journal **alone** does not detect every old snapshot and does not establish
the recovered consensus lock (§5.3). Where correspondence or lock recovery is
unestablished, signing remains refused under the stated prerequisites.

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

To resist rollback, an **independent** commitment is required: **appropriately
trusted state or evidence outside the specified attacker's rollback domain.** That
domain-external state MAY be a **protected local mechanism** (e.g., hardware-
protected local state the attacker's rollback cannot rewind) **or** a **remote
witness**; both are different possible models and **neither is selected,
implemented, or proven** here (cf. the lifecycle contract's T4 row). It is **not**
mandated to be an off-box service, a new pinned remote signing root, or any
particular transport. Whichever model a future mechanism picks, it must answer:

* **Outside the attacker's rollback domain:** what state is *not* restorable by
  the specified attacker? A **local** mechanism MUST state its hardware/access
  assumptions; a **remote** mechanism MUST state its authentication and
  operational assumptions. Neither may silently introduce a classical
  cryptographic dependency.
* **Authentication:** how is that state authenticated (a real verification against
  a pinned trust root — **not** a source label, which is not authenticated
  provenance)?
* **Binding:** what validator/network identity and **signing-history commitment**
  does it bind (must bind this validator + network + a signing-history value, not
  merely an epoch; a **monotonic number alone does not establish history binding**
  and does not prevent two cloned signers from authorizing conflicting decisions)?
* **Freshness / monotonicity / exclusive use:** how are latestness, monotonic
  advance, and single-writer/exclusive use established?
* **Ordering of local-record vs domain-external update (proposed, conditional):**
  which is written first, and what is the recovery rule if one succeeds and the
  other fails? Any such ordering is a **proposed requirement conditional on a
  future concrete mechanism**, not a fixed design.
* **Availability / partial update:** behavior during unavailability, partition,
  cold start, all-validator restart, or a partial update.

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

### 6.5 Ordering and partial-failure (proposed, conditional on a future mechanism)

This ordering is a **proposed requirement conditional on a concrete
domain-external mechanism being chosen**; it is not a fixed design, and a
**monotonic number alone does not establish history binding**. Were such a
mechanism chosen (local protected or remote), local record and domain-external
updates would be ordered so that neither a lost local record nor a lost
domain-external update can license a conflicting future decision: reserve locally
(durable) → advance the domain-external commitment → then sign. If the
domain-external advance succeeds but the local record is lost, recovery treats the
position as potentially-signed (refuse). If the local record persists but the
domain-external advance is uncertain, refuse until it is reconciled. During
unavailability / partition / cold start / all-validator restart, **refuse to
sign** rather than proceed on stale local state.

### 6.6 Domain-external anchor recommendation — EXPLICITLY UNRESOLVED

The repository and current evidence do **not** justify selecting a concrete
rollback-resistant mechanism. A **protected local mechanism** (hardware-protected
state) and a **remote witness** are different possible models; classical
signatures, hardware-attestation roots, external chains, cloud services, and a
centralized signer each introduce distinct cryptographic, operational,
availability, and decentralization assumptions and are **not** silently introduced
here — no off-box service, pinned remote signing root, or particular transport is
mandated. Selection is left **explicitly unresolved**. The unsatisfied activation
gate is: *appropriately trusted, authenticated, rollback-resistant,
freshness-bearing state/evidence outside the attacker's rollback domain, binding
this validator/network to a signing-history commitment* (a monotonic number alone
is insufficient). No "authenticated witness" is invented that no implementation can
supply. **Anchor selection remains UNRESOLVED.**

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
* Repeated position with changed message/binding fields that must **not** evade
  conflict detection.
* Evasion attempts via **inconsistent position fields** — a Proposal or Vote whose
  `height` / `round` does not equal its originating view, **or** a Vote whose `step`
  is not `0` (for this profile `height == round == originating view` and, for a Vote,
  `step == 0` — the step equals zero, **not** the view) — refused **before** lookup,
  never admitted under a second namespace.
* **Originating-view persistence across engine progress:** an action constructed at
  view `V` whose engine advances to `V+1` (via `advance_view()`) **before** the
  action is forwarded to signing keeps its reservation associated with `V`; the
  later `engine.current_view()` never redefines or overwrites the reserved position.
* **Real per-kind field sets:** a Proposal record uses `BlockHeader` fields
  (`height`, `round`, **no step**) and a Vote record uses `height`, `round`, `step`;
  no Proposal step is invented and no embedded-QC field is borrowed to fill a
  Proposal position.
* **Vote.step rejection:** a Vote presenting an unsupported `step` value is refused
  **before** lookup, without inventing or requiring a Proposal step.
* **Independent versions bound correctly:** a wire-message-version-`1` Proposal /
  Vote signed through the existing D6 v2 signing domain reserves and verifies with
  the wire-message version and the D6 signing-format version bound
  **independently** — D6 v2 does not imply wire version 2, and neither is rewritten
  to match the other.
* **Journal-record format-version independence:** changing the journal-record
  format version alters neither the consensus (originating) position nor the signed
  wire message; a record re-encoded under a new record version still reserves the
  same decision.
* **Conflict survives engine progress:** a conflicting decision at the **same
  originating position** (same identity + kind + originating view, different binding
  digest) remains a conflict and is REFUSED even though the engine has since
  advanced to a later view.
* Evasion attempts via changed **key / suite / message version / authority-
  commitment / owner-generation / caller-label** at the same position — treated as
  the same position (exact-message conflict if content differs), never a new
  namespace.
* Signing-persistence failure with **direct zero-backend-call** assertions on
  the signer.
* Durable reservation followed by **process death**: on recovery the position is
  **potentially signed** — refuse (no automatic re-sign, no release); only a
  **live** in-process continuation after its own reservation may sign once (§5.2).
* Signature completion followed by failure **before** handoff (exact-retry resend
  only, after validating the retained result's association + current
  authorization).
* Conflicting callers and cloned-validator-instance limits.
* Wrong network / domain / epoch / key association (refuse).
* Missing / corrupt records and ambiguous first initialization (fail-closed).
* Same-epoch older-snapshot rollback (signed at epoch E, then an earlier epoch-E
  snapshot restored) and whole-directory rollback — refuse pending trusted
  state/evidence outside the rollback domain; the local reader cannot by itself
  recognize a whole-copy rollback.
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
  single guarded signing entrypoint over the shared `sign_proposal_for_broadcast` /
  `sign_vote_for_broadcast` helpers (L3646 / L3733) so the reservation sits
  **before** signing for **both** caller families — the immediate-forwarding
  callers in `binary_consensus_loop.rs::forward_actions_to_facade` (L4101) **and**
  the cached-re-emission callers in `maybe_reemit_on_late_peer_connect` (L3379). A
  wrapper around `forward_actions_to_facade` alone is insufficient (§2.5).
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

## 7.4 Correction note (RUN 422 D7-D9 review pass)

This pass corrected four material inconsistencies in place, re-verified against
the actual worktree; the protocol stays `DEFINED-NOT-IMPLEMENTED` and no successor
is begun:

* **A — one non-bypassable conflict identity.** The canonical position is the
  stable validator identity + kind + **engine view**; height/round/step are
  checked redundant encodings of the view (`height == round == view`, `step == 0`
  enforced **before** lookup), not independent coordinates. Current key / suite /
  message version / authority commitment / owner generation are **exact-message
  bindings**, not namespace selectors; a validated rotation neither opens a new
  namespace nor erases a conflict obligation (rotation/epoch continuity explicitly
  gated). A field-classification table (§3.2) fixes each field's source, role,
  check, and rejection. "Committed height" is no longer used as a signing-position
  description.
* **B — recovery on observable durable state.** A recovered `RESERVED` position
  with no usable retained result is **potentially signed** (refuse; no re-sign, no
  release). Live in-process continuation, recovery after process death, resending a
  retained signature, and re-invoking the signer are kept distinct; every matrix
  row names observable durable evidence (§5.2).
* **C — full caller coverage and exact-input binding.** `maybe_reemit_on_late_peer_connect`
  reaches the shared `sign_*_for_broadcast` helpers via its own admit/confirm cycle
  and bypasses `forward_actions_to_facade`; the proposed guard wraps the shared
  helpers to cover **both** caller families (§2.5, §4.2, §7.3). Suite is prepared
  before the D6 preimage, so the reservation binds the prepared preimage (§4.1).
  Revalidation preserves the original ticket issuer/owner identity and bound
  context — a generation number alone is insufficient (§4.1 step 5).
* **D — same-epoch rollback and rollback-domain trust.** The older-snapshot rows
  use signing-history/recovery-state **correspondence**, not epoch inequality (a
  same-epoch restore is covered); a whole-copy rollback is stated to be locally
  indistinguishable. Trust is **appropriately trusted state/evidence outside the
  attacker's rollback domain** — a protected local hardware mechanism **or** a
  remote witness, neither selected; a monotonic number alone is insufficient and
  anchor selection stays UNRESOLVED (§5.1, §6.2, §6.5, §6.6).

A subsequent correction in the same D7-D9 documentation series additionally
resolved two originating-view / field-mapping issues, re-verified against the
engine and wire sources; the protocol stays `DEFINED-NOT-IMPLEMENTED`:

* **E — originating-view binding.** The reservation position is the **originating
  consensus view carried by the action** (captured at construction; `on_leader_step`
  calls `advance_view()` at L1577 **before returning** the already-built actions at
  L1581–1584, so `engine.current_view()` can already be `V+1` while the action is
  view `V`). The position is read from the action and its provenance, never
  recomputed from a later `current_view`; the message is not rewritten to a newer
  view; current-view equality is **not** a new universal signing prerequisite.
  Decision identity and send-time eligibility are kept separate, and the cached
  re-emission provenance rules are preserved (§3.2). The field-classification table's
  view row now names a concrete action-origin relationship rather than an ambiguous
  `current_view` / `ingest_proposal` listing.
* **F — per-kind fields and independent versions.** A `BlockProposal` /
  `BlockHeader` has **no** step; only a `Vote` has `step` (scoped `step == 0` to the
  locally-emitted Vote profile); an embedded QC's fields certify the QC's own
  position and are never borrowed for the Proposal. Three versions are separated:
  **wire-message version** (`BlockHeader.version` / `Vote.version` = `1`), **D6
  signing-format version** (`ProposalVoteSigningDomainV2`, byte `2` — does not imply
  wire version 2), and the **journal-record format version** (persistence-only,
  independent of both). The field-classification table and record fields now name
  each source separately (§3.2, §3.3).

---

## 8. Validation performed and retained posture

### 8.1 Checks actually performed (documentation-only)

* Verified cited paths, symbols, and caller relationships against the inspected
  `c9025f2` checkout (function line numbers in §1.1; ordering in
  `forward_actions_to_facade` L4114–4160 confirms admit→sign→confirm→facade).
* Re-verified the originating-view and per-kind field facts directly in
  `basic_hotstuff_engine.rs`: `on_leader_step` captures `view = self.current_view`
  (L1443), sets the `BlockHeader` `height = round = view` with no step (L1500–1504),
  the embedded QC's own `height`/`round`/`step` (L1522–1524), and the `Vote`
  `height = round = view`, `step = 0` (L1557–1559 / L1833–1835), then `advance_view()`
  (L1577) runs **before** the actions are returned (L1581–1584); wire structs in
  `crates/qbind-wire/src/consensus.rs` confirm `BlockHeader`/`BlockProposal` carry no
  step while `Vote`/`QuorumCertificate` do; `ProposalVoteSigningDomainV2`
  (`pv_signing_domain.rs`) confirms the v2 signing-format byte is separate from the
  wire `version` field.
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
---

## 9. RUN 422 D7-D10 implementation status (bounded successor, CODE-AND-STORAGE-TEST)

The §7.3 bounded successor is now **implemented as source + tests only** — a
non-authorizing, crash-consistent local signing-reservation journal placed
before the existing Proposal/Vote signer invocations. The §8.2
`D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED` record is a
historical D9 verdict and is **preserved**; D10 adds a separate implementation
status below. No production authority is activated and no signing is enabled in
production; the guard engages only when a journal is explicitly wired (tests).

### 9.1 Reuse inventory and new paths

* **New module** `crates/qbind-node/src/signing_reservation_journal.rs`: record
  format, 5-state machine, conflict rule, exclusivity, `SigningJournalStorage`
  trait, and the `SigningReservationJournal` reserve/sign/record/recover API.
* **`crates/qbind-node/src/storage.rs`**: reuses the existing CRC-32 facility
  (new `signing_journal_crc32`, same polynomial as block/QC/epoch) and the
  existing RocksDB synced-write path; adds a `sig:`-prefixed keyspace and
  `impl SigningJournalStorage` for `RocksDbConsensusStorage` (real
  `WriteOptions::set_sync(true)` fsync) and for `InMemoryConsensusStorage`
  (explicitly-labelled MODEL, non-durable — never a production fallback).
* **`crates/qbind-node/src/binary_consensus_loop.rs`**: one shared
  `guarded_sign_proposal_for_broadcast` / `guarded_sign_vote_for_broadcast`
  wraps the existing `sign_*_for_broadcast` helpers and is threaded through
  **both** caller families — `forward_actions_to_facade` (immediate
  BroadcastProposal / BroadcastVote / SendVoteTo, incl. leader/self-vote) and
  `maybe_reemit_on_late_peer_connect` (cached re-emission). Existing D6
  preimage construction, admission, ticket/owner revalidation, epoch/supersession
  checks, and confirmation are reused unchanged.
* Reuses existing validator identity, signer, `ProposalVoteSigningDomainV2`
  preimage, and verification APIs; no parallel authority registry, parser,
  signing format, or cryptographic construction was introduced.

### 9.2 Conflict key and prepared-input binding

* **Position key** = stable local validator identity + bound network/genesis +
  message kind (Proposal|Vote) + **originating consensus view** taken from the
  action (never recomputed from a later `engine.current_view()`).
* **Per-kind checks before lookup:** Proposal `height == round == originating
  view`, no step; Vote `height == round == originating view` **and `step == 0`**
  (the step equals zero, not the view).
* **Binding digest** covers the position, authorized epoch, prepared suite id,
  wire-message version and D6 signing-format version (bound independently), the
  authority commitment, the block identifier, and the exact D6 canonical
  preimage. Key/suite/epoch/authority-commitment/wire-version/owner-generation/
  caller-label changes are exact-message bindings, never a conflict-evading
  namespace. Directed and broadcast delivery of one Vote are the same decision;
  a Proposal and a self-Vote at one view are distinct decisions.

### 9.3 Storage namespace, record format, bounds, initialization

* Keyspace `sig:` + `sj:v1:` record-key prefix, disjoint from block/QC/epoch
  keys (unchanged). Record layout: `magic | record-format-version | kind |
  stage | validator_id | network_genesis | originating_view | binding |
  sig_len | sig | crc32` (big-endian, checksum over the body). The checksum is
  corruption detection only — **not** authentication or rollback protection.
* Bounds: retained signature ≤ 8 KiB, record ≤ bounded max, reservation count
  budgeted (checked arithmetic; overflow is terminal, never wraparound).
  Exhaustion **refuses further signing** with no silent eviction of conflict
  obligations. Decode is fail-closed on malformed/truncated/incompatible/
  inconsistent input; no allocation from unchecked stored lengths.
* Initialization is explicit: `attach` never creates, repairs, or converts
  missing/corrupt established state into an empty usable journal; its in-memory
  live-permit map starts empty (the crash-recovery posture). Production startup
  does not initialize a journal.

### 9.4 Exclusivity, live continuation, recovered-record behavior

> **Run 422 D7-D10 Corrections B/C (this pass):** the earlier position-level
> boolean ownership was replaced with a shared **ownership domain** plus an
> operation-bound, **one-use** continuation, and result publication is now a
> **checked, capability-gated** transition with an explicit durable-acknowledgement
> rule. The paragraphs below describe the corrected model. Earlier positive
> wording is superseded historical evidence only.

* **Exclusivity (ownership domain):** every supported handle attached over one
  backend instance shares a single `SigningOwnershipDomain` (owned by the
  backend and fetched through the `SigningJournalStorage::signing_ownership_domain`
  trait method, cached per-instance). A second handle **cannot** bypass
  coordination by allocating its own mutex — reservation *and* checked result
  publication run under the one domain mutex, so the read-validate-write is a
  single serialized transition. Scope is **one local journal/storage ownership
  domain**: a different backend instance over the same on-disk directory (a real
  close/reopen, or a modelled restart) is a **fresh** domain — this is the honest
  crash-recovery posture, not cross-copy/cross-host exclusivity. A genuinely
  foreign journal/operation is rejected by domain-token mismatch. The durable
  acknowledgement corresponds to the signing-record synced write itself; an
  atomic batch alone is not treated as sufficient.
* **Operation-bound one-use continuation:** a fresh reservation returns a
  `SigningContinuation` created **only after** the reservation write's durability
  acknowledgement, bound to the domain, position, binding, and a unique live
  operation id. It is **non-cloneable**, has no public constructor (so a durable
  `Reserved` record can never be turned into one), and is consumed **at most
  once** by move (`consume_for_signing`) immediately before the signer runs,
  yielding a `ResultPublicationCapability` for the *same* operation. The API
  rejects: invocation without a fresh continuation, duplicate consumption, wrong
  position/binding, foreign domain/operation, recovered `Reserved` converted to a
  live continuation, and a second caller inheriting another operation's unused
  continuation. Dropping, failing, or losing a continuation does **not** release
  the durable reservation or return the position to unused state.
* **Checked publication:** `record_signed_result` requires the valid
  publication capability (matching domain, live+invoked operation, position, and
  binding), a valid stored record with a permitted transition, and a bounded,
  structurally valid retained result, then performs the required durable synced
  write. It refuses missing/foreign/stale operations, arbitrary position/binding
  arguments, and any conflicting overwrite of an existing signed obligation.
  **Empty and oversized results are rejected at the checked publication boundary
  before any write** (`JournalError::InvalidResultPublication` /
  `OversizeRecord`): an empty signature would encode to a record the decoder
  immediately rejects, so accepting it would report a successful publication for
  bytes that can never be read back — instead the original reserved record and its
  conflict obligation are preserved, no continuation is granted, and no
  publication is reported. Retaining publication authority never re-authorizes
  signing.
* **After process death:** a recovered `Reserved` (or otherwise uncertain state
  without a usable *acknowledged* retained result) is **PotentiallySigned** →
  refuse re-signing and preserve the reservation. A valid retained result for the
  exact decision is eligible only for resend after association +
  current-authorization checks. A conflicting request is refused without altering
  the original obligation.
* **Recovered-result durability barrier (recovery acknowledgement rule):**
  reading valid `Signed` bytes after reopening establishes record availability and
  structural validity only — it is **not**, by itself, a durability
  acknowledgement. Before a *recovered* `Signed` record (one with no live
  operation in this process) may be resent as `ExactRetryRetained`, the journal
  establishes an explicit **signing-record durability barrier**: under the
  ownership-domain lock it reads and validates the exact stored record and
  reissues that identical record through the existing synced-write operation (the
  signing-record durability op, never an unrelated epoch write). The retained
  result is offered **only after** that operation succeeds; a failed or uncertain
  barrier returns an error and **suppresses** retained-result delivery, and
  retrying re-issues the durable write without ever invoking the signer or minting
  a continuation/publication capability. A successful barrier caches the
  acknowledgement **bound to the exact record** within the ownership domain (never
  a generic position flag that could authorize a different record); a conflicting,
  malformed, missing, or differently-associated record fails closed before any
  recovery re-publication and is never overwritten.
* **Uncertain / idempotent result writes:** readable byte-equality is **not** a
  durability barrier. If a result write becomes readable but its durability
  operation returns an error/uncertain outcome, publication is **not** reported
  successful; an in-process retry observes the unacknowledged live operation and
  is refused as **PotentiallySigned** (never re-signing), and re-publication
  through the same capability re-issues the synced write until a durable
  acknowledgement is established. Idempotent identical republication succeeds
  **only** once this operation holds a durable acknowledgement in-process; it can
  never replace its signature with different bytes. If result persistence
  fails/uncertain after signing, the facade handoff is suppressed, the
  reservation is preserved, and the signer is not re-invoked. Retained results are
  validated via existing D6 verification before reuse; no pruning is authorized in
  this task.
* **What is known:** a successful acknowledged write in the live process
  establishes the in-process durable barrier; a visible record following an
  uncertain write establishes readability only (not power-loss durability);
  reopening stored state after process death establishes the recovered durable
  bytes but a fresh (empty) live table. Power-loss durability is **not** inferred
  from a read, checksum, or process restart alone.

### 9.5 Executed evidence levels and unexecuted dependencies

* **Executed (Corrections B/C pass):** source-contract → journal unit tests
  (operation-bound capability ownership: foreign domain, dropped continuation,
  conflicting/idempotent/oversize publication, the store-then-error uncertainty
  rule, **empty-result refusal preserving the reservation**, and the
  **recovered-result durability barrier** under a fresh domain over surviving
  bytes — a failed barrier suppresses delivery, a later successful barrier permits
  only exact retained reuse, and the acknowledgement is cached bound to the exact
  record) → colocated handler tests (fresh continuation consumed once before the
  signer, publication through the matching operation, facade handoff suppressed on
  publication failure **and on invalid empty signer output**, and a
  **deterministic controlled-schedule** contested reservation — the winner
  durably reserves and pauses inside the signer, holding no ownership-domain mutex,
  while the contender runs against a definitely-outstanding reservation and returns
  `PotentiallySigned` (same binding) or `Conflict` (different binding); all
  coordination waits are deadline-bounded and paused workers are always released on
  every path) → real-RocksDB restart/reopen
  (reserve→consume→publish→reopen→exact retrieval demonstrating the recovery
  acknowledgement path, reserved-only reopen refusing a new continuation,
  conflict-after-reopen, empty-result refusal over the real backend, idempotent +
  conflicting-overwrite, shared-handle ownership over the real backend) → bounded
  child-process death/reopen (the child self-aborts after a durable reserve and
  the parent reopens a fresh domain; note this control uses an unbounded
  `.status()` wait and only asserts an unsuccessful exit — it is **not** a
  bounded/classified process-death test, which remains OPEN under F). Direct
  signer-call counts and facade effects are
  asserted (not logs alone). A separate post-publication exact-retry control
  confirms a legitimate retained resend after publication costs zero additional
  signer calls (the current resend policy is not weakened to an incorrect global
  "one handoff" assertion).
* **Still OPEN in D10 (not addressed by this pass):** Correction A
  (missing-journal refusal across all signing routes), Correction D (post-storage
  original-owner revalidation and remaining identity/version checks), Correction E
  (established-journal initialization and persistent capacity accounting), and the
  remaining F engine-progress/process-runner work.
* **Not executed / still unmet (unchanged posture):** durable anti-rollback
  anchor (§6.6), consensus-lock recovery (§5.3/§6.7), whole-copy rollback,
  copied-key/cross-host exclusivity, Timeout/NewView compatibility, power-loss
  evidence, and production authority activation. Local crash consistency does
  **not** close any of these.

```
D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL   (Corrections B/C complete for their demonstrated local scope; A, D, E, F remain OPEN. Supersedes the earlier CODE-AND-STORAGE-TEST-POSITIVE wording, which is retained only as historical evidence.)
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED   (D9 record preserved)
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No production activation, PR, or Run 423 work is performed.