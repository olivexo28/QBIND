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
   is introduced (existing canonicalization is reused). **Correction D** adds two
   pre-journal gates here, evaluated **before** the conflict lookup at step 3: the
   wire-message version must be a supported local Proposal/Vote version
   (`LOCAL_PROPOSAL_VOTE_WIRE_MESSAGE_VERSION = 1`, kept distinct from the D6
   signing-format version and the journal-record format version), and the wire
   `proposer_index` / `validator_index` must equal the bound signer's stable
   `ValidatorId` (compared by **widening** the wire index to `u64`, so a large id
   cannot alias a representable wire index through narrowing) **and** that signer
   must belong to the admitted membership. Either mismatch refuses before any
   journal lookup/write and before the signer, with a distinct counter
   (`outbound_{proposal,vote}_wire_version_unsupported_total` /
   `outbound_{proposal,vote}_signer_identity_mismatch_total`); no field is rewritten.
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
   semantics on the single serialized handler; the serialized boundary is what
   closes the check-to-sign gap, and no concurrent mutation is assumed in today's
   implementation. **Correction D implements this step, and binds the prepared
   operation across the prepare/complete split.** The original selection obtained
   at step 1 — the `AuthorizationTicket`, the bound signing context, and the
   selected signer — is **frozen before any journal work** into a small private
   `BoundSigningOperation` (an owned clone of the original ticket, preserving its
   exact issuer/generation identity, plus borrowed references to the selected
   context and signer — never a freshly-minted ticket, a separately-supplied
   authority, or a newly-selected signer). The completion phase takes **no**
   independent ticket, context, or signer parameter: those are carried inside the
   prepared operation and cannot be replaced after storage. Completion receives
   **only** the current snapshot, used solely for drift detection.
   `reconfirm_bound_operation` runs immediately **after** `consume_for_signing`
   (which acquires the ownership-domain mutex) and immediately **before**
   `signer.sign_*`, so that mutex acquisition is not an unaccounted wait between
   the confirmation and signing; no journal mutex is held during signing and no
   other blocking storage op sits between the confirmation and the signer. It
   first checks the operation still signs through its **frozen bound context** —
   the frozen context must be the current snapshot's exact bound verifier by
   pointer identity (`outbound_{proposal,vote}_bound_context_unbound_total` on
   mismatch) — then `current.owner().confirm(<frozen original ticket>)` (foreign
   issuer / generation advance / exhaustion ⇒
   `outbound_{proposal,vote}_post_journal_authorization_revalidation_failed_total`).
   A new ticket minted for the updated owner is never accepted, because there is
   no ticket parameter; only the frozen original is confirmed. A supplied current
   owner does not become the original issuer merely because its fields match.
   On any failure: zero signer calls, no result publication, no delivery, the
   durable `Reserved` record and its conflict obligation preserved (the operation
   capability is dropped, never released/reset), and no re-admit/retry within the
   operation. The retained-result reuse path performs the **same** reconfirmation
   after the B/C recovery-acknowledgement barrier and before treating the retained
   signature as an authorized reuse (existing D6 verification of the exact retained
   message/signature is retained). Required-versus-permitted fixture semantics stay
   explicit across the split: a required operation freezes `Some(ticket)` and MUST
   reconfirm (an absent current snapshot at completion ⇒ refuse fail-closed, it
   never degrades into a fixture operation by omitting admission); the
   `LocalFixtureUnsigned` no-context passthrough freezes `None` and has nothing to
   revalidate.
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

### 9.3 Storage namespace, record format, bounds, attach

* Keyspace `sig:` + `sj:v1:` record-key prefix, disjoint from block/QC/epoch
  keys (unchanged). Record layout: `magic | record-format-version | kind |
  stage | validator_id | network_genesis | originating_view | binding |
  sig_len | sig | crc32` (big-endian, checksum over the body). The checksum is
  corruption detection only — **not** authentication or rollback protection.
* Bounds: retained signature ≤ 8 KiB, record ≤ bounded max. The reservation
  counter (`reserved_positions`) and the position `max_reserved_positions`
  **limit** are both **journal-wide** and **persisted**: initialization durably
  publishes the established limit with a zero count, and every supported handle
  attached over the backend instance shares that single established limit and the
  single shared counter (checked arithmetic; overflow is terminal, never
  wraparound). A handle does **not** carry its own independent per-handle limit,
  and a second handle **cannot** relax or raise the established limit. Exhaustion
  **refuses further signing** with no silent eviction of conflict obligations.
  Decode is fail-closed on malformed/truncated/incompatible/inconsistent input;
  no allocation from unchecked stored lengths.
* Lifecycle is **explicit initialize / open** (as implemented), not an implicit
  "attach":
  * `SigningReservationJournal::initialize` is the only route that creates
    initialization metadata. It requires an **empty** signing namespace (no
    metadata and no records), rejects an unsupported limit before any durable
    write, durably publishes fixed-length initialization metadata (established
    limit, zero count), and refuses fail-closed (`AlreadyInitialized`) rather
    than resetting an established journal or one whose metadata already exists. A
    store-then-error initialization write (bytes become readable, durability
    acknowledgement uncertain) is **not** reported as a successful
    initialization; it yields no handle, metadata absence is not required
    afterwards, and a later validating `open` over the surviving well-formed,
    consistent metadata may independently establish the journal.
  * `SigningReservationJournal::open` validates an **established** journal
    (metadata present, supported version, limit/count consistent with a bounded
    whole-namespace streaming validation of every record's key/association and
    bounds) and **never** falls back to initialization or creates metadata. It
    refuses fail-closed on missing metadata (`NotInitialized`), records without
    metadata (`LegacyRecordsWithoutMetadata`), corruption/truncation/unsupported
    version, or accounting inconsistency. A second `open` over an
    already-established instance **shares** the existing ownership domain unchanged
    (live operations, operation ids, acknowledgement state, the durable counter,
    and shared ownership preserved; the namespace is not re-scanned).
  * Only a **newly created** domain (a freshly opened backend instance, i.e. a
    modelled restart) starts with fresh, empty process-local state (empty
    live-permit and recovered-acknowledgement maps); the durable reservation
    count is **reconstructed from storage** on open rather than reset. This is the
    honest crash-recovery posture: a `Reserved` record already in the store is
    treated as potentially-signed on the next reservation, and no live
    continuation is ever minted from it.
  * Production startup does **not** initialize or open a journal; journal
    initialization models a LOCAL storage operation only and does not authorize
    production activation.
  > **Historical (superseded).** Earlier drafts of this section described an
  > implicit `attach` that "reuses the backend instance's existing ownership
  > domain" and was "not an initialization step", asserted a **per-handle
  > configured limit** against the shared counter, and recorded that explicit
  > first-time-initialization-versus-validation and **persistent capacity
  > accounting** were "OPEN under E" (the reservation counter and limit being
  > process-local in-memory state only). That description is **historical and no
  > longer operative**: explicit `initialize`/`open`, the journal-wide persisted
  > limit and count, and the bounded recovered-acknowledgement cache (§9.4) are
  > implemented and tested. The historical wording is retained only as superseded
  > evidence.

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
  recovery re-publication and is never overwritten. The acknowledgement cache is
  **bounded** (`MAX_RECOVERED_ACK_ENTRIES`, FIFO): an exact cache hit serves the
  retained resend **without** reissuing the synced write, while a position whose
  acknowledgement has been **evicted** re-establishes the barrier from scratch on
  revisit (one additional synced durability write) — eviction drops only
  process-local state, never a durable record, the persisted count/limit, or a
  conflict obligation. This full post-eviction flow is exercised **through the
  journal** (and through the colocated D10 guarded handler), not by direct cache
  insert/get alone.
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
  `PotentiallySigned` (same binding) or `Conflict` (different binding). The
  test gate returns an **explicit outcome** — `Released`, `TimedOut`, or
  `Cancelled` — and only an explicit `Released` permits the paused signer to
  invoke the underlying `LocalKeySigner`; a timeout or a cleanup cancellation
  returns a signer error (via the existing `SignError`) **without** invoking the
  underlying signer, so no timeout can silently authorize a real signature or a
  passing handoff (direct controls assert both: explicit release ⇒ one real
  D6-verifiable signature and one handoff; an immediate `Duration::ZERO`
  deadline ⇒ zero underlying calls, a signing failure, and no delivery — with no
  30-second wait). Wrapper entry and underlying-call counts are tracked
  separately, so a counter incremented before the pause cannot stand in for a
  real signature. **Exactly two coordination waits are deadline-bounded** —
  `wait_entered` (test waits for the paused worker to reach the signer) and
  `wait_release` (worker waits inside the signer); the later `thread::scope`
  join is **not** itself a deadline. Prompt termination on a failing/panicking
  path is guaranteed by a test-local cleanup guard that **cancels** (not
  releases) the gate on drop, and a cancellation is never counted as a
  successful schedule. Successful schedules additionally assert that no gate
  timeout occurred) → an **actual guarded-handler recovery-handoff** leg over a
  **fresh model ownership domain** (real signer + recording facade): after an
  uncertain result write leaves readable `Signed` bytes, a reopened domain over
  the surviving bytes suppresses delivery while the recovery durability barrier
  fails or is uncertain (journal-error counter, zero facade delivery, unchanged
  signer count, exact record preserved, conflicting binding still refused), and
  permits **only** an exact retained resend once the barrier succeeds — the
  delivered signature is D6-verified and byte-identical to the retained journal
  record, with the signer count remaining one across the entire sequence
  (labelled model storage representing lost process-local knowledge, **not** a
  process-death/power-loss/release-binary/production-authorization claim) →
  real-RocksDB restart/reopen
  (reserve→consume→publish→reopen→exact retrieval demonstrating the recovery
  acknowledgement path, reserved-only reopen refusing a new continuation,
  conflict-after-reopen, empty-result refusal over the real backend, idempotent +
  conflicting-overwrite, shared-handle ownership over the real backend) → an
  **unrepaired** child-process death/reopen runner (the child self-aborts after a
  durable reserve and the parent reopens a fresh domain; this control uses an
  **unbounded** `.status()` wait and only asserts an unsuccessful exit — it is
  explicitly **not** a bounded/classified process-death test. This earlier runner
  is **superseded by Correction F (below)**, which replaces it with a
  deadline-bounded, SIGABRT-classified runner; the description here is retained
  only as the historical prior posture). Direct
  signer-call counts and facade effects are
  asserted (not logs alone). A separate post-publication exact-retry control
  confirms a legitimate retained resend after publication costs zero additional
  signer calls (the current resend policy is not weakened to an incorrect global
  "one handoff" assertion).
* **Executed (Correction A — this pass):** the missing-journal signing refusal
  now guards **every** signer-eligible outbound route. An otherwise-eligible
  Proposal/Vote (admitted current authorization, present signer, matching wire
  domain) with **no** signing-reservation journal refuses **before** the signer
  runs — before any signer invocation, reservation, retained resend, or facade
  handoff — and records a distinct per-family counter
  (`outbound_proposal_journal_unavailable_total` /
  `outbound_vote_journal_unavailable_total`). The guard sits **after** the
  existing authority / current-state / epoch / provenance / signer-availability
  / wire-domain admission (those earlier rejections keep their own counters and
  are never relabelled), and a signature already present on the message does not
  exempt it. The refusal is enforced inside `guarded_sign_proposal_for_broadcast`
  / `guarded_sign_vote_for_broadcast`, through which **all** production signing
  routes flow: immediate/broadcast Proposal and broadcast + directed Vote
  (`forward_actions_to_facade`), the leader Proposal and paired self-Vote
  (`do_leader_tick`), and the cached Proposal/Vote re-emission
  (`maybe_reemit_on_late_peer_connect`). The raw `sign_proposal_for_broadcast` /
  `sign_vote_for_broadcast` helpers are now `#[cfg(test)]` cryptographic-unit
  fixtures with **no** production call site. `LocalFixtureUnsigned` is **not** an
  exemption: its no-context passthrough has no signer and therefore no signing
  decision to reserve, but once a signer is supplied a missing journal still
  refuses. Route-level acceptance tests use otherwise-valid fixtures and assert
  the exact refusal counter, **zero** underlying signer calls, **zero** facade
  handoffs, and no false signing-success / reservation / resend / sent counters,
  each paired with a journal-present positive control that actually signs and
  delivers, plus earlier-refusal controls (authority/provenance/epoch/missing-
  signer/wire-domain) so a missing journal cannot mask an earlier failure. The
  immediate/broadcast/directed cases live in
  `run422_d7a::run422_d7b::correction_a_immediate` (`ca_a_*`, `ca_b_*`, `ca_e_*`);
  the leader-self-emit and cached re-emission cases live with their fixtures in
  `run420::run422_d7b2` (`ca_c_leader_tick_missing_journal_refuses_both_families`,
  `ca_d_cached_reemission_missing_journal_prevents_signing_and_reemission`). In
  the cached path the Proposal is signed **first**, so its missing-journal
  refusal short-circuits the whole attempt and the paired cached **Vote**'s
  missing-journal branch is **not** reached (the negative reports Proposal
  counter 1, Vote counter 0); cached-Vote missing-journal coverage is
  established instead by the shared Vote guard negative (`ca_a_vote_*`), the
  verified production cached-Vote call site, and the journal-present cached-Vote
  positive control. This closes Correction A for its demonstrated local scope; it
  does **not** supply configured-authority runtime evidence and does **not**
  close the separate Correction F engine-progress obligation.
* **Executed (Correction A required-admission — this pass):** the shared signing
  guard is now **policy-aware**. Under the fail-closed
  `ConsensusVerificationPolicy::Required` default, a signer-eligible Proposal/Vote
  with **no** original admission (the coherently-bound snapshot AND the exact
  ticket its owner issued at admission) is refused at the guard itself — **before**
  any journal access (`reserve_for_sign`), retained-result reuse, or signer
  invocation — via `outbound_{proposal,vote}_required_admission_missing_total`.
  This is the shared-guard contract; it does not depend on the outer callers'
  earlier missing-authorization rejections. `resolve_admitted_identity` still
  refuses an impossible half-pair (snapshot XOR ticket) fail-closed, and neither
  component is accepted through the test-only `LocalFixtureUnsigned` case: a
  signer-bearing fixture under that policy has no bound admission to reconfirm but
  still reaches the journal and the identity/version/suite checks. A genuinely
  unsigned no-context fixture keeps its existing passthrough. Direct-guard
  negatives (`cd_g_*`) invoke the actual shared guard with a valid context, signer,
  and journal but no admission under `Required` and assert refusal, zero journal
  reads/writes, zero signer calls, and no returned message; a `LocalFixtureUnsigned`
  control still signs.
* **Executed (Correction B suite/key/backend — this pass):** before any journal
  lookup or reservation, `check_governed_suite_backend` additionally requires,
  reusing the admitted `SuiteAwareValidatorKeyProvider` and
  `ConsensusSigBackendRegistry` (no parallel allowlist or parser), that (i) a
  governed suite/key entry exists for the selected validator
  (`outbound_{proposal,vote}_signer_key_entry_missing_total`), (ii) the bound
  signer's suite matches that governed suite
  (`outbound_{proposal,vote}_signer_suite_mismatch_total`), and (iii) the admitted
  backend registry permits and supplies the governed suite backend
  (`outbound_{proposal,vote}_signer_backend_unavailable_total`). Permitted suite
  assignment happens **before** the D6 preimage is constructed; validator identity,
  epoch, chain, version, and position are never rewritten to make a mismatch pass.
  These checks establish signer/governance suite correspondence and backend
  availability **only** — they do **not** prove possession of the corresponding
  private key (no key introspection is performed); that remains the separate
  retained-result D6 verification. Controlled negatives (`cd_h_*`, Proposal + a Vote
  counterpart) exercise missing key entry, suite mismatch, and missing backend,
  each refusing before journal access and signing; the existing real-signer/D6
  positive control is retained.
* **Executed (Correction D operation binding across the split — this pass):** the
  prepared signing operation is now **bound** to its original admission, signing
  context, and selected signer across the prepare/complete journal split. Before any
  journal work, `prepare_{proposal,vote}_signing_reservation` **freezes** the
  original `AuthorizationTicket` (an owned clone preserving its exact issuer/
  generation identity), the selected bound context, and the selected signer into a
  small private `BoundSigningOperation` carried inside the returned prepared value.
  `complete_{proposal,vote}_signing` takes **no** independent `ctx`, `admission`, or
  `signer` parameter — those cannot be replaced after storage — and receives **only**
  the current snapshot for drift detection. `reconfirm_bound_operation` runs
  immediately after `consume_for_signing` takes the ownership-domain mutex and
  immediately before `signer.sign_*` on the fresh path (and after the recovery-
  acknowledgement barrier before retained reuse); it first requires the frozen bound
  context to be the current snapshot's exact bound verifier by **pointer identity**
  (`outbound_{proposal,vote}_bound_context_unbound_total` on mismatch), then confirms
  the **frozen original ticket** against the current owner. A ticket freshly minted
  for a replaced/advanced owner is **never** accepted — there is no ticket parameter
  to supply it; only the frozen original is confirmed (`ForeignIssuer`, `Stale`,
  owner-unavailable, or terminal `Exhausted` ⇒
  `outbound_{proposal,vote}_post_journal_authorization_revalidation_failed_total`).
  Required-versus-permitted fixture semantics stay explicit across the split: a
  required operation freezes `Some(ticket)` and refuses fail-closed if the current
  snapshot is absent at completion (it never degrades into a fixture operation);
  `LocalFixtureUnsigned` freezes `None` and has nothing to reconfirm. The frozen
  signer is a structural guarantee that completion cannot silently substitute a
  same-`ValidatorId`/same-suite replacement signer, established by source/type
  inspection (no signer parameter) and a direct staged control. The production
  caller (`_reserved` thin wrapper) and the staged tests use the **same**
  `prepare`/`complete` implementation. On any refusal: **zero** signer calls, no
  publication/handoff, the durable `Reserved` record and its conflict obligation
  preserved byte-identically (dropping the operation capability never releases it),
  exact retry ⇒ `PotentiallySigned`, conflicting binding ⇒ refused. Both caller
  families are covered — immediate broadcast Proposal / broadcast + directed Vote
  (`forward_actions_to_facade`) and cached Proposal/Vote re-emission
  (`maybe_reemit_on_late_peer_connect`, Proposal-first cached ordering).
* **Test reconciliation (accurate labelling):** the earlier stale-owner tests
  (`cd_b_*`, `cd_c_*`, `cd_d_*`, `cd_e_*`) invalidate the owner (or substitute the
  context) **before** invoking the whole guard; they demonstrate stale-ticket /
  substituted-context refusal for a reservation created with an already-stale
  ticket, **not** mutation between journal completion and signing, and are retained
  and labelled as such. The new `cd_i_*` staged tests exercise the genuine
  **between-phase** boundary through the production split: prepare + durable
  reservation, capture the exact stored `Reserved` bytes, mutate the fixture
  authorization state between the two owned phases (no unsafe aliasing, no production
  mutation hook, no sleeps, no fabricated concurrent owner, no replacement boolean
  authorization callback), then run the production completion — asserting zero signer
  calls, no publication/handoff, byte-identical `Reserved`, retry ⇒
  `PotentiallySigned`, and a conflicting binding still refused, across generation
  advance, made-unavailable, and terminal exhaustion, with a Vote counterpart and a
  positive staged control that signs once and D6-verifies. For the **recovered
  retained result** (MODEL reopen through the test storage's fresh ownership domain —
  **not** power-loss or release-binary evidence), a genuine real-signer `Signed`
  record is produced, the store is reopened, the journal's recovered-record
  acknowledgement completes inside `prepare` (Retained, no new signer call), the
  original admission is invalidated before `complete`, and the completion suppresses
  reuse with **no** new signature, no authorized reuse/handoff, and the exact `Signed`
  record byte-preserved; a valid recovered-reuse control resends once (D6-verified)
  with no additional signer call. In addition, dedicated operation-binding cases
  drive the frozen selection across the split: a **replacement ticket** obtained
  after an owner-generation advance (a valid new ticket T1 for the updated owner)
  cannot authorize the T0-prepared operation — completion confirms only the frozen
  T0 (now `Stale`) and refuses; a **substituted current context** at completion (an
  independent equal-looking verifier instance) is refused by bound-context pointer
  identity; a **required operation with an absent current snapshot** at completion
  refuses fail-closed rather than degrading into a fixture operation; and a **frozen
  signer** control proves completion signs through the signer selected at preparation
  (a distinct same-`ValidatorId`/same-suite `Arc`), while the snapshot's own bound
  signer is not used — there is no completion signer parameter to substitute. Evidence
  is in `run422_d7d10::correction_d` (36 tests). Fresh pre-sign rejection preserves
  `Reserved` (dropping `publish_cap`
  never releases the obligation); retained-reuse rejection preserves the existing
  `Signed` record, produces no additional signature, delivers nothing, and never
  turns the record back into `Reserved` — a completed historical signature is never
  described as having never existed. This is a bounded local demonstration on the
  **serialized** handler; it supplies **no** configured-authority runtime evidence
  and does **not** close E or F.
* **Correction E now implemented and tested (see superseding §9.6):** explicit
  initialization vs established-journal validation, persistent capacity accounting,
  direct-read/iterator bounds, and recovered-record acknowledgement-cache evidence
  are complete for their demonstrated local code-and-storage scope. Correction F
  (engine-progress evidence + bounded-and-classified child-process runner) is now
  demonstrated for its local code-and-process-test scope
  (D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE);
  the aggregate A–F review (§9.7) consolidates the local verdict. The earlier
  stand-alone child-death test alone did not close F.
* **Not executed / still unmet (unchanged posture):** durable anti-rollback
  anchor (§6.6), consensus-lock recovery (§5.3/§6.7), whole-copy rollback,
  copied-key/cross-host exclusivity, Timeout/NewView compatibility, power-loss
  evidence, and production authority activation. Local crash consistency does
  **not** close any of these.

```
D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE   (Correction A: signer-eligible Proposal/Vote with no journal refuses before the signer across every production route; distinct per-family counters; earlier admission precedence intact; LocalFixtureUnsigned no-signer passthrough preserved. Local demonstrated scope only — no configured-authority runtime evidence, F engine-progress obligation unaffected.)
D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE   (Correction D: policy-aware Required admission refuses a missing original admission at the shared guard before journal/reuse/signer; governed suite/key/backend correspondence is checked before reservation (establishing signer/governance suite correspondence and backend availability only — not private-key possession); the prepared operation FREEZES its original admission ticket, bound context, and selected signer before journal work into a private BoundSigningOperation, and completion takes no independent ctx/admission/signer parameter — it receives only the current snapshot for drift detection and reconfirms the frozen selection immediately before the signer on the fresh path (after the ownership-domain mutex is taken by consume_for_signing) and before retained-result reuse; a replacement ticket minted for a replaced/advanced owner cannot authorize the prepared operation, substituted context, foreign/stale/exhausted issuer, unsupported wire version, signer-index/membership mismatch, and missing key/suite-mismatch/missing-backend all refuse fail-closed with distinct counters; genuine between-phase mutation through the same production completion preserves the durable Reserved record byte-identically (retry ⇒ PotentiallySigned, conflict ⇒ refused) and recovered-retained reuse preserves the exact Signed record with no new signature; immediate and cached callers share the boundary. Serialized-handler local demonstrated scope only — model reopen is not power-loss/release-binary evidence; no configured-authority runtime evidence; E is complete for its demonstrated local scope (see §9.6) and F is likewise demonstrated for its local code-and-process-test scope (D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE); the aggregate A–F review (§9.7) consolidates the local verdict.)
D7D10_CORRECTION_E_NAMESPACE_CAPACITY_CACHE=CODE-AND-STORAGE-TEST-POSITIVE   (Correction E: explicit initialize/open vs established-journal validation, persisted journal-wide limit/count, shared ownership domain, and the bounded recovered-acknowledgement cache — including the strengthened post-eviction failed-retry assertions proving a failed/uncertain recovery leaves no usable cache acknowledgement (another storage error, no retained delivery/handoff, no additional signer call, preserved record and conflict obligation) and that the later permitted write issues exactly one additional synced recovery write before the exact retained signature is reused — are complete for their demonstrated local code-and-storage scope. Serialized/local demonstrated scope only — no configured-authority runtime evidence. F is now demonstrated for its local code-and-process-test scope; see the aggregate A–F consolidation (§9.7).)
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE   (Corrections A, B/C, D, E, and F are complete for their demonstrated local scope; the subsequent aggregate A–F review (§9.7) concluded LOCAL SCOPE SUPPORTED and reconciles this canonical local verdict. Scope: a non-authorizing local signing-reservation component; shared ownership coordination over supported handles of one backend instance; acknowledged reservation before signing; one-use operation-bound continuation; checked result publication and exact retained-result reuse; frozen-operation authorization revalidation; explicit initialization/opening, namespace validation, persistent capacity, and a bounded recovery-acknowledgement cache; and demonstrated real-process abort/reopen behavior under the stated storage and operating-system assumptions. Production wiring was an explicit exclusion from this bounded local component and is NOT a completion requirement for this local token; production lifecycle and readiness remain represented by their own separate markers. This is a scoped local disposition following the completed A–F review; it does not retroactively approve the earlier defective D10 implementation or establish production readiness.)
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


### 9.6 RUN 422 D7-D10 Correction E — superseding evidence (direct-read bounds, acceptance matrix, validation)

This section SUPERSEDES the "Still OPEN under E" wording in §9.3–§9.5 for the
parts now implemented and tested. The accepted D restoration (§9.5,
`run422_d7d10::correction_d`, four restored regressions) and the completed E
namespace/accounting corrections are preserved unchanged; this pass finishes the
remaining direct-read bounds and acceptance evidence without reopening their
design.

**Initialization / opening and namespace policy (as implemented).** Explicit
`SigningReservationJournal::initialize` establishes a fresh namespace at a
checked, supported position limit and durably publishes fixed-length
initialization metadata before any signing; `SigningReservationJournal::open`
validates an established namespace (metadata present, supported version,
consistent limit/count, whole-namespace streaming validation) and never silently
falls back to initialization. A store-then-error initialization write (readable
bytes, uncertain durable acknowledgement) is not reported as a successful
initialization. Duplicate initialization over an established namespace refuses
and preserves state; opening another handle preserves an outstanding operation
and its identity. These are exercised over the real RocksDB backend, the model
reopen, and the colocated D10 store.

**Direct-read and iterator bounds, with their allocation limits.** The
whole-namespace iterator already length-checked each stored value before copying
or unwrapping. This pass extends the same bounded-read discipline to the DIRECT
reads on every supported backend (RocksDB, InMemory, the model store, and the
colocated D10 store):

* `get_signing_record` checks the backend-owned stored value's length against the
  bounded decision-record size — `MAX_RECORD_LEN` for raw-stored backends, or
  `4 + MAX_RECORD_LEN` for the CRC-enveloped RocksDB value — BEFORE copying the
  payload or unwrapping the checksum envelope.
* `get_signing_metadata` checks against the fixed metadata encoding size —
  `METADATA_ENCODED_LEN`, or `4 + METADATA_ENCODED_LEN` enveloped — likewise
  before any copy/unwrap.
* The bounds reuse codec-owned constants (`MAX_RECORD_LEN`,
  `METADATA_ENCODED_LEN`); no duplicated unexplained lengths are introduced.
* Genuine absence returns `None`; a malformed, oversized, truncated, or otherwise
  unreadable existing value returns an error. Version, checksum, and semantic
  validation remain intact; there is no legacy fallback. Failure injection and
  the established rejection precedence are preserved.

Allocation-limit scope (stated honestly): these bounds limit the APPLICATION-
owned copy/decode that follows a read. On RocksDB the underlying `get` still
allocates its own backend-owned value; the length check limits only the
subsequent payload copy and envelope unwrap. This does NOT make the RocksDB API
allocation-free and does NOT constitute a complete storage DoS audit.

**Persistent position accounting and uncertain-write behavior (preserved).** The
shared ownership-domain reservation counter is reconstructed from durable state
on open and enforced through additional handles and a real-backend reopen; both
`Reserved` and `Signed` positions count, while publication, exact retry, and
recovered acknowledgement do not increment position usage. An uncertain atomic
reservation/accounting write is reconciled against the fixed limit and the
prior/attempted counts (the only two consistent durable outcomes), refusing a
regressed, overrun, or limit-changed count. A surviving `Reserved` record never
grants a reconstructed live continuation, and no failed outcome erases or
overwrites an obligation. This relies on the backend's atomic-write assumption;
the local consistency checks are NOT whole-copy rollback detection.

**Cache pressure, eviction, and re-acknowledgement evidence.** The bounded,
process-local recovered-acknowledgement FIFO cache
(`MAX_RECOVERED_ACK_ENTRIES`) is exercised with small colocated fixtures: the
entry limit holds under pressure (never exceeding the bound; each over-capacity
insert evicts exactly one oldest process-local entry, FIFO); the retained-payload
bound follows from the enforced per-record bound and the checked entry count; a
hit returns the EXACT identical record bound to its position (no cross-position
substitution); re-acknowledging an already-cached position updates in place
without growth or peer eviction; revisiting an evicted position simply re-inserts
it (repeating the durability barrier); and a zero-capacity cache declines to
cache. Eviction drops only process-local acknowledgement state — durable records,
accounting, and conflict obligations are untouched. The handler-level guarantees
(a cache hit/eviction/re-acknowledgement never re-invokes the signer and never
mints a fresh continuation; failed/uncertain acknowledgement permits no retained
delivery and creates no successful cache entry; successful acknowledgement
permits only exact retained reuse) are covered by the colocated D10
`binary_consensus_loop` handler tests with direct signer and handoff
observations. Opaque journal-result fixtures remain distinct from
cryptographically verified handler results.

**Remaining first-use and rollback limitations (unchanged).** Journal
initialization models a LOCAL storage operation only: it is not proof that a
validator key has never signed, and it does not authorize production activation.
Production journal initialization and authority activation remain UNWIRED. The
durable anti-rollback anchor (§6.6), consensus-lock recovery (§5.3/§6.7),
whole-copy rollback detection, copied-key/cross-host fencing, Timeout/NewView
compatibility, and empirical power-loss behavior are NOT established. Synced
writes implement a durability mechanism under the stated storage assumptions; the
executed tests do not establish empirical power-loss behavior.

**Correction F (executed — this pass; test + documentation only).** Both
remaining F obligations are now demonstrated; the earlier synthetic/unbounded
evidence above is retained only as the historical prior posture.

*F-A — actual engine progress.* The prior lib test `d10_reserves_action_view_not_a_later_view`
(which constructed synthetic actions and opened a second journal handle, and did
**not** demonstrate engine progress) is replaced by a `correction_f_engine`
module driving the real `BasicHotStuffEngine` through its real guarded outbound
path. A single-validator engine at view V has its `on_leader_step` entrypoint
invoked: the self-vote forms a QC and the engine **advances to V+1 before the
returned actions are forwarded**, yet the returned Proposal (height/round V) and
self-Vote (height/round V, step 0) still carry originating view V. Those actual
actions are forwarded through the existing Required-policy guarded signer/journal/
facade path; direct journal inspection shows the Proposal and Vote occupy their
distinct kind-specific positions at **V, not the engine's newer view**. Signer-call
and facade-handoff counts are asserted exactly and the delivered signatures are
D6-verified; emitted fields are unchanged except the permitted signing preparation
(suite assignment + signature population). A deliberately-labelled conflicting
variant submitted at the SAME originating position for each kind yields the journal
`Conflict` outcome with **no** additional signer call, **no** handoff, and a
byte-identical original record. Positive controls confirm an exact permitted retry
reuses the retained signature without another signer call, and that a subsequently
emitted action at a NEW originating view (a second `on_leader_step` at V+1) occupies
a distinct legitimate position without disturbing the earlier obligation. No progress
is simulated by variable assignment, a second handle, a rewritten view, or a restart
initializer, and engine-current-view equality is **not** introduced as a new signing
prerequisite. Cached-reemission eligibility rules are preserved unchanged.

*F-B — bounded, classified child recovery (deadline-bounded draining + verified
cleanup).* `reserved_only_child_death_then_reopen_refuses`
is rewritten as a `#[cfg(unix)]` deadline-bounded, explicitly termination-classified
runner whose process-status deadline **also bounds output draining and cleanup** and
whose cleanup is a verified, structured result (superseding the earlier F-B posture,
which left draining bounded only by unconditional thread joins and reported `Timeout` as
"killed and reaped" without directly establishing reaping). The capture + bounded
process-status-wait + pure-classification patterns are
adapted **minimally** from the established D3 runner — the whole D3 target is **not**
duplicated. It re-executes THIS integration-test executable with the exact ignored
child-helper selection via **per-`Command`** environment configuration (no
process-global `set_var`). `d7d10_child_reserve_then_abort` now emits+flushes a
distinctive readiness marker to stderr **only after** the real RocksDB reservation
returns its `FreshlyReserved` durable acknowledgement, then intentionally `abort()`s
before any signer invocation or result publication. The parent waits with an INTERNAL
deadline and explicit `try_wait` process-status observation, preserves the FULL
`ExitStatus`, and accepts the crash **only** when it is SIGABRT (signal 6) **and** the
readiness marker was captured completely: an ordinary nonzero exit, a panic (nonzero
exit, no signal), an unrelated terminating signal, a missing/unusable marker, or a
deadline all fail. **The process-status deadline additionally bounds the work that
follows it via two separate finite budgets**, so no blocking boundary is unbounded:
output draining is **deadline-aware** (non-blocking pipe reads plus an armed stop
deadline — joining a drain thread is **not** itself the bound; the armed stop is), and
cleanup/reaping is bounded by `try_wait` polling (never a blocking `Child::wait()` on a
potentially live child). A drain thread that only ever sees `WouldBlock` because a
descendant inherited the pipe after the direct child exited therefore **stops at the
stop deadline and is joined**, and that stream's capture is classified as the explicit
unusable outcome `DeadlineExceeded` rather than letting an incomplete capture pass or
blocking the join forever. A deadline is a test failure with explicit kill+reap (never
reinterpreted as crash evidence); spawn/status/capture/cleanup errors are surfaced as
**structured, inspectable outcomes** rather than discarded. Cleanup is reported as an
explicit `CleanupResult` — `AlreadyReaped`, `KilledAndReaped` (termination requested
**and** reaping verified by an observed status, covering the exit-vs-kill race),
`TerminationRequestFailed`, `ReapObservationFailed`, or `DeadlineExpired` — and `reaped`
is set **only** on an observation that establishes reaping, so a failed cleanup is never
described as "killed and reaped". The `Timeout` outcome carries this concrete
`CleanupResult` and capture outcome; the timeout control **asserts verified reaping**
(`KilledAndReaped`) and a bounded capture, with the short elapsed time as corroboration
only — not as the mechanism enforcing the deadline. After the child is reaped, the
parent opens a FRESH RocksDB handle + ownership domain, inspects the valid `Reserved`
record at the exact position/binding, and asserts exact retry returns `PotentiallySigned`
(never a fresh continuation or signed result), a conflicting binding returns `Conflict`,
and the raw record bytes + persistent accounting are unchanged across the refusals. The
child helper now **fails** (rather than silently discarding) if the readiness marker
write or flush errors. Focused runner controls on the SAME classification path cover,
over **real processes**: marker+SIGABRT accepted; marker+normal-nonzero-exit rejected;
marker+unexpected signal (SIGTERM) rejected; SIGABRT-without-marker rejected;
alive-past-deadline → `Timeout` with asserted `KilledAndReaped` + bounded capture; and a
**held-pipe** control where a backgrounded descendant keeps the pipe open past the direct
child's marker-then-SIGABRT, proving the runner returns within its capture budget,
classifies the capture `DeadlineExceeded`, and refuses the incomplete capture
(`SignalButMarkerUnusable`) while cleaning up the descendant's process group. A separate
**injected-seam** control drives the pure cleanup classifier with scripted
kill/observe/expiry results (no real process) to show each failure outcome is reached
without any false `reaped=true`. A pure constructed-`ExitStatus` decision table remains.
No fixed sleep stands in for a child's exit, and no outer tool timeout is the runner
deadline.

*F-B finalization (this pass — test + documentation only).* Two residual F-B findings
are now repaired, superseding the two statements above that (a) a `WouldBlock`-only check
bounded all draining and (b) the discarded process-group kill of a backgrounded orphan
established descendant cleanup:

* **Unconditional drain deadline.** The armed stop deadline is now checked on **every**
  `run_drain` iteration — at the top of the loop, BEFORE the next `read` and regardless of
  the previous read's outcome — not only on `WouldBlock`. Continuous successful reads
  (`Ok(n)`) can no longer postpone or reset it, repeated `Interrupted` retries can no
  longer bypass it, and output that keeps arriving after the capture cap is reached still
  terminates at the deadline. The capture cap bounds **memory only** and is explicitly not
  a timing mechanism; the armed deadline is the sole timing bound and makes the drain
  worker return (and be joined) without relying on EOF or an eventual `WouldBlock`. Both
  stdout and stderr follow this bounded drain. The five capture outcomes remain distinct
  (`Complete`, `Truncated`, `ReadFailed`, `DeadlineExceeded`, `ThreadPanicked`/
  `StillDraining`); deadline termination remains the explicit **unusable** `DeadlineExceeded`
  outcome. Two deterministic reader-seam controls drive the actual `run_drain` loop with
  synthetic `Read` fixtures — one producing continuous successful reads, one producing
  repeated `Interrupted` — each bounded INDEPENDENTLY of the runner deadline (its own
  fixture cap) so a regression that ignored the deadline fails on a different terminal
  (fixture EOF) rather than hanging. These are deterministic seams, not real processes.
* **Test-owned, verified pipe-holder cleanup.** The held-pipe control no longer backgrounds
  a descendant orphaned to init and no longer discards a process-group kill. Instead the
  test builds its OWN pipes and spawns a separate **holder process whose lifetime the test
  owns**, sharing the direct child's stdout+stderr so the captured stream stays open after
  the direct child exits. The holder's cleanup guard (`OwnedHolder`) is installed
  **immediately** on creation, before any fallible observation: its `Drop` performs a
  best-effort, non-panicking, bounded kill+reap so an assertion unwind cannot leak it, and
  the normal path additionally calls `verify_cleanup`, which returns the structured
  `CleanupResult` (reusing the same `drive_cleanup` driver) — the kill error is never
  discarded and reaping is claimed only on an observed status, so a cleanup failure is
  reported, not assumed. The direct child's observed abort is kept distinct from the
  independently owned holder. Two real-process controls exercise this: an **idle** holder
  (`exec sleep`) that holds the pipe open without output, and an **active** holder (a POSIX
  `while :; do printf … 1>&2; done` loop) that keeps writing after the direct child exits —
  the latter exercising the every-iteration deadline under continuous successful reads.
  Both require the runner to return within its capture policy, classify the capture
  `DeadlineExceeded`, refuse the incomplete capture (`SignalButMarkerUnusable`, never
  `AbortedAfterMarker`), and then **verify** `KilledAndReaped` on the normal path. A focused
  early-failure control panics while a holder is owned and observes (via `kill(pid, 0)` →
  ESRCH) that the guard killed+reaped the holder during unwinding — demonstrating the guard
  is installed and used. No process group, subreaper, or process-global signal handler is
  introduced, so parallel tests are unaffected. The injected-seam cleanup classifier
  control and the pure constructed-`ExitStatus` decision table are retained.

*Platform honesty.* The signal classification uses the Unix `ExitStatusExt::signal()`
and the POSIX-fixed SIGABRT value, so the bounded parent and runner controls are
`#[cfg(unix)]`; the supported profile is Unix/Linux. Model reopen, real-RocksDB reopen,
classified process-death observation, release compilation, and empirical power-loss
evidence remain distinct and are not conflated — this establishes crash-consistency of
the LOCAL journal across real process death, **not** empirical power-loss / whole-copy
rollback resistance (no DB-wide monotonic anchor is established). The re-executed
artifact is the **test executable**, never the production node binary.

**Exact commands, checkpoints, feature counts, release identity, and tool
outcomes (historical — prior report).** The per-command figures below are the
**historical** record attributed to the prior reporting pass at implementation
checkpoint `fabb16c5b5a0fae104d3e64a2cdd1b24868383ee`; their logs were not
retained and they are **not** relabelled as newly executed here (reviewed-branch
and reviewed checkpoint `7de6c7698a0567bbc598579f9a9f55e8164be126` were
UNAVAILABLE in the shallow single-branch clone; source correspondence was
inspected directly, no ancestry was manufactured). The freshly executed
Correction E validation — including the corrected D6 target and the added
post-eviction and store-then-error acceptance tests — is recorded separately in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D10 Correction E
execution). Historical per-command results:

* `cargo test -p qbind-node --lib signing_reservation_journal` — 50 passed, 0 failed.
* `cargo test -p qbind-node --lib correction_d` — 36 passed, 0 failed (the four restored D regressions remain collected and pass).
* `cargo test -p qbind-node --lib storage` — 61 passed, 0 failed.
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests` — 22 passed, 1 ignored (child helper), 0 failed (default features).
* `cargo test -p qbind-node --features test-utils --test run_422_d7d10_signing_reservation_journal_tests` — 27 passed, 1 ignored, 0 failed. The +5 cases over the default run are the `test-utils`-gated unknown-version and raw-seam direct-read cases; the 1 ignored helper and the shared passing subset overlap both runs.
* `cargo test -p qbind-node --lib` — 1833 passed, 0 failed.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` — 3 passed, 0 failed.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` — 4 passed, 0 failed.
* `cargo check -p qbind-node` (binary-inclusive; the historical `--lib` check does not substitute) — exit 0.
* `cargo build --release -p qbind-node --bin qbind-node` — exit 0.
* D6 PV-domain isolation target. **Correction (this supersedes the earlier
  claim):** the D6 target is
  `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`.
  The previously recorded `cargo test -p qbind-node --test m10_signer_isolation_tests`
  (13 passed) is **remote-signer key-isolation** coverage and **cannot substitute**
  for the PV-domain isolation target; that earlier line is withdrawn as an
  incorrect evidence claim. The correct target was executed in the Correction E
  execution pass — see `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422
  D7-D10 Correction E execution) for the observed `34 passed, 0 failed` result.
* Focused Clippy `cargo clippy -p qbind-node --lib` — exit 0, no warnings in the changed files (`storage.rs`, `signing_reservation_journal.rs`, `binary_consensus_loop.rs`); the changed integration target reports only pre-existing style warnings. The whole-workspace `--tests` clippy run additionally compiles `m16_epoch_transition_hardening_tests`, which fails to build WITHOUT `--features test-utils` (a pre-existing feature-gating limitation on `set_inject_write_failure`/`clear_epoch_transition_marker`, unrelated to this change).

Release compilation evidence ONLY (not configured-authority runtime evidence):

* Build-source SHA: `fabb16c5b5a0fae104d3e64a2cdd1b24868383ee`
* Path: `target/release/qbind-node`
* Profile / features: `release` / default (`--bin qbind-node`)
* Byte length: `17075336`
* SHA-256: `31ef90a69afc0608b38ca91ef585485168c775a31b2c82c854ba563625ee06df`

Security-tool outcomes (recorded literally): independent Code Review and CodeQL
were attempted via the harness's `parallel_validation` with production storage
changes declared non-trivial for CodeQL. Code Review DID NOT run — the review tool
was unavailable in this environment (the `autofind` binary was not found), so
"no review comments" is NOT a clean review. CodeQL DID NOT complete — the `rust`
analysis was SKIPPED because the database size was too large (0 alerts reported
is therefore NOT a successful scan). Neither constitutes a passed security
analysis; both remain unexecuted obligations. Security posture remains
RS1-OPEN / PUBLIC-DEVNET-NO-GO.

**Scoped verdict.** The scoped code, acceptance tests, documentation, and
required validation for journal initialization, direct-read/iterator bounds, and
persistent capacity accounting are complete for their demonstrated local
code-and-storage scope:

```
D7D10_JOURNAL_INITIALIZATION_AND_CAPACITY=CODE-AND-STORAGE-TEST-POSITIVE
```

This is CODE-AND-STORAGE-TEST scope only. It is NOT configured-authority runtime
evidence and does NOT promote readiness. Correction F is now demonstrated for its
code-and-process-test scope:

```
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
```

C4/C5 remain OPEN. The subsequent aggregate A–F D10 review (§9.7) has now been
completed and concluded LOCAL SCOPE SUPPORTED, reconciling the canonical local
verdict to `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE` for its
demonstrated local scope; closing Correction F and this local consolidation do NOT
promote production readiness, anti-rollback, or security-analysis completion.
Production activation is not performed.

### 9.7 RUN 422 D7-D10 aggregate A–F consolidation — LOCAL SCOPE SUPPORTED and reconciled canonical verdict

This subsection is the authoritative in-contract summary of the completed aggregate
A–F review. The corresponding evidence record is in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (RUN 422 D10 aggregate
consolidation). It supersedes every prior §9 statement that said “F remains OPEN”,
that the active child test does not close F, that E or F remains unfinished for its
demonstrated local scope, or that `D7D10_LOCAL_SIGNING_RESERVATION` is PARTIAL
pending the aggregate review. Accurately labelled historical partial verdicts in the
earlier evidence passes are preserved unchanged.

**Aggregate-reviewed revision.** Reviewed/tested HEAD
`2cf125ccd2ee9b4af29280095b48461ec0eae975`, reported on branch
`copilot/run-422-corrections`. The review ran against a shallow, single-branch
clone: the previously accepted Correction F references
`f069bd7dfeaac3dd6e5de91efefe644cf2d9257f` (final) and
`06c6423e577f9235ea772e2e59267dbe693ee3e6` (code/test checkpoint) are not present as
objects in this checkout. The source reviewer verified identical Git blob hashes
between `2cf125c` and `f069bd7` for the journal, storage, handler, D10 integration
target, this continuity contract, and the D7 evidence document — establishing
correspondence of those files only, not ancestry or identity of every repository
file. The aggregate review was **read-only**: it produced no change set.

**A–F invariant matrix (aggregate review).**

| Correction | Invariant | Enforcing mechanism | Evidence level | Limitation | Disposition |
| --- | --- | --- | --- | --- | --- |
| A | Missing-journal signing refusal with admission precedence preserved | `guarded_sign_{proposal,vote}_for_broadcast` refuse a missing journal before the signer on every production route; raw `sign_*_for_broadcast` are `#[cfg(test)]` | CODE-TEST | Serialized local handler; no configured-authority runtime evidence | CODE-TEST-POSITIVE |
| B/C | Acknowledged reservation before signing; one-use operation-bound continuation; checked/suppressed publication | `SignGate::wait_release` –> `GateOutcome`; only `Released` reaches the underlying signer; failed/uncertain writes suppress delivery | CODE-AND-STORAGE-TEST | Model reopen; serialized handler; not power-loss/release-binary evidence | CODE-AND-STORAGE-TEST-POSITIVE (local) |
| D | Frozen-operation authorization revalidation of the original ticket, bound context, and signer | `BoundSigningOperation` freezes the admission ticket, bound context, and selected signer; completion reconfirms immediately before the signer and before retained reuse; distinct fail-closed counters | CODE-TEST | Serialized local handler; signer/suite correspondence only (no private-key possession); no runtime evidence | CODE-TEST-POSITIVE |
| E | Explicit initialization/opening, namespace validation, persistent capacity, bounded recovery-acknowledgement cache | Explicit initialize/open vs established-journal validation; persisted journal-wide limit/count; bounded recovered-acknowledgement cache with post-eviction failed-retry assertions | CODE-AND-STORAGE-TEST | Serialized/local; no configured-authority runtime evidence | CODE-AND-STORAGE-TEST-POSITIVE |
| F | Engine progress preserves the originating decision and conflict position; bounded child-process abort/reopen recovery | Engine-progress recorder preserves the originating decision/conflict; bounded, classified child-process runner with an unconditional drain deadline and test-owned verified cleanup; real-process abort/reopen | CODE-AND-PROCESS-TEST | Stated storage/OS assumptions; not power-loss durability; not configured-authority runtime evidence | CODE-AND-PROCESS-TEST-POSITIVE |

**Reviewed interactions between corrections.**

1. Admission precedence and missing-journal refusal.
2. Reservation acknowledgement, one-use capability, and original-ticket revalidation.
3. Failed/uncertain result publication suppressing delivery.
4. Recovery acknowledgement/cache handling followed by authorization revalidation and exact reuse.
5. Cache eviction and failed/uncertain retries requiring a later successful acknowledgement.
6. Capacity or metadata failure refusing without signing or erasing obligations.
7. Engine progress preserving the originating decision and conflict position.

**Conclusion — LOCAL SCOPE SUPPORTED.** The aggregate A–F review found **no material
findings** in the reviewed local signing-reservation implementation and evidence.
“No material findings” is attributed to the aggregate review; it is not proof that
the implementation is free of every possible defect. On that basis the canonical
local verdict is reconciled to:

```
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
```

**Scope of the reconciled local token.**

* A non-authorizing local signing-reservation component.
* Shared ownership coordination over supported handles of one backend instance.
* Acknowledged reservation before signing.
* One-use operation-bound continuation.
* Checked result publication and exact retained-result reuse.
* Frozen-operation authorization revalidation.
* Explicit initialization/opening, namespace validation, persistent capacity, and a bounded recovery-acknowledgement cache.
* Demonstrated real-process abort/reopen behavior under the stated storage and operating-system assumptions.

Production wiring was an **explicit exclusion** from this bounded local component. It
must not become a newly invented completion requirement for the local token.
Production lifecycle and readiness remain represented by their existing separate
markers (`D7_STATUS`, `DURABLE_ANTI_ROLLBACK`, `GENESIS_AUTHORITY_ACTIVATION`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE`, `SECURITY_POSTURE`). This scoped
disposition does not retroactively approve the earlier defective D10 implementation
or establish production readiness.

The separate process-evidence token is retained:

```
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
```

**Security-tool outcomes (aggregate review, recorded literally).** Independent Code
Review — **NOT RUN**. CodeQL — **NOT RUN**. The aggregate review did not invoke the
diff-oriented validation harness because it produced no change set; an empty diff
does not establish completed source review or security analysis. Prior
tool-unavailable errors and CodeQL skips remain historical outcomes at their own
revisions. “NOT RUN” is not “unavailable”, “passed”, “zero findings”, or “nothing
exists to analyze”. The aggregate source review is kept distinct from completed
independent tooling.

**Validation attribution.** The validations tabulated in the D7 evidence document
(lib tests; the `run_422_d7d10_signing_reservation_journal_tests` D10 integration
target under default and `test-utils` features; the
`run_422_d6_pv_domain_isolation_tests` D6 PV-domain isolation target; the
`run_420_production_policy_reachability_tests` reachability target; the
`run_422_startup_refusal_tests` startup-refusal target; `cargo check`; and the
Clippy runs) were executed at `2cf125c` during the aggregate review. They are prior
aggregate-review executions, not commands executed by this documentation-only
consolidation; no new build, test, or scan was performed here.

**Unchanged remaining obligations (kept separate and OPEN).** Production journal
initialization and wiring; activation authorization and current-authority freshness;
consensus-lock and broader consensus-state recovery; same-epoch snapshot/signing-
history correspondence; whole-copy rollback resistance and independent freshness-
anchor selection; copied-key/cross-host signing exclusivity; Timeout/NewView
compatibility; empirical power-loss durability; configured-authority release/runtime
evidence; independent security-analysis obligations; and C4/C5 and broader
production readiness. The preserved markers `D7_STATUS=PARTIAL-CODE-TEST /
PRODUCTION-LIFECYCLE-UNAVAILABLE`, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`, and
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO` are unchanged. No D11, Run 423,
production initialization, signing enablement, activation, or architectural redesign
is authorized.