# QBIND DevNet Evidence — Run 144

**Subject**: Specification / design report for the **peer-driven live PQC
trust-bundle apply safety gate** that any future implementation MUST pass
before it may be wired, enabled, or claimed.

## Scope notice (mandatory per `task/RUN_144_TASK.txt`)

* **Run 144 is specification / design only.**
* **No production runtime source changed.** No mutating surface is
  added or modified. No CLI flag is added, renamed, or removed. No
  metric family is added, renamed, or removed. No trust-bundle,
  peer-candidate, ratification, authority-marker, or sequence-file
  schema is changed.
* **No peer-driven live apply was implemented.** The live inbound
  `0x05` path remains **validation-only / propagation-only** exactly
  as Runs 142/143 already evidence.
* **Existing validation-only and propagation-only semantics remain
  unchanged.** Runs 132/133/142/143 invariants are preserved
  verbatim.
* **Full C4 remains open. C5 remains open.**

## Deliverables landed under Run 144

1. `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
   the new canonical safety specification for any future peer-driven
   live trust-bundle apply path (Phase 0–5 pipeline, per-environment
   policy matrix, mandatory invariants, mandatory threat model, and
   required future run decomposition).
2. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_144.md` (this file) — the
   canonical Run 144 design / evidence report.
3. Documentation alignment for Run 144:
   * `docs/whitepaper/contradiction.md` — append-only Run 144 paragraph.
   * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 144 entry.
   * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 144
     entry.
   * `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` —
     Run 144 supersession pointer for the apply surface (the Run 087
     design gate still describes the propagation-only surface; apply
     is now governed by Run 144).

## Why a design/specification run before implementation

The live inbound `0x05` receive path is the **only** PQC trust-bundle
mutating surface not yet covered by v2 wiring. The five other
mutating surfaces (process-start reload-apply, startup
`--p2p-trust-bundle`, SIGHUP live-reload, snapshot/restore, and the
local peer-candidate-check binary surface) all moved through a
documented `source/test → release-binary evidence` pair (Runs
134/135, 136/137, 138/139, 140/141, 132/133). Peer-driven live apply
is qualitatively different from those five surfaces because:

- the candidate originates from an **untrusted peer**, not an
  operator-supplied disk artifact;
- a single malicious or partitioned peer must not be able to drive
  authority state on the receiver;
- MainNet authority MUST NOT be mutable by peers in the absence of a
  separately specified governance / ratification / KMS-HSM track.

Run 144 therefore writes the safety gate **before** implementation so
that subsequent runs (the Run 145+ decomposition documented in the
specification) inherit a fail-closed, operator-controllable, and
per-environment-policy-bound contract from day one.

## Cluster architecture

**None.** Run 144 introduces no harness, no cluster, no scenario
matrix, and no release-binary execution. The Run 142/143 N=3 DevNet
cluster topology (V0 publisher, V1 validation-only v2 receiver, V2
validation-only propagation observer) remains the **only** in-tree
release-binary topology that exercises the live inbound `0x05`
surface, and it continues to do so under the validation-only /
propagation-only contract.

## Design summary

The specification defines a six-phase pipeline:

| Phase | Name | Mutation? | Run 144 status |
|------:|------|-----------|----------------|
| 0 | receive | none | unchanged from Runs 076/079/088 |
| 1 | validation-only | none | unchanged from Runs 142/143 |
| 2 | eligibility-to-stage | none (in-memory stage queue only) | **future work** (Run 145/146) |
| 3 | local authorization gate (per-environment policy) | none | **future work** (Run 147) |
| 4 | apply via existing Run 070 contract | mutation | **future work** (Run 147/148); MainNet **blocked** until Run 149+ |
| 5 | evidence and audit | n/a | **future work** (per-implementation-run release-binary evidence) |

Mandatory authorization stance:

- **DevNet** — peer-driven apply MAY be enabled in a future run behind
  an explicit hidden DevNet-only flag; **disabled by default**.
- **TestNet** — peer-driven apply MAY be enabled only with explicit
  operator opt-in **and** a ratified v2 authority on the receiving
  node; **disabled by default**.
- **MainNet** — peer-driven apply MUST be **refused** until
  governance / ratification / KMS-HSM authority is separately
  specified and evidenced.

Mandatory apply ordering (when eventually implemented, Phase 4):

```
validate → snapshot previous → swap LivePqcTrustState
        → evict sessions → commit_sequence
        → persist v2 authority marker (post-commit)
```

— byte-for-byte the Run 070 contract reused by Runs 134/136/138, with
the only new element being a distinct
`last_update_source=peer-driven-apply` audit variant on the v2 marker
so audit tooling can distinguish a peer-driven apply from a
reload-apply, startup-load, SIGHUP-reload, or snapshot-restore.

Mandatory threat model coverage (T1–T14) and mandatory invariant set
(18 numbered invariants) are documented in
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` §4–§5
and are not repeated here.

## Verdict

**Strongest-positive for specification / design scope.** The Run 144
acceptance criteria are met when:

1. peer-driven live apply safety requirements are specified before
   implementation;
2. DevNet / TestNet / MainNet policy boundaries are explicit;
3. MainNet peer-driven apply remains blocked without governance /
   ratification authority;
4. existing validation-only and propagation-only paths remain
   unchanged;
5. future implementation is decomposed into safe, evidence-first
   runs;
6. `contradiction.md` and operator / protocol docs are updated;
7. no runtime behavior changes are introduced;
8. no full C4 or C5 closure is claimed.

All eight criteria are satisfied by the deliverables listed above.

## Out-of-scope and remains-open after Run 144

- peer-driven live trust-bundle apply (the `0x05` path remains
  validation-only on every scenario) — **remains OPEN**
  (decomposed into Runs 145–148+);
- staged peer-driven apply candidate queue (Phase 2) — **remains
  OPEN** (Run 145/146);
- DevNet hidden flag for peer-driven apply (Phase 3 / Phase 4) —
  **remains OPEN** (Run 147/148);
- TestNet peer-driven apply with explicit operator opt-in and
  ratified v2 authority — **remains OPEN** (Run 149+);
- MainNet peer-driven apply — **BLOCKED** until governance /
  ratification / KMS-HSM authority track is specified and
  evidenced;
- signing-key rotation / revocation lifecycle — **remains OPEN**
  (Run 149+);
- KMS / HSM authority key custody — **remains OPEN** (Run 149+);
- MainNet governance attestation track — **remains OPEN**
  (Run 149+);
- validator-set rotation — **remains OPEN**;
- `--p2p-trusted-root` fallback authority lineage — **remains
  REJECTED**;
- `DummySig` / `DummyKem` / `DummyAead` test-shim hot path —
  **remains REJECTED**;
- full C4 closure — **remains OPEN**;
- C5 closure — **remains OPEN**.

## Validation commands

Per `task/RUN_144_TASK.txt`, Run 144 is docs-only and changes no
Rust source. The task still requires a small regression set to prove
no accidental drift:

```
# Markdown / link / lint checks if available (none defined in-tree for these doc paths).

cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

Run 144 changes no production runtime source and no test source, so
all four regression targets remain bit-for-bit identical to their
Run 143 results when run against this commit.

## Acceptance criteria (Run 144)

1. The peer-driven live apply safety requirements are specified
   before any implementation work begins. ✅
   (`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
   §3–§5.)
2. DevNet / TestNet / MainNet policy boundaries are explicit. ✅
   (Specification §6 policy matrix.)
3. MainNet peer-driven apply remains blocked without governance /
   ratification authority. ✅ (Specification §3 Phase 3 and §6.)
4. Existing validation-only and propagation-only paths remain
   unchanged. ✅ (No production runtime source changed; Runs
   142/143 invariants preserved verbatim.)
5. Future implementation is decomposed into safe, evidence-first
   runs (Run 145+). ✅ (Specification §7.)
6. `contradiction.md` and operator / protocol docs are updated. ✅
   (See "Deliverables landed under Run 144" above.)
7. No runtime behavior changes are introduced. ✅ (Docs-only run.)
8. No full C4 or C5 closure is claimed. ✅ (Specification §1,
   §8.)