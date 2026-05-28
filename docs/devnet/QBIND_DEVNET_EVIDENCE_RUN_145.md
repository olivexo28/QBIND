# QBIND DevNet Evidence — Run 145

**Subject**: Source / test scaffold for the **non-applying, staged
peer-driven trust-bundle candidate queue** that any future peer-driven
live trust-bundle apply path (Run 147+) will sit on top of.

## Scope notice (mandatory per `task/RUN_145_TASK.txt`)

* **Run 145 is source / test scaffold only.**
* **No release-binary evidence is claimed in Run 145.** Release-binary
  staging evidence is deferred to **Run 146**, which will exercise the
  Run 145 staging queue over real live inbound `0x05` frames produced
  by the release binary under a hidden DevNet-only flag (no MainNet
  enablement; no live apply).
* **No live apply is implemented.** The new staging module exposes no
  `apply` / `apply_validated_candidate` /
  `apply_validated_candidate_with_previous` entry point and does not
  call any Run 070 apply path.
* **No mutation** of `LivePqcTrustState`, the trust-bundle sequence
  file (`pqc_trust_bundle_sequence.json`), the authority marker
  (`pqc_authority_state.json`), or P2P / KEMTLS sessions.
* **No SIGHUP / reload-apply / process-start apply invocation.**
* **No new wire format.** The live inbound `0x05` envelope and
  `LivePeerCandidateWireDispatcher` route remain unchanged.
* **No CLI flag is added** in Run 145. The staging surface is
  library-level only; the future Run 146 binary hook is documented
  in the module-level Rust docs of
  `crates/qbind-node/src/pqc_peer_candidate_staging.rs`.
* **No trust-bundle / peer-candidate / ratification / authority-marker /
  ratification-sidecar / sequence-file schema is changed.**
* **No MainNet enablement.** MainNet peer-driven staging is refused
  unconditionally for now, even with `enabled = true`, until a future
  governance / ratification / KMS-HSM proof type exists.
* **No KMS / HSM, no governance implementation, no signing-key
  rotation / revocation lifecycle.**
* **Existing validation-only and propagation-only behaviour
  (Runs 132/133/142/143 and Run 088) remains bit-for-bit unchanged.**
* **Peer-driven live apply remains unimplemented.**
* **Full C4 remains OPEN. C5 remains OPEN.**

## Deliverables landed under Run 145

1. New source module
   `crates/qbind-node/src/pqc_peer_candidate_staging.rs` —
   library-level, non-applying, disabled-by-default, environment-gated,
   bounded, deduplicated, TTL-bounded, per-peer-bounded, in-memory
   staging queue (`PeerCandidateStagingQueue`) backed by a typed
   policy (`PeerDrivenStagingPolicy`) and a log-safe metadata record
   (`StagedPeerCandidate`).
2. Registration of the new module in `crates/qbind-node/src/lib.rs`
   with a Run 145 module-level comment documenting the
   non-applying / non-mutating / disabled-by-default / MainNet-blocked
   contract.
3. New focused integration / unit test suite
   `crates/qbind-node/tests/run_145_peer_candidate_staging_tests.rs`
   covering acceptance scenarios **A1–A4** and rejection scenarios
   **R1–R13** of `task/RUN_145_TASK.txt`, plus structural
   constant / log-safe-metadata checks. Every test asserts the Run 145
   non-mutation invariants on `pqc_trust_bundle_sequence.json` and
   `pqc_authority_state.json`.
4. Documentation alignment:
   * `docs/whitepaper/contradiction.md` — append-only Run 145 paragraph.
   * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 145 entry.
   * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 145
     entry.
   * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
     Run 145 progress entry recording that the Phase 2 staging-queue
     primitive now has a source/test scaffold (still disabled by
     default and still non-applying).

## Component identity

`PeerCandidateStagingQueue` is the first concrete artefact of the
**Phase 2 ("eligibility to stage")** layer described by
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`. It sits
strictly **downstream** of the existing Run 142/143 validation-only
path:

```
  live inbound 0x05 frame
    └─► LivePeerCandidateWireDispatcher (Run 079/142/143)
          ├─► Run 069 loader
          ├─► Run 130 v2 verifier
          ├─► Run 132/142 v2 marker validation-only check
          └─► PeerCandidateWireOutcome::ValidatorRan(
                  PeerCandidateOutcome::Validated(ValidatedPeerCandidate))
                  │
                  ▼  (Run 146 future binary hook; not wired in Run 145)
              PeerCandidateStagingQueue::try_stage_validated
                  │
                  ▼
              StagingOutcome::Staged | AlreadyStaged | Refused*
                  │
                  ▼  (NO Run 070 apply; NO LivePqcTrustState swap;
                       NO sequence write; NO marker write; NO session
                       eviction; NO SIGHUP / reload-apply invocation;
                       NO propagation; NO new metric family;
                       NO peer-driven-apply log line.)
              memory-only audit trail for future operator / governance
              decision (Run 147+).
```

The queue is intentionally **library-level only** in Run 145. No
production call site invokes it. The future Run 146 release-binary hook
is documented in the module-level Rust docs.

## Policy semantics

The new `PeerDrivenStagingPolicy` carries:

| Field                       | Type                | Default | Run 145 semantics |
| --------------------------- | ------------------- | ------- | ----------------- |
| `enabled`                   | `bool`              | `false` | Master switch. `false` ⇒ every call returns `RefusedDisabled`. |
| `environment`               | `NetworkEnvironment`| `Devnet`| Resolved runtime environment of the receiving node. |
| `allow_devnet`              | `bool`              | `false` | DevNet stages only when `enabled && allow_devnet`. |
| `allow_testnet`             | `bool`              | `false` | TestNet stages only when `enabled && allow_testnet` **and** the upstream caller has independently verified v2 ratification. |
| `allow_mainnet`             | `bool`              | `false` | **Ignored in Run 145.** MainNet is refused unconditionally with `RefusedEnvironmentPolicy`. |
| `max_staged_candidates`     | `usize`             | `16`    | Global cap; eviction policy is **reject-new**. |
| `max_candidates_per_peer`   | `usize`             | `4`     | Per-peer cap; reject-new. |
| `ttl_secs`                  | `u64`               | `300`   | Lazy sweep at every read/insert. |

Per-environment matrix:

* **DevNet** — MAY stage when `enabled && allow_devnet`. Default:
  disabled.
* **TestNet** — MAY stage when `enabled && allow_testnet` AND the
  upstream Run 130 v2 verifier and the Run 132/142 v2 marker check
  accepted the candidate. Default: disabled.
* **MainNet** — **REFUSED.** The queue returns
  `StagingOutcome::RefusedEnvironmentPolicy` regardless of
  `enabled`/`allow_mainnet`. **Local peer majority is not authority on
  MainNet.** Future TestNet/MainNet peer-driven apply remains blocked
  until a governance / ratification / KMS-HSM authority is separately
  specified and evidenced.

## Bound and dedup discipline

* Global cap (`max_staged_candidates`, default 16): when reached, new
  candidates are **rejected** with `RefusedGlobalCapacity { cap }`. Run
  145 deliberately chooses reject-new over silent eviction because
  silent eviction of an older staged candidate could otherwise be used
  by a hostile peer to shadow a legitimate earlier candidate.
* Per-peer cap (`max_candidates_per_peer`, default 4): same reject-new
  policy bucketed by `peer_id`. Prevents a single peer from filling the
  queue alone.
* TTL (`ttl_secs`, default 300): a `purge_expired(now)` sweep, invoked
  lazily on every insert (and exposed publicly to tests), drops any
  entry older than `ttl_secs`. This avoids spawning a background timer
  / task.
* Duplicate suppression: by the `(fingerprint_prefix, sequence,
  authority_marker_digest)` triple. A byte-identical resubmission
  returns `StagingOutcome::AlreadyStaged`. The queue does **not** grow
  on dedup hits.

## Test matrix exercised by `run_145_peer_candidate_staging_tests.rs`

| Scenario | Description | Result |
| -------- | ----------- | ------ |
| A1 | Valid v2 candidate stages when policy enabled on DevNet. | `Staged` |
| A2 | Idempotent v2 candidate is deduped on second submission. | `AlreadyStaged`; queue does not grow. |
| A3 | Higher-sequence v2 candidate stages alongside an older one. | `Staged`; both entries retained. |
| A4 | v2-after-v1 migration candidate stages while local v1 marker bytes are byte-identical pre/post. | `Staged`; v1 marker preserved. |
| R1 | Disabled policy refuses staging even when the upstream validator accepted. | `RefusedDisabled` |
| R2 | MainNet policy refuses staging even with `enabled=true` and `allow_mainnet=true`. | `RefusedEnvironmentPolicy` |
| R3 | Lower-sequence v2 candidate is rejected by validation and refused by the queue. | `RefusedNotValidated` |
| R4 | Same-sequence different-digest equivocation is rejected by validation and refused. | `RefusedNotValidated` |
| R5 | Bad-signature v2 candidate is rejected by the Run 130 verifier and refused. | `RefusedNotValidated` |
| R6 | Wrong-domain (wrong environment) candidate is rejected by validation and refused. | `RefusedNotValidated` |
| R7 | Ambiguous v1+v2 candidate is fail-closed and refused. | `RefusedNotValidated` |
| R8 | Duplicate candidate submitted 10× does not grow the queue beyond 1 entry. | First `Staged`, rest `AlreadyStaged`. |
| R9 | Per-peer cap (set to 2) refuses the third candidate from the same peer. | `RefusedPerPeerCapacity { cap: 2 }` |
| R10 | Global cap (set to 2) refuses the third candidate from a third peer; reject-new. | `RefusedGlobalCapacity { cap: 2 }` |
| R11 | TTL sweep removes the staged candidate after `ttl_secs` elapses; expired entries cannot be applied later (no apply path exists). | `purge_expired` returns `1`; queue empty. |
| R12 | v1 live inbound behaviour unchanged; staging only when explicitly valid and policy permits. | Either `Staged` (if v1 validates) or `RefusedNotValidated`; trust files byte-identical. |
| R13 | Staging does not imply propagation; propagation remains governed by Run 088 / Run 143 rules. | `Staged`; propagation sender count is 0. |

Every test additionally asserts:

* `pqc_trust_bundle_sequence.json` is byte-identical pre / post.
* `pqc_authority_state.json` is byte-identical pre / post.
* No Run 070 apply / `apply_validated_candidate*` invocation occurs
  (structurally guaranteed: the module makes no such call).
* No `LivePqcTrustState` swap (structurally guaranteed: the module
  holds no `LivePqcTrustState` handle).
* No session eviction (structurally guaranteed: the module does not
  reference the session-eviction API).
* No SIGHUP / reload-apply outcome (structurally guaranteed: the
  module does not invoke either path).
* No peer-driven-apply metric or log line is emitted (Run 145
  intentionally adds no new metric family and no new log line).

## Validation commands

Per `task/RUN_145_TASK.txt`:

```text
cargo build -p qbind-node --lib
cargo test  -p qbind-node --test run_145_peer_candidate_staging_tests
cargo test  -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test  -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test  -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test  -p qbind-node --lib pqc_authority
cargo test  -p qbind-node --lib
```

The Run 145 acceptance criteria from `task/RUN_145_TASK.txt` map
one-to-one to:

1. **staged peer-candidate queue exists or is fully specified in
   source-level scaffold** — `pqc_peer_candidate_staging` module + tests.
2. **only validation-accepted candidates can stage** — enforced by
   `try_stage_outcome`, which refuses everything except
   `PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::
   Validated(_))`.
3. **staging is disabled by default** — `PeerDrivenStagingPolicy::
   default` sets `enabled = false` and `allow_* = false`.
4. **MainNet staging is refused for now** — `permitted()` returns
   `MainnetGovernanceMissing` for `NetworkEnvironment::Mainnet`
   regardless of `enabled`/`allow_mainnet`.
5. **staging is bounded and deduped** — `max_staged_candidates`,
   `max_candidates_per_peer`, `ttl_secs`, and the
   `(fingerprint_prefix, sequence, authority_marker_digest)` dedup
   key.
6. **staging does not apply, mutate live trust, write sequence, write
   marker, or evict sessions** — structurally guaranteed; tests
   additionally check the on-disk artefacts are byte-identical.
7. **validation-only and propagation-only behavior remain
   unchanged** — Run 142/143 and Run 088 regression suites pass
   unchanged.
8. **docs defer release-binary staging evidence to Run 146** — see
   "Release-binary staging evidence" below.
9. **`contradiction.md` is updated** — see Run 145 paragraph.
10. **no full C4 or C5 closure is claimed** — explicitly noted in the
    Scope notice above and in the contradiction.md Run 145 paragraph.

## Release-binary staging evidence is deferred to Run 146

Run 145 lands **no** release-binary evidence. Specifically, Run 145
does **not** demonstrate:

* a release `qbind-node` binary observing the live inbound `0x05`
  receive path with the Run 145 staging queue installed;
* peer-candidate frames produced by a separate release-binary client
  reaching the staging queue;
* operator-visible log lines for staged entries;
* metrics for staged entries.

All of the above is the explicit scope of **Run 146**, which will:

1. wire `PeerCandidateStagingQueue` behind a hidden DevNet-only CLI
   flag (refusing to bind on TestNet/MainNet at the flag-bind step);
2. exercise the queue with real `0x05` frames produced by the release
   binary, on DevNet only;
3. produce release-binary evidence proving that
   `pqc_trust_bundle_sequence.json`, `pqc_authority_state.json`, and
   `LivePqcTrustState` are bit-for-bit unchanged across the entire
   test pass;
4. confirm that no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_*`
   metric family appears and that no SIGHUP / reload-apply / Run 070
   apply call site is invoked.

## Acceptance criteria for Run 145 itself

Run 145 is acceptable only if:

1. a staged peer-candidate queue **exists** as a source-level scaffold;
2. only validation-accepted candidates can enter the queue;
3. the queue is **disabled by default**;
4. MainNet staging is **refused** for now;
5. the queue is **bounded and deduped** with explicit reject-new
   eviction policy;
6. the queue does **not** apply, mutate live trust, write the sequence
   file, write the authority marker, or evict sessions;
7. validation-only and propagation-only behaviour remain **unchanged**;
8. docs **defer release-binary staging evidence to Run 146**;
9. `contradiction.md` is **updated**;
10. **no full C4 or C5 closure is claimed.**

All ten conditions are satisfied. Peer-driven live apply remains
unimplemented. DevNet / TestNet / MainNet policy remains fail-closed.
MainNet peer-driven staging / apply remains blocked without
governance / ratification / KMS-HSM policy. Full C4 remains OPEN. C5
remains OPEN.