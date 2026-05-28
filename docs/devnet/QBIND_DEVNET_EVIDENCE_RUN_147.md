# QBIND DevNet Evidence — Run 147

**Subject**: Release-binary evidence for the live inbound `0x05`
peer-candidate **staging hook** wired into the Run 146
`LivePeerCandidateWireDispatcher` and armed at the binary level
behind a hidden, disabled-by-default operator opt-in flag.

## Verdict (mandatory disclosure per `task/RUN_147_TASK.txt`)

**Run 147 is NOT pure evidence-only.** The feasibility gate
returned **NO** against the Run 146 state, and the task's
"preferred path if a flag is necessary" allowance was taken to add
the smallest hidden, disabled-by-default DevNet/TestNet-only
arming flag. Run 147 is therefore classified as

> **"source/test + release-binary evidence for hidden opt-in
> staging arming."**

The source delta is exactly:

1. One new hidden CLI flag in `crates/qbind-node/src/cli.rs`:
   `--p2p-trust-bundle-peer-candidate-staging-enabled`. Defaults
   `false`; hidden from `--help`; documented inline; refused on
   MainNet; requires
   `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`.
2. One top-level partial-config refusal gate in
   `crates/qbind-node/src/main.rs` that fail-closes startup when:
   * the flag is supplied on MainNet (exit code 1; Run 147 FATAL
     log line; P2P transport never up); or
   * the flag is supplied without
     `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
     (exit code 1; Run 147 FATAL log line; P2P transport never
     up).
3. One inline branch in `crates/qbind-node/src/main.rs` that, when
   the flag is accepted, replaces the Run 146 placeholder
   `staging_queue: None` in the dispatcher config with a freshly
   constructed bounded, non-applying `PeerCandidateStagingQueue`
   built from `PeerDrivenStagingPolicy::devnet_enabled` or
   `PeerDrivenStagingPolicy::testnet_enabled` (per
   `config.environment`). MainNet is also refused fail-closed at
   this defensive second guard.

**No other production runtime change.** No new metric family, no
new wire-format change, no new schema, no new fixture helper, no
new propagation surface. Run 143 / Run 146 behaviour is bit-for-bit
preserved when the new flag is **not** supplied (the default).

## Scope notice (mandatory per `task/RUN_147_TASK.txt`)

* **Real `target/release/qbind-node`** is used by the harness.
* **Real live P2P `0x05` frame exchange** is used by the harness
  (the cluster matrix runs on the same N=3 DevNet topology as
  Run 143; the V1 receiver simply receives the Run 147 staging
  flag in addition to Run 143's V1 args).
* **Real DevNet fixture material** from the Run 143 pipeline is
  reused verbatim.
* **No peer-driven live apply.**
* **No Run 070 apply invocation.**
* **No `LivePqcTrustState` mutation.**
* **No sequence write** (`pqc_trust_bundle_sequence.json` is
  byte-identical pre/post on every Run 147 scenario).
* **No authority-marker write** (`pqc_authority_state.json` is
  byte-identical pre/post on every Run 147 scenario when it is
  present).
* **No P2P / KEMTLS session eviction.**
* **No SIGHUP / reload-apply invocation.**
* **No trust-bundle / ratification-sidecar / authority-marker
  schema change.**
* **No wire-format change.**
* **No KMS / HSM.**
* **No governance implementation.**
* **No signing-key rotation / revocation lifecycle.**
* **No MainNet staging enablement.** MainNet refuses staging
  startup unconditionally, both at the top-level CLI gate and
  again defensively at queue construction.
* **Validation-only and propagation-only behaviour remain
  unchanged.** When the Run 147 flag is not supplied, the
  dispatcher field `staging_queue` is `None`, and every Run 143 /
  Run 146 outcome on the live inbound `0x05` path is bit-for-bit
  identical.
* **Full C4 remains OPEN. C5 remains OPEN.**

## Feasibility gate

**Question.** "Can a real `target/release/qbind-node` binary arm
`LivePeerCandidateWireDispatcher::staging_queue` through an
existing runtime config path?"

**Answer (Run 146 state).** **NO.** Run 146 explicitly left
`dispatcher_cfg.staging_queue = None` in
`crates/qbind-node/src/main.rs`. The `set_staging_queue` /
`staging_queue()` / `staging_hook_is_armed()` surface on
`LivePeerCandidateWireDispatcher` existed solely for source/test
wiring. There was no existing CLI flag, environment variable, or
node-config field that arms the queue on the release binary.

**Run 147 resolution.** Per `task/RUN_147_TASK.txt`'s explicit
"preferred path if a flag is necessary" allowance, Run 147 added
the smallest hidden, disabled-by-default DevNet/TestNet-only
arming flag described above. Without this flag, the Run 147
release binary remains identical to the Run 146 release binary.
With this flag, the Run 146 hook is genuinely armed at the
release-binary level on DevNet/TestNet; MainNet is refused
fail-closed.

## Component identity (Run 147)

Run 147 promotes the Run 146 dispatcher-observable staging hook
to a **release-binary-observable** primitive on DevNet/TestNet.
The startup wiring becomes:

```
  qbind-node CLI parse
      │
      ▼  (Run 147 top-level gate)
      │   if --p2p-trust-bundle-peer-candidate-staging-enabled:
      │       refuse on MainNet  (exit 1; transport not up)
      │       refuse if --p2p-trust-bundle-peer-candidate-wire-validation-enabled is missing
      │       log "[binary] Run 147: peer-candidate staging hook arming flag accepted"
      │
      ▼  (Run 079 dispatcher construction branch)
      │   if --p2p-trust-bundle-peer-candidate-staging-enabled:
      │       policy = PeerDrivenStagingPolicy::devnet_enabled()  / testnet_enabled()
      │       queue  = PeerCandidateStagingQueue::new(policy)
      │       dispatcher_cfg.staging_queue = Some(Arc::new(Mutex::new(queue)))
      │       log "[run-147] live peer-candidate staging hook ARMED ..."
      │   else:
      │       dispatcher_cfg.staging_queue = None    (bit-for-bit Run 143 / Run 146)
      │
      ▼  LivePeerCandidateWireDispatcher::new(dispatcher_cfg, metrics)
      ▼  (read-loop installs sink as before; no other change)
```

The receive-path data flow is unchanged from Run 146:

```
  live inbound 0x05 frame
      │
      ▼  (Run 079 decode + size checks)
      ▼  (Run 109 v1 ratification gate, when enabled)
      ▼  (Run 142 v2 ratification gate, when enabled)
      ▼  PeerCandidateOutcome::Validated(v)  │ or Rejected/Oversize/…
      ▼  (Run 142 v2 authority-marker conflict check)
      ▼  (Run 123 v1 authority-marker conflict check)
      ▼  ───────────  Run 146 staging hook (Run 147 arms it)  ───────
      │   if staging_queue.is_some()  &&  outcome is Validated
      │     queue.try_stage_outcome(outcome, fp+seq digest, now)
      │   else: no-op  (Run 143 / Run 146 default behaviour)
      ▼  (Run 088 propagation-only rebroadcast, when enabled)
      ▼  outcome returned to caller
```

The staging hook remains strictly downstream of validation and
strictly upstream of propagation, exactly as
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
prescribes. The Run 145 / Run 146 source-level proof that the
queue is non-applying, bounded, deduped, MainNet-refused, and
non-authoritative is unchanged; Run 147 just arms it on the
release binary on DevNet/TestNet.

## Scenario matrix

The harness `scripts/devnet/run_147_live_0x05_peer_candidate_staging_release_binary.sh`
exercises the full Run 147 matrix. Per-scenario artefacts are
archived under `docs/devnet/run_147_live_0x05_peer_candidate_staging_release_binary/`.

### Partial-config refusal scenarios (operationally new in Run 147)

| ID | Inputs | Expected outcome |
|----|--------|------------------|
| **C1** | `--p2p-trust-bundle-peer-candidate-staging-enabled` without `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` | `qbind-node` exits with code 1; stderr contains `[binary] Run 147: FATAL: ... requires --p2p-trust-bundle-peer-candidate-wire-validation-enabled`; no P2P transport bound; no staging queue constructed. |
| **C2 / R2** | `--p2p-trust-bundle-peer-candidate-staging-enabled` on `--env mainnet` | `qbind-node` exits with code 1; stderr contains `[binary] Run 147: FATAL: ... refused on MainNet unconditionally`; no P2P transport bound; no staging queue constructed. |
| **C3** | `--p2p-trust-bundle-peer-candidate-staging-enabled` is hidden from `--help` (by design: `hide = true`); recognition is proved by the C1 / C2 refusals firing the Run 147 FATAL line (not the clap "unrecognized argument" error). | Confirmed by C1 / C2 / R2. |

### Cluster ACCEPT scenarios (V1 armed with Run 147 flag)

| ID | Cluster setup | Expected outcome |
|----|---------------|------------------|
| **A1** | V0 sends valid v2 candidate; V1 has the v2 sidecar and the Run 147 flag. | Run 142 v2 path selected; validation accepted; `[run-147] live peer-candidate staging hook ARMED` on V1; `[binary] Run 146: ...STAGED ...` on V1; queue length = 1 on V1; no sequence write; no authority-marker write; no `LivePqcTrustState` mutation; no session eviction; no apply. |
| **A2** | V0 sends the same valid v2 candidate twice. | First arrival stages; second arrival is deduped at the Run 088 duplicate-suppression gate **before** staging is consulted (Run 146 `try_stage_outcome` is therefore never called with a duplicate; queue length remains 1; no unbounded growth; no mutation). |
| **A3** | V1 has local v2 marker `seq = N`; candidate `seq = N + 1`. | Validation accepts; candidate stages; local marker bytes unchanged; sequence bytes unchanged. |
| **A4** | V1 has local v1 marker; candidate is a valid v2 migration. | Validation accepts; candidate stages; v1 marker bytes preserved; no v2 marker write. |

### Cluster REJECT / REGRESSION scenarios

| ID | Cluster setup | Expected outcome |
|----|---------------|------------------|
| **R1** | V1 validation enabled, Run 147 flag NOT supplied (default). | Behaviour bit-for-bit identical to Run 143. Queue is `None`; no `[run-147]` log lines fire; no staging; existing Run 143 invariants hold. |
| **R2** | (Covered by C2 above.) MainNet refusal. | (See C2.) |
| **R3** | Candidate `seq < local`. | Validation rejects upstream; no staging; no mutation; no invalid propagation. |
| **R4** | Same-seq different-digest candidate. | Validation rejects; no staging; no mutation. |
| **R5** | Bad-signature candidate. | Run 130 verifier failure; no staging; no mutation. |
| **R6** | Wrong chain / environment / genesis. | Validation rejects; no staging. |
| **R7** | Ambiguous v1+v2 sidecar. | Versioned sidecar loader fails preflight refusal at process start (no transport up); no staging. Source-level R7 coverage is the in-process Run 146 test `run146_r7_ambiguous_v1_plus_v2_candidate_does_not_stage`. |
| **R8** | Propagation disabled + staging enabled. | Valid candidate stages on V1; no rebroadcast to V2. |
| **R9** | Propagation enabled + staging disabled. | Valid candidate may propagate under existing Run 088 / Run 143 rules; queue stays empty on V1. |
| **R10** | Propagation enabled + staging enabled. | Valid candidate both stages and propagates; invalid candidate neither stages nor propagates; no apply. |
| **R11** | Queue-bound behaviour. | Per-peer and global caps from the Run 145 conservative defaults are enforced. Exhaustively proven by the in-process Run 145 `run145_r9_per_peer_bound_enforced` and Run 146 `run146_r11_queue_bounds_enforced_through_live_hook` tests under the same dispatcher object the release binary arms; the harness verifies cap-related log lines surface on the release binary when the cap is hit. |
| **R12** | v1 live inbound regression. | Existing v1 candidate behaviour unchanged. No accidental v2 staging unless explicitly the policy allowed it. Still no apply. |
| **R13** | Legacy / no-sidecar regression. | Existing behaviour unchanged. No staging unless validation outcome and policy explicitly allow it. |

## Required evidence capture

The Run 147 harness captures, for each cluster scenario:

* `qbind-node` SHA-256 and ELF Build ID;
* helper SHA-256 + Build ID for every fixture helper reused from
  Run 143;
* git commit hash; `rustc --version`; `cargo --version`;
* exact command lines for every release-binary invocation;
* node PIDs; per-node stdout / stderr logs;
* metrics scrape from every node at the moment each invariant
  was asserted;
* per-node `pqc_trust_bundle_sequence.json` SHA-256 pre/post
  (asserted byte-identical);
* per-node `pqc_authority_state.json` SHA-256 pre/post when
  seeded (asserted byte-identical);
* per-node data-dir `find` inventory (asserted absent of
  `pqc_authority_state.json.tmp`, `RESTORED_FROM_SNAPSHOT.json`);
* staging proof:
  * `[binary] Run 147: peer-candidate staging hook arming flag
    accepted` log line on V1 only;
  * `[run-147] live peer-candidate staging hook ARMED` log line
    on V1 only;
  * `[binary] Run 146: ...STAGED ...` log line on V1 for every
    A-row positive scenario; `... refused ...` line for R-row
    scenarios where the queue receives a non-`Validated` outcome
    (queue's `RefusedNotValidated` guard) or refused by policy
    (e.g. R1's disabled policy path);
* denylist grep across every captured log (asserted empty).

## Non-mutation proof

Every Run 147 scenario asserts the Run 146 negative invariants
restated here for clarity:

| Invariant | How the test asserts it |
|---|---|
| No Run 070 apply call | The dispatcher has no apply path; the staging hook itself calls only `try_stage_outcome` which is a pure queue insert. Denylist grep confirms no `[run-070]` apply log line and no `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` metric family. |
| No `LivePqcTrustState` swap | The dispatcher does not own a `LivePqcTrustState`; the staging hook does not construct one. |
| No sequence write | Per-node `pqc_trust_bundle_sequence.json` SHA-256 pre/post is byte-identical. |
| No authority-marker write | Per-node `pqc_authority_state.json` SHA-256 pre/post (when present) is byte-identical. |
| No session eviction | The dispatcher has no `P2pSessionEvictor` handle; the staging hook does not construct one. Denylist grep confirms no `qbind_p2p_session_eviction_*` counter advances. |
| No SIGHUP / reload-apply outcome | The dispatcher does not call the Run 070 / Run 073 / Run 074 apply / reload paths. Denylist grep confirms no `SIGHUP ... reload-apply` line. |
| No peer-driven apply metric/log | Run 147 introduces no new metric family. The only Run 147-specific log lines are the documented `[binary] Run 147: ...` and `[run-147] ...` markers; both explicitly disclaim apply / sequence persistence / live trust mutation / marker write / session touch. |
| No trusted-root fallback | The reused Run 069 / Run 076 / Run 130 validator pipeline rejects `DummySig` / `DummyKem` / `DummyAead` at startup; the staging hook does not relax this. Denylist grep confirms. |

## Out-of-scope deferral list

Run 147 explicitly does NOT close any of the following:

* **Peer-driven live trust-bundle apply** remains **OPEN**.
* **Signing-key rotation / revocation lifecycle** remains **OPEN**.
* **KMS / HSM authority custody** remains **OPEN**.
* **MainNet governance artifact verification** remains **OPEN**.
* **Full C4** ("peer-driven trust-bundle apply") remains **OPEN**:
  Run 147 stages observation only. No applied state changes hands.
* **C5** ("operator / governance approval surface") remains
  **OPEN**: the queue is a candidate list, not an approval
  decision.
* **MainNet staging enablement** remains refused unconditionally,
  both at the CLI gate and at queue construction. A future
  governance / ratification / KMS-HSM proof type is required to
  even consider MainNet staging.

## What Run 147 honestly evidences

* **Peer-driven live apply remains unimplemented.**
* **Staging is non-authoritative.** Holding a staged candidate
  does NOT mean it has been applied.
* **MainNet staging remains refused.**
* **Release-binary staging is evidenced** only because the
  Run 147 hidden opt-in flag was added and is genuinely armed in
  the real binary under DevNet/TestNet. Default behaviour (no
  flag supplied) is bit-for-bit Run 143 / Run 146.
* **Full C4 remains OPEN. C5 remains OPEN.**

## Required validation commands (per `task/RUN_147_TASK.txt`)

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example devnet_pqc_root_helper \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_consensus_signer_keystore_helper \
  --example run_133_v2_validation_only_fixture_helper
bash scripts/devnet/run_147_live_0x05_peer_candidate_staging_release_binary.sh
cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests
cargo test -p qbind-node --test run_145_peer_candidate_staging_tests
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --test run_079_peer_candidate_wire_tests
cargo test -p qbind-node --test run_109_peer_candidate_wire_ratification_tests
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

## Crosscheck against existing design / spec

The Run 147 source delta is intentionally the minimum surface
that the existing Run 145 / Run 146 / Run 144 design / spec
documents already anticipate. Crosscheck results:

* `crates/qbind-node/src/pqc_peer_candidate_staging.rs` (Run 145)
  module documentation already names a future `qbind-node`
  `main.rs` arming branch and a `PeerDrivenStagingPolicy` policy
  constructor as the production-binary surface. Run 147's `main.rs`
  branch matches this anticipated shape exactly.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_146.md` already names the
  Run 147 expected flag surface
  (`--p2p-trust-bundle-peer-candidate-staging-enabled`, hidden,
  defaults `false`, refuses MainNet unconditionally, requires the
  existing live `0x05` validation flag, does not imply
  propagation, does not imply apply) and states "When Run 147 adds
  the flag, no dispatcher-level code needs to change." Run 147
  honours this contract: only `main.rs` and `cli.rs` change; no
  dispatcher-level code change.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
  (Run 144) explicitly designates the Phase 2 staging queue as
  strictly downstream of validation and strictly upstream of
  propagation, with no apply path. Run 147 preserves this
  ordering bit-for-bit.

No contradictions were found. `docs/whitepaper/contradiction.md`
is updated with a Run 147 paragraph that documents the verdict,
the source delta, and the explicit deferral list.
