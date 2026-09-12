# QBIND Public DevNet — Run 422 Evidence

**Genesis-bound consensus authority and standalone-binary activation**

- Task branch expected by the task: `copilot/copilotrun-422-task-update`
- **Actual checked-out branch:** `copilot/copilotcopilotrun-422-task-update`
  (the environment's branch name doubles the `copilot` segment; the corrective
  work below is committed and pushed on this actual branch — recorded honestly
  as a branch-name deviation, no rename/force-push performed)
- Reviewed commit recorded in the containment task:
  `9dbdbe4ad1f45433d2acca319d1dae74554ee378`
- **Workflow deviation (recorded honestly):** this environment provides a
  *squashed* single-branch shallow clone whose tip before this pass was
  `514e433` ("update"), which contains the reviewed Run 422 implementation
  file-for-file. The reviewed commit `9dbdbe4a` is **not** an object in this
  clone, so a direct-continuation ancestry cannot be proven by `git`. The
  containment correction below is applied on top of `514e433`.
- **This pass — RUN 422 CONTAINMENT CORRECTION.** The prior corrective
  continuation left the new genesis-authority route *reachable*: valid genesis
  + matching signer + `--consensus-authority-from-genesis` still built an
  active context and reached the consensus loop. This pass makes that NEW route
  genuinely unavailable in production via an early startup refusal (exit
  non-zero, "disabled pending D4-D7") enforced before P2P service construction
  and before any consensus task, across every network mode and environment. The
  legacy `--validator-consensus-key` CLI route is intentionally left unchanged
  and remains reachable. D4–D7 are **not** attempted in this pass.
- Successor: Run 423 (configured-authority standalone release-binary adversarial
  evidence) — **not** started here.

## Verdict (containment correction — supersedes the reachable-activation state)

```text
RESULT=PARTIAL-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-D4-D7
LEGACY_CLI_CONTEXT_ACTIVATION=UNCHANGED-AND-STILL-REACHABLE
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The prior Run 422 corrective continuation reported the genesis-bound route as a
reachable (if fail-closed) activation path. Source review established that this
still allowed valid genesis + signer inputs to construct `Some(ctx)` and reach
the consensus loop, and that changing the documentation verdict to PARTIAL did
not disable that path. **This containment correction disables the NEW
genesis-authority activation route entirely**: `--consensus-authority-from-genesis`
now causes an early non-zero startup refusal ("genesis-authority activation is
disabled pending D4-D7") before P2P service construction and before any
consensus task, across every production network mode and environment, with no
override, hidden flag, environment bypass, or unsigned fallback.

This does **not** claim that all production context activation is unavailable:
the legacy `--validator-consensus-key` CLI-key route is unchanged and still
reachable (see `LEGACY_CLI_CONTEXT_ACTIVATION` above). Only the new
genesis-authority route is blocked. The corrected authority loader,
boot-identity comparison, and membership-count rejection are retained and remain
exercised by tests, but they can no longer activate in production.

### Reviewed defects and their disposition

| # | Defect (as reviewed) | Disposition |
| --- | --- | --- |
| D1 | **Genesis multiple-read inconsistency** — `main.rs` re-loaded the genesis, then separately called `compute_print_genesis_hash` (which reopens the file with no authority validation); keys from one read were paired with a hash from another. | **FIXED.** Replaced with the shared `load_verify_and_build_genesis_authority`, which reads the genesis **exactly once** into an owned snapshot, fully re-validates those same bytes via `verify_boot_time_genesis` (structural + authority + chain_id + expected-hash), derives the canonical identity from that same parse, and (when supplied) requires equality with the boot-accepted identity. `compute_print_genesis_hash` is no longer used to establish signing authority. Behavioral tests: `shared_activation_valid_genesis_matching_count_succeeds`, `shared_activation_replaced_input_rejected`, `shared_activation_matching_boot_identity_succeeds`, `shared_activation_expected_hash_mismatch_rejects`, `shared_activation_malformed_genesis_file_rejects`. |
| D2 | **Engine/verifier membership divergence** — authority used `GenesisConfig.validators` while the engine derived `num_validators` from `static_peers.len()+1`. | **FIXED (fail-closed reject).** The shared boundary rejects any `peer_derived_count != genesis_authority_count` (`MembershipCountMismatch`) rather than silently resizing. Consensus membership is defined by the committed authority; the connected-peer count can never resize/redefine it. Behavioral tests: `shared_activation_membership_count_mismatch_rejects`, `shared_activation_valid_genesis_matching_count_succeeds`, `shared_activation_out_of_range_local_id_rejects`. |
| D3 | **Activation flag ignored outside `run_p2p_node`** — LocalMesh could accept `--consensus-authority-from-genesis` without executing any validation. | **SUPERSEDED BY CONTAINMENT.** A single early startup guard now refuses the flag non-zero for **every** network mode (LocalMesh and P2P) and every environment, before the per-mode service dispatch. The earlier LocalMesh-only string guard is removed in favor of this unified refusal. Behavioral tests: process-level `local_mesh_mode_cannot_bypass_the_refusal`, `valid_genesis_and_signer_plus_flag_refused_before_p2p_service_start`; source guard `main_rs_refuses_genesis_activation_before_service_dispatch`. |
| D4 | **P2P service starts before authority validation** — `P2pNodeBuilder::build` (and the engine `num_validators` config) run before the authority checks. | **CONTAINED (not solved).** The reorder is not attempted. Instead the genesis-authority route is disabled: the startup guard exits before `run_p2p_node` is entered, so no P2P transport is constructed and no consensus task starts for this route. Proven by the process-level test asserting the P2P/LocalMesh service-start log markers never appear. The underlying ordering restructuring remains **UNRESOLVED** and is a precondition for any future re-enablement. |
| D5 | **Shared context across Proposal/Vote + Timeout/NewView** — one context; "flag off ⇒ None" is not universally true because the legacy CLI-key path can still build the shared context. | **UNRESOLVED (documented blocker).** No separate Proposal/Vote canonical-authority activation boundary is introduced here; the immutable crypto components remain shared. The legacy `--validator-consensus-key` route still builds the shared context, so no blanket "all production activation is unavailable" claim is made. See `shared_context_impact.txt`. |
| D6 | **Signed-domain gap** — an authority commitment is not a signature-domain binding; replay across accepted identities not disproved. | **UNRESOLVED (documented blocker).** Round-trip / wrong-genesis / wrong-chain signature rejection is **not** demonstrated with the real backend here. Requires a versioned protocol change that is out of this task's scope. See `adversarial_matrix.txt` / `verification_context_trace.txt`. |
| D7 | **Genesis-static lifetime** — an immutable provider does not prove continued authorization across epoch/membership/restore transitions. | **UNRESOLVED (documented blocker).** No new lifetime enforcement beyond the existing per-startup re-validation is added. |

Because D4–D7 remain, the genesis-authority route is **disabled** (not activated)
and the verdict is **PARTIAL**: `GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-D4-D7`.

## What changed (containment correction)

Route A (genesis-bound) is **disabled** in production. The opt-in flag
`--consensus-authority-from-genesis` remains defined for forward compatibility,
but supplying it now triggers a single early startup refusal rather than
building any consensus context. The corrective authority loader
(`load_verify_and_build_genesis_authority`, single-snapshot provenance +
boot-identity equality + membership-count reject) is retained and still tested,
but is no longer reachable from a normally built binary because the flag is
contained upstream.

The legacy `--validator-consensus-key` CLI route (Runs 031–033) is unchanged and
still reachable — this pass blocks only the new genesis-authority route.

Changed files — reviewed implementation (`514e433`) plus this containment delta:

| File | Change |
| --- | --- |
| `crates/qbind-node/src/main.rs` | **containment:** added the single production startup guard that refuses `--consensus-authority-from-genesis` (exit 1, "genesis-authority activation is disabled pending D4-D7") immediately before the `match config.network_mode` service dispatch — after Run 102 boot verification, before P2P service construction / consensus tasks, uniform across modes and environments. Removed the earlier LocalMesh-only string guard (subsumed). The downstream `run_p2p_node` genesis-authority block is retained but is now unreachable (documented in-place). |
| `crates/qbind-node/src/genesis_consensus_authority.rs` | Route A module + unit tests + shared `load_verify_and_build_genesis_authority` — **unchanged** this pass (retained loader). |
| `crates/qbind-node/src/cli.rs` | `--consensus-authority-from-genesis` flag — **unchanged** this pass. |
| `crates/qbind-node/tests/run_422_startup_refusal_tests.rs` | **new:** process-level startup-refusal proof driving the real binary (valid DevNet genesis + matching signer): refused before service start, LocalMesh cannot bypass, flag-absent preserves behavior, `--help` preserved. |
| `crates/qbind-node/tests/run_422_genesis_consensus_authority_tests.rs` | **containment:** replaced the LocalMesh-only source guard with `main_rs_refuses_genesis_activation_before_service_dispatch` (unified guard precedes service dispatch); all provider/loader tests retained (15 total). |

## Activation semantics (disabled — fail-closed refusal)

When `--consensus-authority-from-genesis` is set during normal startup, `main`
exits non-zero at the single startup guard with:

```text
[binary] FATAL: --consensus-authority-from-genesis is refused: genesis-authority
activation is disabled pending D4-D7. ... This refusal is enforced before P2P
service construction and before any consensus task starts, across every network
mode and environment, with no override, hidden flag, environment bypass, or
unsigned fallback.
```

Guard location: `crates/qbind-node/src/main.rs`, immediately before
`match config.network_mode { … }` (after the Run 102 boot-time genesis
verification, before `run_p2p_node` / `run_local_mesh_node`). Because the guard
precedes the per-mode dispatch, no genesis is paired into an active context and
the consensus loop is never reached for this route.

When the flag is **absent**, existing configuration determines context
availability: the unavailable-authority default remains `None` plus
`ConsensusVerificationPolicy::Required`; valid legacy CLI-key configuration can
still produce `Some(ctx)`. This containment leaves both cases unchanged.
`LocalFixtureUnsigned` remains unavailable in production. F6 and existing
Timeout/NewView checks are preserved. Ordinary `--help` is unchanged.

## Validation summary (this containment correction)

- **Process-level startup-refusal (new, default Cargo test profile):** `run_422_startup_refusal_tests` — 4/4
  (`valid_genesis_and_signer_plus_flag_refused_before_p2p_service_start`,
  `local_mesh_mode_cannot_bypass_the_refusal`,
  `flag_absent_is_not_refused_by_the_guard`, `help_behavior_is_preserved`).
- Run 422 activation/provider tests: **15/15** (`run_422_genesis_consensus_authority_tests`).
- Regressions: `run_420` (3/3), `run_418` sender-binding (18/18), `run_418`
  newview demux (3/3) — all pass, no F6/policy regression.
- `qbind-node` release binary build: see `commands.txt` for command + exit code.
- rustfmt/clippy: changed files formatted; pre-existing repo-wide drift/warnings
  unchanged and not claimed clean.
- CodeQL: see `commands.txt` — recorded honestly (a skipped Rust database
  analysis provides no zero-alert conclusion).

Full command/exit detail: `run_422_consensus_authority_activation/commands.txt`.

## Scope guards (unchanged posture)

No readiness item moves Green. **RS1 stays OPEN/launch-blocking; C4/C5 stay
OPEN; M4 stays Yellow; M6 stays Yellow/Partial; S5/S7 stay Yellow; public DevNet
remains NO-GO.** No TestNet/MainNet readiness claim, no `devnet-seeds.live.json`,
candidate seed status and reachability evidence unchanged. F1/F2/F5/F7 remain
unresolved; F6 remains code/test plus partial runtime evidence. F3/F4/F8 are
**PARTIAL** (provenance/membership/mode-handling corrected and behaviorally
tested; ordering/shared-context/signed-domain/lifetime unresolved).

## Archive

`docs/devnet/run_422_consensus_authority_activation/` — see its `README.md`.
`SHA256SUMS.txt` covers every publish-safe archive file (LF endings).

## Successor

Run 423 (configured-authority standalone release-binary adversarial evidence) is
**not** started here and implies no public DevNet launch readiness. The
unresolved boundaries D4–D7 above must be closed before any positive activation
verdict.

---

## Superseded initial conclusion (historical, retained)

The initial Run 422 review reported
`RESULT=POSITIVE-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST` with
F3/F4/F8 `CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE`. That
conclusion is **superseded** by the corrective PARTIAL result above following
source review. It is retained here only as historical record.