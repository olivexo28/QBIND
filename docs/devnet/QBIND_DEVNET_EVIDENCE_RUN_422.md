# QBIND Public DevNet — Run 422 Evidence

**Genesis-bound consensus authority and standalone-binary activation**

- Baseline: `main` @ `5c2f9381` (full `5c2f93816a3ff67cec11605878bfb6705d637a47`)
- Task branch: `copilot/copilotrun-422-task-update` (working branch for this
  corrective continuation; the reviewed branch name recorded in the task,
  `copilot/run-422-task-update`, is not the branch checked out in this
  environment)
- Reviewed tip recorded in task: `664a4845b7f0523ae85f91e484b209ac593a8a08`
- Reported tested implementation recorded in task: `a62624acc1ca6be7656e8219e0235f8cc3f44e22`
- **Workflow deviation (recorded honestly):** this environment provides a
  *squashed* single-branch shallow clone. The reviewed Run 422 implementation is
  present as commit `af38558` ("update"); the reviewed tip `664a4845` and tested
  SHA `a62624ac` are **not** objects in this clone, so a direct-continuation
  ancestry cannot be proven by `git`. The corrective work below is applied on top
  of `af38558`, which contains the reviewed implementation file-for-file.
- Successor: Run 423 (configured-authority standalone release-binary adversarial
  evidence) — **not** started here.

## Verdict (corrective continuation — supersedes the initial positive)

```text
RESULT=PARTIAL-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
PRODUCTION_ACTIVATION=UNAVAILABLE-FOR-UNRESOLVED-BOUNDARIES
F3_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-PARTIAL (ordering/shared-context/signed-domain/lifetime unresolved)
F4_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-PARTIAL (ordering/shared-context/signed-domain/lifetime unresolved)
F8_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-PARTIAL (signed-domain round-trip not demonstrated)
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
AUTHORITY_SCOPE=GENESIS-BOUND-DEVNET
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The **initial Run 422 positive verdict was not accepted** by source review and is
**superseded** by this corrective result. Source review identified defects in
genesis provenance, engine/verifier membership, startup ordering, activation
coverage, and shared-context policy. This continuation corrects the tractable,
clearly-scoped defects and keeps activation **fail-closed**; the remaining
boundaries stay unavailable and are reported as blockers rather than claimed.

### Reviewed defects and their disposition

| # | Defect (as reviewed) | Disposition |
| --- | --- | --- |
| D1 | **Genesis multiple-read inconsistency** — `main.rs` re-loaded the genesis, then separately called `compute_print_genesis_hash` (which reopens the file with no authority validation); keys from one read were paired with a hash from another. | **FIXED.** Replaced with the shared `load_verify_and_build_genesis_authority`, which reads the genesis **exactly once** into an owned snapshot, fully re-validates those same bytes via `verify_boot_time_genesis` (structural + authority + chain_id + expected-hash), derives the canonical identity from that same parse, and (when supplied) requires equality with the boot-accepted identity. `compute_print_genesis_hash` is no longer used to establish signing authority. Behavioral tests: `shared_activation_valid_genesis_matching_count_succeeds`, `shared_activation_replaced_input_rejected`, `shared_activation_matching_boot_identity_succeeds`, `shared_activation_expected_hash_mismatch_rejects`, `shared_activation_malformed_genesis_file_rejects`. |
| D2 | **Engine/verifier membership divergence** — authority used `GenesisConfig.validators` while the engine derived `num_validators` from `static_peers.len()+1`. | **FIXED (fail-closed reject).** The shared boundary rejects any `peer_derived_count != genesis_authority_count` (`MembershipCountMismatch`) rather than silently resizing. Consensus membership is defined by the committed authority; the connected-peer count can never resize/redefine it. Behavioral tests: `shared_activation_membership_count_mismatch_rejects`, `shared_activation_valid_genesis_matching_count_succeeds`, `shared_activation_out_of_range_local_id_rejects`. |
| D3 | **Activation flag ignored outside `run_p2p_node`** — LocalMesh could accept `--consensus-authority-from-genesis` without executing any validation. | **FIXED.** LocalMesh startup now rejects the flag non-zero with a precise diagnostic (`does not implement genesis-bound consensus authority activation`) rather than silently ignoring an explicit security request. Guard test: `main_rs_rejects_genesis_activation_under_local_mesh`. |
| D4 | **P2P service starts before authority validation** — `P2pNodeBuilder::build` (and the engine `num_validators` config) run before the authority checks. | **PARTIAL / UNRESOLVED.** The authority/signer/membership validation still runs after `builder.build(...)` and after the engine config is assembled, so the transport is constructed before the authority is proven. Inbound consensus frames are buffered on the bounded `ChannelConsensusHandler` channel and only drained by the consensus loop that is spawned *after* the verification context is enforced; but a full reorder that completes all authority validation **before** transport construction is a deep restructuring of the ~2600-line `run_p2p_node` and is **not** performed here. Activation therefore remains reported UNAVAILABLE for this boundary. |
| D5 | **Shared context across Proposal/Vote + Timeout/NewView** — one context; "flag off ⇒ None" is not universally true because the legacy CLI-key path can still build the shared context. | **UNRESOLVED (documented blocker).** No separate Proposal/Vote canonical-authority activation boundary is introduced here; the immutable crypto components remain shared. See `shared_context_impact.txt`. |
| D6 | **Signed-domain gap** — an authority commitment is not a signature-domain binding; replay across accepted identities not disproved. | **UNRESOLVED (documented blocker).** Round-trip / wrong-genesis / wrong-chain signature rejection is **not** demonstrated with the real backend here. Requires a versioned protocol change that is out of this task's scope. See `adversarial_matrix.txt` / `verification_context_trace.txt`. |
| D7 | **Genesis-static lifetime** — an immutable provider does not prove continued authorization across epoch/membership/restore transitions. | **UNRESOLVED (documented blocker).** No new lifetime enforcement beyond the existing per-startup re-validation is added. |

Because D4–D7 remain, no positive activation boundary is claimed and the verdict
is **PARTIAL** with production activation reported UNAVAILABLE for the unresolved
boundaries.

## What changed

Route A (genesis-bound). A new opt-in, fail-closed production flag
`--consensus-authority-from-genesis` lets the standalone `qbind-node` production
path construct the consensus verification/signing context from the
**boot-verified canonical genesis** (`GenesisConfig.validators[].pqc_public_key`,
ML-DSA-44) plus an operator-supplied local signing key, instead of the
uncommitted `--validator-consensus-key` CLI overrides used by Runs 031–033.

Changed files — reviewed implementation (`af38558`) plus this corrective delta:

| File | Change |
| --- | --- |
| `crates/qbind-node/src/genesis_consensus_authority.rs` | Route A module + 14 unit tests; **corrective:** added shared `load_verify_and_build_genesis_authority` (single-snapshot provenance + boot-identity equality + membership-count reject) and `GenesisAuthorityActivationError`. |
| `crates/qbind-node/src/main.rs` | genesis-authority resolution + bridge wiring (fail-closed); **corrective:** retain boot-accepted canonical hash, thread it into `run_p2p_node`, call the shared single-snapshot boundary, reject the flag under LocalMesh. |
| `crates/qbind-node/src/cli.rs` | `--consensus-authority-from-genesis` flag (unchanged this continuation). |
| `crates/qbind-node/src/lib.rs` | `pub mod genesis_consensus_authority;` (unchanged this continuation). |
| `crates/qbind-node/tests/run_422_genesis_consensus_authority_tests.rs` | **corrective:** +9 behavioral tests for the shared boundary + updated source guards (15 total). |

## Activation semantics (fail-closed)

When `--consensus-authority-from-genesis` is set, P2P startup routes through the
single shared boundary `load_verify_and_build_genesis_authority`, which:

1. requires an external `--genesis-path` (already boot-verified by Run 102);
2. reads the genesis **exactly once** into an owned snapshot;
3. fully re-validates those same bytes and derives the canonical identity from
   that same parse (no second file read for the hash);
4. requires equality with the boot-accepted identity when available (reject a
   file swapped after boot);
5. builds an immutable, validated `GenesisConsensusAuthority`;
6. rejects any engine/verifier membership-count disagreement;

then `main` requires a loaded local signer, enforces
`signer_public_key == genesis_committed_key`, and feeds the **same**
`try_build_timeout_verification_context` used elsewhere. Any failure exits
non-zero; when the flag is absent, behavior is byte-identical to the Run 421
default (`None` + `ConsensusVerificationPolicy::Required`). Under `--network-mode
local-mesh` the flag is rejected non-zero.

## Validation summary (this corrective continuation)

- Run 422 activation tests: **15/15** (`run_422_genesis_consensus_authority_tests`).
- Module unit tests: **14/14** (`genesis_consensus_authority`).
- Regressions: `run_420` (3/3), `run_418` sender-binding (18/18), `run_418`
  newview demux (3/3) — all pass, no F6/policy regression.
- `qbind-node` release binary build: see `commands.txt` for command + exit code.
- rustfmt/clippy: changed files formatted; pre-existing repo-wide drift/warnings
  (e.g. `p2p_node_builder.rs` `cert_bound_node_id` dead_code) unchanged and not
  claimed clean.
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