# QBIND DevNet Evidence — Run 109

**Task:** `task/RUN_109_TASK.txt` — ratification enforcement on the live inbound `0x05` peer-candidate wire validation path.

**Verdict:** **partial-positive**. Source and focused integration-test proof landed; release-binary live multi-node evidence was not produced in this run (Run 089's N=3 DevNet propagation harness covers the live `0x05` path mechanically, but no fresh multi-node ratification capture was added under Run 109).

## Implemented surface

Run 109 wires the existing Run 105 / 106 / 107 bundle-signing-key ratification model into the live inbound `0x05` peer-candidate dispatcher **before** the inner Run 069 validation accepts the candidate and **before** the Run 088 propagation gate can rebroadcast it. No new metric family, no new wire format, no parallel validation stack.

- `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
  - adds `PeerCandidateWireReceiver::try_handle_frame_with_ratification(...)`, a thin wrapper around the existing `try_handle_frame_inner(...)` private path that routes the inner Run 076 validator through `try_accept_with_ratification(...)` (the same Run 107 entry point);
  - adds `LiveRatificationConfig` — the owned-fields version of the borrowed `RatificationEnforcementContext` (authority block + canonical genesis hash + per-environment policy enum + chain id string + optional ratification sidecar + Run 106 enforcement policy + Run 106 gate decision);
  - adds `LivePeerCandidateWireDispatcherConfig::live_ratification: Option<LiveRatificationConfig>`;
  - dispatcher now reborrows the owned context per-frame and chooses the ratification-aware receiver path iff `live_ratification.is_some()` AND `gate_decision.should_invoke()`;
  - introspection: `LivePeerCandidateWireDispatcher::ratification_gate_is_invoked()` and `live_ratification()`.
- `crates/qbind-node/src/main.rs`
  - the live dispatcher build path in `run_p2p_node` consults `ratification_gate_decision(config.environment, args.p2p_trust_bundle_ratification_enforcement_enabled)`;
  - on `Invoke(_)`, calls the existing `build_run_105_reload_check_context(&args, &config)` helper (same one Run 105 and Run 107 use) and wires the owned `LiveRatificationConfig`;
  - on `Skip(_)` (DevNet, no opt-in), the dispatcher is built with `live_ratification: None` and uses the pre-Run-109 unguarded path;
  - on context-build error AND `should_invoke()`, the binary refuses to install the dispatcher (fail-closed FATAL; no fallback path, no apply, no sequence write, no session eviction).

No changes to the Run 076 validator type, the Run 078 wire envelope, the Run 079 receiver internals, the Run 088 propagation state machine, the Run 088 metric family, or the Run 098 epoch read.

## Decision on ratification object input for live candidates

Run 109 reuses the **already-existing Run 105 sidecar model** for the live wire path: the operator-supplied `--p2p-trust-bundle-ratification <PATH>` JSON object (the same flag Runs 105 and 107 use) is loaded once at startup, owned by the dispatcher for the process lifetime, and reborrowed per-frame. No new wire-format field, no peer-supplied ratification object, no separate sidecar.

This is the most conservative choice consistent with the strict scope:

- It does not change the `0x05` wire envelope.
- It does not introduce peer-supplied ratification material (which would re-open the "who ratifies the ratification" recursion that Runs 100–105 explicitly resolved by binding to the genesis authority root).
- It is honest about coverage: live frames are validated against the **locally configured** ratification object, which means the live `0x05` path enforces "is this candidate's bundle-signing key ratified by the genesis authority **and matches the local operator's ratification record**". A future run can extend this with peer-distributed ratification objects when (and only when) the wire format gains a new typed field for that purpose.

## Policy behavior

The same Run 106 `ratification_gate_decision` function used by startup, reload-check, and the Run 107 local peer-candidate check:

| Environment | Opt-in flag | Run 109 live `0x05` decision                              |
|-------------|-------------|-----------------------------------------------------------|
| MainNet     | absent or present | invoke ratification (`mainnet-default-strict`)      |
| TestNet     | absent or present | invoke ratification (`testnet-default-strict`)      |
| DevNet      | absent      | skip ratification; preserve pre-Run-109 unguarded path    |
| DevNet      | present     | invoke ratification (`devnet-operator-opt-in`)            |

MainNet cannot reach the Skip branch because `ratification_gate_decision` never returns `Skip` for MainNet/TestNet — this is pinned by `run109_mainnet_dispatcher_invokes_gate_regardless_of_devnet_opt_in_flag` and `run109_policy_matches_run106_for_every_environment`.

## Propagation interaction (Run 088 gating proof)

The Run 088 propagation step in `maybe_propagate_after_validation` runs **after** `try_handle_frame_inner` and is gated on a `PeerCandidateOutcome::Validated(_)` outcome. The ratification-aware receiver path returns `PeerCandidateOutcome::Rejected(PeerCandidateRejection::ValidationFailed(ReloadCheckError::RatificationRefused(..)))` on every ratification refusal — the SAME shape Runs 105 / 107 already produce. The existing Run 088 invalid-outcome branch (`PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(_))`) already routes to `record_peer_candidate_propagation_suppressed_invalid()` and returns without enqueueing any frame. Therefore:

- unratified candidates → `Rejected(RatificationRefused(Missing))` → propagation suppressed (`suppressed_invalid_total` increments, no `sent_total` increment);
- bad ratification → `Rejected(RatificationRefused(Verifier(BadSignature)))` → propagation suppressed;
- valid ratified candidates → `Validated(_)` → propagation behaves exactly as Run 088 already specified (source-peer exclusion, duplicate suppression, rate limiting, max-fanout).

Pinned by:

- `run109_unratified_candidate_does_not_rebroadcast`
- `run109_bad_ratification_candidate_does_not_rebroadcast`
- `run109_valid_ratified_candidate_may_rebroadcast_under_run088_rules`
- `run109_duplicate_unratified_candidate_does_not_become_accepted_via_dup_cache`

## Non-mutation audit

Run 109 inherits the Run 076 / 077 / 078 / 079 / 088 strict non-mutation contract by construction:

- the `RatificationEnforcementContext` is read-only at every layer;
- the inner `try_accept_with_ratification` reuses the existing Run 069 `validate_candidate_bundle_full_with_ratification` which holds the `peek_sequence` invariant from Run 055;
- the receiver does not hold a `LivePqcTrustState`, sequence writer, or `P2pSessionEvictor`;
- no `_applied_total` metric family was added.

Pinned by:

- `run109_unratified_rejection_does_not_write_sequence_file`
- `run109_bad_ratification_rejection_does_not_write_sequence_file`
- `run109_valid_ratified_acceptance_does_not_write_sequence_file_either`

## Test evidence

New focused test file:

- `crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs`

Passing focused run:

```text
cargo test -p qbind-node --test run_109_pqc_peer_candidate_wire_live_ratification_tests

running 23 tests
test run109_devnet_with_opt_in_invokes_gate_and_rejects_missing_ratification ... ok
test run109_devnet_without_opt_in_skips_gate_and_uses_legacy_path ... ok
test run109_bad_ratification_rejection_does_not_write_sequence_file ... ok
test run109_bad_ratification_candidate_does_not_rebroadcast ... ok
test run109_duplicate_unratified_candidate_does_not_become_accepted_via_dup_cache ... ok
test run109_mainnet_bad_signature_rejects ... ok
test run109_mainnet_dispatcher_invokes_gate_regardless_of_devnet_opt_in_flag ... ok
test run109_mainnet_missing_authority_key_material_rejects ... ok
test run109_mainnet_missing_ratification_rejects_before_validation_success ... ok
test run109_mainnet_malformed_authority_key_material_rejects ... ok
test run109_mainnet_transport_root_cannot_ratify_signing_keys ... ok
test run109_mainnet_unknown_authority_root_rejects ... ok
test run109_mainnet_unsupported_suite_rejects ... ok
test run109_mainnet_valid_ratification_passes_live_validation ... ok
test run109_policy_matches_run106_for_every_environment ... ok
test run109_mainnet_wrong_chain_rejects ... ok
test run109_no_live_ratification_installed_preserves_pre_run109_unguarded_path ... ok
test run109_mainnet_wrong_environment_rejects ... ok
test run109_testnet_default_strict_rejects_missing_ratification ... ok
test run109_unratified_candidate_does_not_rebroadcast ... ok
test run109_unratified_rejection_does_not_write_sequence_file ... ok
test run109_valid_ratified_acceptance_does_not_write_sequence_file_either ... ok
test run109_valid_ratified_candidate_may_rebroadcast_under_run088_rules ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Regression runs (unchanged before/after Run 109):

```text
cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --test run_107_peer_candidate_ratification_tests
cargo test -p qbind-node --lib   # 1099 passed
```

All pass. The Run 079 and Run 088 test files were updated to set `live_ratification: None` for the existing pre-Run-109 behaviour they pin (the legacy path is bit-for-bit preserved).

## Release-binary live evidence

Not produced in this run. The Run 089 N=3 DevNet release-binary propagation harness mechanically covers the live `0x05` path; layering a fresh ratification-aware multi-node capture on top of it would require regenerating the harness with a populated genesis authority block + sidecar, which is feasible but was descoped in this run to keep changes minimal.

A future run (Run 110 or later) should produce:

- Scenario 1: MainNet/TestNet live valid ratification passes validation (and may rebroadcast under Run 088 rules);
- Scenario 2: MainNet/TestNet live missing ratification rejects, no rebroadcast, no mutation;
- Scenario 3: MainNet/TestNet live bad ratification rejects, no rebroadcast, no mutation;
- Scenario 4: DevNet no-opt-in legacy preserved; DevNet opt-in enforces.

The source/test proof above is sufficient to assert the same invariants at the library level.

## Strict non-goals reaffirmed

Run 109 does NOT implement:

- peer-driven live apply (the dispatcher still holds no `LivePqcTrustState`, `LiveReloadController`, or `P2pSessionEvictor` handle — by construction);
- reload-apply enforcement (the Run 070 apply path is untouched);
- SIGHUP enforcement (the Run 074 live reload path is untouched);
- signing-key rotation or revocation lifecycle;
- authority anti-rollback persistence;
- persistent ratified-authority state;
- KMS/HSM custody;
- governance or validator-set rotation;
- broad changes to the trust-bundle or peer-candidate wire formats;
- static production source-code anchors;
- fallback roots / fallback signing keys;
- transport-root → bundle-signing authorisation (the `TransportRootNotAllowed` rejection is pinned in `run109_mainnet_transport_root_cannot_ratify_signing_keys`);
- treating local config alone as MainNet signing authority;
- full C4 closure or C5 closure.

## C4 sub-piece status

Before Run 109: the live `0x05` path validated candidates through Run 076 / 069 / 088 but did NOT consult the Run 103 / 105 / 106 / 107 ratification verifier — a hole in the "peer-supplied / gossiped bundle acceptance" C4 sub-piece.

After Run 109: the live `0x05` path enforces ratification with MainNet/TestNet default-strict policy AND the Run 088 propagation gate suppresses every unratified candidate. The C4 sub-piece "live inbound peer-candidate ratification" is now narrowed to:

- still **open**: peer-driven live apply, reload-apply ratification, SIGHUP ratification, signing-key rotation/revocation, authority anti-rollback persistence, peer-distributed ratification objects on the wire, fast-sync ratification parity, KMS/HSM, governance;
- now **closed (source/test)**: live inbound peer-candidate `0x05` validation enforces ratification on MainNet/TestNet by default and on DevNet under opt-in; unratified / bad / wrong-chain / wrong-env / unknown-root / transport-root / unsupported-suite / missing-key-material candidates are rejected BEFORE validation success and BEFORE any Run 088 rebroadcast; non-mutation invariants are pinned by tests.

Full C4 closure remains explicitly out of scope until peer-driven live apply, reload-apply ratification, SIGHUP ratification, rotation/revocation lifecycle, authority anti-rollback persistence, and KMS/HSM custody are also implemented and release-binary-evidenced.
