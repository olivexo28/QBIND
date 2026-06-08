# Run 218 — Release-binary governance-execution runtime-arming evidence

## Scope

Run 218 is the release-binary evidence run for the Run 217 governance-execution
runtime-arming carrier
(`GovernanceExecutionRuntimeArmingConfig` in
`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`).

Where Run 216 proved the Run 215 hidden selector parses on the real binary, Run
218 proves on real `target/release/qbind-node` plus a release-built helper that
the resolved policy is **consumed through the Run 217 runtime-arming carrier**
and routed into the production preflight contexts:

* default remains `GovernanceExecutionPolicy::Disabled`;
* the hidden CLI flag `--p2p-trust-bundle-governance-execution-policy` and env
  var `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` reach runtime arming;
* CLI-over-env precedence is deterministic at the runtime config boundary and
  invalid values fail closed **before any runtime mutation**;
* the armed policy reaches all seven runtime preflight surfaces through the
  carrier (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
  local peer-candidate-check, live inbound `0x05`, peer-driven drain);
* fixture and emergency-council fixture governance are evidence-only and
  non-production;
* production/on-chain/MainNet governance execution remains unavailable/fail-closed;
* MainNet peer-driven apply remains refused even with
  `mainnet-governance-required` and fixture governance approval.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
exit_codes/
helper_evidence/run_218/
reachability/source_reachability.txt
reachability/cli_flag_reachability.txt
reachability/runtime_hook_reachability.txt
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
test_results/
```

## Reproduce

```bash
bash scripts/devnet/run_218_governance_execution_runtime_arming_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while
preserving the three tracked files.

## Honest limitations

* The hidden CLI/env selector for `GovernanceExecutionPolicy` is additive and
  disabled by default; default behaviour remains
  `GovernanceExecutionPolicy::Disabled`. An invalid selector value fails closed
  with a typed parse error — the runtime config is never constructed — and
  CLI-over-env precedence is deterministic. There is no schema / wire / metric
  drift.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet governance execution always returns the typed unavailable outcome,
  regardless of the armed policy.
* No real on-chain governance proof verifier is implemented.
* Fixture governance execution remains DevNet/TestNet evidence-only and is
  refused on a MainNet trust domain.
* Emergency council fixture governance is explicit and non-production.
* The live inbound `0x05` runtime path does not yet thread a per-connection
  governance-execution policy from its live runtime config; the carrier exposes
  the policy injection at the source/test level so the armed policy reaches the
  Run 213 live inbound `0x05` routing helper and an invalid live `0x05`
  candidate is not propagated, staged, or applied. This is the documented A16
  limitation.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even with
  a fixture governance approval.
* Full C4 remains open. C5 remains open.
