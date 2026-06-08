# Run 216 — Release-binary governance-execution policy-selector evidence

## Scope

Run 216 is the release-binary evidence run for the Run 215 hidden governance-execution policy selector in `crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`.

It proves on real `target/release/qbind-node` plus a release-built helper that:

* default remains `GovernanceExecutionPolicy::Disabled`;
* the hidden CLI flag `--p2p-trust-bundle-governance-execution-policy` and env var `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` are accepted;
* CLI-over-env precedence is deterministic and invalid values fail closed;
* selected policies reach all seven production preflight wrappers;
* fixture and emergency-council fixture governance are evidence-only and non-production;
* production/on-chain/MainNet governance execution remains unavailable/fail-closed;
* MainNet peer-driven apply remains refused.

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`. Everything else is regenerated and ignored:

```text
provenance.txt
logs/
exit_codes/
helper_evidence/run_216/
reachability/source_reachability.txt
reachability/cli_flag_reachability.txt
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
test_results/
```

## Reproduce

```bash
bash scripts/devnet/run_216_governance_execution_policy_release_binary.sh
```

The harness is idempotent: it wipes and regenerates generated artifacts while preserving the three tracked files.