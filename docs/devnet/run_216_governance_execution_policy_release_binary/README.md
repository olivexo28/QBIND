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

The harness regenerates artifacts and atomically replaces `summary.txt`.
Use an exclusive `OUTDIR`: one invocation/writer, including its children,
until all children have completed. Invocation IDs are not locks.

## Current-run regression verdict

Before any work, stderr identifies `run_id` and the summary is replaced with
that invocation's `verdict: INCOMPLETE`. All 35 integration targets and both
library commands are required. Ordinary Cargo failures do not stop later
safely capturable commands; missing targets fail rather than skip.
Existing logs and numeric `.rc` files remain. The aggregation input is
`exit_codes/regression_results.tsv`: `run_id=<id>`, then the TSV header
`command_key`, `state`, `rc`, and exactly 37 rows. Keys are
`run216:test:<target>` and `run216:lib:<label>`; library labels are
`pqc_authority` and `lib_all`. States are `returned` with shell status 0-255,
or `missing_target` / `capture_error` with an empty status.

The harness validates identity, schema, exact inventory, uniqueness and
status-file consistency before incorporating records into the summary.
Complete nonzero/missing-target results yield `FAIL`; invalid/incomplete
records or I/O errors yield `INCOMPLETE`, taking precedence over failure.
Both exit nonzero. PASS requires every required result to be zero and
successful atomic summary publication, not human-readable PASS text alone.
Scenario/helper/denylist assertions remain separate.

Summary writes use checked same-directory temporary files and rename.
Initialization failure stops work and warns that any old summary is
untrusted. SIGINT/SIGTERM/SIGHUP trigger best-effort INCOMPLETE repair and
nonzero exit when Bash runs the handler; foreground commands can defer it.
The invoking supervisor must signal the process group, allow bounded cleanup,
contain survivors if needed, and reap children before OUTDIR reuse.
SIGKILL, host failure or unavailable storage may prevent repair. Atomic
visibility is not crash durability. Success requires matching invocation
identity, validated incorporated records, and parent/operator-observed normal
zero exit; a PASS file without that completion evidence is insufficient.

The isolated fixture command (from the repository root) is:

```bash
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh /tmp/new-exclusive-fixture-evidence
```

It executes LF-normalized temporary copies with guarded stubs, not real
Cargo/node/helper binaries or the committed CRLF full release harness.
See [bounded evidence](../../security/evidence/a37-1-c2/README.md).

## Honest limitations

* The hidden CLI/env selector for `GovernanceExecutionPolicy` is additive and
  disabled by default; default behaviour remains
  `GovernanceExecutionPolicy::Disabled`. An invalid selector value fails closed
  with a typed parse error, and CLI-over-env precedence is deterministic. There
  is no schema / wire / metric drift.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet governance execution always returns the typed unavailable outcome,
  regardless of the selected policy.
* No real on-chain governance proof verifier is implemented.
* Fixture governance execution remains DevNet/TestNet evidence-only and is
  refused on a MainNet trust domain.
* Emergency council fixture governance is explicit and non-production.
* The Run 215 selector is consumed at the library level; the release binary
  parses the flag (hidden from `--help`) but does not wire a resolved policy
  into a long-running node runtime — arming it enables no production governance.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even with
  a fixture governance approval.
* Full C4 remains open. C5 remains open.