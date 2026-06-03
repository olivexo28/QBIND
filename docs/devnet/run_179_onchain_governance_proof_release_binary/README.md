# Run 179 — Release-binary OnChainGovernance proof boundary evidence

## Scope

Closes the Run 178-deferred release-binary boundary for the typed
`OnChainGovernance` proof verifier landed in Run 178. Run 178 added the
source/test typed verifier, reserved policy, additive wire shape, and
canonical commitment bytes for the `OnChainGovernance` proof family, but
explicitly stopped short of release-binary evidence and explicitly
stopped short of wiring the verifier into any production caller — see
`crates/qbind-node/src/lib.rs:231` (sole `pub mod`) and the absence of
`verify_onchain_governance_proof` callers anywhere under
`crates/qbind-node/src/` except the defining module itself.

Run 179 captures **release-binary fixture/boundary evidence only**:

* a release-built helper
  (`crates/qbind-node/examples/run_179_onchain_governance_proof_release_binary_helper.rs`)
  drives the full Run 178 A1–A7 / R1–R25 corpus through
  `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`, and the additive
  `OnChainGovernanceProofWire` JSON round-trip in **release mode**, with
  bit-identical fixtures (KEY_A / KEY_B / ROOT_FP / CHAIN_ID /
  GENESIS_HASH_A-B / DIGEST_2-3 / RATIFY_DIGEST_1 / GOV_DOMAIN /
  PROPOSAL_ID / PROPOSAL_DIGEST / UNIQUE_DECISION_ID / NOW=1_700_000_000)
  so the canonical commitment bytes match the Run 178 source-test target
  exactly;
* the real `target/release/qbind-node` binary is exercised to confirm
  no new operator-visible CLI surface was introduced (no `--help` flag
  named `onchain-governance` / `run-179` is surfaced) and to capture
  provenance;
* a source-reachability proof is recorded showing
  `verify_onchain_governance_proof`,
  `validate_lifecycle_with_onchain_governance_proof`,
  `OnChainGovernanceProofPolicy::AllowFixtureSourceTest`, and
  `OnChainGovernanceProofWire` have **zero** production callers under
  `crates/qbind-node/src/`.

This is the honest **release-binary fixture/boundary** counterpart of
Run 178; release-binary **production-surface** evidence is deferred to
the next integration run (the run that wires the verifier into a
production marker-decision caller behind a hidden selector, mirroring
the Run 165 / Run 169 / Run 171 / Run 173 / Run 176 / Run 177
governance-gate composition).

## Strict scope (no production-source change)

Per `task/RUN_179_TASK.txt`:

* **No production source change.** Run 179 introduces no new field,
  enum variant, CLI flag, env knob, schema bump, wire shape, metric, or
  exit code in any production module. The only new file in
  `crates/qbind-node/` is `examples/run_179_onchain_governance_proof_release_binary_helper.rs`,
  which is built as a Cargo example and is not linked into the
  production `qbind-node` binary.
* **No MainNet apply enablement.** The Run 147 FATAL invariant
  (`MainNet peer-driven apply remains FATAL refusal regardless of CLI /
  env / fixture state`) survives Run 179 unchanged.
* **No real on-chain verifier / bridge / light-client / KMS-HSM /
  validator-set rotation / autonomous apply / apply-on-receipt /
  peer-majority authority** is introduced.
* **No schema / wire / metric drift** beyond the Run 178 additive
  wire shape (`ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION = 1`,
  optional sibling field on `GovernanceAuthorityProofWire`).

## What is committed

Only `README.md`, `summary.txt`, and `.gitignore` are tracked. Every
per-run artifact under this directory (`logs/`, `data/`, `exit_codes/`,
`marker_hashes/`, `sequence_hashes/`, `data_inventories/`,
`grep_summaries/`, `reachability/`, `test_results/`, `fixtures/`,
`helper_evidence/`, `helper_corpus/`, `provenance.txt`,
`fixture_manifest.txt`, `scenario_assertions.txt`,
`negative_invariants.txt`) contains absolute paths and ephemeral data
and is `.gitignore`d on purpose, matching the
Run 153 / 155 / 158 / 172 / 175 / 177 evidence-archive convention.

## Reproducibility

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_179_onchain_governance_proof_release_binary_helper
bash scripts/devnet/run_179_onchain_governance_proof_release_binary.sh
```

`OUTDIR` defaults to this directory. The harness is **idempotent** —
it wipes `logs/`, `data/`, `exit_codes/`, `helper_evidence/`,
`reachability/`, `test_results/`, and `grep_summaries/` on every
invocation and re-mints the helper corpus from the release-built
helper. The summary line written at the end of `summary.txt` is the
canonical verdict.

## Scenario corpus

Mirrors `task/RUN_179_TASK.txt` exactly, which mirrors the Run 178
source/test corpus one-for-one in release mode:

* **A1 — A7**: Disabled-skip (legacy back-compat); RequiredSidecar with
  Disabled policy; AllowFixtureSourceTest + Validate accept;
  AllowFixtureSourceTest + Ratify accept; AllowFixtureSourceTest +
  Revoke accept; AllowFixtureSourceTest + EmergencyRevoke accept;
  AllowFixtureSourceTest with co-present
  `GovernanceAuthorityProofWire` (Run 167) sibling does not weaken or
  alter `OnChainGovernance` typed verification.
* **R1 — R25**: missing-when-required; lifecycle digest mismatch (R6 +
  R6b carrier mismatch); root-fingerprint mismatch; environment
  mismatch (R8); chain-id mismatch (R9); genesis-hash mismatch (R10);
  signature mismatch (R11) and tampered-message variant (R11b);
  threshold underflow (R12) and zero-quorum variant (R12b); replay
  guard (R13); freshness guard (R14); unsupported suite-id (R16) and
  unsupported wire schema version (R16b); refused suite-id `0xA2`
  (R17), refused suite-id with `Disabled` policy (R17b),
  `Disabled`-with-sidecar refusal (R17c), `RequiredSidecar`-without-
  sidecar refusal (R17d); duplicate signers (R18); pseudo-Validate
  rejection (R19); pseudo-Ratify rejection (R20); pseudo-Revoke
  rejection (R21); pseudo-EmergencyRevoke rejection (R22); MainNet
  refusal (R23); Run 167 backwards-compat (R24) and Run 178
  round-trip (R24b); proposal-id mismatch (R25), proposal-digest
  mismatch (R25b), unique-decision-id mismatch (R25c).

Per-scenario rc, expected typed outcome, actual typed outcome,
canonical commitment bytes (BLAKE3 / SHA3-256), and JSON wire bytes are
written to the helper corpus under `helper_evidence/` and surfaced in
`summary.txt` (regenerated each run).

## Honest limitations preserved

* **Verdict is `partial-positive`, not `strongest-positive`.** The
  Run 178 `verify_onchain_governance_proof` symbol still has zero
  production callers under `crates/qbind-node/src/`. The release-built
  Run 179 helper exercises the verifier in-process through the
  production library symbols. This is honest release-binary
  fixture/boundary evidence; it is **not** release-binary
  production-surface evidence.
* **No real on-chain governance, no execution, no bridge / light
  client / KMS-HSM / validator-set rotation.** Run 179 is fixture-only
  and source-reachability-only — exactly as Run 178 declared its
  scope.
* **MainNet peer-driven apply remains refused** under all
  combinations (Run 147 FATAL invariant). R23 captures this.
* **No claim of full C4 / C5 closure.** OnChainGovernance execution,
  governance program integration, and validator-set rotation remain
  out of scope.

## Negative invariants

Captured in `negative_invariants.txt` (regenerated each run). Highlights:

* No `DummySig` / `DummyKem` / `DummyAead` symbol in any captured log.
* No `fallback to --p2p-trusted-root` and no peer-majority authority
  claim.
* No autonomous apply / apply-on-receipt / governance-execution
  language in helper or `--help` output.
* The Run 178/179 verifier is not surfaced via `qbind-node --help`
  (no new flag named `onchain-governance` or `run-179`).
* No new schema / wire / metric drift beyond the Run 178 additive
  shape.

## Cross-references

* `task/RUN_179_TASK.txt` — driving spec (acceptance / rejection
  matrix, validation commands, deliverables, honest verdict).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_179.md` — canonical evidence
  report for this run.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md` — Run 178 source/test
  typed verifier.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md` — closest precedent
  for the release-binary boundary template (live `0x05`
  governance-proof carrier).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_172.md` — single-binary
  release evidence layout Run 179 inherits its harness shape from.
* `docs/devnet/run_172_governance_required_policy_release_binary/` —
  single-binary release evidence template Run 179 mirrors.
* `crates/qbind-node/src/pqc_onchain_governance_proof.rs` — Run 178
  module (untouched by Run 179).
* `crates/qbind-node/tests/run_178_onchain_governance_proof_tests.rs` —
  Run 178 source/test corpus mirrored by Run 179 in release mode
  (untouched by Run 179).
