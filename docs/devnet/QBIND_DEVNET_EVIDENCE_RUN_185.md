# QBIND DevNet evidence — Run 185

**Title.** Release-binary OnChainGovernance proof-payload-carrying
accepted-proof evidence on real `target/release/qbind-node`. Closes
the Run 184-deferred release-binary boundary for the additive
optional `onchain_governance_proof` sibling on the v2 ratification
sidecar JSON wire and for the Run 182 production call-site wrappers
that consume it.

**Status.** PASS (release-binary, partial-positive) — the Run 178
typed `OnChainGovernanceProof` material can now be carried through
the existing production v2 ratification sidecar JSON via the Run 184
additive optional `onchain_governance_proof` sibling and reaches the
seven Run 182 production call-site named entries on real
`target/release/qbind-node` payload/context paths. Real
`target/release/qbind-node --p2p-trust-bundle-reload-check
<sidecar-with-sibling>
--p2p-trust-bundle-onchain-governance-fixture-allowed` accepts a
fully-valid DevNet fixture proof carried through the v2 sidecar
sibling on the validation-only surface, with no marker write, no
sequence write, no live trust swap, no session eviction, and no
Run 070 call. The matching reload-apply binary surface arms the
selector, loads the sidecar, extracts and parses the typed sibling,
invokes the Run 182 reload-apply named callsite entry, and on a
non-long-running invocation returns the Run 070-honest
`ReloadApplyError::UnsupportedRuntimeContext`; the matching accepted
typed outcome is captured in release mode through the same library
symbols by the new Run 185 release-built helper. The Run 184
release-binary boundary previously deferred is now closed for the
additive optional sibling and for every Run 182 named callsite
entry. The default policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`. MainNet peer-driven apply
remains refused (Run 147 FATAL invariant) even with the selector
armed AND a fully-valid MainNet fixture proof carried through the
Run 184 sibling. Malformed sibling payloads (non-object,
unknown_schema, empty required field, empty proof bytes) fail closed
at the typed `OnChainGovernanceProofPayloadParseError` boundary
*before* any verifier or marker decision runs on every surface,
regardless of policy. Real on-chain governance proof verification,
governance execution, KMS/HSM custody, validator-set rotation,
bridge / light-client integration, autonomous apply, and
apply-on-receipt all remain unimplemented. Full C4 and C5 remain
**OPEN** invariants tracked by the contradiction ledger.

**Driving spec.** `task/RUN_185_TASK.txt`.

## 1. Strict scope

Run 185 closes the release-binary boundary that Run 184 explicitly
deferred. Run 184 introduced — at source/test level only — the
additive optional `onchain_governance_proof` sibling on the existing
v2 ratification sidecar JSON wire, the typed
`OnChainGovernanceProofWire` parsed from that sibling, the Run 184
loader path
[`load_v2_ratification_sidecar_with_onchain_governance_proof_*`](
  ../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs),
the
[`callsite_context_with_loaded_onchain_governance_proof`](
  ../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs)
constructor that materializes
[`OnChainGovernanceCallsiteContext`](
  ../../crates/qbind-node/src/pqc_onchain_governance_callsite_wiring.rs)
with the typed proof reference attached, and the seven
`route_loaded_onchain_governance_proof_to_*_callsite_decision`
helpers that route the loaded payload through every Run 182 named
production call-site entry.

Run 185 is **strictly release-binary boundary evidence** and adds
**only**:

* A new release-built example helper
  [`run_185_onchain_governance_payload_release_binary_helper`](
    ../../crates/qbind-node/examples/run_185_onchain_governance_payload_release_binary_helper.rs)
  that, in release mode and through the production library symbols,
  mints v2 ratification sidecar JSONs both with and without the
  Run 184 additive sibling, drives every
  `route_loaded_onchain_governance_proof_to_*_callsite_decision`
  helper across the A1/A1b/A2/A6/R2/R26 acceptance/rejection
  matrix, and exits non-zero if any scenario diverges from its
  expected typed outcome.
* A new release-binary harness
  [`scripts/devnet/run_185_onchain_governance_payload_release_binary.sh`](
    ../../scripts/devnet/run_185_onchain_governance_payload_release_binary.sh)
  that builds `target/release/qbind-node`, the Run 179 verifier-corpus
  helper, and the new Run 185 payload-carrying helper; drives the
  release-binary acceptance/rejection matrix on real
  `target/release/qbind-node` (default-Disabled invariants,
  CLI selector arming, env selector arming across truthy/falsey
  variants, reload-check loading a sidecar with the Run 184 sibling,
  reload-apply loading the same sidecar, malformed-sibling
  rejection, and MainNet refusal under armed selector AND
  fully-valid MainNet fixture proof); records source-reachability
  for every Run 178 / 180 / 182 / 184 production symbol; records the
  denylist of forbidden tokens; records the no-mutation proof for
  every rejected scenario; records the mutation/no-mutation proof
  for accepted reload-check / reload-apply scenarios; and runs the
  full targeted regression slice in release mode.
* A canonical evidence archive
  [`docs/devnet/run_185_onchain_governance_payload_release_binary/`](
    ./run_185_onchain_governance_payload_release_binary/)
  tracking only `README.md`, `summary.txt`, and `.gitignore`; every
  per-run artifact (logs, exit codes, grep summaries, sidecars,
  reachability dumps, helper evidence trees, denylist verification,
  mutation/no-mutation proofs, regression test logs) is regenerated
  on every harness invocation and lives under `.gitignore`.
* This canonical evidence Markdown.

Run 185 does **not**:

* introduce any production source change beyond what Run 184 already
  added at source/test level,
* bump any wire schema version,
* add any new metric / counter / log line beyond Run 180's
  pre-existing armed banner,
* change any default policy on any surface,
* enable MainNet peer-driven apply,
* implement any real on-chain proof verifier,
* implement governance execution / KMS-HSM / validator-set rotation,
* expose anything new on the public binary CLI `--help` surface (the
  Run 180 selector remains hidden via `clap(hide = true)`),
* claim closure of C4 or C5.

## 2. Acceptance summary

All A1–A9 acceptance scenarios and R1–R26 rejection scenarios listed
in `task/RUN_185_TASK.txt` are exercised either:

* on real `target/release/qbind-node` directly, by the
  Run 185 harness, for the scenarios that have a public binary
  surface (default-Disabled invariants, CLI/env selector arming,
  reload-check / reload-apply with a v2 sidecar carrying the
  Run 184 sibling, malformed-sibling rejection at reload-check,
  MainNet refusal under armed selector AND fully-valid MainNet
  fixture proof); or
* in release mode through the production library symbols, by the
  release-built Run 185 helper, for every Run 182 named callsite
  entry across every Run 180 per-surface composed wrapper, including
  the `live inbound 0x05` and `peer-driven drain` surfaces whose
  end-to-end wire carriers may not yet be wired in this tree (the
  honest limitation is recorded explicitly in
  `mutation_proof.txt` / `no_mutation_proof.txt`).

Run command (canonical):

```text
bash scripts/devnet/run_185_onchain_governance_payload_release_binary.sh
```

The harness is idempotent and regenerates every per-run artifact
under `docs/devnet/run_185_onchain_governance_payload_release_binary/`
on every invocation. The canonical verdict line is written to
`docs/devnet/run_185_onchain_governance_payload_release_binary/summary.txt`.

The release-built helpers (Run 179 verifier corpus + Run 185
payload-carrying corpus) each exit non-zero on any scenario divergence
from its expected typed outcome, so the `helper_summary.txt` files
under `helper_evidence/run_179/` and `helper_evidence/run_185/` are
the canonical machine-checkable verdicts for the in-process
release-mode coverage of the A1–A9 / R1–R26 corpus.

## 3. Honest limitations

* **Release-binary boundary only — no new production code.** Run 185
  ships no production source change; it only proves that the Run 184
  additive optional sibling and the Run 182 named call-site entries
  can be reached in release mode on real `target/release/qbind-node`
  payload/context paths.
* **Default Disabled preserved.** Carrying a fully-valid DevNet
  fixture proof through the Run 184 sibling has zero observable
  effect unless the hidden Run 180 `AllowFixtureSourceTest` selector
  is armed via the existing CLI flag
  (`--p2p-trust-bundle-onchain-governance-fixture-allowed`) or env
  var (`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  with a truthy value), both of which remain hidden from
  `qbind-node --help` per Runs 180/181/183.
* **MainNet still refused.** The Run 182 peer-driven drain callsite
  entry continues to refuse MainNet peer-driven apply *before*
  invoking the underlying verifier (Run 147 FATAL invariant), so
  even a fully-valid MainNet fixture proof carried through the
  Run 184 sibling cannot enable MainNet peer-driven apply.
* **Malformed sibling fail-closed surface-uniformly.** When the
  optional sibling is structurally malformed (non-object,
  unknown schema, empty required field, empty proof bytes), every
  surface short-circuits to a typed
  `OnChainGovernanceProofPayloadParseError` *before* any verifier or
  marker decision runs, regardless of policy.
* **Reload-apply on a non-long-running qbind-node invocation
  honestly returns `UnsupportedRuntimeContext`.** Per Run 070, the
  Run 134 reload-apply path requires a runtime trust-context handle
  the binary does not have on a one-shot invocation; the matching
  accepted typed outcome through the Run 182 reload-apply named
  callsite entry is captured in release mode through the same
  library symbols by the Run 185 helper corpus.
* **`live 0x05` and peer-driven drain end-to-end carriers may not
  yet exist.** Run 184 added the additive sibling on the v2
  ratification sidecar JSON wire used by reload-check / reload-apply
  / startup `--p2p-trust-bundle` / SIGHUP. The live `0x05`
  peer-candidate envelope and the peer-driven drain inbound payload
  may not yet carry the typed OnChainGovernance proof end-to-end on
  a real binary. Where they do not, Run 185 captures the
  source-reachability for the matching Run 182 named callsite entry
  through the release-built helper in release mode AND records the
  boundary explicitly in `mutation_proof.txt`.
* **No real on-chain proof verifier.** Run 185 still carries proof
  *material* through the production payload/context paths — it does
  not introduce any real on-chain governance proof verification
  beyond the Run 178 fixture-only verifier.
* **No governance execution.** Accepting an `OnChainGovernance`
  fixture proof on the validation-only reload-check surface **does
  not** mutate authority state, **does not** enable MainNet apply,
  **does not** advance the validator set, and **does not** execute
  any governance action. The accepted outcome is observable only as
  the typed `OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(_)`
  with `is_accept() == true` through the Run 180 / 182 typed surface.
* **No schema/wire/metric drift.** Run 185 changes no schema, no
  wire, no metric, no counter, no log line, and does not bump any
  version. The Run 180 banner remains the only emitted token, only
  when the selector is armed.
* **C4 / C5 remain OPEN.** Run 185 does not claim closure of C4 or
  C5; both remain open invariants tracked by the contradiction
  ledger. Run 185 strictly closes the Run 184 release-binary
  boundary for the additive optional sibling and for the Run 182
  production call-site wrappers.

## 4. Cross-references

* Driving spec: `task/RUN_185_TASK.txt`.
* Predecessor release-binary boundary runs: Run 181
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`) and Run 183
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`).
* Source/test predecessor: Run 184
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_184.md`).
* Verifier source/test foundation: Run 178
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`) and the typed
  `OnChainGovernanceProofPolicy` selector wire-up Run 180
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`).
* Production call-site wrappers: Run 182
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`).
* Authority lifecycle invariants: Run 055 / 070 / 132 / 134 / 136 /
  138 / 142 / 147 / 148 / 150 / 152.
* Contradiction ledger: `docs/whitepaper/contradiction.md` (C4 / C5
  remain OPEN).