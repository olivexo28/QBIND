# Run 193 — Release-binary authority-custody policy selector evidence

## Scope

Closes the Run 192-deferred release-binary boundary for the source/test
hidden authority-custody **policy selector** added by
[`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody_policy_surface.rs).
Run 192 added the typed selector surface on top of the Run 190 typed
authority-custody payload-carrying surface
[`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
and the Run 188 typed authority-custody boundary
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs):

* a hidden CLI flag `--p2p-trust-bundle-authority-custody-policy <POLICY>`
  with clap `hide = true` (declared in
  [`crates/qbind-node/src/cli.rs`](../../../crates/qbind-node/src/cli.rs));
* an env var
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=<POLICY>`
  anchored by the public const
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`;
* the typed parse-error
  `AuthorityCustodyPolicySelectorParseError` (`Empty` /
  `UnknownValue { value }`);
* the selector parsers
  `authority_custody_policy_from_selector`,
  `authority_custody_policy_env_selector`,
  `authority_custody_policy_from_cli_or_env` (CLI-over-env precedence);
* seven per-surface preflight wrappers
  `preflight_v2_marker_authority_custody_for_reload_check`,
  `preflight_v2_marker_authority_custody_for_reload_apply`,
  `preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle`,
  `preflight_v2_marker_authority_custody_for_sighup`,
  `preflight_v2_marker_authority_custody_for_local_peer_candidate_check`,
  `preflight_v2_marker_authority_custody_for_live_inbound_0x05`,
  `preflight_v2_marker_authority_custody_for_peer_driven_drain`,
  each threading the resolved `AuthorityCustodyPolicy` into the matching
  Run 190 routing helper without mutating any marker, sequence,
  trust-bundle, or wire field.

Run 192 is source/test only with the A1–A12 / R1–R29 corpus
[`crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`](
  ../../../crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs)
all passing; release-binary policy-selector evidence is **this Run 193**.

Run 193 captures **release-binary** evidence that real
`target/release/qbind-node` preserves the Run 192 typed authority-
custody policy selector contract end-to-end:

* the production default `AuthorityCustodyPolicy::Disabled` is preserved
  when neither CLI nor env selector is set — `target/release/qbind-node
  --help` does NOT advertise the hidden Run 192 flag, surfaces no
  `(?i)authority.?custody`, no KMS/HSM, no remote-signer claim
  (S1), and the default `--print-genesis-hash --env {devnet,mainnet}`
  invocations emit no Run 192 custody enablement banner and no MainNet
  peer-driven apply enablement claim (S2);
* the env selector
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only` armed
  on DevNet does not drift any binary banner (S3);
* the CLI selector
  `--p2p-trust-bundle-authority-custody-policy devnet-local-allowed`
  armed on DevNet does not drift any binary banner (S4);
* CLI-over-env precedence is deterministic at the binary surface —
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only` with
  `--p2p-trust-bundle-authority-custody-policy disabled` resolves to
  `Disabled` and emits no banner drift (S5);
* an invalid CLI selector value (`garbage`) is rejected fail-closed
  by clap's typed value parser, with no MainNet apply / KMS / HSM /
  production-custody banner emitted (S6);
* even with the Run 192 hidden selector explicitly set to
  `mainnet-production-custody-required` at both env and CLI on MainNet
  startup, the binary still emits no MainNet peer-driven apply
  enablement claim, no KMS/HSM/remote-signer enablement claim, no
  production-custody enablement banner, and no validator-set rotation
  / autonomous apply claim — Run 147 / 148 / 152 FATAL invariant is
  preserved (S7);
* combining the Run 192 selector and the Run 187 hidden fixture
  selector both armed on MainNet still refuses MainNet peer-driven
  apply (S8);
* the release-built Run 193 helper
  [`run_193_authority_custody_policy_release_binary_helper`](
    ../../../crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs)
  exercises the Run 192 A1–A12 / R1–R29 selector + preflight wrapper
  corpus end-to-end in **release mode** through the production library
  symbols `pqc_authority_custody_policy_surface::*` —
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`,
  `AuthorityCustodyPolicySelectorParseError`,
  `authority_custody_policy_from_selector`,
  `authority_custody_policy_env_selector`,
  `authority_custody_policy_from_cli_or_env`,
  `preflight_v2_marker_authority_custody_for_{reload_check,
  reload_apply, startup_p2p_trust_bundle, sighup,
  local_peer_candidate_check, live_inbound_0x05, peer_driven_drain}` —
  layered above the Run 190 typed payload-carrying surface and the
  Run 188 typed authority-custody boundary.

## Strict scope (from `task/RUN_193_TASK.txt`)

* Release-binary evidence only.
* Use real `target/release/qbind-node`.
* Use the release-built Run 193 helper to exercise the Run 192
  selector + preflight wrappers in release mode through production
  library symbols.
* No production-source change.
* No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* No real on-chain governance proof verifier; no governance execution;
  no validator-set rotation; no autonomous apply; no apply-on-receipt;
  no peer-majority authority.
* No MainNet peer-driven apply enablement.
* No marker / sequence-file / trust-bundle / wire / metric drift.
* No new CLI flag, env var, schema bump, sidecar field, metric, or
  exit code (Run 192 already added the hidden CLI flag and env var).
* Do not weaken Runs 070, 130–192.
* Do not claim full C4 / C5 closure.

## Layout

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in git.
All other artifacts are produced by the harness and contain absolute
paths and ephemeral data; they are listed in `.gitignore`.

* `summary.txt` — canonical verdict line emitted by the harness; the
  committed copy is a placeholder overwritten by every run.
* `logs/` — captured stdout/stderr for build / scenarios S1–S8 and
  helper invocation.
* `exit_codes/` — per-scenario exit codes for the harness.
* `helper_evidence/run_193/` — Run 193 release-helper output:
  manifest.txt, scenarios/A*/R*, selector_parser_table.txt,
  precedence_table.txt, preflight_wrappers_table.txt,
  binding_mismatch_table.txt, no_mutation_evidence.txt,
  determinism_evidence.txt, helper_summary.txt.
* `reachability/source_reachability.txt` — `grep -RIn` evidence that
  every Run 192 / 190 / 188 typed symbol the helper exercises is wired
  in production source under `crates/qbind-node/src/`.
* `test_results/` — captured stdout/stderr for each cargo test target
  named in `task/RUN_193_TASK.txt` (skipped tests are recorded as
  `rc=skipped(not-present)`).
* `provenance.txt` — git commit, branch, rustc/cargo versions, host,
  binary SHA-256 + ELF Build ID for `target/release/qbind-node` and
  the Run 193 helper.
* `negative_invariants.txt` — denylist results.
* `mutation_proof.txt` — release-binary mutation reachability summary.
* `no_mutation_proof.txt` — non-mutation evidence for rejected
  selector / preflight / validator / routing scenarios.

## Reproducing

```
bash scripts/devnet/run_193_authority_custody_policy_release_binary.sh
```

The harness is idempotent: it wipes and regenerates everything under
this directory **except** `README.md`, `summary.txt`, and `.gitignore`.
The committed `summary.txt` is a placeholder and is overwritten by
every successful run.

## Honest limits

* default `AuthorityCustodyPolicy::Disabled` preserved when neither CLI
  nor env selector is set;
* hidden CLI flag `--p2p-trust-bundle-authority-custody-policy` is not
  advertised in normal `--help`;
* env `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` activates the
  selector when set; CLI-over-env precedence is deterministic;
* invalid selector values surface as typed
  `AuthorityCustodyPolicySelectorParseError` (fail-closed);
* fixture / local-operator custody remain DevNet/TestNet evidence-only
  and explicitly cannot satisfy MainNet production custody;
* `RemoteSigner` / `Kms` / `Hsm` placeholders fail closed at the typed
  validator (`RemoteSignerUnavailable` / `KmsUnavailable` /
  `HsmUnavailable`) regardless of policy or environment;
* MainNet peer-driven apply remains refused (Run 147 / 148 / 152 FATAL
  invariant) at every binary surface — including with the Run 192
  hidden selector set to `mainnet-production-custody-required` on both
  env and CLI and the Run 187 hidden fixture selector armed — and at
  the typed custody boundary via
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`;
* no real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend is
  wired in Run 193;
* no real on-chain governance proof verifier / no governance execution
  / no validator-set rotation / no autonomous apply / no
  apply-on-receipt / no peer-majority authority;
* no schema/wire/metric drift in Run 193 (release-binary evidence
  only);
* full C4 and C5 remain OPEN.