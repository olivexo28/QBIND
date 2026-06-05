# QBIND DevNet evidence — Run 192

**Title.** Source/test hidden authority-custody policy selector and
production preflight integration.

**Status.** PASS (source/test). Run 192 adds the smallest hidden
selector surface that lets DevNet/TestNet evidence preflight contexts
explicitly choose an [`AuthorityCustodyPolicy`](../../crates/qbind-node/src/pqc_authority_custody.rs)
variant, and threads the resolved policy into the seven Run 190
production v2 marker-decision preflight contexts via thin per-surface
wrappers. The default
[`AuthorityCustodyPolicy::Disabled`](../../crates/qbind-node/src/pqc_authority_custody.rs)
is preserved bit-for-bit; legacy no-custody payloads remain accepted
exactly as in Run 190 / Run 191.

**Strict scope.**

* Source/test only. Release-binary custody-policy selector evidence
  is deferred to **Run 193**.
* Hidden selector only:
    * CLI: `--p2p-trust-bundle-authority-custody-policy <POLICY>`
      (clap `hide = true`).
    * Env: `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=<POLICY>`.
* Disabled by default — when both sources are absent the resolver
  returns [`AuthorityCustodyPolicy::Disabled`].
* No real KMS/HSM/cloud-KMS/PKCS#11/remote-signer backend.
* No MainNet peer-driven apply enablement. The Run 147 / 148 / 152
  MainNet refusal at the peer-driven apply surface remains intact
  even with `mainnet-production-custody-required` and metadata
  claiming KMS/HSM/RemoteSigner.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority
  authority.
* No marker / sequence-file / authority-marker / trust-bundle core /
  ratification-sidecar / wire / schema change.
* Run 192 does not weaken any prior run (Runs 070, 130–191) and does
  not claim full C4 or C5 closure.

## Source surface added

* New module:
  [`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`](
    ../../crates/qbind-node/src/pqc_authority_custody_policy_surface.rs).
* New hidden CLI field on
  [`crates/qbind-node/src/cli.rs`](../../crates/qbind-node/src/cli.rs):
  `p2p_trust_bundle_authority_custody_policy: Option<String>` (clap
  `hide = true`, `value_name = "POLICY"`).

### Selector parsers

* `pub const QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`
* `pub fn authority_custody_policy_from_selector(value: &str)
   -> Result<AuthorityCustodyPolicy, AuthorityCustodyPolicySelectorParseError>`
* `pub fn authority_custody_policy_env_selector()
   -> Result<Option<AuthorityCustodyPolicy>, AuthorityCustodyPolicySelectorParseError>`
* `pub fn authority_custody_policy_from_cli_or_env(cli_value: Option<&str>)
   -> Result<AuthorityCustodyPolicy, AuthorityCustodyPolicySelectorParseError>`

The parser accepts these case-insensitive tags (whitespace trimmed):

| value                                 | resolved policy                                      |
|---------------------------------------|------------------------------------------------------|
| `disabled`                            | `AuthorityCustodyPolicy::Disabled`                   |
| `fixture-only`                        | `AuthorityCustodyPolicy::FixtureOnly`                |
| `devnet-local-allowed`                | `AuthorityCustodyPolicy::DevnetLocalAllowed`         |
| `testnet-local-allowed`               | `AuthorityCustodyPolicy::TestnetLocalAllowed`        |
| `production-custody-required`         | `AuthorityCustodyPolicy::ProductionCustodyRequired`  |
| `mainnet-production-custody-required` | `AuthorityCustodyPolicy::MainnetProductionCustodyRequired` |

Empty / whitespace-only values return
`AuthorityCustodyPolicySelectorParseError::Empty`. Unknown non-empty
values return `AuthorityCustodyPolicySelectorParseError::UnknownValue
{ value }`. The resolver never silently downgrades to `Disabled`
when an explicit value is present but invalid.

**Precedence.** When both the CLI flag and the env var are supplied,
the CLI flag wins. Either source alone is sufficient to select a
non-default policy. Both absent or the env var unset preserves the
`Disabled` default.

### Per-surface preflight wrappers

Seven thin wrappers bind the resolved policy into the Run 190
[`AuthorityCustodyCallsiteContext`](
  ../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
for each of the seven production v2 marker-decision preflight
contexts and dispatch to the matching Run 190
`route_loaded_authority_custody_attestation_to_*_callsite_decision`
helper:

* `preflight_v2_marker_authority_custody_for_reload_check`
* `preflight_v2_marker_authority_custody_for_reload_apply`
* `preflight_v2_marker_authority_custody_for_startup_p2p_trust_bundle`
* `preflight_v2_marker_authority_custody_for_sighup`
* `preflight_v2_marker_authority_custody_for_local_peer_candidate_check`
* `preflight_v2_marker_authority_custody_for_live_inbound_0x05`
* `preflight_v2_marker_authority_custody_for_peer_driven_drain`

These wrappers exist so the Run 192 source-reachability claim ("the
selected policy reaches all seven production-context helpers") is
grep-verifiable from each surface. They are pure: no I/O, no marker
write, no sequence write, no live-trust swap, no session eviction,
no Run 070 invocation. Mutating callers continue to honor the
existing `commit_sequence` →
`persist_accepted_v2_marker_after_commit_boundary`
sequence-before-marker ordering AFTER acceptance.

## Tests added

[`crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs`](
  ../../crates/qbind-node/tests/run_192_authority_custody_policy_selector_tests.rs)
covers the full A1–A10 / R1–R29 matrix from `task/RUN_192_TASK.txt`:

* selector parsing and precedence — default, CLI, env, CLI-over-env,
  invalid value fail-closed, unrelated env does not enable policy;
* A1–A10 accepted scenarios (where representable) — default disabled
  bypass, CLI/env `fixture-only`, CLI/env `devnet-local-allowed`,
  CLI/env `testnet-local-allowed`, `production-custody-required` and
  `mainnet-production-custody-required` typed fail-closed at the
  validator, no Disabled-time governance behaviour change, mutating
  reload-apply DevNet fixture acceptance, live `0x05` policy
  reachability;
* R1–R29 rejection scenarios — invalid selector, unrelated env,
  no-custody under FixtureOnly / DevnetLocalAllowed, fixture/local
  rejection under ProductionCustodyRequired, fixture/local rejection
  on MainNet, environment-mismatched policies, KMS/HSM/RemoteSigner
  placeholder fail-closed, malformed payload short-circuit, every
  binding-tuple mismatch (env / chain / genesis / authority-root /
  signing-key fingerprint / candidate digest / authority-domain
  sequence / expiry / custody key id / custody suite),
  validation-only and mutating rejection non-mutation, live-`0x05`
  invalid candidate not propagated, MainNet peer-driven apply
  refused under MainnetProductionCustodyRequired with KMS/HSM
  metadata;
* source reachability — the resolved policy reaches all seven
  production-context per-surface preflight wrappers (single test
  exercising every wrapper).

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
* `cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests`
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests`
* `cargo test -p qbind-node --lib pqc_authority`

All commands run on this checkout completed successfully:

* `run_192_authority_custody_policy_selector_tests`: 46 passed.
* `run_190_authority_custody_payload_callsite_tests`: 55 passed.
* `run_188_authority_custody_boundary_tests`: passes unchanged.
* `cargo test -p qbind-node --lib pqc_authority`: 164 passed.

## Acceptance summary

1. Hidden authority-custody policy selector exists (CLI hidden flag
   + env var, both routed through pure parsers in
   `pqc_authority_custody_policy_surface`). ✅
2. Default remains `AuthorityCustodyPolicy::Disabled`. ✅
3. Selector reaches production preflight contexts at source/test
   level via the seven `preflight_v2_marker_authority_custody_for_*`
   wrappers. ✅
4. Valid DevNet/TestNet fixture/local custody metadata passes only
   where policy allows (see A2/A3/A4/A5/A9/A10 tests). ✅
5. Missing/malformed/invalid custody metadata fails closed under
   explicit policy (see R4/R5/R15/R16–R25 tests). ✅
6. KMS/HSM/RemoteSigner placeholders remain fail-closed (see
   R12/R13/R14 and A6/A7 tests). ✅
7. Validation-only surfaces remain non-mutating (see R26 test). ✅
8. Mutating rejection surfaces produce no mutation (see R27 test —
   the wrappers are pure data transforms; no I/O is performed). ✅
9. MainNet peer-driven apply remains refused even with custody
   metadata claiming KMS/HSM (see R29 / A7 tests). ✅
10. Release-binary custody-policy selector evidence deferred to
    Run 193. ✅
11. No real KMS/HSM / governance execution / real on-chain proof /
    validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary custody-policy selector evidence: **Run 193**.
* Real KMS / HSM / cloud-KMS / PKCS#11 / remote-signer backend
  remains unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.
