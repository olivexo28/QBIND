# QBIND DevNet evidence — Run 199

**Title.** Release-binary hidden RemoteSigner policy selector and
production preflight routing evidence.

**Status.** PASS (release-binary evidence). Run 199 captures
release-binary evidence that the real `target/release/qbind-node`
accepts the Run 198 hidden RemoteSigner policy selector (one hidden CLI
flag plus one environment variable) while keeping it hidden from
`--help`, and that a release-built helper resolves the selector and
routes the resolved `RemoteSignerPolicy` through the seven Run 198
per-surface production preflight wrappers
([`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`](
  ../../crates/qbind-node/src/pqc_remote_signer_policy_surface.rs))
into the Run 196 RemoteSigner payload-carrying call-site helpers
([`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`](
  ../../crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs))
layered over the Run 194 RemoteSigner boundary
([`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../crates/qbind-node/src/pqc_remote_authority_signer.rs)). Run 199
is **release-binary RemoteSigner policy selector evidence**; it makes no
production-source change (it adds a release example helper, a release
harness, and documentation only).

Run 199 does **not** implement a real RemoteSigner backend. The default
remains `RemoteSignerPolicy::Disabled`. Fixture loopback RemoteSigner
material remains DevNet/TestNet evidence-only and cannot satisfy MainNet
production RemoteSigner; production RemoteSigner material reaches the
boundary and fails closed as unavailable; malformed/invalid material
fails closed; and MainNet peer-driven apply remains the Run 147 / 148 /
152 FATAL refusal even with `MainnetProductionRemoteSignerRequired` and
fixture loopback RemoteSigner material.

## Strict scope

* Release-binary evidence only, on real `target/release/qbind-node`.
* No production-source change (helper + harness + docs only).
* Hidden selector only (one hidden CLI flag + one env var); no new
  `--help` surface.
* Disabled by default.
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema / wire / metric drift; no authority-marker / sequence-file /
  trust-bundle core schema change.
* Run 199 does not weaken any prior run (Runs 070, 130–198) and does not
  claim full C4 or C5 closure.

## Run 199 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_199_remote_signer_policy_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_199_remote_signer_policy_release_binary.sh`](
    ../../scripts/devnet/run_199_remote_signer_policy_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_199_remote_signer_policy_release_binary/`](
    run_199_remote_signer_policy_release_binary/) (tracked: `README.md`,
  `summary.txt`, `.gitignore`; all per-run artifacts are gitignored).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Release-binary surface evidence

Run 198 added one hidden CLI flag (`--p2p-trust-bundle-remote-signer-policy`,
clap `hide = true`) and one env var
(`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY`). The harness proves the
real `target/release/qbind-node` accepts the selector while keeping the
existing Run 070 / 130–198 surfaces RemoteSigner-silent:

* **S1** — `qbind-node --help` advertises no
  `--p2p-trust-bundle-remote-signer-policy` flag, no RemoteSigner / KMS /
  HSM surface, no `remote_signer_attestation` field, and no
  governance-execution / validator-set-rotation claim. The selector flag
  remains hidden.
* **S2–S4** — `--print-genesis-hash --env {devnet,testnet,mainnet}`
  (with `--genesis-path`) emits no RemoteSigner enablement banner, no
  "RemoteSigner backend connected" / "RemoteSigner production active"
  claim, no KMS/HSM active claim, and no MainNet peer-driven apply
  enablement.
* **S5** — the hidden CLI selector
  (`--p2p-trust-bundle-remote-signer-policy fixture-loopback-allowed`) is
  accepted by the real binary on `--env devnet` with no RemoteSigner
  banner drift.
* **S6** — the env selector
  (`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=production-remote-signer-required`)
  is accepted by the real binary on `--env devnet` with no RemoteSigner
  banner drift and no "production active" claim.
* **S7** — the Run 193 hidden custody policy selector remains compatible
  with the Run 198 RemoteSigner policy selector (no banner drift).
* **S8** — the governance fixture flag remains compatible with no
  RemoteSigner banner drift and no governance-execution claim.
* **S9** — even with the RemoteSigner policy selector set to
  `mainnet-production-remote-signer-required` on `--env mainnet`, MainNet
  peer-driven apply remains the Run 147 FATAL refusal and no
  RemoteSigner / KMS / HSM enablement is emitted.

The real binary resolves `--print-genesis-hash` through the existing
genesis-hash path; the selector *semantics* (resolution + routing) are
proven by the release-built helper below, which links the production
library symbols. The binary scenarios assert only that the selector flag
and env var are accepted with no banner / `--help` drift and that MainNet
peer-driven apply stays refused — exactly the Run 197 release-surface
approach.

## Release-helper corpus evidence

The release-built helper exercises the Run 198 selector + A1–A11 /
R4–R34 corpus in **release mode** through the production library symbols
`pqc_remote_signer_policy_surface::*` layered over
`pqc_remote_signer_payload_carrying::*` and
`pqc_remote_authority_signer::*`. It registers nine tables:

* **selector_resolution (16):** default (no CLI, no env) ⇒ `Disabled`;
  CLI selector resolves each tag; env selector resolves each tag;
  CLI-over-env precedence (CLI wins); empty value ⇒
  `RemoteSignerPolicySelectorParseError::Empty`; unknown value ⇒
  `UnknownValue { value }`; unrelated env does not enable a policy. An
  RAII env guard sets and restores
  `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY` around each readback.
* **scenarios (37):** the A1–A11 accepted family (legacy no-RemoteSigner
  bypass under `Disabled`; DevNet/TestNet fixture loopback accepted under
  `FixtureLoopbackAllowed`; production/MainNet-production reaching the
  boundary and returning the typed unavailable outcome) and the R4–R34
  rejected family (absent-where-required, malformed
  identity/request/response/combined attestation, fixture-rejected under
  production / mainnet-production required, every binding-tuple mismatch,
  stale/replayed/expired material, unsupported suite, invalid signature,
  local-operator-key and peer-majority cannot satisfy RemoteSigner,
  custody-invalid composition rejection, validation-only and
  mutating-preflight no-mutation, invalid live `0x05` not propagated, and
  MainNet peer-driven apply refused even with fixture loopback material).
* **seven_surface_reachability (14):** the resolved policy reaches all
  seven `preflight_v2_marker_remote_signer_for_*` wrappers (accept and
  required-but-absent each).
* **custody_routing (4):** custody-class RemoteSigner routing.
* **governance_bypass (7):** governance / other-custody compatibility
  under `Disabled`.
* **loader (2):** combined v2-sidecar + RemoteSigner attestation loader
  round-trips.
* **refusal_helpers (4):** the named MainNet refusal helper.
* **no_mutation (4):** rejected cases produce no marker / sequence write,
  no Run 070 call, no live swap, no session eviction.
* **determinism (37):** repeated resolution + routing is byte-identical.

The helper writes a per-table breakdown plus a `helper_summary.txt`
ending in the canonical `verdict: PASS` line, and exits non-zero if any
scenario does not match its expected typed outcome. The harness asserts
`verdict: PASS` before continuing. On this checkout the helper reports
**total_pass: 125, total_fail: 0, verdict: PASS**.

## Selector surface

The hidden selector is exposed via:

* CLI: `--p2p-trust-bundle-remote-signer-policy <value>` (clap
  `hide = true`).
* Env: `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=<value>`.

Both share one pure parser (`remote_signer_policy_from_selector`), read
through `remote_signer_policy_env_selector`, and resolved by
`remote_signer_policy_from_cli_or_env`. Accepted case-insensitive tags
(whitespace trimmed): `disabled`, `fixture-loopback-allowed`,
`production-remote-signer-required`,
`mainnet-production-remote-signer-required`. Empty/whitespace-only
values return `Empty`; unknown non-empty values return
`UnknownValue { value }`. The resolver never silently downgrades to
`Disabled` when an explicit value is present but invalid.

* **Default.** Both absent ⇒ `RemoteSignerPolicy::Disabled`.
* **Precedence.** CLI flag wins over env var (deterministic; either
  source alone is sufficient to select a non-default policy).

## Source/release reachability

The harness records source-grep reachability under
`reachability/source_reachability.txt` for `pqc_remote_signer_policy_surface`;
`QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY`;
`remote_signer_policy_from_selector`; `remote_signer_policy_env_selector`;
`remote_signer_policy_from_cli_or_env`;
`RemoteSignerPolicySelectorParseError`; the seven
`preflight_v2_marker_remote_signer_for_*` wrappers; and the hidden CLI
field `p2p_trust_bundle_remote_signer_policy`.

## Mutation / no-mutation evidence

For every rejected RemoteSigner-policy scenario the helper proves no
mutation: the validation-only routing helpers (reload-check /
local-peer-candidate-check / live-inbound-0x05) are pure functions
returning typed outcomes, and the mutating-preflight helpers
(reload-apply / startup-p2p / sighup / peer-driven-drain) short-circuit a
malformed or required-but-absent carrier **before** the Run 194 verifier
and therefore before any sequence/marker write or Run 070 call. No Run
070 apply call, no live trust swap, no session eviction, no sequence
write, no marker write, no `.tmp` residue, no fallback to
`--p2p-trusted-root`, and no active DummySig / DummyKem / DummyAead are
produced (`no_mutation_proof.txt`, `no_mutation_evidence.txt`,
`determinism_evidence.txt`). The harness denylist
(`negative_invariants.txt`) proves all forbidden patterns empty across
captured logs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_199_remote_signer_policy_release_binary_helper
bash scripts/devnet/run_199_remote_signer_policy_release_binary.sh
```

The harness additionally runs the Run 198 / Run 196 / Run 194 / Run 192 /
Run 190 / Run 188 and the governance / lifecycle / peer-driven-apply
regression test targets from `task/RUN_199_TASK.txt`, plus
`cargo test -p qbind-node --lib pqc_authority`,
`--lib pqc_remote_signer_policy_surface`, and `--lib`. Per-target exit
codes are captured under `exit_codes/` and summarised in `summary.txt`.
Targets absent from the tree are recorded as `skipped(not-present)`. On
this checkout all listed targets completed with `rc=0`.

## Acceptance summary

1. Real release binaries exercise the hidden RemoteSigner policy selector
   (CLI flag + env var accepted by `target/release/qbind-node`; resolved
   and routed by the release-built helper). ✅
2. Default `RemoteSignerPolicy::Disabled` remains proven. ✅
3. CLI selector and env selector both work. ✅
4. CLI-over-env precedence is proven deterministic. ✅
5. Invalid selector values fail closed with typed parse errors. ✅
6. Fixture loopback RemoteSigner material passes only where the selected
   policy allows (DevNet/TestNet `FixtureLoopbackAllowed`). ✅
7. Production RemoteSigner remains fail-closed as unavailable. ✅
8. MainNet peer-driven apply remains refused even with
   `MainnetProductionRemoteSignerRequired` and fixture loopback
   material. ✅
9. Rejected RemoteSigner-policy cases produce no mutation. ✅
10. Existing custody/governance proof paths remain compatible. ✅
11. No real RemoteSigner / KMS / HSM / governance execution / real
    on-chain proof / validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Standing invariants (unchanged by Run 199)

* Default resolution remains `RemoteSignerPolicy::Disabled`.
* No real RemoteSigner backend is implemented.
* No real KMS / HSM / cloud-KMS / PKCS#11 backend is implemented.
* Fixture loopback RemoteSigner is DevNet/TestNet evidence-only and
  cannot satisfy MainNet production RemoteSigner.
* Production RemoteSigner remains unavailable / fail-closed.
* RemoteSigner policy selector evidence does not enable MainNet
  peer-driven apply.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Existing custody / governance proof paths remain compatible.
* Full C4 remains open.
* C5 remains open.
