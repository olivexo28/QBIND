# Run 197 — Release-binary RemoteSigner payload-carrying evidence

## Scope

Closes the Run 196-deferred release-binary boundary for the source/test
**RemoteSigner attestation payload-carrying / production-context** surface
added by
[`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`](
  ../../../crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs).
Run 196 added the typed payload-carrying surface on top of the Run 194
typed RemoteSigner production-custody boundary
[`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../../crates/qbind-node/src/pqc_remote_authority_signer.rs)
and the Run 188 typed authority-custody composition
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs):

* the combined wire form `RemoteSignerAttestationWire` and its
  `RemoteSignerIdentityWire` / `RemoteSignerRequestWire` /
  `RemoteSignerResponseWire` parts (`schema_version = 1`);
* `RemoteSignerLoadStatus::{Absent, Available, Malformed}`;
* the optional `remote_signer_attestation` JSON sibling extraction
  (`parse_optional_remote_signer_attestation_sibling_from_json_value`),
  performed *before* the strict v2 parse so pre-Run-196 sidecars yield
  `Absent`;
* the combined v2-sidecar loader
  (`load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes`
  / `_from_path`);
* the seven per-surface production-context routing helpers
  `route_loaded_remote_signer_attestation_to_{reload_check, reload_apply,
  startup_p2p_trust_bundle, sighup, local_peer_candidate_check,
  live_inbound_0x05, peer_driven_drain}_callsite_decision`;
* the custody-class router
  `route_remote_signer_attestation_for_custody_class`;
* `validate_loaded_remote_signer`;
* the named MainNet refusal helper
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying`.

Run 196 is source/test only with the A1–A10 / R1–R34 corpus
[`crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`](
  ../../../crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs)
all passing; release-binary RemoteSigner payload-carrying evidence is
**this Run 197**.

Run 197 captures **release-binary** evidence that real
`target/release/qbind-node` production payload/context paths can carry
RemoteSigner identity/request/response attestation material and route it
into the Run 194 RemoteSigner boundary through the Run 196
production-context helpers end-to-end:

* Run 196 added NO new CLI flag and NO new env var — it is a pure
  library boundary plus a strictly additive optional JSON sibling;
  `target/release/qbind-node --help` surfaces no RemoteSigner / KMS /
  HSM / governance-execution / validator-set-rotation enablement claim
  and no `remote_signer_attestation` field (S1);
* the default `--print-genesis-hash --env {devnet,testnet,mainnet}`
  invocations emit no RemoteSigner enablement banner and no MainNet
  peer-driven apply enablement claim (S2–S4);
* the Run 193 hidden authority-custody policy selector
  (`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` /
  `--p2p-trust-bundle-authority-custody-policy`) and the governance
  fixture flag remain compatible with no RemoteSigner banner drift
  (S5–S6);
* even with the Run 193 selector set to
  `mainnet-production-custody-required` on `--env mainnet`, MainNet
  peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal (S7).

The release-built helper
[`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`](
  ../../../crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs)
exercises the Run 196 A1–A10 / R1–R34 corpus end-to-end in **release
mode** through the production library symbols, routing each loaded
carrier through the seven per-surface helpers and asserting the typed
`RemoteSignerPayloadCarryingDecisionOutcome`.

## What this run proves

1. legacy / no-RemoteSigner payloads remain compatible under the default
   `RemoteSignerPolicy::Disabled` behaviour (`Absent` →
   `NoRemoteSignerSupplied`);
2. fixture loopback RemoteSigner material reaches the production-context
   routing helpers in release mode where the policy is the explicit
   `FixtureLoopbackAllowed`, and is accepted;
3. production RemoteSigner material reaches the Run 194 boundary and
   fails closed as `ProductionRemoteSignerUnavailable` /
   `MainNetProductionRemoteSignerUnavailable`;
4. malformed / invalid RemoteSigner material fails closed at the typed
   `MalformedRemoteSignerAttestationPayload` outcome before the Run 194
   verifier is reached;
5. RemoteSigner request/response canonical digest is preserved
   deterministically through wire conversion and remains domain-bound;
6. rejected cases produce no mutation (no marker / sequence write, no
   Run 070 call, no live trust swap, no session eviction);
7. MainNet peer-driven apply remains refused even with fixture loopback
   RemoteSigner material;
8. no real RemoteSigner / KMS / HSM / governance execution / validator-set
   rotation is claimed.

## Helper corpus (release mode, production library symbols)

The helper writes a per-table breakdown under
`helper_evidence/run_197/`:

| table | covers |
| --- | --- |
| `manifest.txt` / `scenarios/<id>/` | A1–A10 / R1–R34 routed through the seven per-surface decision helpers (plus `A7-sighup` / `A7-localpeer` so all seven helpers are exercised) |
| `custody_routing_table.txt` | A6 / R26 + the refused `Kms` / `Hsm` classes via `route_remote_signer_attestation_for_custody_class` |
| `canonical_digest_table.txt` | A5 request/response canonical-digest preservation through wire conversion |
| `governance_bypass_table.txt` | A8 governance-class invariance + A9 other-custody compatibility under `Disabled` |
| `loader_table.txt` | combined v2-sidecar loader: legacy `Absent` + sibling `Available` |
| `refusal_helpers_table.txt` | R27 peer-majority refusal, the MainNet refusal helper, `validate_loaded_remote_signer` reachability |
| `no_mutation_evidence.txt` | R31 purity/determinism + R32 mutating-helper malformed short-circuit |
| `determinism_evidence.txt` | re-evaluates every scenario three times for stable typed outcomes |

The helper exits non-zero if any scenario does not match its expected
typed outcome, and writes `helper_summary.txt` with the canonical
`verdict: PASS` / `verdict: FAIL` line.

## How to reproduce

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_197_remote_signer_payload_release_binary_helper
bash scripts/devnet/run_197_remote_signer_payload_release_binary.sh
```

The harness regenerates everything under this directory except
`README.md`, `summary.txt`, and `.gitignore`. The committed `summary.txt`
is a placeholder overwritten in place by every run.

## Honest limitations

* **No real RemoteSigner backend** and no networked signer service is
  implemented. Every `Production` signer-mode response routes to the
  typed `ProductionRemoteSignerUnavailable` /
  `MainNetProductionRemoteSignerUnavailable` reject.
* **Fixture loopback RemoteSigner is DevNet/TestNet evidence-only** and
  cannot satisfy MainNet production custody.
* **KMS / HSM remain unimplemented** — no real KMS, HSM, cloud KMS, or
  PKCS#11 integration.
* **RemoteSigner payload/carrying evidence does not enable MainNet
  peer-driven apply** — the Run 147 / 148 / 152 FATAL refusal is
  preserved at the binary surface and at the typed peer-driven drain
  helper.
* **Governance execution remains unimplemented**, real on-chain proof
  verification remains unimplemented, and validator-set rotation remains
  open.
* Existing custody / governance proof paths remain compatible; no
  schema / wire / metric drift beyond Run 196's additive optional
  RemoteSigner sibling.
* **Full C4 remains OPEN and C5 remains OPEN.**
