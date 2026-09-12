# QBIND Public DevNet — Run 422 Evidence

**Genesis-bound consensus authority and standalone-binary activation**

- Baseline: `main` @ `5c2f9381` (full `5c2f93816a3ff67cec11605878bfb6705d637a47`)
- Task branch: `copilot/run-422-task-update`
- Tested implementation SHA: `a62624acc1ca6be7656e8219e0235f8cc3f44e22`
- Successor: Run 423 (configured-authority standalone release-binary adversarial evidence)

## Verdict

```text
RESULT=POSITIVE-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
F3_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
F4_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
F8_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
AUTHORITY_SCOPE=GENESIS-BOUND-DEVNET
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This is a **source/test-positive** activation verdict. Configured-authority
**adversarial release-binary** evidence is **not** claimed here — it is the Run
423 successor scope. Release compilation and parser/startup smoke checks do not
constitute that evidence.

## What changed

Route A (genesis-bound). A new opt-in, fail-closed production flag
`--consensus-authority-from-genesis` lets the standalone `qbind-node` production
path construct the consensus verification/signing context from the
**boot-verified canonical genesis** (`GenesisConfig.validators[].pqc_public_key`,
ML-DSA-44) plus an operator-supplied local signing key, instead of the
uncommitted `--validator-consensus-key` CLI overrides used by Runs 031–033.

Changed files (`crates/`, baseline..`a62624ac`):

| File | Change |
| --- | --- |
| `crates/qbind-node/src/genesis_consensus_authority.rs` | **new** (666 lines) Route A module + 14 unit tests |
| `crates/qbind-node/src/main.rs` | +181/-8 genesis-authority resolution + bridge wiring (fail-closed) |
| `crates/qbind-node/src/cli.rs` | +24 `--consensus-authority-from-genesis` flag |
| `crates/qbind-node/src/lib.rs` | +4 `pub mod genesis_consensus_authority;` |
| `crates/qbind-node/tests/run_422_genesis_consensus_authority_tests.rs` | **new** (229 lines) 6 integration/source-guard tests |

## Activation semantics (fail-closed)

When `--consensus-authority-from-genesis` is set, startup:

1. requires an external `--genesis-path` (already boot-verified by Run 102);
2. re-loads and re-hashes it to obtain the canonical genesis hash;
3. builds an immutable, validated `GenesisConsensusAuthority` (membership + one
   authorized ML-DSA-44 `(suite, key)` per validator + a domain-tagged authority
   commitment bound to `chain_id` + genesis hash);
4. requires a loaded local signer (`--signer-keystore-path`);
5. enforces `signer_public_key == genesis_committed_key` for the local validator;
6. feeds the **same** `try_build_timeout_verification_context` that `main` uses
   on the existing path.

Any failure in 1–5 exits nonzero **before** P2P/consensus start — no silent
downgrade to `None`/unsigned, and the CLI `--validator-consensus-key` override
path is bypassed on the genesis path. When the flag is absent, behavior is
byte-identical to the Run 421 default (`None` + `ConsensusVerificationPolicy::Required`).

## Validation summary

- Unit tests: **14/14** (`genesis_consensus_authority`).
- Integration/source-guard tests: **6/6** (`run_422_...`).
- Regressions: `run_420` (3/3), `run_418` sender-binding (18/18) + newview demux (3/3).
- Release-binary evidence-preservation harnesses re-run out-of-tree (no archive
  drift): `run_421` retained `PARTIAL-POSITIVE` unavailable-authority verdict;
  `run_419` retained `PARTIAL-FOR-F6` verdict — F6/unavailable-authority
  boundaries intact after Run 422.
- rustfmt/clippy clean on changed files (pre-existing repo-wide drift/warnings
  unchanged and not claimed clean).

Full command/exit detail: `run_422_consensus_authority_activation/commands.txt`.

## Scope guards (unchanged posture)

No readiness item moves Green. **RS1 stays OPEN/launch-blocking; C4/C5 stay
OPEN; M4 stays Yellow; M6 stays Yellow/Partial; S5/S7 stay Yellow; public DevNet
remains NO-GO.** No TestNet/MainNet readiness claim, no `devnet-seeds.live.json`,
candidate seed status and reachability evidence unchanged. F1/F2/F5/F7 remain
unresolved; F6 remains code/test plus partial runtime evidence. F3/F4/F8 are
labeled **configured-authority production-path code/test positive only** — not
release-binary adversarial, not full closure.

## Archive

`docs/devnet/run_422_consensus_authority_activation/` — see its `README.md`.
`SHA256SUMS.txt` covers every publish-safe archive file (LF endings).

## Successor

Run 423 is recommended (configured-authority standalone release-binary
adversarial evidence) **only after review** of this code/test-positive
activation. It is not started here and implies no public DevNet launch readiness.
