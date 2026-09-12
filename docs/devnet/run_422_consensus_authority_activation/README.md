RUN 422 — GENESIS-BOUND CONSENSUS AUTHORITY AND STANDALONE-BINARY ACTIVATION
Evidence archive README

============================================================================
VERDICT (see summary.txt for the exact label block)
============================================================================

RESULT=POSITIVE-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
F3_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
F4_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
F8_STATUS=CONFIGURED-AUTHORITY-PRODUCTION-PATH-CODE-TEST-POSITIVE
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
AUTHORITY_SCOPE=GENESIS-BOUND-DEVNET
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO

This is a SOURCE/TEST-positive activation verdict only. Configured-authority
adversarial *release-binary* evidence is explicitly NOT claimed here; it is the
Run 423 successor scope. No readiness item moves Green. RS1 stays OPEN/launch-
blocking, C4/C5 stay OPEN, M4 stays Yellow, M6 stays Yellow/Partial, S5/S7 stay
Yellow, public DevNet remains NO-GO. No TestNet/MainNet readiness claim. No
`devnet-seeds.live.json`. Candidate seed status and reachability evidence are
unchanged.

============================================================================
WHAT RUN 422 DOES
============================================================================

Route A (genesis-bound). Enables the normal standalone `qbind-node` production
code path to construct an immutable, validated consensus verification/signing
context whose validator membership and per-validator authorized `(suite,
public_key)` are derived DIRECTLY from the already boot-verified canonical
genesis (`qbind_ledger::GenesisConfig.validators[].pqc_public_key`, ML-DSA-44),
rather than from the uncommitted `--validator-consensus-key` CLI overrides used
by Runs 031–033.

New opt-in production flag: `--consensus-authority-from-genesis` (default off).
When set, the node:

  1. REQUIRES an external `--genesis-path` (already boot-verified by Run 102);
  2. re-loads + re-hashes that genesis to obtain the canonical genesis hash;
  3. builds an immutable, validated `GenesisConsensusAuthority` (membership +
     one authorized ML-DSA-44 key/suite per validator + a domain-tagged
     authority commitment bound to chain_id and genesis hash);
  4. REQUIRES a loaded local signer (`--signer-keystore-path`);
  5. enforces that the loaded signer public key EQUALS the genesis-committed
     key for the local validator;
  6. feeds the SAME validated constructor `main` already uses
     (`try_build_timeout_verification_context`) to obtain an active context.

Any failure in 1–5 exits startup NONZERO before P2P/consensus start. There is
no silent downgrade to `None`/unsigned operation, and the CLI
`--validator-consensus-key` override path is NOT consulted on the genesis path.

When the flag is absent, behavior is byte-for-byte the Run 421 default:
`verification_ctx == None` + `ConsensusVerificationPolicy::Required`
(unavailable-authority fail-closed).

============================================================================
ARCHIVE CONTENTS
============================================================================

README.md                     - this file
summary.txt                   - verdict labels + one-paragraph result
source_trace.txt              - the gap (Runs 031–033) and the Route A fix
authority_model.txt           - trust model, authority separation, commitment
configuration_matrix.txt      - activation matrix across environments/flags
adversarial_matrix.txt        - negative/adversarial cases and where enforced
verification_context_trace.txt- main -> validated constructor call trace
shared_context_impact.txt     - Timeout/NewView shared-context scope analysis
commands.txt                  - every validation command + exit status
test_results.txt              - test names/counts and pass/fail
performance.txt               - startup/validation/crypto observations + limits
SHA256SUMS.txt                - sha256 of every publish-safe archive file
.gitignore                    - excludes private/generated material

Files use LF line endings. SHA256SUMS covers every archive file except itself
and `.gitignore`.
