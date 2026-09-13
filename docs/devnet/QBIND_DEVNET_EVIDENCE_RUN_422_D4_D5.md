# QBIND Public DevNet — Run 422 D4/D5 Evidence

**Consensus-security preflight ordering (D4) and message-family authority
separation (D5) — code + test evidence**

- Actual working branch: `copilot/copilotrun-422-follow-up-d4-d5-startup`
- Accepted baseline (comparison base): `26fa246c769158c31cbb570d2d13ccb3a963928f`
- Reviewed D4/D5 implementation tip named by the task:
  `b709f7b30c26fccd2fc0b36f0855f5ce8e9a77c7` — **ABSENT** from this shallow
  single-branch checkout (`git cat-file -t` cannot resolve the object). The
  functionally equivalent reviewed work is present at the task-branch tip
  `f14c3dd` (parent = the accepted baseline `26fa246`); this continuation
  builds on `f14c3dd` and records the deviation rather than claiming direct
  ancestry to an object not in the checkout.
- Tested revision (all test counts below): `e1b95948c6ce604aa97f317e88f8c8b2e41a6b2b`
- Final revision: the commit that adds this evidence (documentation-only
  relative to the tested revision).
- This is a **continuation** of the existing D4/D5 work. Run 423 is **not**
  started and genesis authority is **not** activated.

## Verdict (scoped code + test result)

```text
RESULT=POSITIVE-FOR-CONSENSUS-SECURITY-PREFLIGHT-AND-CONTEXT-SEPARATION-CODE-TEST
D4_STATUS=PRE-P2P-AND-CONSENSUS-PREFLIGHT-CODE-TEST-POSITIVE
D5_STATUS=MESSAGE-FAMILY-AUTHORITY-SEPARATION-CODE-TEST-POSITIVE
GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-REMAINING-BOUNDARIES
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

Implementation, validation, and runtime-evidence axes are kept separate. The
POSITIVE label is a **code + test** result. It is not a runtime,
release-binary, or public-deployment claim.

## What this run adds

1. **D5 combined-context tests** (`crates/qbind-node/src/binary_consensus_loop.rs`,
   `mod run420`). The reviewed D5 tests constructed a valid
   `TimeoutVerificationContext` but never passed it through the Proposal/Vote
   path under test. Six new tests now drive, in a single handler/loop
   invocation, a valid Timeout context **and** `proposal_vote_authority = None`
   under `ConsensusVerificationPolicy::Required` with a real
   `PeerConsensusBindingGate` + matching `AuthenticatedConsensusOrigin` and
   encoded Proposal/Vote messages, asserting actual inbound and outbound
   effects (not a helper returning `None`):
   - `run422_d5a_authenticated_proposal_timeout_only_rejects_before_crypto`
   - `run422_d5b_authenticated_vote_timeout_only_rejects_before_crypto`
   - `run422_d5c_proposal_f6_mismatch_precedes_pv_authority_lookup`
   - `run422_d5c_vote_f6_mismatch_precedes_pv_authority_lookup`
   - `run422_d5d_outbound_forwarding_suppressed_without_pv_authority`
   - `run422_d5f_timeout_context_usable_only_for_its_own_family`

2. **D4 startup-ordering process tests**
   (`crates/qbind-node/tests/run_422_d4_startup_ordering_tests.rs`). Five
   bounded tests spawn the real `qbind-node` via `CARGO_BIN_EXE_qbind-node`
   with valid temporary DevNet configuration:
   - four RequireOrFail negative cases (missing local signer; invalid peer
     key-provider hex; unsupported suite id; local key mismatches the loaded
     signer) each asserting a nonzero exit, the `[binary] Run 032:`/`Run 033:`
     preflight positive-control present, and the post-build
     `[binary] P2P transport up.` marker absent — refusal **before** P2P
     service construction (`builder.build()`), peer dialing, and consensus-task
     startup;
   - one positive case (valid legacy configuration) that passes preflight,
     activates the Timeout/NewView context, and reaches
     `[binary] P2P transport up.` with Proposal/Vote authority still absent.

3. **Stale-comment corrections** in `binary_consensus_loop.rs`: the
   `ConsensusVerificationPolicy` doc block, the `verification_ctx` and
   `verification_policy` field docs, and the inbound-handler comment now name
   the `proposal_vote_authority` dependency for the Proposal/Vote family
   (previously mis-attributed to `verification_ctx`). The legacy activation
   route is described precisely: its Timeout/NewView policy is preserved, but
   its former ability to also enable Proposal/Vote has been removed. Historical
   Run 420-422 facts are retained and separated from the current successor
   behavior.

## The metrics exception (D4 scope)

`main()` may spawn the optional metrics HTTP server (`main.rs:4643`, gated by
`QBIND_METRICS_HTTP_ADDR`) **before** entering the per-mode P2P function and
its consensus-security preflight. Therefore D4 is scoped as *preflight before
P2P service construction, peer dialing, and consensus-task startup* — **not**
before "any networking", "all listeners", or "every service". The preflight
function itself starts no network service, and no unrelated metrics/storage
startup was moved. See
`run_422_d4_d5_preflight_context_separation/startup_order.txt`.

## Evidence archive

`docs/devnet/run_422_d4_d5_preflight_context_separation/` contains: `README.md`,
`summary.txt`, `source_trace.txt`, `activation_matrix.txt`, `startup_order.txt`,
`message_family_matrix.txt`, `commands.txt`, `test_results.txt`,
`SHA256SUMS.txt`, `.gitignore`. `SHA256SUMS.txt` covers every publish-safe file
in that directory except itself and `.gitignore`.

## Validation summary

`cargo check -p qbind-node` (default features, no test-utils) and
`cargo build --release -p qbind-node --bin qbind-node` both exit 0. Focused
test targets all pass: binary_consensus_loop lib 104; `run420::run422_d5` 10;
`run_422_d4_startup_ordering_tests` 5; `run_422_startup_refusal_tests` 4;
`run_422_genesis_consensus_authority_tests` 15;
`run_420_production_policy_reachability_tests` 3;
`run_418_authenticated_peer_consensus_sender_binding_tests` 18;
`run_418_newview_demux_chain_integration_tests` 3;
`c4_b6_p2p_binary_path_interconnect_tests` 5; `b9` 6; `b10` 5; `b11` 5. Clippy
on the changed regions introduced no new warnings. The
`m16_epoch_transition_hardening_tests` target needs `--features test-utils`
(pre-existing, unrelated) and is recorded separately. Exact commands and exit
codes are in `commands.txt` / `test_results.txt`.

**Security analysis:** CodeQL / dedicated security scan was **not** executed to
completion for these changes; **no zero-alert conclusion is asserted**. A code
review is not a substitute for security analysis. Secret/privacy scan of
changed files is clean.

## Preserved limitations and readiness (unchanged)

Genesis-authority activation remains DISABLED pending D4-D7. D6 (signed-domain)
and D7 (epoch/restore authority lifetime) remain UNRESOLVED. F3/F4/F8 are not
fully remediated/activated in production; F6 remains partial; F1/F2/F5/F7 are
unresolved (F5 — TimeoutCertificate signer — is **not** closed). RS1 and C4/C5
remain OPEN. M4/M6/S5/S7 remain Yellow. Public DevNet remains **NO-GO**; no
live-seed / TestNet / MainNet readiness is claimed. Configured-authority
release-binary adversarial evidence is **not** captured (default-profile
process tests are not standalone release-binary evidence). The liveness
limitation is intentional: under Required with Proposal/Vote authority absent,
inbound Proposal/Vote are rejected and outbound Proposal/Vote are suppressed
(fail-closed). Run 423 is **not** started.