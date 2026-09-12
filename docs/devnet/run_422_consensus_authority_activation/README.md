RUN 422 — GENESIS-BOUND CONSENSUS AUTHORITY AND STANDALONE-BINARY ACTIVATION
Evidence archive README

============================================================================
VERDICT (see summary.txt for the exact label block)
============================================================================

*** CONTAINMENT CORRECTION — supersedes the reachable-activation state below ***

RESULT=PARTIAL-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-D4-D7
LEGACY_CLI_CONTEXT_ACTIVATION=UNCHANGED-AND-STILL-REACHABLE
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO

The prior corrective continuation left the genesis-authority route reachable:
valid genesis + matching signer + `--consensus-authority-from-genesis` still
built an active context and reached the consensus loop. This containment pass
disables that NEW route entirely via a single early startup refusal (exit
nonzero, "genesis-authority activation is disabled pending D4-D7") enforced
before P2P service construction and before any consensus task, across every
network mode and environment, with no override/bypass/fallback. D4-D7 remain
UNRESOLVED and are the precondition for any future re-enablement. The legacy
`--validator-consensus-key` CLI-key route is UNCHANGED and still reachable, so
no blanket "all production activation is unavailable" claim is made. See
../QBIND_DEVNET_EVIDENCE_RUN_422.md for the full defect table.

--- CORRECTIVE CONTINUATION (HISTORICAL, SUPERSEDED BY CONTAINMENT) ---

RESULT=PARTIAL-FOR-DEVNET-CONSENSUS-AUTHORITY-ACTIVATION-CODE-TEST
PRODUCTION_ACTIVATION=UNAVAILABLE-FOR-UNRESOLVED-BOUNDARIES (reachable path — corrected)
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
AUTHORITY_SCOPE=GENESIS-BOUND-DEVNET
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO

--- INITIAL CONCLUSION (HISTORICAL, SUPERSEDED) ---

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

Route A (genesis-bound) is DISABLED in production by this containment pass. The
opt-in flag `--consensus-authority-from-genesis` remains defined, but supplying
it during normal startup now triggers a single early startup refusal rather than
building any consensus context.

New/retained opt-in production flag: `--consensus-authority-from-genesis`
(default off). When set during normal startup, the node:

  1. exits NONZERO at the single startup guard in `main` (immediately before the
     `match config.network_mode` service dispatch), with the diagnostic
     "genesis-authority activation is disabled pending D4-D7";
  2. does so AFTER Run 102 boot-time genesis verification but BEFORE any P2P
     service is constructed and BEFORE any consensus task is spawned;
  3. applies uniformly across every network mode (LocalMesh and P2P) and every
     environment, with no override, hidden flag, environment bypass, or unsigned
     fallback, and never silently continues with `None` after the explicit
     activation request.

The corrected authority loader (`load_verify_and_build_genesis_authority`:
single-snapshot provenance, boot-identity equality, membership-count reject) is
RETAINED and still exercised by the provider tests, but is no longer reachable
from a normally built binary because the flag is contained upstream.

When the flag is absent, existing configuration determines context availability.
The unavailable-authority default remains None plus Required. Valid legacy
--validator-consensus-key configuration can still build Some(ctx). Both cases
are unchanged; this pass blocks only the new genesis-authority route.

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