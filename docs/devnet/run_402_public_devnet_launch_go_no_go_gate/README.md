# Run 402 evidence archive — public DevNet launch go/no-go gate + blocker register

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_402_public_devnet_launch_go_no_go_gate.sh` and contains only
publish-safe values: the two document SHA-256 hashes and the OK / POSITIVE status
lines. **No secret key, private material, generated identity, data dir, raw log,
raw metrics dump, private endpoint, or absolute path is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_402_public_devnet_launch_go_no_go_gate.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust
source change). Run 402 publishes the public DevNet **launch go/no-go gate**
package — `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` (DevNet-only /
experimental / resettable / no-value label; current decision **NO-GO / NOT
launch-ready**; Green-items summary; blocking-items summary; exact M4 Green
prerequisites; exact M6 Green prerequisites; S5/S7 M4-gated explanation; C4/C5
OPEN statement; TestNet/MainNet non-claim; final go/no-go rule) and
`docs/release/public-devnet/BLOCKER_REGISTER.md` (the M4 / M6 / S5 / S7 blockers
with owner / action / evidence-needed / status columns, plus the "no launch until
every must-have is Green and launch is explicitly in scope" rule).

The harness verifies both docs against the **canonical readiness matrix**
`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`: the go/no-go doc and
blocker register exist and are safety-labelled; the decision is **NO-GO / NOT
launch-ready**; the M4 / M6 / S5 / S7 blockers and their owner/action/
evidence-needed/status columns are present; the go/no-go rule requires **every
must-have Green AND launch explicitly in scope**; C4/C5 are stated **OPEN**; the
cross-links to the M4 checklist, evidence template, identity continuity, rotation
deferral, status decision, readiness criteria, C4/C5, and contradiction ledger are
present; the non-claim grep passes (no launch-ready / M4-M6-S5-S7-Green /
C4-C5-closure / TestNet-MainNet-ready / deployment claim); and no private/raw
artifact, absolute path, private endpoint, or secret is committed. It reconciles
the readiness matrix (**M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN**; public DevNet
NOT launch-ready).

This run adds clarity **only**. It starts no node, opens no externally reachable
port, deploys no seed/bootnode/faucet/RPC/explorer/status service, changes no wire
format, weakens no peer admission, enables no peer-driven apply, adds no CLI flag,
and mutates no trust/validator/epoch/sequence/marker/`LivePqcTrustState` state.
**No** readiness item moves Green. **M4** stays Yellow/launch-blocking, **M6**
stays Yellow/Partial, **S5** and **S7** stay Yellow, public DevNet remains **NOT
launch-ready**, and **C4/C5 remain OPEN**. No M4 Green, no M6 Green, no S5 Green,
no S7 Green, and no C4/C5 closure is claimed. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_402.md`.
