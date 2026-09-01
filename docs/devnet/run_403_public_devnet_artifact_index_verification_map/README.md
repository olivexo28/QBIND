# Run 403 evidence archive — public DevNet artifact index + operator verification map

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_403_public_devnet_artifact_index_verification_map.sh` and
contains only publish-safe values: the two document SHA-256 hashes and the OK /
POSITIVE status lines. **No secret key, private material, generated identity, data
dir, raw log, raw metrics dump, private endpoint, or absolute path is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_403_public_devnet_artifact_index_verification_map.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust source
change). Run 403 publishes the public DevNet **release package index + operator
verification map** — `docs/release/public-devnet/ARTIFACT_INDEX.md` (DevNet-only /
experimental / resettable / no-value label; thirteen artifact groups each with
path / purpose / readiness item / verification command or document / current
status / non-claims) and `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`
(recommended read orders for an external operator, a security reviewer, and a
release manager; an exact verification map for genesis / binary provenance /
identity / P2P posture / observability / recovery / go-no-go verification; and a
four-part launch stop rule).

The harness verifies both docs against the **on-disk package tree** and the
**canonical readiness matrix** `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`:
both docs exist and are safety-labelled; every present public DevNet package path is
indexed (or explicitly marked absent); the launch go/no-go + blocker register, the
M4 Route-A checklist + seed reachability evidence template, identity continuity +
rotation/revocation deferral, and the C4/C5 closure criteria + contradiction ledger
are all referenced and resolve on disk; the four-part launch stop rule is present;
the non-claim grep passes (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure /
TestNet-MainNet-ready / deployment claim); and no private/raw artifact, absolute
path, private endpoint, or secret is committed. It reconciles the readiness matrix
(**M4 🟡; M6 🟡; S5 🟡; S7 🟡; C4/C5 OPEN**; public DevNet NOT launch-ready).

This run adds navigation + clarity **only**. It starts no node, opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status service,
changes no wire format, weakens no peer admission, enables no peer-driven apply,
adds no CLI flag, and mutates no
trust/validator/epoch/sequence/marker/`LivePqcTrustState` state. **No** readiness
item moves Green. **M4** stays Yellow/launch-blocking, **M6** stays Yellow/Partial,
**S5** and **S7** stay Yellow, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**. TestNet/MainNet untouched.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_403.md`.