# QBIND DevNet Evidence — Run 401

Public DevNet **M6 operator-root reuse / rotation deferral package** — operator
identity continuity documentation + verification harness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 401 adds **no** production Rust source change, **no** `build.rs` change,
**no** new CLI flag; it starts no externally reachable listener, opens no
externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status
service, changes no P2P wire format, weakens no peer admission, enables no
peer-driven apply, and mutates no trust/validator/epoch/sequence/marker/
`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet M6 identity continuity package POSITIVE.** The operator
identity continuity + rotation/revocation deferral documentation lands cleanly
and is verified against the **real** first-class `qbind-node identity` CLI
surfaces. **M6 remains Yellow / Partial (better documented, not Green).** No M4
Green, no M6 Green, no C4/C5 closure is claimed.

## 2. Files changed

New:
- `docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md`
- `docs/release/public-devnet/identity/ROTATION_REVOCATION_DEFERRAL.md`
- `scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md` (this file)
- `docs/devnet/run_401_public_devnet_m6_identity_continuity/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs only):
- `docs/release/public-devnet/identity/README.md` (Run 401 note + Contents rows)
- `docs/release/public-devnet/identity/VERIFY.md` (Run 401 verification note)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 401 narrative + M6 row/checklist/gap-matrix; M6 stays 🟡)
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` (Run 401 bullet)
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 401 paragraph)
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 401 paragraph)
- `docs/whitepaper/contradiction.md` (Run 401 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B (expected).** Durable operator identity reuse across DevNet restarts is
**mostly operational guidance** over the already-shipped identity primitives, so
the package is **docs + verification harness only** — no new CLI surface and no
source change. Route A was not taken because no additional CLI capability was
needed (the existing `identity` surfaces already support reuse verification via
deterministic `verify`); Route C was not taken because reuse **can** be documented
honestly without overclaiming C4/C5 (rotation/revocation are documented as
explicitly deferred, not delivered).

## 4. M6 investigation result

- The first-class `qbind-node identity` command (Run 375) and the non-mutating
  `register-check` verifier (Run 376) already make the **generation + verification**
  and **registration/admission-check** halves of M6 **Green-for-scope**.
- Durable reuse is a property of the **leaf** material: keeping the same
  `leaf.kem.sk.bin` + `leaf.cert.bin` preserves `node_id`/`peer_id` across
  restarts, and `identity verify <leaf.cert.bin>` re-derives the same `node_id`
  deterministically (proven by the harness).
- The `identity generate` tool mints a **fresh root ML-DSA-44 signing key in
  memory only** per run, so operator-supplied durable-**root** reuse/rotation is
  **not** provided — this, plus the absence of a live public DevNet to register a
  continuous identity into (M4-gated), is why **M6 remains Yellow / Partial**.

## 5. Identity continuity guidance

`IDENTITY_CONTINUITY.md` documents: what a durable operator identity is (the
`(leaf.kem.sk.bin, leaf.cert.bin, trusted_root_spec/root.pk.hex)` triple);
safe public/private material handling; exactly **what may be reused** between
restarts (same leaf secret + cert → same `node_id`/`peer_id`, same
`trusted_root_spec`, same `validator_address`/`--validator-id`, same
`status: planned` candidate); **what must not be rotated/edited by hand** (no
hand-editing of cert/secret/JSON/seed entries; no manual live-`node_id` rotation;
no hand-editing of trust/authority/validator/epoch/sequence/marker state); and the
honest root-signing-key limitation (in-memory-only root; durable-root reuse is
C4/C5-deferred).

## 6. Rotation/revocation deferral

`ROTATION_REVOCATION_DEFERRAL.md` states plainly that production key **rotation**
and **revocation** are **NOT implemented** for public DevNet and are **explicitly
deferred** to C4/C5/MainNet: no CA lifecycle, no CRL/revocation-list flow, no
online revocation of a published DevNet `node_id`, no operator-supplied
durable-root reuse/rotation, and no live trust-state mutation. On DevNet
"rotation" is regeneration (`identity generate` → new `status: planned`
candidate), acceptable only because DevNet material is experimental, resettable,
and valueless. This is anchored to the existing C4/C5, trust-anchor, and PQC
lifecycle references.

## 7. CLI/help verification

The harness builds `target/release/qbind-node` and confirms every documented
identity command is present in the authoritative `qbind-node identity`
help/usage surface:

```
identity_help_commands=OK (generate/verify/print-public/seed-candidate/register-check present in identity usage)
```

(The `identity` subcommand is dispatched **before** flag parsing, so its usage —
not the top-level clap `--help` — is the authoritative command surface; the
harness captures `qbind-node identity` usage output and greps each command.)

## 8. Existing identity test evidence

The existing identity test suites are run unchanged and pass:

- `cargo test -p qbind-node run_375_public_devnet_identity_cli` — first-class
  `identity generate/verify/print-public/seed-candidate` + MainNet/TestNet
  refusal.
- `cargo test -p qbind-node run_376_public_devnet_identity_registration` —
  non-mutating `register-check` admission boundary + fail-closed cases.

The harness additionally re-proves, on the real binary, that
`generate/verify/print-public/seed-candidate/register-check` are functional,
`node_id` is deterministically re-derivable (durable reuse), the leaf KEM secret
is `0600`, and MainNet/TestNet generation is **REFUSED**.

## 9. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-Green / C4-C5-closure / TestNet-MainNet-ready / rotation-delivered claim)
```

The normalized non-claim grep over the two new continuity docs finds no
forbidden readiness/closure/rotation-delivered claim.

## 10. Security scans

- **Secret scan:** the changed files were scanned; **no** secret / API key /
  token / credential is present. The identity package is docs/schema only; the
  harness `.gitignore` excludes `*.kem.sk.bin`, `*.cert.bin`, `*.pem`,
  `*.public.json`, logs, and data dirs. `committed_private_material=NONE`.
- No private key/KEM/root/signing material is committed under
  `docs/release/public-devnet/identity/`.

## 11. Runtime mutation check

None. Run 401 applies **no** trust bundle, performs **no** live/peer-driven
apply, and mutates **no** validator set / `LivePqcTrustState` / epoch / sequence
/ marker. It opens no externally reachable port and starts no node listener
beyond the offline `identity` tooling.

## 12. Readiness delta — M6

**Yellow / Partial → Yellow / Partial (better documented).** M6 does **not** move
Green: no live public DevNet exists to register a continuous identity into
(M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN. The
continuity + deferral docs make the exact remaining blocker clearer.

## 13. M4 status

**Yellow / launch-blocking (unchanged).** This package publishes no live seed and
no external reachability evidence.

## 14. S5/S7 status

**S5 Yellow (unchanged)** — no deployed status page; live status M4-gated.
**S7 Yellow (unchanged)** — seed-node runbook published; operating a live seed is
M4-gated.

## 15. Public DevNet status

**NOT launch-ready (unchanged).** The remaining launch blocker is M4 (a live,
externally reachable seed/bootnode with off-host reachability evidence).

## 16. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains
**Red**. Rotation/revocation are documented as **deferred**, not delivered; no
closure is claimed.

## 17. TestNet/MainNet blockers

`identity generate` refuses `mainnet`/`testnet` (verified). No TestNet or MainNet
identity/custody artifact is created; N1–N7 remain Red; no TestNet/MainNet
readiness is claimed.

## 18. Tests run

- `bash scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh` →
  `RESULT=POSITIVE` (all OK lines; see `run_401_.../summary.txt`).
- `cargo test -p qbind-node run_375_public_devnet_identity_cli` → pass.
- `cargo test -p qbind-node run_376_public_devnet_identity_registration` → pass.
- `cargo build -p qbind-node --release --locked --bin qbind-node` → builds (help
  verification path).
- Non-claim grep → OK. Secret scan → no secrets.

## 19. CodeQL

**Docs + shell only; no production Rust/source change** → trivial / not
meaningful for CodeQL. No skipped CodeQL result is presented as clean.

## 20. Honest limitations

- Continuity is anchored on **leaf** reuse; durable operator-supplied **root**
  reuse/rotation is not provided (in-memory-only root) and is C4/C5-deferred.
- No live registration path is exercised (M4-gated); reuse is proven over the
  offline `identity` tooling only, not against a running public DevNet.
- The harness verifies the identity command surface via the `identity` usage
  output (authoritative, since `identity` is dispatched before flag parsing),
  not the top-level clap `--help`.

## 21. Suggested Run 402

Pursue the real launch blocker: **M4** — deploy or validate a genuinely
externally reachable public DevNet seed/bootnode under strict KEMTLS static-root,
capture independent off-host reachability evidence, publish a schema-valid
`devnet-seeds.live.json`, and only then close the M4-gated live-registration half
of M6. Do not attempt operator-root reuse/rotation/revocation until C4/C5 work is
scoped, to avoid overclaiming closure.
