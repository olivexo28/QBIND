# QBIND DevNet Evidence — Run 063: Local Revoked-Issuer-Root Startup Self-Check on the PQC Trust Bundle (NARROW C4 sub-piece)

## Exact objective

Run 063 introduces, exercises on the live release binary, and proves
the smallest production-honest **root-level** local revocation startup
self-check on the PQC trust-bundle surface introduced by Run 050 and
extended by Runs 051/052/054/055/057/058/059/060/061/062. Before
Run 063, when an operator launched `qbind-node` with a `--p2p-leaf-cert`
whose decoded `NetworkDelegationCert.root_key_id` referred to a
transport root that the loaded signed PQC trust bundle had **root-
revoked** (i.e. listed on the active `revoked_root_ids` set, with no
matching active `revoked_leaf_fingerprints` entry), the binary would
nevertheless construct its `P2pNodeBuilder`, install the trust
context, and proceed toward dialling/listening. The bundle's
root-revocation axis was still enforced *at peer cert-verify time*
under `--p2p-mutual-auth required` (Run 050), but the fact that the
node was carrying — locally — a leaf credential whose issuer the
bundle had revoked was not surfaced as a fail-closed startup
boundary. Run 061 closed this only on the leaf-fingerprint axis;
Run 063 closes it on the **root** axis.

After Run 063, every startup that loads a signed PQC trust bundle
with a non-empty `--p2p-leaf-cert` runs exactly one new self-check —
`check_local_leaf_issuer_root_not_revoked` — over the local cert's
decoded `root_key_id` against the bundle's *active*
`revoked_root_ids` set (the same set the cert-verify path consults).
If the local issuing root is on the active set, the binary emits
exactly one `[binary] FATAL: Run 063 local leaf certificate issuer
root revoked …` line on stderr and exits 1, BEFORE any P2P state is
constructed, BEFORE the `pqc_config` is moved into the builder, and
BEFORE any peer connection is attempted. PENDING root revocations
(Run 062 `pending_revoked_root_ids`) are explicitly NOT consulted —
the self-check fires only on satisfied, currently-enforced
revocations, never on scheduled-future ones.

The scope is intentionally narrow (per the task):

- add the smallest possible helper API surface
  (`check_local_leaf_issuer_root_not_revoked` returning
  `Result<[u8; 32], LocalLeafIssuerRootSelfCheckError>`) in
  `crates/qbind-node/src/pqc_trust_bundle.rs`, alongside the existing
  Run 061 `check_local_leaf_not_revoked`;
- call it from exactly one binary call site in
  `crates/qbind-node/src/main.rs`, immediately after the Run 061
  call site and before `pqc_config` is moved into the builder;
- on success, emit one `[binary] Run 063: local-leaf issuer-root
  startup self-check passed (local_issuer_root_id=AAAA..
  bundle_fp=BBBB.. active_revoked_root_ids=N)` log line;
- on `IssuerRootRevoked`, emit exactly one `[binary] FATAL: Run 063
  …` line and call `std::process::exit(1)`;
- on `DecodeFailed` (defence-in-depth; unreachable on this path
  because `PqcLeafCredentialPaths::load` already validated the cert
  shape), emit exactly one `[binary] FATAL: Run 063 local
  --p2p-leaf-cert could not be decoded …` line and exit 1;
- preserve the Run 061 leaf-fingerprint local self-check
  bit-for-bit (the two checks run independently; either failing is
  sufficient to fail closed; both passing emits both log lines);
- preserve every Run 050/051/052/053/054/055/057/058/059/060/061/062
  negative path bit-for-bit;
- preserve the Run 062 "pending entries are never enforced"
  invariant — the helper takes the active set only (`loaded
  .revoked_root_ids`), never the pending set;
- NEVER widen the helper signature to accept private-key material
  (`leaf_kem_sk` / `signing_sk` / `root_sk` never crosses the
  boundary; the helper takes only public cert bytes + the public
  active revoked-root set + the public 32-byte bundle fingerprint);
- NEVER bump the Run 052 peer-handshake counter
  `qbind_p2p_pqc_cert_verify_rejected_revoked_total` (it is a
  handshake-only contract; a startup self-check failure is NOT a
  handshake event); the Run 063 helper signature does not take any
  metrics sink, and the boundary is pinned by the unit test
  `run063_self_check_does_not_touch_peer_handshake_metric_family`;
- NEVER introduce a new `/metrics` family — the node exits before
  the HTTP server binds, so a counter bumped here would not be
  scrapeable; the only operator-facing signal is the single stderr
  line.

The scope is intentionally NOT widened (per the task):

- Run 063 does NOT introduce in-binary bundle-signing-key
  ratification; the existing Run 060 boundary stands.
- Run 063 does NOT introduce a runtime per-environment minimum
  activation-margin policy on root revocations; the Run 062 boundary
  stands.
- Run 063 does NOT add an `activation_epoch` runtime source; the
  Run 057/058/059/060/061/062 boundary stands.
- Run 063 does NOT add a `Dummy*` / classical-signature fallback —
  the bundle remains suite 100 (ML-DSA-44) only and the transport
  remains ML-KEM-768 + ML-DSA-44 only.
- Run 063 does NOT touch the qbind-net handshake surface, the
  forged-traffic policy, the consensus wire format, or the timeout
  / NewView wire format. C5 is untouched.

## Verdict

PASS. The new Run 063 helper is wired exactly once on the binary
path between the Run 061 local-leaf fingerprint self-check and the
construction of `pqc_config`; it returns `Ok(local_issuer_root_id)`
on every honest startup, and `Err(IssuerRootRevoked { … })` on every
startup where the bundle's active `revoked_root_ids` set lists the
local cert's decoded `root_key_id`. The three live release-binary
smokes (positive non-revoked, negative active-revoked issuer root,
positive pending-revoked issuer root) execute exactly as
specified — see "Release-binary smoke harness" below. All required
regression suites are green; the four legacy boundaries (Run 050
root-axis cert-verify time, Run 052 peer-handshake leaf revocation,
Run 061 local-leaf-fingerprint startup self-check, Run 062 active vs
pending revocation split) are preserved bit-for-bit and proven by
the integration tests `run063_signed_devnet_bundle_with_pending_
revoked_local_issuer_root_passes_self_check`, `run063_signed_devnet_
bundle_with_unrelated_active_revoked_root_passes_self_check`,
`run063_does_not_weaken_run_061_local_leaf_fingerprint_self_check`,
and the lib unit test `run063_self_check_does_not_touch_peer_
handshake_metric_family`. Full C4 remains OPEN — Run 063 narrows
the Run 060 §10 / Run 061 §10 / Run 062 §10 item (a) "root-level
local revocation self-check" boundary only; all other Run 060/061/062
§10 remaining items persist unchanged.

## Files changed

| Surface | File | Change |
| ------- | ---- | ------ |
| helper API + error type | `crates/qbind-node/src/pqc_trust_bundle.rs` `check_local_leaf_issuer_root_not_revoked` + `LocalLeafIssuerRootSelfCheckError` | NEW pure helper returning `Result<[u8; 32], …>`; mirrors the Run 061 helper's shape but consults the *root* axis |
| binary call site | `crates/qbind-node/src/main.rs` (immediately after the existing Run 061 block, immediately before `let pqc_config = PqcStaticRootConfig { … }`) | NEW one-shot call. Emits `[binary] Run 063: … passed` on `Ok`; emits `[binary] FATAL: Run 063 …` + `exit(1)` on `Err(IssuerRootRevoked)` or `Err(DecodeFailed)` |
| lib unit tests | `crates/qbind-node/src/pqc_trust_bundle.rs::tests::run063_*` | 9 tests covering positive non-revoked, positive unrelated active-revoked, negative active-revoked (`IssuerRootRevoked`), negative decode-failed (`DecodeFailed`), root_id parity with the cert-verify path, no private-key dependency (API pin), orthogonality to Run 061 leaf axis, log-safe Display prefixes only, and no peer-handshake metric bleed |
| integration tests | `crates/qbind-node/tests/run_063_pqc_local_issuer_root_self_check_tests.rs` | 8 tests covering positive non-revoked end-to-end on a signed DevNet bundle, negative active-revoked end-to-end, positive pending-revoked end-to-end (Run 062 boundary), positive unrelated-active-revoked end-to-end (two-root bundle), root_id parity with `decode_network_delegation_cert`, Run 061 leaf-axis preservation, no-private-material API pin, and active-vs-pending set disjointness at the call site |
| helper modes | `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | NEW modes `signed-devnet-issuer-root-revocation-active-v0` and `signed-devnet-issuer-root-revocation-pending-v0`. Both mint a SECOND fresh DevNet root and append it to `roots[]` before signing, then root-revoke `roots[0]` (the leaf-issuing root). The second root is the smallest possible extension that prevents the Run 050 `trusted_roots.is_empty()` FATAL from firing before the Run 063 self-check on the negative smoke. The second root's secret key is generated in memory only and discarded — never written to disk, never used to sign any cert |
| evidence | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md` | THIS FILE |
| contradiction row | `docs/whitepaper/contradiction.md` C4 | NEW Run 063 row appended after the Run 062 row; C4 still OPEN |

## Commands run (cargo test / build)

```
$ cargo test -p qbind-node --lib pqc_trust_bundle
test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 826 filtered out

$ cargo test -p qbind-node --lib -- pqc_trust_activation pqc_trust_sequence metrics
test result: ok. 143 passed; 0 failed; 0 ignored; 0 measured; 783 filtered out

$ cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests \
                            --test run_040_pqc_static_root_real_aead_tests \
                            --test run_044_pqc_cert_verify_metrics_adapter_tests
test result: ok. 10 + 10 + 10 = 30 passed; 0 failed

$ cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test -p qbind-node --lib
test result: ok. 926 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-net --lib
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-crypto --lib
test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured

$ cargo build --release -p qbind-node \
    --bin qbind-node \
    --example devnet_pqc_trust_bundle_helper \
    --example devnet_pqc_root_helper
    Finished `release` profile [optimized] target(s)
```

The pre-existing `bincode::config` deprecation warnings on
`crates/qbind-node/src/binary_consensus_loop.rs:2332` /
`:2461` and the pre-existing `verify_pool::worker_id` unused-variable
warning are unchanged by Run 063 and remain unrelated to this run.

## Issuer root_id extraction semantics (identity parity with cert-verify path)

The Run 063 helper extracts the local cert's issuing root identity
by decoding the cert with the bundle parser's existing wire-format
path (`NetworkDelegationCert::decode`, the same decoder
`qbind_node::pqc_root_config::decode_network_delegation_cert` calls
on the cert-verify path) and reading the `root_key_id: [u8; 32]`
field. This is byte-identical to the identity the cert-verify path
uses to look up the trusted root pk when validating a peer cert
under `--p2p-mutual-auth required`. The boundary is pinned by:

- `run063_self_check_uses_same_root_id_as_cert_verify_path` (lib
  unit test in `pqc_trust_bundle.rs`): asserts that the helper's
  returned `[u8; 32]` equals `decode_network_delegation_cert(
  &cert_bytes).unwrap().root_key_id`.
- `run063_self_check_uses_same_root_id_as_cert_verify_path`
  (integration test in
  `tests/run_063_pqc_local_issuer_root_self_check_tests.rs`):
  asserts the same equality end-to-end against a freshly minted
  DevNet root.

If the cert bytes fail to decode at all (a defence-in-depth path
that cannot be reached when the cert was loaded via
`PqcLeafCredentialPaths::load`, which performs the same decode
already), the helper returns `LocalLeafIssuerRootSelfCheckError::
DecodeFailed` and the binary fails closed with the dedicated FATAL
line. This is intentional: the helper itself is the smallest piece
of self-contained machinery that does NOT trust its inputs.

## Ordering vs. Run 050/051/052/053/057/061/062

The Run 063 self-check runs at exactly one well-defined point on
the binary boot path:

1. CLI parsing (`Cli::parse_args`) — no Run 063 work.
2. `PqcStaticRootConfig` candidate `mode` resolution from the
   `--p2p-pqc-root-mode` flag — no Run 063 work.
3. Resolve `trusted_roots` from `--p2p-trusted-root` (DevNet only)
   and/or `--p2p-trust-bundle` — Run 050 active-roots filtering
   happens here; the Run 062 active/pending split happens here.
4. Run 050 `if pqc_required && trusted_roots.is_empty()` fail-closed
   FATAL — unchanged. (If this fires, Run 063 is NOT reached. Run 063
   only matters when `active_roots` is non-empty AND a local leaf is
   configured.)
5. Run 050/051 `[binary] Run 050/051: trust bundle loaded …` log line
   — unchanged.
6. Run 062 `[binary] Run 062: trust-bundle revocation activation …`
   log line — unchanged.
7. **Run 061 local-leaf-fingerprint startup self-check** — emits its
   passed/FATAL line; unchanged.
8. **Run 063 local-leaf-ISSUER-ROOT startup self-check** — NEW.
   Emits `[binary] Run 063: … passed (…)` on success, or `[binary]
   FATAL: Run 063 …` + `exit(1)` on `IssuerRootRevoked`. This is the
   only new line in the boot sequence.
9. `let pqc_config = PqcStaticRootConfig { … };` — moves
   `leaf_credentials` and `peer_leaf_certs` into the config struct.
   Run 063 has already run by here and has already validated the
   local cert.
10. `[binary] Run 039: pqc_root_mode=… configured_roots=N …` log line
    — unchanged.
11. `let builder = builder.with_pqc_root_config(pqc_config);` —
    handed to the builder.
12. `builder.with_pqc_leaf_revocations(loaded.revoked_leaf_fingerprints)`
    — Run 052 peer-handshake revocation set wired; receives only the
    active set per Run 062. Run 063 has no analog here because the
    qbind-net handshake stack already enforces root revocation at
    cert-verify time (Run 050) via the trusted-roots set itself —
    revoked roots are simply absent from `loaded.active_roots`.
13. `builder.build(…)` — constructs the live P2P node; Run 063 has
    completed before this point.

The Run 063 self-check runs **after** every existing fail-closed
boundary on the loaded bundle (signature verification, env binding,
chain_id binding, sequence anti-rollback, activation-height gating,
revocation-activation height gating, local leaf-fingerprint
self-check) — so if the bundle itself fails to verify or to satisfy
any of those, the Run 063 line never appears. The Run 063 check
runs **before** any P2P state is constructed (no listener bind, no
peer dial, no metrics HTTP bind), so an active-revoked local issuer
root deterministically denies the node any P2P presence.

## Active vs. pending revocation semantics (Run 062 boundary preserved)

Run 062 split the trust-bundle's revocation surface into two
disjoint sets:

- `loaded.revoked_root_ids: HashSet<[u8; 32]>` — the *active* set;
  every entry is currently enforced (its `effective_from <=
  validation_time` AND its `activation_height` is `None` OR `<=
  current_height`).
- `loaded.pending_revoked_root_ids: BTreeSet<[u8; 32]>` — the
  *pending* set; every entry is signature-valid and `effective_from`-
  satisfied but its `activation_height` is in the future relative to
  `current_height`, or `current_height` is unavailable.

The Run 063 helper takes ONLY `loaded.revoked_root_ids` (active set)
as input. Pending entries are deliberately NOT consulted. This means:

- A bundle that root-revokes the local cert's issuing root with
  `activation_height = None` (legacy Run 050 immediate) fires the
  Run 063 FATAL.
- A bundle that root-revokes the local cert's issuing root with
  `activation_height <= current_height` (Run 062 satisfied) fires
  the Run 063 FATAL — semantically identical to the legacy immediate
  case.
- A bundle that root-revokes the local cert's issuing root with
  `activation_height > current_height` (Run 062 pending) does NOT
  fire the Run 063 FATAL. The node starts cleanly; the operator has
  declared a scheduled revocation that does not yet apply. When the
  runtime height catches up, the bundle MUST be reloaded for the
  revocation to take effect — Run 063 is a startup-time check, not
  an on-the-fly check (see "Explicit remaining boundaries" below).

The boundary is pinned by:

- `run063_pending_revoked_root_never_bleeds_into_active_set_used_by_helper`
  (integration test): asserts `loaded.revoked_root_ids` and
  `loaded.pending_revoked_root_ids` are disjoint and that the helper
  receives only the former.
- `run063_signed_devnet_bundle_with_pending_revoked_local_issuer_root_passes_self_check`
  (integration test): exercises the end-to-end pending path against
  a freshly minted, ML-DSA-44-signed DevNet bundle.
- Live release-binary Smoke 3 (below): a bundle with
  `activation_height = u64::MAX` keeps the local issuer root in
  `active_roots`, Run 062 reports `root_pending=1 root_active=0`,
  and Run 063 logs `… passed (active_revoked_root_ids=0)`.

## Metrics / logging decision (why no new counter)

Run 063 deliberately introduces NO new `/metrics` family and NO new
counter on any existing family. The decision is documented in the
binary-side comment and pinned by the unit test
`run063_self_check_does_not_touch_peer_handshake_metric_family`.
The reasoning:

1. **Scrapeability.** The Run 063 check runs *before* the metrics
   HTTP server is bound by the live binary path. A counter bumped
   here would be incremented in process memory and then the process
   would either exit (negative path: FATAL + exit 1) or continue to
   bind `/metrics` (positive path: counter still at zero by
   construction, because the helper returned Ok). On the negative
   path the counter is never scrapeable. Adding it would be
   misleading: operators would see a metric definition with no
   accompanying scrape evidence on the very smokes where the
   metric's only non-zero value occurs.
2. **No overlap with Run 052 peer-handshake counter.** The Run 052
   counter `qbind_p2p_pqc_cert_verify_rejected_revoked_total` is
   the peer-handshake contract for "a peer's cert was rejected
   because its root or leaf was revoked." A *local* startup
   self-check is NOT a peer-handshake event; bumping the Run 052
   counter from the Run 063 path would silently re-meaning the
   counter ("revoked at handshake time OR at startup time") and
   would corrupt the existing Prometheus dashboards anchored on
   that counter. The Run 063 helper signature explicitly does not
   take any metrics sink, so this cannot happen by mistake.
3. **Single source of truth on the negative path.** The single
   `[binary] FATAL: Run 063 …` stderr line is the only operator-
   facing signal of a Run 063 failure. It carries only public
   material (8-hex prefixes of the local issuer root id, the
   bundle fingerprint, and the local leaf fingerprint — never the
   full digests, never any private key material), the static
   marker phrase "local leaf certificate issuer root revoked", and
   the explicit non-fallback claim "Refusing to start P2P. No
   fallback to --p2p-trusted-root on bundle-revoked local issuer
   root."
4. **Positive-path log line.** The `[binary] Run 063: local-leaf
   issuer-root startup self-check passed (local_issuer_root_id=
   AAAA.. bundle_fp=BBBB.. active_revoked_root_ids=N)` line is
   emitted on every successful startup that has both a loaded
   bundle and a configured local leaf. It carries only 8-hex
   prefixes and the count of active revoked roots, never the full
   digests, never any private key material.

The two log lines (positive and negative) appear in the same
relative position in the boot sequence on every smoke, exactly once
each, and never both on the same run.

## Binary identity (release smoke harness)

| Binary | sha256 | Build ID (ELF NT_GNU_BUILD_ID) |
| ------ | ------ | ------------------------------ |
| `target/release/qbind-node` | `196792247254ff3999434fc6bbb74176c75ca7d4de77a543419dd3f9a907faac` | `bafaeef5956288f4093e396828373568df8509cd` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `3c2a1772b134834b28af5269756197ef4a81cc73d3861d24a997590b07168c3a` | `2e588f0187624fa7d53c09a70bd4033194dbff24` |
| `target/release/examples/devnet_pqc_root_helper` | `f1d882f4b7896f3f381e2e949ad037cb3233fbe954ef44a03339609b67808088` | `ff4472fa9bdcff238249bc76ae15cf6c7d87da98` |

These exact binaries were used for all smokes below. Both helpers'
ephemeral signing-key handling is unchanged from Run 050/051/060/061/062:
`root_sk` and the bundle's `signing_sk` (and, in Run 063 modes, the
second root's ephemeral `root_sk`) are held in memory only and
discarded at the end of the helper process — never written to disk
in any form, never logged.

## Release-binary smoke harness

```bash
# 1) Build release binaries (qbind-node, two helpers).
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper

# 2) Mint three signed DevNet bundle fixtures (one per smoke).
mkdir -p /tmp/qbind_run063
for mode in \
    signed-devnet \
    signed-devnet-issuer-root-revocation-active-v0 \
    signed-devnet-issuer-root-revocation-pending-v0; do
  outdir="/tmp/qbind_run063/${mode}"
  mkdir -p "$outdir"
  ./target/release/examples/devnet_pqc_trust_bundle_helper \
    "$outdir" 2 "$mode" > "$outdir/helper.stdout.log" 2>&1
done

# 3) Smoke 1 — positive non-revoked local issuer root.
#    Standard `signed-devnet` bundle: 1 root, 0 revocations, the
#    local v0 leaf is issued by that root. Run 063 must pass; the
#    node must reach the dial/listen loop and time out cleanly.
BD=/tmp/qbind_run063/signed-devnet
SIGN_SPEC="$(cat $BD/signing-key.spec)"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19810 timeout 6 \
  ./target/release/qbind-node \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19610 --p2p-peer 1@127.0.0.1:19611 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "$BD/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
    --p2p-leaf-cert "$BD/v0.cert.bin" \
    --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
    --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
    --validator-id 0 --data-dir /tmp/qbind_run063/data/s1
# Expected: exit 124 (clean startup, then `timeout` SIGKILL); stderr
# contains exactly one `[binary] Run 063: … passed (…
# active_revoked_root_ids=0)` line; no FATAL.

# 4) Smoke 2 — negative active-revoked local issuer root.
#    Two-root bundle: roots[0] is the leaf-issuing root and is
#    root-revoked with `activation_height = None` (active under the
#    binary's loader), roots[1] is a fresh still-active root added
#    purely to keep `active_roots` non-empty so the Run 050
#    `trusted_roots.is_empty()` FATAL does NOT fire. The local v0
#    cert is issued by roots[0]. Run 063 must fail closed with the
#    new FATAL.
BD=/tmp/qbind_run063/signed-devnet-issuer-root-revocation-active-v0
SIGN_SPEC="$(cat $BD/signing-key.spec)"
timeout 15 ./target/release/qbind-node \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19620 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "$BD/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
    --p2p-leaf-cert "$BD/v0.cert.bin" \
    --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
    --validator-id 0 --data-dir /tmp/qbind_run063/data/s2
# Expected: exit 1; stderr contains exactly one `[binary] FATAL: Run
# 063 local leaf certificate issuer root revoked …` line, NO Run 052
# / Run 061 FATAL.

# 5) Smoke 3 — positive pending-revoked local issuer root.
#    Two-root bundle: roots[0] is the leaf-issuing root and is
#    root-revoked with `activation_height = u64::MAX` (PENDING under
#    the binary's loader at `current_height = 0`), roots[1] is a
#    fresh still-active root. The local v0 cert is issued by
#    roots[0]. Run 062 reports `root_pending=1 root_active=0`; the
#    pending entry never reaches `loaded.revoked_root_ids`, so
#    Run 063 must pass.
BD=/tmp/qbind_run063/signed-devnet-issuer-root-revocation-pending-v0
SIGN_SPEC="$(cat $BD/signing-key.spec)"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19830 timeout 6 \
  ./target/release/qbind-node \
    --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19630 --p2p-peer 1@127.0.0.1:19631 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "$BD/trust-bundle.json" \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
    --p2p-leaf-cert "$BD/v0.cert.bin" \
    --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
    --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
    --validator-id 0 --data-dir /tmp/qbind_run063/data/s3
# Expected: exit 124; stderr contains exactly one `[binary] Run 063:
# … passed (… active_revoked_root_ids=0)` line (because the entry
# is PENDING, not active); `[binary] Run 062: … configured=1
# active=0 pending=1 root_active=0 root_pending=1 …` line; no FATAL.

# Smoke 4 (positive unrelated active-revoked root) is covered at the
# API level by the integration test
# `run063_signed_devnet_bundle_with_unrelated_active_revoked_root_passes_self_check`
# in `crates/qbind-node/tests/run_063_pqc_local_issuer_root_self_check_tests.rs`,
# which mints a two-root signed DevNet bundle, root-revokes the
# OTHER root only, and asserts that the helper still returns
# Ok(local_root_id). A dedicated release-binary smoke for this case
# is intentionally NOT added because the existing
# `devnet_pqc_trust_bundle_helper` issues every leaf cert from
# `roots[0]`; minting a second leaf cert from `roots[1]` would
# require a larger helper restructure than this run's narrow scope
# permits, and the integration test exercises exactly the same code
# path (the same `check_local_leaf_issuer_root_not_revoked` helper)
# against exactly the same signed-bundle shape.
```

## Observed stderr (key excerpts)

### Smoke 1 (positive non-revoked)

```
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run063/signed-devnet/trust-bundle.json env=devnet fp=0707c7517056a449e7e3f04d166229d60ca4faaa61b1d3b6c5ab79ee4be2f941 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=54eb7a4a..) signing_keys_configured=1. Bundle root IDs: [d6ba8886..]
[binary] Run 062: trust-bundle revocation activation (configured=0 active=0 pending=0 root_active=0 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=d6ba8886.. bundle_fp=0707c751.. active_revoked_root_ids=0)
[binary] Run 052: revoked_leaf_fingerprints=0 (from trust bundle env=devnet sequence=1)
…
exit=124
```

Verdict: Run 063 logs `passed` with the local issuer root prefix
matching the only `Bundle root IDs` entry (`d6ba8886..`), and
`active_revoked_root_ids=0`. The node continues to the dial/listen
loop and is SIGKILL'd cleanly by `timeout`.

### Smoke 2 (negative active-revoked issuer root)

```
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run063/signed-devnet-issuer-root-revocation-active-v0/trust-bundle.json env=devnet fp=665789f349b41d71d580e06115e3296a19428aaf8157896aaddead87a9e25f56 active_roots=1 revoked_roots=1 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=1964a8c8..) signing_keys_configured=1. Bundle root IDs: [64d426c0..]
[binary] Run 062: trust-bundle revocation activation (configured=1 active=1 pending=0 root_active=1 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] FATAL: Run 063 local leaf certificate issuer root revoked: the local --p2p-leaf-cert was issued by transport root id (cb31da51..) which appears in the active revoked_root_ids set of the loaded trust bundle (bundle fp 665789f3.., local leaf fp c97611b9..). Refusing to start P2P. No fallback to --p2p-trusted-root on bundle-revoked local issuer root. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_063.md and docs/whitepaper/contradiction.md C4 (signed root distribution).
exit=1
```

Verdict: Run 062 reports `configured=1 active=1 root_active=1
root_pending=0` — the revocation is currently enforced. `Bundle root
IDs` shows ONLY the still-active second root (`64d426c0..`); the
revoked `cb31da51..` is correctly excluded from `active_roots`. The
local v0 cert's decoded `root_key_id` is the revoked `cb31da51..`
(matching the 8-hex prefix in the FATAL line). Run 063 fires;
no Run 050 / Run 052 / Run 061 FATAL appears (they did not fire
because `active_roots = 1` is non-empty and the leaf fingerprint is
not on `revoked_leaf_fingerprints`). The FATAL line carries 8-hex
prefixes only, the static marker phrase "local leaf certificate
issuer root revoked", and the explicit non-fallback claim.

### Smoke 3 (positive pending-revoked issuer root)

```
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run063/signed-devnet-issuer-root-revocation-pending-v0/trust-bundle.json env=devnet fp=50c0f337de3bb71d669fc6e76f8c93d72e9d2f871ef72726e0dff61360f75d91 active_roots=2 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=d45c34b0..) signing_keys_configured=1. Bundle root IDs: [1617d35a.., 8a3980a4..]
[binary] Run 062: trust-bundle revocation activation (configured=1 active=0 pending=1 root_active=0 root_pending=1 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=1617d35a.. bundle_fp=50c0f337.. active_revoked_root_ids=0)
[binary] Run 052: revoked_leaf_fingerprints=0 (from trust bundle env=devnet sequence=1)
…
exit=124
```

Verdict: Run 062 reports `configured=1 active=0 pending=1
root_active=0 root_pending=1` — the revocation is signature-valid
but its `activation_height` is in the future, so it is PENDING.
Both roots remain in `active_roots` (`Bundle root IDs: [1617d35a..,
8a3980a4..]`); the bundle DECLARES `1617d35a..` revoked but the
helper does NOT consult the pending set. Run 063 logs `passed` with
`active_revoked_root_ids=0`, confirming that the Run 062 → Run 063
boundary is preserved bit-for-bit. The node continues to the
dial/listen loop and is SIGKILL'd cleanly by `timeout`.

## No-fallback proof (Run 063)

- No `Cargo.toml` was touched. No new dependency was introduced. No
  feature flag was added. No `Dummy*` primitive was added,
  strengthened, or referenced. No classical signature surface was
  introduced.
- No removal or modification of any existing test (only additions).
- No transport-root reuse as a bundle-signing authority.
- No protocol / wire-format / consensus / forged-traffic / KEMTLS
  change.
- The helper signature accepts no private-key material. The boundary
  is pinned by the lib unit test
  `run063_self_check_does_not_require_private_key_material` and the
  integration test
  `run063_helper_signature_pins_no_private_key_dependency`.
- The two new helper bundle modes mint a SECOND root key in memory
  only and discard the corresponding `root_sk` at the end of the
  process. The second root is NEVER used to sign any leaf cert (the
  helper still issues v0..vN leaves from `roots[0]` only); the
  second root exists purely as a still-active anchor so that the
  Run 050 `trusted_roots.is_empty()` FATAL does NOT fire before
  Run 063 on the negative smoke. Verified by inspecting
  `/tmp/qbind_run063/**/second-root.id.hex` exists (public-only) and
  `/tmp/qbind_run063/**/second-root.sk.bin` does NOT exist on any
  Run 063 fixture directory.
- The FATAL log line emitted in the negative smoke carries only
  public material: 8-hex prefixes (root id, leaf fingerprint, bundle
  fingerprint), the static marker phrase, the explicit non-fallback
  claim, and references to the evidence + contradiction docs.
- The Run 052 peer-handshake counter
  `qbind_p2p_pqc_cert_verify_rejected_revoked_total` is NOT bumped
  by Run 063. Boundary pinned by the lib unit test
  `run063_self_check_does_not_touch_peer_handshake_metric_family`.
- No new `/metrics` family was introduced. No existing family was
  renamed or widened.

## Explicit remaining boundaries (NOT done in Run 063)

(a) **Per-environment minimum activation-margin policy on root
revocations.** Run 063 enforces the *current* active revoked-root
set as published by the loaded bundle; it does NOT enforce a minimum
margin between a scheduled root revocation's `activation_height`
and the current finalised height. Unchanged from the Run 062 §10
item (c) boundary.

(b) **On-the-fly trust-bundle hot-reload.** Run 063 is a startup-
time check. If the trust bundle is rotated under the running binary
(e.g. by writing a new file under the same `--p2p-trust-bundle` path
and SIGHUP'ing — currently NOT a supported operation), the Run 063
check does not re-run on the live process. Operators must restart
`qbind-node` to re-evaluate the local leaf's issuing root against
the new bundle. Unchanged from the Run 050/051/052/057/061/062
boundary.

(c) **`activation_epoch` runtime source.** Unchanged from the
Run 057/058/059/060/061/062 boundary.

(d) **In-binary bundle-signing-key ratification.** Unchanged from
the Run 060 boundary; out-of-band CLI overlap (Run 060 §6.D) remains
the supported rotation path.

(e) **External KMS / HSM integration.** Unchanged.

(f) **Multi-validator MainNet release-binary peer-connection
smoke.** Unchanged from the Run 059/060/061/062 boundary.

(g) **Production fast-sync / consensus-storage restore.** Unchanged.

(h) **Operator playbook prose update.** Run 060's
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` does not yet
describe the Run 063 startup-time root-revoked-local-issuer
self-check. The runbook is intentionally NOT updated in Run 063
(Run 063 is source-and-evidence, not operator-doc); a future
evidence/documentation-only run may align the runbook prose to
record the new fail-closed boundary.

(i) **No new `/metrics` family.** See "Metrics / logging decision"
above. A future run may add a `qbind_p2p_pqc_trust_bundle_startup_
self_check_rejected_total` counter family if/when on-the-fly
hot-reload is supported (so that a counter bumped at the
self-check site is then scrapeable across the process lifetime).

(j) **Leaf-axis pending semantics.** Run 062's pending leaf
revocations are NOT consulted by the Run 061 helper, and Run 063
does NOT change that. The leaf axis and the root axis are
independent; Run 063 only adds the root-axis startup check. C5
(forged-traffic policy, timeout / NewView / KEMTLS wire formats,
consensus message wire formats) is untouched.

**C5 remains NOT closed** by Run 063; Run 063 does not touch
timeout / NewView wire formats, forged-traffic policy, KEMTLS wire
formats, consensus message wire formats, or any signature/
verification semantics outside the trust-bundle startup self-check
surface. **Full C4 remains OPEN** — Run 063 narrows the Run 060 §10 /
Run 061 §10 / Run 062 §10 item (a) "root-level local revocation
self-check" boundary only; all other Run 060 / Run 061 / Run 062 §10
remaining items persist unchanged.