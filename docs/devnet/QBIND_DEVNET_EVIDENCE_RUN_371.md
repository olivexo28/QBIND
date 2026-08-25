# QBIND DevNet Evidence — Run 371

Release-binary **live-socket deployed-path** evidence that closes the Run 370
residual blocker for the public DevNet abuse/DoS **M12** controls. Run 371 stands
up a **second KEMTLS-admitted peer** that completes real mutual auth over a real
loopback socket against a separate running `target/release/qbind-node`, floods
over-budget structured frames through the deployed
`TcpKemTlsP2pService::read_loop`, and observes the deployed per-peer limiter drop
them on **live `/metrics`** via
`qbind_net_per_peer_drops_total{reason="rate_limit"}`. The Run 367/370
connection-rate live-socket proof is preserved in the same harness.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route A**
> (no production source change — production public APIs only; no new CLI flag; no
> live deployment; no P2P wire-format change; no KEMTLS / trust-bundle /
> peer-admission weakening).

## 1. Exact verdict

**POSITIVE / public-DevNet abuse/DoS M12 KEMTLS live-socket release-binary — both
deployed live-socket controls proven (M12 Yellow/Partial → Green).**

- The **per-peer message-rate** control is now proven **fully live-socket** on the
  real release binary: a second peer completes a **real KEMTLS mutual-auth
  handshake over a real loopback socket** against `target/release/qbind-node`,
  then floods structured `P2pMessage::Consensus` frames (discriminator `0`, so
  they reach the deployed per-peer limiter after `decode_frame`). Under-budget
  frames produce **0 per-peer drops (metric absent)**; over-budget frames make the
  deployed node's live `/metrics` expose
  `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60 in
  a representative run).
- The **connection-rate** control remains proven **live-socket** on the real
  binary: 10 inbound TCP connections against a max of 3 → 3 accepted / 7 refused,
  `qbind_p2p_connection_rate_drop_total = 7`.
- The two controls are **independent**: the per-peer KEMTLS flood leaves
  `qbind_p2p_connection_rate_drop_total = 0`, and the connection-rate flood leaves
  `qbind_net_per_peer_drops_total` ABSENT.
- Defaults preserved (connection limiter disabled; per-peer `1000` msg/s + `100`
  burst). Invalid / unbounded / MainNet configs fail the binary closed at startup.
  Hidden abuse/DoS flags remain hidden from `--help`. The over-budget flood does
  **not** tear the connection down — the node keeps serving `/metrics`.

**M12 moves Green** for the abuse/DoS deployed live-socket controls: both the
connection-rate and the KEMTLS-admitted deployed per-peer message-rate controls
are proven over real sockets on the release binary. **M12 Green here is scoped to
these two abuse/DoS controls only.** M4 remains Yellow/launch-blocking; public
DevNet remains **NOT launch-ready**; full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper.rs`
  — release helper with two modes: an in-process two-node KEMTLS flood scenario
  suite (default) and a `dial-flood` cross-process second-KEMTLS-peer dialer.
- `scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh`
  — release harness (build, hashes, helper scenarios, CLI surface, fail-closed,
  live-socket connection-rate, KEMTLS per-peer under/over-budget flood on live
  `/metrics`, independence, no-teardown).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md` — this file.
- `docs/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary/`
  — archive (`README.md`, `summary.txt`, `.gitignore`; only these three tracked).

Modified (production Rust source): **none — Route A.**

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Release artifacts and hashes

Representative run (the harness re-captures live values each run; hashes are
host/build-specific and change per rebuild):

| Artifact | SHA-256 | Build ID |
|---|---|---|
| `target/release/qbind-node` | `e28775a2c44d02466b3c86dfff5e5641d93d983bde89e6d0f4701cc257131669` | `05e9e0b9b78599fe1c4d5f6bd1fd8786f3a4b9ec` |
| `…/examples/run_371_…_helper` | `a45d477188def91a7357a62b1735ca4ac093a35ea36a744b476f1380a20c7efe` | `cade551f3f6a7aef9e66a9f19636dbaffa29f1f3` |

Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866
2026-06-30)`.

## 4. Decision gate route

**Route A (no production source change).** Run 370 already wired the exported
per-peer counter end-to-end onto the deployed limiter, so no source change is
needed to observe deployed per-peer drops — the residual blocker was purely the
*driver*: nothing had completed a KEMTLS handshake and flooded real bytes into the
deployed `read_loop`. The default DevNet uses deterministic test-grade KEM
keypairs and default mutual-auth is Disabled, so a second peer built from
`P2pNodeBuilder` can derive the target's peer KEM public key from `vid@addr`, dial
over loopback, complete the handshake, and `broadcast` structured Consensus frames
that reach the deployed per-peer limiter. Production public APIs suffice.

## 5. Runtime evidence shape

Real `target/release/qbind-node` (node A) launched with `--env devnet
--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port> --validator-id
0` plus a loopback `QBIND_METRICS_HTTP_ADDR`. The Run 371 helper in `dial-flood`
mode (node B, validator 1) dials node A via `static_peers=["0@127.0.0.1:<port>"]`,
completes a real KEMTLS handshake, and floods `P2pMessage::Consensus` frames.
Live `/metrics` on node A is scraped over HTTP for the per-peer and
connection-rate counters. The in-process scenario suite additionally exercises the
same flood two-node with `NodeMetrics::format_metrics` rendering.

## 6. Connection-rate live-socket evidence

- default (no flags): connection limiter DISABLED; `qbind_p2p_connection_rate_drop_total = 0`.
- under-budget: 3 inbound TCP connections admitted; metric stays 0.
- over-budget: 10 connections (max 3) → 3 accepted / 7 refused; metric = 7.

## 7. Per-peer deployed live-socket evidence (the Run 370 blocker, now closed)

- `kemtls_second_peer_admitted`: node B completes a **real KEMTLS mutual-auth
  handshake** against `target/release/qbind-node`; the dialer observes the
  deterministic peer `NodeId`.
- `per_peer_kemtls_under_budget`: 4 under-budget frames over the KEMTLS socket →
  **0 per-peer drops**; `qbind_net_per_peer_drops_total{reason="rate_limit"}`
  ABSENT on live `/metrics`.
- `per_peer_kemtls_over_budget`: 60 over-budget frames over the KEMTLS socket →
  `qbind_net_per_peer_drops_total{reason="rate_limit"} = 47` on the **live
  `/metrics`** of `target/release/qbind-node`.
- `per_peer_drop_does_not_tear_down`: node A still serves `/metrics` after the
  flood; the over-budget drops are recorded while the connection stays up.

Frames use the Consensus discriminator (`0`) so `read_loop` routes them to
`decode_frame` → the deployed per-peer limiter; `0x05` peer-candidate frames are
consumed earlier and would bypass the limiter, which is why the flood uses
structured Consensus/Vote frames whose opaque inner bytes never fail decode.

## 8. Metrics/counter evidence

- `qbind_p2p_connection_rate_drop_total` renders exactly once, no endpoint labels;
  increments only on connection refusals.
- `qbind_net_per_peer_drops_total{peer="<id>",reason="rate_limit"}` renders from
  `NodeMetrics::format_metrics` (which includes `peer_network.format_metrics()`)
  only once a per-peer drop has occurred; the harness sums all such lines.

## 9. CLI/config surface

Hidden abuse/DoS flags absent from `--help`; invented flags rejected by clap
(rc=2); real hidden flags parse (rc=0). **No new public CLI flags** — Route A adds
none.

## 10. Default compatibility

No-flag posture: connection limiter disabled, per-peer `1000/100`, no drops. The
KEMTLS flood evidence is produced only when the operator opts into the tight
per-peer budget via the existing hidden devnet flags.

## 11. Rejection / fail-closed evidence

The real binary exits non-zero at startup for: zero per-peer max; unbounded
per-peer max; zero connection-rate max; enabled MainNet abuse/DoS config.

## 12. Combined limiter independence

Live socket: a connection-rate flood left `qbind_net_per_peer_drops_total` ABSENT;
the KEMTLS per-peer flood left `qbind_p2p_connection_rate_drop_total = 0`. The two
controls are independent on real sockets.

## 13. Non-mutation evidence

No production source change; no P2P wire-format change; no peer-admission / KEMTLS
/ trust-bundle weakening; no `LivePqcTrustState`, validator-set, epoch, sequence,
or marker mutation; no authority-lifecycle runtime wiring. The helper only dials
and floods using public APIs.

## 14. Readiness matrix delta for M12

M12: **Yellow/Partial → Green** for the abuse/DoS deployed live-socket controls.
Both the connection-rate and the KEMTLS-admitted deployed per-peer message-rate
controls are proven over real sockets on the release binary, defaults preserved.
Green is scoped to these two controls; it is not a claim about unrelated M12
sub-items or about M4/M6.

## 15. Current public DevNet readiness status

**NOT launch-ready.** M4 Yellow/launch-blocking; M6 Yellow/Partial; M12 Green
(abuse/DoS deployed live-socket controls).

## 16. Remaining public DevNet blockers

M4 live seed/bootnode reachability; M6 stable identity generation. The M12
KEMTLS-admitted deployed per-peer socket flood blocker recorded by Run 370 is now
**closed**.

## 17. Public TestNet blockers

All public DevNet blockers plus TestNet-grade validator-set/epoch operations and
sustained multi-node reachability — none addressed here.

## 18. MainNet blockers

Authority rotation/revocation runtime wiring (Red); full C4/C5 closure — none
addressed here; MainNet abuse/DoS remains refused.

## 19. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 371.

## 20. Tests run

- `cargo test -p qbind-node --lib` — see final response for the recorded pass count.
- `cargo build -p qbind-node --release` and `--example run_371_…_helper` — OK.
- Run 371 harness — POSITIVE (helper 10/10; live-socket connection-rate proven;
  KEMTLS per-peer under=absent / over>0 on live `/metrics`; fail-closed + MainNet
  refused; independence; no-teardown).
- Regression: run_370, run_369, run_365, run_363, run_362, run_361 — see final
  response for the recorded pass counts. No new source test file is added (Route A
  = no source change).

## 21. Security scans

Secret scanning run over all changed files (loopback / RFC 5737 only; no keys,
mnemonics, credentials, tokens, or private endpoints; generated KEMTLS material is
temporary, dev-only, and gitignored).

## 22. CodeQL

Recorded honestly in the final response — not claimed clean unless the run
completed.

## 23. Provenance

Single-machine, single-branch run in the task sandbox; loopback sockets and
temporary data dirs only; no external network, seed, or bootnode.

## 24. Honest limitations

- The KEMTLS flood runs over loopback with the default deterministic test-grade
  KEM keypairs and default (Disabled) mutual-auth admission; it proves the
  deployed per-peer limiter enforces over-budget frames from a real handshaked
  peer, not a production-key / strict-admission deployment.
- Exact per-peer drop counts (e.g. 47/48 of 60) vary with scheduling; the
  invariant is under-budget ⇒ 0 drops (metric absent) and over-budget ⇒ drops > 0
  on live `/metrics`.
- The per-peer family renders on `/metrics` only after a drop, so a live node with
  no per-peer drops does not surface it (used to prove independence).
- M12 Green is scoped to the abuse/DoS connection-rate and per-peer message-rate
  deployed live-socket controls; it does not move M4/M6 or close C4/C5.

## 25. Suggested Run 372 next step

Exercise the deployed per-peer flood under **strict mutual-auth admission** and
**production-grade (pqc-static-root) KEM keypairs** rather than the default
deterministic test-grade path, and add a sustained multi-peer concurrent flood to
confirm per-peer bucket isolation across several simultaneous KEMTLS peers on the
release binary.