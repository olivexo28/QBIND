# Run 377 — Reachability Evidence: `qbind-devnet-seed-1` (PREFLIGHT)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim. **DevNet only.**
>
> **Verdict: Partial-positive (Route B).** Only **loopback / same-host**
> reachability was demonstrated. **External reachability from outside the seed
> operator's own host/NAT was NOT proven.** **M4 stays Yellow.** This document is
> a preflight reachability record, **not** a live-seed reachability proof.

This is the reachability evidence record referenced by the Run 377 preflight
live-seed candidate
(`docs/release/public-devnet/network/devnet-seeds.live-candidate.json`). It
captures the exact bounded reachability probe performed in Run 377 and states
honestly what was and was not proven.

## 1. Timestamp (UTC)

`2026-08-26T15:00:05Z` (recorded by the Run 377 harness at TCP-dial time; the
value is regenerated on every harness run — see
`scripts/devnet/run_377_public_devnet_live_seed_reachability.sh`).

## 2. Seed identity hash / node_id

- Preflight candidate `node_id` (committed, illustrative):
  `4111c4be4715f26d8cf6f9d3764f2ff7779bd431036ece77d28f47567945f688`
  (a real public identifier from the Run 375 `qbind-node identity generate
  devnet seed` path; its secret material was generated ephemerally and
  discarded).
- The loopback listener booted by the harness uses the node's **default**
  identity, logged as `NodeId(<8-byte prefix>)` (e.g. `NodeId(4bd96f97b1aaec9d)`);
  it is **not** the committed candidate identity, because Run 377 does not
  provision a durable operator seed identity. This is a preflight of the
  **listener path**, not a live seed under the candidate identity.

## 3. Source vantage point

The **same host** as the seed listener — the Run 377 harness process on the
sandboxed CI runner (`127.0.0.1`). **No external vantage point is available in
this environment.**

## 4. Target host/port

`127.0.0.1:<ephemeral>` (an OS-assigned loopback port chosen at run time, e.g.
`127.0.0.1:56661`). The committed candidate documents a non-routable RFC 5737
TEST-NET-3 host (`203.0.113.10:30333`) that is **not** dialed and is **not**
externally reachable.

## 5. Route type

**loopback / same-host.** Not `external`, not `same-cloud-external`.

## 6. TCP dial result

**ACCEPTED.** A same-host TCP `connect()` to the loopback P2P listener
succeeded; the release `qbind-node` logged `[P2P] Accepted connection from
127.0.0.1:<client-port>`. The listener was started with the pre-existing default
posture via `--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`
(`ss -ltnp` confirms `qbind-node` owns the listening socket).

## 7. KEMTLS strict-auth handshake result

**Not completed in this run.** The loopback preflight demonstrates TCP-level
reachability of the deployed listener only. A full KEMTLS strict-auth
(`--p2p-mutual-auth required` + `--p2p-pqc-root-mode pqc-static-root`) cross-host
handshake against an **externally reachable** seed is the Route A step that
remains outstanding. The standing in-process / cross-process strict-auth +
static-root evidence is Run 371–373; the standing loopback strict-auth **boot
admission** evidence is Run 374/375. None of those prove external reachability.

## 8. Observed remote NodeId / cert-derived identity

The listener logs its own `NodeId(<prefix>)` on bind and on accept. Deterministic
NodeId re-derivation from a leaf cert is separately proven by
`qbind-node identity register-check --cert <leaf.cert.bin>` (Run 376), which
Run 377 also exercises on the live admission path (see §11 of the canonical
evidence).

## 9. Metrics endpoint evidence

Not enabled in this preflight. The node's `/metrics` endpoint is opt-in
(`QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>`) and, when used, is bound to
localhost only. No metrics dump with private endpoints is committed.

## 10. Exact command used

```bash
# boot a real release P2P listener on loopback (pre-existing default posture)
target/release/qbind-node --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:<port> --validator-id 0 --data-dir <tmp>

# same-host TCP dial (from the harness)
python3 -c "import socket; socket.create_connection(('127.0.0.1', <port>), timeout=5)"
```

Both are driven deterministically by
`scripts/devnet/run_377_public_devnet_live_seed_reachability.sh`.

## 11. Logs (secrets redacted)

```
[P2P] Listening on 127.0.0.1:<port> (node_id=NodeId(<prefix>))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(<prefix>) num_validators=1 mutual_auth=Disabled
[binary] P2P transport up. Listen address: 127.0.0.1:<port>, static peers: 0
[P2P] Accepted connection from 127.0.0.1:<client-port>
```

No private key, root signing key, KEM secret key, or credential appears in the
logs; the node data dir and identity material are temporary and removed on exit.

## 12. Conclusion

**External reachability NOT proven.** Loopback / same-host reachability of the
deployed `qbind-node` P2P listener path IS demonstrated. Because M4 Green
requires reachability proven from **outside** the seed operator's own host/NAT
(and, preferably, a KEMTLS strict-auth handshake from that external vantage
point), **M4 remains Yellow**. The committed candidate is therefore kept at
`status: planned` with `last_reachability_evidence: null`; it is **not** marked
live.

## 13. What is required to promote this to a live entry (Route A)

1. Provision a durable operator seed identity via `qbind-node identity generate
   devnet seed` (keep the KEM secret / root material private, never committed).
2. Deploy that seed as an **externally reachable** KEMTLS static-root listener on
   a real public host/port.
3. From a genuinely external vantage point (different host, outside the seed's
   NAT), perform at minimum a TCP dial and preferably a KEMTLS strict-auth
   handshake; capture the timestamped result.
4. Record that result here (or in a sibling `RUN_<n>_<seed-id>.md`) and set the
   candidate's `last_reachability_evidence` to that reference.
5. Set the entry's `status` to `live` and run
   `qbind-node identity register-check … --status live --reachability-evidence
   <ref>` to confirm admission.
6. Only then may **M4** move Yellow → Green, and only if all other M4 Green rules
   (genesis pinning, no private material, schema validity, safety labels) hold.
