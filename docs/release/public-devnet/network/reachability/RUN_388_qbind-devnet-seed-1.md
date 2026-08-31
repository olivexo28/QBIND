# Run 388 — Reachability Evidence: `qbind-devnet-seed-1` (EXTERNAL EXECUTION)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim. **DevNet only.**
>
> **Verdict: Route C — no safe external seed infrastructure available.** Run 388
> executes the **Route A** objective (stand up or validate a real externally
> reachable seed and prove reachability from an independent off-host vantage
> point) but the sandboxed CI environment has **no external ingress and no
> independent off-host vantage point**. Exposing a real endpoint is therefore not
> possible here. **External reachability from outside the seed operator's own
> host/NAT was NOT proven.** **M4 stays Yellow.** This document records the
> execution honestly and lists the infrastructure prerequisites that a real
> operator must satisfy to obtain M4 Green. This finding is unchanged from
> Run 378; Run 386/387 preflight posture (`signed_release=false`,
> `slsa_grade=false`) is likewise unchanged.

This is the reachability evidence record referenced by the Run 388 external-seed
reachability execution. It captures the bounded probe that IS reproducible in this
environment (loopback / same-host, continuity with Run 377/378) and states
honestly what was and was not proven for the **external** step required by
M4 Green.

## 1. Timestamp (UTC)

`2026-08-31T17:44:01Z` (recorded by the Run 388 harness at probe time; the value
is regenerated on every harness run — see
`scripts/devnet/run_388_public_devnet_m4_external_seed_reachability.sh`).

## 2. Seed identity — seed id / node_id / peer_id / environment / genesis

- Seed id: `qbind-devnet-seed-1` (preflight operator handle).
- Preflight candidate `node_id` (committed, illustrative):
  `4111c4be4715f26d8cf6f9d3764f2ff7779bd431036ece77d28f47567945f688`
  (a real public identifier from the Run 375 `qbind-node identity generate
  devnet seed` path; its secret material was generated ephemerally and
  discarded).
- Candidate `peer_id`:
  `4111c4be4715f26d8cf6f9d3764f2ff7779bd431036ece77d28f47567945f688`.
- `environment`: `devnet`.
- Expected genesis hash (Run 356):
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`
  (genesis-file SHA-256
  `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`).
- The loopback listener booted by the harness uses the node's **default**
  identity, logged as `NodeId(<8-byte prefix>)`; it is **not** the committed
  candidate identity, because Run 388 does not provision a durable operator seed
  identity and — critically — does **not** expose a real externally reachable
  endpoint. This remains a preflight of the **listener path**, not a live seed
  under the candidate identity.

## 3. Source vantage identity / independence proof

The **same host** as the seed listener — the Run 388 harness process on the
sandboxed CI runner (`127.0.0.1`). **No independent off-host vantage point is
available in this environment.** No independent second host, no cloud VM in a
different network, no residential/mobile vantage, and no public egress-to-ingress
path exists to dial a real endpoint from outside the operator's own host/NAT.
Independence proof is therefore **NOT AVAILABLE**; the only demonstrable path is
same-host loopback, which is by definition non-independent.

## 4. Public endpoint host/IP and port + ownership/operator note

`127.0.0.1:<ephemeral>` (an OS-assigned loopback port chosen at run time). The
committed candidate documents a non-routable RFC 5737 TEST-NET-3 host
(`203.0.113.10:30333`) that is **not** dialed and is **not** externally
reachable. No real public host/port is exposed by Run 388. Operator note: the
committed `operator` handle `qbind-devnet-seed-1-preflight` is a placeholder; no
publish-safe real endpoint ownership can be recorded because no real endpoint
exists.

## 5. Target listener command / binary SHA-256 / BuildID / build_info

- Target listener command (loopback preflight):
  `target/release/qbind-node --network-mode p2p --enable-p2p
  --p2p-listen-addr 127.0.0.1:<port> --validator-id 0 --data-dir <tmp>`.
- Target `qbind-node` binary SHA-256 / BuildID / toolchain: captured by the
  harness at run time and archived (publish-safe) in
  `docs/devnet/run_388_public_devnet_m4_external_seed_reachability/summary.txt`.
- `qbind_node_build_info`: metrics are opt-in
  (`QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>`, loopback-only) and not enabled in
  this run; no metrics dump is committed.

## 6. Route type

**unknown → recorded as Route C (no external infrastructure).** The only probe
that succeeds is **loopback / same-host**, which is explicitly **not** an external
route. Run 388 does not claim `external` or `same-cloud-external`.

## 7. TCP dial result

**ACCEPTED (loopback / same-host only).** A same-host TCP `connect()` to the
loopback P2P listener succeeded and the release `qbind-node` logged
`[P2P] Accepted connection from 127.0.0.1:<client-port>`. **No external TCP dial
was performed**, because no externally reachable endpoint exists in this
environment. The external TCP-dial requirement of M4 Green is therefore **NOT
satisfied**.

## 8. KEMTLS / static-root handshake result + root/leaf fingerprints

**Not performed against an external endpoint.** The standing in-process /
cross-process KEMTLS strict-auth + `PqcStaticRoot` evidence is Run 371–373 and the
loopback strict-auth **boot admission** evidence is Run 374/375; none prove
external reachability. The preferred external KEMTLS static-root handshake requires
a real externally reachable seed and an independent off-host vantage point,
neither of which is available here. KEMTLS/static-root mode for the intended live
seed is `kemtls-mutual-auth-required` / `pqc-static-root`; no external root or leaf
certificate fingerprint was captured because no external handshake occurred.

## 9. Observed remote NodeId / cert-derived identity

The listener logs its own `NodeId(<prefix>)` on bind and on accept. Deterministic
NodeId re-derivation from a leaf cert is separately proven by
`qbind-node identity register-check --cert <leaf.cert.bin>` (Run 376), which
Run 388 also exercises on the live admission path. Because no external observer
exists, **no externally observed remote NodeId / cert-derived identity** was
captured; the M4 Green rule that the observed remote identity matches the
published entry is therefore **NOT satisfied**.

## 10. Exact command(s) used / verifier command(s)

```bash
# boot a real release P2P listener on loopback (pre-existing default posture)
target/release/qbind-node --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:<port> --validator-id 0 --data-dir <tmp>

# same-host TCP dial (from the harness) — the ONLY reachable path in this env
python3 -c "import socket; socket.create_connection(('127.0.0.1', <port>), timeout=5)"

# live-admission verifier (structural admission decision, not a reachability proof)
target/release/qbind-node identity register-check <public-identity.json> \
    --seed-list docs/release/public-devnet/network/devnet-seeds.live-candidate.json \
    --role seed --cert <leaf.cert.bin> \
    --status live --reachability-evidence \
    docs/release/public-devnet/network/reachability/RUN_388_qbind-devnet-seed-1.md

# the EXTERNAL step that CANNOT run here (documented for a real operator):
#   from an independent off-host host, outside the seed's NAT:
#   nc -vz <public-host> <public-port>            # external TCP dial
#   qbind-node --network-mode p2p --enable-p2p \  # external KEMTLS static-root join
#     --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
#     --p2p-peer <node_id>@<public-host>:<public-port> ...
```

Both loopback commands are driven deterministically by
`scripts/devnet/run_388_public_devnet_m4_external_seed_reachability.sh`. The
external commands are illustrative prerequisites, not executed in this
environment.

## 11. Logs (secrets redacted)

```
[P2P] Listening on 127.0.0.1:<port> (node_id=NodeId(<prefix>))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(<prefix>) num_validators=1 mutual_auth=Disabled
[binary] P2P transport up. Listen address: 127.0.0.1:<port>, static peers: 0
[P2P] Accepted connection from 127.0.0.1:<client-port>
```

No private key, root signing key, KEM secret key, or credential appears in the
logs; the node data dir and identity material are temporary and removed on exit.

## 12. Firewall / NAT / LB details

**None — no endpoint is exposed.** Run 388 opens no externally reachable port,
configures no port-forward, no NAT rule, no load balancer, and no security-group
ingress. Documenting a reproducible external path would require exposing a real
endpoint, which Route C explicitly declines to do in this environment.

## 13. Redaction statement

Only publish-safe values are recorded: the public `node_id`/`peer_id`, loopback
addresses, RFC 5737 documentation host, release-binary SHA-256/BuildID/toolchain,
and OK/REFUSED/NOT_PROVEN status lines. No secret key, ML-DSA root signing key,
KEM secret key, mnemonic, seed phrase, credential, token, raw log, raw metrics
dump, data directory, private endpoint, private hostname, or absolute build path
is committed.

## 14. Conclusion

- `external_tcp_reachability=false`
- `external_kemtls_reachability=false`
- `live_reachability_claim=false`
- `m4_green_claim=false`

**External reachability NOT proven; Route C.** Loopback / same-host reachability
of the deployed `qbind-node` P2P listener path IS demonstrated (continuity with
Run 377/378), but M4 Green requires reachability proven from **outside** the seed
operator's own host/NAT with at minimum an external TCP dial and preferably an
external KEMTLS static-root handshake. None of those external conditions can be
met in this sandboxed environment, so **M4 remains Yellow**. The committed
candidate is kept at `status: planned` with `last_reachability_evidence: null`; it
is **not** marked live.

## 15. Infrastructure prerequisites to obtain M4 Green (Route A)

A real operator, on real infrastructure, must:

1. **Durable operator seed identity.** Generate via `qbind-node identity generate
   devnet seed`; keep the ML-KEM leaf secret and ML-DSA root material private and
   never committed. Publish only the public `node_id` / `peer_id`.
2. **Real public endpoint.** Deploy the seed on a host with a routable public IP
   (or a DNS name resolving to one) and open exactly the P2P port through the
   host firewall / cloud security group / NAT port-forward.
3. **KEMTLS static-root listener.** Boot the seed under
   `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with the
   published trust bundle, so joiners perform strict-auth against a pinned root.
4. **Independent off-host vantage point.** Use a genuinely separate network
   (different host, outside the seed's NAT — e.g. a different cloud provider or a
   residential/mobile connection) to dial the public endpoint. Same-host,
   same-VPC, same-cloud-internal, same-NAT, or VPN-only reachability is
   **insufficient** (that would be Route B, and M4 stays Yellow).
5. **Capture external evidence.** Record a timestamped external TCP dial and,
   preferably, an external KEMTLS static-root handshake; capture the observed
   remote NodeId / cert-derived identity and confirm it matches the published seed
   entry.
6. **Pin genesis.** Confirm the joining client pins the Run 356 genesis hash and
   genesis-file SHA-256 already recorded in the seed-list document.
7. **Promote and verify.** Set the entry's `p2p_host` / `p2p_multiaddr` /
   `operator` to the real public values, set `status: live`, set
   `last_reachability_evidence` to this (or a successor) evidence reference, and
   confirm admission with
   `qbind-node identity register-check … --status live --reachability-evidence
   <ref>`.
8. **Only then** may **M4** move Yellow → Green, and only if all other M4 Green
   rules (no private material, schema validity, safety labels, no other readiness
   item silently marked Green) hold.
