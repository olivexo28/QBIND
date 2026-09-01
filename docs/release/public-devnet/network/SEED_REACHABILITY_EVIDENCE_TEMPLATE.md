# QBIND Public DevNet — Seed Reachability Evidence Template (Run 392)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim. **DevNet only.**
>
> This is the canonical **format** for a per-seed reachability evidence record. It is a **template**:
> filling it in does not by itself move M4 Green — the recorded results must show real external
> off-host reachability. This template contains **no** live seed, **no** real endpoint, and makes
> **no** reachability/M4/C4/C5 claim. Existing records that follow this shape:
> `reachability/RUN_377_qbind-devnet-seed-1.md`, `RUN_378…`, `RUN_388…`, `RUN_391…`.

Copy this file to `docs/release/public-devnet/network/reachability/RUN_<n>_<seed-id>.md` and fill in
every field with **publish-safe** values only. Redact all private material (see §16).

---

## 1. Run id

`Run <n>` — the run that produced this evidence.

## 2. UTC timestamp

`<YYYY-MM-DDThh:mm:ssZ>` — recorded at probe time.

## 3. Seed id

`<seed-id>` — the operator handle for this seed (e.g. `qbind-devnet-seed-1`).

## 4. node_id

`<node_id>` — the public node identifier (hex), as published in the seed-list entry.

## 5. peer_id

`<peer_id>` — the public peer identifier (hex).

## 6. Environment

`devnet` — must be DevNet; MainNet/TestNet material must never appear.

## 7. Expected genesis hash

`0x…` — must equal the Run 356 `genesis_hash`
(`0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`) and pair with genesis-file
SHA-256 `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.

## 8. Binary SHA-256

`<sha256>` — SHA-256 of the release `qbind-node` binary the seed runs.

## 9. ELF BuildID

`<build-id>` — the ELF BuildID of the release binary (provenance; see
`docs/release/public-devnet/binary/`).

## 10. Toolchain

`<rustc … / cargo …>` — the toolchain that built the binary.

## 11. Public host / port

`<public-host>:<port>` — the externally reachable host/port joiners dial. Must be routable (not
loopback, not RFC 1918 private, not RFC 5737 documentation).

## 12. Vantage identity and independence statement

`<vantage-identity>` plus an explicit statement that the vantage is **outside** the seed host and
**outside** the seed's NAT (different network / cloud provider / residential-mobile). State
explicitly that same-host, same-NAT, same-VPC, private-VPN-only, loopback, and RFC 5737 hosts were
**not** used as the vantage. If no independent off-host vantage exists, record **Route C** honestly
and set the conclusion claims to `false`.

## 13. TCP dial result

`<ACCEPTED | REFUSED | TIMEOUT>` from the external dial (e.g. `nc -vz <public-host> <port>`), with the
UTC timestamp. Note whether this was an **external** dial or only a loopback/same-host preflight
(Route B).

## 14. KEMTLS / static-root handshake result

`<COMPLETED | FAILED | NOT-PERFORMED>` for the external KEMTLS mutual-auth + PQC static-root handshake
(`--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root`), including the intended
transport-security mode (`kemtls-mutual-auth-required`). Record whether it was external or preflight.

## 15. Observed remote NodeId / cert-derived identity

`<observed-node-id>` — the remote identity observed by the external vantage, and confirmation that it
**matches** the published seed entry's `node_id`. If no external observer exists, record
**not captured** and keep the claims `false`.

## 16. Firewall / NAT / security-group summary

Publish-safe summary of the ingress path: which single P2P port is open, NAT/port-forward or cloud
security-group posture, and confirmation that no other service is publicly exposed for joining. Do
**not** include private management rules or secrets.

## 17. Redaction statement

State that only publish-safe values are recorded: public `node_id`/`peer_id`, routable public host,
release-binary SHA-256/BuildID/toolchain, and OK/REFUSED/NOT_PROVEN status lines. Confirm that **no**
secret key, ML-DSA root signing key, ML-KEM secret key, mnemonic, seed phrase, credential, token, raw
log, raw metrics dump, data directory, private endpoint, private hostname, or absolute build path is
committed.

## 18. Conclusion fields

Set each field truthfully; anything unproven must be `false`:

- `external_tcp_reachability=<true|false>`
- `external_kemtls_reachability=<true|false>`
- `live_reachability_claim=<true|false>`
- `m4_green_claim=<true|false>`
- `c4_c5_closure_claim=<true|false>`

A `live_reachability_claim=true` / `m4_green_claim=true` record is admissible **only** when
`external_tcp_reachability=true` (and preferably `external_kemtls_reachability=true`) with a genuine
independent off-host vantage (§12). `c4_c5_closure_claim` must always be `false` in a seed
reachability record — seed reachability never closes C4 or C5.
