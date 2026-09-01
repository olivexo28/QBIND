# Run 401 evidence archive — public DevNet M6 operator identity continuity package

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in this directory.

`summary.txt` is the tee'd output of
`scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh` and contains only publish-safe
values: the release-binary SHA-256, BuildID, toolchain, and the OK / POSITIVE status lines. **No secret
key, private material, generated identity, data dir, raw log, or raw metrics dump is committed.**

Regenerate locally with:

```bash
bash scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh
```

**Decision gate = Route B** (docs + verification harness; no production Rust source change). The Run 401
identity continuity package (`docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md`,
`ROTATION_REVOCATION_DEFERRAL.md`) documents how an external DevNet operator keeps a **durable operator
identity** across public DevNet restarts (reuse the same `leaf.kem.sk.bin` + `leaf.cert.bin` to preserve
`node_id`/`peer_id`), safe public/private material handling, exactly what may be reused, what must not be
rotated/edited by hand, and states that production key **rotation**/**revocation** is **NOT implemented**
and is **explicitly deferred** to C4/C5/MainNet. The harness verifies the docs against the **real**
first-class `qbind-node identity` (`generate`/`verify`/`print-public`/`seed-candidate`/`register-check`)
surfaces — building the release binary, confirming the commands are present in the identity usage,
deterministically re-deriving a `node_id` (durable reuse), and confirming MainNet/TestNet generation is
refused. It starts no node listener beyond the offline `identity` tooling, opens no externally reachable
port, deploys no seed/bootnode/faucet/RPC/explorer/status page, changes no wire format, weakens no peer
admission, and mutates no trust/validator/epoch/sequence/marker/LivePqcTrustState. No CLI flag is added.

**M6** stays **Yellow / Partial** (better documented; no live registration path — M4-gated — and
operator-supplied root reuse/rotation/revocation is C4/C5-OPEN). **M4** stays Yellow/launch-blocking,
**S5** and **S7** stay Yellow, **M12–M16** remain Green, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**. No M4 Green, no M6 Green, and no C4/C5 closure is claimed.

Canonical evidence record:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md`.
