# QBIND Public DevNet — Operator Onboarding Verification (Run 358)

> **Safety label (applies to every file in this directory):**
> **experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.**

These are the exact operator verification steps for the external onboarding package. All commands run
from the repository root. Only pre-existing repository tooling is used (the release binary,
`sha256sum`, `grep`, and Python 3); Run 358 adds **no** new dependency and **no** new CLI flag.

Paths used below:

- Operator docs: `docs/release/public-devnet/operator/{README,QUICKSTART,IDENTITY,SAFETY,VERIFY}.md`
- Run 356 genesis package: `docs/release/public-devnet/genesis/`
- Run 357 seed-list package: `docs/release/public-devnet/network/`

## 0. Build the binary once

```bash
cargo build -p qbind-node --release
# binary: ./target/release/qbind-node
```

## 1. Genesis verification (cross-check to Run 356)

Run the Run 356 genesis verification (see `docs/release/public-devnet/genesis/VERIFY.md`). Cross-check
that the quickstart references the same genesis hash the binary prints:

```bash
HASH=$(./target/release/qbind-node --env devnet \
  --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json \
  --print-genesis-hash 2>/dev/null)
echo "printed: $HASH"
grep -qF "$HASH" docs/release/public-devnet/operator/QUICKSTART.md \
  && echo "quickstart references printed genesis hash: OK"
# line-ending-tolerant file digest cross-check against the published SHA-256
python3 -c "import hashlib; b=open('docs/release/public-devnet/genesis/devnet-genesis.json','rb').read().replace(b'\r\n',b'\n'); h=hashlib.sha256(b).hexdigest(); assert h=='d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c', h; print('genesis file SHA-256 (LF-normalized) matches published:', h)"
grep -qF 'd1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c' docs/release/public-devnet/operator/QUICKSTART.md \
  && echo "quickstart references genesis SHA-256: OK"
```

Expected: printed hash `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`,
`quickstart references printed genesis hash: OK`,
`genesis file SHA-256 (LF-normalized) matches published: d1db07fe…5c86c`, and
`quickstart references genesis SHA-256: OK`. The `--print-genesis-hash` value is the authoritative,
line-ending-independent integrity gate.

## 2. Seed-list validation (cross-check to Run 357)

Run the Run 357 seed-list verification (see `docs/release/public-devnet/network/VERIFY.md`).
Cross-check that the quickstart points at the placeholder artifact and warns not to dial it:

```bash
python3 -c "import json; json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json')); print('placeholder valid json')"
grep -qF 'devnet-seeds.placeholder.json' docs/release/public-devnet/operator/QUICKSTART.md \
  && grep -qiE 'must not be dialed|must not be dialed|do .?not.? dial|not be dialed' docs/release/public-devnet/operator/QUICKSTART.md \
  && echo "quickstart references placeholder + warns not to dial: OK"
```

Expected: `placeholder valid json` and `quickstart references placeholder + warns not to dial: OK`.

## 3. `qbind-node --help` contains every flag referenced by the quickstart

Extract every `--flag` token from the quickstart and confirm each appears in `--help`:

```bash
./target/release/qbind-node --help 2>&1 | grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u > /tmp/help_flags.txt
# extract qbind-node flags from the quickstart, excluding the cargo build-tool flag --release
grep -oE '\-\-[a-z][a-z0-9-]*' docs/release/public-devnet/operator/QUICKSTART.md \
  | grep -vxF -- '--release' | sort -u > /tmp/quickstart_flags.txt
missing=$(comm -23 /tmp/quickstart_flags.txt /tmp/help_flags.txt)
if [ -z "$missing" ]; then echo "all quickstart qbind-node flags exist in --help: OK"; else echo "MISSING: $missing"; fi
```

Expected: `all quickstart qbind-node flags exist in --help: OK`. (`--release` is a `cargo build`
flag, not a `qbind-node` flag, and is excluded; every `qbind-node` flag referenced by the quickstart
is pre-existing in `crates/qbind-node/src/cli.rs` — Run 358 adds none.)

## 4. The placeholder seed list is not marked live

```bash
python3 -c "
import json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
assert all(n['status']!='live' for n in d['seed_nodes']), 'a live entry is present'
print('no seed entry is marked live: OK')
"
```

Expected: `no seed entry is marked live: OK`.

## 5. Every placeholder `p2p_host` is documentation-safe / non-live

The placeholder uses only RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 6761
(`.invalid`, `.example`, `example.com/net/org`) documentation values:

```bash
python3 -c "
import ipaddress, json
d=json.load(open('docs/release/public-devnet/network/devnet-seeds.placeholder.json'))
doc_nets=[ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24')]
doc_names=('.invalid','.example','example.com','example.net','example.org')
for n in d['seed_nodes']:
    h=n['p2p_host']
    try:
        ip=ipaddress.ip_address(h); ok=any(ip in net for net in doc_nets)
    except ValueError:
        ok=any(h.endswith(s) or h==s.lstrip('.') for s in doc_names)
    assert ok, f'host {h!r} is not a documentation-safe value'
print('all placeholder p2p_host values are documentation-safe / non-live: OK')
"
```

Expected: `all placeholder p2p_host values are documentation-safe / non-live: OK`.

## 6. No operator doc claims public DevNet is launch-ready

Each content doc must assert public DevNet is NOT launch-ready and must contain no positive
launch-ready claim. (`VERIFY.md` is the verification script and necessarily contains the literal
search term, so it is scanned for the negated assertion but excluded from the positive-claim scan.)

```bash
for f in README QUICKSTART IDENTITY SAFETY VERIFY; do
  grep -qiE 'NOT launch-ready|not[^.]{0,40}launch-ready' "docs/release/public-devnet/operator/$f.md" \
    || echo "MISSING not-launch-ready in $f.md"
done
# positive-claim scan over the four content docs (exclude the verifier VERIFY.md)
if grep -rniE 'launch-ready' \
      docs/release/public-devnet/operator/README.md \
      docs/release/public-devnet/operator/QUICKSTART.md \
      docs/release/public-devnet/operator/IDENTITY.md \
      docs/release/public-devnet/operator/SAFETY.md \
    | grep -viE "\b(not|no|never|n't)\b" ; then
  echo "FOUND launch-ready claim"; else echo "no launch-ready claim: OK"; fi
```

Expected: no `MISSING` lines, and `no launch-ready claim: OK`. (Every occurrence of "launch-ready"
in the content docs is negated — e.g. "NOT launch-ready".)

## 7. The safety label appears in every operator doc

```bash
LABEL='experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim'
for f in docs/release/public-devnet/operator/*.md; do
  grep -qF "$LABEL" "$f" && echo "label present: $f" || echo "label MISSING: $f"
done
```

Expected: `label present:` for all five operator docs; no `label MISSING`.

## 8. MainNet / TestNet are not modified by this run

Run 358 is docs/artifact-only under `docs/release/public-devnet/operator/` and `docs/devnet/`, plus
narrow readiness/protocol doc updates. It creates or modifies **no** TestNet or MainNet genesis, seed
list, custody, or authority artifact:

```bash
# operator docs are DevNet-scoped: every qbind-node invocation uses --env devnet only
grep -roE '\-\-env [a-z]+' docs/release/public-devnet/operator/*.md | sort -u
# expected: only "--env devnet"
grep -rniE 'testnet[^.]{0,20}(ready|launch)|mainnet[^.]{0,20}(ready|launch|enable)' \
  docs/release/public-devnet/operator/*.md \
  | grep -viE 'not|separate future|remains? red|no mainnet readiness' \
  && echo "FOUND testnet/mainnet readiness claim" || echo "no testnet/mainnet readiness claim: OK"
```

Expected: the only `--env` value is `devnet`, and `no testnet/mainnet readiness claim: OK`.