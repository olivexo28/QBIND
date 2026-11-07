"""Documentation/source integrity only; no Rust tests or builds."""

import hashlib
import re
import subprocess
from pathlib import Path

BASE = "1d5d12e85f7ad939b731e56bf929d20403d00d11"
MAIN = "9bf0eb43e4e3c601d02d3886d220b0abeb3a103e"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "authority-provenance-contract"
APPENDS = [Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md")] + [
    ROOT / name for name in ["README.md", "CHANGED_PATHS.txt", "commands.txt"]
]


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: four exact historical document byte prefixes")
preserved = [
    Path(path) for path in git("ls-tree", "-r", "--name-only", BASE, str(ROOT), "Audit").decode().splitlines()
    if Path(path) not in APPENDS
]
for path in preserved:
    assert path.read_bytes() == blob(BASE, path), path
print(f"PASS: {len(preserved)} prior evidence/Audit files byte-identical")
assert hashlib.sha256(Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md").read_bytes()).hexdigest() == "6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9"
producers = [
    ("SHA256SUMS", "61028eb6dbb91f0834a5235f20c935bb0ff5b549"),
    ("CORRECTION-SHA256SUMS", "8344e92412d37882ef059b6158ead1959b0fa165"),
    ("CONTRACT-SHA256SUMS", "a4620f1e9363fbd30b23f06448e8f19174de8192"),
    ("AP1-CORRECTION-SHA256SUMS", "c12b46497a404171ca41c640f614f0c308ae514b"),
    ("WITNESS-SHA256SUMS", "e893d0bf7359deb87998ff67e63fbd92aabffd91"),
    ("BINDING-SHA256SUMS", "6ba38e9fa66f216e45906b3eb0575d67aa0cd071"),
    ("OPTIONS-SHA256SUMS", "0a405c6063d49d8b0d0a4211d091f5405d79b6a6"),
    ("TEST-PLAN-CORRECTION-SHA256SUMS", "3725ff080830df60e274fdaa080e390ccdbcc827"),
    ("STRUCTURAL-CONTROL-SHA256SUMS", "4ab46f22a66afdfae2363da7da3e493f56155451"),
    ("binding-sensitivity-execution/SHA256SUMS", "4162a9c20b2686f6a4d662e7e487eb536073e37a"),
    ("content-binding-experiment/SHA256SUMS", "e531a7c5a96b978cd1b82b006396c08b24e0933e"),
    ("authority-context-experiment/SHA256SUMS", BASE),
]
total = 0
for name, revision in producers:
    entries = blob(revision, ROOT / name).decode().splitlines()
    for entry in entries:
        digest, path = entry.split("  ", 1)
        assert hashlib.sha256(blob(revision, path)).hexdigest() == digest, (name, path)
    total += len(entries)
    print(f"PASS: {name}: {len(entries)} entries at producer {revision}")
assert total == 198
print("PASS: twelve producer manifests /198 entries, separate from current appended hashes; audit unchanged")

changed = set(git("diff", "--name-only", BASE).decode().splitlines())
untracked = set(git("ls-files", "--others", "--exclude-standard").decode().splitlines())
for path in changed | untracked:
    assert Path(path) in APPENDS or path.startswith(str(HERE) + "/"), path
assert not git("diff", "--name-only", BASE, "--", "crates", "Cargo.toml", "Cargo.lock", ".cargo", ".github", "Audit").strip()
print("PASS: documentation-only scope; production/test/Cargo/config/audit unchanged")

document = (HERE / "README.md").read_text()
links = re.findall(r"https://github\.com/olivexo28/QBIND/blob/([0-9a-f]{40})/([^\s)#]+)#L(\d+)-L(\d+)", document)
assert len(links) >= 30
for revision, path, first, last in links:
    assert revision in [MAIN, BASE]
    lines = blob(revision, path).decode().splitlines()
    assert 1 <= int(first) <= int(last) <= len(lines), path
    if path.startswith("crates/") and "/tests/" not in path:
        assert revision == MAIN, path
        assert Path(path).read_bytes() == blob(MAIN, path), path
    else:
        assert revision == BASE, path
    assert any(line.strip() for line in lines[int(first) - 1:int(last)])
print(f"PASS: {len(links)} exact pinned nonempty source/decision ranges; main production bytes equal pinned revision")
for path in [APPENDS[0], ROOT / "README.md"]:
    addition = path.read_bytes()[len(blob(BASE, path)):].decode()
    link = re.search(r"\]\(([^)]+authority-provenance-contract/README.md)\)", addition)
    if link is None:
        link = re.search(r"\]\((authority-provenance-contract/README.md)\)", addition)
    assert link and (path.parent / link.group(1)).is_file(), path
print("PASS: contract discoverable from append-only plan and index")

def contains(path, *tokens):
    text = blob(MAIN, path).decode()
    for token in tokens:
        assert token in text, (path, token)

contains("crates/qbind-node/src/main.rs", "if args.consensus_authority_from_genesis {",
         "genesis-authority activation is disabled", "proposal_vote_authority: None,",
         "verification_policy: ConsensusVerificationPolicy::Required,",
         "trusted_roots.push(r.clone());", "check_and_update_sequence(")
contains("crates/qbind-node/src/pqc_trust_bundle.rs", "MlDsa44Backend::verify(&key.pk_bytes, &preimage, &sig_bytes)",
         "BundleSignatureStatus::Verified", "signing_keys.lookup(&signing_id_bytes)")
contains("crates/qbind-node/src/genesis_consensus_authority.rs", "voting_power: 1,",
         "authorized_wire_chain_id: None,", "pub fn unavailable(", "observed.epoch != self.authorized_epoch")
contains("crates/qbind-node/src/pqc_boot_genesis.rs", "SkippedNoExternalGenesis", "load_external_genesis(path)?")
for token in ["FUTURE / NOT EXECUTED", "PASSED / CLOSED", "P1", "P2", "P0",
              "currentness", "Unknown", "Founder approval must never",
              "B/C remain unselected", "Activation remains DISABLED"]:
    assert token in document, token
matrix = document.split("## 7. Future acceptance matrix", 1)[1]
assert "**Every row below is FUTURE / NOT EXECUTED.**" in matrix
assert len([line for line in matrix.splitlines() if line.startswith("|")]) == 15
print("PASS: documented source distinctions, preserved bounded acceptances and13 FUTURE cases")
subprocess.run(["git", "diff", "--check"], check=True)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
print("PASS: documentation whitespace (no raw Rust outputs created)")
print("NO RUST TESTS/BUILDS EXECUTED; no production authority/currentness/application/signing/resume established")
