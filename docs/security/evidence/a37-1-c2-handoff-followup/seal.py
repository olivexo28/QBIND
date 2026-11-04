#!/usr/bin/env python3
"""Generate/check non-circular complete follow-up identities."""
import hashlib
from pathlib import Path
import subprocess
import sys

ENTRY = "551e7cdd08eb01ce05914c4bba49562d8901b7ec"
E = Path("docs/security/evidence/a37-1-c2-handoff-followup")
MANIFEST, SUMS = E/"MANIFEST.tsv", E/"SHA256SUMS"
CHECK = sys.argv[1:] == ["--check"]
assert not sys.argv[1:] or CHECK


def git(*args):
    return subprocess.check_output(["git", *args]).decode().strip()


paths = set(git("diff", "--name-only", ENTRY).splitlines())
paths.update(git("ls-files", "--others", "--exclude-standard").splitlines())
paths.update([str(MANIFEST), str(SUMS)])
rows = ["# Base: "+ENTRY, "# Self-artifact identities are supplied as two final handoff entries.",
        "status\told_mode\told_blob\tnew_mode\tnew_blob\tpath"]
for path in sorted(paths - {str(MANIFEST), str(SUMS)}):
    assert path in ("scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh",
                    "docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md") or path.startswith(str(E)+"/")
    p = Path(path)
    assert p.is_file() and not p.is_symlink()
    old = git("ls-tree", ENTRY, "--", path)
    if old:
        old_mode, kind, old_blob = old.split("\t", 1)[0].split()
        assert kind == "blob"
        status = "M"
    else:
        old_mode, old_blob, status = "000000", "0"*40, "A"
    mode = "100755" if p.stat().st_mode & 0o111 else "100644"
    if old:
        assert old_mode == mode
    rows.append("\t".join([status, old_mode, old_blob, mode, git("hash-object", "--", path), path]))
manifest = ("\n".join(rows)+"\n").encode()
if CHECK:
    assert MANIFEST.read_bytes() == manifest
else:
    MANIFEST.write_bytes(manifest)
sums = "".join(hashlib.sha256(Path(p).read_bytes()).hexdigest()+"  "+p+"\n"
               for p in sorted(paths - {str(SUMS)})).encode()
if CHECK:
    assert SUMS.read_bytes() == sums
else:
    SUMS.write_bytes(sums)
print("PASS:", len(paths), "changed paths;", len(paths)-2, "manifest rows plus two handoff entries;",
      len(paths)-1, "checksums")
