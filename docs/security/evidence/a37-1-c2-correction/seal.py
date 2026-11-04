#!/usr/bin/env python3
"""Generate or check the non-circular changed-file manifest and checksums."""
import hashlib
from pathlib import Path
import subprocess
import sys

ENTRY = "6fdc0f0dcfc45c65037de3e53215121f5332689a"
BASE = Path("docs/security/evidence/a37-1-c2-correction")
MANIFEST = BASE / "MANIFEST.tsv"
SUMS = BASE / "SHA256SUMS"
CHECK = sys.argv[1:] == ["--check"]
assert not sys.argv[1:] or CHECK, "usage: python3 seal.py [--check]"


def git(*args):
    return subprocess.check_output(["git", *args]).decode().strip()


paths = set(git("diff", "--name-only", ENTRY).splitlines())
paths.update(git("ls-files", "--others", "--exclude-standard").splitlines())
paths.update([str(MANIFEST), str(SUMS)])
rows = [
    "# Base: " + ENTRY,
    "# MANIFEST.tsv and SHA256SUMS final entries are in the delivery handoff (no circular hashing).",
    "status\told_mode\told_blob\tnew_mode\tnew_blob\tpath",
]
for path in sorted(paths - {str(MANIFEST), str(SUMS)}):
    p = Path(path)
    assert p.is_file() and not p.is_symlink(), path
    old = git("ls-tree", ENTRY, "--", path)
    if old:
        old_mode, kind, old_blob = old.split("\t", 1)[0].split()
        assert kind == "blob"
        status = "M"
    else:
        old_mode, old_blob, status = "000000", "0" * 40, "A"
    mode = "100755" if p.stat().st_mode & 0o111 else "100644"
    if old:
        assert mode == old_mode, path
    rows.append("\t".join([status, old_mode, old_blob, mode, git("hash-object", "--", path), path]))
manifest = ("\n".join(rows) + "\n").encode()
if CHECK:
    assert MANIFEST.read_bytes() == manifest, "changed-path manifest mismatch"
else:
    MANIFEST.write_bytes(manifest)
sums = "".join(
    hashlib.sha256(Path(path).read_bytes()).hexdigest() + "  " + path + "\n"
    for path in sorted(paths - {str(SUMS)})
).encode()
if CHECK:
    assert SUMS.read_bytes() == sums, "changed-file checksum mismatch"
else:
    SUMS.write_bytes(sums)
print("PASS:", len(paths), "changed paths;", len(rows)-3, "manifest rows plus two handoff entries;",
      len(paths)-1, "checksums")
