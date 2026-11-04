# A21-F1 test and evidence review artifacts

These archives preserve original and corrective A21-F1 evidence as separate,
byte-identified collections. Archive membership was inspected without
executing contents; each archive's embedded manifest was checked against
every listed member's bytes and SHA-256.

| Archive | Bytes | SHA-256 | Included manifest | Manifest SHA-256 |
|---|---:|---|---|---|
| [`a21-f1-original-evidence.tar.gz`](a21-f1-original-evidence.tar.gz) | 17,251 | `5b1356c1d731caf1cbe3d2a05faa23c433de275591f770d6e736098b1293fa76` | `AUTHORITATIVE-MANIFEST.txt` | `942f0041fd609d044b66db0be7581e4f096517b70abed2aa3069e00997658e3a` |
| [`a21-f1-corrective-evidence.tar.gz`](a21-f1-corrective-evidence.tar.gz) | 73,138 | `437d11defd1a8017f9b04f2da58b62e3f1d5b563fbc37f4dd52282384153d1cd` | `MANIFEST.txt` | `42d05cf978609726db91485e8df8787769e118a454fc72263e166d9503f102b3` |

The original implementation and test revision is
[`9bc10bb0313505697ce7a4e46e4612edec7e9814`](https://github.com/olivexo28/QBIND/commit/9bc10bb0313505697ce7a4e46e4612edec7e9814).
The authoritative corrective test revision is
[`2007126aec85dcd4b470e18d08bbed01ff67a942`](https://github.com/olivexo28/QBIND/commit/2007126aec85dcd4b470e18d08bbed01ff67a942).

The original archive contains the prior implementation/test evidence and its
original manifest. The corrective archive contains the authoritative
corrective run, revised modest baseline controls using the exact test overlay,
an earlier corrective run, and explicitly non-authoritative development
evidence. The archive's README and manifest distinguish those phases; an
earlier run is not recast as the authoritative run.

The supplied independent ChatGPT review stated: “At revision
8497c7b52bbb483675ebd9be480b694f40d160bd, source review found the three
requested code/test corrections resolved: shared real-validator negatives,
missing matrix cases, and bounded child cleanup. The production decoder was
unchanged. The reviewer did not rerun Rust tests or inspect the undelivered
raw archives. Independent raw-evidence verification remains pending.”
This is the review statement conveyed with the task, not a signed review,
timestamp, transcript URL, or review of these newly delivered archives.

Archiving and delivering these bytes does not independently validate test
outcomes, confirm interpretations of the records, or establish release
readiness. Independent raw-evidence inspection remains pending. A21-F1
remains OPEN; implementation remains IMPLEMENTED — VERIFICATION PENDING.
OBL-PAR-1/E12/E13 remain open, activation remains DISABLED, and public
DevNet remains NO-GO.
