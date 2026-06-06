# QBIND Run 130–199 Authority Lifecycle Index

Static index of the Runs 130–199 authority-lifecycle evidence series,
introduced by Run 200 (docs/spec/crosscheck only). Each run has a
canonical evidence report at
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_NNN.md`; release-binary runs also
have an evidence archive at `docs/devnet/run_NNN_*/` (tracked files:
`README.md`, `summary.txt`, `.gitignore`; per-run generated artifacts are
gitignored). This index does not restate evidence; it locates it. Full
C4 remains OPEN; C5 remains OPEN.

## Phase map

| Runs | Phase |
|------|-------|
| 130–143 | v2 authority marker / v2 ratification / live `0x05` v2 validation + release-binary evidence |
| 144–158 | Peer-driven apply safety / staging / drain / DevNet+TestNet release-binary apply evidence |
| 159–162 | Authority signing-key lifecycle validator + marker integration + release-binary enforcement |
| 163–177 | Governance authority verifier / proof carrier / Required policy / validation-only + live `0x05` proof-carrying evidence |
| 178–187 | OnChainGovernance fixture verifier / production boundary / call-site wiring / payload / accepted-proof + fail-closed evidence |
| 188–193 | Authority custody boundary / metadata carrying / policy selector + release-binary custody-policy evidence |
| 194–199 | RemoteSigner boundary / payload carrying / policy selector + release-binary RemoteSigner policy evidence |

## Per-run index

| Run | Kind | Topic |
|-----|------|-------|
| 130 | source/test | v2 ratification schema + domain-separated digest + verifier |
| 131 | source/test | v2 authority marker extension + v1→v2 migration |
| 132 | source/test | v2 ratification wired into validation-only surfaces |
| 133 | release-binary | v2 validation-only |
| 134 | source/test | v2 ratification wired into reload-apply mutating surface |
| 135 | release-binary | v2 reload-apply |
| 136 | source/test | v2 startup trust bundle |
| 137 | release-binary | v2 startup trust bundle |
| 138 | source/test | SIGHUP v2 live reload |
| 139 | release-binary | SIGHUP v2 live reload |
| 140 | source/test | snapshot/restore v2 authority marker |
| 141 | release-binary | snapshot/restore v2 authority marker |
| 142 | source/test | live inbound `0x05` v2 validation |
| 143 | release-binary | live inbound `0x05` v2 validation |
| 144 | source/test | peer-driven apply safety |
| 145 | source/test | peer-driven apply staging |
| 146 | source/test | live `0x05` peer-candidate staging |
| 147 | release-binary | live `0x05` peer-candidate staging (MainNet refusal) |
| 148 | source/test | peer-driven apply |
| 149 | release-binary | peer-driven apply |
| 150 | source/test | peer-driven apply drain |
| 151 | release-binary | peer-driven apply drain |
| 152 | source/test | peer-driven apply end-to-end (MainNet refusal) |
| 153 | release-binary | peer-driven apply end-to-end |
| 154 | source/test | TestNet peer-driven apply end-to-end |
| 155 | release-binary | TestNet peer-driven apply end-to-end |
| 156 | release-binary | TestNet positive peer-driven apply end-to-end |
| 157 | source/test | TestNet positive peer-driven apply fixture tooling |
| 158 | release-binary | TestNet positive peer-driven apply |
| 159 | source/test | authority signing-key lifecycle validator |
| 160 | release-binary | authority lifecycle |
| 161 | source/test | authority lifecycle marker integration |
| 162 | release-binary | authority lifecycle enforcement |
| 163 | source/test | governance authority verifier |
| 164 | release-binary | governance authority |
| 165 | source/test | governance gate |
| 166 | release-binary | governance gate enforcement |
| 167 | source/test | governance proof carrier |
| 168 | release-binary | governance proof carrier |
| 169 | source/test | governance proof production surface |
| 170 | release-binary | governance proof production surface |
| 171 | source/test | governance Required policy |
| 172 | release-binary | governance Required policy |
| 173 | source/test | validation-only governance Required policy |
| 174 | release-binary | validation-only governance Required policy |
| 175 | release-binary | peer-candidate-check governance Required policy |
| 176 | source/test | live `0x05` governance proof |
| 177 | release-binary | live `0x05` governance proof |
| 178 | source/test | OnChainGovernance proof fixture verifier |
| 179 | release-binary | OnChainGovernance proof |
| 180 | source/test | OnChainGovernance production surface |
| 181 | release-binary | OnChainGovernance production surface |
| 182 | source/test | OnChainGovernance call-site |
| 183 | release-binary | OnChainGovernance call-site |
| 184 | source/test | OnChainGovernance payload |
| 185 | release-binary | OnChainGovernance payload |
| 186 | source/test | OnChainGovernance verifier boundary |
| 187 | release-binary | OnChainGovernance verifier boundary (fail-closed) |
| 188 | source/test | authority custody boundary |
| 189 | release-binary | authority custody boundary |
| 190 | source/test | authority custody payload / call-site |
| 191 | release-binary | authority custody payload |
| 192 | source/test | authority custody policy selector |
| 193 | release-binary | authority custody policy |
| 194 | source/test | RemoteSigner boundary |
| 195 | release-binary | RemoteSigner boundary |
| 196 | source/test | RemoteSigner payload / call-site |
| 197 | release-binary | RemoteSigner payload |
| 198 | source/test | RemoteSigner policy selector |
| 199 | release-binary | RemoteSigner policy selector |

## Notes

* "Kind" reflects the primary deliverable; consult each canonical
  `QBIND_DEVNET_EVIDENCE_RUN_NNN.md` for the exact scope, test counts,
  and validation commands. Topic labels are summaries, not titles.
* Every run in this series preserves the MainNet peer-driven apply
  refusal (Runs 147 / 148 / 152) and does not claim full C4 or C5
  closure.
* Fixture / local / loopback evidence across this series is
  DevNet/TestNet evidence-only and cannot satisfy MainNet production
  authority.
* For consolidation, closure criteria, and the next implementation
  sequence, see
  [`QBIND_DEVNET_EVIDENCE_RUN_200.md`](QBIND_DEVNET_EVIDENCE_RUN_200.md)
  and
  [`../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](
    ../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md).
