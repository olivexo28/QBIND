"""Verify P1 test-only implementation scope and preserved prior evidence."""

import gzip
import hashlib
import subprocess
from pathlib import Path

BASE = "1d0b66739633b1232187b0cdc04849900f6f411e"
ROOT = Path("docs/security/evidence/recovery-resume-inventory-20261107")
HERE = ROOT / "p1-provider-model-implementation"
TEST = Path("crates/qbind-consensus/tests/p1_provider_model_tests.rs")
AUDIT = Path("Audit/QBIND_SECURITY_FINDINGS_REGISTER.md")
APPENDS = [
    Path("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md"),
    ROOT / "README.md",
    ROOT / "CHANGED_PATHS.txt",
    ROOT / "commands.txt",
]


def git(*args):
    return subprocess.check_output(["git", *args])


def blob(revision, path):
    return git("show", f"{revision}:{path}")


for path in APPENDS:
    assert path.read_bytes().startswith(blob(BASE, path)), path
print("PASS: all four append-only plan/index/log prefixes preserved")

historical = [
    Path(name)
    for name in git("ls-tree", "-r", "--name-only", BASE, str(ROOT))
    .decode()
    .splitlines()
    if Path(name) not in APPENDS
]
for path in historical:
    assert path.read_bytes() == blob(BASE, path), path
assert AUDIT.read_bytes() == blob(BASE, AUDIT)
print(f"PASS: {len(historical)} prior evidence files and audit-register bytes unchanged")

changed = set(git("diff", "--name-only", BASE, "HEAD").decode().splitlines())
changed.update(git("diff", "--cached", "--name-only", BASE).decode().splitlines())
changed.update(
    git("ls-files", "--others", "--exclude-standard").decode().splitlines()
)
rust_paths = {path for path in changed if path.startswith("crates/")}
assert rust_paths == {TEST.as_posix()}, rust_paths
assert "Cargo.toml" not in changed and "Cargo.lock" not in changed
for source in [
    "crates/qbind-consensus/src",
    "crates/qbind-node/src",
    "crates/qbind-runtime/src",
]:
    assert not any(path.startswith(source + "/") for path in changed)
print("PASS: the only Rust change is the standalone integration-test target")

test_source = TEST.read_text()
test_names = [
    "independently_supplied_catalog_and_restored_positive_admission",
    "complete_context_mismatches_refuse_against_unchanged_fixture",
    "uniqueness_stage_mutants_fail_the_same_strict_oracle",
    "trust_selection_omitted_field_and_currentness_mutants_are_detected",
    "currentness_states_and_rollback_without_independent_observation_refuse",
    "provider_slot_rejects_a_different_fixture_identity",
    "use_rechecks_independent_currentness_before_sentinel",
    "each_unavailable_use_currentness_class_refuses_after_admission",
    "use_scans_bounded_evidence_before_sentinel",
    "provider_replacement_destruction_and_lease_release_are_isolated",
    "slot_destruction_and_identity_exhaustion_do_not_reuse_authority_tokens",
    "descriptor_gate_materialization_and_descriptor_correspondence",
    "borrowed_envelope_max_schema_and_separate_evidence_caps",
    "nested_evidence_count_and_length_controls_are_stage_specific",
    "nested_evidence_rejects_empty_count_and_entry_lengths",
    "scanner_rejects_malformed_and_duplicate_candidates_before_decoder",
    "candidate_member_source_content_limits_and_restored_positive",
]
for name in test_names:
    assert f"fn {name}()" in test_source, name
assert test_source.count("#[test]") == 17
for token in [
    "QBP1TEST",
    "QBE1TEST",
    "MAX_CANDIDATE: usize = 16_384",
    "MAX_EVIDENCE: usize = 19_389",
    "MAX_COMBINED: usize = 35_773",
    "EvidenceEntryCountExceeded",
    "EvidenceEntryTooLarge",
    "ProviderReplaced",
    "ProviderDestroyed",
    "CurrentnessUnknown",
]:
    assert token in test_source, token
print("PASS: all 17 named test-only cases and accepted fixture limits present")

provider_log = gzip.decompress((HERE / "03-focused-provider.log.gz").read_bytes()).decode()
regression_log = gzip.decompress((HERE / "04-related-regressions.log.gz").read_bytes()).decode()
assert "17 passed; 0 failed; 0 ignored" in provider_log
assert "9 passed; 0 failed; 0 ignored" in regression_log
assert "7 passed; 0 failed; 0 ignored" in regression_log
assert "test result: ok." in provider_log and "test result: ok." in regression_log
readme = (HERE / "README.md").read_text()
for token in [
    "no production caller",
    "not evidence",
    "signer exclusivity",
    "A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN",
]:
    assert token in readme, token
print("PASS: captured test outputs and limitations/status are documented")

manifest = HERE / "SHA256SUMS"
for line in manifest.read_text().splitlines():
    expected, name = line.split("  ", 1)
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, name
print(f"PASS: {len(manifest.read_text().splitlines())} evidence hashes verified")

for path in [
    ROOT / "p1-provider-model-specification/README.md",
    ROOT / "p1-provider-model-specification-correction/README.md",
    ROOT / "p1-nested-evidence-controls/README.md",
]:
    assert path.read_bytes() == blob(BASE, path), path
print("PASS: original P1 specification and both corrections remain byte-identical")

subprocess.run(["git", "diff", "--check", BASE, "HEAD"], check=True)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
print("PASS: committed whitespace check")
print("NOT ESTABLISHED: real authority/currentness, finality, application, fencing or resume")
