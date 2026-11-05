//! Isolated decision/effect model only; it does not call production reset,
//! lock, storage, startup, signer, or transport code.

use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    Applying,
    RecordedOutcome,
    AbsentOnly,
    Malformed,
    Unsupported,
    Foreign,
    Mismatched,
    Unavailable,
    Uncertain,
    LocalCleanLooking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeparateAuthority {
    None,
    HypotheticalApprovedCurrentAndReconciled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Refuse,
    HypotheticallyAuthorize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteStage {
    RefusalAuditFinal,
    PendingAuditFinal,
    FinalAuditFinal,
    AuditTemporary,
    AuthorityMarkerPersistence,
    AuthorityMarkerTemporary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    DataDirectoryCreated,
    LockFileCreated,
    OwnershipAcquired,
    OwnershipFailed,
    QuarantineClassified(Observation, Decision),
    ResetWriteInvoked(WriteStage, PathBuf),
    WriteRefusedByPathGuard(WriteStage),
    Restarted,
    PassiveStatus(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Separation {
    Separate,
    Alias,
    Indeterminate,
}

#[derive(Default)]
struct ResetModel {
    events: Vec<Event>,
    ownership: bool,
    classified: bool,
    decision: Option<Decision>,
    quarantine_latched: bool,
}

impl ResetModel {
    fn setup_destination(&mut self, lock_succeeds: bool) {
        self.events.push(Event::DataDirectoryCreated);
        self.events.push(Event::LockFileCreated);
        self.ownership = false;
        self.classified = false;
        self.decision = None;
        if lock_succeeds {
            self.ownership = true;
            self.events.push(Event::OwnershipAcquired);
        } else {
            self.events.push(Event::OwnershipFailed);
        }
    }

    fn classify(
        &mut self,
        observation: Observation,
        separate_authority: SeparateAuthority,
    ) -> Decision {
        assert!(
            self.ownership,
            "classification requires destination ownership"
        );
        let requested_decision = match (observation, separate_authority) {
            (
                Observation::LocalCleanLooking,
                SeparateAuthority::HypotheticalApprovedCurrentAndReconciled,
            ) => Decision::HypotheticallyAuthorize,
            _ => Decision::Refuse,
        };
        let decision = if self.quarantine_latched {
            Decision::Refuse
        } else {
            requested_decision
        };
        self.events
            .push(Event::QuarantineClassified(observation, decision));
        self.classified = true;
        self.decision = Some(decision);
        if decision == Decision::Refuse {
            self.quarantine_latched = true;
        }
        decision
    }

    fn admit_write(
        &mut self,
        stage: WriteStage,
        destination: &Path,
        quarantine_paths: &[PathBuf],
        separation: Separation,
    ) -> bool {
        if self.quarantine_latched
            || !self.ownership
            || !self.classified
            || self.decision != Some(Decision::HypotheticallyAuthorize)
        {
            return false;
        }
        if separation != Separation::Separate
            || quarantine_paths
                .iter()
                .any(|protected| lexical_identity(destination) == lexical_identity(protected))
        {
            self.events.push(Event::WriteRefusedByPathGuard(stage));
            return false;
        }
        self.events
            .push(Event::ResetWriteInvoked(stage, destination.to_path_buf()));
        true
    }

    fn reset_result(&mut self, _success: bool) {
        // Authority reset has no transition that releases catch-up quarantine.
        if self.classified && self.decision == Some(Decision::Refuse) {
            self.quarantine_latched = true;
        }
    }

    fn passive_event(&mut self, status: &'static str) {
        self.events.push(Event::PassiveStatus(status));
        self.quarantine_latched = true;
    }

    fn restart(&mut self) {
        self.events.push(Event::Restarted);
        self.ownership = false;
        self.classified = false;
        self.decision = None;
    }
}

fn trace_is_valid(trace: &[Event]) -> bool {
    let mut ownership = false;
    let mut classified = false;
    let mut authorized = false;
    let mut latched = false;
    for event in trace {
        match event {
            Event::OwnershipAcquired => {
                ownership = true;
                classified = false;
                authorized = false;
            }
            Event::OwnershipFailed => {
                ownership = false;
                classified = false;
                authorized = false;
            }
            Event::QuarantineClassified(_, decision) => {
                if !ownership {
                    return false;
                }
                classified = true;
                if latched || *decision == Decision::Refuse {
                    latched = true;
                    authorized = false;
                } else {
                    authorized = true;
                }
            }
            Event::ResetWriteInvoked(..) => {
                if !ownership || !classified || !authorized || latched {
                    return false;
                }
            }
            Event::Restarted => {
                ownership = false;
                classified = false;
                authorized = false;
            }
            Event::DataDirectoryCreated
            | Event::LockFileCreated
            | Event::WriteRefusedByPathGuard(_)
            | Event::PassiveStatus(_) => {}
        }
    }
    true
}

fn lexical_identity(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn reset_write_paths(root: &Path) -> [(WriteStage, PathBuf); 6] {
    let audit = root.join("reset-audit.json");
    let marker = root.join("pqc_authority_state.json");
    [
        (WriteStage::RefusalAuditFinal, audit.clone()),
        (WriteStage::PendingAuditFinal, audit.clone()),
        (WriteStage::FinalAuditFinal, audit.clone()),
        (WriteStage::AuditTemporary, audit.with_extension("json.tmp")),
        (WriteStage::AuthorityMarkerPersistence, marker.clone()),
        (
            WriteStage::AuthorityMarkerTemporary,
            PathBuf::from(format!("{}.tmp", marker.display())),
        ),
    ]
}

const LOCAL_OBSERVATIONS: [Observation; 10] = [
    Observation::Applying,
    Observation::RecordedOutcome,
    Observation::AbsentOnly,
    Observation::Malformed,
    Observation::Unsupported,
    Observation::Foreign,
    Observation::Mismatched,
    Observation::Unavailable,
    Observation::Uncertain,
    Observation::LocalCleanLooking,
];

#[test]
fn ownership_then_classification_then_authorization_precedes_every_reset_write() {
    let root = Path::new("/synthetic-reset-model");
    let paths = reset_write_paths(root);
    let mut model = ResetModel::default();
    model.setup_destination(true);
    assert!(
        !model.quarantine_latched,
        "hypothetical-authority positive control starts unlatched"
    );
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::HypotheticallyAuthorize
    );
    assert!(trace_is_valid(&model.events));
    for (stage, path) in &paths {
        assert!(model.admit_write(*stage, path, &[], Separation::Separate,));
    }
    let classified_at = model
        .events
        .iter()
        .position(|event| matches!(event, Event::QuarantineClassified(..)))
        .unwrap();
    let first_write_at = model
        .events
        .iter()
        .position(|event| matches!(event, Event::ResetWriteInvoked(..)))
        .unwrap();
    let ownership_at = model
        .events
        .iter()
        .position(|event| *event == Event::OwnershipAcquired)
        .unwrap();
    assert!(ownership_at < classified_at && classified_at < first_write_at);
    assert_eq!(
        model
            .events
            .iter()
            .filter(|e| matches!(e, Event::ResetWriteInvoked(..)))
            .count(),
        6
    );
    println!("MODEL PASS: ownership -> classification -> hypothetical external authority -> all 6 reset write destinations");
}

#[test]
fn ownership_failure_skips_classification_and_reset_writes_but_records_setup_effects() {
    let mut model = ResetModel::default();
    model.setup_destination(false);
    assert!(!model.ownership);
    assert!(model.events.contains(&Event::DataDirectoryCreated));
    assert!(model.events.contains(&Event::LockFileCreated));
    assert!(!model.events.iter().any(|event| matches!(
        event,
        Event::QuarantineClassified(..) | Event::ResetWriteInvoked(..)
    )));
    assert!(model.events.contains(&Event::OwnershipFailed));
    println!("MODEL PASS: directory/lock setup artifacts distinct; ownership failure skips classification and writes");
}

#[test]
fn every_local_observation_refuses_without_invoking_any_reset_write() {
    let root = Path::new("/synthetic-reset-model");
    let paths = reset_write_paths(root);
    for observation in LOCAL_OBSERVATIONS {
        let mut model = ResetModel::default();
        model.setup_destination(true);
        assert_eq!(
            model.classify(observation, SeparateAuthority::None),
            Decision::Refuse,
            "{observation:?}"
        );
        for (stage, path) in &paths {
            assert!(!model.admit_write(*stage, path, &[], Separation::Separate,));
        }
        assert!(!model
            .events
            .iter()
            .any(|event| matches!(event, Event::ResetWriteInvoked(..))));
        assert!(model.quarantine_latched);
        model.reset_result(true);
        model.reset_result(false);
        model.passive_event("audit-published");
        model.passive_event("marker-replaced");
        model.passive_event("cancellation-requested");
        model.passive_event("timeout");
        model.passive_event("outbound-enqueued");
        model.restart();
        assert!(model.quarantine_latched, "{observation:?}");
    }
    println!("MODEL PASS: 10 local observations refuse; no reset write invoked; success/refusal/audit/marker/restart do not clear latch");
}

#[test]
fn reset_write_destinations_cannot_alias_synthetic_quarantine_record_or_publish_paths() {
    let root = Path::new("/synthetic-reset-model");
    let audit = root.join("reset-audit.json");
    let marker = root.join("pqc_authority_state.json");
    let quarantine_record = root.join("quarantine.record");
    let cases = [
        (
            "equal-final",
            quarantine_record.clone(),
            vec![quarantine_record.clone()],
            Separation::Alias,
        ),
        (
            "equivalent-spelling",
            root.join("qdata/../quarantine.record"),
            vec![quarantine_record.clone()],
            Separation::Separate,
        ),
        (
            "modeled-parent-symlink-alias",
            root.join("alias/quarantine.record"),
            vec![quarantine_record.clone()],
            Separation::Alias,
        ),
        (
            "audit-temp-alias",
            audit.with_extension("json.tmp"),
            vec![audit.with_extension("json.tmp")],
            Separation::Separate,
        ),
        (
            "marker-final-alias",
            marker.clone(),
            vec![marker.clone()],
            Separation::Separate,
        ),
        (
            "marker-temp-alias",
            PathBuf::from(format!("{}.tmp", marker.display())),
            vec![PathBuf::from(format!("{}.tmp", marker.display()))],
            Separation::Separate,
        ),
        (
            "indeterminate",
            root.join("uncertain-audit.json"),
            vec![quarantine_record.clone()],
            Separation::Indeterminate,
        ),
    ];
    for (name, destination, protected, separation) in cases {
        let mut model = ResetModel::default();
        model.setup_destination(true);
        assert_eq!(
            model.classify(
                Observation::LocalCleanLooking,
                SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
            ),
            Decision::HypotheticallyAuthorize
        );
        assert!(
            !model.admit_write(
                WriteStage::FinalAuditFinal,
                &destination,
                &protected,
                separation,
            ),
            "{name}"
        );
        assert!(!model
            .events
            .iter()
            .any(|event| matches!(event, Event::ResetWriteInvoked(..))));
        println!("MODEL PASS path case {name}: no write admitted");
    }
    // Exercise every instrumented reset stage against each reserved
    // quarantine record/publication pathname, including the audit's derived
    // temporary destination and the marker's append-.tmp destination.
    let quarantine_paths = [
        root.join("quarantine.record"),
        root.join("quarantine.record.tmp"),
        root.join("quarantine.record.publish"),
    ];
    for (stage, _) in reset_write_paths(root) {
        for protected in &quarantine_paths {
            let mut model = ResetModel::default();
            model.setup_destination(true);
            model.classify(
                Observation::LocalCleanLooking,
                SeparateAuthority::HypotheticalApprovedCurrentAndReconciled,
            );
            assert!(
                !model.admit_write(stage, protected, &quarantine_paths, Separation::Separate),
                "{stage:?} overwrote {protected:?}"
            );
        }
    }
}

#[test]
fn cancellation_timeout_and_enqueue_are_not_completion_observations() {
    let mut model = ResetModel::default();
    model.quarantine_latched = true;
    for status in [
        "signing-cancel-requested",
        "storage-timeout",
        "outbound-enqueued",
        "worker-completion-unknown",
    ] {
        model.passive_event(status);
        assert!(model.quarantine_latched);
    }
    println!("MODEL PASS: passive cancellation/timeout/enqueue/unknown statuses retain quarantine");
}

#[test]
fn reset_success_audit_marker_replacement_and_restart_never_clear_latched_quarantine() {
    let root = Path::new("/synthetic-reset-model");
    let mut model = ResetModel::default();
    model.setup_destination(true);
    assert_eq!(
        model.classify(Observation::LocalCleanLooking, SeparateAuthority::None),
        Decision::Refuse
    );
    model.reset_result(false);
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::Refuse,
        "hypothetical authority cannot override the first refusal"
    );
    for (stage, path) in reset_write_paths(root) {
        assert!(!model.admit_write(stage, &path, &[], Separation::Separate));
    }
    for success in [true, false] {
        model.reset_result(success);
        assert!(model.quarantine_latched);
    }
    for status in [
        "refusal-audit-published",
        "pending-audit-published",
        "final-audit-published",
        "authority-marker-replaced",
        "marker-persistence-acknowledged",
    ] {
        model.passive_event(status);
        assert!(model.quarantine_latched, "{status}");
    }
    model.restart();
    assert!(model.quarantine_latched);
    model.setup_destination(true);
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::Refuse,
        "reacquisition and reclassification cannot bypass latch"
    );
    for (stage, path) in reset_write_paths(root) {
        assert!(!model.admit_write(stage, &path, &[], Separation::Separate));
    }
    model.restart();
    assert!(model.quarantine_latched);
    println!("MODEL PASS: first refusal latches; later hypothetical Clean classification and all six writes refuse; reset/audit/marker/restart do not clear latch");
}

#[test]
fn restart_invalidates_process_local_authorization_until_reacquired_and_reclassified() {
    let root = Path::new("/synthetic-reset-model");
    let mut model = ResetModel::default();
    model.setup_destination(true);
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::HypotheticallyAuthorize
    );
    model.restart();
    assert!(!model.ownership && !model.classified && model.decision.is_none());
    for (stage, path) in reset_write_paths(root) {
        assert!(!model.admit_write(stage, &path, &[], Separation::Separate));
    }
    model.setup_destination(true);
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::HypotheticallyAuthorize
    );
    for (stage, path) in reset_write_paths(root) {
        assert!(model.admit_write(stage, &path, &[], Separation::Separate));
    }
    println!("MODEL PASS: restart invalidates ownership/classification/authorization; reacquisition permits only unlatched hypothetical control");
}

fn defective_trace(kind: &str) -> Vec<Event> {
    let write = Event::ResetWriteInvoked(
        WriteStage::RefusalAuditFinal,
        PathBuf::from("/synthetic-reset-model/reset-audit.json"),
    );
    match kind {
        "before-ownership" => vec![write],
        "before-classification" => vec![Event::OwnershipAcquired, write],
        "after-refusal" => vec![
            Event::OwnershipAcquired,
            Event::QuarantineClassified(Observation::Applying, Decision::Refuse),
            write,
        ],
        _ => panic!("unknown defective trace"),
    }
}

#[test]
fn shared_trace_checker_accepts_valid_order_and_rejects_all_defective_orders() {
    let valid = [
        Event::OwnershipAcquired,
        Event::QuarantineClassified(
            Observation::LocalCleanLooking,
            Decision::HypotheticallyAuthorize,
        ),
        Event::ResetWriteInvoked(
            WriteStage::RefusalAuditFinal,
            PathBuf::from("/synthetic-reset-model/reset-audit.json"),
        ),
    ];
    assert!(trace_is_valid(&valid));
    for kind in ["before-ownership", "before-classification", "after-refusal"] {
        assert!(!trace_is_valid(&defective_trace(kind)), "{kind}");
    }
    println!("MODEL PASS: shared trace checker accepts valid sequence and rejects writes before ownership, before classification and after refusal");
}

#[test]
#[ignore = "parent test launches this deliberately defective ordering as a sensitivity control"]
fn negative_control_before_ownership_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("before-ownership")),
        "shared ordering checker rejected write before ownership"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective ordering as a sensitivity control"]
fn negative_control_before_classification_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("before-classification")),
        "shared ordering checker rejected write before classification"
    );
}

#[test]
#[ignore = "parent test launches this deliberately defective ordering as a sensitivity control"]
fn negative_control_after_refusal_must_fail() {
    assert!(
        trace_is_valid(&defective_trace("after-refusal")),
        "shared ordering checker rejected write after quarantine refusal"
    );
}

#[test]
fn negative_control_children_fail_and_corrected_shared_checker_passes() {
    use std::process::Command;

    for (name, expected_diagnostic) in [
        (
            "negative_control_before_ownership_must_fail",
            "shared ordering checker rejected write before ownership",
        ),
        (
            "negative_control_before_classification_must_fail",
            "shared ordering checker rejected write before classification",
        ),
        (
            "negative_control_after_refusal_must_fail",
            "shared ordering checker rejected write after quarantine refusal",
        ),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", name, "--nocapture"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name} did not fail");
        let combined = String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(combined.contains(expected_diagnostic), "{name}: {combined}");
        println!(
            "EXPECTED NEGATIVE CONTROL: {name} failed (status {:?}); shared checker detected defect",
            output.status.code()
        );
    }
    assert!(trace_is_valid(&[
        Event::OwnershipAcquired,
        Event::QuarantineClassified(
            Observation::LocalCleanLooking,
            Decision::HypotheticallyAuthorize,
        ),
        Event::ResetWriteInvoked(
            WriteStage::RefusalAuditFinal,
            PathBuf::from("/synthetic-reset-model/reset-audit.json"),
        ),
    ]));
    println!(
        "CORRECTED CONTROL: shared checker accepts ownership -> classification -> authorized write"
    );
}
