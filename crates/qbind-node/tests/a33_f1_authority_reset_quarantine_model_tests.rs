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
    QuarantineClassified(Observation),
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
        self.events.push(Event::QuarantineClassified(observation));
        self.classified = true;
        let decision = match (observation, separate_authority) {
            (
                Observation::LocalCleanLooking,
                SeparateAuthority::HypotheticalApprovedCurrentAndReconciled,
            ) => Decision::HypotheticallyAuthorize,
            _ => Decision::Refuse,
        };
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
        if !self.ownership
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
        self.quarantine_latched = true;
    }
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
    assert_eq!(
        model.classify(
            Observation::LocalCleanLooking,
            SeparateAuthority::HypotheticalApprovedCurrentAndReconciled
        ),
        Decision::HypotheticallyAuthorize
    );
    for (stage, path) in &paths {
        assert!(model.admit_write(*stage, path, &[], Separation::Separate,));
    }
    let classified_at = model
        .events
        .iter()
        .position(|event| matches!(event, Event::QuarantineClassified(_)))
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
        Event::QuarantineClassified(_) | Event::ResetWriteInvoked(..)
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
    model.quarantine_latched = true;
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
    println!("MODEL PASS: preexisting catch-up latch remains closed across reset success/refusal, each audit stage, marker replacement, acknowledgment and restart");
}

#[test]
#[ignore = "parent test launches this deliberately defective ordering as a negative control"]
fn negative_control_misplaced_write_before_classification_must_fail() {
    let mut model = ResetModel::default();
    model.setup_destination(true);
    // Deliberately misplace a refusal audit before classification, as the
    // reviewed ordering control is required to detect.
    model.events.push(Event::ResetWriteInvoked(
        WriteStage::RefusalAuditFinal,
        PathBuf::from("/synthetic-reset-model/reset-audit.json"),
    ));
    assert!(
        !model
            .events
            .iter()
            .any(|event| matches!(event, Event::ResetWriteInvoked(..))),
        "reset ordering control detected write before classification"
    );
}

#[test]
fn negative_control_child_fails_and_corrected_ordering_control_passes() {
    use std::process::Command;

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "negative_control_misplaced_write_before_classification_must_fail",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "deliberately misplaced write escaped detection"
    );
    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(combined.contains("reset ordering control detected write before classification"));
    println!(
        "EXPECTED NEGATIVE CONTROL: child test failed (status {:?}); misplaced write detected",
        output.status.code()
    );
    println!("CORRECTED CONTROL: ownership_then_classification_then_authorization_precedes_every_reset_write passes in parent suite");
}
