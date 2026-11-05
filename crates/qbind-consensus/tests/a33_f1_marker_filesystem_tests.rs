//! Isolated Linux filesystem experiment, NOT a marker backend or durability
//! proof. Synthetic bytes, scripted failures, no database/signing/startup use.
//! Cooperating single-threaded fixtures exclude hostile concurrent path swaps.

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "unsupported: Linux openat/no-follow flag profile required"]
fn filesystem_profile_unsupported() {}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Linux-only constants. No platform portability or production API claim.
    const O_WRONLY: i32 = 1;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    const O_NONBLOCK: i32 = 0o4000;
    const O_NOFOLLOW: i32 = 0o400000;
    const O_CLOEXEC: i32 = 0o2000000;
    const LIMIT: usize = 65_536;
    const MAGIC: &[u8] = b"fixture:";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const i8, flags: i32, ...) -> i32;
        fn renameat(oldfd: i32, old: *const i8, newfd: i32, new: *const i8) -> i32;
        fn mkfifoat(dirfd: i32, path: *const i8, mode: u32) -> i32;
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stage {
        Create,
        Write,
        FileSync,
        Rename,
        DirectorySync,
    }
    const STAGES: [Stage; 5] = [
        Stage::Create,
        Stage::Write,
        Stage::FileSync,
        Stage::Rename,
        Stage::DirectorySync,
    ];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Injection {
        None,
        Before(Stage),
        UnknownAfter(Stage),
        PartialWrite,
        ReplaceDirectoryBeforeRename,
        ReplaceFinalBeforeRename,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Visibility {
        PriorRetained,
        NewVisible,
        Unknown,
    }

    #[derive(Debug)]
    enum Cause {
        Harness(Injection),
        Os(io::Error),
        Rejected(&'static str),
    }

    #[derive(Debug)]
    struct Failure {
        stage: Stage,
        visibility: Visibility,
        cause: Cause,
    }

    #[derive(Debug)]
    struct Ack {
        // Fixture readback bytes only; no format, identity or durability token.
        bytes: Vec<u8>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Inspection {
        Missing,
        Malformed,
        Oversized,
        Refused,
        Bytes(Vec<u8>),
    }

    struct Fixture {
        base: PathBuf,
        path: PathBuf,
        directory: File,
        identity: (u64, u64),
    }

    impl Fixture {
        fn new() -> Self {
            let base = loop {
                let path = std::env::temp_dir().join(format!(
                    "qbind-a33-fs-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => break path,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("isolated temp directory: {error}"),
                }
            };
            let path = base.join("marker-directory");
            fs::create_dir(&path).unwrap();
            let directory = File::open(&path).unwrap();
            let metadata = directory.metadata().unwrap();
            Self {
                base,
                path,
                directory,
                identity: (metadata.dev(), metadata.ino()),
            }
        }

        fn unchanged(&self) -> bool {
            fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
                metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.identity
            })
        }

        fn open(&self, name: &str, flags: i32) -> io::Result<File> {
            let name = CString::new(name).unwrap();
            // Fixed fixture-relative names; returned descriptor is exclusively
            // transferred to File. Directory stays alive for the syscall.
            let fd = unsafe {
                openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                    0o600u32,
                )
            };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_fd(fd) })
            }
        }

        fn inspect(&self) -> Inspection {
            if !self.unchanged() {
                return Inspection::Refused;
            }
            let file = match self.open("marker", 0) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Inspection::Missing
                }
                Err(_) => return Inspection::Refused,
            };
            if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
                return Inspection::Refused;
            }
            let mut bytes = Vec::new();
            if file
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .is_err()
            {
                return Inspection::Refused;
            }
            if bytes.len() > LIMIT {
                Inspection::Oversized
            } else if !bytes.starts_with(MAGIC) {
                Inspection::Malformed
            } else {
                Inspection::Bytes(bytes)
            }
        }

        fn publish(
            &self,
            bytes: &[u8],
            injection: Injection,
            trace: &mut Vec<Stage>,
        ) -> Result<Ack, Failure> {
            let mut visibility = Visibility::PriorRetained;
            let failure = |stage, visibility, cause| Failure {
                stage,
                visibility,
                cause,
            };
            if !self.unchanged() {
                return Err(failure(
                    Stage::Create,
                    Visibility::Unknown,
                    Cause::Rejected("directory changed"),
                ));
            }
            if bytes.len() > LIMIT || !bytes.starts_with(MAGIC) {
                return Err(failure(
                    Stage::Create,
                    visibility,
                    Cause::Rejected("fixture bytes"),
                ));
            }
            let initial = self.inspect();
            if !matches!(initial, Inspection::Missing | Inspection::Bytes(_)) {
                return Err(failure(
                    Stage::Create,
                    visibility,
                    Cause::Rejected("final observation"),
                ));
            }
            let mut temp = None;
            for stage in STAGES {
                if stage == Stage::Rename {
                    if injection == Injection::ReplaceDirectoryBeforeRename {
                        fs::rename(&self.path, self.base.join("moved")).map_err(|error| {
                            failure(stage, Visibility::Unknown, Cause::Os(error))
                        })?;
                        fs::create_dir(&self.path).map_err(|error| {
                            failure(stage, Visibility::Unknown, Cause::Os(error))
                        })?;
                    }
                    if injection == Injection::ReplaceFinalBeforeRename {
                        fs::write(self.path.join("marker"), b"fixture:changed").map_err(
                            |error| failure(stage, Visibility::Unknown, Cause::Os(error)),
                        )?;
                    }
                }
                if !self.unchanged() {
                    return Err(failure(
                        stage,
                        Visibility::Unknown,
                        Cause::Rejected("directory changed"),
                    ));
                }
                if injection == Injection::Before(stage) {
                    return Err(failure(stage, visibility, Cause::Harness(injection)));
                }
                if stage == Stage::Rename && self.inspect() != initial {
                    return Err(failure(
                        stage,
                        Visibility::Unknown,
                        Cause::Rejected("final changed"),
                    ));
                }
                let result = match stage {
                    Stage::Create => self
                        .open("marker.tmp", O_WRONLY | O_CREAT | O_EXCL)
                        .map(|file| temp = Some(file)),
                    Stage::Write => {
                        if injection == Injection::PartialWrite {
                            temp.as_mut()
                                .unwrap()
                                .write_all(&bytes[..bytes.len() / 2])
                                .map_err(|error| failure(stage, visibility, Cause::Os(error)))?;
                            return Err(failure(stage, visibility, Cause::Harness(injection)));
                        }
                        temp.as_mut().unwrap().write_all(bytes)
                    }
                    Stage::FileSync => temp.as_ref().unwrap().sync_all(),
                    Stage::Rename => {
                        let old = CString::new("marker.tmp").unwrap();
                        let new = CString::new("marker").unwrap();
                        let result = unsafe {
                            renameat(
                                self.directory.as_raw_fd(),
                                old.as_ptr(),
                                self.directory.as_raw_fd(),
                                new.as_ptr(),
                            )
                        };
                        if result == 0 {
                            visibility = Visibility::NewVisible;
                            Ok(())
                        } else {
                            // Do not infer prior retention from an OS rename
                            // error whose actual replacement was not observed.
                            visibility = Visibility::Unknown;
                            Err(io::Error::last_os_error())
                        }
                    }
                    Stage::DirectorySync => self.directory.sync_all(),
                };
                result.map_err(|error| failure(stage, visibility, Cause::Os(error)))?;
                trace.push(stage);
                if injection == Injection::UnknownAfter(stage) {
                    return Err(failure(stage, visibility, Cause::Harness(injection)));
                }
            }
            Ok(Ack {
                bytes: bytes.to_vec(),
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Exact unique directory created by this fixture, never node data.
            fs::remove_dir_all(&self.base).expect("cleanup isolated fixture");
        }
    }

    fn payload(length: usize) -> Vec<u8> {
        let mut bytes = vec![b'x'; length];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        bytes
    }

    #[test]
    fn successful_publication_orders_real_calls_and_exact_readback() {
        let fixture = Fixture::new();
        let bytes = payload(32);
        let mut trace = Vec::new();
        let ack = fixture
            .publish(&bytes, Injection::None, &mut trace)
            .unwrap();
        assert_eq!(trace, STAGES);
        assert_eq!(ack.bytes, bytes);
        assert_eq!(fixture.inspect(), Inspection::Bytes(bytes));
        assert!(!fixture.path.join("marker.tmp").exists());
    }

    #[test]
    fn each_scripted_failed_or_unknown_stage_returns_no_ack() {
        for stage in STAGES {
            for injection in [Injection::Before(stage), Injection::UnknownAfter(stage)] {
                let fixture = Fixture::new();
                let old = payload(24);
                fixture
                    .publish(&old, Injection::None, &mut Vec::new())
                    .unwrap();
                let new = payload(48);
                let mut trace = Vec::new();
                let error = fixture.publish(&new, injection, &mut trace).unwrap_err();
                assert_eq!(error.stage, stage);
                assert!(matches!(error.cause, Cause::Harness(actual) if actual == injection));
                let renamed = trace.contains(&Stage::Rename);
                assert_eq!(
                    error.visibility,
                    if renamed {
                        Visibility::NewVisible
                    } else {
                        Visibility::PriorRetained
                    }
                );
                assert_eq!(
                    fixture.inspect(),
                    Inspection::Bytes(if renamed { new } else { old })
                );
                println!("{injection:?}: {error:?}; trace={trace:?}");
            }
        }
    }

    #[test]
    fn partial_write_keeps_old_final_and_unpromoted_artifact() {
        let fixture = Fixture::new();
        let old = payload(24);
        fixture
            .publish(&old, Injection::None, &mut Vec::new())
            .unwrap();
        let new = payload(40);
        let error = fixture
            .publish(&new, Injection::PartialWrite, &mut Vec::new())
            .unwrap_err();
        assert_eq!(error.visibility, Visibility::PriorRetained);
        assert!(matches!(
            error.cause,
            Cause::Harness(Injection::PartialWrite)
        ));
        assert_eq!(fixture.inspect(), Inspection::Bytes(old));
        assert_eq!(
            fs::read(fixture.path.join("marker.tmp")).unwrap(),
            new[..20]
        );
    }

    #[test]
    fn existing_temp_os_failure_does_not_truncate_or_promote() {
        let fixture = Fixture::new();
        fs::write(fixture.path.join("marker.tmp"), b"diagnostic").unwrap();
        let error = fixture
            .publish(&payload(24), Injection::None, &mut Vec::new())
            .unwrap_err();
        assert_eq!(error.stage, Stage::Create);
        assert!(
            matches!(error.cause, Cause::Os(ref error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fixture.inspect(), Inspection::Missing);
        assert_eq!(
            fs::read(fixture.path.join("marker.tmp")).unwrap(),
            b"diagnostic"
        );
    }

    #[test]
    fn bounded_missing_malformed_oversized_and_special_observations() {
        let fixture = Fixture::new();
        assert_eq!(fixture.inspect(), Inspection::Missing);
        fs::write(fixture.path.join("marker"), b"bad").unwrap();
        assert_eq!(fixture.inspect(), Inspection::Malformed);
        fs::write(fixture.path.join("marker"), payload(LIMIT + 1)).unwrap();
        assert_eq!(fixture.inspect(), Inspection::Oversized);
        fs::remove_file(fixture.path.join("marker")).unwrap();
        let name = CString::new("marker").unwrap();
        assert_eq!(
            unsafe { mkfifoat(fixture.directory.as_raw_fd(), name.as_ptr(), 0o600) },
            0
        );
        assert_eq!(fixture.inspect(), Inspection::Refused);
        fs::remove_file(fixture.path.join("marker")).unwrap();
        fs::create_dir(fixture.path.join("marker")).unwrap();
        assert_eq!(fixture.inspect(), Inspection::Refused);
    }

    #[test]
    fn symlink_final_and_temp_do_not_follow_or_replace_targets() {
        for name in ["marker", "marker.tmp"] {
            let fixture = Fixture::new();
            let target = fixture.base.join("target");
            fs::write(&target, b"untouched").unwrap();
            symlink(&target, fixture.path.join(name)).unwrap();
            assert!(fixture
                .publish(&payload(32), Injection::None, &mut Vec::new())
                .is_err());
            assert_eq!(fs::read(target).unwrap(), b"untouched");
            assert!(fs::symlink_metadata(fixture.path.join(name))
                .unwrap()
                .is_symlink());
        }
    }

    #[test]
    fn replaced_directory_is_refused_without_writing_either_destination() {
        let fixture = Fixture::new();
        let moved = fixture.base.join("moved");
        fs::rename(&fixture.path, &moved).unwrap();
        fs::create_dir(&fixture.path).unwrap();
        assert_eq!(fixture.inspect(), Inspection::Refused);
        let error = fixture
            .publish(&payload(32), Injection::None, &mut Vec::new())
            .unwrap_err();
        assert_eq!(error.visibility, Visibility::Unknown);
        assert!(!moved.join("marker").exists());
        assert!(!fixture.path.join("marker").exists());
    }

    #[test]
    fn exact_fixture_size_boundary_rejects_before_replacement() {
        let fixture = Fixture::new();
        let ack = fixture
            .publish(&payload(LIMIT), Injection::None, &mut Vec::new())
            .unwrap();
        assert_eq!(ack.bytes.len(), 65_536);
        let mut trace = Vec::new();
        let error = fixture
            .publish(&payload(LIMIT + 1), Injection::None, &mut trace)
            .unwrap_err();
        assert!(matches!(error.cause, Cause::Rejected("fixture bytes")));
        assert!(trace.is_empty());
        assert_eq!(fixture.inspect(), Inspection::Bytes(ack.bytes));
        assert!(!fixture.path.join("marker.tmp").exists());
    }

    #[test]
    fn repeated_success_and_post_rename_error_never_relabel_old_ack() {
        let fixture = Fixture::new();
        let old_ack = fixture
            .publish(&payload(24), Injection::None, &mut Vec::new())
            .unwrap();
        let next_ack = fixture
            .publish(&payload(32), Injection::None, &mut Vec::new())
            .unwrap();
        assert_eq!(old_ack.bytes, payload(24));
        assert_eq!(fixture.inspect(), Inspection::Bytes(next_ack.bytes));
        let error = fixture
            .publish(
                &payload(40),
                Injection::Before(Stage::DirectorySync),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert_eq!(error.visibility, Visibility::NewVisible);
        assert_eq!(fixture.inspect(), Inspection::Bytes(payload(40)));
        assert_eq!(old_ack.bytes, payload(24));
        fixture
            .publish(&payload(48), Injection::None, &mut Vec::new())
            .unwrap();
        assert_eq!(fixture.inspect(), Inspection::Bytes(payload(48)));
    }

    #[test]
    fn scripted_directory_or_final_changes_before_rename_refuse_replacement() {
        for injection in [
            Injection::ReplaceDirectoryBeforeRename,
            Injection::ReplaceFinalBeforeRename,
        ] {
            let fixture = Fixture::new();
            fixture
                .publish(&payload(24), Injection::None, &mut Vec::new())
                .unwrap();
            let mut trace = Vec::new();
            let error = fixture
                .publish(&payload(40), injection, &mut trace)
                .unwrap_err();
            assert_eq!(error.stage, Stage::Rename);
            assert_eq!(error.visibility, Visibility::Unknown);
            assert_eq!(trace, vec![Stage::Create, Stage::Write, Stage::FileSync]);
            if injection == Injection::ReplaceDirectoryBeforeRename {
                assert_eq!(fixture.inspect(), Inspection::Refused);
                assert_eq!(
                    fs::read(fixture.base.join("moved/marker")).unwrap(),
                    payload(24)
                );
                assert!(!fixture.path.join("marker").exists());
            } else {
                assert_eq!(
                    fixture.inspect(),
                    Inspection::Bytes(b"fixture:changed".to_vec())
                );
                assert_eq!(
                    fs::read(fixture.path.join("marker.tmp")).unwrap(),
                    payload(40)
                );
            }
        }
    }

    #[test]
    fn repeated_failed_attempts_preserve_ack_and_refuse_leftover_temp() {
        let fixture = Fixture::new();
        let ack = fixture
            .publish(&payload(24), Injection::None, &mut Vec::new())
            .unwrap();
        fixture
            .publish(
                &payload(32),
                Injection::Before(Stage::FileSync),
                &mut Vec::new(),
            )
            .unwrap_err();
        let leftover = fs::read(fixture.path.join("marker.tmp")).unwrap();
        for _ in 0..2 {
            let error = fixture
                .publish(&payload(40), Injection::None, &mut Vec::new())
                .unwrap_err();
            assert!(
                matches!(error.cause, Cause::Os(ref error) if error.kind() == io::ErrorKind::AlreadyExists)
            );
            assert_eq!(fixture.inspect(), Inspection::Bytes(ack.bytes.clone()));
            assert_eq!(fs::read(fixture.path.join("marker.tmp")).unwrap(), leftover);
        }
    }
}
