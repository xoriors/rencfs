use super::*;
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};

struct Password;
impl PasswordProvider for Password {
    fn get_password(&self) -> Option<SecretString> {
        Some(secret("windows-callback-test"))
    }
}

struct Fixture {
    adapter: WindowsFs,
    _runtime: Runtime,
    _directory: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        let fs = runtime
            .block_on(EncryptedFs::new(
                directory.path().to_path_buf(),
                Box::new(Password),
                Cipher::ChaCha20Poly1305,
                false,
            ))
            .unwrap();
        let (sender, _) = mpsc::channel();
        let adapter = WindowsFs {
            fs,
            runtime: runtime.handle().clone(),
            data_dir: directory.path().to_path_buf(),
            read_only: false,
            descriptor: mounting_user_descriptor().unwrap(),
            opened: Mutex::default(),
            stopped: sender,
        };
        Self {
            adapter,
            _runtime: runtime,
            _directory: directory,
        }
    }

    fn create(&self, path: &str, directory: bool) -> ContextRef {
        self.adapter
            .create(
                &name(path),
                CreateFileInfo {
                    create_options: if directory {
                        CreateOptions::FILE_DIRECTORY_FILE
                    } else {
                        CreateOptions::FILE_NON_DIRECTORY_FILE
                    },
                    granted_access: FileAccessRights::FILE_ALL_ACCESS,
                    file_attributes: if directory {
                        FileAttributes::DIRECTORY
                    } else {
                        FileAttributes::NORMAL
                    },
                    allocation_size: 0,
                },
                self.adapter.descriptor.clone(),
            )
            .unwrap()
            .0
    }

    fn open(&self, path: &str, access: FileAccessRights) -> NtResult<ContextRef> {
        self.adapter
            .open(&name(path), CreateOptions(0), access)
            .map(|result| result.0)
    }
}

fn name(path: &str) -> U16CString {
    U16CString::from_str(path).unwrap()
}

#[test]
fn windows_names_reject_traversal_streams_and_invalid_utf16() {
    assert!(components(&name("\\")).unwrap().is_empty());
    assert_eq!(
        components(&name("\\日本語\\hello.txt")).unwrap(),
        ["日本語", "hello.txt"]
    );
    for invalid in [
        "relative",
        "\\..\\escape",
        "\\a\\.\\b",
        "\\a\\\\b",
        "\\a/other",
        "\\a:stream",
        "\\a.",
        "\\a ",
    ] {
        assert!(components(&name(invalid)).is_err(), "accepted {invalid}");
    }
    assert_eq!(
        components(&name(&format!("\\{}", "x".repeat(256)))),
        Err(STATUS_NAME_TOO_LONG)
    );
    let invalid = U16CString::from_vec(vec![b'\\' as u16, 0xd800]).unwrap();
    assert_eq!(components(&invalid), Err(STATUS_OBJECT_NAME_INVALID));
}

#[test]
fn windows_filetime_roundtrip_including_before_unix_epoch() {
    for ticks in [
        0,
        1,
        FILETIME_UNIX_EPOCH - 10_000_001,
        FILETIME_UNIX_EPOCH,
        FILETIME_UNIX_EPOCH + 12_345_678,
        FILETIME_UNIX_EPOCH + 86_400 * 10_000_000,
    ] {
        assert_eq!(to_filetime(from_filetime(ticks).unwrap()), ticks);
    }
}

#[test]
fn windows_callback_file_lifecycle_and_truncation() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\résumé.txt", false);
    let (written, info) = fs
        .write(file.clone(), b"abcdef", WriteMode::Normal { offset: 0 })
        .unwrap();
    assert_eq!(written, 6);
    assert_eq!(info.file_size(), 6);
    fs.flush(file.clone()).unwrap();
    let mut buffer = [0; 16];
    assert_eq!(fs.read(file.clone(), &mut buffer, 0).unwrap(), 6);
    assert_eq!(&buffer[..6], b"abcdef");
    assert_eq!(
        fs.write(file.clone(), b"XYZ", WriteMode::ConstrainedIO { offset: 5 })
            .unwrap()
            .0,
        1
    );
    assert_eq!(fs.get_file_info(file.clone()).unwrap().file_size(), 6);
    fs.set_file_size(file.clone(), 3, false).unwrap();
    fs.write(file.clone(), b"!", WriteMode::WriteToEOF).unwrap();
    fs.flush(file.clone()).unwrap();
    assert_eq!(fs.read(file.clone(), &mut buffer, 0).unwrap(), 4);
    assert_eq!(&buffer[..4], b"abc!");
    fs.rename(
        file.clone(),
        &name("\\résumé.txt"),
        &name("\\renamed.txt"),
        false,
    )
    .unwrap();
    assert!(fixture
        .open("\\résumé.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .is_err());
    assert!(fixture
        .open("\\renamed.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .is_ok());
    // The temporary metadata-open context above was never transferred to WinFsp;
    // it is dropped here, leaving only this file context in the registry.
    fs.set_delete(file.clone(), &name("\\renamed.txt"), true)
        .unwrap();
    fs.cleanup(
        file.clone(),
        Some(&name("\\renamed.txt")),
        CleanupFlags::DELETE,
    );
    fs.close(file);
    assert!(!fs
        .fs
        .exists_by_name(ROOT_INODE, &secret("renamed.txt"))
        .unwrap());
}

#[test]
fn windows_overwrite_and_access_rights() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\access.txt", false);
    fs.write(file.clone(), b"old", WriteMode::Normal { offset: 0 })
        .unwrap();
    fs.overwrite(file.clone(), FileAttributes::NORMAL, true, 4096)
        .unwrap();
    assert_eq!(fs.get_file_info(file.clone()).unwrap().file_size(), 0);
    fs.close(file);
    let readonly = fixture
        .open("\\access.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    assert_eq!(
        fs.write(readonly.clone(), b"bad", WriteMode::Normal { offset: 0 })
            .unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        fs.set_file_size(readonly.clone(), 3, false).unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    fs.close(readonly);
    let metadata = fixture
        .open("\\access.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .unwrap();
    assert!(metadata.handle.lock().unwrap().is_none());
    assert_eq!(
        fs.read(metadata.clone(), &mut [0; 1], 0).unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    fs.close(metadata);
}

#[test]
fn windows_readonly_projection_and_unsupported_metadata() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\protected.txt", false);
    fs.set_basic_info(file.clone(), FileAttributes::READONLY, 0, 0, 0, 0)
        .unwrap();
    assert!(fs
        .get_file_info(file.clone())
        .unwrap()
        .file_attributes()
        .is(FileAttributes::READONLY));
    assert_eq!(
        fs.write(file.clone(), b"bad", WriteMode::WriteToEOF)
            .unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(
        fs.set_basic_info(file.clone(), FileAttributes::HIDDEN, 0, 0, 0, 0)
            .unwrap_err(),
        STATUS_NOT_SUPPORTED
    );
    fs.set_basic_info(file.clone(), FileAttributes::NORMAL, 0, 0, 0, 0)
        .unwrap();
    assert!(!fs
        .get_file_info(file.clone())
        .unwrap()
        .file_attributes()
        .is(FileAttributes::READONLY));
    fs.close(file);
}

#[test]
fn windows_directory_enumeration_paginates_utf16_snapshot() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let directory = fixture.create("\\dir", true);
    for file in ["b", "a", "文"] {
        fs.close(fixture.create(&format!("\\dir\\{file}"), false));
    }
    let mut page = Vec::new();
    fs.read_directory(directory.clone(), None, |entry| {
        if !page.is_empty() {
            return false;
        }
        page.push(entry);
        true
    })
    .unwrap();
    assert_eq!(page.len(), 1);
    let first = &page[0].file_name;
    let first = U16CString::from_vec(
        first
            .iter()
            .take_while(|c| **c != 0)
            .copied()
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(first.to_string_lossy(), "a");
    let mut rest = Vec::new();
    fs.read_directory(directory.clone(), Some(&first), |entry| {
        rest.push(entry);
        true
    })
    .unwrap();
    assert_eq!(rest.len(), 2);
    assert_eq!(rest[0].file_name[0], b'b' as u16);
    assert_eq!(
        fs.set_delete(directory.clone(), &name("\\dir"), true)
            .unwrap_err(),
        STATUS_DIRECTORY_NOT_EMPTY
    );
    fs.close(directory);
}

#[test]
fn windows_delete_is_deferred_cancellable_and_checks_open_handles() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\delete.txt", false);
    let observer = fixture
        .open("\\delete.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .unwrap();
    assert_eq!(
        fs.set_delete(file.clone(), &name("\\delete.txt"), true)
            .unwrap_err(),
        STATUS_SHARING_VIOLATION
    );
    fs.close(observer);
    fs.set_delete(file.clone(), &name("\\delete.txt"), true)
        .unwrap();
    assert!(fs
        .fs
        .exists_by_name(ROOT_INODE, &secret("delete.txt"))
        .unwrap());
    assert!(fixture
        .open("\\delete.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .is_err());
    fs.set_delete(file.clone(), &name("\\delete.txt"), false)
        .unwrap();
    fs.cleanup(file.clone(), Some(&name("\\delete.txt")), CleanupFlags(0));
    assert!(fs
        .fs
        .exists_by_name(ROOT_INODE, &secret("delete.txt"))
        .unwrap());
    fs.close(file);
}

#[test]
fn windows_readonly_mount_rejects_all_mutation_callbacks() {
    let mut fixture = Fixture::new();
    let file = fixture.create("\\existing.txt", false);
    fixture.adapter.close(file);
    fixture.adapter.read_only = true;
    let file = fixture
        .open("\\existing.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    assert_eq!(
        fixture
            .adapter
            .write(file.clone(), b"bad", WriteMode::WriteToEOF)
            .unwrap_err(),
        STATUS_MEDIA_WRITE_PROTECTED
    );
    assert_eq!(
        fixture
            .adapter
            .set_file_size(file.clone(), 1, false)
            .unwrap_err(),
        STATUS_MEDIA_WRITE_PROTECTED
    );
    assert!(fixture
        .open("\\existing.txt", FileAccessRights::FILE_WRITE_DATA)
        .is_err());
    fixture.adapter.close(file);
}

#[test]
fn windows_null_volume_flush_context_never_constructs_null_arc() {
    let fixture = Fixture::new();
    // SAFETY: NULL is the documented WinFsp volume-flush context sentinel.
    let context = unsafe { ContextRef::access(std::ptr::null_mut()) };
    assert!(context.0.is_none());
    assert_eq!(
        fixture.adapter.flush(context).unwrap_err(),
        STATUS_NOT_SUPPORTED
    );
}

#[test]
fn windows_security_queries_return_valid_restricted_descriptor() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let root = fixture
        .open("\\", FileAccessRights::FILE_READ_ATTRIBUTES)
        .unwrap();
    let (_, descriptor, reparse) = fs.get_security_by_name(&name("\\"), || None).unwrap();
    assert!(!reparse);
    let descriptor: SecurityDescriptor = descriptor.into();
    assert!(!descriptor.is_empty());
    assert_eq!(
        fs.set_security(root.clone(), 0, descriptor.as_ptr()),
        Err(STATUS_NOT_SUPPORTED)
    );
    fs.close(root);
}

#[test]
fn windows_nofollow_open_is_safe_on_regular_files_and_create_flags_are_validated() {
    let fixture = Fixture::new();
    fixture
        .adapter
        .close(fixture.create("\\regular.txt", false));
    let file = fixture
        .adapter
        .open(
            &name("\\regular.txt"),
            CreateOptions::FILE_NON_DIRECTORY_FILE | CreateOptions::FILE_OPEN_REPARSE_POINT,
            FileAccessRights::FILE_READ_DATA,
        )
        .unwrap()
        .0;
    fixture.adapter.close(file);
    let invalid = fixture.adapter.create(
        &name("\\must-not-exist"),
        CreateFileInfo {
            create_options: CreateOptions::FILE_DIRECTORY_FILE
                | CreateOptions::FILE_NON_DIRECTORY_FILE,
            granted_access: FileAccessRights::FILE_ALL_ACCESS,
            file_attributes: FileAttributes::NORMAL,
            allocation_size: 0,
        },
        fixture.adapter.descriptor.clone(),
    );
    assert!(matches!(invalid, Err(STATUS_INVALID_PARAMETER)));
    assert!(!fixture
        .adapter
        .fs
        .exists_by_name(ROOT_INODE, &secret("must-not-exist"))
        .unwrap());
}

#[test]
fn windows_write_is_visible_before_explicit_flush_and_after_overwrite() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\visible.txt", false);
    fs.write(file.clone(), b"abcdef", WriteMode::Normal { offset: 0 })
        .unwrap();
    let mut buffer = [0; 16];
    assert_eq!(fs.read(file.clone(), &mut buffer, 0).unwrap(), 6);
    assert_eq!(&buffer[..6], b"abcdef");
    let metadata = fixture
        .open("\\visible.txt", FileAccessRights::FILE_READ_ATTRIBUTES)
        .unwrap();
    assert_eq!(fs.get_file_info(metadata.clone()).unwrap().file_size(), 6);
    fs.overwrite(file.clone(), FileAttributes::NORMAL, true, 0)
        .unwrap();
    assert_eq!(fs.get_file_info(metadata.clone()).unwrap().file_size(), 0);
    assert_eq!(fs.read(file.clone(), &mut buffer, 0).unwrap(), 0);
    fs.write(file.clone(), b"new", WriteMode::WriteToEOF)
        .unwrap();
    assert_eq!(fs.read(file.clone(), &mut buffer, 0).unwrap(), 3);
    assert_eq!(&buffer[..3], b"new");
    fs.close(metadata);
    fs.close(file);
    let reader = fixture
        .open("\\visible.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    assert_eq!(fs.read(reader.clone(), &mut buffer, 0).unwrap(), 3);
    assert_eq!(&buffer[..3], b"new");
    fs.close(reader);
}

#[test]
fn windows_cleanup_allows_reopen_and_late_paging_io_before_close() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let original = fixture.create("\\cached.txt", false);
    fs.write(original.clone(), b"abc", WriteMode::Normal { offset: 0 })
        .unwrap();
    fs.cleanup(
        original.clone(),
        Some(&name("\\cached.txt")),
        CleanupFlags(0),
    );

    let reopened = fixture
        .open(
            "\\cached.txt",
            FileAccessRights::FILE_READ_DATA
                | FileAccessRights::FILE_WRITE_DATA
                | FileAccessRights::FILE_APPEND_DATA,
        )
        .unwrap();
    fs.write(reopened.clone(), b"d", WriteMode::WriteToEOF)
        .unwrap();
    let mut buffer = [0; 16];
    assert_eq!(fs.read(original.clone(), &mut buffer, 0).unwrap(), 4);
    assert_eq!(&buffer[..4], b"abcd");

    // WinFsp can issue paging writes through a cleaned context before Close.
    fs.write(original.clone(), b"Z", WriteMode::Normal { offset: 1 })
        .unwrap();
    assert_eq!(fs.read(reopened.clone(), &mut buffer, 0).unwrap(), 4);
    assert_eq!(&buffer[..4], b"aZcd");
    fs.close(original);
    fs.write(reopened.clone(), b"!", WriteMode::WriteToEOF)
        .unwrap();
    assert_eq!(fs.read(reopened.clone(), &mut buffer, 0).unwrap(), 5);
    assert_eq!(&buffer[..5], b"aZcd!");
    fs.cleanup(
        reopened.clone(),
        Some(&name("\\cached.txt")),
        CleanupFlags(0),
    );
    fs.close(reopened);

    let reader = fixture
        .open("\\cached.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    assert_eq!(fs.read(reader.clone(), &mut buffer, 0).unwrap(), 5);
    assert_eq!(&buffer[..5], b"aZcd!");
    fs.close(reader);
}

#[test]
fn windows_multiple_write_contexts_share_current_data_and_enforce_access() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let first = fixture.create("\\writers.txt", false);
    let second = fixture
        .open(
            "\\writers.txt",
            FileAccessRights::FILE_WRITE_DATA | FileAccessRights::FILE_APPEND_DATA,
        )
        .unwrap();
    let append_only = fixture
        .open("\\writers.txt", FileAccessRights::FILE_APPEND_DATA)
        .unwrap();

    fs.write(second.clone(), b"abc", WriteMode::Normal { offset: 0 })
        .unwrap();
    fs.write(first.clone(), b"!", WriteMode::WriteToEOF)
        .unwrap();
    fs.write(append_only.clone(), b"?", WriteMode::WriteToEOF)
        .unwrap();
    fs.write(second.clone(), b"XYZ", WriteMode::Normal { offset: 1 })
        .unwrap();
    let mut buffer = [0; 16];
    assert_eq!(fs.read(first.clone(), &mut buffer, 0).unwrap(), 5);
    assert_eq!(&buffer[..5], b"aXYZ?");
    assert_eq!(fs.read(second.clone(), &mut buffer, 0).unwrap(), 5);
    assert_eq!(&buffer[..5], b"aXYZ?");
    assert_eq!(fs.read(append_only.clone(), &mut buffer, 0).unwrap(), 5);
    assert_eq!(&buffer[..5], b"aXYZ?");
    assert_eq!(
        fs.write(append_only.clone(), b"bad", WriteMode::Normal { offset: 0 })
            .unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    fs.close(first);
    fs.write(second.clone(), b"!", WriteMode::WriteToEOF)
        .unwrap();
    assert_eq!(
        fs.get_file_info(append_only.clone()).unwrap().file_size(),
        6
    );
    fs.close(second);
    fs.close(append_only);
}

#[test]
fn windows_failed_write_does_not_block_later_writes() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let first = fixture.create("\\write-error.txt", false);
    assert_eq!(
        fs.write(
            first.clone(),
            b"x",
            WriteMode::Normal {
                offset: u64::MAX - 1,
            },
        )
        .unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(fs.get_file_info(first.clone()).unwrap().file_size(), 0);
    fs.write(first.clone(), b"safe", WriteMode::Normal { offset: 0 })
        .unwrap();
    let second = fixture
        .open("\\write-error.txt", FileAccessRights::FILE_WRITE_DATA)
        .unwrap();
    assert_eq!(
        fs.write(
            second.clone(),
            b"x",
            WriteMode::Normal {
                offset: u64::MAX - 1,
            },
        )
        .unwrap_err(),
        STATUS_INVALID_PARAMETER
    );
    fs.write(second.clone(), b"tail", WriteMode::WriteToEOF)
        .unwrap();
    let mut buffer = [0; 16];
    assert_eq!(fs.read(first.clone(), &mut buffer, 0).unwrap(), 8);
    assert_eq!(&buffer[..8], b"safetail");
    fs.close(first);
    fs.close(second);
}

#[test]
fn windows_delete_allows_cleaned_cached_readers_but_rejects_active_ones() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fixture.create("\\cached-delete.txt", false);
    let deleted_ino = file.ino;
    fs.write(file.clone(), b"cached", WriteMode::Normal { offset: 0 })
        .unwrap();
    let reader = fixture
        .open("\\cached-delete.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    assert_eq!(
        fs.set_delete(file.clone(), &name("\\cached-delete.txt"), true)
            .unwrap_err(),
        STATUS_SHARING_VIOLATION
    );
    fs.cleanup(
        reader.clone(),
        Some(&name("\\cached-delete.txt")),
        CleanupFlags(0),
    );
    let mut buffer = [0; 16];
    assert_eq!(fs.read(reader.clone(), &mut buffer, 0).unwrap(), 6);
    assert_eq!(&buffer[..6], b"cached");
    fs.set_delete(file.clone(), &name("\\cached-delete.txt"), true)
        .unwrap();
    assert!(fs
        .fs
        .exists_by_name(ROOT_INODE, &secret("cached-delete.txt"))
        .unwrap());
    fs.cleanup(
        file.clone(),
        Some(&name("\\cached-delete.txt")),
        CleanupFlags::DELETE,
    );
    assert!(!fs
        .fs
        .exists_by_name(ROOT_INODE, &secret("cached-delete.txt"))
        .unwrap());
    assert!(!fs.fs.exists(deleted_ino));
    assert_eq!(
        fs.get_file_info(reader.clone()).unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        fs.read(reader.clone(), &mut buffer, 0).unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        fs.set_basic_info(file.clone(), FileAttributes::NORMAL, 0, 0, 0, 0)
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        fs.set_file_size(file.clone(), 1, false).unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        fs.write(file.clone(), b"late", WriteMode::WriteToEOF)
            .unwrap_err(),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert!(!fs.fs.exists(deleted_ino));

    let replacement = fixture.create("\\cached-delete.txt", false);
    fs.write(
        replacement.clone(),
        b"replacement",
        WriteMode::Normal { offset: 0 },
    )
    .unwrap();
    fs.close(reader);
    fs.close(file);
    assert!(!fs.fs.exists(deleted_ino));
    assert_eq!(fs.read(replacement.clone(), &mut buffer, 0).unwrap(), 11);
    assert_eq!(&buffer[..11], b"replacement");
    fs.close(replacement);
}

#[test]
fn windows_context_registry_removes_closed_contexts_and_empty_inode_entries() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    assert!(fs.contexts(u64::MAX).is_empty());
    assert!(fs.opened.lock().unwrap().is_empty());

    let first = fixture.create("\\tracked.txt", false);
    let ino = first.ino;
    let retained_first = first.clone();
    let second = fixture
        .open("\\tracked.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    let retained_second = second.clone();
    assert_eq!(fs.contexts(ino).len(), 2);
    assert_eq!(fs.opened.lock().unwrap().len(), 1);

    fs.close(first);
    assert!(retained_first.closed.load(Ordering::Acquire));
    assert_eq!(fs.contexts(ino).len(), 1);
    assert_eq!(fs.opened.lock().unwrap().get(&ino).unwrap().len(), 1);

    fs.close(second);
    assert!(retained_second.closed.load(Ordering::Acquire));
    assert!(fs.opened.lock().unwrap().is_empty());
    assert!(fs.contexts(ino).is_empty());
    assert!(fs.opened.lock().unwrap().is_empty());
}

#[test]
fn windows_read_ahead_allows_repeated_reads_from_zero_after_eof() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let writer = fixture.create("\\readahead.txt", false);
    fs.write(writer.clone(), b"abcXYZ++", WriteMode::Normal { offset: 0 })
        .unwrap();
    fs.close(writer);
    let reader = fixture
        .open("\\readahead.txt", FileAccessRights::FILE_READ_DATA)
        .unwrap();
    let mut page = [0; 4096];
    assert_eq!(fs.read(reader.clone(), &mut page, 0).unwrap(), 8);
    assert_eq!(&page[..8], b"abcXYZ++");
    let mut exact = [0; 8];
    assert_eq!(fs.read(reader.clone(), &mut exact, 0).unwrap(), 8);
    assert_eq!(&exact, b"abcXYZ++");
    assert_eq!(fs.read(reader.clone(), &mut page, 7).unwrap(), 1);
    assert_eq!(page[0], b'+');
    assert_eq!(fs.read(reader.clone(), &mut page, 8).unwrap(), 0);
    assert_eq!(fs.read(reader.clone(), &mut exact, 0).unwrap(), 8);
    assert_eq!(&exact, b"abcXYZ++");
    fs.close(reader);
}

#[test]
fn windows_write_only_create_services_internal_reads_until_close() {
    let fixture = Fixture::new();
    let fs = &fixture.adapter;
    let file = fs
        .create(
            &name("\\write-only.txt"),
            CreateFileInfo {
                create_options: CreateOptions::FILE_NON_DIRECTORY_FILE,
                granted_access: FileAccessRights::FILE_WRITE_DATA,
                file_attributes: FileAttributes::NORMAL,
                allocation_size: 0,
            },
            fs.descriptor.clone(),
        )
        .unwrap()
        .0;
    fs.write(file.clone(), b"internal", WriteMode::Normal { offset: 0 })
        .unwrap();
    let mut page = [0; 4096];
    assert_eq!(fs.read(file.clone(), &mut page, 0).unwrap(), 8);
    assert_eq!(&page[..8], b"internal");
    fs.cleanup(
        file.clone(),
        Some(&name("\\write-only.txt")),
        CleanupFlags(0),
    );
    let mut exact = [0; 8];
    assert_eq!(fs.read(file.clone(), &mut exact, 0).unwrap(), 8);
    assert_eq!(&exact, b"internal");
    fs.close(file);
}
