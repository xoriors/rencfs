use crate::encryptedfs::HASH_DIR;
use crate::encryptedfs::LS_DIR;
use std::fs::File;
use std::future::Future;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::ToString;
use std::sync::{Arc, LazyLock};
use std::{fs, io};

use bincode::deserialize_from;
use secrecy::{ExposeSecret, SecretString};
use tempfile::NamedTempFile;
use thread_local::ThreadLocal;
use tokio::sync::Mutex;
use tracing_test::traced_test;

use crate::encryptedfs::write_all_bytes_to_fs;
use crate::encryptedfs::INODES_DIR;
use crate::encryptedfs::KEY_ENC_FILENAME;
use crate::encryptedfs::KEY_SALT_FILENAME;
use crate::encryptedfs::SECURITY_DIR;
use crate::encryptedfs::{
    Cipher, CreateFileAttr, DirectoryEntry, DirectoryEntryPlus, EncryptedFs, FileType, FsError,
    FsResult, PasswordProvider, CONTENTS_DIR, ROOT_INODE,
};
use crate::test_common::create_attr;
use crate::test_common::run_test;
use crate::test_common::TestSetup;
use crate::test_common::SETUP_RESULT;
use crate::{crypto, test_common};

static ROOT_INODE_STR: &str = "1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_write() {
    run_test(TestSetup { key: "test_write" }, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_file = SecretString::from_str("test-file").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        assert_eq!(
            data,
            test_common::read_to_string(
                fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                &fs,
            )
            .await
        );
        let attr = fs.get_inode(attr.ino).await.unwrap();
        assert_eq!(data.len() as u64, attr.size);

        // offset greater than current position
        let data = "37";
        let fh = fs.open(attr.ino, false, true).await.unwrap();
        write_all_bytes_to_fs(&fs, attr.ino, 5, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        assert_eq!(
            data,
            &test_common::read_to_string(
                fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                &fs,
            )
            .await[5..]
        );

        // offset after file end
        let data = "37";
        let fh = fs.open(attr.ino, false, true).await.unwrap();
        write_all_bytes_to_fs(&fs, attr.ino, 42, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        assert_eq!(
            format!("test-37{}37", "\0".repeat(35)),
            test_common::read_to_string(
                fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                &fs,
            )
            .await
        );

        // offset before current position, several blocks
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file_2,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42-37-42";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        let data1 = "01";
        write_all_bytes_to_fs(&fs, attr.ino, 5, data1.as_bytes(), fh)
            .await
            .unwrap();
        let data2 = "02";
        write_all_bytes_to_fs(&fs, attr.ino, 8, data2.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        assert_eq!(
            "test-01-02-42",
            &test_common::read_to_string(
                fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                &fs,
            )
            .await
        );

        // write before current position then write to the end, also check it preserves the content from
        // the first write to offset to end of the file
        let test_file_3 = SecretString::from_str("test-file-3").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file_3,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42-37";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        write_all_bytes_to_fs(&fs, attr.ino, 5, b"37", fh)
            .await
            .unwrap();
        write_all_bytes_to_fs(&fs, attr.ino, data.len() as u64, b"-42", fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let new_content = test_common::read_to_string(
            fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
            &fs,
        )
        .await;
        assert_eq!("test-37-37-42", new_content);

        let buf = [0; 0];
        let fh = fs.open(attr.ino, false, true).await.unwrap();
        assert!(matches!(
            fs.write(ROOT_INODE, 0, &buf, fh).await,
            Err(FsError::InvalidInodeType)
        ));
        assert!(matches!(
            fs.write(0, 0, &buf, fh).await,
            Err(FsError::InodeNotFound)
        ));
        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (fh, dir_attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_dir,
                create_attr(FileType::Directory),
                false,
                true,
            )
            .await
            .unwrap();
        assert!(matches!(
            fs.write(dir_attr.ino, 0, &buf, fh).await,
            Err(FsError::InvalidInodeType)
        ));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_read() {
    run_test(TestSetup { key: "test_read" }, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_test_file = SecretString::from_str("test-file").unwrap();
        let test_file = test_test_file;
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = b"test-42";
        let mut buf = [0; 7];
        write_all_bytes_to_fs(&fs, attr.ino, 0, data, fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(fs, attr.ino, 0, &mut buf, fh).await;
        assert_eq!(data, &buf);

        // larger buffer
        let len = fs.read(attr.ino, 0, &mut [0; 42], fh).await.unwrap();
        assert_eq!(len, 7);

        // offset
        let data = b"test-37";
        let mut buf = [0; 2];
        let fh = fs.open(attr.ino, false, true).await.unwrap();
        write_all_bytes_to_fs(&fs, attr.ino, 0, data, fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(fs, attr.ino, 5, &mut buf, fh).await;
        assert_eq!(b"37", &buf);

        // offset after file end
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        let len = fs.read(attr.ino, 42, &mut [0, 1], fh).await.unwrap();
        assert_eq!(len, 0);

        // if it picks up new value after a write after current read position
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file_2,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(fs, attr.ino, 0, &mut [0_u8; 1], fh).await;
        let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
        let new_data = "37";
        write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
            .await
            .unwrap();
        fs.flush(fh_2).await.unwrap();
        fs.release(fh_2).await.unwrap();
        let mut buf = [0_u8; 2];
        test_common::read_exact(fs, attr.ino, 5, &mut buf, fh).await;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it picks up new value after a write before current read position
        let test_file_3 = SecretString::from_str("test-file-3").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file_3,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42-37";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(fs, attr.ino, 8, &mut [0_u8; 1], fh).await;
        let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
        let new_data = "37";
        write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
            .await
            .unwrap();
        fs.flush(fh_2).await.unwrap();
        fs.release(fh_2).await.unwrap();
        let mut buf = [0_u8; 2];
        test_common::read_exact(fs, attr.ino, 5, &mut buf, fh).await;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it continues to read correctly after a write before current read position
        let test_file_4 = SecretString::from_str("test-file-4").unwrap();
        let (fh, attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_file_4,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        let data = "test-42-37";
        write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
            .await
            .unwrap();
        fs.flush(fh).await.unwrap();
        fs.release(fh).await.unwrap();
        let fh = fs.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(fs, attr.ino, 7, &mut [0_u8; 1], fh).await;
        let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
        let new_data = "37";
        write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
            .await
            .unwrap();
        fs.flush(fh_2).await.unwrap();
        fs.release(fh_2).await.unwrap();
        let mut buf = [0_u8; 2];
        test_common::read_exact(fs, attr.ino, 8, &mut buf, fh).await;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // invalid values
        let mut buf = [0; 0];
        assert!(matches!(
            fs.read(ROOT_INODE, 0, &mut buf, fh).await,
            Err(FsError::InvalidInodeType)
        ));
        assert!(matches!(
            fs.read(0, 0, &mut buf, fh).await,
            Err(FsError::InodeNotFound)
        ));
        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (fh, dir_attr) = fs
            .create_nod(
                ROOT_INODE,
                &test_dir,
                create_attr(FileType::Directory),
                true,
                false,
            )
            .await
            .unwrap();
        assert!(matches!(
            fs.read(dir_attr.ino, 0, &mut buf, fh).await,
            Err(FsError::InvalidInodeType)
        ));
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_truncate() {
    run_test(
        TestSetup {
            key: "test_truncate",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_file = SecretString::from_str("test-file").unwrap();
            let (fh, attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    true,
                )
                .await
                .unwrap();
            let data = "test-42";
            write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.flush(fh).await.unwrap();
            fs.release(fh).await.unwrap();

            // size increase, preserve opened writer content
            let fh = fs.open(attr.ino, false, true).await.unwrap();
            let data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 5, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.truncate(attr.ino, 10).await.unwrap();
            assert_eq!(10, fs.get_inode(attr.ino).await.unwrap().size);
            assert_eq!(
                format!("test-37{}", "\0".repeat(3)),
                test_common::read_to_string(
                    fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                    &fs,
                )
                .await
            );
            fs.release(fh).await.unwrap();

            // size doesn't change
            fs.truncate(attr.ino, 10).await.unwrap();
            assert_eq!(10, fs.get_inode(attr.ino).await.unwrap().size);
            assert_eq!(
                format!("test-37{}", "\0".repeat(3)),
                test_common::read_to_string(
                    fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                    &fs,
                )
                .await
            );

            // size decrease, preserve opened writer content
            let fh = fs.open(attr.ino, false, true).await.unwrap();
            let data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.truncate(attr.ino, 4).await.unwrap();
            assert_eq!(4, fs.get_inode(attr.ino).await.unwrap().size);
            assert_eq!(
                "37st",
                test_common::read_to_string(
                    fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                    &fs,
                )
                .await
            );
            fs.release(fh).await.unwrap();

            // size decrease to 0
            fs.truncate(attr.ino, 0).await.unwrap();
            assert_eq!(0, fs.get_inode(attr.ino).await.unwrap().size);
            assert_eq!(
                "".to_string(),
                test_common::read_to_string(
                    fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()),
                    &fs,
                )
                .await
            );
        },
    )
    .await
}

// todo: see why it fails on github
// called `Result::unwrap()` on an `Err` value: Io { source: Os { code: 2, kind: NotFound, message: "No such file or directory" }, backtrace: <disabled> }
// #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// #[traced_test]
async fn test_copy_file_range() {
    run_test(
        TestSetup {
            key: "test_copy_file_range",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_file_1 = SecretString::from_str("test-file-1").unwrap();
            let (fh, attr_1) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file_1,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .unwrap();
            let data = "test-42";
            write_all_bytes_to_fs(fs, attr_1.ino, 0, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.flush(fh).await.unwrap();
            fs.release(fh).await.unwrap();
            let fh = fs.open(attr_1.ino, true, false).await.unwrap();
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (fh2, attr_2) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file_2,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .unwrap();

            // whole file
            test_common::copy_all_file_range(fs, attr_1.ino, 0, attr_2.ino, 0, 7, fh, fh2).await;
            fs.flush(fh2).await.unwrap();
            fs.release(fh2).await.unwrap();
            let mut buf = [0; 7];
            let fh = fs.open(attr_2.ino, true, false).await.unwrap();
            test_common::read_exact(fs, attr_2.ino, 0, &mut buf, fh).await;
            assert_eq!(data, String::from_utf8(buf.to_vec()).unwrap());

            // offset
            let data_37 = "37";
            let fh = fs.open(attr_1.ino, false, true).await.unwrap();
            write_all_bytes_to_fs(&fs, attr_1.ino, 7, data_37.as_bytes(), fh)
                .await
                .unwrap();
            fs.flush(fh).await.unwrap();
            fs.release(fh).await.unwrap();
            let fh = fs.open(attr_1.ino, true, false).await.unwrap();
            let fh_2 = fs.open(attr_2.ino, false, true).await.unwrap();
            test_common::copy_all_file_range(fs, attr_1.ino, 7, attr_2.ino, 5, 2, fh, fh_2).await;
            fs.flush(fh_2).await.unwrap();
            fs.release(fh_2).await.unwrap();
            let fh = fs.open(attr_2.ino, true, false).await.unwrap();
            test_common::read_exact(fs, attr_2.ino, 0, &mut buf, fh).await;
            assert_eq!("test-37", String::from_utf8(buf.to_vec()).unwrap());

            // out of bounds
            let fh = fs.open(attr_1.ino, true, false).await.unwrap();
            let fh_2 = fs.open(attr_2.ino, false, true).await.unwrap();
            let len = fs
                .copy_file_range(attr_1.ino, 42, attr_2.ino, 0, 2, fh, fh_2)
                .await
                .unwrap();
            assert_eq!(len, 0);

            // invalid inodes
            assert!(matches!(
                fs.copy_file_range(0, 0, 0, 0, 0, fh, fh_2).await,
                Err(FsError::InodeNotFound)
            ));
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_read_dir() {
    run_test(
        TestSetup {
            key: "test_read_dir",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            // file and directory in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_dir = SecretString::from_str("test-dir").unwrap();
            let (_fh, dir_attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntry>> =
                fs.read_dir(dir_attr.ino, 0).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(
                vec![
                    DirectoryEntry {
                        ino: dir_attr.ino,
                        name: SecretString::from_str(".").unwrap(),
                        kind: FileType::Directory,
                    },
                    DirectoryEntry {
                        ino: ROOT_INODE,
                        name: SecretString::from_str("..").unwrap(),
                        kind: FileType::Directory,
                    },
                ],
                entries
            );

            let iter = fs.read_dir(ROOT_INODE, 0).await.unwrap();
            let mut entries: Vec<FsResult<DirectoryEntry>> = iter.into_iter().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
            let mut sample = vec![
                DirectoryEntry {
                    ino: ROOT_INODE,
                    name: SecretString::from_str(".").unwrap(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: file_attr.ino,
                    name: test_file.clone(),
                    kind: FileType::RegularFile,
                },
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: test_dir.clone(),
                    kind: FileType::Directory,
                },
            ];
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            assert_eq!(entries.len(), 3);
            assert_eq!(sample, entries);

            // file and directory in another directory
            let parent = dir_attr.ino;
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (_fh, file_attr) = fs
                .create_nod(
                    parent,
                    &test_file_2,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
            let (_fh, dir_attr) = fs
                .create_nod(
                    parent,
                    &test_dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntry>> =
                fs.read_dir(dir_attr.ino, 0).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(
                vec![
                    DirectoryEntry {
                        ino: dir_attr.ino,
                        name: SecretString::from_str(".").unwrap(),
                        kind: FileType::Directory,
                    },
                    DirectoryEntry {
                        ino: parent,
                        name: SecretString::from_str("..").unwrap(),
                        kind: FileType::Directory,
                    },
                ],
                entries
            );

            let iter = fs.read_dir(parent, 0).await.unwrap();
            let mut entries: Vec<DirectoryEntry> = iter.map(|e| e.unwrap()).collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            let mut sample = vec![
                DirectoryEntry {
                    ino: parent,
                    name: SecretString::from_str(".").unwrap(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: ROOT_INODE,
                    name: SecretString::from_str("..").unwrap(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: file_attr.ino,
                    name: test_file_2.clone(),
                    kind: FileType::RegularFile,
                },
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: test_dir_2.clone(),
                    kind: FileType::Directory,
                },
            ];
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            assert_eq!(entries.len(), 4);
            assert_eq!(sample, entries);
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_read_dir_plus() {
    run_test(
        TestSetup {
            key: "test_read_dir_plus",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            // file and directory in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_dir = SecretString::from_str("test-dir").unwrap();
            let (_fh, dir_attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntryPlus>> =
                fs.read_dir_plus(dir_attr.ino, 0).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(|e| e.unwrap()).collect();
            assert_eq!(entries.len(), 2);
            let attr_root = fs.get_inode(ROOT_INODE).await.unwrap();
            assert_eq!(
                vec![
                    DirectoryEntryPlus {
                        ino: dir_attr.ino,
                        name: SecretString::from_str(".").unwrap(),
                        kind: FileType::Directory,
                        attr: dir_attr,
                    },
                    DirectoryEntryPlus {
                        ino: ROOT_INODE,
                        name: SecretString::from_str("..").unwrap(),
                        kind: FileType::Directory,
                        attr: attr_root,
                    },
                ],
                entries
            );

            let iter = fs.read_dir_plus(ROOT_INODE, 0).await.unwrap();
            let mut entries: Vec<FsResult<DirectoryEntryPlus>> = iter.into_iter().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(|e| e.unwrap()).collect();
            let mut sample = vec![
                DirectoryEntryPlus {
                    ino: ROOT_INODE,
                    name: SecretString::from_str(".").unwrap(),
                    kind: FileType::Directory,
                    attr: attr_root,
                },
                DirectoryEntryPlus {
                    ino: file_attr.ino,
                    name: test_file.clone(),
                    kind: FileType::RegularFile,
                    attr: file_attr,
                },
                DirectoryEntryPlus {
                    ino: dir_attr.ino,
                    name: test_dir.clone(),
                    kind: FileType::Directory,
                    attr: dir_attr,
                },
            ];
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            assert_eq!(entries.len(), 3);
            assert_eq!(sample, entries);

            // file and directory in another directory
            let parent = dir_attr.ino;
            let attr_parent = dir_attr;
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (_fh, file_attr) = fs
                .create_nod(
                    parent,
                    &test_file_2,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
            let (_fh, dir_attr) = fs
                .create_nod(
                    parent,
                    &test_dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            // for some reason the tv_nsec is not the same between what create_nod() and read_dir_plus() returns, so we reload it again
            let dir_attr = fs.get_inode(dir_attr.ino).await.unwrap();
            let attr_parent = fs.get_inode(attr_parent.ino).await.unwrap();
            let mut entries: Vec<FsResult<DirectoryEntryPlus>> =
                fs.read_dir_plus(dir_attr.ino, 0).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(|e| e.unwrap()).collect();
            assert_eq!(entries.len(), 2);
            assert_eq!(
                vec![
                    DirectoryEntryPlus {
                        ino: dir_attr.ino,
                        name: SecretString::from_str(".").unwrap(),
                        kind: FileType::Directory,
                        attr: dir_attr,
                    },
                    DirectoryEntryPlus {
                        ino: parent,
                        name: SecretString::from_str("..").unwrap(),
                        kind: FileType::Directory,
                        attr: attr_parent,
                    },
                ],
                entries
            );

            let iter = fs.read_dir_plus(parent, 0).await.unwrap();
            let mut entries: Vec<DirectoryEntryPlus> = iter.map(|e| e.unwrap()).collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            let mut sample = vec![
                DirectoryEntryPlus {
                    ino: parent,
                    name: SecretString::from_str(".").unwrap(),
                    kind: FileType::Directory,
                    attr: attr_parent,
                },
                DirectoryEntryPlus {
                    ino: ROOT_INODE,
                    name: SecretString::from_str("..").unwrap(),
                    kind: FileType::Directory,
                    attr: attr_root,
                },
                DirectoryEntryPlus {
                    ino: file_attr.ino,
                    name: test_file_2.clone(),
                    kind: FileType::RegularFile,
                    attr: file_attr,
                },
                DirectoryEntryPlus {
                    ino: dir_attr.ino,
                    name: test_dir_2.clone(),
                    kind: FileType::Directory,
                    attr: dir_attr,
                },
            ];
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
            assert_eq!(entries.len(), 4);
            assert_eq!(sample, entries);
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_find_by_name() {
    run_test(
        TestSetup {
            key: "test_find_by_name",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            assert_eq!(
                Some(file_attr),
                fs.find_by_name(ROOT_INODE, &test_file).await.unwrap()
            );
            assert_eq!(
                None,
                fs.find_by_name(ROOT_INODE, &SecretString::from_str("42").unwrap())
                    .await
                    .unwrap()
            );
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_exists_by_name() {
    run_test(
        TestSetup {
            key: "test_exists_by_name",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_file = SecretString::from_str("test-file").unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            assert_eq!(
                false,
                (fs.exists_by_name(ROOT_INODE, &SecretString::from_str("42").unwrap())
                    .unwrap())
            );
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_remove_dir() {
    run_test(
        TestSetup {
            key: "test_remove_dir",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_dir = SecretString::from_str("test-dir").unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();

            assert!(fs.exists_by_name(ROOT_INODE, &test_dir).unwrap());
            fs.delete_dir(ROOT_INODE, &test_dir).await.unwrap();
            assert_eq!(false, fs.exists_by_name(ROOT_INODE, &test_dir).unwrap());
            assert_eq!(None, fs.find_by_name(ROOT_INODE, &test_dir).await.unwrap());
            assert_eq!(
                0,
                fs.read_dir(ROOT_INODE, 0)
                    .await
                    .unwrap()
                    .filter(|entry| {
                        entry.as_ref().unwrap().name.expose_secret() == test_dir.expose_secret()
                    })
                    .count()
            )
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_remove_file() {
    run_test(
        TestSetup {
            key: "test_remove_file",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            let test_file = SecretString::from_str("test-file").unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            fs.delete_file(ROOT_INODE, &test_file).await.unwrap();
            assert_eq!(false, fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            assert_eq!(None, fs.find_by_name(ROOT_INODE, &test_file).await.unwrap());
            assert_eq!(
                0,
                fs.read_dir(ROOT_INODE, 0)
                    .await
                    .unwrap()
                    .filter(|entry| {
                        entry.as_ref().unwrap().name.expose_secret() == test_file.expose_secret()
                    })
                    .count()
            )
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_find_by_name_exists_by_name100files() {
    run_test(
        TestSetup {
            key: "test_find_by_name_exists_by_name_many_files",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            for i in 0..100 {
                let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
                let _ = fs
                    .create_nod(
                        ROOT_INODE,
                        &test_file,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();
            }

            let test_file = SecretString::from_str("test-file-42").unwrap();
            assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            assert!(matches!(
                fs.find_by_name(ROOT_INODE, &test_file).await.unwrap(),
                Some(_)
            ));
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_create_structure_and_root() {
    run_test(TestSetup { key: "test_sample" }, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        assert!(fs.node_exists(ROOT_INODE));
        assert!(fs.is_dir(ROOT_INODE));

        assert!(fs.data_dir.join(INODES_DIR).is_dir());
        assert!(fs.data_dir.join(CONTENTS_DIR).is_dir());
        assert!(fs.data_dir.join(SECURITY_DIR).is_dir());
        assert!(fs
            .data_dir
            .join(SECURITY_DIR)
            .join(KEY_ENC_FILENAME)
            .is_file());
        assert!(fs
            .data_dir
            .join(SECURITY_DIR)
            .join(KEY_SALT_FILENAME)
            .is_file());

        assert!(fs.data_dir.join(INODES_DIR).join(ROOT_INODE_STR).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).is_dir());
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_create_nod() {
    run_test(
        TestSetup {
            key: "test_create_nod",
        },
        async {
            let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut fs = fs.lock().await;
            let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

            // file in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (fh, attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    true,
                    false,
                )
                .await
                .unwrap();
            assert_ne!(fh, 0);
            assert_ne!(attr.ino, 0);
            assert!(fs
                .data_dir
                .join(INODES_DIR)
                .join(attr.ino.to_string())
                .is_file());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(attr.ino.to_string())
                .is_file());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(ROOT_INODE_STR)
                .join(HASH_DIR)
                .join(crypto::hash_file_name(&test_file))
                .is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).await.unwrap());

            let entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(ROOT_INODE_STR)
                        .join(LS_DIR)
                        .join(crypto::hash_file_name(&test_file)),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::RegularFile));

            // directory in root
            let test_dir = SecretString::from_str("test-dir").unwrap();
            let (_fh, attr) = fs
                .create_nod(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            assert_ne!(attr.ino, 0);
            assert!(fs
                .data_dir
                .join(INODES_DIR)
                .join(attr.ino.to_string())
                .is_file());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(attr.ino.to_string())
                .is_dir());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(ROOT_INODE_STR)
                .join(HASH_DIR)
                .join(crypto::hash_file_name(&test_dir))
                .is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).await.unwrap());
            assert!(fs.is_dir(attr.ino));
            let entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(ROOT_INODE_STR)
                        .join(LS_DIR)
                        .join(crypto::hash_file_name(&test_dir)),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
            let dot_entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(attr.ino.to_string())
                        .join(LS_DIR)
                        .join("$."),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
            let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(attr.ino.to_string())
                        .join(LS_DIR)
                        .join("$.."),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(dot_dot_entry_in_parent, (ROOT_INODE, FileType::Directory));

            // directory in another directory
            let parent = attr.ino;
            let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
            let (_fh, attr) = fs
                .create_nod(
                    parent,
                    &test_dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            assert!(fs
                .data_dir
                .join(INODES_DIR)
                .join(attr.ino.to_string())
                .is_file());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(attr.ino.to_string())
                .is_dir());
            assert!(fs
                .data_dir
                .join(CONTENTS_DIR)
                .join(parent.to_string())
                .join(HASH_DIR)
                .join(crypto::hash_file_name(&test_dir_2))
                .is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).await.unwrap());
            assert!(fs.is_dir(attr.ino));
            let entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(parent.to_string())
                        .join(LS_DIR)
                        .join(crypto::hash_file_name(&test_dir_2)),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
            let dot_entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(attr.ino.to_string())
                        .join(LS_DIR)
                        .join("$."),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
            let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(
                File::open(
                    fs.data_dir
                        .join(CONTENTS_DIR)
                        .join(attr.ino.to_string())
                        .join(LS_DIR)
                        .join("$.."),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(dot_dot_entry_in_parent, (parent, FileType::Directory));

            // existing file
            assert!(matches!(
                fs.create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false
                )
                .await,
                Err(FsError::AlreadyExists)
            ));

            // existing directory
            assert!(matches!(
                fs.create_nod(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false
                )
                .await,
                Err(FsError::AlreadyExists)
            ));
        },
    )
    .await
}

// #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// #[traced_test]
async fn test_sample() {
    run_test(TestSetup { key: "test_sample" }, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();
    })
    .await
}
