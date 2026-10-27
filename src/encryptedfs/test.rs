use std::str::FromStr;
use std::string::ToString;
use std::time::SystemTime;

use shush_rs::{ExposeSecret, SecretString};
use tracing_test::traced_test;

use crate::crypto::Cipher;
use crate::encryptedfs::write_all_bytes_to_fs;
use crate::encryptedfs::INODES_DIR;
use crate::encryptedfs::KEY_ENC_FILENAME;
use crate::encryptedfs::KEY_SALT_FILENAME;
use crate::encryptedfs::SECURITY_DIR;
use crate::encryptedfs::{CopyFileRangeReq, HASH_DIR};
use crate::encryptedfs::{
    DirectoryEntry, DirectoryEntryPlus, EncryptedFs, FileType, FsError, FsResult, SetFileAttr,
    CONTENTS_DIR, ROOT_INODE,
};
use crate::test_common::run_test;
use crate::test_common::TestSetup;
use crate::test_common::{create_attr, get_fs, PasswordProviderImpl};
use crate::{crypto, test_common};

static ROOT_INODE_STR: &str = "1";

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_write() {
    run_test(
        TestSetup {
            key: "test_write",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_file = SecretString::from_str("test-file").unwrap();
            let (fh, attr) = fs
                .create(
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
            assert_eq!(data, test_common::read_to_string(attr.ino, &fs,).await);
            let attr = fs.get_attr(attr.ino).await.unwrap();
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
                &test_common::read_to_string(attr.ino, &fs,).await[5..]
            );

            // offset after the file end
            let data = "37";
            let fh = fs.open(attr.ino, false, true).await.unwrap();
            write_all_bytes_to_fs(&fs, attr.ino, 42, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.flush(fh).await.unwrap();
            fs.release(fh).await.unwrap();
            assert_eq!(
                format!("test-37{}37", "\0".repeat(35)),
                test_common::read_to_string(attr.ino, &fs,).await
            );

            // offset before current position, several blocks
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (fh, attr) = fs
                .create(
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
                &test_common::read_to_string(attr.ino, &fs,).await
            );

            // write before current position then write to the end, also check it preserves the content from
            // the first write to offset to end of the file
            let test_file_3 = SecretString::from_str("test-file-3").unwrap();
            let (fh, attr) = fs
                .create(
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
            let new_content = test_common::read_to_string(attr.ino, &fs).await;
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
                .create(
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
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
// #[ignore]
async fn test_read() {
    run_test(
        TestSetup {
            key: "test_read",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_test_file = SecretString::from_str("test-file").unwrap();
            let test_file = test_test_file;
            let (fh, attr) = fs
                .create(
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
            test_common::read_exact(&fs, attr.ino, 0, &mut buf, fh).await;
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
            test_common::read_exact(&fs, attr.ino, 5, &mut buf, fh).await;
            assert_eq!(b"37", &buf);

            // offset after file end
            let fh = fs.open(attr.ino, true, false).await.unwrap();
            let len = fs.read(attr.ino, 42, &mut [0, 1], fh).await.unwrap();
            assert_eq!(len, 0);

            // if it picks up new value after a write after current read position
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (fh, attr) = fs
                .create(
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
            test_common::read_exact(&fs, attr.ino, 0, &mut [0_u8; 1], fh).await;
            let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
            let new_data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
                .await
                .unwrap();
            fs.flush(fh_2).await.unwrap();
            fs.release(fh_2).await.unwrap();
            let mut buf = [0_u8; 2];
            test_common::read_exact(&fs, attr.ino, 5, &mut buf, fh).await;
            assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

            // if it picks up new value after a write before current read position
            let test_file_3 = SecretString::from_str("test-file-3").unwrap();
            let (fh, attr) = fs
                .create(
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
            test_common::read_exact(&fs, attr.ino, 8, &mut [0_u8; 1], fh).await;
            let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
            let new_data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
                .await
                .unwrap();
            fs.flush(fh_2).await.unwrap();
            fs.release(fh_2).await.unwrap();
            let mut buf = [0_u8; 2];
            test_common::read_exact(&fs, attr.ino, 5, &mut buf, fh).await;
            assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

            // if it continues to read correctly after a write before current read position
            let test_file_4 = SecretString::from_str("test-file-4").unwrap();
            let (fh, attr) = fs
                .create(
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
            test_common::read_exact(&fs, attr.ino, 7, &mut [0_u8; 1], fh).await;
            let fh_2 = fs.open(attr.ino, false, true).await.unwrap();
            let new_data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 5, new_data.as_bytes(), fh_2)
                .await
                .unwrap();
            fs.flush(fh_2).await.unwrap();
            fs.release(fh_2).await.unwrap();
            let mut buf = [0_u8; 2];
            test_common::read_exact(&fs, attr.ino, 8, &mut buf, fh).await;
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
                .create(
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
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
// #[ignore]
async fn test_set_len() {
    run_test(
        TestSetup {
            key: "test_set_len",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_file = SecretString::from_str("test-file").unwrap();
            let (fh, attr) = fs
                .create(
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
            fs.set_len(attr.ino, 10).await.unwrap();
            assert_eq!(10, fs.get_attr(attr.ino).await.unwrap().size);
            assert_eq!(
                format!("test-37{}", "\0".repeat(3)),
                test_common::read_to_string(attr.ino, &fs,).await
            );
            fs.release(fh).await.unwrap();

            // size doesn't change
            fs.set_len(attr.ino, 10).await.unwrap();
            assert_eq!(10, fs.get_attr(attr.ino).await.unwrap().size);
            assert_eq!(
                format!("test-37{}", "\0".repeat(3)),
                test_common::read_to_string(attr.ino, &fs,).await
            );

            // size decrease, preserve opened writer content
            let fh = fs.open(attr.ino, false, true).await.unwrap();
            let data = "37";
            write_all_bytes_to_fs(&fs, attr.ino, 0, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.set_len(attr.ino, 4).await.unwrap();
            assert_eq!(4, fs.get_attr(attr.ino).await.unwrap().size);
            assert_eq!("37st", test_common::read_to_string(attr.ino, &fs,).await);
            fs.release(fh).await.unwrap();

            // size decrease to 0
            fs.set_len(attr.ino, 0).await.unwrap();
            assert_eq!(0, fs.get_attr(attr.ino).await.unwrap().size);
            assert_eq!(
                String::new(),
                test_common::read_to_string(attr.ino, &fs,).await
            );
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_copy_file_range() {
    run_test(
        TestSetup {
            key: "test_copy_file_range",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_file_1 = SecretString::from_str("test-file-1").unwrap();
            let (fh, attr_1) = fs
                .create(
                    ROOT_INODE,
                    &test_file_1,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .unwrap();
            let data = "test-42";
            write_all_bytes_to_fs(&fs, attr_1.ino, 0, data.as_bytes(), fh)
                .await
                .unwrap();
            fs.flush(fh).await.unwrap();
            fs.release(fh).await.unwrap();
            let fh = fs.open(attr_1.ino, true, false).await.unwrap();
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (fh2, attr_2) = fs
                .create(
                    ROOT_INODE,
                    &test_file_2,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .unwrap();

            // whole file
            test_common::copy_all_file_range(&fs, attr_1.ino, 0, attr_2.ino, 0, 7, fh, fh2).await;
            fs.flush(fh2).await.unwrap();
            fs.release(fh2).await.unwrap();
            let mut buf = [0; 7];
            let fh = fs.open(attr_2.ino, true, false).await.unwrap();
            test_common::read_exact(&fs, attr_2.ino, 0, &mut buf, fh).await;
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
            test_common::copy_all_file_range(&fs, attr_1.ino, 7, attr_2.ino, 5, 2, fh, fh_2).await;
            fs.flush(fh_2).await.unwrap();
            fs.release(fh_2).await.unwrap();
            let fh = fs.open(attr_2.ino, true, false).await.unwrap();
            test_common::read_exact(&fs, attr_2.ino, 0, &mut buf, fh).await;
            assert_eq!("test-37", String::from_utf8(buf.to_vec()).unwrap());

            // out of bounds
            let fh = fs.open(attr_1.ino, true, false).await.unwrap();
            let fh_2 = fs.open(attr_2.ino, false, true).await.unwrap();
            let file_range_req = CopyFileRangeReq::builder()
                .src_ino(attr_1.ino)
                .src_offset(42)
                .dest_ino(attr_2.ino)
                .dest_offset(0)
                .src_fh(fh)
                .dest_fh(fh_2)
                .build();
            let size = 2;
            let len = fs.copy_file_range(&file_range_req, size).await.unwrap();
            assert_eq!(len, 0);

            let size = 0;
            let file_range_req = CopyFileRangeReq::builder()
                .src_ino(0)
                .src_offset(0)
                .dest_ino(0)
                .dest_offset(0)
                .src_fh(fh)
                .dest_fh(fh_2)
                .build();
            // invalid inodes
            assert!(matches!(
                fs.copy_file_range(&file_range_req, size).await,
                Err(FsError::InodeNotFound)
            ));
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_read_dir() {
    run_test(
        TestSetup {
            key: "test_read_dir",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            // file and directory in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create(
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
                .create(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntry>> =
                fs.read_dir(dir_attr.ino).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(Result::unwrap).collect();
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

            let mut entries: Vec<FsResult<DirectoryEntry>> =
                fs.read_dir(ROOT_INODE).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(Result::unwrap).collect();
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
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(entries.len(), 3);
            assert_eq!(sample, entries);

            // file and directory in another directory
            let parent = dir_attr.ino;
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (_fh, file_attr) = fs
                .create(
                    parent,
                    &test_file_2,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_file_3 = SecretString::from_str("test_file_3").unwrap();
            let (_fh, file_attr_2) = fs
                .create(
                    parent,
                    &test_file_3,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_dir_2 = SecretString::from_str("test_dir_2").unwrap();
            let (_fh, dir_attr) = fs
                .create(
                    parent,
                    &test_dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntry>> =
                fs.read_dir(dir_attr.ino).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntry> = entries.into_iter().map(Result::unwrap).collect();
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

            let iter = fs.read_dir(parent).await.unwrap();
            let mut entries: Vec<DirectoryEntry> = iter.map(Result::unwrap).collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
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
                    ino: file_attr_2.ino,
                    name: test_file_3.clone(),
                    kind: FileType::RegularFile,
                },
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: test_dir_2.clone(),
                    kind: FileType::Directory,
                },
            ];
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(entries.len(), 5);
            assert_eq!(sample, entries);
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_read_dir_plus() {
    run_test(
        TestSetup {
            key: "test_read_dir_plus",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            // file and directory in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create(
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
                .create(
                    ROOT_INODE,
                    &test_dir,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let mut entries: Vec<FsResult<DirectoryEntryPlus>> =
                fs.read_dir_plus(dir_attr.ino).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(Result::unwrap).collect();
            assert_eq!(entries.len(), 2);
            let attr_root = fs.get_attr(ROOT_INODE).await.unwrap();
            // reload it as atime is changed on read_dir*()
            let dir_attr = fs.get_attr(dir_attr.ino).await.unwrap();
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

            let mut entries: Vec<FsResult<DirectoryEntryPlus>> =
                fs.read_dir_plus(ROOT_INODE).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(Result::unwrap).collect();
            // reload it as atime is changed on read_dir*()
            let attr_root = fs.get_attr(ROOT_INODE).await.unwrap();
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
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(entries.len(), 3);
            assert_eq!(sample, entries);

            // file and directory in another directory
            let parent = dir_attr.ino;
            let attr_parent = dir_attr;
            let test_file_2 = SecretString::from_str("test-file-2").unwrap();
            let (_fh, file_attr) = fs
                .create(
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
                .create(
                    parent,
                    &test_dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let attr_parent = fs.get_attr(attr_parent.ino).await.unwrap();
            let mut entries: Vec<FsResult<DirectoryEntryPlus>> =
                fs.read_dir_plus(dir_attr.ino).await.unwrap().collect();
            entries.sort_by(|a, b| {
                a.as_ref()
                    .unwrap()
                    .name
                    .expose_secret()
                    .cmp(&*b.as_ref().unwrap().name.expose_secret())
            });
            let entries: Vec<DirectoryEntryPlus> =
                entries.into_iter().map(Result::unwrap).collect();
            // reload it as atime is changed on read_dir*()
            let dir_attr = fs.get_attr(dir_attr.ino).await.unwrap();
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

            let iter = fs.read_dir_plus(parent).await.unwrap();
            let mut entries: Vec<DirectoryEntryPlus> = iter.map(Result::unwrap).collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            // reload it as atime is changed on read_dir*()
            let attr_parent = fs.get_attr(attr_parent.ino).await.unwrap();
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
            sample.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(entries.len(), 4);
            assert_eq!(sample, entries);
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_find_by_name() {
    run_test(
        TestSetup {
            key: "test_find_by_name",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, file_attr) = fs
                .create(
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
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_exists_by_name() {
    run_test(
        TestSetup {
            key: "test_exists_by_name",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            for file in ["test-file", "test--file"] {
                let test_file = SecretString::from_str(file).unwrap();
                let _ = fs
                    .create(
                        ROOT_INODE,
                        &test_file,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();

                assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
                assert!(
                    !(fs.exists_by_name(ROOT_INODE, &SecretString::from_str("42").unwrap())
                        .unwrap())
                );
            }
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_remove_dir() {
    run_test(
        TestSetup {
            key: "test_remove_dir",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            for dir in ["test-dir", "test-dir_", "test-dir-"] {
                let test_dir = SecretString::from_str(dir).unwrap();
                let _ = fs
                    .create(
                        ROOT_INODE,
                        &test_dir,
                        create_attr(FileType::Directory),
                        false,
                        false,
                    )
                    .await
                    .unwrap();

                assert!(fs.exists_by_name(ROOT_INODE, &test_dir).unwrap());
                fs.remove_dir(ROOT_INODE, &test_dir).await.unwrap();
                assert!(!fs.exists_by_name(ROOT_INODE, &test_dir).unwrap());
                assert_eq!(None, fs.find_by_name(ROOT_INODE, &test_dir).await.unwrap());
                assert_eq!(
                    0,
                    fs.read_dir(ROOT_INODE)
                        .await
                        .unwrap()
                        .filter(|entry| {
                            entry.as_ref().unwrap().name.expose_secret() == test_dir.expose_secret()
                        })
                        .count()
                );
            }
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_remove_file() {
    run_test(
        TestSetup {
            key: "test_remove_file",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            for dir in ["test-dir", "test-dir_", "test-dir-clear"] {
                let test_file = SecretString::from_str(dir).unwrap();
                let _ = fs
                    .create(
                        ROOT_INODE,
                        &test_file,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();

                assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
                fs.remove_file(ROOT_INODE, &test_file).await.unwrap();
                assert!(!fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
                assert_eq!(None, fs.find_by_name(ROOT_INODE, &test_file).await.unwrap());
                assert_eq!(
                    0,
                    fs.read_dir(ROOT_INODE)
                        .await
                        .unwrap()
                        .filter(|entry| {
                            entry.as_ref().unwrap().name.expose_secret()
                                == test_file.expose_secret()
                        })
                        .count()
                );
            }
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_find_by_name_exists_by_name100files() {
    run_test(
        TestSetup {
            key: "test_find_by_name_exists_by_name_many_files",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            for i in 0..100 {
                let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
                let _ = fs
                    .create(
                        ROOT_INODE,
                        &test_file,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();
            }

            let special_test_file = SecretString::from_str("test-_file").unwrap();
            let _ = fs
                .create(
                    ROOT_INODE,
                    &special_test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();

            let test_file = SecretString::from_str("test-file-42").unwrap();
            assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            assert!(fs
                .find_by_name(ROOT_INODE, &test_file)
                .await
                .unwrap()
                .is_some());

            assert!(fs.exists_by_name(ROOT_INODE, &special_test_file).unwrap());
            assert!(fs
                .find_by_name(ROOT_INODE, &special_test_file)
                .await
                .unwrap()
                .is_some());
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_create_structure_and_root() {
    run_test(
        TestSetup {
            key: "test_sample",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            assert!(fs.exists(ROOT_INODE));
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
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_create() {
    run_test(
        TestSetup {
            key: "test_create",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            // file in root
            let test_file = SecretString::from_str("test-file").unwrap();
            let (fh, attr) = fs
                .create(
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
            assert!(fs.exists(attr.ino));
            assert_eq!(attr, fs.get_attr(attr.ino).await.unwrap());
            let mut entries: Vec<DirectoryEntryPlus> = fs
                .read_dir_plus(ROOT_INODE)
                .await
                .unwrap()
                .map(Result::unwrap)
                .collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(attr, entries[1].attr);
            assert!(fs.exists_by_name(ROOT_INODE, &test_file).unwrap());
            assert_eq!(
                attr,
                fs.find_by_name(ROOT_INODE, &test_file)
                    .await
                    .unwrap()
                    .unwrap()
            );

            // directory in root
            let test_dir = SecretString::from_str("test-dir").unwrap();
            let (_fh, attr) = fs
                .create(
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
            assert!(fs.exists(attr.ino));
            assert_eq!(attr, fs.get_attr(attr.ino).await.unwrap());
            assert!(fs.is_dir(attr.ino));
            let mut entries: Vec<DirectoryEntryPlus> = fs
                .read_dir_plus(ROOT_INODE)
                .await
                .unwrap()
                .map(Result::unwrap)
                .collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(ROOT_INODE, entries[0].attr.ino);
            assert_eq!(attr, entries[1].attr);
            assert!(fs.exists_by_name(ROOT_INODE, &test_dir).unwrap());
            assert_eq!(
                attr,
                fs.find_by_name(ROOT_INODE, &test_dir)
                    .await
                    .unwrap()
                    .unwrap()
            );

            // directory in another directory
            let parent = attr.ino;
            let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
            let (_fh, attr) = fs
                .create(
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
            assert!(fs.exists(attr.ino));
            assert_eq!(attr, fs.get_attr(attr.ino).await.unwrap());
            assert!(fs.is_dir(attr.ino));
            let mut entries: Vec<DirectoryEntryPlus> = fs
                .read_dir_plus(parent)
                .await
                .unwrap()
                .map(Result::unwrap)
                .collect();
            entries.sort_by(|a, b| a.name.expose_secret().cmp(&*b.name.expose_secret()));
            assert_eq!(attr, entries[2].attr);
            assert_eq!(parent, entries[0].attr.ino);
            assert!(fs.exists_by_name(parent, &test_dir_2).unwrap());
            assert_eq!(
                attr,
                fs.find_by_name(parent, &test_dir_2).await.unwrap().unwrap()
            );

            // existing file
            assert!(matches!(
                fs.create(
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
                fs.create(
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
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_rename() {
    run_test(
        TestSetup {
            key: "test_rename",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            // new file in same directory
            let new_parent = ROOT_INODE;
            let file_1 = SecretString::from_str("file-1").unwrap();
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            let file_1_new = SecretString::from_str("file-1-new").unwrap();
            fs.rename(ROOT_INODE, &file_1, new_parent, &file_1_new)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &file_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &file_1_new).unwrap());
            let new_attr = fs
                .find_by_name(new_parent, &file_1_new)
                .await
                .unwrap()
                .unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1_new.expose_secret())
                    .count(),
                1
            );

            // new directory in same directory
            let new_parent = ROOT_INODE;
            let dir_1 = SecretString::from_str("dir-1").unwrap();
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let dir_1_new = SecretString::from_str("dir-1-new").unwrap();
            fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_1_new)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &dir_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &dir_1_new).unwrap());
            let new_attr = fs
                .find_by_name(new_parent, &dir_1_new)
                .await
                .unwrap()
                .unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1_new.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            let dir_new_parent = SecretString::from_str("dir-new-parent").unwrap();
            let (_, new_parent_attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_new_parent,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();

            // new file to another directory
            let new_parent = new_parent_attr.ino;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            let file_2 = SecretString::from_str("file-2").unwrap();
            fs.rename(ROOT_INODE, &file_1, new_parent, &file_2)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &file_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &file_2).unwrap());
            let new_attr = fs.find_by_name(new_parent, &file_2).await.unwrap().unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| {
                        let file_new = "file-new";
                        *entry.as_ref().unwrap().name.expose_secret() == file_new
                    })
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_2.expose_secret())
                    .count(),
                1
            );

            // new directory to another directory
            let new_parent = new_parent_attr.ino;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let dir_2 = SecretString::from_str("dir-_2").unwrap();
            fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_2)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &dir_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &dir_2).unwrap());
            let new_attr = fs.find_by_name(new_parent, &dir_2).await.unwrap().unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_2.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_2.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // file to existing file in same directory
            let file_1 = SecretString::from_str("file-1").unwrap();
            let file_2 = SecretString::from_str("file--2").unwrap();
            let new_parent = ROOT_INODE;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &file_2,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &file_1, new_parent, &file_2)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &file_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &file_2).unwrap());
            let new_attr = fs.find_by_name(new_parent, &file_2).await.unwrap().unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_2.expose_secret())
                    .count(),
                1
            );

            // directory to existing directory in same directory
            let new_parent = ROOT_INODE;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &dir_2,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_2)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &dir_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &dir_2).unwrap());
            let new_attr = fs.find_by_name(new_parent, &dir_2).await.unwrap().unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_2.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // file to existing file in another directory
            let new_parent = new_parent_attr.ino;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &file_1, new_parent, &file_1)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &file_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &file_1).unwrap());
            let new_attr = fs.find_by_name(new_parent, &file_1).await.unwrap().unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                1
            );

            // directory to existing directory in another directory
            let new_parent = new_parent_attr.ino;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_1)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &dir_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &dir_1).unwrap());
            let new_attr = fs.find_by_name(new_parent, &dir_1).await.unwrap().unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // overwriting directory with file
            let new_parent = ROOT_INODE;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_1,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &dir_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &file_1, new_parent, &dir_1)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &file_1).unwrap());
            assert!(fs.exists_by_name(new_parent, &dir_1).unwrap());
            let new_attr = fs.find_by_name(new_parent, &dir_1).await.unwrap().unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_1.expose_secret())
                    .count(),
                1
            );

            // overwriting file with directory
            let new_parent = ROOT_INODE;
            let dir_3 = SecretString::from_str("dir-3").unwrap();
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_3,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let (_, _attr_2) = fs
                .create(
                    new_parent,
                    &file_1,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &dir_3, new_parent, &file_1)
                .await
                .unwrap();
            assert!(!fs.exists_by_name(ROOT_INODE, &dir_3).unwrap());
            assert!(fs.exists_by_name(new_parent, &file_1).unwrap());
            let new_attr = fs.find_by_name(new_parent, &file_1).await.unwrap().unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_3.expose_secret())
                    .count(),
                0
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_1.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // overwriting non-empty directory
            let new_parent = ROOT_INODE;
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_3,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            let _ = new_parent_attr;
            let name_2 = dir_new_parent;
            assert!(matches!(
                fs.rename(ROOT_INODE, &dir_3, new_parent, &name_2).await,
                Err(FsError::NotEmpty)
            ));
            assert!(fs.exists_by_name(ROOT_INODE, &dir_3).unwrap());
            assert!(fs.exists_by_name(new_parent, &name_2).unwrap());
            let attr_3 = fs.find_by_name(ROOT_INODE, &dir_3).await.unwrap().unwrap();
            assert!(fs.is_dir(attr_3.ino));
            let attr_2 = fs.find_by_name(new_parent, &name_2).await.unwrap().unwrap();
            assert!(fs.is_dir(attr_2.ino));
            let new_attr = fs.find_by_name(new_parent, &dir_3).await.unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            let new_attr_2 = fs.find_by_name(new_parent, &name_2).await.unwrap().unwrap();
            assert_eq!(new_attr_2.ino, attr_2.ino);
            assert_eq!(new_attr_2.kind, attr_2.kind);
            assert_eq!(
                fs.read_dir(ROOT_INODE)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_3.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == name_2.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr_2.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr_2.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr_2.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // same file in same directory
            let new_parent = ROOT_INODE;
            let file_3 = SecretString::from_str("file-3").unwrap();
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &file_3,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &file_3, new_parent, &file_3)
                .await
                .unwrap();
            assert!(fs.exists_by_name(new_parent, &file_3).unwrap());
            let new_attr = fs.find_by_name(new_parent, &file_3).await.unwrap().unwrap();
            assert!(fs.is_file(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == file_3.expose_secret())
                    .count(),
                1
            );

            // same directory in same directory
            let new_parent = ROOT_INODE;
            let dir_5 = SecretString::from_str("dir-5").unwrap();
            let (_, attr) = fs
                .create(
                    ROOT_INODE,
                    &dir_5,
                    create_attr(FileType::Directory),
                    false,
                    false,
                )
                .await
                .unwrap();
            fs.rename(ROOT_INODE, &dir_5, new_parent, &dir_5)
                .await
                .unwrap();
            assert!(fs.exists_by_name(new_parent, &dir_5).unwrap());
            let new_attr = fs.find_by_name(new_parent, &dir_5).await.unwrap().unwrap();
            assert!(fs.is_dir(new_attr.ino));
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(
                fs.read_dir(new_parent)
                    .await
                    .unwrap()
                    .filter(|entry| entry.as_ref().unwrap().name.expose_secret()
                        == dir_5.expose_secret())
                    .count(),
                1
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_parent
            );
            assert_eq!(
                fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                new_attr.ino
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == "..")
                    .count(),
                1
            );
            assert_eq!(
                fs.read_dir(new_attr.ino)
                    .await
                    .unwrap()
                    .filter(|entry| *entry.as_ref().unwrap().name.expose_secret() == ".")
                    .count(),
                1
            );

            // invalid nodes and name
            let invalid = SecretString::from_str("invalid").unwrap();
            assert!(matches!(
                fs.rename(0, &invalid, 0, &invalid).await,
                Err(FsError::InodeNotFound)
            ));
            let existing_file = SecretString::from_str("existing-file").unwrap();
            let (_, attr_file) = fs
                .create(
                    ROOT_INODE,
                    &existing_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            assert!(matches!(
                fs.rename(attr_file.ino, &invalid, 0, &invalid).await,
                Err(FsError::InvalidInodeType)
            ));
            assert!(matches!(
                fs.rename(ROOT_INODE, &invalid, ROOT_INODE, &invalid).await,
                Err(FsError::NotFound(_))
            ));
            assert!(matches!(
                fs.rename(ROOT_INODE, &existing_file, 0, &invalid).await,
                Err(FsError::InodeNotFound)
            ));
            assert!(matches!(
                fs.rename(ROOT_INODE, &existing_file, attr_file.ino, &invalid)
                    .await,
                Err(FsError::InvalidInodeType)
            ));
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
async fn test_open() {
    run_test(
        TestSetup {
            key: "test_open",
            read_only: false,
        },
        async {
            let fs = get_fs().await;

            let test_file = SecretString::from_str("test-file").unwrap();
            let (_fh, attr) = fs
                .create(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
            // single read
            let fh = fs.open(attr.ino, true, false).await.unwrap();
            assert_ne!(fh, 0);
            // multiple read
            let fh_2 = fs.open(attr.ino, true, false).await.unwrap();
            assert_ne!(fh_2, 0);
            // write and read
            let _ = fs.open(attr.ino, false, true).await.unwrap();
            // ensure cannot open multiple write
            assert!(matches!(
                fs.open(attr.ino, false, true).await,
                Err(FsError::AlreadyOpenForWrite)
            ));
        },
    )
    .await;
}

// #[tokio::test]
// #[traced_test]
#[allow(clippy::too_many_lines)]
async fn _test_sample() {
    run_test(
        TestSetup {
            key: "test_sample",
            read_only: false,
        },
        async {
            let _ = get_fs().await;
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_read_only_create() {
    run_test(
        TestSetup {
            key: "test_read_only_create",
            read_only: true,
        },
        async {
            let fs = get_fs().await;

            // Check creating a file in a read only fs
            let test_file = SecretString::from_str("test-file").unwrap();
            let create_file_result = fs
                .create(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    true,
                    false,
                )
                .await;
            assert!(matches!(create_file_result, Err(FsError::ReadOnly)));
        },
    )
    .await;
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_read_only_write() {
    run_test(
        TestSetup {
            key: "read_only_test_write",
            read_only: false,
        },
        async {
            let fs_rw = get_fs().await;
            let data_dir = fs_rw.data_dir.clone();
            let cipher = Cipher::ChaCha20Poly1305;
            let file1 = SecretString::from_str("file1").unwrap();
            let file_dest = SecretString::from_str("file_dest").unwrap();
            let dir1 = SecretString::from_str("dir1").unwrap();
            let data = "Hello, world!";

            let (fh, attr) = fs_rw
                .create(
                    ROOT_INODE,
                    &file1,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .expect("read_only_test_create: Error creating file.");
            let (fh_dest, attr_dest) = fs_rw
                .create(
                    ROOT_INODE,
                    &file_dest,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await
                .expect("read_only_test_create: Error creating file.");
            let (_, _) = fs_rw
                .create(
                    ROOT_INODE,
                    &dir1,
                    create_attr(FileType::Directory),
                    false,
                    true,
                )
                .await
                .expect("read_only_test_create: Error creating dir.");

            // Create a succesful write on the file
            crate::encryptedfs::write_all_string_to_fs(&fs_rw, attr.ino, 0, data, fh)
                .await
                .unwrap();
            fs_rw.flush(fh).await.unwrap();
            fs_rw.release(fh).await.unwrap();
            drop(fs_rw);
            let fs_ro = EncryptedFs::new(data_dir, Box::new(PasswordProviderImpl {}), cipher, true)
                .await
                .expect("test_read_only_write: Error creating rw fs.");
            let fh = fs_ro
                .open(attr.ino, true, false)
                .await
                .expect("read_only_test_create: Error opening file in ro.");

            // Test a succesful reading the file in rw mode
            let mut buf = vec![0; data.len()];
            fs_ro.read(attr.ino, 0, &mut buf, fh).await.unwrap();
            assert_eq!(data, String::from_utf8(buf).unwrap());

            // Test creating a file
            let file2 = SecretString::from_str("file2").unwrap();
            let create_file_result = fs_ro
                .create(
                    ROOT_INODE,
                    &file2,
                    create_attr(FileType::RegularFile),
                    true,
                    true,
                )
                .await;
            assert!(matches!(create_file_result, Err(FsError::ReadOnly)));
            // Test renaming the file
            let new_file = SecretString::from_str("file1").unwrap();
            let rename_result = fs_ro
                .rename(ROOT_INODE, &file1, ROOT_INODE, &new_file)
                .await;
            assert!(matches!(rename_result, Err(FsError::ReadOnly)));
            // Test removing a file
            let remove_file_result = fs_ro.remove_file(ROOT_INODE, &file1).await;
            assert!(matches!(remove_file_result, Err(FsError::ReadOnly)));
            // Test copy file range
            let file_range_req = CopyFileRangeReq::builder()
                .src_ino(attr.ino)
                .src_offset(0)
                .dest_ino(attr_dest.ino)
                .dest_offset(0)
                .src_fh(fh)
                .dest_fh(fh_dest)
                .build();
            let copy_file_range_result = fs_ro.copy_file_range(&file_range_req, data.len()).await;
            assert!(matches!(copy_file_range_result, Err(FsError::ReadOnly)));
            // Test removing a dir
            let remove_dir_result = fs_ro.remove_dir(ROOT_INODE, &dir1).await;
            assert!(matches!(remove_dir_result, Err(FsError::ReadOnly)));
            // Test changing the length of the file
            let set_len_result = fs_ro.set_len(attr.ino, 55).await;
            assert!(matches!(set_len_result, Err(FsError::ReadOnly)));
            // Test setting attr of a file
            let set_attr = SetFileAttr::default().with_atime(SystemTime::now());
            let set_attr_result = fs_ro.set_attr(attr.ino, set_attr).await;
            assert!(matches!(set_attr_result, Err(FsError::ReadOnly)));
            // Test writing to file with Read Only enabled.
            let write_all_strings_result =
                crate::encryptedfs::write_all_string_to_fs(&fs_ro, attr.ino, 0, data, fh).await;
            assert!(matches!(write_all_strings_result, Err(FsError::ReadOnly)));
            // Test flushing data to file
            let flush_result = fs_ro.flush(fh).await;
            assert!(matches!(flush_result, Err(FsError::ReadOnly)));
        },
    )
    .await;
}

/// Portable stores must not depend on Windows' treatment of trailing dots.
#[tokio::test]
async fn test_portable_storage_dot_records_and_literal_names() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let (_, child) = fs
        .create(
            ROOT_INODE,
            &SecretString::from_str("child").unwrap(),
            create_attr(FileType::Directory),
            false,
            false,
        )
        .await
        .unwrap();
    for (ino, parent) in [(ROOT_INODE, ROOT_INODE), (child.ino, ROOT_INODE)] {
        let path = fs.contents_path(ino);
        assert!(path.join(super::LS_DIR).join(crypto::DOT_ENTRY).is_file());
        assert!(path.join(HASH_DIR).join(crypto::DOT_ENTRY).is_file());
        assert_eq!(
            fs.find_by_name(ino, &SecretString::from_str(".").unwrap())
                .await
                .unwrap()
                .unwrap()
                .ino,
            ino
        );
        if ino != ROOT_INODE {
            assert!(path
                .join(super::LS_DIR)
                .join(crypto::DOTDOT_ENTRY)
                .is_file());
            assert_eq!(
                fs.find_by_name(ino, &SecretString::from_str("..").unwrap())
                    .await
                    .unwrap()
                    .unwrap()
                    .ino,
                parent
            );
        }
    }
    for literal in ["$dot", "$dotdot"] {
        let name = SecretString::from_str(literal).unwrap();
        let (_, file) = fs
            .create(
                child.ino,
                &name,
                create_attr(FileType::RegularFile),
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            fs.find_by_name(child.ino, &name)
                .await
                .unwrap()
                .unwrap()
                .ino,
            file.ino
        );
        fs.remove_file(child.ino, &name).await.unwrap();
    }
    assert_eq!(fs.len(child.ino).unwrap(), 0);
}

// Windows cannot create legacy names containing `|` or ending in a dot. Build
// an authentic old-format fixture on Unix and check that the new reader can
// still traverse and modify it, including migrating a moved directory's `..`.
#[cfg(unix)]
#[tokio::test]
async fn test_portable_storage_reads_legacy_and_updates_parent_link() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let name = SecretString::from_str("old-child").unwrap();
    let (_, child) = fs
        .create(
            ROOT_INODE,
            &name,
            create_attr(FileType::Directory),
            false,
            false,
        )
        .await
        .unwrap();
    let (_, parent) = fs
        .create(
            ROOT_INODE,
            &SecretString::from_str("new-parent").unwrap(),
            create_attr(FileType::Directory),
            false,
            false,
        )
        .await
        .unwrap();
    let key = fs.key.get().await.unwrap();
    for (canonical, legacy) in [(crypto::DOT_ENTRY, "$."), (crypto::DOTDOT_ENTRY, "$..")] {
        let path = fs.contents_path(child.ino);
        let hash = path.join(HASH_DIR).join(canonical);
        let mut record: (u64, FileType, String) = bincode::deserialize_from(crypto::create_read(
            std::fs::File::open(&hash).unwrap(),
            fs.cipher,
            &key,
        ))
        .unwrap();
        record.2 = legacy.to_owned();
        crypto::atomic_serialize_encrypt_into(
            &path.join(HASH_DIR).join(legacy),
            &record,
            fs.cipher,
            &key,
        )
        .unwrap();
        std::fs::remove_file(hash).unwrap();
        std::fs::rename(
            path.join(super::LS_DIR).join(canonical),
            path.join(super::LS_DIR).join(legacy),
        )
        .unwrap();
    }
    for (component, expected) in [(".", child.ino), ("..", ROOT_INODE)] {
        let component = SecretString::from_str(component).unwrap();
        assert!(fs.exists_by_name(child.ino, &component).unwrap());
        assert_eq!(
            fs.find_by_name(child.ino, &component)
                .await
                .unwrap()
                .unwrap()
                .ino,
            expected
        );
    }
    let listing = fs
        .read_dir(child.ino)
        .await
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(listing.len(), 2);
    let moved = SecretString::from_str("moved").unwrap();
    fs.rename(ROOT_INODE, &name, parent.ino, &moved)
        .await
        .unwrap();
    assert_eq!(
        fs.find_by_name(child.ino, &SecretString::from_str("..").unwrap())
            .await
            .unwrap()
            .unwrap()
            .ino,
        parent.ino
    );
    assert_eq!(fs.len(child.ino).unwrap(), 0);
    let path = fs.contents_path(child.ino);
    assert!(!path.join(super::LS_DIR).join("$..").exists());
    assert!(!path.join(HASH_DIR).join("$..").exists());
    assert!(path.join(HASH_DIR).join(crypto::DOTDOT_ENTRY).is_file());
}

#[tokio::test]
async fn test_portable_storage_read_only_listing_and_close_do_not_write() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let (_, file) = fs
        .create(
            ROOT_INODE,
            &SecretString::from_str("file").unwrap(),
            create_attr(FileType::RegularFile),
            false,
            false,
        )
        .await
        .unwrap();
    let inode_before = std::fs::read(fs.ino_file(file.ino)).unwrap();
    let root_before = std::fs::read(fs.ino_file(ROOT_INODE)).unwrap();
    drop(fs);
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        true,
    )
    .await
    .unwrap();
    let handle = fs.open(file.ino, true, false).await.unwrap();
    assert_eq!(fs.read(file.ino, 0, &mut [0; 8], handle).await.unwrap(), 0);
    fs.release(handle).await.unwrap();
    assert!(fs.read_handles.read().await.is_empty());
    assert!(fs.opened_files_for_read.read().await.is_empty());
    assert_eq!(fs.read_dir(ROOT_INODE).await.unwrap().count(), 2);
    assert_eq!(fs.read_dir_plus(ROOT_INODE).await.unwrap().count(), 2);
    assert_eq!(std::fs::read(fs.ino_file(file.ino)).unwrap(), inode_before);
    assert_eq!(std::fs::read(fs.ino_file(ROOT_INODE)).unwrap(), root_before);
}

#[tokio::test]
async fn test_portable_storage_failed_write_open_does_not_leak_read_handle() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let (first, file) = fs
        .create(
            ROOT_INODE,
            &SecretString::from_str("file").unwrap(),
            create_attr(FileType::RegularFile),
            false,
            true,
        )
        .await
        .unwrap();
    assert!(matches!(
        fs.open(file.ino, true, true).await,
        Err(FsError::AlreadyOpenForWrite)
    ));
    assert!(fs.read_handles.read().await.is_empty());
    assert!(fs.opened_files_for_read.read().await.is_empty());
    fs.release(first).await.unwrap();
    let next = fs.open(file.ino, true, true).await.unwrap();
    fs.release(next).await.unwrap();
    assert!(fs.read_handles.read().await.is_empty());
    assert!(fs.write_handles.read().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn test_portable_storage_reads_and_removes_legacy_encrypted_filename() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let name = SecretString::new(Box::new("private-name".repeat(7)));
    let (handle, file) = fs
        .create(
            ROOT_INODE,
            &name,
            create_attr(FileType::RegularFile),
            false,
            true,
        )
        .await
        .unwrap();
    write_all_bytes_to_fs(&fs, file.ino, 0, b"private data", handle)
        .await
        .unwrap();
    fs.release(handle).await.unwrap();
    let directory = fs.contents_path(ROOT_INODE);
    let hash_path = directory.join(HASH_DIR).join(crypto::hash_file_name(&name));
    let key = fs.key.get().await.unwrap();
    let mut record: (u64, FileType, String) = bincode::deserialize_from(crypto::create_read(
        std::fs::File::open(&hash_path).unwrap(),
        fs.cipher,
        &key,
    ))
    .unwrap();
    let legacy_name = record.2.replace('_', "|");
    if legacy_name != record.2 {
        std::fs::rename(
            directory.join(super::LS_DIR).join(&record.2),
            directory.join(super::LS_DIR).join(&legacy_name),
        )
        .unwrap();
    }
    record.2 = legacy_name;
    crypto::atomic_serialize_encrypt_into(&hash_path, &record, fs.cipher, &key).unwrap();
    let names = fs
        .read_dir(ROOT_INODE)
        .await
        .unwrap()
        .map(|entry| entry.unwrap().name.expose_secret().to_string())
        .collect::<Vec<_>>();
    assert!(names.contains(&name.expose_secret().to_string()));
    assert_eq!(
        fs.find_by_name(ROOT_INODE, &name)
            .await
            .unwrap()
            .unwrap()
            .ino,
        file.ino
    );
    assert_eq!(
        test_common::read_to_string(file.ino, &fs).await,
        "private data"
    );
    fs.remove_file(ROOT_INODE, &name).await.unwrap();
    assert!(!hash_path.exists());
    assert!(!directory.join(super::LS_DIR).join(&record.2).exists());
    assert_eq!(fs.len(ROOT_INODE).unwrap(), 0);
}

#[tokio::test]
async fn test_portable_storage_competing_writer_opens_keep_single_owner() {
    let directory = tempfile::tempdir().unwrap();
    let fs = EncryptedFs::new(
        directory.path().to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await
    .unwrap();
    let (_, file) = fs
        .create(
            ROOT_INODE,
            &SecretString::from_str("file").unwrap(),
            create_attr(FileType::RegularFile),
            false,
            false,
        )
        .await
        .unwrap();
    let (first, second) =
        tokio::join!(fs.open(file.ino, true, true), fs.open(file.ino, true, true));
    let owner = match (first, second) {
        (Ok(handle), Err(FsError::AlreadyOpenForWrite))
        | (Err(FsError::AlreadyOpenForWrite), Ok(handle)) => handle,
        other => panic!("expected exactly one writer, got {other:?}"),
    };
    assert_eq!(fs.write_handles.read().await.len(), 1);
    assert_eq!(fs.read_handles.read().await.len(), 1);
    fs.release(owner).await.unwrap();
    assert!(fs.write_handles.read().await.is_empty());
    assert!(fs.read_handles.read().await.is_empty());
}

#[tokio::test]
async fn test_live_handle_reads_after_write_and_flush() {
    for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
        let backing = tempfile::tempdir().unwrap();
        let fs = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        let name = SecretString::from_str("live-read-write").unwrap();
        let (handle, attr) = fs
            .create(
                ROOT_INODE,
                &name,
                create_attr(FileType::RegularFile),
                true,
                true,
            )
            .await
            .unwrap();
        assert_eq!(fs.write(attr.ino, 0, b"abcdef", handle).await.unwrap(), 6);
        assert_eq!(fs.get_attr(attr.ino).await.unwrap().size, 6);
        fs.flush(handle).await.unwrap();
        let mut buffer = [0; 16];
        assert_eq!(fs.read(attr.ino, 0, &mut buffer, handle).await.unwrap(), 6);
        assert_eq!(&buffer[..6], b"abcdef");
        // A reader opened on an earlier encrypted snapshot must also observe
        // an overwrite of the same plaintext block through its paired writer.
        assert_eq!(fs.write(attr.ino, 2, b"XY", handle).await.unwrap(), 2);
        fs.flush(handle).await.unwrap();
        assert_eq!(fs.read(attr.ino, 0, &mut buffer, handle).await.unwrap(), 6);
        assert_eq!(&buffer[..6], b"abXYef");
        fs.release(handle).await.unwrap();
    }
}

#[tokio::test]
async fn test_live_handle_truncate_changes_eof_and_persists() {
    for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
        let backing = tempfile::tempdir().unwrap();
        let fs = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        let name = SecretString::from_str("live-truncate").unwrap();
        let (handle, attr) = fs
            .create(
                ROOT_INODE,
                &name,
                create_attr(FileType::RegularFile),
                true,
                true,
            )
            .await
            .unwrap();
        fs.write(attr.ino, 0, b"abcdef", handle).await.unwrap();
        let observer = fs.open(attr.ino, true, false).await.unwrap();
        fs.set_len(attr.ino, 3).await.unwrap();
        assert_eq!(fs.get_attr(attr.ino).await.unwrap().size, 3);
        let mut buffer = [0; 16];
        for reader in [handle, observer] {
            assert_eq!(fs.read(attr.ino, 0, &mut buffer, reader).await.unwrap(), 3);
            assert_eq!(&buffer[..3], b"abc");
            assert_eq!(fs.read(attr.ino, 3, &mut buffer, reader).await.unwrap(), 0);
        }
        fs.set_len(attr.ino, 0).await.unwrap();
        assert_eq!(fs.get_attr(attr.ino).await.unwrap().size, 0);
        for reader in [handle, observer] {
            assert_eq!(fs.read(attr.ino, 0, &mut buffer, reader).await.unwrap(), 0);
        }
        fs.write(attr.ino, 0, b"new", handle).await.unwrap();
        fs.flush(handle).await.unwrap();
        fs.release(observer).await.unwrap();
        fs.release(handle).await.unwrap();
        drop(fs);
        let reopened = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        assert_eq!(reopened.get_attr(attr.ino).await.unwrap().size, 3);
        let reader = reopened.open(attr.ino, true, false).await.unwrap();
        assert_eq!(
            reopened
                .read(attr.ino, 0, &mut buffer, reader)
                .await
                .unwrap(),
            3
        );
        assert_eq!(&buffer[..3], b"new");
        reopened.release(reader).await.unwrap();
    }
}

#[tokio::test]
async fn test_live_handle_flushes_partial_and_boundary_blocks_for_all_readers() {
    for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
        let backing = tempfile::tempdir().unwrap();
        let fs = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        let name = SecretString::from_str("live-boundary-write").unwrap();
        let (handle, attr) = fs
            .create(
                ROOT_INODE,
                &name,
                create_attr(FileType::RegularFile),
                true,
                true,
            )
            .await
            .unwrap();
        let observer = fs.open(attr.ino, true, false).await.unwrap();
        let block = crate::crypto::write::BLOCK_SIZE;
        let mut expected = (0..block * 2 + 7)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let mut written = 0;
        while written < expected.len() {
            let count = fs
                .write(attr.ino, written as u64, &expected[written..], handle)
                .await
                .unwrap();
            assert!(count > 0);
            written += count;
        }
        fs.flush(handle).await.unwrap();
        // Repeated flush must preserve both EOF and the last partial block.
        fs.flush(handle).await.unwrap();
        let mut buffer = vec![0; expected.len() + 32];
        for reader in [handle, observer] {
            test_common::read_exact(&fs, attr.ino, 0, &mut buffer[..expected.len()], reader).await;
            assert_eq!(&buffer[..expected.len()], expected.as_slice());
        }
        let mut written = 0;
        while written < 3 {
            let count = fs
                .write(
                    attr.ino,
                    (block - 1 + written) as u64,
                    &b"XYZ"[written..],
                    handle,
                )
                .await
                .unwrap();
            assert!(count > 0);
            written += count;
        }
        expected[block - 1..block + 2].copy_from_slice(b"XYZ");
        fs.flush(handle).await.unwrap();
        for reader in [handle, observer] {
            test_common::read_exact(&fs, attr.ino, 0, &mut buffer[..expected.len()], reader).await;
            assert_eq!(&buffer[..expected.len()], expected.as_slice());
        }
        fs.set_len(attr.ino, (block + 1) as u64).await.unwrap();
        expected.truncate(block + 1);
        fs.set_len(attr.ino, (block * 3 + 5) as u64).await.unwrap();
        expected.resize(block * 3 + 5, 0);
        buffer.resize(expected.len() + 32, 0xff);
        assert_eq!(
            fs.get_attr(attr.ino).await.unwrap().size,
            expected.len() as u64
        );
        for reader in [handle, observer] {
            test_common::read_exact(&fs, attr.ino, 0, &mut buffer[..expected.len()], reader).await;
            assert_eq!(&buffer[..expected.len()], expected.as_slice());
            assert_eq!(
                fs.read(attr.ino, expected.len() as u64, &mut buffer, reader)
                    .await
                    .unwrap(),
                0
            );
        }
        fs.release(handle).await.unwrap();
        fs.release(observer).await.unwrap();
        drop(fs);
        let reopened = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            reopened.get_attr(attr.ino).await.unwrap().size,
            expected.len() as u64
        );
        let reader = reopened.open(attr.ino, true, false).await.unwrap();
        test_common::read_exact(
            &reopened,
            attr.ino,
            0,
            &mut buffer[..expected.len()],
            reader,
        )
        .await;
        assert_eq!(&buffer[..expected.len()], expected.as_slice());
        reopened.release(reader).await.unwrap();
    }
}

#[tokio::test]
async fn test_repeated_reads_after_oversized_read_rewind_from_eof() {
    for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
        let backing = tempfile::tempdir().unwrap();
        let fs = EncryptedFs::new(
            backing.path().to_path_buf(),
            Box::new(PasswordProviderImpl {}),
            cipher,
            false,
        )
        .await
        .unwrap();
        let name = SecretString::from_str("readahead-rewind").unwrap();
        let (writer, attr) = fs
            .create(
                ROOT_INODE,
                &name,
                create_attr(FileType::RegularFile),
                false,
                true,
            )
            .await
            .unwrap();
        fs.write(attr.ino, 0, b"abcXYZ++", writer).await.unwrap();
        fs.release(writer).await.unwrap();
        let reader = fs.open(attr.ino, true, false).await.unwrap();

        // Windows can request a full page for read-ahead, then repeat the
        // application read from zero through the same context.
        let mut page = [0; 4096];
        assert_eq!(fs.read(attr.ino, 0, &mut page, reader).await.unwrap(), 8);
        assert_eq!(&page[..8], b"abcXYZ++");
        let mut exact = [0; 8];
        for _ in 0..2 {
            assert_eq!(fs.read(attr.ino, 0, &mut exact, reader).await.unwrap(), 8);
            assert_eq!(&exact, b"abcXYZ++");
            let mut tail = [0; 16];
            assert_eq!(fs.read(attr.ino, 7, &mut tail, reader).await.unwrap(), 1);
            assert_eq!(tail[0], b'+');
            assert_eq!(fs.read(attr.ino, 8, &mut tail, reader).await.unwrap(), 0);
            assert_eq!(fs.read(attr.ino, 0, &mut page, reader).await.unwrap(), 8);
            assert_eq!(&page[..8], b"abcXYZ++");
        }
        fs.release(reader).await.unwrap();
    }
}
