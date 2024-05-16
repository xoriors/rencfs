// use std::fs;
// use std::fs::{File, OpenOptions};
// use std::io::{Read, Write};
// use std::path::PathBuf;
// use std::str::FromStr;
// use std::string::String;
// use secrecy::{ExposeSecret, SecretString};
//
// use crate::encryptedfs::{CONTENTS_DIR, DirectoryEntry, DirectoryEntryPlus, EncryptedFs, Cipher, FileAttr, FileType, FsError, FsResult, INODES_DIR, ROOT_INODE, SECURITY_DIR};
//
// const TESTS_DATA_DIR: &str = "./tests-data/";
//
// const ROOT_INODE_STR: &str = "1";
//
//
// #[derive(Debug, Clone)]
// struct TestSetup {
//     data_path: String,
// }
//
// struct SetupResult {
//     fs: Option<EncryptedFs>,
//     setup: TestSetup,
// }
//
// async fn setup(setup: TestSetup) -> SetupResult {
//     let path = setup.data_path.as_str();
//     if fs::metadata(path).is_ok() {
//         fs::remove_dir_all(path).unwrap();
//     }
//     fs::create_dir_all(path).unwrap();
//     let fs = EncryptedFs::new(path, SecretString::from_str("pass-42").unwrap(), Cipher::ChaCha20).await.unwrap();
//
//     SetupResult {
//         fs: Some(fs),
//         setup,
//     }
// }
//
// fn teardown(mut result: SetupResult) {
//     {
//         let _fs = result.fs.take().unwrap();
//     }
//     fs::remove_dir_all(result.setup.data_path).unwrap();
// }
//
// async fn run_test<T>(init: TestSetup, test: T)
//     where T: FnOnce(&mut SetupResult) {
//     let mut result = setup(init).await;
//     test(&mut result);
//     teardown(result);
// }
//
// fn create_attr(ino: u64, file_type: FileType) -> FileAttr {
//     FileAttr {
//         ino,
//         size: 0,
//         blocks: 0,
//         atime: std::time::SystemTime::now(),
//         mtime: std::time::SystemTime::now(),
//         ctime: std::time::SystemTime::now(),
//         crtime: std::time::SystemTime::now(),
//         kind: file_type,
//         perm: if file_type == FileType::Directory { 0o755 } else { 0o644 },
//         nlink: if file_type == FileType::Directory { 2 } else { 1 },
//         uid: 0,
//         gid: 0,
//         rdev: 0,
//         blksize: 0,
//         flags: 0,
//     }
// }
//
// fn create_attr_from_type(file_type: FileType) -> FileAttr {
//     create_attr(0, file_type)
// }
//
// #[test]
// fn test_write_and_get_inode() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_write_and_get_inode") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let attr = create_attr(42, FileType::RegularFile);
//         fs.write_inode(&attr).unwrap();
//
//         assert!(fs.node_exists(42));
//         assert_eq!(fs.get_inode(42).unwrap(), attr);
//         assert!(fs.data_dir.join(INODES_DIR).join("42").is_file());
//
//         assert!(matches!(fs.get_inode(0), Err(FsError::InodeNotFound)));
//     });
// }
//
// fn deserialize_from<T>(file: File, fs: &mut EncryptedFs) -> T
//     where
//         T: serde::de::DeserializeOwned,
// {
//     bincode::deserialize_from(fs.create_decryptor(file)).unwrap()
// }
//
// fn read_to_string(path: PathBuf, fs: &mut EncryptedFs) -> String {
//     let mut buf: Vec<u8> = vec![];
//     fs.create_decryptor(OpenOptions::new().read(true).write(true).open(path).unwrap()).read_to_end(&mut buf).unwrap();
//     String::from_utf8(buf).unwrap()
// }
//
// #[allow(dead_code)]
// fn write(path: PathBuf, data: &[u8], fs: &mut EncryptedFs) {
//     let mut enc = fs.create_encryptor(OpenOptions::new().read(true).write(true).open(&path).unwrap());
//     enc.write_all(data).unwrap();
//     enc.finish().unwrap();
// }
//
// #[test]
// fn test_create_structure_and_root() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_create_structure_and_root") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         assert!(fs.node_exists(ROOT_INODE));
//         assert!(fs.is_dir(ROOT_INODE));
//
//         assert!(fs.data_dir.join(INODES_DIR).is_dir());
//         assert!(fs.data_dir.join(CONTENTS_DIR).is_dir());
//         assert!(fs.data_dir.join(SECURITY_DIR).is_dir());
//
//         assert!(fs.data_dir.join(INODES_DIR).join(ROOT_INODE_STR).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).is_dir());
//     });
// }
//
// #[test]
// fn test_create_nod() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_create_nod") }, |setup| {
//         let mut fs = setup.fs.as_mut().unwrap();
//
//         // file in root
//         let test_file = SecretString::from_str("test-file").unwrap();
//         let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), true, false).unwrap();
//         assert_ne!(fh, 0);
//         assert_ne!(attr.ino, 0);
//         assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(&test_file)).is_file());
//         assert!(fs.node_exists(attr.ino));
//         assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
//
//         let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(&test_file))).unwrap(), &mut fs);
//         assert_eq!(entry_in_parent, (attr.ino, FileType::RegularFile));
//
//         // directory in root
//         let test_dir = SecretString::from_str("test-dir").unwrap();
//         let (_fh, attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         assert_ne!(attr.ino, 0);
//         assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(&test_dir)).is_file());
//         assert!(fs.node_exists(attr.ino));
//         assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
//         assert!(fs.is_dir(attr.ino));
//         let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(&test_dir))).unwrap(), &mut fs);
//         assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
//         let dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap(), &mut fs);
//         assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
//         let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap(), &mut fs);
//         assert_eq!(dot_dot_entry_in_parent, (ROOT_INODE, FileType::Directory));
//
//         // directory in another directory
//         let parent = attr.ino;
//         let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
//         let (_fh, attr) = fs.create_nod(parent, &test_dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(fs.normalize_end_encrypt_file_name(&test_dir_2)).is_file());
//         assert!(fs.node_exists(attr.ino));
//         assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
//         assert!(fs.is_dir(attr.ino));
//         let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(fs.normalize_end_encrypt_file_name(&test_dir_2))).unwrap(), &mut fs);
//         assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
//         let dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap(), &mut fs);
//         assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
//         let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap(), &mut fs);
//         assert_eq!(dot_dot_entry_in_parent, (parent, FileType::Directory));
//
//         // existing file
//         assert!(matches!(
//                 fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false),
//                 Err(FsError::AlreadyExists)
//                 )
//         );
//
//         // existing directory
//         assert!(matches!(
//                 fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, false),
//                 Err(FsError::AlreadyExists)
//                 )
//         );
//     });
// }
//

//
// #[test]
// fn test_find_by_name() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_find_by_name") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let test_file = SecretString::from_str("test-file").unwrap();
//         fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         assert!(fs.find_by_name(ROOT_INODE, &test_file).unwrap().is_some());
//         assert!(fs.find_by_name(ROOT_INODE, &SecretString::from_str("invalid").unwrap()).unwrap().is_none());
//     });
// }
//
// #[test]
// fn test_remove_dir() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_remove_dir") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let test_dir = SecretString::from_str("test-dir").unwrap();
//         let (_fh, dir_attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let test_file = SecretString::from_str("test-file").unwrap();
//         let (_fh, file_attr) = fs.create_nod(dir_attr.ino, &test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//
//         assert!(matches!(fs.remove_dir(ROOT_INODE, &test_dir), Err(FsError::NotEmpty)));
//         assert!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(INODES_DIR).join(file_attr.ino.to_string()).is_file());
//         assert!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).join(fs.normalize_end_encrypt_file_name(&test_file)).is_file());
//
//         fs.remove_file(dir_attr.ino, &test_file).unwrap();
//         assert!(fs.remove_dir(ROOT_INODE, &test_dir).is_ok());
//         assert_ne!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).exists(), true);
//         assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).exists(), true);
//
//         assert!(matches!(fs.remove_file(ROOT_INODE, &SecretString::from_str("invalid").unwrap()), Err(FsError::NotFound(_))));
//     });
// }
//
// #[test]
// fn test_remove_file() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_remove_file") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let test_file = SecretString::from_str("test-file").unwrap();
//         let (_fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         assert!(fs.remove_file(ROOT_INODE, &test_file).is_ok());
//         assert_ne!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file(), true);
//         assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file(), true);
//         assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.encrypt_string(&test_file)).is_file(), true);
//         assert!(fs.find_by_name(ROOT_INODE, &test_file).unwrap().is_none());
//
//         assert!(matches!(fs.remove_file(ROOT_INODE, &SecretString::from_str("invalid").unwrap()), Err(FsError::NotFound(_))));
//     });
// }
//

//

//
// #[test]
// fn test_rename() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_rename") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         // new file in same directory
//         let new_parent = ROOT_INODE;
//         let file_1 = SecretString::from_str("file-1").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         let file_1_new = SecretString::from_str("file-1-new").unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_1_new).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_1_new), true);
//         let new_attr = fs.find_by_name(new_parent, &file_1_new).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1_new.expose_secret()).count(), 1);
//
//         // new directory in same directory
//         let new_parent = ROOT_INODE;
//         let dir_1 = SecretString::from_str("dir-1").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let dir_1_new = SecretString::from_str("dir-1-new").unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_1_new).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_1_new), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_1_new).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1_new.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         let dir_new_parent = SecretString::from_str("dir-new-parent").unwrap();
//         let (_, new_parent_attr) = fs.create_nod(ROOT_INODE, &dir_new_parent, create_attr_from_type(FileType::Directory), false, false).unwrap();
//
//         // new file to another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         let file_2 = SecretString::from_str("file-2").unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_2), true);
//         let new_attr = fs.find_by_name(new_parent, &file_2).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| {
//             let file_new = "file-new";
//             entry.as_ref().unwrap().name.expose_secret() == file_new
//         }).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_2.expose_secret()).count(), 1);
//
//         // new directory to another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let dir_2 = SecretString::from_str("dir-2").unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_2), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_2).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_2.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_2.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // file to existing file in same directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_2, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_2), true);
//         let new_attr = fs.find_by_name(new_parent, &file_2).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_2.expose_secret()).count(), 1);
//
//         // directory to existing directory in same directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_2).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_2), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_2).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_2.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // file to existing file in another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &file_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_1), true);
//         let new_attr = fs.find_by_name(new_parent, &file_1).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 1);
//
//         // directory to existing directory in another directory
//         let new_parent = new_parent_attr.ino;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_1, new_parent, &dir_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_1), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_1).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // overwriting directory with file
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_1, new_parent, &dir_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &file_1), true);
//         assert_eq!(fs.exists_by_name(new_parent, &dir_1), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_1).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_1.expose_secret()).count(), 1);
//
//         // overwriting file with directory
//         let new_parent = ROOT_INODE;
//         let dir_3 = SecretString::from_str("dir-3").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_3, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let (_, _attr_2) = fs.create_nod(new_parent, &file_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_3, new_parent, &file_1).unwrap();
//         assert_ne!(fs.exists_by_name(ROOT_INODE, &dir_3), true);
//         assert_eq!(fs.exists_by_name(new_parent, &file_1), true);
//         let new_attr = fs.find_by_name(new_parent, &file_1).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_3.expose_secret()).count(), 0);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_1.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // overwriting non-empty directory
//         let new_parent = ROOT_INODE;
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_3, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         let _attr_2 = new_parent_attr;
//         let name_2 = dir_new_parent;
//         assert!(matches!(fs.rename(ROOT_INODE, &dir_3, new_parent, &name_2), Err(FsError::NotEmpty)));
//         assert_eq!(fs.exists_by_name(ROOT_INODE, &dir_3), true);
//         assert_eq!(fs.exists_by_name(new_parent, &name_2), true);
//         let attr_3 = fs.find_by_name(ROOT_INODE, &dir_3).unwrap().unwrap();
//         assert_eq!(fs.is_dir(attr_3.ino), true);
//         let attr_2 = fs.find_by_name(new_parent, &name_2).unwrap().unwrap();
//         assert_eq!(fs.is_dir(attr_2.ino), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_3).unwrap().unwrap();
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         let new_attr_2 = fs.find_by_name(new_parent, &name_2).unwrap().unwrap();
//         assert_eq!(new_attr_2.ino, attr_2.ino);
//         assert_eq!(new_attr_2.kind, attr_2.kind);
//         assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_3.expose_secret()).count(), 1);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == name_2.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr_2.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr_2.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr_2.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // same file in same directory
//         let new_parent = ROOT_INODE;
//         let file_3 = SecretString::from_str("file-3").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &file_3, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         fs.rename(ROOT_INODE, &file_3, new_parent, &file_3).unwrap();
//         assert_eq!(fs.exists_by_name(new_parent, &file_3), true);
//         let new_attr = fs.find_by_name(new_parent, &file_3).unwrap().unwrap();
//         assert_eq!(fs.is_file(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == file_3.expose_secret()).count(), 1);
//
//         // same directory in same directory
//         let new_parent = ROOT_INODE;
//         let dir_5 = SecretString::from_str("dir-5").unwrap();
//         let (_, attr) = fs.create_nod(ROOT_INODE, &dir_5, create_attr_from_type(FileType::Directory), false, false).unwrap();
//         fs.rename(ROOT_INODE, &dir_5, new_parent, &dir_5).unwrap();
//         assert_eq!(fs.exists_by_name(new_parent, &dir_5), true);
//         let new_attr = fs.find_by_name(new_parent, &dir_5).unwrap().unwrap();
//         assert_eq!(fs.is_dir(new_attr.ino), true);
//         assert_eq!(new_attr.ino, attr.ino);
//         assert_eq!(new_attr.kind, attr.kind);
//         assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == dir_5.expose_secret()).count(), 1);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str("..").unwrap()).unwrap().unwrap().ino, new_parent);
//         assert_eq!(fs.find_by_name(new_attr.ino, &SecretString::from_str(".").unwrap()).unwrap().unwrap().ino, new_attr.ino);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == "..").count(), 1);
//         assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name.expose_secret() == ".").count(), 1);
//
//         // invalid nodes and name
//         let invalid = SecretString::from_str("invalid").unwrap();
//         assert!(matches!(fs.rename(0, &invalid, 0, &invalid), Err(FsError::InodeNotFound)));
//         let existing_file = SecretString::from_str("existing-file").unwrap();
//         let (_, attr_file) = fs.create_nod(ROOT_INODE, &existing_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         assert!(matches!(fs.rename(attr_file.ino, &invalid, 0, &invalid), Err(FsError::InvalidInodeType)));
//         assert!(matches!(fs.rename(ROOT_INODE, &invalid, ROOT_INODE, &invalid), Err(FsError::NotFound(_))));
//         assert!(matches!(fs.rename(ROOT_INODE, &existing_file, 0, &invalid), Err(FsError::InodeNotFound)));
//         assert!(matches!(fs.rename(ROOT_INODE, &existing_file, attr_file.ino, &invalid), Err(FsError::InvalidInodeType)));
//     });
// }
//
// #[test]
// fn test_open() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_open") }, |setup| {
//         let fs = setup.fs.as_mut().unwrap();
//
//         let test_file = SecretString::from_str("test-file").unwrap();
//         let (_fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
//         // single read
//         let fh = fs.open(attr.ino, true, false).unwrap();
//         assert_ne!(fh, 0);
//         // multiple read
//         let fh_2 = fs.open(attr.ino, true, false).unwrap();
//         assert_ne!(fh_2, 0);
//         // write and read
//         let _fh_w = fs.open(attr.ino, false, true).unwrap();
//         // ensure cannot open multiple write
//         assert!(matches!(fs.open(attr.ino, false, true), Err(FsError::AlreadyOpenForWrite)));
//     });
// }
//
// #[allow(dead_code)]
// // #[test]
// fn test_sample() {
//     run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}/test_sample") }, |setup| {
//         let _fs = setup.fs.as_mut().unwrap();
//     });
// }
