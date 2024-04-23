use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::string::String;

use crate::encryptedfs::{CONTENTS_DIR, DirectoryEntry, DirectoryEntryPlus, EncryptedFs, Cipher, FileAttr, FileType, FsError, FsResult, INODES_DIR, ROOT_INODE, SECURITY_DIR};

const TESTS_DATA_DIR: &str = "./tests-data/";

const ROOT_INODE_STR: &str = "1";


#[derive(Debug, Clone)]
struct TestSetup {
    data_path: String,
}

struct SetupResult {
    fs: Option<EncryptedFs>,
    setup: TestSetup,
}

fn setup(setup: TestSetup) -> SetupResult {
    let path = setup.data_path.as_str();
    if fs::metadata(path).is_ok() {
        fs::remove_dir_all(path).unwrap();
    }
    fs::create_dir_all(path).unwrap();
    let fs = EncryptedFs::new(path, "pass-42", Cipher::ChaCha20, 0).unwrap();

    SetupResult {
        fs: Some(fs),
        setup,
    }
}

fn teardown(mut result: SetupResult) {
    {
        let _fs = result.fs.take().unwrap();
    }
    fs::remove_dir_all(result.setup.data_path).unwrap();
}

fn run_test<T>(init: TestSetup, test: T)
    where T: FnOnce(&mut SetupResult) {
    let mut result = setup(init);
    test(&mut result);
    teardown(result);
}

fn create_attr(ino: u64, file_type: FileType) -> FileAttr {
    FileAttr {
        ino,
        size: 0,
        blocks: 0,
        atime: std::time::SystemTime::now(),
        mtime: std::time::SystemTime::now(),
        ctime: std::time::SystemTime::now(),
        crtime: std::time::SystemTime::now(),
        kind: file_type,
        perm: if file_type == FileType::Directory { 0o755 } else { 0o644 },
        nlink: if file_type == FileType::Directory { 2 } else { 1 },
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 0,
        flags: 0,
    }
}

fn create_attr_from_type(file_type: FileType) -> FileAttr {
    create_attr(0, file_type)
}

#[test]
fn test_write_and_get_inode() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_write_and_get_inode") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let attr = create_attr(42, FileType::RegularFile);
        fs.write_inode(&attr).unwrap();

        assert!(fs.node_exists(42));
        assert_eq!(fs.get_inode(42).unwrap(), attr);
        assert!(fs.data_dir.join(INODES_DIR).join("42").is_file());

        assert!(matches!(fs.get_inode(0), Err(FsError::InodeNotFound)));
    });
}

fn deserialize_from<T>(file: File, fs: &EncryptedFs) -> T
    where
        T: serde::de::DeserializeOwned,
{
    bincode::deserialize_from(fs.create_decryptor(file)).unwrap()
}

fn read_to_string(path: PathBuf, fs: &EncryptedFs) -> String {
    let mut buf: Vec<u8> = vec![];
    fs.create_decryptor(OpenOptions::new().read(true).write(true).open(path).unwrap()).read_to_end(&mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[allow(dead_code)]
fn write(path: PathBuf, data: &[u8], fs: &EncryptedFs) {
    let mut enc = fs.create_encryptor(OpenOptions::new().read(true).write(true).open(&path).unwrap());
    enc.write_all(data).unwrap();
    enc.finish().unwrap();
}

#[test]
fn test_create_structure_and_root() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_create_structure_and_root") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        assert!(fs.node_exists(ROOT_INODE));
        assert!(fs.is_dir(ROOT_INODE));

        assert!(fs.data_dir.join(INODES_DIR).is_dir());
        assert!(fs.data_dir.join(CONTENTS_DIR).is_dir());
        assert!(fs.data_dir.join(SECURITY_DIR).is_dir());

        assert!(fs.data_dir.join(INODES_DIR).join(ROOT_INODE_STR).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).is_dir());
    });
}

#[test]
fn test_create_nod() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_create_nod") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        // file in root
        let test_file = "test-file";
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), true, false).unwrap();
        assert_ne!(fh, 0);
        assert_ne!(attr.ino, 0);
        assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(test_file)).is_file());
        assert!(fs.node_exists(attr.ino));
        assert_eq!(attr, fs.get_inode(attr.ino).unwrap());

        let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(test_file))).unwrap(), &fs);
        assert_eq!(entry_in_parent, (attr.ino, FileType::RegularFile));

        // directory in root
        let test_dir = "test-dir";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
        assert_ne!(attr.ino, 0);
        assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(test_dir)).is_file());
        assert!(fs.node_exists(attr.ino));
        assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
        assert!(fs.is_dir(attr.ino));
        let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(fs.normalize_end_encrypt_file_name(test_dir))).unwrap(), &fs);
        assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
        let dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap(), &fs);
        assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
        let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap(), &fs);
        assert_eq!(dot_dot_entry_in_parent, (ROOT_INODE, FileType::Directory));

        // directory in another directory
        let parent = attr.ino;
        let test_dir_2 = "test-dir-2";
        let (fh, attr) = fs.create_nod(parent, test_dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
        assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(fs.normalize_end_encrypt_file_name(test_dir_2)).is_file());
        assert!(fs.node_exists(attr.ino));
        assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
        assert!(fs.is_dir(attr.ino));
        let entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(fs.normalize_end_encrypt_file_name(test_dir_2))).unwrap(), &fs);
        assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
        let dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap(), &fs);
        assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
        let dot_dot_entry_in_parent: (u64, FileType) = deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap(), &fs);
        assert_eq!(dot_dot_entry_in_parent, (parent, FileType::Directory));

        // existing file
        assert!(matches!(
                fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false),
                Err(FsError::AlreadyExists)
                )
        );

        // existing directory
        assert!(matches!(
                fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, false),
                Err(FsError::AlreadyExists)
                )
        );
    });
}

#[test]
fn test_read_dir() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read_dir") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        // file and directory in root
        let test_file = "test-file";
        let (fh, file_attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        let test_dir = "test-dir";
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let mut entries: Vec<FsResult<DirectoryEntry>> = fs.read_dir(dir_attr.ino).unwrap().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
            DirectoryEntry {
                ino: dir_attr.ino,
                name: ".".to_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: ROOT_INODE,
                name: "..".to_string(),
                kind: FileType::Directory,
            },
        ], entries);

        let iter = fs.read_dir(ROOT_INODE);
        let mut entries: Vec<FsResult<DirectoryEntry>> = iter.unwrap().into_iter().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        let mut sample = vec![
            DirectoryEntry {
                ino: ROOT_INODE,
                name: ".".to_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: file_attr.ino,
                name: test_file.to_string(),
                kind: FileType::RegularFile,
            },
            DirectoryEntry {
                ino: dir_attr.ino,
                name: test_dir.to_string(),
                kind: FileType::Directory,
            }];
        sample.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 3);
        assert_eq!(sample, entries);

        // file and directory in another directory
        let parent = dir_attr.ino;
        let test_file_2 = "test-file-2";
        let (fh, file_attr) = fs.create_nod(parent, test_file_2, create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        let test_dir_2 = "test-dir-2";
        let (fh, dir_attr) = fs.create_nod(parent, test_dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let mut entries: Vec<FsResult<DirectoryEntry>> = fs.read_dir(dir_attr.ino).unwrap().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
            DirectoryEntry {
                ino: dir_attr.ino,
                name: ".".to_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: parent,
                name: "..".to_string(),
                kind: FileType::Directory,
            },
        ], entries);

        let iter = fs.read_dir(parent);
        let mut entries: Vec<DirectoryEntry> = iter.unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut sample = vec![
            DirectoryEntry {
                ino: parent,
                name: ".".to_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: ROOT_INODE,
                name: "..".to_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: file_attr.ino,
                name: test_file_2.to_string(),
                kind: FileType::RegularFile,
            },
            DirectoryEntry {
                ino: dir_attr.ino,
                name: test_dir_2.to_string(),
                kind: FileType::Directory,
            }];
        sample.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 4);
        assert_eq!(sample, entries);
    });
}

#[test]
fn test_read_dir_plus() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read_dir_plus") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        // file and directory in root
        let test_file = "test-file";
        let (fh, file_attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        let test_dir = "test-dir";
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = fs.read_dir_plus(dir_attr.ino).unwrap().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        let attr_root = fs.get_inode(ROOT_INODE).unwrap();
        assert_eq!(vec![
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: ".".to_string(),
                kind: FileType::Directory,
                attr: dir_attr,
            },
            DirectoryEntryPlus {
                ino: ROOT_INODE,
                name: "..".to_string(),
                kind: FileType::Directory,
                attr: attr_root,
            },
        ], entries);

        let iter = fs.read_dir_plus(ROOT_INODE);
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = iter.unwrap().into_iter().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        let mut sample = vec![
            DirectoryEntryPlus {
                ino: ROOT_INODE,
                name: ".".to_string(),
                kind: FileType::Directory,
                attr: attr_root,
            },
            DirectoryEntryPlus {
                ino: file_attr.ino,
                name: test_file.to_string(),
                kind: FileType::RegularFile,
                attr: file_attr,
            },
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: test_dir.to_string(),
                kind: FileType::Directory,
                attr: dir_attr,
            }];
        sample.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 3);
        assert_eq!(sample, entries);

        // file and directory in another directory
        let parent = dir_attr.ino;
        let attr_parent = dir_attr;
        let test_file_2 = "test-file-2";
        let (fh, file_attr) = fs.create_nod(parent, test_file_2, create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        let test_dir_2 = "test-dir-2";
        let (fh, dir_attr) = fs.create_nod(parent, test_dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
        // for some reason the tv_nsec is not the same between what create_nod() and read_dir_plus() returns, so we reload it again
        let dir_attr = fs.get_inode(dir_attr.ino).unwrap();
        let attr_parent = fs.get_inode(attr_parent.ino).unwrap();
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = fs.read_dir_plus(dir_attr.ino).unwrap().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.cmp(&b.as_ref().unwrap().name));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: ".".to_string(),
                kind: FileType::Directory,
                attr: dir_attr,
            },
            DirectoryEntryPlus {
                ino: parent,
                name: "..".to_string(),
                kind: FileType::Directory,
                attr: attr_parent,
            },
        ], entries);

        let iter = fs.read_dir_plus(parent);
        let mut entries: Vec<DirectoryEntryPlus> = iter.unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut sample = vec![
            DirectoryEntryPlus {
                ino: parent,
                name: ".".to_string(),
                kind: FileType::Directory,
                attr: attr_parent,
            },
            DirectoryEntryPlus {
                ino: ROOT_INODE,
                name: "..".to_string(),
                kind: FileType::Directory,
                attr: attr_root,
            },
            DirectoryEntryPlus {
                ino: file_attr.ino,
                name: test_file_2.to_string(),
                kind: FileType::RegularFile,
                attr: file_attr,
            },
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: test_dir_2.to_string(),
                kind: FileType::Directory,
                attr: dir_attr,
            }];
        sample.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 4);
        assert_eq!(sample, entries);
    });
}

#[test]
fn test_find_by_name() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_find_by_name") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_file = "test-file";
        fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        assert!(fs.find_by_name(ROOT_INODE, test_file).unwrap().is_some());
        assert!(fs.find_by_name(ROOT_INODE, "invalid").unwrap().is_none());
    });
}

#[test]
fn test_remove_dir() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_remove_dir") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_dir = "test-dir";
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let test_file = "test-file";
        let (fh, file_attr) = fs.create_nod(dir_attr.ino, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        assert!(matches!(fs.remove_dir(ROOT_INODE, test_dir), Err(FsError::NotEmpty)));
        assert!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(INODES_DIR).join(file_attr.ino.to_string()).is_file());
        assert!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).join(fs.normalize_end_encrypt_file_name(test_file)).is_file());

        fs.remove_file(dir_attr.ino, test_file).unwrap();
        assert!(fs.remove_dir(ROOT_INODE, test_dir).is_ok());
        assert_ne!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).exists(), true);
        assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).exists(), true);

        assert!(matches!(fs.remove_file(ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
    });
}

#[test]
fn test_remove_file() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_remove_file") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_file = "test-file";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        assert!(fs.remove_file(ROOT_INODE, test_file).is_ok());
        assert_ne!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file(), true);
        assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file(), true);
        assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join(test_file).is_file(), true);
        assert!(fs.find_by_name(ROOT_INODE, test_file).unwrap().is_none());

        assert!(matches!(fs.remove_file(ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
    });
}

#[test]
fn test_write_all() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_write_all") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_file = "test-file";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = "test-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        assert_eq!(data, read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs));
        let attr = fs.get_inode(attr.ino).unwrap();
        assert_eq!(data.len() as u64, attr.size);

        // offset greater than current position
        let data = "37";
        let fh = fs.open(attr.ino, false, true).unwrap();
        fs.write_all(attr.ino, 5, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        assert_eq!(data, &read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs)[5..]);

        // offset before current position
        // first write no bytes to the end to move the position
        let fh = fs.open(attr.ino, false, true).unwrap();
        fs.write_all(attr.ino, 7, &[0u8; 0], fh).unwrap();
        let data = "42";
        fs.write_all(attr.ino, 5, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        assert_eq!(data, &read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs)[5..]);

        // offset after file end
        let data = "37";
        let fh = fs.open(attr.ino, false, true).unwrap();
        fs.write_all(attr.ino, 42, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        assert_eq!(format!("test-42{}37", "                                   ".replace(" ", "\0")),
                   read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs));

        // write before current position then write to the end, also check it preserves the content from
        // the first write to offset to end of the file
        let test_file_2 = "test-file-2";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file_2, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
        fs.write_all(attr.ino, 5, b"37", fh).unwrap();
        fs.write_all(attr.ino, data.len() as u64, b"-42", fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let new_content = read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs);
        assert_eq!("test-37-37-42", new_content);

        let buf = [0; 0];
        let fh = fs.open(attr.ino, false, true).unwrap();
        assert!(matches!(fs.write_all(ROOT_INODE, 0, &buf, fh), Err(FsError::InvalidInodeType)));
        assert!(matches!(fs.write_all(0, 0, &buf, fh), Err(FsError::InodeNotFound)));
        let test_dir = "test-dir";
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), false, true).unwrap();
        assert!(matches!(fs.write_all(dir_attr.ino, 0, &buf, fh), Err(FsError::InvalidInodeType)));
    });
}

#[test]
fn test_read() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_test_file = "test-file";
        let test_file = test_test_file;
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = b"test-42";
        let mut buf = [0; 7];
        fs.write_all(attr.ino, 0, data, fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr.ino, true, false).unwrap();
        let len = fs.read(attr.ino, 0, &mut buf, fh).unwrap();
        assert_eq!(len, 7);
        assert_eq!(data, &buf);

        // larger buffer
        let len = fs.read(attr.ino, 0, &mut [0; 42], fh).unwrap();
        assert_eq!(len, 7);

        // offset
        let data = b"test-37";
        let mut buf = [0; 2];
        let fh = fs.open(attr.ino, false, true).unwrap();
        fs.write_all(attr.ino, 0, data, fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr.ino, true, false).unwrap();
        fs.read(attr.ino, 5, &mut buf, fh).unwrap();
        assert_eq!(b"37", &buf);

        // offset after file end
        let fh = fs.open(attr.ino, true, false).unwrap();
        let len = fs.read(attr.ino, 42, &mut [0, 1], fh).unwrap();
        assert_eq!(len, 0);

        // if it picks up new value after a write after current read position
        let test_file_2 = "test-file-2";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file_2, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = "test-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr.ino, true, false).unwrap();
        fs.read(attr.ino, 0, &mut [0u8; 1], fh).unwrap();
        let fh_2 = fs.open(attr.ino, false, true).unwrap();
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).unwrap();
        fs.flush(fh_2).unwrap();
        fs.release_handle(fh_2).unwrap();
        let mut buf = [0u8; 2];
        fs.read(attr.ino, 5, &mut buf, fh).unwrap();
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it picks up new value after a write before current read position
        let test_file_3 = "test-file-3";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file_3, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr.ino, true, false).unwrap();
        fs.read(attr.ino, 8, &mut [0u8; 1], fh).unwrap();
        let fh_2 = fs.open(attr.ino, false, true).unwrap();
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).unwrap();
        fs.flush(fh_2).unwrap();
        fs.release_handle(fh_2).unwrap();
        let mut buf = [0u8; 2];
        fs.read(attr.ino, 5, &mut buf, fh).unwrap();
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it continues to read correctly after a write before current read position
        let test_file_4 = "test-file-4";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file_4, create_attr_from_type(FileType::RegularFile), false, true).unwrap();
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr.ino, true, false).unwrap();
        fs.read(attr.ino, 7, &mut [0u8; 1], fh).unwrap();
        let fh_2 = fs.open(attr.ino, false, true).unwrap();
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).unwrap();
        fs.flush(fh_2).unwrap();
        fs.release_handle(fh_2).unwrap();
        let mut buf = [0u8; 2];
        fs.read(attr.ino, 8, &mut buf, fh).unwrap();
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // invalid values
        let mut buf = [0; 0];
        assert!(matches!(fs.read(ROOT_INODE, 0, &mut buf, fh), Err(FsError::InvalidInodeType)));
        assert!(matches!(fs.read(0, 0,&mut buf, fh), Err(FsError::InodeNotFound)));
        let test_dir = "test-dir";
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, test_dir, create_attr_from_type(FileType::Directory), true, false).unwrap();
        assert!(matches!(fs.read(dir_attr.ino, 0, &mut buf, fh), Err(FsError::InvalidInodeType)));
    });
}

#[test]
fn test_truncate() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_truncate") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let (fh, attr) = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile), false, false).unwrap();

        // size increase
        fs.truncate(attr.ino, 42).unwrap();
        assert_eq!(42, fs.get_inode(attr.ino).unwrap().size);

        // size doesn't change
        fs.truncate(attr.ino, 42).unwrap();
        assert_eq!(42, fs.get_inode(attr.ino).unwrap().size);

        // size decrease
        fs.truncate(attr.ino, 37).unwrap();
        assert_eq!(37, fs.get_inode(attr.ino).unwrap().size);

        // size decrease to 0
        fs.truncate(attr.ino, 0).unwrap();
        assert_eq!(0, fs.get_inode(attr.ino).unwrap().size);
    });
}

#[test]
fn test_copy_file_range() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_copy_file_range") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_file_1 = "test-file-1";
        let (fh, attr_1) = fs.create_nod(ROOT_INODE, test_file_1, create_attr_from_type(FileType::RegularFile), true, true).unwrap();
        let data = "test-42";
        fs.write_all(attr_1.ino, 0, data.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr_1.ino, true, false).unwrap();
        let test_file_2 = "test-file-2";
        let (fh2, attr_2) = fs.create_nod(ROOT_INODE, test_file_2, create_attr_from_type(FileType::RegularFile), true, true).unwrap();

        // whole file
        let len = fs.copy_file_range(attr_1.ino, 0, attr_2.ino, 0, 7, fh, fh2).unwrap();
        fs.flush(fh2).unwrap();
        fs.release_handle(fh2).unwrap();
        assert_eq!(len, 7);
        let mut buf = [0; 7];
        let fh = fs.open(attr_2.ino, true, false).unwrap();
        fs.read(attr_2.ino, 0, &mut buf, fh).unwrap();
        assert_eq!(data, String::from_utf8(buf.to_vec()).unwrap());

        // offset
        let data_37 = "37";
        let fh = fs.open(attr_1.ino, false, true).unwrap();
        fs.write_all(attr_1.ino, 7, data_37.as_bytes(), fh).unwrap();
        fs.flush(fh).unwrap();
        fs.release_handle(fh).unwrap();
        let fh = fs.open(attr_1.ino, true, false).unwrap();
        let fh_2 = fs.open(attr_2.ino, false, true).unwrap();
        let len = fs.copy_file_range(attr_1.ino, 7, attr_2.ino, 5, 2, fh, fh_2).unwrap();
        fs.flush(fh_2).unwrap();
        fs.release_handle(fh_2).unwrap();
        assert_eq!(len, 2);
        let fh = fs.open(attr_2.ino, true, false).unwrap();
        fs.read(attr_2.ino, 0, &mut buf, fh).unwrap();
        assert_eq!("test-37", String::from_utf8(buf.to_vec()).unwrap());

        // out of bounds
        let fh = fs.open(attr_1.ino, true, false).unwrap();
        let fh_2 = fs.open(attr_2.ino, false, true).unwrap();
        let len = fs.copy_file_range(attr_1.ino, 42, attr_2.ino, 0, 2, fh, fh_2).unwrap();
        assert_eq!(len, 0);

        // invalid inodes
        assert!(matches!(fs.copy_file_range(0, 0, 0, 0, 0, fh, fh_2), Err(FsError::InodeNotFound)));
    });
}

#[test]
fn test_rename() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_rename") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        // new file in same directory
        let new_parent = ROOT_INODE;
        let file_1 = "file-1";
        let (_, attr) = fs.create_nod(ROOT_INODE, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        let file_1_new = "file-1-new";
        fs.rename(ROOT_INODE, file_1, new_parent, file_1_new).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, file_1), true);
        assert_eq!(fs.exists_by_name(new_parent, file_1_new), true);
        let new_attr = fs.find_by_name(new_parent, file_1_new).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1_new).count(), 1);

        // new directory in same directory
        let new_parent = ROOT_INODE;
        let dir_1 = "dir-1";
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let dir_1_new = "dir-1-new";
        fs.rename(ROOT_INODE, dir_1, new_parent, dir_1_new).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, dir_1), true);
        assert_eq!(fs.exists_by_name(new_parent, dir_1_new), true);
        let new_attr = fs.find_by_name(new_parent, dir_1_new).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1_new).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        let (_, new_parent_attr) = fs.create_nod(ROOT_INODE, "dir-new-parent", create_attr_from_type(FileType::Directory), false, false).unwrap();

        // new file to another directory
        let new_parent = new_parent_attr.ino;
        let (_, attr) = fs.create_nod(ROOT_INODE, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        let file_2 = "file-2";
        fs.rename(ROOT_INODE, file_1, new_parent, file_2).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, file_1), true);
        assert_eq!(fs.exists_by_name(new_parent, file_2), true);
        let new_attr = fs.find_by_name(new_parent, file_2).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 0);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "file-new").count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_2).count(), 1);

        // new directory to another directory
        let new_parent = new_parent_attr.ino;
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let dir_2 = "dir-2";
        fs.rename(ROOT_INODE, dir_1, new_parent, dir_2).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, dir_1), true);
        assert_eq!(fs.exists_by_name(new_parent, dir_2), true);
        let new_attr = fs.find_by_name(new_parent, dir_2).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 0);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_2).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_2).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // file to existing file in same directory
        let new_parent = ROOT_INODE;
        let (_, attr) = fs.create_nod(ROOT_INODE, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, file_2, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        fs.rename(ROOT_INODE, file_1, new_parent, file_2).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, file_1), true);
        assert_eq!(fs.exists_by_name(new_parent, file_2), true);
        let new_attr = fs.find_by_name(new_parent, file_2).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_2).count(), 1);

        // directory to existing directory in same directory
        let new_parent = ROOT_INODE;
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, dir_2, create_attr_from_type(FileType::Directory), false, false).unwrap();
        fs.rename(ROOT_INODE, dir_1, new_parent, dir_2).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, dir_1), true);
        assert_eq!(fs.exists_by_name(new_parent, dir_2), true);
        let new_attr = fs.find_by_name(new_parent, dir_2).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_2).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // file to existing file in another directory
        let new_parent = new_parent_attr.ino;
        let (_, attr) = fs.create_nod(ROOT_INODE, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        fs.rename(ROOT_INODE, file_1, new_parent, file_1).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, file_1), true);
        assert_eq!(fs.exists_by_name(new_parent, file_1), true);
        let new_attr = fs.find_by_name(new_parent, file_1).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 1);

        // directory to existing directory in another directory
        let new_parent = new_parent_attr.ino;
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        fs.rename(ROOT_INODE, dir_1, new_parent, dir_1).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, dir_1), true);
        assert_eq!(fs.exists_by_name(new_parent, dir_1), true);
        let new_attr = fs.find_by_name(new_parent, dir_1).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // overwriting directory with file
        let new_parent = ROOT_INODE;
        let (_, attr) = fs.create_nod(ROOT_INODE, file_1, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, dir_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        fs.rename(ROOT_INODE, file_1, new_parent, dir_1).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, file_1), true);
        assert_eq!(fs.exists_by_name(new_parent, dir_1), true);
        let new_attr = fs.find_by_name(new_parent, dir_1).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_1).count(), 1);

        // overwriting file with directory
        let new_parent = ROOT_INODE;
        let dir_3 = "dir-3";
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_3, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let (_, attr_2) = fs.create_nod(new_parent, file_1, create_attr_from_type(FileType::Directory), false, false).unwrap();
        fs.rename(ROOT_INODE, dir_3, new_parent, file_1).unwrap();
        assert_ne!(fs.exists_by_name(ROOT_INODE, dir_3), true);
        assert_eq!(fs.exists_by_name(new_parent, file_1), true);
        let new_attr = fs.find_by_name(new_parent, file_1).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_3).count(), 0);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_1).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // overwriting non-empty directory
        let new_parent = ROOT_INODE;
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_3, create_attr_from_type(FileType::Directory), false, false).unwrap();
        let attr_2 = new_parent_attr;
        let name_2 = "dir-new-parent";
        assert!(matches!(fs.rename(ROOT_INODE, dir_3, new_parent, name_2), Err(FsError::NotEmpty)));
        assert_eq!(fs.exists_by_name(ROOT_INODE, dir_3), true);
        assert_eq!(fs.exists_by_name(new_parent, name_2), true);
        let attr_3 = fs.find_by_name(ROOT_INODE, dir_3).unwrap().unwrap();
        assert_eq!(fs.is_dir(attr_3.ino), true);
        let attr_2 = fs.find_by_name(new_parent, name_2).unwrap().unwrap();
        assert_eq!(fs.is_dir(attr_2.ino), true);
        let new_attr = fs.find_by_name(new_parent, dir_3).unwrap().unwrap();
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        let new_attr_2 = fs.find_by_name(new_parent, name_2).unwrap().unwrap();
        assert_eq!(new_attr_2.ino, attr_2.ino);
        assert_eq!(new_attr_2.kind, attr_2.kind);
        assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_3).count(), 1);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == name_2).count(), 1);
        assert_eq!(fs.find_by_name(new_attr_2.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr_2.ino, ".").unwrap().unwrap().ino, new_attr_2.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // same file in same directory
        let new_parent = ROOT_INODE;
        let file_3 = "file-3";
        let (_, attr) = fs.create_nod(ROOT_INODE, file_3, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        fs.rename(ROOT_INODE, file_3, new_parent, file_3).unwrap();
        assert_eq!(fs.exists_by_name(new_parent, file_3), true);
        let new_attr = fs.find_by_name(new_parent, file_3).unwrap().unwrap();
        assert_eq!(fs.is_file(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == file_3).count(), 1);

        // same directory in same directory
        let new_parent = ROOT_INODE;
        let dir_5 = "dir-5";
        let (_, attr) = fs.create_nod(ROOT_INODE, dir_5, create_attr_from_type(FileType::Directory), false, false).unwrap();
        fs.rename(ROOT_INODE, dir_5, new_parent, dir_5).unwrap();
        assert_eq!(fs.exists_by_name(new_parent, dir_5), true);
        let new_attr = fs.find_by_name(new_parent, dir_5).unwrap().unwrap();
        assert_eq!(fs.is_dir(new_attr.ino), true);
        assert_eq!(new_attr.ino, attr.ino);
        assert_eq!(new_attr.kind, attr.kind);
        assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == dir_5).count(), 1);
        assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
        assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == "..").count(), 1);
        assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.as_ref().unwrap().name == ".").count(), 1);

        // invalid nodes and name
        assert!(matches!(fs.rename(0, "invalid", 0, "invalid"), Err(FsError::InodeNotFound)));
        let (_, attr_file) = fs.create_nod(ROOT_INODE, "existing-file", create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        assert!(matches!(fs.rename(attr_file.ino, "invalid", 0, "invalid"), Err(FsError::InvalidInodeType)));
        assert!(matches!(fs.rename(ROOT_INODE, "invalid", ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
        assert!(matches!(fs.rename(ROOT_INODE, "existing-file", 0, "invalid"), Err(FsError::InodeNotFound)));
        assert!(matches!(fs.rename(ROOT_INODE, "existing-file", attr_file.ino, "invalid"), Err(FsError::InvalidInodeType)));
    });
}

#[test]
fn test_open() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_open") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();

        let test_file = "test-file";
        let (fh, attr) = fs.create_nod(ROOT_INODE, test_file, create_attr_from_type(FileType::RegularFile), false, false).unwrap();
        // single read
        let fh = fs.open(attr.ino, true, false).unwrap();
        assert_ne!(fh, 0);
        // multiple read
        let fh_2 = fs.open(attr.ino, true, false).unwrap();
        assert_ne!(fh_2, 0);
        // write and read
        let fh_w = fs.open(attr.ino, false, true).unwrap();
        // ensure cannot open multiple write
        assert!(matches!(fs.open(attr.ino, false, true), Err(FsError::AlreadyOpenForWrite)));
    });
}

#[allow(dead_code)]
// #[test]
fn test_sample() {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_sample") }, |setup| {
        let fs = setup.fs.as_mut().unwrap();
    });
}
