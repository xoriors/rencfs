use std::{fs, io};
use std::fs::OpenOptions;
use std::io::Read;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Mutex;

use crate::encryptedfs::{Cipher, CONTENTS_DIR, DirectoryEntry, DirectoryEntryPlus, EncryptedFs, FileAttr, FileType, FsError, FsResult, ROOT_INODE};

const TESTS_DATA_DIR: &str = "/tmp/rencfs-test-data/";

#[derive(Debug, Clone)]
struct TestSetup {
    data_path: String,
}

struct SetupResult {
    fs: Option<EncryptedFs>,
    setup: TestSetup,
}

async fn setup(setup: TestSetup) -> FsResult<SetupResult> {
    let path = setup.data_path.as_str();
    if fs::metadata(path).is_ok() {
        fs::remove_dir_all(path)?;
    }
    fs::create_dir_all(path)?;
    let fs = EncryptedFs::new(path, SecretString::from_str("pass-42").unwrap(), Cipher::ChaCha20).await?;

    Ok(SetupResult {
        fs: Some(fs),
        setup,
    })
}

async fn teardown() -> Result<(), io::Error> {
    let s = SETUP_RESULT.with(|s| Arc::clone(s));
    let mut s = s.lock().await;
    fs::remove_dir_all(s.as_mut().unwrap().setup.data_path.clone())?;

    Ok(())
}

async fn run_test<T>(init: TestSetup, t: T) -> FsResult<()>
    where T: std::future::Future
// + std::panic::UnwindSafe
{
    {
        let s = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut s = s.lock().await;
        *s.deref_mut() = Some(setup(init).await?);
    }

    // let res = std::panic::catch_unwind(|| {
    //     let handle = tokio::runtime::Handle::current();
    //     handle.block_on(async {
    t.await;
    // });
    // });

    teardown().await?;

    Ok(())

    // assert!(res.is_ok());
}

thread_local!(static SETUP_RESULT: Arc<Mutex<Option<SetupResult>>> = Arc::new(Mutex::new(None)));

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

async fn read_to_string(path: PathBuf, fs: &EncryptedFs) -> String {
    let mut buf: Vec<u8> = vec![];
    fs.create_decryptor(OpenOptions::new().read(true).write(true).open(path).unwrap()).await.unwrap().read_to_end(&mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[tokio::test]
async fn test_write_all() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_write_all") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_file = SecretString::from_str("test-file").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        assert_eq!(data, read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);
        let attr = fs.get_inode(attr.ino).await?;
        assert_eq!(data.len() as u64, attr.size);

        // offset greater than current position
        let data = "37";
        let fh = fs.open(attr.ino, false, true).await?;
        fs.write_all(attr.ino, 5, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        assert_eq!(data, &read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await[5..]);

        // offset after file end
        let data = "37";
        let fh = fs.open(attr.ino, false, true).await?;
        fs.write_all(attr.ino, 42, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        assert_eq!(format!("test-37{}37", "\0".repeat(35)), read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);

        // offset before current position, several blocks
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file_2, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42-37-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        let data1 = "01";
        fs.write_all(attr.ino, 5, data1.as_bytes(), fh).await?;
        let data2 = "02";
        fs.write_all(attr.ino, 8, data2.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        assert_eq!("test-01-02-42", &read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);

        // write before current position then write to the end, also check it preserves the content from
        // the first write to offset to end of the file
        let test_file_3 = SecretString::from_str("test-file-3").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file_3, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.write_all(attr.ino, 5, b"37", fh).await?;
        fs.write_all(attr.ino, data.len() as u64, b"-42", fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let new_content = read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await;
        assert_eq!("test-37-37-42", new_content);

        let buf = [0; 0];
        let fh = fs.open(attr.ino, false, true).await?;
        assert!(matches!(fs.write_all(ROOT_INODE, 0, &buf, fh).await, Err(FsError::InvalidInodeType)));
        assert!(matches!(fs.write_all(0, 0, &buf, fh).await, Err(FsError::InodeNotFound)));
        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, true).await?;
        assert!(matches!(fs.write_all(dir_attr.ino, 0, &buf, fh).await, Err(FsError::InvalidInodeType)));

        Ok::<(), FsError>(())
    }).await
}

#[tokio::test]
async fn test_read() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_test_file = SecretString::from_str("test-file").unwrap();
        let test_file = test_test_file;
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = b"test-42";
        let mut buf = [0; 7];
        fs.write_all(attr.ino, 0, data, fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr.ino, true, false).await?;
        let len = fs.read(attr.ino, 0, &mut buf, fh).await?;
        assert_eq!(len, 7);
        assert_eq!(data, &buf);

        // larger buffer
        let len = fs.read(attr.ino, 0, &mut [0; 42], fh).await?;
        assert_eq!(len, 7);

        // offset
        let data = b"test-37";
        let mut buf = [0; 2];
        let fh = fs.open(attr.ino, false, true).await?;
        fs.write_all(attr.ino, 0, data, fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr.ino, true, false).await?;
        fs.read(attr.ino, 5, &mut buf, fh).await?;
        assert_eq!(b"37", &buf);

        // offset after file end
        let fh = fs.open(attr.ino, true, false).await?;
        let len = fs.read(attr.ino, 42, &mut [0, 1], fh).await?;
        assert_eq!(len, 0);

        // if it picks up new value after a write after current read position
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file_2, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr.ino, true, false).await?;
        fs.read(attr.ino, 0, &mut [0_u8; 1], fh).await?;
        let fh_2 = fs.open(attr.ino, false, true).await?;
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).await?;
        fs.flush(fh_2).await?;
        fs.release(fh_2).await?;
        let mut buf = [0_u8; 2];
        fs.read(attr.ino, 5, &mut buf, fh).await?;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it picks up new value after a write before current read position
        let test_file_3 = SecretString::from_str("test-file-3").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file_3, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr.ino, true, false).await?;
        fs.read(attr.ino, 8, &mut [0_u8; 1], fh).await?;
        let fh_2 = fs.open(attr.ino, false, true).await?;
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).await?;
        fs.flush(fh_2).await?;
        fs.release(fh_2).await?;
        let mut buf = [0_u8; 2];
        fs.read(attr.ino, 5, &mut buf, fh).await?;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // if it continues to read correctly after a write before current read position
        let test_file_4 = SecretString::from_str("test-file-4").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file_4, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42-37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr.ino, true, false).await?;
        fs.read(attr.ino, 7, &mut [0_u8; 1], fh).await?;
        let fh_2 = fs.open(attr.ino, false, true).await?;
        let new_data = "37";
        fs.write_all(attr.ino, 5, new_data.as_bytes(), fh_2).await?;
        fs.flush(fh_2).await?;
        fs.release(fh_2).await?;
        let mut buf = [0_u8; 2];
        fs.read(attr.ino, 8, &mut buf, fh).await?;
        assert_eq!(new_data, String::from_utf8(buf.to_vec()).unwrap());

        // invalid values
        let mut buf = [0; 0];
        assert!(matches!(fs.read(ROOT_INODE, 0, &mut buf, fh).await, Err(FsError::InvalidInodeType)));
        assert!(matches!(fs.read(0, 0,&mut buf, fh).await, Err(FsError::InodeNotFound)));
        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (fh, dir_attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), true, false).await?;
        assert!(matches!(fs.read(dir_attr.ino, 0, &mut buf, fh).await, Err(FsError::InvalidInodeType)));

        Ok::<(), FsError>(())
    }).await
}

#[tokio::test]
async fn test_truncate() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_truncate") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_file = SecretString::from_str("test-file").unwrap();
        let (fh, attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, true).await?;
        let data = "test-42";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;

        // size increase, preserve opened writer content
        let fh = fs.open(attr.ino, false, true).await?;
        let data = "37";
        fs.write_all(attr.ino, 5, data.as_bytes(), fh).await?;
        fs.truncate(attr.ino, 10).await?;
        assert_eq!(10, fs.get_inode(attr.ino).await?.size);
        assert_eq!(format!("test-37{}", "\0".repeat(3)), read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);
        fs.release(fh).await?;

        // size doesn't change
        fs.truncate(attr.ino, 10).await?;
        assert_eq!(10, fs.get_inode(attr.ino).await?.size);
        assert_eq!(format!("test-37{}", "\0".repeat(3)), read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);

        // size decrease, preserve opened writer content
        let fh = fs.open(attr.ino, false, true).await?;
        let data = "37";
        fs.write_all(attr.ino, 0, data.as_bytes(), fh).await?;
        fs.truncate(attr.ino, 4).await?;
        assert_eq!(4, fs.get_inode(attr.ino).await?.size);
        assert_eq!("37st", read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);
        fs.release(fh).await?;

        // size decrease to 0
        fs.truncate(attr.ino, 0).await?;
        assert_eq!(0, fs.get_inode(attr.ino).await?.size);
        assert_eq!("".to_string(), read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), &fs).await);

        Ok::<(), FsError>(())
    }).await
}

#[tokio::test]
async fn test_copy_file_range() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_copy_file_range") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let test_file_1 = SecretString::from_str("test-file-1").unwrap();
        let (fh, attr_1) = fs.create_nod(ROOT_INODE, &test_file_1, create_attr_from_type(FileType::RegularFile), true, true).await?;
        let data = "test-42";
        fs.write_all(attr_1.ino, 0, data.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr_1.ino, true, false).await?;
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (fh2, attr_2) = fs.create_nod(ROOT_INODE, &test_file_2, create_attr_from_type(FileType::RegularFile), true, true).await?;

        // whole file
        let len = fs.copy_file_range(attr_1.ino, 0, attr_2.ino, 0, 7, fh, fh2).await?;
        fs.flush(fh2).await?;
        fs.release(fh2).await?;
        assert_eq!(len, 7);
        let mut buf = [0; 7];
        let fh = fs.open(attr_2.ino, true, false).await?;
        fs.read(attr_2.ino, 0, &mut buf, fh).await?;
        assert_eq!(data, String::from_utf8(buf.to_vec()).unwrap());

        // offset
        let data_37 = "37";
        let fh = fs.open(attr_1.ino, false, true).await?;
        fs.write_all(attr_1.ino, 7, data_37.as_bytes(), fh).await?;
        fs.flush(fh).await?;
        fs.release(fh).await?;
        let fh = fs.open(attr_1.ino, true, false).await?;
        let fh_2 = fs.open(attr_2.ino, false, true).await?;
        let len = fs.copy_file_range(attr_1.ino, 7, attr_2.ino, 5, 2, fh, fh_2).await?;
        fs.flush(fh_2).await?;
        fs.release(fh_2).await?;
        assert_eq!(len, 2);
        let fh = fs.open(attr_2.ino, true, false).await?;
        fs.read(attr_2.ino, 0, &mut buf, fh).await?;
        assert_eq!("test-37", String::from_utf8(buf.to_vec()).unwrap());

        // out of bounds
        let fh = fs.open(attr_1.ino, true, false).await?;
        let fh_2 = fs.open(attr_2.ino, false, true).await?;
        let len = fs.copy_file_range(attr_1.ino, 42, attr_2.ino, 0, 2, fh, fh_2).await?;
        assert_eq!(len, 0);

        // invalid inodes
        assert!(matches!(fs.copy_file_range(0, 0, 0, 0, 0, fh, fh_2).await, Err(FsError::InodeNotFound)));

        Ok::<(), FsError>(())
    }).await
}

#[tokio::test]
async fn test_read_dir() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read_dir") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        // file and directory in root
        let test_file = SecretString::from_str("test-file").unwrap();
        let (_fh, file_attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false).await?;

        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (_fh, dir_attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, false).await?;
        let mut entries: Vec<FsResult<DirectoryEntry>> = fs.read_dir(dir_attr.ino).await?.collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
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
        ], entries);

        let iter = fs.read_dir(ROOT_INODE).await?;
        let mut entries: Vec<FsResult<DirectoryEntry>> = iter.into_iter().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        let mut sample = vec![
            DirectoryEntry {
                ino: ROOT_INODE,
                name: SecretString::from_str(".").unwrap(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                ino: file_attr.ino,
                name: SecretString::new(test_file.expose_secret().to_owned()),
                kind: FileType::RegularFile,
            },
            DirectoryEntry {
                ino: dir_attr.ino,
                name: SecretString::new(test_dir.expose_secret().to_owned()),
                kind: FileType::Directory,
            }];
        sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
        assert_eq!(entries.len(), 3);
        assert_eq!(sample, entries);

        // file and directory in another directory
        let parent = dir_attr.ino;
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (_fh, file_attr) = fs.create_nod(parent, &test_file_2, create_attr_from_type(FileType::RegularFile), false, false).await?;

        let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
        let (_fh, dir_attr) = fs.create_nod(parent, &test_dir_2, create_attr_from_type(FileType::Directory), false, false).await?;
        let mut entries: Vec<FsResult<DirectoryEntry>> = fs.read_dir(dir_attr.ino).await?.collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntry> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
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
        ], entries);

        let iter = fs.read_dir(parent).await?;
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
                name: SecretString::new(test_file_2.expose_secret().to_owned()),
                kind: FileType::RegularFile,
            },
            DirectoryEntry {
                ino: dir_attr.ino,
                name: SecretString::new(test_dir_2.expose_secret().to_owned()),
                kind: FileType::Directory,
            }];
        sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
        assert_eq!(entries.len(), 4);
        assert_eq!(sample, entries);

        Ok::<(), FsError>(())
    }).await
}

#[tokio::test]
async fn test_read_dir_plus() -> FsResult<()> {
    run_test(TestSetup { data_path: format!("{TESTS_DATA_DIR}test_read_dir_plus") }, async {
        let fs = SETUP_RESULT.with(|s| Arc::clone(s));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        // file and directory in root
        let test_file = SecretString::from_str("test-file").unwrap();
        let (_fh, file_attr) = fs.create_nod(ROOT_INODE, &test_file, create_attr_from_type(FileType::RegularFile), false, false).await?;

        let test_dir = SecretString::from_str("test-dir").unwrap();
        let (_fh, dir_attr) = fs.create_nod(ROOT_INODE, &test_dir, create_attr_from_type(FileType::Directory), false, false).await?;
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = fs.read_dir_plus(dir_attr.ino).await?.collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        let attr_root = fs.get_inode(ROOT_INODE).await?;
        assert_eq!(vec![
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
        ], entries);

        let iter = fs.read_dir_plus(ROOT_INODE).await?;
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = iter.into_iter().collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        let mut sample = vec![
            DirectoryEntryPlus {
                ino: ROOT_INODE,
                name: SecretString::from_str(".").unwrap(),
                kind: FileType::Directory,
                attr: attr_root,
            },
            DirectoryEntryPlus {
                ino: file_attr.ino,
                name: SecretString::new(test_file.expose_secret().to_owned()),
                kind: FileType::RegularFile,
                attr: file_attr,
            },
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: SecretString::new(test_dir.expose_secret().to_owned()),
                kind: FileType::Directory,
                attr: dir_attr,
            }];
        sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
        assert_eq!(entries.len(), 3);
        assert_eq!(sample, entries);

        // file and directory in another directory
        let parent = dir_attr.ino;
        let attr_parent = dir_attr;
        let test_file_2 = SecretString::from_str("test-file-2").unwrap();
        let (_fh, file_attr) = fs.create_nod(parent, &test_file_2, create_attr_from_type(FileType::RegularFile), false, false).await?;

        let test_dir_2 = SecretString::from_str("test-dir-2").unwrap();
        let (_fh, dir_attr) = fs.create_nod(parent, &test_dir_2, create_attr_from_type(FileType::Directory), false, false).await?;
        // for some reason the tv_nsec is not the same between what create_nod() and read_dir_plus() returns, so we reload it again
        let dir_attr = fs.get_inode(dir_attr.ino).await?;
        let attr_parent = fs.get_inode(attr_parent.ino).await?;
        let mut entries: Vec<FsResult<DirectoryEntryPlus>> = fs.read_dir_plus(dir_attr.ino).await?.collect();
        entries.sort_by(|a, b| a.as_ref().unwrap().name.expose_secret().cmp(&b.as_ref().unwrap().name.expose_secret()));
        let entries: Vec<DirectoryEntryPlus> = entries.into_iter().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(vec![
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
        ], entries);

        let iter = fs.read_dir_plus(parent).await?;
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
                name: SecretString::new(test_file_2.expose_secret().to_owned()),
                kind: FileType::RegularFile,
                attr: file_attr,
            },
            DirectoryEntryPlus {
                ino: dir_attr.ino,
                name: SecretString::new(test_dir_2.expose_secret().to_owned()),
                kind: FileType::Directory,
                attr: dir_attr,
            }];
        sample.sort_by(|a, b| a.name.expose_secret().cmp(&b.name.expose_secret()));
        assert_eq!(entries.len(), 4);
        assert_eq!(sample, entries);

        Ok::<(), FsError>(())
    }).await
}