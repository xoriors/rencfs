#![allow(dead_code)]
#![allow(unused_variables)]

use crate::crypto::fs::OpenOptions;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileType, FsError, FsResult, PasswordProvider
};
use crate::test_common::{init_run_test, TestSetup};
use shush_rs::SecretString;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

static FILENAME: &str = "test1";

static INIT_FS_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_oo_flags() {
    init_run_test(
        TestSetup {
            key: "test_async_file_oo_flags",
            read_only: false,
        },
        async move {
            let _init_lock = INIT_FS_MUTEX.lock().await;

            let fs = get_fs().await.unwrap();
            let path = &fs.data_dir;
            dbg!(path);
            let dir_path_sec = SecretString::from_str("dir").unwrap();
            let file_path_sec = SecretString::from_str(FILENAME).unwrap();
            // Create dir and file in dir
            let dir_new = fs
                .create(1, &dir_path_sec, dir_attr(), true, true)
                .await
                .unwrap();
            fs.release(dir_new.0).await.unwrap();
            let fh_file_in_dir = fs
                .create(dir_new.1.ino, &file_path_sec, file_attr(), true, true)
                .await
                .unwrap();
            fs.release(fh_file_in_dir.0).await.unwrap();
            // Create file in root
            let file_in_root = fs
                .create(1, &file_path_sec, file_attr(), true, true)
                .await
                .unwrap();
            fs.release(file_in_root.0).await.unwrap();

            // Case 1. No flags - existing and non existing file. Read true with existing file in root.
            let file = OpenOptions::new()
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));
            let file = OpenOptions::new().open("aaaa").await.map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            let file = OpenOptions::new()
                .read(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            // File existing in sub directory
            let file = OpenOptions::new()
                .read(true)
                .open("/dir/test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            // Case 2. Create true - existing and non existing file.
            let file = OpenOptions::new()
                .create(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            let file = OpenOptions::new()
                .create(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            // Case 3. Truncate true - existing and non existing file.
            let file = OpenOptions::new()
                .truncate(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            let file = OpenOptions::new()
                .truncate(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            // Case 4. Truncate and Create true - existing and non existing file.
            let file = OpenOptions::new()
                .truncate(true)
                .create(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            let file = OpenOptions::new()
                .truncate(true)
                .create(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::PermissionDenied)));
            // Case 5. Append true.
            let mut file = OpenOptions::new().write(true).open(FILENAME).await.unwrap();
            file.write_all(b"Hello World!").await.unwrap();
            fs.flush(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let file = OpenOptions::new().append(true).open(FILENAME).await;
            assert!(matches!(file, Ok(_)));

            let mut file = file.unwrap();
            assert_eq!(file.stream_position().await.unwrap(), 12);
            fs.set_len(file.context.ino, 0).await.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .append(true)
                .open("aaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::NotFound)));
            // Case 6. Append and Create true.
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(FILENAME)
                .await;
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("aaaa")
                .await;
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();

            // 7. Append and Truncate true
            let file = OpenOptions::new()
                .append(true)
                .truncate(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            let file = OpenOptions::new()
                .append(true)
                .truncate(true)
                .open("aaaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            // 8. Append, Truncate and Create true
            let file = OpenOptions::new()
                .append(true)
                .truncate(true)
                .create(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            let file = OpenOptions::new()
                .append(true)
                .truncate(true)
                .create(true)
                .open("aaaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            // 9. Write true
            let file = OpenOptions::new()
                .write(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .write(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::NotFound)));

            // 10. Write and Create true
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();

            // 11. Write and Truncate true
            let mut file = OpenOptions::new().write(true).open(FILENAME).await.unwrap();
            file.write_all(b"Hello World!").await.unwrap();
            fs.flush(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let size = fs.get_attr(file.context.ino).await.unwrap().size;
            assert_eq!(size, 12);

            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let size = fs.get_attr(file.context.ino).await.unwrap().size;
            assert_eq!(size, 0);

            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();

            // 12. Write, Truncate and Create true
            let mut file = OpenOptions::new().write(true).open(FILENAME).await.unwrap();
            file.write_all(b"Hello World!").await.unwrap();
            fs.flush(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let size = fs.get_attr(file.context.ino).await.unwrap().size;
            assert_eq!(size, 12);

            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let size = fs.get_attr(file.context.ino).await.unwrap().size;
            assert_eq!(size, 0);

            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();

            // 13. Create_new true
            let file = OpenOptions::new()
                .create_new(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::AlreadyExists)));
            let file = OpenOptions::new()
                .create_new(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            // 14. Append and create new
            let file = OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::AlreadyExists)));

            let file = OpenOptions::new()
                .append(true)
                .create_new(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();

            // 15. Write and Create new true
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::AlreadyExists)));

            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("aaaa")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();
            let new_file = SecretString::from_str("aaaa").unwrap();
            fs.remove_file(1, &new_file).await.unwrap();
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_options_paths() {
    init_run_test(
        TestSetup {
            key: "test_async_file_options_paths",
            read_only: false,
        },
        async  {
            let _init_lock = INIT_FS_MUTEX.lock().await;

            let fs = get_fs().await.unwrap();
            let path = &fs.data_dir;
            dbg!(path);

            let dir_path_sec = SecretString::from_str("dir").unwrap();
            let file_path_sec = SecretString::from_str(FILENAME).unwrap();
            // Create dir and file in dir
            let dir_new = fs
                .create(1, &dir_path_sec, dir_attr(), true, true)
                .await
                .unwrap();
            fs.release(dir_new.0).await.unwrap();
            let fh_file_in_dir = fs
                .create(dir_new.1.ino, &file_path_sec, file_attr(), true, true)
                .await
                .unwrap();
            fs.release(fh_file_in_dir.0).await.unwrap();
            // Create file in root
            let file_in_root = fs
                .create(1, &file_path_sec, file_attr(), true, true)
                .await
                .unwrap();
            fs.release(file_in_root.0).await.unwrap();

            // TODO:
            // Empty paths handling
            // Current directory symbols: "././dir/test1"
            // Paths with parent directory? "./../dir/test1"

            // Test paths and sub directories
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(FILENAME)
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(".test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::InvalidInput)));

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("./test1/")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(".//test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("./dir/test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(".//dir//test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("////////dir//test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Ok(_)));
            let file = file.unwrap();
            fs.release(file.context.fh_write).await.unwrap();
            fs.release(file.context.fh_read).await.unwrap();

            // Try to create new in non-existing sub directory
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open("./dir1/test1")
                .await
                .map_err(|e| e.kind());
            assert!(matches!(file, Err(std::io::ErrorKind::NotFound)));
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_write_read() {
    init_run_test(
        TestSetup {
            key: "test_async_file_write_read",
            read_only: false,
        },
        async move {
            let _init_lock = INIT_FS_MUTEX.lock().await;

            let mut file = OpenOptions::new().read(true).write(true).create(true).open("file_read_write").await.unwrap();
            file.write_all(b"Hello world!").await.unwrap();
            let cur = file.stream_position().await.unwrap();
            assert_eq!(cur, 12);

            file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
            let cur = file.stream_position().await.unwrap();
            assert_eq!(cur, 0);
            file.shutdown().await.unwrap();

            let mut file = OpenOptions::new().read(true).open("file_read_write").await.unwrap();

            let mut buf = vec![0u8; 2];
            let bytes_read = file.read(&mut buf).await.unwrap();
            let read_content =
                std::str::from_utf8(&buf[..bytes_read]).unwrap();
            assert_eq!(read_content, "He");

            file.seek(std::io::SeekFrom::Start(2)).await.unwrap();
            let cur = file.stream_position().await.unwrap();
            assert_eq!(cur, 2);

            let mut buf = vec![0u8; 2];
            let bytes_read = file.read(&mut buf).await.unwrap();
            let read_content =
                std::str::from_utf8(&buf[..bytes_read]).unwrap();
            assert_eq!(read_content, "ll");

            file.seek(std::io::SeekFrom::End(0)).await.unwrap();
            let cur = file.stream_position().await.unwrap();

        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_bufread() {
    init_run_test(
        TestSetup {
            key: "test_async_bufread",
            read_only: false,
        },
        async {
            let _init_lock = INIT_FS_MUTEX.lock().await;

            let mut file = OpenOptions::new().read(true).write(true).create(true).open("file_bufread").await.unwrap();
            file.write_all(b"Hello world!").await.unwrap();
            file.shutdown().await.unwrap();
            
            let file = OpenOptions::new().read(true).open("file_bufread").await.unwrap();

            let reader = tokio::io::BufReader::new(file);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                eprintln!("Read line: {}", line);
                assert_eq!(line, "Hello world!");
            }
        },
    )
    .await;
}

struct PasswordProviderImpl {}

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("pass42").unwrap())
    }
}

const fn file_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

const fn dir_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
    EncryptedFs::instance().ok_or(FsError::Other("not initialized"))
}