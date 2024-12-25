#![allow(dead_code)]
#![allow(unused_variables)]

use std::str::FromStr;

use shush_rs::{SecretBox, SecretString};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::crypto::fs_api::fs::{
    create_dir, create_dir_all, remove_dir, remove_dir_all, remove_file, OpenOptions,
};
use crate::crypto::fs_api::path::Path;
use crate::encryptedfs::{CreateFileAttr, FileType, PasswordProvider};
use crate::test_common::{get_fs, run_test, TestSetup};

static FILENAME: &str = "test1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_funcs() {
    run_test(
        TestSetup {
            key: "test_async_file_funcs",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            // Test `create_dir` function
            // Normal dir
            let path = Path::new("dir");
            create_dir(path).await.unwrap();
            assert!(path.try_exists().unwrap());

            // Create normal dir again
            create_dir(path).await.unwrap();
            assert!(path.try_exists().unwrap());

            let name = SecretBox::from_str("dir").unwrap();
            let result = fs.find_by_name(1, &name).await.unwrap();
            assert!(result.is_some());
            assert_eq!(result.unwrap().kind, FileType::Directory);

            // Create dir path that doesn't exist
            let path = Path::new("foo/bar");
            let result = create_dir(path).await;
            assert!(result.is_err());

            // Create subdir in dir that already exists
            let path = Path::new("dir/more_dir");
            assert!(!path.try_exists().unwrap());
            create_dir(path).await.unwrap();
            assert!(path.try_exists().unwrap());

            // Create dir with empty path
            let path = Path::new("");
            let result = create_dir(path).await;
            assert!(result.is_err());

            // Create dir over a file
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .open("new")
                .await
                .unwrap();
            let path = Path::new("new");
            let result = create_dir_all(path).await;
            let name = SecretBox::from_str("new").unwrap();
            let result = fs.find_by_name(1, &name).await.unwrap();
            assert!(result.is_some());
            assert_eq!(result.unwrap().kind, FileType::RegularFile);

            // Test `create_dir_all` function
            // Create new dirs
            let path = Path::new("foo/bar/baz");
            let result = create_dir_all(path).await;
            assert!(path.try_exists().unwrap());

            // Create new subdir in already existing path
            let path = Path::new("foo/bar/baz/qux");
            let result = create_dir_all(path).await;
            assert!(path.try_exists().unwrap());

            // Create many dirs
            let path = Path::new("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z");
            let result = create_dir_all(path).await;
            assert!(path.try_exists().unwrap());

            // Add .. and . and create_dir in existing path
            let path = Path::new(
                "a/b/c/./d/../d/e/f/./g/h/i/../i/j/k/l/m/n/o/p/q/../q/r/s/t/u/v/w/x/y/z/a",
            );
            let result = create_dir(path).await;
            assert!(path.try_exists().unwrap());

            // Test `remove_file` function
            // Test removing a file that exists
            let path = Path::new("test_file");
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
                .await
                .unwrap();
            assert!(path.try_exists().unwrap());

            // Call remove_file and ensure file is removed
            remove_file(path).await.unwrap();
            assert!(!path.try_exists().unwrap());

            // Test removing a file that doesn't exist
            let path = Path::new("non_existent_file");
            let result = remove_file(path).await;
            assert!(result.is_err());

            // Test removing a file from a directory
            let path = Path::new("dir/file_in_dir");
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&path)
                .await
                .unwrap();
            assert!(path.try_exists().unwrap());

            // Remove the file from the directory
            remove_file(path).await.unwrap();
            assert!(!path.try_exists().unwrap());

            // Test removing a directory instead of a file
            let dir_path = Path::new("another_dir");
            create_dir(dir_path).await.unwrap();
            let result = remove_file(dir_path).await;
            assert!(result.is_err());

            // Test `remove_dir` function
            // Test removing a directory that exists
            let path = Path::new("dir_to_remove");
            create_dir(path).await.unwrap();
            assert!(path.try_exists().unwrap());

            // Call remove_dir and ensure directory is removed
            remove_dir(path).await.unwrap();
            assert!(!path.try_exists().unwrap());

            // Test removing a non-empty directory (should fail if directory contains files)
            let path = Path::new("dir_with_file");
            create_dir(path).await.unwrap();
            let file_path = path.join("file_in_dir");
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&file_path)
                .await
                .unwrap();
            assert!(file_path.try_exists().unwrap());

            // Try to remove the directory with files inside (should fail)
            let result = remove_dir(path).await;
            assert!(result.is_err());

            // Remove the file first, then remove the directory
            remove_file(file_path).await.unwrap();
            remove_dir(path).await.unwrap();
            assert!(!path.try_exists().unwrap());

            // Test removing a directory that doesn't exist
            let path = Path::new("non_existent_dir");
            let result = remove_dir(path).await;
            assert!(result.is_err());

            // Test removing a directory that's not a directory (a file instead)
            let path = Path::new("test_file");
            let _ = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
                .await
                .unwrap();
            let result = remove_dir(path).await;
            assert!(result.is_err());
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_delete_dir_all() {
    run_test(
        TestSetup {
            key: "test_async_file_delete_dir_all",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            // Testing the `remove_dir_all` function
            let dir_path1 = Path::new("foo/dir1/dir_in_dir1");
            let dir_path2 = Path::new("foo/dir2/dir_in_dir2");
            let dir_path3 = Path::new("foo/a/b/c/d/e/f/g/h/i/");
            create_dir_all(dir_path1).await.unwrap();
            create_dir_all(dir_path2).await.unwrap();
            create_dir_all(dir_path3).await.unwrap();
            let file_path1 = Path::new("foo/dir1/dir_in_dir1/file_dir_dir1.rs");
            let file_path2 = Path::new("foo/file_in_root.rs");
            let file_path3 = Path::new("foo/a/b/c/d/e/f/file_in_f.rs");
            let mut file1 = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path1)
                .await
                .unwrap();
            let mut file2 = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path2)
                .await
                .unwrap();
            let mut file3 = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path3)
                .await
                .unwrap();
            file1.shutdown().await.unwrap();
            file2.shutdown().await.unwrap();
            file3.shutdown().await.unwrap();
            remove_dir_all("foo").await.unwrap();
            assert!(!dir_path1.try_exists().unwrap());
            assert!(!dir_path2.try_exists().unwrap());
            assert!(!dir_path3.try_exists().unwrap());
            assert!(!file_path1.try_exists().unwrap());
            assert!(!file_path2.try_exists().unwrap());
            assert!(!file_path3.try_exists().unwrap());
            assert!(!Path::new("foo/a/").try_exists().unwrap());
            assert!(!Path::new("foo").try_exists().unwrap());

            // Delete folder that does not exist
            let result = remove_dir_all("nonexistent_dir").await;
            assert!(result.is_err());

            // Delete a single dir with a folder
            create_dir_all("single_file_dir").await.unwrap();
            let file_path = Path::new("single_file_dir/file.rs");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path)
                .await
                .unwrap();
            file.shutdown().await.unwrap();

            remove_dir_all("single_file_dir").await.unwrap();
            assert!(!file_path.try_exists().unwrap());
            assert!(!Path::new("single_file_dir").try_exists().unwrap());

            // Delete an empty dir
            create_dir_all("empty_dir").await.unwrap();
            remove_dir_all("empty_dir").await.unwrap();
            assert!(!Path::new("empty_dir").try_exists().unwrap());

            // Delete nested empty dirs
            create_dir_all("nested_empty/a/b/c/d").await.unwrap();
            remove_dir_all("nested_empty").await.unwrap();
            assert!(!Path::new("nested_empty").try_exists().unwrap());

            // Delete many files
            create_dir_all("many_files_dir").await.unwrap();
            for i in 0..100 {
                let path = format!("many_files_dir/file_{}.rs", i);
                let file_path = Path::new(&path);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(file_path)
                    .await
                    .unwrap();
                file.shutdown().await.unwrap();
            }

            remove_dir_all("many_files_dir").await.unwrap();
            assert!(!Path::new("many_files_dir").try_exists().unwrap());

            // Delete partialy deleted folder
            create_dir_all("partial_dir/subdir").await.unwrap();
            let file_path = Path::new("partial_dir/file.rs");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path)
                .await
                .unwrap();
            file.shutdown().await.unwrap();

            remove_dir_all("partial_dir/subdir").await.unwrap();

            remove_dir_all("partial_dir").await.unwrap();
            assert!(!Path::new("partial_dir").try_exists().unwrap());
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_oo_flags() {
    run_test(
        TestSetup {
            key: "test_async_file_oo_flags",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            let res: Result<(), String> = async move {
                let path = &fs.data_dir;
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
                // Create a file in root
                let file_in_root = fs
                    .create(1, &file_path_sec, file_attr(), true, true)
                    .await
                    .unwrap();
                fs.release(file_in_root.0).await.unwrap();

                // Case.
                // No flags - existing and non-existing file.
                // Read true with an existing file in root.
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
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();
                // File existing in sub directory
                let file = OpenOptions::new()
                    .read(true)
                    .open("/dir/test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                // Case 2. Create true - existing and non-existing file.
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
                // Case 3. Truncate true - existing and non-existing file.
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
                // Case 4. Truncate and Create true - existing and non-existing file.
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
                assert!(file.is_ok());

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
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("aaaa")
                    .await;
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open("aaaa")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
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
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();
                let new_file = SecretString::from_str("aaaa").unwrap();
                fs.remove_file(1, &new_file).await.unwrap();

                Ok(())
            }
            .await;

            OpenOptions::clear_scope().await;
            res.unwrap();
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_options_paths() {
    run_test(
        TestSetup {
            key: "test_async_file_options_paths",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            let res: Result<(), String> = async move {
                let path = &fs.data_dir;

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
                // Create a file in root
                let file_in_root = fs
                    .create(1, &file_path_sec, file_attr(), true, true)
                    .await
                    .unwrap();
                fs.release(file_in_root.0).await.unwrap();

                // Test paths and sub directories
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(FILENAME)
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(".test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_err());

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
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(".//test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("./dir/test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(".//dir//test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(".//dir//..//dir//test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("././dir//test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
                let file = file.unwrap();
                fs.release(file.context.fh_write).await.unwrap();
                fs.release(file.context.fh_read).await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("////////dir//test1")
                    .await
                    .map_err(|e| e.kind());
                assert!(file.is_ok());
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

                Ok(())
            }
            .await;

            OpenOptions::clear_scope().await;
            res.unwrap();
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_write_read() {
    run_test(
        TestSetup {
            key: "test_async_file_write_read",
            read_only: false,
        },
        async move {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            let res: Result<(), String> = async move {
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open("file_read_write")
                    .await
                    .unwrap();
                file.write_all(b"Hello world!").await.unwrap();
                let cur = file.stream_position().await.unwrap();
                assert_eq!(cur, 12);

                file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
                let cur = file.stream_position().await.unwrap();
                assert_eq!(cur, 0);
                file.shutdown().await.unwrap();

                let mut file = OpenOptions::new()
                    .read(true)
                    .open("file_read_write")
                    .await
                    .unwrap();

                let mut buf = vec![0u8; 2];
                let bytes_read = file.read(&mut buf).await.unwrap();
                let read_content = std::str::from_utf8(&buf[..bytes_read]).unwrap();
                assert_eq!(read_content, "He");

                file.seek(std::io::SeekFrom::Start(2)).await.unwrap();
                let cur = file.stream_position().await.unwrap();
                assert_eq!(cur, 2);

                let mut buf = vec![0u8; 2];
                let bytes_read = file.read(&mut buf).await.unwrap();
                let read_content = std::str::from_utf8(&buf[..bytes_read]).unwrap();
                assert_eq!(read_content, "ll");

                file.seek(std::io::SeekFrom::End(0)).await.unwrap();
                let cur = file.stream_position().await.unwrap();

                Ok(())
            }
            .await;

            OpenOptions::clear_scope().await;
            res.unwrap();
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn test_async_file_bufread() {
    run_test(
        TestSetup {
            key: "test_async_bufread",
            read_only: false,
        },
        async {
            let fs = get_fs().await;
            OpenOptions::set_scope(fs.clone()).await;

            let res: Result<(), String> = async move {
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open("file_bufread")
                    .await
                    .unwrap();
                file.write_all(b"Hello world!").await.unwrap();
                file.shutdown().await.unwrap();

                let file = OpenOptions::new()
                    .read(true)
                    .open("file_bufread")
                    .await
                    .unwrap();

                let reader = tokio::io::BufReader::new(file);
                let mut lines = reader.lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    eprintln!("Read line: {}", line);
                    assert_eq!(line, "Hello world!");
                }

                Ok(())
            }
            .await;

            OpenOptions::clear_scope().await;
            res.unwrap();
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
