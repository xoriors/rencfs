#![cfg(target_os = "linux")]
mod linux_mount_setup;
use linux_mount_setup::{count_files, TestGuard, DATA_PATH, MOUNT_PATH};
use serial_test::serial;
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::MetadataExt,
    path::Path,
};

#[test]
#[serial]
fn it_mount() {
    let _guard = TestGuard::setup();
    let exists = fs::exists(Path::new(MOUNT_PATH));
    assert!(exists.is_ok(), "failed on mount {}", exists.err().unwrap());
}

#[test]
#[serial]
fn it_create_and_write_file() {
    let _guard = TestGuard::setup();
    let test_file = format!("{MOUNT_PATH}/demo.txt");
    let path = Path::new(&test_file);
    {
        let mut file = File::create_new(path).expect("failed to create file");
        file.write_all(b"test").expect("failed to write to file");

        let metadata = fs::metadata(path).expect("failed to retrieve metadata");
        assert!(metadata.is_file());
        // size as seen through the mount
        assert_eq!(metadata.size(), 4);
        // the encrypted inode must exist in the data dir
        let inode_path = format!("{DATA_PATH}/inodes/{}", metadata.ino());
        assert!(
            fs::exists(Path::new(&inode_path)).unwrap(),
            "inode file not found at {inode_path}"
        );
    }
    fs::remove_file(path).expect("failed to delete file");
}

#[test]
#[serial]
fn it_create_and_rename_file() {
    let _guard = TestGuard::setup();
    let test_file1 = format!("{MOUNT_PATH}/demo1.txt");
    let test_file2 = format!("{MOUNT_PATH}/demo2.txt");
    let path1 = Path::new(&test_file1);
    let path2 = Path::new(&test_file2);

    let mut file1 = File::create_new(path1).expect("failed to create file");
    file1
        .write_all(b"test content")
        .expect("failed to write to file");
    drop(file1);

    fs::rename(path1, path2).expect("failed to rename file");
    assert!(
        !path1.exists(),
        "original file should not exist after rename"
    );
    assert!(path2.exists(), "renamed file should exist after rename");

    // warning! remove does not guarantee immediate removal so this leaks inodes
    fs::remove_file(path2).expect("failed to remove file");
}

#[test]
#[serial]
fn it_create_write_rename_read_delete() {
    const WRITTEN_TEXT: &str = "the quick brown fox jumps over the lazy dog";

    let _guard = TestGuard::setup();
    let test_folder = format!("{MOUNT_PATH}/random");
    let test_file1 = format!("{MOUNT_PATH}/random/initial.txt");
    let test_file1_renamed = format!("{MOUNT_PATH}/random/renamed.txt");
    let test_file2 = format!("{MOUNT_PATH}/random/another.txt");
    let tf_path = Path::new(&test_folder);
    let f1_path = Path::new(&test_file1);
    let f1_renamed_path = Path::new(&test_file1_renamed);
    let f2_path = Path::new(&test_file2);
    let initial_file_count = count_files("/tmp");

    fs::create_dir(tf_path).expect("failed to create directory");

    let mut file1 = File::create_new(f1_path).expect("failed to create file");
    file1
        .write_all(WRITTEN_TEXT.as_bytes())
        .expect("failed to write to file");
    // closing the file flushes it
    drop(file1);

    fs::rename(f1_path, f1_renamed_path).expect("failed to rename file");
    assert!(!f1_path.exists(), "old name should be gone after rename");

    let _file2 = File::create_new(f2_path).expect("failed to create second file");

    // the content must survive the rename
    let content = fs::read_to_string(f1_renamed_path).expect("failed to read renamed file");
    assert_eq!(content, WRITTEN_TEXT, "file content mismatch");

    // check there are no extra files left in /tmp
    assert_eq!(initial_file_count, count_files("/tmp"));

    fs::remove_dir_all(tf_path).expect("failed to remove directory");
}

#[test]
#[serial]
fn it_create_empty_dir_check_attr() {
    let _guard = TestGuard::setup();
    let test_folder = format!("{MOUNT_PATH}/chk_attr");
    let tfd_path = Path::new(&test_folder);

    fs::create_dir(tfd_path).expect("failed to create directory");

    let metadata = fs::metadata(tfd_path).expect("failed to read metadata");
    assert!(metadata.is_dir());
    assert_eq!(metadata.size(), 0);
    assert_ne!(metadata.uid(), 0); // we don't create it as root
    let inode_path = format!("{DATA_PATH}/inodes/{}", metadata.ino());
    assert!(
        fs::exists(Path::new(&inode_path)).unwrap(),
        "inode file not found at {inode_path}"
    );

    fs::remove_dir_all(tfd_path).expect("failed to delete directory");
}
