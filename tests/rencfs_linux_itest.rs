#![cfg(target_os = "linux")]
mod linux_mount_setup;
use linux_mount_setup::{TestGuard, DATA_PATH, MOUNT_PATH};
use serial_test::serial; // <--- ADDED
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    thread,
    time::Duration,
};

#[test]
#[serial] // <--- ADDED
fn it_mount() {
    let _guard = TestGuard::setup();
    let exists = fs::exists(Path::new(MOUNT_PATH));
    assert!(exists.is_ok(), "failed on mount {}", exists.err().unwrap());
}

#[test]
#[serial] // <--- ADDED
fn it_create_and_write_file() {
    let _guard = TestGuard::setup();
    let test_file = format!("{}/demo.txt", MOUNT_PATH);
    let path = Path::new(&test_file);
    {
        let mut file = File::create_new(path).expect("failed to create file");
        let write_result = file.write_all(b"test");
        assert!(write_result.is_ok(), "failed to write to file");
        // Flush to ensure data is written
        file.flush().expect("failed to flush file");

        // Get the inode of the file
        let metadata = file.metadata().expect("failed to get metadata");
        let inode = metadata.ino();

        // Construct the expected inode file path
        let inode_path = format!("{}/inodes/{}", DATA_PATH, inode);

        // Check that the inode file exists (size check removed as encrypted FileAttr is never 4 bytes)
        let mut found = false;
        for _ in 0..5 {
            if let Ok(metadata) = fs::metadata(&inode_path) {
                if metadata.is_file() {
                    found = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(found, "inode file not found at {}", inode_path);
    }
    let _ = fs::remove_file(path);
}

#[test]
#[serial] // <--- ADDED
fn it_create_and_rename_file() {
    let _guard = TestGuard::setup();
    let test_file1 = format!("{}/demo1.txt", MOUNT_PATH);
    let test_file2 = format!("{}/demo2.txt", MOUNT_PATH);

    // Create the first file
    let mut file1 = File::create_new(Path::new(&test_file1))
        .expect("failed to create file");
    // Write some data to make sure it's a valid file
    file1.write_all(b"test content")
        .expect("failed to write to file");
    file1.flush().expect("failed to flush file");

    // Rename the file
    fs::rename(Path::new(&test_file1), Path::new(&test_file2))
        .expect("failed to rename file");

    // Verify the original file no longer exists
    assert!(!Path::new(&test_file1).exists(),
            "original file should not exist after rename");

    // Verify the renamed file exists
    assert!(Path::new(&test_file2).exists(),
            "renamed file should exist after rename");

    // Clean up
    fs::remove_file(Path::new(&test_file2))
        .expect("failed to remove file");
}

#[test]
#[serial] // <--- ADDED
fn it_create_write_rename_read_delete() {
    let _guard = TestGuard::setup();
    let test_folder = format!("{}/random", MOUNT_PATH);
    let test_file1 = format!("{}/random/initial.txt", MOUNT_PATH);
    let test_file1_renamed = format!("{}/random/renamed.txt", MOUNT_PATH);
    let test_file2 = format!("{}/random/another.txt", MOUNT_PATH);

    let tf_path = Path::new(&test_folder);
    let f1_path = Path::new(&test_file1);
    let f1_renamed_path = Path::new(&test_file1_renamed);
    let f2_path = Path::new(&test_file2);

    // Create directory
    fs::create_dir_all(&tf_path).expect("failed to create directory");

    // Create and write to first file
    let mut file1 = File::create_new(&f1_path).expect("failed to create file");
    let written = file1.write(b"the quick brown fox jumps over the lazy dog")
        .expect("failed to write to file");
    assert_eq!(written, 43, "expected to write 43 bytes");
    // Flush to ensure data is written
    file1.flush().expect("failed to flush file");
    // Drop the file handle to close the file
    drop(file1);

    // Rename the file
    fs::rename(&f1_path, &f1_renamed_path).expect("failed to rename file");

    // Create second file
    let _file2 = File::create_new(&f2_path).expect("failed to create second file");

    // Read back the renamed file to ensure data integrity
    let mut buf = Vec::new();
    let mut file1_renamed = File::open(&f1_renamed_path).expect("failed to open renamed file");
    let bytes_read = file1_renamed.read_to_end(&mut buf)
        .expect("failed to read from renamed file");
    assert_eq!(bytes_read, 43, "expected to read 43 bytes");
    assert_eq!(buf, b"the quick brown fox jumps over the lazy dog", "file content mismatch");

    // Clean up
    fs::remove_dir_all(&tf_path).expect("failed to remove directory");
}

#[test]
#[serial] // <--- ADDED
fn it_create_empty_dir_check_attr() {
    let _guard = TestGuard::setup();
    let test_folder = format!("{}/chk_attr", MOUNT_PATH);
    let tfd_path = Path::new(&test_folder);

    let _ = fs::create_dir(tfd_path);

    let mut success = false;
    for _ in 0..50 {
        if let Ok(metadata) = fs::metadata(tfd_path) {
            if metadata.is_dir() {
                success = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    assert!(
        success,
        "Timed out waiting for directory to exist/be accessible."
    );

    let inode_dir = format!("{}/inodes/", DATA_PATH);
    let mut found = false;
    if let Ok(dir) = fs::read_dir(&inode_dir) {
        if dir.count() > 0 {
            found = true;
        }
    }
    assert!(
        found,
        "No inode file (directory entry) was created in data folder"
    );

    let _ = fs::remove_dir_all(tfd_path);
}
