mod common;
use common::{cleanup, setup};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

const MOUNT_PATH: &str = "/tmp/rencfs/mnt";

#[test]
fn it_mount() {
    setup();
    let exists = fs::exists(Path::new(&MOUNT_PATH));
    assert!(
        exists.is_ok(),
        "oops .. failed on mount {}",
        exists.err().unwrap()
    );
    cleanup();
}

#[test]
fn it_create_and_write_file() {
    setup();
    let test_file = format!("{}{}", MOUNT_PATH, "/demo.txt");
    let path = Path::new(&test_file);
    {
        let fh = File::create_new(path);
        assert!(fh.is_ok(), "failed to create [{}]", &test_file);
        let bytes_written = fh.unwrap().write_all("test".as_bytes());
        assert!(
            bytes_written.is_ok(),
            "failed to write [{}]",
            bytes_written.err().unwrap()
        );
    }
    // warning! remove does not guarantee immediate removal so this leaks inodes
    let res = fs::remove_file(path);
    assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
    cleanup();
}

#[test]
fn it_create_and_rename_file() {
    setup();
    let test_file1 = format!("{}{}", MOUNT_PATH, "/demo1.txt");
    let test_file2 = format!("{}{}", MOUNT_PATH, "/demo2.txt");
    {
        let fh = File::create_new(Path::new(&test_file1));
        assert!(fh.is_ok(), "failed to create [{}]", &test_file1);
        let rename = fs::rename(Path::new(&test_file1),Path::new(&test_file2));
        assert!(rename.is_ok()," failed to rename [{}] into [{}]", &test_file1, &test_file2);
    }
    // warning! remove does not guarantee immediate removal so this leaks inodes
    let res = fs::remove_file(Path::new(&test_file2));
    assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
    cleanup();
}