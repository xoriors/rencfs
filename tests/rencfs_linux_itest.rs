#![cfg(target_os = "linux")]
mod linux_mount_setup;
use linux_mount_setup::{count_files, TestGuard, DATA_PATH, MOUNT_PATH};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

#[test]
fn it_mount() {
    let _guard = TestGuard::setup();
    let exists = fs::exists(Path::new(&MOUNT_PATH));
    assert!(
        exists.is_ok(),
        "oops .. failed on mount {}",
        exists.err().unwrap()
    );
}

#[test]
fn it_create_and_write_file() {
    let _guard = TestGuard::setup();
    let test_file = format!("{}{}", MOUNT_PATH, "/demo.txt");
    let path = Path::new(&test_file);
    {
        let res = File::create_new(path);
        assert!(res.is_ok(), "failed to create [{}]", res.err().unwrap());
        let bytes_written = res.unwrap().write_all(b"test");
        assert!(
            bytes_written.is_ok(),
            "failed to write [{}]",
            bytes_written.err().unwrap()
        );
        let res = fs::metadata(path);
        assert!(
            res.is_ok(),
            "failed to retrieve metadata [{}]",
            res.err().unwrap()
        );
        let metadata = res.unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.size(), 4);
        let inode_path = format!("{}{}{}", DATA_PATH, "/inodes/", metadata.ino());
        let inode_exists = fs::exists(Path::new(&inode_path));
        assert!(inode_exists.unwrap());
    }
    let res = fs::remove_file(path);
    assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
}

#[test]
fn it_create_and_rename_file() {
    let _guard = TestGuard::setup();
    let test_file1 = format!("{}{}", MOUNT_PATH, "/demo1.txt");
    let test_file2 = format!("{}{}", MOUNT_PATH, "/demo2.txt");
    {
        let fh = File::create_new(Path::new(&test_file1));
        assert!(fh.is_ok(), "failed to create [{}]", &test_file1);
        let rename = fs::rename(Path::new(&test_file1), Path::new(&test_file2));
        assert!(
            rename.is_ok(),
            " failed to rename [{}] into [{}]",
            &test_file1,
            &test_file2
        );
    }
    // warning! remove does not guarantee immediate removal so this leaks inodes
    let res = fs::remove_file(Path::new(&test_file2));
    assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
}

#[test]
fn it_create_write_rename_read_delete() {
    let _guard = TestGuard::setup();
    let test_folder = format!("{}{}", MOUNT_PATH, "/random");
    let test_file1 = format!("{}{}", MOUNT_PATH, "/random/initial.txt");
    let test_file1_renamed = format!("{}{}", MOUNT_PATH, "/random/renamed.txt");
    let test_file2 = format!("{}{}", MOUNT_PATH, "/random/another.txt");
    let initial_file_count = count_files("/tmp");
    const WRITTEN_TEXT: &str = "the quick brown fox jumps over the lazy dog";
    {
        let tf_path = Path::new(&test_folder);
        let f1_path = Path::new(&test_file1);
        let f2_path = Path::new(&test_file2);
        let mut content = String::new();
        // create folder
        let res = fs::create_dir(tf_path);
        assert!(res.is_ok(), "failed to create [{}]", &test_folder);
        // create file 1
        let fh1 = File::create_new(f1_path);
        assert!(fh1.is_ok(), "failed to create [{}]", &test_file1);
        let mut file_handle1 = fh1.unwrap();
        // write to file 1
        let bytes = &file_handle1.write_all(WRITTEN_TEXT.as_bytes());
        assert!(bytes.is_ok(), "failed to write into [{}]", &test_file1);
        // rename file 1 to renamed
        let rn_path = Path::new(&test_file1_renamed);
        let renamed = fs::rename(f1_path, rn_path);
        assert!(
            renamed.is_ok(),
            "failed to rename [{}] into [{}]",
            &test_file1,
            &test_file1_renamed
        );
        // read contents from file 1 and replace on string
        let _ = &file_handle1.read_to_string(&mut content);
        let to_replace = "fox";
        let with = "bear";
        let modified = content.replace(to_replace, with);
        let bytes = &file_handle1.write_all(modified.as_bytes());
        assert!(
            bytes.is_ok(),
            "failed to write modified contents into [{}]",
            &test_file1
        );
        // create file 2
        let fh2 = File::create_new(f2_path);
        assert!(fh2.is_ok(), "failed to create [{}]", &test_file2);
        let final_file_count = count_files("/tmp");
        // check there are no extra files in /tmp
        assert_eq!(initial_file_count, final_file_count);
    }
    let res = fs::remove_dir_all(Path::new(&test_folder));
    assert!(res.is_ok(), "failed to delete [{}]", &test_folder);
}

#[test]
fn it_create_empty_dir_check_attr() {
    let _guard = TestGuard::setup();
    let test_folder = format!("{}{}", MOUNT_PATH, "/chk_attr");
    let tfd_path = Path::new(&test_folder);
    {
        let res = fs::create_dir(tfd_path);
        assert!(res.is_ok(), "failed to create [{}]", &test_folder);
        let res = fs::metadata(tfd_path);
        assert!(res.is_ok(), "failed to read metadata on [{}]", &test_folder);
        let metadata = res.unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.size(), 0);
        assert_ne!(metadata.uid(), 0); //we don't create it as root
        let inode_path = format!("{}{}{}", DATA_PATH, "/inodes/", metadata.ino());
        let inode_exists = fs::exists(Path::new(&inode_path));
        assert!(inode_exists.unwrap());
    }
    let res = fs::remove_dir_all(Path::new(&test_folder));
    assert!(res.is_ok(), "failed to delete [{}]", &test_folder);
}
