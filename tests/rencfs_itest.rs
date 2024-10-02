mod common;
use common::setup;
use rencfs::{
    crypto::Cipher,
    mount::{create_mount_point, MountPoint},
};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
const DATA_PATH: &str = "/tmp/rencfs/data";

// fn cleanup() {
//     let _ = fs::remove_dir_all(Path::new(MOUNT_PATH));
//     let _ = fs::remove_dir_all(Path::new(DATA_PATH));
// }
#[test]
fn it_mount() {
    setup();
    let exists = fs::exists(Path::new(&MOUNT_PATH));
    assert!(exists.is_ok(),"oops .. failed on mount {}",exists.err().unwrap());

    // let mount_point = create_mount_point(
    //     Path::new(&MOUNT_PATH),
    //     Path::new(&DATA_PATH),
    //     common::get_password_provider(),
    //     Cipher::ChaCha20Poly1305,
    //     false,
    //     false,
    //     false,
    // );
    // let runtime = tokio::runtime::Builder::new_multi_thread()
    //     .worker_threads(1)
    //     .enable_all()
    //     .build()
    //     .unwrap();
    // let mh = runtime
    //     .block_on(async {
    //         let mount_handle = mount_point.mount().await;
    //         return mount_handle;
    //     });
    //     assert!(mh.is_ok(),"failed to mount [{}]",mh.err().unwrap());
    //     let handle = mh.unwrap();
    //     // this above doesn't actually block so maybe there's a race condition
    //     sleep(Duration::from_millis(50));
    //     let res = runtime.block_on( async {
    //         return handle.umount().await;
    //     });
    //     assert!(res.is_ok(), "failed to unmount [{}]", res.err().unwrap());
}

#[test]
fn it_create_file() {
    setup();
    let test_file = format!("{}{}", MOUNT_PATH, "/demo.txt");
    let inodes_path = format!("{}{}", DATA_PATH, "/inodes");
    let fh = File::create_new(Path::new(&test_file));
    assert!(fh.is_ok(), "failed to create [{}]", &test_file);
    let bytes_written = fh.unwrap().write_all("test".as_bytes());
    assert!(bytes_written.is_ok(),"failed to write [{}]",bytes_written.err().unwrap());
    let mut count = 0;
    fs::read_dir(&inodes_path)
        .unwrap()
        .for_each(|_entry| count += 1);
    assert_eq!(count, 2);
    // remove does not guarantee immediate removal
    let res = fs::remove_file(Path::new(&test_file));
    assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
}

#[test]
#[ignore = "not valid yet"]
fn it_create_file2() {
    let mount_point = create_mount_point(
        Path::new(&MOUNT_PATH),
        Path::new(&DATA_PATH),
        common::get_password_provider(),
        Cipher::ChaCha20Poly1305,
        false,
        false,
        false,
    );
    let test_file = format!("{}{}", MOUNT_PATH, "/demo.txt");
    // let test_file2 = format!("{}{}", MOUNT_PATH, "/demo2.txt");
    // let test_file3 = format!("{}{}", MOUNT_PATH, "/demo3.txt");
    let inodes_path = format!("{}{}", DATA_PATH, "/inodes");
    // let contents_path = format!("{}{}", DATA_PATH,"/content");
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mount_handle = mount_point.mount().await;
            assert!(
                mount_handle.is_ok(),
                "failed to mount [{}]",
                mount_handle.err().unwrap()
            );
            let handle = mount_handle.unwrap();
            {
                let fh = File::create_new(Path::new(&test_file));
                assert!(fh.is_ok(), "failed to create [{}]", &test_file);
                let _bytes_written = fh.unwrap().write_all("test".as_bytes());
            }
            let mut count = 0;
            fs::read_dir(&inodes_path)
                .unwrap()
                .for_each(|_entry| count += 1);
            assert_eq!(count, 2);
            // remove does not guarantee immediate removal
            let res = fs::remove_file(Path::new(&test_file));
            assert!(res.is_ok(), "failed to delete [{}]", res.err().unwrap());
            let res = handle.umount().await;
            assert!(res.is_ok(), "failed to unmount [{}]", res.err().unwrap());
        })
}
