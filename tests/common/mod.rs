
use std::path::Path;
use std::str::FromStr;

use futures_util::TryFutureExt;
use rencfs::crypto::Cipher;
use rencfs::mount::{create_mount_point, MountPoint, MountHandle};
use rencfs::encryptedfs::PasswordProvider;
use shush_rs::SecretString;

// struct TestResource {
//     mount_handle : MountHandle,
// }

// const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
// const DATA_PATH: &str = "/tmp/rencfs/data";

// impl TestResource {
//     fn new() -> Self {
//         let mount_point = create_mount_point(
//             Path::new(&MOUNT_PATH),
//             Path::new(&DATA_PATH),
//             get_password_provider(),
//             Cipher::ChaCha20Poly1305,
//             false,
//             false,
//             false,
//         );
//         let mnt_handle;
//         tokio::runtime::Builder::new_multi_thread()
//         .worker_threads(1)
//         .enable_all()
//         .build()
//         .unwrap()
//         .block_on(async {
//             mnt_handle =  mount_point.mount().await;
//         });
//         Self { 
//            mount_handle = mnt_handle.unwrap(),
//         }
//     }
// } 

// impl Drop for TestResource {
//     fn drop(&mut self) {
//     }
// }


struct TestPasswordProvider {}
impl PasswordProvider for TestPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        return Some(SecretString::from_str("test").unwrap());
    }
}

pub fn get_password_provider() -> Box<dyn PasswordProvider> {
    return Box::new(TestPasswordProvider {});
}
