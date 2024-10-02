use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, Once};
use std::thread::sleep;
use std::time::Duration;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::PasswordProvider;
use rencfs::mount::{create_mount_point, MountHandle, MountPoint};
use shush_rs::SecretString;
use tokio::runtime::Runtime;

struct TestResource {
    mount_handle: Option<MountHandle>,
    runtime: Runtime,
}

const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
const DATA_PATH: &str = "/tmp/rencfs/data";

impl TestResource {
    fn new() -> Self {
        let mount_point = create_mount_point(
            Path::new(&MOUNT_PATH),
            Path::new(&DATA_PATH),
            get_password_provider(),
            Cipher::ChaCha20Poly1305,
            false,
            false,
            false,
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let mh = runtime.block_on(async {
            let mh = mount_point.mount().await;
            sleep(Duration::from_millis(50));
            return mh;
        });

        return Self {
            mount_handle: match mh {
                Ok(mh) => Some(mh),
                Err(e) => panic!("Encountered an error mounting {}", e),
            },
            runtime: runtime,
        };
    }
}

impl Drop for TestResource {
    fn drop(&mut self) {
        println!("Trying to unmount...");
        let mh = self
            .mount_handle
            .take()
            .expect("MountHandle should be some");
        let res = self.runtime.block_on(async {
            return mh.umount().await;
        });
        match res {
            Ok(_) => println!("Succesfully unmounted"),
            Err(e) => panic!(
                "Something went wrong when unmounting {}.You may need to manually unmount",
                e
            ),
        }
    }
}

static mut TEST_RESOURCES: Option<Mutex<TestResource>> = None;
static INIT: Once = Once::new();

pub fn setup() {
    unsafe {
        INIT.call_once(|| {
            TEST_RESOURCES = Some(Mutex::new(TestResource::new()));
        });
    }
}

struct TestPasswordProvider {}
impl PasswordProvider for TestPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        return Some(SecretString::from_str("test").unwrap());
    }
}

pub fn get_password_provider() -> Box<dyn PasswordProvider> {
    return Box::new(TestPasswordProvider {});
}
