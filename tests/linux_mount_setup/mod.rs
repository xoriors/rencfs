#![cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
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

pub const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
pub const DATA_PATH: &str = "/tmp/rencfs/data";

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
            sleep(Duration::from_millis(100));
            mh
        });

        Self {
            mount_handle: match mh {
                Ok(mh) => Some(mh),
                Err(e) => panic!("Encountered an error mounting {}", e),
            },
            runtime,
        }
    }
}

impl Drop for TestResource {
    fn drop(&mut self) {
        let mh = self
            .mount_handle
            .take()
            .expect("MountHandle should be some");
        let res = self.runtime.block_on(async { mh.umount().await });
        match res {
            Ok(_) => println!("Succesfully unmounted"),
            Err(e) => {
                panic!(
                    "Something went wrong when unmounting {}.You may need to manually unmount",
                    e
                )
            }
        }
    }
}

static mut TEST_RESOURCES: Option<Arc<Mutex<TestResource>>> = None;
static INIT: Once = Once::new();
static TEARDOWN: Once = Once::new();
static RESOURCE_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct TestGuard;

impl TestGuard {
    pub fn setup() -> Self {
        unsafe {
            INIT.call_once(|| {
                println!("Initializing the mount");
                TEST_RESOURCES = Some(Arc::new(Mutex::new(TestResource::new())));
            });
        }
        RESOURCE_COUNT.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

#[allow(static_mut_refs)]
impl Drop for TestGuard {
    fn drop(&mut self) {
        if RESOURCE_COUNT.fetch_sub(1, Ordering::SeqCst) == 1 {
            TEARDOWN.call_once(|| unsafe {
                if let Some(resources) = TEST_RESOURCES.take() {
                    println!("Deinitializing the mount");
                    drop(resources);
                }
            });
        }
    }
}

struct TestPasswordProvider {}
impl PasswordProvider for TestPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("test").unwrap())
    }
}

pub fn get_password_provider() -> Box<dyn PasswordProvider> {
    Box::new(TestPasswordProvider {})
}

pub fn count_files(folder_path: &str) -> u32 {
    println!("<<<[{}]>>>", &folder_path);
    let path = Path::new(folder_path);
    let mut file_count = 0;
    if let Ok(dir_iterator) = fs::read_dir(path) {
        for _entry in dir_iterator {
            let _ = _entry.inspect(|e| println!("[{:?}]", e.file_name()));
            file_count += 1;
        }
    }
    println!("<<< File count [{}] >>>", &file_count);
    file_count
}
