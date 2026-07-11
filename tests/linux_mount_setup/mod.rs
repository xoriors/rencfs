#![cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::sleep;
use std::time::Duration;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::PasswordProvider;
use rencfs::mount::{create_mount_point, MountHandle, MountPoint, umount};
use shush_rs::SecretString;
use tokio::runtime::Runtime;

#[allow(dead_code)]
struct TestResource {
    mount_handle: Option<MountHandle>,
    runtime: Runtime,
}

pub const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
pub const DATA_PATH: &str = "/tmp/rencfs/data";

// Use OnceLock for thread-safe global initialization
static TEST_RESOURCES: OnceLock<Arc<Mutex<TestResource>>> = OnceLock::new();

impl TestResource {
    fn ensure_clean_environment() {
        // Try to unmount using the library function first
        let _ = umount(MOUNT_PATH);
        // Fallback to fusermount3 and fusermount if the above fails
        let _ = Command::new("fusermount3")
            .arg("-u")
            .arg(MOUNT_PATH)
            .status();
        let _ = Command::new("fusermount")
            .arg("-u")
            .arg(MOUNT_PATH)
            .status();
        let _ = fs::remove_dir_all(MOUNT_PATH);
        let _ = fs::remove_dir_all(DATA_PATH);
        let _ = fs::create_dir_all(MOUNT_PATH);
        let _ = fs::create_dir_all(DATA_PATH);
    }

    fn new() -> Self {
        Self::ensure_clean_environment();

        let mount_point = create_mount_point(
            Path::new(MOUNT_PATH),
            Path::new(DATA_PATH),
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
                Err(e) => panic!("Encountered an error mounting {e}"),
            },
            runtime,
        }
    }
}

pub struct TestGuard;

impl TestGuard {
    pub fn setup() -> Self {
        // Initialize once, safely, without unsafe blocks
        TEST_RESOURCES.get_or_init(|| {
            println!("Initializing the mount");
            Arc::new(Mutex::new(TestResource::new()))
        });
        Self
    }
}

// We removed the custom Drop implementation that was manually triggering teardown.
// The OS handles the FUSE cleanup when the process exits, which is safer
// than forcing a teardown during a potential panic or shutdown.

struct TestPasswordProvider {}
impl PasswordProvider for TestPasswordProvider {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("test").unwrap())
    }
}

pub fn get_password_provider() -> Box<dyn PasswordProvider> {
    Box::new(TestPasswordProvider {})
}

#[allow(dead_code)]
pub fn count_files(folder_path: &str) -> u32 {
    let path = Path::new(folder_path);
    let mut file_count = 0;
    if let Ok(dir_iterator) = fs::read_dir(path) {
        for _entry in dir_iterator {
            file_count += 1;
        }
    }
    file_count
}
