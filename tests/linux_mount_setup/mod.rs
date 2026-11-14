#![cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::thread::sleep;
use std::time::Duration;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::PasswordProvider;
use rencfs::mount::{create_mount_point, umount, MountHandle, MountPoint};
use shush_rs::SecretString;
use tokio::runtime::Runtime;

struct TestResource {
    mount_handle: Option<MountHandle>,
    runtime: Runtime,
}

pub const MOUNT_PATH: &str = "/tmp/rencfs/mnt";
pub const DATA_PATH: &str = "/tmp/rencfs/data";

static TEST_RESOURCES: OnceLock<Mutex<TestResource>> = OnceLock::new();

/// Unmounts whatever is mounted on [`MOUNT_PATH`], ignoring "not mounted" errors.
fn force_umount() {
    if umount(MOUNT_PATH).is_ok() {
        return;
    }
    for cmd in ["fusermount3", "fusermount"] {
        if let Ok(status) = Command::new(cmd).arg("-u").arg(MOUNT_PATH).status() {
            if status.success() {
                return;
            }
        }
    }
}

/// Runs when the test process exits, statics are never dropped so we cannot rely on `Drop`.
extern "C" fn teardown() {
    let Some(resources) = TEST_RESOURCES.get() else {
        return;
    };
    // don't panic in an exit handler, a test could have failed while holding the lock
    let mut resources = match resources.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(mh) = resources.mount_handle.take() {
        if let Err(err) = resources.runtime.block_on(mh.umount()) {
            eprintln!("cannot unmount {MOUNT_PATH}: {err}, trying to force unmount");
            force_umount();
        }
    }
}

impl TestResource {
    fn ensure_clean_environment() {
        // a previous run that was killed could have left a stale mount behind
        force_umount();
        for path in [MOUNT_PATH, DATA_PATH] {
            match fs::remove_dir_all(path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => panic!("cannot clean {path}: {err}"),
            }
            fs::create_dir_all(path).unwrap_or_else(|err| panic!("cannot create {path}: {err}"));
        }
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
        TEST_RESOURCES.get_or_init(|| {
            println!("Initializing the mount");
            let resources = Mutex::new(TestResource::new());
            // unmount when the test binary exits
            unsafe {
                libc::atexit(teardown);
            }
            resources
        });
        Self
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
    let path = Path::new(folder_path);
    let mut file_count = 0;
    if let Ok(dir_iterator) = fs::read_dir(path) {
        for _entry in dir_iterator {
            file_count += 1;
        }
    }
    file_count
}
