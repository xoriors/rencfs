use crate::crypto::Cipher;
use crate::encryptedfs::{CreateFileAttr, EncryptedFs, FileType, PasswordProvider};
use secrecy::SecretString;
use std::io::Read;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::{fs, io};
use tempfile::NamedTempFile;
use thread_local::ThreadLocal;
use tokio::sync::Mutex;

pub(crate) const TESTS_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let tmp = NamedTempFile::new().unwrap().into_temp_path();
    fs::remove_file(tmp.to_str().unwrap()).expect("cannot remove tmp file");
    tmp.parent()
        .expect("oops, we don't have a parent")
        .join("rencfs-test-data")
});

pub(crate) static SETUP_RESULT: ThreadLocal<Mutex<Option<SetupResult>>> = ThreadLocal::new();

pub(crate) fn create_attr_from_type(kind: FileType) -> CreateFileAttr {
    CreateFileAttr {
        kind,
        perm: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestSetup {
    pub(crate) key: &'static str,
}

pub(crate) struct SetupResult {
    pub(crate) fs: Option<Arc<EncryptedFs>>,
    setup: TestSetup,
}

async fn setup(setup: TestSetup) -> SetupResult {
    let path = TESTS_DATA_DIR.join(setup.key).to_path_buf();
    let data_dir_str = path.to_str().unwrap();
    let _ = fs::remove_dir_all(data_dir_str);
    let _ = fs::create_dir_all(data_dir_str);
    println!("data dir {}", data_dir_str);

    struct PasswordProviderImpl {}
    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            Some(SecretString::from_str("password").unwrap())
        }
    }

    let fs = EncryptedFs::new(
        Path::new(data_dir_str).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
    )
    .await
    .unwrap();

    SetupResult {
        fs: Some(fs),
        setup,
    }
}

async fn teardown() -> Result<(), io::Error> {
    let s = SETUP_RESULT.get_or(|| Mutex::new(None));
    let s = s.lock().await;
    let path = TESTS_DATA_DIR
        .join(s.as_ref().unwrap().setup.key)
        .to_path_buf();
    let data_dir_str = path.to_str().unwrap();
    fs::remove_dir_all(data_dir_str)?;

    Ok(())
}

pub(crate) async fn run_test<T>(init: TestSetup, t: T)
where
    T: std::future::Future, // + std::panic::UnwindSafe
{
    {
        let s = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut s = s.lock().await;
        *s.deref_mut() = Some(setup(init).await);
    }

    // let res = std::panic::catch_unwind(|| {
    //     let handle = tokio::runtime::Handle::current();
    //     handle.block_on(async {
    t.await;
    // });
    // });

    teardown().await.unwrap();

    // assert!(res.is_ok());
}

pub async fn read_to_string(path: PathBuf, fs: &EncryptedFs) -> String {
    let mut buf: Vec<u8> = vec![];
    fs.create_file_reader(&path, None)
        .await
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    String::from_utf8(buf).unwrap()
}

pub async fn copy_all_file_range(
    fs: &EncryptedFs,
    src_ino: u64,
    src_offset: u64,
    dest_ino: u64,
    dest_offset: u64,
    size: usize,
    src_fh: u64,
    dest_fh: u64,
) {
    let mut copied = 0;
    while copied < size {
        let len = fs
            .copy_file_range(
                src_ino,
                src_offset + copied as u64,
                dest_ino,
                dest_offset + copied as u64,
                size - copied,
                src_fh,
                dest_fh,
            )
            .await
            .unwrap();
        if len == 0 && copied < size {
            panic!("Failed to copy all bytes");
        }
        copied += len;
    }
}

pub async fn read_exact(fs: &EncryptedFs, ino: u64, offset: u64, buf: &mut [u8], handle: u64) {
    let mut read = 0;
    while read < buf.len() {
        let len = fs
            .read(ino, offset + read as u64, &mut buf[read..], handle)
            .await
            .unwrap();
        if len == 0 && read < buf.len() {
            panic!("Failed to read all bytes");
        }
        read += len;
    }
}
