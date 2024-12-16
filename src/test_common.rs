use std::future::Future;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use std::{env, fs, io};

use criterion::{black_box, Criterion};
use shush_rs::SecretString;
use tempfile::NamedTempFile;
use thread_local::ThreadLocal;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CopyFileRangeReq, CreateFileAttr, EncryptedFs, FileType, PasswordProvider,
};

pub static ATOMIC: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

#[allow(dead_code)]
pub static TESTS_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let tmp = if env::var("RENCFS_RUN_ON_GH")
        .unwrap_or_else(|_| String::new())
        .eq("1")
    {
        NamedTempFile::new_in(".")
            .unwrap()
            .into_temp_path()
            .to_path_buf()
    } else {
        let tmp = NamedTempFile::new().unwrap().into_temp_path();
        fs::remove_file(tmp.to_str().unwrap()).expect("cannot remove tmp file");
        tmp.to_path_buf()
    };
    tmp.parent()
        .expect("oops, we don't have a parent")
        .join("rencfs-test-data")
});

#[allow(dead_code)]
pub static SETUP_RESULT: ThreadLocal<Mutex<Option<SetupResult>>> = ThreadLocal::new();

#[allow(dead_code)]
pub const fn create_attr(kind: FileType) -> CreateFileAttr {
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
pub struct TestSetup {
    /// `id` Needs to be a unique identifier which is used:
    ///    - For the name of the test in the criterion, which is printed in the output and reports,
    ///    - As a prefix to create a tmp dir for the fs.
    ///         It will add the timestamp in millis and a random number to the end of the key to make it unique.
    ///         This is useful if test fails, and you want to see the actual data, as if test fails,
    ///    the tmp dir is not removed.
    #[allow(dead_code)]
    pub id: &'static str,
    pub read_only_fs: bool,
}

pub struct SetupResult {
    #[allow(dead_code)]
    pub fs: Option<Arc<EncryptedFs>>,
    #[allow(dead_code)]
    setup: TestSetup,
}

#[allow(dead_code)]
pub struct PasswordProviderImpl {}
impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("password").unwrap())
    }
}
#[allow(dead_code)]
pub async fn setup(setup: TestSetup) -> SetupResult {
    let path = TESTS_DATA_DIR
        .join(setup.id)
        .join("_")
        .join(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string(),
        )
        .join(rand::random::<u32>().to_string());
    let read_only = setup.read_only_fs;
    let data_dir_str = path.to_str().unwrap();
    let _ = fs::remove_dir_all(data_dir_str);
    let _ = fs::create_dir_all(data_dir_str);

    let fs = EncryptedFs::new(
        Path::new(data_dir_str).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        read_only,
    )
    .await
    .unwrap();

    SetupResult {
        fs: Some(fs),
        setup,
    }
}

#[allow(dead_code)]
pub async fn teardown() -> Result<(), io::Error> {
    let s = SETUP_RESULT.get_or(|| Mutex::new(None));
    let s = s.lock().await;
    let path = TESTS_DATA_DIR.join(s.as_ref().unwrap().setup.id);
    let data_dir_str = path.to_str().unwrap();
    fs::remove_dir_all(data_dir_str)?;

    Ok(())
}

#[allow(dead_code)]
#[allow(clippy::future_not_send)]
pub async fn run_test<T>(setup_in: TestSetup, t: T)
where
    T: Future,
{
    {
        let res = Some(setup(setup_in).await);
        let s = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut s = s.lock().await;
        *s = res;
    }
    t.await;
    teardown().await.unwrap();
}

#[allow(dead_code)]
pub async fn read_to_string(ino: u64, fs: &EncryptedFs) -> String {
    let fh = fs.open(ino, true, false).await.unwrap();
    let buf = &mut [0; 4096];
    let buf2 = vec![];
    let mut cur = Cursor::new(buf2);
    let mut read = 0;
    let mut offset = 0;
    loop {
        if read == buf.len() {
            read = 0;
        }
        let len = fs.read(ino, offset, &mut buf[read..], fh).await.unwrap();
        if len == 0 {
            fs.release(fh).await.unwrap();
            return String::from_utf8(cur.into_inner()).unwrap();
        }
        cur.write_all(&buf[read..len]).unwrap();
        read += len;
        offset += len as u64;
    }
}

#[allow(dead_code)]
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
    let file_range_req = CopyFileRangeReq::builder()
        .src_ino(src_ino)
        .src_offset(src_offset)
        .dest_ino(dest_ino)
        .dest_offset(dest_offset)
        .src_fh(src_fh)
        .dest_fh(dest_fh)
        .build();
    while copied < size {
        let len = fs
            .copy_file_range(&file_range_req, size - copied)
            .await
            .unwrap();
        assert!(!(len == 0 && copied < size), "Failed to copy all bytes");
        copied += len;
    }
}

#[allow(dead_code)]
pub async fn read_exact(fs: &EncryptedFs, ino: u64, offset: u64, buf: &mut [u8], handle: u64) {
    let mut read = 0;
    while read < buf.len() {
        let len = fs
            .read(ino, offset + read as u64, &mut buf[read..], handle)
            .await
            .unwrap();
        assert!(!(len == 0 && read < buf.len()), "Failed to read all bytes");
        read += len;
    }
}

#[allow(dead_code)]
pub fn bench<F: Future + Send + Sync>(
    key: &'static str,
    worker_threads: usize,
    read_only: bool,
    f: F,
) {
    block_on(
        async {
            run_test(
                TestSetup {
                    id: key,
                    read_only_fs: read_only,
                },
                f,
            )
            .await;
        },
        worker_threads,
    );
}

#[allow(dead_code)]
pub fn block_on<F: Future>(future: F, worker_threads: usize) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[allow(dead_code)]
pub fn create_rt(worker_threads: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap()
}

#[allow(dead_code)]
pub async fn get_fs() -> Arc<EncryptedFs> {
    // todo: see if we can simplify how we keep in SETUP_RESULT
    let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
    let mut fs = fs.lock().await;
    fs.as_mut().unwrap().fs.as_ref().unwrap().clone()
}

#[allow(dead_code)]
pub fn bench_setup(setup_in: TestSetup) -> (Runtime, Arc<EncryptedFs>) {
    let rt = create_rt(2);
    let fs = rt.block_on(async {
        {
            let res = Some(setup(setup_in).await);
            let s = SETUP_RESULT.get_or(|| Mutex::new(None));
            let mut s = s.lock().await;
            *s = res;
        }
        let fs = get_fs().await;
        fs
    });
    (rt, fs)
}

#[allow(dead_code)]
pub fn bench_teardown(rt: Runtime) {
    rt.block_on(async {
        teardown().await.unwrap();
    });
}

#[allow(dead_code)]
pub fn run_bench<'a, FSetup, FutSetup, FRun, FutRun>(
    setup: TestSetup,
    c: &mut Criterion,
    setup_fn: FSetup,
    run_fn: FRun,
) where
    FSetup: Fn(Arc<EncryptedFs>, &'a AtomicU64) -> FutSetup,
    FutSetup: Future<Output = ()>,
    FRun: Fn(Arc<EncryptedFs>, &'a AtomicU64) -> FutRun,
    FutRun: Future<Output = ()>,
{
    let id = setup.id;
    let (rt, fs) = bench_setup(setup);

    rt.block_on(async {
        setup_fn(fs.clone(), &ATOMIC).await;
    });

    let z = AtomicBool::new(false);
    c.bench_function(id, |b| {
        b.iter(|| {
            let z2 = z.swap(true, Ordering::SeqCst);
            let _ = rt.block_on(async {
                run_fn(fs.clone(), &ATOMIC).await;
            });
            black_box(z2);
        });
    });

    bench_teardown(rt);
}
