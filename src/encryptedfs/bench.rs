use crate::async_util;
use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, DirectoryEntry, DirectoryEntryPlus, EncryptedFs, FileType, PasswordProvider,
    ROOT_INODE,
};
use crate::test_common::{create_attr_from_type, run_test, TestSetup, SETUP_RESULT};
use rand::Rng;
use secrecy::SecretString;
use std::future::Future;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::{fs, io};
use tempfile::NamedTempFile;
use test::{black_box, Bencher};
use thread_local::ThreadLocal;
use tokio::sync::Mutex;

pub fn block_on<F: Future>(future: F, worker_threads: usize) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

pub(crate) fn bench<F: Future>(key: &'static str, worker_threads: usize, f: F) {
    block_on(
        async {
            run_test(TestSetup { key }, f).await;
        },
        worker_threads,
    );
}

#[bench]
fn bench_create_nod(b: &mut Bencher) {
    bench("bench_create_nod", 1, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let mut i = 1;
        let i = &mut i;
        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
                    let _ = fs
                        .create_nod(
                            ROOT_INODE,
                            &test_file,
                            create_attr_from_type(FileType::RegularFile),
                            false,
                            false,
                        )
                        .await
                        .unwrap();
                });
                *i += 1;
                i.clone()
            })
        });
        println!("i: {}", i);
    });
}

#[bench]
fn bench_exists_by_name(b: &mut Bencher) {
    bench("exists_by_name", 1, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        let mut rnd = rand::thread_rng();
        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let _ = fs
                        .exists_by_name(
                            ROOT_INODE,
                            &SecretString::from_str(&format!(
                                "test-file-{}",
                                rnd.gen_range(1..100)
                            ))
                            .unwrap(),
                        )
                        .unwrap();
                });
            })
        });
    });
}

#[bench]
fn bench_find_by_name(b: &mut Bencher) {
    bench("bench_find_by_name", 1, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr_from_type(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
        }

        let mut rnd = rand::thread_rng();
        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let _ = fs.get_inode(ROOT_INODE).await.unwrap();
                    let _ = fs
                        .find_by_name(
                            ROOT_INODE,
                            &SecretString::from_str(&format!(
                                "test-file-{}",
                                rnd.gen_range(1..100)
                            ))
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                });
            })
        });
    });
}

#[bench]
fn bench_read_dir(b: &mut Bencher) {
    bench("bench_read_dir", 1, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr_from_type(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
        }

        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let iter = fs.read_dir(ROOT_INODE, 0).await.unwrap();
                    let vec: Vec<DirectoryEntry> = iter.map(|e| e.unwrap()).collect();
                    black_box(vec);
                });
            })
        });
    });
}

#[bench]
fn bench_read_dir_plus(b: &mut Bencher) {
    bench("bench_read_dir_plus", 1, async {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        let fs = fs.as_mut().unwrap().fs.as_ref().unwrap();

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create_nod(
                    ROOT_INODE,
                    &test_file,
                    create_attr_from_type(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
        }

        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let iter = fs.read_dir_plus(ROOT_INODE, 0).await.unwrap();
                    let vec: Vec<DirectoryEntryPlus> = iter.map(|e| e.unwrap()).collect();
                    black_box(vec);
                });
            })
        });
    });
}
