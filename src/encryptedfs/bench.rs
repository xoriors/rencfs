use std::str::FromStr;
use test::{black_box, Bencher};

use rand::Rng;
use secrecy::SecretString;

use crate::encryptedfs::{DirectoryEntry, DirectoryEntryPlus, FileType, ROOT_INODE};
use crate::test_common::{create_attr, get_fs};
use crate::{async_util, test_common};

#[bench]
fn bench_create_nod(b: &mut Bencher) {
    test_common::bench("bench_create_nod", 1, async {
        let fs = get_fs().await;

        let mut i = 1;
        let i = &mut i;
        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
                    let _ = fs
                        .mk(
                            ROOT_INODE,
                            &test_file,
                            create_attr(FileType::RegularFile),
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
    test_common::bench("exists_by_name", 1, async {
        let fs = get_fs().await;

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
    test_common::bench("bench_find_by_name", 1, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .mk(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
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
                    let _ = fs.get(ROOT_INODE).await.unwrap();
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
    test_common::bench("bench_read_dir", 1, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .mk(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
        }

        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let iter = fs.ls(ROOT_INODE).await.unwrap();
                    let vec: Vec<DirectoryEntry> = iter.map(|e| e.unwrap()).collect();
                    black_box(vec);
                });
            })
        });
    });
}

#[bench]
fn bench_read_dir_plus(b: &mut Bencher) {
    test_common::bench("bench_read_dir_plus", 1, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .mk(
                    ROOT_INODE,
                    &test_file,
                    create_attr(FileType::RegularFile),
                    false,
                    false,
                )
                .await
                .unwrap();
        }

        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let iter = fs.ls_plus(ROOT_INODE).await.unwrap();
                    let vec: Vec<DirectoryEntryPlus> = iter.map(|e| e.unwrap()).collect();
                    black_box(vec);
                });
            })
        });
    });
}
