#[allow(unused_imports)]
use std::str::FromStr;
#[allow(unused_imports)]
use test::{black_box, Bencher};

#[allow(unused_imports)]
use rand::Rng;
#[allow(unused_imports)]
use secrecy::SecretString;

#[allow(unused_imports)]
use crate::encryptedfs::{DirectoryEntry, DirectoryEntryPlus, FileType, ROOT_INODE};
#[allow(unused_imports)]
use crate::test_common::{create_attr, get_fs};
#[allow(unused_imports)]
use crate::{async_util, test_common};

#[bench]
fn bench_create(b: &mut Bencher) {
    test_common::bench("bench_create", 1, false, async {
        let fs = get_fs().await;

        let mut i = 1;
        let i = &mut i;
        b.iter(|| {
            black_box({
                async_util::call_async(async {
                    let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
                    let _ = fs
                        .create(
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
                *i
            })
        });
    });
}

#[bench]
fn bench_exists_by_name(b: &mut Bencher) {
    test_common::bench("exists_by_name", 1, false, async {
        let fs = get_fs().await;

        let mut rnd = rand::thread_rng();
        b.iter(|| {
            async_util::call_async(async {
                let _ = fs
                    .exists_by_name(
                        ROOT_INODE,
                        &SecretString::from_str(&format!("test-file-{}", rnd.gen_range(1..100)))
                            .unwrap(),
                    )
                    .unwrap();
            });
            black_box(());
        });
    });
}

#[bench]
fn bench_find_by_name(b: &mut Bencher) {
    test_common::bench("bench_find_by_name", 1, false, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create(
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
            async_util::call_async(async {
                let _ = fs.get_attr(ROOT_INODE).await.unwrap();
                let _ = fs
                    .find_by_name(
                        ROOT_INODE,
                        &SecretString::from_str(&format!("test-file-{}", rnd.gen_range(1..100)))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            });
            black_box(());
        });
    });
}

#[bench]
fn bench_read_dir(b: &mut Bencher) {
    test_common::bench("bench_read_dir", 1, false, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create(
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
            async_util::call_async(async {
                let iter = fs.read_dir(ROOT_INODE).await.unwrap();
                let vec: Vec<DirectoryEntry> = iter.map(|e| e.unwrap()).collect();
                black_box(vec);
            });
            black_box(());
        });
    });
}

#[bench]
fn bench_read_dir_plus(b: &mut Bencher) {
    test_common::bench("bench_read_dir_plus", 1, false, async {
        let fs = get_fs().await;

        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{i}")).unwrap();
            let _ = fs
                .create(
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
            async_util::call_async(async {
                let iter = fs.read_dir_plus(ROOT_INODE).await.unwrap();
                let vec: Vec<DirectoryEntryPlus> = iter.map(|e| e.unwrap()).collect();
                black_box(vec);
            });
            black_box(());
        });
    });
}
