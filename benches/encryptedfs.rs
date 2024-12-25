use rand::Rng;
use shush_rs::SecretString;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use rencfs::encryptedfs::EncryptedFs;
use rencfs::encryptedfs::{DirectoryEntry, DirectoryEntryPlus, FileType, ROOT_INODE};
use rencfs::test_common::create_attr;
use rencfs::test_common::{run_bench, TestSetup};

fn bench_create(c: &mut Criterion) {
    run_bench(
        TestSetup {
            id: "bench_create",
            read_only_fs: false,
        },
        c,
        setup_fn,
        run_fn,
    );

    async fn setup_fn(_fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {}

    async fn run_fn(fs: Arc<EncryptedFs>, atomic: &AtomicU64) {
        let i = atomic.fetch_add(1, Ordering::SeqCst);
        let test_file = SecretString::from_str(&format!("test-file-{}", i)).unwrap();
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
}

fn bench_exists_by_name(c: &mut Criterion) {
    run_bench(
        TestSetup {
            id: "bench_exists_by_name",
            read_only_fs: false,
        },
        c,
        setup_fn,
        run_fn,
    );

    async fn setup_fn(_fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {}

    async fn run_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        let _ = fs
            .exists_by_name(
                ROOT_INODE,
                &SecretString::from_str(&format!("test-file-{}", thread_rng().gen_range(1..100)))
                    .unwrap(),
            )
            .unwrap();
    }
}

fn bench_find_by_name(c: &mut Criterion) {
    run_bench(
        TestSetup {
            id: "bench_find_by_name",
            read_only_fs: false,
        },
        c,
        setup_fn,
        run_fn,
    );

    // Setup: Pre-create files
    async fn setup_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{}", i)).unwrap();
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
    }

    async fn run_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        let _ = fs
            .find_by_name(
                ROOT_INODE,
                &SecretString::from_str(&format!("test-file-{}", thread_rng().gen_range(1..100)))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}

fn bench_read_dir(c: &mut Criterion) {
    run_bench(
        TestSetup {
            id: "bench_read_dir",
            read_only_fs: false,
        },
        c,
        setup_fn,
        run_fn,
    );

    // Setup: Pre-create files
    async fn setup_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{}", i)).unwrap();
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
    }

    async fn run_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        let iter = fs.read_dir(ROOT_INODE).await.unwrap();
        let _: Vec<DirectoryEntry> = iter.map(|e| e.unwrap()).collect();
    }
}

fn bench_read_dir_plus(c: &mut Criterion) {
    run_bench(
        TestSetup {
            id: "bench_read_dir_plus",
            read_only_fs: false,
        },
        c,
        setup_fn,
        run_fn,
    );

    // Setup: Pre-create files
    async fn setup_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        for i in 0..100 {
            let test_file = SecretString::from_str(&format!("test-file-{}", i)).unwrap();
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
    }

    async fn run_fn(fs: Arc<EncryptedFs>, _atomic: &AtomicU64) {
        let iter = fs.read_dir_plus(ROOT_INODE).await.unwrap();
        let _: Vec<DirectoryEntryPlus> = iter.map(|e| e.unwrap()).collect();
    }
}

criterion_group!(
    benches,
    bench_create,
    bench_exists_by_name,
    bench_find_by_name,
    bench_read_dir,
    bench_read_dir_plus
);
criterion_main!(benches);
