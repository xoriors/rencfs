use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::RngCore;
use rencfs::crypto;
use rencfs::crypto::write::CryptoWrite;
use rencfs::crypto::Cipher;
use shush_rs::SecretVec;
use std::io;
use std::io::Seek;

fn bench_read_1mb_chacha_file(c: &mut Criterion) {
    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(Box::new(key));

    let file = tempfile::tempfile().unwrap();
    let mut writer = crypto::create_write(file, cipher, &key);
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let file = writer.finish().unwrap();

    c.bench_function("bench_read_1mb_chacha_file", |b| {
        b.iter(|| {
            let mut file = file.try_clone().unwrap();
            file.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(file, cipher, &key);
            black_box(&reader);
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

fn bench_read_1mb_aes_file(c: &mut Criterion) {
    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(Box::new(key));

    c.bench_function("bench_read_1mb_aes_file", |b| {
        b.iter(|| {
            let file = tempfile::tempfile().unwrap();
            let mut writer = crypto::create_write(file, cipher, &key);
            let mut cursor_random = io::Cursor::new(vec![0; len]);
            rand::thread_rng().fill_bytes(cursor_random.get_mut());
            cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
            io::copy(&mut cursor_random, &mut writer).unwrap();
            black_box(&writer);
            writer.finish().unwrap();
        });
    });
}

fn bench_read_1mb_chacha_ram(c: &mut Criterion) {
    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(Box::new(key));

    let cursor_write = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(cursor_write, cipher, &key);
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let cursor_write = writer.finish().unwrap();

    c.bench_function("bench_read_1mb_chacha_ram", |b| {
        b.iter(|| {
            let mut cursor = cursor_write.clone();
            cursor.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(cursor, cipher, &key);
            black_box(&reader);
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

fn bench_read_1mb_aes_ram(c: &mut Criterion) {
    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(Box::new(key));

    let cursor_write = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(cursor_write, cipher, &key);
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let cursor_write = writer.finish().unwrap();

    c.bench_function("bench_read_1mb_aes_file", |b| {
        b.iter(|| {
            let mut cursor = cursor_write.clone();
            cursor.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(cursor, cipher, &key);
            black_box(&reader);
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_read_1mb_chacha_file,
    bench_read_1mb_aes_file,
    bench_read_1mb_chacha_ram,
    bench_read_1mb_aes_ram
);
criterion_main!(benches);
