use std::io;
use std::io::Seek;
use std::sync::Arc;
use test::{black_box, Bencher};

use rand::RngCore;
use secrecy::SecretVec;

use crate::crypto;
use crate::crypto::write::CryptoWrite;
use crate::crypto::Cipher;

#[bench]
fn bench_read_1mb_chacha_file(b: &mut Bencher) {
    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let file = tempfile::tempfile().unwrap();
    let mut writer = crypto::create_write(file, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let file = writer.finish().unwrap();

    b.iter(|| {
        black_box({
            let mut file = file.try_clone().unwrap();
            file.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(file, cipher, key.clone());
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

#[bench]
fn bench_read_1mb_aes_file(b: &mut Bencher) {
    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let file = tempfile::tempfile().unwrap();
    let mut writer = crypto::create_write(file, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let file = writer.finish().unwrap();

    b.iter(|| {
        black_box({
            let mut file = file.try_clone().unwrap();
            file.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(file, cipher, key.clone());
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

#[bench]
fn bench_read_1mb_chacha_ram(b: &mut Bencher) {
    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let mut cursor_write = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(&mut cursor_write, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let cursor_write = writer.finish().unwrap();

    b.iter(|| {
        black_box({
            let mut cursor = cursor_write.clone();
            cursor.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(cursor, cipher, key.clone());
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}

#[bench]
fn bench_read_1mb_aes_ram(b: &mut Bencher) {
    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let mut cursor_write = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(&mut cursor_write, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let cursor_write = writer.finish().unwrap();

    b.iter(|| {
        black_box({
            let mut cursor = cursor_write.clone();
            cursor.seek(io::SeekFrom::Start(0)).unwrap();
            let mut reader = crypto::create_read(cursor, cipher, key.clone());
            io::copy(&mut reader, &mut io::sink()).unwrap();
        });
    });
}
