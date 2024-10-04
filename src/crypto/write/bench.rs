#[allow(unused_imports)]
use ::test::Bencher;

#[bench]
fn bench_writer_1mb_cha_cha20poly1305_file(b: &mut Bencher) {
    use ::test::black_box;
    use std::io;

    use rand::RngCore;
    use shush_rs::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;
    use crate::stream_util::RandomReader;

    let cipher = Cipher::ChaCha20Poly1305;
    let len = 10 * 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::from(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let mut writer = crypto::create_write(tempfile::tempfile().unwrap(), cipher, &key);
            io::copy(&mut reader, &mut writer).unwrap();
            writer.finish().unwrap()
        })
    });
}

#[bench]
fn bench_writer_1mb_aes256gcm_file(b: &mut Bencher) {
    use ::test::black_box;
    use std::io;

    use rand::RngCore;
    use shush_rs::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;
    use crate::stream_util::RandomReader;

    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::from(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let mut writer = crypto::create_write(tempfile::tempfile().unwrap(), cipher, &key);
            io::copy(&mut reader, &mut writer).unwrap();
            writer.finish().unwrap()
        })
    });
}

#[bench]
fn bench_writer_1mb_cha_cha20poly1305_mem(b: &mut Bencher) {
    use ::test::black_box;
    use std::io;

    use rand::RngCore;
    use shush_rs::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;
    use crate::stream_util::RandomReader;

    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::from(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let cursor_write = io::Cursor::new(vec![]);
            let mut writer = crypto::create_write(cursor_write, cipher, &key);
            io::copy(&mut reader, &mut writer).unwrap();
            writer.finish().unwrap()
        })
    });
}

#[bench]
fn bench_writer_1mb_aes256gcm_mem(b: &mut Bencher) {
    use ::test::black_box;
    use std::io;

    use rand::RngCore;
    use shush_rs::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;
    use crate::stream_util::RandomReader;

    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::from(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let cursor_write = io::Cursor::new(vec![]);
            let mut writer = crypto::create_write(cursor_write, cipher, &key);
            io::copy(&mut reader, &mut writer).unwrap();
            writer.finish().unwrap()
        })
    });
}
