#[allow(unused_imports)]
use ::test::Bencher;
use std::io;
use std::io::{Error, Read, Seek, SeekFrom};
use std::sync::Arc;

use rand_core::RngCore;

#[allow(dead_code)]
struct RandomReader {
    buf: Arc<Vec<u8>>,
    pos: usize,
}

impl RandomReader {
    #[allow(dead_code)]
    pub fn new(len: usize) -> Self {
        let mut buf = vec![0; len];
        rand::thread_rng().fill_bytes(&mut buf);
        Self {
            buf: Arc::new(buf),
            pos: 0,
        }
    }
}

impl Read for RandomReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos > self.buf.len() {
            return Ok(0);
        }
        let len = buf.len().min(self.buf.len() - self.pos);
        buf[0..len].copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;
        Ok(len)
    }
}

impl Seek for RandomReader {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.buf.len() as i64 + pos,
            SeekFrom::Current(pos) => self.pos as i64 + pos,
        };
        if new_pos < 0 || new_pos > self.buf.len() as i64 {
            return Err(Error::new(io::ErrorKind::InvalidInput, "outside of bounds"));
        }
        self.pos = new_pos as usize;
        Ok(new_pos as u64)
    }
}

impl Clone for RandomReader {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            pos: 0,
        }
    }
}

#[bench]
fn bench_writer_1mb_cha_cha20poly1305_file(b: &mut Bencher) {
    use ::test::black_box;
    use std::io;

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;

    let cipher = Cipher::ChaCha20Poly1305;
    let len = 10 * 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

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
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;

    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

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
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;

    let cipher = Cipher::ChaCha20Poly1305;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let cursor_write = io::Cursor::new(vec![0; len]);
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
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;

    let cipher = Cipher::Aes256Gcm;
    let len = 1024 * 1024;

    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

    let rnd_reader = RandomReader::new(len);
    b.iter(|| {
        black_box({
            let mut reader = rnd_reader.clone();
            let cursor_write = io::Cursor::new(vec![0; len]);
            let mut writer = crypto::create_write(cursor_write, cipher, &key);
            io::copy(&mut reader, &mut writer).unwrap();
            writer.finish().unwrap()
        })
    });
}
