use std::fs::File;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use rand::Rng;
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::SecretVec;
use tracing_test::traced_test;

use crate::crypto::read::RingCryptoRead;
use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_chacha() {
    // Create a buffer with some data
    let data = "Hello, world!";
    let mut cursor = Cursor::new(vec![]);

    let algorithm = &CHACHA20_POLY1305;
    // Create a key for encryption
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(data.as_bytes()).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new(&mut cursor, algorithm, key);

    // Seek to the middle of the data
    reader.seek(SeekFrom::Start(7)).unwrap();

    // Read the rest of the data
    let mut buffer = [0; 6];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the second half of the data
    assert_eq!(&buffer, b"world!");

    // Seek to the start of the data
    reader.seek(SeekFrom::Start(0)).unwrap();

    // Read the first half of the data
    let mut buffer = [0; 5];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the first half of the data
    assert_eq!(&buffer, b"Hello");
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_aes() {
    // Create a buffer with some data
    let data = "Hello, world!";
    let mut cursor = Cursor::new(vec![]);

    let algorithm = &AES_256_GCM;
    // Create a key for encryption
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(data.as_bytes()).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    // Seek to the middle of the data
    reader.seek(SeekFrom::Start(7)).unwrap();

    // Read the rest of the data
    let mut buffer = [0; 6];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the second half of the data
    assert_eq!(&buffer, b"world!");

    // Seek to the start of the data
    reader.seek(SeekFrom::Start(0)).unwrap();

    // Read the first half of the data
    let mut buffer = [0; 5];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the first half of the data
    assert_eq!(&buffer, b"Hello");
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_blocks_chacha() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    // Seek in the second block
    reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();

    // Read the rest of the data
    let mut buffer = vec![0; data.len() - BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the second block of the data
    assert_eq!(&buffer, &data[BLOCK_SIZE..]);

    // Seek inside the first block
    reader.seek(SeekFrom::Start(42)).unwrap();

    // Read some data that extends to second block
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the first block of the data
    assert_eq!(&buffer, &data[42..BLOCK_SIZE + 42]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_blocks_aes() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    // Seek in the second block
    reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();

    // Read the rest of the data
    let mut buffer = vec![0; data.len() - BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the second block of the data
    assert_eq!(&buffer, &data[BLOCK_SIZE..]);

    // Seek inside the first block
    reader.seek(SeekFrom::Start(42)).unwrap();

    // Read some data that extends to second block
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();

    // Check that we read the first block of the data
    assert_eq!(&buffer, &data[42..BLOCK_SIZE + 42]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_blocks_boundary_chacha() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    reader.read_exact(&mut [0; 1]).unwrap();
    // Seek to the second block boundary
    reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    // seek inside the second block
    reader.seek(SeekFrom::Current(42)).unwrap();
    let mut buffer = vec![0; data.len() - BLOCK_SIZE - 42];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[BLOCK_SIZE + 42..]);

    reader.seek(SeekFrom::Start(0)).unwrap();
    // read to position to boundary of second block
    reader.read_exact(&mut [0; BLOCK_SIZE]).unwrap();
    reader.seek(SeekFrom::Current(42)).unwrap();
    let mut buffer = vec![0; data.len() - BLOCK_SIZE - 42];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[BLOCK_SIZE + 42..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_blocks_boundary_aes() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    reader.read_exact(&mut [0; 1]).unwrap();
    // Seek to the second block boundary
    reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    // seek inside the second block
    reader.seek(SeekFrom::Current(42)).unwrap();
    let mut buffer = vec![0; data.len() - BLOCK_SIZE - 42];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[BLOCK_SIZE + 42..]);

    reader.seek(SeekFrom::Start(0)).unwrap();
    // read to position to boundary of second block
    reader.read_exact(&mut [0; BLOCK_SIZE]).unwrap();
    reader.seek(SeekFrom::Current(42)).unwrap();
    let mut buffer = vec![0; data.len() - BLOCK_SIZE - 42];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[BLOCK_SIZE + 42..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_skip_blocks_chacha() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 3 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    reader.seek(SeekFrom::Start(2 * BLOCK_SIZE as u64)).unwrap();
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[2 * BLOCK_SIZE..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_skip_blocks_aes() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 3 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    reader.seek(SeekFrom::Start(2 * BLOCK_SIZE as u64)).unwrap();
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[2 * BLOCK_SIZE..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_in_second_block() {
    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, key.clone());
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, key);

    assert_eq!(
        reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap(),
        BLOCK_SIZE as u64
    );
}
