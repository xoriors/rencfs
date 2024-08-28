use secrecy::SecretVec;
#[allow(unused_imports)]
use tracing_test::traced_test;
#[allow(dead_code)]
fn create_secret_key(key_len: usize) -> SecretVec<u8> {
    use rand::RngCore;
    use secrecy::SecretVec;
    let mut key = vec![0; key_len];
    rand::thread_rng().fill_bytes(&mut key);
    SecretVec::new(key)
}
#[allow(dead_code)]
fn create_encrypted_data(data: &[u8], key: &SecretVec<u8>) -> Vec<u8> {
    use crate::crypto;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;
    use std::io::Write;
    let writer = Vec::new();
    let cipher = Cipher::ChaCha20Poly1305;

    let mut crypto_writer = crypto::create_write(writer, cipher, key);

    crypto_writer.write_all(data).unwrap();

    crypto_writer.finish().unwrap()
}

#[test]
#[traced_test]
fn test_read_empty() {
    use super::RingCryptoRead;
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;
    use std::io::Read;
    let reader = Cursor::new(vec![]);
    let mut buf = [0u8; 10];
    let cipher = &CHACHA20_POLY1305;
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let mut crypto_reader = RingCryptoRead::new(reader, cipher, &key);
    let result = &crypto_reader.read(&mut buf).unwrap();
    let expected: usize = 0;
    assert_eq!(*result, expected);
}

#[test]
#[traced_test]
fn test_basic_read() {
    use super::RingCryptoRead;
    use crate::crypto::{create_write, write::CryptoWrite, Cipher};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Read;
    use std::io::{Cursor, Write};

    let writer = Vec::new();
    let cipher = Cipher::ChaCha20Poly1305;
    let key = create_secret_key(cipher.key_len());

    let mut crypto_writer = create_write(writer, cipher, &key);

    let data = b"hello, world!";
    crypto_writer.write_all(data).unwrap();
    let encrypted = crypto_writer.finish().unwrap();

    let reader = Cursor::new(encrypted);

    let mut buf = [0u8; 13];
    let cipher = &CHACHA20_POLY1305;
    let mut crypto_reader = RingCryptoRead::new(reader, cipher, &key);

    crypto_reader.read_exact(&mut buf).unwrap();

    assert_eq!(*data, buf);
}

#[test]
#[traced_test]
fn test_read_single_block() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;

    use std::io::Read;
    let binding = "h".repeat(BLOCK_SIZE);
    let data = binding.as_bytes();
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let encrypted_data = create_encrypted_data(data, &key);
    let mut reader = RingCryptoRead::new(Cursor::new(encrypted_data), &CHACHA20_POLY1305, &key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    assert_eq!(reader.read(&mut buf).unwrap(), BLOCK_SIZE);
}

#[test]
#[traced_test]
fn test_read_multiple_blocks() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;

    use std::io::Read;
    let num_blocks = 5;

    let block_size = BLOCK_SIZE * num_blocks;

    let binding = "h".repeat(block_size);
    let data = binding.as_bytes();
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let encrypted_data = create_encrypted_data(data, &key);
    let mut reader = RingCryptoRead::new(Cursor::new(encrypted_data), &CHACHA20_POLY1305, &key);
    let mut buf = vec![0u8; block_size];
    for _ in 0..num_blocks {
        assert_eq!(reader.read(&mut buf).unwrap(), BLOCK_SIZE);
    }
    assert_eq!(reader.read(&mut buf).unwrap(), 0);
}

#[test]
#[traced_test]
fn test_partial_read() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;

    use std::io::Read;
    let binding = "h".repeat(BLOCK_SIZE);
    let data = binding.as_bytes();
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let encrypted_data = create_encrypted_data(data, &key);
    let mut reader = RingCryptoRead::new(Cursor::new(encrypted_data), &CHACHA20_POLY1305, &key);
    let mut buf = vec![0u8; BLOCK_SIZE / 2];
    assert_eq!(reader.read(&mut buf).unwrap(), BLOCK_SIZE / 2);
}

#[test]
#[traced_test]
fn test_read_one_byte_less_than_block() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE, NONCE_LEN};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;
    use std::io::Read;
    let data = vec![0u8; NONCE_LEN + BLOCK_SIZE + CHACHA20_POLY1305.tag_len() - 1];
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let mut reader = RingCryptoRead::new(Cursor::new(data), &CHACHA20_POLY1305, &key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    assert!(reader.read(&mut buf).is_err());
}

#[test]
#[traced_test]
fn test_alternating_small_and_large_reads() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;

    use std::io::Read;
    let num_blocks = 5;

    let block_size = BLOCK_SIZE + num_blocks;

    let binding = "h".repeat(block_size);
    let data = binding.as_bytes();
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let encrypted_data = create_encrypted_data(data, &key);
    let mut reader = RingCryptoRead::new(Cursor::new(encrypted_data), &CHACHA20_POLY1305, &key);
    let mut small_buf = vec![0u8; 10];
    let mut large_buf = vec![0u8; 40];
    assert_eq!(reader.read(&mut small_buf).unwrap(), 10);
    assert_eq!(reader.read(&mut large_buf).unwrap(), 40);
    assert_eq!(reader.read(&mut small_buf).unwrap(), 10);
    assert_eq!(reader.read(&mut large_buf).unwrap(), 40);
    assert_eq!(reader.read(&mut small_buf).unwrap(), 5);
    assert_eq!(reader.read(&mut large_buf).unwrap(), 0);
    assert_eq!(reader.read(&mut small_buf).unwrap(), 0);
}

#[test]
#[traced_test]
fn test_read_one_byte_more_than_block() {
    use crate::crypto::read::{RingCryptoRead, BLOCK_SIZE, NONCE_LEN};
    use ring::aead::CHACHA20_POLY1305;
    use std::io::Cursor;
    use std::io::Read;
    let data = vec![0u8; NONCE_LEN + BLOCK_SIZE + CHACHA20_POLY1305.tag_len() + 1];
    let key = create_secret_key(CHACHA20_POLY1305.key_len());
    let mut reader = RingCryptoRead::new(Cursor::new(data), &CHACHA20_POLY1305, &key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    assert!(reader.read(&mut buf).is_err());
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_chacha() {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use ring::aead::CHACHA20_POLY1305;
    use secrecy::SecretVec;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite};

    // Create a buffer with some data
    let data = "Hello, world!";
    let mut cursor = Cursor::new(vec![]);

    let algorithm = &CHACHA20_POLY1305;
    // Create a key for encryption
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(data.as_bytes()).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use ring::aead::AES_256_GCM;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite};

    // Create a buffer with some data
    let data = "Hello, world!";
    let mut cursor = Cursor::new(vec![]);

    let algorithm = &AES_256_GCM;
    // Create a key for encryption
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(data.as_bytes()).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::CHACHA20_POLY1305;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::AES_256_GCM;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::CHACHA20_POLY1305;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::AES_256_GCM;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::CHACHA20_POLY1305;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 3 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &CHACHA20_POLY1305;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

    reader.seek(SeekFrom::Start(2 * BLOCK_SIZE as u64)).unwrap();
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[2 * BLOCK_SIZE..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_skip_blocks_aes() {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::AES_256_GCM;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0u8; 3 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

    reader.seek(SeekFrom::Start(2 * BLOCK_SIZE as u64)).unwrap();
    let mut buffer = vec![0; BLOCK_SIZE];
    reader.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, &data[2 * BLOCK_SIZE..]);
}

#[test]
#[traced_test]
fn test_ring_crypto_read_seek_in_second_block() {
    use std::io::{Cursor, Seek, SeekFrom, Write};

    use rand::Rng;
    use ring::aead::AES_256_GCM;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite, BLOCK_SIZE};

    // Create a buffer with some data larger than BUF_SIZE
    let mut data = vec![0; 2 * BLOCK_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut data[..]);
    let mut cursor = Cursor::new(vec![]);

    // Create a key for encryption
    let algorithm = &AES_256_GCM;
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(&mut cursor, algorithm, &key);
    writer.write_all(&data).unwrap();
    writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

    assert_eq!(
        reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap(),
        BLOCK_SIZE as u64
    );
}
