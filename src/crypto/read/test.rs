#[allow(unused_imports)]
use std::io::{self, Seek};

#[allow(unused_imports)]
use ring::aead::AES_256_GCM;
#[allow(unused_imports)]
use secrecy::SecretVec;
#[allow(unused_imports)]
use tracing_test::traced_test;

#[allow(unused_imports)]
use crate::crypto::read::{CryptoRead, RingCryptoRead};

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(data.as_bytes()).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

    use crate::crypto::read::RingCryptoRead;
    use crate::crypto::write::{CryptoWrite, RingCryptoWrite};

    // Create a buffer with some data
    let data = "Hello, world!";
    let mut cursor = Cursor::new(vec![]);

    let algorithm = &AES_256_GCM;
    // Create a key for encryption
    let key = SecretVec::new(vec![0; algorithm.key_len()]);

    // write the data
    let mut writer = RingCryptoWrite::new(cursor, true, algorithm, &key);
    writer.write_all(data.as_bytes()).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, true, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, true, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(cursor, algorithm, &key);

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
    use secrecy::SecretVec;

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
    let mut writer = RingCryptoWrite::new(cursor, false, algorithm, &key);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();

    // Create a RingCryptoReaderSeek
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = RingCryptoRead::new_seek(&mut cursor, algorithm, &key);

    assert_eq!(
        reader.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap(),
        BLOCK_SIZE as u64
    );
}

#[test]
#[traced_test]
fn finish_seek() {
    let reader = io::Cursor::new(vec![0; 10]);
    let mut reader = RingCryptoRead::new_seek(reader, &AES_256_GCM, &SecretVec::new(vec![0; 32]));
    let mut reader = reader.into_inner();
    let _ = reader.seek(io::SeekFrom::Start(0));
}

#[test]
#[traced_test]
fn reader_only_read() {
    use std::io::Read;

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::Cipher;

    struct ReadOnly {}
    impl Read for ReadOnly {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

    let reader = ReadOnly {};
    let _reader = crypto::create_read(reader, cipher, &key);
    // we are not Seek, this would fail compilation
    // _reader.seek(io::SeekFrom::Start(0)).unwrap();
}

#[test]
#[traced_test]
fn reader_with_seeks() {
    use std::io::{self, Seek, SeekFrom};

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::read::BLOCK_SIZE;
    use crate::crypto::write::CryptoWrite;
    use crate::crypto::Cipher;

    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);

    let len = BLOCK_SIZE * 3 + 42;

    let cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write(cursor, cipher, &key);
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();
    let mut cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();

    let mut reader = crypto::create_read_seek(cursor, cipher, &key);
    reader.seek(SeekFrom::Start(42)).unwrap();
    assert_eq!(reader.stream_position().unwrap(), 42);
}
