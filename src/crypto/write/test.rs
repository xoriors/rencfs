use std::io;
use std::io::{Read, Seek};
use std::io::{SeekFrom, Write};
use std::sync::Arc;

use rand::RngCore;
use secrecy::SecretVec;
use tracing_test::traced_test;

use crate::crypto;
use crate::crypto::read::CryptoRead;
use crate::crypto::write::{CryptoWrite, BLOCK_SIZE};
use crate::crypto::Cipher;

#[test]
#[traced_test]
fn test_reader_writer_chacha() {
    let cipher = Cipher::ChaCha20Poly1305;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    // simple text
    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let data = "hello, this is my secret message";
    writer.write_all(data.as_bytes()).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    assert_eq!(data, s);

    // larger data
    let mut cursor = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let mut data: [u8; BLOCK_SIZE + 42] = [0; BLOCK_SIZE + 42];
    rand::thread_rng().fill_bytes(&mut data);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    let mut data2 = vec![];
    reader.read_to_end(&mut data2).unwrap();
    assert_eq!(data.len(), data2.len());
    assert_eq!(crypto::hash(&data), crypto::hash(&data2));
}

#[test]
#[traced_test]
fn test_reader_writer_1mb_chacha() {
    let cipher = Cipher::ChaCha20Poly1305;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let len = 1024 * 1024;

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();
    cursor = writer.finish().unwrap();
    cursor_random.seek(SeekFrom::Start(0)).unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    let hash1 = crypto::hash_reader(&mut cursor_random).unwrap();
    let hash2 = crypto::hash_reader(&mut reader).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
#[traced_test]
fn test_reader_writer_aes() {
    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    // simple text
    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let data = "hello, this is my secret message";
    writer.write_all(data.as_bytes()).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    assert_eq!(data, s);

    // larger data
    let mut cursor = io::Cursor::new(vec![]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let mut data: [u8; BLOCK_SIZE + 42] = [0; BLOCK_SIZE + 42];
    rand::thread_rng().fill_bytes(&mut data);
    writer.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    let mut data2 = vec![];
    reader.read_to_end(&mut data2).unwrap();
    assert_eq!(data.len(), data2.len());
    assert_eq!(crypto::hash(&data), crypto::hash(&data2));
}

#[test]
#[traced_test]
fn test_reader_writer_1mb_aes() {
    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = SecretVec::new(key);
    let key = Arc::new(key);

    let len = 1024 * 1024;

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();
    cursor = writer.finish().unwrap();
    cursor_random.seek(SeekFrom::Start(0)).unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    let hash1 = crypto::hash_reader(&mut cursor_random).unwrap();
    let hash2 = crypto::hash_reader(&mut reader).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_text_chacha() {
    let cipher = Cipher::ChaCha20Poly1305;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer
        .write_all(b"This is a test message for the seek capability")
        .unwrap();
    writer.seek(SeekFrom::Start(5)).unwrap();
    writer.write_all(b"IS").unwrap();
    writer.seek(SeekFrom::Start(27)).unwrap();
    writer.write_all(b"THE").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a test message for THE seek capability", s.as_str());

    // open existing content
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(10)).unwrap();
    writer.write_all(b"TEST").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST message for THE seek capability", s.as_str());

    // seek current
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Current(15)).unwrap();
    writer.write_all(b"MESSAGE").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST MESSAGE for THE seek capability", s.as_str());

    // seek from the end
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(-15)).unwrap();
    writer.write_all(b"SEEK").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST MESSAGE for THE SEEK capability", s.as_str());

    // seek < 0
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    assert!(writer.seek(SeekFrom::Current(-1)).is_err());
    cursor = writer.finish().unwrap();

    // seek after content size
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(1)).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    reader.into_inner();
    assert_eq!(
        "This IS a TEST MESSAGE for THE SEEK capability\0",
        s.as_str()
    );

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut buf: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    writer.write_all(&buf).unwrap();
    writer.seek(SeekFrom::Start(5)).unwrap();
    writer.write_all(&[1, 1]).unwrap();
    writer.seek(SeekFrom::Start(8)).unwrap();
    writer.write_all(&[2, 2]).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut buf2 = [0; 10];
    reader.read_exact(&mut buf2).unwrap();
    cursor = reader.into_inner();
    buf[5] = 1;
    buf[6] = 1;
    buf[8] = 2;
    buf[9] = 2;
    assert_eq!(buf, buf2);

    // open existing content
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(3)).unwrap();
    writer.write_all(&[3, 3]).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    buf[3] = 3;
    buf[4] = 3;
    let mut buf2 = [0; 10];
    reader.read_exact(&mut buf2).unwrap();
    reader.into_inner();
    assert_eq!(buf, buf2);
}

#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_text_aes() {
    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer
        .write_all(b"This is a test message for the seek capability")
        .unwrap();
    writer.seek(SeekFrom::Start(5)).unwrap();
    writer.write_all(b"IS").unwrap();
    writer.seek(SeekFrom::Start(27)).unwrap();
    writer.write_all(b"THE").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a test message for THE seek capability", s.as_str());

    // open existing content
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(10)).unwrap();
    writer.write_all(b"TEST").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST message for THE seek capability", s.as_str());

    // seek current
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Current(15)).unwrap();
    writer.write_all(b"MESSAGE").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST MESSAGE for THE seek capability", s.as_str());

    // seek from the end
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(-15)).unwrap();
    writer.write_all(b"SEEK").unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    cursor = reader.into_inner();
    assert_eq!("This IS a TEST MESSAGE for THE SEEK capability", s.as_str());

    // seek < 0
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    assert!(writer.seek(SeekFrom::Current(-1)).is_err());
    cursor = writer.finish().unwrap();

    // seek after content size
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(1)).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut s = String::new();
    reader.read_to_string(&mut s).unwrap();
    reader.into_inner();
    assert_eq!(
        "This IS a TEST MESSAGE for THE SEEK capability\0",
        s.as_str()
    );

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut buf: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    writer.write_all(&buf).unwrap();
    writer.seek(SeekFrom::Start(5)).unwrap();
    writer.write_all(&[1, 1]).unwrap();
    writer.seek(SeekFrom::Start(8)).unwrap();
    writer.write_all(&[2, 2]).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key.clone());
    let mut buf2 = [0; 10];
    reader.read_exact(&mut buf2).unwrap();
    cursor = reader.into_inner();
    buf[5] = 1;
    buf[6] = 1;
    buf[8] = 2;
    buf[9] = 2;
    assert_eq!(buf, buf2);

    // open existing content
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(3)).unwrap();
    writer.write_all(&[3, 3]).unwrap();
    cursor = writer.finish().unwrap();
    cursor.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(cursor, cipher, key);
    buf[3] = 3;
    buf[4] = 3;
    let mut buf2 = [0; 10];
    reader.read_exact(&mut buf2).unwrap();
    reader.into_inner();
    assert_eq!(buf, buf2);
}

#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_blocks_chacha() {
    let cipher = Cipher::ChaCha20Poly1305;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let len = BLOCK_SIZE * 3 + 42;
    let data = [42];

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();

    // seek and write in the first block
    writer.seek(SeekFrom::Start(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42);
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write something that extends to the second block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42);
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(vec![0_u8; BLOCK_SIZE].as_slice()).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42 + BLOCK_SIZE as u64);
    cursor_random
        .write_all(vec![0_u8; BLOCK_SIZE].as_slice())
        .unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write at the boundary of block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write after boundary of block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64 + 42);
    cursor_random.seek(SeekFrom::Current(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write until block boundary then seek and write inside new block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    writer.seek(SeekFrom::Current(43)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 43 + BLOCK_SIZE as u64);
    cursor_random.seek(SeekFrom::Current(43)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek from block boundary to block boundary
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(BLOCK_SIZE as i64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 2 * BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Current(BLOCK_SIZE as i64))
        .unwrap();
    writer
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        2 * BLOCK_SIZE as u64 + 43
    );
    cursor_random
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek after content size, make sure it writes zeros
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek after content size, more blocks, make sure it writes zeros
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer
        .seek(SeekFrom::End(10 * BLOCK_SIZE as i64 + 43))
        .unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 10 * BLOCK_SIZE as u64 + 43
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random
        .write_all(vec![0; 10 * BLOCK_SIZE + 43].as_slice())
        .unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write something after the end then seek after the end, after write we should have a bigger end
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap()
    );
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after the end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key);
}

#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_blocks_aes() {
    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let len = BLOCK_SIZE * 3 + 42;
    let data = [42];

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();

    // seek and write in the first block
    writer.seek(SeekFrom::Start(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42);
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write something that extends to the second block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42);
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(vec![0_u8; BLOCK_SIZE].as_slice()).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 42 + BLOCK_SIZE as u64);
    cursor_random
        .write_all(vec![0_u8; BLOCK_SIZE].as_slice())
        .unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write at the boundary of block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write after boundary of block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(42)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64 + 42);
    cursor_random.seek(SeekFrom::Current(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write until block boundary then seek and write inside new block
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    writer.seek(SeekFrom::Current(43)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 43 + BLOCK_SIZE as u64);
    cursor_random.seek(SeekFrom::Current(43)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek from block boundary to block boundary
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(BLOCK_SIZE as i64)).unwrap();
    assert_eq!(writer.stream_position().unwrap(), 2 * BLOCK_SIZE as u64);
    cursor_random
        .seek(SeekFrom::Current(BLOCK_SIZE as i64))
        .unwrap();
    writer
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        2 * BLOCK_SIZE as u64 + 43
    );
    cursor_random
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek after content size, make sure it writes zeros
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // seek after content size, more blocks, make sure it writes zeros
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer
        .seek(SeekFrom::End(10 * BLOCK_SIZE as i64 + 43))
        .unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 10 * BLOCK_SIZE as u64 + 43
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random
        .write_all(vec![0; 10 * BLOCK_SIZE + 43].as_slice())
        .unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key.clone());

    // write something after the end then seek after the end, after write we should have a bigger end
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap()
    );
    writer.seek(SeekFrom::End(42)).unwrap();
    assert_eq!(
        writer.stream_position().unwrap(),
        cursor_random.stream_len().unwrap() + 42
    );
    // Cursor does not write zeros if we seek after the end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key);
}

/// Do all operations and compare only at the end. Harder to debug to see which operation failed but helps test more real world scenarios.
#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_blocks_one_go_chacha() {
    let cipher = Cipher::ChaCha20Poly1305;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let len = BLOCK_SIZE * 3 + 42;
    let data = [42];

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();

    // seek and write in the first block
    writer.seek(SeekFrom::Start(42)).unwrap();
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write something that extends to the second block
    writer.seek(SeekFrom::Start(42)).unwrap();
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(vec![0_u8; BLOCK_SIZE].as_slice()).unwrap();
    cursor_random
        .write_all(vec![0_u8; BLOCK_SIZE].as_slice())
        .unwrap();

    // write at the boundary of block
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write after boundary of block
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(42)).unwrap();
    cursor_random.seek(SeekFrom::Current(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write until block boundary then seek and write inside new block
    writer.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    cursor_random.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    writer.seek(SeekFrom::Current(43)).unwrap();
    cursor_random.seek(SeekFrom::Current(43)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // seek from block boundary to block boundary
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(BLOCK_SIZE as i64)).unwrap();
    cursor_random
        .seek(SeekFrom::Current(BLOCK_SIZE as i64))
        .unwrap();
    writer
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    cursor_random
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // seek after content size, make sure it writes zeros
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();

    // seek after content size, more blocks, make sure it writes zeros
    writer
        .seek(SeekFrom::End(10 * BLOCK_SIZE as i64 + 43))
        .unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random
        .write_all(vec![0; 10 * BLOCK_SIZE + 43].as_slice())
        .unwrap();

    // write something after the end then seek after the end, after write we should have a bigger end
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after the end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();

    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key);
}

/// Do all operations and compare only at the end. Harder to debug to see which operation failed but helps test more real world scenarios.
#[test]
#[traced_test]
#[allow(clippy::too_many_lines)]
fn test_writer_seek_blocks_one_go_aes() {
    let cipher = Cipher::Aes256Gcm;
    let mut key: Vec<u8> = vec![0; cipher.key_len()];
    rand::thread_rng().fill_bytes(&mut key);
    let key = Arc::new(SecretVec::new(key));

    let len = BLOCK_SIZE * 3 + 42;
    let data = [42];

    let mut cursor = io::Cursor::new(vec![0; 0]);
    let mut writer = crypto::create_write_seek(cursor, cipher, key.clone());
    let mut cursor_random = io::Cursor::new(vec![0; len]);
    rand::thread_rng().fill_bytes(cursor_random.get_mut());
    io::copy(&mut cursor_random, &mut writer).unwrap();

    // seek and write in the first block
    writer.seek(SeekFrom::Start(42)).unwrap();
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write something that extends to the second block
    writer.seek(SeekFrom::Start(42)).unwrap();
    cursor_random.seek(SeekFrom::Start(42)).unwrap();
    writer.write_all(vec![0_u8; BLOCK_SIZE].as_slice()).unwrap();
    cursor_random
        .write_all(vec![0_u8; BLOCK_SIZE].as_slice())
        .unwrap();

    // write at the boundary of block
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write after boundary of block
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(42)).unwrap();
    cursor_random.seek(SeekFrom::Current(42)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // write until block boundary then seek and write inside new block
    writer.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    cursor_random.write_all(&[0_u8; BLOCK_SIZE]).unwrap();
    writer.seek(SeekFrom::Current(43)).unwrap();
    cursor_random.seek(SeekFrom::Current(43)).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // seek from block boundary to block boundary
    writer.seek(SeekFrom::Start(BLOCK_SIZE as u64)).unwrap();
    cursor_random
        .seek(SeekFrom::Start(BLOCK_SIZE as u64))
        .unwrap();
    writer.seek(SeekFrom::Current(BLOCK_SIZE as i64)).unwrap();
    cursor_random
        .seek(SeekFrom::Current(BLOCK_SIZE as i64))
        .unwrap();
    writer
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    cursor_random
        .seek(SeekFrom::Start(2 * BLOCK_SIZE as u64 + 43))
        .unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();

    // seek after content size, make sure it writes zeros
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();

    // seek after content size, more blocks, make sure it writes zeros
    writer
        .seek(SeekFrom::End(10 * BLOCK_SIZE as i64 + 43))
        .unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random
        .write_all(vec![0; 10 * BLOCK_SIZE + 43].as_slice())
        .unwrap();

    // write something after the end then seek after the end, after write we should have a bigger end
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();
    writer.write_all(&data).unwrap();
    cursor_random.write_all(&data).unwrap();
    writer.seek(SeekFrom::End(42)).unwrap();
    // Cursor does not write zeros if we seek after the end, so we write our own instead of seeking
    cursor_random.seek(SeekFrom::End(0)).unwrap();
    cursor_random.write_all(vec![0; 42].as_slice()).unwrap();

    cursor = writer.finish().unwrap();
    cursor = compare(&mut cursor_random, cursor, cipher, key);
}

fn compare(
    mut plaintext: &mut io::Cursor<Vec<u8>>,
    mut ciphertext: io::Cursor<Vec<u8>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> io::Cursor<Vec<u8>> {
    plaintext.seek(SeekFrom::Start(0)).unwrap();
    ciphertext.seek(SeekFrom::Start(0)).unwrap();
    let mut reader = crypto::create_read(ciphertext, cipher, key);
    let hash1 = crypto::hash_reader(&mut plaintext).unwrap();
    let hash2 = crypto::hash_reader(&mut reader).unwrap();
    assert_eq!(hash1, hash2);
    ciphertext = reader.into_inner();
    plaintext.seek(SeekFrom::Start(0)).unwrap();
    ciphertext.seek(SeekFrom::Start(0)).unwrap();
    ciphertext
}
