use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, NONCE_LEN,
};
use ring::error;
use secrecy::{ExposeSecret, SecretVec};
use tokio::sync::RwLock;
use tracing::{error, instrument, warn};

use crate::arc_hashmap::Holder;
use crate::crypto;
use crate::crypto::buf_mut::BufMut;
use crate::crypto::write::BUF_SIZE;
use crate::crypto::Cipher;

/// Reads encrypted content from the wrapped Reader.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoReader<R: Read + Send + Sync>: Read + Send + Sync {}

/// ring

#[macro_export]
macro_rules! decrypt_block {
    ($block_index:expr, $buf:expr, $input:expr, $last_nonce:expr, $opening_key:expr) => {{
        let len = {
            $buf.clear();
            let buffer = $buf.as_mut_remaining();
            let len = {
                let mut pos = 0;
                loop {
                    match $input.read(&mut buffer[pos..]) {
                        Ok(read) => {
                            pos += read;
                            if read == 0 {
                                break;
                            }
                        }
                        Err(err) => return Err(err),
                    }
                }
                pos
            };
            if len == 0 {
                return Ok(0);
            }
            let data = &mut buffer[..len];
            let aad = Aad::from(($block_index).to_le_bytes());
            // extract nonce
            $last_nonce
                .lock()
                .unwrap()
                .replace(data[..NONCE_LEN].to_vec());
            let data = &mut data[NONCE_LEN..];
            let plaintext = $opening_key.open_within(aad, data, 0..).map_err(|err| {
                error!("error opening within: {}", err);
                io::Error::new(io::ErrorKind::Other, "error opening within")
            })?;
            plaintext.len()
        };
        $buf.seek_available(SeekFrom::Start(NONCE_LEN as u64 + len as u64))
            .unwrap();
        // skip nonce
        $buf.seek_read(SeekFrom::Start(NONCE_LEN as u64)).unwrap();
        $block_index += 1;
        Ok::<usize, io::Error>(len)
    }};
}

pub(crate) use decrypt_block;

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoReader<R: Read> {
    input: R,
    opening_key: OpeningKey<ExistingNonceSequence>,
    buf: BufMut,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
}

impl<R: Read> RingCryptoReader<R> {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(reader: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let ciphertext_block_size = NONCE_LEN + BUF_SIZE + algorithm.tag_len();
        let buf = BufMut::new(vec![0; ciphertext_block_size]);
        let last_nonce = Arc::new(Mutex::new(None));
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        Self {
            input: reader,
            opening_key,
            buf,
            last_nonce,
            ciphertext_block_size,
            plaintext_block_size: BUF_SIZE,
            block_index: 0,
        }
    }
}

impl<R: Read> Read for RingCryptoReader<R> {
    #[instrument(name = "RingCryptoReader:read", skip(self, buf))]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // first try to read remaining decrypted data
        let len = self.buf.read(buf)?;
        if len != 0 {
            return Ok(len);
        }
        // we read all the data from the buffer, so we need to read a new block and decrypt it
        decrypt_block!(
            self.block_index,
            self.buf,
            self.input,
            self.last_nonce,
            self.opening_key
        )?;
        let len = self.buf.read(buf)?;
        Ok(len)
    }
}

pub(crate) struct ExistingNonceSequence {
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ExistingNonceSequence {
    pub fn new(last_nonce: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self { last_nonce }
    }
}

impl NonceSequence for ExistingNonceSequence {
    fn advance(&mut self) -> Result<Nonce, error::Unspecified> {
        Nonce::try_assume_unique_for_key(self.last_nonce.lock().unwrap().as_mut().unwrap())
    }
}

impl<R: Read + Send + Sync> CryptoReader<R> for RingCryptoReader<R> {}

/// Reader with seek

pub trait CryptoReaderSeek<R: Read + Seek + Send + Sync>: CryptoReader<R> + Seek {}

pub struct RingCryptoReaderSeek<R: Read + Seek> {
    inner: RingCryptoReader<R>,
}

impl<R: Read + Seek> RingCryptoReaderSeek<R> {
    pub fn new(reader: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        Self {
            inner: RingCryptoReader::new(reader, algorithm, key),
        }
    }

    fn pos(&mut self) -> u64 {
        self.inner.block_index.saturating_sub(1) * self.inner.plaintext_block_size as u64
            + self.inner.buf.pos_read().saturating_sub(NONCE_LEN) as u64
    }
}

impl<R: Read + Seek> Seek for RingCryptoReaderSeek<R> {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "can't seek from end",
                ))
            }
            SeekFrom::Current(pos) => self.pos() as i64 + pos,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outside of bounds",
            ));
        }
        // keep in bounds
        let ciphertext_len = self.inner.input.stream_len()?;
        let plaintext_len = ciphertext_len
            - ((ciphertext_len / self.inner.ciphertext_block_size as u64) + 1)
                * (self.inner.ciphertext_block_size - self.inner.plaintext_block_size) as u64;
        let mut new_pos = new_pos as u64;
        if new_pos > plaintext_len {
            new_pos = plaintext_len;
        }
        if self.pos() == new_pos {
            return Ok(new_pos);
        }
        let block_index = self.pos() / self.inner.plaintext_block_size as u64;
        let new_block_index = new_pos / self.inner.plaintext_block_size as u64;
        if block_index == new_block_index {
            // seek inside current block
            if self.inner.buf.available() == 0 {
                // decrypt the first block
                self.inner.input.seek(SeekFrom::Start(
                    block_index * self.inner.ciphertext_block_size as u64,
                ))?;
                self.inner.block_index = block_index;
                decrypt_block!(
                    self.inner.block_index,
                    self.inner.buf,
                    self.inner.input,
                    self.inner.last_nonce,
                    self.inner.opening_key
                )?;
            }
            self.inner.buf.seek_read(SeekFrom::Start(
                NONCE_LEN as u64 + new_pos % self.inner.plaintext_block_size as u64,
            ))?;
        } else {
            // change block
            self.inner.input.seek(SeekFrom::Start(
                new_block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            // decrypt new block
            self.inner.block_index = new_block_index;
            decrypt_block!(
                self.inner.block_index,
                self.inner.buf,
                self.inner.input,
                self.inner.last_nonce,
                self.inner.opening_key
            )?;
            // seek inside new block
            self.inner.buf.seek_read(SeekFrom::Start(
                NONCE_LEN as u64 + new_pos % self.inner.plaintext_block_size as u64,
            ))?;
        }
        Ok(self.pos())
    }
}

impl<R: Read + Seek + Send + Sync> Read for RingCryptoReaderSeek<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek + Send + Sync> CryptoReader<R> for RingCryptoReaderSeek<R> {}

impl<R: Read + Seek + Send + Sync> CryptoReaderSeek<R> for RingCryptoReaderSeek<R> {}

/// file reader

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoReader {
    file: PathBuf,
    reader: Box<dyn CryptoReaderSeek<File>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    lock: Option<Holder<RwLock<bool>>>,
}

impl FileCryptoReader {
    /// **`lock`** is used to read lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we read  
    ///     You need to provide the same lock to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same lock
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        lock: Option<Holder<RwLock<bool>>>,
    ) -> io::Result<Self> {
        Ok(Self {
            file: file.to_owned(),
            reader: Box::new(crypto::create_reader_seek(
                File::open(file)?,
                cipher,
                key.clone(),
            )),
            cipher,
            key,
            lock,
        })
    }
}

impl Read for FileCryptoReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let _guard = self.lock.as_ref().map(|lock| lock.read());
        let len = self.reader.read(buf)?;
        Ok(len)
    }
}

impl Seek for FileCryptoReader {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "can't seek from end",
                ))
            }
            SeekFrom::Current(pos) => {
                let new_pos = self.reader.stream_position()? as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "can't seek before start",
                    ));
                }
                new_pos as u64
            }
        };
        let current_pos = self.reader.stream_position()?;
        if current_pos > pos {
            // we need to recreate the reader
            self.reader = Box::new(crypto::create_reader_seek(
                File::open(&self.file)?,
                self.cipher,
                self.key.clone(),
            ));
        }
        self.reader.seek(SeekFrom::Start(pos))?;
        self.reader.stream_position()
    }
}

impl CryptoReader<File> for FileCryptoReader {}

impl CryptoReaderSeek<File> for FileCryptoReader {}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::sync::Arc;

    use rand::Rng;
    use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
    use secrecy::SecretVec;
    use tracing_test::traced_test;

    use crate::crypto::read::RingCryptoReaderSeek;
    use crate::crypto::write::{CryptoWriter, RingCryptoWriter, BUF_SIZE};

    #[test]
    #[traced_test]
    fn test_ring_crypto_reader_seek_chacha() {
        // Create a buffer with some data
        let data = "Hello, world!";
        let mut cursor = Cursor::new(vec![]);

        let algorithm = &CHACHA20_POLY1305;
        // Create a key for encryption
        let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

        // write the data
        let mut writer = RingCryptoWriter::new(&mut cursor, algorithm, key.clone());
        writer.write_all(data.as_bytes()).unwrap();
        writer.finish().unwrap();

        // Create a RingCryptoReaderSeek
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = RingCryptoReaderSeek::new(&mut cursor, algorithm, key);

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
    fn test_ring_crypto_reader_seek_blocks_chacha() {
        // Create a buffer with some data larger than BUF_SIZE
        let mut data = vec![0u8; 2 * BUF_SIZE]; // 2 MiB
        let mut rng = rand::thread_rng();
        rng.fill(&mut data[..]);
        let mut cursor = Cursor::new(vec![]);

        // Create a key for encryption
        let algorithm = &CHACHA20_POLY1305;
        let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

        // write the data
        let mut writer = RingCryptoWriter::new(&mut cursor, algorithm, key.clone());
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();

        // Create a RingCryptoReaderSeek
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = RingCryptoReaderSeek::new(&mut cursor, algorithm, key);

        // Seek in the second block
        reader.seek(SeekFrom::Start(BUF_SIZE as u64)).unwrap();

        // Read the rest of the data
        let mut buffer = vec![0; data.len() - BUF_SIZE];
        reader.read_exact(&mut buffer).unwrap();

        // Check that we read the second block of the data
        assert_eq!(&buffer, &data[BUF_SIZE..]);

        // Seek inside the first block
        reader.seek(SeekFrom::Start(42)).unwrap();

        // Read some data that extends to second block
        let mut buffer = vec![0; BUF_SIZE];
        reader.read_exact(&mut buffer).unwrap();

        // Check that we read the first block of the data
        assert_eq!(&buffer, &data[42..BUF_SIZE + 42]);
    }

    #[test]
    #[traced_test]
    fn test_ring_crypto_reader_seek_aws() {
        // Create a buffer with some data
        let data = "Hello, world!";
        let mut cursor = Cursor::new(vec![]);

        let algorithm = &AES_256_GCM;
        // Create a key for encryption
        let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

        // write the data
        let mut writer = RingCryptoWriter::new(&mut cursor, algorithm, key.clone());
        writer.write_all(data.as_bytes()).unwrap();
        writer.finish().unwrap();

        // Create a RingCryptoReaderSeek
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = RingCryptoReaderSeek::new(&mut cursor, algorithm, key);

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
    fn test_ring_crypto_reader_seek_blocks_aes() {
        // Create a buffer with some data larger than BUF_SIZE
        let mut data = vec![0u8; 2 * BUF_SIZE]; // 2 MiB
        let mut rng = rand::thread_rng();
        rng.fill(&mut data[..]);
        let mut cursor = Cursor::new(vec![]);

        // Create a key for encryption
        let algorithm = &AES_256_GCM;
        let key = Arc::new(SecretVec::new(vec![0; algorithm.key_len()]));

        // write the data
        let mut writer = RingCryptoWriter::new(&mut cursor, algorithm, key.clone());
        writer.write_all(&data).unwrap();
        writer.finish().unwrap();

        // Create a RingCryptoReaderSeek
        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = RingCryptoReaderSeek::new(&mut cursor, algorithm, key);

        // Seek in the second block
        reader.seek(SeekFrom::Start(BUF_SIZE as u64)).unwrap();

        // Read the rest of the data
        let mut buffer = vec![0; data.len() - BUF_SIZE];
        reader.read_exact(&mut buffer).unwrap();

        // Check that we read the second block of the data
        assert_eq!(&buffer, &data[BUF_SIZE..]);

        // Seek inside the first block
        reader.seek(SeekFrom::Start(42)).unwrap();

        // Read some data that extends to second block
        let mut buffer = vec![0; BUF_SIZE];
        reader.read_exact(&mut buffer).unwrap();

        // Check that we read the first block of the data
        assert_eq!(&buffer, &data[42..BUF_SIZE + 42]);
    }
}

#[allow(unused_imports)]
mod bench {
    use std::io;
    use std::io::Seek;
    use std::sync::Arc;
    use test::{black_box, Bencher};

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWriter;
    use crate::crypto::Cipher;

    #[bench]
    fn bench_reader_10mb_cha_cha20poly1305_file(b: &mut Bencher) {
        let cipher = Cipher::ChaCha20Poly1305;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let file = tempfile::tempfile().unwrap();
        let mut writer = crypto::create_writer(file, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        let file = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut file = file.try_clone().unwrap();
                file.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(file, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            });
        });
    }

    #[bench]
    fn bench_reader_10mb_cha_aes256gcm_file(b: &mut Bencher) {
        let cipher = Cipher::Aes256Gcm;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let file = tempfile::tempfile().unwrap();
        let mut writer = crypto::create_writer(file, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        let file = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut file = file.try_clone().unwrap();
                file.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(file, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            });
        });
    }

    #[bench]
    fn bench_reader_10mb_cha_cha20poly1305_ram(b: &mut Bencher) {
        let cipher = Cipher::ChaCha20Poly1305;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let mut cursor_write = io::Cursor::new(vec![]);
        let mut writer = crypto::create_writer(&mut cursor_write, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        let cursor_write = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut cursor = cursor_write.clone();
                cursor.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(cursor, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            });
        });
    }

    #[bench]
    fn bench_reader_10mb_cha_aes256gcm_ram(b: &mut Bencher) {
        let cipher = Cipher::Aes256Gcm;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let mut cursor_write = io::Cursor::new(vec![]);
        let mut writer = crypto::create_writer(&mut cursor_write, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        let cursor_write = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut cursor = cursor_write.clone();
                cursor.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(cursor, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            });
        });
    }
}
