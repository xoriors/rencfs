use std::fs::File;
use std::io;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use atomic_write_file::AtomicWriteFile;
use num_format::{Locale, ToFormattedString};
use rand_chacha::rand_core::RngCore;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tokio::sync::RwLock;
use tracing::{debug, error};

use crate::arc_hashmap::Holder;
use crate::crypto::buf_mut::BufMut;
use crate::crypto::read::{ExistingNonceSequence, RingCryptoReader};
use crate::crypto::Cipher;
use crate::{crypto, decrypt_block, fs_util, stream_util};

#[cfg(test)]
pub(crate) const BUF_SIZE: usize = 4096;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
pub(crate) const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

/// Writes encrypted content to the wrapped Writer.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoWriter<W: Write + Send + Sync>: Write + Send + Sync {
    /// You must call this after the last write to make sure we write the last block. This handles the flush also.
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<W>;
}

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWriter<W: Write> {
    out: Option<W>,
    sealing_key: SealingKey<RandomNonceSequenceWrapper>,
    buf: BufMut,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
}

impl<W: Write> RingCryptoWriter<W> {
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(writer: W, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        let sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        let buf = BufMut::new(vec![0; BUF_SIZE]);
        Self {
            out: Some(writer),
            sealing_key,
            buf,
            nonce_sequence,
            ciphertext_block_size: NONCE_LEN + BUF_SIZE + algorithm.tag_len(),
            plaintext_block_size: BUF_SIZE,
            block_index: 0,
        }
    }

    fn encrypt_and_write(&mut self) -> io::Result<()> {
        let data = self.buf.as_mut();
        let aad = Aad::from(self.block_index.to_le_bytes());
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(aad, data)
            .map_err(|err| {
                error!("error sealing in place: {}", err);
                io::Error::from(io::ErrorKind::Other)
            })?;
        let nonce_sequence = self.nonce_sequence.lock().unwrap();
        let nonce = nonce_sequence.last_nonce.as_ref().unwrap();
        self.out.as_mut().unwrap().write_all(nonce)?;
        self.out.as_mut().unwrap().write_all(data)?;
        self.buf.clear();
        self.out.as_mut().unwrap().write_all(tag.as_ref())?;
        self.block_index += 1;
        Ok(())
    }
}

impl<W: Write> Write for RingCryptoWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "write called on already finished writer",
            ));
        }
        if self.buf.remaining() == 0 {
            self.flush()?;
        }
        let len = self.buf.write(buf)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "flush called on already finished writer",
            ));
        }
        if self.buf.available() == 0 {
            return Ok(());
        }
        if self.buf.remaining() == 0 {
            // encrypt and write when we have a full buffer
            self.encrypt_and_write()?;
        }

        Ok(())
    }
}

impl<W: Write + Send + Sync> CryptoWriter<W> for RingCryptoWriter<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "finish called on already finished writer",
            ));
        }
        self.flush()?;
        if self.buf.available() > 0 {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        let mut out = self.out.take().unwrap();
        out.flush()?;
        Ok(out)
    }
}

struct RandomNonceSequence {
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
    last_nonce: Option<Vec<u8>>,
}

impl Default for RandomNonceSequence {
    fn default() -> Self {
        Self {
            rng: Mutex::new(Box::new(crypto::create_rng())),
            last_nonce: None,
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.last_nonce = Some(vec![0; NONCE_LEN]);
        self.rng
            .lock()
            .unwrap()
            .fill_bytes(self.last_nonce.as_mut().unwrap());
        Nonce::try_assume_unique_for_key(self.last_nonce.as_mut().unwrap())
    }
}

struct RandomNonceSequenceWrapper {
    inner: Arc<Mutex<RandomNonceSequence>>,
}

impl RandomNonceSequenceWrapper {
    pub fn new(inner: Arc<Mutex<RandomNonceSequence>>) -> Self {
        Self { inner }
    }
}

impl NonceSequence for RandomNonceSequenceWrapper {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inner.lock().unwrap().advance()
    }
}

/// Writer with Seek

pub trait CryptoWriterSeek<W: Write + Seek + Send + Sync>: CryptoWriter<W> + Seek {}

struct RingCryptoWriterSeek<W: Write + Seek + Read> {
    inner: RingCryptoWriter<W>,
    opening_key: OpeningKey<ExistingNonceSequence>,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
}

impl<W: Write + Seek + Read> RingCryptoWriterSeek<W> {
    fn new(writer: W, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let last_nonce = Arc::new(Mutex::new(None));
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        Self {
            inner: RingCryptoWriter::new(writer, algorithm, key),
            opening_key,
            last_nonce,
        }
    }

    const fn pos(&self) -> u64 {
        self.inner.block_index.saturating_sub(1) * self.inner.plaintext_block_size as u64
            + self.inner.buf.pos_write() as u64
    }
}

impl<W: Write + Seek + Read> Seek for RingCryptoWriterSeek<W> {
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
        let ciphertext_len = self.inner.out.as_mut().unwrap().stream_len()?;
        let plaintext_len = ciphertext_len / self.inner.ciphertext_block_size as u64
            + ciphertext_len % self.inner.ciphertext_block_size as u64;
        if new_pos < 0 || new_pos > plaintext_len as i64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "outside of bounds",
            ));
        }
        let new_pos = new_pos as u64;
        if new_pos == self.pos() {
            return Ok(new_pos);
        }
        let current_block_index = self.pos() / self.inner.ciphertext_block_size as u64;
        let mut new_block_index = new_pos / self.inner.ciphertext_block_size as u64;
        if current_block_index == new_block_index {
            // seek inside the block
            self.inner.buf.seek_write(SeekFrom::Start(
                new_pos % self.inner.ciphertext_block_size as u64,
            ))?;
        } else {
            // todo: write zeros if we need to seek outside of the file
            // seek to new block
            let ciphertext_block_size = self.inner.ciphertext_block_size;
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(
                new_block_index * ciphertext_block_size as u64,
            ))?;
            // decrypt new block
            decrypt_block!(
                new_block_index,
                self.inner.buf,
                self.inner.out.as_mut().unwrap(),
                self.last_nonce,
                self.opening_key
            )?;
            // seek inside new block
            self.inner
                .buf
                .seek_write(SeekFrom::Start(new_pos % ciphertext_block_size as u64))?;
            self.inner.block_index = new_block_index;
        }
        Ok(self.pos())
    }
}

impl<W: Write + Seek + Read + Send + Sync> Write for RingCryptoWriterSeek<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek + Read + Send + Sync> CryptoWriter<W> for RingCryptoWriterSeek<W> {
    fn finish(&mut self) -> io::Result<W> {
        self.inner.finish()
    }
}
impl<W: Write + Seek + Read + Send + Sync> CryptoWriterSeek<W> for RingCryptoWriterSeek<W> {}

/// File writer

#[allow(clippy::module_name_repetitions)]
pub trait FileCryptoWriterCallback: Send + Sync {
    #[allow(clippy::missing_errors_doc)]
    fn on_file_content_changed(&self, changed_from_pos: i64, last_write_pos: u64)
        -> io::Result<()>;
}

#[allow(clippy::module_name_repetitions)]
pub trait FileCryptoWriterMetadataProvider: Send + Sync {
    fn size(&self) -> io::Result<u64>;
}

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoWriter {
    file_path: PathBuf,
    writer: Option<Box<dyn CryptoWriter<BufWriter<AtomicWriteFile>>>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    callback: Option<Box<dyn FileCryptoWriterCallback>>,
    lock: Option<Holder<RwLock<bool>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
    pos: u64,
}

impl FileCryptoWriter {
    /// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position
    ///
    /// **`lock`** is used to write lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we do  
    ///     You need to provide the same lock to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same lock
    ///
    /// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file  
    ///     If the file exists or is created before flushing, in worse case scenarios, it can reduce the overall write speed by half, so it's recommended to provide it
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file_path: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        callback: Option<Box<dyn FileCryptoWriterCallback>>,
        lock: Option<Holder<RwLock<bool>>>,
        metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
    ) -> io::Result<Self> {
        if !file_path.exists() {
            File::create(file_path)?;
        }
        Ok(Self {
            file_path: file_path.to_owned(),
            writer: None,
            cipher,
            key,
            callback,
            lock,
            metadata_provider,
            pos: 0,
        })
    }

    #[allow(clippy::unnecessary_wraps)] // remove this when we will seek the inner writer
    fn pos(&self) -> io::Result<u64> {
        if self.writer.is_some() {
            Ok(self.pos)
        } else {
            Ok(0)
        }
    }

    fn ensure_writer_created(&mut self) -> io::Result<()> {
        if self.writer.is_none() {
            self.writer = Some(Box::new(crypto::create_writer(
                BufWriter::new(fs_util::open_atomic_write(&self.file_path)?),
                self.cipher,
                self.key.clone(),
            )));
            self.pos = 0;
        }
        Ok(())
    }

    fn seek_from_start(&mut self, pos: u64) -> io::Result<u64> {
        if pos == self.pos()? {
            return Ok(pos);
        }

        self.ensure_writer_created()?;

        if self.pos()? < pos {
            // seek forward
            debug!(
                pos = pos.to_formatted_string(&Locale::en),
                current_pos = self.pos()?.to_formatted_string(&Locale::en),
                "seeking forward"
            );
            let len = pos - self.pos()?;
            crypto::copy_from_file(
                self.file_path.clone(),
                self.pos()?,
                len,
                self.cipher,
                self.key.clone(),
                self,
                true,
            )?;
            if self.pos()? < pos {
                // eof, we write zeros until pos
                stream_util::fill_zeros(self, pos - self.pos()?)?;
            }
        } else {
            // seek backward
            // write dirty data, recreate writer and copy until pos

            debug!(
                pos = pos.to_formatted_string(&Locale::en),
                current_pos = self.pos()?.to_formatted_string(&Locale::en),
                "seeking backward"
            );

            // write dirty data
            self.writer.as_mut().unwrap().flush()?;

            let size = {
                if let Some(metadata_provider) = &self.metadata_provider {
                    metadata_provider.size()?
                } else {
                    // we don't have actual size, we use a max value to copy all remaining data
                    u64::MAX
                }
            };
            if self.pos()? < size {
                // copy remaining data from file
                debug!(size, "copying remaining data from file");
                crypto::copy_from_file(
                    self.file_path.clone(),
                    self.pos()?,
                    u64::MAX,
                    self.cipher,
                    self.key.clone(),
                    self,
                    true,
                )?;
            }

            let last_write_pos = self.pos()?;

            // finish writer
            let mut writer = self.writer.take().unwrap();
            let mut file = writer.finish()?;
            file.flush()?;
            let file = file.into_inner()?;
            self.pos = 0;
            {
                let _guard = self.lock.as_ref().map(|lock| lock.write());
                file.commit()?;
            }

            if let Some(callback) = &self.callback {
                // notify back that file content has changed
                // set pos to -1 to reset also readers that opened the file but didn't read anything yet, because we need to take the new moved file
                callback
                    .on_file_content_changed(-1, last_write_pos)
                    .map_err(|err| {
                        error!("error notifying file content changed: {}", err);
                        err
                    })?;
            }

            // copy until pos
            let len = pos;
            if len != 0 {
                crypto::copy_from_file_exact(
                    self.file_path.clone(),
                    self.pos()?,
                    len,
                    self.cipher,
                    self.key.clone(),
                    self,
                )?;
            }
        }
        self.pos()
    }
}

impl Write for FileCryptoWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_writer_created()?;
        let len = self.writer.as_mut().unwrap().write(buf)?;
        self.pos += len as u64;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer.as_mut() {
            writer.flush()?;
        }

        Ok(())
    }
}

impl CryptoWriter<File> for FileCryptoWriter {
    fn finish(&mut self) -> io::Result<File> {
        self.flush()?;
        self.seek(SeekFrom::Start(0))?; // this will handle moving the tmp file to the original file
        if let Some(mut writer) = self.writer.take() {
            writer.finish()?;
        }
        File::open(self.file_path.clone())
    }
}

impl Seek for FileCryptoWriter {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.seek_from_start(pos),
            SeekFrom::End(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "seek from end not supported",
            )),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos()? as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "can't seek before start",
                    ));
                }
                self.seek_from_start(new_pos as u64)
            }
        }
    }
}

impl CryptoWriterSeek<File> for FileCryptoWriter {}

#[cfg(test)]
mod test {
    use std::io;
    use std::io::Write;
    use std::io::{Read, Seek};
    use std::sync::Arc;

    use rand::RngCore;
    use secrecy::SecretVec;
    use tracing_test::traced_test;

    use crate::crypto;
    use crate::crypto::write::{CryptoWriter, BUF_SIZE};
    use crate::crypto::Cipher;

    #[test]
    #[traced_test]
    fn test_reader_writer_chacha() {
        let cipher = Cipher::ChaCha20Poly1305;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        // simple text
        let mut cursor = io::Cursor::new(vec![0; 0]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let data = "hello, this is my secret message";
        writer.write_all(data.as_bytes()).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key.clone());
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(data, s);

        // larger data
        let mut cursor = io::Cursor::new(vec![]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let mut data: [u8; BUF_SIZE + 42] = [0; BUF_SIZE + 42];
        crypto::create_rng().fill_bytes(&mut data);
        writer.write_all(&data).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key);
        let mut data2 = vec![];
        reader.read_to_end(&mut data2).unwrap();
        assert_eq!(data.len(), data2.len());
        assert_eq!(crypto::hash(&data), crypto::hash(&data2));
    }

    #[test]
    #[traced_test]
    fn test_reader_writer_10mb_chacha() {
        let cipher = Cipher::ChaCha20Poly1305;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let mut cursor = io::Cursor::new(vec![0; 0]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        cursor = writer.finish().unwrap();
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key);
        let hash1 = crypto::hash_reader(&mut cursor_random).unwrap();
        let hash2 = crypto::hash_reader(&mut reader).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    #[traced_test]
    fn test_reader_writer_aes() {
        let cipher = Cipher::Aes256Gcm;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        // simple text
        let mut cursor = io::Cursor::new(vec![0; 0]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let data = "hello, this is my secret message";
        writer.write_all(data.as_bytes()).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key.clone());
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(data, s);

        // larger data
        let mut cursor = io::Cursor::new(vec![]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let mut data: [u8; BUF_SIZE + 42] = [0; BUF_SIZE + 42];
        crypto::create_rng().fill_bytes(&mut data);
        writer.write_all(&data).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key);
        let mut data2 = vec![];
        reader.read_to_end(&mut data2).unwrap();
        assert_eq!(data.len(), data2.len());
        assert_eq!(crypto::hash(&data), crypto::hash(&data2));
    }

    #[test]
    #[traced_test]
    fn test_reader_writer_10mb_aes() {
        let cipher = Cipher::Aes256Gcm;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let mut cursor = io::Cursor::new(vec![0; 0]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let mut cursor_random = io::Cursor::new(vec![0; len]);
        crypto::create_rng().fill_bytes(cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        cursor = writer.finish().unwrap();
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        cursor.seek(io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key);
        let hash1 = crypto::hash_reader(&mut cursor_random).unwrap();
        let hash2 = crypto::hash_reader(&mut reader).unwrap();
        assert_eq!(hash1, hash2);
    }
}

#[allow(unused_imports)]
mod bench {
    use ::test::{black_box, Bencher};
    use std::io;
    use std::io::Write;
    use std::io::{Error, SeekFrom};
    use std::io::{Read, Seek};
    use std::sync::Arc;

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::write::CryptoWriter;
    use crate::crypto::Cipher;

    #[allow(dead_code)]
    struct RandomReader {
        buf: Arc<Vec<u8>>,
        pos: usize,
    }

    impl RandomReader {
        #[allow(dead_code)]
        pub fn new(len: usize) -> Self {
            let mut buf = vec![0; len];
            crypto::create_rng().fill_bytes(&mut buf);
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
    fn bench_writer_10mb_cha_cha20poly1305_file(b: &mut Bencher) {
        let cipher = Cipher::ChaCha20Poly1305;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let rnd_reader = RandomReader::new(len);
        b.iter(|| {
            black_box({
                let mut reader = rnd_reader.clone();
                let mut writer =
                    crypto::create_writer(tempfile::tempfile().unwrap(), cipher, key.clone());
                io::copy(&mut reader, &mut writer).unwrap();
                writer.finish().unwrap()
            })
        });
    }

    #[bench]
    fn bench_writer_10mb_aes256gcm_file(b: &mut Bencher) {
        let cipher = Cipher::Aes256Gcm;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let rnd_reader = RandomReader::new(len);
        b.iter(|| {
            black_box({
                let mut reader = rnd_reader.clone();
                let mut writer =
                    crypto::create_writer(tempfile::tempfile().unwrap(), cipher, key.clone());
                io::copy(&mut reader, &mut writer).unwrap();
                writer.finish().unwrap()
            })
        });
    }

    #[bench]
    fn bench_writer_10mb_cha_cha20poly1305_mem(b: &mut Bencher) {
        let cipher = Cipher::ChaCha20Poly1305;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let rnd_reader = RandomReader::new(len);
        b.iter(|| {
            black_box({
                let mut reader = rnd_reader.clone();
                let cursor_write = io::Cursor::new(vec![0; len]);
                let mut writer = crypto::create_writer(cursor_write, cipher, key.clone());
                io::copy(&mut reader, &mut writer).unwrap();
                writer.finish().unwrap()
            })
        });
    }

    #[bench]
    fn bench_writer_10mb_aes256gcm_mem(b: &mut Bencher) {
        let cipher = Cipher::Aes256Gcm;
        let len = 10 * 1024 * 1024;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        let rnd_reader = RandomReader::new(len);
        b.iter(|| {
            black_box({
                let mut reader = rnd_reader.clone();
                let cursor_write = io::Cursor::new(vec![0; len]);
                let mut writer = crypto::create_writer(cursor_write, cipher, key.clone());
                io::copy(&mut reader, &mut writer).unwrap();
                writer.finish().unwrap()
            })
        });
    }
}
