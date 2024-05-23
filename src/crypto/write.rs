mod bench;
mod test;

use std::fs::File;
use std::io;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use atomic_write_file::AtomicWriteFile;
use bytes::Buf;
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
use crate::crypto::read::ExistingNonceSequence;
use crate::crypto::Cipher;
use crate::{crypto, decrypt_block, fs_util, stream_util};

#[cfg(test)]
pub(crate) const BLOCK_SIZE: usize = 100; // round value easier for debugging
#[cfg(not(test))]
pub(crate) const BLOCK_SIZE: usize = 16 * 1024; // 16 KB block size

/// Writes encrypted content to the wrapped Writer.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoWrite<W: Write + Send + Sync>: Write + Send + Sync {
    /// You must call this after the last write to make sure we write the last block. This handles the flush also.
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<W>;
}

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWrite<W: Write> {
    out: Option<W>,
    sealing_key: SealingKey<RandomNonceSequenceWrapper>,
    buf: BufMut,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
}

impl<W: Write> RingCryptoWrite<W> {
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(writer: W, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        let sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        let buf = BufMut::new(vec![0; BLOCK_SIZE]);
        Self {
            out: Some(writer),
            sealing_key,
            buf,
            nonce_sequence,
            ciphertext_block_size: NONCE_LEN + BLOCK_SIZE + algorithm.tag_len(),
            plaintext_block_size: BLOCK_SIZE,
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
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("error sealing in place: {err}"),
                )
            })?;
        let nonce_sequence = self.nonce_sequence.lock().unwrap();
        let nonce = nonce_sequence.last_nonce.as_ref().unwrap();
        self.out.as_mut().unwrap().write_all(nonce)?;
        self.out.as_mut().unwrap().write_all(data)?;
        self.buf.clear();
        self.out.as_mut().unwrap().write_all(tag.as_ref())?;
        self.out.as_mut().unwrap().flush()?;
        self.block_index += 1;
        Ok(())
    }
}

impl<W: Write> Write for RingCryptoWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "write called on already finished writer",
            ));
        }
        if self.buf.is_dirty() && self.buf.remaining() == 0 {
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
        if !self.buf.is_dirty() {
            return Ok(());
        }
        // encrypt and write when we have a full buffer
        if self.buf.remaining() == 0 {
            self.encrypt_and_write()?;
        }

        Ok(())
    }
}

impl<W: Write + Send + Sync> CryptoWrite<W> for RingCryptoWrite<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "finish called on already finished writer",
            ));
        }
        if self.buf.is_dirty() {
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

/// Write with Seek

pub trait CryptoWriteSeek<W: Write + Seek + Send + Sync>: CryptoWrite<W> + Seek {}

pub struct RingCryptoWriteSeek<W: Write + Seek + Read> {
    inner: RingCryptoWrite<W>,
    opening_key: OpeningKey<ExistingNonceSequence>,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    decrypt_buf: BufMut,
}

impl<W: Write + Seek + Read> RingCryptoWriteSeek<W> {
    pub(crate) fn new(writer: W, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let last_nonce = Arc::new(Mutex::new(None));
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        let ciphertext_block_size = NONCE_LEN + BLOCK_SIZE + algorithm.tag_len();
        let decrypt_buf = BufMut::new(vec![0; ciphertext_block_size]);
        Self {
            inner: RingCryptoWrite::new(writer, algorithm, key),
            opening_key,
            last_nonce,
            decrypt_buf,
        }
    }

    const fn pos(&self) -> u64 {
        self.inner.block_index * self.inner.plaintext_block_size as u64
            + self.inner.buf.pos_write() as u64
    }

    fn decrypt_block(&mut self) -> io::Result<bool> {
        let old_block_index = self.inner.block_index;
        decrypt_block!(
            self.inner.block_index,
            self.decrypt_buf,
            self.inner.out.as_mut().unwrap(),
            self.last_nonce,
            self.opening_key
        );
        if old_block_index == self.inner.block_index {
            // no decryption happened
            Ok(false)
        } else {
            // a decryption happened
            self.inner.buf.clear();
            // bring back block index to current block, it's incremented by decrypt_block if it can decrypt something
            self.inner.block_index -= 1;
            // bring back file pos also so the next writing will write to the same block
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(
                self.inner.block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            // copy plaintext
            self.inner
                .buf
                .seek_available(SeekFrom::Start(self.decrypt_buf.available_read() as u64))?;
            self.decrypt_buf
                .as_ref_read_available()
                .copy_to_slice(&mut self.inner.buf.as_mut()[..self.decrypt_buf.available_read()]);
            Ok(true)
        }
    }

    fn get_plaintext_len(&mut self) -> io::Result<u64> {
        let ciphertext_len = self.inner.out.as_mut().unwrap().stream_len()?;
        if ciphertext_len == 0 && self.inner.buf.available() == 0 {
            return Ok(0);
        }
        let stream_last_block_index = self.inner.out.as_mut().unwrap().stream_len()?
            / self.inner.ciphertext_block_size as u64;
        let plaintext_len = if self.inner.block_index == stream_last_block_index
            && self.inner.buf.is_dirty()
        {
            // we are at the last block, we consider what we have in buffer,
            // as we might have additional content that is not written yet
            self.inner.block_index * self.inner.plaintext_block_size as u64
                + self.inner.buf.available() as u64
        } else {
            ciphertext_len
                - ((ciphertext_len / self.inner.ciphertext_block_size as u64) + 1)
                    * (self.inner.ciphertext_block_size - self.inner.plaintext_block_size) as u64
        };
        Ok(plaintext_len)
    }
}

impl<W: Write + Seek + Read> Seek for RingCryptoWriteSeek<W> {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => self.get_plaintext_len()? as i64 + pos,
            SeekFrom::Current(pos) => self.pos() as i64 + pos,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "position < 0"));
        }
        let new_pos = new_pos as u64;
        if new_pos == self.pos() {
            return Ok(new_pos);
        }
        let current_block_index = self.pos() / self.inner.plaintext_block_size as u64;
        let new_block_index = new_pos / self.inner.plaintext_block_size as u64;
        if current_block_index == new_block_index {
            if self.pos() == 0 && self.inner.buf.available() == 0 {
                // first write since we opened the writer, try to load the first block
                self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(0))?;
                self.inner.block_index = 0;
                self.decrypt_block()?;
            }
            let at_full_block_end = self.pos() % self.inner.plaintext_block_size as u64 == 0
                && self.inner.buf.pos_write() == self.inner.buf.available();
            if self.inner.buf.available() == 0
                // this checks if we are at the end of the current block,
                // which is the start boundary of next block
                // in that case we need to seek inside the next block
                || at_full_block_end
            {
                // write current block
                if self.inner.buf.is_dirty() {
                    self.inner.encrypt_and_write()?;
                }
                // decrypt the next block
                self.decrypt_block()?;
            }
            // seek inside the block as much as we can
            let desired_offset = new_pos % self.inner.plaintext_block_size as u64;
            self.inner.buf.seek_write(SeekFrom::Start(
                desired_offset.min(self.inner.buf.available() as u64),
            ))?;
        } else {
            // we need to seek to a new block

            // write current block
            if self.inner.buf.is_dirty() {
                self.inner.encrypt_and_write()?;
            }

            // seek to new block, or until the last block in stream
            let last_block_index = self.inner.out.as_mut().unwrap().stream_len()?
                / self.inner.ciphertext_block_size as u64;
            let target_block_index = new_block_index.min(last_block_index);
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(
                target_block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            // try to decrypt target block
            self.inner.block_index = target_block_index;
            self.decrypt_block()?;
            if self.inner.block_index == new_block_index {
                // seek inside new block as much as we can
                let desired_offset = new_pos % self.inner.plaintext_block_size as u64;
                self.inner.buf.seek_write(SeekFrom::Start(
                    desired_offset.min(self.inner.buf.available() as u64),
                ))?;
            } else {
                // we don't have this block, seek as much in target block
                self.inner
                    .buf
                    .seek_write(SeekFrom::Start(self.inner.buf.available() as u64))?;
            }
        }
        // if we couldn't seek until new pos, write zeros until new position
        if self.pos() < new_pos {
            let len = new_pos - self.pos();
            stream_util::fill_zeros(&mut self.inner, len)?;
        }
        Ok(self.pos())
    }
}

impl<W: Write + Seek + Read + Send + Sync> Write for RingCryptoWriteSeek<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos() == 0 && self.inner.buf.available() == 0 {
            // first write since we opened the writer, try to load the first block
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(0))?;
            self.inner.block_index = 0;
            self.decrypt_block()?;
        } else if self.inner.buf.is_dirty() && self.inner.buf.remaining() == 0 {
            self.flush()?;
            // try to decrypt the next block if we have any
            let block_index = self.pos() / self.inner.plaintext_block_size as u64;
            if self.inner.out.as_mut().unwrap().stream_len()?
                > block_index * self.inner.ciphertext_block_size as u64
            {
                self.decrypt_block()?;
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek + Read + Send + Sync> CryptoWrite<W> for RingCryptoWriteSeek<W> {
    fn finish(&mut self) -> io::Result<W> {
        self.inner.finish()
    }
}

impl<W: Write + Seek + Read + Send + Sync> CryptoWriteSeek<W> for RingCryptoWriteSeek<W> {}

/// File Writer

#[allow(clippy::module_name_repetitions)]
pub trait FileCryptoWriteCallback: Send + Sync {
    #[allow(clippy::missing_errors_doc)]
    fn on_file_content_changed(&self, changed_from_pos: i64, last_write_pos: u64)
        -> io::Result<()>;
}

#[allow(clippy::module_name_repetitions)]
pub trait FileCryptoWriteMetadataProvider: Send + Sync {
    fn size(&self) -> io::Result<u64>;
}

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoWrite {
    file_path: PathBuf,
    writer: Option<Box<dyn CryptoWrite<BufWriter<AtomicWriteFile>>>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    callback: Option<Box<dyn FileCryptoWriteCallback>>,
    lock: Option<Holder<RwLock<bool>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriteMetadataProvider>>,
    pos: u64,
}

impl FileCryptoWrite {
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
        callback: Option<Box<dyn FileCryptoWriteCallback>>,
        lock: Option<Holder<RwLock<bool>>>,
        metadata_provider: Option<Box<dyn FileCryptoWriteMetadataProvider>>,
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

    #[allow(clippy::unnecessary_wraps)] // remove this when we seek the inner writer
    fn pos(&self) -> io::Result<u64> {
        if self.writer.is_some() {
            Ok(self.pos)
        } else {
            Ok(0)
        }
    }

    fn ensure_writer_created(&mut self) -> io::Result<()> {
        if self.writer.is_none() {
            self.writer = Some(Box::new(crypto::create_write(
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

impl Write for FileCryptoWrite {
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

impl CryptoWrite<File> for FileCryptoWrite {
    fn finish(&mut self) -> io::Result<File> {
        self.flush()?;
        self.seek(SeekFrom::Start(0))?; // this will handle moving the tmp file to the original file
        if let Some(mut writer) = self.writer.take() {
            writer.finish()?;
        }
        File::open(self.file_path.clone())
    }
}

impl Seek for FileCryptoWrite {
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

impl CryptoWriteSeek<File> for FileCryptoWrite {}
