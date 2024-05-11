use num_format::{Locale, ToFormattedString};
use parking_lot::RwLock;
use std::fs::File;
use std::io::{BufWriter, Error, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fs, io};

use crate::arc_hashmap::Holder;
use crate::{crypto, stream_util};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tempfile::NamedTempFile;
use tokio::io::{AsyncSeek, AsyncWrite};
use tracing::{debug, error};

use crate::crypto::buf_mut::BufMut;
use crate::crypto::Cipher;

#[cfg(test)]
pub(crate) const BUF_SIZE: usize = 256 * 1024;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
pub(crate) const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

#[allow(clippy::module_name_repetitions)]
pub trait CryptoWriter<W: Write>: Write + Send + Sync {
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<W>;
}

/// cryptostream

// pub struct CryptostreamCryptoWriter<W: Write> {
//     inner: Option<cryptostream::write::Encryptor<W>>,
// }
//
// impl<W: Write> CryptostreamCryptoWriter<W> {
//     pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> crypto::Result<Self> {
//         Ok(Self {
//             inner: Some(cryptostream::write::Encryptor::new(writer, cipher, key, iv)?),
//         })
//     }
// }
//
// impl<W: Write> Write for CryptostreamCryptoWriter<W> {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         self.inner.as_mut().unwrap().write(buf)
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         self.inner.as_mut().unwrap().flush()
//     }
// }
//
// impl<W: Write + Send + Sync> CryptoWriter<W> for CryptostreamCryptoWriter<W> {
//     fn finish(&mut self) -> io::Result<Option<W>> {
//         Ok(Some(self.inner.take().unwrap().finish()?))
//     }
// }

/// Ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWriter<W: Write + Send + Sync> {
    out: Option<BufWriter<W>>,
    sealing_key: SealingKey<RandomNonceSequence>,
    buf: BufMut,
}

impl<W: Write + Send + Sync> RingCryptoWriter<W> {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(
        w: W,
        algorithm: &'static Algorithm,
        key: &Arc<SecretVec<u8>>,
        nonce_seed: u64,
    ) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = RandomNonceSequence::new(nonce_seed);
        let sealing_key = SealingKey::new(unbound_key, nonce_sequence);
        let buf = BufMut::new(vec![0; BUF_SIZE]);
        Self {
            out: Some(BufWriter::new(w)),
            sealing_key,
            buf,
        }
    }
}

impl<W: Write + Send + Sync> Write for RingCryptoWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.is_none() {
            return Err(Error::new(
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
            return Err(Error::new(
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

impl<W: Write + Send + Sync> RingCryptoWriter<W> {
    fn encrypt_and_write(&mut self) -> io::Result<()> {
        let data = self.buf.as_mut();
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(Aad::empty(), data)
            .map_err(|err| {
                error!("error sealing in place: {}", err);
                io::Error::from(io::ErrorKind::Other)
            })?;
        if self.out.is_none() {
            panic!("encrypt_and_write called on already finished writer")
        }
        let out = self.out.as_mut().unwrap();
        out.write_all(data)?;
        self.buf.clear();
        out.write_all(tag.as_ref())?;
        out.flush()?;
        Ok(())
    }
}

impl<W: Write + Send + Sync> CryptoWriter<W> for RingCryptoWriter<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.out.is_none() {
            return Err(Error::new(
                io::ErrorKind::Other,
                "finish called on already finished writer",
            ));
        }
        if self.buf.available() > 0 {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        Ok(self.out.take().unwrap().into_inner()?)
    }
}

pub(in crate::crypto) struct RandomNonceSequence {
    rng: ChaCha20Rng,
    // seed: u64,
}

impl RandomNonceSequence {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            // seed,
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let num = self.rng.next_u64();
        // let num = self.seed;
        // self.seed = self.seed + 1;
        let bytes = num.to_le_bytes();
        // let bytes = self.seed.to_le_bytes();
        nonce_bytes[4..].copy_from_slice(&bytes);
        // println!("nonce_bytes = {}", hex::encode(&nonce_bytes));
        // self.seed += 1;

        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Writer with Seek

pub trait CryptoWriterSeek<W: Write>: CryptoWriter<W> + Seek {}

/// Async writer

pub trait AsyncCryptoWriter: AsyncWrite + Send + Sync {}

/// Async writer with seek

pub trait AsyncSeekCryptoWriter: AsyncCryptoWriter + AsyncSeek {}

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
    file: PathBuf,
    tmp_dir: PathBuf,
    writer: Box<dyn CryptoWriter<File>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
    pos: u64,
    tmp_file_path: PathBuf,
    callback: Option<Box<dyn FileCryptoWriterCallback>>,
    lock: Option<Holder<RwLock<bool>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
}

impl FileCryptoWriter {
    /// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position\
    /// **`lock`** is used to write lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we do\
    /// **`tmp_dir`** is used to store the temporary files while writing the chunks. It **MUST** be on the same filesystem as the **`file_dir`**\
    ///    New changes are written to a temporary file and on **`flush`** or **`finish`** the tmp file is renamed to the original file\
    /// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file_path: &Path,
        tmp_dir: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        callback: Option<Box<dyn FileCryptoWriterCallback>>,
        lock: Option<Holder<RwLock<bool>>>,
        metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
    ) -> io::Result<Self> {
        if !file_path.exists() {
            File::create(file_path)?;
        }
        // start writer in tmp file
        let tmp_path = NamedTempFile::new_in(tmp_dir)?
            .into_temp_path()
            .to_path_buf();
        let tmp_file = File::create(tmp_path.clone())?;
        Ok(Self {
            file: file_path.to_owned(),
            tmp_dir: tmp_dir.to_owned(),
            writer: Box::new(crypto::create_writer(tmp_file, cipher, &key, nonce_seed)),
            cipher,
            key,
            nonce_seed,
            pos: 0,
            tmp_file_path: tmp_path,
            callback,
            lock,
            metadata_provider,
        })
    }

    fn seek_from_start(&mut self, pos: u64) -> io::Result<u64> {
        if pos == self.pos {
            return Ok(pos);
        }

        if self.pos < pos {
            // seek forward
            debug!(
                pos = pos.to_formatted_string(&Locale::en),
                current_pos = self.pos.to_formatted_string(&Locale::en),
                "seeking forward"
            );
            let len = pos - self.pos;
            crypto::copy_from_file(
                self.file.clone(),
                self.pos,
                len,
                self.cipher,
                self.key.clone(),
                self.nonce_seed,
                self,
                true,
            )?;
            if self.pos < pos {
                // eof, we write zeros until pos
                stream_util::fill_zeros(self, pos - self.pos)?;
            }
        } else {
            // seek backward
            // write dirty data, recreate writer and copy until pos

            debug!(
                pos = pos.to_formatted_string(&Locale::en),
                current_pos = self.pos.to_formatted_string(&Locale::en),
                "seeking backward"
            );

            // write dirty data
            self.writer.flush()?;

            let size = {
                if let Some(metadata_provider) = &self.metadata_provider {
                    metadata_provider.size()?
                } else {
                    // we don't have actual size, we use a max value to copy all remaining data
                    u64::MAX
                }
            };
            if self.pos < size {
                // copy remaining data from file
                debug!("copying remaining data from file until size {}", size);
                crypto::copy_from_file(
                    self.file.clone(),
                    self.pos,
                    u64::MAX,
                    self.cipher,
                    self.key.clone(),
                    self.nonce_seed,
                    self,
                    true,
                )?;
            }

            self.writer.finish()?;
            {
                if let Some(lock) = &self.lock {
                    let _guard = lock.write();
                    // move tmp file to file
                    fs::rename(self.tmp_file_path.clone(), self.file.clone())?;
                }
            }

            if let Some(callback) = &self.callback {
                // notify back that file content has changed
                // set pos to -1 to reset also readers that opened the file but didn't read anything yet, because we need to take the new moved file
                callback
                    .on_file_content_changed(-1, self.pos)
                    .map_err(|err| {
                        error!("error notifying file content changed: {}", err);
                        err
                    })?;
            }

            // recreate writer
            let tmp_path = NamedTempFile::new_in(self.tmp_dir.clone())?
                .into_temp_path()
                .to_path_buf();
            let tmp_file = File::create(tmp_path.clone())?;
            self.writer = Box::new(crypto::create_writer(
                tmp_file,
                self.cipher,
                &self.key.clone(),
                self.nonce_seed,
            ));
            self.tmp_file_path = tmp_path;
            self.pos = 0;

            // copy until pos
            let len = pos;
            if len != 0 {
                crypto::copy_from_file_exact(
                    self.file.clone(),
                    self.pos,
                    len,
                    self.cipher,
                    self.key.clone(),
                    self.nonce_seed,
                    self,
                )?;
            }
        }

        Ok(self.pos)
    }
}

impl Write for FileCryptoWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.writer.write(buf)?;
        self.pos += len as u64;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.seek(SeekFrom::Start(0))?; // this will handle the flush and write any dirty data

        Ok(())
    }
}

impl CryptoWriter<File> for FileCryptoWriter {
    fn finish(&mut self) -> io::Result<File> {
        self.flush()?;
        {
            self.writer.finish()?;
        }
        if self.tmp_file_path.exists() {
            if let Err(err) = fs::remove_file(&self.tmp_file_path) {
                error!("error removing tmp file: {}", err);
                return Err(Error::new(io::ErrorKind::NotFound, err.to_string()));
            }
        }
        File::open(self.file.clone())
    }
}

impl Seek for FileCryptoWriter {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.seek_from_start(pos),
            SeekFrom::End(_) => Err(Error::new(
                io::ErrorKind::Other,
                "seek from end not supported",
            )),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos as i64 + pos;
                if new_pos < 0 {
                    return Err(Error::new(
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

/// Chunked writer
/// File is split into chunks files. This writer iterates over the chunks and write them one by one.

// todo: expose as param
#[cfg(test)]
pub(in crate::crypto) const CHUNK_SIZE: u64 = 1024; // 1K for tests
#[cfg(not(test))]
pub(in crate::crypto) const CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64M

// use this when we want to lock the whole file
pub const WHOLE_FILE_CHUNK_INDEX: u64 = u64::MAX - 42_u64;

pub trait SequenceLockProvider: Send + Sync {
    fn get(&self, index: u64) -> Holder<RwLock<bool>>;
}

#[allow(clippy::module_name_repetitions)]
pub struct ChunkedFileCryptoWriter {
    file_dir: PathBuf,
    tmp_dir: PathBuf,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
    callback: Option<Arc<Box<dyn FileCryptoWriterCallback>>>,
    chunk_size: u64,
    chunk_index: u64,
    writer: Option<Box<dyn CryptoWriterSeek<File>>>,
    locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
}

struct CallbackWrapper(Arc<Box<dyn FileCryptoWriterCallback>>, u64);
impl FileCryptoWriterCallback for CallbackWrapper {
    fn on_file_content_changed(
        &self,
        changed_from_pos: i64,
        last_write_pos: u64,
    ) -> io::Result<()> {
        self.0
            .on_file_content_changed(self.1 as i64 + changed_from_pos, self.1 + last_write_pos)
    }
}

struct FileCryptoWriterMetadataProviderImpl(u64);
impl FileCryptoWriterMetadataProvider for FileCryptoWriterMetadataProviderImpl {
    fn size(&self) -> io::Result<u64> {
        Ok(self.0)
    }
}

impl ChunkedFileCryptoWriter {
    /// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position\
    /// **`lock`** is used to write lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we do\
    /// **`tmp_dir`** is used to store the temporary file while writing. It **MUST** be on the same filesystem as the **`file_dir`**\
    ///    New changes are written to a temporary file and on **`flush`**, **`shutdown`** or when we write to another chunk the tmp file is renamed to the original chunk\
    /// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file
    pub fn new(
        file_dir: &Path,
        tmp_dir: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        callback: Option<Box<dyn FileCryptoWriterCallback>>,
        locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
        metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
    ) -> io::Result<Self> {
        Ok(Self {
            file_dir: file_dir.to_owned(),
            tmp_dir: tmp_dir.to_owned(),
            cipher,
            key: key.clone(),
            nonce_seed,
            callback: callback.map(|c| Arc::new(c)),
            chunk_size: CHUNK_SIZE,
            chunk_index: 0,
            writer: None,
            locks,
            metadata_provider,
        })
    }

    fn create_new_writer(
        &mut self,
        pos: u64,
        current_pos: u64,
    ) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
        let metadata_provider = if let Some(metadata_provider) = &self.metadata_provider {
            let mut size = metadata_provider.size()?;
            if current_pos > size {
                // we received and old size
                size = current_pos % self.chunk_size;
            }
            // check if we are in the last chunk
            let chunk_index = pos / self.chunk_size;
            let path = Path::new(&self.file_dir).join((chunk_index + 1).to_string());
            if path.exists() {
                // we are in the last chunk, size is remaining after multiple of chunk size
                size %= self.chunk_size;
            } else {
                // we are NOT in the last chunk, size is a full chunk size
                size /= self.chunk_size;
            }

            Some(Box::new(FileCryptoWriterMetadataProviderImpl(size))
                as Box<dyn FileCryptoWriterMetadataProvider>)
        } else {
            None
        };

        Self::create_writer(
            pos,
            &self.file_dir,
            &self.tmp_dir,
            self.cipher,
            self.key.clone(),
            self.nonce_seed,
            self.chunk_size,
            &self.locks,
            self.callback.clone(),
            metadata_provider,
        )
    }

    fn create_writer(
        pos: u64,
        file_dir: &Path,
        tmp_dir: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        chunk_size: u64,
        locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
        callback: Option<Arc<Box<dyn FileCryptoWriterCallback>>>,
        metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
    ) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
        let chunk_index = pos / chunk_size;
        debug!(
            chunk_index = chunk_index.to_formatted_string(&Locale::en),
            "creating new writer"
        );
        let chunk_file = file_dir.join(chunk_index.to_string());
        {
            let mut _lock = None;
            let mut _lock2 = None;
            let (_g1, _g2) = if let Some(locks) = locks {
                _lock = Some(locks.get(chunk_index));
                let guard = _lock.as_ref().unwrap().write();
                // obtain a write lock to whole file, we ue a special value to indicate this.
                _lock2 = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
                let guard_all = _lock2.as_ref().unwrap().read();
                (Some(guard), Some(guard_all))
            } else {
                (None, None)
            };

            if !chunk_file.exists() {
                File::create(&chunk_file)?;
            }
        }
        crypto::create_file_writer(
            chunk_file.as_path(),
            tmp_dir,
            cipher,
            key.clone(),
            nonce_seed,
            callback.as_ref().map(|c| {
                Box::new(CallbackWrapper(c.clone(), pos / chunk_size))
                    as Box<dyn FileCryptoWriterCallback>
            }),
            locks.as_ref().map(|lock| lock.get(chunk_index)),
            metadata_provider,
        )
    }

    fn seek_from_start(&mut self, pos: u64) -> io::Result<u64> {
        if pos == self.pos()? {
            return Ok(pos);
        }
        debug!(pos = pos.to_formatted_string(&Locale::en), "seeking");

        // obtain a read lock to whole file, we ue a special value to indicate this.
        // this helps if someone is truncating the file while we are using it, they will to a write lock
        let mut _lock = None;
        let _guard_all = {
            if let Some(locks) = &self.locks {
                _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
                Some(_lock.as_ref().unwrap().read())
            } else {
                None
            }
        };

        let chunk_index = pos / self.chunk_size;
        if pos == 0 {
            // reset the writer if we seek at the beginning to pick up any filesize changes
            if let Some(mut writer) = self.writer.take() {
                writer.flush()?;
                writer.finish()?;
            }
            let current_pos = self.pos()?;
            self.writer = Some(self.create_new_writer(pos, current_pos)?);
        } else {
            if self.chunk_index != chunk_index {
                // we need to switch to a new chunk
                debug!(
                    chunk_index = chunk_index.to_formatted_string(&Locale::en),
                    "switching to new chunk"
                );
                if let Some(mut writer) = self.writer.take() {
                    writer.flush()?;
                    writer.finish()?;
                }
                let current_pos = self.pos()?;
                self.writer = Some(self.create_new_writer(pos, current_pos)?);
            }
            let offset_in_chunk = pos % self.chunk_size;
            debug!(
                offset_in_chunk = offset_in_chunk.to_formatted_string(&Locale::en),
                "seeking in chunk"
            );
            if self.writer.is_none() {
                let current_pos = self.pos()?;
                self.writer = Some(self.create_new_writer(pos, current_pos)?);
            }
            self.writer
                .as_mut()
                .unwrap()
                .seek(SeekFrom::Start(offset_in_chunk))?;
            self.chunk_index = pos / self.chunk_size;
        }
        Ok(pos)
    }

    fn pos(&mut self) -> io::Result<u64> {
        if self.writer.is_none() {
            self.writer = Some(self.create_new_writer(self.chunk_index, self.chunk_index)?);
        }
        Ok(self.chunk_index * CHUNK_SIZE + self.writer.as_mut().unwrap().stream_position()?)
    }
}

impl AsyncWrite for ChunkedFileCryptoWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let this = Pin::into_inner(self);
        debug!(
            pos = this.pos()?.to_formatted_string(&Locale::en),
            chunk_index = this.chunk_index.to_formatted_string(&Locale::en),
            "writing {} bytes",
            buf.len().to_formatted_string(&Locale::en)
        );
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // obtain a read lock to whole file, we ue a special value to indicate this.
        // this helps if someone is truncating the file while we are using it, they will to a write lock
        let mut _lock = None;
        let _guard_all = if let Some(locks) = &this.locks {
            _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
            Some(_lock.as_ref().unwrap().read())
        } else {
            None
        };

        let mut buf = &buf[..];
        let mut written = 0_u64;
        loop {
            let current_pos = this.pos()?;
            if this.writer.is_none() {
                let pos = current_pos;
                this.writer = Some(this.create_new_writer(pos, pos)?);
            }
            if (current_pos + buf.len() as u64) / this.chunk_size > (current_pos / this.chunk_size)
            {
                // buf expands to next chunk, split it
                let len = (((current_pos / this.chunk_size + 1) * this.chunk_size) - current_pos)
                    as usize;
                debug!(
                    at = len.to_formatted_string(&Locale::en),
                    pos = this.pos()?.to_formatted_string(&Locale::en),
                    chunk_index = this.chunk_index.to_formatted_string(&Locale::en),
                    "splitting buf"
                );
                let (buf1, buf2) = buf.split_at(len);
                let res = this.writer.as_mut().unwrap().write(buf1);
                if let Err(err) = res {
                    error!("error writing to chunk: {}", err);
                    return Poll::Ready(Err(err));
                }
                if let Ok(len2) = res {
                    written += len2 as u64;
                    if len2 != len {
                        // we didn't write all of buf1, return early
                        return Poll::Ready(Ok(written as usize + len2));
                    }
                    // flush and finish current chunk
                    if let Err(err) = this.writer.as_mut().unwrap().flush() {
                        error!("error flushing chunk: {}", err);
                        return Poll::Ready(Err(err));
                    }
                    if let Err(err) = this.writer.as_mut().unwrap().finish() {
                        error!("error finishing chunk: {}", err);
                        return Poll::Ready(Err(err));
                    }
                    this.writer.take();

                    if buf2.is_empty() {
                        return Poll::Ready(Ok(written as usize));
                    }

                    // now write buf2 to next chunk
                    debug!(
                        pos = this.pos()?.to_formatted_string(&Locale::en),
                        len = buf2.len().to_formatted_string(&Locale::en),
                        chunk_index = this.chunk_index.to_formatted_string(&Locale::en),
                        "writing to next chunk"
                    );
                    buf = buf2;
                    this.chunk_index += 1;
                }
            } else {
                debug!(
                    pos = this.pos()?.to_formatted_string(&Locale::en),
                    chunk_index = this.chunk_index.to_formatted_string(&Locale::en),
                    "writing to chunk"
                );
                let res = this.writer.as_mut().unwrap().write(buf);
                if let Err(err) = res {
                    error!("error writing to chunk: {}", err);
                    return Poll::Ready(Err(err));
                }
                if let Ok(len) = res {
                    written += len as u64;
                    return Poll::Ready(Ok(written as usize));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = Pin::into_inner(self);
        if let Some(writer) = this.writer.as_mut() {
            let res = writer.flush();
            return Poll::Ready(res);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = Pin::into_inner(self);
        if let Some(mut writer) = this.writer.take() {
            let _ = writer.flush();
            let _ = writer.finish();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for ChunkedFileCryptoWriter {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = Pin::into_inner(self);
        let new_pos = match position {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(_) => {
                return Err(Error::new(
                    io::ErrorKind::Other,
                    "seek from end not supported",
                ))
            }
            SeekFrom::Current(pos) => this.pos()? as i64 + pos,
        };
        if new_pos < 0 {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                "can't seek before start",
            ));
        }
        this.seek_from_start(new_pos as u64)?;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = Pin::into_inner(self);
        Poll::Ready(Ok(this.pos()?))
    }
}

impl AsyncCryptoWriter for ChunkedFileCryptoWriter {}

impl AsyncSeekCryptoWriter for ChunkedFileCryptoWriter {}
