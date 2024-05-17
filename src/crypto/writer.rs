use ::test::{black_box, Bencher};
use std::fs::File;
use std::io;
use std::io::{BufWriter, Error, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use atomic_write_file::AtomicWriteFile;
use num_format::{Locale, ToFormattedString};
use rand_chacha::rand_core::RngCore;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tokio::sync::RwLock;
use tracing::{debug, error};

use crate::arc_hashmap::Holder;
use crate::crypto::buf_mut::BufMut;
use crate::crypto::Cipher;
use crate::{crypto, fs_util, stream_util};

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

/// Ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWriter<W: Write + Send + Sync> {
    out: Option<BufWriter<W>>,
    sealing_key: SealingKey<RandomNonceSequenceWrapper>,
    buf: BufMut,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    block_index: u64,
    algorithm: &'static Algorithm,
    key: Arc<SecretVec<u8>>,
}

impl<W: Write + Send + Sync> RingCryptoWriter<W> {
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(w: W, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        let sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        let buf = BufMut::new(vec![0; BUF_SIZE]);
        Self {
            out: Some(BufWriter::new(w)),
            sealing_key,
            buf,
            nonce_sequence,
            block_index: 0,
            algorithm,
            key,
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
        // let unbound_key =
        //     UnboundKey::new(self.algorithm, self.key.expose_secret()).expect("unbound key");
        // let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        // let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        // self.sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        // self.nonce_sequence = nonce_sequence;

        let data = self.buf.as_mut();
        let aad = Aad::from(self.block_index.to_le_bytes());
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(aad, data)
            .map_err(|err| {
                error!("error sealing in place: {}", err);
                io::Error::from(io::ErrorKind::Other)
            })?;
        let out = self
            .out
            .as_mut()
            .expect("encrypt_and_write called on already finished writer");
        let nonce_sequence = self.nonce_sequence.lock().unwrap();
        let nonce = nonce_sequence.last_nonce.as_ref().unwrap();
        out.write_all(nonce)?;
        out.write_all(data)?;
        self.buf.clear();
        out.write_all(tag.as_ref())?;
        self.block_index += 1;
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
        self.flush()?;
        if self.buf.available() > 0 {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        let mut out = self.out.take().unwrap();
        out.flush()?;
        Ok(out.into_inner()?)
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

pub trait CryptoWriterSeek<W: Write>: CryptoWriter<W> + Seek {}

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
            writer.flush()?;
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
            SeekFrom::End(_) => Err(Error::new(
                io::ErrorKind::Other,
                "seek from end not supported",
            )),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos()? as i64 + pos;
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

// // todo: expose as param
// #[cfg(test)]
// pub(crate) const CHUNK_SIZE: u64 = 1024; // 1K for tests
// #[cfg(not(test))]
// // pub(crate) const CHUNK_SIZE: u64 = 16 * 1024 * 1024; // 64M
// pub(crate) const CHUNK_SIZE: u64 = 512 * 1024;
//
// // use this when we want to lock the whole file
// pub const WHOLE_FILE_CHUNK_INDEX: u64 = u64::MAX - 42_u64;
//
// pub trait SequenceLockProvider: Send + Sync {
//     fn get(&self, index: u64) -> Holder<RwLock<bool>>;
// }
//
// #[allow(clippy::module_name_repetitions)]
// pub struct ChunkedTmpFileCryptoWriter {
//     file_dir: PathBuf,
//     cipher: Cipher,
//     key: Arc<SecretVec<u8>>,
//     callback: Option<Arc<Box<dyn FileCryptoWriterCallback>>>,
//     chunk_size: u64,
//     chunk_index: u64,
//     writer: Option<Box<dyn CryptoWriterSeek<File>>>,
//     locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
//     metadata_provider: Option<Arc<Box<dyn FileCryptoWriterMetadataProvider>>>,
// }
//
// struct CallbackWrapper(Arc<Box<dyn FileCryptoWriterCallback>>, u64);
// impl FileCryptoWriterCallback for CallbackWrapper {
//     fn on_file_content_changed(
//         &self,
//         changed_from_pos: i64,
//         last_write_pos: u64,
//     ) -> io::Result<()> {
//         self.0
//             .on_file_content_changed(self.1 as i64 + changed_from_pos, self.1 + last_write_pos)
//     }
// }
//
// struct FileCryptoWriterMetadataProviderImpl {
//     chunk_index: u64,
//     chunk_size: u64,
//     file_dir: PathBuf,
//     provider: Arc<Box<dyn FileCryptoWriterMetadataProvider>>,
// }
// impl FileCryptoWriterMetadataProvider for FileCryptoWriterMetadataProviderImpl {
//     fn size(&self) -> io::Result<u64> {
//         let mut size = self.provider.size()?;
//         // check if we are in the last chunk
//         let path = Path::new(&self.file_dir).join((self.chunk_index + 1).to_string());
//         if !path.exists() {
//             // we are in the last chunk, size is remaining after multiple of chunk size
//             size %= self.chunk_size;
//         } else {
//             // we are NOT in the last chunk, size is a full chunk size
//             size = self.chunk_size;
//         }
//         Ok(size)
//     }
// }
//
// // todo: create traits for lock and metadata provider and don't use [`Guard`]
// impl ChunkedTmpFileCryptoWriter {
//     /// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position
//     ///
//     /// **`lock`** is used to write lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we do
//     ///     You need to provide the same lock to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same lock
//     ///
//     /// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file
//     ///     If the file exists or is created before flushing, in worse case scenarios, it can reduce the overall write speed by half, so it's recommended to provide it
//     pub fn new(
//         file_dir: &Path,
//         cipher: Cipher,
//         key: Arc<SecretVec<u8>>,
//         callback: Option<Box<dyn FileCryptoWriterCallback>>,
//         locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
//         metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
//     ) -> io::Result<Self> {
//         if !file_dir.exists() {
//             fs::create_dir_all(file_dir)?;
//         }
//         Ok(Self {
//             file_dir: file_dir.to_owned(),
//             cipher,
//             key: key.clone(),
//             callback: callback.map(|c| Arc::new(c)),
//             chunk_size: CHUNK_SIZE,
//             chunk_index: 0,
//             writer: None,
//             locks,
//             metadata_provider: metadata_provider.map(|m| Arc::new(m)),
//         })
//     }
//
//     fn create_new_writer(&mut self, pos: u64) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
//         Self::create_writer(
//             pos,
//             &self.file_dir,
//             self.cipher,
//             self.key.clone(),
//             self.chunk_size,
//             &self.locks,
//             self.callback.clone(),
//             self.metadata_provider.as_ref().map(|m| {
//                 Box::new(FileCryptoWriterMetadataProviderImpl {
//                     chunk_size: self.chunk_size,
//                     chunk_index: pos / self.chunk_size,
//                     file_dir: self.file_dir.clone(),
//                     provider: m.clone(),
//                 }) as Box<dyn FileCryptoWriterMetadataProvider>
//             }),
//         )
//     }
//
//     fn create_writer(
//         pos: u64,
//         file_dir: &Path,
//         cipher: Cipher,
//         key: Arc<SecretVec<u8>>,
//         chunk_size: u64,
//         locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
//         callback: Option<Arc<Box<dyn FileCryptoWriterCallback>>>,
//         metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
//     ) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
//         let chunk_index = pos / chunk_size;
//         debug!(
//             chunk_index = chunk_index.to_formatted_string(&Locale::en),
//             "creating new writer"
//         );
//         let chunk_file = file_dir.join(chunk_index.to_string());
//         {
//             let mut _lock = None;
//             let mut _lock2 = None;
//             let (_g1, _g2) = if let Some(locks) = locks {
//                 _lock = Some(locks.get(chunk_index));
//                 let guard = _lock.as_ref().unwrap().write();
//                 // obtain a write lock to whole file, we ue a special value to indicate this.
//                 _lock2 = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
//                 let guard_all = _lock2.as_ref().unwrap().read();
//                 (Some(guard), Some(guard_all))
//             } else {
//                 (None, None)
//             };
//
//             if !chunk_file.exists() {
//                 File::create(&chunk_file)?;
//             }
//         }
//         crypto::create_file_writer(
//             chunk_file.as_path(),
//             cipher,
//             key.clone(),
//             callback.as_ref().map(|c| {
//                 Box::new(CallbackWrapper(c.clone(), pos / chunk_size))
//                     as Box<dyn FileCryptoWriterCallback>
//             }),
//             locks.as_ref().map(|lock| lock.get(chunk_index)),
//             metadata_provider,
//         )
//     }
//
//     fn seek_from_start(&mut self, pos: u64) -> io::Result<u64> {
//         if pos == self.pos()? {
//             return Ok(pos);
//         }
//         debug!(pos = pos.to_formatted_string(&Locale::en), "seeking");
//
//         // obtain a read lock to whole file, we ue a special value to indicate this.
//         // this helps if someone is truncating the file while we are using it, they will to a write lock
//         let mut _lock = None;
//         let _guard_all = {
//             if let Some(locks) = &self.locks {
//                 _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
//                 Some(_lock.as_ref().unwrap().read())
//             } else {
//                 None
//             }
//         };
//
//         let new_chunk_index = pos / self.chunk_size;
//         if pos == 0 {
//             // reset the writer if we seek at the beginning to pick up any filesize changes
//             if let Some(mut writer) = self.writer.take() {
//                 writer.flush()?;
//                 writer.finish()?;
//             }
//             self.writer = Some(self.create_new_writer(pos)?);
//         } else {
//             if self.chunk_index != new_chunk_index {
//                 // we need to switch to a new chunk
//                 debug!(
//                     chunk_index = new_chunk_index.to_formatted_string(&Locale::en),
//                     "switching to new chunk"
//                 );
//                 if self.chunk_index < new_chunk_index {
//                     // we need to seek forward, maybe we don't yet have chunks created until new chunk
//                     // in that case create them and fill up with zeros
//                     if self.writer.is_none() {
//                         let current_pos = self.pos()?;
//                         self.writer = Some(self.create_new_writer(current_pos)?);
//                     }
//                     // first seek in current chunk to the end to fill up with zeros as needed
//                     self.writer
//                         .as_mut()
//                         .unwrap()
//                         .seek(SeekFrom::Start(self.chunk_size))?;
//                     // iterate through all chunks until new chunk and create missing ones
//                     for i in self.chunk_index + 1..new_chunk_index {
//                         let current_pos = i * self.chunk_size;
//                         if !self.chunk_exists(i) {
//                             let mut writer = self.create_new_writer(current_pos)?;
//                             writer.seek(SeekFrom::Start(self.chunk_size))?; // fill up with zeros
//                             writer.flush()?;
//                             writer.finish()?;
//                         }
//                     }
//                 }
//                 // finish any existing writer
//                 if let Some(mut writer) = self.writer.take() {
//                     writer.flush()?;
//                     writer.finish()?;
//                 }
//             }
//             // seeking in current chunk
//             let offset_in_chunk = pos % self.chunk_size;
//             debug!(
//                 offset_in_chunk = offset_in_chunk.to_formatted_string(&Locale::en),
//                 "seeking in chunk"
//             );
//             if self.writer.is_none() {
//                 self.writer = Some(self.create_new_writer(pos)?);
//             }
//             self.writer
//                 .as_mut()
//                 .unwrap()
//                 .seek(SeekFrom::Start(offset_in_chunk))?;
//             self.chunk_index = pos / self.chunk_size;
//         }
//         Ok(pos)
//     }
//
//     fn chunk_exists(&self, chunk_index: u64) -> bool {
//         let path = self.file_dir.join(chunk_index.to_string());
//         path.exists()
//     }
//
//     fn pos(&mut self) -> io::Result<u64> {
//         if self.writer.is_none() {
//             self.writer = Some(self.create_new_writer(self.chunk_index * self.chunk_size)?);
//         }
//         Ok(self.chunk_index * self.chunk_size + self.writer.as_mut().unwrap().stream_position()?)
//     }
// }
//
// impl Write for ChunkedTmpFileCryptoWriter {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         debug!(
//             pos = self.pos()?.to_formatted_string(&Locale::en),
//             chunk_index = self.chunk_index.to_formatted_string(&Locale::en),
//             "writing {} bytes",
//             buf.len().to_formatted_string(&Locale::en)
//         );
//         if buf.is_empty() {
//             return Ok(0);
//         }
//
//         // obtain a read lock to whole file, we ue a special value to indicate this.
//         // this helps if someone is truncating the file while we are using it, they will to a write lock
//         let mut _lock = None;
//         let _guard_all = if let Some(locks) = &self.locks {
//             _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
//             Some(_lock.as_ref().unwrap().read())
//         } else {
//             None
//         };
//
//         let mut buf = &buf[..];
//         let mut written = 0_u64;
//         loop {
//             let current_pos = self.pos()?;
//             if self.writer.is_none() {
//                 let pos = current_pos;
//                 self.writer = Some(self.create_new_writer(pos)?);
//             }
//
//             let remaining = self.chunk_size - self.writer.as_mut().unwrap().stream_position()?;
//             let (current_buf, next_buf) = if buf.len() > remaining as usize {
//                 // buf expands to next chunk, split it
//                 debug!(
//                     at = remaining.to_formatted_string(&Locale::en),
//                     pos = self.pos()?.to_formatted_string(&Locale::en),
//                     chunk_index = self.chunk_index.to_formatted_string(&Locale::en),
//                     "splitting buf"
//                 );
//                 let (buf1, buf2) = buf.split_at(remaining as usize);
//                 (buf1, Some(buf2))
//             } else {
//                 (buf, None)
//             };
//
//             // write current buf
//             match self.writer.as_mut().unwrap().write(current_buf) {
//                 Ok(len) => {
//                     written += len as u64;
//                     if len < current_buf.len() && next_buf.is_some() {
//                         // we didn't write all the current buf, but we have a next buf also, return early
//                         return Ok(written as usize + len);
//                     }
//                 }
//                 Err(err) => {
//                     error!("error writing to chunk: {}", err);
//                     return Err(err);
//                 }
//             }
//
//             let remaining = self.chunk_size - self.writer.as_mut().unwrap().stream_position()?;
//             if remaining == 0 {
//                 // flush and finish current chunk
//                 if let Err(err) = self.writer.as_mut().unwrap().flush() {
//                     error!("error flushing chunk: {}", err);
//                     return Err(err);
//                 }
//                 if let Err(err) = self.writer.as_mut().unwrap().finish() {
//                     error!("error finishing chunk: {}", err);
//                     return Err(err);
//                 }
//                 self.writer.take();
//                 self.chunk_index += 1;
//             }
//
//             if next_buf.is_none() {
//                 // we're done writing
//                 return Ok(written as usize);
//             } else {
//                 // prepare writing to next chunk
//                 debug!(
//                     pos = self.pos()?.to_formatted_string(&Locale::en),
//                     len = next_buf
//                         .as_ref()
//                         .unwrap()
//                         .len()
//                         .to_formatted_string(&Locale::en),
//                     chunk_index = self.chunk_index.to_formatted_string(&Locale::en),
//                     "writing to next chunk"
//                 );
//                 buf = next_buf.unwrap();
//             }
//         }
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         if let Some(writer) = self.writer.as_mut() {
//             writer.flush()?;
//         }
//         Ok(())
//     }
// }
//
// impl CryptoWriter<File> for ChunkedTmpFileCryptoWriter {
//     fn finish(&mut self) -> io::Result<File> {
//         if let Some(mut writer) = self.writer.take() {
//             let _ = writer.flush();
//             let _ = writer.finish();
//         }
//
//         let path = self.file_dir.join(0.to_string());
//         if !path.exists() {
//             File::create(&path)?;
//         }
//         Ok(File::open(path)?)
//     }
// }
//
// impl Seek for ChunkedTmpFileCryptoWriter {
//     fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
//         let new_pos = match pos {
//             SeekFrom::Start(pos) => pos as i64,
//             SeekFrom::End(_) => {
//                 return Err(Error::new(
//                     io::ErrorKind::Other,
//                     "seek from end not supported",
//                 ))
//             }
//             SeekFrom::Current(pos) => self.pos()? as i64 + pos,
//         };
//         if new_pos < 0 {
//             return Err(Error::new(
//                 io::ErrorKind::InvalidInput,
//                 "can't seek before start",
//             ));
//         }
//         self.seek_from_start(new_pos as u64)?;
//         Ok(self.pos()?)
//     }
// }
//
// impl CryptoWriterSeek<File> for ChunkedTmpFileCryptoWriter {}

#[cfg(test)]
mod test {
    use std::io::Write;
    use std::io::{Read, Seek};
    use std::sync::Arc;

    use rand::RngCore;
    use secrecy::SecretVec;
    use tracing_test::traced_test;

    use crate::crypto;
    use crate::crypto::writer::{CryptoWriter, BUF_SIZE};
    use crate::crypto::Cipher;

    #[test]
    #[traced_test]
    fn test_reader_writer() {
        let cipher = Cipher::ChaCha20Poly1305;

        let mut key: Vec<u8> = vec![0; cipher.key_len()];
        crypto::create_rng().fill_bytes(&mut key);
        let key = SecretVec::new(key);
        let key = Arc::new(key);

        // simple text
        let mut cursor = std::io::Cursor::new(vec![0; 0]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let data = "hello, this is my secret message";
        writer.write_all(&data.as_bytes()).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key.clone());
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(data, s);

        // larger data
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut writer = crypto::create_writer(cursor, cipher, key.clone());
        let mut data: [u8; BUF_SIZE + 42] = [0; BUF_SIZE + 42];
        crypto::create_rng().fill_bytes(&mut data);
        writer.write_all(&data).unwrap();
        cursor = writer.finish().unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = crypto::create_reader(cursor, cipher, key.clone());
        let mut data2 = vec![];
        reader.read_to_end(&mut data2).unwrap();
        assert_eq!(data.len(), data2.len());
        assert_eq!(crypto::hash(&data), crypto::hash(&data2));
    }
}

#[bench]
fn bench_writer_10mb_cha_cha20poly1305(b: &mut Bencher) {
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
            writer.flush().unwrap();
            writer.finish().unwrap()
        })
    });
}

#[bench]
fn bench_writer_10mb_aes256gcm(b: &mut Bencher) {
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
            writer.flush().unwrap();
            writer.finish().unwrap()
        })
    });
}

struct RandomReader {
    buf: Arc<Vec<u8>>,
    pos: usize,
}

impl RandomReader {
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
