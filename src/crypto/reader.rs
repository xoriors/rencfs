use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use num_format::{Locale, ToFormattedString};
use parking_lot::RwLock;
use ring::aead::{Aad, Algorithm, BoundKey, OpeningKey, UnboundKey};
use secrecy::{ExposeSecret, SecretVec};
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};
use tracing::{debug, error, instrument, warn};

use crate::arc_hashmap::Holder;
use crate::crypto::buf_mut::BufMut;
use crate::crypto::writer::{
    RandomNonceSequence, SequenceLockProvider, BUF_SIZE, CHUNK_SIZE, WHOLE_FILE_CHUNK_INDEX,
};
use crate::crypto::Cipher;
use crate::{crypto, stream_util};

#[allow(clippy::module_name_repetitions)]
pub trait CryptoReader<R: Read + Seek>: Read + Seek + Send + Sync {
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<R>;
}

/// cryptostream

// pub struct CryptostreamCryptoReader<R: Read> {
//     inner: Option<cryptostream::read::Decryptor<R>>,
// }
//
// impl<R: Read> CryptostreamCryptoReader<R> {
//     pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> crypto::Result<Self> {
//         Ok(Self {
//             inner: Some(cryptostream::read::Decryptor::new(reader, cipher, key, iv)?),
//         })
//     }
// }
//
// impl<R: Read> Read for CryptostreamCryptoReader<R> {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         self.inner.as_mut().unwrap().read(buf)
//     }
// }
//
// impl<R: Read + Sync + Send> Seek for CryptostreamCryptoReader<R> {
//     fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
//         todo!()
//     }
// }
//
// impl<R: Read + Sync + Send> CryptoReader<R> for CryptostreamCryptoReader<R> {
//     fn finish(&mut self) -> Option<R> {
//         Some(self.inner.take().unwrap().finish())
//     }
// }

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoReader<R: Read + Seek + Send + Sync> {
    input: Option<R>,
    opening_key: OpeningKey<RandomNonceSequence>,
    buf: BufMut,
    pos: u64,
    algorithm: &'static Algorithm,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
}

impl<R: Read + Seek + Send + Sync> RingCryptoReader<R> {
    pub fn new(
        r: R,
        algorithm: &'static Algorithm,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
    ) -> Self {
        let opening_key = Self::create_opening_key(algorithm, &key, nonce_seed);
        let buf = BufMut::new(vec![0; BUF_SIZE + algorithm.tag_len()]);
        Self {
            input: Some(r),
            opening_key,
            buf,
            pos: 0,
            algorithm,
            key,
            nonce_seed,
        }
    }

    fn create_opening_key(
        algorithm: &'static Algorithm,
        key: &Arc<SecretVec<u8>>,
        nonce_seed: u64,
    ) -> OpeningKey<RandomNonceSequence> {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = RandomNonceSequence::new(nonce_seed);
        OpeningKey::new(unbound_key, nonce_sequence)
    }

    fn seek_from_start(&mut self, offset: u64) -> io::Result<u64> {
        if self.pos != offset {
            // in order to seek we need to read the bytes from current position until the offset
            if self.pos > offset {
                // if we need an offset before the current position, we can't seek back, we need
                // to read from the beginning until the desired offset
                debug!("seeking back, recreating decryptor");
                self.opening_key =
                    Self::create_opening_key(self.algorithm, &self.key, self.nonce_seed);
                self.buf.clear();
                self.pos = 0;
                self.input.as_mut().unwrap().seek(SeekFrom::Start(0))?;
            }
            debug!(
                pos = self.pos.to_formatted_string(&Locale::en),
                offset = offset.to_formatted_string(&Locale::en),
                "seeking"
            );
            let len = offset - self.pos;
            stream_util::seek_forward(self, len, true)?;
            debug!("new pos {}", self.pos.to_formatted_string(&Locale::en));
        }
        Ok(self.pos)
    }
}

impl<R: Read + Seek + Send + Sync> Read for RingCryptoReader<R> {
    #[instrument(name = "RingCryptoReader:read", skip(self, buf))]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // first try to read remaining decrypted data
        {
            let len = self.buf.read(buf)?;
            if len != 0 {
                self.pos += len as u64;
                return Ok(len);
            }
        }
        // we read all the data from the buffer, so we need to read a new block and decrypt it
        let pos = {
            self.buf.clear();
            let buffer = self.buf.as_mut_remaining();
            let len = {
                let mut pos = 0;
                loop {
                    match self.input.as_mut().unwrap().read(&mut buffer[pos..]) {
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
            let plaintext = self
                .opening_key
                .open_within(Aad::empty(), data, 0..)
                .map_err(|err| {
                    error!("error opening within: {}", err);
                    io::Error::new(io::ErrorKind::Other, "error opening within")
                })?;
            plaintext.len()
        };
        self.buf.seek(SeekFrom::Start(pos as u64)).unwrap();
        let len = self.buf.read(buf)?;
        self.pos += len as u64;
        Ok(len)
    }
}

impl<R: Read + Seek + Send + Sync> Seek for RingCryptoReader<R> {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.seek_from_start(pos),
            SeekFrom::End(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "can't seek from end",
            )),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos as i64 + pos;
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

impl<R: Read + Seek + Send + Sync> CryptoReader<R> for RingCryptoReader<R> {
    fn finish(&mut self) -> io::Result<R> {
        if self.input.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "RingCryptoReader already finished",
            ));
        }
        Ok(self.input.take().unwrap())
    }
}

/// file reader

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoReader {
    file: PathBuf,
    reader: Box<dyn CryptoReader<File>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
    lock: Option<Holder<RwLock<bool>>>,
}

impl FileCryptoReader {
    /// `lock` is used to read lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we read
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        lock: Option<Holder<RwLock<bool>>>,
    ) -> io::Result<Self> {
        Ok(Self {
            file: file.to_owned(),
            reader: Box::new(crypto::create_reader(
                File::open(file)?,
                cipher,
                key.clone(),
                nonce_seed,
            )),
            cipher,
            key,
            nonce_seed,
            lock,
        })
    }
}

impl Read for FileCryptoReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let _guard = {
            if let Some(lock) = &self.lock {
                Some(lock.read())
            } else {
                None
            }
        };
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
        // pos 0 means also we need to recreate the reader as maybe the actual file got replaced
        if pos == 0 || self.reader.stream_position()? != pos {
            if pos == 0 || self.reader.stream_position()? > pos {
                self.reader.finish()?;
                self.reader = Box::new(crypto::create_reader(
                    File::open(&self.file).unwrap(),
                    self.cipher,
                    self.key.clone(),
                    self.nonce_seed,
                ));
            }
            self.reader.seek(SeekFrom::Start(pos))?;
        }
        self.reader.stream_position()
    }
}

impl CryptoReader<File> for FileCryptoReader {
    fn finish(&mut self) -> io::Result<File> {
        self.reader.finish()
    }
}

/// Async reader

pub trait AsyncCryptoReader: AsyncRead + AsyncSeek + Send + Sync {}

/// Chunked reader
/// File is split into chunks files. This reader iterates over the chunks and reads them one by one.

#[allow(clippy::module_name_repetitions)]
pub struct ChunkedFileCryptoReader {
    file_dir: PathBuf,
    reader: Option<Box<dyn CryptoReader<File>>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
    locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
    chunk_size: u64,
    chunk_index: u64,
}

impl ChunkedFileCryptoReader {
    /// `locks` is used to read lock the chunks files when accessing them. This ensures offer multiple reads but exclusive writes to a given chunk
    ///     If not provided, it will not ensure that other instances are not writing the chunks while we read them
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file_dir: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
    ) -> io::Result<Self> {
        let mut s = Self {
            file_dir: file_dir.to_owned(),
            reader: None,
            cipher,
            key: key.clone(),
            nonce_seed,
            locks,
            chunk_size: CHUNK_SIZE,
            chunk_index: 0,
        };
        s.reader = Self::try_create_reader(
            0,
            CHUNK_SIZE,
            file_dir.to_owned(),
            cipher,
            key,
            nonce_seed,
            &s.locks,
        )?;
        Ok(s)
    }

    fn try_create_reader(
        pos: u64,
        chunk_size: u64,
        file_dir: PathBuf,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
    ) -> io::Result<Option<Box<dyn CryptoReader<File>>>> {
        let chunk_index = pos / chunk_size;
        let chunk_file = file_dir.join(chunk_index.to_string());
        if !chunk_file.exists() {
            return Ok(None);
        }
        Ok(Some(Self::create_reader(
            pos,
            chunk_size,
            file_dir.to_owned(),
            cipher,
            key.clone(),
            nonce_seed,
            locks,
        )?))
    }

    fn create_reader(
        pos: u64,
        chunk_size: u64,
        file_dir: PathBuf,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
    ) -> io::Result<Box<dyn CryptoReader<File>>> {
        let chunk_index = pos / chunk_size;
        let chunk_file = file_dir.join(chunk_index.to_string());
        Ok(crypto::create_file_reader(
            &chunk_file,
            cipher,
            key.clone(),
            nonce_seed,
            locks.as_ref().map(|lock| lock.get(pos / chunk_size)),
        )?)
    }

    fn pos(&mut self) -> io::Result<u64> {
        Ok(self.chunk_index + self.reader.as_mut().unwrap().stream_position()?)
    }
}

impl AsyncRead for ChunkedFileCryptoReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        if this.reader.is_none() {
            return Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // obtain a read lock to whole file, we ue a special value to indicate this.
        // this helps if someone is truncating the file while we are using it, they will to a write lock
        let mut _lock = None;
        let _guard_all = {
            if let Some(locks) = &this.locks {
                _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
                Some(_lock.as_ref().unwrap().read())
            } else {
                None
            }
        };

        let len = buf.remaining();
        debug!(len = len.to_formatted_string(&Locale::en), "reading");
        let mut buffer = vec![0; len];
        this.reader.as_mut().unwrap().read(&mut buffer)?;
        buf.put_slice(&buffer);
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for ChunkedFileCryptoReader {
    fn start_seek(self: Pin<&mut Self>, pos: SeekFrom) -> io::Result<()> {
        let this = Pin::into_inner(self);
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "can't seek from end",
                ))
            }
            SeekFrom::Current(pos) => {
                let new_pos = this.pos()? as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "can't seek before start",
                    ));
                }
                new_pos as u64
            }
        };
        if this.pos()? != new_pos {
            debug!(
                pos = this.pos()?.to_formatted_string(&Locale::en),
                new_pos = new_pos.to_formatted_string(&Locale::en),
                "seeking"
            );

            // obtain a read lock to whole file, we ue a special value to indicate this.
            // this helps if someone is truncating the file while we are using it, they will to a write lock
            let mut _lock = None;
            let _guard_all = {
                if let Some(locks) = &this.locks {
                    _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
                    Some(_lock.as_ref().unwrap().read())
                } else {
                    None
                }
            };

            let pos = this.pos()?;
            if let Some(reader) = &mut this.reader {
                if pos / this.chunk_size == new_pos / this.chunk_size {
                    // seek in current chunk as much as we can
                    let new_pos_in_chunk = new_pos % this.chunk_size;
                    reader.seek(SeekFrom::Start(new_pos_in_chunk))?;
                } else {
                    // we need to switch to another chunk
                    let chunk_index = new_pos / this.chunk_size;
                    let chunk_file = this.file_dir.join(chunk_index.to_string());
                    if !chunk_file.exists() {
                        return Ok(());
                    }
                    debug!("switching to next chunk");
                    this.reader = Self::try_create_reader(
                        new_pos,
                        this.chunk_size,
                        this.file_dir.to_owned(),
                        this.cipher,
                        this.key.clone(),
                        this.nonce_seed,
                        &this.locks,
                    )?;
                    if let Some(reader) = &mut this.reader {
                        // seek in chunk
                        let new_pos_in_chunk = new_pos % this.chunk_size;
                        debug!(
                            new_pos_in_chunk = new_pos_in_chunk.to_formatted_string(&Locale::en),
                            "seeking in new chunk"
                        );
                        reader.seek(SeekFrom::Start(new_pos_in_chunk))?;
                        this.chunk_index = new_pos / this.chunk_size;
                    }
                }
            }
        }
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<u64>> {
        let this = Pin::into_inner(self);
        Poll::Ready(this.pos())
    }
}

impl AsyncCryptoReader for ChunkedFileCryptoReader {}
