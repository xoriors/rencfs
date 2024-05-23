mod bench;
mod test;

use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
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
use crate::crypto::buf_mut::BufMut;
use crate::crypto::write::BLOCK_SIZE;
use crate::crypto::Cipher;
use crate::{crypto, stream_util};

/// Reads encrypted content from the wrapped Reader.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoRead<R: Read + Send + Sync>: Read + Send + Sync {
    fn into_inner(&mut self) -> R;
}

/// ring

#[macro_export]
macro_rules! decrypt_block {
    ($block_index:expr, $buf:expr, $input:expr, $last_nonce:expr, $opening_key:expr) => {{
        let len = {
            $buf.clear();
            let buffer = $buf.as_mut_remaining();
            let mut len = {
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
            if len != 0 {
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
                len = plaintext.len();
            }
            len
        };
        if len != 0 {
            $buf.seek_available(SeekFrom::Start(NONCE_LEN as u64 + len as u64))
                .unwrap();
            // skip nonce
            $buf.seek_read(SeekFrom::Start(NONCE_LEN as u64)).unwrap();
            $block_index += 1;
        }
    }};
}

pub(crate) use decrypt_block;

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoRead<R: Read> {
    input: Option<R>,
    opening_key: OpeningKey<ExistingNonceSequence>,
    buf: BufMut,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
}

impl<R: Read> RingCryptoRead<R> {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(reader: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let ciphertext_block_size = NONCE_LEN + BLOCK_SIZE + algorithm.tag_len();
        let buf = BufMut::new(vec![0; ciphertext_block_size]);
        let last_nonce = Arc::new(Mutex::new(None));
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        Self {
            input: Some(reader),
            opening_key,
            buf,
            last_nonce,
            ciphertext_block_size,
            plaintext_block_size: BLOCK_SIZE,
            block_index: 0,
        }
    }
}

impl<R: Read> Read for RingCryptoRead<R> {
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
            self.input.as_mut().unwrap(),
            self.last_nonce,
            self.opening_key
        );
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

impl<R: Read + Send + Sync> CryptoRead<R> for RingCryptoRead<R> {
    fn into_inner(&mut self) -> R {
        self.input.take().unwrap()
    }
}

impl<R: Read + Seek> Seek for RingCryptoRead<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        todo!()
    }
}

/// Read with Seek

pub trait CryptoReadSeek<R: Read + Seek + Send + Sync>: CryptoRead<R> + Seek {}

pub struct RingCryptoReaderSeek<R: Read + Seek> {
    inner: RingCryptoRead<R>,
}

impl<R: Read + Seek> RingCryptoReaderSeek<R> {
    pub fn new(reader: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        Self {
            inner: RingCryptoRead::new(reader, algorithm, key),
        }
    }

    fn pos(&mut self) -> u64 {
        self.inner.block_index.saturating_sub(1) * self.inner.plaintext_block_size as u64
            + self.inner.buf.pos_read().saturating_sub(NONCE_LEN) as u64
    }

    fn get_plaintext_len(&mut self) -> io::Result<u64> {
        let ciphertext_len = self.inner.input.as_mut().unwrap().stream_len()?;
        if ciphertext_len == 0 {
            return Ok(0);
        }
        let plaintext_len = ciphertext_len
            - ((ciphertext_len / self.inner.ciphertext_block_size as u64) + 1)
                * (self.inner.ciphertext_block_size - self.inner.plaintext_block_size) as u64;
        Ok(plaintext_len)
    }
}

impl<R: Read + Seek> Seek for RingCryptoReaderSeek<R> {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let plaintext_len = self.get_plaintext_len()?;
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => plaintext_len as i64 + pos,
            SeekFrom::Current(pos) => self.pos() as i64 + pos,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new position < 0",
            ));
        }
        // keep in bounds
        let mut new_pos = new_pos as u64;
        new_pos = new_pos.min(plaintext_len);
        if self.pos() == new_pos {
            return Ok(new_pos);
        }
        let block_index = self.pos() / self.inner.plaintext_block_size as u64;
        let new_block_index = new_pos / self.inner.plaintext_block_size as u64;
        if block_index == new_block_index {
            let at_full_block_end = self.pos() % self.inner.plaintext_block_size as u64 == 0
                && self.inner.buf.available_read() == 0;
            if self.inner.buf.available() > 0
                // this make sure we are not at the end of current block, which is the start boundary of next block
                // in that case we need to seek inside the next block
                && !at_full_block_end
            {
                // seek inside current block
                self.inner.buf.seek_read(SeekFrom::Start(
                    NONCE_LEN as u64 + new_pos % self.inner.plaintext_block_size as u64,
                ))?;
            } else {
                // we need to read a new block and seek inside that block
                let plaintext_block_size = self.inner.plaintext_block_size;
                stream_util::seek_forward(
                    &mut self.inner,
                    new_pos % plaintext_block_size as u64,
                    true,
                )?;
            }
        } else {
            // change block
            self.inner.input.as_mut().unwrap().seek(SeekFrom::Start(
                new_block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            self.inner.buf.clear();
            self.inner.block_index = new_block_index;
            // seek inside new block
            let plaintext_block_size = self.inner.plaintext_block_size;
            stream_util::seek_forward(
                &mut self.inner,
                new_pos % plaintext_block_size as u64,
                true,
            )?;
        }
        Ok(self.pos())
    }
}

impl<R: Read + Seek + Send + Sync> Read for RingCryptoReaderSeek<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek + Send + Sync> CryptoRead<R> for RingCryptoReaderSeek<R> {
    fn into_inner(&mut self) -> R {
        self.inner.into_inner()
    }
}

impl<R: Read + Seek + Send + Sync> CryptoReadSeek<R> for RingCryptoReaderSeek<R> {}

/// File Read

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoRead {
    file: PathBuf,
    reader: Option<Box<dyn CryptoReadSeek<File>>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    lock: Option<Holder<RwLock<bool>>>,
}

impl FileCryptoRead {
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
            reader: Some(Box::new(crypto::create_read_seek(
                File::open(file)?,
                cipher,
                key.clone(),
            ))),
            cipher,
            key,
            lock,
        })
    }
}

impl Read for FileCryptoRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let _guard = self.lock.as_ref().map(|lock| lock.read());
        let len = self.reader.as_mut().unwrap().read(buf)?;
        Ok(len)
    }
}

impl Seek for FileCryptoRead {
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
                let new_pos = self.reader.as_mut().unwrap().stream_position()? as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "can't seek before start",
                    ));
                }
                new_pos as u64
            }
        };
        let current_pos = self.reader.as_mut().unwrap().stream_position()?;
        if current_pos > pos {
            // we need to recreate the reader
            self.reader = Some(Box::new(crypto::create_read_seek(
                File::open(&self.file)?,
                self.cipher,
                self.key.clone(),
            )));
        }
        self.reader.as_mut().unwrap().seek(SeekFrom::Start(pos))?;
        self.reader.as_mut().unwrap().stream_position()
    }
}

impl CryptoRead<File> for FileCryptoRead {
    fn into_inner(&mut self) -> File {
        self.reader.take().unwrap().into_inner()
    }
}
impl CryptoReadSeek<File> for FileCryptoRead {}
