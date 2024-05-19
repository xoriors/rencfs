use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use num_format::{Locale, ToFormattedString};
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, NONCE_LEN,
};
use ring::error;
use secrecy::{ExposeSecret, SecretVec};
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, warn};

use crate::arc_hashmap::Holder;
use crate::crypto::buf_mut::BufMut;
use crate::crypto::writer::BUF_SIZE;
use crate::crypto::Cipher;
use crate::{crypto, stream_util};

#[allow(clippy::module_name_repetitions)]
pub trait CryptoReader: Read + Seek + Send + Sync {}

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoReader<R: Read + Seek + Send + Sync> {
    input: Option<BufReader<R>>,
    opening_key: OpeningKey<ExistingNonceSequence>,
    buf: BufMut,
    pos: u64,
    algorithm: &'static Algorithm,
    key: Arc<SecretVec<u8>>,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
}

impl<R: Read + Seek + Send + Sync> RingCryptoReader<R> {
    pub fn new(r: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>) -> Self {
        let buf = BufMut::new(vec![0; NONCE_LEN + BUF_SIZE + algorithm.tag_len()]);
        let last_nonce = Arc::new(Mutex::new(None));
        let opening_key = Self::create_opening_key(algorithm, &key, last_nonce.clone());
        Self {
            input: Some(BufReader::new(r)),
            opening_key,
            buf,
            pos: 0,
            algorithm,
            key,
            last_nonce,
        }
    }

    fn create_opening_key(
        algorithm: &'static Algorithm,
        key: &Arc<SecretVec<u8>>,
        last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> OpeningKey<ExistingNonceSequence> {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce);
        OpeningKey::new(unbound_key, nonce_sequence)
    }

    fn seek_from_start(&mut self, offset: u64) -> io::Result<u64> {
        if self.pos != offset {
            // in order to seek we need to read the bytes from current position until the offset
            if self.pos > offset {
                // if we need an offset before the current position, we can't seek back, we need
                // to read from the beginning until the desired offset
                debug!(
                    pos = self.pos.to_formatted_string(&Locale::en),
                    offset = offset.to_formatted_string(&Locale::en),
                    "seeking back, recreating decryptor"
                );
                self.opening_key =
                    Self::create_opening_key(self.algorithm, &self.key, self.last_nonce.clone());
                self.buf.clear();
                self.pos = 0;
                self.input.as_mut().unwrap().seek(SeekFrom::Start(0))?;
            }
            let len = offset - self.pos;
            stream_util::seek_forward(self, len, true)?;
        }
        Ok(self.pos)
    }
}

impl<R: Read + Seek + Send + Sync> Read for RingCryptoReader<R> {
    #[instrument(name = "RingCryptoReader:read", skip(self, buf))]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // first try to read remaining decrypted data
        let len = self.buf.read(buf)?;
        if len != 0 {
            self.pos += len as u64;
            return Ok(len);
        }
        // we read all the data from the buffer, so we need to read a new block and decrypt it
        let len = {
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
            let aad = Aad::from((self.pos / BUF_SIZE as u64).to_le_bytes());
            // extract nonce
            self.last_nonce
                .lock()
                .unwrap()
                .replace(data[..NONCE_LEN].to_vec());
            let data = &mut data[NONCE_LEN..];
            // self.opening_key =
            //     Self::create_opening_key(self.algorithm, &self.key, self.last_nonce.clone());
            let plaintext = self
                .opening_key
                .open_within(aad, data, 0..)
                .map_err(|err| {
                    error!("error opening within: {}", err);
                    io::Error::new(io::ErrorKind::Other, "error opening within")
                })?;
            plaintext.len()
        };
        self.buf
            .seek(SeekFrom::Start(NONCE_LEN as u64 + len as u64))
            .unwrap();
        // skip nonce
        self.buf
            .seek_read(SeekFrom::Start(NONCE_LEN as u64))
            .unwrap();
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

struct ExistingNonceSequence {
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ExistingNonceSequence {
    fn new(last_nonce: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self { last_nonce }
    }
}

impl NonceSequence for ExistingNonceSequence {
    fn advance(&mut self) -> Result<Nonce, error::Unspecified> {
        Nonce::try_assume_unique_for_key(self.last_nonce.lock().unwrap().as_mut().unwrap())
    }
}

impl<R: Read + Seek + Send + Sync> CryptoReader for RingCryptoReader<R> {}

/// file reader

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoReader {
    file: PathBuf,
    reader: Box<dyn CryptoReader>,
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
            reader: Box::new(crypto::create_reader(
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
            self.reader = Box::new(crypto::create_reader(
                File::open(&self.file)?,
                self.cipher,
                self.key.clone(),
            ));
        }
        self.reader.seek(SeekFrom::Start(pos))?;
        self.reader.stream_position()
    }
}

impl CryptoReader for FileCryptoReader {}

// /// Chunked reader
// /// File is split into chunks files. This reader iterates over the chunks and reads them one by one.
//
// #[allow(clippy::module_name_repetitions)]
// pub struct ChunkedFileCryptoReader {
//     file_dir: PathBuf,
//     reader: Option<Box<dyn CryptoReader>>,
//     cipher: Cipher,
//     key: Arc<SecretVec<u8>>,
//     locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
//     chunk_size: u64,
//     chunk_index: u64,
// }
//
// impl ChunkedFileCryptoReader {
//     /// **`locks`** is used to read lock the chunks files when accessing them. This ensures offer multiple reads but exclusive writes to a given chunk
//     ///     If not provided, it will not ensure that other instances are not writing the chunks while we read them
//     ///     You need to provide the same locks to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same locks
//     #[allow(clippy::missing_errors_doc)]
//     pub fn new(
//         file_dir: &Path,
//         cipher: Cipher,
//         key: Arc<SecretVec<u8>>,
//         locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
//     ) -> io::Result<Self> {
//         Ok(Self {
//             file_dir: file_dir.to_owned(),
//             reader: Self::try_create_reader(
//                 0,
//                 CHUNK_SIZE,
//                 file_dir.to_owned(),
//                 cipher,
//                 key.clone(),
//                 &locks,
//             )?,
//             cipher,
//             key,
//             locks,
//             chunk_size: CHUNK_SIZE,
//             chunk_index: 0,
//         })
//     }
//
//     fn try_create_reader(
//         pos: u64,
//         chunk_size: u64,
//         file_dir: PathBuf,
//         cipher: Cipher,
//         key: Arc<SecretVec<u8>>,
//         locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
//     ) -> io::Result<Option<Box<dyn CryptoReader>>> {
//         let chunk_index = pos / chunk_size;
//         let chunk_file = file_dir.join(chunk_index.to_string());
//         if !chunk_file.exists() {
//             return Ok(None);
//         }
//         Ok(Some(Self::create_reader(
//             pos,
//             chunk_size,
//             file_dir.to_owned(),
//             cipher,
//             key.clone(),
//             locks,
//         )?))
//     }
//
//     fn create_reader(
//         pos: u64,
//         chunk_size: u64,
//         file_dir: PathBuf,
//         cipher: Cipher,
//         key: Arc<SecretVec<u8>>,
//         locks: &Option<Holder<Box<dyn SequenceLockProvider>>>,
//     ) -> io::Result<Box<dyn CryptoReader>> {
//         let chunk_index = pos / chunk_size;
//         let chunk_file = file_dir.join(chunk_index.to_string());
//         Ok(crypto::create_file_reader(
//             &chunk_file,
//             cipher,
//             key.clone(),
//             locks.as_ref().map(|lock| lock.get(pos / chunk_size)),
//         )?)
//     }
//
//     fn pos(&mut self) -> io::Result<u64> {
//         if self.reader.is_none() {
//             return Ok(self.chunk_index * self.chunk_size);
//         }
//         Ok(self.chunk_index * self.chunk_size + self.reader.as_mut().unwrap().stream_position()?)
//     }
// }
//
// impl Read for ChunkedFileCryptoReader {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         if buf.is_empty() {
//             return Ok(0);
//         }
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
//         if self.reader.is_none() {
//             // create the reader
//             let current_pos = self.pos()?;
//             self.reader = Self::try_create_reader(
//                 current_pos,
//                 self.chunk_size,
//                 self.file_dir.to_owned(),
//                 self.cipher,
//                 self.key.clone(),
//                 &self.locks,
//             )?;
//         }
//         if self.reader.is_none() {
//             // we don't have any more chunks
//             return Ok(0);
//         }
//
//         debug!(len = buf.len().to_formatted_string(&Locale::en), "reading");
//         let mut len = self.reader.as_mut().unwrap().read(buf)?;
//
//         if len == 0 {
//             debug!("switching to next chunk");
//             self.chunk_index += 1;
//             self.reader = Self::try_create_reader(
//                 self.chunk_index * self.chunk_size,
//                 self.chunk_size,
//                 self.file_dir.to_owned(),
//                 self.cipher,
//                 self.key.clone(),
//                 &self.locks,
//             )?;
//             if let Some(reader) = &mut self.reader {
//                 debug!(len = len.to_formatted_string(&Locale::en), "reading");
//                 len = reader.read(buf)?;
//             }
//         }
//
//         Ok(len)
//     }
// }
//
// impl Seek for ChunkedFileCryptoReader {
//     fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
//         let new_pos = match pos {
//             SeekFrom::Start(pos) => pos,
//             SeekFrom::End(_) => {
//                 return Err(io::Error::new(
//                     io::ErrorKind::InvalidInput,
//                     "can't seek from end",
//                 ))
//             }
//             SeekFrom::Current(pos) => {
//                 let new_pos = self.pos()? as i64 + pos;
//                 if new_pos < 0 {
//                     return Err(io::Error::new(
//                         io::ErrorKind::InvalidInput,
//                         "can't seek before start",
//                     ));
//                 }
//                 new_pos as u64
//             }
//         };
//         if self.pos()? != new_pos {
//             debug!(
//                 pos = self.pos()?.to_formatted_string(&Locale::en),
//                 new_pos = new_pos.to_formatted_string(&Locale::en),
//                 "seeking"
//             );
//
//             // obtain a read lock to whole file, we ue a special value to indicate this.
//             // this helps if someone is truncating the file while we are using it, they will use a write lock
//             let mut _lock = None;
//             let _guard_all = {
//                 if let Some(locks) = &self.locks {
//                     _lock = Some(locks.get(WHOLE_FILE_CHUNK_INDEX));
//                     Some(_lock.as_ref().unwrap().read())
//                 } else {
//                     None
//                 }
//             };
//
//             if self.reader.is_none() {
//                 // create the reader
//                 let current_pos = self.pos()?;
//                 self.reader = Some(Self::create_reader(
//                     current_pos,
//                     self.chunk_size,
//                     self.file_dir.to_owned(),
//                     self.cipher,
//                     self.key.clone(),
//                     &self.locks,
//                 )?);
//             }
//             let pos = self.pos()?;
//             if self.chunk_index == new_pos / self.chunk_size {
//                 // seek in current chunk as much as we can
//                 let reader = self.reader.as_mut().unwrap();
//                 let new_pos_in_chunk = new_pos % self.chunk_size;
//                 reader.seek(SeekFrom::Start(new_pos_in_chunk))?;
//             } else {
//                 // we need to switch to another chunk
//                 debug!("switching to another chunk");
//                 self.reader = Self::try_create_reader(
//                     new_pos,
//                     self.chunk_size,
//                     self.file_dir.to_owned(),
//                     self.cipher,
//                     self.key.clone(),
//                     &self.locks,
//                 )?;
//                 if self.reader.is_none() {
//                     return Ok(pos);
//                 }
//                 let reader = self.reader.as_mut().unwrap();
//                 // seek in chunk
//                 let new_pos_in_chunk = new_pos % self.chunk_size;
//                 debug!(
//                     new_pos_in_chunk = new_pos_in_chunk.to_formatted_string(&Locale::en),
//                     "seeking in new chunk"
//                 );
//                 reader.seek(SeekFrom::Start(new_pos_in_chunk))?;
//                 self.chunk_index = new_pos / self.chunk_size;
//             }
//         }
//         Ok(self.pos()?)
//     }
// }
//
// impl CryptoReader for ChunkedFileCryptoReader {}

mod bench {
    use std::io;
    use std::io::Seek;
    use std::io::Write;
    use std::sync::Arc;
    use test::{black_box, Bencher};

    use rand::RngCore;
    use secrecy::SecretVec;

    use crate::crypto;
    use crate::crypto::writer::CryptoWriter;
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
        crypto::create_rng().fill_bytes(&mut cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        writer.flush().unwrap();
        let file = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut file = file.try_clone().unwrap();
                file.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(file, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            })
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
        crypto::create_rng().fill_bytes(&mut cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        writer.flush().unwrap();
        let file = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut file = file.try_clone().unwrap();
                file.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(file, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            })
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
        crypto::create_rng().fill_bytes(&mut cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        writer.flush().unwrap();
        let cursor_write = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut cursor = cursor_write.clone();
                cursor.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(cursor, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            })
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
        crypto::create_rng().fill_bytes(&mut cursor_random.get_mut());
        cursor_random.seek(io::SeekFrom::Start(0)).unwrap();
        io::copy(&mut cursor_random, &mut writer).unwrap();
        writer.flush().unwrap();
        let cursor_write = writer.finish().unwrap();

        b.iter(|| {
            black_box({
                let mut cursor = cursor_write.clone();
                cursor.seek(io::SeekFrom::Start(0)).unwrap();
                let mut reader = crypto::create_reader(cursor, cipher, key.clone());
                io::copy(&mut reader, &mut io::sink()).unwrap();
            })
        });
    }
}
