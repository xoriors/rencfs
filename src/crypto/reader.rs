use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use num_format::{Locale, ToFormattedString};
use ring::aead::{Aad, Algorithm, BoundKey, OpeningKey, UnboundKey};
use secrecy::{ExposeSecret, SecretVec};
use tracing::{debug, error, instrument, warn};

use crate::crypto::buf_mut::BufMut;
use crate::crypto::writer::{RandomNonceSequence, BUF_SIZE};
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

impl<R: Read + Seek + Send + Sync> Drop for RingCryptoReader<R> {
    fn drop(&mut self) {
        let _ = self.finish();
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
}

impl FileCryptoReader {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
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
        })
    }
}

impl Read for FileCryptoReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
        if self.reader.stream_position()? != pos {
            if self.reader.stream_position()? > pos {
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

impl Drop for FileCryptoReader {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
