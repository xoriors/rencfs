use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use num_format::{Locale, ToFormattedString};
use ring::aead::{Aad, Algorithm, BoundKey, OpeningKey, UnboundKey};
use secrecy::{ExposeSecret, SecretVec};
use tracing::{debug, error, info, instrument, warn};

use crate::crypto::buf_mut::BufMut;
use crate::crypto::writer::{BUF_SIZE, RandomNonceSequence};
use crate::stream_util;

pub trait CryptoReader<R: Read + Seek>: Read + Seek + Send + Sync {
    fn finish(&mut self) -> Option<R>;
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

pub struct RingCryptoReader<R: Read + Seek> {
    input: Option<R>,
    opening_key: OpeningKey<RandomNonceSequence>,
    buf: BufMut,
    pos: u64,
    algorithm: &'static Algorithm,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
}

impl<R: Read + Seek> RingCryptoReader<R> {
    pub fn new(r: R, algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> Self {
        let opening_key = Self::create_opening_key(algorithm, key.clone(), nonce_seed);
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

    fn create_opening_key(algorithm: &'static Algorithm, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> OpeningKey<RandomNonceSequence> {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = RandomNonceSequence::new(nonce_seed);
        OpeningKey::new(unbound_key, nonce_sequence)
    }

    fn seek_from_start(&mut self, offset: u64) -> io::Result<u64> {
        if self.pos != offset {
            debug!("seeking to offset {} from {}", offset.to_formatted_string(&Locale::en), self.pos.to_formatted_string(&Locale::en));
            // in order to seek we need to read the bytes from current position until the offset
            if self.pos > offset {
                // if we need an offset before the current position, we can't seek back, we need
                // to read from the beginning until the desired offset
                debug!("seeking back, recreating decryptor");
                self.opening_key = Self::create_opening_key(self.algorithm, self.key.clone(), self.nonce_seed);
                self.buf.clear();
                self.pos = 0;
                self.input.as_mut().unwrap().seek(SeekFrom::Start(0))?;
            }
            debug!(pos = self.pos.to_formatted_string(&Locale::en), offset = offset.to_formatted_string(&Locale::en), "seeking");
            let len = offset - self.pos;
            stream_util::seek_forward(self, len)?;
        }

        Ok(self.pos)
    }
}

impl<R: Read + Seek> Read for RingCryptoReader<R> {
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
            let buffer = self.buf.as_mut_read();
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
            let mut data = &mut buffer[..len];
            let plaintext = self.opening_key.open_within(Aad::empty(), &mut data, 0..).map_err(|err| {
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
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.seek_from_start(pos),
            SeekFrom::End(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "can't seek from end")),
            SeekFrom::Current(pos) => {
                let new_pos = self.pos as i64 + pos;
                if new_pos < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "can't seek before start"));
                }
                self.seek_from_start(new_pos as u64)
            }
        }
    }
}

impl<R: Read + Seek + Send + Sync> CryptoReader<R> for RingCryptoReader<R> {
    fn finish(&mut self) -> Option<R> {
        Some(self.input.take().unwrap())
    }
}