use std::io;
use std::io::{Read, Seek, SeekFrom};

use ring::aead::{Aad, Algorithm, BoundKey, OpeningKey, UnboundKey};
use tracing::{error, instrument};

use crate::crypto::buf_mut::BufMut;
use crate::crypto::encryptor::{BUF_SIZE, CounterNonceSequence};

pub trait CryptoReader<R: Read>: Read + Seek + Send + Sync {
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

pub struct RingCryptoReader<R: Read> {
    input: Option<R>,
    opening_key: OpeningKey<CounterNonceSequence>,
    buf: BufMut,
}

impl<R: Read> RingCryptoReader<R> {
    pub fn new<'a: 'static>(r: R, algorithm: &'a Algorithm, key: &[u8], nonce_seed: u64) -> Self {
        let unbound_key = UnboundKey::new(algorithm, &key).unwrap();
        let nonce_sequence = CounterNonceSequence::new(nonce_seed);
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        let buf = BufMut::new(vec![0; BUF_SIZE + algorithm.tag_len()]);
        Self {
            input: Some(r),
            opening_key,
            buf,
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
            let res = self.opening_key.open_within(Aad::empty(), &mut data, 0..);
            if res.is_err() {
                error!("error opening in place: {:?}", res);
            }
            let plaintext = res.unwrap();
            plaintext.len()
        };
        self.buf.seek(SeekFrom::Start(pos as u64)).unwrap();
        let len = self.buf.read(buf)?;
        Ok(len)
    }
}

impl<R: Read + Send + Sync> Seek for RingCryptoReader<R> {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        todo!()
    }
}

impl<R: Read + Send + Sync> CryptoReader<R> for RingCryptoReader<R> {
    fn finish(&mut self) -> Option<R> {
        Some(self.input.take().unwrap())
    }
}