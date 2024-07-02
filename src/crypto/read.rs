use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, NONCE_LEN,
};
use ring::error;
use secrecy::{ExposeSecret, SecretVec};
use tracing::{error, instrument, warn};

use crate::crypto::buf_mut::BufMut;
use crate::crypto::write::BLOCK_SIZE;
use crate::stream_util;

mod bench;
mod test;

/// Reads encrypted content from the wrapped Reader.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoRead<R: Read + Send + Sync>: Read + Send + Sync {
    #[allow(clippy::wrong_self_convention)]
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
    pub fn new(reader: R, algorithm: &'static Algorithm, key: &SecretVec<u8>) -> Self {
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
    pub const fn new(last_nonce: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
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

/// Read with Seek

pub trait CryptoReadSeek<R: Read + Seek + Send + Sync>:
    CryptoRead<R> + Read + Seek + Send + Sync
{
}

impl<R: Read + Seek> RingCryptoRead<R> {
    pub fn new_seek(reader: R, algorithm: &'static Algorithm, key: &SecretVec<u8>) -> Self {
        Self::new(reader, algorithm, key)
    }

    const fn pos(&self) -> u64 {
        self.block_index.saturating_sub(1) * self.plaintext_block_size as u64
            + self.buf.pos_read().saturating_sub(NONCE_LEN) as u64
    }

    fn get_plaintext_len(&mut self) -> io::Result<u64> {
        let ciphertext_len = self.input.as_mut().unwrap().stream_len()?;
        if ciphertext_len == 0 {
            return Ok(0);
        }
        let plaintext_len = ciphertext_len
            - ((ciphertext_len / self.ciphertext_block_size as u64) + 1)
                * (self.ciphertext_block_size - self.plaintext_block_size) as u64;
        Ok(plaintext_len)
    }
}

impl<R: Read + Seek> Seek for RingCryptoRead<R> {
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
        let block_index = self.pos() / self.plaintext_block_size as u64;
        let new_block_index = new_pos / self.plaintext_block_size as u64;
        if block_index == new_block_index {
            let at_full_block_end = self.pos() % self.plaintext_block_size as u64 == 0
                && self.buf.available_read() == 0;
            if self.buf.available() > 0
                // this make sure we are not at the end of the current block, which is the start boundary of next block
                // in that case we need to seek inside the next block
                && !at_full_block_end
            {
                // seek inside current block
                self.buf.seek_read(SeekFrom::Start(
                    NONCE_LEN as u64 + new_pos % self.plaintext_block_size as u64,
                ))?;
            } else {
                // we need to read a new block and seek inside that block
                let plaintext_block_size = self.plaintext_block_size;
                stream_util::seek_forward(self, new_pos % plaintext_block_size as u64, true)?;
            }
        } else {
            // change block
            self.input.as_mut().unwrap().seek(SeekFrom::Start(
                new_block_index * self.ciphertext_block_size as u64,
            ))?;
            self.buf.clear();
            self.block_index = new_block_index;
            if new_pos % self.plaintext_block_size as u64 == 0 {
                // in case we need to seek at the start of the new block, we need to decrypt here, because we altered
                // the block_index but the seek seek_forward from below will not decrypt anything
                // as the offset in new block is 0. In that case the po()
                // method is affected as it will use the wrong block_index value
                decrypt_block!(
                    self.block_index,
                    self.buf,
                    self.input.as_mut().unwrap(),
                    self.last_nonce,
                    self.opening_key
                );
            }
            // seek inside new block
            let plaintext_block_size = self.plaintext_block_size;
            stream_util::seek_forward(self, new_pos % plaintext_block_size as u64, true)?;
        }
        Ok(self.pos())
    }
}

impl<R: Read + Seek + Send + Sync> CryptoReadSeek<R> for RingCryptoRead<R> {}
