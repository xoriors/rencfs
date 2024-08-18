use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

use bytes::Buf;
use rand_chacha::rand_core::RngCore;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tracing::error;

use crate::crypto::buf_mut::BufMut;
use crate::crypto::read::ExistingNonceSequence;
use crate::{crypto, decrypt_block, stream_util};

mod bench;
mod test;

#[cfg(test)]
pub(crate) const BLOCK_SIZE: usize = 100; // round value easier for debugging
#[cfg(not(test))]
pub(crate) const BLOCK_SIZE: usize = 256 * 1024; // 256 KB block size

pub trait WriteSeekRead: Write + Seek + Read {}

impl<T: Write + Seek + Read> WriteSeekRead for T {}

trait InnerWriter: Write {
    fn as_write(&mut self) -> Option<&mut dyn Write>;
    fn as_write_seek_read(&mut self) -> Option<&mut dyn WriteSeekRead>;
}

impl<T: Write + Seek + Read> InnerWriter for T {
    fn as_write(&mut self) -> Option<&mut dyn Write> {
        Some(self)
    }
    fn as_write_seek_read(&mut self) -> Option<&mut dyn WriteSeekRead> {
        Some(self)
    }
}

/// Writes encrypted content to the wrapped Writer.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoWrite<W: Send + Sync>: Write + Send + Sync {
    /// You must call this after the last write to make sure we write the last block. This handles the flush also.
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<W>;
}

/// Write with Seek
pub trait CryptoWriteSeek<W: InnerWriter + Send + Sync>: CryptoWrite<W> + Seek {}

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWrite<W: InnerWriter + Send + Sync> {
    writer: Option<W>,
    sealing_key: SealingKey<RandomNonceSequenceWrapper>,
    buf: BufMut,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
    opening_key: Option<OpeningKey<ExistingNonceSequence>>,
    last_nonce: Option<Arc<Mutex<Option<Vec<u8>>>>>,
    decrypt_buf: Option<BufMut>,
}

impl<W: InnerWriter + Send + Sync> RingCryptoWrite<W> {
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(mut writer: W, algorithm: &'static Algorithm, key: &SecretVec<u8>) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        let sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        let buf = BufMut::new(vec![0; BLOCK_SIZE]);

        let (last_nonce, opening_key, decrypt_buf) = if let Some(_) = writer.as_write_seek_read() {
            let last_nonce = Arc::new(Mutex::new(None));
            let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
            let nonce_sequence2 = ExistingNonceSequence::new(last_nonce.clone());
            let opening_key = OpeningKey::new(unbound_key, nonce_sequence2);
            let ciphertext_block_size = NONCE_LEN + BLOCK_SIZE + algorithm.tag_len();
            let decrypt_buf = BufMut::new(vec![0; ciphertext_block_size]);

            (Some(last_nonce), Some(opening_key), Some(decrypt_buf))
        } else {
            (None, None, None)
        };
        Self {
            writer: Some(writer),
            sealing_key,
            buf,
            nonce_sequence,
            ciphertext_block_size: NONCE_LEN + BLOCK_SIZE + algorithm.tag_len(),
            plaintext_block_size: BLOCK_SIZE,
            block_index: 0,
            opening_key,
            last_nonce,
            decrypt_buf,
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
        let nonce = &nonce_sequence.last_nonce;
        let writer = self
            .writer
            .as_mut()
            .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
        writer.write_all(nonce)?;
        writer.write_all(data)?;
        self.buf.clear();
        writer.write_all(tag.as_ref())?;
        writer.flush()?;
        self.block_index += 1;
        Ok(())
    }

    const fn pos(&self) -> u64 {
        self.block_index * self.plaintext_block_size as u64 + self.buf.pos_write() as u64
    }

    fn decrypt_block(&mut self) -> io::Result<bool> {
        let old_block_index = self.block_index;
        let writer = self
            .writer
            .as_mut()
            .unwrap()
            .as_write_seek_read()
            .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
        decrypt_block!(
            self.block_index,
            self.decrypt_buf.as_mut().unwrap(),
            writer,
            self.last_nonce.as_ref().unwrap(),
            self.opening_key.as_mut().unwrap()
        );
        if old_block_index == self.block_index {
            // no decryption happened
            Ok(false)
        } else {
            // a decryption happened
            self.buf.clear();
            // bring back block index to current block, it's incremented by decrypt_block if it can decrypt something
            self.block_index -= 1;
            // bring back file pos also so the next writing will write to the same block
            let writer = self
                .writer
                .as_mut()
                .unwrap()
                .as_write_seek_read()
                .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
            writer.seek(SeekFrom::Start(
                self.block_index * self.ciphertext_block_size as u64,
            ))?;
            // copy plaintext
            self.buf.seek_available(SeekFrom::Start(
                self.decrypt_buf.as_ref().unwrap().available_read() as u64,
            ))?;
            self.decrypt_buf
                .as_ref()
                .unwrap()
                .as_ref_read_available()
                .copy_to_slice(
                    &mut self.buf.as_mut()[..self.decrypt_buf.as_ref().unwrap().available_read()],
                );
            Ok(true)
        }
    }
}

impl<W: InnerWriter + Send + Sync> Write for RingCryptoWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos() == 0 && self.buf.available() == 0 {
            // first write since we opened the writer, try to load the first block
            let writer = self
                .writer
                .as_mut()
                .unwrap()
                .as_write_seek_read()
                .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
            writer.seek(SeekFrom::Start(0))?;
            self.block_index = 0;
            self.decrypt_block()?;
        } else if self.buf.is_dirty() && self.buf.remaining() == 0 {
            self.flush()?;
            // try to decrypt the next block if we have any
            let block_index = self.pos() / self.plaintext_block_size as u64;
            let writer = self
                .writer
                .as_mut()
                .unwrap()
                .as_write_seek_read()
                .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
            let stream_len = writer.stream_len()?;
            if stream_len > block_index * self.ciphertext_block_size as u64 {
                self.decrypt_block()?;
            }
        }
        if self.buf.is_dirty() && self.buf.remaining() == 0 {
            self.flush()?;
        }
        let len = self.buf.write(buf)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
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

impl<W: Send + Sync> CryptoWrite<W> for RingCryptoWrite<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.buf.is_dirty() {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        Ok(self.writer.take().unwrap())
    }
}

struct RandomNonceSequence {
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
    last_nonce: Vec<u8>,
}

impl Default for RandomNonceSequence {
    fn default() -> Self {
        Self {
            rng: Mutex::new(Box::new(crypto::create_rng())),
            last_nonce: vec![0; NONCE_LEN],
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.rng.lock().unwrap().fill_bytes(&mut self.last_nonce);
        Nonce::try_assume_unique_for_key(&self.last_nonce)
    }
}

struct RandomNonceSequenceWrapper {
    inner: Arc<Mutex<RandomNonceSequence>>,
}

impl RandomNonceSequenceWrapper {
    pub const fn new(inner: Arc<Mutex<RandomNonceSequence>>) -> Self {
        Self { inner }
    }
}

impl NonceSequence for RandomNonceSequenceWrapper {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.inner.lock().unwrap().advance()
    }
}

impl<W: InnerWriter + Send + Sync> RingCryptoWrite<W> {
    fn get_plaintext_len(&mut self) -> io::Result<u64> {
        let writer = self
            .writer
            .as_mut()
            .unwrap()
            .as_write_seek_read()
            .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
        let ciphertext_len = writer.stream_len()?;
        if ciphertext_len == 0 && self.buf.available() == 0 {
            return Ok(0);
        }
        let stream_last_block_index = ciphertext_len / self.ciphertext_block_size as u64;
        let plaintext_len = if self.block_index == stream_last_block_index && self.buf.is_dirty() {
            // we are at the last block, we consider what we have in buffer,
            // as we might have additional content that is not written yet
            self.block_index * self.plaintext_block_size as u64 + self.buf.available() as u64
        } else {
            ciphertext_len
                - ((ciphertext_len / self.ciphertext_block_size as u64) + 1)
                    * (self.ciphertext_block_size - self.plaintext_block_size) as u64
        };
        Ok(plaintext_len)
    }
}

impl<W: InnerWriter + Send + Sync> Seek for RingCryptoWrite<W> {
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
        let current_block_index = self.pos() / self.plaintext_block_size as u64;
        let new_block_index = new_pos / self.plaintext_block_size as u64;
        if current_block_index == new_block_index {
            if self.pos() == 0 && self.buf.available() == 0 {
                // first write since we opened the writer, try to load the first block
                let writer = self
                    .writer
                    .as_mut()
                    .unwrap()
                    .as_write_seek_read()
                    .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
                writer.seek(SeekFrom::Start(0))?;
                self.block_index = 0;
                self.decrypt_block()?;
            }
            let at_full_block_end = self.pos() % self.plaintext_block_size as u64 == 0
                && self.buf.pos_write() == self.buf.available();
            if self.buf.available() == 0
                // this checks if we are at the end of the current block,
                // which is the start boundary of next block
                // in that case we need to seek inside the next block
                || at_full_block_end
            {
                // write current block
                if self.buf.is_dirty() {
                    self.encrypt_and_write()?;
                }
                // decrypt the next block
                self.decrypt_block()?;
            }
            // seek inside the block as much as we can
            let desired_offset = new_pos % self.plaintext_block_size as u64;
            self.buf.seek_write(SeekFrom::Start(
                desired_offset.min(self.buf.available() as u64),
            ))?;
        } else {
            // we need to seek to a new block

            // write current block
            if self.buf.is_dirty() {
                self.encrypt_and_write()?;
            }
            // seek to new block, or until the last block in stream
            let writer = self
                .writer
                .as_mut()
                .unwrap()
                .as_write_seek_read()
                .ok_or(io::Error::new(io::ErrorKind::NotConnected, "no writer"))?;
            let last_block_index = writer.stream_len()? / self.ciphertext_block_size as u64;
            let target_block_index = new_block_index.min(last_block_index);
            writer.seek(SeekFrom::Start(
                target_block_index * self.ciphertext_block_size as u64,
            ))?;
            // try to decrypt target block
            self.block_index = target_block_index;
            self.decrypt_block()?;
            if self.block_index == new_block_index {
                // seek inside new block as much as we can
                let desired_offset = new_pos % self.plaintext_block_size as u64;
                self.buf.seek_write(SeekFrom::Start(
                    desired_offset.min(self.buf.available() as u64),
                ))?;
            } else {
                // we don't have this block, seek as much in target block
                self.buf
                    .seek_write(SeekFrom::Start(self.buf.available() as u64))?;
            }
        }
        // if we couldn't seek until new pos, write zeros until new position
        if self.pos() < new_pos {
            let len = new_pos - self.pos();
            stream_util::fill_zeros(self, len)?;
        }
        Ok(self.pos())
    }
}

impl<W: InnerWriter + Send + Sync> CryptoWriteSeek<W> for RingCryptoWrite<W> {}
