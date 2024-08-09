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
pub(crate) const BLOCK_SIZE: usize = 16 * 1024; // 16 KB block size

/// Writes encrypted content to the wrapped Writer.
#[allow(clippy::module_name_repetitions)]
pub trait CryptoWrite<W: Write + Send + Sync>: Write + Send + Sync {
    /// You must call this after the last write to make sure we write the last block. This handles the flush also.
    #[allow(clippy::missing_errors_doc)]
    fn finish(&mut self) -> io::Result<W>;
}

/// ring
#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWrite<W: Write> {
    out: Option<W>,
    sealing_key: SealingKey<RandomNonceSequenceWrapper>,
    buf: BufMut,
    nonce_sequence: Arc<Mutex<RandomNonceSequence>>,
    ciphertext_block_size: usize,
    plaintext_block_size: usize,
    block_index: u64,
}

impl<W: Write> RingCryptoWrite<W> {
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(writer: W, algorithm: &'static Algorithm, key: &SecretVec<u8>) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = Arc::new(Mutex::new(RandomNonceSequence::default()));
        let wrapping_nonce_sequence = RandomNonceSequenceWrapper::new(nonce_sequence.clone());
        let sealing_key = SealingKey::new(unbound_key, wrapping_nonce_sequence);
        let buf = BufMut::new(vec![0; BLOCK_SIZE]);
        Self {
            out: Some(writer),
            sealing_key,
            buf,
            nonce_sequence,
            ciphertext_block_size: NONCE_LEN + BLOCK_SIZE + algorithm.tag_len(),
            plaintext_block_size: BLOCK_SIZE,
            block_index: 0,
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
        self.out.as_mut().unwrap().write_all(nonce)?;
        self.out.as_mut().unwrap().write_all(data)?;
        self.buf.clear();
        self.out.as_mut().unwrap().write_all(tag.as_ref())?;
        self.out.as_mut().unwrap().flush()?;
        self.block_index += 1;
        Ok(())
    }
}

impl<W: Write> Write for RingCryptoWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "write called on already finished writer",
            ));
        }
        if self.buf.is_dirty() && self.buf.remaining() == 0 {
            self.flush()?;
        }
        let len = self.buf.write(buf)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "flush called on already finished writer",
            ));
        }
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

impl<W: Write + Send + Sync> CryptoWrite<W> for RingCryptoWrite<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "finish called on already finished writer",
            ));
        }
        if self.buf.is_dirty() {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        let mut out = self.out.take().unwrap();
        out.flush()?;
        Ok(out)
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

/// Write with Seek
pub trait CryptoWriteSeek<W: Write + Seek + Send + Sync>: CryptoWrite<W> + Seek {}

pub struct RingCryptoWriteSeek<W: Write + Seek + Read> {
    inner: RingCryptoWrite<W>,
    opening_key: OpeningKey<ExistingNonceSequence>,
    last_nonce: Arc<Mutex<Option<Vec<u8>>>>,
    decrypt_buf: BufMut,
}

impl<W: Write + Seek + Read> RingCryptoWriteSeek<W> {
    pub(crate) fn new(writer: W, algorithm: &'static Algorithm, key: &SecretVec<u8>) -> Self {
        let last_nonce = Arc::new(Mutex::new(None));
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).unwrap();
        let nonce_sequence = ExistingNonceSequence::new(last_nonce.clone());
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        let ciphertext_block_size = NONCE_LEN + BLOCK_SIZE + algorithm.tag_len();
        let decrypt_buf = BufMut::new(vec![0; ciphertext_block_size]);
        Self {
            inner: RingCryptoWrite::new(writer, algorithm, key),
            opening_key,
            last_nonce,
            decrypt_buf,
        }
    }

    const fn pos(&self) -> u64 {
        self.inner.block_index * self.inner.plaintext_block_size as u64
            + self.inner.buf.pos_write() as u64
    }

    fn decrypt_block(&mut self) -> io::Result<bool> {
        let old_block_index = self.inner.block_index;
        decrypt_block!(
            self.inner.block_index,
            self.decrypt_buf,
            self.inner.out.as_mut().unwrap(),
            self.last_nonce,
            self.opening_key
        );
        if old_block_index == self.inner.block_index {
            // no decryption happened
            Ok(false)
        } else {
            // a decryption happened
            self.inner.buf.clear();
            // bring back block index to current block, it's incremented by decrypt_block if it can decrypt something
            self.inner.block_index -= 1;
            // bring back file pos also so the next writing will write to the same block
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(
                self.inner.block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            // copy plaintext
            self.inner
                .buf
                .seek_available(SeekFrom::Start(self.decrypt_buf.available_read() as u64))?;
            self.decrypt_buf
                .as_ref_read_available()
                .copy_to_slice(&mut self.inner.buf.as_mut()[..self.decrypt_buf.available_read()]);
            Ok(true)
        }
    }

    fn get_plaintext_len(&mut self) -> io::Result<u64> {
        let ciphertext_len = self.inner.out.as_mut().unwrap().stream_len()?;
        if ciphertext_len == 0 && self.inner.buf.available() == 0 {
            return Ok(0);
        }
        let stream_last_block_index = self.inner.out.as_mut().unwrap().stream_len()?
            / self.inner.ciphertext_block_size as u64;
        let plaintext_len = if self.inner.block_index == stream_last_block_index
            && self.inner.buf.is_dirty()
        {
            // we are at the last block, we consider what we have in buffer,
            // as we might have additional content that is not written yet
            self.inner.block_index * self.inner.plaintext_block_size as u64
                + self.inner.buf.available() as u64
        } else {
            ciphertext_len
                - ((ciphertext_len / self.inner.ciphertext_block_size as u64) + 1)
                    * (self.inner.ciphertext_block_size - self.inner.plaintext_block_size) as u64
        };
        Ok(plaintext_len)
    }
}

impl<W: Write + Seek + Read> Seek for RingCryptoWriteSeek<W> {
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
        let current_block_index = self.pos() / self.inner.plaintext_block_size as u64;
        let new_block_index = new_pos / self.inner.plaintext_block_size as u64;
        if current_block_index == new_block_index {
            if self.pos() == 0 && self.inner.buf.available() == 0 {
                // first write since we opened the writer, try to load the first block
                self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(0))?;
                self.inner.block_index = 0;
                self.decrypt_block()?;
            }
            let at_full_block_end = self.pos() % self.inner.plaintext_block_size as u64 == 0
                && self.inner.buf.pos_write() == self.inner.buf.available();
            if self.inner.buf.available() == 0
                // this checks if we are at the end of the current block,
                // which is the start boundary of next block
                // in that case we need to seek inside the next block
                || at_full_block_end
            {
                // write current block
                if self.inner.buf.is_dirty() {
                    self.inner.encrypt_and_write()?;
                }
                // decrypt the next block
                self.decrypt_block()?;
            }
            // seek inside the block as much as we can
            let desired_offset = new_pos % self.inner.plaintext_block_size as u64;
            self.inner.buf.seek_write(SeekFrom::Start(
                desired_offset.min(self.inner.buf.available() as u64),
            ))?;
        } else {
            // we need to seek to a new block

            // write current block
            if self.inner.buf.is_dirty() {
                self.inner.encrypt_and_write()?;
            }

            // seek to new block, or until the last block in stream
            let last_block_index = self.inner.out.as_mut().unwrap().stream_len()?
                / self.inner.ciphertext_block_size as u64;
            let target_block_index = new_block_index.min(last_block_index);
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(
                target_block_index * self.inner.ciphertext_block_size as u64,
            ))?;
            // try to decrypt target block
            self.inner.block_index = target_block_index;
            self.decrypt_block()?;
            if self.inner.block_index == new_block_index {
                // seek inside new block as much as we can
                let desired_offset = new_pos % self.inner.plaintext_block_size as u64;
                self.inner.buf.seek_write(SeekFrom::Start(
                    desired_offset.min(self.inner.buf.available() as u64),
                ))?;
            } else {
                // we don't have this block, seek as much in target block
                self.inner
                    .buf
                    .seek_write(SeekFrom::Start(self.inner.buf.available() as u64))?;
            }
        }
        // if we couldn't seek until new pos, write zeros until new position
        if self.pos() < new_pos {
            let len = new_pos - self.pos();
            stream_util::fill_zeros(&mut self.inner, len)?;
        }
        Ok(self.pos())
    }
}

impl<W: Write + Seek + Read + Send + Sync> Write for RingCryptoWriteSeek<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos() == 0 && self.inner.buf.available() == 0 {
            // first write since we opened the writer, try to load the first block
            self.inner.out.as_mut().unwrap().seek(SeekFrom::Start(0))?;
            self.inner.block_index = 0;
            self.decrypt_block()?;
        } else if self.inner.buf.is_dirty() && self.inner.buf.remaining() == 0 {
            self.flush()?;
            // try to decrypt the next block if we have any
            let block_index = self.pos() / self.inner.plaintext_block_size as u64;
            if self.inner.out.as_mut().unwrap().stream_len()?
                > block_index * self.inner.ciphertext_block_size as u64
            {
                self.decrypt_block()?;
            }
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek + Read + Send + Sync> CryptoWrite<W> for RingCryptoWriteSeek<W> {
    fn finish(&mut self) -> io::Result<W> {
        self.inner.finish()
    }
}

impl<W: Write + Seek + Read + Send + Sync> CryptoWriteSeek<W> for RingCryptoWriteSeek<W> {}
