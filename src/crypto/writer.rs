use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

use crate::{crypto, stream_util};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tempfile::NamedTempFile;
use tracing::error;

use crate::crypto::buf_mut::BufMut;
use crate::crypto::Cipher;

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

/// cryptostream

// pub struct CryptostreamCryptoWriter<W: Write> {
//     inner: Option<cryptostream::write::Encryptor<W>>,
// }
//
// impl<W: Write> CryptostreamCryptoWriter<W> {
//     pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> crypto::Result<Self> {
//         Ok(Self {
//             inner: Some(cryptostream::write::Encryptor::new(writer, cipher, key, iv)?),
//         })
//     }
// }
//
// impl<W: Write> Write for CryptostreamCryptoWriter<W> {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         self.inner.as_mut().unwrap().write(buf)
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         self.inner.as_mut().unwrap().flush()
//     }
// }
//
// impl<W: Write + Send + Sync> CryptoWriter<W> for CryptostreamCryptoWriter<W> {
//     fn finish(&mut self) -> io::Result<Option<W>> {
//         Ok(Some(self.inner.take().unwrap().finish()?))
//     }
// }

/// ring

#[allow(clippy::module_name_repetitions)]
pub struct RingCryptoWriter<W: Write + Send + Sync> {
    out: Option<BufWriter<W>>,
    sealing_key: SealingKey<RandomNonceSequence>,
    buf: BufMut,
}

impl<W: Write + Send + Sync> RingCryptoWriter<W> {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(
        w: W,
        algorithm: &'static Algorithm,
        key: &Arc<SecretVec<u8>>,
        nonce_seed: u64,
    ) -> Self {
        let unbound_key = UnboundKey::new(algorithm, key.expose_secret()).expect("unbound key");
        let nonce_sequence = RandomNonceSequence::new(nonce_seed);
        let sealing_key = SealingKey::new(unbound_key, nonce_sequence);
        let buf = BufMut::new(vec![0; BUF_SIZE]);
        Self {
            out: Some(BufWriter::new(w)),
            sealing_key,
            buf,
        }
    }
}

impl<W: Write + Send + Sync> Write for RingCryptoWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buf.remaining() == 0 {
            self.flush()?;
        }
        let len = self.buf.write(buf)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
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
        let data = self.buf.as_mut();
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(Aad::empty(), data)
            .map_err(|err| {
                error!("error sealing in place: {}", err);
                io::Error::from(io::ErrorKind::Other)
            })?;
        let out = self.out.as_mut().unwrap();
        out.write_all(data)?;
        self.buf.clear();
        out.write_all(tag.as_ref())?;
        out.flush()?;
        Ok(())
    }
}

impl<W: Write + Send + Sync> CryptoWriter<W> for RingCryptoWriter<W> {
    fn finish(&mut self) -> io::Result<W> {
        if self.out.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "finish called on already finished writer",
            ));
        }
        if self.buf.available() > 0 {
            // encrypt and write last block, use as many bytes as we have
            self.encrypt_and_write()?;
        }
        Ok(self.out.take().unwrap().into_inner()?)
    }
}

impl<W: Write + Send + Sync> Drop for RingCryptoWriter<W> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

pub(crate) struct RandomNonceSequence {
    rng: ChaCha20Rng,
    // seed: u64,
}

impl RandomNonceSequence {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            // seed,
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let num = self.rng.next_u64();
        // let num = self.seed;
        // self.seed = self.seed + 1;
        let bytes = num.to_le_bytes();
        // let bytes = self.seed.to_le_bytes();
        nonce_bytes[4..].copy_from_slice(&bytes);
        // println!("nonce_bytes = {}", hex::encode(&nonce_bytes));
        // self.seed += 1;

        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// writer with Seek

pub trait CryptoWriterSeek<W: Write>: CryptoWriter<W> + Seek {}

/// file writer

#[allow(clippy::module_name_repetitions)]
pub trait FileCryptoWriterCallback: Send + Sync {
    #[allow(clippy::missing_errors_doc)]
    fn on_file_content_changed(&self, changed_from_pos: u64, last_write_pos: u64)
        -> io::Result<()>;
}

#[allow(clippy::module_name_repetitions)]
pub struct FileCryptoWriter<Callback: FileCryptoWriterCallback> {
    file: PathBuf,
    tmp_dir: PathBuf,
    writer: Box<dyn CryptoWriter<File>>,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    nonce_seed: u64,
    pos: u64,
    tmp_file_path: PathBuf,
    callback: Callback,
}

impl<Callback: FileCryptoWriterCallback> FileCryptoWriter<Callback> {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        file_path: &Path,
        tmp_dir: &Path,
        cipher: Cipher,
        key: Arc<SecretVec<u8>>,
        nonce_seed: u64,
        callback: Callback,
    ) -> io::Result<Self> {
        if !file_path.exists() {
            File::create(file_path)?;
        }
        // start writer in tmp file
        let tmp_path = NamedTempFile::new_in(tmp_dir)?
            .into_temp_path()
            .to_path_buf();
        let tmp_file = File::create(tmp_path.clone())?;
        Ok(Self {
            file: file_path.to_owned(),
            tmp_dir: tmp_dir.to_owned(),
            writer: Box::new(crypto::create_writer(tmp_file, cipher, &key, nonce_seed)),
            cipher,
            key,
            nonce_seed,
            pos: 0,
            tmp_file_path: tmp_path,
            callback,
        })
    }

    fn seek_from_start(&mut self, pos: u64) -> io::Result<u64> {
        if pos == self.pos {
            return Ok(pos);
        }

        if self.pos < pos {
            // seek forward
            let len = pos - self.pos;
            crypto::copy_from_file(
                self.file.clone(),
                self.pos,
                len,
                self.cipher,
                self.key.clone(),
                self.nonce_seed,
                self,
                true,
            )?;
            if self.pos < pos {
                // eof, we write zeros until pos
                stream_util::fill_zeros(self, pos - self.pos)?;
            }
        } else {
            // seek backward
            // write dirty data, recreate writer and copy until pos

            // write dirty data
            self.writer.flush()?;

            // write any remaining data from file
            let cipher = self.cipher;
            crypto::copy_from_file(
                self.file.clone(),
                self.pos,
                u64::MAX,
                cipher,
                self.key.clone(),
                self.nonce_seed,
                self,
                true,
            )?;

            self.writer.finish()?;

            // move tmp file to file
            fs::rename(self.tmp_file_path.clone(), self.file.clone())?;

            // notify back that file content has changed
            self.callback
                .on_file_content_changed(0, self.pos)
                .map_err(|err| {
                    error!("error notifying file content changed: {}", err);
                    err
                })?;

            // recreate writer
            let tmp_path = NamedTempFile::new_in(self.tmp_dir.clone())?
                .into_temp_path()
                .to_path_buf();
            let tmp_file = File::create(tmp_path.clone())?;
            self.writer = Box::new(crypto::create_writer(
                tmp_file,
                cipher,
                &self.key.clone(),
                self.nonce_seed,
            ));
            self.tmp_file_path = tmp_path;
            self.pos = 0;

            // copy until pos
            let len = pos;
            crypto::copy_from_file_exact(
                self.file.clone(),
                self.pos,
                len,
                cipher,
                self.key.clone(),
                self.nonce_seed,
                self,
            )?;
        }

        Ok(self.pos)
    }
}

impl<Callback: FileCryptoWriterCallback> Write for FileCryptoWriter<Callback> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.writer.write(buf)?;
        self.pos += len as u64;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.seek(SeekFrom::Start(0))?; // this will handle the flush and write any dirty data

        Ok(())
    }
}

impl<Callback: FileCryptoWriterCallback> CryptoWriter<File> for FileCryptoWriter<Callback> {
    fn finish(&mut self) -> io::Result<File> {
        self.flush()?;
        {
            self.writer.finish()?;
        }
        if self.tmp_file_path.exists() {
            if let Err(err) = fs::remove_file(&self.tmp_file_path) {
                error!("error removing tmp file: {}", err);
                return Err(io::Error::new(io::ErrorKind::NotFound, err.to_string()));
            }
        }
        File::open(self.file.clone())
    }
}

impl<Callback: FileCryptoWriterCallback> Seek for FileCryptoWriter<Callback> {
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.seek_from_start(pos),
            SeekFrom::End(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "seek from end not supported",
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

impl<Callback: FileCryptoWriterCallback> CryptoWriterSeek<File> for FileCryptoWriter<Callback> {}

impl<Callback: FileCryptoWriterCallback> Drop for FileCryptoWriter<Callback> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
