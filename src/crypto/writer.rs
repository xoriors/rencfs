use std::io;
use std::io::{BufWriter, Write};
use std::sync::Arc;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use ring::aead::{Aad, Algorithm, BoundKey, Nonce, NONCE_LEN, NonceSequence, SealingKey, UnboundKey};
use ring::error::Unspecified;
use secrecy::{ExposeSecret, SecretVec};
use tracing::{error, instrument};

use crate::crypto::buf_mut::BufMut;

pub trait CryptoWriter<W: Write>: Write + Sync + Send {
    fn finish(&mut self) -> io::Result<Option<W>>;
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
#[cfg(test)]
pub(crate) const BUF_SIZE: usize = 256 * 1024;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
pub(crate) const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

pub struct RingCryptoWriter<W: Write> {
    out: Option<BufWriter<W>>,
    sealing_key: SealingKey<RandomNonceSequence>,
    buf: BufMut,
}

impl<W: Write> RingCryptoWriter<W> {
    pub fn new<'a: 'static>(w: W, algorithm: &'a Algorithm, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> Self {
        // todo: param for start nonce sequence
        let unbound_key = UnboundKey::new(&algorithm, key.expose_secret()).unwrap();
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

impl<W: Write> Write for RingCryptoWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buf.remaining() == 0 {
            self.flush()?;
        }
        let len = self.buf.write(buf)?;
        Ok(len)
    }

    #[instrument(name = "RingEncryptor::flush", skip(self))]
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

impl<W: Write> RingCryptoWriter<W> {
    fn encrypt_and_write(&mut self) -> io::Result<()> {
        let mut data = self.buf.as_mut();
        let tag = self.sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut data).map_err(|err| {
            error!("error sealing in place: {}", err);
            io::Error::from(io::ErrorKind::Other)
        })?;
        self.out.as_mut().unwrap().write_all(&data)?;
        self.buf.clear();
        self.out.as_mut().unwrap().write_all(tag.as_ref())?;
        self.out.as_mut().unwrap().flush()?;
        Ok(())
    }
}

impl<W: Write + Send + Sync> CryptoWriter<W> for RingCryptoWriter<W> {
    fn finish(&mut self) -> io::Result<Option<W>> {
        if self.buf.available() > 0 {
            // encrypt and write last block, use as many bytes we have
            self.encrypt_and_write()?;
        }
        Ok(Some(self.out.take().unwrap().into_inner()?))
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
            // seed: 1,
        }
    }
}

impl NonceSequence for RandomNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.rng.next_u64().to_le_bytes();
        // let bytes = self.seed.to_le_bytes();
        nonce_bytes[4..].copy_from_slice(&bytes);
        // println!("nonce_bytes = {}", hex::encode(&nonce_bytes));
        // self.seed += 1;

        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}