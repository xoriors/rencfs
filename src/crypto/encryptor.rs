use std::io;
use std::io::Write;
use openssl::symm::Cipher;
use crate::crypto;

pub trait Encryptor<W: Write>: Write + Sync + Send {
    fn finish(&mut self) -> io::Result<W>;
}

pub struct EncryptorCryptostream<W: Write> {
    inner: Option<cryptostream::write::Encryptor<W>>,
}

impl<W: Write> EncryptorCryptostream<W> {
    pub fn new(writer: W, cipher: Cipher, key: &[u8], iv: &[u8]) -> crypto::Result<Self> {
        Ok(Self {
            inner: Some(cryptostream::write::Encryptor::new(writer, cipher, key, iv)?),
        })
    }
}

impl<W: Write> Write for EncryptorCryptostream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.as_mut().unwrap().flush()
    }
}

impl<W: Write + Send + Sync> Encryptor<W> for EncryptorCryptostream<W> {
    fn finish(&mut self) -> io::Result<W> {
        Ok(self.inner.take().unwrap().finish()?)
    }
}
