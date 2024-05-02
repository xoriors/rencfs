use std::io::Read;

use openssl::symm::Cipher;

use crate::crypto;

pub trait Decryptor<R: Read>: Read + Send + Sync {
    fn finish(&mut self) -> R;
}

pub struct CryptostreamDecryptor<R: Read> {
    inner: Option<cryptostream::read::Decryptor<R>>,
}

impl<R: Read> CryptostreamDecryptor<R> {
    pub fn new(reader: R, cipher: Cipher, key: &[u8], iv: &[u8]) -> crypto::Result<Self> {
        Ok(Self {
            inner: Some(cryptostream::read::Decryptor::new(reader, cipher, key, iv)?),
        })
    }
}

impl<R: Read> Read for CryptostreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.as_mut().unwrap().read(buf)
    }
}

impl<R: Read + Sync + Send> Decryptor<R> for CryptostreamDecryptor<R> {
    fn finish(&mut self) -> R {
        self.inner.take().unwrap().finish()
    }
}

pub struct AesStreamDecryptor<R: Read> {
    inner: Option<cryptostream::read::Decryptor<R>>,
}
