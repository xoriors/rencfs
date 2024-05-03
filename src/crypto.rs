use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::io;
use std::path::PathBuf;

use argon2::Argon2;
use hex::FromHexError;
use num_format::{Locale, ToFormattedString};
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tracing::{debug, error, instrument};

use crate::crypto::decryptor::{CryptoReader, RingCryptoReader};
use crate::crypto::encryptor::{CryptoWriter, RingCryptoWriter};
use crate::encryptedfs::FsResult;
use crate::stream_util;

pub mod decryptor;
pub mod encryptor;
pub mod buf_mut;

#[derive(Debug, Clone, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq)]
pub enum Cipher {
    ChaCha20,
    Aes256Gcm,
}

#[derive(Debug, Error)]
pub enum Error {
    // #[error("cryptostream error: {source}")]
    // OpenSsl {
    //     #[from]
    //     source: ErrorStack,
    //     // backtrace: Backtrace,
    // },
    #[error("IO error: {source}")]
    Io {
        #[from]
        source: io::Error,
        // backtrace: Backtrace,
    },
    #[error("hex error: {source}")]
    Hex {
        #[from]
        source: FromHexError,
        // backtrace: Backtrace,
    },
    #[error("crypto error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn create_crypto_writer<W: Write + Send + Sync>(writer: W, cipher: &Cipher, key: &SecretVec<u8>) -> impl CryptoWriter<W> {
    // create_cryptostream_crypto_writer(file, cipher, key)
    create_ring_crypto_writer(writer, cipher, key)
}

fn create_ring_crypto_writer<W: Write + Send + Sync>(writer: W, cipher: &Cipher, key: &SecretVec<u8>) -> RingCryptoWriter<W> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoWriter::new(writer, algorithm, &key.expose_secret())
}

fn create_ring_crypto_reader<R: Read + Send + Sync>(reader: R, cipher: &Cipher, key: &SecretVec<u8>) -> RingCryptoReader<R> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoReader::new(reader, algorithm, &key.expose_secret())
}

// fn _create_cryptostream_crypto_writer(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> impl CryptoWriter<File> {
//     let iv_len = match cipher {
//         Cipher::ChaCha20 => 16,
//         Cipher::Aes256Gcm => 16,
//     };
//     let mut iv: Vec<u8> = vec![0; iv_len];
//     if file.metadata().unwrap().size() == 0 {
//         // generate random IV
//         thread_rng().fill_bytes(&mut iv);
//         file.write_all(&iv).unwrap();
//     } else {
//         // read IV from file
//         file.read_exact(&mut iv).unwrap();
//     }
//     CryptostreamCryptoWriter::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
// }

#[instrument(skip(reader, key))]
pub fn create_crypto_reader<R: Read + Send + Sync>(reader: R, cipher: &Cipher, key: &SecretVec<u8>) -> impl CryptoReader<R> {
    // create_cryptostream_crypto_reader(file, cipher, &key)
    create_ring_crypto_reader(reader, cipher, &key)
}

// fn _create_cryptostream_crypto_reader(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> CryptostreamCryptoReader<File> {
//     let iv_len = match cipher {
//         Cipher::ChaCha20 => 16,
//         Cipher::Aes256Gcm => 16,
//     };
//     let mut iv: Vec<u8> = vec![0; iv_len];
//     if file.metadata().unwrap().size() == 0 {
//         // generate random IV
//         thread_rng().fill_bytes(&mut iv);
//         file.write_all(&iv).map_err(|err| {
//             error!("{err}");
//             err
//         }).unwrap();
//     } else {
//         // read IV from file
//         file.read_exact(&mut iv).map_err(|err| {
//             error!("{err}");
//             err
//         }).unwrap();
//     }
//     CryptostreamCryptoReader::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
// }

pub fn encrypt_string(s: &SecretString, cipher: &Cipher, key: &SecretVec<u8>) -> Result<String> {
    let mut cursor = io::Cursor::new(vec![]);

    let mut writer = create_crypto_writer(cursor, cipher, key);
    writer.write_all(s.expose_secret().as_bytes()).unwrap();
    writer.flush().unwrap();
    cursor = writer.finish()?.unwrap();
    Ok(hex::encode(&cursor.into_inner()))
}

pub fn decrypt_string(s: &str, cipher: &Cipher, key: &SecretVec<u8>) -> Result<SecretString> {
    let vec = hex::decode(s)?;
    let cursor = io::Cursor::new(vec);

    let mut reader = create_crypto_reader(cursor, cipher, key);
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;
    Ok(SecretString::new(decrypted))
}

pub fn decrypt_and_unnormalize_end_file_name(name: &str, cipher: &Cipher, key: &SecretVec<u8>) -> Result<SecretString> {
    // let name = String::from(name).replace("|", "/");
    decrypt_string(&name, cipher, key)
}

#[instrument(skip(password, salt))]
pub fn derive_key(password: &SecretString, cipher: &Cipher, salt: SecretVec<u8>) -> Result<SecretVec<u8>> {
    let mut dk = vec![];
    let key_len = match cipher {
        Cipher::ChaCha20 => 32,
        Cipher::Aes256Gcm => 32,
    };
    dk.resize(key_len, 0);
    Argon2::default().hash_password_into(password.expose_secret().as_bytes(), salt.expose_secret(), &mut dk)
        .map_err(|err| Error::Generic(err.to_string()))?;
    Ok(SecretVec::new(dk))
}

pub fn encrypt_file_name(name: &SecretString, cipher: &Cipher, key: &SecretVec<u8>) -> FsResult<String> {
    if name.expose_secret() != "$." && name.expose_secret() != "$.." {
        let normalized_name = SecretString::new(name.expose_secret().replace("/", " ").replace("\\", " "));
        let encrypted = encrypt_string(&normalized_name, cipher, key)?;
        // encrypted = encrypted.replace("/", "|");
        return Ok(encrypted);
    }
    Ok(name.expose_secret().to_owned())
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_secret(data: &SecretString) -> SecretVec<u8> {
    SecretVec::new(hash(data.expose_secret().as_bytes()).to_vec())
}

/// Copy from `pos` position in file `len` bytes
#[instrument(skip(w, key), fields(pos = pos.to_formatted_string(& Locale::en), len = len.to_formatted_string(& Locale::en)))]
pub fn copy_from_file_exact(w: &mut impl Write, pos: u64, len: u64, cipher: &Cipher, key: &SecretVec<u8>, file: PathBuf) -> io::Result<()> {
    debug!("");
    if len == 0 {
        // no-op
        return Ok(());
    }
    // create a new reader by reading from the beginning of the file
    let mut reader = create_crypto_reader(OpenOptions::new().read(true).open(file)?, cipher, key);
    // move read position to the write position
    stream_util::read_seek_forward_exact(&mut reader, pos)?;

    // copy the rest of the file
    stream_util::copy_exact(&mut reader, w, len)?;
    reader.finish();
    Ok(())
}
