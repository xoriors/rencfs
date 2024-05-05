use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::sync::Arc;

use argon2::Argon2;
use base64::DecodeError;
use hex::FromHexError;
use num_format::{Locale, ToFormattedString};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tracing::{debug, error, instrument};

use crate::stream_util;
use crate::crypto::reader::{CryptoReader, RingCryptoReader};
use crate::crypto::writer::{CryptoWriter, RingCryptoWriter};
use crate::encryptedfs::FsResult;

pub mod reader;
pub mod writer;
pub mod buf_mut;

#[derive(Debug, Clone, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq)]
pub enum Cipher {
    ChaCha20,
    Aes256Gcm,
}

pub const ENCRYPT_FILENAME_OVERHEAD_CHARS: usize = 4;

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
    #[error("from hex error: {source}")]
    FromHexError {
        #[from]
        source: FromHexError,
        // backtrace: Backtrace,
    },
    #[error("hex decode: {source}")]
    DecodeError {
        #[from]
        source: DecodeError,
        // backtrace: Backtrace,
    },
    #[error("parse int: {source}")]
    ParseIntError {
        #[from]
        source: ParseIntError,
        // backtrace: Backtrace,
    },
    #[error("generic error: {0}")]
    Generic(&'static str),
    #[error("generic error: {0}")]
    GenericString(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn create_writer<W: Write + Send + Sync>(writer: W, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> impl CryptoWriter<W> {
    create_ring_writer(writer, cipher, key, nonce_seed)
}

fn create_ring_writer<W: Write + Send + Sync>(writer: W, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> RingCryptoWriter<W> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoWriter::new(writer, algorithm, key, nonce_seed)
}

fn create_ring_reader<R: Read + Seek + Send + Sync>(reader: R, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> RingCryptoReader<R> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoReader::new(reader, algorithm, key, nonce_seed)
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
pub fn create_reader<R: Read + Seek + Send + Sync>(reader: R, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> impl CryptoReader<R> {
    create_ring_reader(reader, cipher, key, nonce_seed)
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

/// `nonce_seed`: If we should include the nonce seed in the result so that it can be used when decrypting.
pub fn encrypt_string_with_nonce_seed(s: &SecretString, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64, include_nonce_seed: bool) -> Result<String> {
    let mut cursor = io::Cursor::new(vec![]);
    let mut writer = create_writer(cursor, cipher, key, nonce_seed);
    writer.write_all(s.expose_secret().as_bytes())?;
    writer.flush()?;
    cursor = writer.finish()?;
    let v = cursor.into_inner();
    if include_nonce_seed {
        Ok(format!("{}.{}", base64::encode(v), nonce_seed))
    } else {
        Ok(base64::encode(v))
    }
}

/// Encrypt a string with a random nonce seed. It will include the nonce seed in the result so that it can be used when decrypting.
pub fn encrypt_string(s: &SecretString, cipher: &Cipher, key: Arc<SecretVec<u8>>) -> Result<String> {
    let mut cursor = io::Cursor::new(vec![]);
    let nonce_seed = create_rng().next_u64();
    let mut writer = create_writer(cursor, cipher, key, nonce_seed);
    writer.write_all(s.expose_secret().as_bytes())?;
    writer.flush()?;
    cursor = writer.finish()?;
    let v = cursor.into_inner();
    Ok(format!("{}.{}", base64::encode(v), nonce_seed))
}

/// Decrypt a string that was encrypted with including the nonce seed.
pub fn decrypt_string(s: &str, cipher: &Cipher, key: Arc<SecretVec<u8>>) -> Result<SecretString> {
    // extract nonce seed
    if !s.contains(".") {
        return Err(Error::Generic("nonce seed is missing"));
    }
    let nonce_seed = s.split('.').last().unwrap().parse::<u64>()?;
    let s = s.split('.').next().unwrap();

    let vec = base64::decode(s)?;
    let cursor = io::Cursor::new(vec);

    let mut reader = create_reader(cursor, cipher, key, nonce_seed);
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;
    Ok(SecretString::new(decrypted))
}

/// Decrypt a string that was encrypted with a specific nonce seed.
pub fn decrypt_string_with_nonce_seed(s: &str, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> Result<SecretString> {
    let vec = base64::decode(s)?;
    let cursor = io::Cursor::new(vec);

    let mut reader = create_reader(cursor, cipher, key, nonce_seed);
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;
    Ok(SecretString::new(decrypted))
}

pub fn decrypt_file_name(name: &str, cipher: &Cipher, key: Arc<SecretVec<u8>>) -> Result<SecretString> {
    let name = String::from(name).replace("|", "/");
    decrypt_string(&name, cipher, key)
}

#[instrument(skip(password, salt))]
pub fn derive_key(password: &SecretString, cipher: &Cipher, salt: [u8; 32]) -> Result<SecretVec<u8>> {
    let mut dk = vec![];
    let key_len = match cipher {
        Cipher::ChaCha20 => 32,
        Cipher::Aes256Gcm => 32,
    };
    dk.resize(key_len, 0);
    Argon2::default().hash_password_into(password.expose_secret().as_bytes(), &salt, &mut dk)
        .map_err(|err| Error::GenericString(err.to_string()))?;
    Ok(SecretVec::new(dk))
}

/// Encrypt a file name with provided nonce seed. It will **INCLUDE** the nonce seed in the result so that it can be used when decrypting.
pub fn encrypt_file_name(name: &SecretString, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64) -> FsResult<String> {
    // in order not to add too much to filename length we keep just 3 digits from nonce seed
    let nonce_seed = nonce_seed % 1000;

    if name.expose_secret() != "$." && name.expose_secret() != "$.." {
        let normalized_name = SecretString::new(name.expose_secret().replace("/", " ").replace("\\", " "));
        let mut encrypted = encrypt_string_with_nonce_seed(&normalized_name, cipher, key, nonce_seed, true)?;
        encrypted = encrypted.replace("/", "|");
        Ok(encrypted)
    } else {
        // add nonce seed
        let mut name = name.expose_secret().clone();
        name.push_str(&nonce_seed.to_string());
        Ok(name)
    }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_secret_string(data: &SecretString) -> [u8; 32] {
    hash(data.expose_secret().as_bytes())
}

pub fn hash_secret_vec(data: &SecretVec<u8>) -> [u8; 32] {
    hash(data.expose_secret())
}

/// Copy from `pos` position in file `len` bytes
#[instrument(skip(w, key), fields(pos = pos.to_formatted_string(& Locale::en), len = len.to_formatted_string(& Locale::en)))]
pub fn copy_from_file_exact(w: &mut impl Write, pos: u64, len: u64, cipher: &Cipher, key: Arc<SecretVec<u8>>, nonce_seed: u64, file: PathBuf) -> io::Result<()> {
    debug!("");
    if len == 0 {
        // no-op
        return Ok(());
    }
    // create a new reader by reading from the beginning of the file
    let mut reader = create_reader(OpenOptions::new().read(true).open(file)?, cipher, key, nonce_seed);
    // move read position to the write position
    stream_util::seek_forward(&mut reader, pos)?;

    // copy the rest of the file
    stream_util::copy_exact(&mut reader, w, len)?;
    reader.finish();
    Ok(())
}


pub fn extract_nonce_from_encrypted_string(name: &str) -> Result<u64> {
    if !name.contains(".") {
        return Err(Error::Generic("nonce seed is missing"));
    }
    let nonce_seed = name.split('.').last().unwrap().parse::<u64>()?;
    Ok(nonce_seed)
}

pub fn create_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}