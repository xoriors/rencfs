pub mod decryptor;
pub mod encryptor;

use std::fs::{File, OpenOptions};
use cryptostream::{read, write};
use std::os::unix::fs::MetadataExt;
use rand::thread_rng;
use std::io::{Read, Write};
use base64::decode;
use std::io;
use std::path::PathBuf;
use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use num_format::{Locale, ToFormattedString};
use openssl::sha::sha256;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use thiserror::Error;
use tracing::{debug, error, info, instrument};
use strum_macros::{Display, EnumIter, EnumString};
use serde::{Deserialize, Serialize};
use openssl::error::ErrorStack;
use crate::crypto::decryptor::{Decryptor, CryptostreamDecryptor};
use crate::crypto::encryptor::{Encryptor, CryptostreamEncryptor};
use crate::stream_util;

#[derive(Debug, Clone, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq)]
pub enum Cipher {
    ChaCha20,
    Aes256Gcm,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("cryptostream error: {source}")]
    OpenSsl {
        #[from]
        source: ErrorStack,
        // backtrace: Backtrace,
    },
    #[error("crypto error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn create_encryptor(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> impl Encryptor<File> {
    let iv_len = match cipher {
        Cipher::ChaCha20 => 16,
        Cipher::Aes256Gcm => 16,
    };
    let mut iv: Vec<u8> = vec![0; iv_len];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        thread_rng().fill_bytes(&mut iv);
        file.write_all(&iv).unwrap();
    } else {
        // read IV from file
        file.read_exact(&mut iv).unwrap();
    }
    CryptostreamEncryptor::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
}

#[instrument(skip(key))]
pub fn create_decryptor(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> impl Decryptor<File> {
    let iv_len = match cipher {
        Cipher::ChaCha20 => 16,
        Cipher::Aes256Gcm => 16,
    };
    let mut iv: Vec<u8> = vec![0; iv_len];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        thread_rng().fill_bytes(&mut iv);
        file.write_all(&iv).map_err(|err| {
            error!("{err}");
            err
        }).unwrap();
    } else {
        // read IV from file
        file.read_exact(&mut iv).map_err(|err| {
            error!("{err}");
            err
        }).unwrap();
    }
    CryptostreamDecryptor::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
}

pub fn encrypt_string(s: &SecretString, cipher: &Cipher, key: &SecretVec<u8>) -> String {
    // use the same IV so the same string will be encrypted to the same value
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let mut cursor = io::Cursor::new(vec![]);

    let mut encryptor = write::Encryptor::new(cursor, get_cipher(cipher), key.expose_secret(), &iv).unwrap();
    encryptor.write_all(s.expose_secret().as_bytes()).unwrap();
    cursor = encryptor.finish().unwrap();
    base64::encode(&cursor.into_inner())
}

pub fn decrypt_string(s: &str, cipher: &Cipher, key: &SecretVec<u8>) -> SecretString {
    // use the same IV so the same string will be encrypted to the same value&SecretString::from_str(
    let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();

    let vec = decode(s).unwrap();
    let cursor = io::Cursor::new(vec);

    let mut decryptor = read::Decryptor::new(cursor, get_cipher(cipher), &key.expose_secret(), &iv).unwrap();
    let mut decrypted = String::new();
    decryptor.read_to_string(&mut decrypted).unwrap();
    SecretString::new(decrypted)
}

pub fn decrypt_and_unnormalize_end_file_name(name: &str, cipher: &Cipher, key: &SecretVec<u8>) -> SecretString {
    let name = String::from(name).replace("|", "/");
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

pub fn normalize_end_encrypt_file_name(name: &SecretString, cipher: &Cipher, key: &SecretVec<u8>) -> String {
    if name.expose_secret() != "$." && name.expose_secret() != "$.." {
        let normalized_name = SecretString::new(name.expose_secret().replace("/", " ").replace("\\", " "));
        let mut encrypted = encrypt_string(&normalized_name, cipher, key);
        encrypted = encrypted.replace("/", "|");
        return encrypted;
    }
    name.expose_secret().to_owned()
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

pub fn hash_secret(data: &SecretString) -> SecretVec<u8> {
    SecretVec::new(sha256(data.expose_secret().as_bytes()).to_vec())
}

fn get_cipher(cipher: &Cipher) -> openssl::symm::Cipher {
    match cipher {
        Cipher::ChaCha20 => openssl::symm::Cipher::chacha20(),
        Cipher::Aes256Gcm => openssl::symm::Cipher::aes_256_gcm(),
    }
}

/// Copy from `pos` position in file `len` bytes
#[instrument(skip(w, key), fields(pos = pos.to_formatted_string(& Locale::en), len = len.to_formatted_string(& Locale::en)))]
pub fn copy_from_file_exact(w: &mut impl Write, pos: u64, len: u64, cipher: &Cipher, key: &SecretVec<u8>, file: PathBuf) -> io::Result<()> {
    debug!("");
    if len == 0 {
        // no-op
        return Ok(());
    }
    // create a new decryptor by reading from the beginning of the file
    let mut decryptor = create_decryptor(OpenOptions::new().read(true).open(file)?, cipher, key);
    // move read position to the write position
    stream_util::read_seek_forward_exact(&mut decryptor, pos)?;

    // copy the rest of the file
    stream_util::copy_exact(&mut decryptor, w, len)?;
    decryptor.finish();
    Ok(())
}
