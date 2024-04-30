use std::fs::File;
use cryptostream::{read, write};
use std::os::unix::fs::MetadataExt;
use rand::Rng;
use std::io::{Read, Write};
use base64::decode;
use std::io;
use argon2::Argon2;
use cryptostream::read::Decryptor;
use cryptostream::write::Encryptor;
use openssl::sha::sha256;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use thiserror::Error;
use tracing::{error, instrument};
use crate::encryptedfs::Cipher;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("crypto error: {0}")]
    Generic(String),
}

pub fn create_encryptor(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> write::Encryptor<File> {
    let iv_len = match cipher {
        Cipher::ChaCha20 => 16,
        Cipher::Aes256Gcm => 316,
    };
    let mut iv: Vec<u8> = vec![0; iv_len];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        rand::thread_rng().fill_bytes(&mut iv);
        file.write_all(&iv).unwrap();
    } else {
        // read IV from file
        file.read_exact(&mut iv).unwrap();
    }
    Encryptor::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
}

#[instrument(skip(key))]
pub fn create_decryptor(mut file: File, cipher: &Cipher, key: &SecretVec<u8>) -> Decryptor<File> {
    let iv_len = match cipher {
        Cipher::ChaCha20 => 16,
        Cipher::Aes256Gcm => 316,
    };
    let mut iv: Vec<u8> = vec![0; iv_len];
    if file.metadata().unwrap().size() == 0 {
        // generate random IV
        rand::thread_rng().fill_bytes(&mut iv);
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
    Decryptor::new(file, get_cipher(cipher), &key.expose_secret(), &iv).unwrap()
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
pub fn derive_key(password: &SecretString, cipher: &Cipher, salt: SecretVec<u8>) -> Result<SecretVec<u8>, CryptoError> {
    let mut dk = vec![];
    let key_len = match cipher {
        Cipher::ChaCha20 => 32,
        Cipher::Aes256Gcm => 32,
    };
    dk.resize(key_len, 0);
    Argon2::default().hash_password_into(password.expose_secret().as_bytes(), salt.expose_secret(), &mut dk)
        .map_err(|err| CryptoError::Generic(err.to_string()))?;
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
