use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, Write};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use argon2::Argon2;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use base64::{DecodeError, Engine};
use hex::FromHexError;
use num_format::{Locale, ToFormattedString};
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tracing::{debug, error, instrument};
use write::CryptoInnerWriter;

use crate::crypto::read::{CryptoRead, CryptoReadSeek, RingCryptoRead};
use crate::crypto::write::{CryptoWrite, CryptoWriteSeek, RingCryptoWrite};
use crate::encryptedfs::FsResult;
use crate::{fs_util, stream_util};

pub mod buf_mut;
pub mod read;
pub mod write;

pub static BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

#[derive(
    Debug, Clone, Copy, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq, Eq,
)]
pub enum Cipher {
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl Cipher {
    /// In bytes.
    #[must_use]
    #[allow(clippy::use_self)]
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => CHACHA20_POLY1305.key_len(),
            Cipher::Aes256Gcm => AES_256_GCM.key_len(),
        }
    }

    /// Max length (in bytes) of the plaintext that can be encrypted before becoming unsafe.
    #[must_use]
    #[allow(clippy::use_self)]
    pub const fn max_plaintext_len(&self) -> usize {
        match self {
            Cipher::ChaCha20Poly1305 => (2_usize.pow(32) - 1) * 64,
            Cipher::Aes256Gcm => (2_usize.pow(39) - 256) / 8,
        }
    }
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
    #[error("serialize error: {source}")]
    SerializeError {
        #[from]
        source: bincode::Error,
        // backtrace: Backtrace,
    },
    #[error("generic error: {0}")]
    Generic(&'static str),
    #[error("generic error: {0}")]
    GenericString(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Creates an encrypted writer
pub fn create_write<W: CryptoInnerWriter + Send + Sync + 'static>(
    writer: W,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> impl CryptoWrite<W> {
    create_ring_write(writer, cipher, key)
}

/// Creates an encrypted writer with seek
pub fn create_write_seek<W: CryptoInnerWriter + Seek + Read + Send + Sync + 'static>(
    writer: W,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> impl CryptoWriteSeek<W> {
    create_ring_write_seek(writer, cipher, key)
}

fn create_ring_write<W: CryptoInnerWriter + Send + Sync>(
    writer: W,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> RingCryptoWrite<W> {
    let algorithm = match cipher {
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoWrite::new(writer, algorithm, key)
}

fn create_ring_write_seek<W: CryptoInnerWriter + Seek + Read + Send + Sync>(
    writer: W,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> RingCryptoWrite<W> {
    let algorithm = match cipher {
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoWrite::new(writer, algorithm, key)
}

fn create_ring_read<R: Read + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> RingCryptoRead<R> {
    let algorithm = match cipher {
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoRead::new(reader, algorithm, key)
}

fn create_ring_read_seek<R: Read + Seek + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> RingCryptoRead<R> {
    let algorithm = match cipher {
        Cipher::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoRead::new_seek(reader, algorithm, key)
}

/// Creates an encrypted reader
pub fn create_read<R: Read + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> impl CryptoRead<R> {
    create_ring_read(reader, cipher, key)
}

/// Creates an encrypted reader with seek
pub fn create_read_seek<R: Read + Seek + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> impl CryptoReadSeek<R> {
    create_ring_read_seek(reader, cipher, key)
}

#[allow(clippy::missing_errors_doc)]
pub fn encrypt(s: &SecretString, cipher: Cipher, key: &SecretVec<u8>) -> Result<String> {
    let mut cursor = io::Cursor::new(vec![]);
    let mut writer = create_write(cursor, cipher, key);
    writer.write_all(s.expose_secret().as_bytes())?;
    cursor = writer.finish()?;
    let v = cursor.into_inner();
    Ok(BASE64.encode(v))
}

#[allow(clippy::missing_panics_doc)]
#[allow(clippy::missing_errors_doc)]
pub fn decrypt(s: &str, cipher: Cipher, key: &SecretVec<u8>) -> Result<SecretString> {
    let vec = BASE64.decode(s)?;
    let cursor = io::Cursor::new(vec);

    let mut reader = create_read(cursor, cipher, key);
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;
    Ok(SecretString::new(decrypted))
}

#[allow(clippy::missing_errors_doc)]
pub fn decrypt_file_name(name: &str, cipher: Cipher, key: &SecretVec<u8>) -> Result<SecretString> {
    let name = String::from(name).replace('|', "/");
    decrypt(&name, cipher, key)
}

#[instrument(skip(password, salt))]
#[allow(clippy::missing_errors_doc)]
pub fn derive_key(password: &SecretString, cipher: Cipher, salt: &[u8]) -> Result<SecretVec<u8>> {
    let mut dk = vec![];
    let key_len = cipher.key_len();
    dk.resize(key_len, 0);
    Argon2::default()
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut dk)
        .map_err(|err| Error::GenericString(err.to_string()))?;
    Ok(SecretVec::new(dk))
}

#[allow(clippy::missing_errors_doc)]
pub fn encrypt_file_name(
    name: &SecretString,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> FsResult<String> {
    let secret_string = name.expose_secret();

    match secret_string.as_str() {
        "$." | "$.." => Ok(secret_string.clone()),
        "." | ".." => Ok(format!("${secret_string}")),
        _ => {
            let secret = SecretString::from_str(secret_string)
                .map_err(|err| Error::GenericString(err.to_string()))?;
            let mut encrypted = encrypt(&secret, cipher, key)?;
            encrypted = encrypted.replace('/', "|");

            Ok(encrypted)
        }
    }
}

#[allow(clippy::missing_errors_doc)]
#[must_use]
pub fn hash_file_name(name: &SecretString) -> String {
    if name.expose_secret() == "$." || name.expose_secret() == "$.." {
        name.expose_secret().clone()
    } else if name.expose_secret() == "." || name.expose_secret() == ".." {
        format!("${}", name.expose_secret())
    } else {
        hex::encode(hash_secret_string(name))
    }
}

#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[allow(clippy::missing_panics_doc)]
pub fn hash_reader<R: Read + ?Sized>(r: &mut R) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut reader = io::BufReader::new(r);
    io::copy(&mut reader, &mut hasher)?;
    Ok(hasher.finalize().into())
}

#[must_use]
pub fn hash_secret_string(data: &SecretString) -> [u8; 32] {
    hash(data.expose_secret().as_bytes())
}

#[must_use]
pub fn hash_secret_vec(data: &SecretVec<u8>) -> [u8; 32] {
    hash(data.expose_secret())
}

/// Copy from `pos` position in file `len` bytes
#[instrument(skip(w, key), fields(pos = pos.to_formatted_string(& Locale::en), len = len.to_formatted_string(& Locale::en)))]
#[allow(clippy::missing_errors_doc)]
pub fn copy_from_file_exact(
    file: PathBuf,
    pos: u64,
    len: u64,
    cipher: Cipher,
    key: &SecretVec<u8>,
    w: &mut impl Write,
) -> io::Result<()> {
    debug!("");
    copy_from_file(file, pos, len, cipher, key, w, false)?;
    Ok(())
}

#[allow(clippy::missing_errors_doc)]
pub fn copy_from_file(
    file: PathBuf,
    pos: u64,
    len: u64,
    cipher: Cipher,
    key: &SecretVec<u8>,
    w: &mut impl Write,
    stop_on_eof: bool,
) -> io::Result<u64> {
    if len == 0 || file.metadata()?.len() == 0 {
        // no-op
        return Ok(0);
    }
    // create a new reader by reading from the beginning of the file
    let mut reader = create_read(OpenOptions::new().read(true).open(file)?, cipher, key);
    // move read position to the write position
    let pos2 = stream_util::seek_forward(&mut reader, pos, stop_on_eof)?;
    if pos2 < pos {
        return if stop_on_eof {
            Ok(0)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ))
        };
    }

    // copy the rest of the file
    let len = stream_util::copy(&mut reader, w, len, stop_on_eof)?;
    Ok(len)
}

#[must_use]
pub fn create_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}

pub fn serialize_encrypt_into<W, T>(
    writer: W,
    value: &T,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> Result<W>
where
    W: CryptoInnerWriter + Send + Sync + 'static,
    T: serde::Serialize + ?Sized,
{
    let mut writer = create_write(writer, cipher, key);
    bincode::serialize_into(&mut writer, value)?;
    let writer = writer.finish()?;
    Ok(writer)
}

pub fn atomic_serialize_encrypt_into<T>(
    file: &Path,
    value: &T,
    cipher: Cipher,
    key: &SecretVec<u8>,
) -> Result<()>
where
    T: serde::Serialize + ?Sized,
{
    let parent = file.parent().ok_or(Error::Generic("file has no parent"))?;
    let mut file = fs_util::open_atomic_write(file)?;
    // println!("file: {:#?}", file.as_file_mut().metadata()?);
    file = serialize_encrypt_into(file, value, cipher, key)?;
    file.commit()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::RngCore;
    use secrecy::{ExposeSecret, Secret, SecretString, SecretVec};
    use std::{
        fs::File,
        io::{self, Write},
        path::{Path, PathBuf},
    };
    use tempfile::{tempdir, TempDir};

    fn create_encrypted_file(
        content: &str,
        cipher: Cipher,
        key: &Secret<Vec<u8>>,
    ) -> (TempDir, PathBuf) {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");

        let mut file = File::create(file_path.clone()).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();

        let encrypted_file_path = Path::new(&file_path).to_path_buf().with_extension("enc");
        if encrypted_file_path.exists() {
            std::fs::remove_file(&encrypted_file_path).unwrap();
        }

        let mut file = File::open(file_path).unwrap();
        let mut writer = create_write(
            File::create(encrypted_file_path.clone()).unwrap(),
            cipher,
            key,
        );
        io::copy(&mut file, &mut writer).unwrap();
        writer.finish().unwrap();

        (temp_dir, encrypted_file_path)
    }

    fn secret_key(cipher: Cipher) -> Secret<Vec<u8>> {
        let mut key = vec![0; cipher.key_len()];
        create_rng().fill_bytes(&mut key);
        SecretVec::new(key)
    }

    #[test]
    fn test_simple_encrypt_and_decrypt() {
        let secret = SecretString::new("Test secret".to_string());

        for &cipher in &[Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = secret_key(cipher);

            let encrypted = encrypt(&secret, cipher, &key).unwrap();
            let decrypted = decrypt(&encrypted, cipher, &key).unwrap();
            assert_eq!(decrypted.expose_secret(), secret.expose_secret());
        }
    }

    #[test]
    fn test_encrypt_and_decrypt_file_name() {
        let secret_name = SecretString::new("testfile.txt".to_string());

        for &cipher in &[Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = secret_key(cipher);
            let encrypted = encrypt_file_name(&secret_name, cipher, &key).unwrap();
            let decrypted = decrypt_file_name(&encrypted, cipher, &key).unwrap();
            assert_eq!(decrypted.expose_secret(), secret_name.expose_secret());
        }

        let secret_name = SecretString::new("testfile\\With/slash.txt".to_string());

        for &cipher in &[Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = secret_key(cipher);
            let encrypted = encrypt_file_name(&secret_name, cipher, &key).unwrap();
            let decrypted = decrypt_file_name(&encrypted, cipher, &key).unwrap();
            assert_eq!(decrypted.expose_secret(), secret_name.expose_secret());
        }
    }

    #[test]
    fn test_encrypt_and_decrypt_file_name_invalid_cipher() {
        let key = secret_key(Cipher::ChaCha20Poly1305);
        let secret_name = SecretString::new("testfile.txt".to_string());

        let encrypted = encrypt_file_name(&secret_name, Cipher::ChaCha20Poly1305, &key).unwrap();
        let result = decrypt_file_name(&encrypted, Cipher::Aes256Gcm, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key() {
        let password = SecretString::new("password".to_string());
        let salt = b"salt_of_pass";

        for &cipher in &[Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let derived_key = derive_key(&password, cipher, salt).unwrap();
            assert_eq!(derived_key.expose_secret().len(), cipher.key_len());
        }
    }

    #[test]
    fn test_derive_key_consistency() {
        let password = SecretString::new("password".to_string());
        let salt = b"random_salt";

        let derived_key_1 = derive_key(&password, Cipher::ChaCha20Poly1305, salt).unwrap();
        let derived_key_2 = derive_key(&password, Cipher::ChaCha20Poly1305, salt).unwrap();

        assert_eq!(derived_key_1.expose_secret(), derived_key_2.expose_secret());
    }

    #[test]
    fn test_derive_key_empty_salt() {
        let empty_password = SecretString::new("password".to_string());
        let empty_salt = b"";

        let result = derive_key(&empty_password, Cipher::ChaCha20Poly1305, empty_salt);

        // Salt is too small
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_uniqueness() {
        let password = SecretString::new("password".to_string());
        let salts = vec![b"random_salt1", b"random_salt2", b"random_salt3"];

        let mut derived_keys = std::collections::HashSet::new();
        for salt in salts.clone() {
            let derived_key = derive_key(&password, Cipher::ChaCha20Poly1305, salt).unwrap();
            derived_keys.insert(derived_key.expose_secret().clone());
        }

        assert_eq!(derived_keys.len(), salts.len());
    }

    #[test]
    fn test_encrypt_decrypt() {
        for &cipher in &[Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = secret_key(cipher);

            let data = SecretString::new("A".to_string());
            let encrypted = encrypt(&data, cipher, &key).unwrap();
            let decrypted = decrypt(&encrypted, cipher, &key).unwrap();
            assert_eq!(decrypted.expose_secret(), data.expose_secret());

            let large_data = SecretString::new("A".repeat(1024 * 1024)); // 1 MB
            let encrypted = encrypt(&large_data, cipher, &key).unwrap();
            let decrypted = decrypt(&encrypted, cipher, &key).unwrap();
            assert_eq!(decrypted.expose_secret(), large_data.expose_secret());
        }
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let key = SecretVec::new(vec![0; 32]);
        let secret = SecretString::new("".to_string());

        let encrypted = encrypt(&secret, Cipher::ChaCha20Poly1305, &key).unwrap();
        let decrypted = decrypt(&encrypted, Cipher::ChaCha20Poly1305, &key).unwrap();

        assert_eq!(decrypted.expose_secret(), "");
    }

    #[test]
    fn test_hash_file_name_special_cases() {
        let expected = "$.".to_string();
        let name = SecretString::new(expected.clone());
        let result = hash_file_name(&name);
        assert_eq!(result, expected);

        let expected = "$..".to_string();
        let name = SecretString::new(expected.clone());
        let result = hash_file_name(&name);
        assert_eq!(result, expected);

        let input = ".".to_string();
        let expected = "$.".to_string();
        let name = SecretString::new(input);
        let result = hash_file_name(&name);
        assert_eq!(result, expected);

        let input = "..".to_string();
        let expected = "$..".to_string();
        let name = SecretString::new(input);
        let result = hash_file_name(&name);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_file_name_regular_case() {
        let name = SecretString::new("filename.txt".to_string());
        let result = hash_file_name(&name);
        let expected_hash = hex::encode(hash_secret_string(&name));
        assert_eq!(result, expected_hash);
    }

    #[test]
    fn test_hash_secret_string() {
        let secret = SecretString::new("hash this secret".to_string());
        let expected_hash_hex = "d820cbf278fc742d8ec30e43947674689cd06d5aa9b71a2f9afe162a4ce408dc";

        let hash_hex = hex::encode(hash_secret_string(&secret));
        assert_eq!(hash_hex, expected_hash_hex);
    }

    #[test]
    fn test_copy_from_file_exact() {
        let cipher = Cipher::ChaCha20Poly1305;
        let key = secret_key(cipher);

        let content = "Hello World!";
        let (_temp_dir, file_path) = create_encrypted_file(content, cipher, &key);

        let mut output = Vec::new();
        copy_from_file_exact(
            file_path.clone(),
            0,
            content.len() as u64,
            cipher,
            &key,
            &mut output,
        )
        .unwrap();
        assert_eq!(&output, content.as_bytes());
    }

    #[test]
    fn test_copy_from_file_exact_zero_length() {
        let key = SecretVec::new(vec![0; 32]);
        let (_temp_dir, file_path) =
            create_encrypted_file("Hello, world!", Cipher::ChaCha20Poly1305, &key);

        let mut output = Vec::new();
        let result = copy_from_file_exact(
            file_path.clone(),
            0,
            0,
            Cipher::ChaCha20Poly1305,
            &key,
            &mut output,
        );

        assert!(result.is_ok());
        assert!(output.is_empty());
    }

    #[test]
    fn test_copy_from_file_exact_position_beyond_eof() {
        let cipher = Cipher::ChaCha20Poly1305;
        let key = secret_key(cipher);

        let content = "Hello, world!";
        let (_temp_dir, file_path) = create_encrypted_file(content, Cipher::ChaCha20Poly1305, &key);

        let mut output = Vec::new();
        let result = copy_from_file_exact(
            file_path.clone(),
            content.len() as u64 + 1,
            10,
            Cipher::ChaCha20Poly1305,
            &key,
            &mut output,
        );

        assert!(result.is_err());
    }
}
