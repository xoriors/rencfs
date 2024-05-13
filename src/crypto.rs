use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, Write};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::arc_hashmap::Holder;
use argon2::Argon2;
use base64::alphabet::STANDARD;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use base64::{DecodeError, Engine};
use hex::FromHexError;
use num_format::{Locale, ToFormattedString};
use parking_lot::RwLock;
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::aead::{AES_256_GCM, CHACHA20_POLY1305};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, error, instrument};

use crate::crypto::reader::{
    ChunkedFileCryptoReader, CryptoReader, FileCryptoReader, RingCryptoReader,
};
use crate::crypto::writer::{
    ChunkedTmpFileCryptoWriter, CryptoWriter, CryptoWriterSeek, FileCryptoWriterCallback,
    FileCryptoWriterMetadataProvider, RingCryptoWriter, SequenceLockProvider, TmpFileCryptoWriter,
};
use crate::encryptedfs::FsResult;
use crate::stream_util;

pub mod buf_mut;
pub mod reader;
pub mod writer;

pub static BASE64: GeneralPurpose = GeneralPurpose::new(&STANDARD, NO_PAD);

#[derive(
    Debug, Clone, Copy, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq, Eq,
)]
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

pub fn create_writer<W: Write + Send + Sync>(
    writer: W,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> impl CryptoWriter<W> {
    create_ring_writer(writer, cipher, key)
}

/// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position
///
/// **`lock`** is used to write lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we do\
///     You need to provide the same lock to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same lock
///
/// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file\
///     If the file exists or is created before flushing, in worse case scenarios, it can reduce the overall write speed by half, so it's recommended to provide it
///
/// **`tmp_dir`** is used to store the temporary file while writing. It **MUST** be on the same filesystem as the **`file_dir`**\
///     New changes are written to a temporary file and on **`finish`** the tmp file is renamed to the original file
#[allow(clippy::missing_errors_doc)]
pub fn create_tmp_file_writer(
    file: &Path,
    tmp_dir: &Path,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    callback: Option<Box<dyn FileCryptoWriterCallback>>,
    lock: Option<Holder<RwLock<bool>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
    Ok(Box::new(TmpFileCryptoWriter::new(
        file,
        tmp_dir,
        cipher,
        key,
        callback,
        lock,
        metadata_provider,
    )?))
}

/// **`callback`** is called when the file content changes. It receives the position from where the file content changed and the last write position\
/// **`locks`** is used to write lock the chunks files when accessing them. This ensures that we have exclusive write to a given chunk when we need to change it's content\
///     If not provided, it will not ensure that other instances are not accessing the chunks while we do\
///     You need to provide the same locks to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same locks\
/// **`metadata_provider`** it's used to do some optimizations to reduce some copy operations from original file\
///     If the file exists or is created before flushing, in worse case scenarios, it can reduce the overall write speed by half, so it's recommended to provide it\
/// **`tmp_dir`** is used to store temporary files while writing to chunks. It **MUST** be on the same filesystem as the `file_dir`\
///   New changes are written to a temporary file and on **`finish`** or when we write to another chunk the tmp file is renamed to the original chunk
#[allow(clippy::missing_errors_doc)]
pub fn create_chunked_tmp_file_writer(
    file_dir: &Path,
    tmp_dir: &Path,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    callback: Option<Box<dyn FileCryptoWriterCallback>>,
    locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
    metadata_provider: Option<Box<dyn FileCryptoWriterMetadataProvider>>,
) -> io::Result<Box<dyn CryptoWriterSeek<File>>> {
    Ok(Box::new(ChunkedTmpFileCryptoWriter::new(
        file_dir,
        tmp_dir,
        cipher,
        key,
        callback,
        locks,
        metadata_provider,
    )?))
}

/// **`locks`** is used to read lock the chunks files when accessing them. This ensures offer multiple reads but exclusive writes to a given chunk\
///     If not provided, it will not ensure that other instances are not writing the chunks while we read them\
///     You need to provide the same locks to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same locks
#[allow(clippy::missing_errors_doc)]
pub fn create_chunked_file_reader(
    file_dir: &Path,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    locks: Option<Holder<Box<dyn SequenceLockProvider>>>,
) -> io::Result<Box<dyn CryptoReader>> {
    Ok(Box::new(ChunkedFileCryptoReader::new(
        file_dir, cipher, key, locks,
    )?))
}

fn create_ring_writer<W: Write + Send + Sync>(
    writer: W,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> RingCryptoWriter<W> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoWriter::new(writer, algorithm, key)
}

fn create_ring_reader<R: Read + Seek + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> RingCryptoReader<R> {
    let algorithm = match cipher {
        Cipher::ChaCha20 => &CHACHA20_POLY1305,
        Cipher::Aes256Gcm => &AES_256_GCM,
    };
    RingCryptoReader::new(reader, algorithm, key)
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

pub fn create_reader<R: Read + Seek + Send + Sync>(
    reader: R,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> impl CryptoReader {
    create_ring_reader(reader, cipher, key)
}

/// **`lock`** is used to read lock the file when accessing it. If not provided, it will not ensure that other instances are not writing to the file while we read\
///     You need to provide the same lock to all writers and readers of this file, you should obtain a new [`Holder`] that wraps the same lock
#[allow(clippy::missing_errors_doc)]
pub fn create_file_reader(
    file: &Path,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
    lock: Option<Holder<RwLock<bool>>>,
) -> io::Result<Box<dyn CryptoReader>> {
    Ok(Box::new(FileCryptoReader::new(file, cipher, key, lock)?))
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

#[allow(clippy::missing_errors_doc)]
pub fn encrypt_string(s: &SecretString, cipher: Cipher, key: Arc<SecretVec<u8>>) -> Result<String> {
    let mut cursor = io::Cursor::new(vec![]);
    let mut writer = create_writer(cursor, cipher, key);
    writer.write_all(s.expose_secret().as_bytes())?;
    writer.flush()?;
    cursor = writer.finish()?;
    let v = cursor.into_inner();
    Ok(BASE64.encode(v))
}

#[allow(clippy::missing_panics_doc)]
#[allow(clippy::missing_errors_doc)]
pub fn decrypt_string(s: &str, cipher: Cipher, key: Arc<SecretVec<u8>>) -> Result<SecretString> {
    let vec = BASE64.decode(s)?;
    let cursor = io::Cursor::new(vec);

    let mut reader = create_reader(cursor, cipher, key);
    let mut decrypted = String::new();
    reader.read_to_string(&mut decrypted)?;
    Ok(SecretString::new(decrypted))
}

#[allow(clippy::missing_errors_doc)]
pub fn decrypt_file_name(
    name: &str,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> Result<SecretString> {
    let name = String::from(name).replace('|', "/");
    decrypt_string(&name, cipher, key)
}

#[instrument(skip(password, salt))]
#[allow(clippy::missing_errors_doc)]
pub fn derive_key(
    password: &SecretString,
    cipher: Cipher,
    salt: [u8; 32],
) -> Result<SecretVec<u8>> {
    let mut dk = vec![];
    let key_len = match cipher {
        Cipher::ChaCha20 | Cipher::Aes256Gcm => 32,
    };
    dk.resize(key_len, 0);
    Argon2::default()
        .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut dk)
        .map_err(|err| Error::GenericString(err.to_string()))?;
    Ok(SecretVec::new(dk))
}

#[allow(clippy::missing_errors_doc)]
pub fn encrypt_file_name(
    name: &SecretString,
    cipher: Cipher,
    key: Arc<SecretVec<u8>>,
) -> FsResult<String> {
    if name.expose_secret() != "$." && name.expose_secret() != "$.." {
        let normalized_name = SecretString::new(name.expose_secret().replace(['/', '\\'], " "));
        let mut encrypted = encrypt_string(&normalized_name, cipher, key)?;
        encrypted = encrypted.replace('/', "|");
        Ok(encrypted)
    } else {
        Ok(name.expose_secret().clone())
    }
}

#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[allow(clippy::missing_panics_doc)]
pub fn hash_reader<R: Read + ?Sized>(r: &mut R) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut reader = io::BufReader::new(r);
    io::copy(&mut reader, &mut hasher)?;
    Ok(hasher.finalize().into())
}

#[allow(clippy::missing_panics_doc)]
pub async fn hash_async_reader(r: &mut (impl AsyncRead + ?Sized + Unpin)) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();

    let mut r = tokio::io::BufReader::new(r);
    let buf = &mut [0; 1024 * 1024];
    loop {
        let n = r.read(buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
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
    key: Arc<SecretVec<u8>>,
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
    key: Arc<SecretVec<u8>>,
    w: &mut impl Write,
    stop_on_eof: bool,
) -> io::Result<u64> {
    if len == 0 || file.metadata()?.len() == 0 {
        // no-op
        return Ok(0);
    }
    // create a new reader by reading from the beginning of the file
    let mut reader = create_reader(OpenOptions::new().read(true).open(file)?, cipher, key);
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
