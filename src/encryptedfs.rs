use std::{fs, io};
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::{File, OpenOptions, ReadDir};
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime};

use argon2::password_hash::rand_core::RngCore;
use cryptostream::read::Decryptor;
use cryptostream::write::Encryptor;
use futures_util::TryStreamExt;
use num_format::{Locale, ToFormattedString};
use openssl::error::ErrorStack;
use rand::thread_rng;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tokio::sync::{Mutex, MutexGuard, RwLock};
use tokio_stream::wrappers::ReadDirStream;
use tracing::{debug, error, instrument, warn};

use crate::arc_hashmap::{ArcHashMap, Guard};
use crate::expire_value;
use crate::expire_value::{ExpireValue, Provider};

pub mod crypto_util;
#[cfg(test)]
mod encryptedfs_test;
#[cfg(test)]
mod moved_test;

pub(crate) const INODES_DIR: &str = "inodes";
pub(crate) const CONTENTS_DIR: &str = "contents";
pub(crate) const SECURITY_DIR: &str = "security";
pub(crate) const KEY_ENC_FILENAME: &str = "key.enc";

pub(crate) const ROOT_INODE: u64 = 1;

/// File attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileAttr {
    /// Inode number
    pub ino: u64,
    /// Size in bytes
    pub size: u64,
    /// Size in blocks
    pub blocks: u64,
    /// Time of last access
    pub atime: SystemTime,
    /// Time of last modification
    pub mtime: SystemTime,
    /// Time of last change
    pub ctime: SystemTime,
    /// Time of creation (macOS only)
    pub crtime: SystemTime,
    /// Kind of file (directory, file, pipe, etc)
    pub kind: FileType,
    /// Permissions
    pub perm: u16,
    /// Number of hard links
    pub nlink: u32,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    /// Block size
    pub blksize: u32,
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
}

/// File types.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum FileType {
    // /// Named pipe (S_IFIFO)
    // NamedPipe,
    // /// Character device (S_IFCHR)
    // CharDevice,
    // /// Block device (S_IFBLK)
    // BlockDevice,
    /// Directory (S_IFDIR)
    Directory,
    /// Regular file (S_IFREG)
    RegularFile,
    // /// Symbolic link (S_IFLNK)
    // Symlink,
    // /// Unix domain socket (S_IFSOCK)
    // Socket,
}

#[derive(Debug, Clone, Default)]
pub struct SetFileAttr {
    /// Size in bytes
    pub size: Option<u64>,
    /// Time of last access
    pub atime: Option<SystemTime>,
    /// Time of last modification
    pub mtime: Option<SystemTime>,
    /// Time of last change
    pub ctime: Option<SystemTime>,
    /// Time of creation (macOS only)
    pub crtime: Option<SystemTime>,
    /// Permissions
    pub perm: Option<u16>,
    /// User id
    pub uid: Option<u32>,
    /// Group id
    pub gid: Option<u32>,
    /// Rdev
    pub rdev: Option<u32>,
    /// Flags (macOS only, see chflags(2))
    pub flags: Option<u32>,
}

impl SetFileAttr {
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_atime(mut self, atime: SystemTime) -> Self {
        self.atime = Some(atime);
        self
    }

    pub fn with_mtime(mut self, mtime: SystemTime) -> Self {
        self.mtime = Some(mtime);
        self
    }

    pub fn with_ctime(mut self, ctime: SystemTime) -> Self {
        self.ctime = Some(ctime);
        self
    }

    pub fn with_crtime(mut self, crtime: SystemTime) -> Self {
        self.crtime = Some(crtime);
        self
    }

    pub fn with_perm(mut self, perm: u16) -> Self {
        self.perm = Some(perm);
        self
    }

    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    pub fn with_rdev(mut self, rdev: u32) -> Self {
        self.rdev = Some(rdev);
        self
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.rdev = Some(flags);
        self
    }
}

#[derive(Debug, Clone)]
pub struct CreateFileAttr {
    /// Kind of file (directory, file, pipe, etc)
    pub kind: FileType,
    /// Permissions
    pub perm: u16,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
}

impl From<CreateFileAttr> for FileAttr {
    fn from(value: CreateFileAttr) -> Self {
        Self {
            ino: 0,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: value.kind,
            perm: value.perm,
            nlink: if value.kind == FileType::Directory { 2 } else { 1 },
            uid: value.uid,
            gid: value.gid,
            rdev: value.rdev,
            blksize: 0,
            flags: value.flags,
        }
    }
}

#[derive(Error, Debug)]
pub enum FsError {
    #[error("IO error: {source}")]
    Io {
        #[from]
        source: io::Error,
        // backtrace: Backtrace,
    },

    #[error("serialize error: {source}")]
    SerializeError {
        #[from]
        source: bincode::Error,
        // backtrace: Backtrace,
    },

    #[error("item not found")]
    NotFound(String),

    #[error("inode not found")]
    InodeNotFound,

    #[error("invalid input")]
    InvalidInput(String),

    #[error("invalid node type")]
    InvalidInodeType,

    #[error("invalid file handle")]
    InvalidFileHandle,

    #[error("already exists")]
    AlreadyExists,

    #[error("already open for write")]
    AlreadyOpenForWrite,

    #[error("not empty")]
    NotEmpty,

    #[error("other")]
    Other(String),

    #[error("encryption error: {source}")]
    Encryption {
        #[from]
        source: ErrorStack,
        // backtrace: Backtrace,
    },

    #[error("invalid password")]
    InvalidPassword,

    #[error("invalid structure of data directory")]
    InvalidDataDirStructure,

    #[error("crypto error: {source}")]
    Crypto {
        #[from]
        source: crypto_util::CryptoError,
        // backtrace: Backtrace,
    },

    #[error("keyring error: {source}")]
    Keyring {
        #[from]
        source: keyring::Error,
        // backtrace: Backtrace,
    },
}

#[derive(Debug, Clone, EnumIter, EnumString, Display, Serialize, Deserialize, PartialEq)]
pub enum Cipher {
    ChaCha20,
    Aes256Gcm,
}

#[derive(Debug, Clone)]
struct TimeAndSizeFileAttr {
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    crtime: SystemTime,
    size: u64,
}

impl TimeAndSizeFileAttr {
    #[allow(dead_code)]
    fn new(atime: SystemTime, mtime: SystemTime, ctime: SystemTime, crtime: SystemTime, size: u64) -> Self {
        Self {
            atime,
            mtime,
            ctime,
            crtime,
            size,
        }
    }
}

impl From<FileAttr> for TimeAndSizeFileAttr {
    fn from(value: FileAttr) -> Self {
        Self {
            atime: value.atime,
            mtime: value.mtime,
            ctime: value.ctime,
            crtime: value.crtime,
            size: value.size,
        }
    }
}

impl From<TimeAndSizeFileAttr> for SetFileAttr {
    fn from(value: TimeAndSizeFileAttr) -> Self {
        SetFileAttr::default()
            .with_atime(value.atime)
            .with_mtime(value.mtime)
            .with_ctime(value.ctime)
            .with_crtime(value.crtime)
            .with_size(value.size)
    }
}


#[derive(Debug)]
pub struct DirectoryEntry {
    pub ino: u64,
    pub name: SecretString,
    pub kind: FileType,
}

impl PartialEq for DirectoryEntry {
    fn eq(&self, other: &Self) -> bool {
        self.ino == other.ino && self.name.expose_secret() == other.name.expose_secret() && self.kind == other.kind
    }
}

/// Like [`DirectoryEntry`] but with ['FileAttr'].
#[derive(Debug)]
pub struct DirectoryEntryPlus {
    pub ino: u64,
    pub name: SecretString,
    pub kind: FileType,
    pub attr: FileAttr,
}

impl PartialEq for DirectoryEntryPlus {
    fn eq(&self, other: &Self) -> bool {
        self.ino == other.ino && self.name.expose_secret() == other.name.expose_secret() && self.kind == other.kind && self.attr == other.attr
    }
}

pub type FsResult<T> = Result<T, FsError>;

pub struct DirectoryEntryIterator(ReadDir, Cipher, Arc<SecretVec<u8>>, Arc<std::sync::RwLock<ArcHashMap<String, std::sync::RwLock<bool>>>>);

impl Iterator for DirectoryEntryIterator {
    type Item = FsResult<DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        if let Err(e) = entry {
            return Some(Err(e.into()));
        }
        let entry = entry.unwrap();

        let map = self.3.read().unwrap();
        let lock = map.get_or_insert_with(entry.path().to_str().unwrap().to_string(), || std::sync::RwLock::new(false));
        let _guard = lock.read().unwrap();

        let file = File::open(entry.path());
        if let Err(e) = file {
            return Some(Err(e.into()));
        }

        let file = file.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        let name = {
            if name == "$." {
                SecretString::from_str(".").unwrap()
            } else if name == "$.." {
                SecretString::from_str("..").unwrap()
            } else {
                crypto_util::decrypt_and_unnormalize_end_file_name(&name, &self.1, &self.2)
            }
        };

        let res: bincode::Result<(u64, FileType)> = bincode::deserialize_from(crypto_util::create_decryptor(file, &self.1, &self.2));
        if let Err(e) = res {
            return Some(Err(e.into()));
        }
        let (ino, kind): (u64, FileType) = res.unwrap();
        Some(Ok(DirectoryEntry { ino, name, kind }))
    }
}

pub struct DirectoryEntryPlusIterator(ReadDir, PathBuf, Cipher, Arc<SecretVec<u8>>,
                                      Arc<std::sync::RwLock<ArcHashMap<String, std::sync::RwLock<bool>>>>,
                                      Arc<std::sync::RwLock<ArcHashMap<u64, std::sync::RwLock<bool>>>>);

impl Iterator for DirectoryEntryPlusIterator {
    type Item = FsResult<DirectoryEntryPlus>;

    #[instrument(name = "DirectoryEntryPlusIterator::next", skip(self))]
    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        if let Err(e) = entry {
            error!(err = %e, "reading directory entry");
            return Some(Err(e.into()));
        }
        let entry = entry.unwrap();

        let map = self.4.read().unwrap();
        let lock = map.get_or_insert_with(entry.path().to_str().unwrap().to_string(), || std::sync::RwLock::new(false));
        let _guard = lock.read().unwrap();

        let file = File::open(entry.path());
        if let Err(e) = file {
            error!(err = %e, "opening file");
            return Some(Err(e.into()));
        }
        let file = file.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        let name = {
            if name == "$." {
                SecretString::from_str(".").unwrap()
            } else if name == "$.." {
                SecretString::from_str("..").unwrap()
            } else {
                crypto_util::decrypt_and_unnormalize_end_file_name(&name, &self.2, &self.3)
            }
        };
        let res: bincode::Result<(u64, FileType)> = bincode::deserialize_from(crypto_util::create_decryptor(file, &self.2, &self.3));
        if let Err(e) = res {
            error!(err = %e, "deserializing directory entry");
            return Some(Err(e.into()));
        }
        let (ino, kind): (u64, FileType) = res.unwrap();

        let map_guard_ino = self.5.read().unwrap();
        let lock_ino = map_guard_ino.get_or_insert_with(ino, || std::sync::RwLock::new(false));
        let _guard_ino = lock_ino.read().unwrap();

        let file = File::open(&self.1.join(ino.to_string()));
        if let Err(e) = file {
            error!(err = %e, "opening file");
            return Some(Err(e.into()));
        }
        let file = file.unwrap();
        let attr = bincode::deserialize_from(crypto_util::create_decryptor(file, &self.2, &self.3));
        if let Err(e) = attr {
            error!(err = %e, "deserializing file attr");
            return Some(Err(e.into()));
        }
        let attr = attr.unwrap();
        Some(Ok(DirectoryEntryPlus {
            ino,
            name,
            kind,
            attr,
        }))
    }
}

fn key_serialize<S>(key: &SecretVec<u8>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.collect_seq(key.expose_secret())
}

fn key_unserialize<'de, D>(deserializer: D) -> Result<SecretVec<u8>, D::Error>
    where D: Deserializer<'de> {
    let vec = Vec::deserialize(deserializer)?;
    Ok(SecretVec::new(vec))
}

#[derive(Serialize, Deserialize)]
struct KeyStore {
    #[serde(serialize_with = "key_serialize")]
    #[serde(deserialize_with = "key_unserialize")]
    key: SecretVec<u8>,
    hash: [u8; 32],
}

impl KeyStore {
    fn new(key: SecretVec<u8>) -> Self {
        let hash = crypto_util::hash(key.expose_secret());
        Self { key, hash }
    }
}

struct ReadHandleContext {
    ino: u64,
    attr: TimeAndSizeFileAttr,
    pos: u64,
    decryptor: Option<Decryptor<File>>,
    _lock: Guard<Mutex<bool>>, // we don't use it but just keep a reference to keep it alive in `read_write_inode_locks` while handle is open
}

enum ReadHandleContextOperation<'a> {
    Create {
        ino: u64,
        lock: Guard<Mutex<bool>>,
    },
    RecreateDecryptor {
        existing: MutexGuard<'a, ReadHandleContext>,
    },
}

impl ReadHandleContextOperation<'_> {
    fn get_ino(&self) -> u64 {
        match *self {
            ReadHandleContextOperation::Create { ino, .. } => ino,
            ReadHandleContextOperation::RecreateDecryptor { ref existing } => existing.ino,
        }
    }
}

enum WriteHandleContextOperation<'a> {
    Create {
        ino: u64,
        lock: Guard<Mutex<bool>>,
    },
    RecreateEncryptor {
        existing: MutexGuard<'a, WriteHandleContext>,
        reset_size: bool,
    },
}

impl WriteHandleContextOperation<'_> {
    fn get_ino(&self) -> u64 {
        match *self {
            WriteHandleContextOperation::Create { ino, .. } => ino,
            WriteHandleContextOperation::RecreateEncryptor { ref existing, .. } => existing.ino,
        }
    }
}

struct WriteHandleContext {
    ino: u64,
    attr: TimeAndSizeFileAttr,
    path: PathBuf,
    pos: u64,
    encryptor: Option<Encryptor<File>>,
    _lock: Guard<Mutex<bool>>, // we don't use it but just keep a reference to keep it alive in `read_write_inode_locks` while handle is open
}

struct KeyProvider {
    path: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
}

impl expire_value::Provider<SecretVec<u8>, FsError> for KeyProvider {
    fn provide(&self) -> Result<SecretVec<u8>, FsError> {
        let password = self.password_provider.get_password().ok_or(FsError::InvalidPassword)?;
        EncryptedFs::read_or_create_key(&self.path, &password, &self.cipher)
    }
}

pub trait PasswordProvider: Send + Sync + 'static {
    fn get_password(&self) -> Option<SecretString>;
}

/// Encrypted FS that stores encrypted files in a dedicated directory with a specific structure based on `inode`.
pub struct EncryptedFs {
    pub(crate) data_dir: PathBuf,
    write_handles: RwLock<HashMap<u64, Mutex<WriteHandleContext>>>,
    read_handles: RwLock<HashMap<u64, Mutex<ReadHandleContext>>>,
    current_handle: AtomicU64,
    cipher: Cipher,
    // (ino, fh)
    opened_files_for_read: RwLock<HashMap<u64, HashSet<u64>>>,
    opened_files_for_write: RwLock<HashMap<u64, u64>>,
    // used for rw ops of actual serialization
    serialize_inode_locks: Arc<std::sync::RwLock<ArcHashMap<u64, std::sync::RwLock<bool>>>>,
    // used for the update op
    serialize_update_inode_locks: Mutex<ArcHashMap<u64, Mutex<bool>>>,
    serialize_dir_entries_locks: Arc<std::sync::RwLock<ArcHashMap<String, std::sync::RwLock<bool>>>>,
    read_write_inode_locks: Mutex<ArcHashMap<u64, Mutex<bool>>>,
    key: ExpireValue<SecretVec<u8>, FsError, KeyProvider>,
}

#[cfg(test)]
const BUF_SIZE: usize = 256 * 1024;
// 256 KB buffer, smaller for tests because they all run in parallel
#[cfg(not(test))]
const BUF_SIZE: usize = 1024 * 1024; // 1 MB buffer

impl EncryptedFs {
    pub async fn new(data_dir: &str, password_provider: Box<dyn PasswordProvider>, cipher: Cipher) -> FsResult<Self> {
        let path = PathBuf::from(&data_dir);

        let key_provider = KeyProvider {
            path: path.join(SECURITY_DIR).join(KEY_ENC_FILENAME),
            password_provider,
            cipher: cipher.clone(),
        };

        ensure_structure_created(&path.clone(), &key_provider).await?;

        let fs = EncryptedFs {
            data_dir: path.clone(),
            write_handles: RwLock::new(HashMap::new()),
            read_handles: RwLock::new(HashMap::new()),
            current_handle: AtomicU64::new(1),
            cipher,
            opened_files_for_read: RwLock::new(HashMap::new()),
            opened_files_for_write: RwLock::new(HashMap::new()),
            read_write_inode_locks: Mutex::new(ArcHashMap::new()),
            serialize_inode_locks: Arc::new(std::sync::RwLock::new(ArcHashMap::new())),
            serialize_update_inode_locks: Mutex::new(ArcHashMap::new()),
            serialize_dir_entries_locks: Arc::new(std::sync::RwLock::new(ArcHashMap::new())),
            // todo: take duration from param
            key: ExpireValue::new(key_provider, Duration::from_secs(10 * 60)).await,
        };

        let _ = fs.ensure_root_exists().await;

        Ok(fs)
    }

    pub fn node_exists(&self, ino: u64) -> bool {
        let path = self.data_dir.join(INODES_DIR).join(ino.to_string());
        path.is_file()
    }

    pub fn is_dir(&self, ino: u64) -> bool {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        path.is_dir()
    }

    pub fn is_file(&self, ino: u64) -> bool {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        path.is_file()
    }

    /// Create a new node in the filesystem
    pub async fn create_nod(&self, parent: u64, name: &SecretString, create_attr: CreateFileAttr, read: bool, write: bool) -> FsResult<(u64, FileAttr)> {
        if name.expose_secret() == "." || name.expose_secret() == ".." {
            return Err(FsError::InvalidInput("name cannot be '.' or '..'".to_string()));
        }
        if !self.node_exists(parent) {
            return Err(FsError::InodeNotFound);
        }
        if self.find_by_name(parent, name).await?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let mut attr: FileAttr = create_attr.into();
        attr.ino = self.generate_next_inode();

        // write inode
        self.write_inode_to_storage(&attr, &*self.key.get().await?).await?;

        // create in contents directory
        match attr.kind {
            FileType::RegularFile => {
                let path = self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string());
                // create the file
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)?;
            }
            FileType::Directory => {
                // create the directory
                tokio::fs::create_dir(self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).await?;

                // add "." and ".." entries
                self.insert_directory_entry(attr.ino, DirectoryEntry {
                    ino: attr.ino,
                    name: SecretString::from_str("$.").unwrap(),
                    kind: FileType::Directory,
                }, &*self.key.get().await?).await?;
                self.insert_directory_entry(attr.ino, DirectoryEntry {
                    ino: parent,
                    name: SecretString::from_str("$..").unwrap(),
                    kind: FileType::Directory,
                }, &*self.key.get().await?).await?;
            }
        }

        // edd entry in parent directory, used for listing
        self.insert_directory_entry(parent, DirectoryEntry {
            ino: attr.ino,
            name: SecretString::new(name.expose_secret().to_owned()),
            kind: attr.kind,
        }, &*self.key.get().await?).await?;
        self.update_inode(parent, SetFileAttr::default()
            .with_mtime(SystemTime::now())
            .with_ctime(SystemTime::now())).await?;

        let handle = if attr.kind == FileType::RegularFile {
            if read || write {
                self.open(attr.ino, read, write).await?
            } else {
                // we don't create handle for files that are not opened
                0
            }
        } else {
            // we don't use handle for directories
            0
        };

        Ok((handle, attr))
    }

    pub async fn find_by_name(&self, parent: u64, name: &SecretString) -> FsResult<Option<FileAttr>> {
        if !self.node_exists(parent) {
            return Err(FsError::InodeNotFound);
        }
        if !self.exists_by_name(parent, name).await? {
            return Ok(None);
        }
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }
        let name = {
            if name.expose_secret() == "." {
                SecretString::from_str("$.").unwrap()
            } else if name.expose_secret() == ".." {
                SecretString::from_str("$..").unwrap()
            } else {
                SecretString::new(name.expose_secret().to_owned())
            }
        };
        let name = crypto_util::normalize_end_encrypt_file_name(&name, &self.cipher, &*self.key.get().await?);
        let file = File::open(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name))?;
        let (inode, _): (u64, FileType) = bincode::deserialize_from(crypto_util::create_decryptor(file, &self.cipher, &*self.key.get().await?))?;
        Ok(Some(self.get_inode(inode).await?))
    }

    /// Count children of a directory. This includes also `.` and `..`.
    pub async fn children_count(&self, ino: u64) -> FsResult<usize> {
        let iter = self.read_dir(ino).await?;
        Ok(iter.into_iter().count())
    }

    pub async fn remove_dir(&self, parent: u64, name: &SecretString) -> FsResult<()> {
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }

        if !self.exists_by_name(parent, name).await? {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        let attr = self.find_by_name(parent, name).await?.ok_or(FsError::NotFound("name not found".to_string()))?;
        if !matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }
        // check if it's empty
        let iter = self.read_dir(attr.ino).await?;
        let count_children = iter.into_iter().take(3).count();
        if count_children > 2 {
            return Err(FsError::NotEmpty);
        }

        let ino_str = attr.ino.to_string();

        // remove inode file
        {
            let map = self.serialize_inode_locks.write().unwrap();
            let lock = map.get_or_insert_with(attr.ino, || std::sync::RwLock::new(false));
            let _guard = lock.write().unwrap();
            fs::remove_file(self.data_dir.join(INODES_DIR).join(&ino_str))?;
        }

        // remove contents directory
        tokio::fs::remove_dir_all(self.data_dir.join(CONTENTS_DIR).join(&ino_str)).await?;
        // remove from parent directory
        self.remove_directory_entry(parent, name).await?;

        self.update_inode(parent, SetFileAttr::default()
            .with_mtime(SystemTime::now())
            .with_ctime(SystemTime::now())).await?;

        Ok(())
    }

    pub async fn remove_file(&self, parent: u64, name: &SecretString) -> FsResult<()> {
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.exists_by_name(parent, name).await? {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        let attr = self.find_by_name(parent, name).await?.ok_or(FsError::NotFound("name not found".to_string()))?;
        if !matches!(attr.kind, FileType::RegularFile) {
            return Err(FsError::InvalidInodeType);
        }
        let ino_str = attr.ino.to_string();

        // remove inode file
        {
            let map = self.serialize_inode_locks.write().unwrap();
            let lock = map.get_or_insert_with(attr.ino, || std::sync::RwLock::new(false));
            let _guard = lock.write().unwrap();
            fs::remove_file(self.data_dir.join(INODES_DIR).join(&ino_str))?;
        }

        // remove contents file
        tokio::fs::remove_file(self.data_dir.join(CONTENTS_DIR).join(&ino_str)).await?;
        // remove from parent directory
        // remove from parent contents
        self.remove_directory_entry(parent, name).await?;

        self.update_inode(parent, SetFileAttr::default()
            .with_mtime(SystemTime::now())
            .with_ctime(SystemTime::now())).await?;

        Ok(())
    }

    pub async fn exists_by_name(&self, parent: u64, name: &SecretString) -> FsResult<bool> {
        let name = {
            if name.expose_secret() == "." {
                SecretString::from_str("$.").unwrap()
            } else if name.expose_secret() == ".." {
                SecretString::from_str("$..").unwrap()
            } else {
                SecretString::new(name.expose_secret().to_owned())
            }
        };
        let name = crypto_util::normalize_end_encrypt_file_name(&name, &self.cipher, &*self.key.get().await?);
        Ok(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name).exists())
    }

    pub async fn read_dir(&self, ino: u64) -> FsResult<DirectoryEntryIterator> {
        let contents_dir = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        if !contents_dir.is_dir() {
            return Err(FsError::InvalidInodeType);
        }

        let iter = fs::read_dir(contents_dir)?;
        Ok(DirectoryEntryIterator(iter.into_iter(), self.cipher.clone(), self.key.get().await?, self.serialize_dir_entries_locks.clone()))
    }

    /// Like [read_dir](EncryptedFs::read_dir) but with [FileAttr] so we don't need to query again for those.
    pub async fn read_dir_plus(&self, ino: u64) -> FsResult<DirectoryEntryPlusIterator> {
        let contents_dir = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        if !contents_dir.is_dir() {
            return Err(FsError::InvalidInodeType);
        }

        let iter = fs::read_dir(contents_dir)?;
        Ok(DirectoryEntryPlusIterator(iter.into_iter(), self.data_dir.join(INODES_DIR), self.cipher.clone(), self.key.get().await?,
                                      self.serialize_dir_entries_locks.clone(), self.serialize_inode_locks.clone()))
    }

    async fn get_inode_from_storage(&self, ino: u64, key: &SecretVec<u8>) -> FsResult<FileAttr> {
        let map_guard = self.serialize_inode_locks.read().unwrap();
        let lock = map_guard.get_or_insert_with(ino, || std::sync::RwLock::new(false));
        let _guard = lock.read().unwrap();

        let path = self.data_dir.join(INODES_DIR).join(ino.to_string());
        let file = OpenOptions::new().read(true).write(true).open(path).map_err(|_| { FsError::InodeNotFound })?;
        Ok(bincode::deserialize_from::<Decryptor<File>, FileAttr>(crypto_util::create_decryptor(file, &self.cipher, key))?)
    }

    pub async fn get_inode(&self, ino: u64) -> FsResult<FileAttr> {
        debug!("get inode");
        let mut attr = self.get_inode_from_storage(ino, &*self.key.get().await?).await?;

        // merge time info and size with any open read handles
        let open_reads = { self.opened_files_for_read.read().await.contains_key(&ino) };
        if open_reads {
            let fhs = self.opened_files_for_read.read().await.get(&ino).map(|v| v.clone());
            if let Some(fhs) = fhs {
                for fh in fhs {
                    if let Some(ctx) = self.read_handles.read().await.get(&fh) {
                        let ctx = ctx.lock().await;
                        merge_attr(&mut attr, ctx.attr.clone().into());
                    }
                }
            }
        }

        // merge time info and size with any open write handles
        let open_writes = { self.opened_files_for_write.read().await.contains_key(&ino) };
        if open_writes {
            let fh = self.opened_files_for_write.read().await.get(&ino).map(|v| *v);
            if let Some(fh) = fh {
                if let Some(ctx) = self.write_handles.read().await.get(&fh) {
                    let ctx = ctx.lock().await;
                    merge_attr(&mut attr, ctx.attr.clone().into());
                }
            }
        }

        Ok(attr)
    }

    pub async fn update_inode(&self, ino: u64, set_attr: SetFileAttr) -> FsResult<()> {
        let map_serialize_update = self.serialize_update_inode_locks.lock().await;
        let lock_serialize_update = map_serialize_update.get_or_insert_with(ino, || Mutex::new(false));
        let _guard_serialize_update = lock_serialize_update.lock().await;

        let mut attr = self.get_inode(ino).await?;
        merge_attr(&mut attr, set_attr);

        self.write_inode_to_storage(&attr, &*self.key.get().await?).await?;
        Ok(())
    }

    async fn write_inode_to_storage(&self, attr: &FileAttr, key: &SecretVec<u8>) -> Result<(), FsError> {
        let map = self.serialize_inode_locks.write().unwrap();
        let lock = map.get_or_insert_with(attr.ino, || std::sync::RwLock::new(false));
        let _guard = lock.write().unwrap();

        let path = self.data_dir.join(INODES_DIR).join(attr.ino.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        bincode::serialize_into(crypto_util::create_encryptor(file, &self.cipher, key), &attr)?;
        Ok(())
    }

    /// Read the contents from an 'offset'. If we try to read outside of file size, we return 0 bytes.
    /// Depending on the encryption type we might need to re-read bytes until the 'offset', in some case even
    /// from the beginning of the file to the desired `offset`. This will slow down the read operation if we
    /// read from very distanced offsets.
    /// The most speed is obtained when we read sequentially from the beginning of the file.
    /// If the file is not opened for read, it will return an error of type ['FsError::InvalidFileHandle'].
    #[instrument(skip(self, buf))]
    pub async fn read(&self, ino: u64, offset: u64, mut buf: &mut [u8], handle: u64) -> FsResult<usize> {
        debug!("read");
        // lock for reading
        let lock = {
            let map_guard = self.read_write_inode_locks.lock().await;
            map_guard.get_or_insert_with(ino, || Mutex::new(false))
        };
        let _guard = lock.lock().await;

        if !self.node_exists(ino) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_file(ino) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.read_handles.read().await.contains_key(&handle) {
            return Err(FsError::InvalidFileHandle);
        }

        let guard = self.read_handles.read().await;
        let mut ctx = guard.get(&handle).unwrap().lock().await;

        if ctx.ino != ino {
            return Err(FsError::InvalidFileHandle);
        }
        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }
        if buf.len() == 0 {
            // no-op
            return Ok(0);
        }
        if offset >= ctx.attr.size {
            // if we need an offset after file size we don't read anything
            return Ok(0);
        }

        if ctx.pos != offset {
            debug!("seeking to offset {} from {}", offset.to_formatted_string(&Locale::en), ctx.pos.to_formatted_string(&Locale::en));
            // in order to seek we need to read the bytes from current position until the offset
            if ctx.pos > offset {
                // if we need an offset before the current position, we can't seek back, we need
                // to read from the beginning until the desired offset
                debug!("seeking back, recreating decryptor");
                self.do_with_read_handle(handle, ReadHandleContextOperation::RecreateDecryptor { existing: ctx }).await?;
                ctx = guard.get(&handle).unwrap().lock().await;
            }
            if offset > 0 {
                debug!("reading from current position to offset");
                let mut buffer = vec![0; BUF_SIZE];
                loop {
                    let read_len = if ctx.pos + buffer.len() as u64 > offset {
                        (offset - ctx.pos) as usize
                    } else {
                        buffer.len()
                    };
                    debug!(read_len = read_len.to_formatted_string(&Locale::en), "reading");
                    if read_len > 0 {
                        ctx.decryptor.as_mut().unwrap().read_exact(&mut buffer[..read_len])?;
                        ctx.pos += read_len as u64;
                        if ctx.pos == offset {
                            break;
                        }
                        debug!(pos = ctx.pos.to_formatted_string(&Locale::en), offset = offset.to_formatted_string(&Locale::en), "read");
                    } else {
                        break;
                    }
                }
            }
        }
        if offset + buf.len() as u64 > ctx.attr.size {
            buf = &mut buf[..(ctx.attr.size - offset) as usize];
        }
        ctx.decryptor.as_mut().unwrap().read_exact(&mut buf)?;
        ctx.pos += buf.len() as u64;

        ctx.attr.atime = SystemTime::now();

        Ok(buf.len())
    }

    pub async fn release(&self, handle: u64) -> FsResult<()> {
        debug!("release");
        if handle == 0 {
            // in case of directory or if the file was crated without being opened we don't use handle
            return Ok(());
        }
        let mut valid_fh = false;

        // read
        let ctx = { self.read_handles.write().await.remove(&handle) };
        if let Some(ctx) = ctx {
            let mut ctx = ctx.lock().await;

            // write attr only here to avoid serializing it multiple times while reading
            // it will merge time fields with existing data because it might got change while we kept the handle
            self.update_inode(ctx.ino, ctx.attr.clone().into()).await?;

            ctx.decryptor.take().unwrap().finish();
            let mut opened_files_for_read = self.opened_files_for_read.write().await;
            opened_files_for_read.get_mut(&ctx.ino).and_then(|set| {
                set.remove(&handle);
                Some(())
            });
            if opened_files_for_read.get(&ctx.ino).unwrap().is_empty() {
                opened_files_for_read.remove(&ctx.ino);
            }

            valid_fh = true;
        }

        // write
        let ctx = { self.write_handles.write().await.remove(&handle) };
        if let Some(ctx) = ctx {
            let mut ctx = ctx.lock().await;

            // if we have dirty content (ctx.pos > 0) and position is before file end we copy the rest of the file from position to the end
            if ctx.pos > 0 && ctx.pos < ctx.attr.size {
                debug!("dirty content, copying remaining of file");
                let ino_str = ctx.ino.to_string();
                let file_size = ctx.attr.size;
                Self::copy_remaining_of_file(&mut ctx, file_size, &self.cipher, &*self.key.get().await?, self.data_dir.join(CONTENTS_DIR).join(ino_str))?;
            }

            debug!("finishing encryptwarnor");
            ctx.encryptor.take().unwrap().finish()?;
            // if we are in tmp file move it to actual file
            let mut recreate_readers = false;
            if ctx.path.to_str().unwrap().ends_with(".tmp") {
                debug!("renaming file");
                tokio::fs::rename(ctx.path.clone(), self.data_dir.join(CONTENTS_DIR).join(ctx.ino.to_string())).await?;

                // also recreate readers because the file has changed
                recreate_readers = true;
            }
            self.opened_files_for_write.write().await.remove(&ctx.ino);

            // write attr only here to avoid serializing it multiple times while writing
            // it will merge time fields with existing data because it might got change while we kept the handle
            self.update_inode(ctx.ino, ctx.attr.clone().into()).await?;

            if recreate_readers {
                self.recreate_handles(ctx.ino, None).await?;
            }

            valid_fh = true;
        }
        if !valid_fh {
            return Err(FsError::InvalidFileHandle);
        }
        debug!(serialize_inode_locks.size = self.serialize_inode_locks.read().unwrap().len());
        debug!(serialize_update_inode_locks.size = self.serialize_update_inode_locks.lock().await.len());
        debug!(read_write_inode_locks.size = self.read_write_inode_locks.lock().await.len());
        Ok(())
    }

    /// Check if a file is opened for read with this handle.
    pub async fn is_read_handle(&self, fh: u64) -> bool {
        self.read_handles.read().await.contains_key(&fh)
    }

    /// Check if a file is opened for write with this handle.
    pub async fn is_write_handle(&self, fh: u64) -> bool {
        self.write_handles.read().await.contains_key(&fh)
    }

    /// Writes the contents of `buf` to the file at `ino` starting at `offset`.
    /// Depending on the encryption type we might need to re-write bytes until the 'offset', in some case even
    /// from the beginning of the file to the desired `offset`. This will slow down the write operation if we
    /// write to very distanced offsets.
    /// The most speed is obtained when we write sequentially from the beginning of the file.
    /// If we write outside of file size, we fill up with zeros until offset.
    /// If the file is not opened for write, it will return an error of type ['FsError::InvalidFileHandle'].
    #[instrument(skip(self, buf))]
    pub async fn write_all(&self, ino: u64, offset: u64, buf: &[u8], handle: u64) -> FsResult<()> {
        debug!("write_all");
        // lock for writing
        let lock = {
            let map_guard = self.read_write_inode_locks.lock().await;
            map_guard.get_or_insert_with(ino, || Mutex::new(false))
        };
        let _guard = lock.lock().await;
        debug!("ptr {:p}", lock.deref());

        if !self.node_exists(ino) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_file(ino) {
            return Err(FsError::InvalidInodeType);
        }
        {
            if !self.write_handles.read().await.contains_key(&handle) {
                return Err(FsError::InvalidFileHandle);
            }
        }

        // write lock to avoid writing from multiple threads
        // let binding = self.get_read_write_inode_lock(ino).await;
        // let _guard = binding.write();
        debug!("write_all after lock");

        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }
        {
            let guard = self.write_handles.read().await;
            let ctx = guard.get(&handle).unwrap().lock().await;
            if ctx.ino != ino {
                return Err(FsError::InvalidFileHandle);
            }
        }
        if buf.len() == 0 {
            // no-op
            return Ok(());
        }

        let (path, pos, ino, size) = {
            let guard = self.write_handles.read().await;
            let ctx = guard.get(&handle).unwrap().lock().await;
            (ctx.path.clone(), ctx.pos, ctx.ino, ctx.attr.size)
        };
        if pos != offset {
            debug!("seeking to offset {} from pos {}",offset.to_formatted_string(&Locale::en),pos.to_formatted_string(&Locale::en));
            if pos < offset && pos > 0 {
                debug!("seeking forward");
                // we can seek forward only if we have dirty writer
                // we do that by copying the rest of the file from current position to the desired offset
                let guard = self.write_handles.read().await;
                let mut ctx = guard.get(&handle).unwrap().lock().await;
                let ino_str = ino.to_string();
                Self::copy_remaining_of_file(&mut ctx, offset, &self.cipher, &*self.key.get().await?, self.data_dir.join(CONTENTS_DIR).join(ino_str))?;
            } else {
                debug!("seeking backward or from the beginning of the file");
                // we need to seek backward, or we can't seek forward, but we cannot do that, we need to recreate all stream from the beginning until the desired offset
                // for that we create a new encryptor into a tmp file reading from original file and writing to tmp one
                // when we release the handle we will move this tmp file to the actual file

                // if we have dirty content (ctx.pos > 0) and position is before file end we copy the rest of the file from position to the end
                if pos > 0 && pos < size {
                    debug!("dirty content, copying remaining of file");
                    let ino_str = ino.to_string();
                    let file_size = size;
                    let guard = self.write_handles.read().await;
                    let mut ctx = guard.get(&handle).unwrap().lock().await;
                    Self::copy_remaining_of_file(&mut ctx, file_size, &self.cipher, &*self.key.get().await?, self.data_dir.join(CONTENTS_DIR).join(ino_str))?;
                }
                {
                    let guard = self.write_handles.read().await;
                    let mut ctx = guard.get(&handle).unwrap().lock().await;
                    // finish the current writer so we flush all data to the file
                    debug!("finishing current writer");
                    ctx.encryptor.take().unwrap().finish()?;
                }

                // if we are already in the tmp file first copy tmp to actual file
                if path.to_str().unwrap().ends_with(".tmp") {
                    debug!("renaming tmp file to actual file");
                    tokio::fs::rename(path.clone(), self.data_dir.join(CONTENTS_DIR).join(ino.to_string())).await?;

                    // update metadata
                    let (ino, attr) = {
                        let guard = self.write_handles.read().await;
                        let ctx = guard.get(&handle).unwrap().lock().await;
                        (ctx.ino, ctx.attr.clone())
                    };
                    self.update_inode(ino, attr.into()).await?;

                    // also recreate readers because the file has changed
                    self.recreate_handles(ino, Some(HashSet::from([handle])))
                        .await?;
                }

                let guard = self.write_handles.read().await;
                let mut ctx = guard.get(&handle).unwrap().lock().await;

                let tmp_path_str = format!("{}.{}.tmp", ctx.ino.to_string(), &handle.to_string());
                let tmp_path = self.data_dir.join(CONTENTS_DIR).join(tmp_path_str);
                let tmp_file = OpenOptions::new().write(true).create(true).truncate(true).open(tmp_path.clone())?;

                let encryptor =
                    crypto_util::create_encryptor(tmp_file, &self.cipher, &*self.key.get().await?);
                debug!("recreating encryptor");
                ctx.encryptor.replace(encryptor);
                ctx.pos = 0;
                ctx.path = tmp_path;
                let ino_str = ctx.ino.to_string();
                Self::copy_remaining_of_file(&mut ctx, offset, &self.cipher, &*self.key.get().await?, self.data_dir.join(CONTENTS_DIR).join(ino_str))?;
            }

            let guard = self.write_handles.read().await;
            let mut ctx = guard.get(&handle).unwrap().lock().await;
            // if offset is after current position (max file size) we fill up with zeros until offset
            if offset > ctx.pos {
                debug!("filling up with zeros until offset");
                let buffer = vec![0; BUF_SIZE];
                loop {
                    let len = min(buffer.len(), (offset - ctx.pos) as usize);
                    ctx.encryptor.as_mut().unwrap().write_all(&buffer[..len])?;
                    ctx.pos += len as u64;
                    if ctx.pos == offset {
                        break;
                    }
                }
            }
        }

        let guard = self.write_handles.read().await;
        let mut ctx = guard.get(&handle).unwrap().lock().await;

        // now write the new data
        debug!("writing new data");
        ctx.encryptor.as_mut().unwrap().write_all(buf)?;
        ctx.pos += buf.len() as u64;

        if ctx.pos > ctx.attr.size {
            // if we write pass file size set the new size
            debug!("setting new file size {}", ctx.pos);
            ctx.attr.size = ctx.pos;
        }
        let actual_file_size = fs::metadata(ctx.path.clone())?.len();
        debug!("new file size {} actual size {}", ctx.attr.size.to_formatted_string(&Locale::en), actual_file_size.to_formatted_string(&Locale::en));
        ctx.attr.mtime = SystemTime::now();
        ctx.attr.ctime = SystemTime::now();

        Ok(())
    }

    #[instrument(skip(ctx, key))]
    fn copy_remaining_of_file(ctx: &mut MutexGuard<WriteHandleContext>, mut end_offset: u64, cipher: &Cipher, key: &SecretVec<u8>, file: PathBuf) -> Result<(), FsError> {
        debug!("copy_remaining_of_file from file {}", file.to_str().unwrap());
        let actual_file_size = fs::metadata(ctx.path.clone())?.len();
        debug!("copy_remaining_of_file from {} to {}, file size {} actual file size {}", ctx.pos.to_formatted_string(&Locale::en), end_offset.to_formatted_string(&Locale::en), ctx.attr.size.to_formatted_string(&Locale::en), actual_file_size.to_formatted_string(&Locale::en));
        // keep offset in file size bounds
        if end_offset > ctx.attr.size {
            debug!("end offset {} is bigger than file size {}", end_offset.to_formatted_string(&Locale::en), ctx.attr.size.to_formatted_string(&Locale::en));
            end_offset = ctx.attr.size;
        }
        if ctx.pos == end_offset {
            debug!("no need to copy, pos {} end_offset {}", ctx.pos.to_formatted_string(&Locale::en), end_offset.to_formatted_string(&Locale::en));
            // no-op
            return Ok(());
        }
        // create a new decryptor by reading from the beginning of the file
        let mut decryptor = crypto_util::create_decryptor(OpenOptions::new().read(true).open(file)?, cipher, key);
        // move read position to the write position
        if ctx.pos > 0 {
            let mut buffer = vec![0; BUF_SIZE];
            let mut read_pos = 0u64;
            loop {
                let len = min(buffer.len(), (ctx.pos - read_pos) as usize);
                decryptor.read_exact(&mut buffer[..len]).map_err(|err| {
                    error!("error reading from file pos {} read_pos {} len {} file size {} actual file size {}",
                        ctx.pos.to_formatted_string(&Locale::en), read_pos.to_formatted_string(&Locale::en), len.to_formatted_string(&Locale::en), ctx.attr.size.to_formatted_string(&Locale::en), actual_file_size.to_formatted_string(&Locale::en));
                    err
                })?;
                read_pos += len as u64;
                if read_pos == ctx.pos {
                    break;
                }
            }
        }

        // copy the rest of the file
        let mut buffer = vec![0; BUF_SIZE];
        loop {
            let len = min(buffer.len(), (end_offset - ctx.pos) as usize);
            decryptor.read_exact(&mut buffer[..len]).map_err(|err| {
                debug!("error reading from file pos {} len {} {end_offset} file size {} actual file size {}",
                    ctx.pos.to_formatted_string(&Locale::en), len.to_formatted_string(&Locale::en), ctx.attr.size.to_formatted_string(&Locale::en), actual_file_size.to_formatted_string(&Locale::en));
                err
            })?;
            ctx.encryptor.as_mut().unwrap().write_all(&buffer[..len])?;
            ctx.pos += len as u64;
            if ctx.pos == end_offset {
                break;
            }
        }
        decryptor.finish();
        Ok(())
    }

    /// Flush the data to the underlying storage.
    pub async fn flush(&self, handle: u64) -> FsResult<()> {
        if handle == 0 {
            // in case of directory or if the file was crated without being opened we don't use handle
            return Ok(());
        }
        if let Some(_) = self.read_handles.read().await.get(&handle) {
            return Ok(());
        }
        if let Some(ctx) = self.write_handles.read().await.get(&handle) {
            ctx.lock().await.encryptor.as_mut().unwrap().flush()?;
            return Ok(());
        }

        Err(FsError::InvalidFileHandle)
    }

    /// Helpful when we want to copy just some portions of the file.
    pub async fn copy_file_range(&self, src_ino: u64, src_offset: u64, dest_ino: u64, dest_offset: u64, size: usize, src_fh: u64, dest_fh: u64) -> FsResult<usize> {
        if self.is_dir(src_ino) || self.is_dir(dest_ino) {
            return Err(FsError::InvalidInodeType);
        }

        let mut buf = vec![0; size];
        let len = self.read(src_ino, src_offset, &mut buf, src_fh).await?;
        self.write_all(dest_ino, dest_offset, &buf[..len], dest_fh).await?;

        Ok(len)
    }

    /// Open a file. We can open multiple times for read but only one for write at a time.
    pub async fn open(&self, ino: u64, read: bool, write: bool) -> FsResult<u64> {
        if !read && !write {
            return Err(FsError::InvalidInput("read and write cannot be false at the same time".to_string()));
        }
        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }

        let map_guard = self.read_write_inode_locks.lock().await;
        let mut handle = 0_u64;
        if read {
            let lock = map_guard.get_or_insert_with(ino, || Mutex::new(false));
            handle = self.allocate_next_handle();
            self.do_with_read_handle(handle, ReadHandleContextOperation::Create { ino, lock }).await?;
        }
        if write {
            let lock = map_guard.get_or_insert_with(ino, || Mutex::new(false));
            handle = self.allocate_next_handle();
            let res = self.do_with_write_handle(handle, WriteHandleContextOperation::Create { ino, lock }).await;
            if res.is_err() && read {
                // on error remove the read handle if it was added above
                // remove the read handle if it was added above
                self.read_handles.write().await.remove(&handle);
                return Err(FsError::AlreadyOpenForWrite);
            }
            res?;
        }
        Ok(handle)
    }

    pub async fn truncate(&self, ino: u64, size: u64) -> FsResult<()> {
        let lock = {
            let map_guard = self.read_write_inode_locks.lock().await;
            map_guard.get_or_insert_with(ino, || Mutex::new(false))
        };
        let _guard = lock.lock().await;

        let mut attr = self.get_inode(ino).await?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        if size == attr.size {
            // no-op
            return Ok(());
        } else if size == 0 {
            debug!("truncate to zero");
            // truncate to zero
            OpenOptions::new().write(true).create(true).truncate(true).open(self.data_dir.join(CONTENTS_DIR).join(ino.to_string()))?;
        } else if size < attr.size {
            debug!("truncate decrease size to {}", size.to_formatted_string(&Locale::en));
            // decrease size, copy from beginning until size as offset

            // if we have opened writers before the truncated size, flush those
            self.flush_writers(ino).await?;

            let in_path = self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string());
            let in_file = OpenOptions::new().read(true).write(true).open(in_path.clone())?;
            let key = self.key.get().await?;
            let mut decryptor = crypto_util::create_decryptor(in_file, &self.cipher, &*key);

            let tmp_path_str = format!("{}.truncate.tmp", attr.ino.to_string());
            let tmp_path = self.data_dir.join(CONTENTS_DIR).join(tmp_path_str);
            let tmp_file = OpenOptions::new().write(true).create(true).truncate(true).open(tmp_path.clone())?;
            let mut encryptor = crypto_util::create_encryptor(tmp_file, &self.cipher, &*key);

            // copy existing data until new size
            debug!("copying data until new size");
            let mut buf = vec![0; BUF_SIZE];
            let mut pos = 0_u64;
            loop {
                let len = min(buf.len(), (size - pos) as usize);
                decryptor.read_exact(&mut buf[..len])?;
                encryptor.write_all(&buf[..len])?;
                pos += len as u64;
                if pos == size {
                    break;
                }
            }
            debug!("rename from tmp file");
            tokio::fs::rename(tmp_path, self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).await?;
        } else {
            debug!("truncate increase size to {}", size.to_formatted_string(&Locale::en));
            // increase size, write zeros from actual size to new size

            // if we have opened writers, flush those
            self.flush_writers(ino).await?;

            let in_path = self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string());
            let in_file = OpenOptions::new().read(true).write(true).open(in_path.clone())?;
            let mut decryptor = crypto_util::create_decryptor(in_file, &self.cipher, &*self.key.get().await?);

            let tmp_path_str = format!("{}.truncate.tmp", attr.ino.to_string());
            let tmp_path = self.data_dir.join(CONTENTS_DIR).join(tmp_path_str);
            let tmp_file = OpenOptions::new().write(true).create(true).truncate(true).open(tmp_path.clone())?;
            let mut encryptor = crypto_util::create_encryptor(tmp_file, &self.cipher, &*self.key.get().await?);

            // copy existing data
            debug!("copying existing data");
            let mut buf = vec![0; BUF_SIZE];
            let mut pos = 0_u64;
            loop {
                let len = min(buf.len(), (attr.size - pos) as usize);
                decryptor.read_exact(&mut buf[..len])?;
                encryptor.write_all(&buf[..len])?;
                pos += len as u64;
                if pos == attr.size {
                    break;
                }
            }

            // now fill up with zeros until new size
            debug!("filling up with zeros until new size");
            let buf = vec![0; BUF_SIZE];
            loop {
                let len = min(buf.len(), (size - attr.size) as usize);
                encryptor.write_all(&buf[..len])?;
                attr.size += len as u64;
                if attr.size == size {
                    break;
                }
            }

            encryptor.finish()?;
            debug!("rename from tmp file");
            tokio::fs::rename(tmp_path, self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).await?;
        }

        let set_attr = SetFileAttr::default()
            .with_size(size)
            .with_mtime(SystemTime::now())
            .with_ctime(SystemTime::now());
        debug!("new file size {}", set_attr.size.as_ref().unwrap().to_formatted_string(&Locale::en));
        self.update_inode(ino, set_attr).await?;

        // also recreate handles because the file has changed
        self.recreate_handles(attr.ino, None).await?;

        Ok(())
    }

    /// This will write any dirty data to the file and recreate handles.
    /// > ⚠️ **Warning**
    /// > Need to be called in a context with write lock on `self.read_write_inode_locks.lock().await.get(ino)`.
    async fn flush_writers(&self, ino: u64) -> FsResult<()> {
        debug!("flush_writers");
        let keys: Vec<u64> = self.write_handles.read().await.keys().cloned().collect();
        for key in keys {
            let should_process = {
                let guard = self.write_handles.read().await;
                let v = guard.get(&key);
                if let None = v {
                    false
                } else {
                    let ctx = v.unwrap().lock().await;
                    ctx.ino == ino
                }
            };
            if !should_process {
                continue;
            }
            {
                let guard = self.write_handles.read().await;
                let mut ctx = guard.get(&key).unwrap().lock().await;
                // if we have dirty content (ctx.pos > 0) and position is before file end we copy the rest of the file from position to the end
                if ctx.pos > 0 && ctx.pos < ctx.attr.size {
                    debug!("dirty content, copying remaining of file");
                    let ino_str = ctx.ino.to_string();
                    let file_size = ctx.attr.size;
                    Self::copy_remaining_of_file(&mut ctx, file_size, &self.cipher, &*self.key.get().await?, self.data_dir.join(CONTENTS_DIR).join(ino_str))?;
                }
            }
            {
                let guard = self.write_handles.read().await;
                let mut ctx = guard.get(&key).unwrap().lock().await;
                debug!("finishing current writer");
                ctx.encryptor.take().unwrap().finish()?;
            }
            // if we are in tmp file move it to actual file
            let (path, ino) = {
                let guard = self.write_handles.read().await;
                let ctx = guard.get(&key).unwrap().lock().await;
                (ctx.path.clone(), ctx.ino)
            };
            if path.to_str().unwrap().ends_with(".tmp") {
                debug!("renaming tmp file to actual file");
                tokio::fs::rename(path, self.data_dir.join(CONTENTS_DIR).join(ino.to_string())).await?;
                // also recreate handles because the file has changed
                self.recreate_handles(ino, Some(HashSet::from([key]))).await?;
            }
            // recreate the write handle so opened handle can continue writing
            {
                let guard = self.write_handles.read().await;
                let ctx = guard.get(&key).unwrap().lock().await;
                self.do_with_write_handle(key, WriteHandleContextOperation::RecreateEncryptor { existing: ctx, reset_size: true }).await?;
            }
        }

        Ok(())
    }

    pub async fn rename(&self, parent: u64, name: &SecretString, new_parent: u64, new_name: &SecretString) -> FsResult<()> {
        if !self.node_exists(parent) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.node_exists(new_parent) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_dir(new_parent) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.exists_by_name(parent, name).await? {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        if parent == new_parent && name.expose_secret() == new_name.expose_secret() {
            // no-op
            return Ok(());
        }

        // Only overwrite an existing directory if it's empty
        if let Ok(Some(new_attr)) = self.find_by_name(new_parent, new_name).await {
            if new_attr.kind == FileType::Directory && self.children_count(new_attr.ino).await? > 2 {
                return Err(FsError::NotEmpty);
            }
        }

        let mut attr = self.find_by_name(parent, name).await?.unwrap();
        // remove from parent contents
        self.remove_directory_entry(parent, name).await?;
        // add to new parent contents
        self.insert_directory_entry(new_parent, DirectoryEntry {
            ino: attr.ino,
            name: SecretString::new(new_name.expose_secret().to_owned()),
            kind: attr.kind,
        }, &*self.key.get().await?).await?;

        let mut parent_attr = self.get_inode(parent).await?;
        parent_attr.mtime = SystemTime::now();
        parent_attr.ctime = SystemTime::now();

        let mut new_parent_attr = self.get_inode(new_parent).await?;
        new_parent_attr.mtime = SystemTime::now();
        new_parent_attr.ctime = SystemTime::now();

        attr.ctime = SystemTime::now();

        if attr.kind == FileType::Directory {
            // add parent link to new directory
            self.insert_directory_entry(attr.ino, DirectoryEntry {
                ino: new_parent,
                name: SecretString::from_str("$..").unwrap(),
                kind: FileType::Directory,
            }, &*self.key.get().await?).await?;
        }

        Ok(())
    }

    /// Create an encryptor using internal encryption info.
    pub async fn create_encryptor(&self, file: File) -> FsResult<Encryptor<File>> {
        Ok(crypto_util::create_encryptor(file, &self.cipher, &*self.key.get().await?))
    }

    /// Create a decryptor using internal encryption info.
    pub async fn create_decryptor(&self, file: File) -> FsResult<Decryptor<File>> {
        Ok(crypto_util::create_decryptor(file, &self.cipher, &*self.key.get().await?))
    }

    /// Encrypts a string using internal encryption info.
    pub async fn encrypt_string(&self, s: &SecretString) -> FsResult<String> {
        Ok(crypto_util::encrypt_string(s, &self.cipher, &*self.key.get().await?))
    }

    /// Decrypts a string using internal encryption info.
    pub async fn decrypt_string(&self, s: &str) -> FsResult<SecretString> {
        Ok(crypto_util::decrypt_string(s, &self.cipher, &*self.key.get().await?))
    }

    /// Normalize and encrypt a file name.
    pub async fn normalize_end_encrypt_file_name(&self, name: &SecretString) -> FsResult<String> {
        Ok(crypto_util::normalize_end_encrypt_file_name(name, &self.cipher, &*self.key.get().await?))
    }

    /// Change the password of the filesystem used to access the encryption key.
    pub async fn change_password(data_dir: &str, old_password: SecretString, new_password: SecretString, cipher: Cipher) -> FsResult<()> {
        let data_dir = PathBuf::from(data_dir);

        check_structure(&data_dir, false).await?;

        // decrypt key
        let salt = crypto_util::hash_secret(&old_password);
        let initial_key = crypto_util::derive_key(&old_password, &cipher, salt)?;
        let enc_file = data_dir.join(SECURITY_DIR).join(KEY_ENC_FILENAME);
        let decryptor = crypto_util::create_decryptor(File::open(enc_file.clone())?, &cipher, &initial_key);
        let key_store: KeyStore = bincode::deserialize_from(decryptor).map_err(|_| FsError::InvalidPassword)?;
        // check hash
        if key_store.hash != crypto_util::hash(key_store.key.expose_secret()) {
            return Err(FsError::InvalidPassword);
        }

        // encrypt it with new key derived from new password
        let salt = crypto_util::hash_secret(&new_password);
        let new_key = crypto_util::derive_key(&new_password, &cipher, salt)?;
        tokio::fs::remove_file(enc_file.clone()).await?;
        let mut encryptor = crypto_util::create_encryptor(OpenOptions::new().read(true).write(true).create(true).truncate(true).open(enc_file.clone())?,
                                                          &cipher, &new_key);
        bincode::serialize_into(&mut encryptor, &key_store)?;

        Ok(())
    }

    fn allocate_next_handle(&self) -> u64 {
        self.current_handle.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    async fn recreate_handles(&self, ino: u64, skip: Option<HashSet<u64>>) -> FsResult<()> {
        debug!("recreate_handles");
        let keys: Vec<u64> = self.read_handles.read().await.keys().cloned()
            .filter(|k| if let Some(ref skip) = skip { !skip.contains(k) } else { true })
            .collect();
        for key in keys {
            {
                // using if let to skip if the key was removed from another thread
                if let Some(ctx) = self.read_handles.read().await.get(&key) {
                    if ctx.lock().await.ino != ino {
                        continue;
                    }
                }
            }
            {
                if let Some(ctx) = self.read_handles.read().await.get(&key) {
                    debug!("recreating read handle");
                    self.do_with_read_handle(key, ReadHandleContextOperation::RecreateDecryptor { existing: ctx.lock().await }).await?;
                }
            }
        }

        // write
        let keys: Vec<u64> = self.write_handles.read().await.keys().cloned()
            .filter(|k| if let Some(ref skip) = skip { !skip.contains(k) } else { true })
            .collect();
        for key in keys {
            // using if let to skip if the key was removed from another thread
            if let Some(ctx) = self.write_handles.read().await.get(&key) {
                if ctx.lock().await.ino != ino {
                    continue;
                }
                debug!("recreating write handle");
                self.do_with_write_handle(key, WriteHandleContextOperation::RecreateEncryptor { existing: ctx.lock().await, reset_size: true }).await?;
            }
        }

        Ok(())
    }

    async fn do_with_read_handle(&self, handle: u64, op: ReadHandleContextOperation<'_>) -> FsResult<()> {
        let ino = op.get_ino();
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let decryptor = crypto_util::create_decryptor(file, &self.cipher, &*self.key.get().await?);
        let attr = self.get_inode_from_storage(ino, &*self.key.get().await?).await?;
        match op {
            ReadHandleContextOperation::Create { ino, lock } => {
                let attr: TimeAndSizeFileAttr = attr.into();
                let ctx = ReadHandleContext {
                    ino,
                    attr,
                    pos: 0,
                    decryptor: Some(decryptor),
                    _lock: lock,
                };
                self.read_handles.write().await.insert(handle, Mutex::new(ctx));
                self.opened_files_for_read.write().await.entry(ino).or_insert_with(|| HashSet::new()).insert(handle);
            }
            ReadHandleContextOperation::RecreateDecryptor { mut existing } => {
                existing.pos = 0;
                existing.decryptor.replace(decryptor);
                existing.attr.size = attr.size;
            }
        }
        Ok(())
    }

    async fn do_with_write_handle(&self, handle: u64, op: WriteHandleContextOperation<'_>) -> FsResult<()> {
        let ino = op.get_ino();
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.clone())?;
        let encryptor = crypto_util::create_encryptor(file, &self.cipher, &*self.key.get().await?);
        match op {
            WriteHandleContextOperation::Create { ino, lock } => {
                debug!("creating write handle");
                let attr = self.get_inode(ino).await?.into();
                let ctx = WriteHandleContext {
                    ino,
                    attr,
                    path,
                    pos: 0,
                    encryptor: Some(encryptor),
                    _lock: lock,
                };
                self.write_handles.write().await.insert(handle, Mutex::new(ctx));
                self.opened_files_for_write.write().await.insert(ino, handle);
            }
            WriteHandleContextOperation::RecreateEncryptor { mut existing, reset_size } => {
                existing.pos = 0;
                debug!("recreating encryptor");
                existing.encryptor.replace(encryptor);
                existing.path = path.clone();
                if reset_size {
                    let attr = self.get_inode_from_storage(ino, &*self.key.get().await?).await?;
                    existing.attr.size = attr.size;
                    debug!("resetting size to {}", attr.size.to_formatted_string(&Locale::en));
                }
            }
        }

        Ok(())
    }

    async fn ensure_root_exists(&self) -> FsResult<()> {
        if !self.node_exists(ROOT_INODE) {
            let mut attr: FileAttr = CreateFileAttr {
                kind: FileType::Directory,
                perm: 0o755,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
            }.into();
            attr.ino = ROOT_INODE;
            #[cfg(target_os = "linux")] unsafe {
                attr.uid = libc::getuid();
                attr.gid = libc::getgid();
            }

            self.write_inode_to_storage(&attr, &*self.key.get().await?).await?;

            // create the directory
            tokio::fs::create_dir(self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).await?;

            // add "." entry
            self.insert_directory_entry(attr.ino, DirectoryEntry {
                ino: attr.ino,
                name: SecretString::from_str("$.").unwrap(),
                kind: FileType::Directory,
            }, &*self.key.get().await?).await?;
        }

        Ok(())
    }

    async fn insert_directory_entry(&self, parent: u64, entry: DirectoryEntry, key: &SecretVec<u8>) -> FsResult<()> {
        let parent_path = self.data_dir.join(CONTENTS_DIR).join(parent.to_string());
        let name = crypto_util::normalize_end_encrypt_file_name(&entry.name, &self.cipher, &*self.key.get().await?);
        let file_path = parent_path.join(name);

        let map = self.serialize_dir_entries_locks.write().unwrap();
        let lock = map.get_or_insert_with(file_path.to_str().unwrap().to_string(), || std::sync::RwLock::new(false));
        let _guard = lock.write().unwrap();

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;

        // write inode and file type
        let entry = (entry.ino, entry.kind);
        bincode::serialize_into(crypto_util::create_encryptor(file, &self.cipher, key), &entry)?;

        Ok(())
    }

    async fn remove_directory_entry(&self, parent: u64, name: &SecretString) -> FsResult<()> {
        let parent_path = self.data_dir.join(CONTENTS_DIR).join(parent.to_string());
        let name = crypto_util::normalize_end_encrypt_file_name(name, &self.cipher, &*self.key.get().await?);
        let file_path = parent_path.join(name);

        let map = self.serialize_dir_entries_locks.write().unwrap();
        let lock = map.get_or_insert_with(file_path.to_str().unwrap().to_string(), || std::sync::RwLock::new(false));
        let _guard = lock.write().unwrap();

        fs::remove_file(file_path)?;
        Ok(())
    }

    fn generate_next_inode(&self) -> u64 {
        loop {
            let ino = thread_rng().next_u64();

            if ino <= ROOT_INODE {
                continue;
            }
            if self.node_exists(ino) {
                continue;
            }

            return ino;
        }
    }

    fn read_or_create_key(path: &PathBuf, password: &SecretString, cipher: &Cipher) -> FsResult<SecretVec<u8>> {
        // derive key from password
        let salt = crypto_util::hash_secret(&password);
        let derived_key = crypto_util::derive_key(&password, cipher, salt)?;
        if path.exists() {
            // read key

            let decryptor = crypto_util::create_decryptor(File::open(path)?, cipher, &derived_key);
            let key_store: KeyStore = bincode::deserialize_from(decryptor).map_err(|_| FsError::InvalidPassword)?;
            // check hash
            if key_store.hash != crypto_util::hash(key_store.key.expose_secret()) {
                return Err(FsError::InvalidPassword);
            }
            Ok(key_store.key)
        } else {
            // first time, create a random key and encrypt it with the derived key from password

            let mut key: Vec<u8> = vec![];
            let key_len = match cipher {
                Cipher::ChaCha20 => 32,
                Cipher::Aes256Gcm => 32,
            };
            key.resize(key_len, 0);
            thread_rng().fill_bytes(&mut key);
            let key = SecretVec::new(key);
            let key_store = KeyStore::new(key);
            let mut encryptor = crypto_util::create_encryptor(OpenOptions::new().read(true).write(true).create(true).open(path)?,
                                                              cipher, &derived_key);
            bincode::serialize_into(&mut encryptor, &key_store)?;
            Ok(key_store.key)
        }
    }
}

async fn ensure_structure_created(data_dir: &PathBuf, key_provider: &KeyProvider) -> FsResult<()> {
    if data_dir.exists() {
        check_structure(data_dir, true).await?;
    } else {
        tokio::fs::create_dir_all(&data_dir).await?;
    }

    // create directories
    let dirs = vec![INODES_DIR, CONTENTS_DIR, SECURITY_DIR];
    for dir in dirs {
        let path = data_dir.join(dir);
        if !path.exists() {
            tokio::fs::create_dir_all(path).await?;
        }
    }

    // create encryption key
    key_provider.provide()?;

    Ok(())
}

async fn check_structure(data_dir: &PathBuf, ignore_empty: bool) -> FsResult<()> {
    if !data_dir.exists() || !data_dir.is_dir() {
        return Err(FsError::InvalidDataDirStructure);
    }
    let mut vec = ReadDirStream::new(tokio::fs::read_dir(data_dir).await?).try_collect::<Vec<_>>().await?.iter()
        .map(|dir| dir.file_name().to_string_lossy().to_string()).collect::<Vec<String>>();
    if vec.len() == 0 && ignore_empty {
        return Ok(());
    }
    if vec.len() != 3 {
        return Err(FsError::InvalidDataDirStructure);
    }
    // make sure existing structure is ok
    vec.sort();
    let mut vec2 = vec![INODES_DIR, CONTENTS_DIR, SECURITY_DIR];
    vec2.sort();
    if vec != vec2 || !data_dir.join(SECURITY_DIR).join(KEY_ENC_FILENAME).is_file() {
        return Err(FsError::InvalidDataDirStructure);
    }

    Ok(())
}

fn merge_attr(attr: &mut FileAttr, set_attr: SetFileAttr) {
    if let Some(size) = set_attr.size {
        attr.size = size;
    }
    if let Some(atime) = set_attr.atime {
        attr.atime = max(atime, attr.atime);
    }
    if let Some(mtime) = set_attr.mtime {
        attr.mtime = max(mtime, attr.mtime);
    }
    if let Some(ctime) = set_attr.ctime {
        attr.ctime = max(ctime, attr.ctime);
    }
    if let Some(crtime) = set_attr.crtime {
        attr.crtime = max(crtime, attr.crtime);
    }
    if let Some(perm) = set_attr.perm {
        attr.perm = perm;
    }
    if let Some(uid) = set_attr.uid {
        attr.uid = uid;
    }
    if let Some(gid) = set_attr.gid {
        attr.gid = gid;
    }
    if let Some(flags) = set_attr.flags {
        attr.flags = flags;
    }
}

fn check_password(data_dir: &PathBuf, password: &SecretString, cipher: &Cipher) -> FsResult<()> {
    let salt = crypto_util::hash_secret(password);
    let initial_key = crypto_util::derive_key(password, cipher, salt)?;
    let enc_file = data_dir.join(SECURITY_DIR).join(KEY_ENC_FILENAME);
    let decryptor = crypto_util::create_decryptor(File::open(enc_file.clone())?, cipher, &initial_key);
    let key_store: KeyStore = bincode::deserialize_from(decryptor).map_err(|_| FsError::InvalidPassword)?;
    // check hash
    if key_store.hash != crypto_util::hash(key_store.key.expose_secret()) {
        return Err(FsError::InvalidPassword);
    }

    Ok(())
}
