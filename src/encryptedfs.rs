use std::{fs, io, process};
use std::cmp::{max, min};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::{File, OpenOptions, ReadDir};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{PathBuf};
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use cryptostream::{read, write};
use openssl::error::ErrorStack;
use rand::{OsRng, Rng};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter, EnumString};
use thiserror::Error;
use tracing::error;

#[cfg(test)]
mod encryptedfs_test;
pub mod encryptedfs;

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

#[derive(Error, Debug)]
pub enum FsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("serialize error: {0}")]
    SerializeError(#[from] bincode::Error),

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

    #[error("encryption error: {0}")]
    Encryption(#[from] ErrorStack),
}

#[derive(Debug, Clone, EnumIter, EnumString, Display)]
pub enum Cipher {
    ChaCha20,
    Aes256Gcm,
}

struct TimeAndSizeFileAttr {
    ino: u64,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    crtime: SystemTime,
    size: u64,
}

impl TimeAndSizeFileAttr {
    #[allow(dead_code)]
    fn new(ino: u64, atime: SystemTime, mtime: SystemTime, ctime: SystemTime, crtime: SystemTime, size: u64) -> Self {
        Self {
            ino,
            atime,
            mtime,
            ctime,
            crtime,
            size,
        }
    }

    fn from_file_attr(attr: &FileAttr) -> Self {
        Self {
            ino: attr.ino,
            atime: attr.atime,
            mtime: attr.mtime,
            ctime: attr.ctime,
            crtime: attr.crtime,
            size: attr.size,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct DirectoryEntry {
    pub ino: u64,
    pub name: String,
    pub kind: FileType,
}

/// Like [`DirectoryEntry`] but with ['FileAttr'].
#[derive(Debug, PartialEq)]
pub struct DirectoryEntryPlus {
    pub ino: u64,
    pub name: String,
    pub kind: FileType,
    pub attr: FileAttr,
}

pub type FsResult<T> = Result<T, FsError>;

pub struct DirectoryEntryIterator(ReadDir, Cipher, Vec<u8>);

impl Iterator for DirectoryEntryIterator {
    type Item = FsResult<DirectoryEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        if let Err(e) = entry {
            return Some(Err(e.into()));
        }
        let entry = entry.unwrap();
        let file = File::open(entry.path());
        if let Err(e) = file {
            return Some(Err(e.into()));
        }
        let file = file.unwrap();
        let mut name = entry.file_name().to_string_lossy().to_string();
        if name == "$." {
            name = ".".to_string();
        } else if name == "$.." {
            name = "..".to_string();
        } else {
            name = encryptedfs::decrypt_and_unnormalize_end_file_name(&name, &self.1, &self.2);
        }
        let res: bincode::Result<(u64, FileType)> = bincode::deserialize_from(encryptedfs::create_decryptor(file, &self.1, &self.2));
        if let Err(e) = res {
            return Some(Err(e.into()));
        }
        let (ino, kind): (u64, FileType) = res.unwrap();
        Some(Ok(DirectoryEntry {
            ino,
            name,
            kind,
        }))
    }
}

pub struct DirectoryEntryPlusIterator(ReadDir, PathBuf, Cipher, Vec<u8>);

impl Iterator for DirectoryEntryPlusIterator {
    type Item = FsResult<DirectoryEntryPlus>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.0.next()?;
        if let Err(e) = entry {
            error!("error reading directory entry: {:?}", e);
            return Some(Err(e.into()));
        }
        let entry = entry.unwrap();
        let file = File::open(entry.path());
        if let Err(e) = file {
            error!("error opening file: {:?}", e);
            return Some(Err(e.into()));
        }
        let file = file.unwrap();
        let mut name = entry.file_name().to_string_lossy().to_string();
        if name == "$." {
            name = ".".to_string();
        } else if name == "$.." {
            name = "..".to_string();
        } else {
            name = encryptedfs::decrypt_and_unnormalize_end_file_name(&name, &self.2, &self.3);
        }
        let res: bincode::Result<(u64, FileType)> = bincode::deserialize_from(encryptedfs::create_decryptor(file, &self.2, &self.3));
        if let Err(e) = res {
            error!("error deserializing directory entry: {:?}", e);
            return Some(Err(e.into()));
        }
        let (ino, kind): (u64, FileType) = res.unwrap();

        let file = File::open(&self.1.join(ino.to_string()));
        if let Err(e) = file {
            error!("error opening file: {:?}", e);
            return Some(Err(e.into()));
        }
        let file = file.unwrap();
        let attr = bincode::deserialize_from(encryptedfs::create_decryptor(file, &self.2, &self.3));
        if let Err(e) = attr {
            error!("error deserializing file attr: {:?}", e);
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

/// Encrypted FS that stores encrypted files in a dedicated directory with a specific structure based on `inode`.
pub struct EncryptedFs {
    pub(crate) data_dir: PathBuf,
    write_handles: HashMap<u64, (TimeAndSizeFileAttr, PathBuf, u64, write::Encryptor<File>)>,
    read_handles: HashMap<u64, (TimeAndSizeFileAttr, u64, read::Decryptor<File>)>,
    current_handle: AtomicU64,
    cipher: Cipher,
    key: Vec<u8>,
    opened_files_for_write: HashMap<u64, u64>,
}

impl EncryptedFs {
    pub fn new(data_dir: &str, password: &str, cipher: Cipher, derive_key_hash_rounds: u32) -> FsResult<Self> {
        let path = PathBuf::from(&data_dir);

        ensure_structure_created(&path)?;

        let mut fs = EncryptedFs {
            data_dir: path.clone(),
            write_handles: HashMap::new(),
            read_handles: HashMap::new(),
            current_handle: AtomicU64::new(1),
            cipher: cipher.clone(),
            key: read_or_create_key(path.join(SECURITY_DIR).join(KEY_ENC_FILENAME), password, &cipher, derive_key_hash_rounds)?,
            opened_files_for_write: HashMap::new(),
        };
        let _ = fs.ensure_root_exists();
        fs.check_password();

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
    /// You don't need to provide `attr.ino`, it will be auto-generated anyway.
    pub fn create_nod(&mut self, parent: u64, name: &str, mut attr: FileAttr, read: bool, write: bool) -> FsResult<(u64, FileAttr)> {
        if !self.node_exists(parent) {
            return Err(FsError::InodeNotFound);
        }
        if self.find_by_name(parent, name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        attr.ino = self.generate_next_inode();

        // write inode
        self.write_inode(&attr)?;

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
                fs::create_dir(self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()))?;

                // add "." and ".." entries
                self.insert_directory_entry(attr.ino, DirectoryEntry {
                    ino: attr.ino,
                    name: "$.".to_string(),
                    kind: FileType::Directory,
                })?;
                self.insert_directory_entry(attr.ino, DirectoryEntry {
                    ino: parent,
                    name: "$..".to_string(),
                    kind: FileType::Directory,
                })?;
            }
        }

        // edd entry in parent directory, used for listing
        self.insert_directory_entry(parent, DirectoryEntry {
            ino: attr.ino,
            name: name.to_string(),
            kind: attr.kind,
        })?;

        let mut parent_attr = self.get_inode(parent)?;
        parent_attr.mtime = SystemTime::now();
        parent_attr.ctime = SystemTime::now();
        self.write_inode(&parent_attr)?;

        let handle = if attr.kind == FileType::RegularFile {
            if read || write {
                self.open(attr.ino, read, write)?
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

    pub fn find_by_name(&mut self, parent: u64, mut name: &str) -> FsResult<Option<FileAttr>> {
        if !self.node_exists(parent) {
            return Err(FsError::InodeNotFound);
        }
        if !self.exists_by_name(parent, name) {
            return Ok(None);
        }
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }
        if name == "." {
            name = "$.";
        } else if name == ".." {
            name = "$..";
        }
        let name = encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key);
        let file = File::open(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name))?;
        let (inode, _): (u64, FileType) = bincode::deserialize_from(encryptedfs::create_decryptor(file, &self.cipher, &self.key))?;
        Ok(Some(self.get_inode(inode)?))
    }

    /// Count children of a directory. This includes also `.` and `..`.
    pub fn children_count(&self, ino: u64) -> FsResult<usize> {
        let iter = self.read_dir(ino)?;
        Ok(iter.into_iter().count())
    }

    pub fn remove_dir(&mut self, parent: u64, name: &str) -> FsResult<()> {
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }

        if !self.exists_by_name(parent, name) {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        let attr = self.find_by_name(parent, name)?.ok_or(FsError::NotFound("name not found".to_string()))?;
        if !matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }
        // check if it's empty
        let iter = self.read_dir(attr.ino)?;
        let count_children = iter.into_iter().take(3).count();
        if count_children > 2 {
            return Err(FsError::NotEmpty);
        }

        let ino_str = attr.ino.to_string();
        // remove inode file
        fs::remove_file(self.data_dir.join(INODES_DIR).join(&ino_str))?;
        // remove contents directory
        fs::remove_dir_all(self.data_dir.join(CONTENTS_DIR).join(&ino_str))?;
        // remove from parent directory
        let name = encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key);
        fs::remove_file(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name))?;

        let mut parent_attr = self.get_inode(parent)?;
        parent_attr.mtime = std::time::SystemTime::now();
        parent_attr.ctime = std::time::SystemTime::now();
        self.write_inode(&parent_attr)?;

        Ok(())
    }

    pub fn remove_file(&mut self, parent: u64, name: &str) -> FsResult<()> {
        if !self.is_dir(parent) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.exists_by_name(parent, name) {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        let attr = self.find_by_name(parent, name)?.ok_or(FsError::NotFound("name not found".to_string()))?;
        if !matches!(attr.kind, FileType::RegularFile) {
            return Err(FsError::InvalidInodeType);
        }
        let ino_str = attr.ino.to_string();

        // remove inode file
        fs::remove_file(self.data_dir.join(INODES_DIR).join(&ino_str))?;
        // remove contents file
        fs::remove_file(self.data_dir.join(CONTENTS_DIR).join(&ino_str))?;
        // remove from parent directory
        let name = encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key);
        fs::remove_file(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name))?;

        let mut parent_attr = self.get_inode(parent)?;
        parent_attr.mtime = std::time::SystemTime::now();
        parent_attr.ctime = std::time::SystemTime::now();
        self.write_inode(&parent_attr)?;

        Ok(())
    }

    pub fn exists_by_name(&self, parent: u64, mut name: &str) -> bool {
        if name == "." {
            name = "$.";
        } else if name == ".." {
            name = "$..";
        }
        let name = encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key);
        self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name).exists()
    }

    pub fn read_dir(&self, ino: u64) -> FsResult<DirectoryEntryIterator> {
        let contents_dir = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        if !contents_dir.is_dir() {
            return Err(FsError::InvalidInodeType);
        }

        let iter = fs::read_dir(contents_dir)?;
        Ok(DirectoryEntryIterator(iter.into_iter(), self.cipher.clone(), self.key.clone()))
    }

    /// Like [read_dir](EncryptedFs::read_dir) but with [FileAttr] so we don't need to query again for those.
    pub fn read_dir_plus(&self, ino: u64) -> FsResult<DirectoryEntryPlusIterator> {
        let contents_dir = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        if !contents_dir.is_dir() {
            return Err(FsError::InvalidInodeType);
        }

        let iter = fs::read_dir(contents_dir)?;
        Ok(DirectoryEntryPlusIterator(iter.into_iter(), self.data_dir.join(INODES_DIR), self.cipher.clone(), self.key.clone()))
    }

    pub fn get_inode(&mut self, ino: u64) -> FsResult<FileAttr> {
        let path = self.data_dir.join(INODES_DIR).join(ino.to_string());
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(path) {
            let mut attr: FileAttr = bincode::deserialize_from(encryptedfs::create_decryptor(file, &self.cipher, &self.key))?;
            if self.opened_files_for_write.contains_key(&ino) {
                // merge time info and size with any open write handles
                if let Some((attr_handle, _, _, _)) = self.write_handles.get(&self.opened_files_for_write.get(&ino).unwrap()) {
                    merge_attr_time_and_time_obj(&mut attr, &attr_handle);
                } else {
                    self.opened_files_for_write.remove(&ino);
                }
            }

            Ok(attr)
        } else {
            Err(FsError::InodeNotFound)
        }
    }

    pub fn update_inode(&mut self, ino: u64, perm: u16, atime: SystemTime, mtime: SystemTime, ctime: SystemTime, crtime: SystemTime, uid: u32, gid: u32, size: u64, nlink: u32, flags: u32) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;

        merge_attr(&mut attr, perm, atime, mtime, ctime, crtime, uid, gid, size, nlink, flags);

        self.write_inode(&attr)
    }

    /// Read the contents from an 'offset'. If we try to read outside of file size, we return 0 bytes.
    /// Depending on the encryption type we might need to re-read bytes until the 'offset', in some case even
    /// from the beginning of the file to the desired `offset`. This will slow down the read operation if we
    /// read from very distanced offsets.
    /// The most speed is obtained when we read sequentially from the beginning of the file.
    /// If the file is not opened for read, it will return an error of type ['FsError::InvalidFileHandle'].
    pub fn read(&mut self, ino: u64, offset: u64, mut buf: &mut [u8], handle: u64) -> FsResult<usize> {
        if !self.node_exists(ino) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_file(ino) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.read_handles.contains_key(&handle) {
            return Err(FsError::InvalidFileHandle);
        }
        let (attr, position, _) = self.read_handles.get(&handle).unwrap();
        if attr.ino != ino {
            return Err(FsError::InvalidFileHandle);
        }
        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }
        if buf.len() == 0 {
            // no-op
            return Ok(0);
        }
        if offset >= attr.size {
            // if we need an offset after file size we don't read anything
            return Ok(0);
        }

        if *position != offset {
            // in order to seek we need to read the bytes from current position until the offset
            if *position > offset {
                // if we need an offset before the current position, we can't seek back, we need
                // to read from the beginning until the desired offset
                self.create_read_handle(ino, handle)?;
            }
            if offset > 0 {
                let (_, position, decryptor) =
                    self.read_handles.get_mut(&handle).unwrap();
                let mut buffer: [u8; 4096] = [0; 4096];
                loop {
                    let read_len = if *position + buffer.len() as u64 > offset {
                        (offset - *position) as usize
                    } else {
                        buffer.len()
                    };
                    if read_len > 0 {
                        decryptor.read_exact(&mut buffer[..read_len])?;
                        *position += read_len as u64;
                        if *position == offset {
                            break;
                        }
                    }
                }
            }
        }
        let (attr, position, decryptor) =
            self.read_handles.get_mut(&handle).unwrap();
        if offset + buf.len() as u64 > attr.size {
            buf = &mut buf[..(attr.size - offset) as usize];
        }
        decryptor.read_exact(&mut buf)?;
        *position += buf.len() as u64;

        attr.atime = std::time::SystemTime::now();

        Ok(buf.len())
    }

    pub fn release_handle(&mut self, handle: u64) -> FsResult<()> {
        if handle == 0 {
            // in case of directory or if the file was crated without being opened we don't use handle
            return Ok(());
        }
        let mut valid_fh = false;
        if let Some((attr, _, decryptor)) = self.read_handles.remove(&handle) {
            // write attr only here to avoid serializing it multiple times while reading
            // merge time fields with existing data because it might got change while we kept the handle
            let mut attr_0 = self.get_inode(attr.ino)?;
            merge_attr_time_and_time_obj(&mut attr_0, &attr);
            self.write_inode(&attr_0)?;
            decryptor.finish();
            valid_fh = true;
        }
        if let Some((attr, path, _, encryptor)) = self.write_handles.remove(&handle) {
            // write attr only here to avoid serializing it multiple times while writing
            // merge time fields with existing data because it might got change while we kept the handle
            let mut attr_0 = self.get_inode(attr.ino)?;
            merge_attr_time_and_time_obj(&mut attr_0, &attr);
            self.write_inode(&attr_0)?;
            self.write_inode(&attr_0)?;
            encryptor.finish()?;
            // if we are in tmp file move it to actual file
            if path.to_str().unwrap().ends_with(".tmp") {
                fs::rename(path, self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap();

                // also recreate readers because the file has changed
                self.recreate_read_handles();
            }
            self.opened_files_for_write.remove(&attr.ino);
            valid_fh = true;
        }
        if !valid_fh {
            return Err(FsError::InvalidFileHandle);
        }
        Ok(())
    }

    /// Check if a file is opened for read with this handle.
    pub fn is_read_handle(&self, fh: u64) -> bool {
        self.read_handles.contains_key(&fh)
    }

    /// Check if a file is opened for write with this handle.
    pub fn is_write_handle(&self, fh: u64) -> bool {
        self.write_handles.contains_key(&fh)
    }

    /// Writes the contents of `buf` to the file at `ino` starting at `offset`.
    /// Depending on the encryption type we might need to re-write bytes until the 'offset', in some case even
    /// from the beginning of the file to the desired `offset`. This will slow down the write operation if we
    /// write to very distanced offsets.
    /// The most speed is obtained when we write sequentially from the beginning of the file.
    /// If we write outside of file size, we fill up with zeros until offset.
    /// If the file is not opened for write, it will return an error of type ['FsError::InvalidFileHandle'].
    pub fn write_all(&mut self, ino: u64, offset: u64, buf: &[u8], handle: u64) -> FsResult<()> {
        if !self.node_exists(ino) {
            return Err(FsError::InodeNotFound);
        }
        if !self.is_file(ino) {
            return Err(FsError::InvalidInodeType);
        }
        if !self.write_handles.contains_key(&handle) {
            return Err(FsError::InvalidFileHandle);
        }
        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }
        let (attr, _, position, _) =
            self.write_handles.get_mut(&handle).unwrap();
        if attr.ino != ino {
            return Err(FsError::InvalidFileHandle);
        }
        if buf.len() == 0 {
            // no-op
            return Ok(());
        }

        if *position != offset {
            // in order to seek we need to recreate all stream from the beginning until the desired position of file size
            // for that we create a new encryptor into a tmp file reading from original file and writing to tmp one
            // when we release the handle we will move this tmp file to the actual file

            // remove handle data because we will replace it with the tmp one
            let (attr, path, _, encryptor) =
                self.write_handles.remove(&handle).unwrap();

            // finish the current writer so we flush all data to the file
            encryptor.finish()?;

            // if we are already in the tmp file first copy tmp to actual file
            if path.to_str().unwrap().ends_with(".tmp") {
                fs::rename(path, self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap();
            }

            let in_path = self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string());
            let in_file = OpenOptions::new().read(true).write(true).open(in_path.clone())?;

            let tmp_path_str = format!("{}.{}.tmp", attr.ino.to_string(), &handle.to_string());
            let tmp_path = self.data_dir.join(CONTENTS_DIR).join(tmp_path_str);
            let tmp_file = OpenOptions::new().read(true).write(true).create(true).open(tmp_path.clone())?;

            let mut decryptor = encryptedfs::create_decryptor(in_file, &self.cipher, &self.key);
            let mut encryptor = encryptedfs::create_encryptor(tmp_file, &self.cipher, &self.key);

            let mut buffer: [u8; 4096] = [0; 4096];
            let mut pos_read = 0;
            let mut position = 0;
            if offset > 0 {
                loop {
                    let offset_in_bounds = min(offset, attr.size); // keep offset in bounds of file
                    let read_len = if pos_read + buffer.len() as u64 > offset_in_bounds {
                        (offset_in_bounds - pos_read) as usize
                    } else {
                        buffer.len()
                    };
                    if read_len > 0 {
                        decryptor.read_exact(&mut buffer[..read_len])?;
                        encryptor.write_all(&buffer[..read_len])?;
                        pos_read += read_len as u64;
                        position += read_len as u64;
                        if pos_read == offset_in_bounds {
                            break;
                        }
                    }
                }
            }
            self.replace_handle_data(handle, attr, tmp_path, position, encryptor);
        }
        let (attr, _, position, encryptor) =
            self.write_handles.get_mut(&handle).unwrap();

        // if offset is after current position (max file size) we fill up with zeros until offset
        if offset > *position {
            let buffer: [u8; 4096] = [0; 4096];
            loop {
                let len = min(4096, offset - *position) as usize;
                encryptor.write_all(&buffer[..len])?;
                *position += len as u64;
                if *position == offset {
                    break;
                }
            }
        }

        // now write the new data
        encryptor.write_all(buf)?;
        *position += buf.len() as u64;

        // if position is before file end we copy the rest of the file from position to the end
        if *position < attr.size {
            let mut buffer: [u8; 4096] = [0; 4096];
            let mut decryptor = encryptedfs::create_decryptor(OpenOptions::new().read(true).open(self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()))?,
                                                              &self.cipher, &self.key);
            // move read position to the desired position
            loop {
                let mut read_pos = 0u64;
                let len = min(4096, *position - read_pos) as usize;
                decryptor.read_exact(&mut buffer[..len])?;
                read_pos += len as u64;
                if read_pos == *position {
                    break;
                }
            }
            // copy the rest of the file
            loop {
                let len = min(4096, attr.size - *position) as usize;
                decryptor.read_exact(&mut buffer[..len])?;
                encryptor.write_all(&buffer[..len])?;
                *position += len as u64;
                if *position == attr.size {
                    break;
                }
            }
            decryptor.finish();
        }

        let size = *position;
        attr.size = size;
        attr.mtime = std::time::SystemTime::now();
        attr.ctime = std::time::SystemTime::now();

        Ok(())
    }

    /// Flush the data to the underlying storage.
    pub fn flush(&mut self, handle: u64) -> FsResult<()> {
        if handle == 0 {
            // in case of directory or if the file was crated without being opened we don't use handle
            return Ok(());
        }
        if !self.write_handles.contains_key(&handle) {
            return Err(FsError::InvalidFileHandle);
        }
        if let Some((_, _, _, encryptor)) = self.write_handles.get_mut(&handle) {
            encryptor.flush()?;
        }
        Ok(())
    }

    /// Helpful when we want to copy just some portions of the file.
    pub fn copy_file_range(&mut self, src_ino: u64, src_offset: u64, dest_ino: u64, dest_offset: u64, size: usize, src_fh: u64, dest_fh: u64) -> FsResult<usize> {
        if self.is_dir(src_ino) || self.is_dir(dest_ino) {
            return Err(FsError::InvalidInodeType);
        }

        let mut buf = vec![0; size];
        let len = self.read(src_ino, src_offset, &mut buf, src_fh)?;
        self.write_all(dest_ino, dest_offset, &buf[..len], dest_fh)?;

        Ok(len)
    }

    /// Open a file. We can open multiple times for read but only one for write at a time.
    pub fn open(&mut self, ino: u64, read: bool, write: bool) -> FsResult<u64> {
        if !read && !write {
            return Err(FsError::InvalidInput("read and write cannot be false at the same time".to_string()));
        }
        if self.is_dir(ino) {
            return Err(FsError::InvalidInodeType);
        }

        let mut handle = 0u64;
        if read {
            handle = self.allocate_next_handle();
            self.create_read_handle(ino, handle)?;
        }
        if write {
            if self.opened_files_for_write.contains_key(&ino) {
                return Err(FsError::AlreadyOpenForWrite);
            }
            handle = self.allocate_next_handle();
            self.create_write_handle(ino, handle)?;
        }
        Ok(handle)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        if size == attr.size {
            // no-op
            return Ok(());
        } else if size == 0 {
            // truncate to zero
            OpenOptions::new().write(true).create(true).truncate(true).open(self.data_dir.join(CONTENTS_DIR).join(ino.to_string()))?;
        } else if size < attr.size {
            // decrease size, copy from beginning until size as offset
            // TODO
            let fh = self.open(ino, false, true)?;
            self.write_all(ino, size, &[], fh)?;
            self.release_handle(fh)?;
        } else {
            // increase size, write zeros from actual size to new size
            let fh = self.open(ino, false, true)?;
            let buf: [u8; 4096] = [0; 4096];
            loop {
                let len = min(4096, size - attr.size) as usize;
                self.write_all(ino, attr.size, &buf[..len], fh)?;
                attr.size += len as u64;
                if attr.size == size {
                    break;
                }
            }
            self.flush(fh)?;
            self.release_handle(fh)?;
        }

        attr.size = size;
        attr.mtime = std::time::SystemTime::now();
        attr.ctime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

        // also recreate readers because the file has changed
        self.recreate_read_handles();

        Ok(())
    }

    pub fn rename(&mut self, parent: u64, name: &str, new_parent: u64, new_name: &str) -> FsResult<()> {
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
        if !self.exists_by_name(parent, name) {
            return Err(FsError::NotFound("name not found".to_string()));
        }

        if parent == new_parent && name == new_name {
            // no-op
            return Ok(());
        }

        // Only overwrite an existing directory if it's empty
        if let Ok(Some(new_attr)) = self.find_by_name(new_parent, new_name) {
            if new_attr.kind == FileType::Directory &&
                self.children_count(new_attr.ino)? > 2 {
                return Err(FsError::NotEmpty);
            }
        }

        let mut attr = self.find_by_name(parent, name)?.unwrap();
        // remove from parent contents
        self.remove_directory_entry(parent, name)?;
        // add to new parent contents
        self.insert_directory_entry(new_parent, DirectoryEntry {
            ino: attr.ino,
            name: new_name.to_string(),
            kind: attr.kind,
        })?;

        let mut parent_attr = self.get_inode(parent)?;
        parent_attr.mtime = std::time::SystemTime::now();
        parent_attr.ctime = std::time::SystemTime::now();

        let mut new_parent_attr = self.get_inode(new_parent)?;
        new_parent_attr.mtime = std::time::SystemTime::now();
        new_parent_attr.ctime = std::time::SystemTime::now();

        attr.ctime = std::time::SystemTime::now();

        if attr.kind == FileType::Directory {
            // add parent link to new directory
            self.insert_directory_entry(attr.ino, DirectoryEntry {
                ino: new_parent,
                name: "$..".to_string(),
                kind: FileType::Directory,
            })?;
        }

        Ok(())
    }

    pub(crate) fn write_inode(&mut self, attr: &FileAttr) -> FsResult<()> {
        let path = self.data_dir.join(INODES_DIR).join(attr.ino.to_string());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(bincode::serialize_into(encryptedfs::create_encryptor(file, &self.cipher, &self.key), &attr)?)
    }

    /// Create an encryptor using internal encryption info.
    pub fn create_encryptor(&self, file: File) -> write::Encryptor<File> {
        encryptedfs::create_encryptor(file, &self.cipher, &self.key)
    }

    /// Create a decryptor using internal encryption info.
    pub fn create_decryptor(&self, file: File) -> read::Decryptor<File> {
        encryptedfs::create_decryptor(file, &self.cipher, &self.key)
    }

    /// Encrypts a string using internal encryption info.
    pub fn encrypt_string(&self, s: &str) -> String {
        encryptedfs::encrypt_string(s, &self.cipher, &self.key)
    }

    /// Decrypts a string using internal encryption info.
    pub fn decrypt_string(&self, s: &str) -> String {
        encryptedfs::decrypt_string(s, &self.cipher, &self.key)
    }

    /// Normalize and encrypt a file name.
    pub fn normalize_end_encrypt_file_name(&self, name: &str) -> String {
        encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key)
    }
    /// Change the password of the filesystem used to access the encryption key.
    pub fn change_password(data_dir: &str, old_password: &str, new_password: &str, cipher: &Cipher, derive_key_hash_rounds: u32) -> FsResult<()> {
        let data_dir = PathBuf::from(data_dir);

        // decrypt key
        let initial_key = encryptedfs::derive_key(old_password, &cipher, derive_key_hash_rounds, "salt-42");
        let enc_file = data_dir.join(SECURITY_DIR).join(KEY_ENC_FILENAME);
        let mut decryptor = encryptedfs::create_decryptor(File::open(enc_file.clone())?, cipher, &initial_key);
        let mut key: Vec<u8> = vec![];
        decryptor.read_to_end(&mut key)?;
        decryptor.finish();

        // encrypt it with new key derived from new password
        let new_key = encryptedfs::derive_key(new_password, &cipher, derive_key_hash_rounds, "salt-42");
        fs::remove_file(enc_file.clone())?;
        let mut encryptor = encryptedfs::create_encryptor(OpenOptions::new().read(true).write(true).create(true).truncate(true).open(enc_file.clone())?,
                                                          cipher, &new_key);
        encryptor.write_all(&key)?;
        encryptor.finish()?;

        Ok(())
    }

    fn allocate_next_handle(&mut self) -> u64 {
        self.current_handle.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn recreate_read_handles(&mut self) {
        let keys: Vec<u64> = self.read_handles.keys().cloned().collect();
        for key in keys {
            let (attr, _, _) = self.read_handles.remove(&key).unwrap();
            self.create_read_handle(attr.ino, key).unwrap();
        }
    }

    fn check_password(&mut self) {
        match self.get_inode(ROOT_INODE) {
            Err(FsError::SerializeError(_)) => {
                println!("Cannot decrypt data, maybe password is wrong");
                process::exit(2);
            }
            Err(err) => { panic!("Error while checking password: {:?}", err); }
            _ => {}
        }
    }

    fn create_read_handle(&mut self, ino: u64, handle: u64) -> FsResult<u64> {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new().read(true).write(true).open(path)?;

        let decryptor = encryptedfs::create_decryptor(file, &self.cipher, &self.key);
        let attr = self.get_inode(ino)?;
        // save attr also to avoid loading it multiple times while reading
        self.read_handles.insert(handle, (TimeAndSizeFileAttr::from_file_attr(&attr), 0, decryptor));
        Ok(handle)
    }

    fn create_write_handle(&mut self, ino: u64, handle: u64) -> FsResult<u64> {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new().read(true).write(true).open(path.clone())?;

        let encryptor = encryptedfs::create_encryptor(file, &self.cipher, &self.key);
        // save attr also to avoid loading it multiple times while writing
        let attr = self.get_inode(ino)?;
        self.write_handles.insert(handle, (TimeAndSizeFileAttr::from_file_attr(&attr), path, 0, encryptor));
        self.opened_files_for_write.insert(ino, handle);
        Ok(handle)
    }

    fn replace_handle_data(&mut self, handle: u64, attr: TimeAndSizeFileAttr, new_path: PathBuf, position: u64, new_encryptor: write::Encryptor<File>) {
        self.write_handles.insert(handle, (attr, new_path, position, new_encryptor));
    }

    fn ensure_root_exists(&mut self) -> FsResult<()> {
        if !self.node_exists(ROOT_INODE) {
            let mut attr = FileAttr {
                ino: ROOT_INODE,
                size: 0,
                blocks: 0,
                atime: SystemTime::now(),
                mtime: SystemTime::now(),
                ctime: SystemTime::now(),
                crtime: SystemTime::now(),
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 0,
                flags: 0,
            };
            #[cfg(target_os = "linux")]
            {
                let metadata = fs::metadata(self.data_dir.clone())?;
                attr.uid = metadata.uid();
                attr.gid = metadata.gid();
            }

            self.write_inode(&attr)?;

            // create the directory
            fs::create_dir(self.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()))?;

            // add "." entry
            self.insert_directory_entry(attr.ino, DirectoryEntry {
                ino: attr.ino,
                name: "$.".to_string(),
                kind: FileType::Directory,
            })?;
        }

        Ok(())
    }

    fn insert_directory_entry(&self, parent: u64, entry: DirectoryEntry) -> FsResult<()> {
        let parent_path = self.data_dir.join(CONTENTS_DIR).join(parent.to_string());
        // remove path separators from name
        let name = encryptedfs::normalize_end_encrypt_file_name(&entry.name, &self.cipher, &self.key);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&parent_path.join(name))?;

        // write inode and file type
        let entry = (entry.ino, entry.kind);
        bincode::serialize_into(encryptedfs::create_encryptor(file, &self.cipher, &self.key), &entry)?;

        Ok(())
    }

    fn remove_directory_entry(&self, parent: u64, name: &str) -> FsResult<()> {
        let parent_path = self.data_dir.join(CONTENTS_DIR).join(parent.to_string());
        let name = encryptedfs::normalize_end_encrypt_file_name(name, &self.cipher, &self.key);
        fs::remove_file(parent_path.join(name))?;
        Ok(())
    }

    fn generate_next_inode(&self) -> u64 {
        loop {
            let mut rng = rand::thread_rng();
            let ino = rng.gen::<u64>();

            if ino <= ROOT_INODE {
                continue;
            }
            if self.node_exists(ino) {
                continue;
            }

            return ino;
        }
    }
}

fn ensure_structure_created(data_dir: &PathBuf) -> FsResult<()> {
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }

    // create directories
    let dirs = vec![INODES_DIR, CONTENTS_DIR, SECURITY_DIR];
    for dir in dirs {
        let path = data_dir.join(dir);
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
    }

    Ok(())
}

fn merge_attr(attr: &mut FileAttr, perm: u16, atime: SystemTime, mtime: SystemTime, ctime: SystemTime, crtime: SystemTime, uid: u32, gid: u32, size: u64, nlink: u32, flags: u32) {
    attr.perm = perm;
    merge_attr_time_and_time(attr, atime, mtime, ctime, crtime, size);
    attr.uid = uid;
    attr.gid = gid;
    attr.nlink = nlink;
    attr.flags = flags;
}

fn merge_attr_time_and_time(attr: &mut FileAttr, atime: SystemTime, mtime: SystemTime, ctime: SystemTime, crtime: SystemTime, size: u64) {
    attr.atime = max(attr.atime, atime);
    attr.mtime = max(attr.mtime, mtime);
    attr.ctime = max(attr.ctime, ctime);
    attr.crtime = max(attr.ctime, crtime);
    attr.crtime = max(attr.ctime, crtime);
    attr.size = size;
}

fn merge_attr_time_and_time_obj(attr: &mut FileAttr, from: &TimeAndSizeFileAttr) {
    attr.atime = max(attr.atime, from.atime);
    attr.mtime = max(attr.mtime, from.mtime);
    attr.ctime = max(attr.ctime, from.ctime);
    attr.crtime = max(attr.ctime, from.crtime);
    attr.crtime = max(attr.ctime, from.crtime);
    attr.size = from.size;
}

fn read_or_create_key(path: PathBuf, password: &str, cipher: &Cipher, rounds: u32) -> FsResult<Vec<u8>> {
    let derived_key = encryptedfs::derive_key(password, cipher, rounds, "salt-42");
    if !path.exists() {
        // first time, create a random key and encrypt it with the derived key from password
        let mut key: Vec<u8> = vec![];
        let key_len = match cipher {
            Cipher::ChaCha20 => 32,
            Cipher::Aes256Gcm => 32,
        };
        key.resize(key_len, 0);
        OsRng::new()?.fill_bytes(&mut key);
        let mut encryptor = encryptedfs::create_encryptor(OpenOptions::new().read(true).write(true).create(true).open(path.clone())?,
                                                          cipher, &derived_key);
        encryptor.write_all(&key)?;
        encryptor.finish()?;

        return Ok(key);
    }
    let mut decryptor = encryptedfs::create_decryptor(File::open(path)?, cipher, &derived_key);
    let mut key: Vec<u8> = vec![];
    decryptor.read_to_end(&mut key)?;
    decryptor.finish();
    Ok(key)
}
