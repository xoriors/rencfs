use std::{fs, io};
use std::cmp::max;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use base64::decode;
use cryptostream::{read, write};
use fuser::{FileAttr, FileType};
use openssl::symm::Cipher;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
mod encrypted_fs_tests;

pub(crate) const INODES_DIR: &str = "inodes";
pub(crate) const CONTENTS_DIR: &str = "contents";
pub(crate) const SECURITY_DIR: &str = "security";

pub(crate) const ROOT_INODE: u64 = 1;

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
    InvalidInput,

    #[error("invalid node type")]
    InvalidInodeType,

    #[error("already exists")]
    AlreadyExists,

    #[error("not empty")]
    NotEmpty,

    #[error("other")]
    Other(String),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub ino: u64,
    pub name: String,
    pub kind: FileType,
}

pub type FsResult<T> = Result<T, FsError>;

pub struct EncryptedFs {
    pub data_dir: PathBuf,
    write_handles: BTreeMap<u64, (u64, write::Encryptor<File>)>,
    read_handles: BTreeMap<u64, (u64, read::Decryptor<File>)>,
    // TODO: change to AtomicU64
    current_file_handle: u64,
}

impl EncryptedFs {
    pub fn new(data_dir: &str) -> FsResult<Self> {
        let path = PathBuf::from(&data_dir);

        ensure_structure_created(&path)?;

        let mut fs = EncryptedFs {
            data_dir: path,
            write_handles: BTreeMap::new(),
            read_handles: BTreeMap::new(),
            current_file_handle: 0,
        };
        let _ = fs.ensure_root_exists();

        Ok(fs)
    }

    pub fn node_exists(&self, ino: u64) -> bool {
        let path = self.data_dir.join(INODES_DIR).join(ino.to_string());
        path.is_file()
    }

    pub fn is_dir(&self, ino: u64) -> bool {
        if let Some(attr) = self.get_inode(ino).ok() {
            return matches!(attr.kind, FileType::Directory);
        }
        return false;
    }

    pub fn is_file(&self, ino: u64) -> bool {
        if let Some(attr) = self.get_inode(ino).ok() {
            return matches!(attr.kind, FileType::RegularFile);
        }
        return false;
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
            _ => { return Err(FsError::InvalidInodeType); }
        }

        // edd entry in parent directory, used for listing
        self.insert_directory_entry(parent, DirectoryEntry {
            ino: attr.ino,
            name: name.to_string(),
            kind: attr.kind,
        })?;

        let mut parent_attr = self.get_inode(parent)?;
        parent_attr.mtime = std::time::SystemTime::now();
        parent_attr.ctime = std::time::SystemTime::now();
        self.write_inode(&parent_attr)?;

        let handle = self.open(attr.ino, read, write)?;

        Ok((handle, attr.clone()))
    }

    pub fn find_by_name(&self, parent: u64, mut name: &str) -> FsResult<Option<FileAttr>> {
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
        let (inode, _): (u64, FileType) = bincode::deserialize_from(File::open(self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name))?)?;
        Ok(Some(self.get_inode(inode)?))
    }

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
        self.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join(name).exists()
    }

    pub fn read_dir(&self, ino: u64) -> FsResult<impl IntoIterator<Item=DirectoryEntry>> {
        let contents_dir = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        if !contents_dir.is_dir() {
            return Err(FsError::InodeNotFound);
        }
        let mut entries = vec![];
        for entry in fs::read_dir(contents_dir)? {
            let entry = entry?;
            let file = File::open(entry.path())?;
            let mut name = entry.file_name().to_string_lossy().to_string();
            if name == "$." {
                name = ".".to_string();
            } else if name == "$.." {
                name = "..".to_string();
            }
            let (ino, kind): (u64, FileType) = bincode::deserialize_from(file)?;
            entries.push(DirectoryEntry {
                ino,
                name,
                kind,
            });
        }

        Ok(entries)
    }

    pub fn get_inode(&self, ino: u64) -> FsResult<FileAttr> {
        let path = self.data_dir.join(INODES_DIR).join(ino.to_string());
        if let Ok(file) = File::open(path) {
            Ok(bincode::deserialize_from(file)?)
        } else {
            Err(FsError::InodeNotFound)
        }
    }

    pub fn replace_inode(&mut self, ino: u64, attr: &mut FileAttr) -> FsResult<()> {
        if !self.node_exists(ino) {
            return Err(FsError::InodeNotFound);
        }
        if !matches!(attr.kind, FileType::Directory) && !matches!(attr.kind, FileType::RegularFile) {
            return Err(FsError::InvalidInodeType);
        }

        attr.ctime = std::time::SystemTime::now();

        self.write_inode(attr)
    }

    // pub fn read(&mut self, ino: u64, offset: u64, mut buf: &mut [u8]) -> FsResult<usize> {
    //     let mut attr = self.get_inode(ino)?;
    //     if matches!(attr.kind, FileType::Directory) {
    //         return Err(FsError::InvalidInodeType);
    //     }
    //
    //     let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
    //     let file = OpenOptions::new().read(true).open(path)?;
    //
    //     let key: [u8; 16] = "a".repeat(16).as_bytes().try_into().unwrap();
    //
    //     let decryptor = AesSafe128Decryptor::new(&key);
    //     let mut reader = AesReader::new(file, decryptor).unwrap();
    //     reader.seek(io::SeekFrom::Start(offset))?;
    //     let len = reader.read(&mut buf)?;
    //
    //     attr.atime = std::time::SystemTime::now();
    //     self.write_inode(&attr)?;
    //
    //     Ok(len)
    // }

    pub fn read(&mut self, ino: u64, offset: u64, mut buf: &mut [u8], handle: u64) -> FsResult<usize> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        if !self.read_handles.contains_key(&handle) {
            self.create_read_handle(ino, handle)?;
        }

        let (position, _) = self.read_handles.get(&handle).unwrap();
        if *position != offset {
            if *position > offset {
                self.create_read_handle(ino, handle)?;
            }
            if offset > 0 {
                let (position, decryptor) = self.read_handles.get_mut(&handle).unwrap();
                let mut buffer: [u8; 4096] = [0; 4096];
                loop {
                    let mut read_len = if *position + buffer.len() as u64 > offset {
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
        let (position, decryptor) = self.read_handles.get_mut(&handle).unwrap();
        if offset + buf.len() as u64 > attr.size {
            buf = &mut buf[..(attr.size - offset) as usize];
        }
        decryptor.read_exact(&mut buf)?;
        *position += buf.len() as u64;

        attr.atime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

        Ok(buf.len())
    }

    pub fn release_handle(&mut self, handle: u64) -> FsResult<()> {
        if let Some((_, decryptor)) = self.read_handles.remove(&handle) {
            decryptor.finish();
        }
        if let Some((_, encryptor)) = self.write_handles.remove(&handle) {
            encryptor.finish()?;
        }
        Ok(())
    }

    // pub fn write_all(&mut self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<()> {
    //     let mut attr = self.get_inode(ino)?;
    //     if matches!(attr.kind, FileType::Directory) {
    //         return Err(FsError::InvalidInodeType);
    //     }
    //
    //     let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
    //     let file = OpenOptions::new().write(true).open(path.clone())?;
    //     let read_file = OpenOptions::new().read(true).open(path.clone())?;
    //
    //     let key: [u8; 16] = "a".repeat(16).as_bytes().try_into().unwrap();
    //     let encryptor = AesSafe128Encryptor::new(&key);
    //     let mut writer = AesWriter::new(file, read_file, encryptor, attr.size == 0)?;
    //     if offset > 0 {
    //         if offset >= attr.size {
    //             writer.seek_to_end(attr.size)?;
    //         } else {
    //             writer.seek(io::SeekFrom::Start(offset))?;
    //         }
    //     }
    //     writer.write_all(buf)?;
    //     writer.flush()?;
    //
    //     let size = max(attr.size, offset + buf.len() as u64);
    //     attr.size = size;
    //     attr.mtime = std::time::SystemTime::now();
    //     attr.ctime = std::time::SystemTime::now();
    //     self.write_inode(&attr)?;
    //
    //     Ok(())
    // }

    pub fn write_all(&mut self, ino: u64, offset: u64, buf: &[u8], handle: u64) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        if !self.write_handles.contains_key(&handle) {
            self.create_write_handle(ino, handle)?;
        }

        let (position, encryptor) = self.write_handles.get_mut(&handle).unwrap();
        if *position > offset {
            // TODO: seek from start
            return Err(FsError::Other("seek from start not implemented".to_string()));
        }
        encryptor.write_all(buf)?;
        *position += buf.len() as u64;

        let size = max(attr.size, offset + buf.len() as u64);
        attr.size = size;
        attr.mtime = std::time::SystemTime::now();
        attr.ctime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

        Ok(())
    }

    pub fn flush(&mut self, handle: u64) -> FsResult<()> {
        // if let Some((_, encryptor)) = self.write_handles.get_mut(&handle) {
        //     encryptor.flush()?;
        // }
        Ok(())
    }

    pub fn copy_file_range(&mut self, src_ino: u64, src_offset: u64, dest_ino: u64, dest_offset: u64, size: usize, src_fh: u64, dest_fh: u64) -> FsResult<usize> {
        let src_attr = self.get_inode(src_ino)?;
        if matches!(src_attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }
        let dest_attr = self.get_inode(dest_ino)?;
        if matches!(dest_attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        let mut buf = vec![0; size];
        let len = self.read(src_ino, src_offset, &mut buf, src_fh)?;
        self.write_all(dest_ino, dest_offset, &buf[..len], dest_fh)?;

        Ok(len)
    }

    pub fn open(&mut self, ino: u64, read: bool, write: bool) -> FsResult<u64> {
        let handle = self.allocate_next_file_handle();
        if read {
            self.create_read_handle(ino, handle)?;
        }
        if write {
            self.create_write_handle(ino, handle)?;
        }
        Ok(handle)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        if size == 0 {
            OpenOptions::new().write(true).create(true).truncate(true).open(self.data_dir.join(CONTENTS_DIR).join(ino.to_string()))?;
        }
        // let file = OpenOptions::new().write(true).open(self.data_dir.join(CONTENTS_DIR).join(ino.to_string()))?;
        // TODO: truncate file
        // file.set_len(size)?;
        // if size == 0 {
        // } else if size < attr.size {
        // }

        attr.size = size;
        attr.mtime = std::time::SystemTime::now();
        attr.ctime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

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
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(bincode::serialize_into(file, &attr)?)
    }

    fn allocate_next_file_handle(&mut self) -> u64 {
        self.current_file_handle += 1;

        self.current_file_handle
    }

    fn create_read_handle(&mut self, ino: u64, handle: u64) -> FsResult<u64> {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new().read(true).open(path)?;

        let key: Vec<_> = "a".repeat(32).as_bytes().to_vec();
        let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();
        let mut decryptor = read::Decryptor::new(file, Cipher::chacha20(), &key, &iv).unwrap();
        self.read_handles.insert(handle, (0, decryptor));
        Ok(handle)
    }

    fn create_write_handle(&mut self, ino: u64, handle: u64) -> FsResult<u64> {
        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let file = OpenOptions::new().write(true).open(path)?;

        let key: Vec<_> = "a".repeat(32).as_bytes().to_vec();
        let iv: Vec<_> = decode("dB0Ej+7zWZWTS5JUCldWMg==").unwrap();
        let mut encryptor = write::Encryptor::new(file, Cipher::chacha20(), &key, &iv).unwrap();
        self.write_handles.insert(handle, (0, encryptor));
        Ok(handle)
    }

    fn ensure_root_exists(&mut self) -> FsResult<()> {
        if !self.node_exists(ROOT_INODE) {
            let mut attr = FileAttr {
                ino: ROOT_INODE,
                size: 0,
                blocks: 0,
                atime: std::time::SystemTime::now(),
                mtime: std::time::SystemTime::now(),
                ctime: std::time::SystemTime::now(),
                crtime: std::time::SystemTime::now(),
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
                use std::os::unix::fs::MetadataExt;
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
        let normalized_name = entry.name.replace("/", "").replace("\\", "");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&parent_path.join(normalized_name))?;

        // write inode and file type
        let entry = (entry.ino, entry.kind);
        bincode::serialize_into(file, &entry)?;

        Ok(())
    }

    fn remove_directory_entry(&self, parent: u64, name: &str) -> FsResult<()> {
        let parent_path = self.data_dir.join(CONTENTS_DIR).join(parent.to_string());
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
