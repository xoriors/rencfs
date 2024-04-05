use std::{fs, io};
use std::cmp::max;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use fuser::{FileAttr, FileType};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const INODES_DIR: &str = "inodes";
const CONTENTS_DIR: &str = "contents";
const SECURITY_DIR: &str = "security";

const ROOT_INODE: u64 = 1;

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
}

impl EncryptedFs {
    pub fn new(data_dir: &str) -> FsResult<Self> {
        let path = PathBuf::from(&data_dir);

        ensure_structure_created(&path)?;

        let mut fs = EncryptedFs { data_dir: path };
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
    pub fn create_nod(&mut self, parent: u64, name: &str, mut attr: FileAttr) -> FsResult<FileAttr> {
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

        Ok(attr.clone())
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
        }else if name == ".." {
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

    pub fn read(&mut self, ino: u64, offset: u64, mut buf: &mut [u8]) -> FsResult<usize> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let mut file = OpenOptions::new().read(true).open(path)?;
        file.seek(io::SeekFrom::Start(offset))?;
        let len = file.read(&mut buf)?;

        attr.atime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

        Ok(len)
    }

    pub fn write_all(&mut self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        let path = self.data_dir.join(CONTENTS_DIR).join(ino.to_string());
        let mut file = OpenOptions::new().write(true).open(path)?;
        file.seek(io::SeekFrom::Start(offset))?;
        file.write_all(buf)?;

        let size = max(attr.size, offset + buf.len() as u64);
        attr.size = size;
        attr.mtime = std::time::SystemTime::now();
        attr.ctime = std::time::SystemTime::now();
        self.write_inode(&attr)?;

        Ok(())
    }

    pub fn copy_file_range(&mut self, src_ino: u64, src_offset: u64, dest_ino: u64, dest_offset: u64, size: usize) -> FsResult<usize> {
        let mut src_attr = self.get_inode(src_ino)?;
        if matches!(src_attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }
        let mut dest_attr = self.get_inode(dest_ino)?;
        if matches!(dest_attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        let mut buf = vec![0; size];
        let len = self.read(src_ino, src_offset, &mut buf)?;
        self.write_all(dest_ino, dest_offset, &buf[..len])?;

        Ok(len)
    }

    pub fn truncate(&mut self, ino: u64, size: u64) -> FsResult<()> {
        let mut attr = self.get_inode(ino)?;
        if matches!(attr.kind, FileType::Directory) {
            return Err(FsError::InvalidInodeType);
        }

        let file = OpenOptions::new().write(true).open(self.data_dir.join(CONTENTS_DIR).join(ino.to_string()))?;
        file.set_len(size)?;
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

    fn write_inode(&mut self, attr: &FileAttr) -> FsResult<()> {
        let path = self.data_dir.join(INODES_DIR).join(attr.ino.to_string());
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok(bincode::serialize_into(file, &attr)?)
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
                use std::os::unix::fs::{MetadataExt};
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::{File, OpenOptions};
    use std::string::String;

    use fuser::{FileAttr, FileType};

    use crate::encrypted_fs::{CONTENTS_DIR, DirectoryEntry, EncryptedFs, FsError, INODES_DIR, ROOT_INODE, SECURITY_DIR};

    const TESTS_DATA_DIR: &str = "./tests-data/";

    const ROOT_INODE_STR: &str = "1";


    #[derive(Debug, Clone)]
    struct TestSetup {
        data_path: String,
    }

    struct SetupResult {
        fs: Option<EncryptedFs>,
        setup: TestSetup,
    }

    fn setup(setup: TestSetup) -> SetupResult {
        let path = setup.data_path.as_str();
        if fs::metadata(path).is_ok() {
            fs::remove_dir_all(path).unwrap();
        }
        fs::create_dir_all(path).unwrap();
        let fs = EncryptedFs::new(path).unwrap();

        SetupResult {
            fs: Some(fs),
            setup,
        }
    }

    fn teardown(mut result: SetupResult) {
        {
            let _fs = result.fs.take().unwrap();
        }
        fs::remove_dir_all(result.setup.data_path).unwrap();
    }

    fn run_test<T>(init: TestSetup, test: T)
        where T: FnOnce(&mut SetupResult) {
        let mut result = setup(init);
        test(&mut result);
        teardown(result);
    }

    fn create_attr(ino: u64, file_type: FileType) -> FileAttr {
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: std::time::SystemTime::now(),
            mtime: std::time::SystemTime::now(),
            ctime: std::time::SystemTime::now(),
            crtime: std::time::SystemTime::now(),
            kind: file_type,
            perm: if file_type == FileType::Directory { 0o755 } else { 0o644 },
            nlink: if file_type == FileType::Directory { 2 } else { 1 },
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags: 0,
        }
    }

    fn create_attr_from_type(file_type: FileType) -> FileAttr {
        create_attr(0, file_type)
    }

    #[test]
    fn test_write_and_get_inode() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_write_and_get_inode") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr = create_attr(42, FileType::RegularFile);
            fs.write_inode(&attr).unwrap();

            assert!(fs.node_exists(42));
            assert_eq!(fs.get_inode(42).unwrap(), attr);
            assert!(matches!(fs.get_inode(0), Err(FsError::InodeNotFound)));
            assert!(fs.data_dir.join(INODES_DIR).join("42").is_file());
        });
    }

    #[test]
    fn test_create_structure_and_root() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_create_structure_and_root") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            assert!(fs.node_exists(ROOT_INODE));
            assert!(fs.is_dir(ROOT_INODE));

            assert!(fs.data_dir.join(INODES_DIR).is_dir());
            assert!(fs.data_dir.join(CONTENTS_DIR).is_dir());
            assert!(fs.data_dir.join(SECURITY_DIR).is_dir());

            assert!(fs.data_dir.join(INODES_DIR).join(ROOT_INODE_STR).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).is_dir());
        });
    }

    #[test]
    fn test_create_nod() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_create_nod") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            // file in root
            let attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            assert_ne!(attr.ino, 0);
            assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join("test-file").is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).unwrap());

            let entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join("test-file")).unwrap()).unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::RegularFile));

            // directory in root
            let attr = fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)).unwrap();
            assert_ne!(attr.ino, 0);
            assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join("test-dir").is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
            assert!(fs.is_dir(attr.ino));
            let entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join("test-dir")).unwrap()).unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
            let dot_entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap()).unwrap();
            assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
            let dot_dot_entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap()).unwrap();
            assert_eq!(dot_dot_entry_in_parent, (ROOT_INODE, FileType::Directory));

            // directory in another directory
            let parent = attr.ino;
            let attr = fs.create_nod(parent, "test-dir-2", create_attr_from_type(FileType::Directory)).unwrap();
            assert!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_dir());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join("test-dir-2").is_file());
            assert!(fs.node_exists(attr.ino));
            assert_eq!(attr, fs.get_inode(attr.ino).unwrap());
            assert!(fs.is_dir(attr.ino));
            let entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(parent.to_string()).join("test-dir-2")).unwrap()).unwrap();
            assert_eq!(entry_in_parent, (attr.ino, FileType::Directory));
            let dot_entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$.")).unwrap()).unwrap();
            assert_eq!(dot_entry_in_parent, (attr.ino, FileType::Directory));
            let dot_dot_entry_in_parent: (u64, FileType) = bincode::deserialize_from(File::open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).join("$..")).unwrap()).unwrap();
            assert_eq!(dot_dot_entry_in_parent, (parent, FileType::Directory));

            // existing file
            assert!(matches!(
                fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)),
                Err(FsError::AlreadyExists)
                )
            );

            // existing directory
            assert!(matches!(
                fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)),
                Err(FsError::AlreadyExists)
                )
            );
        });
    }

    #[test]
    fn test_read_dir() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_read_dir") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            // file and directory in root
            let file_attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();

            let dir_attr = fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)).unwrap();
            let mut entries: Vec<DirectoryEntry> = fs.read_dir(dir_attr.ino).unwrap().into_iter().collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(entries.len(), 2);
            assert_eq!(vec![
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: ".".to_string(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: ROOT_INODE,
                    name: "..".to_string(),
                    kind: FileType::Directory,
                },
            ], entries);

            let into_iter = fs.read_dir(ROOT_INODE);
            let mut entries: Vec<DirectoryEntry> = into_iter.unwrap().into_iter().collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            let mut sample = vec![
                DirectoryEntry {
                    ino: ROOT_INODE,
                    name: ".".to_string(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: file_attr.ino,
                    name: "test-file".to_string(),
                    kind: FileType::RegularFile,
                },
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: "test-dir".to_string(),
                    kind: FileType::Directory,
                }];
            sample.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(entries.len(), 3);
            assert_eq!(sample, entries);

            // file and directory in another directory
            let parent = dir_attr.ino;
            let file_attr = fs.create_nod(parent, "test-file-2", create_attr_from_type(FileType::RegularFile)).unwrap();

            let dir_attr = fs.create_nod(parent, "test-dir-2", create_attr_from_type(FileType::Directory)).unwrap();
            let mut entries: Vec<DirectoryEntry> = fs.read_dir(dir_attr.ino).unwrap().into_iter().collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(entries.len(), 2);
            assert_eq!(vec![
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: ".".to_string(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: parent,
                    name: "..".to_string(),
                    kind: FileType::Directory,
                },
            ], entries);

            let into_iter = fs.read_dir(parent);
            let mut entries: Vec<DirectoryEntry> = into_iter.unwrap().into_iter().collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            let mut sample = vec![
                DirectoryEntry {
                    ino: parent,
                    name: ".".to_string(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: ROOT_INODE,
                    name: "..".to_string(),
                    kind: FileType::Directory,
                },
                DirectoryEntry {
                    ino: file_attr.ino,
                    name: "test-file-2".to_string(),
                    kind: FileType::RegularFile,
                },
                DirectoryEntry {
                    ino: dir_attr.ino,
                    name: "test-dir-2".to_string(),
                    kind: FileType::Directory,
                }];
            sample.sort_by(|a, b| a.name.cmp(&b.name));
            assert_eq!(entries.len(), 4);
            assert_eq!(sample, entries);
        });
    }

    #[test]
    fn test_find_by_name() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_find_by_name") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            assert!(fs.find_by_name(ROOT_INODE, "test-file").unwrap().is_some());
            assert!(fs.find_by_name(ROOT_INODE, "invalid").unwrap().is_none());
        });
    }

    #[test]
    fn test_remove_dir() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_remove_dir") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let dir_attr = fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)).unwrap();
            let file_attr = fs.create_nod(dir_attr.ino, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();

            assert!(matches!(fs.remove_dir(ROOT_INODE, "test-dir"), Err(FsError::NotEmpty)));
            assert!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(INODES_DIR).join(file_attr.ino.to_string()).is_file());
            assert!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).join("test-file").is_file());

            fs.remove_file(dir_attr.ino, "test-file").unwrap();
            assert!(fs.remove_dir(ROOT_INODE, "test-dir").is_ok());
            assert_ne!(fs.data_dir.join(INODES_DIR).join(dir_attr.ino.to_string()).exists(), true);
            assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(dir_attr.ino.to_string()).exists(), true);

            assert!(matches!(fs.remove_file(ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
        });
    }

    #[test]
    fn test_remove_file() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_remove_file") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            assert!(fs.remove_file(ROOT_INODE, "test-file").is_ok());
            assert_ne!(fs.data_dir.join(INODES_DIR).join(attr.ino.to_string()).is_file(), true);
            assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()).is_file(), true);
            assert_ne!(fs.data_dir.join(CONTENTS_DIR).join(ROOT_INODE_STR).join("test-file").is_file(), true);
            assert!(fs.find_by_name(ROOT_INODE, "test-file").unwrap().is_none());

            assert!(matches!(fs.remove_file(ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
        });
    }

    #[test]
    fn test_write_all() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_write_all") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            let data = "test-42";
            fs.write_all(attr.ino, 0, data.as_bytes()).unwrap();
            assert_eq!(data, fs::read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap());
            let attr = fs.get_inode(attr.ino).unwrap();
            assert_eq!(data.len() as u64, attr.size);

            // offset
            let data = "37";
            fs.write_all(attr.ino, 5, data.as_bytes()).unwrap();
            assert_eq!(data, &fs::read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap()[5..]);
            fs.write_all(attr.ino, 42, data.as_bytes()).unwrap();
            assert_eq!(format!("test-37{}37", "                                   ".replace(" ", "\0")),
                       fs::read_to_string(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap());

            let buf = [0; 0];
            assert!(matches!(fs.write_all(ROOT_INODE, 0, &buf), Err(FsError::InvalidInodeType)));
            assert!(matches!(fs.write_all(0, 0, &buf), Err(FsError::InodeNotFound)));
            let dir_attr = fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)).unwrap();
            assert!(matches!(fs.write_all(dir_attr.ino, 0, &buf), Err(FsError::InvalidInodeType)));
        });
    }

    #[test]
    fn test_read() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_read") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            let data = b"test-42";
            let mut buf = [0; 7];
            fs::write(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), data).unwrap();
            let len = fs.read(attr.ino, 0, &mut buf).unwrap();
            assert_eq!(len, 7);
            assert_eq!(data, &buf);

            // larger buffer
            let len = fs.read(attr.ino, 0, &mut [0; 42]).unwrap();
            assert_eq!(len, 7);

            // offset
            let data = b"test-37";
            let mut buf = [0; 2];
            fs::write(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string()), data).unwrap();
            fs.read(attr.ino, 5, &mut buf).unwrap();
            assert_eq!(b"37", &buf);
            let len = fs.read(attr.ino, 42, &mut [0, 1]).unwrap();
            assert_eq!(len, 0);

            let mut buf = [0; 0];
            assert!(matches!(fs.read(ROOT_INODE, 0, &mut buf), Err(FsError::InvalidInodeType)));
            assert!(matches!(fs.read(0, 0,&mut buf), Err(FsError::InodeNotFound)));
            let dir_attr = fs.create_nod(ROOT_INODE, "test-dir", create_attr_from_type(FileType::Directory)).unwrap();
            assert!(matches!(fs.read(dir_attr.ino, 0, &mut buf), Err(FsError::InvalidInodeType)));
        });
    }

    #[test]
    fn test_truncate() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_truncate") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr = fs.create_nod(ROOT_INODE, "test-file", create_attr_from_type(FileType::RegularFile)).unwrap();

            // size increase
            fs.truncate(attr.ino, 42).unwrap();
            let file = OpenOptions::new().write(true).open(fs.data_dir.join(CONTENTS_DIR).join(attr.ino.to_string())).unwrap();
            assert_eq!(42, file.metadata().unwrap().len());
            assert_eq!(42, fs.get_inode(attr.ino).unwrap().size);

            // size doesn't change
            fs.truncate(attr.ino, 42).unwrap();
            assert_eq!(42, file.metadata().unwrap().len());
            assert_eq!(42, fs.get_inode(attr.ino).unwrap().size);

            // size decrease
            fs.truncate(attr.ino, 37).unwrap();
            assert_eq!(37, file.metadata().unwrap().len());
            assert_eq!(37, fs.get_inode(attr.ino).unwrap().size);

            // size decrease to 0
            fs.truncate(attr.ino, 0).unwrap();
            assert_eq!(0, file.metadata().unwrap().len());
            assert_eq!(0, fs.get_inode(attr.ino).unwrap().size);
        });
    }

    #[test]
    fn test_copy_file_range() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_sample") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            let attr_1 = fs.create_nod(ROOT_INODE, "test-file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            let data = "test-42";
            fs.write_all(attr_1.ino, 0, data.as_bytes()).unwrap();
            let attr_2 = fs.create_nod(ROOT_INODE, "test-file-2", create_attr_from_type(FileType::RegularFile)).unwrap();

            // whole file
            let len = fs.copy_file_range(attr_1.ino, 0, attr_2.ino, 0, 7).unwrap();
            assert_eq!(len, 7);
            let mut buf = [0; 7];
            fs.read(attr_2.ino, 0, &mut buf).unwrap();
            assert_eq!(data, String::from_utf8(buf.to_vec()).unwrap());

            // offset
            let data_37 = "37";
            fs.write_all(attr_1.ino, 7, data_37.as_bytes()).unwrap();
            let len = fs.copy_file_range(attr_1.ino, 7, attr_2.ino, 5, 2).unwrap();
            assert_eq!(len, 2);
            fs.read(attr_2.ino, 0, &mut buf).unwrap();
            assert_eq!("test-37", String::from_utf8(buf.to_vec()).unwrap());

            // out of bounds
            let len = fs.copy_file_range(attr_1.ino, 42, attr_2.ino, 0, 2).unwrap();
            assert_eq!(len, 0);

            // invalid inodes
            assert!(matches!(fs.copy_file_range(0, 0, 0, 0, 0), Err(FsError::InodeNotFound)));
        });
    }

    #[test]
    fn test_rename() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_rename") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();

            // new file in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            fs.rename(ROOT_INODE, "file-1", new_parent, "file-1-new").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "file-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "file-1-new"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "file-1-new").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-1-new").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-1-new").count(), 1);

            // new directory in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-1", new_parent, "dir-1-new").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "dir-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "dir-1-new"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "dir-1-new").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-1-new").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-1-new").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            let new_parent_attr = fs.create_nod(ROOT_INODE, "dir-new-parent", create_attr_from_type(FileType::Directory)).unwrap();

            // new file to another directory
            let new_parent = new_parent_attr.ino;
            let attr = fs.create_nod(ROOT_INODE, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            fs.rename(ROOT_INODE, "file-1", new_parent, "file-2").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "file-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "file-2"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "file-2").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-2").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 0);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-new").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-2").count(), 1);

            // new directory to another directory
            let new_parent = new_parent_attr.ino;
            let attr = fs.create_nod(ROOT_INODE, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-1", new_parent, "dir-2").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "dir-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "dir-2"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "dir-2").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-2").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 0);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-2").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-2").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // file to existing file in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "file-2", create_attr_from_type(FileType::RegularFile)).unwrap();
            fs.rename(ROOT_INODE, "file-1", new_parent, "file-2").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "file-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "file-2"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "file-2").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-2").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-2").count(), 1);

            // directory to existing directory in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "dir-2", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-1", new_parent, "dir-2").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "dir-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "dir-2"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "dir-2").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-2").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-2").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // file to existing file in another directory
            let new_parent = new_parent_attr.ino;
            let attr = fs.create_nod(ROOT_INODE, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            fs.rename(ROOT_INODE, "file-1", new_parent, "file-1").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "file-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "file-1"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "file-1").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-1").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 1);

            // directory to existing directory in another directory
            let new_parent = new_parent_attr.ino;
            let attr = fs.create_nod(ROOT_INODE, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-1", new_parent, "dir-1").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "dir-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "dir-1"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "dir-1").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-1").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // overwriting directory with file
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "file-1", create_attr_from_type(FileType::RegularFile)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "dir-1", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "file-1", new_parent, "dir-1").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "file-1"), true);
            assert_eq!(fs.exists_by_name(new_parent, "dir-1"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "dir-1").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-1").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-1").count(), 1);

            // overwriting file with directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "dir-3", create_attr_from_type(FileType::Directory)).unwrap();
            let attr_2 = fs.create_nod(new_parent, "file-1", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-3", new_parent, "file-1").unwrap();
            assert_ne!(fs.exists_by_name(ROOT_INODE, "dir-3"), true);
            assert_eq!(fs.exists_by_name(new_parent, "file-1"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "file-1").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-1").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-3").count(), 0);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-1").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // overwriting non-empty directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "dir-3", create_attr_from_type(FileType::Directory)).unwrap();
            let attr_2 = new_parent_attr;
            let name_2 = "dir-new-parent";
            assert!(matches!(fs.rename(ROOT_INODE, "dir-3", new_parent, name_2), Err(FsError::NotEmpty)));
            assert_eq!(fs.exists_by_name(ROOT_INODE, "dir-3"), true);
            assert_eq!(fs.exists_by_name(new_parent, name_2), true);
            assert_eq!(fs.is_dir(fs.find_by_name(ROOT_INODE, "dir-3").unwrap().unwrap().ino), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, name_2).unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-3").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            let new_attr_2 = fs.find_by_name(new_parent, name_2).unwrap().unwrap();
            assert_eq!(new_attr_2.ino, attr_2.ino);
            assert_eq!(new_attr_2.kind, attr_2.kind);
            assert_eq!(fs.read_dir(ROOT_INODE).unwrap().into_iter().filter(|entry| entry.name == "dir-3").count(), 1);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == name_2).count(), 1);
            assert_eq!(fs.find_by_name(new_attr_2.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr_2.ino, ".").unwrap().unwrap().ino, new_attr_2.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // same file in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "file-3", create_attr_from_type(FileType::RegularFile)).unwrap();
            fs.rename(ROOT_INODE, "file-3", new_parent, "file-3").unwrap();
            assert_eq!(fs.exists_by_name(new_parent, "file-3"), true);
            assert_eq!(fs.is_file(fs.find_by_name(new_parent, "file-3").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "file-3").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "file-3").count(), 1);

            // same directory in same directory
            let new_parent = ROOT_INODE;
            let attr = fs.create_nod(ROOT_INODE, "dir-5", create_attr_from_type(FileType::Directory)).unwrap();
            fs.rename(ROOT_INODE, "dir-5", new_parent, "dir-5").unwrap();
            assert_eq!(fs.exists_by_name(new_parent, "dir-5"), true);
            assert_eq!(fs.is_dir(fs.find_by_name(new_parent, "dir-5").unwrap().unwrap().ino), true);
            let new_attr = fs.find_by_name(new_parent, "dir-5").unwrap().unwrap();
            assert_eq!(new_attr.ino, attr.ino);
            assert_eq!(new_attr.kind, attr.kind);
            assert_eq!(fs.read_dir(new_parent).unwrap().into_iter().filter(|entry| entry.name == "dir-5").count(), 1);
            assert_eq!(fs.find_by_name(new_attr.ino, "..").unwrap().unwrap().ino, new_parent);
            assert_eq!(fs.find_by_name(new_attr.ino, ".").unwrap().unwrap().ino, new_attr.ino);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == "..").count(), 1);
            assert_eq!(fs.read_dir(new_attr.ino).unwrap().into_iter().filter(|entry| entry.name == ".").count(), 1);

            // invalid nodes and name
            assert!(matches!(fs.rename(0, "invalid", 0, "invalid"), Err(FsError::InodeNotFound)));
            let attr_file = fs.create_nod(ROOT_INODE, "existing-file", create_attr_from_type(FileType::RegularFile)).unwrap();
            assert!(matches!(fs.rename(attr_file.ino, "invalid", 0, "invalid"), Err(FsError::InvalidInodeType)));
            assert!(matches!(fs.rename(ROOT_INODE, "invalid", ROOT_INODE, "invalid"), Err(FsError::NotFound(_))));
            assert!(matches!(fs.rename(ROOT_INODE, "existing-file", 0, "invalid"), Err(FsError::InodeNotFound)));
            assert!(matches!(fs.rename(ROOT_INODE, "existing-file", attr_file.ino, "invalid"), Err(FsError::InvalidInodeType)));
        });
    }

    fn test_sample() {
        run_test(TestSetup { data_path: format!("{}{}", TESTS_DATA_DIR, "test_sample") }, |setup| {
            let fs = setup.fs.as_mut().unwrap();
        });
    }
}