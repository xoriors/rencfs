use pyo3::exceptions::{PyFileNotFoundError, PyPermissionError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rencfs::crypto::Cipher as RustCipher;
use rencfs::encryptedfs::{
    CreateFileAttr as RustCreateFileAttr, FileAttr as RustFileAttr, FileType as RustFileType,
    FsError, SetFileAttr as RustSetFileAttr,
};

/// Wrapper for the FileType
#[pyclass]
#[derive(Clone, PartialEq, Debug)]
pub enum FileType {
    RegularFile,
    Directory,
}

impl From<RustFileType> for FileType {
    fn from(kind: RustFileType) -> Self {
        match kind {
            RustFileType::RegularFile => FileType::RegularFile,
            RustFileType::Directory => FileType::Directory,
        }
    }
}

impl From<FileType> for RustFileType {
    fn from(kind: FileType) -> Self {
        match kind {
            FileType::RegularFile => RustFileType::RegularFile,
            FileType::Directory => RustFileType::Directory,
        }
    }
}

/// Wrapper for the supported Ciphers
#[pyclass]
#[derive(Clone, PartialEq, Debug)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl From<RustCipher> for Cipher {
    fn from(cipher: RustCipher) -> Self {
        match cipher {
            RustCipher::Aes256Gcm => Cipher::Aes256Gcm,
            RustCipher::ChaCha20Poly1305 => Cipher::ChaCha20Poly1305,
        }
    }
}

impl From<Cipher> for RustCipher {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::Aes256Gcm => RustCipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305 => RustCipher::ChaCha20Poly1305,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct CreateFileAttr {
    #[pyo3(get, set)]
    pub kind: FileType,
    #[pyo3(get, set)]
    pub perm: u16,
    #[pyo3(get, set)]
    pub uid: u32,
    #[pyo3(get, set)]
    pub gid: u32,
    #[pyo3(get, set)]
    pub rdev: u32,
    #[pyo3(get, set)]
    pub flags: u32,
}

#[pymethods]
impl CreateFileAttr {
    #[new]
    #[pyo3(signature = (kind, perm, uid, gid, rdev=0, flags=0))]
    fn new(kind: FileType, perm: u16, uid: u32, gid: u32, rdev: u32, flags: u32) -> Self {
        Self {
            kind,
            perm,
            uid,
            gid,
            rdev,
            flags,
        }
    }
}

impl From<CreateFileAttr> for RustCreateFileAttr {
    fn from(attr: CreateFileAttr) -> Self {
        RustCreateFileAttr {
            kind: attr.kind.into(),
            perm: attr.perm,
            uid: attr.uid,
            gid: attr.gid,
            rdev: attr.rdev,
            flags: attr.flags,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct FileAttr {
    #[pyo3(get, set)]
    pub ino: u64,
    #[pyo3(get, set)]
    pub size: u64,
    #[pyo3(get, set)]
    pub blocks: u64,
    #[pyo3(get, set)]
    pub atime: u64,
    #[pyo3(get, set)]
    pub mtime: u64,
    #[pyo3(get, set)]
    pub ctime: u64,
    #[pyo3(get, set)]
    pub crtime: u64,
    #[pyo3(get, set)]
    pub kind: FileType,
    #[pyo3(get, set)]
    pub perm: u16,
    #[pyo3(get, set)]
    pub nlink: u32,
    #[pyo3(get, set)]
    pub uid: u32,
    #[pyo3(get, set)]
    pub gid: u32,
    #[pyo3(get, set)]
    pub rdev: u32,
    #[pyo3(get, set)]
    pub blksize: u32,
    #[pyo3(get, set)]
    pub flags: u32,
}

impl From<RustFileAttr> for FileAttr {
    fn from(attr: RustFileAttr) -> Self {
        Self {
            ino: attr.ino,
            size: attr.size,
            blocks: attr.blocks,
            atime: attr
                .atime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mtime: attr
                .mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ctime: attr
                .ctime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            crtime: attr
                .crtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            kind: attr.kind.into(),
            perm: attr.perm,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: attr.rdev,
            blksize: attr.blksize,
            flags: attr.flags,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SetFileAttr {
    #[pyo3(get, set)]
    pub size: Option<u64>,
    #[pyo3(get, set)]
    pub atime: Option<u64>,
    #[pyo3(get, set)]
    pub mtime: Option<u64>,
    #[pyo3(get, set)]
    pub ctime: Option<u64>,
    #[pyo3(get, set)]
    pub crtime: Option<u64>,
    #[pyo3(get, set)]
    pub perm: Option<u16>,
    #[pyo3(get, set)]
    pub uid: Option<u32>,
    #[pyo3(get, set)]
    pub gid: Option<u32>,
    #[pyo3(get, set)]
    pub rdev: Option<u32>,
    #[pyo3(get, set)]
    pub flags: Option<u32>,
}

#[pymethods]
impl SetFileAttr {
    #[new]
    #[pyo3(signature = (size=None, atime=None, mtime=None, ctime=None, crtime=None, perm=None, uid=None, gid=None, rdev=None, flags=None))]
    fn new(
        size: Option<u64>,
        atime: Option<u64>,
        mtime: Option<u64>,
        ctime: Option<u64>,
        crtime: Option<u64>,
        perm: Option<u16>,
        uid: Option<u32>,
        gid: Option<u32>,
        rdev: Option<u32>,
        flags: Option<u32>,
    ) -> Self {
        Self {
            size,
            atime,
            mtime,
            ctime,
            crtime,
            perm,
            uid,
            gid,
            rdev,
            flags,
        }
    }
}

impl SetFileAttr {
    pub fn into_rust(&self) -> RustSetFileAttr {
        let to_system_time = |opt: Option<u64>| {
            opt.map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
        };
        RustSetFileAttr {
            size: self.size,
            atime: to_system_time(self.atime),
            mtime: to_system_time(self.mtime),
            ctime: to_system_time(self.ctime),
            crtime: to_system_time(self.crtime),
            perm: self.perm,
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            flags: self.flags,
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct DirEntry {
    #[pyo3(get)]
    pub ino: u64,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub kind: FileType,
}

#[pymethods]
impl DirEntry {
    #[new]
    pub fn new(ino: u64, name: String, kind: FileType) -> Self {
        Self { ino, name, kind }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct DirEntryPlus {
    #[pyo3(get)]
    pub ino: u64,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub kind: FileType,
    #[pyo3(get)]
    pub attr: FileAttr,
}

#[pymethods]
impl DirEntryPlus {
    #[new]
    pub fn new(ino: u64, name: String, kind: FileType, attr: FileAttr) -> Self {
        Self {
            ino,
            name,
            kind,
            attr,
        }
    }
}

pub struct PyFsError(pub FsError);

impl From<FsError> for PyFsError {
    fn from(err: FsError) -> Self {
        PyFsError(err)
    }
}

impl From<PyFsError> for PyErr {
    fn from(err: PyFsError) -> PyErr {
        match err.0 {
            FsError::InodeNotFound => PyFileNotFoundError::new_err("Inode not found"),
            FsError::AlreadyExists => {
                pyo3::exceptions::PyFileExistsError::new_err("File already exists")
            }
            FsError::InvalidInput(msg) => PyValueError::new_err(msg.to_string()),
            FsError::ReadOnly => PyPermissionError::new_err("File system is read only"),
            e => PyRuntimeError::new_err(e.to_string()),
        }
    }
}
