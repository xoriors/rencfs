#![allow(dead_code)]
#![allow(unused_variables)]

use crate::async_util;
use shush_rs::SecretBox;

use crate::crypto::fs::OpenOptions;
use crate::encryptedfs::{EncryptedFs, FileAttr, FileType, FsError, FsResult};
use std::collections::TryReserveError;
use std::ffi::OsStr;
use std::ops::Deref;
use std::{
    borrow::Cow,
    ffi::OsString,
    fs::ReadDir,
    io::Result,
    path::{Components, Display, Iter, StripPrefixError},
    sync::Arc,
    time::SystemTime,
};

#[cfg(test)]
mod test;

pub struct Metadata {
    pub attr: FileAttr,
}

impl std::fmt::Debug for Metadata {
    fn fmt<'a>(&self, f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result {
        f.debug_struct("Metadata")
            .field("ino", &self.attr.ino)
            .field("size", &self.attr.size)
            .field("blocks", &self.attr.blocks)
            .field("kind", &self.attr.kind)
            .field("perm", &format_args!("{:#o}", self.attr.perm))
            .field("nlink", &self.attr.nlink)
            .field("uid", &self.attr.uid)
            .field("gid", &self.attr.gid)
            .finish()
    }
}

impl Metadata {
    pub fn accessed(&self) -> Result<SystemTime> {
        Ok(self.attr.atime)
    }

    pub fn modified(&self) -> Result<SystemTime> {
        Ok(self.attr.mtime)
    }

    pub fn created(&self) -> Result<SystemTime> {
        Ok(self.attr.crtime)
    }

    pub fn file_type(&self) -> FileType {
        self.attr.kind
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.attr.kind, FileType::RegularFile)
    }

    pub fn is_file(&self) -> bool {
        matches!(self.attr.kind, FileType::Directory)
    }

    // pub fn is_symlink(&self) -> bool {
    // matches!(self.attr.kind, FileType::Symlink)
    // }

    pub fn len(&self) -> u64 {
        self.attr.size
    }

    pub fn permissions(&self) -> u64 {
        self.attr.perm as u64
    }
}

#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Path<'a> {
    inner: &'a OsStr,
}

impl<'a> Path<'a> {
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &'a S) -> &'a Path<'a> {
        unsafe { &*(s.as_ref() as *const OsStr as *const Path) }
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.inner
    }

    pub fn to_str(&self) -> Option<&str> {
        self.inner.to_str()
    }

    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        self.inner.to_string_lossy()
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.inner)
    }

    pub fn is_absolute(&self) -> bool {
        let path = std::path::Path::new(&self.inner);
        std::path::Path::is_absolute(path)
    }

    pub fn is_relative(&self) -> bool {
        let path = std::path::Path::new(&self.inner);
        std::path::Path::is_relative(path)
    }

    pub fn has_root(&self) -> bool {
        let path = std::path::Path::new(&self.inner);
        std::path::Path::has_root(path)
    }

    pub fn parent(&self) -> Option<&Path> {
        let path = std::path::Path::new(self.inner);
        path.parent().map(|parent| Path::new(parent.as_os_str()))
    }

    pub fn ancestors(&self) -> impl Iterator<Item = &Path<'a>> + '_ {
        let path = std::path::Path::new(self.inner);

        path.ancestors()
            .map(|ancestor| Path::new(ancestor.as_os_str()))
    }

    pub fn file_name(&self) -> Option<&OsStr> {
        let path = std::path::Path::new(&self.inner);
        path.file_name()
    }

    pub fn strip_prefix<P>(&'a self, base: P) -> std::result::Result<&'a Path<'a>, StripPrefixError>
    where
        P: AsRef<std::path::Path>,
    {
        let path = std::path::Path::new(&self.inner);

        match path.strip_prefix(base.as_ref()) {
            Ok(stripped) => {
                Ok(Path::new(stripped.as_os_str()))
            }
            Err(e) => Err(e),
        }
    }

    pub fn starts_with<P: AsRef<std::path::Path>>(&self, base: P) -> bool {
        let path = std::path::Path::new(&self.inner);
        let base_path = base.as_ref();
        path.starts_with(base_path)
    }

    pub fn ends_with<P: AsRef<std::path::Path>>(&self, base: P) -> bool {
        let path = std::path::Path::new(&self.inner);
        let child_path = base.as_ref();
        path.ends_with(child_path)
    }

    pub fn file_stem(&self) -> Option<&OsStr> {
        let path = std::path::Path::new(&self.inner);
        path.file_stem()
    }

    pub fn extension(&self) -> Option<&OsStr> {
        let path = std::path::Path::new(&self.inner);
        path.extension()
    }

    pub fn join<S: AsRef<str>>(&self, subpath: S) -> PathBuf {
        let path = std::path::Path::new(&self.inner);
        let sub_path = std::path::Path::new(subpath.as_ref());
        PathBuf::from(path.join(sub_path))
    }

    pub fn with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> PathBuf {
        let path = std::path::Path::new(&self.inner);
        let file_name = std::path::Path::new(file_name.as_ref());
        PathBuf::from(path.with_file_name(file_name))
    }

    pub fn with_extension<S: AsRef<OsStr>>(&self, extension: S) -> PathBuf {
        let path = std::path::Path::new(&self.inner);
        let extension = std::path::Path::new(extension.as_ref());
        PathBuf::from(path.with_extension(extension))
    }

    pub fn components(&self) -> Components<'_> {
        let path = std::path::Path::new(&self.inner);
        path.components()
    }

    pub fn iter(&self) -> Iter<'_> {
        let path = std::path::Path::new(&self.inner);
        path.iter()
    }

    pub fn display(&self) -> Display<'_> {
        let path = std::path::Path::new(&self.inner);
        path.display()
    }

    pub fn metadata(&self) -> Result<Metadata> {
        let mut dir_inode = 1;

        let fs = async_util::call_async(get_fs())?;

        let paths = get_path_and_file_name(
            &self
                .to_str()
                .ok_or_else(|| FsError::InvalidInput("Invalid path"))?,
        );

        if paths.len() > 1 {
            for node in paths.iter().take(paths.len() - 1) {
                dir_inode = async_util::call_async(fs.find_by_name(dir_inode, node))?
                    .ok_or_else(|| FsError::InodeNotFound)?
                    .ino;
            }
        }

        let file_name = paths
            .last()
            .ok_or_else(|| FsError::InvalidInput("No filename"))?;
        let attr = async_util::call_async(fs.find_by_name(dir_inode, file_name))?
            .ok_or_else(|| FsError::InodeNotFound)?;
        let file_attr = async_util::call_async(fs.get_attr(attr.ino))?;

        let metadata = Metadata { attr: file_attr };
        Ok(metadata)
    }

    // pub fn symlink_metadata(&self) -> Result<Metadata> {
    //     todo!()
    // }

    pub fn canonicalize(&self) -> Result<PathBuf> {
        todo!()
    }

    pub fn read_link(&self) -> Result<PathBuf> {
        todo!()
    }

    pub fn read_dir(&self) -> Result<ReadDir> {
        todo!()
    }

    pub fn exists(&self) -> bool {
        Path::metadata(&self).is_ok()
    }

    pub async fn try_exists(&self) -> Result<bool> {
        let fs = async_util::call_async(get_fs())?;
        let paths = get_path_and_file_name(
            &self
                .to_str()
                .ok_or_else(|| FsError::InvalidInput("Invalid path"))?,
        );
        let file_name = paths
            .last()
            .ok_or_else(|| FsError::InvalidInput("No filename"))?;
        let mut dir_inode = 1;
        if paths.len() > 1 {
            for node in paths.iter().take(paths.len() - 1) {
                dir_inode = async_util::call_async(fs.find_by_name(dir_inode, node))?
                    .ok_or_else(|| FsError::InodeNotFound)?
                    .ino;
            }
        }
        let file_exists = async_util::call_async(fs.find_by_name(dir_inode, file_name))?.is_some();
        Ok(file_exists)
    }

    pub async fn is_file(&self) -> bool {
        Path::metadata(&self).unwrap().is_file()
    }

    pub async fn is_dir(&self) -> bool {
        Path::metadata(&self).unwrap().is_dir()
    }

    // pub async fn is_symlink(&self) -> bool {
    //     Path::metadata(&self).unwrap().is_symlink()
    // }

    pub async fn into_path_buf(self: Box<Path<'a>>) -> PathBuf {
        PathBuf::from(self.inner)
    }
}

impl<'a> std::fmt::Debug for Path<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl<'a> AsRef<std::path::Path> for Path<'a> {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.inner)
    }
}

impl<'a> AsRef<OsStr> for Path<'a> {
    fn as_ref(&self) -> &OsStr {
        self.inner.as_ref()
    }
}

impl<'a> From<&'a String> for Path<'a> {
    fn from(s: &'a String) -> Self {
        Path {
            inner: &OsStr::new(s),
        }
    }
}

impl<'a> From<&'a str> for Path<'a> {
    fn from(s: &'a str) -> Self {
        Path {
            inner: &OsStr::new(s),
        }
    }
}

impl<'a> From<&'a std::path::Path> for Path<'a> {
    fn from(p: &'a std::path::Path) -> Self {
        Path {
            inner: p.as_os_str(),
        }
    }
}

impl<'a> From<&'a std::path::PathBuf> for Path<'a> {
    fn from(p: &'a std::path::PathBuf) -> Self {
        let inner = p.as_os_str();
        Path { inner }
    }
}

impl<'a> Into<OsString> for Path<'a> {
    fn into(self) -> OsString {
        self.inner.to_owned()
    }
}

impl<'a> PartialEq<PathBuf> for Path<'a> {
    fn eq(&self, other: &PathBuf) -> bool {
        self.inner == other.inner.as_os_str()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PathBuf {
    inner: OsString,
}

impl std::fmt::Debug for PathBuf {
    fn fmt<'a>(&self, f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl PathBuf {
    pub fn new() -> Self {
        PathBuf {
            inner: OsString::new(),
        }
    }

    pub fn from<S: Into<OsString>>(path: S) -> Self {
        Self { inner: path.into() }
    }

    pub fn with_capacity(capacity: usize) -> PathBuf {
        todo!()
    }

    pub fn as_path(&self) -> Self {
        todo!()
    }

    pub fn push<'a, P: AsRef<Path<'a>>>(&mut self, path: P) {
        todo!()
    }

    pub fn pop(&mut self) -> bool {
        todo!()
    }

    pub fn set_file_name<S: AsRef<OsStr>>(&mut self, file_name: S) {
        todo!()
    }

    pub fn set_extension<S: AsRef<OsStr>>(&mut self, extension: S) -> bool {
        todo!()
    }

    pub fn as_mut_os_str(&mut self) -> &mut OsString {
        todo!()
    }

    pub fn into_os_string(self) -> OsString {
        todo!()
    }

    pub fn into_boxed_path(self) -> Box<Path<'static>> {
        todo!()
    }

    pub fn capacity(&self) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn reserve(&mut self, additional: usize) {
        todo!()
    }

    pub fn try_reserve(&mut self, additional: usize) -> std::result::Result<(), TryReserveError> {
        todo!()
    }

    pub fn reserve_exact(&mut self, additional: usize) {
        todo!()
    }

    pub fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), TryReserveError> {
        todo!()
    }

    pub fn shrink_to_fit(&mut self) {
        todo!()
    }

    pub fn shrink_to(&mut self, min_capacity: usize) {
        todo!()
    }
}

impl<'a> PartialEq<&Path<'a>> for PathBuf {
    fn eq(&self, other: &&Path) -> bool {
        self.inner == other.inner
    }
}

impl AsRef<std::path::Path> for PathBuf {
    fn as_ref(&self) -> &std::path::Path {
        self.inner.as_ref()
    }
}

impl AsRef<OsStr> for PathBuf {
    fn as_ref(&self) -> &OsStr {
        self.inner.as_os_str()
    }
}

impl Into<OsString> for PathBuf {
    fn into(self) -> OsString {
        self.inner
    }
}

impl<'a> AsRef<Path<'a>> for PathBuf {
    fn as_ref(&self) -> &Path<'a> {
        Path::new(self)
    }
}

impl Deref for PathBuf {
    type Target = Path<'static>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
    OpenOptions::from_scope()
        .await
        .ok_or(FsError::Other("not initialized"))
}

pub fn get_path_and_file_name(path: &str) -> Vec<SecretBox<String>> {
    let path = Path::new(path);
    path.components()
        .filter_map(|comp| {
            if let std::path::Component::Normal(c) = comp {
                Some(SecretBox::new(Box::new(c.to_string_lossy().to_string())))
            } else {
                None
            }
        })
        .collect()
}
