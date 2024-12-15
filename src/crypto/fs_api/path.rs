#![allow(dead_code)]
#![allow(unused_variables)]

use crate::async_util;

use crate::crypto::fs_api::fs::{Metadata, OpenOptions};
use crate::encryptedfs::{EncryptedFs, FsError, FsResult};
use std::borrow::Borrow;
use std::collections::TryReserveError;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::str::FromStr;
use std::{
    borrow::Cow,
    ffi::OsString,
    fs::ReadDir,
    io::Result,
    path::{Components, Display, Iter, StripPrefixError},
    sync::Arc,
};

#[cfg(test)]
mod test;

/// Wrapper around [`std::path::Path`] to allow use on EncryptedFs.
///
#[allow(clippy::new_without_default)]
#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Path {
    inner: OsStr,
}

impl Path {
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &Path {
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

    pub fn as_mut_os_str(&mut self) -> &mut OsStr {
        &mut self.inner
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
        let path = std::path::Path::new(&self.inner);
        path.parent().map(|parent| Path::new(parent.as_os_str()))
    }

    pub fn ancestors(&self) -> impl Iterator<Item = &Path> + '_ {
        let path = std::path::Path::new(&self.inner);

        path.ancestors()
            .map(|ancestor| Path::new(ancestor.as_os_str()))
    }

    pub fn file_name(&self) -> Option<&OsStr> {
        let path = std::path::Path::new(&self.inner);
        path.file_name()
    }

    pub fn strip_prefix<P>(&self, base: P) -> std::result::Result<&Path, StripPrefixError>
    where
        P: AsRef<std::path::Path>,
    {
        let path = std::path::Path::new(&self.inner);

        match path.strip_prefix(base.as_ref()) {
            Ok(stripped) => Ok(Path::new(stripped.as_os_str())),
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

    /// Queries the EncryptedFs file system to get information about a file or directory.
    ///
    /// Due to how the paths are canonicalized, they may leak.
    ///
    /// Metadata is a wrapped for rencfs::encryptedfs::FileAttr
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rencfs::crypto::fs_api::path::Path;
    ///
    /// let path = Path::new("/Minas/tirith");
    /// let metadata = path.metadata().expect("metadata call failed");
    /// println!("{:?}", metadata.file_type());
    /// ```
    pub fn metadata(&self) -> Result<Metadata> {
        async_util::call_async(crate::crypto::fs_api::fs::metadata(self))
    }

    pub fn symlink_metadata(&self) -> Result<Metadata> {
        unimplemented!()
    }

    /// Returns the canonical form of the path with all intermediate
    /// components normalized and symbolic links resolved.
    ///
    /// Will not reveal the canonical base directory.
    ///
    /// Due to how the paths are canonicalized, they may leak.
    ///
    /// ```no_run
    /// use rencfs::crypto::fs_api::path::{Path, PathBuf};
    ///
    /// let path = Path::new("/foo/test/../test/bar.rs");
    /// assert_eq!(path.canonicalize().unwrap(), PathBuf::from("/foo/test/bar.rs"));
    /// ```
    pub fn canonicalize(&self) -> Result<PathBuf> {
        let mut stack = vec![];
        for comp in self.components() {
            match comp {
                std::path::Component::Normal(c) => {
                    stack.push(c);
                }
                std::path::Component::ParentDir => {
                    stack.pop();
                }
                std::path::Component::CurDir => {
                    continue;
                }
                _ => {
                    continue;
                }
            }
        }

        Ok(stack.iter().collect::<PathBuf>())
    }

    pub fn read_link(&self) -> Result<PathBuf> {
        let path = std::path::Path::new(&self.inner);
        Ok(PathBuf::from(path.read_link()))
    }

    pub fn read_dir(&self) -> Result<ReadDir> {
        let path = std::path::Path::new(&self.inner);
        path.read_dir()
    }

    /// Returns `true` if the path points at an existing entity.
    ///
    /// Due to how the paths are canonicalized, they may leak.
    pub fn exists(&self) -> bool {
        Path::metadata(self).is_ok()
    }

    /// Returns `Ok(true)` if the path points at an existing entity.
    ///
    /// Due to how the paths are canonicalized, they may leak.
    pub fn try_exists(&self) -> Result<bool> {
        async_util::call_async(crate::crypto::fs_api::fs::exists(self))
    }

    pub fn is_file(&self) -> bool {
        match Path::metadata(self) {
            Ok(metadata) => metadata.is_file(),
            Err(_) => false,
        }
    }

    pub fn is_dir(&self) -> bool {
        match Path::metadata(self) {
            Ok(metadata) => metadata.is_dir(),
            Err(_) => false,
        }
    }

    pub fn is_symlink(&self) -> bool {
        match Path::metadata(self) {
            Ok(metadata) => metadata.is_symlink(),
            Err(_) => false,
        }
    }

    #[allow(clippy::boxed_local)]
    pub fn into_path_buf(self: Box<Path>) -> PathBuf {
        PathBuf::from(&self.inner)
    }

    fn from_inner_mut(inner: &mut OsStr) -> &mut Path {
        unsafe { &mut *(inner as *mut OsStr as *mut Path) }
    }
}

impl Deref for Path {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        std::path::Path::new(&self.inner)
    }
}

impl AsRef<std::path::Path> for Path {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.inner)
    }
}

impl AsRef<OsStr> for Path {
    fn as_ref(&self) -> &OsStr {
        &self.inner
    }
}

impl AsRef<Path> for Cow<'_, OsStr> {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for Iter<'_> {
    fn as_ref(&self) -> &Path {
        Path::new(self.as_path())
    }
}

impl AsRef<Path> for OsStr {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for OsString {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self.deref()
    }
}

impl Clone for Box<Path> {
    fn clone(&self) -> Self {
        self.to_path_buf().into_boxed_path()
    }
}

impl From<&Path> for Arc<Path> {
    fn from(s: &Path) -> Arc<Path> {
        let arc: Arc<OsStr> = Arc::from(s.as_os_str());
        unsafe { Arc::from_raw(Arc::into_raw(arc) as *const Path) }
    }
}

impl From<&Path> for Box<Path> {
    fn from(path: &Path) -> Box<Path> {
        let boxed: Box<OsStr> = path.inner.into();
        let rw = Box::into_raw(boxed) as *mut Path;
        unsafe { Box::from_raw(rw) }
    }
}

impl<'a> From<&'a Path> for Cow<'a, Path> {
    fn from(s: &'a Path) -> Cow<'a, Path> {
        Cow::Borrowed(s)
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;
    fn to_owned(&self) -> PathBuf {
        self.to_path_buf()
    }
    fn clone_into(&self, target: &mut PathBuf) {
        self.inner.clone_into(&mut target.inner);
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self.inner)
    }
}

impl PartialEq<PathBuf> for Path {
    fn eq(&self, other: &PathBuf) -> bool {
        &self.inner == other.inner.as_os_str()
    }
}

impl PartialEq<PathBuf> for &Path {
    fn eq(&self, other: &PathBuf) -> bool {
        (*self).eq(other)
    }
}

impl PartialEq<std::path::Path> for Path {
    fn eq(&self, other: &std::path::Path) -> bool {
        &self.inner == other.as_os_str()
    }
}

/// Wrapper around [`std::path::PathBuf`] to allow use on EncryptedFs.
///
#[derive(PartialEq, Eq)]
pub struct PathBuf {
    inner: OsString,
}

impl std::fmt::Debug for PathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

#[allow(clippy::new_without_default)]
impl PathBuf {
    pub fn new() -> PathBuf {
        PathBuf {
            inner: OsString::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> PathBuf {
        PathBuf {
            inner: OsString::with_capacity(capacity),
        }
    }

    pub fn as_path(&self) -> &Path {
        self
    }

    pub fn push<P: AsRef<Path>>(&mut self, path: P) {
        let mut path_buf = std::path::PathBuf::with_capacity(self.capacity());
        path_buf.push(&self.inner);
        path_buf.push(path.as_ref());
        self.inner = path_buf.into_os_string();
    }

    pub fn pop(&mut self) -> bool {
        let mut path_buf = std::path::PathBuf::with_capacity(self.capacity());
        path_buf.push(&self.inner);
        let result = path_buf.pop();
        self.inner = path_buf.into();
        result
    }

    pub fn set_file_name<S: AsRef<OsStr>>(&mut self, file_name: S) {
        let mut path_buf = std::path::PathBuf::with_capacity(self.capacity());
        path_buf.push(&self.inner);
        path_buf.set_file_name(file_name);
        self.inner = path_buf.into();
    }

    pub fn set_extension<S: AsRef<OsStr>>(&mut self, extension: S) -> bool {
        let mut path_buf = std::path::PathBuf::with_capacity(self.capacity());
        path_buf.push(&self.inner);
        let result = path_buf.set_extension(extension);
        self.inner = path_buf.into();
        result
    }

    pub fn as_mut_os_string(&mut self) -> &mut OsString {
        &mut self.inner
    }

    pub fn into_os_string(self) -> OsString {
        self.inner
    }

    pub fn into_boxed_path(self) -> Box<Path> {
        let rw = Box::into_raw(self.inner.into_boxed_os_str()) as *mut Path;
        unsafe { Box::from_raw(rw) }
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    pub fn clear(&mut self) {
        self.inner.clear()
    }

    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional)
    }

    pub fn try_reserve(&mut self, additional: usize) -> std::result::Result<(), TryReserveError> {
        self.inner.try_reserve(additional)
    }

    pub fn reserve_exact(&mut self, additional: usize) {
        self.inner.reserve_exact(additional)
    }

    pub fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), TryReserveError> {
        self.inner.try_reserve_exact(additional)
    }

    pub fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit()
    }

    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.inner.shrink_to(min_capacity)
    }
}

impl Clone for PathBuf {
    fn clone(&self) -> Self {
        PathBuf {
            inner: self.inner.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.inner.clone_from(&source.inner)
    }
}

impl<'a> From<&'a PathBuf> for Cow<'a, Path> {
    fn from(p: &'a PathBuf) -> Cow<'a, Path> {
        Cow::Borrowed(p.as_path())
    }
}

impl<T: ?Sized + AsRef<OsStr>> From<&T> for PathBuf {
    fn from(s: &T) -> PathBuf {
        PathBuf::from(s.as_ref().to_os_string())
    }
}

impl From<std::result::Result<std::path::PathBuf, std::io::Error>> for PathBuf {
    fn from(value: std::result::Result<std::path::PathBuf, std::io::Error>) -> Self {
        match value {
            Ok(path) => PathBuf::from(path),
            Err(err) => PathBuf::new(),
        }
    }
}

#[allow(clippy::boxed_local)]
impl From<Box<Path>> for PathBuf {
    fn from(boxed: Box<Path>) -> PathBuf {
        boxed.into_path_buf()
    }
}

impl<'a> From<Cow<'a, Path>> for PathBuf {
    fn from(p: Cow<'a, Path>) -> Self {
        p.into_owned()
    }
}

impl From<OsString> for PathBuf {
    fn from(s: OsString) -> PathBuf {
        PathBuf { inner: s }
    }
}

impl From<PathBuf> for Arc<Path> {
    fn from(s: PathBuf) -> Arc<Path> {
        let arc: Arc<OsStr> = Arc::from(s.into_os_string());
        unsafe { Arc::from_raw(Arc::into_raw(arc) as *const Path) }
    }
}

impl From<PathBuf> for Box<Path> {
    fn from(p: PathBuf) -> Box<Path> {
        p.into_boxed_path()
    }
}

impl<'a> From<PathBuf> for Cow<'a, Path> {
    fn from(s: PathBuf) -> Cow<'a, Path> {
        Cow::Owned(s)
    }
}

impl From<PathBuf> for OsString {
    fn from(path_buf: PathBuf) -> OsString {
        path_buf.inner
    }
}

impl From<PathBuf> for Rc<Path> {
    fn from(s: PathBuf) -> Rc<Path> {
        let rc: Rc<OsStr> = Rc::from(s.into_os_string());
        unsafe { Rc::from_raw(Rc::into_raw(rc) as *const Path) }
    }
}

impl From<String> for PathBuf {
    fn from(s: String) -> PathBuf {
        PathBuf::from(OsString::from(s))
    }
}

impl<P: AsRef<Path>> FromIterator<P> for PathBuf {
    fn from_iter<I: IntoIterator<Item = P>>(iter: I) -> PathBuf {
        let mut path_buf = PathBuf {
            inner: OsString::new(),
        };
        for component in iter {
            path_buf.push(component.as_ref());
        }
        path_buf
    }
}

impl FromStr for PathBuf {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(PathBuf::from(s))
    }
}

impl From<std::path::PathBuf> for PathBuf {
    fn from(value: std::path::PathBuf) -> Self {
        PathBuf {
            inner: value.as_os_str().to_os_string(),
        }
    }
}

impl Hash for PathBuf {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.as_path().hash(h)
    }
}

impl<'a> IntoIterator for &'a PathBuf {
    type Item = &'a OsStr;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl PartialEq<&Path> for PathBuf {
    fn eq(&self, other: &&Path) -> bool {
        self.inner == other.inner.to_os_string()
    }
}

impl PartialEq<std::path::Path> for PathBuf {
    fn eq(&self, other: &std::path::Path) -> bool {
        self.inner == other.as_os_str().to_os_string()
    }
}

impl PartialEq<&std::path::Path> for PathBuf {
    fn eq(&self, other: &&std::path::Path) -> bool {
        self.inner == other.as_os_str().to_os_string()
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

impl AsRef<str> for PathBuf {
    fn as_ref(&self) -> &str {
        let a = self.inner.to_str().unwrap_or("");
        a
    }
}

impl Deref for PathBuf {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for PathBuf {
    fn deref_mut(&mut self) -> &mut Path {
        Path::from_inner_mut(&mut self.inner)
    }
}

async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
    OpenOptions::from_scope()
        .await
        .ok_or(FsError::Other("not initialized"))
}
