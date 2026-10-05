//! Path based access to [`EncryptedFs`].
//!
//! [`EncryptedFs`] is inode based, like FUSE. Other platforms, like Windows (Dokan), address files by
//! their full path, and open files have a context instead of FUSE's file handle. This module adapts
//! between the two, it is platform-independent so it can be tested everywhere.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use shush_rs::{ExposeSecret, SecretString};
use tokio::sync::Mutex;

use crate::encryptedfs::{
    CreateFileAttr, DirectoryEntryPlus, EncryptedFs, FileAttr, FileType, FsError, FsResult,
    SetFileAttr, ROOT_INODE,
};

/// Splits a path into its components, both `\` and `/` are accepted as separators.
///
/// Empty components and `.` are ignored, `\\a\\.\\b\\` is `["a", "b"]`.
pub(crate) fn split_path(path: &str) -> Vec<&str> {
    path.split(['\\', '/'])
        .filter(|c| !c.is_empty() && *c != ".")
        .collect()
}

fn secret(name: &str) -> SecretString {
    SecretString::from_str(name).expect("cannot create secret string")
}

const fn create_attr(kind: FileType) -> CreateFileAttr {
    CreateFileAttr {
        kind,
        perm: match kind {
            FileType::Directory => 0o777,
            FileType::RegularFile => 0o644,
        },
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

pub(crate) struct PathFs {
    fs: Arc<EncryptedFs>,
}

impl PathFs {
    pub(crate) const fn new(fs: Arc<EncryptedFs>) -> Self {
        Self { fs }
    }

    pub(crate) fn fs(&self) -> &Arc<EncryptedFs> {
        &self.fs
    }

    /// Finds the node with the given path, `None` if it, or any of its parents, doesn't exist.
    pub(crate) async fn lookup(&self, path: &str) -> FsResult<Option<FileAttr>> {
        let mut attr = self.fs.get_attr(ROOT_INODE).await?;
        for name in split_path(path) {
            if attr.kind != FileType::Directory {
                return Ok(None);
            }
            match self.fs.find_by_name(attr.ino, &secret(name)).await? {
                Some(child) => attr = child,
                None => return Ok(None),
            }
        }
        Ok(Some(attr))
    }

    /// Returns the inode of the parent directory and the name of the last component.
    ///
    /// Fails with [`FsError::NotFound`] if the parent doesn't exist and [`FsError::InvalidInput`]
    /// for the root, which has no parent.
    pub(crate) async fn parent_and_name(&self, path: &str) -> FsResult<(u64, SecretString)> {
        let mut components = split_path(path);
        let name = components
            .pop()
            .ok_or(FsError::InvalidInput("root has no parent"))?;
        let parent = self
            .lookup(&components.join("\\"))
            .await?
            .ok_or(FsError::NotFound("parent not found"))?;
        if parent.kind != FileType::Directory {
            return Err(FsError::InvalidInodeType);
        }
        Ok((parent.ino, secret(name)))
    }

    pub(crate) async fn create(&self, path: &str, kind: FileType) -> FsResult<FileAttr> {
        let (parent, name) = self.parent_and_name(path).await?;
        let (fh, attr) = self
            .fs
            .create(parent, &name, create_attr(kind), false, false)
            .await?;
        if fh != 0 {
            self.fs.release(fh).await?;
        }
        Ok(attr)
    }

    /// Lists the children of a directory, without `.` and `..`.
    pub(crate) async fn read_dir(&self, ino: u64) -> FsResult<Vec<DirectoryEntryPlus>> {
        let mut entries = vec![];
        for entry in self.fs.read_dir_plus(ino).await? {
            let entry = entry?;
            let name = entry.name.expose_secret();
            if *name != "." && *name != ".." {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub(crate) async fn remove(&self, path: &str) -> FsResult<()> {
        let attr = self
            .lookup(path)
            .await?
            .ok_or(FsError::NotFound("path not found"))?;
        let (parent, name) = self.parent_and_name(path).await?;
        match attr.kind {
            FileType::Directory => self.fs.remove_dir(parent, &name).await,
            FileType::RegularFile => self.fs.remove_file(parent, &name).await,
        }
    }

    /// Moves `from` to `to`. If `to` exists it's replaced only if `replace` is `true`,
    /// a directory can be replaced only if it's empty.
    pub(crate) async fn rename(&self, from: &str, to: &str, replace: bool) -> FsResult<()> {
        let (parent, name) = self.parent_and_name(from).await?;
        let (new_parent, new_name) = self.parent_and_name(to).await?;
        if parent == new_parent && name.expose_secret() == new_name.expose_secret() {
            return Ok(());
        }
        if let Some(existing) = self.fs.find_by_name(new_parent, &new_name).await? {
            if !replace {
                return Err(FsError::AlreadyExists);
            }
            // remove it so its content doesn't remain orphan in the data dir
            match existing.kind {
                FileType::Directory => self.fs.remove_dir(new_parent, &new_name).await?,
                FileType::RegularFile => self.fs.remove_file(new_parent, &new_name).await?,
            }
        }
        self.fs.rename(parent, &name, new_parent, &new_name).await
    }

    pub(crate) async fn set_times(
        &self,
        ino: u64,
        crtime: Option<SystemTime>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> FsResult<()> {
        let mut set_attr = SetFileAttr::default();
        if let Some(crtime) = crtime {
            set_attr = set_attr.with_crtime(crtime);
        }
        if let Some(atime) = atime {
            set_attr = set_attr.with_atime(atime);
        }
        if let Some(mtime) = mtime {
            set_attr = set_attr.with_mtime(mtime);
        }
        self.fs.set_attr(ino, set_attr).await
    }
}

/// An opened file or directory.
///
/// The underlying [`EncryptedFs`] handles are opened lazily, on first read or write, because Windows
/// opens files also to only query or change metadata. A file can be opened for write only once at a
/// time by [`EncryptedFs`], so the write handle is requested only when actually writing.
///
/// Reads and writes use separate handles. Written data becomes readable only after the write handle
/// is released, so it's released before reading, if there are pending writes.
pub(crate) struct OpenNode {
    pub(crate) ino: u64,
    pub(crate) kind: FileType,
    handles: Mutex<Handles>,
}

#[derive(Default)]
struct Handles {
    read: Option<u64>,
    write: Option<u64>,
    // if there are writes not flushed yet
    dirty: bool,
}

impl Handles {
    async fn flush(&mut self, fs: &EncryptedFs) -> FsResult<()> {
        if let (Some(fh), true) = (self.write, self.dirty) {
            fs.flush(fh).await?;
            self.dirty = false;
        }
        Ok(())
    }

    /// The last block is committed only when the write handle is released, release it so the
    /// written data can be read. It will be reopened on next write.
    async fn commit(&mut self, fs: &EncryptedFs) -> FsResult<()> {
        if !self.dirty {
            return Ok(());
        }
        self.flush(fs).await?;
        if let Some(fh) = self.write.take() {
            fs.release(fh).await?;
        }
        Ok(())
    }
}

impl OpenNode {
    pub(crate) fn new(attr: &FileAttr) -> Self {
        Self {
            ino: attr.ino,
            kind: attr.kind,
            handles: Mutex::new(Handles::default()),
        }
    }

    pub(crate) fn is_dir(&self) -> bool {
        self.kind == FileType::Directory
    }

    pub(crate) async fn read(
        &self,
        fs: &EncryptedFs,
        offset: u64,
        buf: &mut [u8],
    ) -> FsResult<usize> {
        let mut handles = self.handles.lock().await;
        // make our writes visible for read
        handles.commit(fs).await?;
        let fh = match handles.read {
            Some(fh) => fh,
            None => *handles.read.insert(fs.open(self.ino, true, false).await?),
        };
        fs.read(self.ino, offset, buf, fh).await
    }

    /// Writes at `offset`, or at the end of the file if `offset` is `None`.
    pub(crate) async fn write(
        &self,
        fs: &EncryptedFs,
        offset: Option<u64>,
        buf: &[u8],
    ) -> FsResult<usize> {
        let mut handles = self.handles.lock().await;
        let fh = match handles.write {
            Some(fh) => fh,
            None => *handles.write.insert(fs.open(self.ino, false, true).await?),
        };
        let offset = match offset {
            Some(offset) => offset,
            None => fs.get_attr(self.ino).await?.size,
        };
        handles.dirty = true;
        fs.write(self.ino, offset, buf, fh).await
    }

    pub(crate) async fn flush(&self, fs: &EncryptedFs) -> FsResult<()> {
        self.handles.lock().await.flush(fs).await
    }

    pub(crate) async fn set_len(&self, fs: &EncryptedFs, size: u64) -> FsResult<()> {
        let mut handles = self.handles.lock().await;
        handles.flush(fs).await?;
        fs.set_len(self.ino, size).await
    }

    /// Flushes and releases the underlying handles, if any.
    pub(crate) async fn release(&self, fs: &EncryptedFs) -> FsResult<()> {
        let mut handles = self.handles.lock().await;
        handles.flush(fs).await?;
        if let Some(fh) = handles.write.take() {
            fs.release(fh).await?;
        }
        if let Some(fh) = handles.read.take() {
            fs.release(fh).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_common::{run_test, TestSetup, SETUP_RESULT};

    async fn path_fs() -> PathFs {
        let fs = SETUP_RESULT.get_or(|| Mutex::new(None));
        let mut fs = fs.lock().await;
        PathFs::new(fs.as_mut().unwrap().fs.as_ref().unwrap().clone())
    }

    async fn names(pfs: &PathFs, path: &str) -> Vec<String> {
        let ino = pfs.lookup(path).await.unwrap().unwrap().ino;
        let mut names: Vec<_> = pfs
            .read_dir(ino)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name.expose_secret().clone())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn test_split_path() {
        assert_eq!(split_path("\\"), Vec::<&str>::new());
        assert_eq!(split_path(""), Vec::<&str>::new());
        assert_eq!(split_path("\\a"), vec!["a"]);
        assert_eq!(split_path("\\a\\b c\\d.txt"), vec!["a", "b c", "d.txt"]);
        assert_eq!(split_path("/a//b/"), vec!["a", "b"]);
        assert_eq!(split_path("\\a\\.\\b\\"), vec!["a", "b"]);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_lookup_create_and_read_dir() {
        run_test(
            TestSetup {
                key: "test_path_fs_lookup_create_and_read_dir",
                read_only: false,
            },
            async {
                let pfs = path_fs().await;

                let root = pfs.lookup("\\").await.unwrap().unwrap();
                assert_eq!(root.ino, ROOT_INODE);
                assert!(pfs.lookup("\\missing").await.unwrap().is_none());
                assert!(pfs.lookup("\\missing\\child").await.unwrap().is_none());

                let dir = pfs.create("\\dir", FileType::Directory).await.unwrap();
                let file = pfs
                    .create("\\dir\\file.txt", FileType::RegularFile)
                    .await
                    .unwrap();
                pfs.create("\\top.txt", FileType::RegularFile)
                    .await
                    .unwrap();

                assert_eq!(pfs.lookup("\\dir").await.unwrap().unwrap().ino, dir.ino);
                assert_eq!(
                    pfs.lookup("\\dir\\file.txt").await.unwrap().unwrap().ino,
                    file.ino
                );
                assert_eq!(
                    pfs.lookup("/dir/file.txt").await.unwrap().unwrap().ino,
                    file.ino
                );
                // a file has no children
                assert!(pfs.lookup("\\top.txt\\x").await.unwrap().is_none());

                assert!(matches!(
                    pfs.create("\\dir", FileType::Directory).await,
                    Err(FsError::AlreadyExists)
                ));
                assert!(matches!(
                    pfs.create("\\missing\\x", FileType::RegularFile).await,
                    Err(FsError::NotFound(_))
                ));
                assert!(matches!(
                    pfs.create("\\top.txt\\x", FileType::RegularFile).await,
                    Err(FsError::InvalidInodeType)
                ));
                assert!(matches!(
                    pfs.parent_and_name("\\").await,
                    Err(FsError::InvalidInput(_))
                ));

                assert_eq!(names(&pfs, "\\").await, vec!["dir", "top.txt"]);
                assert_eq!(names(&pfs, "\\dir").await, vec!["file.txt"]);
            },
        )
        .await;
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_read_write() {
        run_test(
            TestSetup {
                key: "test_path_fs_read_write",
                read_only: false,
            },
            async {
                let pfs = path_fs().await;
                let fs = pfs.fs().clone();
                let attr = pfs.create("\\file", FileType::RegularFile).await.unwrap();

                // write, then read with the same opened node
                let node = OpenNode::new(&attr);
                assert_eq!(node.write(&fs, Some(0), b"hello").await.unwrap(), 5);
                // append
                assert_eq!(node.write(&fs, None, b" world").await.unwrap(), 6);
                let mut buf = [0_u8; 32];
                let len = node.read(&fs, 0, &mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"hello world");
                node.release(&fs).await.unwrap();
                assert_eq!(fs.get_attr(attr.ino).await.unwrap().size, 11);

                // read first, then upgrade to write
                let node = OpenNode::new(&attr);
                let len = node.read(&fs, 6, &mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"world");
                node.write(&fs, Some(0), b"HELLO").await.unwrap();
                let len = node.read(&fs, 0, &mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"HELLO world");

                // truncate
                node.set_len(&fs, 5).await.unwrap();
                node.release(&fs).await.unwrap();
                assert_eq!(fs.get_attr(attr.ino).await.unwrap().size, 5);

                // another opened node sees the content
                let node = OpenNode::new(&attr);
                let len = node.read(&fs, 0, &mut buf).await.unwrap();
                assert_eq!(&buf[..len], b"HELLO");
                node.release(&fs).await.unwrap();
                // releasing twice is a no-op
                node.release(&fs).await.unwrap();
            },
        )
        .await;
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_remove_and_rename() {
        run_test(
            TestSetup {
                key: "test_path_fs_remove_and_rename",
                read_only: false,
            },
            async {
                let pfs = path_fs().await;
                let fs = pfs.fs().clone();
                pfs.create("\\a", FileType::Directory).await.unwrap();
                pfs.create("\\b", FileType::Directory).await.unwrap();
                let f1 = pfs.create("\\a\\f1", FileType::RegularFile).await.unwrap();
                let f2 = pfs.create("\\b\\f2", FileType::RegularFile).await.unwrap();

                // rename in the same dir
                pfs.rename("\\a\\f1", "\\a\\g1", false).await.unwrap();
                assert_eq!(names(&pfs, "\\a").await, vec!["g1"]);
                assert_eq!(pfs.lookup("\\a\\g1").await.unwrap().unwrap().ino, f1.ino);

                // move to another dir
                pfs.rename("\\a\\g1", "\\b\\g1", false).await.unwrap();
                assert!(names(&pfs, "\\a").await.is_empty());
                assert_eq!(names(&pfs, "\\b").await, vec!["f2", "g1"]);

                // don't replace unless asked to
                assert!(matches!(
                    pfs.rename("\\b\\g1", "\\b\\f2", false).await,
                    Err(FsError::AlreadyExists)
                ));
                pfs.rename("\\b\\g1", "\\b\\f2", true).await.unwrap();
                assert_eq!(names(&pfs, "\\b").await, vec!["f2"]);
                assert_eq!(pfs.lookup("\\b\\f2").await.unwrap().unwrap().ino, f1.ino);
                // the replaced file is deleted
                assert!(!fs.exists(f2.ino));

                // move a dir
                pfs.rename("\\b", "\\a\\b", false).await.unwrap();
                assert_eq!(pfs.lookup("\\a\\b\\f2").await.unwrap().unwrap().ino, f1.ino);

                // remove
                assert!(matches!(pfs.remove("\\a\\b").await, Err(FsError::NotEmpty)));
                pfs.remove("\\a\\b\\f2").await.unwrap();
                pfs.remove("\\a\\b").await.unwrap();
                assert!(pfs.lookup("\\a\\b").await.unwrap().is_none());
                assert!(matches!(
                    pfs.remove("\\a\\b").await,
                    Err(FsError::NotFound(_))
                ));
                assert!(names(&pfs, "\\").await == vec!["a"]);
            },
        )
        .await;
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_set_times() {
        run_test(
            TestSetup {
                key: "test_path_fs_set_times",
                read_only: false,
            },
            async {
                let pfs = path_fs().await;
                let attr = pfs.create("\\file", FileType::RegularFile).await.unwrap();
                // EncryptedFs keeps the newest time, so set one in the future
                let time = SystemTime::now() + std::time::Duration::from_secs(3600);
                pfs.set_times(attr.ino, None, None, Some(time))
                    .await
                    .unwrap();
                let new_attr = pfs.fs().get_attr(attr.ino).await.unwrap();
                assert_eq!(new_attr.mtime, time);
                assert_eq!(new_attr.crtime, attr.crtime);
            },
        )
        .await;
    }
}
