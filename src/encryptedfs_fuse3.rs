use tracing::Level;
use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter::Skip;
use std::num::NonZeroU32;
use std::os::raw::c_int;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use fuse3::{Inode, Result, SetAttr, Timestamp};
use fuse3::raw::prelude::{DirectoryEntry, DirectoryEntryPlus, ReplyAttr, ReplyCopyFileRange, ReplyCreated, ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs, ReplyWrite};
use fuse3::raw::{Filesystem, Request};
use futures_util::stream;
use futures_util::stream::Iter;
use libc::{EACCES, EBADF, EIO, ENOENT, ENOTDIR, ENOTEMPTY, EPERM};
use parking_lot::{const_reentrant_mutex, RawMutex, RawThreadId, ReentrantMutex};
use parking_lot::lock_api::ReentrantMutexGuard;
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, error, instrument, trace, warn};

use crate::encryptedfs::{EncryptedFs, Cipher, FileAttr, FileType, FsError, FsResult};

const TTL: Duration = Duration::from_secs(1);
const STATFS: ReplyStatFs = ReplyStatFs {
    blocks: 1,
    bfree: 0,
    bavail: 0,
    files: 1,
    ffree: 0,
    bsize: 4096,
    namelen: u32::MAX,
    frsize: 0,
};

const FMODE_EXEC: i32 = 0x20;

const MAX_NAME_LENGTH: u32 = 255;

const BLOCK_SIZE: u64 = 512;

// Flags returned by the open request
const FOPEN_DIRECT_IO: u32 = 1 << 0; // bypass page cache for this open file

pub struct DirectoryEntryIterator(crate::encryptedfs::DirectoryEntryIterator, u64);

impl Iterator for DirectoryEntryIterator {
    type Item = Result<DirectoryEntry>;

    #[instrument(name = "DirectoryEntryIterator::next", skip(self))]
    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next() {
            Some(Ok(entry)) => {
                let kind = if entry.kind == FileType::Directory {
                    fuse3::raw::prelude::FileType::Directory
                } else {
                    fuse3::raw::prelude::FileType::RegularFile
                };
                self.1 += 1;
                Some(Ok(DirectoryEntry {
                    inode: entry.ino,
                    kind,
                    name: OsString::from(entry.name.expose_secret()),
                    offset: self.1 as i64,
                }))
            }
            Some(Err(FsError::Io(err))) => {
                error!(err = %err);
                Some(Err(err.into()))
            }
            Some(Err(err)) => {
                error!(err = %err);
                Some(Err(EIO.into()))
            }
            None => None,
        }
    }
}

pub struct DirectoryEntryPlusIterator(crate::encryptedfs::DirectoryEntryPlusIterator, u64);

impl Iterator for DirectoryEntryPlusIterator {
    type Item = Result<DirectoryEntryPlus>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0.next() {
            Some(Ok(entry)) => {
                let kind = if entry.kind == FileType::Directory {
                    fuse3::raw::prelude::FileType::Directory
                } else {
                    fuse3::raw::prelude::FileType::RegularFile
                };
                self.1 += 1;
                Some(Ok(DirectoryEntryPlus {
                    inode: entry.ino,
                    generation: 0,
                    kind,
                    name: OsString::from(entry.name.expose_secret()),
                    offset: self.1 as i64,
                    attr: from_attr(entry.attr),
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                }))
            }
            Some(Err(FsError::Io(err))) => {
                error!(err = %err);
                Some(Err(err.into()))
            }
            Some(Err(err)) => {
                error!(err = %err);
                Some(Err(EIO.into()))
            }
            None => None,
        }
    }
}

pub struct EncryptedFsFuse3 {
    fs: ReentrantMutex<RefCell<EncryptedFs>>,
    direct_io: bool,
    suid_support: bool,
}

impl EncryptedFsFuse3 {
    pub fn new(data_dir: &str, password: SecretString, cipher: Cipher,
               direct_io: bool, _suid_support: bool) -> FsResult<Self> {
        #[cfg(feature = "abi-7-26")] {
            Ok(Self {
                fs: const_reentrant_mutex(RefCell::new(EncryptedFs::new(data_dir, password, cipher)?)),
                direct_io,
                suid_support: _suid_support,
            })
        }
        #[cfg(not(feature = "abi-7-26"))] {
            Ok(Self {
                fs: const_reentrant_mutex(RefCell::new(EncryptedFs::new(data_dir, password, cipher)?)),
                direct_io,
                suid_support: false,
            })
        }
    }

    fn get_fs(&self) -> ReentrantMutexGuard<'_, RawMutex, RawThreadId, RefCell<EncryptedFs>> {
        self.fs.lock()
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if self.suid_support {
            mode as u16
        } else {
            (mode & !(libc::S_ISUID | libc::S_ISGID)) as u16
        }
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    fn create_nod(&self, parent: u64, mut mode: u32, req: &Request, name: &OsStr, read: bool, write: bool) -> std::result::Result<(u64, FileAttr), c_int> {
        let parent_attr = match self.get_fs().borrow_mut().get_inode(parent) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT);
            }
            Ok(parent_attr) => parent_attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(EACCES);
        }

        if req.uid != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        let kind = as_file_kind(mode);
        let mut attr = if kind == FileType::Directory {
            dir_attr()
        } else {
            file_attr(0)
        };
        attr.perm = self.creation_mode(mode);
        attr.uid = req.uid;
        attr.gid = creation_gid(&parent_attr, req.gid);

        match self.get_fs().borrow_mut().create_nod(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap(), attr, read, write) {
            Ok((fh, attr)) => Ok((fh, attr)),
            Err(err) => {
                error!(err = %err);
                match err {
                    FsError::AlreadyExists => { Err(libc::EEXIST) }
                    _ => { return Err(ENOENT); }
                }
            }
        }
    }
}

fn creation_gid(parent: &FileAttr, gid: u32) -> u32 {
    if parent.perm & libc::S_ISGID as u16 != 0 {
        return parent.gid;
    }

    gid
}

fn from_attr(from: FileAttr) -> fuse3::raw::prelude::FileAttr {
    fuse3::raw::prelude::FileAttr {
        ino: from.ino,
        size: from.size,
        blocks: from.blocks,
        atime: from.atime.into(),
        mtime: from.mtime.into(),
        ctime: from.ctime.into(),
        kind: if from.kind == FileType::Directory {
            fuse3::raw::prelude::FileType::Directory
        } else {
            fuse3::raw::prelude::FileType::RegularFile
        },
        perm: from.perm,
        nlink: from.nlink,
        uid: from.uid,
        gid: from.gid,
        rdev: from.rdev,
        blksize: from.blksize,
    }
}

impl Filesystem for EncryptedFsFuse3 {
    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        trace!("");

        Ok(ReplyInit {
            max_write: NonZeroU32::new(1024 * 1024).unwrap(),
        })
    }

    #[instrument(skip(self))]
    async fn destroy(&self, _req: Request) {
        trace!("");
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn lookup(&self, req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        trace!("");

        if name.len() > MAX_NAME_LENGTH as usize {
            warn!(name = %name.to_str().unwrap(), "name too long");
            return Err(libc::ENAMETOOLONG.into());
        }

        match self.get_fs().borrow_mut().get_inode(parent) {
            Err(err) => {
                error!(parent, err = %err, "not found");
                return Err(ENOENT.into());
            }
            Ok(parent_attr) => {
                if !check_access(
                    parent_attr.uid,
                    parent_attr.gid,
                    parent_attr.perm,
                    req.uid,
                    req.gid,
                    libc::X_OK,
                ) {
                    return Err(EACCES.into());
                }
            }
        }

        let attr = match self.get_fs().borrow_mut().find_by_name(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            Ok(Some(attr)) => attr,
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            _ => {
                debug!(name = name.to_str().unwrap(), "not found");
                return Err(ENOENT.into());
            }
        };

        if attr.kind == FileType::Directory {
            debug!("dir {}", attr.ino);
        } else {
            debug!("file {}", attr.ino);
        }

        Ok(ReplyEntry {
            ttl: TTL,
            attr: from_attr(attr),
            generation: 0,
        })
    }

    #[instrument(skip(self))]
    async fn forget(&self, req: Request, inode: Inode, nlookup: u64) {
        trace!("");
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn getattr(
        &self,
        _req: Request,
        inode: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        trace!("");

        match self.get_fs().borrow_mut().get_inode(inode) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            Ok(attr) => {
                if attr.kind == FileType::Directory {
                    debug!(inode, "dir");
                } else {
                    debug!(inode, "file");
                }
                Ok(ReplyAttr {
                    ttl: TTL,
                    attr: from_attr(attr),
                })
            }
        }
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn setattr(
        &self,
        req: Request,
        inode: Inode,
        fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr>
    {
        trace!("");
        debug!("{set_attr:#?}");

        let mut attr = if let Ok(attr) = self.get_fs().borrow_mut().get_inode(inode) { attr } else {
            error!(inode, "not found");
            return Err(ENOENT.into());
        };

        if let Some(mode) = set_attr.mode {
            debug!("chmod mode={mode:o}");
            if req.uid != 0 && req.uid != attr.uid {
                return Err(libc::EPERM.into());
            }
            if req.uid != 0
                && req.gid != attr.gid
                && !get_groups(req.pid).contains(&attr.gid)
            {
                // If SGID is set and the file belongs to a group that the caller is not part of
                // then the SGID bit is suppose to be cleared during chmod
                attr.perm = (mode & !libc::S_ISGID as u32) as u16;
            } else {
                attr.perm = mode as u16;
            }
            attr.ctime = SystemTime::now();
            if let Err(err) = self.get_fs().borrow_mut().update_inode(inode, attr.perm, attr.atime, attr.mtime, attr.ctime, attr.crtime, attr.uid, attr.gid, attr.size, attr.nlink, attr.flags) {
                error!(err = %err);
                return Err(EBADF.into());
            }
            return Ok(ReplyAttr {
                ttl: TTL,
                attr: from_attr(attr),
            });
        }

        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            debug!(?set_attr.uid, ?set_attr.gid, "chown");

            if let Some(gid) = set_attr.gid {
                // Non-root users can only change gid to a group they're in
                if req.uid != 0 && !get_groups(req.pid).contains(&gid) {
                    return Err(libc::EPERM.into());
                }
            }
            if let Some(uid) = set_attr.uid {
                if req.uid != 0
                    // but no-op changes by the owner are not an error
                    && !(uid == attr.uid && req.uid == attr.uid) {
                    return Err(EPERM.into());
                }
            }
            // Only owner may change the group
            if set_attr.gid.is_some() && req.uid != 0 && req.uid != attr.uid {
                return Err(EPERM.into());
            }

            if attr.perm & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) as u16 != 0 {
                // SUID & SGID are suppose to be cleared when chown'ing an executable file
                clear_suid_sgid(&mut attr);
            }

            if let Some(uid) = set_attr.uid {
                attr.uid = uid;
                // Clear SETUID on owner change
                attr.perm &= !libc::S_ISUID as u16;
            }
            if let Some(gid) = set_attr.gid {
                attr.gid = gid;
                // Clear SETGID unless user is root
                if req.uid != 0 {
                    attr.perm &= !libc::S_ISGID as u16;
                }
            }
            attr.ctime = SystemTime::now();
            if let Err(err) = self.get_fs().borrow_mut().update_inode(inode, attr.perm, attr.atime, attr.mtime, attr.ctime, attr.crtime, attr.uid, attr.gid, attr.size, attr.nlink, attr.flags) {
                error!(err = %err);
                return Err(EBADF.into());
            }
            return Ok(ReplyAttr {
                ttl: TTL,
                attr: from_attr(attr),
            });
        }

        if let Some(size) = set_attr.size {
            debug!(size, "truncate");

            if let Err(err) = self.get_fs().borrow_mut().truncate(inode, size) {
                error!(err = %err);
                return Err(EBADF.into());
            }
            attr.size = size;

            // Clear SETUID & SETGID on truncate
            clear_suid_sgid(&mut attr);
        }

        if let Some(atime) = set_attr.atime {
            debug!(?atime, "utimens");

            if attr.uid != req.uid
                && !check_access(
                attr.uid,
                attr.gid,
                attr.perm,
                req.uid,
                req.gid,
                libc::W_OK,
            ) {
                return Err(EACCES.into());
            }

            attr.atime = system_time_from_timestamp(atime);
            attr.ctime = SystemTime::now();
        }

        if let Some(mtime) = set_attr.mtime {
            debug!(?mtime, "utimens");

            if attr.uid != req.uid
                && !check_access(
                attr.uid,
                attr.gid,
                attr.perm,
                req.uid,
                req.gid,
                libc::W_OK,
            ) {
                return Err(EACCES.into());
            }

            attr.mtime = system_time_from_timestamp(mtime);
            attr.ctime = SystemTime::now();
        }

        if let Err(err) = self.get_fs().borrow_mut().update_inode(inode, attr.perm, attr.atime, attr.mtime, attr.ctime, attr.crtime, attr.uid, attr.gid, attr.size, attr.nlink, attr.flags) {
            error!(err = %err);
            return Err(EBADF.into());
        }

        Ok(ReplyAttr {
            ttl: TTL,
            attr: from_attr(attr),
        })
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn mknod(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<ReplyEntry> {
        trace!("");
        debug!("mode={mode:o}");

        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            // && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
        {
            // TODO
            warn!("implementation is incomplete. Only supports regular files and directories. Got mode={mode:o}");
            return Err(libc::ENOSYS.into());
        }

        match self.create_nod(parent, mode, &req, name, false, false) {
            Ok((_, attr)) => {
                // TODO: implement flags
                Ok(ReplyEntry {
                    ttl: TTL,
                    attr: from_attr(attr),
                    generation: 0,
                })
            }
            Err(err) => {
                error!(err = %err);
                Err(err.into())
            }
        }
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn mkdir(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<ReplyEntry> {
        trace!("");
        debug!("mode={mode:o}");

        let parent_attr = match self.get_fs().borrow_mut().get_inode(parent) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            Ok(parent_attr) => parent_attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(EACCES.into());
        }

        let mut attr = dir_attr();
        attr.size = BLOCK_SIZE;
        attr.atime = SystemTime::now();
        attr.mtime = SystemTime::now();
        attr.ctime = SystemTime::now();

        let mut mode = mode;
        if req.uid != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }
        if parent_attr.perm & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }
        attr.perm = self.creation_mode(mode);

        attr.uid = req.uid;
        attr.gid = creation_gid(&parent_attr, req.gid);

        match self.get_fs().borrow_mut().create_nod(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap(), attr, false, false) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            Ok((_, attr)) => {
                Ok(ReplyEntry {
                    ttl: TTL,
                    attr: from_attr(attr),
                    generation: 0,
                })
            }
        }
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn unlink(&self, req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        trace!("");

        let parent_attr = match self.get_fs().borrow_mut().get_inode(parent) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            Ok(attr) => attr,
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(EACCES.into());
        }

        let attr = match self.get_fs().borrow_mut().find_by_name(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            Ok(Some(attr)) => attr,
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            _ => return Err(ENOENT.into()),
        };

        let uid = req.uid;
        // "Sticky bit" handling
        if parent_attr.perm & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attr.uid
            && uid != attr.uid
        {
            return Err(EACCES.into());
        }

        if let Err(err) = self.get_fs().borrow_mut().remove_file(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            error!(err = %err);
            return Err(ENOENT.into());
        }

        Ok(())
    }


    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn rmdir(&self, req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        trace!("");

        let parent_attr = if let Ok(attr) = self.get_fs().borrow_mut().get_inode(parent) { attr } else {
            error!(parent, "not found");
            return Err(ENOENT.into());
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(EACCES.into());
        }

        let attr = match self.get_fs().borrow_mut().find_by_name(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            Ok(Some(attr)) => attr,
            _ => {
                error!(parent, name = name.to_str().unwrap());
                return Err(ENOENT.into());
            }
        };

        if attr.kind != FileType::Directory {
            return Err(ENOTDIR.into());
        }

        let uid = req.uid;
        // "Sticky bit" handling
        if parent_attr.perm & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attr.uid
            && uid != attr.uid
        {
            return Err(EACCES.into());
        }

        if let Err(err) = self.get_fs().borrow_mut().remove_dir(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            error!(err = %err);
            return Err(EBADF.into());
        }

        Ok(())
    }

    #[instrument(skip(self, name, new_name), fields(name = name.to_str().unwrap(), new_name = new_name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn rename(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        new_parent: Inode,
        new_name: &OsStr,
    ) -> Result<()> {
        trace!("");

        let attr = if let Ok(Some(attr)) = self.get_fs().borrow_mut().find_by_name(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap()) {
            attr
        } else {
            error!(parent, name = name.to_str().unwrap(), new_name = new_name.to_str().unwrap());
            return Err(ENOENT.into());
        };

        let parent_attr = if let Ok(attr) = self.get_fs().borrow_mut().get_inode(parent) { attr } else {
            error!(parent, "parent not found");
            return Err(ENOENT.into());
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK) {
            return Err(EACCES.into());
        }

        // "Sticky bit" handling
        if parent_attr.perm & libc::S_ISVTX as u16 != 0
            && req.uid != 0
            && req.uid != parent_attr.uid
            && req.uid != attr.uid {
            return Err(EACCES.into());
        }

        let new_parent_attr = if let Ok(attr) = self.get_fs().borrow_mut().get_inode(new_parent) { attr } else {
            error!(new_parent, "not found");
            return Err(ENOENT.into());
        };

        if !check_access(
            new_parent_attr.uid,
            new_parent_attr.gid,
            new_parent_attr.perm,
            req.uid,
            req.gid,
            libc::W_OK) {
            return Err(EACCES.into());
        }

        // "Sticky bit" handling in new_parent
        if new_parent_attr.perm & libc::S_ISVTX as u16 != 0 {
            if let Ok(Some(new_attrs)) = self.get_fs().borrow_mut().find_by_name(new_parent, &SecretString::from_str(new_name.to_str().unwrap()).unwrap()) {
                if req.uid != 0
                    && req.uid != new_parent_attr.uid
                    && req.uid != new_attrs.uid
                {
                    return Err(EACCES.into());
                }
            }
        }

        // Only move an existing directory to a new parent, if we have write access to it,
        // because that will change the ".." link in it
        if attr.kind == FileType::Directory
            && parent != new_parent
            && !check_access(
            attr.uid,
            attr.gid,
            attr.perm,
            req.uid,
            req.gid,
            libc::W_OK,
        ) {
            return Err(EACCES.into());
        }

        match self.get_fs().borrow_mut().rename(parent, &SecretString::from_str(name.to_str().unwrap()).unwrap(), new_parent, &SecretString::from_str(new_name.to_str().unwrap()).unwrap()) {
            Ok(_) => Ok(()),
            Err(FsError::NotEmpty) => {
                Err(ENOTEMPTY.into())
            }
            _ => {
                Err(ENOENT.into())
            }
        }
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn open(&self, req: Request, inode: Inode, flags: u32) -> Result<ReplyOpen> {
        trace!("");

        let (access_mask, read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC as u32 != 0 {
                    return Err(EACCES.into());
                }
                if flags & FMODE_EXEC as u32 != 0 {
                    // Open is from internal exec syscall
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        let create = flags & libc::O_CREAT as u32 != 0;
        let truncate = flags & libc::O_TRUNC as u32 != 0;
        let append = flags & libc::O_APPEND as u32 != 0;

        let attr = self.get_fs().borrow_mut().get_inode(inode).map_err(|err| {
            error!(err = %err);
            EBADF
        })?;

        if check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, access_mask) {
            if truncate {
                self.get_fs().borrow_mut().truncate(attr.ino, 0).map_err(|err| {
                    error!(err = %err);
                    EIO
                })?;
            }
            let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
            let fh = self.get_fs().borrow_mut().open(inode, read, write).map_err(|err| {
                error!(err = %err);
                EBADF
            })?;
            debug!(fh, "opened handle");
            Ok(ReplyOpen { fh, flags: open_flags })
        } else {
            Err(EACCES.into())
        }
    }

    #[instrument(skip(self), err(level = Level::DEBUG))]
    async fn read(
        &self,
        _req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        trace!("");

        let mut buf = vec![0; size as usize];
        match self.get_fs().borrow_mut().read(inode, offset, &mut buf, fh) {
            Err(err) => {
                error!(err = %err);
                return Err(EIO.into());
            }
            Ok(len) => {
                Ok(ReplyData {
                    data: Bytes::copy_from_slice(buf[..len].as_ref()),
                })
            }
        }
    }

    #[instrument(skip(self, data), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn write(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        _flags: u32,
    ) -> Result<ReplyWrite>
    {
        trace!("");
        debug!(size = data.len());

        self.get_fs().borrow_mut().write_all(inode, offset, data, fh).map_err(|err| {
            error!(err = %err);
            EIO
        })?;

        Ok(ReplyWrite {
            written: data.len() as u32,
        })
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn statfs(&self, _req: Request, inode: u64) -> Result<ReplyStatFs> {
        trace!("");
        warn!("implementation is a stub");
        Ok(STATFS)
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn release(
        &self,
        req: Request,
        inode: Inode,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        trace!("");

        if flush {
            if let Err(err) = self.get_fs().borrow_mut().flush(fh) {
                error!(err = %err);
                return Err(EIO.into());
            }
        }

        let is_write_handle = self.get_fs().borrow().is_write_handle(fh);

        if let Err(err) = self.get_fs().borrow_mut().release(fh) {
            error!(err = %err, "release_handle");
            return Err(EIO.into());
        }

        if is_write_handle {
            let mut attr = self.get_fs().borrow_mut().get_inode(inode).unwrap();
            // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
            // However, xfstests fail in that case
            clear_suid_sgid(&mut attr);
            if let Err(err) = self.get_fs().borrow_mut().update_inode(inode, attr.perm, attr.atime, attr.mtime, attr.ctime, attr.crtime, attr.uid, attr.gid, attr.size, attr.nlink, attr.flags) {
                error!(err = %err, "replace attr");
                return Err(EBADF.into());
            }
        }

        Ok(())
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn flush(&self, req: Request, inode: Inode, fh: u64, lock_owner: u64) -> Result<()> {
        trace!("");

        if let Err(err) = self.get_fs().borrow_mut().flush(fh) {
            error!(err = %err, fh);
            return Err(EIO.into());
        }

        Ok(())
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn opendir(&self, req: Request, inode: Inode, flags: u32) -> Result<ReplyOpen> {
        trace!("");

        let (access_mask, _read, _write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC as u32 != 0 {
                    return Err(EACCES.into());
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        let attr = match self.get_fs().borrow_mut().get_inode(inode) {
            Err(err) => {
                error!(err = %err);
                return Err(ENOENT.into());
            }
            Ok(attr) => attr
        };

        if check_access(
            attr.uid,
            attr.gid,
            attr.perm,
            req.uid,
            req.gid,
            access_mask,
        ) {
            let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
            Ok(ReplyOpen {
                fh: 0, // we don't use handles for directories
                flags: open_flags,
            })
        } else {
            return Err(EACCES.into());
        }
    }

    type DirEntryStream<'a> = Iter<Skip<DirectoryEntryIterator>> where Self: 'a;

    #[instrument(skip(self), err(level = Level::DEBUG))]
    async fn readdir(
        &self,
        _req: Request,
        inode: u64,
        fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<Self::DirEntryStream<'_>>> {
        trace!("");

        let iter = match self.get_fs().borrow_mut().read_dir(inode) {
            Err(err) => {
                error!(err = %err);
                return Err(EIO.into());
            }
            Ok(iter) => iter,
        };
        let iter = DirectoryEntryIterator(iter, 0);

        Ok(ReplyDirectory {
            entries: stream::iter(iter.skip(offset as usize)),
        })
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn releasedir(&self, req: Request, inode: Inode, fh: u64, flags: u32) -> Result<()> {
        trace!("");

        Ok(())
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn access(&self, req: Request, inode: u64, mask: u32) -> Result<()> {
        trace!("");

        match self.get_fs().borrow_mut().get_inode(inode) {
            Ok(attr) => {
                if check_access(attr.uid, attr.gid, attr.perm, req.uid, req.gid, mask as i32) {
                    Ok(())
                } else {
                    Err(EACCES.into())
                }
            }
            _ => Err(ENOENT.into()),
        }
    }

    #[instrument(skip(self, name), fields(name = name.to_str().unwrap()), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn create(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        trace!("");

        let (read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        return match self.create_nod(parent, mode, &req, name, read, write) {
            Ok((handle, attr)) => {
                debug!(handle, "created handle");
                // TODO: implement flags
                Ok(ReplyCreated {
                    ttl: TTL,
                    attr: from_attr(attr),
                    generation: 0,
                    fh: handle,
                    flags: 0,
                })
            }
            Err(err) => {
                error!(err = %err);
                Err(ENOENT.into())
            }
        };
    }


    type DirEntryPlusStream<'a> = Iter<Skip<DirectoryEntryPlusIterator>> where Self: 'a;

    #[instrument(skip(self), err(level = Level::DEBUG))]
    async fn readdirplus(
        &self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<Self::DirEntryPlusStream<'_>>> {
        trace!("");

        let iter = match self.get_fs().borrow_mut().read_dir_plus(parent) {
            Err(err) => {
                error!(err = %err);
                return Err(EIO.into());
            }
            Ok(iter) => iter,
        };
        let iter = DirectoryEntryPlusIterator(iter, 0);

        Ok(ReplyDirectoryPlus {
            entries: stream::iter(iter.skip(offset as usize)),
        })
    }

    #[instrument(skip(self), err(level = Level::DEBUG), ret(level = Level::DEBUG))]
    async fn copy_file_range(
        &self,
        req: Request,
        inode: Inode,
        fh_in: u64,
        off_in: u64,
        inode_out: Inode,
        fh_out: u64,
        off_out: u64,
        length: u64,
        flags: u64,
    ) -> Result<ReplyCopyFileRange> {
        trace!("");

        match self.get_fs().borrow_mut()
            .copy_file_range(inode, off_in, inode_out, off_out, length as usize, fh_in, fh_out) {
            Err(err) => {
                error!(err = %err);
                return Err(EBADF.into());
            }
            Ok(len) => {
                Ok(ReplyCopyFileRange {
                    copied: len as u64,
                })
            }
        }
    }
}

fn get_groups(pid: u32) -> Vec<u32> {
    #[cfg(not(target_os = "macos"))]
    {
        let path = format!("/proc/{pid}/task/{pid}/status");
        let file = File::open(path).unwrap();
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            if line.starts_with("Groups:") {
                return line["Groups: ".len()..]
                    .split(' ')
                    .filter(|x| !x.trim().is_empty())
                    .map(|x| x.parse::<u32>().unwrap())
                    .collect();
            }
        }
    }

    vec![]
}

fn clear_suid_sgid(attr: &mut FileAttr) {
    attr.perm &= !libc::S_ISUID as u16;
    // SGID is only suppose to be cleared if XGRP is set
    if attr.perm & libc::S_IXGRP as u16 != 0 {
        attr.perm &= !libc::S_ISGID as u16;
    }
}

fn as_file_kind(mut mode: u32) -> FileType {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileType::RegularFile;
        // } else if mode == libc::S_IFLNK as u32 {
        //     return FileType::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileType::Directory;
    } else {
        unimplemented!("{mode}");
    }
}

fn dir_attr() -> FileAttr {
    let mut f = FileAttr {
        ino: 0,
        size: BLOCK_SIZE,
        blocks: 0,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind: FileType::Directory,
        perm: 0o777,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
        blksize: BLOCK_SIZE as u32,
    };
    f.blocks = (f.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    f
}

fn file_attr(size: u64) -> FileAttr {
    let mut f = FileAttr {
        ino: 0,
        size,
        blocks: (size + BLOCK_SIZE - 1) / BLOCK_SIZE,
        atime: SystemTime::now(),
        mtime: SystemTime::now(),
        ctime: SystemTime::now(),
        crtime: SystemTime::now(),
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
        blksize: 512,
    };
    f.blocks = (f.size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    f
}

fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    mut access_mask: i32,
) -> bool {
    // F_OK tests for existence of file
    if access_mask == libc::F_OK {
        return true;
    }
    let file_mode = i32::from(file_mode);

    // root is allowed to read & write anything
    if uid == 0 {
        // root only allowed to exec if one of the X bits is set
        access_mask &= libc::X_OK;
        access_mask -= access_mask & (file_mode >> 6);
        access_mask -= access_mask & (file_mode >> 3);
        access_mask -= access_mask & file_mode;
        return access_mask == 0;
    }

    if uid == file_uid {
        access_mask -= access_mask & (file_mode >> 6);
    } else if gid == file_gid {
        access_mask -= access_mask & (file_mode >> 3);
    } else {
        access_mask -= access_mask & file_mode;
    }

    return access_mask == 0;
}

fn system_time_from_timestamp(t: Timestamp) -> SystemTime {
    UNIX_EPOCH + Duration::new(t.sec as u64, t.nsec)
}
