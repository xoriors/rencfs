use std::cmp::min;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, SeekFrom};
use std::os::fd::IntoRawFd;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use fuser::{FileAttr, Filesystem, FileType, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow};
use fuser::consts::FOPEN_DIRECT_IO;
use fuser::TimeOrNow::Now;
use libc::{EBADF, EIO, ENOENT, ENOTDIR, ENOTEMPTY};
use log::{debug, warn};
use crate::encrypted_fs::{EncryptedFs, FsError, FsResult};

const BLOCK_SIZE: u64 = 512;

const FMODE_EXEC: i32 = 0x20;

const MAX_NAME_LENGTH: u32 = 255;

pub struct EncryptedFsFuse {
    fs: EncryptedFs,
    direct_io: bool,
    suid_support: bool,
    // TODO: change to AtomicU64
    current_file_handle: u64,
}

impl EncryptedFsFuse {
    pub fn new(data_dir: &str, direct_io: bool, _suid_support: bool) -> FsResult<Self> {
        #[cfg(feature = "abi-7-26")] {
            Ok(EncryptedFsFuse {
                fs: EncryptedFs::new(data_dir)?,
                direct_io,
                suid_support: _suid_support,
                current_file_handle: 0,
            })
        }
        #[cfg(not(feature = "abi-7-26"))] {
            Ok(EncryptedFsFuse {
                fs: EncryptedFs::new(data_dir)?,
                direct_io,
                suid_support: false,
                current_file_handle: 0,
            })
        }
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if !self.suid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID)) as u16
        } else {
            mode as u16
        }
    }

    fn allocate_next_file_handle(&mut self) -> u64 {
        self.current_file_handle += 1;

        self.current_file_handle
    }

    fn create_nod(&mut self, parent: u64, mut mode: u32, req: &Request, name: &OsStr) -> Result<FileAttr, c_int> {
        match self.fs.get_inode(parent) {
            Err(_) => { Err(ENOENT) }
            Ok(parent_attr) => {
                if !check_access(
                    parent_attr.uid,
                    parent_attr.gid,
                    parent_attr.perm,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                ) {
                    return Err(libc::EACCES);
                }

                if req.uid() != 0 {
                    mode &= !(libc::S_ISUID | libc::S_ISGID);
                }

                let kind = as_file_kind(mode);
                let mut attr = if kind == FileType::Directory {
                    dir_attr()
                } else {
                    file_attr(0)
                };
                attr.perm = self.creation_mode(mode);
                attr.uid = req.uid();
                attr.gid = creation_gid(&parent_attr, req.gid());

                match self.fs.create_nod(parent, name.to_str().unwrap(), attr) {
                    Ok(attr) => { Ok(attr) }
                    Err(err) => {
                        match err {
                            FsError::AlreadyExists => { Err(libc::EEXIST) }
                            _ => { return Err(ENOENT); }
                        }
                    }
                }
            }
        }
    }
}

impl Filesystem for EncryptedFsFuse {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> Result<(), c_int> {
        #[cfg(feature = "abi-7-26")]
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();

        Ok(())
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        debug!("lookup {}, {}", parent, name.to_str().unwrap());

        if name.len() > MAX_NAME_LENGTH as usize {
            reply.error(libc::ENAMETOOLONG);
            return;
        }

        match self.fs.get_inode(parent) {
            Err(err) => {
                debug!("  not found {} {:?} {}", parent, name, err);
                reply.error(ENOENT);
            }
            Ok(parent_attr) => {
                if !check_access(
                    parent_attr.uid,
                    parent_attr.gid,
                    parent_attr.perm,
                    req.uid(),
                    req.gid(),
                    libc::X_OK,
                ) {
                    reply.error(libc::EACCES);
                    return;
                }

                match self.fs.find_by_name(parent, name.to_str().unwrap()) {
                    Ok(Some(attr)) => {
                        if attr.kind == FileType::Directory {
                            debug!("  dir {}", attr.ino);
                            reply.entry(&Duration::new(0, 0), &&attr, 0);
                        } else {
                            debug!("  file {}", attr.ino);
                            reply.entry(&Duration::new(0, 0), &&attr, 0);
                        }
                    }
                    _ => {
                        debug!("  not found");
                        reply.error(ENOENT);
                    }
                }
            }
        }
    }

    fn forget(&mut self, _req: &Request<'_>, _ino: u64, _nlookup: u64) {
        debug!("forget() called with {:?} {:?}", _ino, _nlookup);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        debug!("getattr {}", ino);

        match self.fs.get_inode(ino) {
            Err(err) => {
                debug!("  not found {}", err);
                reply.error(ENOENT)
            }
            Ok(attr) => {
                if attr.kind == FileType::Directory {
                    debug!("  dir {}", ino);
                    reply.attr(&Duration::new(0, 0), &attr);
                } else {
                    debug!("  file {}", ino);
                    reply.attr(&Duration::new(0, 0), &attr);
                }
            }
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        debug!("mknod() called with {:?} {:?} {:o}", parent, name, mode);

        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            // && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
        {
            // TODO
            warn!("mknod() implementation is incomplete. Only supports regular files and directories. Got {:o}", mode);
            reply.error(libc::ENOSYS);
            return;
        }

        match self.create_nod(parent, mode, req, name) {
            Ok(attr) => {
                // TODO: implement flags
                reply.entry(&Duration::new(0, 0), &attr, 0);
            }
            Err(err) => reply.error(err)
        }
    }

    fn access(&mut self, req: &Request, inode: u64, mask: i32, reply: ReplyEmpty) {
        debug!("access() called with {:?} {:?}", inode, mask);

        match self.fs.get_inode(inode) {
            Ok(attr) => {
                if check_access(attr.uid, attr.gid, attr.perm, req.uid(), req.gid(), mask) {
                    reply.ok();
                } else {
                    reply.error(libc::EACCES);
                }
            }
            _ => reply.error(ENOENT),
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        debug!("create() called with {:?} {:?}", parent, name);

        let (_read, _write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.create_nod(parent, mode, req, name) {
            Ok(attr) => {
                // TODO: implement flags
                reply.created(
                    &Duration::new(0, 0),
                    &attr,
                    0,
                    self.allocate_next_file_handle(),
                    0,
                );
            }
            Err(err) => reply.error(err)
        }
    }
    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("open() called for {:?}", inode);

        let (access_mask, _read, _write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                if flags & FMODE_EXEC != 0 {
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
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.fs.get_inode(inode) {
            Ok(attr) => {
                if check_access(attr.uid, attr.gid, attr.perm, req.uid(), req.gid(), access_mask) {
                    let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
                    reply.opened(self.allocate_next_file_handle(), open_flags);
                } else {
                    reply.error(libc::EACCES);
                }
            }
            _ => reply.error(ENOENT)
        }
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("opendir() called on {:?}", inode);

        let (access_mask, _read, _write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.fs.get_inode(inode) {
            Ok(attr) => {
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.perm,
                    req.uid(),
                    req.gid(),
                    access_mask,
                ) {
                    let open_flags = if self.direct_io { FOPEN_DIRECT_IO } else { 0 };
                    reply.opened(self.allocate_next_file_handle(), open_flags);
                }
            }
            _ => reply.error(ENOENT)
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        debug!("read {} {} {}", ino, offset, size);

        match self.fs.get_inode(ino) {
            Err(err) => {
                debug!("  not found {}", err);

                reply.error(ENOENT)
            }
            Ok(attr) => {
                if attr.kind == FileType::Directory {
                    reply.error(ENOENT);
                    return;
                }
                debug!("  is dir {}", ino);
                let read_size = min(size, attr.size as u32);
                debug!("  read size={}", read_size);
                let mut buffer = vec![0; read_size as usize];
                match self.fs.read(ino, offset as u64, &mut buffer) {
                    Err(err) => {
                        debug!("  read error {}", err);
                        reply.error(EIO);
                        return;
                    }
                    Ok(len) => {
                        reply.data(&buffer[..len]);
                    }
                }
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        inode: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        #[allow(unused_variables)] flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!("write() called with {:?} size={:?}", inode, data.len());

        assert!(offset >= 0);

        match self.fs.get_inode(inode) {
            Ok(mut attr) => {
                if attr.kind == FileType::Directory {
                    reply.error(ENOENT);
                    return;
                }
                match self.fs.write_all(inode, offset as u64, data) {
                    Err(err) => {
                        debug!("  write error {}", err);
                        reply.error(EIO);
                        return;
                    }
                    Ok(_) => {
                        let mut attr = self.fs.get_inode(inode).unwrap();
                        // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
                        // However, xfstests fail in that case
                        clear_suid_sgid(&mut attr);
                        if let Err(err) = self.fs.replace_inode(inode, &mut attr) {
                            debug!("  write error {}", err);
                            reply.error(ENOENT);
                            return;
                        }

                        reply.written(data.len() as u32);
                    }
                }
            }
            Err(err) => {
                debug!("  not found {}", err);
                reply.error(ENOENT);
            }
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        debug!("flush() called with {:?} {:?} {:?}", ino, fh, lock_owner);

        reply.ok();
    }

    fn release(&mut self, _req: &Request<'_>, _ino: u64, _fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        debug!("release() called with {:?} {:?} {:?}", _ino, _fh, _lock_owner);

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        debug!("releasedir() called with {:?} {:?}", inode, _fh);

        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir {} {} {}", ino, _fh, offset);

        match self.fs.get_inode(ino) {
            Ok(attr) => {
                if attr.kind != FileType::Directory {
                    reply.error(ENOTDIR);
                    return;
                }

                match self.fs.read_dir(ino) {
                    Ok(iter) => {
                        for (i, entry) in iter.into_iter().enumerate().skip(offset as usize) {
                            if reply.add(entry.ino, (i + 1) as i64, entry.kind, entry.name) {
                                break;
                            }
                        }
                    }
                    _ => {
                        reply.error(ENOENT);
                        return;
                    }
                }

                reply.ok();
            }
            _ => reply.error(ENOENT),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        debug!("mkdir() called with {:?} {:?} {:o}", parent, name, mode);

        if self.fs.exists_by_name(parent, name.to_str().unwrap()) {
            reply.error(libc::EEXIST);
            return;
        }

        match self.fs.get_inode(parent) {
            Err(_) => {
                reply.error(ENOENT);
                return;
            }
            Ok(parent_attr) => {
                if !check_access(
                    parent_attr.uid,
                    parent_attr.gid,
                    parent_attr.perm,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                ) {
                    reply.error(libc::EACCES);
                    return;
                }

                let mut attr = dir_attr();
                attr.size = BLOCK_SIZE;
                attr.atime = SystemTime::now();
                attr.mtime = SystemTime::now();
                attr.ctime = SystemTime::now();

                if req.uid() != 0 {
                    mode &= !(libc::S_ISUID | libc::S_ISGID);
                }
                if parent_attr.perm & libc::S_ISGID as u16 != 0 {
                    mode |= libc::S_ISGID as u32;
                }
                attr.perm = self.creation_mode(mode);

                attr.uid = req.uid();
                attr.gid = creation_gid(&parent_attr, req.gid());

                match self.fs.create_nod(parent, name.to_str().unwrap(), attr) {
                    Err(err) => {
                        debug!("  mkdir error {}", err);
                        reply.error(ENOENT);

                        return;
                    }
                    Ok(attr) => reply.entry(&Duration::new(0, 0), &attr, 0)
                }
            }
        }
    }

    fn setattr(
        &mut self,
        req: &Request,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        debug!("setattr() called with {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}", inode, mode, uid, gid, size, atime, mtime, fh);

        let mut attr = if let Ok(attr) = self.fs.get_inode(inode) { attr } else {
            reply.error(ENOENT);
            return;
        };

        if let Some(mode) = mode {
            debug!("chmod() called with {:?}, {:o}", inode, mode);

            if req.uid() != 0 && req.uid() != attr.uid {
                reply.error(libc::EPERM);
                return;
            }
            if req.uid() != 0
                && req.gid() != attr.gid
                && !get_groups(req.pid()).contains(&attr.gid)
            {
                // If SGID is set and the file belongs to a group that the caller is not part of
                // then the SGID bit is suppose to be cleared during chmod
                attr.perm = (mode & !libc::S_ISGID as u32) as u16;
            } else {
                attr.perm = mode as u16;
            }
            attr.ctime = SystemTime::now();
            reply.attr(&Duration::new(0, 0), &attr);
            return;
        }

        if uid.is_some() || gid.is_some() {
            debug!("chown() called with {:?} {:?} {:?}", inode, uid, gid);

            if let Some(gid) = gid {
                // Non-root users can only change gid to a group they're in
                if req.uid() != 0 && !get_groups(req.pid()).contains(&gid) {
                    reply.error(libc::EPERM);
                    return;
                }
            }
            if let Some(uid) = uid {
                if req.uid() != 0
                    // but no-op changes by the owner are not an error
                    && !(uid == attr.uid && req.uid() == attr.uid)
                {
                    reply.error(libc::EPERM);
                    return;
                }
            }
            // Only owner may change the group
            if gid.is_some() && req.uid() != 0 && req.uid() != attr.uid {
                reply.error(libc::EPERM);
                return;
            }

            if attr.perm & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) as u16 != 0 {
                // SUID & SGID are suppose to be cleared when chown'ing an executable file
                clear_suid_sgid(&mut attr);
            }

            if let Some(uid) = uid {
                attr.uid = uid;
                // Clear SETUID on owner change
                attr.perm &= !libc::S_ISUID as u16;
            }
            if let Some(gid) = gid {
                attr.gid = gid;
                // Clear SETGID unless user is root
                if req.uid() != 0 {
                    attr.perm &= !libc::S_ISGID as u16;
                }
            }
            attr.ctime = SystemTime::now();
            reply.attr(&Duration::new(0, 0), &attr);
            return;
        }

        if let Some(size) = size {
            debug!("truncate() called with {:?} {:?}", inode, size);

            if let Err(err) = self.fs.truncate(inode, size) {
                debug!("  truncate error {}", err);
                reply.error(EBADF);
                return;
            }

            // Clear SETUID & SETGID on truncate
            clear_suid_sgid(&mut attr);
        }

        if let Some(atime) = atime {
            debug!("utimens() called with {:?}, atime={:?}", inode, atime);

            if attr.uid != req.uid() && req.uid() != 0 && atime != Now {
                reply.error(libc::EPERM);
                return;
            }

            if attr.uid != req.uid()
                && !check_access(
                attr.uid,
                attr.gid,
                attr.perm,
                req.uid(),
                req.gid(),
                libc::W_OK,
            ) {
                reply.error(libc::EACCES);
                return;
            }

            attr.atime = match atime {
                TimeOrNow::SpecificTime(time) => time,
                Now => SystemTime::now(),
            };
            attr.ctime = SystemTime::now();
        }
        if let Some(mtime) = mtime {
            debug!("utimens() called with {:?}, mtime={:?}", inode, mtime);

            if attr.uid != req.uid() && req.uid() != 0 && mtime != Now {
                reply.error(libc::EPERM);
                return;
            }

            if attr.uid != req.uid()
                && !check_access(
                attr.uid,
                attr.gid,
                attr.perm,
                req.uid(),
                req.gid(),
                libc::W_OK,
            ) {
                reply.error(libc::EACCES);
                return;
            }

            attr.mtime = match mtime {
                TimeOrNow::SpecificTime(time) => time,
                Now => SystemTime::now(),
            };
            attr.ctime = SystemTime::now();
        }

        if let Err(err) = self.fs.replace_inode(inode, &mut attr) {
            debug!("  setattr error {}", err);
            reply.error(ENOENT);
            return;
        }

        reply.attr(&Duration::new(0, 0), &attr);
        return;
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("unlink() called with {:?} {:?}", parent, name);

        match self.fs.get_inode(parent) {
            Err(_) => { reply.error(ENOENT) }
            Ok(parent_attr) => {
                if parent_attr.kind != FileType::Directory {
                    reply.error(ENOENT);
                    return;
                }

                match self.fs.find_by_name(parent, name.to_str().unwrap()) {
                    Ok(Some(attr)) => {
                        let uid = req.uid();
                        // "Sticky bit" handling
                        if parent_attr.perm & libc::S_ISVTX as u16 != 0
                            && uid != 0
                            && uid != parent_attr.uid
                            && uid != attr.uid
                        {
                            reply.error(libc::EACCES);
                            return;
                        }

                        if let Err(err) = self.fs.remove_file(parent, name.to_str().unwrap()) {
                            debug!("  unlink error {}", err);
                            reply.error(ENOENT);
                            return;
                        }

                        reply.ok();
                    }
                    _ => {
                        reply.error(ENOENT);
                        return;
                    }
                }
            }
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("rmdir() called with {:?} {:?}", parent, name);

        match self.fs.get_inode(parent) {
            Ok(parent_attr) => {
                if !check_access(
                    parent_attr.uid,
                    parent_attr.gid,
                    parent_attr.perm,
                    req.uid(),
                    req.gid(),
                    libc::W_OK,
                ) {
                    reply.error(libc::EACCES);
                    return;
                }

                match self.fs.find_by_name(parent, name.to_str().unwrap()) {
                    Ok(Some(attr)) => {
                        if attr.kind != FileType::Directory {
                            reply.error(libc::EACCES);
                            return;
                        }
                        if let Ok(children) = self.fs.children_count(attr.ino) {
                            if children > 2 {
                                reply.error(libc::ENOTEMPTY);
                                return;
                            }
                        }

                        // "Sticky bit" handling
                        if parent_attr.perm & libc::S_ISVTX as u16 != 0
                            && req.uid() != 0
                            && req.uid() != parent_attr.uid
                            && req.uid() != attr.uid
                        {
                            reply.error(libc::EACCES);
                            return;
                        }

                        if let Err(err) = self.fs.remove_dir(parent, name.to_str().unwrap()) {
                            debug!("  rmdir error {}", err);
                            reply.error(ENOENT);

                            return;
                        }

                        reply.ok();
                    }
                    _ => reply.error(ENOENT)
                }
            }
            _ => reply.error(ENOENT)
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        warn!("statfs() implementation is a stub");
        // TODO: real implementation of this
        reply.statfs(
            10_000,
            10_000,
            10_000,
            1,
            10_000,
            BLOCK_SIZE as u32,
            MAX_NAME_LENGTH,
            BLOCK_SIZE as u32,
        );
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        debug!(
            "copy_file_range() called with src ({}, {}, {}) dest ({}, {}, {}) size={}",
            src_fh, src_inode, src_offset, dest_fh, dest_inode, dest_offset, size
        );

        match self.fs.copy_file_range(src_inode, src_offset as u64, dest_inode, dest_offset as u64, size as usize) {
            Err(err) => {
                debug!("  copy_file_range error {}", err);
                reply.error(EBADF);
                return;
            }
            Ok(len) => {
                reply.written(len as u32);
            }
        }
    }

    fn rename(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let attr = match self.fs.find_by_name(parent, name.to_str().unwrap()) {
            Ok(Some(attr)) => attr,
            _ => {
                reply.error(ENOENT);
                return;
            }
        };
        let parent_attr = match self.fs.get_inode(parent) {
            Ok(parent_attr) => parent_attr,
            _ => {
                reply.error(ENOENT);
                return;
            }
        };

        if !check_access(
            parent_attr.uid,
            parent_attr.gid,
            parent_attr.perm,
            req.uid(),
            req.gid(),
            libc::W_OK) {
            reply.error(libc::EACCES);
            return;
        }

        // "Sticky bit" handling
        if parent_attr.perm & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attr.uid
            && req.uid() != attr.uid {
            reply.error(libc::EACCES);
            return;
        }

        let new_parent_attr = match self.fs.get_inode(new_parent) {
            Ok(new_parent_attr) => new_parent_attr,
            _ => {
                reply.error(ENOENT);
                return;
            }
        };

        if !check_access(
            new_parent_attr.uid,
            new_parent_attr.gid,
            new_parent_attr.perm,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        // "Sticky bit" handling in new_parent
        if new_parent_attr.perm & libc::S_ISVTX as u16 != 0 {
            if let Ok(Some(existing_attrs)) = self.fs.find_by_name(new_parent, new_name.to_str().unwrap()) {
                if req.uid() != 0
                    && req.uid() != new_parent_attr.uid
                    && req.uid() != existing_attrs.uid
                {
                    reply.error(libc::EACCES);
                    return;
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
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        match self.fs.rename(parent, name.to_str().unwrap(), new_parent, new_name.to_str().unwrap()) {
            Ok(_) => reply.ok(),
            Err(FsError::NotEmpty) => {
                reply.error(ENOTEMPTY);
                return;
            }
            _ => {
                reply.error(ENOENT);
                return;
            }
        }
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
        crtime: UNIX_EPOCH,
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
        crtime: UNIX_EPOCH,
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

fn creation_gid(parent: &FileAttr, gid: u32) -> u32 {
    if parent.perm & libc::S_ISGID as u16 != 0 {
        return parent.gid;
    }

    gid
}

pub fn check_access(
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

fn as_file_kind(mut mode: u32) -> FileType {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileType::RegularFile;
    } else if mode == libc::S_IFLNK as u32 {
        return FileType::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileType::Directory;
    } else {
        unimplemented!("{}", mode);
    }
}

fn clear_suid_sgid(attr: &mut FileAttr) {
    attr.perm &= !libc::S_ISUID as u16;
    // SGID is only suppose to be cleared if XGRP is set
    if attr.perm & libc::S_IXGRP as u16 != 0 {
        attr.perm &= !libc::S_ISGID as u16;
    }
}
