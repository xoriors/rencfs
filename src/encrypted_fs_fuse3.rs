use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::iter::Skip;
use std::num::NonZeroU32;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use std::vec::IntoIter;

use bytes::Bytes;
use fuse3::{Inode, Result};
use fuse3::raw::prelude::*;
use fuse3::raw::prelude::*;
use futures_util::stream;
use futures_util::stream::Iter;

use crate::encrypted_fs::EncryptedFs;

const CONTENT: &str = "hello world\n";

const PARENT_INODE: u64 = 1;
const FILE_INODE: u64 = 2;
const FILE_NAME: &str = "hello-world.txt";
const PARENT_MODE: u16 = 0o755;
const FILE_MODE: u16 = 0o644;
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

pub struct EncryptedFsFuse3 {
    fs: Mutex<RefCell<EncryptedFs>>,
    direct_io: bool,
    suid_support: bool,
    dir_handle: u64,
}

impl EncryptedFsFuse3 {
    pub fn new(data_dir: String) -> Self {
        Self {
            fs: Mutex::new(RefCell::new(EncryptedFs::new(data_dir.as_str()).unwrap())),
            // TODO: make these configurable
            direct_io: false,
            suid_support: false,
            dir_handle: 0,
        }
    }

    fn get_fs(&self) -> MutexGuard<'_, RefCell<EncryptedFs>> {
        self.fs.lock().unwrap()
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if !self.suid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID)) as u16
        } else {
            mode as u16
        }
    }
}

fn creation_gid(parent: &fuser::FileAttr, gid: u32) -> u32 {
    if parent.perm & libc::S_ISGID as u16 != 0 {
        return parent.gid;
    }

    gid
}

struct DirectoryEntryIterator {
    iter: Box<dyn Iterator<Item=crate::encrypted_fs::DirectoryEntry>>,
}

impl DirectoryEntryIterator {
    fn new(iter: Box<dyn Iterator<Item=crate::encrypted_fs::DirectoryEntry>>) -> Box<Self> {
        Box::from(Self { iter })
    }
}

// impl Iterator for DirectoryEntryIterator {
//     type Item = DirectoryEntry;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         self.iter.next().map(|entry| Ok(DirectoryEntry {
//             inode: entry.ino,
//             name: OsString::from(entry.name),
//             kind: if entry.kind == fuser::FileType::Directory {
//                 FileType::Directory
//             } else {
//                 FileType::RegularFile
//             },
//             offset: 0,
//         }))
//     }
//
// }


fn to_attr(from: fuser::FileAttr) -> FileAttr {
    FileAttr {
        ino: from.ino,
        size: from.size,
        blocks: from.blocks,
        atime: from.atime.into(),
        mtime: from.mtime.into(),
        ctime: from.ctime.into(),
        kind: if from.kind == fuser::FileType::Directory {
            FileType::Directory
        } else {
            FileType::RegularFile
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
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        Ok(ReplyInit {
            max_write: NonZeroU32::new(16 * 1024).unwrap(),
        })
    }

    async fn destroy(&self, _req: Request) {}

    async fn lookup(&self, _req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        let attr = self.get_fs().borrow()
            .find_by_name(parent, name.to_str().unwrap()).unwrap();
        if attr.is_none() {
            return Err(libc::ENOENT.into());
        }

        Ok(ReplyEntry {
            ttl: TTL,
            attr: to_attr(attr.unwrap()),
            generation: 0,
        })
    }

    async fn getattr(
        &self,
        _req: Request,
        inode: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        let attr = self.get_fs().borrow()
            .get_inode(inode).unwrap();

        Ok(ReplyAttr {
            ttl: TTL,
            attr: to_attr(attr),
        })
    }

    async fn open(&self, _req: Request, inode: u64, flags: u32) -> Result<ReplyOpen> {
        let (access_mask, read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC as u32 != 0 {
                    return Err(libc::EACCES.into());
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

        let fh = self.get_fs().borrow_mut()
            .open(inode, read, write).unwrap();

        Ok(ReplyOpen { fh, flags })
    }

    async fn read(
        &self,
        _req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        let mut buf: Vec<u8> = vec![0; size as usize];
        // let len = self.get_fs().borrow_mut()
        //     .read(inode, offset, &mut buf, fh).unwrap();
        let len = size as usize ;

        Ok(ReplyData {
            data: Bytes::copy_from_slice(buf[..len].as_ref()),
        })
    }

    type DirEntryStream<'a> = Iter<Skip<IntoIter<Result<DirectoryEntry>>>> where Self: 'a;

    async fn readdir(
        &self,
        _req: Request,
        inode: u64,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<Self::DirEntryStream<'_>>> {
        let items: Vec<crate::encrypted_fs::DirectoryEntry> = self.get_fs().borrow()
            .read_dir(inode).unwrap().into_iter().collect();
        let mut i = 0;
        let items: Vec<Result<DirectoryEntry>> = items.iter().map(|entry| {
            i += 1;
            Ok(DirectoryEntry {
                inode: entry.ino,
                name: OsString::from(entry.name.to_string()),
                kind: if entry.kind == fuser::FileType::Directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                offset: i,
            }
            )
        }).collect();


        Ok(ReplyDirectory {
            entries: stream::iter(items.into_iter().skip(offset as usize)),
        })
    }

    async fn access(&self, _req: Request, inode: u64, _mask: u32) -> Result<()> {
        if inode != PARENT_INODE && inode != FILE_INODE {
            return Err(libc::ENOENT.into());
        }

        Ok(())
    }

    type DirEntryPlusStream<'a> = Iter<Skip<IntoIter<Result<DirectoryEntryPlus>>>> where Self: 'a;

    async fn readdirplus(
        &self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<Self::DirEntryPlusStream<'_>>> {
        let items: Vec<crate::encrypted_fs::DirectoryEntry> = self.get_fs().borrow().read_dir(parent).unwrap().into_iter().collect();
        let mut i = 0;
        let items: Vec<Result<DirectoryEntryPlus>> = items.iter().map(|entry| {
            i += 1;

            Ok(DirectoryEntryPlus {
                inode: entry.ino,
                name: OsString::from(entry.name.to_string()),
                kind: if entry.kind == fuser::FileType::Directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                offset: i,
                attr: to_attr(self.get_fs().borrow().get_inode(entry.ino).unwrap()),
                entry_ttl: Default::default(),
                generation: 0,
                attr_ttl: Default::default(),
            })
        }).collect();


        Ok(ReplyDirectoryPlus {
            entries: stream::iter(items.into_iter().skip(offset as usize)),
        })
    }

    async fn statfs(&self, _req: Request, _inode: u64) -> Result<ReplyStatFs> {
        Ok(STATFS)
    }

    async fn release(
        &self,
        req: Request,
        inode: Inode,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        if flush {
            self.get_fs().borrow_mut().flush(fh).unwrap();
        }
        self.get_fs().borrow_mut().release_handle(fh).unwrap();

        Ok(())
    }

    async fn flush(&self, req: Request, inode: Inode, fh: u64, lock_owner: u64) -> Result<()> {
        self.get_fs().borrow_mut().flush(fh).unwrap();

        Ok(())
    }

    async fn create(
        &self,
        req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        let (read, write) = match flags as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(libc::EINVAL.into());
            }
        };

        let mut mode = mode;
        if req.uid != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID);
        }

        let parent_attr = self.get_fs().borrow_mut().get_inode(parent).unwrap();
        let mut attr = fuser::FileAttr {
            ino: 0,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: fuser::FileType::RegularFile,
            perm: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 0,
            flags,
        };
        attr.perm = self.creation_mode(mode);
        attr.uid = req.uid;
        attr.gid = creation_gid(&parent_attr, req.gid);


        let (fh, attr) = self.get_fs().borrow_mut().create_nod(parent, name.to_str().unwrap(), attr, read, write).unwrap();

        Ok(ReplyCreated {
            ttl: TTL,
            attr: to_attr(attr),
            generation: 0,
            fh,
            flags: 0,
        })
    }

    async fn setattr(
        &self,
        req: Request,
        inode: Inode,
        fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr>
    {
        Ok(ReplyAttr {
            ttl: TTL,
            attr: to_attr(self.get_fs().borrow_mut().get_inode(inode).unwrap()),
        })
    }

    async fn unlink(&self, req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        self.get_fs().borrow_mut().remove_file(parent, name.to_str().unwrap()).unwrap();

        Ok(())
    }

    async fn write(
        &self,
        req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite>
    {
        self.get_fs().borrow_mut().write_all(inode, offset, data, fh).unwrap();

        Ok(ReplyWrite {
            written: data.len() as u32,
        })
    }
}
