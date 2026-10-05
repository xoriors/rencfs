//! Windows implementation using [Dokan](https://dokan-dev.github.io).
//!
//! The Dokan driver needs to be installed, see <https://github.com/dokan-dev/dokany/releases>.
//! We use Dokan and not `WinFsp` because the `WinFsp` Rust bindings are GPLv3, while Dokan bindings
//! are MIT and its user mode library is LGPL.
//!
//! Path to inode resolution and opened file handling are in [`super::path_fs`], which is tested on
//! all platforms, this module only maps Dokan callbacks to it.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use std::time::SystemTime;

use async_trait::async_trait;
use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter,
    FileTimeOperation, FillDataError, FillDataResult, FindData, MountFlags, MountOptions,
    OperationInfo, OperationResult, VolumeInfo, IO_SECURITY_CONTEXT,
};
use dokan_sys::win32::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_MAXIMUM_DISPOSITION,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF,
    FILE_SUPERSEDE,
};
use shush_rs::ExposeSecret;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use widestring::{U16CStr, U16CString};
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INTERNAL_ERROR, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED,
    STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SHARING_VIOLATION,
};
use winapi::um::fileapi::GetDiskFreeSpaceExW;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY,
    FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH, FILE_READ_ONLY_VOLUME,
    FILE_UNICODE_ON_DISK, ULARGE_INTEGER,
};

use crate::crypto::Cipher;
use crate::encryptedfs::{EncryptedFs, FileAttr, FileType, FsError, PasswordProvider};
use crate::mount;
use crate::mount::path_fs::{OpenNode, PathFs};
use crate::mount::{MountHandleInner, MountPoint};

const MAX_COMPONENT_LENGTH: u32 = 255;

fn to_ntstatus(err: FsError) -> NTSTATUS {
    match err {
        FsError::NotFound(_) | FsError::InodeNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::InvalidInput(_) => STATUS_OBJECT_NAME_INVALID,
        FsError::InvalidInodeType => STATUS_INVALID_PARAMETER,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::MaxFilesizeExceeded(_) => STATUS_DISK_FULL,
        FsError::Io { source, .. } if source.kind() == io::ErrorKind::PermissionDenied => {
            STATUS_ACCESS_DENIED
        }
        err => {
            error!(err = %err);
            STATUS_INTERNAL_ERROR
        }
    }
}

fn file_attributes(attr: &FileAttr, read_only: bool) -> u32 {
    match attr.kind {
        FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        FileType::RegularFile if read_only => FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY,
        FileType::RegularFile => FILE_ATTRIBUTE_ARCHIVE,
    }
}

const fn time(op: FileTimeOperation) -> Option<SystemTime> {
    match op {
        FileTimeOperation::SetTime(time) => Some(time),
        _ => None,
    }
}

struct Handler {
    pfs: PathFs,
    rt: tokio::runtime::Runtime,
    data_dir: PathBuf,
    read_only: bool,
}

impl Handler {
    /// Dokan callbacks are sync and run on Dokan's threads, run the async ops on our runtime.
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    fn fs(&self) -> &EncryptedFs {
        self.pfs.fs()
    }

    fn check_writable(&self) -> OperationResult<()> {
        if self.read_only {
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        } else {
            Ok(())
        }
    }

    async fn open_or_create(
        &self,
        path: &str,
        create_disposition: u32,
        create_options: u32,
    ) -> OperationResult<CreateFileInfo<OpenNode>> {
        let want_dir = create_options & FILE_DIRECTORY_FILE != 0;
        let want_file = create_options & FILE_NON_DIRECTORY_FILE != 0;
        let delete_on_close = create_options & FILE_DELETE_ON_CLOSE != 0;

        if let Some(attr) = self.pfs.lookup(path).await.map_err(to_ntstatus)? {
            let is_dir = attr.kind == FileType::Directory;
            if is_dir && want_file {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            if !is_dir && want_dir {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
            if delete_on_close {
                self.check_writable()?;
            }
            match create_disposition {
                FILE_CREATE => return Err(STATUS_OBJECT_NAME_COLLISION),
                FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                    if is_dir {
                        return Err(STATUS_INVALID_PARAMETER);
                    }
                    self.check_writable()?;
                    self.fs().set_len(attr.ino, 0).await.map_err(to_ntstatus)?;
                }
                _ => {}
            }
            return Ok(CreateFileInfo {
                context: OpenNode::new(&attr),
                is_dir,
                new_file_created: false,
            });
        }

        if create_disposition == FILE_OPEN || create_disposition == FILE_OVERWRITE {
            return Err(match self.pfs.parent_and_name(path).await {
                Ok(_) => STATUS_OBJECT_NAME_NOT_FOUND,
                Err(_) => STATUS_OBJECT_PATH_NOT_FOUND,
            });
        }
        if want_dir && create_disposition != FILE_CREATE && create_disposition != FILE_OPEN_IF {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.check_writable()?;
        let kind = if want_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let attr = self.pfs.create(path, kind).await.map_err(|err| match err {
            FsError::NotFound(_) => STATUS_OBJECT_PATH_NOT_FOUND,
            err => to_ntstatus(err),
        })?;
        Ok(CreateFileInfo {
            context: OpenNode::new(&attr),
            is_dir: want_dir,
            new_file_created: true,
        })
    }
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for Handler {
    type Context = OpenNode;

    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        _info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        if create_disposition > FILE_MAXIMUM_DISPOSITION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let path = file_name.to_string_lossy();
        debug!(path, create_disposition, create_options, "create_file");
        self.block_on(self.open_or_create(&path, create_disposition, create_options))
    }

    fn cleanup(
        &'h self,
        file_name: &U16CStr,
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) {
        self.block_on(async {
            if let Err(err) = context.release(self.fs()).await {
                error!(err = %err, "release");
            }
            if info.delete_on_close() {
                let path = file_name.to_string_lossy();
                if let Err(err) = self.pfs.remove(&path).await {
                    error!(err = %err, path, "delete on close");
                }
            }
        });
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) {
        if let Err(err) = self.block_on(context.release(self.fs())) {
            error!(err = %err, "release");
        }
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if context.is_dir() {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.block_on(async {
            let mut read = 0;
            while read < buffer.len() {
                let len = context
                    .read(self.fs(), offset as u64 + read as u64, &mut buffer[read..])
                    .await
                    .map_err(to_ntstatus)?;
                if len == 0 {
                    break;
                }
                read += len;
            }
            Ok(read as u32)
        })
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn write_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &[u8],
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if context.is_dir() {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        self.check_writable()?;
        let mut offset = if info.write_to_eof() {
            None
        } else if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        } else {
            Some(offset as u64)
        };
        self.block_on(async {
            let mut written = 0;
            while written < buffer.len() {
                let len = context
                    .write(self.fs(), offset, &buffer[written..])
                    .await
                    .map_err(to_ntstatus)?;
                if len == 0 {
                    return Err(STATUS_INTERNAL_ERROR);
                }
                written += len;
                offset = offset.map(|o| o + len as u64);
            }
            Ok(written as u32)
        })
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        self.block_on(context.flush(self.fs())).map_err(to_ntstatus)
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        let attr = self
            .block_on(self.fs().get_attr(context.ino))
            .map_err(to_ntstatus)?;
        Ok(FileInfo {
            attributes: file_attributes(&attr, self.read_only),
            creation_time: attr.crtime,
            last_access_time: attr.atime,
            last_write_time: attr.mtime,
            file_size: attr.size,
            number_of_links: attr.nlink,
            file_index: attr.ino,
        })
    }

    fn find_files(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        if !context.is_dir() {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let entries = self
            .block_on(self.pfs.read_dir(context.ino))
            .map_err(to_ntstatus)?;
        for entry in entries {
            let Ok(file_name) = U16CString::from_str(entry.name.expose_secret().as_str()) else {
                warn!("skip file name with nul char");
                continue;
            };
            let res = fill_find_data(&FindData {
                attributes: file_attributes(&entry.attr, self.read_only),
                creation_time: entry.attr.crtime,
                last_access_time: entry.attr.atime,
                last_write_time: entry.attr.mtime,
                file_size: entry.attr.size,
                file_name,
            });
            match res {
                Ok(()) | Err(FillDataError::NameTooLong) => {}
                Err(FillDataError::BufferFull) => return Err(STATUS_BUFFER_OVERFLOW),
            }
        }
        Ok(())
    }

    fn set_file_attributes(
        &'h self,
        _file_name: &U16CStr,
        _file_attributes: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        // Windows file attributes (hidden, system, ...) are not stored
        self.check_writable()
    }

    fn set_file_time(
        &'h self,
        _file_name: &U16CStr,
        creation_time: FileTimeOperation,
        last_access_time: FileTimeOperation,
        last_write_time: FileTimeOperation,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        self.check_writable()?;
        self.block_on(self.pfs.set_times(
            context.ino,
            time(creation_time),
            time(last_access_time),
            time(last_write_time),
        ))
        .map_err(to_ntstatus)
    }

    fn delete_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        // the actual delete is done in cleanup
        self.check_writable()?;
        if context.is_dir() {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        Ok(())
    }

    fn delete_directory(
        &'h self,
        _file_name: &U16CStr,
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        // the actual delete is done in cleanup
        self.check_writable()?;
        if info.delete_on_close() && self.fs().len(context.ino).map_err(to_ntstatus)? > 0 {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        Ok(())
    }

    fn move_file(
        &'h self,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        self.check_writable()?;
        let from = file_name.to_string_lossy();
        let to = new_file_name.to_string_lossy();
        self.block_on(self.pfs.rename(&from, &to, replace_if_existing))
            .map_err(|err| match err {
                FsError::NotEmpty | FsError::AlreadyExists if !replace_if_existing => {
                    STATUS_OBJECT_NAME_COLLISION
                }
                FsError::NotEmpty => STATUS_ACCESS_DENIED,
                err => to_ntstatus(err),
            })
    }

    #[allow(clippy::cast_sign_loss)]
    fn set_end_of_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        self.check_writable()?;
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.block_on(context.set_len(self.fs(), offset as u64))
            .map_err(to_ntstatus)
    }

    #[allow(clippy::cast_sign_loss)]
    fn set_allocation_size(
        &'h self,
        _file_name: &U16CStr,
        alloc_size: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        self.check_writable()?;
        if alloc_size < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // we don't preallocate, only shrink if needed
        self.block_on(async {
            let size = self.fs().get_attr(context.ino).await?.size;
            if (alloc_size as u64) < size {
                context.set_len(self.fs(), alloc_size as u64).await?;
            }
            Ok(())
        })
        .map_err(to_ntstatus)
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        // report the space of the disk where data dir is
        let dir = U16CString::from_os_str(self.data_dir.as_os_str())
            .map_err(|_| STATUS_INTERNAL_ERROR)?;
        unsafe {
            let mut available: ULARGE_INTEGER = std::mem::zeroed();
            let mut total: ULARGE_INTEGER = std::mem::zeroed();
            let mut free: ULARGE_INTEGER = std::mem::zeroed();
            if GetDiskFreeSpaceExW(dir.as_ptr(), &mut available, &mut total, &mut free) == 0 {
                return Err(STATUS_INTERNAL_ERROR);
            }
            Ok(DiskSpaceInfo {
                byte_count: *total.QuadPart(),
                free_byte_count: *free.QuadPart(),
                available_byte_count: *available.QuadPart(),
            })
        }
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<VolumeInfo> {
        let mut fs_flags =
            FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
        if self.read_only {
            fs_flags |= FILE_READ_ONLY_VOLUME;
        }
        Ok(VolumeInfo {
            name: U16CString::from_str("rencfs").unwrap(),
            serial_number: 0,
            max_component_length: MAX_COMPONENT_LENGTH,
            fs_flags,
            // custom names don't play well with UAC
            fs_name: U16CString::from_str("NTFS").unwrap(),
        })
    }

    fn mounted(
        &'h self,
        mount_point: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<()> {
        info!(mount_point = %mount_point.to_string_lossy(), "mounted");
        Ok(())
    }

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        info!("unmounted");
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
}

#[async_trait]
impl MountPoint for MountPointImpl {
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self {
        Self {
            mountpoint,
            data_dir,
            password_provider: Some(password_provider),
            cipher,
            allow_root,
            allow_other,
            read_only,
        }
    }

    async fn mount(mut self) -> crate::encryptedfs::FsResult<mount::MountHandle> {
        if self.allow_root || self.allow_other {
            warn!("allow_root and allow_other are not supported on Windows, ignoring");
        }
        // a drive letter like `M:` or `M:\`, else an empty directory
        let is_drive = self.mountpoint.as_os_str().len() <= 3;
        if !is_drive && !self.mountpoint.exists() {
            tokio::fs::create_dir_all(&self.mountpoint).await?;
        }
        let mount_point = U16CString::from_os_str(self.mountpoint.as_os_str())
            .map_err(|_| FsError::InvalidInput("invalid mount point"))?;

        let (mounted_tx, mounted_rx) = oneshot::channel();
        let (unmounted_tx, unmounted_rx) = oneshot::channel();
        let password_provider = self.password_provider.take().unwrap();
        let data_dir = self.data_dir.clone();
        let cipher = self.cipher;
        let read_only = self.read_only;
        let mount_point_clone = mount_point.clone();
        thread::Builder::new()
            .name("rencfs-dokan".to_string())
            .spawn(move || {
                run_dokan(
                    &mount_point_clone,
                    data_dir,
                    password_provider,
                    cipher,
                    read_only,
                    mounted_tx,
                    unmounted_tx,
                );
            })?;
        mounted_rx
            .await
            .map_err(|_| FsError::Other("mount thread exited"))??;

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                mount_point,
                unmounted: unmounted_rx,
            },
        })
    }
}

/// Mounts and blocks until the file system is unmounted.
fn run_dokan(
    mount_point: &U16CStr,
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    read_only: bool,
    mounted_tx: oneshot::Sender<crate::encryptedfs::FsResult<()>>,
    unmounted_tx: oneshot::Sender<io::Result<()>>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            let _ = mounted_tx.send(Err(err.into()));
            return;
        }
    };
    let fs = match rt.block_on(EncryptedFs::new(
        data_dir.clone(),
        password_provider,
        cipher,
        read_only,
    )) {
        Ok(fs) => fs,
        Err(err) => {
            let _ = mounted_tx.send(Err(err));
            return;
        }
    };
    let handler = Handler {
        pfs: PathFs::new(fs),
        rt,
        data_dir,
        read_only,
    };
    let mut flags = MountFlags::CASE_SENSITIVE;
    if read_only {
        flags |= MountFlags::WRITE_PROTECT;
    }
    let options = MountOptions {
        flags,
        ..Default::default()
    };

    dokan::init();
    {
        let mut mounter = FileSystemMounter::new(&handler, mount_point, &options);
        match mounter.mount() {
            Ok(file_system) => {
                let _ = mounted_tx.send(Ok(()));
                // blocks until unmounted
                drop(file_system);
                let _ = unmounted_tx.send(Ok(()));
            }
            Err(err) => {
                let _ = mounted_tx.send(Err(io::Error::other(err.to_string()).into()));
            }
        }
    }
    dokan::shutdown();
}

pub(in crate::mount) struct MountHandleInnerImpl {
    mount_point: U16CString,
    unmounted: oneshot::Receiver<io::Result<()>>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.unmounted)
            .poll(cx)
            .map(|res| res.unwrap_or_else(|_| Err(io::Error::other("mount thread exited"))))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        if !dokan::unmount(&self.mount_point) {
            return Err(io::Error::other("cannot unmount"));
        }
        self.await
    }
}

pub(super) fn umount(mountpoint: &str) -> io::Result<()> {
    let mount_point = U16CString::from_str(mountpoint)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid mount point"))?;
    if dokan::unmount(mount_point) {
        Ok(())
    } else {
        Err(io::Error::other(format!("cannot umount {mountpoint}")))
    }
}
