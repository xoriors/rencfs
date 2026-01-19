use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tracing::{debug, error, info, trace};
use widestring::{U16CStr, U16CString};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    VolumeInfo,
};
use winfsp::host::FileSystemHost;
use windows::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

const TTL: Duration = Duration::from_secs(1);
const WINDOWS_TICK: u64 = 10_000_000;
const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;

pub struct EncryptedFsFileContext {
    ino: u64,
    fh: Option<u64>,
    is_directory: bool,
    dir_buffer: DirBuffer,
}

struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
    runtime: Runtime,
    read_only: bool,
}

impl EncryptedFsWinFsp {
    pub fn new(fs: Arc<EncryptedFs>, read_only: bool) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime");

        Self {
            fs,
            runtime,
            read_only,
        }
    }

    fn get_fs(&self) -> Arc<EncryptedFs> {
        self.fs.clone()
    }

    fn path_to_inode(&self, path: &U16CStr) -> winfsp::Result<u64> {
        let path_str = path
            .to_string()
            .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

        if path_str.is_empty() || path_str == "\\" {
            return Ok(1);
        }

        let path_str = path_str.trim_start_matches('\\');
        let components: Vec<&str> = path_str.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current_ino = 1u64;

        for component in components {
            let secret_name =
                SecretString::from_str(component).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

            let result = self
                .runtime
                .block_on(async { self.fs.find_by_name(current_ino, &secret_name).await });

            match result {
                Ok(Some(attr)) => current_ino = attr.ino,
                Ok(None) | Err(_) => return Err(STATUS_OBJECT_NAME_NOT_FOUND.into()),
            }
        }

        Ok(current_ino)
    }

    fn path_to_parent_and_name(&self, path: &U16CStr) -> winfsp::Result<(u64, String)> {
        let path_str = path
            .to_string()
            .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

        let path_str = path_str.trim_start_matches('\\');
        let components: Vec<&str> = path_str.split('\\').filter(|s| !s.is_empty()).collect();

        if components.is_empty() {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND.into());
        }

        let name = components.last().unwrap().to_string();
        let parent_components = &components[..components.len() - 1];
        let mut parent_ino = 1u64;

        for component in parent_components {
            let secret_name =
                SecretString::from_str(component).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

            let result = self
                .runtime
                .block_on(async { self.fs.find_by_name(parent_ino, &secret_name).await });

            match result {
                Ok(Some(attr)) => parent_ino = attr.ino,
                Ok(None) | Err(_) => return Err(STATUS_OBJECT_NAME_NOT_FOUND.into()),
            }
        }

        Ok((parent_ino, name))
    }

    fn attr_to_file_info(attr: &FileAttr) -> FileInfo {
        let mut file_info = FileInfo::default();

        file_info.file_attributes = if attr.kind == FileType::Directory {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };

        file_info.file_size = attr.size;
        file_info.allocation_size = attr.blocks * attr.blksize as u64;
        file_info.creation_time = system_time_to_filetime(attr.crtime);
        file_info.last_access_time = system_time_to_filetime(attr.atime);
        file_info.last_write_time = system_time_to_filetime(attr.mtime);
        file_info.change_time = system_time_to_filetime(attr.ctime);
        file_info.index_number = attr.ino;

        file_info
    }

    fn refresh_file_info(&self, ino: u64, file_info: &mut FileInfo) {
        if let Ok(attr) = self.runtime.block_on(async { self.fs.get_attr(ino).await }) {
            *file_info = Self::attr_to_file_info(&attr);
        }
    }
}

fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let nanos = duration.subsec_nanos() as u64;
            (secs + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK + nanos / 100
        }
        Err(_) => 0,
    }
}

fn filetime_to_system_time(filetime: u64) -> SystemTime {
    if filetime == 0 {
        return UNIX_EPOCH;
    }

    let secs = filetime / WINDOWS_TICK;
    let nanos = ((filetime % WINDOWS_TICK) * 100) as u32;

    if secs >= SEC_TO_UNIX_EPOCH {
        UNIX_EPOCH + Duration::new(secs - SEC_TO_UNIX_EPOCH, nanos)
    } else {
        UNIX_EPOCH
    }
}

impl FileSystemContext for EncryptedFsWinFsp {
    type FileContext = EncryptedFsFileContext;

    fn get_volume_info(&self) -> winfsp::Result<VolumeInfo> {
        trace!("get_volume_info");

        let mut volume_info = VolumeInfo::default();
        volume_info.total_size = 1024 * 1024 * 1024 * 100;
        volume_info.free_size = 1024 * 1024 * 1024 * 50;

        let label = U16CString::from_str("rencfs").unwrap();
        let label_slice = label.as_slice_with_nul();
        let copy_len = label_slice.len().min(volume_info.volume_label.len());
        volume_info.volume_label[..copy_len].copy_from_slice(&label_slice[..copy_len]);
        volume_info.volume_label_length = ((copy_len - 1) * 2) as u16;

        Ok(volume_info)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        trace!("get_security_by_name: {:?}", file_name.to_string());

        let ino = self.path_to_inode(file_name)?;
        let result = self
            .runtime
            .block_on(async { self.fs.get_attr(ino).await });

        match result {
            Ok(attr) => {
                let attributes = if attr.kind == FileType::Directory {
                    FILE_ATTRIBUTE_DIRECTORY.0
                } else {
                    FILE_ATTRIBUTE_NORMAL.0
                };

                Ok(FileSecurity {
                    attributes,
                    reparse: false,
                    sz_security_descriptor: 0,
                })
            }
            Err(_) => Err(STATUS_OBJECT_NAME_NOT_FOUND.into()),
        }
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        debug!("open: {:?}", file_name.to_string());

        let ino = self.path_to_inode(file_name)?;
        let result = self
            .runtime
            .block_on(async { self.fs.get_attr(ino).await });

        let attr = result.map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        let is_directory = attr.kind == FileType::Directory;

        let fh = if !is_directory {
            let read = true;
            let write = !self.read_only;

            let handle_result = self
                .runtime
                .block_on(async { self.fs.open(ino, read, write).await });

            Some(handle_result.map_err(|e| {
                error!("Failed to open file: {}", e);
                STATUS_ACCESS_DENIED
            })?)
        } else {
            None
        };

        *file_info.as_mut() = Self::attr_to_file_info(&attr);

        Ok(EncryptedFsFileContext {
            ino,
            fh,
            is_directory,
            dir_buffer: DirBuffer::new(),
        })
    }

    fn close(&self, context: Self::FileContext) {
        debug!("close: ino={}", context.ino);

        if let Some(fh) = context.fh {
            let _ = self.runtime.block_on(async { self.fs.release(fh).await });
        }
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        trace!(
            "read: ino={}, offset={}, len={}",
            context.ino,
            offset,
            buffer.len()
        );

        let fh = context.fh.ok_or(STATUS_ACCESS_DENIED)?;

        let result = self
            .runtime
            .block_on(async { self.fs.read(context.ino, offset, buffer, fh).await });

        match result {
            Ok(bytes_read) => Ok(bytes_read as u32),
            Err(e) => {
                error!("Read error: {}", e);
                Err(STATUS_END_OF_FILE.into())
            }
        }
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        trace!(
            "write: ino={}, offset={}, len={}",
            context.ino,
            offset,
            buffer.len()
        );

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let fh = context.fh.ok_or(STATUS_ACCESS_DENIED)?;

        let result = self
            .runtime
            .block_on(async { self.fs.write(context.ino, offset, buffer, fh).await });

        match result {
            Ok(bytes_written) => {
                self.refresh_file_info(context.ino, file_info);
                Ok(bytes_written as u32)
            }
            Err(e) => {
                error!("Write error: {}", e);
                Err(STATUS_ACCESS_DENIED.into())
            }
        }
    }

    fn flush(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> winfsp::Result<()> {
        trace!("flush: ino={}", context.ino);

        if let Some(fh) = context.fh {
            if let Err(e) = self.runtime.block_on(async { self.fs.flush(fh).await }) {
                error!("Flush error: {}", e);
            }
        }

        self.refresh_file_info(context.ino, file_info);
        Ok(())
    }

    fn get_file_info(&self, context: &Self::FileContext) -> winfsp::Result<FileInfo> {
        trace!("get_file_info: ino={}", context.ino);

        let result = self
            .runtime
            .block_on(async { self.fs.get_attr(context.ino).await });

        match result {
            Ok(attr) => Ok(Self::attr_to_file_info(&attr)),
            Err(_) => Err(STATUS_OBJECT_NAME_NOT_FOUND.into()),
        }
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        trace!("set_basic_info: ino={}", context.ino);

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let mut set_attr = crate::encryptedfs::SetFileAttr::default();

        if creation_time != 0 {
            set_attr = set_attr.with_crtime(filetime_to_system_time(creation_time));
        }
        if last_access_time != 0 {
            set_attr = set_attr.with_atime(filetime_to_system_time(last_access_time));
        }
        if last_write_time != 0 {
            set_attr = set_attr.with_mtime(filetime_to_system_time(last_write_time));
        }

        if let Err(e) = self
            .runtime
            .block_on(async { self.fs.set_attr(context.ino, set_attr).await })
        {
            error!("set_basic_info error: {}", e);
        }

        self.refresh_file_info(context.ino, file_info);
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        trace!("set_file_size: ino={}, new_size={}", context.ino, new_size);

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let result = self
            .runtime
            .block_on(async { self.fs.set_len(context.ino, new_size).await });

        if let Err(e) = result {
            error!("set_file_size error: {}", e);
            return Err(STATUS_ACCESS_DENIED.into());
        }

        self.refresh_file_info(context.ino, file_info);
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        trace!("read_directory: ino={}", context.ino);

        if !context.is_directory {
            return Err(STATUS_NOT_A_DIRECTORY.into());
        }

        if context.dir_buffer.is_empty() {
            let result = self
                .runtime
                .block_on(async { self.fs.read_dir_plus(context.ino).await });

            let entries = match result {
                Ok(iter) => iter,
                Err(e) => {
                    error!("read_directory error: {}", e);
                    return Err(STATUS_ACCESS_DENIED.into());
                }
            };

            for entry in entries {
                if let Ok(entry) = entry {
                    let name = entry.name.expose_secret();
                    if let Ok(name_u16) = U16CString::from_str(name) {
                        let mut dir_info = DirInfo::new();
                        dir_info.set_file_name(&name_u16);

                        let fi = dir_info.file_info_mut();
                        fi.file_attributes = if entry.kind == FileType::Directory {
                            FILE_ATTRIBUTE_DIRECTORY.0
                        } else {
                            FILE_ATTRIBUTE_NORMAL.0
                        };
                        fi.file_size = entry.attr.size;
                        fi.allocation_size = entry.attr.blocks * entry.attr.blksize as u64;
                        fi.creation_time = system_time_to_filetime(entry.attr.crtime);
                        fi.last_access_time = system_time_to_filetime(entry.attr.atime);
                        fi.last_write_time = system_time_to_filetime(entry.attr.mtime);
                        fi.change_time = system_time_to_filetime(entry.attr.ctime);
                        fi.index_number = entry.ino;
                    }
                }
            }
        }

        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        debug!(
            "create: {:?}, attributes={}",
            file_name.to_string(),
            file_attributes
        );

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let (parent_ino, name) = self.path_to_parent_and_name(file_name)?;
        let secret_name =
            SecretString::from_str(&name).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;

        let attr = if is_directory {
            CreateFileAttr {
                kind: FileType::Directory,
                perm: 0o755,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
            }
        } else {
            CreateFileAttr {
                kind: FileType::RegularFile,
                perm: 0o644,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
            }
        };

        let result = self.runtime.block_on(async {
            self.fs
                .create(parent_ino, &secret_name, attr, true, true)
                .await
        });

        match result {
            Ok((fh, created_attr)) => {
                *file_info.as_mut() = Self::attr_to_file_info(&created_attr);

                Ok(EncryptedFsFileContext {
                    ino: created_attr.ino,
                    fh: if is_directory { None } else { Some(fh) },
                    is_directory,
                    dir_buffer: DirBuffer::new(),
                })
            }
            Err(FsError::AlreadyExists) => Err(STATUS_OBJECT_NAME_COLLISION.into()),
            Err(e) => {
                error!("create error: {}", e);
                Err(STATUS_ACCESS_DENIED.into())
            }
        }
    }

    fn cleanup(&self, context: &mut Self::FileContext, _file_name: Option<&U16CStr>, _flags: u32) {
        trace!("cleanup: ino={}", context.ino);

        if let Some(fh) = context.fh {
            let _ = self.runtime.block_on(async { self.fs.flush(fh).await });
        }
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _ea: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        trace!("overwrite: ino={}", context.ino);

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let result = self
            .runtime
            .block_on(async { self.fs.set_len(context.ino, 0).await });

        if let Err(e) = result {
            error!("overwrite error: {}", e);
            return Err(STATUS_ACCESS_DENIED.into());
        }

        self.refresh_file_info(context.ino, file_info);
        Ok(())
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        debug!(
            "rename: {:?} -> {:?}",
            file_name.to_string(),
            new_file_name.to_string()
        );

        if self.read_only {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        let (old_parent_ino, old_name) = self.path_to_parent_and_name(file_name)?;
        let (new_parent_ino, new_name) = self.path_to_parent_and_name(new_file_name)?;

        let old_secret_name =
            SecretString::from_str(&old_name).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        let new_secret_name =
            SecretString::from_str(&new_name).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;

        let result = self.runtime.block_on(async {
            self.fs
                .rename(
                    old_parent_ino,
                    &old_secret_name,
                    new_parent_ino,
                    &new_secret_name,
                )
                .await
        });

        match result {
            Ok(()) => Ok(()),
            Err(FsError::NotEmpty) => Err(STATUS_DIRECTORY_NOT_EMPTY.into()),
            Err(e) => {
                error!("rename error: {}", e);
                Err(STATUS_ACCESS_DENIED.into())
            }
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    #[allow(dead_code)]
    allow_root: bool,
    #[allow(dead_code)]
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

    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        info!("Mounting rencfs on Windows at {:?}", self.mountpoint);

        winfsp::winfsp_init_or_die();

        let fs = EncryptedFs::new(
            self.data_dir.clone(),
            self.password_provider.take().unwrap(),
            self.cipher,
            self.read_only,
        )
        .await?;

        let winfsp_fs = EncryptedFsWinFsp::new(Arc::new(fs), self.read_only);

        let mut host = FileSystemHost::new(winfsp_fs)
            .map_err(|_| FsError::Other("Failed to create FileSystemHost"))?;

        let mount_point_str = self
            .mountpoint
            .to_str()
            .ok_or_else(|| FsError::Other("Invalid mount point path"))?;

        host.mount(mount_point_str)
            .map_err(|_| FsError::Other("Failed to mount filesystem"))?;

        host.start()
            .map_err(|_| FsError::Other("Failed to start filesystem service"))?;

        info!(
            "rencfs mounted successfully on Windows at {}",
            mount_point_str
        );

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                host: Some(host),
                mountpoint: self.mountpoint.clone(),
            },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    host: Option<FileSystemHost<EncryptedFsWinFsp>>,
    mountpoint: PathBuf,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        info!("Unmounting rencfs from {:?}", self.mountpoint);

        if let Some(host) = self.host.take() {
            drop(host);
        }

        Ok(())
    }
}

pub fn umount(mountpoint: &str) -> io::Result<()> {
    info!("Windows unmount requested for {}", mountpoint);
    Ok(())
}
