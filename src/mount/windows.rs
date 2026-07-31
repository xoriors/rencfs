use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tracing::{error, info};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_QUERY,
        TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
use winfsp_wrs::{
    u16cstr, u16str, CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights,
    FileAttributes, FileInfo, FileSystem, FileSystemInterface, PSecurityDescriptor, Params,
    SecurityDescriptor, U16CStr, U16CString, VolumeInfo, VolumeParams, WriteMode, NTSTATUS,
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_END_OF_FILE,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_UNEXPECTED_IO_ERROR,
};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    SetFileAttr, ROOT_INODE,
};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

const ALLOCATION_UNIT: u64 = 4096;
const VOLUME_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[derive(Debug)]
struct WindowsFileContext {
    ino: u64,
    handle: Mutex<Option<u64>>,
    directory_entries: Mutex<Option<Vec<(String, FileInfo)>>>,
    is_dir: bool,
    read: bool,
    write: bool,
}

struct WindowsFs {
    fs: Arc<EncryptedFs>,
    runtime: Runtime,
    security_descriptor: SecurityDescriptor,
    volume_info: VolumeInfo,
    read_only: bool,
}

impl WindowsFs {
    fn new(fs: Arc<EncryptedFs>, read_only: bool) -> FsResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(FsError::from)?;
        let security_descriptor = default_security_descriptor()?;
        let volume_info = VolumeInfo::new(VOLUME_SIZE, VOLUME_SIZE, u16str!("rencfs"))
            .map_err(|_| FsError::Other("cannot create Windows volume info"))?;

        Ok(Self {
            fs,
            runtime,
            security_descriptor,
            volume_info,
            read_only,
        })
    }

    fn block_on<T>(&self, future: impl Future<Output = FsResult<T>>) -> Result<T, NTSTATUS> {
        self.runtime.block_on(future).map_err(fs_error_to_status)
    }

    fn resolve_path(&self, file_name: &U16CStr) -> Result<FileAttr, NTSTATUS> {
        let components = path_components(file_name);
        self.block_on(async {
            let mut attr = self.fs.get_attr(ROOT_INODE).await?;
            for component in components {
                if attr.kind != FileType::Directory {
                    return Err(FsError::InvalidInodeType);
                }
                attr = self
                    .fs
                    .find_by_name(attr.ino, &secret(&component))
                    .await?
                    .ok_or(FsError::NotFound("path component not found"))?;
            }
            Ok(attr)
        })
    }

    fn resolve_parent(&self, file_name: &U16CStr) -> Result<(u64, SecretString), NTSTATUS> {
        let mut components = path_components(file_name);
        let name = components
            .pop()
            .ok_or(STATUS_INVALID_PARAMETER)
            .map(|name| secret(&name))?;

        self.block_on(async {
            let mut attr = self.fs.get_attr(ROOT_INODE).await?;
            for component in components {
                attr = self
                    .fs
                    .find_by_name(attr.ino, &secret(&component))
                    .await?
                    .ok_or(FsError::NotFound("parent path component not found"))?;
                if attr.kind != FileType::Directory {
                    return Err(FsError::InvalidInodeType);
                }
            }
            Ok((attr.ino, name))
        })
    }

    fn open_context(
        &self,
        attr: FileAttr,
        granted_access: FileAccessRights,
    ) -> Result<Arc<WindowsFileContext>, NTSTATUS> {
        if attr.kind == FileType::Directory {
            return Ok(Arc::new(WindowsFileContext {
                ino: attr.ino,
                handle: Mutex::new(None),
                directory_entries: Mutex::new(None),
                is_dir: true,
                read: false,
                write: false,
            }));
        }

        let (read, write) = access_modes(granted_access);
        let handle = self.block_on(self.fs.open(attr.ino, read, write))?;
        Ok(Arc::new(WindowsFileContext {
            ino: attr.ino,
            handle: Mutex::new(Some(handle)),
            directory_entries: Mutex::new(None),
            is_dir: false,
            read,
            write,
        }))
    }

    fn context_handle(context: &WindowsFileContext) -> Result<u64, NTSTATUS> {
        context
            .handle
            .lock()
            .map_err(|_| STATUS_INVALID_HANDLE)?
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn delete_by_name(
        &self,
        context: &WindowsFileContext,
        file_name: &U16CStr,
    ) -> Result<(), NTSTATUS> {
        self.release_context(context)?;
        let (parent, name) = self.resolve_parent(file_name)?;
        if context.is_dir {
            self.block_on(self.fs.remove_dir(parent, &name))
        } else {
            self.block_on(self.fs.remove_file(parent, &name))
        }
    }

    fn release_context(&self, context: &WindowsFileContext) -> Result<(), NTSTATUS> {
        let mut handle = context.handle.lock().map_err(|_| STATUS_INVALID_HANDLE)?;
        if let Some(handle) = handle.take() {
            self.block_on(self.fs.release(handle))?;
        }
        Ok(())
    }

    fn resize_context(&self, context: &WindowsFileContext, new_size: u64) -> Result<(), NTSTATUS> {
        self.release_context(context)?;
        self.block_on(self.fs.set_len(context.ino, new_size))?;
        let handle = self.block_on(self.fs.open(context.ino, context.read, context.write))?;
        context
            .handle
            .lock()
            .map_err(|_| STATUS_INVALID_HANDLE)?
            .replace(handle);
        Ok(())
    }
}

impl FileSystemInterface for WindowsFs {
    type FileContext = Arc<WindowsFileContext>;

    const GET_VOLUME_INFO_DEFINED: bool = true;
    fn get_volume_info(&self) -> Result<VolumeInfo, NTSTATUS> {
        Ok(self.volume_info.clone())
    }

    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, PSecurityDescriptor, bool), NTSTATUS> {
        let attr = self.resolve_path(file_name)?;
        Ok((
            file_attributes(attr.kind),
            self.security_descriptor.as_ptr(),
            false,
        ))
    }

    const CREATE_DEFINED: bool = true;
    fn create(
        &self,
        file_name: &U16CStr,
        create_file_info: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let (parent, name) = self.resolve_parent(file_name)?;
        let is_dir = create_file_info
            .create_options
            .is(CreateOptions::FILE_DIRECTORY_FILE);
        let kind = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let (read, write) = if is_dir {
            (false, false)
        } else {
            access_modes(create_file_info.granted_access)
        };
        let create_attr = CreateFileAttr {
            kind,
            perm: if is_dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };

        let (handle, attr) =
            self.block_on(self.fs.create(parent, &name, create_attr, read, write))?;
        let context = Arc::new(WindowsFileContext {
            ino: attr.ino,
            handle: Mutex::new((handle != 0).then_some(handle)),
            directory_entries: Mutex::new(None),
            is_dir,
            read,
            write,
        });
        Ok((context, attr_to_file_info(attr)))
    }

    const OPEN_DEFINED: bool = true;
    fn open(
        &self,
        file_name: &U16CStr,
        create_options: CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), NTSTATUS> {
        let attr = self.resolve_path(file_name)?;
        if create_options.is(CreateOptions::FILE_DIRECTORY_FILE) && attr.kind != FileType::Directory
        {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if create_options.is(CreateOptions::FILE_NON_DIRECTORY_FILE)
            && attr.kind == FileType::Directory
        {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let context = self.open_context(attr, granted_access)?;
        Ok((context, attr_to_file_info(attr)))
    }

    const OVERWRITE_DEFINED: bool = true;
    fn overwrite(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        _replace_file_attributes: bool,
        _allocation_size: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if file_context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        self.resize_context(&file_context, 0)?;
        self.block_on(self.fs.get_attr(file_context.ino))
            .map(attr_to_file_info)
    }

    const CLEANUP_DEFINED: bool = true;
    fn cleanup(
        &self,
        file_context: Self::FileContext,
        file_name: Option<&U16CStr>,
        flags: CleanupFlags,
    ) {
        if self.read_only || !flags.is(CleanupFlags::DELETE) {
            return;
        }
        if let Some(file_name) = file_name {
            if let Err(status) = self.delete_by_name(&file_context, file_name) {
                error!(status, "WinFSP cleanup delete failed");
            }
        }
    }

    const CLOSE_DEFINED: bool = true;
    fn close(&self, file_context: Self::FileContext) {
        if let Err(status) = self.release_context(&file_context) {
            error!(status, "WinFSP release failed");
        }
    }

    const READ_DEFINED: bool = true;
    fn read(
        &self,
        file_context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, NTSTATUS> {
        if file_context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let attr = self.block_on(self.fs.get_attr(file_context.ino))?;
        if offset >= attr.size {
            return Err(STATUS_END_OF_FILE);
        }
        let handle = Self::context_handle(&file_context)?;
        self.block_on(self.fs.read(file_context.ino, offset, buffer, handle))
    }

    const WRITE_DEFINED: bool = true;
    fn write(
        &self,
        file_context: Self::FileContext,
        buffer: &[u8],
        mode: WriteMode,
    ) -> Result<(usize, FileInfo), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if file_context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let handle = Self::context_handle(&file_context)?;
        let attr = self.block_on(self.fs.get_attr(file_context.ino))?;
        let (offset, write_buffer) = match mode {
            WriteMode::Normal { offset } => (offset, buffer),
            WriteMode::WriteToEOF => (attr.size, buffer),
            WriteMode::ConstrainedIO { offset } => {
                if offset >= attr.size {
                    return Ok((0, attr_to_file_info(attr)));
                }
                let allowed = usize::try_from((attr.size - offset).min(buffer.len() as u64))
                    .map_err(|_| STATUS_INVALID_PARAMETER)?;
                (offset, &buffer[..allowed])
            }
        };
        let written =
            self.block_on(
                self.fs
                    .write(file_context.ino, offset, write_buffer, handle),
            )?;
        let attr = self.block_on(self.fs.get_attr(file_context.ino))?;
        Ok((written, attr_to_file_info(attr)))
    }

    const FLUSH_DEFINED: bool = true;
    fn flush(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        if !self.read_only && !file_context.is_dir {
            let handle = Self::context_handle(&file_context)?;
            self.block_on(self.fs.flush(handle))?;
        }
        self.block_on(self.fs.get_attr(file_context.ino))
            .map(attr_to_file_info)
    }

    const GET_FILE_INFO_DEFINED: bool = true;
    fn get_file_info(&self, file_context: Self::FileContext) -> Result<FileInfo, NTSTATUS> {
        self.block_on(self.fs.get_attr(file_context.ino))
            .map(attr_to_file_info)
    }

    const SET_BASIC_INFO_DEFINED: bool = true;
    fn set_basic_info(
        &self,
        file_context: Self::FileContext,
        _file_attributes: FileAttributes,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
    ) -> Result<FileInfo, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let mut update = SetFileAttr::default();
        if creation_time != 0 {
            update.crtime = Some(system_time_from_filetime(creation_time));
        }
        if last_access_time != 0 {
            update.atime = Some(system_time_from_filetime(last_access_time));
        }
        if last_write_time != 0 {
            update.mtime = Some(system_time_from_filetime(last_write_time));
        }
        if change_time != 0 {
            update.ctime = Some(system_time_from_filetime(change_time));
        }
        self.block_on(self.fs.set_attr(file_context.ino, update))?;
        self.block_on(self.fs.get_attr(file_context.ino))
            .map(attr_to_file_info)
    }

    const SET_FILE_SIZE_DEFINED: bool = true;
    fn set_file_size(
        &self,
        file_context: Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
    ) -> Result<FileInfo, NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if file_context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let current = self.block_on(self.fs.get_attr(file_context.ino))?;
        if !set_allocation_size || new_size < current.size {
            self.resize_context(&file_context, new_size)?;
        }
        self.block_on(self.fs.get_attr(file_context.ino))
            .map(attr_to_file_info)
    }

    const SET_DELETE_DEFINED: bool = true;
    fn set_delete(
        &self,
        file_context: Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        if delete_file && file_context.is_dir {
            let len = self.fs.len(file_context.ino).map_err(fs_error_to_status)?;
            if len > 0 {
                return Err(STATUS_DIRECTORY_NOT_EMPTY);
            }
        }
        Ok(())
    }

    const RENAME_DEFINED: bool = true;
    fn rename(
        &self,
        _file_context: Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<(), NTSTATUS> {
        if self.read_only {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let (parent, name) = self.resolve_parent(file_name)?;
        let (new_parent, new_name) = self.resolve_parent(new_file_name)?;
        if parent == new_parent && name.expose_secret() == new_name.expose_secret() {
            return Ok(());
        }
        self.block_on(self.fs.rename_with_options(
            parent,
            &name,
            new_parent,
            &new_name,
            replace_if_exists,
        ))
    }

    const GET_SECURITY_DEFINED: bool = true;
    fn get_security(
        &self,
        _file_context: Self::FileContext,
    ) -> Result<PSecurityDescriptor, NTSTATUS> {
        Ok(self.security_descriptor.as_ptr())
    }

    const READ_DIRECTORY_DEFINED: bool = true;
    fn read_directory(
        &self,
        file_context: Self::FileContext,
        marker: Option<&U16CStr>,
        mut add_dir_info: impl FnMut(DirInfo) -> bool,
    ) -> Result<(), NTSTATUS> {
        if !file_context.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let marker = marker.map(U16CStr::to_string_lossy);
        let mut cached_entries = file_context
            .directory_entries
            .lock()
            .map_err(|_| STATUS_INVALID_HANDLE)?;
        if marker.is_none() || cached_entries.is_none() {
            let iter = self.block_on(self.fs.read_dir_plus(file_context.ino))?;
            let mut entries = Vec::new();
            for entry in iter {
                let entry = entry.map_err(fs_error_to_status)?;
                entries.push((
                    entry.name.expose_secret().to_string(),
                    attr_to_file_info(entry.attr),
                ));
            }
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            *cached_entries = Some(entries);
        }
        let entries = cached_entries.as_ref().unwrap();
        let mut exhausted = true;
        for (name, info) in entries {
            if marker
                .as_deref()
                .is_some_and(|marker| name.as_str() <= marker)
            {
                continue;
            }
            // DirInfo reserves one UTF-16 unit for the trailing NUL.
            if name.encode_utf16().count() >= 255 {
                continue;
            }
            if !add_dir_info(DirInfo::from_str(*info, name)) {
                exhausted = false;
                break;
            }
        }
        if exhausted {
            cached_entries.take();
        }
        Ok(())
    }
}

fn default_security_descriptor() -> FsResult<SecurityDescriptor> {
    let user_sid = current_user_sid()?;
    let descriptor =
        format!("O:{user_sid}G:{user_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})");
    let descriptor = U16CString::from_str(&descriptor)
        .map_err(|_| FsError::Other("invalid Windows security descriptor"))?;
    SecurityDescriptor::from_wstr(&descriptor)
        .map_err(|_| FsError::Other("cannot create Windows security descriptor"))
}

fn current_user_sid() -> FsResult<String> {
    unsafe {
        let mut token = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let _token = OwnedHandle(token);

        let mut required = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        if required == 0 {
            return Err(FsError::Other("cannot determine Windows token user size"));
        }

        let word_size = std::mem::size_of::<usize>() as u32;
        let mut token_info = vec![0_usize; required.div_ceil(word_size) as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            token_info.as_mut_ptr().cast(),
            required,
            &mut required,
        ) == 0
        {
            return Err(io::Error::last_os_error().into());
        }

        let token_user = &*token_info.as_ptr().cast::<TOKEN_USER>();
        let mut sid_string = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string) == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let _sid_string = LocalAllocation(sid_string.cast());
        let len = (0..)
            .take_while(|offset| *sid_string.add(*offset) != 0)
            .count();
        String::from_utf16(std::slice::from_raw_parts(sid_string, len))
            .map_err(|_| FsError::Other("Windows user SID is not valid UTF-16"))
    }
}

fn path_components(file_name: &U16CStr) -> Vec<String> {
    file_name
        .to_string_lossy()
        .split(['\\', '/'])
        .filter(|component| !component.is_empty() && *component != ".")
        .map(ToOwned::to_owned)
        .collect()
}

fn secret(value: &str) -> SecretString {
    SecretString::new(Box::new(value.to_owned()))
}

fn access_modes(granted_access: FileAccessRights) -> (bool, bool) {
    let read = granted_access.0
        & (FileAccessRights::FILE_READ_DATA.0 | FileAccessRights::FILE_GENERIC_READ.0)
        != 0;
    let write = granted_access.0
        & (FileAccessRights::FILE_WRITE_DATA.0
            | FileAccessRights::FILE_APPEND_DATA.0
            | FileAccessRights::FILE_GENERIC_WRITE.0)
        != 0;
    if read || write {
        (read, write)
    } else {
        // Attribute-only opens still need a backing rencfs handle if a later
        // cached read is issued for the same Windows file object.
        (true, false)
    }
}

fn file_attributes(kind: FileType) -> FileAttributes {
    match kind {
        FileType::Directory => FileAttributes::DIRECTORY,
        FileType::RegularFile => FileAttributes::ARCHIVE,
    }
}

fn attr_to_file_info(attr: FileAttr) -> FileInfo {
    let mut info = FileInfo::default();
    info.set_file_attributes(file_attributes(attr.kind))
        .set_allocation_size(attr.size.div_ceil(ALLOCATION_UNIT) * ALLOCATION_UNIT)
        .set_file_size(attr.size)
        .set_creation_time(filetime_from_system_time(attr.crtime))
        .set_last_access_time(filetime_from_system_time(attr.atime))
        .set_last_write_time(filetime_from_system_time(attr.mtime))
        .set_change_time(filetime_from_system_time(attr.ctime))
        .set_index_number(attr.ino)
        .set_hard_links(attr.nlink);
    info
}

fn filetime_from_system_time(time: SystemTime) -> u64 {
    const WINDOWS_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    WINDOWS_EPOCH_OFFSET
        + duration.as_secs() * 10_000_000
        + u64::from(duration.subsec_nanos()) / 100
}

fn system_time_from_filetime(filetime: u64) -> SystemTime {
    const WINDOWS_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;
    if filetime <= WINDOWS_EPOCH_OFFSET {
        return UNIX_EPOCH;
    }
    let ticks = filetime - WINDOWS_EPOCH_OFFSET;
    UNIX_EPOCH + Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32)
}

fn fs_error_to_status(error: FsError) -> NTSTATUS {
    match error {
        FsError::NotFound(_) | FsError::InodeNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::InvalidInodeType => STATUS_NOT_A_DIRECTORY,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::InvalidInput(_) => STATUS_INVALID_PARAMETER,
        FsError::MaxFilesizeExceeded(_) => STATUS_DISK_FULL,
        FsError::AlreadyOpenForWrite => STATUS_ACCESS_DENIED,
        FsError::InvalidDataDirStructure => STATUS_OBJECT_PATH_NOT_FOUND,
        _ => STATUS_UNEXPECTED_IO_ERROR,
    }
}

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    read_only: bool,
}

#[async_trait]
impl MountPoint for MountPointImpl {
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        _allow_root: bool,
        _allow_other: bool,
        read_only: bool,
    ) -> Self {
        Self {
            mountpoint,
            data_dir,
            password_provider: Some(password_provider),
            cipher,
            read_only,
        }
    }

    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        winfsp_wrs::init().map_err(|err| {
            error!(err = %err, "cannot initialize WinFSP");
            FsError::Other("cannot initialize WinFSP")
        })?;
        let encrypted_fs = EncryptedFs::new(
            self.data_dir,
            self.password_provider.take().unwrap(),
            self.cipher,
            self.read_only,
        )
        .await?;
        let context = WindowsFs::new(encrypted_fs, self.read_only)?;
        let mountpoint = U16CString::from_os_str(self.mountpoint.as_os_str())
            .map_err(|_| FsError::InvalidInput("invalid Windows mount point"))?;

        let mut volume_params = VolumeParams::default();
        volume_params
            .set_sector_size(512)
            .set_sectors_per_allocation_unit((ALLOCATION_UNIT / 512) as u16)
            .set_volume_creation_time(filetime_from_system_time(SystemTime::now()))
            .set_volume_serial_number(0x5245_4E43)
            .set_file_info_timeout(1000)
            .set_case_sensitive_search(true)
            .set_case_preserved_names(true)
            .set_unicode_on_disk(true)
            .set_post_cleanup_when_modified_only(true)
            .set_read_only_volume(self.read_only);
        volume_params
            .set_file_system_name(u16cstr!("rencfs"))
            .map_err(|_| FsError::Other("invalid filesystem name"))?;
        volume_params
            .set_prefix(u16cstr!(""))
            .map_err(|_| FsError::Other("invalid filesystem prefix"))?;

        info!(mountpoint = %mountpoint.to_string_lossy(), "mounting WinFSP filesystem");
        let filesystem = FileSystem::start(
            Params {
                volume_params,
                ..Default::default()
            },
            Some(&mountpoint),
            context,
        )
        .map_err(|status| {
            error!(status, "cannot start WinFSP filesystem");
            FsError::Other("cannot start WinFSP filesystem")
        })?;

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                filesystem: Some(filesystem),
            },
        })
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {
    filesystem: Option<FileSystem>,
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
        if let Some(filesystem) = self.filesystem.take() {
            filesystem.stop();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::tempdir;

    struct TestPasswordProvider;

    impl PasswordProvider for TestPasswordProvider {
        fn get_password(&self) -> Option<SecretString> {
            Some(SecretString::from_str("winfsp-adapter-test").unwrap())
        }
    }

    fn test_security_descriptor() -> SecurityDescriptor {
        default_security_descriptor().unwrap()
    }

    fn file_create_info() -> CreateFileInfo {
        CreateFileInfo {
            create_options: CreateOptions::FILE_NON_DIRECTORY_FILE,
            granted_access: FileAccessRights::FILE_GENERIC_READ
                | FileAccessRights::FILE_GENERIC_WRITE,
            file_attributes: FileAttributes::ARCHIVE,
            // This is a reservation hint, not the logical file length.
            allocation_size: 64 * 1024,
        }
    }

    fn dir_info_name(info: &DirInfo) -> String {
        let len = info
            .file_name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(info.file_name.len());
        String::from_utf16_lossy(&info.file_name[..len])
    }

    #[test]
    fn path_components_handle_windows_and_root_paths() {
        let nested = U16CString::from_str(r"\alpha\beta").unwrap();
        assert_eq!(path_components(&nested), ["alpha", "beta"]);

        let root = U16CString::from_str(r"\").unwrap();
        assert!(path_components(&root).is_empty());
    }

    #[test]
    fn filetime_round_trip_is_stable_to_one_hundred_nanoseconds() {
        let original = UNIX_EPOCH + Duration::new(1_234_567, 890_123_400);
        let round_trip = system_time_from_filetime(filetime_from_system_time(original));
        assert_eq!(original, round_trip);
    }

    #[test]
    fn adapter_supports_basic_file_lifecycle_without_mounting_driver() {
        let data_dir = tempdir().unwrap();
        let setup_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let encrypted_fs = setup_runtime
            .block_on(EncryptedFs::new(
                data_dir.path().to_path_buf(),
                Box::new(TestPasswordProvider),
                Cipher::ChaCha20Poly1305,
                false,
            ))
            .unwrap();

        let adapter = WindowsFs::new(encrypted_fs.clone(), false).unwrap();
        let original_name = U16CString::from_str(r"\hello.txt").unwrap();
        let renamed_name = U16CString::from_str(r"\renamed.txt").unwrap();
        let replacement_name = U16CString::from_str(r"\replacement.txt").unwrap();
        let root_name = U16CString::from_str(r"\").unwrap();

        let (write_context, created) = adapter
            .create(
                &original_name,
                file_create_info(),
                test_security_descriptor(),
            )
            .unwrap();
        assert_eq!(created.file_size(), 0);

        let initial_payload = b"hello before truncate";
        let (written, written_info) = adapter
            .write(
                write_context.clone(),
                initial_payload,
                WriteMode::Normal { offset: 0 },
            )
            .unwrap();
        assert_eq!(written, initial_payload.len());
        assert_eq!(written_info.file_size(), initial_payload.len() as u64);
        let truncated = adapter
            .set_file_size(write_context.clone(), 5, false)
            .unwrap();
        assert_eq!(truncated.file_size(), 5);
        let suffix = b" from WinFSP";
        adapter
            .write(write_context.clone(), suffix, WriteMode::WriteToEOF)
            .unwrap();
        adapter.flush(write_context.clone()).unwrap();
        adapter.close(write_context);

        let payload = b"hello from WinFSP";
        let (read_context, _) = adapter
            .open(
                &original_name,
                CreateOptions::FILE_NON_DIRECTORY_FILE,
                FileAccessRights::FILE_GENERIC_READ,
            )
            .unwrap();
        let mut read_buffer = vec![0; payload.len()];
        let read = adapter
            .read(read_context.clone(), &mut read_buffer, 0)
            .unwrap();
        assert_eq!(read, payload.len());
        assert_eq!(read_buffer, payload);

        adapter
            .rename(read_context.clone(), &original_name, &renamed_name, false)
            .unwrap();
        assert!(adapter.resolve_path(&original_name).is_err());
        assert_eq!(
            adapter.resolve_path(&renamed_name).unwrap().size,
            payload.len() as u64
        );
        adapter.close(read_context);

        let (root_context, _) = adapter
            .open(
                &root_name,
                CreateOptions::FILE_DIRECTORY_FILE,
                FileAccessRights::FILE_LIST_DIRECTORY,
            )
            .unwrap();
        let mut names = Vec::new();
        adapter
            .read_directory(root_context.clone(), None, |entry| {
                names.push(dir_info_name(&entry));
                true
            })
            .unwrap();
        assert!(names.iter().any(|name| name == "renamed.txt"));
        adapter.close(root_context);

        let (replacement_context, _) = adapter
            .create(
                &replacement_name,
                file_create_info(),
                test_security_descriptor(),
            )
            .unwrap();
        adapter.close(replacement_context);
        let replaced_ino = adapter.resolve_path(&replacement_name).unwrap().ino;
        let (rename_context, _) = adapter
            .open(
                &renamed_name,
                CreateOptions::FILE_NON_DIRECTORY_FILE,
                FileAccessRights::FILE_GENERIC_READ | FileAccessRights::DELETE,
            )
            .unwrap();
        assert_eq!(
            adapter.rename(
                rename_context.clone(),
                &renamed_name,
                &replacement_name,
                false,
            ),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert!(adapter.resolve_path(&renamed_name).is_ok());
        assert_eq!(adapter.resolve_path(&replacement_name).unwrap().size, 0);
        adapter
            .rename(
                rename_context.clone(),
                &renamed_name,
                &replacement_name,
                true,
            )
            .unwrap();
        adapter.close(rename_context);
        assert!(adapter.resolve_path(&renamed_name).is_err());
        assert_eq!(
            adapter.resolve_path(&replacement_name).unwrap().size,
            payload.len() as u64
        );
        assert!(!encrypted_fs.exists(replaced_ino));
        assert!(!encrypted_fs.is_file(replaced_ino));

        let (delete_context, _) = adapter
            .open(
                &replacement_name,
                CreateOptions::FILE_NON_DIRECTORY_FILE,
                FileAccessRights::FILE_GENERIC_READ | FileAccessRights::DELETE,
            )
            .unwrap();
        adapter
            .set_delete(delete_context.clone(), &replacement_name, true)
            .unwrap();
        adapter.cleanup(
            delete_context.clone(),
            Some(&replacement_name),
            CleanupFlags::DELETE,
        );
        adapter.close(delete_context);
        assert!(adapter.resolve_path(&replacement_name).is_err());
    }
}
