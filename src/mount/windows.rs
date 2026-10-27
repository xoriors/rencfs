//! Native WinFsp adapter. All encryption and persistence remain in `EncryptedFs`.
//!
//! WinFsp dispatches synchronous callbacks on its own threads. Those callbacks
//! enter the application's existing Tokio runtime; no callback creates a runtime.
//! A worker owns the host and always stops it before reporting unmount completion.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tokio::runtime::Handle;
use tokio::sync::oneshot;
use tracing::error;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use winfsp_wrs::{
    CleanupFlags, CreateFileInfo, CreateOptions, DirInfo, FileAccessRights, FileAttributes,
    FileContextKind, FileContextMode, FileInfo, FileSystem, FileSystemInterface,
    OperationGuardStrategy, PSecurityDescriptor, Params, SecurityDescriptor, U16CStr, U16CString,
    VolumeInfo, WriteMode, STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_MEDIA_WRITE_PROTECTED, STATUS_NAME_TOO_LONG, STATUS_NOT_A_DIRECTORY,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SHARING_VIOLATION,
    STATUS_UNSUCCESSFUL,
};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    SetFileAttr, ROOT_INODE,
};
use crate::mount::{self, MountHandleInner, MountPoint};

type NtResult<T> = Result<T, i32>;
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const SECTOR_SIZE: u64 = 4096;

fn status(error: FsError) -> i32 {
    match error {
        FsError::NotFound(_) | FsError::InodeNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::InvalidInput(_) | FsError::MaxFilesizeExceeded(_) => STATUS_INVALID_PARAMETER,
        FsError::InvalidInodeType => STATUS_INVALID_PARAMETER,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::Io { source, .. } => match source.kind() {
            io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
            io::ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
            io::ErrorKind::InvalidInput => STATUS_INVALID_PARAMETER,
            _ => STATUS_UNSUCCESSFUL,
        },
        other => {
            error!(error = %other, "encrypted filesystem operation failed");
            STATUS_UNSUCCESSFUL
        }
    }
}

fn secret(value: &str) -> SecretString {
    SecretString::from_str(value).expect("SecretString accepts valid Rust strings")
}

/// Accept only rooted, normalized WinFsp names, never host filesystem paths.
fn components(name: &U16CStr) -> NtResult<Vec<String>> {
    let name = name.to_string().map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
    if !name.starts_with('\\') || name.contains('/') {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    if name == "\\" {
        return Ok(Vec::new());
    }
    let parts: Vec<_> = name[1..].split('\\').map(str::to_owned).collect();
    for part in &parts {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.chars().any(|c| c < ' ' || "<>:\"/\\|?*".contains(c))
        {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if part.encode_utf16().count() > 255 {
            return Err(STATUS_NAME_TOO_LONG);
        }
    }
    Ok(parts)
}

fn to_filetime(time: SystemTime) -> u64 {
    let ticks = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::from(duration.as_secs()) * 10_000_000 + i128::from(duration.subsec_nanos() / 100)
        }
        Err(error) => {
            -(i128::from(error.duration().as_secs()) * 10_000_000
                + i128::from(error.duration().subsec_nanos() / 100))
        }
    };
    (i128::from(FILETIME_UNIX_EPOCH) + ticks).clamp(0, i128::from(u64::MAX)) as u64
}

fn from_filetime(ticks: u64) -> NtResult<SystemTime> {
    let delta = ticks.abs_diff(FILETIME_UNIX_EPOCH);
    let duration = Duration::new(delta / 10_000_000, ((delta % 10_000_000) * 100) as u32);
    if ticks >= FILETIME_UNIX_EPOCH {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    }
    .ok_or(STATUS_INVALID_PARAMETER)
}

fn attributes(attr: &FileAttr, read_only: bool) -> FileAttributes {
    let mut result = if attr.kind == FileType::Directory {
        FileAttributes::DIRECTORY
    } else {
        FileAttributes::ARCHIVE
    };
    if read_only || attr.perm & 0o222 == 0 {
        result |= FileAttributes::READONLY;
    }
    result
}

fn information(attr: &FileAttr, read_only: bool) -> FileInfo {
    let mut info = FileInfo::default();
    info.set_file_attributes(attributes(attr, read_only))
        .set_file_size(attr.size)
        .set_allocation_size(attr.size.saturating_add(SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE)
        .set_creation_time(to_filetime(attr.crtime))
        .set_last_access_time(to_filetime(attr.atime))
        .set_last_write_time(to_filetime(attr.mtime))
        .set_change_time(to_filetime(attr.ctime))
        .set_index_number(attr.ino)
        .set_hard_links(1);
    info
}

/// The initial backend persists readonly state, not arbitrary NTFS attributes.
fn validate_attributes(attrs: FileAttributes) -> NtResult<()> {
    let supported = (FileAttributes::READONLY
        | FileAttributes::DIRECTORY
        | FileAttributes::ARCHIVE
        | FileAttributes::NORMAL)
        .0;
    if attrs.0 & !supported != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(())
}

fn validate_options(options: CreateOptions) -> NtResult<()> {
    if options.is(CreateOptions::FILE_DIRECTORY_FILE)
        && options.is(CreateOptions::FILE_NON_DIRECTORY_FILE)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if options.is(CreateOptions::FILE_OPEN_BY_FILE_ID) {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(())
}

#[derive(Clone)]
struct EntryLocation {
    parent: u64,
    name: String,
}

#[derive(Clone)]
struct ListedEntry {
    name: Vec<u16>,
    info: FileInfo,
}

#[allow(clippy::struct_excessive_bools)]
struct OpenContext {
    ino: u64,
    directory: bool,
    access: FileAccessRights,
    handle: Mutex<Option<u64>>,
    location: Mutex<Option<EntryLocation>>,
    pending_delete: AtomicBool,
    removed: AtomicBool,
    directory_entries: Mutex<Option<Vec<ListedEntry>>>,
    cleaned: AtomicBool,
    closed: AtomicBool,
}

/// `winfsp_wrs` 0.4 calls `access(NULL)` for volume flush. Its stock Arc
/// implementation cannot represent that. Keep the NULL sentinel explicit and
/// reject volume flush: the binding also dereferences a nullable FileInfo on
/// success. Per-file flush is fully supported.
#[derive(Clone)]
struct ContextRef(Option<Arc<OpenContext>>);

impl std::ops::Deref for ContextRef {
    type Target = OpenContext;
    fn deref(&self) -> &OpenContext {
        self.0
            .as_deref()
            .expect("WinFsp only supplies NULL context to volume flush")
    }
}

impl FileContextKind for ContextRef {
    const MODE: FileContextMode = FileContextMode::Descriptor;
    unsafe fn write(self, out: *mut *mut std::ffi::c_void) {
        let pointer = self.0.map_or(std::ptr::null_mut(), |context| {
            Arc::into_raw(context).cast_mut().cast()
        });
        // SAFETY: WinFsp supplies a valid output slot to transfer this Arc into.
        unsafe {
            out.write(pointer);
        }
    }
    unsafe fn access(raw: *mut std::ffi::c_void) -> Self {
        if raw.is_null() {
            return Self(None);
        }
        // SAFETY: `write` transferred one live Arc; callbacks borrow it by
        // acquiring another strong reference before reconstruction.
        unsafe {
            Arc::increment_strong_count(raw.cast::<OpenContext>());
        }
        // SAFETY: the incremented reference is consumed by this temporary Arc.
        Self(Some(unsafe { Arc::from_raw(raw.cast::<OpenContext>()) }))
    }
    unsafe fn access_for_close(raw: *mut std::ffi::c_void) -> Self {
        if raw.is_null() {
            return Self(None);
        }
        // SAFETY: close consumes the single strong reference owned by WinFsp.
        Self(Some(unsafe { Arc::from_raw(raw.cast::<OpenContext>()) }))
    }
}

struct WindowsFs {
    fs: Arc<EncryptedFs>,
    runtime: Handle,
    data_dir: PathBuf,
    read_only: bool,
    descriptor: SecurityDescriptor,
    opened: Mutex<HashMap<u64, Vec<Weak<OpenContext>>>>,
    stopped: mpsc::Sender<WorkerSignal>,
}

impl WindowsFs {
    fn run<T>(&self, future: impl Future<Output = FsResult<T>>) -> NtResult<T> {
        self.runtime.block_on(future).map_err(status)
    }

    fn writable(&self) -> NtResult<()> {
        if self.read_only {
            Err(STATUS_MEDIA_WRITE_PROTECTED)
        } else {
            Ok(())
        }
    }

    fn resolve(&self, parts: &[String]) -> NtResult<FileAttr> {
        let mut attr = self.run(self.fs.get_attr(ROOT_INODE))?;
        for (index, part) in parts.iter().enumerate() {
            if attr.kind != FileType::Directory {
                return Err(STATUS_NOT_A_DIRECTORY);
            }
            attr = self
                .run(self.fs.find_by_name(attr.ino, &secret(part)))?
                .ok_or(if index + 1 == parts.len() {
                    STATUS_OBJECT_NAME_NOT_FOUND
                } else {
                    STATUS_OBJECT_PATH_NOT_FOUND
                })?;
        }
        Ok(attr)
    }

    fn parent(&self, parts: &[String]) -> NtResult<EntryLocation> {
        let (name, parent) = parts.split_last().ok_or(STATUS_ACCESS_DENIED)?;
        let attr = self.resolve(parent)?;
        if attr.kind != FileType::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        Ok(EntryLocation {
            parent: attr.ino,
            name: name.clone(),
        })
    }

    fn contexts(&self, ino: u64) -> Vec<Arc<OpenContext>> {
        let mut opened = self.opened.lock().unwrap();
        let Some(entries) = opened.get_mut(&ino) else {
            return Vec::new();
        };
        let mut contexts = Vec::with_capacity(entries.len());
        entries.retain(|entry| {
            let Some(context) = entry.upgrade() else {
                return false;
            };
            if context.closed.load(Ordering::Acquire) {
                return false;
            }
            contexts.push(context);
            true
        });
        if entries.is_empty() {
            opened.remove(&ino);
        }
        contexts
    }

    fn check_open(&self, ino: u64) -> NtResult<()> {
        if self
            .contexts(ino)
            .iter()
            .any(|context| context.pending_delete.load(Ordering::Acquire))
        {
            // The core has no Unix-style unlink-while-open semantics.
            return Err(STATUS_SHARING_VIOLATION);
        }
        Ok(())
    }

    fn context(
        &self,
        attr: FileAttr,
        location: Option<EntryLocation>,
        access: FileAccessRights,
        handle: Option<u64>,
    ) -> ContextRef {
        let context = Arc::new(OpenContext {
            ino: attr.ino,
            directory: attr.kind == FileType::Directory,
            access,
            handle: Mutex::new(handle),
            location: Mutex::new(location),
            pending_delete: AtomicBool::new(false),
            removed: AtomicBool::new(false),
            directory_entries: Mutex::new(None),
            cleaned: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        self.opened
            .lock()
            .unwrap()
            .entry(attr.ino)
            .or_default()
            .push(Arc::downgrade(&context));
        ContextRef(Some(context))
    }

    fn check_type(attr: &FileAttr, options: CreateOptions) -> NtResult<()> {
        validate_options(options)?;
        if options.is(CreateOptions::FILE_DIRECTORY_FILE) && attr.kind != FileType::Directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if options.is(CreateOptions::FILE_NON_DIRECTORY_FILE) && attr.kind == FileType::Directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        Ok(())
    }

    fn check_context(context: &OpenContext) -> NtResult<()> {
        if context.closed.load(Ordering::Acquire) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if context.removed.load(Ordering::Acquire) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        Ok(())
    }

    fn has_data_access(access: FileAccessRights) -> bool {
        access.is(FileAccessRights::FILE_READ_DATA)
            || access.is(FileAccessRights::FILE_WRITE_DATA)
            || access.is(FileAccessRights::FILE_APPEND_DATA)
    }

    fn check_data_write(&self, context: &OpenContext) -> NtResult<()> {
        Self::check_context(context)?;
        self.writable()?;
        if !context.access.is(FileAccessRights::FILE_WRITE_DATA)
            && !context.access.is(FileAccessRights::FILE_APPEND_DATA)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        let attr = self.run(self.fs.get_attr(context.ino))?;
        if attr.perm & 0o222 == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(())
    }

    fn close_core(&self, context: &OpenContext) -> NtResult<()> {
        if let Some(handle) = context.handle.lock().unwrap().take() {
            self.run(self.fs.release(handle))?;
        }
        Ok(())
    }

    fn check_delete(&self, context: &OpenContext) -> NtResult<()> {
        Self::check_context(context)?;
        self.writable()?;
        if context.ino == ROOT_INODE || !context.access.is(FileAccessRights::DELETE) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let attr = self.run(self.fs.get_attr(context.ino))?;
        if attr.perm & 0o222 == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if context.directory && self.fs.len(context.ino).map_err(status)? != 0 {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        if self.contexts(context.ino).iter().any(|other| {
            !std::ptr::eq(other.as_ref(), context) && !other.cleaned.load(Ordering::Acquire)
        }) {
            return Err(STATUS_SHARING_VIOLATION);
        }
        Ok(())
    }

    fn file_info(&self, context: &OpenContext) -> NtResult<FileInfo> {
        Self::check_context(context)?;
        Ok(information(
            &self.run(self.fs.get_attr(context.ino))?,
            self.read_only,
        ))
    }
}

impl FileSystemInterface for WindowsFs {
    type FileContext = ContextRef;
    const GET_VOLUME_INFO_DEFINED: bool = true;
    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    const CREATE_DEFINED: bool = true;
    const OPEN_DEFINED: bool = true;
    const OVERWRITE_DEFINED: bool = true;
    const CLEANUP_DEFINED: bool = true;
    const CLOSE_DEFINED: bool = true;
    const READ_DEFINED: bool = true;
    const WRITE_DEFINED: bool = true;
    const FLUSH_DEFINED: bool = true;
    const GET_FILE_INFO_DEFINED: bool = true;
    const SET_BASIC_INFO_DEFINED: bool = true;
    const SET_FILE_SIZE_DEFINED: bool = true;
    const SET_DELETE_DEFINED: bool = true;
    const RENAME_DEFINED: bool = true;
    const GET_SECURITY_DEFINED: bool = true;
    const SET_SECURITY_DEFINED: bool = true;
    const READ_DIRECTORY_DEFINED: bool = true;
    const DISPATCHER_STOPPED_DEFINED: bool = true;

    fn get_volume_info(&self) -> NtResult<VolumeInfo> {
        let path = U16CString::from_os_str(self.data_dir.as_os_str())
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        let (mut available, mut total, mut free) = (0, 0, 0);
        // SAFETY: The UTF-16 path and all output pointers live through the call.
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut available, &mut total, &mut free) } == 0
        {
            return Err(STATUS_UNSUCCESSFUL);
        }
        VolumeInfo::new(
            total,
            available,
            U16CString::from_str("rencfs").unwrap().as_ustr(),
        )
        .map_err(|_| STATUS_INVALID_PARAMETER)
    }

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> NtResult<(FileAttributes, PSecurityDescriptor, bool)> {
        let attr = self.resolve(&components(file_name)?)?;
        self.check_open(attr.ino)?;
        Ok((
            attributes(&attr, self.read_only),
            self.descriptor.as_ptr(),
            false,
        ))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create: CreateFileInfo,
        _security_descriptor: SecurityDescriptor,
    ) -> NtResult<(ContextRef, FileInfo)> {
        self.writable()?;
        validate_attributes(create.file_attributes)?;
        validate_options(create.create_options)?;
        if create
            .create_options
            .is(CreateOptions::FILE_DELETE_ON_CLOSE)
            && (!create.granted_access.is(FileAccessRights::DELETE)
                || create.file_attributes.is(FileAttributes::READONLY))
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        let parts = components(file_name)?;
        let location = self.parent(&parts)?;
        let directory = create.create_options.is(CreateOptions::FILE_DIRECTORY_FILE);
        let read = Self::has_data_access(create.granted_access);
        let attr = CreateFileAttr {
            kind: if directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if create.file_attributes.is(FileAttributes::READONLY) {
                0o555
            } else if directory {
                0o755
            } else {
                0o644
            },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        let (handle, attr) = self.run(self.fs.create(
            location.parent,
            &secret(&location.name),
            attr,
            !directory && read,
            false,
        ))?;
        let info = information(&attr, self.read_only);
        let context = self.context(
            attr,
            Some(location),
            create.granted_access,
            if handle == 0 { None } else { Some(handle) },
        );
        if create
            .create_options
            .is(CreateOptions::FILE_DELETE_ON_CLOSE)
        {
            if let Err(status) = self.check_delete(&context) {
                self.close(context);
                return Err(status);
            }
            context.pending_delete.store(true, Ordering::Release);
        }
        Ok((context, info))
    }

    fn open(
        &self,
        file_name: &U16CStr,
        options: CreateOptions,
        access: FileAccessRights,
    ) -> NtResult<(ContextRef, FileInfo)> {
        let parts = components(file_name)?;
        let attr = self.resolve(&parts)?;
        Self::check_type(&attr, options)?;
        self.check_open(attr.ino)?;
        let write = access.is(FileAccessRights::FILE_WRITE_DATA)
            || access.is(FileAccessRights::FILE_APPEND_DATA);
        let read = access.is(FileAccessRights::FILE_READ_DATA);
        if write {
            self.writable()?;
            if attr.perm & 0o222 == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
        }
        if self.read_only
            && (access.is(FileAccessRights::DELETE)
                || access.is(FileAccessRights::FILE_WRITE_ATTRIBUTES)
                || access.is(FileAccessRights::FILE_WRITE_EA))
        {
            return Err(STATUS_MEDIA_WRITE_PROTECTED);
        }
        let location = if parts.is_empty() {
            None
        } else {
            Some(self.parent(&parts)?)
        };
        // Native contexts may outlive user handles because Windows retains
        // them for cached I/O. Never reserve the core's single writer for that
        // lifetime. Writes acquire a short lease in the serialized callback.
        let handle = if attr.kind == FileType::RegularFile && (read || write) {
            Some(self.run(self.fs.open(attr.ino, true, false))?)
        } else {
            None
        };
        let context = self.context(attr, location, access, handle);
        if options.is(CreateOptions::FILE_DELETE_ON_CLOSE) {
            if let Err(status) = self.check_delete(&context) {
                self.close(context);
                return Err(status);
            }
            context.pending_delete.store(true, Ordering::Release);
        }
        Ok((context, information(&attr, self.read_only)))
    }

    fn overwrite(
        &self,
        context: ContextRef,
        attrs: FileAttributes,
        replace_attrs: bool,
        _allocation_size: u64,
    ) -> NtResult<FileInfo> {
        self.check_data_write(&context)?;
        validate_attributes(attrs)?;
        if context.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        self.run(self.fs.set_len(context.ino, 0))?;
        let attr = self.run(self.fs.get_attr(context.ino))?;
        let perm = if attrs.is(FileAttributes::READONLY) {
            attr.perm & !0o222
        } else if replace_attrs && attr.perm & 0o222 == 0 {
            attr.perm | 0o200
        } else {
            attr.perm
        };
        if perm != attr.perm {
            self.run(
                self.fs
                    .set_attr(context.ino, SetFileAttr::default().with_perm(perm)),
            )?;
        }
        self.file_info(&context)
    }

    fn cleanup(&self, context: ContextRef, _name: Option<&U16CStr>, flags: CleanupFlags) {
        context.cleaned.store(true, Ordering::Release);
        if flags.is(CleanupFlags::DELETE) && !context.removed.load(Ordering::Acquire) {
            let result = (|| {
                self.check_delete(&context)?;
                let location = context
                    .location
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or(STATUS_ACCESS_DENIED)?;
                // Defend against stale names; never delete a replacement inode.
                let attr = self
                    .run(
                        self.fs
                            .find_by_name(location.parent, &secret(&location.name)),
                    )?
                    .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
                if attr.ino != context.ino {
                    return Err(STATUS_SHARING_VIOLATION);
                }
                // Other contexts have reached Cleanup but Windows may defer
                // their Close. Release every reader before deleting: releasing
                // one afterward could persist its cached inode metadata again.
                let contexts = self.contexts(context.ino);
                for retained in &contexts {
                    self.close_core(retained)?;
                }
                if context.directory {
                    self.run(self.fs.remove_dir(location.parent, &secret(&location.name)))?;
                } else {
                    self.run(
                        self.fs
                            .remove_file(location.parent, &secret(&location.name)),
                    )?;
                }
                for retained in contexts {
                    retained.removed.store(true, Ordering::Release);
                }
                Ok::<_, i32>(())
            })();
            if let Err(status) = result {
                error!(status, "WinFsp delete cleanup failed");
            }
        }
        // Normal Cleanup retains readers for paging I/O until Close. Writes
        // and size changes already commit before their callbacks return.
    }

    fn close(&self, context: ContextRef) {
        if let Err(status) = self.close_core(&context) {
            error!(status, "WinFsp close failed");
        }
        context.closed.store(true, Ordering::Release);
        drop(self.contexts(context.ino));
    }

    fn read(&self, context: ContextRef, buffer: &mut [u8], offset: u64) -> NtResult<usize> {
        Self::check_context(&context)?;
        if context.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        // WinFsp checks user handle rights before dispatch. Kernel/filter I/O
        // can read through a write-only context, so retain backing read access
        // for all data contexts without changing the native granted access.
        if !Self::has_data_access(context.access) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let handle = context
            .handle
            .lock()
            .unwrap()
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.run(self.fs.read(context.ino, offset, buffer, handle))
    }

    fn write(
        &self,
        context: ContextRef,
        buffer: &[u8],
        mode: WriteMode,
    ) -> NtResult<(usize, FileInfo)> {
        if context.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        self.check_data_write(&context)?;
        let size = self.run(self.fs.get_attr(context.ino))?.size;
        let (offset, length) = match mode {
            WriteMode::Normal { offset } => {
                if !context.access.is(FileAccessRights::FILE_WRITE_DATA) {
                    return Err(STATUS_ACCESS_DENIED);
                }
                (offset, buffer.len())
            }
            WriteMode::WriteToEOF => (size, buffer.len()),
            WriteMode::ConstrainedIO { offset } => {
                if !context.access.is(FileAccessRights::FILE_WRITE_DATA) {
                    return Err(STATUS_ACCESS_DENIED);
                }
                (
                    offset,
                    usize::try_from(size.saturating_sub(offset))
                        .unwrap_or(usize::MAX)
                        .min(buffer.len()),
                )
            }
        };
        offset
            .checked_add(length as u64)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let bytes = if length == 0 {
            0
        } else {
            let handle = self.run(self.fs.open(context.ino, false, true))?;
            let written = self.run(self.fs.as_ref().write(
                context.ino,
                offset,
                &buffer[..length],
                handle,
            ));
            // Release finishes and syncs the encrypted tail and refreshes all
            // readers. Always release the lease, including after a write error.
            let released = self.run(self.fs.release(handle));
            let bytes = written?;
            released?;
            bytes
        };
        Ok((bytes, self.file_info(&context)?))
    }

    fn flush(&self, context: ContextRef) -> NtResult<FileInfo> {
        if context.0.is_none() {
            return Err(STATUS_NOT_SUPPORTED);
        }
        // Each mutation is committed synchronously; contexts retain no writer.
        self.file_info(&context)
    }

    fn get_file_info(&self, context: ContextRef) -> NtResult<FileInfo> {
        self.file_info(&context)
    }

    fn set_basic_info(
        &self,
        context: ContextRef,
        attrs: FileAttributes,
        creation: u64,
        access: u64,
        write: u64,
        change: u64,
    ) -> NtResult<FileInfo> {
        Self::check_context(&context)?;
        self.writable()?;
        if !context.access.is(FileAccessRights::FILE_WRITE_ATTRIBUTES) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let attr = self.run(self.fs.get_attr(context.ino))?;
        let mut update = SetFileAttr::default();
        if attrs != FileAttributes::INVALID {
            validate_attributes(attrs)?;
            let perm = if attrs.is(FileAttributes::READONLY) {
                attr.perm & !0o222
            } else if attr.perm & 0o222 == 0 {
                attr.perm | 0o200
            } else {
                attr.perm
            };
            update.perm = Some(perm);
        }
        // Zero and all-one FILETIME values mean "leave this timestamp alone".
        if creation != 0 && creation != u64::MAX {
            update.crtime = Some(from_filetime(creation)?);
        }
        if access != 0 && access != u64::MAX {
            update.atime = Some(from_filetime(access)?);
        }
        if write != 0 && write != u64::MAX {
            update.mtime = Some(from_filetime(write)?);
        }
        if change != 0 && change != u64::MAX {
            update.ctime = Some(from_filetime(change)?);
        }
        self.run(self.fs.set_attr(context.ino, update))?;
        self.file_info(&context)
    }

    fn set_file_size(
        &self,
        context: ContextRef,
        size: u64,
        allocation: bool,
    ) -> NtResult<FileInfo> {
        self.check_data_write(&context)?;
        if context.directory {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if !context.access.is(FileAccessRights::FILE_WRITE_DATA) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let current = self.run(self.fs.get_attr(context.ino))?.size;
        // Allocation may be deferred by a filesystem. Shrinking below EOF must
        // truncate; growing allocation is advisory and never changes logical EOF.
        if !allocation || size < current {
            self.run(self.fs.set_len(context.ino, size))?;
        }
        self.file_info(&context)
    }

    fn set_delete(&self, context: ContextRef, _name: &U16CStr, delete: bool) -> NtResult<()> {
        if delete {
            self.check_delete(&context)?;
        }
        context.pending_delete.store(delete, Ordering::Release);
        Ok(())
    }

    fn rename(
        &self,
        context: ContextRef,
        name: &U16CStr,
        new_name: &U16CStr,
        replace: bool,
    ) -> NtResult<()> {
        Self::check_context(&context)?;
        self.writable()?;
        if !context.access.is(FileAccessRights::DELETE) {
            return Err(STATUS_ACCESS_DENIED);
        }
        if context.ino == ROOT_INODE {
            return Err(STATUS_ACCESS_DENIED);
        }
        let source_parts = components(name)?;
        let target_parts = components(new_name)?;
        if context.directory
            && target_parts.len() > source_parts.len()
            && target_parts.starts_with(&source_parts)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let source = self.parent(&source_parts)?;
        let destination = self.parent(&target_parts)?;
        let current = self.resolve(&source_parts)?;
        if current.ino != context.ino {
            return Err(STATUS_SHARING_VIOLATION);
        }
        if source.parent == destination.parent && source.name == destination.name {
            return Ok(());
        }
        if self
            .run(
                self.fs
                    .find_by_name(destination.parent, &secret(&destination.name)),
            )?
            .is_some()
        {
            return Err(if replace {
                STATUS_NOT_SUPPORTED
            } else {
                STATUS_OBJECT_NAME_COLLISION
            });
        }
        self.run(self.fs.rename(
            source.parent,
            &secret(&source.name),
            destination.parent,
            &secret(&destination.name),
        ))?;
        for opened in self.contexts(context.ino) {
            *opened.location.lock().unwrap() = Some(destination.clone());
        }
        Ok(())
    }

    fn get_security(&self, _context: ContextRef) -> NtResult<PSecurityDescriptor> {
        Ok(self.descriptor.as_ptr())
    }

    fn set_security(
        &self,
        _context: ContextRef,
        _information: u32,
        _modification: PSecurityDescriptor,
    ) -> NtResult<()> {
        Err(STATUS_NOT_SUPPORTED)
    }

    fn read_directory(
        &self,
        context: ContextRef,
        marker: Option<&U16CStr>,
        mut add: impl FnMut(DirInfo) -> bool,
    ) -> NtResult<()> {
        Self::check_context(&context)?;
        if !context.directory {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let mut snapshot = context.directory_entries.lock().unwrap();
        if marker.is_none() || snapshot.is_none() {
            let mut entries = Vec::new();
            for entry in self.run(self.fs.read_dir_plus(context.ino))? {
                let entry = entry.map_err(status)?;
                let name = entry.name.expose_secret();
                if &**name == "." || &**name == ".." {
                    continue;
                }
                let name: Vec<u16> = name.encode_utf16().collect();
                if name.len() > 255 {
                    return Err(STATUS_NAME_TOO_LONG);
                }
                entries.push(ListedEntry {
                    name,
                    info: information(&entry.attr, self.read_only),
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            *snapshot = Some(entries);
        }
        for entry in snapshot.as_ref().unwrap() {
            if marker.is_some_and(|marker| entry.name.as_slice() <= marker.as_slice()) {
                continue;
            }
            let name =
                U16CString::from_vec(entry.name.clone()).map_err(|_| STATUS_OBJECT_NAME_INVALID)?;
            if !add(DirInfo::new(entry.info, &name)) {
                break;
            }
        }
        Ok(())
    }

    fn dispatcher_stopped(&self, normally: bool) {
        let _ = self.stopped.send(WorkerSignal::DispatcherStopped(normally));
    }
}

/// Build a restricted descriptor from the actual mounting account's SID.
fn mounting_user_descriptor() -> io::Result<SecurityDescriptor> {
    let mut token = 0;
    // SAFETY: token is a writable HANDLE output; the pseudo-process handle is valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut bytes = 0;
        // SAFETY: the first call obtains the required byte count without dereferencing a buffer.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: buffer is aligned for TOKEN_USER and has at least `bytes` initialized bytes.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful API call initialized a TOKEN_USER at the aligned buffer start.
        let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let mut sid_string = std::ptr::null_mut();
        // SAFETY: sid points into the live token buffer; the API allocates the output string.
        if unsafe { ConvertSidToStringSidW(sid, &mut sid_string) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful ConvertSidToStringSidW returns a NUL-terminated UTF-16 string.
        let sid = unsafe { U16CStr::from_ptr_str(sid_string) }.to_string_lossy();
        // SAFETY: this allocation belongs to LocalFree under the documented API contract.
        unsafe {
            LocalFree(sid_string.cast());
        }
        let sddl = U16CString::from_str(format!(
            "O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"
        ))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid account SID"))?;
        SecurityDescriptor::from_wstr(&sddl).map_err(io::Error::other)
    })();
    // SAFETY: OpenProcessToken returned this owned HANDLE, closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    result
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

    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        if self.allow_root || self.allow_other {
            return Err(FsError::InvalidInput("--allow-root/--allow-other are Linux-only; Windows mounts are restricted to the mounting account"));
        }
        let mountpoint = U16CString::from_os_str(self.mountpoint.as_os_str())
            .map_err(|_| FsError::InvalidInput("mount point contains a NUL"))?;
        let data_dir = std::fs::canonicalize(&self.data_dir).or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                std::fs::create_dir_all(&self.data_dir)?;
                std::fs::canonicalize(&self.data_dir)
            } else {
                Err(error)
            }
        })?;
        winfsp_wrs::init().map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{error} Install WinFsp 2.x before mounting."),
            )
        })?;
        let descriptor = mounting_user_descriptor()?;
        let fs = EncryptedFs::new(
            data_dir.clone(),
            self.password_provider.take().unwrap(),
            self.cipher,
            self.read_only,
        )
        .await?;
        let runtime = Handle::current();
        let (signal_tx, signal_rx) = mpsc::channel();
        // Cancellation while awaiting startup must not strand a mounted host.
        struct CancelStartup(Option<mpsc::Sender<WorkerSignal>>);
        impl Drop for CancelStartup {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(WorkerSignal::Stop);
                }
            }
        }
        let mut cancel_startup = CancelStartup(Some(signal_tx.clone()));
        let (started_tx, started_rx) = oneshot::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let read_only = self.read_only;
        let callback_tx = signal_tx.clone();
        std::thread::Builder::new()
            .name("rencfs-winfsp".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let context = WindowsFs {
                        fs,
                        runtime,
                        data_dir,
                        read_only,
                        descriptor,
                        opened: Mutex::default(),
                        stopped: callback_tx,
                    };
                    let mut params = Params {
                        guard_strategy: OperationGuardStrategy::Coarse,
                        ..Params::default()
                    };
                    params
                        .volume_params
                        .set_sector_size(512)
                        .set_sectors_per_allocation_unit(8)
                        .set_max_component_length(255)
                        .set_case_sensitive_search(true)
                        .set_case_preserved_names(true)
                        .set_unicode_on_disk(true)
                        .set_read_only_volume(read_only)
                        .set_file_info_timeout(0)
                        .set_persistent_acls(false)
                        .set_named_streams(false)
                        .set_hard_links(false)
                        .set_reparse_point(false)
                        .set_extended_attributes(false)
                        .set_pass_query_directory_pattern(false);
                    params
                        .volume_params
                        .set_file_system_name(winfsp_wrs::u16cstr!("rencfs"))
                        .expect("constant filesystem name fits WinFsp field");
                    let host = match FileSystem::start(params, Some(&mountpoint), context) {
                        Ok(host) => host,
                        Err(status) => {
                            let _ = started_tx.send(Err(io::Error::other(format!(
                                "WinFsp mount failed: NTSTATUS {status:#x}"
                            ))));
                            return Ok(());
                        }
                    };
                    struct StopOnDrop(Option<FileSystem>);
                    impl Drop for StopOnDrop {
                        fn drop(&mut self) {
                            if let Some(host) = self.0.take() {
                                host.stop();
                            }
                        }
                    }
                    let _host = StopOnDrop(Some(host));
                    if started_tx.send(Ok(())).is_err() {
                        return Ok(());
                    }
                    match signal_rx.recv() {
                        Ok(WorkerSignal::Stop) | Ok(WorkerSignal::DispatcherStopped(true)) => {
                            Ok(())
                        }
                        Ok(WorkerSignal::DispatcherStopped(false)) => {
                            Err(io::Error::other("WinFsp dispatcher stopped unexpectedly"))
                        }
                        Err(_) => Ok(()),
                    }
                }))
                .unwrap_or_else(|_| Err(io::Error::other("WinFsp host worker panicked")));
                let _ = finished_tx.send(result);
            })?;
        started_rx
            .await
            .map_err(|_| io::Error::other("WinFsp host worker exited before mount"))??;
        cancel_startup.0.take();
        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                signal: signal_tx,
                finished: finished_rx,
            },
        })
    }
}

enum WorkerSignal {
    Stop,
    DispatcherStopped(bool),
}

pub(in crate::mount) struct MountHandleInnerImpl {
    signal: mpsc::Sender<WorkerSignal>,
    finished: oneshot::Receiver<io::Result<()>>,
}

impl Drop for MountHandleInnerImpl {
    fn drop(&mut self) {
        let _ = self.signal.send(WorkerSignal::Stop);
    }
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.finished).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(io::Error::other("WinFsp host worker disappeared")))
            }
        }
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        let _ = self.signal.send(WorkerSignal::Stop);
        (&mut self).await
    }
}

#[cfg(test)]
mod tests;
