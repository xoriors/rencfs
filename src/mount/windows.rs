//! Windows WinFsp backend for rencfs.
//!
//! Bridges the `winfsp::filesystem::FileSystemContext` trait to the internal
//! `EncryptedFs` engine, providing native Windows filesystem mount support
//! via the WinFsp user-mode filesystem driver.

use std::ffi::c_void;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
use tracing::{debug, error, info, trace, warn};
use widestring::{U16CStr, U16CString};
use windows::Win32::Foundation::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_INVALID_HANDLE,
    STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    ModificationDescriptor, OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, FileSystemParams, FineGuard, VolumeParams};

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    SetFileAttr, ROOT_INODE,
};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 100-nanosecond intervals between the Windows FILETIME epoch (1601-01-01)
/// and the Unix epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Maximum component length reported to Windows.
const MAX_COMPONENT_LENGTH: u32 = 255;

/// Volume label reported to Windows Explorer.
const VOLUME_LABEL: &str = "EncryptedFs";

/// Sector size for the WinFsp volume.
const SECTOR_SIZE: u16 = 4096;

/// File info timeout in milliseconds for WinFsp caching.
const FILE_INFO_TIMEOUT_MS: u32 = 1000;

static CALLBACK_RUNTIME: std::sync::LazyLock<Result<tokio::runtime::Runtime, io::Error>> =
    std::sync::LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    });

/// Windows file attribute constants.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;

/// WinFsp cleanup flags — if this flag is set in `cleanup`, the file should
/// be deleted after all handles are closed.
const FSP_CLEANUP_DELETE: u32 = 0x01;

/// Additional NTSTATUS values not always re-exported by the `windows` crate.
const STATUS_SHARING_VIOLATION: NTSTATUS = NTSTATUS(0xC000_0043_u32 as i32);
const STATUS_DISK_FULL: NTSTATUS = NTSTATUS(0xC000_007F_u32 as i32);
const STATUS_MEDIA_WRITE_PROTECTED: NTSTATUS = NTSTATUS(0xC000_00A2_u32 as i32);
const STATUS_INTERNAL_ERROR: NTSTATUS = NTSTATUS(0xC000_00E5_u32 as i32);
const STATUS_NOT_SUPPORTED: NTSTATUS = NTSTATUS(0xC000_00BB_u32 as i32);
const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = NTSTATUS(0xC000_00BA_u32 as i32);
const STATUS_OBJECT_NAME_INVALID: NTSTATUS = NTSTATUS(0xC000_0033_u32 as i32);

/// Windows access mask bits.
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;

// ---------------------------------------------------------------------------
// Path Normalization & Resolution
// ---------------------------------------------------------------------------

/// Normalize a WinFsp-style path (`\foo\bar`) to a forward-slash internal path
/// with no leading separator. Root is represented as empty string `""`.
fn normalize_path(win_path: &U16CStr) -> Result<String, FsError> {
    let path = win_path
        .to_string()
        .map_err(|_| FsError::InvalidInput("invalid UTF-16 path"))?;
    let normalized = path.replace('\\', "/");
    let mut components = Vec::new();

    for component in normalized.split('/').filter(|part| !part.is_empty()) {
        if component == "." || component == ".." {
            return Err(FsError::InvalidInput(
                "relative path components are not supported",
            ));
        }
        if component.ends_with(' ')
            || component.ends_with('.')
            || component.encode_utf16().count() > MAX_COMPONENT_LENGTH as usize
            || component
                .chars()
                .any(|ch| ch <= '\u{001f}' || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return Err(FsError::InvalidInput("invalid Windows path component"));
        }

        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        let is_reserved_device_name = matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        if is_reserved_device_name {
            return Err(FsError::InvalidInput("reserved Windows device name"));
        }

        components.push(component);
    }

    Ok(components.join("/"))
}

/// Split a normalized path into `(parent_path, final_component)`.
/// Returns `None` for the root path (empty string).
fn split_path(path: &str) -> Option<(&str, &str)> {
    if path.is_empty() {
        return None;
    }
    match path.rfind('/') {
        Some(pos) => Some((&path[..pos], &path[pos + 1..])),
        None => Some(("", path)),
    }
}

// ---------------------------------------------------------------------------
// Error Mapping
// ---------------------------------------------------------------------------

/// Map an `FsError` to a precise NTSTATUS code.
/// Provides granular error reporting to Windows instead of generic failures.
fn fs_error_to_ntstatus(err: &FsError) -> NTSTATUS {
    match err {
        FsError::InodeNotFound | FsError::NotFound(_) => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::InvalidInput(_) => STATUS_OBJECT_NAME_INVALID,
        FsError::InvalidInodeType => STATUS_NOT_A_DIRECTORY,
        FsError::InvalidFileHandle => STATUS_INVALID_HANDLE,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::MaxFilesizeExceeded(_) => STATUS_DISK_FULL,
        FsError::InvalidPassword => STATUS_ACCESS_DENIED,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::Io { source, .. } => match source.kind() {
            io::ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
            io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
            io::ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
            _ => STATUS_INTERNAL_ERROR,
        },
        _ => STATUS_INTERNAL_ERROR,
    }
}

/// Convert an `FsError` into a `winfsp::FspError` for trait return types.
fn fs_err(e: FsError) -> winfsp::FspError {
    let status = fs_error_to_ntstatus(&e);
    error!(err = %e, ntstatus = ?status, "filesystem error");
    status.into()
}

// ---------------------------------------------------------------------------
// Timestamp Conversion
// ---------------------------------------------------------------------------

/// Convert a Rust `SystemTime` to a Windows FILETIME value
/// (100-nanosecond intervals since 1601-01-01 UTC).
fn system_time_to_filetime(st: SystemTime) -> u64 {
    match st.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // Saturating cast: u128 → u64 (overflows past year ~2554, acceptable).
            let nanos_100 = (d.as_nanos() / 100) as u64;
            nanos_100.saturating_add(FILETIME_EPOCH_DIFF)
        }
        Err(_) => FILETIME_EPOCH_DIFF, // fallback to Unix epoch
    }
}

/// Convert a Windows FILETIME value to a Rust `SystemTime`.
fn filetime_to_system_time(ft: u64) -> SystemTime {
    if ft <= FILETIME_EPOCH_DIFF {
        return UNIX_EPOCH;
    }
    let nanos_100 = ft - FILETIME_EPOCH_DIFF;
    let duration = Duration::from_nanos(nanos_100 * 100);
    UNIX_EPOCH + duration
}

// ---------------------------------------------------------------------------
// FileInfo Population
// ---------------------------------------------------------------------------

/// Populate a WinFsp `FileInfo` struct from an `EncryptedFs` `FileAttr`.
fn populate_file_info(fi: &mut FileInfo, attr: &FileAttr, read_only: bool) {
    let mut file_attributes = if attr.kind == FileType::Directory {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    if read_only {
        file_attributes |= FILE_ATTRIBUTE_READONLY;
    }

    fi.file_attributes = file_attributes;
    fi.creation_time = system_time_to_filetime(attr.crtime);
    fi.last_access_time = system_time_to_filetime(attr.atime);
    fi.last_write_time = system_time_to_filetime(attr.mtime);
    fi.change_time = system_time_to_filetime(attr.ctime);
    fi.file_size = attr.size;
    // Allocation size rounded up to the next sector boundary.
    fi.allocation_size = (attr.size + (SECTOR_SIZE as u64 - 1)) & !(SECTOR_SIZE as u64 - 1);
    fi.index_number = attr.ino;
}

// ---------------------------------------------------------------------------
// File Context — lives for the duration of an open handle
// ---------------------------------------------------------------------------

/// Represents an open file or directory handle in the WinFsp bridge.
///
/// Once created by `open` or `create`, subsequent operations (`read`, `write`,
/// `get_file_info`, `flush`) use `context.ino` directly — no re-walking the
/// path tree. Path resolution only happens during the initial open/create.
pub struct WinFspFileContext {
    /// The inode number in the EncryptedFs.
    ino: u64,
    /// Whether this context represents a directory.
    is_dir: bool,
    /// The EncryptedFs file handle. `None` for directories.
    handle: std::sync::Mutex<Option<u64>>,
    /// The normalized path, kept for logging and cleanup/delete operations.
    path: String,
    /// Persistent directory buffer for paginated `read_directory` calls.
    /// WinFsp calls `read_directory` multiple times for large directories,
    /// sending different markers each time. The buffer MUST survive across
    /// consecutive calls for the same open directory handle.
    ///
    /// `DirBuffer` provides interior mutability via an internal SRW lock,
    /// so the outer `Mutex` is belt-and-suspenders safety for our own code.
    dir_buffer: std::sync::Mutex<DirBuffer>,
}

// ---------------------------------------------------------------------------
// Core Bridge
// ---------------------------------------------------------------------------

/// The WinFsp filesystem bridge. Implements `FileSystemContext` by delegating
/// all operations to an `EncryptedFs` instance through a dedicated tokio runtime.
pub struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
    /// Shared callback runtime. It is process-lived so unmounting from the
    /// signal handler never drops a Tokio runtime inside another runtime.
    rt: &'static tokio::runtime::Runtime,
    read_only: bool,
    namespace_lock: std::sync::Mutex<()>,
}

impl EncryptedFsWinFsp {
    /// Resolve a normalized path to its `(inode, FileAttr)`.
    ///
    /// For the root (empty string or "/"), returns `ROOT_INODE`'s attributes.
    /// For deeper paths, walks the directory tree component by component.
    ///
    /// Uses **case-insensitive fallback**: if a direct `find_by_name` fails,
    /// enumerates all entries in the directory and matches case-insensitively.
    /// This handles the Windows case-insensitivity expectation while the
    /// underlying EncryptedFs is case-sensitive.
    fn resolve_path(&self, path: &str) -> Result<(u64, FileAttr), FsError> {
        if path.is_empty() {
            let attr = self.rt.block_on(self.fs.get_attr(ROOT_INODE))?;
            return Ok((ROOT_INODE, attr));
        }

        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_ino = ROOT_INODE;

        for component in &components {
            let name = SecretString::from_str(component)
                .map_err(|_| FsError::InvalidInput("invalid path component"))?;

            // Try exact (case-sensitive) match first — this is the fast path.
            match self.rt.block_on(self.fs.find_by_name(current_ino, &name)) {
                Ok(Some(attr)) => {
                    current_ino = attr.ino;
                    continue;
                }
                Ok(None) => {
                    // Exact match failed — try case-insensitive fallback.
                    match self.case_insensitive_lookup(current_ino, component) {
                        Ok(attr) => {
                            current_ino = attr.ino;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }

        let attr = self.rt.block_on(self.fs.get_attr(current_ino))?;
        Ok((current_ino, attr))
    }

    /// Case-insensitive directory lookup fallback.
    ///
    /// Reads all entries in `parent_ino` and compares names case-insensitively.
    /// This is the "slow path" — only invoked when the fast exact-match fails.
    fn case_insensitive_lookup(
        &self,
        parent_ino: u64,
        target_name: &str,
    ) -> Result<FileAttr, FsError> {
        let (_, ino) = self
            .case_insensitive_entry(parent_ino, target_name)?
            .ok_or(FsError::NotFound("case-insensitive lookup failed"))?;
        self.rt.block_on(self.fs.get_attr(ino))
    }

    /// Find the stored spelling and inode for a Windows case-insensitive name.
    fn case_insensitive_entry(
        &self,
        parent_ino: u64,
        target_name: &str,
    ) -> Result<Option<(String, u64)>, FsError> {
        let target_lower = target_name.to_lowercase();
        let iter = self.rt.block_on(self.fs.read_dir(parent_ino))?;

        let mut found = None;
        for entry_result in iter {
            let entry = entry_result?;
            let entry_name = entry.name.expose_secret().to_string();
            if entry_name == "." || entry_name == ".." {
                continue;
            }
            if entry_name.to_lowercase() == target_lower {
                if found.is_some() {
                    return Err(FsError::InvalidInput(
                        "ambiguous case-insensitive Windows path",
                    ));
                }
                found = Some((entry_name, entry.ino));
            }
        }

        Ok(found)
    }

    /// Resolve an existing entry using Windows lookup rules, preserving its actual spelling.
    fn resolve_existing_name(
        &self,
        parent_ino: u64,
        target_name: &str,
    ) -> Result<Option<(String, u64)>, FsError> {
        let name = SecretString::from_str(target_name)
            .map_err(|_| FsError::InvalidInput("invalid path component"))?;
        if let Some(attr) = self.rt.block_on(self.fs.find_by_name(parent_ino, &name))? {
            return Ok(Some((target_name.to_owned(), attr.ino)));
        }
        self.case_insensitive_entry(parent_ino, target_name)
    }

    /// Read through a short-lived encrypted-file handle. This is the recovery
    /// path for Windows cache reads that receive EOF from an old per-open
    /// reader even though the inode metadata says bytes remain.
    fn read_with_temporary_handle(
        &self,
        ino: u64,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, FsError> {
        let handle = self.rt.block_on(self.fs.open(ino, true, false))?;
        let read_result = self.rt.block_on(self.fs.read(ino, offset, buffer, handle));
        let release_result = self.rt.block_on(self.fs.release(handle));
        match read_result {
            Ok(bytes_read) => {
                release_result?;
                Ok(bytes_read)
            }
            Err(err) => {
                if let Err(release_err) = release_result {
                    warn!(err = %release_err, ino, "failed to close temporary read handle");
                }
                Err(err)
            }
        }
    }

    /// Prevent new entries that Windows would treat as the same name.
    fn name_exists_case_insensitive(
        &self,
        parent_ino: u64,
        target_name: &str,
    ) -> Result<bool, FsError> {
        let target_lower = target_name.to_lowercase();
        let iter = self.rt.block_on(self.fs.read_dir(parent_ino))?;

        for entry_result in iter {
            let entry = entry_result?;
            let entry_name = entry.name.expose_secret().to_string();
            if entry_name != "." && entry_name != ".." && entry_name.to_lowercase() == target_lower
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Resolve a path to the parent inode and the final component name.
    /// Returns `(parent_ino, component_name)`.
    fn resolve_parent(&self, path: &str) -> Result<(u64, String), FsError> {
        match split_path(path) {
            None => {
                // Root itself — no parent in this context.
                Err(FsError::InvalidInput("cannot resolve parent of root"))
            }
            Some((parent_path, name)) => {
                let (parent_ino, _parent_attr) = self.resolve_path(parent_path)?;
                Ok((parent_ino, name.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystemContext Implementation
// ---------------------------------------------------------------------------

impl FileSystemContext for EncryptedFsWinFsp {
    type FileContext = WinFspFileContext;

    // -- Required: get_security_by_name --
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = normalize_path(file_name).map_err(fs_err)?;
        trace!(path = %path, "get_security_by_name");

        let (_ino, attr) = self.resolve_path(&path).map_err(fs_err)?;

        let mut attributes = if attr.kind == FileType::Directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        if self.read_only {
            attributes |= FILE_ATTRIBUTE_READONLY;
        }

        // We don't implement Windows ACLs — return no security descriptor.
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
        })
    }

    // -- Required: open --
    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = normalize_path(file_name).map_err(fs_err)?;
        debug!(path = %path, "open");

        let (ino, attr) = self.resolve_path(&path).map_err(fs_err)?;

        let is_dir = attr.kind == FileType::Directory;
        let handle = if is_dir {
            None // Directories don't use file handles in EncryptedFs.
        } else {
            let read = (granted_access & FILE_READ_DATA) != 0;
            let write = (granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
            let (read, write) = if !read && !write {
                (true, false)
            } else {
                (read, write)
            };
            let fh = self
                .rt
                .block_on(self.fs.open(ino, read, write))
                .map_err(fs_err)?;
            Some(fh)
        };

        populate_file_info(file_info.as_mut(), &attr, self.read_only);

        Ok(WinFspFileContext {
            ino,
            is_dir,
            handle: std::sync::Mutex::new(handle),
            path,
            dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
        })
    }

    // -- Required: close --
    fn close(&self, context: Self::FileContext) {
        let handle = context.handle.lock().expect("handle lock poisoned");
        trace!(ino = context.ino, handle = ?*handle, "close");
        if let Some(fh) = *handle {
            if let Err(e) = self.rt.block_on(self.fs.release(fh)) {
                error!(err = %e, ino = context.ino, "failed to release handle on close");
            }
        }
        // `context` is dropped here, freeing resources including DirBuffer.
    }

    // -- create --
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = normalize_path(file_name).map_err(fs_err)?;
        debug!(path = %path, "create");

        let (parent_ino, name) = self.resolve_parent(&path).map_err(fs_err)?;

        let is_dir = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        let kind = if is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        let create_attr = CreateFileAttr {
            kind,
            perm: if is_dir { 0o777 } else { 0o644 },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };

        let read = (granted_access & FILE_READ_DATA) != 0;
        let write = (granted_access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
        let (read, write) = if !is_dir && !read && !write {
            (true, true)
        } else {
            (read, write)
        };
        let _namespace_guard = self
            .namespace_lock
            .lock()
            .map_err(|_| fs_err(FsError::Other("Windows namespace lock poisoned")))?;
        let secret_name = SecretString::from_str(&name)
            .map_err(|_| fs_err(FsError::InvalidInput("invalid path component")))?;
        if self
            .name_exists_case_insensitive(parent_ino, &name)
            .map_err(fs_err)?
        {
            return Err(fs_err(FsError::AlreadyExists));
        }
        let (fh, attr) = self
            .rt
            .block_on(
                self.fs
                    .create(parent_ino, &secret_name, create_attr, read, write),
            )
            .map_err(fs_err)?;

        populate_file_info(file_info.as_mut(), &attr, self.read_only);

        Ok(WinFspFileContext {
            ino: attr.ino,
            is_dir,
            handle: std::sync::Mutex::new(if is_dir { None } else { Some(fh) }),
            path,
            dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
        })
    }

    // -- cleanup --
    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {
        trace!(ino = context.ino, flags, "cleanup");

        // If the delete flag is set, remove the file/directory.
        if (flags & FSP_CLEANUP_DELETE) != 0 {
            let _namespace_guard = match self.namespace_lock.lock() {
                Ok(guard) => guard,
                Err(err) => {
                    error!(err = %err, "cleanup: Windows namespace lock poisoned");
                    return;
                }
            };
            let path = match file_name.map(normalize_path).transpose() {
                Ok(Some(path)) => path,
                Ok(None) => context.path.clone(),
                Err(err) => {
                    error!(err = %err, "cleanup: invalid deletion path");
                    return;
                }
            };

            debug!(path = %path, ino = context.ino, "cleanup: deleting");

            let (parent_ino, name) = match self.resolve_parent(&path) {
                Ok(parent) => parent,
                Err(err) => {
                    error!(err = %err, path = %path, "cleanup: cannot resolve deletion parent");
                    return;
                }
            };
            let (name, ino) = match self.resolve_existing_name(parent_ino, &name) {
                Ok(Some(entry)) => entry,
                Ok(None) => return,
                Err(err) => {
                    error!(err = %err, path = %path, "cleanup: cannot resolve deletion name");
                    return;
                }
            };
            if ino != context.ino {
                warn!(path = %path, expected_ino = context.ino, actual_ino = ino,
                    "cleanup: refusing to delete a different entry at the opened path");
                return;
            }

            // Release the handle first so the file isn't locked.
            {
                let mut handle_guard = context.handle.lock().expect("handle lock poisoned");
                if let Some(fh) = handle_guard.take() {
                    let _ = self.rt.block_on(self.fs.release(fh));
                }
            }

            let secret_name = match SecretString::from_str(&name) {
                Ok(name) => name,
                Err(err) => {
                    error!(err = %err, path = %path, "cleanup: invalid deletion name");
                    return;
                }
            };
            let result = if context.is_dir {
                self.rt
                    .block_on(self.fs.remove_dir(parent_ino, &secret_name))
            } else {
                self.rt
                    .block_on(self.fs.remove_file(parent_ino, &secret_name))
            };
            if let Err(e) = result {
                error!(err = %e, path = %path, "cleanup: delete failed");
            }
        }
    }

    // -- flush --
    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(ctx) = context {
            let handle = ctx.handle.lock().expect("handle lock poisoned");
            trace!(ino = ctx.ino, handle = ?*handle, "flush");

            if let Some(fh) = *handle {
                self.rt.block_on(self.fs.flush(fh)).map_err(fs_err)?;
            }

            // Refresh file info after flush.
            let attr = self
                .rt
                .block_on(self.fs.get_attr(ctx.ino))
                .map_err(fs_err)?;
            populate_file_info(file_info, &attr, self.read_only);
        }
        // Volume flush (context == None): no-op for now.
        Ok(())
    }

    // -- get_file_info --
    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // Use context.ino directly — no path re-walking needed.
        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- get_volume_info (BUG 4 FIX: out-parameter style) --
    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        trace!("get_volume_info");
        // Report a fixed-size volume. These numbers are cosmetic —
        // EncryptedFs doesn't track real disk usage.
        out_volume_info.total_size = 1024 * 1024 * 1024; // 1 GiB
        out_volume_info.free_size = 1024 * 1024 * 1024; // 1 GiB
        out_volume_info.set_volume_label(VOLUME_LABEL);
        Ok(())
    }

    // -- read --
    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let handle = context.handle.lock().expect("handle lock poisoned");
        trace!(ino = context.ino, handle = ?*handle, offset, len = buffer.len(), "read");

        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }

        let fh = handle.ok_or_else(|| {
            error!(ino = context.ino, "read: no file handle");
            winfsp::FspError::from(STATUS_INVALID_HANDLE)
        })?;

        // Drop the MutexGuard before the blocking I/O to avoid holding the
        // lock across the `block_on` call.
        drop(handle);

        // WinFsp can issue a read through a handle that is also open for
        // writing. Commit the pending authenticated block first so reads do
        // not keep seeing the empty/stale reader created at open time.
        let is_read_handle = self.rt.block_on(self.fs.is_read_handle(fh));
        let is_write_handle = self.rt.block_on(self.fs.is_write_handle(fh));
        if is_write_handle {
            self.rt.block_on(self.fs.flush(fh)).map_err(fs_err)?;
        }

        let mut bytes_read = if is_read_handle {
            self.rt
                .block_on(self.fs.read(context.ino, offset, buffer, fh))
                .map_err(fs_err)?
        } else if is_write_handle {
            self.read_with_temporary_handle(context.ino, buffer, offset)
                .map_err(fs_err)?
        } else {
            self.rt
                .block_on(self.fs.read(context.ino, offset, buffer, fh))
                .map_err(fs_err)?
        };

        if bytes_read == 0 && !buffer.is_empty() {
            let attr = self
                .rt
                .block_on(self.fs.get_attr(context.ino))
                .map_err(fs_err)?;
            if offset < attr.size {
                debug!(
                    ino = context.ino,
                    offset, "retrying short read with a fresh handle"
                );
                bytes_read = self
                    .read_with_temporary_handle(context.ino, buffer, offset)
                    .map_err(fs_err)?;
            }
        }

        trace!(
            ino = context.ino,
            handle = fh,
            offset,
            bytes_read,
            "read complete"
        );

        #[allow(clippy::cast_possible_truncation)]
        Ok(bytes_read as u32)
    }

    // -- write --
    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let handle_guard = context.handle.lock().expect("handle lock poisoned");

        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY.into());
        }

        let fh = handle_guard.ok_or_else(|| {
            error!(ino = context.ino, "write: no file handle");
            winfsp::FspError::from(STATUS_INVALID_HANDLE)
        })?;

        // Drop the MutexGuard before the blocking I/O.
        drop(handle_guard);

        let actual_offset = if write_to_eof {
            let attr = self
                .rt
                .block_on(self.fs.get_attr(context.ino))
                .map_err(fs_err)?;
            attr.size
        } else {
            offset
        };

        trace!(
            ino = context.ino,
            handle = fh,
            offset = actual_offset,
            len = buffer.len(),
            "write"
        );

        let bytes_written = self
            .rt
            .block_on(self.fs.write(context.ino, actual_offset, buffer, fh))
            .map_err(fs_err)?;

        // Refresh file info after write.
        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);

        #[allow(clippy::cast_possible_truncation)]
        Ok(bytes_written as u32)
    }

    // -- read_directory (BUGS 1, 2, 3 FIX) --
    //
    // Canonical DirBuffer pattern from the WinFsp C SDK:
    //   1. If marker.is_none() (first call), acquire & fill the DirBuffer.
    //   2. Read from the (already-filled) DirBuffer into the output slice.
    //   3. Return bytes written as u32.
    //
    // The DirBuffer is persisted in the FileContext so it survives across
    // paginated calls. WinFsp handles marker tracking internally.
    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        trace!(ino = context.ino, "read_directory");

        let db = context.dir_buffer.lock().expect("dir_buffer lock poisoned");

        // On first call (marker is none), fill the DirBuffer with all entries.
        // On subsequent calls (marker is Some), the buffer is already populated;
        // FspFileSystemReadDirectoryBuffer handles pagination via the marker.
        if marker.is_none() {
            let iter = self
                .rt
                .block_on(self.fs.read_dir(context.ino))
                .map_err(fs_err)?;

            // Collect all entries, skipping pseudo-entries and errors.
            let mut entries: Vec<(String, u64)> = Vec::new();
            for entry_result in iter {
                match entry_result {
                    Ok(entry) => {
                        let name = entry.name.expose_secret().to_string();
                        if name == "." || name == ".." {
                            continue;
                        }
                        entries.push((name, entry.ino));
                    }
                    Err(e) => {
                        error!(err = %e, "read_directory: entry error, skipping");
                    }
                }
            }

            // Sort deterministically — required for correct marker pagination.
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            // Acquire the DirBuffer with reset=true to clear stale entries.
            let lock = db.acquire(true, None)?;

            for (name, ino) in &entries {
                let attr = match self.rt.block_on(self.fs.get_attr(*ino)) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(err = %e, name = %name, "read_directory: skipping, bad attr");
                        continue;
                    }
                };

                let mut fi = FileInfo::default();
                populate_file_info(&mut fi, &attr, self.read_only);

                let wide_name = match U16CString::from_str(name) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(err = %e, name = %name, "read_directory: invalid encoding");
                        continue;
                    }
                };

                let mut entry = DirInfo::<{ MAX_COMPONENT_LENGTH as usize }>::new();
                *entry.file_info_mut() = fi;
                entry.set_name_cstr(&wide_name)?;

                if lock.write(&mut entry).is_err() {
                    // DirBuffer internal capacity exceeded — unlikely with
                    // reasonable directory sizes, but we handle it gracefully.
                    break;
                }
            }

            // Drop the DirBufferLock (releases the internal SRW write lock).
            drop(lock);
        }

        // Read cached entries from the DirBuffer into the output slice.
        // FspFileSystemReadDirectoryBuffer handles marker-based pagination
        // and returns the number of bytes copied.
        Ok(db.read(marker, buffer))
    }

    // -- set_basic_info --
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        trace!(ino = context.ino, "set_basic_info");

        let mut set_attr = SetFileAttr::default();

        // Only update timestamps that are non-zero (0 means "don't change").
        if creation_time != 0 {
            set_attr = set_attr.with_crtime(filetime_to_system_time(creation_time));
        }
        if last_access_time != 0 {
            set_attr = set_attr.with_atime(filetime_to_system_time(last_access_time));
        }
        if last_write_time != 0 {
            set_attr = set_attr.with_mtime(filetime_to_system_time(last_write_time));
        }
        if change_time != 0 {
            set_attr = set_attr.with_ctime(filetime_to_system_time(change_time));
        }

        self.rt
            .block_on(self.fs.set_attr(context.ino, set_attr))
            .map_err(fs_err)?;

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);

        Ok(())
    }

    // -- set_file_size --
    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        trace!(
            ino = context.ino,
            new_size,
            set_allocation_size,
            "set_file_size"
        );

        if !set_allocation_size {
            // Setting the actual file size (truncate/extend).
            self.rt
                .block_on(self.fs.set_len(context.ino, new_size))
                .map_err(fs_err)?;
        }
        // For allocation_size changes, EncryptedFs handles allocation internally.

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- rename --
    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let old_path = normalize_path(file_name).map_err(fs_err)?;
        let new_path = normalize_path(new_file_name).map_err(fs_err)?;
        debug!(old_path = %old_path, new_path = %new_path, "rename");

        let _namespace_guard = self
            .namespace_lock
            .lock()
            .map_err(|_| fs_err(FsError::Other("Windows namespace lock poisoned")))?;
        let (old_parent_ino, old_name) = self.resolve_parent(&old_path).map_err(fs_err)?;
        let (new_parent_ino, new_name) = self.resolve_parent(&new_path).map_err(fs_err)?;

        let (old_name, old_ino) = self
            .resolve_existing_name(old_parent_ino, &old_name)
            .map_err(fs_err)?
            .ok_or_else(|| fs_err(FsError::NotFound("rename source not found")))?;
        if old_ino != context.ino {
            return Err(fs_err(FsError::NotFound(
                "rename source no longer matches handle",
            )));
        }

        let old_secret = SecretString::from_str(&old_name)
            .map_err(|_| fs_err(FsError::InvalidInput("invalid source name")))?;

        let case_only_rename =
            old_parent_ino == new_parent_ino && old_name.to_lowercase() == new_name.to_lowercase();
        let destination = self
            .resolve_existing_name(new_parent_ino, &new_name)
            .map_err(fs_err)?;
        if !replace_if_exists && !case_only_rename && destination.is_some() {
            return Err(fs_err(FsError::AlreadyExists));
        }

        // The encrypted filesystem is case-sensitive. Pass the existing spelling
        // when replacing an entry so it is removed instead of creating a duplicate.
        let new_name = if !case_only_rename && replace_if_exists {
            destination.map_or(new_name, |(stored_name, _)| stored_name)
        } else {
            new_name
        };
        let new_secret = SecretString::from_str(&new_name)
            .map_err(|_| fs_err(FsError::InvalidInput("invalid destination name")))?;

        self.rt
            .block_on(
                self.fs
                    .rename(old_parent_ino, &old_secret, new_parent_ino, &new_secret),
            )
            .map_err(fs_err)?;

        Ok(())
    }

    // -- set_delete (BUG 7 FIX: replaces non-existent can_delete) --
    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        trace!(ino = context.ino, delete_file, "set_delete");

        if delete_file && context.is_dir {
            // Check if the directory is empty before allowing deletion.
            let len = self.fs.len(context.ino).map_err(fs_err)?;
            if len > 0 {
                return Err(STATUS_DIRECTORY_NOT_EMPTY.into());
            }
        }
        // Regular files can always be flagged for deletion
        // (access checks are done by WinFsp).
        Ok(())
    }

    // -- overwrite (BUG 5 FIX: file_attributes is FILE_FLAGS_AND_ATTRIBUTES) --
    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!(ino = context.ino, "overwrite");

        // Truncate the file to zero.
        self.rt
            .block_on(self.fs.set_len(context.ino, 0))
            .map_err(fs_err)?;

        let attr = self
            .rt
            .block_on(self.fs.get_attr(context.ino))
            .map_err(fs_err)?;
        populate_file_info(file_info, &attr, self.read_only);
        Ok(())
    }

    // -- get_security (optional — we don't implement Windows ACLs) --
    fn get_security(
        &self,
        _context: &Self::FileContext,
        _security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        // We don't track Windows security descriptors. Return 0 = no descriptor.
        Ok(0)
    }

    // -- set_security (BUG 6 FIX: owned ModificationDescriptor, not &) --
    fn set_security(
        &self,
        _context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        // Gracefully report that we don't support Windows ACLs.
        Err(STATUS_NOT_SUPPORTED.into())
    }

    // Note: get_extended_attributes, set_extended_attributes, reparse point
    // methods, set_volume_label, and control all use the default implementation
    // which returns STATUS_INVALID_DEVICE_REQUEST — exactly the right behavior
    // for unsupported operations.
}

// ---------------------------------------------------------------------------
// Validates that the mount point is a valid Windows drive letter (e.g., "Z:").
// For the MVP, only drive letter mounts are supported to avoid complex
// directory junction / reparse point issues.
// ---------------------------------------------------------------------------

fn validate_mount_point(mountpoint: &std::path::Path) -> io::Result<()> {
    let s = mountpoint.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mount point is not valid UTF-8",
        )
    })?;

    let trimmed = s.trim_end_matches('\\');
    if trimmed.len() == 2
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed.as_bytes()[1] == b':'
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("On Windows, mount point must be a drive letter (e.g., Z:). Got: {s}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// MountPointImpl
// ---------------------------------------------------------------------------

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
        validate_mount_point(&self.mountpoint)
            .map_err(|_e| FsError::Other("invalid mount point: expected drive letter like Z:"))?;

        let password_provider = self
            .password_provider
            .take()
            .ok_or(FsError::Other("password provider already consumed"))?;

        info!("Opening encrypted filesystem");
        // Initialize the async core on the caller's runtime. The separate
        // runtime below is only used by WinFsp's synchronous callback threads.
        let fs = EncryptedFs::new(
            self.data_dir.clone(),
            password_provider,
            self.cipher,
            self.read_only,
        )
        .await?;

        let _fsp_init = winfsp::winfsp_init().map_err(|e| {
            error!(err = ?e, "WinFsp initialization failed");
            FsError::Other("WinFsp is unavailable; install WinFsp and retry")
        })?;

        // WinFsp callbacks are synchronous and run on its dispatcher threads.
        let rt = CALLBACK_RUNTIME
            .as_ref()
            .map_err(|_e| FsError::Other("failed to create callback runtime"))?;

        if self.allow_root || self.allow_other {
            warn!("--allow-root and --allow-other have no effect on Windows");
        }

        let context = EncryptedFsWinFsp {
            fs,
            rt,
            read_only: self.read_only,
            namespace_lock: std::sync::Mutex::new(()),
        };

        // Configure WinFsp volume parameters using the builder API.
        let mut volume_params = VolumeParams::new();
        volume_params
            .sector_size(SECTOR_SIZE)
            .volume_serial_number(0x5245_4E43) // "RENC"
            .file_info_timeout(FILE_INFO_TIMEOUT_MS)
            .case_sensitive_search(false) // Windows-style case insensitive
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(false) // We don't implement ACLs
            .reparse_points(false) // No symlinks
            .named_streams(false) // No alternate data streams
            .post_cleanup_when_modified_only(true)
            .filesystem_name("rencfs");

        if self.read_only {
            volume_params.read_only_volume(true);
        }

        let fs_params = FileSystemParams::default_params(volume_params);

        let mount_path = self
            .mountpoint
            .to_str()
            .ok_or(FsError::Other("mount point not valid UTF-8"))?;

        info!(mount_point = %mount_path, "Mounting WinFsp filesystem");

        // Create the FileSystemHost and mount.
        let mut host =
            FileSystemHost::<EncryptedFsWinFsp, FineGuard>::new_with_options(fs_params, context)
                .map_err(|e| {
                    error!(err = ?e, "failed to create FileSystemHost");
                    FsError::Other("failed to create WinFsp FileSystemHost")
                })?;

        host.mount(mount_path).map_err(|e| {
            error!(err = ?e, "failed to mount WinFsp filesystem");
            FsError::Other("failed to mount WinFsp filesystem")
        })?;

        host.start().map_err(|e| {
            error!(err = ?e, "failed to start WinFsp dispatcher");
            FsError::Other("failed to start WinFsp dispatcher")
        })?;

        info!("WinFsp filesystem mounted successfully at {}", mount_path);

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                host: Some(host),
                _fsp_init,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// MountHandleInnerImpl
// ---------------------------------------------------------------------------

pub(in crate::mount) struct MountHandleInnerImpl {
    host: Option<FileSystemHost<EncryptedFsWinFsp, FineGuard>>,
    _fsp_init: winfsp::FspInit,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The WinFsp dispatcher runs in its own threads internally.
        // This future never completes on its own — it waits for explicit unmount.
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        info!("Unmounting WinFsp filesystem");
        if let Some(mut host) = self.host.take() {
            host.stop();
            host.unmount();
        }
        info!("WinFsp filesystem unmounted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_common::{create_attr, get_fs, run_test, TestSetup};
    use std::str::FromStr;

    fn normalize(input: &str) -> Result<String, FsError> {
        let input = U16CString::from_str(input).unwrap();
        normalize_path(&input)
    }

    #[test]
    fn normalizes_windows_paths_and_root() {
        assert_eq!(normalize("\\").unwrap(), "");
        assert_eq!(normalize("\\alpha\\beta").unwrap(), "alpha/beta");
        assert_eq!(normalize("alpha//beta/").unwrap(), "alpha/beta");
    }

    #[test]
    fn rejects_path_components_windows_cannot_represent() {
        for input in [".\\file", "..\\file", "bad:name", "name. ", "CON.txt"] {
            assert!(normalize(input).is_err(), "accepted {input:?}");
        }

        let too_long = format!("{}\\file", "a".repeat(MAX_COMPONENT_LENGTH as usize + 1));
        assert!(normalize(&too_long).is_err());
    }

    #[test]
    fn accepts_only_drive_letter_mount_points() {
        assert!(validate_mount_point(std::path::Path::new("R:")).is_ok());
        assert!(validate_mount_point(std::path::Path::new("r:\\")).is_ok());
        assert!(validate_mount_point(std::path::Path::new("R:\\mount")).is_err());
        assert!(validate_mount_point(std::path::Path::new("RR:")).is_err());
    }

    #[tokio::test]
    async fn create_write_read_and_cleanup_callbacks_round_trip() {
        run_test(
            TestSetup {
                key: "windows_file_callback_round_trip",
                read_only: false,
            },
            async {
                let fs = get_fs().await;
                let name = SecretString::from_str("callback.txt").unwrap();
                let (handle, attr) = fs
                    .create(
                        ROOT_INODE,
                        &name,
                        create_attr(FileType::RegularFile),
                        true,
                        true,
                    )
                    .await
                    .unwrap();
                let callback_fs = fs.clone();
                let path = U16CString::from_str("\\callback.txt").unwrap();
                let expected = b"WinFsp callback round trip";

                let read_back = std::thread::spawn(move || {
                    let bridge = EncryptedFsWinFsp {
                        fs: callback_fs,
                        rt: CALLBACK_RUNTIME.as_ref().unwrap(),
                        read_only: false,
                        namespace_lock: std::sync::Mutex::new(()),
                    };
                    let context = WinFspFileContext {
                        ino: attr.ino,
                        is_dir: false,
                        handle: std::sync::Mutex::new(Some(handle)),
                        path: "callback.txt".to_owned(),
                        dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
                    };

                    let mut file_info = FileInfo::default();
                    assert_eq!(
                        FileSystemContext::write(
                            &bridge,
                            &context,
                            expected,
                            0,
                            false,
                            false,
                            &mut file_info,
                        )
                        .unwrap(),
                        expected.len() as u32
                    );

                    // WinFsp can read before the handle is closed. Commit
                    // pending encrypted bytes and refresh this combined
                    // read/write handle before serving that read.
                    let mut same_handle_buffer = vec![0; expected.len()];
                    assert_eq!(
                        FileSystemContext::read(&bridge, &context, &mut same_handle_buffer, 0,)
                            .unwrap() as usize,
                        expected.len()
                    );
                    assert_eq!(same_handle_buffer, expected);
                    same_handle_buffer.fill(0);
                    assert_eq!(
                        FileSystemContext::read(&bridge, &context, &mut same_handle_buffer, 0,)
                            .unwrap() as usize,
                        expected.len()
                    );
                    assert_eq!(same_handle_buffer, expected);

                    FileSystemContext::flush(&bridge, Some(&context), &mut file_info).unwrap();
                    FileSystemContext::close(&bridge, context);

                    let read_handle = bridge
                        .rt
                        .block_on(bridge.fs.open(attr.ino, true, false))
                        .unwrap();
                    let read_context = WinFspFileContext {
                        ino: attr.ino,
                        is_dir: false,
                        handle: std::sync::Mutex::new(Some(read_handle)),
                        path: "callback.txt".to_owned(),
                        dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
                    };
                    let mut buffer = vec![0; expected.len()];
                    let bytes_read =
                        FileSystemContext::read(&bridge, &read_context, &mut buffer, 0).unwrap();
                    assert_eq!(bytes_read as usize, expected.len());
                    FileSystemContext::close(&bridge, read_context);

                    let delete_context = WinFspFileContext {
                        ino: attr.ino,
                        is_dir: false,
                        handle: std::sync::Mutex::new(None),
                        path: "callback.txt".to_owned(),
                        dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
                    };
                    FileSystemContext::cleanup(
                        &bridge,
                        &delete_context,
                        Some(&path),
                        FSP_CLEANUP_DELETE,
                    );
                    FileSystemContext::close(&bridge, delete_context);
                    buffer
                })
                .join()
                .unwrap();

                assert_eq!(read_back, expected);
                assert!(fs.find_by_name(ROOT_INODE, &name).await.unwrap().is_none());
            },
        )
        .await;
    }

    #[tokio::test]
    async fn cleanup_deletes_case_insensitive_spelling_of_opened_entry() {
        run_test(
            TestSetup {
                key: "windows_cleanup_case_insensitive_name",
                read_only: false,
            },
            async {
                let fs = get_fs().await;
                let stored_name = SecretString::from_str("Report.txt").unwrap();
                let (_, attr) = fs
                    .create(
                        ROOT_INODE,
                        &stored_name,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();
                let path = U16CString::from_str("\\report.txt").unwrap();
                let fs_for_callback = fs.clone();

                std::thread::spawn(move || {
                    let bridge = EncryptedFsWinFsp {
                        fs: fs_for_callback,
                        rt: CALLBACK_RUNTIME.as_ref().unwrap(),
                        read_only: false,
                        namespace_lock: std::sync::Mutex::new(()),
                    };
                    let context = WinFspFileContext {
                        ino: attr.ino,
                        is_dir: false,
                        handle: std::sync::Mutex::new(None),
                        path: "report.txt".to_owned(),
                        dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
                    };
                    FileSystemContext::cleanup(&bridge, &context, Some(&path), FSP_CLEANUP_DELETE);
                })
                .join()
                .unwrap();

                assert!(fs
                    .find_by_name(ROOT_INODE, &stored_name)
                    .await
                    .unwrap()
                    .is_none());
            },
        )
        .await;
    }

    #[tokio::test]
    async fn rename_resolves_case_insensitive_source_to_stored_spelling() {
        run_test(
            TestSetup {
                key: "windows_rename_case_insensitive_name",
                read_only: false,
            },
            async {
                let fs = get_fs().await;
                let stored_name = SecretString::from_str("Report.txt").unwrap();
                let (_, attr) = fs
                    .create(
                        ROOT_INODE,
                        &stored_name,
                        create_attr(FileType::RegularFile),
                        false,
                        false,
                    )
                    .await
                    .unwrap();
                let old_path = U16CString::from_str("\\report.txt").unwrap();
                let new_path = U16CString::from_str("\\Renamed.txt").unwrap();
                let fs_for_callback = fs.clone();

                std::thread::spawn(move || {
                    let bridge = EncryptedFsWinFsp {
                        fs: fs_for_callback,
                        rt: CALLBACK_RUNTIME.as_ref().unwrap(),
                        read_only: false,
                        namespace_lock: std::sync::Mutex::new(()),
                    };
                    let context = WinFspFileContext {
                        ino: attr.ino,
                        is_dir: false,
                        handle: std::sync::Mutex::new(None),
                        path: "Report.txt".to_owned(),
                        dir_buffer: std::sync::Mutex::new(DirBuffer::new()),
                    };
                    FileSystemContext::rename(&bridge, &context, &old_path, &new_path, false)
                })
                .join()
                .unwrap()
                .unwrap();

                assert!(fs
                    .find_by_name(ROOT_INODE, &stored_name)
                    .await
                    .unwrap()
                    .is_none());
                let renamed = SecretString::from_str("Renamed.txt").unwrap();
                assert_eq!(
                    fs.find_by_name(ROOT_INODE, &renamed)
                        .await
                        .unwrap()
                        .unwrap()
                        .ino,
                    attr.ino
                );
            },
        )
        .await;
    }
}
