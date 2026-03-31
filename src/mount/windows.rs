//! Windows mount implementation using WinFSP
//!
//! This module provides Windows-specific mounting functionality using the WinFSP
//! (Windows File System Proxy) library, which provides a FUSE-like interface for
//! implementing file systems on Windows.
//!
//! WinFSP is released under the GNU GPLv3 license. For commercial licensing,
//! see: https://winfsp.dev/

use std::ffi::OsStr;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::FutureExt;
use shush_rs::{ExposeSecret, SecretString};
use tracing::{debug, error, info, warn};
use winfsp::filesystem::{FileInfo, OpenFileInfo};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::util::U16CString;

use crate::crypto::Cipher;
use crate::encryptedfs::{EncryptedFs, FileAttr, FileType, FsResult, PasswordProvider};
use crate::mount::{MountHandleInner, MountPoint};

/// Windows-specific file context representing an open file or directory
#[derive(Debug)]
pub struct WinFileContext {
    /// Inode number in the encrypted filesystem
    pub ino: u64,
    /// Whether this is a directory
    pub is_dir: bool,
    /// Current position for directory enumeration
    pub dir_position: u64,
    /// File handle for operations that need it
    pub fh: Option<u64>,
}

impl WinFileContext {
    pub fn new(ino: u64, is_dir: bool) -> Self {
        Self {
            ino,
            is_dir,
            dir_position: 0,
            fh: None,
        }
    }
}

/// Windows implementation of the encrypted filesystem using WinFSP
#[derive(Debug)]
pub struct EncryptedFsWinFsp {
    /// The underlying encrypted filesystem
    fs: Arc<EncryptedFs>,
    /// Whether the filesystem is read-only
    read_only: bool,
}

impl EncryptedFsWinFsp {
    /// Create a new WinFSP-wrapped encrypted filesystem
    pub async fn new(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<Self> {
        let fs = EncryptedFs::new(data_dir, password_provider, cipher, read_only).await?;
        Ok(Self { fs: Arc::new(fs), read_only })
    }

    /// Get the underlying encrypted filesystem
    pub fn get_fs(&self) -> Arc<EncryptedFs> {
        self.fs.clone()
    }

    /// Check if filesystem is read-only
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
}

impl winfsp::filesystem::FileSystemContext for EncryptedFsWinFsp {
    type FileContext = WinFileContext;

    fn get_security_by_name(
        &self,
        file_name: &[u16],
        _security_descriptor: Option<&mut std::ffi::c_void>,
        _reparse_point_resolver: impl FnOnce(&[u16]) -> Option<winfsp::filesystem::FileSecurity>,
    ) -> winfsp::Result<winfsp::filesystem::FileSecurity> {
        info!("get_security_by_name: {:?}", String::from_utf16_lossy(file_name));
        // For simplicity, return a default security descriptor
        Ok(winfsp::filesystem::FileSecurity::new(
            0, // owner
            0, // group
            0, // dacl (null DACL - full access)
        ))
    }

    fn open(
        &self,
        file_name: &[u16],
        _create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let file_name_str = String::from_utf16_lossy(file_name);
        debug!("open: {} (access: {:#x})", file_name_str, granted_access);

        // For root directory
        if file_name_str.is_empty() || file_name_str == "\\" || file_name_str == "/" {
            file_info.set_file_attributes(winfsp::filesystem::FILE_ATTRIBUTE_DIRECTORY);
            return Ok(WinFileContext::new(crate::encryptedfs::ROOT_INODE, true));
        }

        // Strip leading backslash if present
        let name = file_name_str.trim_start_matches('\\').trim_start_matches('/');

        // Parse the path to get parent and filename
        let parts: Vec<&str> = name.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            // Root
            file_info.set_file_attributes(winfsp::filesystem::FILE_ATTRIBUTE_DIRECTORY);
            return Ok(WinFileContext::new(crate::encryptedfs::ROOT_INODE, true));
        }

        let rt = tokio::runtime::Handle::current();
        let fs = self.fs.clone();
        let parent_ino = crate::encryptedfs::ROOT_INODE;
        let file_name_secret = SecretString::from_str(name).map_err(|_| winfsp::Error::Other("Invalid filename"))?;

        // Lookup the file
        let result = rt.block_on(async {
            fs.find_by_name(parent_ino, &file_name_secret).await
        });

        match result {
            Ok(Some(attr)) => {
                file_info.set_file_attributes(file_type_to_winattr(attr.kind));
                let is_dir = attr.kind == FileType::Directory;

                // If opening for read/write, get a handle
                let fh = if !is_dir {
                    let rt2 = tokio::runtime::Handle::current();
                    let fs2 = fs.clone();
                    let open_result = rt2.block_on(async {
                        let read = granted_access & 0x80000000 != 0 || granted_access & 0x40000000 != 0; // GENERIC_READ
                        let write = granted_access & 0x80000000 != 0 || granted_access & 0x20000000 != 0; // GENERIC_WRITE
                        if read || write {
                            fs2.open(attr.ino, read, write).await.ok()
                        } else {
                            None
                        }
                    });
                    open_result
                } else {
                    None
                };

                Ok(WinFileContext {
                    ino: attr.ino,
                    is_dir,
                    dir_position: 0,
                    fh,
                })
            }
            Ok(None) => Err(winfsp::Error::Other("File not found")),
            Err(e) => {
                error!("lookup error: {:?}", e);
                Err(winfsp::Error::Other("Lookup failed"))
            }
        }
    }

    fn close(&self, context: Self::FileContext) {
        debug!("close: inode={}", context.ino);
        // Release file handle if open
        if let Some(fh) = context.fh {
            let rt = tokio::runtime::Handle::current();
            let fs = self.fs.clone();
            rt.block_on(async {
                if let Err(e) = fs.release(fh).await {
                    error!("release error: {:?}", e);
                }
            });
        }
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!("get_file_info: inode={}", context.ino);

        let rt = tokio::runtime::Handle::current();
        let fs = self.fs.clone();
        let ino = context.ino;

        let result = rt.block_on(async { fs.get_attr(ino).await });

        match result {
            Ok(attr) => {
                *file_info = file_attr_to_file_info(attr, &context.ino);
                Ok(())
            }
            Err(e) => {
                error!("get_file_info error: {:?}", e);
                Err(winfsp::Error::Other("Failed to get file info"))
            }
        }
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        debug!(
            "read: inode={}, offset={}, size={}",
            context.ino,
            offset,
            buffer.len()
        );

        if context.is_dir {
            return Err(winfsp::Error::Other("Cannot read from directory"));
        }

        // Ensure we have a file handle
        let fh = match context.fh {
            Some(fh) => fh,
            None => {
                // Try to open for reading
                let rt = tokio::runtime::Handle::current();
                let fs = self.fs.clone();
                match rt.block_on(async { fs.open(context.ino, true, false).await }) {
                    Ok(fh) => fh,
                    Err(e) => {
                        error!("open for read error: {:?}", e);
                        return Err(winfsp::Error::Other("Failed to open file for reading"));
                    }
                }
            }
        };

        let rt = tokio::runtime::Handle::current();
        let fs = self.fs.clone();

        let result = rt.block_on(async {
            let mut buf = vec![0u8; buffer.len()];
            let read_len = fs.read(context.ino, offset, &mut buf, fh).await.map_err(|e| {
                error!("read error: {:?}", e);
                winfsp::Error::Other("Read failed")
            })?;

            // Copy to output buffer
            buffer[..read_len].copy_from_slice(&buf[..read_len]);
            Ok::<_, winfsp::Error>(read_len)
        });

        result
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
        debug!(
            "write: inode={}, offset={}, size={}",
            context.ino,
            offset,
            buffer.len()
        );

        if self.read_only {
            return Err(winfsp::Error::Other("Filesystem is read-only"));
        }

        if context.is_dir {
            return Err(winfsp::Error::Other("Cannot write to directory"));
        }

        // Ensure we have a file handle open for writing
        let fh = match context.fh {
            Some(fh) => fh,
            None => {
                let rt = tokio::runtime::Handle::current();
                let fs = self.fs.clone();
                match rt.block_on(async { fs.open(context.ino, false, true).await }) {
                    Ok(fh) => fh,
                    Err(e) => {
                        error!("open for write error: {:?}", e);
                        return Err(winfsp::Error::Other("Failed to open file for writing"));
                    }
                }
            }
        };

        let rt = tokio::runtime::Handle::current();
        let fs = self.fs.clone();
        let ino = context.ino;

        let result = rt.block_on(async {
            fs.write(ino, offset, buffer, fh).await.map_err(|e| {
                error!("write error: {:?}", e);
                winfsp::Error::Other("Write failed")
            })
        });

        match result {
            Ok(len) => {
                // Update file info with new size
                if let Ok(attr) = rt.block_on(async { fs.get_attr(ino).await }) {
                    *file_info = file_attr_to_file_info(attr, &ino);
                }
                Ok(len as u32)
            }
            Err(e) => Err(e),
        }
    }

    fn get_volume_info(
        &self,
        out_volume_info: &mut winfsp::filesystem::VolumeInfo,
    ) -> winfsp::Result<()> {
        debug!("get_volume_info");
        out_volume_info.set_total_size(0);
        out_volume_info.set_free_size(0);
        out_volume_info.set_volume_label("rencfs".into());
        Ok(())
    }

    fn cleanup(
        &self,
        context: &Self::FileContext,
        _file_name: Option<&[u16]>,
        _flags: u32,
    ) {
        debug!("cleanup: inode={}", context.ino);
        // Note: we don't close the handle here because close() will be called separately
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!("flush: context={:?}", context.map(|c| c.ino));
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!("set_file_size: inode={}, size={}", context.ino, new_size);

        if self.read_only {
            return Err(winfsp::Error::Other("Filesystem is read-only"));
        }

        let rt = tokio::runtime::Handle::current();
        let fs = self.fs.clone();
        let ino = context.ino;

        match rt.block_on(async { fs.set_len(ino, new_size).await }) {
            Ok(()) => {
                // Update file info
                if let Ok(attr) = rt.block_on(async { fs.get_attr(ino).await }) {
                    *file_info = file_attr_to_file_info(attr, &ino);
                }
                Ok(())
            }
            Err(e) => {
                error!("set_file_size error: {:?}", e);
                Err(winfsp::Error::Other("Failed to set file size"))
            }
        }
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &[u16],
        new_file_name: &[u16],
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        debug!(
            "rename: inode={}, name={:?}, new_name={:?}, replace={}",
            context.ino,
            String::from_utf16_lossy(file_name),
            String::from_utf16_lossy(new_file_name),
            replace_if_exists
        );

        if self.read_only {
            return Err(winfsp::Error::Other("Filesystem is read-only"));
        }

        // TODO: Implement rename using self.fs.rename()
        Err(winfsp::Error::Other("Rename not yet implemented"))
    }

    fn delete(
        &self,
        context: &Self::FileContext,
        _file_name: &[u16],
        _delete_file: bool,
    ) -> winfsp::Result<()> {
        debug!("delete: inode={}", context.ino);

        if self.read_only {
            return Err(winfsp::Error::Other("Filesystem is read-only"));
        }

        // TODO: Implement delete using self.fs.remove_file() or self.fs.remove_dir()
        Err(winfsp::Error::Other("Delete not yet implemented"))
    }
}

/// Convert a SecretString filename to a wide string for WinFSP
fn secret_to_wide(name: &SecretString) -> U16CString {
    let s = name.expose_secret();
    U16CString::from_str(s).unwrap_or_else(|_| U16CString::from_str("*").unwrap())
}

/// Convert FileType to WinFSP file attributes
fn file_type_to_winattr(kind: FileType) -> u32 {
    match kind {
        FileType::Directory => winfsp::filesystem::FILE_ATTRIBUTE_DIRECTORY,
        FileType::RegularFile => 0,
    }
}

/// Convert SystemTime to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
fn system_time_to_filetime(time: std::time::SystemTime) -> u64 {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Windows FILETIME is relative to 1601-01-01, Unix to 1970-01-01
    // 116444736000000000 = seconds between 1601 and 1970 * 10_000_000
    const WINDOWS_TICK: u64 = 10_000_000;
    const SECS_TO_1601: u64 = 11644473600;
    (duration.as_secs() + SECS_TO_1601) * WINDOWS_TICK + (duration.subsec_nanos() as u64 / 100)
}

/// Convert FileAttr to WinFSP FileInfo
fn file_attr_to_file_info(attr: FileAttr, _ino: &u64) -> FileInfo {
    let file_attributes = file_type_to_winattr(attr.kind);
    let reparse_tag = 0; // Not a reparse point

    FileInfo::new(
        attr.ino,
        file_attributes,
        attr.size,
        0, // allocation_size (we don't use this)
        system_time_to_filetime(attr.ctime),
        system_time_to_filetime(attr.mtime),
        system_time_to_filetime(attr.atime),
        system_time_to_filetime(attr.crtime),
        reparse_tag,
    )
}

/// Mount point implementation for Windows
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

    async fn mount(mut self) -> FsResult<crate::mount::MountHandle> {
        let fs = EncryptedFsWinFsp::new(
            self.data_dir.clone(),
            self.password_provider.take().unwrap(),
            self.cipher,
            self.read_only,
        )
        .await?;

        // Configure volume parameters
        let mut params = VolumeParams::new();
        params.set_file_system_name("rencfs");
        params.set_volume_label("rencfs");
        params.set_case_sensitive(false); // Windows is case-insensitive
        params.set_read_only(self.read_only);

        // Create the filesystem host
        let host = FileSystemHost::new(params, fs).map_err(|e| {
            error!("Failed to create filesystem host: {:?}", e);
            crate::encryptedfs::FsError::Other("Failed to create filesystem host")
        })?;

        Ok(crate::mount::MountHandle {
            inner: MountHandleInnerImpl {
                inner: Some(host),
                mountpoint: self.mountpoint,
            },
        })
    }
}

/// Handle for the mounted Windows filesystem
pub struct MountHandleInnerImpl {
    /// The WinFSP filesystem host
    inner: Option<FileSystemHost<EncryptedFsWinFsp>>,
    /// The mountpoint path
    mountpoint: PathBuf,
}

impl Future for MountHandleInnerImpl {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The filesystem runs in a separate thread managed by WinFSP
        // We just wait for the inner future to complete
        if self.inner.is_some() {
            // Keep the filesystem running
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> std::io::Result<()> {
        info!("Unmounting Windows filesystem");
        if let Some(mut host) = self.inner.take() {
            host.stop();
        }
        Ok(())
    }
}
