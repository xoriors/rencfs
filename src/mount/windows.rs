#[cfg(target_os = "windows")]
use std::future::Future;
#[cfg(target_os = "windows")]
use std::io;
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "windows")]
use async_trait::async_trait;
use shush_rs::{ExposeSecret, SecretString};
#[cfg(target_os = "windows")]
use tracing::info;

use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
    ROOT_INODE,
};
#[cfg(target_os = "windows")]
use crate::mount::{self, MountHandleInner, MountPoint};

/// Seconds between Windows FILETIME epoch (1601-01-01 UTC) and Unix epoch (1970-01-01 UTC).
pub const WINDOWS_EPOCH_OFFSET_SECS: u64 = 11_644_473_600;
/// 100-nanosecond intervals per second.
pub const HNS_PER_SEC: u64 = 10_000_000;

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
pub const STATUS_DISK_FULL: u32 = 0xC000_007F;
pub const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub const STATUS_UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;

/// Convert `SystemTime` to a 64-bit Windows `FILETIME` (100ns ticks since 1601-01-01 UTC).
#[must_use]
pub fn system_time_to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs().saturating_add(WINDOWS_EPOCH_OFFSET_SECS);
            let subsec_hns = u64::from(dur.subsec_nanos() / 100);
            secs.saturating_mul(HNS_PER_SEC).saturating_add(subsec_hns)
        }
        Err(_) => WINDOWS_EPOCH_OFFSET_SECS * HNS_PER_SEC,
    }
}

/// Convert a 64-bit Windows `FILETIME` back to `SystemTime`.
#[must_use]
pub fn filetime_to_system_time(filetime: u64) -> SystemTime {
    let total_secs = filetime / HNS_PER_SEC;
    let subsec_nanos = ((filetime % HNS_PER_SEC) * 100) as u32;
    if total_secs >= WINDOWS_EPOCH_OFFSET_SECS {
        UNIX_EPOCH + Duration::new(total_secs - WINDOWS_EPOCH_OFFSET_SECS, subsec_nanos)
    } else {
        UNIX_EPOCH
    }
}

/// Map `FsError` variants to canonical Windows `NTSTATUS` codes expected by WinFsp callbacks.
#[must_use]
pub const fn fs_error_to_ntstatus(err: &FsError) -> u32 {
    match err {
        FsError::NotFound(_) | FsError::InodeNotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        FsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        FsError::AlreadyOpenForWrite => STATUS_SHARING_VIOLATION,
        FsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        FsError::ReadOnly => STATUS_MEDIA_WRITE_PROTECTED,
        FsError::InvalidInodeType => STATUS_FILE_IS_A_DIRECTORY,
        FsError::InvalidInput(_) => STATUS_OBJECT_NAME_INVALID,
        FsError::InvalidFileHandle => STATUS_INVALID_PARAMETER,
        FsError::MaxFilesizeExceeded(_) => STATUS_DISK_FULL,
        FsError::InvalidPassword => STATUS_ACCESS_DENIED,
        _ => STATUS_UNEXPECTED_IO_ERROR,
    }
}

fn is_reserved_dos_device_name(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
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
    )
}

/// Validate and split a Windows WinFsp path (such as `\`, `\dir\file.txt`, or `/dir/file.txt`)
/// into normalized path components.
pub fn normalize_windows_path(path: &str) -> FsResult<Vec<String>> {
    let trimmed = path.trim_matches(|c| c == '\\' || c == '/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let mut segments = Vec::new();
    for raw_seg in trimmed.split(['\\', '/']) {
        if raw_seg.is_empty() || raw_seg == "." {
            continue;
        }
        if raw_seg == ".." {
            return Err(FsError::InvalidInput("parent traversal is not allowed"));
        }
        if raw_seg.ends_with(' ') || raw_seg.ends_with('.') {
            return Err(FsError::InvalidInput(
                "Windows filenames cannot end with a space or period",
            ));
        }
        if raw_seg
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') || c.is_control())
        {
            return Err(FsError::InvalidInput(
                "Windows path contains reserved characters",
            ));
        }
        let stem = raw_seg.split('.').next().unwrap_or(raw_seg);
        if is_reserved_dos_device_name(stem) {
            return Err(FsError::InvalidInput(
                "Windows path uses a reserved DOS device name",
            ));
        }
        segments.push(raw_seg.to_owned());
    }
    Ok(segments)
}

/// WinFsp-compatible file metadata representation mapped from `FileAttr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinFspFileInfo {
    pub file_attributes: u32,
    pub file_size: u64,
    pub allocation_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
}

impl WinFspFileInfo {
    #[must_use]
    pub fn from_attr(attr: &FileAttr, read_only: bool) -> Self {
        let mut file_attributes = match attr.kind {
            FileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
            FileType::RegularFile => FILE_ATTRIBUTE_ARCHIVE,
        };
        if read_only || (attr.perm & 0o222) == 0 {
            file_attributes |= FILE_ATTRIBUTE_READONLY;
        }
        if file_attributes == 0 {
            file_attributes = FILE_ATTRIBUTE_NORMAL;
        }
        let alloc_unit = 4096_u64;
        let allocation_size = if attr.kind == FileType::Directory || attr.size == 0 {
            0
        } else {
            attr.size.div_ceil(alloc_unit) * alloc_unit
        };
        Self {
            file_attributes,
            file_size: if attr.kind == FileType::Directory {
                0
            } else {
                attr.size
            },
            allocation_size,
            creation_time: system_time_to_filetime(attr.crtime),
            last_access_time: system_time_to_filetime(attr.atime),
            last_write_time: system_time_to_filetime(attr.mtime),
            change_time: system_time_to_filetime(attr.ctime),
            index_number: attr.ino,
        }
    }
}

/// Per-open handle context corresponding to `FileSystemContext::FileContext` in WinFsp.
#[derive(Debug)]
pub struct WinFspOpenContext {
    pub ino: u64,
    pub fh: Option<u64>,
    pub is_dir: bool,
    pub parent_ino: u64,
    pub leaf_name: Option<SecretString>,
    pub delete_on_close: AtomicBool,
}

impl WinFspOpenContext {
    pub fn set_delete_on_close(&self, delete: bool) {
        self.delete_on_close.store(delete, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_delete_on_close(&self) -> bool {
        self.delete_on_close.load(Ordering::SeqCst)
    }
}

/// Bridge adapting path-addressed Windows WinFsp callbacks onto inode-addressed `EncryptedFs`.
pub struct EncryptedFsWinFspBridge {
    fs: Arc<EncryptedFs>,
    read_only: bool,
}

impl EncryptedFsWinFspBridge {
    pub async fn new(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<Self> {
        let fs = EncryptedFs::new(data_dir, password_provider, cipher, read_only).await?;
        Ok(Self { fs, read_only })
    }

    #[must_use]
    pub const fn from_fs(fs: Arc<EncryptedFs>, read_only: bool) -> Self {
        Self { fs, read_only }
    }

    #[must_use]
    pub fn fs(&self) -> Arc<EncryptedFs> {
        Arc::clone(&self.fs)
    }

    /// Resolve a Windows path (`\a\b\c`) to `(parent_ino, leaf_name, FileAttr)`.
    pub async fn resolve_entry(
        &self,
        path: &str,
    ) -> FsResult<(u64, Option<SecretString>, FileAttr)> {
        let segments = normalize_windows_path(path)?;
        if segments.is_empty() {
            let root_attr = self.fs.get_attr(ROOT_INODE).await?;
            return Ok((ROOT_INODE, None, root_attr));
        }

        let mut cur_ino = ROOT_INODE;
        let mut parent_ino = ROOT_INODE;
        let mut last_name: Option<SecretString> = None;
        let mut last_attr: Option<FileAttr> = None;

        for (idx, seg) in segments.iter().enumerate() {
            let secret_seg =
                SecretString::from_str(seg).map_err(|_| FsError::InvalidInput("invalid path"))?;
            let found = self
                .fs
                .find_by_name(cur_ino, &secret_seg)
                .await?
                .ok_or(FsError::InodeNotFound)?;
            if idx + 1 < segments.len() && found.kind != FileType::Directory {
                return Err(FsError::InvalidInodeType);
            }
            parent_ino = cur_ino;
            cur_ino = found.ino;
            last_name = Some(secret_seg);
            last_attr = Some(found);
        }

        Ok((
            parent_ino,
            last_name,
            last_attr.ok_or(FsError::InodeNotFound)?,
        ))
    }

    /// Resolve parent directory inode and leaf name for creating a new file/directory.
    pub async fn resolve_parent_and_leaf(&self, path: &str) -> FsResult<(u64, SecretString)> {
        let segments = normalize_windows_path(path)?;
        let (leaf, parents) = segments
            .split_last()
            .ok_or(FsError::InvalidInput("cannot create root path"))?;

        let mut cur_ino = ROOT_INODE;
        for seg in parents {
            let secret_seg =
                SecretString::from_str(seg).map_err(|_| FsError::InvalidInput("invalid path"))?;
            let attr = self
                .fs
                .find_by_name(cur_ino, &secret_seg)
                .await?
                .ok_or(FsError::InodeNotFound)?;
            if attr.kind != FileType::Directory {
                return Err(FsError::InvalidInodeType);
            }
            cur_ino = attr.ino;
        }
        let secret_leaf =
            SecretString::from_str(leaf).map_err(|_| FsError::InvalidInput("invalid leaf"))?;
        Ok((cur_ino, secret_leaf))
    }

    pub async fn get_file_info(&self, path: &str) -> FsResult<WinFspFileInfo> {
        let (_, _, attr) = self.resolve_entry(path).await?;
        Ok(WinFspFileInfo::from_attr(&attr, self.read_only))
    }

    pub async fn open_path(
        &self,
        path: &str,
        read: bool,
        write: bool,
    ) -> FsResult<(WinFspOpenContext, WinFspFileInfo)> {
        if write && self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (parent_ino, leaf_name, attr) = self.resolve_entry(path).await?;
        let is_dir = attr.kind == FileType::Directory;
        let fh = if is_dir {
            None
        } else {
            Some(self.fs.open(attr.ino, read, write).await?)
        };
        let info = WinFspFileInfo::from_attr(&attr, self.read_only);
        Ok((
            WinFspOpenContext {
                ino: attr.ino,
                fh,
                is_dir,
                parent_ino,
                leaf_name,
                delete_on_close: AtomicBool::new(false),
            },
            info,
        ))
    }

    pub async fn create_path(
        &self,
        path: &str,
        is_dir: bool,
        read: bool,
        write: bool,
    ) -> FsResult<(WinFspOpenContext, WinFspFileInfo)> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (parent_ino, leaf_name) = self.resolve_parent_and_leaf(path).await?;
        let create_attr = CreateFileAttr {
            kind: if is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if is_dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        };
        let (fh, attr) = self
            .fs
            .create(
                parent_ino,
                &leaf_name,
                create_attr,
                if is_dir { false } else { read },
                if is_dir { false } else { write },
            )
            .await?;
        let info = WinFspFileInfo::from_attr(&attr, self.read_only);
        Ok((
            WinFspOpenContext {
                ino: attr.ino,
                fh: if is_dir { None } else { Some(fh) },
                is_dir,
                parent_ino,
                leaf_name: Some(leaf_name),
                delete_on_close: AtomicBool::new(false),
            },
            info,
        ))
    }

    pub async fn read_context(
        &self,
        ctx: &WinFspOpenContext,
        offset: u64,
        buf: &mut [u8],
    ) -> FsResult<usize> {
        let fh = ctx.fh.ok_or(FsError::InvalidFileHandle)?;
        self.fs.read(ctx.ino, offset, buf, fh).await
    }

    pub async fn write_context(
        &self,
        ctx: &WinFspOpenContext,
        offset: u64,
        buf: &[u8],
    ) -> FsResult<usize> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let fh = ctx.fh.ok_or(FsError::InvalidFileHandle)?;
        self.fs.write(ctx.ino, offset, buf, fh).await
    }

    pub async fn flush_context(&self, ctx: &WinFspOpenContext) -> FsResult<()> {
        if let Some(fh) = ctx.fh {
            self.fs.flush(fh).await?;
        }
        Ok(())
    }

    pub async fn close_context(&self, ctx: WinFspOpenContext) -> FsResult<()> {
        if let Some(fh) = ctx.fh {
            self.fs.flush(fh).await?;
            self.fs.release(fh).await?;
        }
        if ctx.is_delete_on_close() {
            if let Some(ref leaf) = ctx.leaf_name {
                if ctx.is_dir {
                    self.fs.remove_dir(ctx.parent_ino, leaf).await?;
                } else {
                    self.fs.remove_file(ctx.parent_ino, leaf).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn read_directory(&self, path: &str) -> FsResult<Vec<(String, WinFspFileInfo)>> {
        let (_, _, dir_attr) = self.resolve_entry(path).await?;
        if dir_attr.kind != FileType::Directory {
            return Err(FsError::InvalidInodeType);
        }
        let iter = self.fs.read_dir_plus(dir_attr.ino).await?;
        let mut entries = Vec::new();
        for item in iter {
            let entry = item?;
            let name = entry.name.expose_secret().to_owned();
            entries.push((name, WinFspFileInfo::from_attr(&entry.attr, self.read_only)));
        }
        Ok(entries)
    }

    pub async fn rename_path(
        &self,
        old_path: &str,
        new_path: &str,
        replace_if_exists: bool,
    ) -> FsResult<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (old_parent, old_leaf) = self.resolve_parent_and_leaf(old_path).await?;
        let (new_parent, new_leaf) = self.resolve_parent_and_leaf(new_path).await?;
        if !replace_if_exists && self.fs.exists_by_name(new_parent, &new_leaf)? {
            return Err(FsError::AlreadyExists);
        }
        self.fs
            .rename(old_parent, &old_leaf, new_parent, &new_leaf)
            .await
    }

    pub async fn remove_path(&self, path: &str) -> FsResult<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (parent_ino, leaf_opt, attr) = self.resolve_entry(path).await?;
        let leaf = leaf_opt.ok_or(FsError::InvalidInput("cannot remove root directory"))?;
        if attr.kind == FileType::Directory {
            self.fs.remove_dir(parent_ino, &leaf).await
        } else {
            self.fs.remove_file(parent_ino, &leaf).await
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(clippy::struct_excessive_bools)]
#[allow(dead_code)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
}

#[cfg(target_os = "windows")]
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
        let password_provider = self
            .password_provider
            .take()
            .ok_or(FsError::InvalidInput("missing password provider"))?;
        let bridge = EncryptedFsWinFspBridge::new(
            self.data_dir.clone(),
            password_provider,
            self.cipher,
            self.read_only,
        )
        .await?;
        info!(
            mountpoint = %self.mountpoint.display(),
            "Initialized Windows EncryptedFsWinFspBridge for mountpoint"
        );
        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl {
                _bridge: Arc::new(bridge),
            },
        })
    }
}

#[cfg(target_os = "windows")]
pub(in crate::mount) struct MountHandleInnerImpl {
    _bridge: Arc<EncryptedFsWinFspBridge>,
}

#[cfg(target_os = "windows")]
impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shush_rs::SecretString;
    use tempfile::tempdir;

    struct StaticPasswordProvider;
    impl PasswordProvider for StaticPasswordProvider {
        fn get_password(&self) -> Option<SecretString> {
            SecretString::from_str("test-windows-bridge-password").ok()
        }
    }

    #[test]
    fn test_filetime_roundtrip() {
        let sample = UNIX_EPOCH + Duration::from_secs(1_722_361_586);
        let ft = system_time_to_filetime(sample);
        let restored = filetime_to_system_time(ft);
        assert_eq!(restored, sample);
    }

    #[test]
    fn test_windows_path_validation() {
        assert_eq!(
            normalize_windows_path(r"\docs\sub\readme.txt").unwrap(),
            vec!["docs", "sub", "readme.txt"]
        );
        assert!(normalize_windows_path(r"\").unwrap().is_empty());
        assert!(normalize_windows_path(r"\docs\..\secret").is_err());
        assert!(normalize_windows_path(r"\docs\CON.txt").is_err());
        assert!(normalize_windows_path(r"\docs\bad:stream").is_err());
        assert!(normalize_windows_path(r"\docs\trailing.").is_err());
    }

    #[test]
    fn test_ntstatus_mapping() {
        assert_eq!(
            fs_error_to_ntstatus(&FsError::InodeNotFound),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            fs_error_to_ntstatus(&FsError::AlreadyExists),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            fs_error_to_ntstatus(&FsError::NotEmpty),
            STATUS_DIRECTORY_NOT_EMPTY
        );
        assert_eq!(
            fs_error_to_ntstatus(&FsError::ReadOnly),
            STATUS_MEDIA_WRITE_PROTECTED
        );
    }

    #[tokio::test]
    async fn test_windows_bridge_end_to_end_lifecycle() {
        let data_dir = tempdir().unwrap();
        let bridge = EncryptedFsWinFspBridge::new(
            data_dir.path().to_path_buf(),
            Box::new(StaticPasswordProvider),
            Cipher::ChaCha20Poly1305,
            false,
        )
        .await
        .unwrap();

        // 1. Create directory \projects
        let (dir_ctx, dir_info) = bridge
            .create_path(r"\projects", true, false, false)
            .await
            .unwrap();
        assert_eq!(
            dir_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_DIRECTORY
        );
        bridge.close_context(dir_ctx).await.unwrap();

        // 2. Create file \projects\notes.txt and write encrypted payload
        let (file_ctx, _) = bridge
            .create_path(r"\projects\notes.txt", false, true, true)
            .await
            .unwrap();
        let payload = b"rencfs WinFsp encrypted content on Windows";
        let written = bridge.write_context(&file_ctx, 0, payload).await.unwrap();
        assert_eq!(written, payload.len());
        bridge.flush_context(&file_ctx).await.unwrap();
        bridge.close_context(file_ctx).await.unwrap();

        // 3. Re-open and read back
        let (read_ctx, info) = bridge
            .open_path(r"\projects\notes.txt", true, false)
            .await
            .unwrap();
        assert_eq!(info.file_size, payload.len() as u64);
        let mut buf = vec![0_u8; payload.len()];
        let read_bytes = bridge.read_context(&read_ctx, 0, &mut buf).await.unwrap();
        assert_eq!(read_bytes, payload.len());
        assert_eq!(&buf[..], payload);
        bridge.close_context(read_ctx).await.unwrap();

        // 4. Enumerate directory \projects
        let entries = bridge.read_directory(r"\projects").await.unwrap();
        assert!(entries.iter().any(|(name, _)| name == "notes.txt"));

        // 5. Rename \projects\notes.txt -> \projects\renamed.txt
        bridge
            .rename_path(r"\projects\notes.txt", r"\projects\renamed.txt", false)
            .await
            .unwrap();
        assert!(bridge.get_file_info(r"\projects\notes.txt").await.is_err());
        let renamed_info = bridge.get_file_info(r"\projects\renamed.txt").await.unwrap();
        assert_eq!(renamed_info.file_size, payload.len() as u64);

        // 6. Delete-on-close semantics
        let (del_ctx, _) = bridge
            .open_path(r"\projects\renamed.txt", true, true)
            .await
            .unwrap();
        del_ctx.set_delete_on_close(true);
        bridge.close_context(del_ctx).await.unwrap();
        assert!(bridge.get_file_info(r"\projects\renamed.txt").await.is_err());
    }
}
