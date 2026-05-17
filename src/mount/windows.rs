// src/mount/windows.rs
//
// Windows filesystem backend for rencfs, implemented via WinFsp.
//
// # Prerequisites
// WinFsp must be installed on the host system before mounting:
//   https://winfsp.dev/rel/  (MIT-licensed; compatible with rencfs MIT OR Apache-2.0)
//
// # Build
//   cargo build --target x86_64-pc-windows-msvc
//
// The `winfsp` crate links against WinFsp at runtime via delay-load; the binary
// runs on machines without WinFsp installed but will return an error on `mount()`.

use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::oneshot;
use tracing::{error, info, instrument};

use crate::crypto::Cipher;
use crate::encryptedfs::{EncryptedFs, FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

use winfsp::filesystem::{
    DirBuffer, DirInfo, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::U16CString;

// ---------------------------------------------------------------------------
// Volume constants
// ---------------------------------------------------------------------------

/// Reported sector size; WinFsp uses this for alignment.
const SECTOR_SIZE: u16 = 512;
/// Reported sectors per allocation unit.
const SECTORS_PER_AU: u16 = 1;
/// Max path component length exposed to Windows (MAX_PATH-1).
const MAX_COMPONENT_LENGTH: u16 = 255;

// ---------------------------------------------------------------------------
// EncryptedFsWinFsp – the FileSystemContext implementation
// ---------------------------------------------------------------------------

/// Bridge between WinFsp callbacks and [`EncryptedFs`].
///
/// Each WinFsp callback is forwarded to the equivalent `EncryptedFs` method
/// running inside a dedicated Tokio runtime so that async operations can be
/// awaited from the synchronous WinFsp thread pool.
pub(crate) struct EncryptedFsWinFsp {
    fs: Arc<EncryptedFs>,
    read_only: bool,
    rt: tokio::runtime::Handle,
}

impl EncryptedFsWinFsp {
    pub fn new(fs: Arc<EncryptedFs>, read_only: bool) -> Self {
        Self {
            fs,
            read_only,
            rt: tokio::runtime::Handle::current(),
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystemContext – operation stubs
//
// Each method documents the intended EncryptedFs call.  The stubs return
// STATUS_NOT_IMPLEMENTED so the filesystem mounts and responds to Explorer
// queries, but file I/O falls back gracefully while the full implementation
// is developed.
//
// Tracking issue: https://github.com/radumarias/rencfs/issues/3
// ---------------------------------------------------------------------------

impl FileSystemContext for EncryptedFsWinFsp {
    /// Context stored per open file handle (inode + file-handle pair).
    type FileContext = u64; // inode number

    fn get_volume_info(&self, out_volume_info: &mut winfsp::filesystem::VolumeInfo) -> winfsp::Result<()> {
        // Expose a 1 TiB virtual volume; actual limits are the data_dir filesystem.
        out_volume_info.set_total_size(1u64 << 40);
        out_volume_info.set_free_size(1u64 << 39);
        out_volume_info.set_volume_label("rencfs");
        Ok(())
    }

    fn get_security_by_name(
        &self,
        file_name: &winfsp::U16CStr,
        _security_descriptor: Option<&mut Vec<u8>>,
        out_file_attributes_and_reparse_tag: &mut u32,
    ) -> winfsp::Result<FileSecurity> {
        // TODO: resolve file_name → inode via EncryptedFs::find_by_name,
        //       then return the inode's mode as an NT security descriptor.
        //       For now every path reports "directory exists" so Explorer can
        //       browse the root.
        *out_file_attributes_and_reparse_tag = winapi::um::winnt::FILE_ATTRIBUTE_DIRECTORY;
        Ok(FileSecurity {
            attributes: winapi::um::winnt::FILE_ATTRIBUTE_DIRECTORY,
            reparse_point: false,
            reparse_tag: 0,
        })
    }

    fn open(
        &self,
        _file_name: &winfsp::U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_context: &mut Self::FileContext,
        _file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::open(inode, read, write) → store fh in FileContext.
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn create(
        &self,
        _file_name: &winfsp::U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[u8]>,
        _allocation_size: u64,
        _file_context: &mut Self::FileContext,
        _file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::create_nod(parent, mode, ...).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn close(&self, _file_context: Self::FileContext) {
        // TODO: EncryptedFs::release(fh).
    }

    fn read(
        &self,
        _file_context: &Self::FileContext,
        _buffer: &mut [u8],
        _offset: u64,
        _bytes_transferred: &mut usize,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::read(inode, offset, buf, fh).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn write(
        &self,
        _file_context: &Self::FileContext,
        _buffer: &[u8],
        _offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        _bytes_transferred: &mut usize,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::write(inode, offset, data, fh).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn flush(
        &self,
        _file_context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::flush(fh).
        Ok(())
    }

    fn get_file_info(
        &self,
        _file_context: &Self::FileContext,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::get_attr(inode) → convert FileAttr to FileInfo.
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn set_basic_info(
        &self,
        _file_context: &Self::FileContext,
        _file_attributes: u32,
        _creation_time: u64,
        _last_access_time: u64,
        _last_write_time: u64,
        _change_time: u64,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::set_attr(inode, SetFileAttr { atime, mtime, .. }).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn set_file_size(
        &self,
        _file_context: &Self::FileContext,
        _new_size: u64,
        _set_allocation_size: bool,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::set_len(inode, new_size).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn rename(
        &self,
        _file_context: &Self::FileContext,
        _file_name: &winfsp::U16CStr,
        _new_file_name: &winfsp::U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::rename(parent, name, new_parent, new_name).
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn get_security(
        &self,
        _file_context: &Self::FileContext,
        _security_descriptor: Option<&mut Vec<u8>>,
    ) -> winfsp::Result<()> {
        Ok(())
    }

    fn set_security(
        &self,
        _file_context: &Self::FileContext,
        _security_information: u32,
        _modification_descriptor: &[u8],
    ) -> winfsp::Result<()> {
        // Security descriptor writes are not supported in rencfs v1 on Windows.
        Ok(())
    }

    fn read_directory(
        &self,
        _file_context: &Self::FileContext,
        _pattern: Option<&winfsp::U16CStr>,
        _marker: Option<&winfsp::U16CStr>,
        _buffer: &mut DirBuffer,
    ) -> winfsp::Result<()> {
        // TODO: EncryptedFs::read_dir(inode) → emit DirInfo entries via buffer.fill().
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
    }

    fn cleanup(
        &self,
        _file_context: &mut Self::FileContext,
        _file_name: Option<&winfsp::U16CStr>,
        _flags: u32,
    ) {
        // TODO: if FspCleanupDelete flag set → EncryptedFs::remove_file / remove_dir.
    }

    fn overwrite(
        &self,
        _file_context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Err(winfsp::FspError::IO(io::Error::from_raw_os_error(
            winapi::shared::winerror::ERROR_NOT_SUPPORTED as i32,
        )))
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

    #[instrument(skip(self))]
    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        let data_dir = self.data_dir.clone();
        let mountpoint = self.mountpoint.clone();
        let cipher = self.cipher;
        let read_only = self.read_only;
        let password_provider = self.password_provider.take().unwrap();

        info!("Initialising EncryptedFs for Windows/WinFsp mount");

        let fs = Arc::new(
            EncryptedFs::new(data_dir, password_provider, cipher, read_only)
                .await
                .map_err(|e| {
                    error!(err = %e, "EncryptedFs init failed");
                    e
                })?,
        );

        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        // Spawn the blocking WinFsp host on a dedicated thread so the async
        // runtime is not stalled.
        let mountpoint_str = mountpoint
            .to_str()
            .ok_or(FsError::Other("mountpoint is not valid UTF-8"))?
            .to_owned();

        let fs_clone = Arc::clone(&fs);
        std::thread::spawn(move || {
            run_winfsp_host(fs_clone, mountpoint_str, read_only, stop_rx);
        });

        Ok(mount::MountHandle {
            inner: MountHandleInnerImpl { stop_tx: Some(stop_tx) },
        })
    }
}

/// Runs the WinFsp [`FileSystemHost`] on the calling (non-async) thread.
///
/// This blocks until `stop_rx` fires or the host exits due to an error.
fn run_winfsp_host(
    fs: Arc<EncryptedFs>,
    mountpoint: String,
    read_only: bool,
    stop_rx: oneshot::Receiver<()>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for WinFsp thread");

    let context = EncryptedFsWinFsp::new(fs, read_only);

    let mut params = VolumeParams::new(SECTOR_SIZE, SECTORS_PER_AU);
    params.set_max_component_length(MAX_COMPONENT_LENGTH);
    params.set_case_sensitive_search(false);
    params.set_case_preserved_names(true);
    params.set_unicode_on_disk(true);
    params.set_persistent_acls(false);
    params.set_read_only_volume(read_only);
    params.set_volume_creation_time(0);
    params.set_volume_serial_number(0x6E636673 /* 'ncfs' */);

    let host = match FileSystemHost::new(params, context) {
        Ok(h) => h,
        Err(e) => {
            error!(err = ?e, "WinFsp FileSystemHost creation failed");
            return;
        }
    };

    if let Err(e) = host.mount(&mountpoint) {
        error!(err = ?e, mountpoint, "WinFsp mount failed");
        return;
    }

    info!(mountpoint, "WinFsp filesystem mounted");

    // Block until a stop signal arrives, then unmount.
    let _ = rt.block_on(stop_rx);

    host.unmount();
    info!(mountpoint, "WinFsp filesystem unmounted");
}

// ---------------------------------------------------------------------------
// MountHandleInnerImpl
// ---------------------------------------------------------------------------

pub(in crate::mount) struct MountHandleInnerImpl {
    stop_tx: Option<oneshot::Sender<()>>,
}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The WinFsp host runs on its own thread; we always report Pending here
        // so the caller can await the MountHandle until explicit unmount.
        Poll::Pending
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn unmount(mut self) -> io::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        Ok(())
    }
}