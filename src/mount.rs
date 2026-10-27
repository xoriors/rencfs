use crate::crypto::Cipher;
use crate::encryptedfs::{FsResult, PasswordProvider};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(not(target_os = "windows"))]
use std::process;
use std::task::{Context, Poll};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::MountHandleInnerImpl;
#[cfg(target_os = "linux")]
use linux::MountPointImpl;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{MountHandleInnerImpl, MountPointImpl};

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod dummy;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::MountHandleInnerImpl;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
use dummy::MountPointImpl;

#[async_trait]
#[allow(clippy::module_name_repetitions)]
#[allow(clippy::struct_excessive_bools)]
pub trait MountPoint {
    #[allow(clippy::fn_params_excessive_bools)]
    fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        read_only: bool,
    ) -> Self
    where
        Self: Sized;
    async fn mount(mut self) -> FsResult<MountHandle>;
}

#[allow(clippy::module_name_repetitions)]
pub struct MountHandle {
    inner: MountHandleInnerImpl,
}
impl MountHandle {
    pub async fn umount(self) -> io::Result<()> {
        self.inner.unmount().await
    }
}

impl Future for MountHandle {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

#[async_trait]
pub(crate) trait MountHandleInner: Future<Output = io::Result<()>> {
    async fn unmount(mut self) -> io::Result<()>;
}
/// Available arguments
///
/// **`mountpoint`** where it wil mount the filesystem
/// **`data_dir`** the directory where the encrypted files will be stored  
/// **`password_provider`** the password provider  
/// **`cipher`** The encryption algorithm to use.
/// Currently, it supports these ciphers [`Cipher`]
///
/// **`allow_root`** allow root to access the file system  
/// **`allow_other`** allow other users to access the file system  
/// **`read_only`** Mount the filesystem read-only; disabled by default.
///
/// # Windows MSVC linking
///
/// Library consumers must enable WinFsp delay loading in the build script of
/// their final executable or `cdylib`; this crate's linker arguments do not
/// propagate to dependent packages. This lets mounting initialize the WinFsp
/// DLL location before its first use. See `docs/readme/Windows.md` and the
/// target-aware settings in this crate's `build.rs`.
#[must_use]
#[allow(clippy::fn_params_excessive_bools)]
#[allow(clippy::too_long_first_doc_paragraph)]
pub fn create_mount_point(
    mountpoint: &Path,
    data_dir: &Path,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    read_only: bool,
) -> impl MountPoint {
    MountPointImpl::new(
        mountpoint.to_path_buf(),
        data_dir.to_path_buf(),
        password_provider,
        cipher,
        allow_root,
        allow_other,
        read_only,
    )
}

#[cfg(target_os = "windows")]
pub fn umount(_mountpoint: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "On Windows, unmount through MountHandle::umount() or stop the owning rencfs process with Ctrl+C",
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn umount(mountpoint: &str) -> io::Result<()> {
    // try normal umount
    if process::Command::new("umount")
        .arg(mountpoint)
        .output()?
        .status
        .success()
    {
        return Ok(());
    }
    // force umount
    if process::Command::new("umount")
        .arg("-f")
        .arg(mountpoint)
        .output()?
        .status
        .success()
    {
        return Ok(());
    }
    // lazy umount
    if process::Command::new("umount")
        .arg("-l")
        .arg(mountpoint)
        .output()?
        .status
        .success()
    {
        Ok(())
    } else {
        Err(io::Error::other(format!("cannot umount {mountpoint}")))
    }
}
