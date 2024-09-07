use crate::crypto::Cipher;
use crate::encryptedfs::{FsResult, PasswordProvider};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, process};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::MountHandleInnerImpl;
#[cfg(target_os = "linux")]
use linux::MountPointImpl;

#[cfg(not(target_os = "linux"))]
mod dummy;
#[cfg(not(target_os = "linux"))]
use dummy::MountHandleInnerImpl;
#[cfg(not(target_os = "linux"))]
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
/// **`read_only`** Set FUSE filesystem read-only mount option, default is disabled.
///
#[must_use]
#[allow(clippy::fn_params_excessive_bools)]
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
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cannot umount {mountpoint}"),
        ))
    }
}
