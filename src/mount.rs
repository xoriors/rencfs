use crate::crypto::Cipher;
use crate::encryptedfs::{FsResult, PasswordProvider};
use async_trait::async_trait;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::Fuse3MountPoint as MountPointImpl;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::MacOsFuse3MountPoint as MountPointImpl;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::WindowsMountPoint as MountPointImpl;

#[async_trait]
pub trait MountPoint {
    async fn mount(&mut self) -> FsResult<()>;
    async fn umount(&mut self) -> FsResult<()>;
}

pub fn create_mount_point(
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    direct_io: bool,
    suid_support: bool,
) -> Box<dyn MountPoint> {
    Box::new(MountPointImpl::new(
        mountpoint,
        data_dir,
        password_provider,
        cipher,
        allow_root,
        allow_other,
        direct_io,
        suid_support,
    ))
}
