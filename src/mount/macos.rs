use crate::crypto::Cipher;
use crate::encryptedfs::{FsResult, PasswordProvider};
use crate::mount::MountPoint;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::warn;

pub(super) struct MacOsFuse3MountPoint {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    direct_io: bool,
    suid_support: bool,
}
impl MacOsFuse3MountPoint {
    pub(super) fn new(
        mountpoint: PathBuf,
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        allow_root: bool,
        allow_other: bool,
        direct_io: bool,
        suid_support: bool,
    ) -> Self {
        Self {
            mountpoint,
            data_dir,
            password_provider: Some(password_provider),
            cipher,
            allow_root,
            allow_other,
            direct_io,
            suid_support,
        }
    }
}

#[async_trait]
impl MountPoint for MacOsFuse3MountPoint {
    async fn mount(&mut self) -> FsResult<()> {
        warn!("he he, not yet ready for this platform, but soon my friend, soon :)");
        Ok(())
    }

    async fn umount(&mut self) -> FsResult<()> {
        todo!()
    }
}
