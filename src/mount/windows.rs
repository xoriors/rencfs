use async_trait::async_trait;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{error, warn};

use crate::crypto::Cipher;
use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
use crate::mount;
use crate::mount::{MountHandleInner, MountPoint};

#[allow(clippy::struct_excessive_bools)]
pub struct MountPointImpl {
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Option<Box<dyn PasswordProvider>>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    direct_io: bool,
    suid_support: bool,
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

    async fn mount(mut self) -> FsResult<mount::MountHandle> {
        Err(FsError::Other(
            "he he, not yet ready for this platform, but soon my friend, soon :)",
        ))
    }
}

pub(in crate::mount) struct MountHandleInnerImpl {}

impl Future for MountHandleInnerImpl {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        error!("he he, not yet ready for this platform, but soon my friend, soon :)");
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl MountHandleInner for MountHandleInnerImpl {
    async fn umount(mut self) -> io::Result<()> {
        Ok(())
    }
}
