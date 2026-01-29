#[cfg(target_os = "macos")]
mod macos_impl {
    use async_trait::async_trait;
    use std::future::Future;
    use std::io;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use fuser::{MountOption, Session, Filesystem};
    use tracing::info;

    use crate::crypto::Cipher;
    use crate::encryptedfs::{FsResult, PasswordProvider};
    use crate::mount::{MountHandleInner, MountPoint};

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

        async fn mount(self) -> FsResult<crate::mount::MountHandle> {
            info!("Mounting rencfs on macOS using fuser...");

            let fs = DummyFS {};

            let mut options = vec![
                MountOption::FSName("rencfs".to_string()),
                MountOption::AutoUnmount,
            ];

            if self.allow_other {
                options.push(MountOption::AllowOther);
            }
            if self.read_only {
                options.push(MountOption::RO);
            }

            let session = Session::new(fs, &self.mountpoint, &options)?;
            let handle = crate::mount::MountHandle {
                inner: MountHandleInnerImpl {
                    session: Some(session),
                },
            };
            Ok(handle)
        }
    }

    pub struct MountHandleInnerImpl {
        session: Option<Session>,
    }

    impl Future for MountHandleInnerImpl {
        type Output = io::Result<()>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(session) = &mut self.session {
                session.poll_unpin(cx)
            } else {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "No session")))
            }
        }
    }

    #[async_trait]
    impl MountHandleInner for MountHandleInnerImpl {
        async fn unmount(mut self) -> io::Result<()> {
            if let Some(session) = self.session.take() {
                drop(session);
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "No session to unmount"))
            }
        }
    }

    struct DummyFS;
    impl Filesystem for DummyFS {}

    pub use MountHandleInnerImpl;
    pub use MountPointImpl;
}

#[cfg(not(target_os = "macos"))]
mod fallback_dummy_impl {
    use async_trait::async_trait;
    use std::future::Future;
    use std::io;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tracing::error;

    use crate::crypto::Cipher;
    use crate::encryptedfs::{FsError, FsResult, PasswordProvider};
    use crate::mount;
    use crate::mount::{MountHandleInner, MountPoint};

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
            Err(FsError::Other("Dummy implementation"))
        }
    }

    pub(in crate::mount) struct MountHandleInnerImpl {}

    impl Future for MountHandleInnerImpl {
        type Output = io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            error!("he he, not yet ready for this platform, but soon my friend, soon :)");
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl MountHandleInner for MountHandleInnerImpl {
        async fn unmount(mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub use MountHandleInnerImpl;
    pub use MountPointImpl;
}

#[cfg(target_os = "macos")]
pub use macos_impl::*;

#[cfg(not(target_os = "macos"))]
pub use fallback_dummy_impl::*;
