use std::future::Future;
use std::io::{self, Error, ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::async_util;
use crate::crypto::Cipher;
use crate::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileAttr, FileType, FsError, FsResult, PasswordProvider,
};
use anyhow::Result;
use shush_rs::{ExposeSecret, SecretBox, SecretString};
use thread_local::ThreadLocal;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

#[cfg(test)]
mod test;

const ROOT_INODE: u64 = 1;

pub static SCOPE: ThreadLocal<Mutex<Option<Arc<EncryptedFs>>>> = ThreadLocal::new();

#[allow(clippy::new_without_default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
        }
    }

    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.create = create;
        self
    }

    pub fn read(&mut self, read: bool) -> &mut OpenOptions {
        self.read = read;
        self
    }

    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.write = write;
        self
    }

    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.append = append;
        self
    }

    pub fn truncate(&mut self, truncate: bool) -> &mut OpenOptions {
        self.truncate = truncate;
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut OpenOptions {
        self.create_new = create_new;
        self
    }

    pub async fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        File::new(FileInit {
            read: self.read,
            write: self.write,
            append: self.append,
            truncate: self.truncate,
            create_new: self.create_new,
            create: self.create,
            path: SecretString::from_str(path.as_ref().to_path_buf().to_str().unwrap()).unwrap(),
        })
        .await
    }

    pub async fn init_scope(
        data_dir: PathBuf,
        password_provider: Box<dyn PasswordProvider>,
        cipher: Cipher,
        read_only: bool,
    ) -> FsResult<()> {
        Self::set_scope(EncryptedFs::new(data_dir, password_provider, cipher, read_only).await?)
            .await;
        Ok(())
    }

    pub async fn set_scope(fs: Arc<EncryptedFs>) {
        SCOPE.get_or_default().lock().await.replace(fs);
    }

    pub async fn clear_scope() {
        SCOPE.get_or_default().lock().await.take();
    }

    pub async fn from_scope() -> Option<Arc<EncryptedFs>> {
        SCOPE
            .get_or_default()
            .lock()
            .await
            .as_ref()
            .map(|scope| scope.clone())
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

pub struct File {
    fs: Arc<EncryptedFs>,
    pub context: FileContext,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("ino", &self.context.ino)
            .field("read", &(self.context.fh_read != 0))
            .field("write", &(self.context.fh_write != 0))
            .field("pos", &self.context.pos)
            .finish()
    }
}

#[derive(Debug)]
struct FileInit {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    path: SecretString,
}

#[derive(Debug)]
pub struct FileContext {
    pub ino: u64,
    pub fh_read: u64,
    pub fh_write: u64,
    pos: u64,
}

impl File {
    async fn new(init: FileInit) -> io::Result<Self> {
        let fs = get_fs().await?;
        let context = File::init(init, fs.clone()).await?;
        Ok(File { fs, context })
    }

    async fn init(init: FileInit, fs: Arc<EncryptedFs>) -> FsResult<FileContext> {
        let paths = get_path_and_file_name(init.path);
        let mut dir_inode = ROOT_INODE;
        let file_name = paths
            .last()
            .ok_or_else(|| FsError::InvalidInput("No filename"))?;

        #[allow(unused_assignments)]
        let mut fh_write: u64 = 0;
        let mut fh_read: u64 = 0;
        let attr: FileAttr;
        let mut pos = 0;

        if paths.len() > 1 {
            for node in paths.iter().take(paths.len() - 1) {
                dir_inode = fs
                    .find_by_name(dir_inode, node)
                    .await?
                    .ok_or(FsError::InodeNotFound)?
                    .ino;
            }
        }
        let file_exists = fs.find_by_name(dir_inode, file_name).await?.is_some();

        match (
            init.write,
            init.append,
            init.truncate,
            init.create,
            init.create_new,
        ) {
            (false, false, false, false, false) => {
                if !file_exists {
                    return Err(FsError::ReadOnly);
                }
                if !init.read {
                    return Err(FsError::InvalidInput("No read or write flags."));
                }
                attr = fs
                    .find_by_name(dir_inode, file_name)
                    .await?
                    .ok_or_else(|| FsError::InodeNotFound)?;
                fh_write = fs.open(attr.ino, true, false).await?;
            }
            // 2
            (false, false, false, true, false) => return Err(FsError::ReadOnly),
            // 3
            (false, false, true, false, false) => return Err(FsError::ReadOnly),
            // 4
            (false, false, true, true, false) => return Err(FsError::ReadOnly),
            // 5
            (_, true, false, false, false) => {
                if !file_exists {
                    return Err(FsError::InodeNotFound);
                }
                attr = fs
                    .find_by_name(dir_inode, file_name)
                    .await?
                    .ok_or_else(|| FsError::InodeNotFound)?;
                fh_write = fs.open(attr.ino, false, true).await?;
                pos = fs.get_attr(attr.ino).await?.size;
            }
            // 6,
            (_, true, false, true, false) => {
                if file_exists {
                    attr = fs
                        .find_by_name(dir_inode, file_name)
                        .await?
                        .ok_or_else(|| FsError::InodeNotFound)?;
                    fh_write = fs.open(attr.ino, false, true).await?;
                    pos = fs.get_attr(attr.ino).await?.size;
                } else {
                    (fh_write, attr) = fs
                        .create(dir_inode, file_name, file_attr(), false, init.write)
                        .await?;
                }
            }
            // 7
            (_, true, true, false, false) => {
                return Err(FsError::InvalidInput(
                    "Append and Truncate cannot be true at the same time.",
                ))
            }
            // 8
            (_, true, true, true, false) => {
                return Err(FsError::InvalidInput(
                    "Append and Truncate cannot be true at the same time.",
                ))
            }
            // 9
            (true, false, false, false, false) => {
                if !file_exists {
                    return Err(FsError::InodeNotFound);
                }
                attr = fs
                    .find_by_name(dir_inode, file_name)
                    .await?
                    .ok_or_else(|| FsError::InodeNotFound)?;
                fh_write = fs.open(attr.ino, false, init.write).await?;
            }
            // 10
            (true, false, false, true, false) => {
                if file_exists {
                    attr = fs
                        .find_by_name(dir_inode, file_name)
                        .await?
                        .ok_or_else(|| FsError::InodeNotFound)?;
                    fh_write = fs.open(attr.ino, false, init.write).await?;
                } else {
                    (fh_write, attr) = fs
                        .create(dir_inode, file_name, file_attr(), false, init.write)
                        .await?;
                }
            }
            // 11
            (true, false, true, false, false) => {
                if file_exists {
                    attr = fs
                        .find_by_name(dir_inode, file_name)
                        .await?
                        .ok_or_else(|| FsError::InodeNotFound)?;
                    fh_write = fs.open(attr.ino, false, init.write).await?;
                    fs.set_len(attr.ino, 0).await?;
                } else {
                    (fh_write, attr) = fs
                        .create(dir_inode, file_name, file_attr(), false, init.write)
                        .await?;
                }
            }
            // 12
            (true, false, true, true, false) => {
                if file_exists {
                    attr = fs
                        .find_by_name(dir_inode, file_name)
                        .await?
                        .ok_or_else(|| FsError::InodeNotFound)?;
                    fh_write = fs.open(attr.ino, false, init.write).await?;
                    fs.set_len(attr.ino, 0).await?;
                } else {
                    (fh_write, attr) = fs
                        .create(dir_inode, file_name, file_attr(), false, init.write)
                        .await?;
                }
            }
            // 13
            (false, false, _, _, true) => {
                return if file_exists {
                    Err(FsError::AlreadyExists)
                } else {
                    Err(FsError::InvalidInput("No write access"))
                }
            }
            // 14
            (_, true, _, _, true) => {
                if file_exists {
                    return Err(FsError::AlreadyExists);
                }
                (fh_write, attr) = fs
                    .create(dir_inode, file_name, file_attr(), false, init.write)
                    .await?;
            }
            // 15
            (true, false, _, _, true) => {
                if file_exists {
                    return Err(FsError::AlreadyExists);
                }
                (fh_write, attr) = fs
                    .create(dir_inode, file_name, file_attr(), false, init.write)
                    .await?;
            }
        };

        if init.read {
            fh_read = fs.open(attr.ino, true, false).await?
        }

        Ok(FileContext {
            ino: attr.ino,
            fh_read,
            fh_write,
            pos,
        })
    }
}

impl AsyncRead for File {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let desired_to_read = buf.remaining();
        let binding = self.fs.clone();

        let async_op = binding.read(
            self.context.ino,
            self.context.pos,
            buf.initialize_unfilled(),
            self.context.fh_read,
        );

        let mut future = Box::pin(async_op);

        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(len)) => {
                drop(future);
                let bytes_to_fill = len.min(desired_to_read);
                buf.advance(bytes_to_fill);

                self.context.pos += bytes_to_fill as u64;

                if len == 0 {
                    return Poll::Ready(Ok(()));
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for File {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let binding = self.fs.clone();
        let async_op = binding.write(
            self.context.ino,
            self.context.pos,
            buf,
            self.context.fh_write,
        );
        let mut future = Box::pin(async_op);

        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(len)) => {
                self.context.pos += len as u64;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let async_op = self.fs.flush(self.context.fh_write);

        let mut future = Box::pin(async_op);

        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let async_op = self.fs.release(self.context.fh_write);

        let mut future = Box::pin(async_op);

        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncSeek for File {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let attr = async_util::call_async(async { self.fs.get_attr(self.context.ino).await })?;

        let new_pos = match position {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(pos) => attr.size as i64 + pos,
            SeekFrom::Current(pos) => self.context.pos as i64 + pos,
        };
        if new_pos < 0 {
            return Err(io::Error::new(ErrorKind::InvalidInput, "position < 0"));
        }
        if new_pos > attr.size as i64 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "position after file size",
            ));
        }

        self.context.pos = new_pos as u64;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.context.pos))
    }
}

pub fn get_path_and_file_name(path: SecretBox<String>) -> Vec<SecretBox<String>> {
    let input = path.expose_secret();
    let path = input.strip_prefix(".").unwrap_or(&input);
    let mut path_segments = Vec::new();
    for segment in path.split("/") {
        if segment.is_empty() {
            continue;
        }
        let segment = SecretString::from_str(segment).unwrap();
        path_segments.push(segment);
    }
    path_segments
}

async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
    OpenOptions::from_scope()
        .await
        .ok_or(FsError::Other("not initialized"))
}

fn file_attr() -> CreateFileAttr {
    #[allow(unused_mut)]
    let mut attr = CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unsafe {
        attr.uid = libc::getuid();
        attr.gid = libc::getgid();
    }
    attr
}
