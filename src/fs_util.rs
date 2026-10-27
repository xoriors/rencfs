#[cfg(unix)]
use atomic_write_file::unix::OpenOptionsExt;
use atomic_write_file::AtomicWriteFile;
use futures_util::TryStreamExt;
use std::path::Path;
use std::{fs, io};
use tokio_stream::wrappers::ReadDirStream;

/// Recursively moves the content of a directory to another.
/// It will create destination directory if it doesn't exist. It will delete the source directory after the move.
pub async fn rename_dir_content(src: &Path, dst: &Path) -> io::Result<()> {
    if !src.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "source directory does not exist",
        ));
    }
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    let read_dir = tokio::fs::read_dir(src).await?;
    let read_dir_stream = ReadDirStream::new(read_dir);
    let vec = read_dir_stream.try_collect::<Vec<_>>().await?;
    let entries = vec.iter().collect::<Vec<_>>();
    for entry in entries {
        let dst = dst.join(entry.file_name());
        if entry.path().is_dir() {
            fs::create_dir_all(&dst)?;
            Box::pin(rename_dir_content(&entry.path(), &dst)).await?;
            fs::remove_dir(entry.path())?;
        } else {
            fs::rename(entry.path(), dst)?;
        }
    }
    fs::remove_dir(src)?;
    Ok(())
}

pub fn open_atomic_write(file: &Path) -> io::Result<AtomicWriteFile> {
    let mut opt = AtomicWriteFile::options();
    opt.read(true);
    #[cfg(unix)]
    opt.preserve_mode(true).preserve_owner(true);
    opt.open(file)
}

/// Flush directory metadata where the operating system supports directory
/// fsync. This implementation does not attempt a per-directory Windows flush.
/// Ordinary directory handles cannot be used like Unix fsync handles. File data
/// is still flushed through writable file handles before this function is
/// called, but we do not claim Unix-style directory-fsync crash guarantees on
/// Windows.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        if !directory.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "directory not found",
            ));
        }
        Ok(())
    }
}
