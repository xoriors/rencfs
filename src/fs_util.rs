use futures_util::TryStreamExt;
use std::io;
use std::path::Path;
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
        tokio::fs::create_dir_all(dst).await?;
    }
    let read_dir = tokio::fs::read_dir(src).await?;
    let read_dir_stream = ReadDirStream::new(read_dir);
    let vec = read_dir_stream.try_collect::<Vec<_>>().await?;
    let entries = vec.iter().collect::<Vec<_>>();
    for entry in entries {
        let dst = dst.join(entry.file_name());
        if entry.path().is_dir() {
            tokio::fs::create_dir_all(&dst).await?;
            Box::pin(rename_dir_content(&entry.path(), &dst)).await?;
            tokio::fs::remove_dir(entry.path()).await?;
        } else {
            tokio::fs::rename(entry.path(), dst).await?;
        }
    }
    tokio::fs::remove_dir(src).await?;
    Ok(())
}
