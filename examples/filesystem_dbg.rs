#![allow(dead_code)]

use rencfs::crypto::fs::OpenOptions;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{CreateFileAttr, EncryptedFs, FileType, FsError, FsResult, PasswordProvider};
use shush_rs::SecretString;
use std::io::SeekFrom;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt};
use std::str::FromStr;

static ROOT_CIPHER_FS_DATA_DIR: &str = "./tmp/rencfs_data_test";
static FILENAME: &str = "test1";

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_fs().await?;
    // let fs = get_fs().await?;
    // let dir1_path = PathBuf::from(ROOT_CIPHER_FS_DATA_DIR).join("dir1");
    // let secret_dir = SecretString::from_str("dir1")?;
    // let secret_file = SecretString::from_str(&FILENAME)?;
    // // let file_path = PathBuf::from(&dir1_path).join(&FILENAME);
    // let file_rel_path = PathBuf::from("./dir1").join(FILENAME);

    // let fs = get_fs().await?;
    // let dir = fs.create(1, &secret_dir, dir_attr(), true, true).await?;
    // let file = fs
    //     .create(dir.1.ino, &secret_file, file_attr(), true, true)
    //     .await?;
    // fs.flush(file.0).await?;
    // fs.release(file.0).await?;

    // let file_in_root = fs.create(1, &secret_file, file_attr(), true, true).await?;
    // fs.flush(file_in_root.0).await?;
    // fs.release(file_in_root.0).await?;
    // dbg!("test1");

    {
        let mut opened_file1 = rencfs::crypto::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(FILENAME)
            .await?;

        opened_file1.write_all(b"Hello world\n").await?;
        opened_file1.write_all(b"This is the second line").await?;
        opened_file1.flush().await?;
        fs.release(opened_file1.context.fh_write).await?;
        opened_file1.seek(SeekFrom::Start(0)).await?;
    }

    let opened_file1 = rencfs::crypto::fs::OpenOptions::new()
    .read(true)
    .open(FILENAME)
    .await?;

    let reader = tokio::io::BufReader::new(opened_file1);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        println!("Read line: {}", line);
    }
    cleanup().await;
    Ok(())
}

async fn init_fs() -> anyhow::Result<()> {
    EncryptedFs::initialize(
        Path::new(ROOT_CIPHER_FS_DATA_DIR).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await?;
    Ok(())
}

fn _add_create<'a>(opts: &'a mut OpenOptions, path: &Path) -> &'a mut OpenOptions {
    if !path.to_path_buf().exists() {
        opts.create(true);
    }
    opts
}

async fn cleanup() {
    // todo: ignore if we delete first time when not present
    let _ = tokio::fs::remove_dir_all(Path::new(ROOT_CIPHER_FS_DATA_DIR)).await;

    // todo: seems we need to abstract also Path because exists() goes against local FS
    // if file_path.exists() {
    //     fs::remove_file(&file_path).await.unwrap();
    // }
}

struct PasswordProviderImpl {}

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("pass42").unwrap())
    }
}

async fn get_fs() -> FsResult<Arc<EncryptedFs>> {
    EncryptedFs::instance().ok_or(FsError::Other("not initialized"))
}

const fn file_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

const fn dir_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::Directory,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}
