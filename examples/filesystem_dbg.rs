#![allow(dead_code)]

use rencfs::crypto::fs_api::r#async::fs::OpenOptions;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{
    CreateFileAttr, EncryptedFs, FileType, FsError, FsResult, PasswordProvider,
};
use shush_rs::SecretString;
use std::io::SeekFrom;
use std::str::FromStr;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt};

static ROOT_CIPHER_FS_DATA_DIR: &str = "./tmp/rencfs_data_test";
static FILENAME: &str = "test1";

use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_fs().await?;
    let fs = get_fs().await?;
    {
        let mut opened_file1 = OpenOptions::new()
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
    let opened_file1 = OpenOptions::new().read(true).open(FILENAME).await?;
    let reader = tokio::io::BufReader::new(opened_file1);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        println!("Read line: {}", line);
    }
    cleanup().await;
    Ok(())
}

async fn init_fs() -> anyhow::Result<()> {
    OpenOptions::init_scope(
        std::path::Path::new(ROOT_CIPHER_FS_DATA_DIR).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
    )
    .await?;
    Ok(())
}

fn _add_create<'a>(
    opts: &'a mut OpenOptions,
    path: &rencfs::crypto::fs_api::path::Path,
) -> &'a mut OpenOptions {
    if !path.to_path_buf().exists() {
        opts.create(true);
    }
    opts
}

async fn cleanup() {
    // todo: ignore if we delete first time when not present
    let _ = tokio::fs::remove_dir_all(std::path::Path::new(ROOT_CIPHER_FS_DATA_DIR)).await;

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
    OpenOptions::from_scope()
        .await
        .ok_or(FsError::Other("not initialized"))
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
