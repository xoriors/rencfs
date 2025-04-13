use core::str::FromStr;

use anyhow::Result;
use rencfs::{
    crypto::Cipher,
    encryptedfs::{
        write_all_string_to_fs, CreateFileAttr, EncryptedFs, FileType, PasswordProvider,
    },
};
use shush_rs::SecretString;
use std::{
    fs,
    path::{Path, PathBuf},
};

const ROOT_INODE: u64 = 1;

struct PasswordProviderImpl;

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str("password").unwrap())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let data_dir = Path::new("/tmp/data_test").to_path_buf();
    clean_up_directory(&data_dir)?;

    let cipher = Cipher::ChaCha20Poly1305;
    let fs = EncryptedFs::new(
        data_dir.clone(),
        Box::new(PasswordProviderImpl),
        cipher,
        false,
    )
    .await?;

    let file_name = SecretString::from_str("file1").unwrap();
    let (file_handle, attr) = fs
        .create(ROOT_INODE, &file_name, file_attributes(), false, true)
        .await?;

    let data = "Hello, world!";
    write_all_string_to_fs(&fs, attr.ino, 0, data, file_handle).await?;

    fs.flush(file_handle).await?;
    fs.release(file_handle).await?;

    let file_handle = fs.open(attr.ino, true, false).await?;
    let mut buffer = vec![0; data.len()];
    fs.read(attr.ino, 0, &mut buffer, file_handle).await?;
    fs.release(file_handle).await?;

    assert_eq!(data, String::from_utf8(buffer)?);

    assert!(fs.exists_by_name(ROOT_INODE, &file_name)?);
    fs.remove_file(ROOT_INODE, &file_name).await?;
    assert!(!fs.exists_by_name(ROOT_INODE, &file_name)?);

    clean_up_directory(&data_dir)?;

    Ok(())
}

const fn file_attributes() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644, // Permissions
        uid: 0,      // User ID
        gid: 0,      // Group ID
        rdev: 0,     // Device ID
        flags: 0,    // File flags
    }
}

fn clean_up_directory(dir: &PathBuf) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }

    Ok(())
}
