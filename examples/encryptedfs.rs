#![deny(warnings)]
use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::Result;
use secrecy::SecretString;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::write_all_string_to_fs;
use rencfs::encryptedfs::{CreateFileAttr, EncryptedFs, FileType, PasswordProvider};

const ROOT_INODE: u64 = 1;

struct PasswordProviderImpl {}

impl PasswordProvider for PasswordProviderImpl {
    fn get_password(&self) -> Option<SecretString> {
        // dummy password, use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
        Some(SecretString::from_str("pass42").unwrap())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let data_dir = Path::new("/tmp/rencfs_data_test").to_path_buf();
    let _ = fs::remove_dir_all(data_dir.to_str().unwrap());
    let cipher = Cipher::ChaCha20Poly1305;
    let fs = EncryptedFs::new(data_dir.clone(), Box::new(PasswordProviderImpl {}), cipher).await?;

    let file1 = SecretString::from_str("file1").unwrap();
    let (fh, attr) = fs
        .create(ROOT_INODE, &file1, file_attr(), false, true)
        .await?;
    let data = "Hello, world!";
    write_all_string_to_fs(&fs, attr.ino, 0, data, fh).await?;
    fs.flush(fh).await?;
    fs.release(fh).await?;
    let fh = fs.open(attr.ino, true, false).await?;
    let mut buf = vec![0; data.len()];
    fs.read(attr.ino, 0, &mut buf, fh).await?;
    fs.release(fh).await?;
    assert_eq!(data, String::from_utf8(buf)?);
    fs::remove_dir_all(data_dir)?;

    Ok(())
}

fn file_attr() -> CreateFileAttr {
    CreateFileAttr {
        kind: FileType::RegularFile,
        perm: 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}
