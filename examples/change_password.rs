use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{EncryptedFs, FsError};
use secrecy::SecretString;
use std::path::Path;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    match EncryptedFs::change_password(
        Path::new("/tmp/rencfs_data"),
        SecretString::from_str("old-pass").unwrap(),
        SecretString::from_str("new-pass").unwrap(),
        Cipher::ChaCha20Poly1305,
    )
    .await
    {
        Ok(_) => println!("Password changed successfully"),
        Err(FsError::InvalidPassword) => println!("Invalid old password"),
        Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
        Err(err) => println!("Error: {err}"),
    }
}
