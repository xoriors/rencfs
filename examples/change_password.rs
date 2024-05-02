use std::str::FromStr;
use secrecy::SecretString;
use rencfs::encryptedfs::{Cipher, EncryptedFs, FsError};

#[tokio::main]
async fn main() {
    match EncryptedFs::change_password("/tmp/rencfs_data", SecretString::from_str("old-pass").unwrap(), SecretString::from_str("new-pass").unwrap(), Cipher::ChaCha20).await {
        Ok(_) => println!("Password changed successfully"),
        Err(FsError::InvalidPassword) => println!("Invalid old password"),
        Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
        Err(err) => println!("Error: {err}"),
    }
}