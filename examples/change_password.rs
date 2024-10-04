use core::str::FromStr;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{EncryptedFs, FsError};
use shush_rs::SecretString;
use std::env::args;
use std::path::Path;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let mut args = args();
    let _ = args.next(); // skip the program name
    let data_dir = args.next().expect("data_dir is missing");

    match EncryptedFs::passwd(
        Path::new(&data_dir),
        SecretString::from_str("old-pass").unwrap(),
        SecretString::from_str("new-pass").unwrap(),
        Cipher::ChaCha20Poly1305,
    )
    .await
    {
        Ok(()) => println!("Password changed successfully"),
        Err(FsError::InvalidPassword) => println!("Invalid old password"),
        Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
        Err(err) => println!("Error: {err}"),
    }
}
