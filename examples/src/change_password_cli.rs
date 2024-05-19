use std::env::args;
use std::io;
use std::io::Write;
use std::str::FromStr;

use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use tracing::{error, info};

use rencfs::encryptedfs::{EncryptedFs, FsError};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let mut args = args();
    let _ = args.next(); // skip the program name
    let data_dir = args.next().expect("data_dir is missing");

    use std::path::Path;
    // read password from stdin
    use rencfs::crypto::Cipher;
    print!("Enter old password: ");
    io::stdout().flush().unwrap();
    let old_password = SecretString::new(read_password().unwrap());
    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = SecretString::new(read_password().unwrap());
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = SecretString::new(read_password().unwrap());
    if new_password.expose_secret() != new_password2.expose_secret() {
        error!("Passwords do not match");
        return;
    }
    println!("Changing password...");
    match EncryptedFs::change_password(
        Path::new(&data_dir),
        old_password,
        new_password,
        Cipher::ChaCha20Poly1305,
    )
    .await
    {
        Ok(_) => info!("Password changed successfully"),
        Err(FsError::InvalidPassword) => error!("Invalid old password"),
        Err(FsError::InvalidDataDirStructure) => error!("Invalid structure of data directory"),
        Err(err) => error!("Error: {err}"),
    }
}
