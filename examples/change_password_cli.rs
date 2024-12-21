use std::io;
use std::io::Write;
use std::{env::args, str::FromStr};

use bip39::{Language, Mnemonic, MnemonicType};
use rpassword::read_password;
use shush_rs::{ExposeSecret, SecretString};
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
    let old_password = SecretString::from_str(&read_password().unwrap()).unwrap();
    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = SecretString::from_str(&read_password().unwrap()).unwrap();
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = SecretString::from_str(&read_password().unwrap()).unwrap();
    if new_password.expose_secret() != new_password2.expose_secret() {
        error!("Passwords do not match");
        return;
    }
    println!("Changing password...");
    match EncryptedFs::passwd(
        Path::new(&data_dir),
        old_password,
        new_password,
        Cipher::ChaCha20Poly1305,
    )
    .await
    {
        Ok(()) => info!("Password changed successfully"),
        Err(FsError::InvalidPassword) => error!("Invalid old password"),
        Err(FsError::InvalidDataDirStructure) => error!("Invalid structure of data directory"),
        Err(err) => error!("Error: {err}"),
    }

    // Generate a 24-word recovery phrase
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    let phrase = mnemonic.phrase();
    println!("Your recovery phrase is: {}", phrase);

    // Use the recovery phrase to change the password
    print!("Enter recovery phrase: ");
    io::stdout().flush().unwrap();
    let recovery_phrase = read_password().unwrap();
    let mnemonic = Mnemonic::from_phrase(&recovery_phrase, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let new_password = SecretString::from_str(&hex::encode(seed)).unwrap();
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = SecretString::from_str(&read_password().unwrap()).unwrap();
    if new_password.expose_secret() != new_password2.expose_secret() {
        error!("Passwords do not match");
        return;
    }
    println!("Changing password using recovery phrase...");
    match EncryptedFs::passwd(
        Path::new(&data_dir),
        SecretString::from_str(&recovery_phrase).unwrap(),
        new_password,
        Cipher::ChaCha20Poly1305,
    )
    .await
    {
        Ok(()) => info!("Password changed successfully using recovery phrase"),
        Err(FsError::InvalidPassword) => error!("Invalid recovery phrase"),
        Err(FsError::InvalidDataDirStructure) => error!("Invalid structure of data directory"),
        Err(err) => error!("Error: {err}"),
    }
}
