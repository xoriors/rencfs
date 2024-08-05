#![cfg_attr(not(debug_assertions), deny(warnings))]
#![feature(test)]
// #![feature(error_generic_member_access)]
#![feature(seek_stream_len)]
#![feature(const_refs_to_cell)]
#![doc(html_playground_url = "https://play.rust-lang.org")]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
// #![deny(missing_docs)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::missing_errors_doc)]
use std::env::args;
use std::io;
use std::io::Write;

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
    match EncryptedFs::passwd(
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
