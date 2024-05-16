#![feature(test)]
// #![feature(error_generic_member_access)]
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
//! # Encrypted File System
//!
//! An encrypted file system that mounts with FUSE on Linux. It can be used to create encrypted directories.
//!
//! # Usage
//!
//! It can be used a library to create an encrypted file system or mount it with FUSE.
//!
//! This crate also contains [main.rs] file that can be used as an example on how to run the encrypted file system from the command line.
//! Documentation for that can be found [here](https://crates.io/crates/encryptedfs).
//!
//! In the following example, we will see how we can use the library.
//!
//! ## Calling (`run_fuse`)[`run_fuse`]
//!
//! ### Example
//!
//! ```no_run
//! use rencfs::run_fuse;
//! use rencfs::crypto::Cipher;
//! use secrecy::SecretString;
//! use rencfs::encryptedfs::PasswordProvider;
//! use std::str::FromStr;
//! use std::path::Path;
//!
//! #[tokio::main]
//! async fn main() {
//! struct PasswordProviderImpl {}
//!     impl PasswordProvider for PasswordProviderImpl {
//!         fn get_password(&self) -> Option<SecretString> {
//!             /// dummy password, better use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
//!             Some(SecretString::from_str("password").unwrap())
//!         }
//!     }
//!     run_fuse(Path::new(&"/tmp/rencfs").to_path_buf(), Path::new(&"/tmp/rencfs_data").to_path_buf(),
//!         Box::new(PasswordProviderImpl{}), Cipher::ChaCha20Poly1305, false, false, false, false).await.unwrap();
//! }
//! ```
//!
//! ## Using [EncryptedFsFuse3](EncryptedFsFuse3)
//!
//! ### Example
//!
//! ```no_run
//! use std::ffi::OsStr;
//! use std::path::{Path, PathBuf};
//! use fuse3::MountOptions;
//! use fuse3::raw::Session;
//! use secrecy::SecretString;
//! use rencfs::crypto::Cipher;
//! use rencfs::encryptedfs::{ PasswordProvider};
//! use rencfs::encryptedfs_fuse3::EncryptedFsFuse3;
//!
//! async fn run_fuse(mountpoint: PathBuf, data_dir: PathBuf, tmp_dir: PathBuf, password_provider: Box<dyn PasswordProvider>, cipher: Cipher, allow_root: bool, allow_other: bool, direct_io: bool, suid_support: bool) -> anyhow::Result<()> {
//!     let uid = unsafe { libc::getuid() };
//!     let gid = unsafe { libc::getgid() };
//!
//!     let mut mount_options = MountOptions::default()
//!         .uid(uid).gid(gid)
//!         .read_only(false)
//!         .allow_root(allow_root)
//!         .allow_other(allow_other)
//!         .clone();
//!     let mount_path = OsStr::new(mountpoint.to_str().unwrap());
//!
//!     Session::new(mount_options)
//!         .mount_with_unprivileged(EncryptedFsFuse3::new(data_dir, password_provider, cipher, direct_io, suid_support).await.unwrap(), mount_path)
//!         .await?
//!         .await?;
//!    Ok(())
//! }
//! ```
//! Parameters:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](Cipher).
//! - `allow_root`: Allow root to access the file system.
//! - `allow_other`: Allow other users to access the file system.
//! - `direct_io`: Use direct I/O (bypass page cache for open files).
//! - `suid_support`: If it should allow setting `SUID` and `SGID` when files are created. On `false` it will unset those flags when creating files.
//!
//! ## Or directly work with [EncryptedFs](EncryptedFs)
//!
//! You need to specify several parameters to create an encrypted file system:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](Cipher).
//!
//! ### Example
//!
//! ```
//! use std::fs;
//! use std::str::FromStr;
//! use secrecy::SecretString;
//! use rencfs::encryptedfs::{EncryptedFs, FileAttr, FileType, PasswordProvider, CreateFileAttr};
//! use rencfs::crypto::Cipher;
//! use anyhow::Result;
//! use std::path::Path;
//! use rencfs::encryptedfs::write_all_string_to_fs;
//!
//! const ROOT_INODE: u64 = 1;
//!
//! struct PasswordProviderImpl {}
//! impl PasswordProvider for PasswordProviderImpl {
//!     fn get_password(&self) -> Option<SecretString> {
//!         /// dummy password, better use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
//!         Some(SecretString::from_str("password").unwrap())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let data_dir = Path::new("/tmp/rencfs_data_test").to_path_buf();
//!     let  _ = fs::remove_dir_all(data_dir.to_str().unwrap());
//!     let password = SecretString::from_str("password").unwrap();
//!     let cipher = Cipher::ChaCha20Poly1305;
//!     let mut fs = EncryptedFs::new(data_dir.clone(), Box::new(PasswordProviderImpl{}), cipher ).await?;
//!
//!     let  file1 = SecretString::from_str("file1").unwrap();
//!     let (fh, attr) = fs.create_nod(ROOT_INODE, &file1, file_attr(), false, true).await?;
//!     let data = "Hello, world!";
//!     write_all_string_to_fs( &fs, attr.ino, 0,data, fh).await?;
//!     fs.flush(fh).await?;
//!     fs.release(fh).await?;
//!     let fh = fs.open(attr.ino, true, false).await?;
//!     let mut buf = vec![0; data.len()];
//!     fs.read(attr.ino, 0, &mut buf, fh).await?;
//!     fs.release(fh).await?;
//!     assert_eq!(data, String::from_utf8(buf)?);
//!     fs::remove_dir_all(data_dir)?;
//!
//!    Ok(())
//! }
//!
//! fn file_attr() -> CreateFileAttr {
//!     CreateFileAttr {
//!         kind: FileType::RegularFile,
//!         perm: 0o644,
//!         uid: 0,
//!         gid: 0,
//!         rdev: 0,
//!         flags: 0,
//!     }
//! }
//! ```
//! ## Change password from code
//!
//! ### Example
//! ```no_run
//! use std::str::FromStr;
//! use secrecy::SecretString;
//! use rencfs::encryptedfs::{EncryptedFs, FsError, FsResult};
//! use rencfs::crypto::Cipher;
//!
//! #[tokio::main]
//! async fn main() {
//!     use std::path::Path;
//! match EncryptedFs::change_password(Path::new(&"/tmp/rencfs_data"), SecretString::from_str("old-pass").unwrap(), SecretString::from_str("new-pass").unwrap(), Cipher::ChaCha20Poly1305).await {
//!         Ok(_) => println!("Password changed successfully"),
//!         Err(FsError::InvalidPassword) => println!("Invalid old password"),
//!         Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
//!         Err(err) => println!("Error: {err}"),
//!     }
//! }
//! ```
//! ## Change password from CLI with `rpassword` crate
//!
//! ### Example
//!
//! ```no_run
//! use std::io;
//! use std::io::Write;
//! use std::str::FromStr;
//! use rpassword::read_password;
//! use secrecy::{ExposeSecret, Secret, SecretString};
//! use rencfs::encryptedfs::{EncryptedFs, FsError};
//!
//! #[tokio::main]
//! async fn main() {
//!     use std::path::Path;
//! // read password from stdin
//!     use rencfs::crypto::Cipher;
//! print!("Enter old password: ");
//!     io::stdout().flush().unwrap();
//!     let password = SecretString::new(read_password().unwrap());
//!     print!("Enter new password: ");
//!     io::stdout().flush().unwrap();
//!     let new_password = SecretString::new(read_password().unwrap());
//!     print!("Confirm new password: ");
//!     io::stdout().flush().unwrap();
//!     let new_password2 = SecretString::new(read_password().unwrap());
//!     if new_password.expose_secret() != new_password2.expose_secret() {
//!         println!("Passwords do not match");
//!         return;
//!     }
//!     println!("Changing password...");
//!     match EncryptedFs::change_password(Path::new(&"/tmp/rencfs_data"), SecretString::from_str("old-pass").unwrap(), SecretString::from_str("new-pass").unwrap(), Cipher::ChaCha20Poly1305).await {
//!         Ok(_) => println!("Password changed successfully"),
//!         Err(FsError::InvalidPassword) => println!("Invalid old password"),
//!         Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
//!         Err(err) => println!("Error: {err}"),
//!     }
//!     println!("Password changed successfully");
//! }
//! ```
use std::ffi::OsStr;
use std::path::PathBuf;

use fuse3::raw::Session;
use fuse3::MountOptions;
use tracing::{info, instrument};

use crate::crypto::Cipher;
use crate::encryptedfs::PasswordProvider;
use crate::encryptedfs_fuse3::EncryptedFsFuse3;

extern crate test;

pub mod arc_hashmap;
pub mod async_util;
pub mod crypto;
pub mod encryptedfs;
pub mod encryptedfs_fuse3;
pub mod expire_value;
pub mod fs_util;
pub mod stream_util;

#[allow(unreachable_code)]
#[must_use]
pub const fn is_debug() -> bool {
    #[cfg(debug_assertions)]
    {
        return true;
    }
    false
}

#[instrument(skip(password_provider))]
pub async fn run_fuse(
    mountpoint: PathBuf,
    data_dir: PathBuf,
    password_provider: Box<dyn PasswordProvider>,
    cipher: Cipher,
    allow_root: bool,
    allow_other: bool,
    direct_io: bool,
    suid_support: bool,
) -> anyhow::Result<()> {
    let mut mount_options = &mut MountOptions::default();
    #[cfg(target_os = "linux")]
    {
        unsafe {
            mount_options = mount_options.uid(libc::getuid()).gid(libc::getgid());
        }
    }
    let mount_options = mount_options
        .read_only(false)
        .allow_root(allow_root)
        .allow_other(allow_other)
        .clone();
    let mount_path = OsStr::new(mountpoint.to_str().unwrap());

    info!("Checking password and mounting FUSE filesystem");
    Session::new(mount_options)
        .mount_with_unprivileged(
            EncryptedFsFuse3::new(data_dir, password_provider, cipher, direct_io, suid_support)
                .await?,
            mount_path,
        )
        .await?
        .await?;

    Ok(())
}
