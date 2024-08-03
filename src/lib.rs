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
//! # Encrypted File System
//!
//! An encrypted file system that mounts with FUSE on Linux. It can be used to create encrypted directories.
//!
//! # Usage
//!
//! It can be used a library to create an encrypted file system or mount it with FUSE.
//!
//! This crate also contains **main.rs** file that can be used as an example on how to run the encrypted file system from the command line.
//! Documentation for that can be found [here](https://github.com/radumarias/rencfs#command-line-tool).
//!
//! In the following example, we will see how we can use the library.
//!
//! ## Using [`mount::create_mount_point`] on Linux
//!
//! ### Example
//!
//! ```no_run
//! use std::env::args;
//! use std::path::Path;
//! use std::str::FromStr;
//! use std::io;
//!
//! use anyhow::Result;
//! use secrecy::SecretString;
//!
//! use rencfs::crypto::Cipher;
//! use rencfs::encryptedfs::PasswordProvider;
//! use rencfs::mount::create_mount_point;
//! use rencfs::mount::MountPoint;
//!
//! /// This will mount and expose the mount point until you press `Enter`, then it will umount and close the program.
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     tracing_subscriber::fmt().init();
//!
//!     let mut args = args();
//!     args.next(); // skip program name
//!     let mount_path = args.next().expect("mount_path expected");
//!     let data_path = args.next().expect("data_path expected");
//!     use tracing::info;struct PasswordProviderImpl {}
//!     impl PasswordProvider for PasswordProviderImpl {
//!         fn get_password(&self) -> Option<SecretString> {
//!             // dummy password, use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
//!             Some(SecretString::from_str("pass42").unwrap())
//!         }
//!     }
//!     let mount_point = create_mount_point(
//!         Path::new(&mount_path),
//!         Path::new(&data_path),
//!         Box::new(PasswordProviderImpl {}),
//!         Cipher::ChaCha20Poly1305,
//!         false,
//!         false,
//!         false,
//!         false,
//!     );
//!     let handle = mount_point.mount().await?;
//!     let mut buffer = String::new();
//!     io::stdin().read_line(&mut buffer)?;
//!     info!("Unmounting...");
//!     info!("Bye!");
//!     handle.umount().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Or directly work with [`encryptedfs::EncryptedFs`]
//!
//! You need to specify several parameters to create an encrypted file system:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use.
//!
//! Currently, it supports these ciphers [Cipher](crypto::Cipher).
//!
//! ### Example
//!
//! ```
//! use std::fs;
//! use std::str::FromStr;
//! use secrecy::SecretString;
//! use rencfs::encryptedfs::{EncryptedFs, FileType, PasswordProvider, CreateFileAttr};
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
//!         // dummy password, use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
//!         Some(SecretString::from_str("pass42").unwrap())
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     tracing_subscriber::fmt().init();
//!
//!     let data_dir = Path::new("/tmp/rencfs_data_test").to_path_buf();
//!     let  _ = fs::remove_dir_all(data_dir.to_str().unwrap());
//!     let cipher = Cipher::ChaCha20Poly1305;
//!     let mut fs = EncryptedFs::new(data_dir.clone(), Box::new(PasswordProviderImpl{}), cipher ).await?;
//!
//!     let  file1 = SecretString::from_str("file1").unwrap();
//!     let (fh, attr) = fs.create(ROOT_INODE, &file1, file_attr(), false, true).await?;
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
//! use rencfs::crypto::Cipher;
//! use rencfs::encryptedfs::{EncryptedFs, FsError};
//! use secrecy::SecretString;
//! use std::env::args;
//! use std::path::Path;
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() {
//!     tracing_subscriber::fmt().init();
//!
//!     let mut args = args();
//!     let _ = args.next(); // skip the program name
//!     let data_dir = args.next().expect("data_dir is missing");
//!
//!     match EncryptedFs::passwd(
//!         Path::new(&data_dir),
//!         SecretString::from_str("old-pass").unwrap(),
//!         SecretString::from_str("new-pass").unwrap(),
//!         Cipher::ChaCha20Poly1305,
//!     )
//!     .await
//!     {
//!         Ok(_) => println!("Password changed successfully"),
//!         Err(FsError::InvalidPassword) => println!("Invalid old password"),
//!         Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
//!         Err(err) => println!("Error: {err}"),
//!     }
//! }
//! ```
//! ## Change password from CLI using [rpassword](https://crates.io/crates/rpassword) crate
//!
//! ### Example
//!
//! ```no_run
//! use std::env::args;
//! use std::io;
//! use std::io::Write;
//! use std::str::FromStr;
//!
//! use rpassword::read_password;
//! use secrecy::{ExposeSecret, SecretString};
//! use tracing::{error, info};
//!
//! use rencfs::encryptedfs::{EncryptedFs, FsError};
//! #[tokio::main]
//! async fn main() {
//!     tracing_subscriber::fmt().init();
//!
//!     let mut args = args();
//!     let _ = args.next(); // skip the program name
//!     let data_dir = args.next().expect("data_dir is missing");
//!
//!     use std::path::Path;
//!     // read password from stdin
//!     use rencfs::crypto::Cipher;
//!     print!("Enter old password: ");
//!     io::stdout().flush().unwrap();
//!     let old_password = SecretString::new(read_password().unwrap());
//!     print!("Enter new password: ");
//!     io::stdout().flush().unwrap();
//!     let new_password = SecretString::new(read_password().unwrap());
//!     print!("Confirm new password: ");
//!     io::stdout().flush().unwrap();
//!     let new_password2 = SecretString::new(read_password().unwrap());
//!     if new_password.expose_secret() != new_password2.expose_secret() {
//!         error!("Passwords do not match");
//!         return;
//!     }
//!     println!("Changing password...");
//!     match EncryptedFs::passwd(
//!         Path::new(&data_dir),
//!         old_password,
//!         new_password,
//!         Cipher::ChaCha20Poly1305,
//!     )
//!     .await
//!     {
//!         Ok(_) => info!("Password changed successfully"),
//!         Err(FsError::InvalidPassword) => error!("Invalid old password"),
//!         Err(FsError::InvalidDataDirStructure) => error!("Invalid structure of data directory"),
//!         Err(err) => error!("Error: {err}"),
//!     }
//! }
//! ```
//!
//! ## Encrypted Writer and Reader
//!
//! We also expose a Writer and Reader in encrypted format, which implements [`std::io::Write`], [`std::io::Read`] and [`std::io::Seek`].
//! You can wrap any [`std::io::Write`] and [`std::io::Read`], like a file, to write and read encrypted content.
//! This is using [ring](https://crates.io/crates/ring) crate to handle encryption.
//!
//! ### Example
//! ```no_run
//! use anyhow::Result;
//! use rand_core::RngCore;
//! use std::env::args;
//! use std::fs::File;
//! use std::io;
//! use std::io::Write;
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use secrecy::SecretVec;
//! use tracing::info;
//!
//! use rencfs::crypto;
//! use rencfs::crypto::write::CryptoWrite;
//! use rencfs::crypto::Cipher;
//!
//! fn main() -> Result<()> {
//!     tracing_subscriber::fmt().init();
//!
//!     let cipher = Cipher::ChaCha20Poly1305;
//!     let mut key = vec![0; cipher.key_len()];
//!     crypto::create_rng().fill_bytes(key.as_mut_slice());
//!     let key = SecretVec::new(key);
//!
//!     let mut args = args();
//!     // skip the program name
//!     let _ = args.next();
//!     // will encrypt this file
//!     let path_in = args.next().expect("path_in is missing");
//!     // will save it in the same directory with .enc suffix
//!     let out = Path::new(&path_in).to_path_buf().with_extension("enc");
//!     if out.exists() {
//!         std::fs::remove_file(&out)?;
//!     }
//!
//!     let mut file = File::open(path_in.clone())?;
//!     let mut writer = crypto::create_write(File::create(out.clone())?, cipher, &key);
//!     info!("encrypt file");
//!     io::copy(&mut file, &mut writer).unwrap();
//!     writer.finish()?;
//!
//!     let mut reader = crypto::create_read(File::open(out)?, cipher, &key);
//!     info!("read file and compare hash to original one");
//!     let hash1 = crypto::hash_reader(&mut File::open(path_in)?)?;
//!     let hash2 = crypto::hash_reader(&mut reader)?;
//!     assert_eq!(hash1, hash2);
//!
//!     Ok(())
//! }
//! ```
extern crate test;

use std::sync::LazyLock;

pub mod arc_hashmap;
pub mod async_util;
pub mod crypto;
pub mod encryptedfs;
pub mod expire_value;
pub mod fs_util;
pub mod log;
pub mod mount;
pub mod stream_util;
pub(crate) mod test_common;

pub static UID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::getuid() });
pub static GID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::getgid() });

#[allow(unreachable_code)]
#[must_use]
pub const fn is_debug() -> bool {
    #[cfg(debug_assertions)]
    return true;
    false
}
