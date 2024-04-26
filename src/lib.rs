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
//! ## Calling (run_fuse)[run_fuse]
//!
//! ### Example
//!
//! ```no_run
//! use rencfs::run_fuse;
//! use rencfs::encryptedfs::Cipher;
//!
//! #[tokio::main]
//! async fn main() {
//!     run_fuse("/tmp/rencfs", "/tmp/rencfs_data", "password", Cipher::ChaCha20, 1000, false, false, false, false).await.unwrap();
//! }
//! ```
//!
//! ## Using [EncryptedFsFuse3](EncryptedFsFuse3)
//!
//! ### Example
//!
//! ```no_run
//! use std::ffi::OsStr;
//! use fuse3::MountOptions;
//! use fuse3::raw::Session;
//! use rencfs::encryptedfs::Cipher;
//! use rencfs::encryptedfs_fuse3::EncryptedFsFuse3;
//!
//! async fn run_fuse(mountpoint: &str, data_dir: &str, password: &str, cipher: Cipher, derive_key_hash_rounds: u32,
//!                   allow_root: bool, allow_other: bool, direct_io: bool, suid_support: bool) {
//!     let uid = unsafe { libc::getuid() };
//!     let gid = unsafe { libc::getgid() };
//!
//!     let mut mount_options = MountOptions::default()
//!         .uid(uid).gid(gid)
//!         .read_only(false)
//!         .allow_root(allow_root)
//!         .allow_other(allow_other)
//!         .clone();
//!     let mount_path = OsStr::new(mountpoint);
//!
//!     Session::new(mount_options)
//!         .mount_with_unprivileged(EncryptedFsFuse3::new(&data_dir, &password, cipher, derive_key_hash_rounds, direct_io, suid_support).unwrap(), mount_path)
//!         .await
//!         .unwrap()
//!         .await
//!         .unwrap();
//! }
//! ```
//! Parameters:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](Cipher).
//! - `derive_key_hash_rounds`: The number of rounds to derive the key hash.
//! - `allow_root`: Allow root to access the file system.
//! - `allow_other`: Allow other users to access the file system.
//! - `direct_io`: Use direct I/O.
//! - `suid_support`: Enable suid support.
//!
//! ## Or directly work with [EncryptedFs](EncryptedFs)
//!
//! You need to specify several parameters to create an encrypted file system:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](Cipher).
//! - `derive_key_hash_rounds`: The number of rounds to derive the key hash.
//!
//! ### Example
//!
//! ```
//! use std::fs;
//! use rencfs::encryptedfs::{EncryptedFs, FileAttr, FileType};
//! const ROOT_INODE: u64 = 1;
//! let data_dir = "/tmp/rencfs_data_test";
//! let  _ = fs::remove_dir_all(data_dir);
//! let password = "password";
//! let cipher = rencfs::encryptedfs::Cipher::ChaCha20;
//! let derive_key_hash_rounds = 1000;
//! let mut fs = EncryptedFs::new(data_dir, password, cipher, derive_key_hash_rounds).unwrap();
//!
//! let (fh, attr) = fs.create_nod(ROOT_INODE, "file1", create_attr(FileType::RegularFile), false, true).unwrap();
//! let data = "Hello, world!";
//! fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
//! fs.flush(fh).unwrap();
//! fs.release(fh).unwrap();
//! let fh = fs.open(attr.ino, true, false).unwrap();
//! let mut buf = vec![0; data.len()];
//! fs.read(attr.ino, 0, &mut buf, fh).unwrap();
//! fs.release(fh).unwrap();
//! assert_eq!(data, String::from_utf8(buf).unwrap());
//! fs::remove_dir_all(data_dir).unwrap();
//!
//! fn create_attr(file_type: FileType) -> FileAttr {
//!     FileAttr {
//!         ino: 0,
//!         size: 0,
//!         blocks: 0,
//!         atime: std::time::SystemTime::now(),
//!         mtime: std::time::SystemTime::now(),
//!         ctime: std::time::SystemTime::now(),
//!         crtime: std::time::SystemTime::now(),
//!         kind: file_type,
//!         perm: if file_type == FileType::Directory { 0o755 } else { 0o644 },
//!         nlink: if file_type == FileType::Directory { 2 } else { 1 },
//!         uid: 0,
//!         gid: 0,
//!         rdev: 0,
//!         blksize: 0,
//!         flags: 0,
//!     }
//! }
//! ```
//! ## Change password from code
//!
//! ### Example
//! ```no_run
//! use rencfs::encryptedfs::{EncryptedFs, FsError, FsResult};
//! use rencfs::encryptedfs::Cipher;
//!
//! match EncryptedFs::change_password("/tmp/rencfs_data", "old-pass", "new-pass", Cipher::ChaCha20, 1000) {
//!     Ok(_) => println!("Password changed successfully"),
//!     Err(FsError::InvalidPassword) => println!("Invalid old password"),
//!     Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
//!     Err(err) => println!("Error: {err}"),
//! }
//! ```
//! ## Change password from CLI with `rpassword` crate
//!
//! ### Example
//!
//! ```no_run
//! use std::io;
//! use std::io::Write;
//! use rpassword::read_password;
//! use rencfs::encryptedfs::{Cipher, EncryptedFs, FsError};
//!
//! // read password from stdin
//! print!("Enter old password: ");
//! io::stdout().flush().unwrap();
//! let password = read_password().unwrap();
//! print!("Enter new password: ");
//! io::stdout().flush().unwrap();
//! let new_password = read_password().unwrap();
//! print!("Confirm new password: ");
//! io::stdout().flush().unwrap();
//! let new_password2 = read_password().unwrap();
//! if new_password != new_password2 {
//!     println!("Passwords do not match");
//!     return;
//! }
//! println!("Changing password...");
//! match EncryptedFs::change_password("/tmp/rencfs_data", "old-pass", "new-pass", Cipher::ChaCha20, 1000) {
//!     Ok(_) => println!("Password changed successfully"),
//!     Err(FsError::InvalidPassword) => println!("Invalid old password"),
//!     Err(FsError::InvalidDataDirStructure) => println!("Invalid structure of data directory"),
//!     Err(err) => println!("Error: {err}"),
//! }
//! println!("Password changed successfully");
//! ```
use tracing::{info, instrument, Level};
use tracing_appender::non_blocking::WorkerGuard;
use fuse3::MountOptions;
use std::ffi::OsStr;
use fuse3::raw::Session;
use crate::encryptedfs::Cipher;
use crate::encryptedfs_fuse3::EncryptedFsFuse3;

pub mod encryptedfs;
pub mod encryptedfs_fuse3;

#[allow(unreachable_code)]
pub fn is_debug() -> bool {
    #[cfg(debug_assertions)] {
        return true;
    }
    return false;
}

pub fn log_init(level: Level) -> WorkerGuard {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let builder = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(level);
    if is_debug() {
        builder
            .pretty()
            .init()
    } else {
        builder.init();
    }

    guard
}

#[instrument(skip(password))]
pub async fn run_fuse(mountpoint: &str, data_dir: &str, password: &str, cipher: Cipher, derive_key_hash_rounds: u32,
                      allow_root: bool, allow_other: bool, direct_io: bool, suid_support: bool) -> anyhow::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mount_options = MountOptions::default()
        .uid(uid)
        .gid(gid)
        .read_only(false).
        allow_root(allow_root).
        allow_other(allow_other)
        .clone();
    let mount_path = OsStr::new(mountpoint);

    info!("Checking password and mounting FUSE filesystem");
    Session::new(mount_options)
        .mount_with_unprivileged(EncryptedFsFuse3::new(data_dir, password, cipher, derive_key_hash_rounds, direct_io, suid_support)?, mount_path)
        .await?
        .await?;

    Ok(())
}
