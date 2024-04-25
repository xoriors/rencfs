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
//! ## EncryptedFsFuse3
//!
//! You can use the [EncryptedFsFuse3](encryptedfs_fuse3::EncryptedFsFuse3) to mount the file system.
//!
//! # Example
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
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](encryptedfs::Cipher).
//! - `derive_key_hash_rounds`: The number of rounds to derive the key hash.
//! - `allow_root`: Allow root to access the file system.
//! - `allow_other`: Allow other users to access the file system.
//! - `direct_io`: Use direct I/O.
//! - `suid_support`: Enable suid support.
//!
//! ## EncryptedFs
//!
//! Or directly work with [EncryptedFs](encryptedfs::EncryptedFs). You need to specify several parameters to create an encrypted file system:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](encryptedfs::Cipher).
//! - `derive_key_hash_rounds`: The number of rounds to derive the key hash.
//!
//! # Example
//!
//! ```
//! use std::fs;
//! use rencfs::encryptedfs::{EncryptedFs, FileAttr, FileType};
//! const ROOT_INODE: u64 = 1;
//! let data_dir = "/tmp/rencfs_data_test";
//! fs::remove_dir_all(data_dir);
//! let password = "password";
//! let cipher = rencfs::encryptedfs::Cipher::ChaCha20;
//! let derive_key_hash_rounds = 1000;
//! let mut fs = EncryptedFs::new(data_dir, password, cipher, derive_key_hash_rounds).unwrap();
//!
//! let (fh, attr) = fs.create_nod(ROOT_INODE, "file1", create_attr_from_type(FileType::RegularFile), false, true).unwrap();
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
//! fn create_attr(ino: u64, file_type: FileType) -> FileAttr {
//!     FileAttr {
//!         ino,
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
//!
//! fn create_attr_from_type(file_type: FileType) -> FileAttr {
//!     create_attr(0, file_type)
//! }
//! ```
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;

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
