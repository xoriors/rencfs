//! # Encrypted File System
//! An encrypted file system that mounts with FUSE. It can be used to create encrypted directories.
//! # Usage
//! You can use the [EncryptedFsFuse3](encrypted_fs_fuse3::EncryptedFsFuse3) to mount the file system.
//! # Example
//! ```
//! use std::ffi::OsStr;
//! use clap::ArgMatches;
//! use fuse3::MountOptions;
//! use fuse3::raw::Session;
//! use encrypted_fs::encrypted_fs::Cipher;
//! use encrypted_fs::encrypted_fs_fuse3::EncryptedFsFuse3;
//!  async fn run_fuse(matches: ArgMatches, mountpoint: String, data_dir: &str, password: &str, cipher: Cipher, derive_key_hash_rounds: u32) {
//!     let uid = unsafe { libc::getuid() };
//!     let gid = unsafe { libc::getgid() };
//!
//!     let mut mount_options = MountOptions::default();
//!     mount_options.uid(uid).gid(gid).read_only(false);
//!     mount_options.allow_root(matches.get_flag("allow-root"));
//!     mount_options.allow_other(matches.get_flag("allow-other"));
//!
//!     let mount_path = OsStr::new(mountpoint.as_str());
//!     Session::new(mount_options)
//!         .mount_with_unprivileged(EncryptedFsFuse3::new(&data_dir, &password, cipher, derive_key_hash_rounds,
//!                                                        matches.get_flag("direct-io"), matches.get_flag("suid")).unwrap(), mount_path)
//!         .await
//!         .unwrap()
//!         .await
//!         .unwrap();
//! }
//! ```
//! Or directly work with [EncryptedFs](encrypted_fs::EncryptedFs). You need to specify several parameters to create an encrypted file system:
//! - `data_dir`: The directory where the file system will be mounted.
//! - `password`: The password to encrypt/decrypt the data.
//! - `cipher`: The encryption algorithm to use. Currently, it supports these ciphers [Cipher](encrypted_fs::Cipher).
//! - `derive_key_hash_rounds`: The number of rounds to derive the key hash.
//! # Example
//! ```
//! use encrypted_fs::encrypted_fs::{EncryptedFs, FileAttr, FileType};
//! const ROOT_INODE: u64 = 1;
//! let data_dir = "/tmp/encrypted_fs";
//! let password = "password";
//! let cipher = encrypted_fs::encrypted_fs::Cipher::ChaCha20;
//! let derive_key_hash_rounds = 1000;
//! let mut fs = EncryptedFs::new(data_dir, password, cipher, derive_key_hash_rounds).unwrap();
//!
//! let (fh, attr) = fs.create_nod(ROOT_INODE, "file1", create_attr_from_type(FileType::RegularFile), false, true).unwrap();
//! let data = "Hello, world!";
//! fs.write_all(attr.ino, 0, data.as_bytes(), fh).unwrap();
//! fs.flush(fh).unwrap();
//! fs.release(fh).unwrap();
//! let fh = fs.open(ROOT_INODE, true, false).unwrap();
//! let mut buf = vec![0; data.len()];
//! fs.read(ROOT_INODE, 0, &mut buf, fh).unwrap();
//! assert_eq!(data, String::from_utf8(buf).unwrap());
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
//!
//! This crate also contains a `main.rs` file that can be used to run the encrypted file system from the command line.
//! Documentation for that can be found in the `main.rs` file.

pub mod encrypted_fs;
pub mod encrypted_fs_fuse3;
