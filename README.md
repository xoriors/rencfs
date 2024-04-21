# EncryptedFS

An encrypted file system that mounts with FUSE on Linux. It can be used to create encrypted directories.

It can then safely backup the encrypted folder on an untrusted server without worrying about the data being exposed.\
You can also store it in any clound storage like Google Drive, Dropbox, etc. and have it synced across multiple devices.

\
[![encryptedfs-bin](https://img.shields.io/aur/version/encrypted_fs-bin?color=1793d1&label=encrypted_fs-bin&logo=arch-linux)](https://aur.archlinux.org/packages/encryptedfs-bin/)
![crates.io](https://img.shields.io/crates/v/encryptedfs.svg)
![docs.rs](https://img.shields.io/docsrs/encryptedfs?label=docs.rs)

# Usage

You can use it as a command line tool to mount an encrypted file system, or directly using the library to build your own binary (for library, you can follow the [documentation](https://docs.rs/encryptedfs/latest/encryptedfs/)).

## Command Line Tool

### Install from AUR

You can install the encrypted file system binary using the following command:
```bash
yay -Syu
yay -S encryptedfs
```

### Install with cargo

You can install the encrypted file system binary using the following command:
```bash
cargo install encryptedfs
```

To use the encrypted file system, you need to have FUSE installed on your system. You can install it by running the following command (or based on your distribution):
```bash
sudo apt-get update
sudo apt-get -y install fuse3
```
A basic example of how to use the encrypted file system is shown below:

```
encryptedfs --mount-point MOUNT_POINT --data-dir DATA_DIR
```
Where `MOUNT_POINT` is the directory where the encrypted file system will be mounted and `DATA_DIR` is the directory where the encrypted data will be stored.\
It will prompt you to enter a password to encrypt/decrypt the data.

### Change Password

The encryption key is stored in a file and encrypted with a key derived from the password.
This offers the possibility to change the password without needing to decrypt and re-encrypt the whole data.
This is done by decrypting the key with the old password and re-encrypting it with the new password.

To change the password, you can run the following command:
```bash
encryptedfs --change-password --data-dir DATA_DIR
```
Where `DATA_DIR` is the directory where the encrypted data is stored.\
It will prompt you to enter the old password and then the new password.

### Encryption info

You can specify the encryption algorithm and derive key hash rounds adding these arguments to the command line:

```bash
--cipher CIPHER --derive-key-hash-rounds ROUNDS
```
Where `CIPHER` is the encryption algorithm and `ROUNDS` is the number of rounds to derive the key hash.\
You can check the available ciphers with `encryptedfs --help`.

Default values are `ChaCha20` and `600_000` respectively.

### Log level
You can specify the log level adding the `--log-level` argument to the command line. Possible values: `TRACE`, `DEBUG`, `INFO` (default), `WARN`, `ERROR`.

```bash
--log-level LEVEL
```
