# RencFs

An encrypted file system that mounts with FUSE on Linux. It can be used to create encrypted directories.

You can then safely backup the encrypted folder on an untrusted server without worrying about the data being exposed.\
You can also store it in any cloud storage like Google Drive, Dropbox, etc. and have it synced across multiple devices.

\
[![rencfs-bin](https://img.shields.io/aur/version/rencfs-bin?color=1793d1&label=rencfs-bin&logo=arch-linux)](https://aur.archlinux.org/packages/rencfs-bin/)
[![crates.io](https://img.shields.io/crates/v/rencfs.svg)](https://crates.io/crates/rencfs)
[![docs.rs](https://img.shields.io/docsrs/rencfs?label=docs.rs)](https://docs.rs/rencfs/)
[![test](https://github.com/radumarias/rencfs/actions/workflows/test.yml/badge.svg)](https://github.com/radumarias/rencfs/actions/workflows/test.yml)


# Functionality

I keeps all encrypted data and encryption key in a dedicated directory with files structured on inodes (with meta info), files for binary content and directories with files/directories entries. All data, metadata and also filenames are encrypted. For new files it generates inode number randomly in `u64` space so it reduces the chance of conflicts when used offline and synced later.

Password is collected from CLI and can be saved in OS keyring.
Encryption key is also encrypted with another key derived from the password. This gives the ability to change the password without re-encrypting all data, we just re-encrypt the key.

# Stack

- it's fully async built upon [tokio](https://crates.io/crates/tokio) and [fuse3](https://crates.io/crates/fuse3)
- [ring](https://crates.io/crates/ring) for encryption and [argon2](https://crates.io/crates/argon2) for key derivation function (creating key used to encrypt master encryption key from password)
- [secrecy](https://crates.io/crates/secrecy) for keeping pass and encryption keys safe in memory and zeroing them when not used. It keeps encryption keys in memory only while being used and when not active it will release and zeroing them from memory
- password can be saved in OS keyring using [keyring](https://crates.io/crates/keyring)
- [tracing](https://crates.io/crates/tracing) for logs

# Usage

You can use it as a command line tool to mount an encrypted file system, or directly using the library to build your own binary (for library, you can follow the [documentation](https://docs.rs/rencfs/latest/rencfs/)).

## Command Line Tool

To use the encrypted file system, you need to have FUSE installed on your system. You can install it by running the following command (or based on your distribution)

Arch
```bash
sudo pacman -Syu && sudo pacman -S fuse3
```
Ubuntu
```bash
sudo apt-get update && sudo apt-get -y install fuse3
```

### Install from AUR

You can install the encrypted file system binary using the following command
```bash
yay -Syu && yay -S rencfs
```

### Install with cargo

You can install the encrypted file system binary using the following command
```bash
cargo install rencfs
```

A basic example of how to use the encrypted file system is shown below

```
rencfs --mount-point MOUNT_POINT --data-dir DATA_DIR
```
Where `MOUNT_POINT` is the directory where the encrypted file system will be mounted and `DATA_DIR` is the directory where the encrypted data will be stored.\
It will prompt you to enter a password to encrypt/decrypt the data.

### Change Password

The encryption key is stored in a file and encrypted with a key derived from the password.
This offers the possibility to change the password without needing to decrypt and re-encrypt the whole data.
This is done by decrypting the key with the old password and re-encrypting it with the new password.

To change the password, you can run the following command
```bash
rencfs --change-password --data-dir DATA_DIR
```
Where `DATA_DIR` is the directory where the encrypted data is stored.\
It will prompt you to enter the old password and then the new password.

### Encryption info

You can specify the encryption algorithm adding this argument to the command line

```bash
--cipher CIPHER
```
Where `CIPHER` is the encryption algorithm.\
You can check the available ciphers with `rencfs --help`.

Default values are `ChaCha20` and `600_000` respectively.

### Log level

You can specify the log level adding the `--log-level` argument to the command line. Possible values: `TRACE`, `DEBUG`, `INFO` (default), `WARN`, `ERROR`.

```bash
--log-level LEVEL
```

## Start it in docker

Get the image
```bash
docker pull xorio42/rencfs
```
Start a container to set up mount in it

`docker run -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined xorio42/rencfs:latest /bin/sh`

In the container create mount and data directories

`mkdir fsmnt && mkdir fsdata`

Start `rencfs`

`rencfs --mount-point fsmnt --data-dir fsdata`

Enter a password for encryption.

Get the container ID

`docker ps`

In another terminal  attach to running container with the above ID

`docker exec -it <ID> /bin/sh`

From here you can play with it by creating files in `fsmnt` directory
```
cd fsmnt
mkdir 1
ls
echo "test" > 1/test
cat 1/test
```

# Building from source

## Getting the sources

```bash
git@github.com:radumarias/rencfs.git
````

## Dependencies

### Rust

To build from source, you need to have Rust installed, you can see more details on how to install it [here](https://www.rust-lang.org/tools/install).
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
````

Accordingly, it is customary for Rust developers to include this directory in their `PATH` environment variable.
During installation `rustup` will attempt to configure the `PATH`. Because of differences between platforms, command shells, 
and bugs in `rustup`, the modifications to `PATH` may not take effect until the console is restarted, or the user is logged out, or it may not succeed at all.

If, after installation, running `rustc --version` in the console fails, this is the most likely reason.
In that case please add it to the `PATH` manually.

### Other dependencies

Also these deps are required (or based on your distribution):

Arch
```bash
sudo pacman -Syu && sudo pacman -S openssl lib32-openssl fuse3 base-devel
```

Ubuntu
```bash
sudo apt-get update && sudo apt-get install libssl-dev openssl fuse3 build-essentials
```

## Build for debug

```bash
cargo build
```

## Build release

```bash
cargo build --release
```

## Run

```bash
cargo run -- --mount-point MOUNT_POINT --data-dir DATA_DIR
```

# Future

- Plan is to implement it also on macOS and Windows
- A systemd service is being worked on [rencfs-daemon](https://github.com/radumarias/rencfs-daemon
- A GUI is on the way [rencfs_desktop](https://github.com/radumarias/rencfs_desktop)
- Mobile apps for Android and iOS are on the way

# Contribution

Feel free to fork it and change it the way you want. If you build something interesting and feel to share pull requests are always apporeciated
