# Usage

<!---
## Give it a quick try with Run on Google Cloud

[![Run on Google Cloud](https://deploy.cloud.run/button.svg)](https://deploy.cloud.run)
-->

## Give it a quick try with Docker

Get the image

```bash
docker pull xorio42/rencfs
```

Start a container to set up mount in it

```bash
docker run -v ~/Downloads:/share -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined xorio42/rencfs:latest /bin/sh
```

**Replace `~/Downloads` with a path you want to share with the container.**

In the container, create mount and data directories

```bash
mkdir mnt && mkdir data
```

Start `rencfs`

```bash
rencfs mount --mount-point mnt --data-dir data -l WARN
```

Enter a password for encryption.

Get the container ID

```bash
docker ps
```

In another terminal, attach to the running container with the above ID

```bash
docker exec -it <CONTAINER-ID> /bin/sh
```

From here, you can play with it by creating files in `mnt` directory

```bash
cd mnt
mkdir 1
ls
echo "test" > 1/test
cat 1/test
```

You can also copy files from `/share`.

```bash
cd mnt
cp /share/file1.txt .
file file1.txt
```

## As a library

For the library, you can follow the [documentation](https://docs.rs/rencfs/latest/rencfs/).

## Command Line Tool

### Dependencies

To use the encrypted file system, you need to have FUSE installed on your system. You can install it by running the
following command (or based on your distribution).

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

### Usage

A basic example of how to use the encrypted file system is shown below

```
rencfs mount --mount-point MOUNT_POINT --data-dir DATA_DIR
```

- `MOUNT_POINT` act as a client, and mount FUSE at the given path
- `DATA_DIR` where to store the encrypted data
  with the sync provider. But it needs to be on the same filesystem as the data-dir

It will prompt you to enter a password to encrypt/decrypt the data.

### Change Password

The master encryption key is stored in a file and encrypted with a key derived from the password.
This offers the possibility to change the password without needing to re-encrypt the whole data. This is done by
decrypting the master key with the old password and re-encrypting it with the new password.

To change the password, you can run the following command

```bash
rencfs passwd --data-dir DATA_DIR 
```

`DATA_DIR` where the encrypted data is stored

It will prompt you to enter the old password and then the new password.

### Encryption info

You can specify the encryption algorithm by adding this argument to the command line

```bash
--cipher CIPHER ...
```

Where `CIPHER` is the encryption algorithm. You can check the available ciphers with `rencfs --help`.  
The default value is `ChaCha20Poly1305`.

### Log level

You can specify the log level by adding the `--log-level` argument to the command line. Possible
values: `TRACE`, `DEBUG`, `INFO` (default), `WARN`, `ERROR`.

```bash
rencfs --log-level LEVEL ...
```

## Use it in Rust

You can see more [here](https://crates.io/crates/rencfs)