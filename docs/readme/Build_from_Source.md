# Build from source

## In the browser

If you want to give it a quick try and not setup anything locally, you can  
[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/radumarias/rencfs)

[![Open Rustlings On Codespaces](https://github.com/codespaces/badge.svg)](https://github.com/codespaces/new/?repo=radumarias%2Frencfs&ref=main)

You can compile, run, and try it quickly in the browser. After you start it from above

```bash
apt-get update && apt-get install fuse3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
mkdir final && mkdir data
cargo run --release -- mount -m final -d data
```

Open another terminal

```bash
cd final
mkdir a && cd a
echo "test" > test.txt
cat test.txt
```

You can also:
- Copy files and folders from your local machine to `tmp` folder in VSCode in the browser. So that we eliminate network errors when testing
- Then copy files and folders from `tmp` to `final` and then do your operations in the `final` folder
- Ensure files were copied successfully by right-clicking a file and then `Download...` and saving it to the local machine to ensure it opens correctly. For popular formats like image text, you can preview them in the browser editor

## Locally

For now, the `FUSE` (`fuse3` crate) only works on `Linux`, so you must be on Linux to start the project. 
Instead, you can [Develop inside a Container](#developing-inside-a-container) by starting a local Linux container to which the IDE will connect. You can build, run, and debug the app there and use the terminal to test it.  
On Windows, you can start it in [WSL](https://harsimranmaan.medium.com/install-and-setup-rust-development-environment-on-wsl2-dccb4bf63700).

### Getting the sources

```bash
git clone git@github.com:radumarias/rencfs.git && cd rencfs
````

### Dependencies

#### Rust

To build from the source, you need to have Rust installed. You can see more details on installing it [here](https://www.rust-lang.org/tools/install).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
````

Accordingly, it is customary for Rust developers to include this directory in their `PATH` environment variable.
During installation, `rustup` will attempt to configure the `PATH`. Because of differences between platforms, command
shells,
and bugs in `rustup`, the modifications to `PATH` may not take effect until the console is restarted or the user is
logged out, or it may not succeed at all.

If, after installation, running `rustc --version` in the console fails, this is the most likely reason.
In that case, please manually add it to the `PATH`.

The project is set up to use the `nightly` toolchain in `rust-toolchain. tool`; on the first build, you will see it fetch the nightly.

Make sure to add this to your `$PATH` too.

```bash
export PATH="$PATH::$HOME/.cargo/bin"
```

```bash
cargo install cargo-aur
cargo install cargo-generate-rpm
```

### Other dependencies

Also, these dependencies are required (or based on your distribution):

#### Arch

```bash
sudo pacman -Syu && sudo pacman -S fuse3 base-devel act
```

#### Ubuntu

```bash
sudo apt-get update && sudo apt-get install fuse3 build-essential act
```

#### Fedora

```bash
sudo dnf update && sudo dnf install fuse3 && dnf install @development-tools act
```

### Build for debug

```bash
cargo build
```

### Build release

```bash
cargo build --release
```

### Run

```bash
cargo run --release -- mount --mount-point MOUNT_POINT --data-dir DATA_DIR
```

#### Dev settings

If you don't want to be prompted for a password, you can set this env var and run it like this:

```bash
RENCFS_PASSWORD=PASS cargo run --release -- mount --mount-point MOUNT_POINT --data-dir DATA_DIR
```

For dev mode, it is recommended to run with `DEBUG` log level:

```bash
cargo run --release -- --log-level DEBUG mount --mount-point MOUNT_POINT --data-dir DATA_DIR
```

### Build local RPM for Fedora

This is using [cargo-generate-rpm](https://crates.io/crates/cargo-generate-rpm)

```bash
cargo install cargo-generate-rpm
cargo build --release
cargo generate-rpm
```

The generated RPM will be located here: `target/generate-rpm`.

#### Install and run local RPM

```bash
cd target/generate-rpm/
sudo dnf localinstall rencfs-xxx.x86_64.rpm
```

## Developing inside a Container

See here how to configure for [RustRover](https://www.jetbrains.com/help/rust/connect-to-devcontainer.html) and for [VsCode](https://code.visualstudio.com/docs/devcontainers/containers).

You can use the `.devcontainer` directory from the project to start a container with all the necessary tools to build
and run the app.
