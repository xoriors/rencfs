# [![](favicon.png)](https://github.com/xoriors/rencfs) rencfs

[![rencfs-bin](https://img.shields.io/aur/version/rencfs-bin?color=1793d1&label=rencfs-bin&logo=arch-linux)](https://aur.archlinux.org/packages/rencfs-bin/)
[![crates.io](https://img.shields.io/crates/v/rencfs.svg)](https://crates.io/crates/rencfs)
[![docs.rs](https://img.shields.io/docsrs/rencfs?label=docs.rs)](https://docs.rs/rencfs/)
[![build-and-tests](https://github.com/xoriors/rencfs/actions/workflows/build_and_tests.yaml/badge.svg)](https://github.com/xoriors/rencfs/actions/workflows/build_and_tests.yaml)
[![release](https://github.com/xoriors/rencfs/actions/workflows/release.yaml/badge.svg)](https://github.com/xoriors/rencfs/actions/workflows/release.yaml)
[![codecov](https://codecov.io/gh/xoriors/rencfs/graph/badge.svg?token=NUQI6XGF2Y)](https://codecov.io/gh/xoriors/rencfs)
<a href="https://bit.ly/3UU1oXi"><img src="website/resources/slack.png" style = "width: 20px; height: 20px;"/></a>
[![Open Source Helpers](https://www.codetriage.com/xoriors/rencfs/badges/users.svg)](https://www.codetriage.com/xoriors/rencfs)

> [!WARNING]  
> **This crate hasn't been audited; it's using `ring` crate, which is a well-known audited library, so in principle, at
least the primitives should offer a similar level of security.  
> This is still under development. Please do not use it with sensitive data for now; please wait for a
stable release.  
> It's mostly ideal for experimental and learning projects.**

An encrypted file system written in Rust mounted with FUSE on Linux. It can be used to create encrypted
directories.

You can then safely back up the encrypted directory to an untrusted server without worrying about the data being
exposed.
You can also store it in a cloud storage service like Google Drive, Dropbox, etc., and sync it across multiple devices.

You can use it as CLI or as a library to build your custom FUSE implementation or other apps that work with encrypted
data.

# Introduction

- Motivation
  Create a `simple,` `performant,` `modular` and `ergonomic` yet `very secure` `encrypted filesystem` to protect
  your `privacy`, which is also `open source` and is correctly and safely using `well-known audited` crates
  as `cryptographic primitives`.
- Read an article [The Hitchhiker’s Guide to Building an Encrypted Filesystem in Rust](https://medium.com/system-weakness/hitchhikers-guide-to-building-a-distributed-filesystem-in-rust-the-very-beginning-2c02eb7313e7).
- A one-pager [The Hitchhiker’s Guide to Building an Encrypted Filesystem in Rust](docs/The_Hitchhiker_s_Guide_to_Building_an_Encrypted_Filesystem_in_Rust.pdf).
- Talks
    - [The Hitchhiker’s Guide to Building an Encrypted Filesystem in Rust](https://startech-rd.io/hitchhikers-guide-to/) @[meetup.com/star-tech-rd-reloaded](https://www.meetup.com/star-tech-rd-reloaded/) and @[OmniOpenCon](https://omniopencon.org/).
    - [Basics of cryptography, Authenticated Encryption, Rust in cryptography and how to build an encrypted filesystem](https://www.youtube.com/live/HwmVxOl3pQg) @ITDays and [slides](https://miro.com/app/board/uXjVLccxeCE=/?share_link_id=342563218323).
- It was [crate of the week](https://this-week-in-rust.org/blog/2024/08/14/this-week-in-rust-560/#crate-of-the-week) in Aug 2024.

# Key features

Some of these are still being worked on and marked with `[WIP]`.

- `Security` using well-known audited `AEAD` cryptography primitives;
- `[WIP]` [Data integrity, data is written with WAL to ensure integrity even on crash or power loss](https://github.com/xoriors/rencfs/issues/48)
- `[WIP]` [Hide all info for enhanced privacy; all metadata, content, file name, file size, *time fields, files count, and directory structure is encrypted](https://github.com/xoriors/rencfs/issues/53)
- `Safely` manage `credentials` in memory with `mlock(2)`, `mprotect`, `zeroize`, and `expiry` to mitigate cold boot
  attacks;
- `Memory safety`, `performance`, and `optimized` for `concurrency` with Rust;
- Simplicity;
- Encryption key generated from password;
- Password saved in OS's `keyring`;
- `Change password` without re-encrypting all data;
- `[WIP]` [Generate unique nonce in offline mode](https://github.com/xoriors/rencfs/issues/47)
- `[WIP]` [Add file inode and chunk index to AAD](https://github.com/xoriors/rencfs/issues/49) This prevents blocks
  from being copied between or within files by an attacker;
- `Fast seek` on both reads and writes;
- `Writes in parallel`;
- Exposed with `FUSE`;
- Fully `concurrent` for all operations;
- `[WIP]` [Handle long file names](https://github.com/xoriors/rencfs/issues/47)
- `[WIP]` [Abstraction layer for Rust File and fs API to use it as lib to switch to using encrypted files by just changing the use statements](https://github.com/xoriors/rencfs/issues/97)
- `[WIP]` [Abstraction layer to access the storage with implementations for desktop, Wasm, Android, and iOS and the ability to write your own implementation](https://github.com/xoriors/rencfs/issues/111)

# [Alternatives](docs/readme/Alternatives.md)

# Implementation

- [Functionality](docs/readme/Functionality.md)
- [Stack](docs/readme/Stack.md)

# Documentation

- [Docs](docs/)

[![rencfs](website/resources/layers.png)](website/resources/layers.png)

Please look into [Flows](docs/readme/flows.md) for a detailed sequence flow description.

# Usage and Development

- [Usage](docs/readme/Usage.md)
- [Build from Source](docs/readme/Build_from_Source.md)
- Minimum Supported Rust Version (MSRV). The minimum supported version is `1.75`.

# Next steps

- The plan is to implement it also on macOS and Windows
- **Systemd service** is being worked on [rencfs-daemon](https://github.com/radumarias/rencfs-daemon)
- **GUI** is being worked on [rencfs-desktop](https://github.com/radumarias/rencfs-desktop)
  and [ciphershell-kotlin](https://github.com/radumarias/ciphershell-kotlin)
- **Mobile apps** for **Android** and **iOS** are being worked
  on [ciphershell-kotlin](https://github.com/radumarias/ciphershell-kotlin)

# Considerations

- Performance
  `Aes256Gcm` is slightly faster than `ChaCha20Poly1305` by an average factor of **1.28**. This is because of the
  hardware acceleration of AES
  on most CPUs via AES-NI. However, where hardware acceleration is unavailable, `ChaCha20Poly1305` is faster.
  Also, `ChaChaPoly1305` is better at `SIMD.`
- [⚠️ Security ](docs/readme/Security.md)
- [Cipher comparison](docs/readme/Cipher_comparison.md)
- [Others](docs/readme/Considerations.md)

# Contribute

If you find any issues or vulnerabilities or you'd like a feature, please follow these steps:
- [Open a bug](https://github.com/xoriors/rencfs/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=): Create a report to help us improve.
- [Report a security vulnerability](https://github.com/xoriors/rencfs/security/advisories/new): Report a security vulnerability.
- [Feature request](https://github.com/xoriors/rencfs/issues/new?assignees=&labels=&projects=&template=feature_request.md&title=): Suggest an idea for this project.

Feel free to fork, change, and use it however you want. We always appreciate it if you build something interesting and feel like sharing pull requests.

- How to contribute
  Please see [CONTRIBUTING.md](.github/CONTRIBUTING.md).

# Follow us

- Blog and tutorial
  There is a [series](https://medium.com/@xorio42/list/828492b94c23) of articles about the evolution of this
  project, trying to keep it like a tutorial. This is
  the [first one](https://systemweakness.com/the-hitchhikers-guide-to-building-an-encrypted-filesystem-in-rust-4d678c57d65c).

# Get in touch

- [Slack](https://bit.ly/3UU1oXi)
- [hello@xorio.rs](mailto:hello@xorio.rs)
- [LinkedIn](https://www.linkedin.com/company/xorio)
