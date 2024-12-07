# [![](favicon.png)](https://github.com/radumarias/rencfs) rencfs

[![rencfs-bin](https://img.shields.io/aur/version/rencfs-bin?color=1793d1&label=rencfs-bin&logo=arch-linux)](https://aur.archlinux.org/packages/rencfs-bin/)
[![crates.io](https://img.shields.io/crates/v/rencfs.svg)](https://crates.io/crates/rencfs)
[![docs.rs](https://img.shields.io/docsrs/rencfs?label=docs.rs)](https://docs.rs/rencfs/)
[![build-and-tests](https://github.com/radumarias/rencfs/actions/workflows/build_and_tests.yaml/badge.svg)](https://github.com/radumarias/rencfs/actions/workflows/build_and_tests.yaml)
[![release](https://github.com/radumarias/rencfs/actions/workflows/release.yaml/badge.svg)](https://github.com/radumarias/rencfs/actions/workflows/release.yaml)
[![codecov](https://codecov.io/gh/radumarias/rencfs/graph/badge.svg?token=NUQI6XGF2Y)](https://codecov.io/gh/radumarias/rencfs)
<a href="https://bit.ly/3UU1oXi"><img src="website/resources/slack3.png" style = "width: 87px; height: 20px;"/></a>
[![Open Source Helpers](https://www.codetriage.com/radumarias/rencfs/badges/users.svg)](https://www.codetriage.com/radumarias/rencfs)
<!-- [![Zulip](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg?label=Zulip)](https://rencfs.zulipchat.com) -->

> [!WARNING]  
> **This crate hasn't been audited; it's using `ring` crate, which is a well-known audited library, so in principle, at
least the primitives should offer a similar level of security.  
> This is still under development. Please do not use it with sensitive data for now; please wait for a
stable release.  
> It's mostly ideal for experimental and learning projects.**

An encrypted file system written in Rust that is mounted with FUSE on Linux. It can be used to create encrypted directories.

You can then safely back up the encrypted directory to an untrusted server without worrying about the data being exposed.
You can also store it in a cloud storage service like Google Drive, Dropbox, etc., and have it synced across multiple devices.

You can use it as CLI or as a library to build your custom FUSE implementation or other apps that work with encrypted data.









# Introduction

- Motivation

  Create a `simple,` `performant,` `modular` and `ergonomic` yet `very secure` `encrypted filesystem` to protect your `privacy`, which is also `open source` and is correctly and safely using `well-known audited` crates as `cryptographic primitives.`

- A short story

[The Hitchhiker’s Guide to Building an Encrypted Filesystem in Rust](docs/The_Hitchhiker_s_Guide_to_Building_an_Encrypted_Filesystem_in_Rust_2.pdf)

- Blog and tutorial

  There will be a [series](https://medium.com/@xorio42/list/828492b94c23) of articles about the evolution of this project, trying to keep it like a tutorial. This is the [first one](https://systemweakness.com/the-hitchhikers-guide-to-building-an-encrypted-filesystem-in-rust-4d678c57d65c).

- Talks

    - [The Hitchhiker’s Guide to Building an Encrypted Filesystem in Rust](https://startech-rd.io/hitchhikers-guide-to/) [@meetup.com/star-tech-rd-reloaded](https://www.meetup.com/star-tech-rd-reloaded/) and [@OmniOpenCon](https://omniopencon.org/)
    
    - [Basics of cryptography, Authenticated Encryption, Rust in cryptography and how to build an encrypted filesystem](https://www.youtube.com/live/HwmVxOl3pQg) @ITDays and [slides](https://miro.com/app/board/uXjVLccxeCE=/?share_link_id=342563218323).


  - Crate of the week in [This Week in Rust](https://this-week-in-rust.org/blog/2024/08/07/this-week-in-rust-559/#cfp-projects)

- It was [crate of the week](https://this-week-in-rust.org/blog/2024/08/14/this-week-in-rust-560/#crate-of-the-week) in Aug 2024.




# Features 

- [KEY features](docs/Key_features.md)

- GUI

There is a [GUI](https://github.com/radumarias/rencfs-desktop/blob/main/demo.gif) too.

- [Alternatives](docs/Alternatives.md)



# Implementation

- [Functionality](docs/Functionality.md)

- [Stack](docs/Stack.md)



# Documentation

- Docs

[![rencfs](website/resources/layers.png)](website/resources/layers.png)

For detailed description of the various sequence flows please look into [Flows](docs/flows.md).


- What separates us

  [Asked](https://chatgpt.com/share/66e7a5a5-d254-8003-9359-9b1556b75fe9) ChatGPT if there are other solutions out there which offer all the key functionalities we do, seems like there are none :)  
You can see the [key features](README.md#key-features) that separate us.
  



# Usage and Development

- [Usage](docs/Usage.md)

- [Build from Source](docs/Build_from_Source.md)

- Minimum Supported Rust Version (MSRV).The minimum supported version is `1.75`.





# Future and Considerations

- Future

    The plan is to implement it also on macOS and Windows
   - **Systemd service** is being worked on [rencfs-daemon](https://github.com/radumarias/rencfs-daemon)
   - **GUI** is being worked on [rencfs-desktop](https://github.com/radumarias/rencfs-desktop) and [rencfs-kotlin](https://github.com/radumarias/rencfs-kotlin)
   - **Mobile apps** for **Android** and **iOS** are being worked on [rencfs-kotlin](https://github.com/radumarias/rencfs-kotlin)

- Performance

  `Aes256Gcm` is slightly faster than `ChaCha20Poly1305` by a factor of **1.28** on average. This is because of the hardware acceleration of AES 
on most CPUs via AES-NI. However, where hardware acceleration is not available, `ChaCha20Poly1305` is faster. Also `ChaChaPoly1305` is better at `SIMD`.

- [Cipher comparison](docs/Cipher_comparison.md)

- [⚠️ Security ](docs/Security.md)

- [Considerations](docs/Considerations.md)



# Contribute

Feel free to fork it, change and use it however you want. If you build something interesting and feel like sharing 
pull requests are always appreciated.

## How to contribute

Please see [CONTRIBUTING.md](CONTRIBUTING.md).
