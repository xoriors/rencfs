# Ramp-up guide

1. Read an [article](https://medium.com/system-weakness/hitchhikers-guide-to-building-a-distributed-filesystem-in-rust-the-very-beginning-2c02eb7313e7) and an [one pager](The_Hitchhiker_s_Guide_to_Building_an_Encrypted_Filesystem_in_Rust-1.pdf) to get more details about the project
2. Read [Basics of cryptography for building a filesystem in Rust](https://miro.com/app/board/uXjVLccxeCE=/?share_link_id=962517464374) and [Building an Encrypted Filesystem in Rust](https://miro.com/app/board/uXjVLa8i1h0=/?share_link_id=745134849333)
3. Become familiar with the [concepts and features](https://github.com/radumarias/rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs)
4. Understand the [layers](https://github.com/radumarias/rencfs/blob/main/website/resources/layers.png)
5. Detailed [sequence flows](docs/flows.md)
6. [Talks](https://startech-rd.io/hitchhikers-guide-to/)
7. Give it a [quick try](https://github.com/radumarias/rencfs#give-it-a-quick-try-with-docker) with Docker
8. Or run it as [CLI](https://github.com/radumarias/rencfs?tab=readme-ov-file#command-line-tool) app
9. Clone or fork the repo. After being added to it, you can work in your branches in the original repo. No need to fork it if you don't want to
10. [Build](https://github.com/radumarias/rencfs?tab=readme-ov-file#build-from-source) from source and start it. If you don't have Linux, you can [develop inside a container](https://github.com/radumarias/rencfs?tab=readme-ov-file#developing-inside-a-container). This will start a new Linux container and remotely connecting the local IDE to the container, you can also connect with IDE's terminal to it and run the code. On Windows, you can use [WSL](https://harsimranmaan.medium.com/install-and-setup-rust-development-environment-on-wsl2-dccb4bf63700). As a last resort, you can [develop in browser](https://github.com/radumarias/rencfs/blob/main/README.md#browser).
11. Run and understand [examples](examples). You can write some new ones to understand the flow and code better. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too
12. Become familiar with [tests](https://github.com/radumarias/rencfs/blob/main/src/encryptedfs/test.rs) (and in other files) and benchmarks. You can write some new ones to understand the flow and code better. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too
