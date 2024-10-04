# Ramp up guide

1. Read an [article](https://medium.com/system-weakness/hitchhikers-guide-to-building-a-distributed-filesystem-in-rust-the-very-beginning-2c02eb7313e7) and [one pager](The_Hitchhiker_s_Guide_to_Building_an_Encrypted_Filesystem_in_Rust-1.pdf) to get more details about the project
2. Become familiar with the [concepts and features](https://github.com/radumarias/rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs)
3. Understand the [layers](https://github.com/radumarias/rencfs/blob/main/website/resources/layers.png)
4. Give it a [quick try](https://github.com/radumarias/rencfs#give-it-a-quick-try-with-docker) with Docker, this is optional
5. Or run it as [CLI](https://github.com/radumarias/rencfs?tab=readme-ov-file#command-line-tool) app
6. Clone or fork the repo. After you're added to the repo you can work in your branches in there, no need to fork it if you don't want to
7. [Build](https://github.com/radumarias/rencfs?tab=readme-ov-file#build-from-source) from source and start it. In case you don't have Linux you can [develop inside a container](https://github.com/radumarias/rencfs?tab=readme-ov-file#developing-inside-a-container). This will start a new Linux container and remotely connecting the local IDE to the container, you can also connect with IDE's terminal to it and run the code. On Windows you can use [WSL](https://harsimranmaan.medium.com/install-and-setup-rust-development-environment-on-wsl2-dccb4bf63700). As a last resort you can [develop in browser](https://github.com/radumarias/rencfs/blob/main/README.md#browser).
8. Run and understand the [examples](examples). You can write some new ones to better understand the flow and code, if you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too
9. Become familiar with some [tests](https://github.com/radumarias/rencfs/blob/main/src/encryptedfs/test.rs) and benchmarks. You can write some new ones to better understand the flow and code, if you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too
