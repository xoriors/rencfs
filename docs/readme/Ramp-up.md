# Ramp-up guide

1. Become familiar with the [basic concepts and features](https://github.com/xoriors/rencfs?tab=readme-ov-file#-rencfs) and [lib docs](https://docs.rs/rencfs/latest/rencfs).
2. Give it a [quick try](https://github.com/xoriors/rencfs#give-it-a-quick-try-with-docker) with Docker.
3. Or run it as [CLI app](https://github.com/xoriors/rencfs?tab=readme-ov-file#command-line-tool).
4. Clone or fork the repo. After being added to it, you can create your branches in the original repo, no need to fork it, only if you want to.
5. [Build from source](Build_from_Source.md) and start it.
6. For now the app works only on Linux, but if you don't have Linux, you can [develop inside a container](Build_from_Source.md#developing-inside-a-container).
  This will start a new Linux container and remotely connecting the local IDE to it. You can also connect with the IDE's terminal to it, run and debug the code.
  On Windows, you can use [WSL](https://harsimranmaan.medium.com/install-and-setup-rust-development-environment-on-wsl2-dccb4bf63700).
7. As a last resort, you can [develop in browser](Build_from_Source.md#browser).
8. Understand and run the [examples](../../examples). You can write your own to better understand the flow and code. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too.
9. Become familiar with [tests](../src/encryptedfs/test.rs) and [benchmarks](../benches), and in other files. You can write your own to better understand the flow and code. If you do, please create a `PR` back to the parent repo targeting the `main` branch to include those for others too.
