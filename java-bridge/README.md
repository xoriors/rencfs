# java-bridge

Bridge between the Rust code and Kotlin/Java code.

# Build

This will build for the current target.

```bash
cargo build --release
```

On Linux this creates `libjava_bridge.so` in `target/release`. You will need to provide that to Kotlin/Java app like:

```bash
java -Djava.library.path=target/release ...
```

Or if you move the files somewhere else, you need to provide the dir in which the file is located.

# Build for specific target

You can use `--target` to build for a specific target. The library is placed in `target/<target>/release` and uses the target platform's library filename.

## Building for Windows

Install the native MSVC Rust toolchain, Visual Studio C++ Build Tools, and the
WinFsp runtime and Developer files described in
[the Windows guide](../docs/readme/Windows.md). From this `java-bridge` directory
in Windows Developer PowerShell, run:

```powershell
cargo +nightly-2025-03-01 build --locked --release
```

The result is `target\release\java_bridge.dll`. The JVM must use the same
architecture as the DLL. Load it by absolute path with `System.load(...)`, or
provide its directory through `java.library.path` and use
`System.loadLibrary("java_bridge")`.

The bridge's `build.rs` supplies `delayimp` and the architecture-specific
`/DELAYLOAD` option for its final Windows MSVC `cdylib` link. Cargo does not
forward `rencfs`'s `rustc-link-arg` output to this dependent package's final
link. Other executable or `cdylib` consumers of `rencfs` must also provide these
settings at their final link; see the Windows guide. Delay loading lets the
bridge load before the mount path calls `winfsp_wrs::init()`, which finds the
installed WinFsp DLL through the registry and loads it by absolute path.

The focused PowerShell check in the Windows guide loads the DLL without
searching `PATH`, verifies its mount export and checks that WinFsp stays
unloaded until initialization. This does not establish a successful JNI
mount/unmount or end-to-end Java/Kotlin integration test.

## Building for Android

```bash
cargo build --release --target aarch64-linux-android
```

You will find `libjava_bridge.so` in `target/aarch64-linux-android/release`.

# Example app

You can find a [Kotlin example app](https://github.com/radumarias/rencfs-kotlin).
