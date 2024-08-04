# java-bridge

Bridge between the Rust code and Kotlin/Java code.

# Build

```bash
cargo build --release
```

This will create `librust_jni.so` in `target/release`. You will need to provide that to Kotlin/Java app like:

```bash
java -Djava.library.path=target/release ...
```

Or if you move the files somewhere else, you need to provide the dir in which the file is located.

# Build for specific target

You can use `--target` to build for a specific target. You will find the `librust_jni.so` in `target/<target>/release`.

## Building for Android

```bash
cargo build --release --target aarch64-linux-android
```

You will find `librust_jni.so` in `target/aarch64-linux-android/release`.

# Example app

You can find a [Kotlin example app](https://github.com/radumarias/rencfs-kotlin).
