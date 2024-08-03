# java-bridge

Bridge between the Rust code and Kotlin/Java code.

Build:

```bash
make
```

This will create `librust_jni.so` in `target/release`. You will need to provide that to Kotlin/Java app like:

```bash
java -Djava.library.path=target/release ...
```

Or if you move the files somewhere else, you need to provide the dir in which the file is located.

You can find a [Kotlin example app](https://github.com/radumarias/rencfs-kotlin).