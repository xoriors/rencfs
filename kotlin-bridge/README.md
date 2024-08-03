# kotlin-bridge

Bridge between the Rust code and Kotlin code.

Build:

```bash
make
```

This will create `librust_jni.so` in `target/release`. You will need to provide that to Kotlin app like:

```bash
java -Djava.library.path=target/release ...
```

Or if you move the files somewhere else you need to provide the dir in which the file is.

Run:

```bash
make run
```

This will run the [example app](../kotlin).
