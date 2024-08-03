# kotlin

Example Kotlin app that uses [kotlin-bridge](../kotlin-bridge) to interact with Rust code.

## Structure

- [Main.kt](src/main/kotlin/Main.kt): Main file that uses the Rust code.
- [Rust.kt](src/main/kotlin/Rust.kt): Namespace for all the exported Rust functions.

### Exposed functions

- `fun hello(str: String): String;`: Test function that takes a string and returns it with some additional one.
- `fun mount(mnt: String, data_dir: String, password: String): Int;`: Mounts a filesystem at `mnt` with `data_dir`
  and `password`, returning the mount handle.
- `fun umount(handle: Int);`: Unmounts the filesystem at `mount` handle returned by `mount`.

## Build

```bash
./gradlew build
```

## Run

```bash
java -Djava.library.path=../kotlin-bridge/target/release/ -classpath build/classes/kotlin/main:/home/gnome/.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.0.0/b48df2c4aede9586cc931ead433bc02d6fd7879e/kotlin-stdlib-2.0.0.jar:/home/gnome/.gradle/caches/modules-2/files-2.1/org.jetbrains/annotations/13.0/919f0dfe192fb4e063e7dacadee7f8bb9a2672a9/annotations-13.0.jar MainKt /home/gnome/rencfs /home/gnome/rencfs_data a
```