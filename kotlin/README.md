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

Change in [build.gradle.kts](build.gradle.kts) in `applicationDefaultJvmArgs` the path of the dir where `librust_jni.so` is, and in `tasks.named<JavaExec>("run")` `args` the paths in this order `mnt`, `data_dir`, `password`.

```bash
JAVA_OPTS="-Djava.library.path=../kotlin-bridge/target/release/" ./gradlew run --args="/home/gnome/rencfs /home/gnome/rencfs_data a"
```
