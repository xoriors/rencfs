/** This file is used as a namespace for all the exported Rust functions. */
@file:JvmName("RustLibrary")

/***
 * Test function that takes a string and returns it with some additional one.
 */
external fun hello(str: String): String;

/***
 * Mounts a filesystem at `mnt` with `data_dir` and `password`, returning the mount handle.
 */
external fun mount(mnt: String, data_dir: String, password: String): Int;

/***
 * Unmounts the filesystem at `mount` handle returned by `mount`.
 */
external fun umount(handle: Int);
