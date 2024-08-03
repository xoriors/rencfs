/** This file is used as a namespace for all the exported Rust functions. */
@file:JvmName("RustLibrary")

/***
 * Test function that takes a string and returns it with some additional one.
 */
external fun hello(str: String): String;

/***
 * Mounts a filesystem at `mnt` with `dataDir` and `password`, returning the mount handle.
 *
 * @param umountFirst: If `true`, unmounts the filesystem at `mnt` before mounting.
 */
external fun mount(mnt: String, dataDir: String, password: String, umountFirst: Boolean): Int;

/***
 * Unmounts the filesystem at `mount handle` returned by [mount].
 */
external fun umount(handle: Int);

/***
 * Unmounts all mounted filesystems.
 */
external fun umountAll();

/***
 * Set state.
 *
 * Helpful to simulate various states.
 */
external fun state(
    dryRun: Boolean = false,
    simulateMountError: Boolean = false,
    simulateUmountError: Boolean = false,
    simulateUmountAllError: Boolean = false,
);
