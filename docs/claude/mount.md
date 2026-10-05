# mount module

Files: `src/mount.rs` (platform-independent API), `src/mount/linux.rs` (fuse3 implementation, Linux only), `src/mount/windows.rs` (Dokan implementation, Windows only, experimental), `src/mount/path_fs.rs` (path based adapter used by the Windows backend, compiled and tested on all platforms), `src/mount/dummy.rs` (stub for other platforms)

Adapts `EncryptedFs` to a FUSE mount. Compiled per-platform via `#[cfg(target_os = ...)]`: Linux gets the real `fuse3` implementation, Windows gets the Dokan one, everything else gets `dummy.rs` (compiles but does not work) so the library still builds cross-platform.

## Public API (`src/mount.rs`)

- `create_mount_point(mountpoint, data_dir, password_provider, cipher, allow_root, allow_other, read_only) -> impl MountPoint`
- `MountPoint::mount()` (async) → `MountHandle`
- `MountHandle`:
  - implements `Future<Output = io::Result<()>>` — await it to block until the fs is unmounted externally
  - `umount()` (async) — unmount programmatically
- `umount(mountpoint)` — shells out to `umount`, escalating: normal → `-f` (force) → `-l` (lazy)

Usage example in `src/lib.rs` rustdoc and `examples/mount.rs`.

## Linux implementation (`src/mount/linux.rs`)

- Implements fuse3's `Filesystem` trait over `EncryptedFs` (struct wraps an `Arc<EncryptedFs>`).
- Attr/entry TTL is 1 second (`TTL` const).
- Maps `FsError` to libc errnos (`ENOENT`, `EACCES`, `EISDIR`, ...).
- Mount options honor `allow_root`, `allow_other` (fuse3 built with the `unprivileged` feature), and `read_only`.
- fuse3 is a Linux-only dependency in `Cargo.toml` (`[target.'cfg(target_os = "linux")'.dependencies]`).

## Windows implementation (`src/mount/windows.rs`)

- Uses Dokan (`dokan` crate, MIT; user mode lib is LGPL). WinFsp bindings are GPLv3, so not used. Needs the Dokan driver installed.
- Dokan addresses files by path, `path_fs.rs` resolves paths to inodes (`PathFs`) and keeps the per open file context (`OpenNode`), which opens `EncryptedFs` handles lazily: a separate read and write handle, the write handle is released before a read if there are pending writes, as the last block is committed only on release.
- Dokan callbacks are sync, they run the async ops with `block_on` on a dedicated tokio runtime. Mount runs on a dedicated thread which blocks until unmounted; `MountHandle` resolves then.
- Mounted case-sensitive, `allow_root`/`allow_other` are ignored. `mount::umount` calls `dokan::unmount`.
- Encrypted file names use `_` instead of `|` for `/` on Windows (`|` is invalid in NTFS names); decryption accepts both on all platforms.

## Flow diagrams

See `docs/uml/mount.md` and the per-operation diagrams (`open_file.md`, `read.md`, `write.md`, etc.) in `docs/uml/`.
