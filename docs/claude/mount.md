# mount module

Files: `src/mount.rs` (platform-independent API), `src/mount/linux.rs` (fuse3 implementation, Linux only), `src/mount/windows.rs` (native WinFsp implementation, Windows only), `src/mount/dummy.rs` (stub for other platforms)

Adapts `EncryptedFs` to a mounted filesystem. Linux selects `linux.rs` (FUSE),
Windows selects `windows.rs` (WinFsp), and other platforms select `dummy.rs`.
Windows prerequisites, limitations and native validation are documented in
[Windows.md](../readme/Windows.md).

## Public API (`src/mount.rs`)

- `create_mount_point(mountpoint, data_dir, password_provider, cipher, allow_root, allow_other, read_only) -> impl MountPoint`
- `MountPoint::mount()` (async) → `MountHandle`
- `MountHandle`:
  - implements `Future<Output = io::Result<()>>` — await it to block until the fs is unmounted externally
  - `umount()` (async) — unmount programmatically
- `umount(mountpoint)` — Unix shells out to `umount`, escalating: normal → `-f` (force) → `-l` (lazy). Windows returns Unsupported; use the owning handle instead.

Usage example in `src/lib.rs` rustdoc and `examples/mount.rs`.

## Linux implementation (`src/mount/linux.rs`)

- Implements fuse3's `Filesystem` trait over `EncryptedFs` (struct wraps an `Arc<EncryptedFs>`).
- Attr/entry TTL is 1 second (`TTL` const).
- Maps `FsError` to libc errnos (`ENOENT`, `EACCES`, `EISDIR`, ...).
- Mount options honor `allow_root`, `allow_other` (fuse3 built with the `unprivileged` feature), and `read_only`.
- fuse3 is a Linux-only dependency in `Cargo.toml` (`[target.'cfg(target_os = "linux")'.dependencies]`).

## Flow diagrams

See `docs/uml/mount.md` and the per-operation diagrams (`open_file.md`, `read.md`, `write.md`, etc.) in `docs/uml/`.
