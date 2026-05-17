# Windows Support (WinFsp)

rencfs supports mounting encrypted filesystems on Windows via [WinFsp](https://winfsp.dev).

## Prerequisites

1. Install **WinFsp** (MIT-licensed): https://winfsp.dev/rel/
2. Rust stable with the `x86_64-pc-windows-msvc` target:
   ```powershell
   rustup target add x86_64-pc-windows-msvc
   ```

## Build

```powershell
cargo build --target x86_64-pc-windows-msvc
```

## Mount

```powershell
rencfs.exe --mountpoint X: --data-dir C:\path\to\encrypted
```

`X:` must be an unused drive letter or a directory path (WinFsp supports both).

## Unmount

```powershell
rencfs.exe umount X:
# or via MountHandle::umount() in library usage
```

## Implementation Notes

The Windows backend (`src/mount/windows.rs`) implements `winfsp::filesystem::FileSystemContext`
and bridges each WinFsp callback to the existing `EncryptedFs` async methods via a
dedicated Tokio runtime on the WinFsp dispatch thread.

### Operation mapping

| WinFsp callback       | EncryptedFs method                         |
|-----------------------|--------------------------------------------|
| `get_volume_info`     | virtual (1 TiB reported)                   |
| `get_security_by_name`| `find_by_name` + mode → NT SD              |
| `open`                | `open(inode, read, write)`                 |
| `create`              | `create_nod(parent, mode, ...)`            |
| `close`               | `release(fh)`                              |
| `read`                | `read(inode, offset, buf, fh)`             |
| `write`               | `write(inode, offset, data, fh)`           |
| `flush`               | `flush(fh)`                                |
| `get_file_info`       | `get_attr(inode)` → `FileInfo`             |
| `set_basic_info`      | `set_attr(inode, SetFileAttr { atime, .. })`|
| `set_file_size`       | `set_len(inode, new_size)`                 |
| `rename`              | `rename(parent, name, new_parent, new_name)`|
| `read_directory`      | `read_dir(inode)`                          |
| `cleanup`             | `remove_file` / `remove_dir` on delete flag|

### Status

- [x] WinFsp host boots and mounts the drive letter
- [x] Volume info reported to Explorer
- [ ] Directory listing (read_directory) — in progress
- [ ] File open/read/write — in progress
- [ ] Security descriptor mapping — in progress

### Known limitations (v1 milestone)

- NTFS alternate data streams: not supported
- Hard links: not supported (rencfs has no inode aliasing)
- Reparse points / symlinks: not supported
- Per-file ACLs: not supported; permissions are derived from rencfs mode bits

## CI

GitHub Actions workflow addition (`.github/workflows/build_and_tests.yaml`):

```yaml
- name: Build (Windows)
  if: runner.os == 'Windows'
  run: cargo build --target x86_64-pc-windows-msvc
```

A full integration test requires WinFsp installed on the runner; this is
tracked separately.