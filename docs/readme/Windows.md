# Windows Native Mount Architecture (`WinFsp` + `EncryptedFsWinFspBridge`)

This document specifies the native Windows filesystem mount architecture for `rencfs` (`#3`) and accompanies the bridge implementation in `src/mount/windows.rs`.

## 1. Backend Selection: Why `WinFsp` (`winfsp` crate)

| Candidate | Kernel Driver | Rust Bindings | Active Maintenance | Fit for `rencfs` |
| :--- | :--- | :--- | :--- | :--- |
| **WinFsp** (`winfsp` / `winfsp-sys`) | Stable (`winfsp-x64.dll` / `.sys`) | `winfsp` `0.12+` (`SnowflakePowered/winfsp-rs`) | Active (used by `sshfs-win`, `rclone`, `cryfs`) | **Recommended**: native NT `IRP` semantics + delay-load runtime linking |
| **Dokan** (`dokan` / `dokan-sys`) | Dokany v2 | Older `dokan` crate (`0.3`) | Slower Rust crate updates | Viable fallback, higher callback friction |
| **ProjFS** (`ProjectedFS`) | Built-in Windows 10+ | Minimal | Virtualization-only | Unsuitable for full random-write encrypted vaults |

## 2. Licensing Checkpoint (GPLv3 with FLOSS Exception)

`rencfs` is licensed under `MIT OR Apache-2.0`. `WinFsp` is licensed under **GPLv3 with a special FLOSS Exception** (`https://github.com/winfsp/winfsp/blob/master/License.txt`).
- Because `MIT` and `Apache-2.0` are explicitly listed as OSI-approved Free/Libre and Open Source Software licenses under the WinFsp FLOSS Exception, `rencfs` can dynamically link against the installed `winfsp-x64.dll` (via Windows delay-loading) **without** relicensing `rencfs` as GPLv3, provided `rencfs` does not bundle modified WinFsp kernel binaries without source attribution.

## 3. Dependency & Build Shape (`Cargo.toml` + `build.rs`)

For full WinFsp host mounting on `x86_64-pc-windows-msvc`:

```toml
[target.'cfg(target_os = "windows")'.dependencies]
winfsp = { version = "0.12", features = ["system"] }

[target.'cfg(target_os = "windows")'.build-dependencies]
winfsp = { version = "0.12", features = ["build"] }
```

And in `build.rs`:

```rust
fn main() {
    #[cfg(target_os = "windows")]
    winfsp::build::winfsp_link_delayload();
}
```

## 4. Path-to-Inode Bridge (`src/mount/windows.rs`)

Unlike Linux `fuse3` (which dispatches operations by `u64` inode number), `WinFsp`'s `FileSystemContext` dispatches `open`, `create`, and `rename` by Windows backslash path (`\dir\sub\file.txt`) and associates an open handle with `Self::FileContext`.

`src/mount/windows.rs` implements `EncryptedFsWinFspBridge` with:
1. **`normalize_windows_path`**: Strips leading/trailing slashes, rejects parent traversal (`..`), trailing dots/spaces, NTFS reserved characters (`<>:"|?*`), and DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
2. **`resolve_entry` & `resolve_parent_and_leaf`**: Walks from `ROOT_INODE` (`1`) segment by segment via `EncryptedFs::find_by_name(parent_ino, &SecretString)`.
3. **`WinFspOpenContext`**: Holds `{ ino, fh: Option<u64>, is_dir, parent_ino, leaf_name, delete_on_close: AtomicBool }`.
4. **`WinFspFileInfo` & `FILETIME` Conversion**: Converts `SystemTime` to 100-nanosecond intervals since `1601-01-01 UTC` (`WINDOWS_EPOCH_OFFSET_SECS = 11_644_473_600`) and maps `FileType` + permissions to `FILE_ATTRIBUTE_DIRECTORY`, `FILE_ATTRIBUTE_ARCHIVE`, and `FILE_ATTRIBUTE_READONLY`.
5. **`fs_error_to_ntstatus`**: Maps every `FsError` variant to its exact Windows `NTSTATUS` code (`STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_NAME_COLLISION`, `STATUS_SHARING_VIOLATION`, `STATUS_DIRECTORY_NOT_EMPTY`, `STATUS_MEDIA_WRITE_PROTECTED`).

## 5. Operation Mapping Table

| WinFsp `FileSystemContext` Callback | `EncryptedFsWinFspBridge` Method | Underlying `EncryptedFs` Call |
| :--- | :--- | :--- |
| `get_security_by_name` | `get_file_info(path)` | `resolve_entry` -> `get_attr(ino)` |
| `open` | `open_path(path, read, write)` | `resolve_entry` -> `open(ino, read, write)` |
| `create` | `create_path(path, is_dir, read, write)` | `resolve_parent_and_leaf` -> `create(...)` |
| `read` | `read_context(ctx, offset, buf)` | `read(ctx.ino, offset, buf, fh)` |
| `write` | `write_context(ctx, offset, buf)` | `write(ctx.ino, offset, buf, fh)` |
| `flush` | `flush_context(ctx)` | `flush(fh)` |
| `cleanup` / `close` | `close_context(ctx)` | `flush(fh)` + `release(fh)` + optional `remove_file`/`remove_dir` |
| `read_directory` | `read_directory(path)` | `read_dir_plus(dir_ino)` |
| `rename` | `rename_path(old, new, replace)` | `rename(old_parent, old_name, new_parent, new_name)` |
