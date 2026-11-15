# Windows support research and implementation status

The first native Windows backend uses WinFsp to expose the existing `EncryptedFs` engine as a drive-letter filesystem. The encrypted storage format is intended to remain compatible with existing data. The Windows debug and release executables build, the Windows library suite passes, and live smoke runs have covered file creation, read/write, case-insensitive lookup, rename, and delete. Remount persistence, read-only behavior, and compatibility with a wider range of Windows applications still need validation.

## Backend choice and alternatives

WinFsp is the selected first milestone because it provides a Windows user-mode filesystem host and the Rust `winfsp` crate exposes a `FileSystemContext` interface that can delegate to `EncryptedFs`. This keeps the encryption and storage implementation shared across platforms while the mount callbacks stay platform-specific.

Alternatives were considered at a first-pass level:

- **Dokan** is another Windows user-mode filesystem option. It would require a separate adapter and was not selected because this implementation already has a WinFsp Rust binding and callback model to build on.
- **A custom Windows kernel filesystem driver** would avoid a user-mode filesystem dependency, but is outside the scope of a basic cross-platform mount milestone.
- **FUSE under WSL or a compatibility layer** remains useful for Linux development on Windows, but does not provide a native Windows drive mount for Windows applications.

This is a bounded implementation choice, not a claim that the alternatives have been exhaustively benchmarked.

## Adapter design

`EncryptedFs` remains responsible for encrypted names, file contents, metadata storage, and inode operations. `src/mount/windows.rs` implements the WinFsp callbacks, normalizes Windows paths, resolves components to `EncryptedFs` inodes, translates filesystem errors to NTSTATUS values, and converts timestamps and attributes to Windows structures. Because WinFsp callbacks are synchronous while `EncryptedFs` operations are asynchronous, the adapter uses a dedicated Tokio runtime to bridge each callback.

| WinFsp operation | `EncryptedFs` behavior |
| --- | --- |
| Name lookup and open | Normalize the path, resolve each component, then open the file by inode. |
| Create | Resolve the parent, reject a Windows case-insensitive name collision, and create a regular file or directory. |
| Read and write | Delegate offset-based I/O through the open file handle. |
| Directory enumeration | Read encrypted directory entries, convert metadata, and use a persistent `DirBuffer` for paging. |
| Flush and close | Flush or release the corresponding encrypted filesystem handle. |
| Truncate and basic metadata | Delegate length and supported timestamp updates. |
| Rename and delete | Resolve stored names using Windows case-insensitive lookup and mutate the matching inode entry. |
| Security, streams, and reparse points | Report unsupported behavior; these are outside the first milestone. |

The mount accepts drive-letter paths such as `R:`. Windows-invalid names and reserved device names are rejected before they reach the case-sensitive encrypted storage layer. Case-insensitive lookup is provided by the adapter, while stored names retain their spelling.

## Windows metadata and limitations

The adapter maps regular-file and directory attributes, file size, inode index, and creation/access/write/change timestamps. It reports a fixed cosmetic volume capacity because `EncryptedFs` does not currently track total volume usage. It does not implement Windows ACLs, alternate data streams, reparse points, hard links, sparse files, or NTFS-specific security and metadata behavior. `--allow-root` and `--allow-other` are Unix-only and have no effect on Windows.

## Prerequisites

- Windows 10 or later.
- The nightly Rust toolchain used by this repository.
- WinFsp installed on the machine. WinFsp supplies the Windows filesystem driver and runtime; building rencfs does not install it.

## Build and mount

Install the Windows SDK build headers and WinFsp, then use the repository's nightly Rust toolchain from a Windows developer prompt. The `winfsp` dependency links the WinFsp import library with delay loading; the WinFsp runtime must still be installed on the machine that runs the mount. Build with:

```powershell
cargo build --release
```

Then mount an encrypted data directory to an unused drive letter:

```powershell
.\target\release\rencfs.exe mount --mount-point R: --data-dir C:\Users\you\rencfs-data
```

The command stays running while the drive is mounted. Press `Ctrl+C` to unmount it. Use `--read-only` for a read-only mount. `--umount-on-start` cannot detach a mount owned by another process. The Unix-only `--allow-root` and `--allow-other` options have no effect on Windows.

## Validation status and remaining checks

Recorded for this implementation:

- Windows debug and release builds succeed on a host with the Windows SDK and WinFsp installed.
- The Windows library suite passes, with regression coverage for mount callbacks and path behavior.
- Live smoke runs cover file creation, write/read, case-insensitive read, rename, read after rename, and delete.
- Documentation lists the current Windows limitations and the bindings-license checkpoint.

Still to validate are remount persistence, write rejection on a read-only mount, Linux compatibility after the shared filesystem changes, and behavior in Explorer and applications that depend on Windows-specific semantics. Windows CI should install or otherwise provide WinFsp and the Windows SDK before building. A successful compile and focused smoke run do not establish broad compatibility.

## Licensing and attribution

WinFsp itself is GPLv3 with a FLOSS linking exception. Its exception requires this notice in user-facing documentation and the application interface:

> WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos

[WinFsp project and license](https://github.com/winfsp/winfsp).

The Rust [`winfsp` and `winfsp-sys` bindings](https://github.com/SnowflakePowered/winfsp-rs) are separately licensed under GPL-3.0. The WinFsp DLL exception does not by itself resolve the bindings' license for a Windows executable whose package is currently declared `MIT OR Apache-2.0`. Maintainers need to settle that distribution question before publishing Windows binaries. This note records the checkpoint; it does not make a licensing decision on behalf of the maintainers.
