# Native Windows support

The Windows backend uses WinFsp and forwards file operations to the existing
`EncryptedFs` encryption and storage implementation. It does not run through
WSL. Linux retains its FUSE backend, and macOS retains the unsupported stub.

## Build and run

Use native 64-bit Windows, Visual Studio C++ Build Tools (including a Windows
SDK), and Rust's `x86_64-pc-windows-msvc` host. Install
[WinFsp 2.1](https://github.com/winfsp/winfsp/releases/tag/v2.1), including its
Developer component, before building. The bindings locate the import library
from the WinFsp installation registry entry. The repository pins its tested
nightly toolchain and dependency lockfiles.

From native Developer PowerShell:

```powershell
cargo build --locked --release
cargo run --locked --release -- mount --mount-point R: --data-dir .\windows-data
```

Choose an unused drive letter and a **new, empty backing directory**. Enter a
test password when prompted. Press Ctrl+C to stop the dispatcher, flush and
release its file handles, and unmount. Library callers must await
`MountHandle::umount()` before dropping their Tokio runtime. Dropping the handle
requests shutdown but does not wait for it to finish.

`--read-only` prevents filesystem mutations. `--allow-root` and `--allow-other`
are Linux options and are rejected on Windows. The volume uses a descriptor
granting the mounting account, SYSTEM and Administrators access. This is one
mount-wide policy, not arbitrary POSIX-to-NTFS ACL translation. ACL mutation is
explicitly unsupported. Path-based `mount::umount(path)` is Unix-only; use the
owning handle or Ctrl+C on Windows.

## Library consumers and the Java bridge

On Windows MSVC, every final executable or `cdylib` that uses the Windows
mount backend must enable WinFsp delay loading in its own build script.
Cargo's `rustc-link-arg` output applies to targets in that package; the
`/DELAYLOAD` argument from rencfs does not propagate to dependent packages.
Use the target-aware settings in `build.rs`: link `delayimp` and delay-load
`winfsp-x64.dll` for x86-64, `winfsp-x86.dll` for x86, or `winfsp-a64.dll` for
ARM64. Emit these MSVC settings only for Windows MSVC targets.

Delay loading lets the process load its executable or DLL before mounting
calls `winfsp_wrs::init()`, which configures access to the separately installed
WinFsp DLL. This is required with the standard installation, where WinFsp is
not next to the application's executable or on the default DLL search path.
The separate `java-bridge` crate therefore has its own build script.

From the repository root, build and check the x86-64 Java bridge on native
Windows:

```powershell
cargo build --locked --release --manifest-path java-bridge/Cargo.toml --target-dir target
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-windows-java-bridge.ps1 -DllPath .\target\release\java_bridge.dll
```

The focused check loads the DLL with the dependency search restricted to its
directory and System32, verifies the mount export, and checks that WinFsp was
not loaded eagerly. It does not invoke JNI or establish a Java mount result.
See [the bridge README](../../java-bridge/README.md) for Java loading details.

## Storage compatibility

New ciphertext filenames replace base64 `/` with `_`, and internal dot entries
use `$dot` / `$dotdot`. This avoids Win32's forbidden `|` and trailing dots.
The new reader also accepts the legacy encodings on systems that can represent
them. **Older rencfs releases cannot read the new filename encoding.** Do not
mix old and new writers on one store. Existing Unix stores with `|` or
trailing-dot names need a separate offline migration before copying to Windows;
this change does not provide a migration tool. Back up an existing store before
opening it with a new version, because writable operations can update its
internal dot records.

File contents and metadata continue to use the existing encryption format.
Windows file data is flushed through writable handles; the implementation does
not claim Unix directory-fsync durability for Windows namespace changes.

## Initial supported scope

Regular files and directories support create, open, read, write, append,
truncate, flush, listing, timestamps, read-only attributes, non-replacing
rename, and deletion. Paths are case-sensitive and case-preserving. Native
contexts can share a file for writing when Windows sharing checks permit it.
Each serialized write callback acquires, commits and releases the core's single
writer. Ordinary Cleanup retains readers for paging I/O until the final Close.
Deleting an object with another active user handle is rejected; cleaned cached
contexts are released together before deletion. Unix unlink-while-open semantics
are not implemented.

WinFsp enforces the granted access on native user handles. Backing readers also
serve internal Windows reads through writable contexts; this does not grant a
write-only user handle read access.

NTFS alternate streams, reparse points, hard links, extended attributes, arbitrary
ACL mutation and unsupported attribute changes fail explicitly. Whole-volume
flush is unsupported; individual file flush is supported. Rename replacement
is deliberately excluded from this first milestone. These restrictions should
be considered when trying applications that expect complete NTFS semantics.

## Native verification

```powershell
.\scripts\test-windows.ps1 -Drive R: -TranscriptPath windows-test.log
```

This checks native MSVC Rust and WinFsp prerequisites, refuses occupied drive
letters, builds the code, runs adapter tests, and runs a real mounted-drive
test. The test uses a temporary backing directory and a throwaway test password.
It exercises Unicode paths, offset writes, EOF, append, truncation, rename,
directory listing and deletion, graceful unmount, persistence across remount,
wrong-password rejection, and read-only enforcement. Failed tests preserve their
temporary backing store for diagnosis. The script never installs drivers or
force-unmounts another process's filesystem.

The ignored integration test is opt-in because it needs the actual driver;
Windows cross-compilation does not establish that it passes. See
[WINDOWS_VALIDATION.md](../../WINDOWS_VALIDATION.md) for the recorded results and
checks that have not been run for this candidate.

## Dependencies

The Rust bindings [`winfsp_wrs`](https://github.com/Scille/winfsp_wrs) are MIT
licensed. WinFsp is a separately installed runtime under its own
[license and FLOSS exception](https://github.com/winfsp/winfsp/blob/v2.1/License.txt).
This source archive does not redistribute the runtime or driver. The
`shush-rs` dependency is pinned to its
[merged Windows drop fix](https://github.com/Eyob94/shush-rs/pull/22), because
the published 0.1.10 and 0.1.11 releases can panic when dropping secrets sharing
an already-unlocked allocation page.

The dependency declaration selects that Git revision directly, so path/Git
consumers also receive the fix without relying on this repository's workspace
patch. Callers that construct `shush_rs::SecretString` for rencfs APIs must use
the same Git source to keep the Rust types compatible. The Java bridge's
workspace patch already selects that revision for its direct dependency.
Cargo uses the declared registry version when packaging for crates.io; that
version remains unfixed. Publishing a Windows-capable release therefore still
requires a separate decision about a fixed published dependency.
