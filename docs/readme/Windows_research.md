# Windows implementation research

Reviewed 2026-09-29 against `radumarias/rencfs` commit
`11d87caa345fcda41849ed5a562fcf357de76857`. The upstream comparison was
`xoriors/rencfs` commit `60c232777006793636165cf6724059d116d3150b`; these differ.

This contribution contains research and a reproducible **native storage probe**,
not a working Windows mount. The technical issue is
[`xoriors/rencfs#3`](https://github.com/xoriors/rencfs/issues/3), which requests a
basic working, tested implementation. This document alone does not complete it.
`radumarias/rencfs#3` is a different pull request, not that issue.

## Recommendation

Use WinFsp's native filesystem interface for a future adapter, but first make the
encrypted backing store portable and test it independently of mounting. Adding
`src/mount/windows.rs` alone cannot make this revision work on Windows. Prioritize
storage format, persistence and handle semantics before exposing writable data.
Start with x64/MSVC and a local NTFS backing directory. Other filesystems, SMB,
ARM64 and cloud-synchronized vaults need separate tests. Resolve the binding's
license before adding its dependency.

## Repository architecture and platform boundaries

| Area | Current responsibility | Windows work |
| --- | --- | --- |
| [`main.rs`](../../src/main.rs), [`run.rs`](../../src/run.rs) | Linux-only CLI dispatch, passwords, mount flags and signal cleanup | Enable dispatch with a functional adapter; define mount points/shutdown; reject unsupported Unix access flags |
| [`mount.rs`](../../src/mount.rs), [`mount/`](../../src/mount/) | Common mount API, Linux FUSE adapter, dummy elsewhere | Add Windows backend; replace shell `umount` with host lifecycle control |
| [`encryptedfs.rs`](../../src/encryptedfs.rs) | Async inode operations, metadata, handles, indexes, locks and caches | Reuse shared core; fix backing-store assumptions and test failures |
| [`crypto.rs`](../../src/crypto.rs), [`crypto/`](../../src/crypto/) | AEAD streams, filename encoding, key derivation and serialization | Preserve authenticated content; explicitly version storage-name changes |
| [`fs_util.rs`](../../src/fs_util.rs) | Atomic replacement and directory moves | Define platform persistence and replacement behavior with open files |
| [`arc_hashmap.rs`](../../src/arc_hashmap.rs), [`expire_value.rs`](../../src/expire_value.rs), [`async_util.rs`](../../src/async_util.rs), [`stream_util.rs`](../../src/stream_util.rs) | Locks, expiring secrets/caches, runtime bridge and buffered I/O | Audit blocking, lock ordering, runtime and secret lifetimes |
| [`keyring.rs`](../../src/keyring.rs), [`log.rs`](../../src/log.rs) | Credentials and tracing | Exercise Windows retrieval, expiration and cleanup; keep secrets out of logs |
| [`java-bridge/`](../../java-bridge/) | Separate JNI crate using common mount API | Preserve build and adapt shutdown if lifecycle changes |
| [`examples/`](../../examples/), [`benches/`](../../benches/), [`tests/`](../../tests/) | Library examples, performance checks and Linux mount tests | Add Windows core runtime coverage, then driver integration |
| [CI](../../.github/workflows/build_and_tests_reusable.yaml), [`docker/`](../../docker/), package metadata | Multi-OS builds and Linux packaging | Windows exists in the matrix, but tests/benches are skipped; Linux packaging is not a Windows installer |

The core stores encrypted attributes in `inodes/<ino>`, file data in
`contents/<ino>`, directory indexes in `contents/<ino>/{ls,hash}`, and key
material in `security/`. `ls` filenames encode encrypted names; `hash` filenames
provide lookup, and their encrypted payloads remember the corresponding `ls`
filename.

Crypto uses 256 KiB plaintext blocks outside unit tests, versus 100-byte blocks
under `cfg(test)`. Test production boundaries with a real binary as well as unit
tests. Having an `okaywal` dependency does not make multi-file create/rename/remove
operations transactional; inspect the operation paths before promising recovery.

## Backing-store blockers

### Names and format migration

`crypto::encrypt_file_name` uses unpadded standard Base64, substituting `/` with
`|`. `insert_directory_entry` uses that result as an actual `ls` filename.
Ordinary Windows paths reject `|`.

Special entries `.` and `..` become `$.` and `$..` in both name and hash functions.
Ordinary Win32 paths normalize trailing dots, so those names can address one file.
Extended paths can differ: the probe below does not reproduce every Rust path
conversion, and the format must also survive ordinary copy and backup tools.

Base64 is case-sensitive. URL-safe Base64 still permits case-only collisions on
case-insensitive backing directories, regardless of the mounted filesystem's
case mode. Lowercasing encoded text corrupts its bytes. See Microsoft's
[path rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
and the native observations below.

**Proposed decision:** choose a versioned, single-case storage representation,
such as prefixed lowercase hex of ciphertext plus explicit non-dot sentinels.
Hex doubles byte length: measure complete encrypted-name expansion against
component limits first. A bounded entry identifier with encrypted names in the
payload is an alternative, but changes the listing format more substantially.
Do not silently choose different storage formats by OS.

Migration must run where legacy names remain accessible, create a separate
destination, and validate inodes, listings, hash entries and content before
switching. Renaming only `ls` entries leaves names in encrypted `hash` payloads
inconsistent with deletion. Copying legacy data to an ordinary Windows directory
*before* conversion can already fail or lose names. Define format detection,
interruption recovery, rollback and old-reader behavior; preserve the original.

### Directory opening versus persistence

`crypto::atomic_serialize_encrypt_into` commits an atomic write, then calls
`File::open(parent)?.sync_all()?`. Similar sequences occur in key/salt creation,
create, release, flush and truncation. The
[CreateFileW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
requires `FILE_FLAG_BACKUP_SEMANTICS` to open directories.

Opening with that flag does not prove that syncing the handle implements POSIX
directory `fsync`. Introduce platform persistence helpers with an explicit
contract; evaluate file flush, replacement and namespace ordering together. Do
not swallow all errors or label a no-op durable. A failure after `commit()` can
leave changed storage despite a failed operation, affecting safe retries.

Audit [`atomic-write-file`](https://docs.rs/atomic-write-file/0.2.2/atomic_write_file/)
at the resolved version, including Windows replacement behavior. Test open
readers/writers and injected failures. Unix preservation flags in
`fs_util::open_atomic_write` are already gated, not an unconditional compile
blocker.

### Open files, deletion and rename

`remove_file` deletes directory indexes, inode metadata and content. `rename`
removes old/replacement indexes before inserting the destination. These are
multi-step operations, not one backing-file rename. Coordinate pending deletion,
replacement eligibility and outstanding handles; test partial failure too.

Sharing flags matter for both backing handles and mounted files. Rust's
[OpenOptionsExt](https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html)
documents its Windows defaults. Do not assume every open handle prevents deletion,
or that ordinary open tests prove delete-on-close behavior.

### Read-only behavior and existing platform guards

`read_dir` and `read_dir_plus` update access time through `set_attr`, which rejects
`read_only`. A read-only mount therefore needs a core fix, not just rejection of
write callbacks. `EncryptedFs::new` also ensures structure/root/key state exists:
a read-only path must validate existing storage without creating missing state.
Test backing-directory snapshots before and after initialization and listing.

`UID`/`GID` and `ensure_root_exists` already guard `getuid/getgid` for Linux/macOS.
Zero Windows ownership fields are metadata placeholders, not authorization. Use
an explicit Windows security descriptor rather than treating all callers as root.

## Reproducible native Windows observations

From the repository root, with Windows PowerShell 5.1 or PowerShell on Windows:

```powershell
.\scripts\probe-windows-storage.ps1 | Format-Table -AutoSize
```

The [probe](../../scripts/probe-windows-storage.ps1) calls `CreateFileW` with
ordinary paths, creates empty files in a unique scratch directory, closes its
handles, enumerates actual names, and cleans up nonrecursively. An optional
`-ParentDirectory` selects an existing scratch parent on the volume to investigate;
do not use a live vault. No driver, elevation, Rust or password is required.

Observed on Windows `10.0.26200.0`, PowerShell `5.1.26100.9549`, local NTFS:

| Probe | Result |
| --- | --- |
| Create `ab\|cd` | Win32 123, invalid name |
| Create `$.` | Success; enumerates as `$` |
| Create `$..` after `$.` | Win32 80, file exists |
| Create `QUJD`, then `qujd` | First succeeds; second returns 80 |
| Open directory without backup semantics | Win32 5, access denied |
| Open directory with backup semantics | Success |
| Enumerate created entries | `$`, `QUJD` |

Base64-shaped inputs demonstrate namespace behavior, not a measured ciphertext
collision probability. Case-sensitive directories and other filesystems can
differ. This is **not** a Rust unit test, WinFsp mount test, atomic replacement
test, or crash-durability test.

## Backend selection and licensing

| Candidate | Assessment |
| --- | --- |
| [WinFsp](https://github.com/winfsp/winfsp) native API | Recommended technical route; maps Windows operations directly and matches the issue's direction |
| [winfsp-rs](https://github.com/SnowflakePowered/winfsp-rs) | Candidate binding with an included `ntptfs-winfsp-rs` example; resolve its own license first |
| [Dokan](https://github.com/dokan-dev/dokany) | Alternative user-mode driver; still needs a core adapter and binding/API evaluation; do not dismiss it as deprecated without evidence |
| [ProjFS](https://learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system) | Projection/hydration model is not a direct substitute for this writable encrypted filesystem |
| WSL/Linux FUSE | Development/workaround using Linux code, not native Windows mounting |

WinFsp's [license](https://github.com/winfsp/winfsp/blob/master/License.txt) is
GPLv3 with a specific FLOSS exception for linking its platform DLL and distributing
unmodified installers, subject to attribution and other conditions, including
restrictions on proprietary combinations. Inferring an automatic MIT/Apache
conflict or unrestricted use from its short license label is wrong.

Separately, the reviewed `winfsp` [manifest](https://github.com/SnowflakePowered/winfsp-rs/blob/master/winfsp/Cargo.toml)
declares GPL-3.0; its [license](https://github.com/SnowflakePowered/winfsp-rs/blob/master/LICENSE.md)
contains GPLv3 without the DLL's exception. Do not assume that exception covers
the Rust wrapper. Record the chosen binding/version and maintainer-approved
licensing/distribution approach before adoption. Delay loading or separate driver
installation is not a resolution of binding license terms. No dependency is added
by this contribution.

## Adapter design after the storage gate

Add Windows `MountPointImpl`/`MountHandleInnerImpl`, preserving Linux dispatch
and `dummy` for other unsupported targets. The context owns `Arc<EncryptedFs>`
and a runtime handle. Each open context tracks inode, optional core handle,
access and deletion state. Resolve paths component-by-component from root inode 1
with `find_by_name`; never join mounted user paths onto the backing directory.

For synchronous callbacks, use a dedicated, long-lived multithread Tokio runtime
from WinFsp dispatcher threads. Do not assume `Handle::current()` exists there,
or recursively block runtime workers. Existing `async_util::call_async` assumes
a runtime context. Keep the runtime alive until dispatch and outstanding I/O
finish. Evaluate the binding's async interface separately; either approach needs
lock-order and cancellation review.

This mapping is proposed, not implemented callback code. Check signatures against
the selected binding's [`FileSystemContext`](https://github.com/SnowflakePowered/winfsp-rs/blob/master/winfsp/src/filesystem/context.rs).

| Windows operation | Core operation / adapter responsibility |
| --- | --- |
| Resolve/open | `find_by_name`, `get_attr`, `open`; enforce access and disposition |
| Create file/directory | `create` with `CreateFileAttr`; retain returned handle where applicable |
| Read/write | `read`/`write` with inode, offset, buffer and handle; EOF, short I/O, append and constrained writes |
| Query metadata | `get_attr`; plaintext logical size and stable inode identity |
| Basic metadata | `set_attr`; checked timestamp conversion and supported attributes |
| Resize/overwrite | `set_len`; distinguish allocation from EOF and honor overwrite disposition |
| Flush | `flush` for live handles; define volume flush and errors |
| Enumerate | `read_dir_plus`; name conversion, stable resume markers, bounded output |
| Rename | `rename` after checking replace-if-exists rules; serialize namespace changes |
| Delete eligibility/cleanup | Check emptiness and pending-delete policy; coordinate `remove_file`/`remove_dir` |
| Close | Release each handle once; record failures where callbacks cannot return errors |
| Security/volume info | Adapter-owned descriptor and truthful capabilities; no direct core equivalent |

Map `FsError` explicitly to NTSTATUS: missing names, collisions, access denial,
read-only, invalid input, nonempty directories, unsupported requests and I/O
failure must remain distinguishable. Do not report unimplemented requests as
successful. Never unwind through C; account for release `panic = "abort"`.

Initially support files/directories for one mounting user. Preserve case-sensitive
core lookup unless a complete case-insensitive resolver is implemented, and
advertise the choice accurately. Reject UTF-16 names the core cannot represent,
rather than using lossy conversion. Define reserved/invalid names, trailing dots,
spaces and lengths. Preflight Linux vault names; never silently rename them.

Specify timestamps and read-only attributes; Unix modes are not DACLs. Reject or
leave unadvertised alternate streams, hard links, reparse points/symlinks, extended
attributes, persistent per-file ACL editing and sparse controls until tested.
`FileType` only represents regular files and directories.

Unmount stops dispatch, completes pending I/O, flushes/releases handles, removes
the mount point, then drops host/runtime state. Cover Ctrl+C, normal exit, startup
failure, occupied mount point and missing driver. CLI/JNI must not use the current
Unix `umount` helper as a Windows fallback.

## Milestones and CI

1. **Portable storage:** version names, implement migration separately, introduce
   persistence helpers, and run `EncryptedFs` on Windows with both ciphers. Test
   initialization, read-only reopen/listing, create/read/write/truncate/rename/
   remove and password change.
2. **Read-only mount:** select a licensed binding, add target-scoped runtime/build
   dependencies, implement startup/lookup/enumeration/reads/metadata/shutdown.
   Prove mounting and reading do not mutate a read-only vault.
3. **Writable prototype:** complete operations, namespace locking, sharing/deletion
   and persistence. Demonstrate remount correctness and failed-operation behavior.
4. **Release integration:** credentials, JNI, driver arrangement, attribution,
   supported-platform documentation and Linux regression coverage.

The [binding setup](https://github.com/SnowflakePowered/winfsp-rs#usage) requires
a delay-load build helper. Gate dependencies/build calls so Linux does not link
Windows libraries; distinguish host from target for cross compilation. Record
tested Rust/SDK/binding/driver versions instead of assuming floating nightly and
a newer edition match the README's old MSRV.

Extend the **existing** Windows job: enable core runtime tests first, separating
credentials from headless storage tests. Driver tests need WinFsp and real mounted
I/O. This fork's top-level workflow calls reusable workflows at
`radumarias/rencfs@main`; editing a reusable file in a PR does not itself make the
caller exercise that revision. Address this when adding CI functionality.

For implementation changes, run formatting, check/build, Clippy and appropriate
root/JNI tests per the contribution guide. Compiling a dummy backend proves no
native Windows mounting capability.

## Acceptance evidence for working support

Use disposable vaults, both ciphers and production 256 KiB boundaries. Record
commands, versions, results and intentionally unsupported features.

- Create nested/Unicode names; enumerate, copy, seek/read, overwrite, append,
  extend/truncate, rename across directories and delete. Compare content hashes
  after unmount/remount.
- Exercise Explorer copies, editor temporary-file replacement, simultaneous
  handles, sharing violations, pending deletion and rename of open files.
- Check no-replace/replace-existing rename, case-only rename, long/invalid names
  and unsupported NTFS requests without false success.
- Prove read-only reads/rejected writes leave storage unchanged; report incorrect
  passwords/authentication errors without plaintext leaks.
- Test missing driver, occupied mount point, cancellation, normal exit and Ctrl+C;
  remount and check handle release.
- Inject write/replacement failures and interrupted migration; separately test
  abrupt process termination. Clean shutdown is not proof of power-loss durability.
- Validate Linux/Windows format round trips and retain Linux mount tests.
  Explicitly record unexecuted checks.

## Validation of this contribution

Executed the native probe on the Windows/NTFS configuration above. Inspected
repository code, platform guards, CI, binding sources and primary Windows docs.
Rust/Cargo were unavailable locally: Rust formatting/builds/Clippy/unit tests
were **not run**. No WinFsp driver was installed and no rencfs mount was tested.
The probe is independent of those prerequisites.
