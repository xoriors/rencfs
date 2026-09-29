# Windows implementation research

This research supports [Windows issue #3](https://github.com/xoriors/rencfs/issues/3).
It examines upstream commit
[`60c2327`](https://github.com/xoriors/rencfs/tree/60c232777006793636165cf6724059d116d3150b).
It does **not** enable Windows mounting. The issue asks for a basic working,
tested implementation; that requires a backend and mounted-drive tests beyond
this research.

Existing work should be reviewed before implementing another adapter:

- [PR #322](https://github.com/xoriors/rencfs/pull/322) proposes an initial WinFsp
  adapter and describes incomplete operations and pending runtime testing.
- [PR #327](https://github.com/xoriors/rencfs/pull/327) proposes a more complete
  adapter, storage changes, callback tests, and a mounted-drive smoke test.

Both were open when this research was prepared. The source audit below describes
**main at the pinned commit**, not the state of either contributor's branch.
The additional experiment here isolates backing-store path behavior without
requiring WinFsp, enabling storage decisions to be evaluated independently.

## Current integration points

| Source | Finding | Work required for Windows |
| --- | --- | --- |
| [`src/main.rs`](../../src/main.rs) | Windows exits before CLI dispatch. | Enable dispatch after its dependencies and mount lifecycle work. |
| [`src/mount.rs`](../../src/mount.rs), [`dummy.rs`](../../src/mount/dummy.rs) | All non-Linux targets use the dummy backend. The free `umount` helper invokes a Unix command. | Add Windows dispatch, backend ownership, and shutdown behavior. |
| [`Cargo.toml`](../../Cargo.toml) | `fuse3` is a Linux-only dependency. | Add a target-specific Windows binding and follow its build/link requirements. |
| [`src/crypto.rs`](../../src/crypto.rs) | Standard unpadded Base64 filenames replace `/` with `\|`; dot entries use `$.` and `$..`. | Address invalid characters, path normalization, and case sensitivity in the backing store. |
| [`src/encryptedfs.rs`](../../src/encryptedfs.rs) | File creation, release, flush, resizing, and key persistence include opening/syncing parent directories. | Audit Windows directory handles and file access rights; specify durability guarantees. |
| [`src/async_util.rs`](../../src/async_util.rs) | `call_async` assumes a current Tokio runtime and uses `block_in_place`. | Establish the runtime context on native callback threads; do not assume it is inherited. |
| [CI workflow](../../.github/workflows/build_and_tests_reusable.yaml) | Builds on Windows but skips its test suite. | Separate compilation, storage tests, callbacks, and actual mounted-drive tests. |

## Reproducible backing-store experiment

Run from the repository root on Windows, using Windows PowerShell 5.1 or later:

```powershell
.\scripts\windows-storage-probe.ps1 | Format-Table PathMode, Case, Name, Created, Win32Error
# Optional machine-readable record:
.\scripts\windows-storage-probe.ps1 | ConvertTo-Json | Set-Content probe.json
```

The [probe](../../scripts/windows-storage-probe.ps1) calls `CreateFileW` directly
with `CREATE_NEW`, in fresh directories below the system temporary directory.
It uses both ordinary absolute paths and `\\?\` extended paths. It records
native error codes, closes handles, and removes its recorded files and empty
directories without recursive deletion. It does not open an existing rencfs store,
install a driver, or change a directory's case-sensitivity setting.

Observed on NTFS, Windows `10.0.26200.0`, Windows PowerShell `5.1.26100.9444`:

| Sequence within a fresh directory | Ordinary path | Extended path |
| --- | --- | --- |
| Create `encrypted\|name` | Error 123 | Error 123 |
| Create `$.`, then `$..` | Success, then error 80 | Both succeed |
| Create `AA`, then `aA` | Success, then error 80 | Success, then error 80 |
| Create `encrypted_name`, `dot`, `dotdot` | All succeed | All succeed |

Error 123 is `ERROR_INVALID_NAME`; error 80 is `ERROR_FILE_EXISTS`.
`AA` and `aA` are unpadded Base64 encodings of different byte values (`00` and
`68`). They are synthetic alphabet examples, not valid rencfs ciphertexts and
not evidence that a ciphertext collision has occurred.

Interpretation:

1. An extended path does not make the pipe character a usable backing filename.
2. Ordinary Win32 normalization aliases the two dot-entry names. Extended paths
   preserve them in this experiment, so trailing dots alone do not establish
   that a particular Rust path operation fails. Test the actual Rust operations,
   copying tools, and backup/restore path too.
3. Extended paths do not themselves enable case-sensitive lookup. Replacing `/`
   with `_` or switching to Base64url retains upper/lowercase distinctions that
   the tested backing directory does not preserve. A directory configured for
   case sensitivity can behave differently; the probe records observations
   rather than assuming one configuration on every Windows host.

This experiment tests **native path behavior**, not `EncryptedFs`, encrypted
round trips, runtime memory protection, directory durability, or WinFsp mounting.
A zero script exit means the experiment and cleanup completed; inspect each
`Created` and `Win32Error` field to interpret the observations.

### Storage format decision

Treat the mounted namespace and backing-store namespace as separate decisions.
Even a case-sensitive virtual volume may store ciphertext on a case-insensitive
host directory. Do not lowercase Base64 ciphertext names: that loses information.

For a new portable storage format, evaluate an injective encoding with one case
only (for example lowercase hex or a specified lowercase Base32 alphabet), plus
explicit non-trailing-dot sentinels. Measure component lengths: hex doubles the
ciphertext byte length, and Base32 also expands it more than Base64. Any proposed
encoding must account for rencfs's existing long-name limitations and filesystem
component limits before adoption. Merely choosing a different alphabet does not
solve name-length constraints.

For existing stores, design version detection and migration on the source
platform before promising copy-and-mount interoperability. A Windows directory
cannot normally receive legacy pipe-containing names through a file copy.
Recognizing old names in the decoder therefore does not by itself establish
that an old Unix store can be transferred intact. Migration needs fixtures,
collision detection, consistent `ls`/`hash` indexes, and recovery after interruption.
Keep the source store recoverable until validation finishes. A mixed-format reader
also needs explicit rules for ambiguous or duplicate entries.

## Backend choice and build plan

Use a native WinFsp adapter around `Arc<EncryptedFs>` as the first candidate,
consistent with the maintainer's issue and the existing implementation PRs.
[WinFsp](https://github.com/winfsp/winfsp) supplies the Windows filesystem driver
and user-mode API; a Rust binding supplies the callback interface. Evaluate the
actual binding/version used by the chosen implementation rather than mixing
traits or build helpers from different crates.

| Candidate | Assessment for this repository |
| --- | --- |
| Native WinFsp API through a Rust binding | Fits a separate Windows mount module and reuses the encrypted core. Requires explicit Windows callback, security, and lifecycle semantics. |
| WinFsp FUSE compatibility API | Useful for compatible FUSE implementations, but the current Linux-only `fuse3` dependency does not become a Windows backend merely by installing WinFsp. Verify binding compatibility before claiming reuse. |
| [Dokany](https://github.com/dokan-dev/dokany) | Alternative driver/API, requiring its own adapter and dependency review. No performance or maintenance ranking is established by this research. |
| WSL running the Linux backend | Useful Linux development environment; does not implement a native Windows filesystem adapter. |

Keep Windows dependencies target-specific and leave Linux's `fuse3` dependency
intact. Distinguish build-host configuration from target configuration in build
scripts. Pin and record the binding, SDK/driver, architecture, and toolchain used
for tests. Verify dynamic loading and a clear missing-driver error on a machine
without WinFsp; a successful link alone does not establish deployment readiness.

Review the binding license separately from the
[WinFsp license and FLOSS exception](https://github.com/winfsp/winfsp/blob/master/License.txt).
That exception permits specified DLL linking and unmodified-installer distribution
subject to its conditions, including attribution in the UI and user documentation
and restrictions involving proprietary software. Distribution should record the
exact versions and applicable terms. Installing the driver separately is not by
itself a conclusion about licensing. Required WinFsp attribution:

> WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos

Project: <https://github.com/winfsp/winfsp>.

## Proposed adapter contract

Own the WinFsp host and a live multi-thread Tokio runtime for the mount lifetime.
Native callbacks need an explicit bridge into that runtime. Stop the dispatcher
and finish outstanding callbacks before dropping `EncryptedFs` or the runtime.
Exercise shutdown both through `MountHandle::umount` and the CLI stop path.
A callback file context should retain the inode, core handle where applicable,
access mode, and state required for directory enumeration and deferred deletion.

The following is a semantic map, not code that compiles against a particular
binding version. Consult the [WinFsp callback contract][winfsp-api].

| Callback responsibility | Core operation | Additional adapter responsibility |
| --- | --- | --- |
| Resolve/open | `find_by_name`, `get_attr`, `open` | Walk UTF-16 path components from the root; define case policy and invalid-name errors. |
| Create | `create` | Translate create disposition, directory flags, access checks, and existing-target behavior. |
| Read/write | `read`, `write` | Preserve offsets and short counts; implement append/constrained-write flags correctly. |
| Flush/resize | `flush`, `set_len` | Distinguish logical length from allocation size; propagate errors and document durability. |
| Metadata | `get_attr`, `set_attr` | Checked time/size conversion and supported Windows attributes. |
| Directory enumeration | `read_dir_plus` | Follow buffer and continuation-marker rules; avoid skips/duplicates across small buffers. |
| Rename | `rename` | Respect replace-if-exists and open-handle semantics; inspect failure recovery in the core. |
| Cleanup/close | `remove_file`, `remove_dir`, `release` as applicable | Separate delete-on-close policy from releasing resources; do not map every cleanup to immediate deletion. |
| Security | No Windows ACL persistence in the current core API | Choose and enforce a documented access policy; return valid security descriptors. |

Do not advertise unsupported alternate data streams, reparse points, hard links,
extended attributes, or persistent per-file ACLs. Returning success for an ignored
operation can mislead applications. Define error mappings (missing path, access
denied, collision, nonempty directory, read-only volume, unsupported operation)
and prevent panics from unwinding across the native boundary.

## Acceptance and validation plan

The research probe above is one layer of evidence. The implementation still needs:

1. **Build:** Windows MSVC build/check and repository formatting/Clippy checks;
   Linux regression checks; reproducible dependency and driver versions.
2. **Storage without a mount:** Both ciphers; create/write/read/reopen/resize;
   password change; dot entries; long and Unicode names; legacy-format fixtures;
   file/directory synchronization; secret-memory lifetime on Windows.
3. **Callback tests:** Real access and disposition flags; append and constrained
   writes; replacement rename; nonempty-directory errors; read-only enforcement;
   repeated cleanup/close; enumeration with small buffers and restart markers;
   runtime lifetime and error propagation.
4. **Mounted-drive test on an isolated Windows runner:** Install a verified WinFsp
   release; select an unused drive; create a fresh store; mount; create directories;
   write deterministic binary data across encrypted-block boundaries; flush and
   read/compare bytes; rename and reopen; unmount gracefully; remount and compare
   persisted bytes; delete entries; verify the mount disappears on shutdown.
   Preserve process logs and fail on a timeout. Forced process termination may be
   a final cleanup fallback, but must not count as successful graceful unmount.
5. **Failure/deployment tests:** Missing driver, wrong password, incompatible
   storage format, occupied mount point, denied access, and interrupted writes.
   Document whether a failure leaves the store usable and which guarantees are
   not yet provided. Do not infer power-loss durability from a remount test.

CI should report these layers separately. The existing Windows build job skips
runtime tests; removing that skip without addressing platform prerequisites does
not establish support. This research changes no Rust behavior or dependencies,
and no Rust suite or mounted-drive test was run for it.

## Primary references

- [Windows file naming and namespaces][naming]
- [CreateFileW semantics and creation dispositions][createfile]
- [Windows error codes 0-499][errors]
- [WinFsp callback contract][winfsp-api]
- [Rust bindings referenced by issue #3](https://github.com/SnowflakePowered/winfsp-rs)

[naming]: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
[createfile]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
[errors]: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
[winfsp-api]: https://github.com/winfsp/winfsp/wiki/WinFsp-API-winfsp.h
