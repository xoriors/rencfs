# Windows implementation candidate — validation record

Date: 2026-10-27. This is an AI-assisted implementation candidate, not a claim
of maintainer acceptance or a completed bounty payment.

The supplied archive was based on 11d87caa345fcda41849ed5a562fcf357de76857.
The changes were applied cleanly to canonical xoriors/rencfs main at
60c232777006793636165cf6724059d116d3150b (version 0.14.11). The package version
is unchanged. Existing source licenses are preserved.

## Initial archive checks

Toolchain: nightly-2025-03-01, rustc 1.87.0-nightly. Execution host: Linux x86-64.

| Check | Result |
|---|---|
| `cargo test --locked --lib -- --test-threads=1` | 113 passed, 0 failed |
| `cargo test --locked --test cli_passwd_itest` | 1 passed, 0 failed |
| `cargo check --locked --all-targets` | passed |
| `cargo build --locked --all-targets` | passed |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-targets` | passed |
| release Clippy, all Linux targets | passed, no warnings |
| release Clippy, all Windows GNU targets | passed, no warnings |
| root and Java bridge rustfmt checks | passed |
| Java bridge `cargo check --locked --all-targets` | passed |
| Java bridge `cargo build --locked` | passed |
| `git diff --check HEAD` | passed |

Clippy used the repository's existing allowlist: similar_names,
too_many_arguments, significant_drop_tightening, redundant_closure,
missing_errors_doc and type_complexity. Windows cross-checks used Rust's
Windows GNU standard library and Zig as the C compiler for ring. They establish
Rust type correctness for that target, not a native MSVC link or driver result.

The 8 new core regressions cover portable filename/dot records, legacy reads,
read-only enumeration/release, failed writer-open cleanup, and concurrent writers.
The total 113 library tests includes these regressions.

## Not executed when the initial archive was prepared

- 11 Windows-only callback tests: compiled by the cross-target checks, not run.
- Real WinFsp mounted-drive integration test: not run.
- Native Windows/MSVC build and driver initialization: not run.
- Updated GitHub Actions jobs: not run.
- Linux FUSE integration tests: not run; this host has no /dev/fuse.
- macOS and Android builds: not run.

Run from native Windows Developer PowerShell with Rust/MSVC and the WinFsp 2.1
runtime and Developer files installed:

```powershell
.\scripts\test-windows.ps1 -Drive R: -TranscriptPath windows-test.log
```

Use an unused D:-Z: drive; the script refuses an occupied letter. It uses only a
temporary encrypted store. Preserve and inspect its transcript before marking
the PR ready or claiming the reward. Runtime defects found by this run need to
be corrected, and the script rerun, before describing the mount as tested.

## Native session and follow-up fixes

The native Windows/MSVC build completed successfully on the user's machine.
After the live-state fix, all 12 Windows callback tests and all 3 focused
`test_live_handle` core tests passed there. The live-state fix also passed all
116 library tests on Linux and release Clippy for Linux and Windows GNU.

The native mounted-drive smoke test then failed with OS error 32 while reopening
the truncated file for append. Its backtrace identified
`write_and_check`, at the append-open operation. The old adapter retained the
core's exclusive writer until the final WinFsp Close, which Windows can defer
after Cleanup.

The sharing-lifetime follow-up replaces persistent writers with transient
writer leases per synchronous callback. It keeps readers through ordinary
Cleanup, releases all cleaned contexts before deletion, and rejects subsequent
operations through removed contexts. Four added callback regressions cover
reopen before Close, late paging I/O, multiple writable contexts, write-error
lease release, and deletion with cached contexts. The native smoke test now
adds operation names to its errors.

The sharing follow-up passes Windows GNU all-target checks and release Clippy.
Its 16 Windows callback tests then passed on native Windows. The mounted-drive
test advanced past append but returned an empty vector when reading the file.
The WinFsp trace showed a read of 4096 bytes at offset zero returning 8 bytes,
followed by a second read at offset zero through the same context returning
zero, despite metadata still reporting a size of 8.

The EOF follow-up reproduces that exact failure on Linux before the fix. The
encrypted reader now tracks logical position independently of its decrypted
buffer, preserves position at EOF, and reloads the encrypted block when a seek
cannot use cached plaintext. Empty reads leave reader state intact. Ciphertext
block overhead uses ceiling division so seeking to the end of an exact full
block returns its true length. The shared decryption macro and writer are
unchanged.

Three new crypto regressions and the filesystem reproduction fail before the
fix. All 120 Linux library tests pass with the fix, including all 86 crypto
tests and the filesystem reproduction covering both ciphers. Release Clippy
passes for all Linux and Windows GNU targets. Two additional
Windows callback tests cover repeated reads after EOF and internal reads on
write-only contexts. The adapter now services those observed internal requests;
the native smoke test additionally checks that a user read through the
append-only handle still fails with PermissionDenied.

After this EOF follow-up, the native Windows x86-64/MSVC session passed both
checks below with nightly-2025-03-01. The library suite included all 18 Windows
callback tests.

The successful native working tree was committed as
[`3d7a05f857374800bc86ee861818d5d58dfaf667`](https://github.com/Code-Demon12/rencfs/commit/3d7a05f857374800bc86ee861818d5d58dfaf667),
the initial head of PR #332. Only reporting documentation changed between those
native runs and that commit; the implementation, manifests and lockfiles match
the tested state. The results in this section are historical evidence for that
revision, not a native pass for later review changes.

| Native check | Result |
|---|---|
| `cargo +nightly-2025-03-01 test --locked --lib -- --nocapture --test-threads=1` | 136 passed, 0 failed; 51.06 s |
| `cargo +nightly-2025-03-01 test --locked --features winfsp_wrs/debug --test rencfs_windows_itest -- --ignored --nocapture --test-threads=1` | 1 passed, 0 failed; 4.24 s |

These native results use Cargo's debug/test profile. The mounted-drive run used
an unused `R:` drive and enabled the binding's diagnostic feature. It completed
Unicode file operations, truncate/append, repeated reads, rename and deletion,
graceful unmount, encrypted backing inspection, wrong-password rejection,
read-only remount checks, persistence and final deletion after a writable
remount. The append-only user-handle read was denied as expected.

At that revision the release-profile PowerShell runner and updated GitHub
Actions jobs had not been executed in the native session. The later release
runner result is recorded separately below; these historical debug-profile
results do not claim that exact runner passed.

## PR #332 review follow-up

The follow-up to initial revision `3d7a05f857374800bc86ee861818d5d58dfaf667`
makes WinFsp delay-load flags depend on Cargo's target OS, environment and
architecture. Windows GNU and non-Windows targets receive no MSVC linker
flags. The unused `winfsp_wrs_build` dependency is removed from both lockfiles
without updating other dependency versions. Native Windows/MSVC remains the
supported link environment; the sys crate's host-specific SDK discovery is not
a promise of complete cross-link support.

It also removes empty/closed entries from the Windows context registry and
restores forced exit for a repeated shutdown signal. The first signal still
requests graceful teardown. Two signal-decision tests pass on Linux, and a new
Windows callback regression covers registry retirement with retained context
references. The Windows callback suite now contains 19 tests.

Local review checks: 13/13 build-script target-selection cases, 2/2 signal
decision tests, Linux and Windows GNU all-target release Clippy, locked root
and Java bridge metadata, rustfmt and whitespace checks passed. The native
release rerun of this follow-up passed as recorded below; the earlier 136-test
and diagnostic mounted-drive results remain associated with the initial PR
revision.

The suggested `TempDir::keep()` change was not applied: locked tempfile 3.13.0
defines `TempDir::into_path()` without deprecation and does not provide
`TempDir::keep()`. Switching to the newer API would break the locked build.

## Native release validation of the review follow-up

Reported on 2026-10-28 from native Windows x86-64/MSVC with WinFsp installed.
The tested commit was
[`94d5432fb54713f6baa03fd3523f199cb7392073`](https://github.com/Code-Demon12/rencfs/commit/94d5432fb54713f6baa03fd3523f199cb7392073)
on `fix/windows-support`. After the run, `git rev-parse HEAD` reported that
revision and `git status --short` was empty. This validation record is a later
documentation-only change; it does not alter the tested implementation.

The pinned toolchain is `nightly-2025-03-01`. The successful command was:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\test-windows.ps1" -Drive R: -TranscriptPath "$env:TEMP\rencfs-pr332-review-native.log"
```

| Runner check | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo build --locked --release --all-targets --all-features` | passed |
| `cargo test --locked --release --lib mount::windows::tests -- --nocapture --test-threads=1` | 19 passed, 0 failed; 4.42 s |
| `cargo test --locked --release --test rencfs_windows_itest -- --ignored --nocapture --test-threads=1` | 1 passed, 0 failed; 1.15 s |
| Temporary mounted drive removed after the integration test | passed |

The runner reached its final success message, which follows all checks above.
The mounted test ran without explicitly enabling the binding's diagnostic
feature. This establishes a native release build and mounted-drive result for
the review follow-up. It does not claim a new full native library-suite run or
execution of the updated GitHub Actions jobs.

## Java bridge delay-load review follow-up

The review of `b3d20a5f7d2fea1d56b0e2d0596d840a5b3acf89` identified that Cargo
does not forward a dependency's `rustc-link-arg` output to a dependent package's
final `cdylib` link. The separate Java bridge now emits its own target-aware
Windows MSVC delay-load settings. No dependency or lockfile is changed.
Consumer documentation explains the same requirement for other final
executables and DLLs that use the mount backend.

Both build scripts compiled with Rust 2021 and `-Dwarnings` and passed 13
target-selection cases each. The Java bridge passed a locked Linux release
build and Windows GNU all-target release Clippy. Root/Java rustfmt, whitespace
checks and parsing of the updated workflow YAML passed. The new native
`scripts/test-windows-java-bridge.ps1` DLL-loading check is also wired into the
Windows CI job after the bridge build.

Native Windows x86-64/MSVC validation was reported on 2026-10-28 for
[`b51f370df5e40411c81e1a9ce174d3612f43466f`](https://github.com/Code-Demon12/rencfs/commit/b51f370df5e40411c81e1a9ce174d3612f43466f).
After the run, `git rev-parse HEAD` reported that revision and
`git status --short` was empty. This record is a later documentation-only
change and does not alter the tested implementation.

| Native Java bridge check | Result |
|---|---|
| `cargo +nightly-2025-03-01 build --locked --release --manifest-path java-bridge/Cargo.toml --target-dir target` | passed; 1 min 46 s |
| `powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\test-windows-java-bridge.ps1" -DllPath ".\target\release\java_bridge.dll"` | passed |

The helper reached its final success message. It loaded and freed
`java_bridge.dll` with dependency lookup restricted to the DLL directory and
System32, found `Java_RustLibrary_mount`, and confirmed that no WinFsp DLL was
loaded before mount initialization. This checks DLL loading and its JNI mount
export; it does not invoke JNI or claim a Java mount/unmount result. The
earlier native CLI and mounted-drive results remain associated with their
recorded revisions. The new GitHub Actions loader step still requires CI
execution.

## Source-consumer dependency follow-up

The review of `17fab012f16c0d7ecb5bd1679a721c392e8071f7` identified that a
dependency package's workspace patch is ignored by an external workspace.
The root `shush-rs` dependency now declares version `=0.1.11` together with
the existing fixed Git revision directly. The root and Java workspace patches
are retained. Registry publication still falls back to the unfixed 0.1.11
release and requires a separate fixed-dependency publication decision.

With nightly-2025-03-01, full locked/offline metadata for the cached Windows GNU
target has identical root and Java resolved graphs and package identities
before and after this edit. Both lockfiles remain byte-for-byte unchanged.
Each graph contains exactly one `shush-rs` at the fixed Git revision, and the
Java bridge and rencfs still use the same `SecretString` type. A locked/offline
Linux Java-bridge all-target check passed.

An external workspace without a patch selected registry 0.1.11 before the fix,
as recorded in its resolved lockfile. After the fix, its metadata selected the
fixed Git revision. This check seeded transitive versions from the repository
lockfile to isolate source selection from unrelated offline resolution.
Adding a matching direct Git dependency and implementing `PasswordProvider`
with `SecretString` also passed a locked Windows GNU release check. These are
resolution/type checks; no new native Windows runtime or published-package
verification is claimed. Earlier native results retain their recorded revisions.

## Scope and compatibility

See docs/readme/Windows.md. This initial backend intentionally excludes rename
replacement, arbitrary NTFS metadata/ACL mutation, whole-volume flush, and
unlink with other active user handles. Native writable contexts share transient
core writer leases under the WinFsp coarse operation guard. File data
flush is implemented; Unix directory-fsync crash guarantees are not claimed on
Windows. New storage names are readable by this reader, including on Linux;
older releases cannot read the new encoding. Existing Unix backing stores with
Win32-invalid names require a separate migration before copying to Windows.

The Opire listing and upstream issue point at different repository identities.
The existing upstream PR #327 reports a rejected claim caused by that mismatch.
Neither the code nor these local results establish that payment is available.
