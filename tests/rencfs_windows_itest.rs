#![cfg(target_os = "windows")]

//! Opt-in tests against a real mounted WinFsp drive. Run through
//! `scripts/test-windows.ps1`; no driver is installed or other drive unmounted.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{FsError, PasswordProvider};
use rencfs::mount::{create_mount_point, MountPoint};
use shush_rs::SecretString;

const PASSWORD: &str = "rencfs-native-windows-smoke-test-only";
const CONTENT: &[u8] = b"rencfs test payload: persist this exact text across a clean remount";
const WAIT: Duration = Duration::from_secs(10);

#[link(name = "kernel32")]
extern "system" {
    fn GetLogicalDrives() -> u32;
}

struct TestPassword(&'static str);

impl PasswordProvider for TestPassword {
    fn get_password(&self) -> Option<SecretString> {
        Some(SecretString::from_str(self.0).expect("SecretString conversion is infallible"))
    }
}

fn drive_letter() -> Result<String> {
    let drive = env::var("RENCFS_TEST_DRIVE")
        .unwrap_or_else(|_| "R:".to_owned())
        .to_ascii_uppercase();
    let bytes = drive.as_bytes();
    ensure!(
        bytes.len() == 2 && (b'D'..=b'Z').contains(&bytes[0]) && bytes[1] == b':',
        "RENCFS_TEST_DRIVE must be an unused drive letter from D: through Z:"
    );
    Ok(drive)
}

fn is_drive_present(drive: &str) -> Result<bool> {
    // SAFETY: GetLogicalDrives takes no pointers and returns the current drive mask.
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Err(std::io::Error::last_os_error()).context("GetLogicalDrives failed");
    }
    let bit = u32::from(drive.as_bytes()[0] - b'A');
    Ok(mask & (1_u32 << bit) != 0)
}

fn ensure_drive_unused(drive: &str) -> Result<()> {
    ensure!(
        !is_drive_present(drive)?,
        "{drive} is already assigned; refusing to use or unmount an existing drive"
    );
    Ok(())
}

fn wait_until_mounted(root: &Path) -> Result<()> {
    let start = Instant::now();
    loop {
        match fs::metadata(root) {
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            Ok(_) => bail!("mounted root is not a directory: {}", root.display()),
            Err(error) if start.elapsed() >= WAIT => {
                return Err(error).context("mounted drive did not become accessible within 10s");
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

async fn wait_until_unmounted(drive: &str) -> Result<()> {
    let start = Instant::now();
    while is_drive_present(drive)? {
        ensure!(
            start.elapsed() < WAIT,
            "{drive} is still assigned after unmount"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

/// Run blocking Win32 file operations away from Tokio's worker threads. Capture
/// their result (including a task panic), then unmount before returning it.
async fn with_mount<F>(drive: &str, backing: &Path, read_only: bool, operation: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()> + Send + 'static,
{
    ensure_drive_unused(drive)?;
    let handle = create_mount_point(
        Path::new(drive),
        backing,
        Box::new(TestPassword(PASSWORD)),
        Cipher::ChaCha20Poly1305,
        false,
        false,
        read_only,
    )
    .mount()
    .await
    .context("mount failed; install WinFsp before running this opt-in test")?;

    let root = PathBuf::from(format!("{drive}\\"));
    let operations = tokio::task::spawn_blocking(move || {
        wait_until_mounted(&root)?;
        operation(&root)
    })
    .await
    .context("mounted file operation panicked");

    let unmount = handle.umount().await;
    if let Err(error) = unmount {
        return Err(anyhow!(
            "graceful unmount failed: {error}; file-operation result: {operations:?}"
        ));
    }
    wait_until_unmounted(drive).await?;
    operations?
}

fn write_and_check(root: &Path) -> Result<()> {
    let directory = root.join("資料-smoke");
    fs::create_dir(&directory).context("create Unicode directory")?;
    let original = directory.join("original.txt");
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&original)
        .context("create original file for read/write")?;
    file.write_all(b"abcdefghij").context("initial write")?;
    file.seek(SeekFrom::Start(3))
        .context("seek for overwrite")?;
    file.write_all(b"XYZ").context("offset overwrite")?;
    file.seek(SeekFrom::Start(0))
        .context("rewind after overwrite")?;
    let mut result = Vec::new();
    file.read_to_end(&mut result)
        .context("read after overwrite")?;
    ensure!(
        result == b"abcXYZghij",
        "offset overwrite changed unrelated bytes"
    );
    file.set_len(6).context("truncate original file")?;
    file.sync_all().context("sync truncated file")?;
    drop(file);
    let mut append = OpenOptions::new()
        .append(true)
        .open(&original)
        .context("reopen for append after dropping original handle")?;
    append
        .write_all(b"++")
        .context("append to truncated file")?;
    append.sync_all().context("sync appended file")?;
    let read_error = append
        .read(&mut [0; 1])
        .expect_err("append-only native handle unexpectedly allowed reading");
    ensure!(
        read_error.kind() == std::io::ErrorKind::PermissionDenied,
        "append-only native read failed unexpectedly: {read_error}"
    );
    drop(append);
    let appended = fs::read(&original).context("read after append")?;
    ensure!(
        appended == b"abcXYZ++",
        "append/truncate result differs: expected 8 bytes abcXYZ++, got {} bytes: {appended:?}",
        appended.len()
    );

    let mut reader = OpenOptions::new()
        .read(true)
        .open(&original)
        .context("reopen for EOF checks")?;
    reader
        .seek(SeekFrom::Start(7))
        .context("seek to last byte")?;
    let mut tail = [0_u8; 16];
    ensure!(
        reader.read(&mut tail).context("read last byte")? == 1 && tail[0] == b'+',
        "partial EOF read differs"
    );
    ensure!(
        reader.read(&mut tail).context("read past EOF")? == 0,
        "read past EOF must return zero bytes"
    );
    drop(reader);

    let renamed = directory.join("renamed.txt");
    fs::rename(&original, &renamed).context("rename original file")?;
    ensure!(
        !original
            .try_exists()
            .context("check old name after rename")?
            && fs::read(&renamed).context("read renamed file")? == b"abcXYZ++"
    );
    let names = fs::read_dir(&directory)
        .context("list Unicode directory")?
        .map(|entry| entry.map(|item| item.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .context("read directory entries")?;
    ensure!(
        names == vec![std::ffi::OsString::from("renamed.txt")],
        "directory listing differs: {names:?}"
    );
    fs::remove_file(&renamed).context("delete renamed file after reads")?;
    fs::remove_dir(&directory).context("delete empty Unicode directory")?;
    ensure!(
        !directory.try_exists().context("check removed directory")?,
        "removed directory is still visible"
    );

    let persistent = root.join("retained.txt");
    let mut writer = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(persistent)
        .context("create file to retain across remount")?;
    writer
        .write_all(CONTENT)
        .context("write retained content")?;
    writer.sync_all().context("sync retained content")?;
    Ok(())
}

fn check_encrypted_backing(backing: &Path) -> Result<()> {
    let mut pending = vec![backing.to_path_buf()];
    let mut files = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            ensure!(
                entry.file_name() != "retained.txt",
                "backing store exposes the plaintext filename"
            );
            let kind = entry.file_type()?;
            ensure!(
                !kind.is_symlink(),
                "unexpected link in temporary backing store"
            );
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files += 1;
                let bytes = fs::read(entry.path())?;
                ensure!(
                    !bytes.windows(CONTENT.len()).any(|window| window == CONTENT),
                    "backing store exposes the plaintext payload"
                );
            }
        }
    }
    ensure!(files > 0, "backing store contains no encrypted files");
    Ok(())
}

async fn reject_wrong_password(drive: &str, backing: &Path) -> Result<()> {
    ensure_drive_unused(drive)?;
    match create_mount_point(
        Path::new(drive),
        backing,
        Box::new(TestPassword("deliberately-wrong-test-password")),
        Cipher::ChaCha20Poly1305,
        false,
        false,
        false,
    )
    .mount()
    .await
    {
        Err(FsError::InvalidPassword) => {}
        Err(error) => bail!("wrong-password mount failed for an unexpected reason: {error}"),
        Ok(handle) => {
            handle.umount().await?;
            bail!("mount unexpectedly accepted a wrong password");
        }
    }
    wait_until_unmounted(drive).await
}

async fn roundtrip(drive: &str, backing: &Path) -> Result<()> {
    // Regress the upstream Windows allocator-page unlock failure before any
    // filesystem work. This must use the fixed shush-rs dependency.
    let secrets = (0..64)
        .map(|index| SecretString::from_str(&format!("test-secret-{index}")).unwrap())
        .collect::<Vec<_>>();
    drop(secrets);

    with_mount(drive, backing, false, write_and_check)
        .await
        .context("initial read/write mount")?;
    check_encrypted_backing(backing).context("inspect encrypted backing")?;
    reject_wrong_password(drive, backing)
        .await
        .context("wrong-password rejection")?;

    with_mount(drive, backing, true, |root| {
        let retained = root.join("retained.txt");
        ensure!(
            fs::read(&retained)? == CONTENT,
            "content changed after read-only remount"
        );
        ensure!(
            fs::write(root.join("must-not-create.txt"), b"denied").is_err(),
            "read-only mount allowed creation"
        );
        ensure!(
            OpenOptions::new().write(true).open(&retained).is_err(),
            "read-only mount allowed opening for write"
        );
        ensure!(
            fs::rename(&retained, root.join("must-not-rename.txt")).is_err(),
            "read-only mount allowed rename"
        );
        ensure!(
            fs::remove_file(&retained).is_err(),
            "read-only mount allowed deletion"
        );
        ensure!(
            fs::read(&retained)? == CONTENT,
            "read-only checks modified content"
        );
        ensure!(!root.join("must-not-create.txt").try_exists()?);
        Ok(())
    })
    .await
    .context("read-only remount")?;

    with_mount(drive, backing, false, |root| {
        let retained = root.join("retained.txt");
        ensure!(
            fs::read(&retained)? == CONTENT,
            "content changed across remount"
        );
        fs::remove_file(retained).context("delete retained file after remount")?;
        ensure!(
            fs::read_dir(root)?.next().is_none(),
            "temporary test filesystem is not empty after cleanup"
        );
        Ok(())
    })
    .await
    .context("final read/write remount")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires native Windows, WinFsp, and an unused RENCFS_TEST_DRIVE (default R:)"]
async fn native_windows_mount_roundtrip() -> Result<()> {
    let drive = drive_letter()?;
    ensure_drive_unused(&drive)?;
    let temporary = tempfile::Builder::new()
        .prefix("rencfs-windows-smoke-")
        .tempdir()?;
    let backing = temporary.path().join("backing");
    fs::create_dir(&backing)?;
    let result = roundtrip(&drive, &backing).await;
    if result.is_err() {
        // Preserve encrypted evidence if teardown failed; never delete a backing
        // store that might still be mounted. The test never unmounts another drive.
        let retained = temporary.into_path();
        eprintln!(
            "Smoke test failed; temporary encrypted backing retained at {}",
            retained.display()
        );
    }
    result
}
