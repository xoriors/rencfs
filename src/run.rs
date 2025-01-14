use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::{env, io, panic, process};

use anyhow::Result;
use clap::{crate_authors, crate_name, crate_version, Arg, ArgAction, ArgMatches, Command};
use ctrlc::set_handler;
use rpassword::read_password;
use shush_rs::{ExposeSecret, SecretString};
use strum::IntoEnumIterator;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::{fs, task};
use tracing::{error, info, warn, Level};

use crate::keyring;
use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{EncryptedFs, FsError, PasswordProvider};
use rencfs::mount::MountPoint;
use rencfs::{crypto, log, mount};
use rencfs::crypto::bip39::Language;

static mut PASS: Option<SecretString> = None;

#[derive(Debug, Error)]
enum ExitStatusError {
    #[error("exit with status {0}")]
    Failure(i32),
}

pub(super) async fn run() -> Result<()> {
    let matches = get_cli_args();

    let str = matches.get_one::<String>("log-level").unwrap().as_str();
    let log_level = Level::from_str(str);
    assert!(log_level.is_ok(), "Invalid log level");
    let log_level = log_level.unwrap();
    let guard = log::log_init(log_level);

    let mount_point = match matches.subcommand() {
        Some(("mount", matches)) => {
            Some(matches.get_one::<String>("mount-point").unwrap().as_str())
        }
        _ => None,
    };

    let res = task::spawn_blocking(|| {
        panic::catch_unwind(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async { async_main().await })
        })
    })
    .await;
    match res {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(err))) => {
            let err2 = err.downcast_ref::<ExitStatusError>();
            if let Some(ExitStatusError::Failure(code)) = err2 {
                info!("Bye!");
                drop(guard);
                process::exit(*code);
            }
            error!("{err}");
            if let Some(mount_point) = mount_point {
                let _ = mount::umount(mount_point).map_err(|err| {
                    warn!("Cannot umount, maybe it was not mounted: {err}");
                    err
                });
            }
            Err(err)
        }
        Ok(Err(err)) => {
            error!("{err:#?}");
            if let Some(mount_point) = mount_point {
                let _ = mount::umount(mount_point).map_err(|err| {
                    warn!("Cannot umount, maybe it was not mounted: {err}");
                    err
                });
            }
            drop(guard);
            panic!("{err:#?}");
        }
        Err(err) => {
            error!("{err}");
            if let Some(mount_point) = mount_point {
                let _ = mount::umount(mount_point).map_err(|err| {
                    warn!("Cannot umount, maybe it was not mounted: {err}");
                    err
                });
            }
            drop(guard);
            panic!("{err}");
        }
    }
}

#[allow(clippy::too_many_lines)]
fn get_cli_args() -> ArgMatches {
    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .arg_required_else_help(true)
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .value_name("log-level")
                .default_value("INFO")
                .global(true)
                .help("Log level, possible values: TRACE, DEBUG, INFO, WARN, ERROR"),
        )
        .arg(
            Arg::new("cipher")
                .long("cipher")
                .short('c')
                .value_name("cipher")
                .default_value("ChaCha20Poly1305")
                .global(true)
                .help(format!("Cipher used for encryption, possible values: {}",
                              Cipher::iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ")),
                )
        )
        .subcommand_required(true)
        .subcommand(
            Command::new("mount")
                .about("Mount the filesystem exposing decrypted content from data dir")
                .arg(
                    Arg::new("mount-point")
                        .long("mount-point")
                        .short('m')
                        .required(true)
                        .value_name("MOUNT_POINT")
                        .requires("data-dir")
                        .help("Act as a client, and mount FUSE at given path"),
                )
                .arg(
                    Arg::new("data-dir")
                        .long("data-dir")
                        .short('d')
                        .required(true)
                        .value_name("DATA_DIR")
                        .requires("mount-point")
                        .help("Where to store the encrypted data"),
                )
                .arg(
                    Arg::new("umount-on-start")
                        .long("umount-on-start")
                        .short('u')
                        .action(ArgAction::SetTrue)
                        .requires("mount-point")
                        .requires("data-dir")
                        .help("If we should try to umount the mountpoint before starting the FUSE server. This can be useful when the previous run crashed or was forced kll and the mountpoint is still mounted."),
                )
                .arg(
                    Arg::new("allow-root")
                        .long("allow-root")
                        .short('s')
                        .action(ArgAction::SetTrue)
                        .requires("mount-point")
                        .requires("data-dir")
                        .help("Allow root user to access filesystem"),
                )
                .arg(
                    Arg::new("allow-other")
                        .long("allow-other")
                        .short('o')
                        .action(ArgAction::SetTrue)
                        .requires("mount-point")
                        .requires("data-dir")
                        .help("Allow other user to access filesystem"),
                )
                .arg(
                    Arg::new("read-only")
                        .long("read-only")
                        .short('r')
                        .action(ArgAction::SetTrue)
                        .requires("mount-point")
                        .requires("data-dir")
                        .help("Set FUSE filesystem read-only mount option, default is disabled.")
                )
        ).subcommand(
        Command::new("passwd")
            .about("Change password for the master key used to encrypt the data")
            .arg(
                Arg::new("data-dir")
                    .long("data-dir")
                    .short('d')
                    .required(true)
                    .value_name("DATA_DIR")
                    .help("Where to store the encrypted data"),
            ).arg(
                Arg::new("recovery-phrase")
                    .long("recovery-phrase")
                    .short('r')
                    .required(false)
                    .value_name("recovery_phrase")
                    .requires("data-dir")
                    .help("Recovery string to restore and change password"),
            )
    )
        .get_matches()
}

async fn async_main() -> Result<()> {
    let matches = get_cli_args();

    let cipher: String = matches.get_one::<String>("cipher").unwrap().to_string();
    let cipher = Cipher::from_str(cipher.as_str());
    if cipher.is_err() {
        error!("Invalid cipher");
        return Err(ExitStatusError::Failure(1).into());
    }
    let cipher = cipher.unwrap();

    match matches.subcommand() {
        Some(("change-password", matches)) => run_change_password(cipher, matches).await?,
        Some(("mount", matches)) => run_mount(cipher, matches).await?,
        None => {
            error!("No subcommand provided");
            return Err(ExitStatusError::Failure(1).into());
        }
        _ => {
            error!("Invalid subcommand");
            return Err(ExitStatusError::Failure(1).into());
        }
    }

    Ok(())
}

async fn run_change_password(cipher: Cipher, matches: &ArgMatches) -> Result<()> {
    let data_dir: String = matches.get_one::<String>("data-dir").unwrap().to_string();
    let recovery_phrase = matches.get_one::<SecretString>("recovery-phrase");

    let password = match recovery_phrase {
        Some(phrase) => {
            crypto::bip39::mnemonic_to_password(&phrase)?
        },
        None => {
            print!("Enter old password: ");
            io::stdout().flush().unwrap();
            SecretString::from_str(&read_password().unwrap()).unwrap()
        }
    };

    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = SecretString::from_str(&read_password().unwrap()).unwrap();
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = SecretString::from_str(&read_password().unwrap()).unwrap();
    if new_password.expose_secret() != new_password2.expose_secret() {
        println!("Passwords do not match");
        return Err(ExitStatusError::Failure(1).into());
    }
    println!("Changing password...");

    EncryptedFs::passwd(Path::new(&data_dir), password, new_password, cipher)
        .await
        .map_err(|err| {
            match err {
                FsError::InvalidPassword => {
                    println!("Invalid old password");
                }
                FsError::InvalidDataDirStructure => {
                    println!("Invalid structure of data directory");
                }
                _ => {
                    error!(err = %err);
                }
            }
            ExitStatusError::Failure(1)
        })?;

    println!("Password changed successfully");

    Ok(())
}

async fn run_mount(cipher: Cipher, matches: &ArgMatches) -> Result<()> {
    let mountpoint: String = matches
        .get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    let data_dir: String = matches.get_one::<String>("data-dir").unwrap().to_string();

    // when running from IDE we can't read from stdin with rpassword, get it from env var
    let mut password = SecretString::from_str(
        env::var("RENCFS_PASSWORD")
            .unwrap_or_else(|_| String::new())
            .as_str(),
    )
    .unwrap();
    if password.expose_secret().is_empty() {
        // read password from stdin
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        password = SecretString::from_str(read_password().unwrap().as_str()).unwrap();

        if !PathBuf::new().join(data_dir.clone()).is_dir()
            || fs::read_dir(&data_dir)
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        {
            // first run, ask to confirm password
            print!("Confirm password: ");
            io::stdout().flush().unwrap();
            let confirm_password =
                SecretString::from_str(read_password().unwrap().as_str()).unwrap();
            if password.expose_secret() != confirm_password.expose_secret() {
                error!("Passwords do not match");
                return Err(ExitStatusError::Failure(1).into());
            }

            let recovery_phrase = crypto::bip39::generate_recovery_phrase(Language::default(), &confirm_password)?;
            info!("Recovery Phrase: {}", recovery_phrase);
        }
    }
    // save password in keyring
    info!("Save password in keyring");
    let res = keyring::save(&password, "password").map_err(|err| {
        warn!(err = %err);
    });
    if res.is_err() {
        // maybe we don't have a security manager, keep it in mem
        unsafe {
            warn!("Cannot save password in keyring, keep it in memory");
            PASS = Some(password.clone());
        }
    }

    if matches.get_flag("umount-on-start") {
        let _ = mount::umount(mountpoint.as_str()).map_err(|err| {
            warn!("Cannot umount, maybe it was not mounted: {err}");
            err
        });
    }

    struct PasswordProviderImpl {}
    #[allow(clippy::items_after_statements)]
    #[allow(static_mut_refs)]
    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            unsafe {
                if PASS.is_some() {
                    info!("Get password from memory");
                    PASS.clone()
                } else {
                    info!("Get password from keyring");
                    keyring::get("password")
                        .map_err(|err| {
                            error!(err = %err, "cannot get password from keyring");
                            err
                        })
                        .ok()
                }
            }
        }
    }
    let mount_point = mount::create_mount_point(
        Path::new(&mountpoint),
        Path::new(&data_dir),
        Box::new(PasswordProviderImpl {}),
        cipher,
        matches.get_flag("allow-root"),
        matches.get_flag("allow-other"),
        matches.get_flag("read-only"),
    );
    let mount_handle = mount_point.mount().await.map_err(|err| {
        error!(err = %err);
        ExitStatusError::Failure(1)
    })?;
    let mount_handle = Arc::new(Mutex::new(Some(Some(mount_handle))));
    let mount_handle_clone = mount_handle.clone();
    // cleanup on process kill
    set_handler(move || {
        // can't use tracing methods here as guard cannot be dropper to flush content before we exit
        eprintln!("Received signal to exit");
        let mut status: Option<ExitStatusError> = None;
        remove_pass();
        eprintln!("Unmounting {mountpoint}");
        // create new tokio runtime
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = rt
            .block_on(async {
                let res = mount_handle_clone
                    .lock()
                    .await
                    .replace(None)
                    .unwrap()
                    .unwrap()
                    .umount()
                    .await;
                if res.is_err() {
                    mount::umount(mountpoint.as_str())?;
                }
                Ok::<(), io::Error>(())
            })
            .map_err(|err| {
                eprintln!("Error: {err}");
                status.replace(ExitStatusError::Failure(1));
                err
            });
        eprintln!("Bye!");
        process::exit(status.map_or(0, |x| match x {
            ExitStatusError::Failure(status) => status,
        }));
    })?;

    task::spawn_blocking(|| {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            tokio::time::sleep(tokio::time::Duration::from_secs(u64::MAX)).await;
        });
    })
    .await?;

    Ok(())
}

#[allow(static_mut_refs)]
fn remove_pass() {
    unsafe {
        if PASS.is_none() {
            info!("Delete password from keyring");
            keyring::remove("password")
                .map_err(|err| {
                    error!(err = %err);
                })
                .ok();
        } else {
            info!("Remove password from memory");
            PASS = None;
        }
    }
}
