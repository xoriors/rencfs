use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, io, panic, process};

use anyhow::Result;
use clap::{crate_version, Arg, ArgAction, ArgMatches, Command};
use ctrlc::set_handler;
use rpassword::read_password;
use secrecy::{ExposeSecret, SecretString};
use strum::IntoEnumIterator;
use thiserror::Error;
use tokio::{fs, task};
use tracing::level_filters::LevelFilter;
use tracing::{error, info, warn, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::{EncryptedFs, FsError, PasswordProvider};
use rencfs::is_debug;

mod keyring;

#[derive(Debug, Error)]
enum ExitStatusError {
    #[error("exit with status {0}")]
    Failure(i32),
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = get_cli_args();

    let log_level = if is_debug() {
        Level::DEBUG
    } else {
        let str = match matches.subcommand() {
            Some(("mount", matches)) => {
                Some(matches.get_one::<String>("log-level").unwrap().as_str())
            }
            Some(("change-password", matches)) => {
                Some(matches.get_one::<String>("log-level").unwrap().as_str())
            }
            _ => None,
        };
        let log_level = Level::from_str(str.unwrap());
        if log_level.is_err() {
            error!("Invalid log level");
            return Err(ExitStatusError::Failure(1).into());
        }

        log_level.unwrap()
    };
    let guard = log_init(log_level);

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
        Ok(Ok(Ok(_))) => Ok(()),
        Ok(Ok(Err(err))) => {
            let err2 = err.downcast_ref::<ExitStatusError>();
            if let Some(ExitStatusError::Failure(code)) = err2 {
                process::exit(*code);
            }
            error!("{err}");
            if let Some(mount_point) = mount_point {
                umount(mount_point)?;
            }
            drop(guard);
            Err(err)
        }
        Ok(Err(err)) => {
            error!("{err:#?}");
            if let Some(mount_point) = mount_point {
                umount(mount_point)?;
            }
            drop(guard);
            panic!("{err:#?}");
        }
        Err(err) => {
            error!("{err}");
            if let Some(mount_point) = mount_point {
                umount(mount_point)?;
            }
            drop(guard);
            panic!("{err}");
        }
    }
}

fn get_cli_args() -> ArgMatches {
    let matches = Command::new("RencFs")
        .version(crate_version!())
        .author("Radu Marias")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("mount")
                .about("Mount the filesystem exposing decrypted content from data dir")
                .arg(
                    Arg::new("mount-point")
                        .long("mount-point")
                        .short('m')
                        .required(true)
                        .value_name("MOUNT_POINT")
                        .help("Act as a client, and mount FUSE at given path"),
                )
                .arg(
                    Arg::new("data-dir")
                        .long("data-dir")
                        .short('d')
                        .required(true)
                        .value_name("DATA_DIR")
                        .help("Where to store the encrypted data"),
                )
                .arg(
                    Arg::new("tmp-dir")
                        .long("tmp-dir")
                        .short('t')
                        .required(true)
                        .value_name("TMP_DIR")
                        .help("Where keep temp data. This should be in a different directory than data-dir as you don't want to sync this with the sync provider. But it needs to be on the same filesystem as the data-dir."),
                )
                .arg(
                    Arg::new("umount-on-start")
                        .long("umount-on-start")
                        .short('u')
                        .action(ArgAction::SetTrue)
                        .help("If we should try to umount the mountpoint before starting the FUSE server. This can be useful when the previous run crashed or was forced kll and the mountpoint is still mounted."),
                )
                .arg(
                    Arg::new("auto_unmount")
                        .long("auto_unmount")
                        .short('x')
                        .default_value("true")
                        .action(ArgAction::SetTrue)
                        .help("Automatically unmount on process exit"),
                )
                .arg(
                    Arg::new("allow-root")
                        .long("allow-root")
                        .short('r')
                        .action(ArgAction::SetTrue)
                        .help("Allow root user to access filesystem"),
                )
                .arg(
                    Arg::new("allow-other")
                        .long("allow-other")
                        .short('o')
                        .action(ArgAction::SetTrue)
                        .help("Allow other user to access filesystem"),
                )
                .arg(
                    Arg::new("direct-io")
                        .long("direct-io")
                        .short('i')
                        .action(ArgAction::SetTrue)
                        .requires("mount-point")
                        .help("Use direct I/O (bypass page cache for an open file)"),
                )
                .arg(
                    Arg::new("suid")
                        .long("suid")
                        .short('s')
                        .action(ArgAction::SetTrue)
                        .help("If it should allow setting SUID and SGID when files are created. Default is false and it will unset those flags when creating files"),
                )
                .arg(
                    Arg::new("cipher")
                        .long("cipher")
                        .short('c')
                        .value_name("cipher")
                        .default_value("ChaCha20")
                        .help(format!("Cipher used for encryption, possible values: {}",
                                      Cipher::iter().fold(String::new(), |mut acc, x| {
                                          acc.push_str(format!("{acc}{}{x}", if acc.len() != 0 { ", " } else { "" }).as_str());
                                          acc
                                      }).as_str()),
                        )
                )
                .arg(
                    Arg::new("log-level")
                        .long("log-level")
                        .short('l')
                        .value_name("log-level")
                        .default_value("INFO")
                        .help("Log level, possible values: TRACE, DEBUG, INFO, WARN, ERROR"),
                )
        ).subcommand(
        Command::new("change-password")
            .about("Change password for the encrypted data")
            .arg(
                Arg::new("data-dir")
                    .long("data-dir")
                    .short('d')
                    .required(true)
                    .value_name("DATA_DIR")
                    .help("Where to store the encrypted data"),
            )
            .arg(
                Arg::new("cipher")
                    .long("cipher")
                    .short('c')
                    .value_name("cipher")
                    .default_value("ChaCha20")
                    .help(format!("Cipher used for encryption, possible values: {}",
                                  Cipher::iter().fold(String::new(), |mut acc, x| {
                                      acc.push_str(format!("{acc}{}{x}", if acc.len() != 0 { ", " } else { "" }).as_str());
                                      acc
                                  }).as_str()),
                    )
            )
            .arg(
                Arg::new("log-level")
                    .long("log-level")
                    .short('l')
                    .value_name("log-level")
                    .default_value("INFO")
                    .help("Log level, possible values: TRACE, DEBUG, INFO, WARN, ERROR"),
            )
    )
        .get_matches();
    matches
}

async fn async_main() -> Result<()> {
    let matches = get_cli_args();

    match matches.subcommand() {
        Some(("change-password", matches)) => run_change_password(&matches).await?,
        Some(("mount", matches)) => run_mount(&matches).await?,
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

async fn run_change_password(matches: &ArgMatches) -> Result<()> {
    let data_dir: String = matches.get_one::<String>("data-dir").unwrap().to_string();

    let cipher: String = matches.get_one::<String>("cipher").unwrap().to_string();
    let cipher = Cipher::from_str(cipher.as_str());
    if cipher.is_err() {
        error!("Invalid cipher");
        return Err(ExitStatusError::Failure(1).into());
    }
    let cipher = cipher.unwrap();

    // read password from stdin
    print!("Enter old password: ");
    io::stdout().flush().unwrap();
    let password = SecretString::new(read_password().unwrap());
    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = SecretString::new(read_password().unwrap());
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = SecretString::new(read_password().unwrap());
    if new_password.expose_secret() != new_password2.expose_secret() {
        println!("Passwords do not match");
        return Err(ExitStatusError::Failure(1).into());
    }
    println!("Changing password...");
    EncryptedFs::change_password(
        Path::new(&data_dir).to_path_buf(),
        password,
        new_password,
        cipher,
    )
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

async fn run_mount(matches: &ArgMatches) -> Result<()> {
    let mountpoint: String = matches
        .get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    let data_dir: String = matches.get_one::<String>("data-dir").unwrap().to_string();

    let tmp_dir: String = matches.get_one::<String>("tmp-dir").unwrap().to_string();

    let cipher: String = matches.get_one::<String>("cipher").unwrap().to_string();
    let cipher = Cipher::from_str(cipher.as_str());
    if cipher.is_err() {
        error!("Invalid cipher");
        return Err(ExitStatusError::Failure(1).into());
    }
    let cipher = cipher.unwrap();

    // when running from IDE we can't read from stdin with rpassword, get it from env var
    let mut password =
        SecretString::new(env::var("RENCFS_PASSWORD").unwrap_or_else(|_| "".to_string()));
    if password.expose_secret().is_empty() {
        // read password from stdin
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        password = SecretString::new(read_password().unwrap());

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
            let confirm_password = SecretString::new(read_password().unwrap());
            if password.expose_secret() != confirm_password.expose_secret() {
                error!("Passwords do not match");
                return Err(ExitStatusError::Failure(1).into());
            }
        }
    }
    // save password in keyring
    keyring::save(password.clone(), "password").map_err(|err| {
        error!(err = %err);
        ExitStatusError::from(ExitStatusError::Failure(1))
    })?;

    if matches.get_flag("umount-on-start") {
        umount(mountpoint.as_str())?;
    }

    let auto_unmount = matches.get_flag("auto_unmount");
    let mountpoint_kill = mountpoint.clone();
    // unmount on process kill
    set_handler(move || {
        info!("Received signal to exit");
        let mut status: Option<ExitStatusError> = None;

        if auto_unmount {
            info!("Unmounting {}", mountpoint_kill);
        }
        umount(mountpoint_kill.as_str())
            .map_err(|err| {
                error!(err = %err);
                status.replace(ExitStatusError::Failure(1));
            })
            .ok();

        info!("Delete key from keyring");
        keyring::delete("password")
            .map_err(|err| {
                error!(err = %err);
                status.replace(ExitStatusError::Failure(1));
            })
            .ok();

        process::exit(status.map_or(0, |x| match x {
            ExitStatusError::Failure(status) => status,
        }));
    })
    .unwrap();

    struct PasswordProviderImpl {}

    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            keyring::get("password")
                .map_err(|err| {
                    error!(err = %err, "cannot get password from keyring");
                    err
                })
                .ok()
        }
    }

    rencfs::run_fuse(
        Path::new(&mountpoint).to_path_buf(),
        Path::new(&data_dir).to_path_buf(),
        Path::new(&tmp_dir).to_path_buf(),
        Box::new(PasswordProviderImpl {}),
        cipher,
        matches.get_flag("allow-root"),
        matches.get_flag("allow-other"),
        matches.get_flag("direct-io"),
        matches.get_flag("suid"),
    )
    .await
}

fn umount(mountpoint: &str) -> Result<()> {
    let output = process::Command::new("umount").arg(mountpoint).output()?;

    if !output.status.success() {
        warn!("Cannot umount, maybe it was not mounted");
    }

    Ok(())
}

pub fn log_init(level: Level) -> WorkerGuard {
    let directive = format!("rencfs={}", level.as_str()).parse().unwrap();
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .unwrap()
        .add_directive(directive);

    let (writer, guard) = tracing_appender::non_blocking(io::stdout());
    let builder = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(filter);
    // .with_max_level(level);
    if is_debug() {
        builder.pretty().init()
    } else {
        builder.pretty().init()
    }

    guard
}
