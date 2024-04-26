use std::{env, io, panic, process};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Arg, ArgAction, ArgMatches, Command, crate_version};
use ctrlc::set_handler;
use rpassword::read_password;
use strum::IntoEnumIterator;
use tokio::{fs, task};
use tracing::{error, info, Level, warn};
use anyhow::Result;
use thiserror::Error;

use rencfs::encryptedfs::{Cipher, EncryptedFs, FsError};
use rencfs::{is_debug, log_init};

#[derive(Debug, Error)]
enum ExitStatusError {
    #[error("exit with status {0}")]
    Failure(i32),
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = get_cli_args();

    let log_level = if is_debug() {
        Level::TRACE
    } else {
        let log_level_str = matches.get_one::<String>("log-level").unwrap().as_str();
        let log_level = Level::from_str(log_level_str);
        if log_level.is_err() {
            error!("Invalid log level");
            return Ok(());
        }

        log_level.unwrap()
    };
    let guard = log_init(log_level);

    let res = task::spawn_blocking(|| {
        panic::catch_unwind(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                async_main().await
            })
        })
    }).await;
    match res {
        Ok(Ok(Ok(_))) => Ok(()),
        Ok(Ok(Err(err))) => {
            let err2 = err.downcast_ref::<ExitStatusError>();
            if let Some(ExitStatusError::Failure(code)) = err2 {
                process::exit(*code);
            }
            error!("{err}");
            drop(guard);
            Err(err)
        }
        Ok(Err(err)) => {
            error!("{err:#?}");
            drop(guard);
            panic!("{err:#?}");
        }
        Err(err) => {
            error!("{err}");
            drop(guard);
            panic!("{err}");
        }
    }
}

fn get_cli_args() -> ArgMatches {
    let matches = Command::new("RencFs")
        .version(crate_version!())
        .author("Radu Marias")
        .arg(
            Arg::new("mount-point")
                .long("mount-point")
                .short('m')
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
            Arg::new("cipher")
                .long("cipher")
                .short('c')
                .value_name("cipher")
                .default_value("ChaCha20")
                .help(format!("Encryption type, possible values: {}",
                              Cipher::iter().fold(String::new(), |mut acc, x| {
                                  acc.push_str(format!("{acc}{}{x}", if acc.len() != 0 { ", " } else { "" }).as_str());
                                  acc
                              }).as_str()),
                )
        )
        .arg(
            Arg::new("derive-key-hash-rounds")
                .long("derive-key-hash-rounds")
                .short('k')
                .value_name("derive-key-hash-rounds")
                .default_value("600000")
                .help("How many times to hash the password to derive the key"),
        )
        .arg(
            Arg::new("umount-on-start")
                .long("umount-on-start")
                .short('x')
                .action(ArgAction::SetTrue)
                .help("If we should try to umount the mountpoint before starting the FUSE server. This can be useful when the previous run crashed or was forced kll and the mountpoint is still mounted."),
        )
        .arg(
            Arg::new("auto_unmount")
                .long("auto_unmount")
                .short('u')
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
                .help("Mount FUSE with direct IO"),
        )
        .arg(
            Arg::new("suid")
                .long("suid")
                .short('s')
                .action(ArgAction::SetTrue)
                .help("Enable setuid support when run as root"),
        )
        .arg(
            Arg::new("change-password")
                .long("change-password")
                .short('p')
                .action(ArgAction::SetTrue)
                .help("Change password for the encrypted data. Old password and new password will be read from the stdin"),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .value_name("log-level")
                .default_value("INFO")
                .help("Log level, possible values: TRACE, DEBUG, INFO, WARN, ERROR"),
        )
        .get_matches();
    matches
}

async fn async_main() -> Result<()> {
    let matches = get_cli_args();

    let data_dir: String = matches
        .get_one::<String>("data-dir")
        .unwrap()
        .to_string();

    let cipher: String = matches
        .get_one::<String>("cipher")
        .unwrap()
        .to_string();
    let cipher = Cipher::from_str(cipher.as_str());
    if cipher.is_err() {
        error!("Invalid cipher");
        return Ok(());
    }
    let cipher = cipher.unwrap();

    let derive_key_hash_rounds: String = matches
        .get_one::<String>("derive-key-hash-rounds")
        .unwrap()
        .to_string();
    let derive_key_hash_rounds = u32::from_str(derive_key_hash_rounds.as_str());
    if derive_key_hash_rounds.is_err() {
        error!("Invalid derive key hash rounds");
        return Ok(());
    }
    let derive_key_hash_rounds = derive_key_hash_rounds.unwrap();

    if matches.get_flag("change-password") {
        // change password
        run_change_password(&data_dir, cipher, derive_key_hash_rounds)?;
    } else {
        //normal run
        run_normal(matches, &data_dir, cipher, derive_key_hash_rounds).await?;
    }

    Ok(())
}

fn run_change_password(data_dir: &String, cipher: Cipher, derive_key_hash_rounds: u32) -> Result<()> {
    // read password from stdin
    print!("Enter old password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = read_password().unwrap();
    print!("Confirm new password: ");
    io::stdout().flush().unwrap();
    let new_password2 = read_password().unwrap();
    if new_password != new_password2 {
        println!("Passwords do not match");
        return Err(ExitStatusError::Failure(1).into());
    }
    println!("Changing password...");
    EncryptedFs::change_password(&data_dir, &password, &new_password, cipher, derive_key_hash_rounds).map_err(|err| {
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

async fn run_normal(matches: ArgMatches, data_dir: &String, cipher: Cipher, derive_key_hash_rounds: u32) -> Result<()> {
    if !matches.contains_id("mount-point") {
        error!("--mount-point <MOUNT_POINT> is required");
        return Ok(());
    }
    let mountpoint: String = matches.get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    // when running from IDE we can't read from stdin with rpassword, get it from env var
    let mut password = env::var("RENCFS_PASSWORD").unwrap_or_else(|_| "".to_string());
    if password.is_empty() {
        // read password from stdin
        print!("Enter password: ");
        io::stdout().flush().unwrap();
        password = read_password().unwrap();

        if !PathBuf::new().join(data_dir).is_dir() || fs::read_dir(&data_dir).await.unwrap().next_entry().await.unwrap().is_none() {
            // first run, ask to confirm password
            print!("Confirm password: ");
            io::stdout().flush().unwrap();
            let confirm_password = read_password().unwrap();
            if password != confirm_password {
                error!("Passwords do not match");
                return Ok(());
            }
        }
    }

    if matches.get_flag("umount-on-start") {
        umount(mountpoint.as_str(), false)?;
    }

    // unmount on process kill
    if matches.get_flag("auto_unmount") {
        let mountpoint_kill = mountpoint.clone();
        set_handler(move || {
            info!("Received signal to exit");
            let _ = umount(mountpoint_kill.as_str(), true).map_err(|err| error!(err = %err));
            process::exit(0);
        }).unwrap();
    }

    rencfs::run_fuse(&mountpoint, &data_dir, &password, cipher, derive_key_hash_rounds,
                     matches.get_flag("allow-root"), matches.get_flag("allow-other"),
                     matches.get_flag("direct-io"), matches.get_flag("suid")).await
}

fn umount(mountpoint: &str, print_fail_status: bool) -> Result<()> {
    let output = process::Command::new("umount")
        .arg(mountpoint)
        .output()?;

    if print_fail_status && !output.status.success() {
        warn!("Cannot umount, maybe it was not mounted");
    }

    Ok(())
}
