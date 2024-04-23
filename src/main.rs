use std::{env, io, panic, process};
use std::backtrace::Backtrace;
use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use clap::{Arg, ArgAction, ArgMatches, Command, crate_version};
use ctrlc::set_handler;
use fuse3::MountOptions;
use fuse3::raw::prelude::*;
use rpassword::read_password;
use strum::IntoEnumIterator;
use tokio::{fs, task};
use tracing::{error, info, Level};

use encryptedfs::encryptedfs::{Cipher, EncryptedFs, FsError};
use encryptedfs::encryptedfs_fuse3::EncryptedFsFuse3;

#[tokio::main]
async fn main() {
    let result = task::spawn_blocking(|| {
        panic::catch_unwind(|| {
            async_main()
        })
    }).await;

    match result {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            error!("panic {err:#?}");
            error!(backtrace = %Backtrace::force_capture());
            panic!("{err:#?}");
        }
        Err(err) => {
            error!(err = %err, "panic");
            error!(backtrace = %Backtrace::force_capture());
            panic!("{err}");
        }
    }
}

fn async_main() {
    let handle = tokio::runtime::Handle::current();
    handle.block_on(async {
        let matches = Command::new("EncryptedFS")
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

        let log_level = matches.get_one::<String>("log-level").unwrap().as_str();
        if Level::from_str(log_level).is_err() {
            println!("Invalid log level");
            return;
        }
        log_init(log_level);

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
            println!("Invalid cipher");
            return;
        }
        let cipher = cipher.unwrap();

        let derive_key_hash_rounds: String = matches
            .get_one::<String>("derive-key-hash-rounds")
            .unwrap()
            .to_string();
        let derive_key_hash_rounds = u32::from_str(derive_key_hash_rounds.as_str());
        if derive_key_hash_rounds.is_err() {
            println!("Invalid derive key hash rounds");
            return;
        }
        let derive_key_hash_rounds = derive_key_hash_rounds.unwrap();

        if matches.get_flag("change-password") {
            // change password
            run_change_password(&data_dir, cipher, derive_key_hash_rounds).await;
        } else {
            //normal run
            run_normal(matches, &data_dir, cipher, derive_key_hash_rounds).await;
        }
    });
}

async fn run_change_password(data_dir: &String, cipher: Cipher, derive_key_hash_rounds: u32) {
    if !PathBuf::new().join(data_dir).is_dir() || fs::read_dir(&data_dir).await.unwrap().next_entry().await.unwrap().is_none() {
        println!("Data dir is not set up yet, nothing to change password for");
        return;
    }

    // read password from stdin
    print!("Enter old password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    {
        let fs = EncryptedFs::new(&data_dir, &password, cipher.clone(), derive_key_hash_rounds);
        if let Err(FsError::InvalidPassword) = fs {
            println!("Cannot decrypt data, maybe the password is wrong");
            process::exit(1);
        }
    }

    print!("Enter new password: ");
    io::stdout().flush().unwrap();
    let new_password = read_password().unwrap();
    EncryptedFs::change_password(&data_dir, &password, &new_password, cipher, derive_key_hash_rounds).unwrap();
    println!("Password changed successfully");
}

async fn run_normal(matches: ArgMatches, data_dir: &String, cipher: Cipher, derive_key_hash_rounds: u32) {
    if !matches.contains_id("mount-point") {
        println!("--mount-point <MOUNT_POINT> is required");
        return;
    }
    let mountpoint: String = matches.get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    // when running from IDE we can't read from stdin with rpassword, get it from env var
    let mut password = env::var("ENCRYPTEDFS_PASSWORD").unwrap_or_else(|_| "".to_string());
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
                println!("Passwords do not match");
                return;
            }
        }
    }

    if matches.get_flag("umount-on-start") {
        umount(mountpoint.as_str(), false);
    }

    // unmount on process kill
    if matches.get_flag("auto_unmount") {
        let mountpoint_kill = mountpoint.clone();
        set_handler(move || {
            info!("Received signal to exit");
            umount(mountpoint_kill.as_str(), true);
            process::exit(0);
        }).unwrap();
    }

    run_fuse(mountpoint, &data_dir, &password, cipher, derive_key_hash_rounds,
             matches.get_flag("allow-root"), matches.get_flag("allow-other"),
             matches.get_flag("direct-io"), matches.get_flag("suid")).await;
}

async fn run_fuse(mountpoint: String, data_dir: &str, password: &str, cipher: Cipher, derive_key_hash_rounds: u32,
                  allow_root: bool, allow_other: bool, direct_io: bool, suid_support: bool) {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mount_options = MountOptions::default()
        .uid(uid)
        .gid(gid)
        .read_only(false).
        allow_root(allow_root).
        allow_other(allow_other)
        .clone();
    let mount_path = OsStr::new(mountpoint.as_str());

    match EncryptedFsFuse3::new(&data_dir, &password, cipher, derive_key_hash_rounds, direct_io, suid_support) {
        Err(FsError::InvalidPassword) => {
            println!("Cannot decrypt data, maybe the password is wrong");
            process::exit(1);
        }
        Err(err) => {
            error!("{err}");
            process::exit(1);
        }
        Ok(fs) =>
            Session::new(mount_options)
                .mount_with_unprivileged(fs, mount_path)
                .await
                .unwrap()
                .await
                .unwrap()
    }
}

fn umount(mountpoint: &str, print_fail_status: bool) {
    let output = process::Command::new("umount")
        .arg(mountpoint)
        .output()
        .expect("Failed to execute command");

    if print_fail_status && !output.status.success() {
        println!("Cannot umount, maybe it was not mounted");
    }
}

fn log_init(level: &str) {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::from_str(level).unwrap())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
