use std::{env, io, panic, process};
use std::ffi::OsStr;
use std::io::Read;
use std::str::FromStr;

use clap::{Arg, ArgAction, Command, crate_version};
use ctrlc::set_handler;
use fuse3::MountOptions;
use fuse3::raw::prelude::*;
use strum::IntoEnumIterator;
use tokio::task;
use tracing::Level;
use encrypted_fs::encrypted_fs::EncryptionType;

use encrypted_fs::encrypted_fs_fuse3::EncryptedFsFuse3;

#[tokio::main]
async fn main() {
    log_init();
    env_logger::init();

    let result = task::spawn_blocking(|| {
        panic::catch_unwind(|| {
            async_main()
        })
    }).await;

    match result {
        Ok(Ok(_)) => println!("There was no panic"),
        Ok(Err(_)) | Err(_) => println!("A panic occurred"),
    }
}

fn async_main() {
    let handle = tokio::runtime::Handle::current();
    handle.block_on(async {
        let matches = Command::new("hello")
            .version(crate_version!())
            .author("Radu Marias")
            .arg(
                Arg::new("mount-point")
                    .long("mount-point")
                    .value_name("MOUNT_POINT")
                    .default_value("")
                    .help("Act as a client, and mount FUSE at given path"),
            )
            .arg(
                Arg::new("data-dir")
                    .long("data-dir")
                    .value_name("data-dir")
                    .default_value("")
                    .help("Where to store the encrypted data"),
            )
            .arg(
                Arg::new("encryption-type")
                    .long("encryption-type")
                    .value_name("encryption-type")
                    .default_value("ChaCha20")
                    .help(format!("Encryption type, possible values: {}",
                                  EncryptionType::iter().fold(String::new(), |mut acc, x| {
                                      acc.push_str(format!("{}{}{:?}", acc, if acc.len() != 0 { ", " } else { "" }, x).as_str());
                                      acc
                                  }).as_str()),
                    )
            )
            .arg(
                Arg::new("derive-key-hash-rounds")
                    .long("derive-key-hash-rounds")
                    .value_name("derive-key-hash-rounds")
                    .default_value("600000")
                    .help("How many times to hash the password to derive the key"),
            )
            .arg(
                Arg::new("auto_unmount")
                    .long("auto_unmount")
                    .action(ArgAction::SetTrue)
                    .help("Automatically unmount on process exit"),
            )
            .arg(
                Arg::new("allow-root")
                    .long("allow-root")
                    .action(ArgAction::SetTrue)
                    .help("Allow root user to access filesystem"),
            )
            .arg(
                Arg::new("direct-io")
                    .long("direct-io")
                    .action(ArgAction::SetTrue)
                    .requires("mount-point")
                    .help("Mount FUSE with direct IO"),
            )
            .arg(
                Arg::new("suid")
                    .long("suid")
                    .action(ArgAction::SetTrue)
                    .help("Enable setuid support when run as root"),
            )
            .get_matches();
        let mountpoint: String = matches
            .get_one::<String>("mount-point")
            .unwrap()
            .to_string();

        unomunt(mountpoint.as_str());

        let mountpoint: String = matches
            .get_one::<String>("mount-point")
            .unwrap()
            .to_string();

        // unmount on process kill
        let mountpoint_kill = mountpoint.clone();
        set_handler(move || {
            unomunt(mountpoint_kill.as_str());
            process::exit(0);
        }).unwrap();

        let data_dir: String = matches
            .get_one::<String>("data-dir")
            .unwrap()
            .to_string();

        // read password from stdin
        print!("Enter password: ");
        let mut password = String::new();
        io::stdin().read_to_string(&mut password).unwrap();

        let encryption_type: String = matches
            .get_one::<String>("encryption-type")
            .unwrap()
            .to_string();
        let encryption_type = EncryptionType::from_str(encryption_type.as_str());
        if encryption_type.is_err() {
            println!("Invalid encryption type");
            return;
        }
        let encryption_type = encryption_type.unwrap();

        let derive_key_hash_rounds: String = matches
            .get_one::<String>("derive-key-hash-rounds")
            .unwrap()
            .to_string();
        let derive_key_hash_rounds = u32::from_str(derive_key_hash_rounds.as_str());
        if derive_key_hash_rounds.is_err() {
            println!("Invalid derive-key-hash-rounds");
            return;
        }
        let derive_key_hash_rounds = derive_key_hash_rounds.unwrap();

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let mut mount_options = MountOptions::default();
        mount_options.uid(uid).gid(gid).read_only(false);

        let mount_path = OsStr::new(mountpoint.as_str());
        Session::new(mount_options)
            .mount_with_unprivileged(EncryptedFsFuse3::new(&data_dir, &password, encryption_type, derive_key_hash_rounds,
                                                           matches.get_flag("direct-io"), matches.get_flag("suid")).unwrap(), mount_path)
            .await
            .unwrap()
            .await
            .unwrap();
    });
}

fn unomunt(mountpoint: &str) {
    let output = std::process::Command::new("umount")
        .arg(mountpoint)
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        let result = String::from_utf8(output.stdout).unwrap();
        println!("{}", result);
    } else {
        let err = String::from_utf8(output.stderr).unwrap();
        println!("Error: {}", err);
    }
}

fn log_init() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
