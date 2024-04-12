use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read};
use std::str::FromStr;

use clap::{Arg, ArgAction, Command, crate_version};
use fuser::MountOption;
use strum::IntoEnumIterator;
use encrypted_fs::encrypted_fs::EncryptionType;
use crate::encrypted_fs_fuse::EncryptedFsFuse;

mod encrypted_fs_fuse;

fn main() {
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

    env_logger::init();

    let mountpoint: String = matches
        .get_one::<String>("mount-point")
        .unwrap()
        .to_string();

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

    let mut options = vec![MountOption::FSName("fuser".to_string())];

    #[cfg(feature = "abi-7-26")]
    {
        if matches.get_flag("suid") {
            info!("setuid bit support enabled");
            options.push(MountOption::Suid);
        } else {
            options.push(MountOption::AutoUnmount);
        }
    }
    #[cfg(not(feature = "abi-7-26"))]
    {
        // options.push(MountOption::AutoUnmount);
    }
    if let Ok(enabled) = fuse_allow_other_enabled() {
        if enabled {
            options.push(MountOption::AllowOther);
        }
    } else {
        eprintln!("Unable to read /etc/fuse.conf");
    }

    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    fuser::mount2(EncryptedFsFuse::new(&data_dir, &password, encryption_type, derive_key_hash_rounds,
                                       matches.get_flag("direct-io"), matches.get_flag("suid")).unwrap(), mountpoint, &options).unwrap();
}

fn fuse_allow_other_enabled() -> io::Result<bool> {
    let file = File::open("/etc/fuse.conf")?;
    for line in BufReader::new(file).lines() {
        if line?.trim_start().starts_with("user_allow_other") {
            return Ok(true);
        }
    }
    Ok(false)
}
