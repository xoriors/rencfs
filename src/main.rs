use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader};

use clap::{Arg, ArgAction, Command, crate_version};
use fuser::MountOption;
use encrypted_fs::encrypted_fs_fuse::EncryptedFsFuse;

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

    fuser::mount2(EncryptedFsFuse::new(&data_dir, matches.get_flag("direct-io"), matches.get_flag("suid")).unwrap(), mountpoint, &options).unwrap();
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
