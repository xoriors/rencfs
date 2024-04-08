use std::{env, panic};
use std::ffi::OsStr;
use std::time::Duration;

use clap::{Arg, ArgAction, Command, crate_version};
use ctrlc::set_handler;
use fuse3::MountOptions;
use fuse3::raw::prelude::*;
use tokio::task;
use tracing::Level;

use encrypted_fs::encrypted_fs_fuse3::EncryptedFsFuse3;

const CONTENT: &str = "hello world\n";

const PARENT_INODE: u64 = 1;
const FILE_INODE: u64 = 2;
const FILE_NAME: &str = "hello-world.txt";
const PARENT_MODE: u16 = 0o755;
const FILE_MODE: u16 = 0o644;
const TTL: Duration = Duration::from_secs(1);
const STATFS: ReplyStatFs = ReplyStatFs {
    blocks: 1,
    bfree: 0,
    bavail: 0,
    files: 1,
    ffree: 0,
    bsize: 4096,
    namelen: u32::MAX,
    frsize: 0,
};

#[tokio::main(flavor = "current_thread")]
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

        let data_dir: String = matches
            .get_one::<String>("data-dir")
            .unwrap()
            .to_string();

        // unmount on process kill
        let mountpoint_kill = mountpoint.clone();
        set_handler(move || {
            unomunt(mountpoint_kill.to_string());
        }).unwrap();

        let mountpoint_panic = mountpoint.clone();

        let args = env::args_os().skip(1).take(1).collect::<Vec<_>>();

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let mut mount_options = MountOptions::default();
        mount_options.uid(uid).gid(gid).read_only(false);

        let mount_path = OsStr::new(mountpoint.as_str());
        Session::new(mount_options)
            .mount_with_unprivileged(EncryptedFsFuse3::new(data_dir.clone()), mount_path)
            .await
            .unwrap()
            .await
            .unwrap();
    });
}

fn unomunt(mountpoint: String) {
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
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
