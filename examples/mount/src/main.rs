use core::str::FromStr;
use std::env::args;
use std::io;
use std::path::Path;

use anyhow::Result;
use shush_rs::SecretString;
use tracing::info;

use rencfs::crypto::Cipher;
use rencfs::encryptedfs::PasswordProvider;
use rencfs::mount::create_mount_point;
use rencfs::mount::MountPoint;

/// This will mount and expose the mount point until you press `Enter`, then it will umount and close the program.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let mut args = args();
    args.next(); // skip program name
    let mount_path = args.next().expect("mount_path expected");
    let data_path = args.next().expect("data_path expected");
    println!("mount_path: {mount_path}");
    println!("data_path: {data_path}");
    struct PasswordProviderImpl {}
    impl PasswordProvider for PasswordProviderImpl {
        fn get_password(&self) -> Option<SecretString> {
            // dummy password, use some secure way to get the password like with [keyring](https://crates.io/crates/keyring) crate
            Some(SecretString::from_str("a").unwrap())
        }
    }
    let mount_point = create_mount_point(
        Path::new(&mount_path),
        Path::new(&data_path),
        Box::new(PasswordProviderImpl {}),
        Cipher::ChaCha20Poly1305,
        false,
        false,
        false,
    );
    let handle = mount_point.mount().await?;
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    info!("Unmounting...");
    info!("Bye!");
    handle.umount().await?;

    Ok(())
}
