use anyhow::Result;

mod keyring;

#[cfg(target_os = "linux")]
mod run;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        eprintln!("he he, not yet ready for this platform, but soon my friend, soon :)");
        eprintln!("Bye!");
        return Ok(());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        eprintln!("sorry but this platform is not supported!");
        eprintln!("Bye!");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    run::run().await
}
