#![cfg_attr(not(debug_assertions), deny(warnings))]
#![feature(test)]
// #![feature(error_generic_member_access)]
#![feature(seek_stream_len)]
#![feature(const_refs_to_cell)]
#![doc(html_playground_url = "https://play.rust-lang.org")]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
// #![deny(missing_docs)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::missing_errors_doc)]
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
