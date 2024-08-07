use anyhow::Result;
use rand_core::RngCore;
use std::env::args;
use std::fs::File;
use std::io;
use std::path::Path;

use secrecy::SecretVec;
use tracing::info;

use rencfs::crypto;
use rencfs::crypto::write::CryptoWrite;
use rencfs::crypto::Cipher;

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let cipher = Cipher::ChaCha20Poly1305;
    let mut key = vec![0; cipher.key_len()];
    crypto::create_rng().fill_bytes(key.as_mut_slice());
    let key = SecretVec::new(key);

    let mut args = args();
    // skip the program name
    let _ = args.next();
    // will encrypt this file
    let path_in = args.next().expect("path_in is missing");
    // will save it in the same directory with .enc suffix
    let out = Path::new(&path_in).to_path_buf().with_extension("enc");
    if out.exists() {
        std::fs::remove_file(&out)?;
    }

    let mut file = File::open(path_in.clone())?;
    let mut writer = crypto::create_write(File::create(out.clone())?, cipher, &key);
    info!("encrypt file");
    io::copy(&mut file, &mut writer).unwrap();
    writer.finish()?;

    let mut reader = crypto::create_read(File::open(out)?, cipher, &key);
    info!("read file and compare hash to original one");
    let hash1 = crypto::hash_reader(&mut File::open(path_in)?)?;
    let hash2 = crypto::hash_reader(&mut reader)?;
    assert_eq!(hash1, hash2);

    Ok(())
}
