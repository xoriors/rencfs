use rand_core::RngCore;
use std::env::args;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

use secrecy::SecretVec;

use rencfs::crypto;
use rencfs::crypto::Cipher;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let cipher = Cipher::ChaCha20Poly1305;
    let mut key = vec![0; cipher.key_len()];
    crypto::create_rng().fill_bytes(key.as_mut_slice());
    let key = Arc::new(SecretVec::new(key));

    let mut args = args();
    let _ = args.next(); // skip the program name
    let path_in = args.next().expect("path_in is missing");
    let path_out = format!(
        "/tmp/{}.enc",
        Path::new(&path_in).file_name().unwrap().to_str().unwrap()
    );
    let out = Path::new(&path_out).to_path_buf();
    if out.exists() {
        std::fs::remove_file(&out)?;
    }

    let mut file = File::open(path_in.clone()).unwrap();
    let mut writer = crypto::create_file_writer(
        &Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        None,
        None,
        None,
    )?;
    io::copy(&mut file, &mut writer).unwrap();
    writer.flush().unwrap();
    writer.finish().unwrap();

    let mut reader = crypto::create_file_reader(
        &Path::new(&path_out).to_path_buf(),
        cipher,
        key.clone(),
        None,
    )?;
    let hash1 = crypto::hash_reader(&mut File::open(path_in)?)?;
    let hash2 = crypto::hash_reader(&mut reader)?;

    assert_eq!(hash1, hash2);

    Ok(())
}
